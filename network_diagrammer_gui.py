#!/usr/bin/env python3
"""
Auto Network Diagrammer - GUI edition (portable / any-network)
==============================================================
A clickable desktop app that scans one or more networks with nmap,
infers a star topology around the detected router/gateway, and renders
an interactive HTML map with pyvis.

This version has NO hardcoded networks. On launch it auto-detects the
subnet(s) your machine is on, reading the REAL subnet mask from the OS
(so a /28, /27, /23 etc. is reported correctly, not assumed as /24).
You can edit, add, or remove targets freely, and it remembers your last
targets between runs.

Requirements:
    pip install python-nmap networkx pyvis
    (and the `nmap` binary must be installed and on PATH)

Run:
    python network_diagrammer_gui.py
"""

import os
import re
import json
import shlex
import socket
import sqlite3
import ipaddress
import subprocess
import queue
import threading
import time
import webbrowser
import xml.etree.ElementTree as ET
from datetime import datetime

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext, simpledialog

import nmap
import networkx as nx
from pyvis.network import Network


# Where we remember the user's last-used settings (next to the exe/script).
CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "diagrammer_config.json")

# SQLite file tracking every past scan (name, targets, result, status).
HISTORY_DB_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "scan_history.db")

# Stops nmap/ipconfig/arp etc. from flashing their own console window when
# this app is run as a windowed (console-less) build on Windows.
_NO_WINDOW = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}

# Parses nmap's live "-v --stats-every" progress tags out of its XML stream,
# e.g. <taskprogress task="ARP Ping Scan" time="..." percent="76.67" remaining="1" etc="..."/>
_TASKPROGRESS_RE = re.compile(rb'<taskprogress\s+([^>]*)/>')
_XML_ATTR_RE = re.compile(rb'(\w+)="([^"]*)"')


# --------------------------------------------------------------------------- #
#  Scan history (SQLite)                                                       #
# --------------------------------------------------------------------------- #
class ScanHistory:
    """Tracks previous scans in a local SQLite file so they can be revisited.

    Each run gets an auto-incrementing name ("Scan 1", "Scan 2", ...) unless
    the user supplies their own, plus a creation timestamp, its target list,
    the resulting diagram path, device count, and final status.
    """

    def __init__(self, db_path=HISTORY_DB_PATH):
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                targets TEXT NOT NULL,
                output_file TEXT,
                device_count INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'running'
            )
        """)
        self.conn.commit()

    def next_name(self):
        """Suggest the next auto-incremented scan name, e.g. 'Scan 4'."""
        n = self.conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0] + 1
        return f"Scan {n}"

    def add(self, name, targets):
        """Insert a new in-progress scan row and return its id."""
        cur = self.conn.execute(
            "INSERT INTO scans (name, created_at, targets, status) "
            "VALUES (?, ?, ?, 'running')",
            (name, datetime.now().isoformat(timespec="seconds"), "\n".join(targets)))
        self.conn.commit()
        return cur.lastrowid

    def finish(self, scan_id, status, device_count, output_file):
        self.conn.execute(
            "UPDATE scans SET status=?, device_count=?, output_file=? WHERE id=?",
            (status, device_count, output_file, scan_id))
        self.conn.commit()

    def rename(self, scan_id, name):
        self.conn.execute("UPDATE scans SET name=? WHERE id=?", (name, scan_id))
        self.conn.commit()

    def delete(self, scan_id):
        self.conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
        self.conn.commit()

    def get(self, scan_id):
        return self.conn.execute(
            "SELECT id, name, created_at, targets, output_file, device_count, status "
            "FROM scans WHERE id=?", (scan_id,)).fetchone()

    def all(self):
        return self.conn.execute(
            "SELECT id, name, created_at, targets, output_file, device_count, status "
            "FROM scans ORDER BY id DESC").fetchall()


# --------------------------------------------------------------------------- #
#  Network auto-detection helpers                                              #
# --------------------------------------------------------------------------- #
def _primary_ip():
    """The local IP that outbound traffic leaves from (no packets sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def _hexmask_to_prefix(hexstr):
    """Convert a macOS-style hex netmask (e.g. 0xffffff00) to a prefix int."""
    try:
        return bin(int(hexstr, 16)).count("1")
    except Exception:
        return None


def _detect_ip_mask_pairs():
    """Return [(ip, netmask_or_prefix), ...] read from the OS, real masks.

    netmask may be a dotted string ('255.255.255.240') or an int prefix (28);
    both are accepted by ipaddress.ip_network below.
    """
    pairs = []
    try:
        if os.name == "nt":
            # Parse `ipconfig`: pair each "IPv4 Address" with the following
            # "Subnet Mask" line within the same adapter block.
            out = subprocess.check_output(["ipconfig"], text=True, errors="ignore", **_NO_WINDOW)
            pending_ip = None
            for line in out.splitlines():
                low = line.lower()
                if "ipv4 address" in low and ":" in line:
                    ip = line.split(":")[-1].strip()
                    ip = ip.replace("(Preferred)", "").strip()
                    pending_ip = ip
                elif "subnet mask" in low and ":" in line and pending_ip:
                    mask = line.split(":")[-1].strip()
                    pairs.append((pending_ip, mask))
                    pending_ip = None
        else:
            # Linux: `ip -o -f inet addr show` gives "inet 192.168.5.10/28 ..."
            try:
                out = subprocess.check_output(
                    ["ip", "-o", "-f", "inet", "addr", "show"],
                    text=True, errors="ignore", **_NO_WINDOW)
                for line in out.splitlines():
                    toks = line.split()
                    if "inet" in toks:
                        cidr = toks[toks.index("inet") + 1]  # 192.168.5.10/28
                        ip, _, prefix = cidr.partition("/")
                        if prefix:
                            pairs.append((ip, int(prefix)))
            except Exception:
                # macOS / BSD: "inet 192.168.5.10 netmask 0xfffffff0"
                out = subprocess.check_output(["ifconfig"], text=True, errors="ignore", **_NO_WINDOW)
                for line in out.splitlines():
                    toks = line.split()
                    if "inet" in toks and "netmask" in toks:
                        ip = toks[toks.index("inet") + 1]
                        raw = toks[toks.index("netmask") + 1]
                        prefix = _hexmask_to_prefix(raw) if raw.startswith("0x") else None
                        if prefix is not None:
                            pairs.append((ip, prefix))
    except Exception:
        pass
    return pairs


def detect_local_subnets():
    """Return de-duplicated CIDR subnets this machine is on, using REAL masks.

    Reads the actual subnet mask from the OS (ipconfig / ip / ifconfig) so a
    /28, /27, /23, etc. is reported correctly instead of assuming /24. Only if
    the OS lookup finds nothing do we fall back to a /24 guess.
    """
    primary = _primary_ip()
    cleaned = []

    for ip, mask in _detect_ip_mask_pairs():
        if not ip or ip.startswith("127."):
            continue
        try:
            net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
        except ValueError:
            continue
        text = str(net)
        if text in cleaned:
            continue
        # Put the subnet containing our primary outbound IP first.
        if primary and ipaddress.ip_address(primary) in net:
            cleaned.insert(0, text)
        else:
            cleaned.append(text)

    # Fallback only if the OS gave us nothing usable.
    if not cleaned and primary:
        cleaned.append(str(ipaddress.ip_network(f"{primary}/24", strict=False)))

    return cleaned


def detect_default_gateway():
    """Best-effort default gateway IP as a string, or None."""
    try:
        if os.name == "nt":
            out = subprocess.check_output(
                ["ipconfig"], text=True, errors="ignore", **_NO_WINDOW)
            for line in out.splitlines():
                if "Default Gateway" in line and ":" in line:
                    ip = line.split(":")[-1].strip()
                    if ip and ip.count(".") == 3:
                        return ip
        else:
            out = subprocess.check_output(
                ["ip", "route"], text=True, errors="ignore", **_NO_WINDOW)
            for line in out.splitlines():
                if line.startswith("default"):
                    parts = line.split()
                    if "via" in parts:
                        return parts[parts.index("via") + 1]
    except Exception:
        pass
    return None


# --------------------------------------------------------------------------- #
#  Core scanning / diagram logic                                              #
# --------------------------------------------------------------------------- #
class AutoNetworkDiagrammer:
    def __init__(self, log=print, gateway_hint=None, stop_event=None, progress=None):
        self.log = log
        self.progress_cb = progress or (lambda pct: None)   # optional live % callback
        self.gateway_hint = gateway_hint      # optional detected gateway IP
        self.stop_event = stop_event or threading.Event()
        self.run_start_ts = None
        self._proc_lock = threading.Lock()
        self._current_proc = None
        self.scanner = nmap.PortScanner()
        self.G = nx.Graph()
        self.net = Network(height="1000px", width="100%",
                           directed=False, notebook=False)
        self.net.set_options("""
        {
            "nodes": {"shape": "dot", "size": 28, "font": {"size": 15}},
            "edges": {"smooth": {"type": "dynamic"}, "font": {"size": 10}},
            "physics": {"stabilization": {"iterations": 2000}}
        }
        """)
        self.router_ip = None
        self.device_count = 0
        self.local_ip = _primary_ip()
        self.traces = {}              # host -> [{"ttl","ip","host","rtt"}, ...] from <trace>
        self.arp_table = {}           # ip -> mac, read from the OS ARP cache
        self.local_segment_ips = set()  # ips confirmed on our local L2 segment (ARP)

    # Discovery probes across several protocols/ports so hosts that drop plain
    # ICMP (common on Windows/firewalled devices) still get found, plus -R to
    # resolve real hostnames and --traceroute to map real hops.
    #
    # NOTE: deliberately NOT using --system-dns — it defers to the OS's
    # synchronous resolver, which is dramatically slower than nmap's own
    # async resolver for hosts with no PTR record (measured ~17x slower,
    # 79s vs 4.6s, on a 16-address /28 with several unnamed hosts).
    NMAP_DISCOVERY_ARGS = (
        "-sn -PR -PE -PP "
        "-PS21,22,23,25,80,443,3389,8080 -PA21,22,80,443,3389 "
        "--traceroute -R --max-retries 2"
    )

    @staticmethod
    def _fmt_elapsed(seconds):
        m, s = divmod(max(0, int(seconds)), 60)
        return f"{m:02d}:{s:02d}"

    @staticmethod
    def _ascii_bar(pct, width=20):
        pct = max(0.0, min(100.0, pct))
        filled = int(width * pct / 100)
        return "[" + "#" * filled + "-" * (width - filled) + "]"

    def scan_network(self, targets):
        self.log("\U0001F50D Scanning...")
        self.run_start_ts = time.time()
        for target in targets:
            if self.stop_event.is_set():
                self.log("⏹ Stopped by user.")
                break
            target = target.strip()
            if not target:
                continue
            self.log(f"  → {target}")
            try:
                if not self._run_nmap(target, arguments=self.NMAP_DISCOVERY_ARGS):
                    self.log("⏹ Stopped by user.")
                    break
                self._refresh_arp_table()
                for host in self.scanner.all_hosts():
                    hostname = self.scanner[host].hostname() or self._resolve_hostname(host)
                    hostname = hostname or f"host-{host.split('.')[-1]}"
                    mac = self.scanner[host]['addresses'].get('mac')
                    if not mac or mac == 'Unknown':
                        mac = self.arp_table.get(host, 'Unknown')
                    device_type = self.guess_device_type(hostname, host)

                    reason = self.scanner[host].get('status', {}).get('reason', '')
                    if 'arp' in reason:
                        self.local_segment_ips.add(host)

                    if self.router_ip is None and any(
                        x in hostname.lower()
                        for x in ['router', 'gateway', 'mikrotik', 'pfsense', 'gw']
                    ):
                        self.router_ip = host

                    label = f"{hostname}\n{host}"
                    title = (f"IP: {host}\nHostname: {hostname}\n"
                             f"MAC: {mac}\nSubnet: {self.get_subnet(host)}")

                    self.G.add_node(host, label=label, title=title, group=device_type)
                    self.net.add_node(host, label=label, title=title,
                                      color=self.get_color(device_type))
                    self.device_count += 1
                    elapsed = self._fmt_elapsed(time.time() - self.run_start_ts)
                    self.log(f"     ✓ [{elapsed}] {hostname} ({host})")
            except Exception as e:
                self.log(f"     ⚠️ Error on {target}: {e}")
        elapsed = self._fmt_elapsed(time.time() - self.run_start_ts)
        self.log(f"Found {self.device_count} device(s) in {elapsed}.")

    def _resolve_hostname(self, ip, timeout=0.5):
        """Fallback reverse-DNS lookup for hosts nmap's own -R couldn't name.

        socket.gethostbyaddr() has no built-in timeout and can block for the
        OS resolver's full retry cycle (measured 5-10+ seconds) on addresses
        with no PTR record — with several such hosts on one subnet that adds
        up fast, so this bounds the wait in a daemon thread instead.
        """
        result = [None]

        def _lookup():
            try:
                result[0] = socket.gethostbyaddr(ip)[0]
            except Exception:
                pass

        t = threading.Thread(target=_lookup, daemon=True)
        t.start()
        t.join(timeout)
        return result[0] or ""

    def _refresh_arp_table(self):
        """Read the OS ARP cache (arp -a / ip neigh) so we get MACs nmap can't
        reach without raw-packet privileges, and can confirm which hosts sit
        on our own local L2 segment (directly reachable, no routing hop).
        """
        table = {}
        try:
            if os.name == "nt":
                out = subprocess.check_output(["arp", "-a"], text=True, errors="ignore", **_NO_WINDOW)
                for line in out.splitlines():
                    parts = line.split()
                    if (len(parts) >= 2 and parts[0].count(".") == 3
                            and re.match(r'^[0-9a-fA-F]{2}([-:][0-9a-fA-F]{2}){5}$', parts[1])):
                        table[parts[0]] = parts[1].replace('-', ':').lower()
            else:
                try:
                    out = subprocess.check_output(
                        ["ip", "neigh", "show"], text=True, errors="ignore", **_NO_WINDOW)
                    for line in out.splitlines():
                        parts = line.split()
                        if parts and parts[0].count(".") == 3 and "lladdr" in parts:
                            table[parts[0]] = parts[parts.index("lladdr") + 1].lower()
                except Exception:
                    out = subprocess.check_output(["arp", "-n"], text=True, errors="ignore", **_NO_WINDOW)
                    for line in out.splitlines():
                        parts = line.split()
                        if (len(parts) >= 3 and parts[0].count(".") == 3
                                and re.match(r'^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$', parts[2])):
                            table[parts[0]] = parts[2].lower()
        except Exception:
            pass
        if table:
            self.arp_table.update(table)
            self.local_segment_ips.update(table.keys())

    def _parse_traceroute_xml(self, xml_bytes):
        """Pull <trace> hop chains out of the raw nmap XML.

        python-nmap's analyse_nmap_xml_scan() discards <trace> entirely, so we
        parse the same XML ourselves to get the real hop-by-hop path to each host.
        """
        if not xml_bytes:
            return
        try:
            root = ET.fromstring(xml_bytes)
        except ET.ParseError:
            return
        for dhost in root.findall("host"):
            addr_el = dhost.find("address[@addrtype='ipv4']")
            if addr_el is None:
                continue
            host_ip = addr_el.get("addr")
            trace_el = dhost.find("trace")
            if trace_el is None:
                continue
            hops = []
            for hop in trace_el.findall("hop"):
                try:
                    ttl = int(hop.get("ttl", 0))
                except ValueError:
                    ttl = 0
                hops.append({
                    "ttl": ttl,
                    "ip": hop.get("ipaddr"),
                    "host": hop.get("host") or "",
                    "rtt": hop.get("rtt", "?"),
                })
            if hops:
                hops.sort(key=lambda h: h["ttl"])
                self.traces[host_ip] = hops

    def _run_nmap(self, target, arguments):
        """Run nmap for one target as a killable subprocess.

        Mirrors what nmap.PortScanner.scan() does internally, but keeps a
        handle to the Popen object so stop() can terminate it immediately
        instead of waiting for the whole scan to finish. Also streams stdout
        live (rather than blocking on communicate()) so we can surface nmap's
        own -v/--stats-every progress as a progress meter in the scan log.

        Returns True if the scan completed and results were parsed into
        self.scanner, or False if it was stopped before/while running.
        """
        args = ([self.scanner._nmap_path, "-oX", "-", "-v", "--stats-every", "2s"]
                + shlex.split(target) + shlex.split(arguments))
        with self._proc_lock:
            if self.stop_event.is_set():
                return False
            self._current_proc = subprocess.Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **_NO_WINDOW)
            proc = self._current_proc

        chunks = []
        progress_state = {"pct": -100.0, "ts": 0.0}

        def _handle_progress(buf):
            for m in _TASKPROGRESS_RE.finditer(buf):
                attrs = dict(_XML_ATTR_RE.findall(m.group(1)))
                try:
                    pct = float(attrs.get(b"percent", b"0"))
                except ValueError:
                    continue
                now = time.time()
                if pct - progress_state["pct"] < 3 and now - progress_state["ts"] < 3:
                    continue
                progress_state["pct"] = pct
                progress_state["ts"] = now
                self.progress_cb(pct)
                task = attrs.get(b"task", b"").decode(errors="ignore")
                remaining = attrs.get(b"remaining")
                elapsed = self._fmt_elapsed(now - (self.run_start_ts or now))
                msg = f"     {self._ascii_bar(pct)} {pct:5.1f}%  {task}"
                if remaining:
                    msg += f"  (~{int(remaining)}s left)"
                msg += f"  [{elapsed}]"
                self.log(msg)

        def _drain_stdout():
            carry = b""
            for chunk in iter(lambda: proc.stdout.read(4096), b""):
                chunks.append(chunk)
                buf = carry + chunk
                _handle_progress(buf)
                carry = buf[-200:]

        t = threading.Thread(target=_drain_stdout, daemon=True)
        t.start()
        err = proc.stderr.read()
        proc.wait()
        t.join()
        out = b"".join(chunks)

        with self._proc_lock:
            self._current_proc = None

        if self.stop_event.is_set():
            return False

        self.scanner.analyse_nmap_xml_scan(
            nmap_xml_output=out, nmap_err=err.decode(errors="ignore"))
        self._parse_traceroute_xml(out)
        return True

    def stop(self):
        """Signal the running scan to stop and kill any in-flight nmap process."""
        self.stop_event.set()
        with self._proc_lock:
            if self._current_proc is not None:
                try:
                    self._current_proc.kill()
                except Exception:
                    pass

    def add_topology_edges(self):
        """Build real edges from traceroute hop chains and ARP-confirmed local
        links, instead of inferring a star around a guessed router.

        For every host we got a traceroute for, we wire together the actual
        hop-by-hop path from this machine to that host (adding any
        intermediate routers we hadn't otherwise scanned). Hosts ARP confirmed
        as being on our own L2 segment get a direct link. Only devices with
        neither signal fall back to the old star-around-the-router guess.
        """
        local_node = self.local_ip or "scanner"
        if local_node not in self.G:
            label = f"This PC\n{local_node}"
            title = f"Scanning host\nIP: {local_node}"
            self.G.add_node(local_node, label=label, title=title, group="scanner")
            self.net.add_node(local_node, label=label, title=title,
                              color=self.get_color("scanner"))

        seen_edges = set()
        linked_nodes = {local_node}  # nodes that already have a real edge

        def link(a, b, label, title):
            if not a or not b or a == b:
                return
            key = frozenset((a, b))
            if key in seen_edges:
                return
            seen_edges.add(key)
            self.G.add_edge(a, b, label=label)
            self.net.add_edge(a, b, label=label, title=title)
            linked_nodes.add(a)
            linked_nodes.add(b)

        # 1) Real hop-by-hop paths from traceroute.
        for host, hops in self.traces.items():
            if host not in self.G:
                continue
            chain = [local_node]
            for hop in hops:
                hop_ip = hop["ip"]
                if not hop_ip:
                    continue
                if hop_ip not in self.G:
                    hop_label = hop["host"] or hop_ip
                    label = f"{hop_label}\n{hop_ip}"
                    title = f"IP: {hop_ip}\n(routing hop, not directly scanned)"
                    self.G.add_node(hop_ip, label=label, title=title, group="router")
                    self.net.add_node(hop_ip, label=label, title=title,
                                      color=self.get_color("router"))
                chain.append(hop_ip)
            if chain[-1] != host:
                chain.append(host)
            for a, b in zip(chain, chain[1:]):
                link(a, b, "traceroute", f"Hop toward {host}")
            self.log(f"  \U0001F5FA traced route to {host}: {' -> '.join(chain)}")

        # 2) ARP-confirmed direct neighbors (same L2 segment, no routing hop
        # needed) for hosts traceroute didn't cover.
        for node in list(self.G.nodes):
            if node in linked_nodes:
                continue
            if node in self.local_segment_ips:
                link(local_node, node, "arp-confirmed",
                     "Directly connected (same L2 segment, ARP-confirmed)")

        # 3) Last resort: star topology around the detected/guessed router,
        # only for devices with neither traceroute nor ARP evidence.
        untraced = [n for n in self.G.nodes if n not in linked_nodes]
        if untraced:
            if not self.router_ip and self.gateway_hint and self.gateway_hint in self.G:
                self.router_ip = self.gateway_hint
            if not self.router_ip:
                for node in list(self.G.nodes):
                    if node.endswith('.1'):
                        self.router_ip = node
                        break
            anchor = self.router_ip if (self.router_ip and self.router_ip in self.G) else local_node
            self.log(f"⚠️ No traceroute/ARP evidence for {len(untraced)} device(s); "
                     f"inferring link to {anchor}.")
            for node in untraced:
                link(anchor, node, "inferred",
                     "Inferred connection (no traceroute/ARP data)")

    def get_subnet(self, ip):
        """Label a host by the /24 block it sits in (display only)."""
        try:
            return str(ipaddress.ip_network(f"{ip}/24", strict=False))
        except ValueError:
            return "?"

    def guess_device_type(self, hostname, ip=""):
        h = hostname.lower()
        if any(x in h for x in ['mikrotik', 'router', 'gateway', 'pfsense', 'gw']): return "router"
        if ip and ip.endswith('.1'): return "router"
        if any(x in h for x in ['switch', 'core']): return "switch"
        if any(x in h for x in ['proxmox', 'pve', 'esxi', 'vm', 'server', 'srv']): return "server"
        if any(x in h for x in ['nas', 'omv', 'synology', 'truenas']): return "nas"
        if any(x in h for x in ['wazuh', 'siem']): return "server"
        if any(x in h for x in ['dns', 'technitium', 'pihole']): return "dns"
        if any(x in h for x in ['ap', 'wifi', 'unifi', 'wap']): return "ap"
        if any(x in h for x in ['printer', 'print', 'hp', 'epson']): return "printer"
        if any(x in h for x in ['cam', 'nvr', 'hikvision']): return "camera"
        if any(x in h for x in ['phone', 'iphone', 'android', 'pixel']): return "phone"
        return "workstation"

    def get_color(self, device_type):
        colors = {
            "router": "#e74c3c", "switch": "#3498db", "server": "#2ecc71",
            "nas": "#1abc9c", "dns": "#8e44ad", "ap": "#9b59b6",
            "printer": "#f39c12", "camera": "#e67e22", "phone": "#16a085",
            "workstation": "#95a5a6", "scanner": "#34495e"
        }
        return colors.get(device_type, "#3498db")

    def generate(self, output_file="auto_network_map.html"):
        self.add_topology_edges()
        self.net.from_nx(self.G)
        self.net.write_html(output_file)
        self.log(f"✅ Diagram saved: {output_file}")
        return output_file


# --------------------------------------------------------------------------- #
#  GUI                                                                          #
# --------------------------------------------------------------------------- #
class DiagrammerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Auto Network Diagrammer")
        self.geometry("780x900")
        self.minsize(660, 720)

        self.log_queue = queue.Queue()
        self.progress_queue = queue.Queue()
        self.output_file = None
        self.worker = None
        self.detected_gateway = None
        self.diag = None
        self.stopping = False
        self.history = ScanHistory()
        self.current_scan_id = None

        self._build_ui()
        self.after(100, self._drain_log_queue)
        self._load_config_or_detect()
        self._refresh_history()
        self.name_var.set(self.history.next_name())

    # ---- layout ---------------------------------------------------------- #
    def _build_ui(self):
        pad = {"padx": 10, "pady": 6}

        ttk.Label(self, text="Auto Network Diagrammer",
                  font=("Segoe UI", 16, "bold")).pack(anchor="w", **pad)
        ttk.Label(
            self,
            text="Enter the networks to scan (one per line), or auto-detect yours.",
            foreground="#555").pack(anchor="w", padx=10)

        # Targets
        tgt_frame = ttk.LabelFrame(self, text="Targets  (e.g. 192.168.1.0/24  or  10.0.0.5)")
        tgt_frame.pack(fill="x", **pad)
        self.targets_text = tk.Text(tgt_frame, height=7, wrap="none",
                                    font=("Consolas", 10))
        self.targets_text.pack(fill="x", padx=6, pady=6)

        tgt_btns = ttk.Frame(tgt_frame)
        tgt_btns.pack(fill="x", padx=6, pady=(0, 6))
        ttk.Button(tgt_btns, text="\U0001F50E Detect my network",
                   command=self._detect_network).pack(side="left")
        ttk.Button(tgt_btns, text="Clear targets",
                   command=lambda: self.targets_text.delete("1.0", "end")
                   ).pack(side="left", padx=6)
        self.gw_label = ttk.Label(tgt_btns, text="", foreground="#777")
        self.gw_label.pack(side="left", padx=6)

        # Scan name row
        name_frame = ttk.Frame(self)
        name_frame.pack(fill="x", **pad)
        ttk.Label(name_frame, text="Scan name:").pack(side="left")
        self.name_var = tk.StringVar()
        ttk.Entry(name_frame, textvariable=self.name_var).pack(
            side="left", fill="x", expand=True, padx=6)

        # Output file row
        out_frame = ttk.Frame(self)
        out_frame.pack(fill="x", **pad)
        ttk.Label(out_frame, text="Output file:").pack(side="left")
        self.out_var = tk.StringVar(value=os.path.abspath("auto_network_map.html"))
        ttk.Entry(out_frame, textvariable=self.out_var).pack(
            side="left", fill="x", expand=True, padx=6)
        ttk.Button(out_frame, text="Browse…",
                   command=self._choose_output).pack(side="left")

        # Buttons
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", **pad)
        self.scan_btn = ttk.Button(btn_frame, text="▶  Scan && Generate",
                                   command=self._start_scan)
        self.scan_btn.pack(side="left")
        self.stop_btn = ttk.Button(btn_frame, text="⏹  Stop Scan",
                                   command=self._stop_scan, state="disabled")
        self.stop_btn.pack(side="left", padx=6)
        self.open_btn = ttk.Button(btn_frame, text="Open Diagram",
                                   command=self._open_diagram, state="disabled")
        self.open_btn.pack(side="left", padx=6)
        ttk.Button(btn_frame, text="Clear Log",
                   command=self._clear_log).pack(side="left")

        self.progress = ttk.Progressbar(self, mode="indeterminate")
        self.progress.pack(fill="x", **pad)

        # Previous scans
        hist_frame = ttk.LabelFrame(self, text="Previous scans")
        hist_frame.pack(fill="x", **pad)
        columns = ("name", "created", "targets", "devices", "status")
        self.history_tree = ttk.Treeview(
            hist_frame, columns=columns, show="headings", height=6,
            selectmode="browse")
        for col, label, width in [
            ("name", "Name", 130), ("created", "Created", 140),
            ("targets", "Targets", 220), ("devices", "Devices", 70),
            ("status", "Status", 90),
        ]:
            self.history_tree.heading(col, text=label)
            self.history_tree.column(col, width=width, anchor="w")
        self.history_tree.pack(fill="x", padx=6, pady=(6, 0))

        hist_btns = ttk.Frame(hist_frame)
        hist_btns.pack(fill="x", padx=6, pady=6)
        ttk.Button(hist_btns, text="Open Diagram",
                   command=self._open_history_diagram).pack(side="left")
        ttk.Button(hist_btns, text="Load Targets",
                   command=self._load_history_targets).pack(side="left", padx=6)
        ttk.Button(hist_btns, text="Rename",
                   command=self._rename_history_scan).pack(side="left")
        ttk.Button(hist_btns, text="Delete",
                   command=self._delete_history_scan).pack(side="left", padx=6)
        ttk.Button(hist_btns, text="Refresh",
                   command=self._refresh_history).pack(side="left")

        # Log
        log_frame = ttk.LabelFrame(self, text="Scan log")
        log_frame.pack(fill="both", expand=True, **pad)
        self.log_widget = scrolledtext.ScrolledText(
            log_frame, wrap="word", font=("Consolas", 9), state="disabled")
        self.log_widget.pack(fill="both", expand=True, padx=6, pady=6)

        self.status = tk.StringVar(value="Ready.")
        ttk.Label(self, textvariable=self.status,
                  relief="sunken", anchor="w").pack(fill="x", side="bottom")

    # ---- config persistence --------------------------------------------- #
    def _load_config_or_detect(self):
        """Load last-used targets; if none saved, auto-detect the network."""
        loaded = False
        try:
            if os.path.exists(CONFIG_PATH):
                with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                targets = cfg.get("targets", [])
                if targets:
                    self.targets_text.insert("1.0", "\n".join(targets))
                    loaded = True
                if cfg.get("output"):
                    self.out_var.set(cfg["output"])
        except Exception:
            pass

        if not loaded:
            self._detect_network()

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _save_config(self):
        try:
            targets = [t for t in self.targets_text.get("1.0", "end").splitlines()
                       if t.strip()]
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump({"targets": targets,
                           "output": self.out_var.get()}, f, indent=2)
        except Exception:
            pass

    def _on_close(self):
        self._save_config()
        if self.diag and self.worker and self.worker.is_alive():
            self.diag.stop()
        self.destroy()

    # ---- actions --------------------------------------------------------- #
    def _detect_network(self):
        subnets = detect_local_subnets()
        gw = detect_default_gateway()
        self.detected_gateway = gw
        if subnets:
            self.targets_text.delete("1.0", "end")
            self.targets_text.insert("1.0", "\n".join(subnets))
            self.status.set(f"Detected {len(subnets)} subnet(s).")
        else:
            self.status.set("Could not auto-detect a network — enter one manually.")
        self.gw_label.configure(text=f"Gateway: {gw}" if gw else "")

    def _choose_output(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML file", "*.html"), ("All files", "*.*")],
            initialfile="auto_network_map.html")
        if path:
            self.out_var.set(path)

    def _log(self, msg):
        self.log_queue.put(msg)

    def _progress(self, pct):
        self.progress_queue.put(pct)

    def _clear_log(self):
        self.log_widget.configure(state="normal")
        self.log_widget.delete("1.0", "end")
        self.log_widget.configure(state="disabled")

    def _drain_log_queue(self):
        while not self.log_queue.empty():
            msg = self.log_queue.get_nowait()
            self.log_widget.configure(state="normal")
            self.log_widget.insert("end", msg + "\n")
            self.log_widget.see("end")
            self.log_widget.configure(state="disabled")

        last_pct = None
        while not self.progress_queue.empty():
            last_pct = self.progress_queue.get_nowait()
        if last_pct is not None:
            if self.progress["mode"] != "determinate":
                self.progress.stop()
                self.progress.configure(mode="determinate", maximum=100)
            self.progress["value"] = last_pct

        self.after(100, self._drain_log_queue)

    def _start_scan(self):
        if self.worker and self.worker.is_alive():
            return
        targets = [t for t in self.targets_text.get("1.0", "end").splitlines()
                   if t.strip()]
        if not targets:
            messagebox.showwarning(
                "No targets",
                "Enter at least one network, or click 'Detect my network'.")
            return

        scan_name = self.name_var.get().strip() or self.history.next_name()
        self.name_var.set(scan_name)
        self.current_scan_id = self.history.add(scan_name, targets)

        # Auto-name the output file per scan (scan_1.html, scan_2.html, ...)
        # in whatever directory was last used, so every run gets its own file.
        out_dir = (os.path.dirname(self.out_var.get().strip())
                   or os.path.dirname(os.path.abspath(__file__)))
        out = os.path.join(out_dir, f"scan_{self.current_scan_id}.html")
        self.out_var.set(out)
        self._save_config()
        self._refresh_history()

        self.scan_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.open_btn.configure(state="disabled")
        self.progress.configure(mode="indeterminate")
        self.progress.start(12)
        self.status.set("Scanning…")
        self.stopping = False
        self._log(f"--- Run started {datetime.now():%Y-%m-%d %H:%M:%S} ---")

        self.worker = threading.Thread(
            target=self._run_scan, args=(targets, out), daemon=True)
        self.worker.start()

    def _stop_scan(self):
        if self.diag and self.worker and self.worker.is_alive():
            self.stopping = True
            self.stop_btn.configure(state="disabled")
            self.status.set("Stopping…")
            self.diag.stop()

    def _run_scan(self, targets, out):
        try:
            self.diag = AutoNetworkDiagrammer(log=self._log,
                                              gateway_hint=self.detected_gateway,
                                              progress=self._progress)
            self.diag.scan_network(targets)
            path = self.diag.generate(out)
            self.output_file = os.path.abspath(path)
            self.after(0, self._scan_done, True, None)
        except Exception as e:
            self.after(0, self._scan_done, False, str(e))

    def _scan_done(self, ok, err):
        self.progress.stop()
        self.progress.configure(mode="indeterminate")
        self.progress["value"] = 0
        self.scan_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        was_stopped = self.stopping
        self.stopping = False
        device_count = self.diag.device_count if self.diag else 0

        if ok:
            if was_stopped:
                self.status.set(f"Stopped. Partial diagram saved to {self.output_file}")
                self._log("⏹ Stopped early — partial diagram saved.\n")
                status = "stopped"
            else:
                self.status.set(f"Done. Saved to {self.output_file}")
                self._log("✔ Finished.\n")
                status = "completed"
            self.open_btn.configure(state="normal")
        else:
            self.status.set("Error — see log.")
            self._log(f"❌ {err}\n")
            status = "error"

        if self.current_scan_id is not None:
            finished_id = self.current_scan_id
            self.history.finish(finished_id, status, device_count,
                                self.output_file if ok else None)
            self.current_scan_id = None
            self._refresh_history()
            # Auto-highlight the scan that just completed.
            if self.history_tree.exists(str(finished_id)):
                self.history_tree.selection_set(str(finished_id))
                self.history_tree.focus(str(finished_id))
                self.history_tree.see(str(finished_id))
        self.name_var.set(self.history.next_name())

        if not ok:
            messagebox.showerror("Scan failed", err)

    def _open_diagram(self):
        if self.output_file and os.path.exists(self.output_file):
            webbrowser.open(f"file://{self.output_file}")
        else:
            messagebox.showinfo("Not found", "Generate a diagram first.")

    # ---- scan history (SQLite) ------------------------------------------- #
    def _refresh_history(self):
        self.history_tree.delete(*self.history_tree.get_children())
        for scan_id, name, created, targets, _out, device_count, status in self.history.all():
            lines = targets.splitlines()
            targets_display = ", ".join(lines[:2]) + (" …" if len(lines) > 2 else "")
            self.history_tree.insert(
                "", "end", iid=str(scan_id),
                values=(name, created, targets_display, device_count, status))

    def _selected_history_id(self):
        sel = self.history_tree.selection()
        return int(sel[0]) if sel else None

    def _open_history_diagram(self):
        scan_id = self._selected_history_id()
        if scan_id is None:
            messagebox.showinfo("No selection", "Select a scan from the list first.")
            return
        row = self.history.get(scan_id)
        output_file = row[4] if row else None
        if output_file and os.path.exists(output_file):
            webbrowser.open(f"file://{output_file}")
        else:
            messagebox.showinfo("Not found", "That scan's diagram file no longer exists.")

    def _load_history_targets(self):
        scan_id = self._selected_history_id()
        if scan_id is None:
            messagebox.showinfo("No selection", "Select a scan from the list first.")
            return
        row = self.history.get(scan_id)
        if row:
            self.targets_text.delete("1.0", "end")
            self.targets_text.insert("1.0", row[3])

    def _rename_history_scan(self):
        scan_id = self._selected_history_id()
        if scan_id is None:
            messagebox.showinfo("No selection", "Select a scan from the list first.")
            return
        row = self.history.get(scan_id)
        new_name = simpledialog.askstring(
            "Rename scan", "New name:", initialvalue=row[1], parent=self)
        if new_name and new_name.strip():
            self.history.rename(scan_id, new_name.strip())
            self._refresh_history()

    def _delete_history_scan(self):
        scan_id = self._selected_history_id()
        if scan_id is None:
            messagebox.showinfo("No selection", "Select a scan from the list first.")
            return
        if messagebox.askyesno(
                "Delete scan",
                "Remove this scan from history?\n"
                "(This only removes the history entry — the diagram file itself is kept.)"):
            self.history.delete(scan_id)
            self._refresh_history()


if __name__ == "__main__":
    DiagrammerApp().mainloop()
