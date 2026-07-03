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
import json
import socket
import ipaddress
import subprocess
import queue
import threading
import webbrowser
from datetime import datetime

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

import nmap
import networkx as nx
from pyvis.network import Network


# Where we remember the user's last-used settings (next to the exe/script).
CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "diagrammer_config.json")


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
            out = subprocess.check_output(["ipconfig"], text=True, errors="ignore")
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
                    text=True, errors="ignore")
                for line in out.splitlines():
                    toks = line.split()
                    if "inet" in toks:
                        cidr = toks[toks.index("inet") + 1]  # 192.168.5.10/28
                        ip, _, prefix = cidr.partition("/")
                        if prefix:
                            pairs.append((ip, int(prefix)))
            except Exception:
                # macOS / BSD: "inet 192.168.5.10 netmask 0xfffffff0"
                out = subprocess.check_output(["ifconfig"], text=True, errors="ignore")
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
                ["ipconfig"], text=True, errors="ignore")
            for line in out.splitlines():
                if "Default Gateway" in line and ":" in line:
                    ip = line.split(":")[-1].strip()
                    if ip and ip.count(".") == 3:
                        return ip
        else:
            out = subprocess.check_output(
                ["ip", "route"], text=True, errors="ignore")
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
    def __init__(self, log=print, gateway_hint=None):
        self.log = log
        self.gateway_hint = gateway_hint      # optional detected gateway IP
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

    def scan_network(self, targets):
        self.log("\U0001F50D Scanning...")
        for target in targets:
            target = target.strip()
            if not target:
                continue
            self.log(f"  → {target}")
            try:
                self.scanner.scan(hosts=target, arguments='-sn -R')
                for host in self.scanner.all_hosts():
                    hostname = self.scanner[host].hostname() or f"host-{host.split('.')[-1]}"
                    mac = self.scanner[host]['addresses'].get('mac', 'Unknown')
                    device_type = self.guess_device_type(hostname, host)

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
                    self.log(f"     ✓ {hostname} ({host})")
            except Exception as e:
                self.log(f"     ⚠️ Error on {target}: {e}")
        self.log(f"Found {self.device_count} device(s).")

    def add_inferred_edges(self):
        # Router priority: name-detected -> detected gateway -> a ".1" host.
        if not self.router_ip and self.gateway_hint and self.gateway_hint in self.G:
            self.router_ip = self.gateway_hint
            self.log(f"Using detected gateway as router: {self.router_ip}")

        if not self.router_ip:
            self.log("⚠️ No router detected by name/gateway. Using fallback (.1 host).")
            for node in list(self.G.nodes):
                if node.endswith('.1'):
                    self.router_ip = node
                    break

        if self.router_ip and self.router_ip in self.G:
            self.log(f"\U0001F517 Connecting devices to router: {self.router_ip}")
            for node in list(self.G.nodes):
                if node != self.router_ip:
                    self.G.add_edge(self.router_ip, node, label="inferred")
                    self.net.add_edge(self.router_ip, node,
                                      title="Inferred connection", label="→")
        else:
            self.log("⚠️ Could not find a central router for edge inference.")

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
            "workstation": "#95a5a6"
        }
        return colors.get(device_type, "#3498db")

    def generate(self, output_file="auto_network_map.html"):
        self.add_inferred_edges()
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
        self.geometry("780x660")
        self.minsize(660, 560)

        self.log_queue = queue.Queue()
        self.output_file = None
        self.worker = None
        self.detected_gateway = None

        self._build_ui()
        self.after(100, self._drain_log_queue)
        self._load_config_or_detect()

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
        self.open_btn = ttk.Button(btn_frame, text="Open Diagram",
                                   command=self._open_diagram, state="disabled")
        self.open_btn.pack(side="left", padx=6)
        ttk.Button(btn_frame, text="Clear Log",
                   command=self._clear_log).pack(side="left")

        self.progress = ttk.Progressbar(self, mode="indeterminate")
        self.progress.pack(fill="x", **pad)

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

        self._save_config()
        out = self.out_var.get().strip() or "auto_network_map.html"
        self.scan_btn.configure(state="disabled")
        self.open_btn.configure(state="disabled")
        self.progress.start(12)
        self.status.set("Scanning…")
        self._log(f"--- Run started {datetime.now():%Y-%m-%d %H:%M:%S} ---")

        self.worker = threading.Thread(
            target=self._run_scan, args=(targets, out), daemon=True)
        self.worker.start()

    def _run_scan(self, targets, out):
        try:
            diag = AutoNetworkDiagrammer(log=self._log,
                                         gateway_hint=self.detected_gateway)
            diag.scan_network(targets)
            path = diag.generate(out)
            self.output_file = os.path.abspath(path)
            self.after(0, self._scan_done, True, None)
        except Exception as e:
            self.after(0, self._scan_done, False, str(e))

    def _scan_done(self, ok, err):
        self.progress.stop()
        self.scan_btn.configure(state="normal")
        if ok:
            self.status.set(f"Done. Saved to {self.output_file}")
            self.open_btn.configure(state="normal")
            self._log("✔ Finished.\n")
        else:
            self.status.set("Error — see log.")
            self._log(f"❌ {err}\n")
            messagebox.showerror("Scan failed", err)

    def _open_diagram(self):
        if self.output_file and os.path.exists(self.output_file):
            webbrowser.open(f"file://{self.output_file}")
        else:
            messagebox.showinfo("Not found", "Generate a diagram first.")


if __name__ == "__main__":
    DiagrammerApp().mainloop()
