# Auto Network Diagrammer

A clickable desktop app that scans one or more IP networks with **nmap**, maps real edge topology from **traceroute** hops and **ARP** cache data, and renders an interactive HTML map using **pyvis**. No networks are hardcoded — it auto-detects the subnet your machine is on, and you can add or edit targets freely.

![status](https://img.shields.io/badge/status-working-brightgreen)
![python](https://img.shields.io/badge/python-3.9%2B-blue)
![license](https://img.shields.io/badge/license-GPLv3-blue)

## Download (no install / Windows)

Don't want to set up Python? Grab the ready-to-run executable straight from the repo:

**[⬇ Download NetworkDiagrammer.exe](dist/NetworkDiagrammer.exe)** — then click the **Download** button on that page.

1. Install **Nmap** (a separate program the app relies on): https://nmap.org/download.html
2. Run **NetworkDiagrammer.exe**. For MAC address / vendor detection, right-click and **Run as administrator** (nmap host discovery needs raw-socket access).
3. Auto-detect or enter the networks to scan, click **Scan & Generate**, then **Open Diagram**.

The exe is unsigned and self-built, so Windows SmartScreen may warn about an unknown publisher — click **More info → Run anyway**. Prefer to build it yourself? See [BUILD.md](BUILD.md).

## Features

- **Auto-detects your network** on launch — nothing to configure to get started.
- **Editable targets** — scan any subnet (`192.168.1.0/24`) or single host (`10.0.0.5`), one per line.
- **Deeper host discovery** — combines ARP, ICMP echo/timestamp, and TCP SYN/ACK probes so devices that drop plain ICMP still get found, with reverse-DNS + a bounded socket-resolver fallback for accurate IP/hostname pairs.
- **Uses your real DNS resolvers** — reverse-DNS lookups are pinned to the DNS servers your OS is actually configured with (plus your gateway) instead of trusting nmap's own resolver auto-detection, which is known to be unreliable on Windows.
- **Filters out phantom hosts** — some routers/firewalls answer discovery probes for IPs nothing is actually using; an address only becomes a node if it has a real hostname or an ARP-confirmed unicast MAC, and the subnet's network/broadcast addresses are always excluded.
- **Real edge topology** — traces the actual hop-by-hop path to every device (`nmap --traceroute`) and cross-references the OS ARP cache to confirm which devices sit on your local L2 segment, instead of just guessing a star around the router. A star-around-the-router guess is only used as a last resort for devices with no traceroute/ARP evidence.
- **Live progress meter and per-device timer** in the scan log — a running `[mm:ss]` elapsed stamp on every device found, plus a real percent-complete/ETA readout parsed straight from nmap's own progress stream.
- **Runs in the background** so the window stays responsive, with no nmap console window flashing on top of it.
- **Each scan gets its own output file** — `scan_1.html`, `scan_2.html`, and so on, so past diagrams are never overwritten by the next run.
- **Auto-highlights the just-finished scan** in the Previous Scans list.
- **Dark mode** — toggle with the 🌙 button in the top-right; themes both the app window and the generated diagram, and is remembered between runs.
- **Device-type coloring** for routers, switches, servers, NAS, DNS, APs, printers, cameras, phones, and workstations.
- **Remembers your last targets** between runs.
- **Interactive output** — pan/zoom/drag the generated HTML map.

## Requirements

- **Python 3.9+**
- **Nmap** installed and on your PATH — https://nmap.org/download.html
- Python packages: `python-nmap`, `networkx`, `pyvis`

```bash
pip install -r requirements.txt
```

> For MAC address / vendor detection, run the app with administrator/root privileges — nmap host discovery needs raw-socket access.

## Run from source

```bash
python network_diagrammer_gui.py
```

Enter (or auto-detect) the networks to scan, click Scan & Generate, then Open Diagram.

## How it works

- Host discovery across each target range using ARP ping, ICMP echo/timestamp, and TCP SYN/ACK probes (`nmap -sn -PR -PE -PP -PS... -PA... -R`), with a Python `socket.gethostbyaddr` fallback for any host nmap can't name. (`-R` uses nmap's own fast async resolver rather than `--system-dns`, which is dramatically slower on hosts with no PTR record.)
- Before each scan, the app reads your OS's actual configured DNS servers (`ipconfig /all` on Windows, `/etc/resolv.conf` on POSIX, falling back to `nslookup`'s reported default) and your gateway, then passes them to nmap via `--dns-servers` so reverse lookups hit your real resolvers — handy if you run multiple local DNS servers and want the authoritative one(s) queried instead of whatever nmap picks on its own.
- `--traceroute` is enabled on every scan; since the `python-nmap` wrapper discards `<trace>` data, the raw nmap XML is parsed directly to recover the real hop-by-hop path to each host.
- The OS ARP cache (`arp -a` / `ip neigh`) is read after each scan pass to fill in MACs nmap can't reach without raw-socket privileges, and to confirm which hosts are directly on your local L2 segment.
- Each host becomes a node, typed and colored by hostname/IP heuristics.
- Edges are built in priority order: real traceroute hop chains first (adding intermediate routers you didn't scan directly), then ARP-confirmed direct links, and only as a last resort — for devices with neither signal — an inferred link to the detected/guessed router.
- pyvis writes a self-contained interactive HTML map.

> Traceroute and ARP-based host discovery need raw-socket access — run the app as Administrator (Windows) / root (Linux/macOS) for the fullest, most accurate topology. Without elevated privileges, nmap falls back to what it can do unprivileged and more devices will land on the inferred-star fallback.

## License

Licensed under the GNU General Public License v3.0 — see LICENSE.
