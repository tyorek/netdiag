# Auto Network Diagrammer

A clickable desktop app that scans one or more IP networks with **nmap**, infers a star topology around the detected router/gateway, and renders an interactive HTML map using **pyvis**. No networks are hardcoded — it auto-detects the subnet your machine is on, and you can add or edit targets freely.

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
- **Runs in the background** so the window stays responsive, with a live scan log.
- **Infers topology** by connecting devices to the detected router/gateway.
- **Device-type coloring** for routers, switches, servers, NAS, DNS, APs, printers, cameras, phones, and workstations.
- **Remembers your last targets** between runs.
- **Interactive output** — pan/zoom/drag the generated `auto_network_map.html`.

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

- `nmap -sn -R` host discovery across each target range.
- Each host becomes a node, typed and colored by hostname/IP heuristics.
- A router is chosen by name, then detected gateway, then a `.1` fallback.
- All other devices are linked to it (an inferred star topology).
- pyvis writes a self-contained interactive HTML map.

Edges are inferred, not traced from switch/ARP tables — this is a quick visual approximation, not an authoritative Layer-2 map.

## License

Licensed under the GNU General Public License v3.0 — see LICENSE.
