# Auto Network Diagrammer

A clickable desktop app that scans one or more IP networks with **nmap**,
infers a star topology around the detected router/gateway, and renders an
interactive HTML map using **pyvis**. No networks are hardcoded — it
auto-detects the subnet your machine is on, and you can add or edit targets
freely.

![status](https://img.shields.io/badge/status-working-brightgreen)
![python](https://img.shields.io/badge/python-3.9%2B-blue)
![license](https://img.shields.io/badge/license-GPLv3-blue)

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

> For MAC address / vendor detection, run the app with administrator/root
> privileges — nmap host discovery needs raw-socket access.

## Run from source

```bash
python network_diagrammer_gui.py
```

Enter (or auto-detect) the networks to scan, click **Scan & Generate**, then
**Open Diagram**.

## Build a standalone Windows .exe

A prebuilt `dist/NetworkDiagrammer.exe` is included. To rebuild it yourself:

1. Put `network_diagrammer_gui.py`, `network_diagrammer_gui.spec`, and
   `build_exe.bat` in the same folder.
2. Double-click **`build_exe.bat`** (it installs deps and runs PyInstaller).
3. The result appears at `dist\NetworkDiagrammer.exe`.

See [BUILD.md](BUILD.md) for details and troubleshooting.

> The exe still needs **Nmap** installed on any machine that runs it.

## How it works

1. `nmap -sn -R` host discovery across each target range.
2. Each host becomes a node, typed and colored by hostname/IP heuristics.
3. A router is chosen by name, then detected gateway, then a `.1` fallback.
4. All other devices are linked to it (an inferred star topology).
5. pyvis writes a self-contained interactive HTML map.

Edges are **inferred**, not traced from switch/ARP tables — this is a quick
visual approximation, not an authoritative Layer-2 map.

## License

Licensed under the **GNU General Public License v3.0** — see [LICENSE](LICENSE).
