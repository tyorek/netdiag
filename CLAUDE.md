# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A single-file Tkinter desktop app (`network_diagrammer_gui.py`) that scans local networks with `nmap`, builds a topology graph from traceroute hops + ARP cache data, and renders it as an interactive HTML map with `pyvis`/`networkx`. Ships as a standalone Windows exe via PyInstaller. There is no test suite, linter, or CI config in this repo — verification is manual (run the app, run a scan, inspect the log/output HTML).

## Commands

```bash
pip install -r requirements.txt   # python-nmap, networkx, pyvis
python network_diagrammer_gui.py  # run from source (needs nmap on PATH)
```

Nmap itself (the external binary, not the pip package) must be installed separately and on PATH: https://nmap.org/download.html. For MAC/vendor detection and full traceroute/ARP topology, run as Administrator/root — host discovery needs raw-socket access; without it nmap degrades gracefully and more devices land on the inferred-star fallback.

Building the Windows exe:
```bat
py -m pip install pyinstaller python-nmap networkx pyvis
py -m PyInstaller --clean --noconfirm network_diagrammer_gui.spec
```
or just double-click `build_exe.bat`. Build from a shallow, non-virtualized folder path (e.g. Desktop) — PyInstaller can fail to create `build\` inside deep/virtualized app-storage paths. See BUILD.md for details on why the spec explicitly bundles pyvis's Jinja2 templates/assets (PyInstaller misses them by default, causing a blank diagram).

## Architecture

The file has three parts, in order:

1. **Network auto-detection helpers** (module-level functions): `detect_local_subnets()`, `detect_default_gateway()`, `detect_dns_servers()`. These shell out to OS tools (`ipconfig`/`ip`/`ifconfig`, `arp`/`ip neigh`, `nslookup`) rather than using a cross-platform library, because the app deliberately reads the *real* subnet mask and the *real* configured DNS resolvers from the OS instead of guessing /24 or trusting nmap's own (unreliable-on-Windows) resolver detection. `_NO_WINDOW` suppresses console-window flashing for these subprocess calls when running as a windowed PyInstaller build.

2. **`AutoNetworkDiagrammer`** (core scan/graph logic, decoupled from the GUI via `log`/`progress` callbacks so it's usable headlessly):
   - `scan_network()` runs nmap per target via `_run_nmap()`, which shells out to the nmap binary directly (not through `python-nmap`'s own `.scan()`) so it can (a) keep a killable `Popen` handle for instant Stop, and (b) stream stdout live to parse `<taskprogress>` tags into a real percent/ETA meter.
   - `_parse_traceroute_xml()` re-parses the raw nmap XML because `python-nmap`'s `analyse_nmap_xml_scan()` silently discards `<trace>` data — this is the only way to recover real hop-by-hop paths.
   - Host filtering: an address only becomes a node if it has a real hostname or an ARP-confirmed unicast MAC (`_is_real_unicast_mac`) — this excludes phantom hosts that some routers answer discovery probes for on behalf of nobody, plus the CIDR's network/broadcast addresses (`_network_broadcast_ips`).
   - `add_topology_edges()` builds edges in priority order: real traceroute hop chains first (adding intermediate routers not directly scanned), then ARP-confirmed direct L2 links, and only as a last resort an inferred star edge to the detected/guessed router for devices with neither signal. This replaced an earlier pure-star-topology approach — don't regress to it.
   - Device type/color inference (`guess_device_type`, `get_color`) is a flat hostname/IP substring heuristic — extend the existing keyword lists rather than restructuring.

3. **`DiagrammerApp`** (Tkinter GUI): worker thread runs the scan (`_run_scan`), communicates back to the main thread via `queue.Queue` (`log_queue`, `progress_queue`) drained on a 100ms `after()` tick — never touch Tk widgets directly from the worker thread. `ScanHistory` (SQLite, `scan_history.db`) tracks every past run (name, targets, output file, device count, status); each scan gets its own `scan_N.html` output file rather than overwriting the last one. `diagrammer_config.json` persists last-used targets/output/dark-mode between runs. Light/dark theme colors live in the module-level `THEMES` dict and are applied to both the ttk widgets (`_apply_theme`) and the generated diagram HTML (`AutoNetworkDiagrammer._darken_page_chrome`, which injects a CSS override since pyvis's `bgcolor` only themes the graph canvas, not the surrounding Bootstrap page chrome).

Both `diagrammer_config.json` and `scan_history.db` are gitignored runtime state, not fixtures — don't commit changes to them.
