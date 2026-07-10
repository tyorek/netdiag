# Changelog

All notable changes to this project are documented here. Versions follow [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`). The running version lives in `APP_VERSION` in `network_diagrammer_gui.py` and is shown in the app's window title.

## [Unreleased]

## [1.0.0] - 2026-07-09

First formally versioned release, covering the app's full accumulated feature set to date.

### Added
- Device-type icons (router, switch, server, NAS, DNS, AP, printer, camera, phone, workstation, scan host) drawn on each node in place of plain colored dots, plus an auto-generated legend — listing only the types present — on every diagram.
- Dark mode for both the app window and the generated diagram.
- Real edge topology built from traceroute hop chains and ARP-confirmed local links, instead of a router-star guess.
- Reverse-DNS lookups pinned to the machine's actual configured DNS resolvers (plus gateway) instead of relying on nmap's own resolver auto-detection.
- Phantom-host filtering — an address only becomes a node if it has a real hostname or an ARP-confirmed unicast MAC.
- Live scan progress meter with a per-device elapsed timer, parsed straight from nmap's own progress stream.
- Per-scan output files (`scan_1.html`, `scan_2.html`, ...) plus a SQLite-backed scan history with rename/delete/reopen.
- Stop-scan button that kills the in-flight nmap process immediately.
- Real subnet mask auto-detection from the OS (no more assuming /24).
