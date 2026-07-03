# Building NetworkDiagrammer.exe

A standalone Windows executable of the Auto Network Diagrammer GUI.

## Quick start (one click)

1. Put these three files in the **same folder**:
   - `network_diagrammer_gui.py`
   - `network_diagrammer_gui.spec`
   - `build_exe.bat`
2. Double-click **`build_exe.bat`** (right-click -> *Run as administrator* is fine too).
3. When it finishes, your program is at **`dist\NetworkDiagrammer.exe`**.

The batch file auto-detects Python (tries the `py` launcher, then `python`),
installs the needed packages (PyInstaller, python-nmap, networkx, pyvis), and
runs the build.

## Requirements to BUILD

- Windows
- Python 3.9+ (install with *"Add python.exe to PATH"* checked):
  https://www.python.org/downloads/

## Requirements to RUN the .exe

The exe bundles all the Python parts, but **nmap itself is a separate program**
and must be installed on any machine that runs the diagrammer:

- Install Nmap: https://nmap.org/download.html
- For MAC address / vendor detection, run `NetworkDiagrammer.exe`
  **as Administrator** (host discovery needs raw-socket privileges).

## Manual build (command line)

```bat
py -m pip install pyinstaller python-nmap networkx pyvis
py -m PyInstaller --clean --noconfirm network_diagrammer_gui.spec
```

## Notes

- Build from a normal folder path (e.g. your Desktop). Building inside deep,
  virtualized app-storage paths can make PyInstaller fail to create its
  `build\` directory.
- The spec explicitly bundles pyvis's Jinja2 templates and JS/CSS assets —
  PyInstaller misses these by default, which otherwise yields a blank diagram.
- To brand it, drop an `icon.ico` next to the spec and uncomment the
  `icon='icon.ico'` line inside `network_diagrammer_gui.spec`.
- If Windows SmartScreen warns about an unknown publisher, that's expected for
  unsigned self-built exes: click *More info -> Run anyway*.
