@echo off
REM ===================================================================
REM  Build a standalone Windows .exe for network_diagrammer_gui.py
REM  Just double-click this file (or right-click > Run as administrator).
REM ===================================================================
setlocal

echo.
echo ==== Auto Network Diagrammer - EXE builder ====
echo.

REM 1) Find a working Python. Prefer the "py" launcher, fall back to "python".
set "PY="
py -3 --version >nul 2>&1
if not errorlevel 1 set "PY=py -3"

if not defined PY (
    python --version >nul 2>&1
    if not errorlevel 1 set "PY=python"
)

if not defined PY (
    echo [ERROR] No Python found ^(tried "py -3" and "python"^).
    echo         Install Python 3.9+ from https://www.python.org/downloads/
    echo         and tick "Add python.exe to PATH" during setup.
    pause
    exit /b 1
)

echo Using Python launcher: %PY%
%PY% --version

REM 2) Install/upgrade the build + runtime dependencies
echo.
echo Installing dependencies...
%PY% -m pip install --upgrade pip
%PY% -m pip install --upgrade pyinstaller python-nmap networkx pyvis
if errorlevel 1 (
    echo [ERROR] Dependency install failed.
    pause
    exit /b 1
)

REM 3) Build using the spec file (bundles pyvis templates automatically)
echo.
echo Building the executable...
%PY% -m PyInstaller --clean --noconfirm network_diagrammer_gui.spec
if errorlevel 1 (
    echo [ERROR] Build failed. See messages above.
    pause
    exit /b 1
)

echo.
echo ==== DONE ====
echo Your program is here:  dist\NetworkDiagrammer.exe
echo.
echo NOTE: nmap must also be installed on the machine that RUNS the exe.
echo       Get it from https://nmap.org/download.html and, for MAC/vendor
echo       detection, run the exe as Administrator.
echo.
pause
