# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for network_diagrammer_gui.py

Builds a single-file windowed .exe named NetworkDiagrammer.exe.
The tricky part is pyvis: it ships Jinja2 HTML templates and static
JS/CSS assets that PyInstaller does not pick up automatically. We
collect them explicitly below so the generated diagram renders.

Build:  pyinstaller --clean --noconfirm network_diagrammer_gui.spec
"""

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

# Bundle pyvis (templates + static assets) and jinja2 fully.
datas = collect_data_files('pyvis') + collect_data_files('jinja2')
hiddenimports = (
    collect_submodules('pyvis')
    + collect_submodules('jinja2')
    + ['nmap', 'networkx']
)

a = Analysis(
    ['network_diagrammer_gui.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='NetworkDiagrammer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,          # windowed app, no console box
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # icon='icon.ico',      # uncomment and supply an .ico to brand it
)
