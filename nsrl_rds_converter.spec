# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for NSRL RDS2TXT Converter.

Single-file, windowed exe with the Omega/RDS2TXT icon and logo files.
"""

from pathlib import Path

block_cipher = None
HERE = Path(SPECPATH).resolve()

datas = []
for name in ("rds2txt.ico", "Omega_header.png", "Omega_ui.png", "Omega.png"):
    path = HERE / name
    if path.is_file():
        datas.append((str(path), "."))

a = Analysis(
    [str(HERE / "nsrl_rds_converter.py")],
    pathex=[str(HERE)],
    binaries=[],
    datas=datas,
    hiddenimports=["tkinter", "tkinter.ttk", "tkinter.filedialog", "tkinter.messagebox"],
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
    name="RDS2TXT",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(HERE / "rds2txt.ico") if (HERE / "rds2txt.ico").is_file() else None,
)
