#!/usr/bin/env python3
"""Build a standalone RDS2TXT executable with PyInstaller.

Same idea as the Synchronoss Toolbox builder: run this script and it
produces the exe.

    python build_exe.py

Output:
    dist/RDS2TXT.exe
    RDS2TXT.exe   (copy next to this script)
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = HERE / "nsrl_rds_converter.spec"
SCRIPT = HERE / "nsrl_rds_converter.py"
ICON = HERE / "rds2txt.ico"
EXE_NAME = "RDS2TXT"


def ensure_pyinstaller() -> None:
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("PyInstaller not found. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])


def build() -> Path:
    if not SCRIPT.is_file():
        raise FileNotFoundError(f"Missing {SCRIPT.name}")
    ensure_pyinstaller()

    cmd = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean"]
    if SPEC.is_file():
        cmd.append(str(SPEC))
    else:
        cmd.extend(
            [
                "--onefile",
                "--windowed",
                "--name",
                EXE_NAME,
                str(SCRIPT),
            ]
        )
        if ICON.is_file():
            cmd.extend(["--icon", str(ICON)])
        for name in ("rds2txt.ico", "Omega_header.png", "Omega_ui.png"):
            asset = HERE / name
            if asset.is_file():
                cmd.extend(["--add-data", f"{asset}{sep_for_add_data()}."])
    print("Running:", " ".join(cmd))
    subprocess.check_call(cmd, cwd=str(HERE))

    built = HERE / "dist" / (EXE_NAME + (".exe" if sys.platform == "win32" else ""))
    if not built.is_file():
        # PyInstaller may have used the spec name on some versions
        candidates = sorted((HERE / "dist").glob("RDS2TXT*"))
        if not candidates:
            raise FileNotFoundError("PyInstaller finished but no exe was found in dist/")
        built = candidates[0]
    dest = HERE / built.name
    shutil.copy2(built, dest)
    return dest


def sep_for_add_data() -> str:
    return ";" if sys.platform == "win32" else ":"


def main() -> int:
    print(f"Building {EXE_NAME} from {SCRIPT.name}")
    dest = build()
    print()
    print("Build complete.")
    print(f"  {dest}")
    print(f"  {HERE / 'dist' / dest.name}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as exc:
        print(f"Build failed with exit code {exc.returncode}", file=sys.stderr)
        raise SystemExit(exc.returncode)
