#!/usr/bin/env python3
"""NSRL RDS v3 to RDS 2.xx text-file converter.

Converts NIST NSRL Reference Data Set v3 SQLite databases (.db) into the
legacy RDS 2.xx text files that forensic tools still ingest. Output names
keep the source database filename:

    RDS_2026.06.1_modern_minimal_NSRLFile.txt
    RDS_2026.06.1_modern_minimal_NSRLMfg.txt
    RDS_2026.06.1_modern_minimal_NSRLOS.txt
    RDS_2026.06.1_modern_minimal_NSRLProd.txt

Those files are quoted CSV with a .txt extension — the official RDS 2.xx
layout documented in RDSv3_to_RDSv2_text_files_WINDOWS.pdf. A second tab
exports a simple one-hash-per-line list (often easier to load into tools
that only want MD5 / SHA-1 / SHA-256).

GUI layout follows the Synchronoss Toolbox (ttk notebook, label + entry +
Browse rows, Run button, indeterminate/determinate progress bar, status
line, work done on a background thread).

Usage:
    python nsrl_rds_converter.py
    python nsrl_rds_converter.py --db path/to/RDS.db --out path/to/folder
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import shutil
import sqlite3
import sys
import threading
import time
import zipfile
from pathlib import Path
from typing import Callable, Iterable, Optional


APP_TITLE = "NSRL RDS Converter"
APP_VERSION = "1.0.0"


def application_directory() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def find_resource(*names: str) -> Optional[Path]:
    here = application_directory()
    folders = [
        here,
        here / "assets",
        Path(getattr(sys, "_MEIPASS", here)),
        here.parent / "Reference Files",
    ]
    seen: set[str] = set()
    for folder in folders:
        for name in names:
            candidate = Path(folder) / name
            key = str(candidate)
            if key in seen:
                continue
            seen.add(key)
            if candidate.is_file():
                return candidate
    return None

# Official RDS 2.xx headers (NIST).
NSRLFILE_HEADER = [
    "SHA-1",
    "MD5",
    "CRC32",
    "FileName",
    "FileSize",
    "ProductCode",
    "OpSystemCode",
    "SpecialCode",
]
NSRLMFG_HEADER = ["MfgCode", "MfgName"]
NSRLOS_HEADER = ["OpSystemCode", "OpSystemName", "OpSystemVersion", "MfgCode"]
NSRLPROD_HEADER = [
    "ProductCode",
    "ProductName",
    "ProductVersion",
    "OpSystemCode",
    "MfgCode",
    "Language",
    "ApplicationType",
]

ProgressCb = Callable[[str, Optional[int], Optional[int]], None]


class ConversionCancelled(Exception):
    """Raised when the user stops a running conversion."""


def format_hms(seconds: Optional[float]) -> str:
    if seconds is None or seconds < 0 or seconds != seconds or seconds == float("inf"):
        return "--:--"
    total = int(round(seconds))
    hours, rem = divmod(total, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}h {minutes:02d}m {secs:02d}s"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


class EtaTracker:
    """Elapsed time and remaining-time estimate for a running job."""

    def __init__(self) -> None:
        self.start = time.monotonic()
        self._last_ui = 0.0

    def reset(self) -> None:
        self.start = time.monotonic()
        self._last_ui = 0.0

    def snapshot(self, done: Optional[int], total: Optional[int]) -> dict:
        elapsed = max(0.001, time.monotonic() - self.start)
        rate = None
        pct = None
        eta = None
        if done and done > 0 and elapsed >= 0.2:
            rate = done / elapsed
        if total and total > 0 and done is not None:
            if done < total:
                pct = min(99.0, max(0.0, (done / total) * 100.0))
                if rate and rate > 0:
                    eta = (total - done) / rate
            else:
                # Estimate was low; keep the bar just under done until the step ends.
                pct = 99.0
                eta = max(5.0, elapsed * 0.08) if rate else 5.0
        return {"elapsed": elapsed, "rate": rate, "pct": pct, "eta": eta}

    def should_paint(self, interval: float = 0.25) -> bool:
        now = time.monotonic()
        if now - self._last_ui >= interval:
            self._last_ui = now
            return True
        return False


def format_progress_line(
    label: str,
    done: Optional[int],
    total: Optional[int],
    snap: dict,
) -> str:
    bits = [label]
    if done is not None and total:
        bits.append(f"{done:,} / ~{total:,}")
    elif done is not None:
        bits.append(f"{done:,} rows")
    if snap.get("pct") is not None:
        bits.append(f"{snap['pct']:.1f}%")
    bits.append(f"elapsed {format_hms(snap.get('elapsed'))}")
    if snap.get("eta") is not None:
        bits.append(f"ETA {format_hms(snap['eta'])}")
    elif done:
        bits.append("ETA calculating…")
    return "  |  ".join(bits)


# ---------------------------------------------------------------------------
# SQLite helpers
# ---------------------------------------------------------------------------


def is_sqlite_file(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return fh.read(16) == b"SQLite format 3\x00"
    except OSError:
        return False


def format_bytes(n: int) -> str:
    value = float(n)
    for unit in ("bytes", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            if unit == "bytes":
                return f"{int(value):,} bytes"
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{n:,} bytes"


def list_zip_databases(zip_path: Path) -> list[dict]:
    """Find NSRL .db members in a NIST zip (usually folder/RDS_….db)."""
    found: list[dict] = []
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = Path(info.filename.replace("\\", "/")).name
            lower = name.lower()
            if not lower.endswith(".db"):
                continue
            if "schema" in lower:
                continue
            found.append(
                {
                    "member": info.filename,
                    "name": name,
                    "size": info.file_size,
                    "compressed": info.compress_size,
                }
            )
    found.sort(key=lambda row: row["size"], reverse=True)
    return found


def existing_extracted_db(zip_path: Path, db_name: str, size: int, extra_dirs: Iterable[Path]) -> Optional[Path]:
    """Reuse a .db that was already unzipped."""
    stem = Path(db_name).stem
    candidates: list[Path] = []
    parent = zip_path.parent
    for folder in [parent, parent / stem, *extra_dirs]:
        candidates.append(Path(folder) / db_name)
    seen: set[str] = set()
    for path in candidates:
        key = str(path).lower()
        if key in seen:
            continue
        seen.add(key)
        try:
            if path.is_file() and path.stat().st_size == size and is_sqlite_file(path):
                return path
        except OSError:
            continue
    return None


def extract_db_from_zip(
    zip_path: Path,
    dest_dir: Path,
    progress: Optional[ProgressCb] = None,
) -> Path:
    """Extract the largest .db from a NIST RDS zip into dest_dir."""
    databases = list_zip_databases(zip_path)
    if not databases:
        raise ValueError(
            f"No NSRL .db file found inside '{zip_path.name}'. "
            "Expected a layout like RDS_2026.03.1_android/RDS_2026.03.1_android.db."
        )
    chosen = databases[0]
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / chosen["name"]
    already = existing_extracted_db(zip_path, chosen["name"], chosen["size"], [dest_dir])
    if already is not None:
        if progress:
            progress(f"Using already extracted {already.name}", chosen["size"], chosen["size"])
        return already

    free = shutil.disk_usage(dest_dir).free
    needed = chosen["size"] + (64 * 1024 * 1024)
    if free < needed:
        raise ValueError(
            f"Not enough free space to extract {chosen['name']} "
            f"({format_bytes(chosen['size'])} needed, {format_bytes(free)} free in {dest_dir})."
        )

    tmp = dest.with_suffix(dest.suffix + ".partial")
    if progress:
        progress(f"Extracting {chosen['name']}", 0, chosen["size"])
    copied = 0
    try:
        with zipfile.ZipFile(zip_path) as zf, zf.open(chosen["member"]) as src, tmp.open("wb") as out:
            while True:
                chunk = src.read(8 * 1024 * 1024)
                if not chunk:
                    break
                out.write(chunk)
                copied += len(chunk)
                if progress:
                    progress(f"Extracting {chosen['name']}", copied, chosen["size"])
        tmp.replace(dest)
    except Exception:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass
        raise
    if progress:
        progress(f"Extracted {chosen['name']}", chosen["size"], chosen["size"])
    return dest


def source_is_zip(path: Path) -> bool:
    path = Path(path)
    return path.suffix.lower() == ".zip" or zipfile.is_zipfile(path)


def permanently_delete_extracted_db(db_path: Path) -> list[str]:
    """Permanently remove an extracted SQLite .db and sidecar temp files.

    This does not send the file to Recycle Bin / Trash.
    """
    db_path = Path(db_path)
    removed: list[str] = []
    leftovers = [
        db_path,
        Path(str(db_path) + "-wal"),
        Path(str(db_path) + "-shm"),
        Path(str(db_path) + "-journal"),
        db_path.with_suffix(db_path.suffix + ".partial"),
    ]
    errors: list[str] = []
    for item in leftovers:
        try:
            if item.is_file():
                item.unlink()
                removed.append(str(item))
        except OSError as exc:
            errors.append(f"{item.name}: {exc}")
    if errors and not removed:
        raise OSError("Could not delete extracted database: " + "; ".join(errors))
    if errors:
        raise OSError(
            "Deleted some files but not all: "
            + "; ".join(errors)
            + (". Removed: " + ", ".join(removed) if removed else "")
        )
    return removed


def resolve_nsrl_source(
    source: Path,
    extract_dir: Optional[Path] = None,
    progress: Optional[ProgressCb] = None,
) -> Path:
    """Return a path to the SQLite .db, extracting from a zip if needed."""
    source = Path(source)
    if not source.is_file():
        raise FileNotFoundError(f"File not found: {source}")
    suffix = source.suffix.lower()
    if suffix == ".zip" or zipfile.is_zipfile(source):
        dest_dir = Path(extract_dir) if extract_dir else source.parent
        return extract_db_from_zip(source, dest_dir, progress=progress)
    if suffix in {".db", ".sqlite", ".sqlite3"} or is_sqlite_file(source):
        return source
    raise ValueError(
        f"Unsupported input '{source.name}'. Choose an NSRL .db or the original NIST .zip."
    )


def inspect_source(path: Path) -> dict:
    """Inspect a .db or a NIST zip without extracting."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")
    if path.suffix.lower() == ".zip" or zipfile.is_zipfile(path):
        databases = list_zip_databases(path)
        if not databases:
            raise ValueError(f"No NSRL .db file found inside '{path.name}'.")
        main = databases[0]
        return {
            "kind": "zip",
            "path": str(path),
            "zip_db_member": main["member"],
            "zip_db_name": main["name"],
            "size_bytes": main["size"],
            "compressed_bytes": main["compressed"],
            "objects": {},
            "file_columns": [],
            "has_file": True,
            "has_mfg": True,
            "has_os": True,
            "has_pkg": True,
            "has_crc32": False,
            "has_sha256": False,
            "version": None,
            "file_rows_estimate": None,
        }
    info = inspect_database(path)
    info["kind"] = "db"
    info["zip_db_name"] = path.name
    return info


def open_readonly(db_path: Path) -> sqlite3.Connection:
    uri = Path(db_path).resolve().as_uri() + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    for pragma in (
        "PRAGMA query_only = ON;",
        "PRAGMA temp_store = MEMORY;",
        "PRAGMA synchronous = OFF;",
        "PRAGMA mmap_size = 30000000000;",
    ):
        try:
            cur.execute(pragma)
        except sqlite3.Error:
            pass
    return conn


def list_objects(conn: sqlite3.Connection) -> dict[str, str]:
    rows = conn.execute(
        "SELECT name, type FROM sqlite_master WHERE type IN ('table','view')"
    ).fetchall()
    return {str(r["name"]).upper(): str(r["type"]) for r in rows}


def columns_of(conn: sqlite3.Connection, name: str) -> set[str]:
    try:
        info = conn.execute(f'PRAGMA table_info("{name}")').fetchall()
    except sqlite3.Error:
        return set()
    return {str(r["name"]).lower() for r in info}


def table_exists(objects: dict[str, str], name: str) -> bool:
    return name.upper() in objects


def _stat1_rows(conn: sqlite3.Connection, name: str) -> Optional[int]:
    try:
        row = conn.execute(
            "SELECT stat FROM sqlite_stat1 WHERE tbl = ? COLLATE NOCASE LIMIT 1",
            (name,),
        ).fetchone()
        if row and row[0]:
            return int(str(row[0]).split()[0])
    except (sqlite3.Error, ValueError, TypeError):
        return None
    return None


def _max_rowid(conn: sqlite3.Connection, name: str) -> Optional[int]:
    try:
        row = conn.execute(f'SELECT MAX(rowid) FROM "{name}"').fetchone()
        if row and row[0] is not None:
            return int(row[0])
    except sqlite3.Error:
        return None
    return None


def _view_base_tables(conn: sqlite3.Connection, name: str) -> list[str]:
    try:
        row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE name = ? COLLATE NOCASE",
            (name,),
        ).fetchone()
    except sqlite3.Error:
        return []
    if not row or not row[0]:
        return []
    found = re.findall(r'(?:FROM|JOIN)\s+["\[]?(\w+)["\]]?', str(row[0]), re.IGNORECASE)
    skip = {name.upper(), "SELECT"}
    return [item for item in found if item.upper() not in skip]


def _dbstat_leaf_cells(conn: sqlite3.Connection, name: str) -> Optional[int]:
    try:
        row = conn.execute(
            "SELECT SUM(ncell) FROM dbstat WHERE name = ? COLLATE NOCASE AND pagetype = 'leaf'",
            (name,),
        ).fetchone()
        if row and row[0]:
            return int(row[0])
    except sqlite3.Error:
        return None
    return None


def _size_based_file_rows(conn: sqlite3.Connection) -> Optional[int]:
    """Rough FILE-row guess from used pages. Avoids a COUNT(*) scan."""
    try:
        page_count = int(conn.execute("PRAGMA page_count").fetchone()[0])
        page_size = int(conn.execute("PRAGMA page_size").fetchone()[0])
        try:
            free = int(conn.execute("PRAGMA freelist_count").fetchone()[0])
        except (sqlite3.Error, TypeError, ValueError):
            free = 0
        used = max(page_count - free, 1) * page_size
        # FILE + its indexes dominate NSRL databases. ~320 bytes per logical row.
        return max(int(used / 320), 1)
    except (sqlite3.Error, TypeError, ValueError):
        return None


def estimate_rows(conn: sqlite3.Connection, name: str) -> Optional[int]:
    """Best-effort row count that avoids a full table scan.

    FILE is a view on some RDS v3 publications, so MAX(rowid) and sqlite_stat1
    often fail. Fall back to the view's base table, dbstat leaf cells, then
    database size.
    """
    for candidate in [name, *(_view_base_tables(conn, name))]:
        for guess in (
            _stat1_rows(conn, candidate),
            _dbstat_leaf_cells(conn, candidate),
            _max_rowid(conn, candidate),
        ):
            if guess and guess > 0:
                return guess
    if name.upper() == "FILE":
        return _size_based_file_rows(conn)
    return None


def strip_quotes(value: object) -> str:
    if value is None:
        return ""
    text = str(value).replace('"', "")
    return text


# ---------------------------------------------------------------------------
# RDS 2.xx writers
# ---------------------------------------------------------------------------


class QuotedCsvWriter:
    """Write RDS 2.xx style CSV: quoted text, bare integers, LF line endings."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = path.open("w", encoding="utf-8", newline="\n")
        self.path = path
        self.rows = 0

    def write_header(self, fields: list[str]) -> None:
        self._fh.write(",".join(f'"{f}"' for f in fields) + "\n")

    def write_row(self, fields: Iterable[object]) -> None:
        parts: list[str] = []
        for field in fields:
            if isinstance(field, int) and not isinstance(field, bool):
                parts.append(str(field))
            else:
                parts.append('"' + strip_quotes(field) + '"')
        self._fh.write(",".join(parts) + "\n")
        self.rows += 1

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> "QuotedCsvWriter":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def output_extension(value: str) -> str:
    ext = (value or "txt").lower().lstrip(".")
    if ext not in {"txt", "csv"}:
        raise ValueError("Output format must be txt or csv")
    return ext


def db_output_stem(db_path: Path) -> str:
    """Use the source database filename (without extension) as the output prefix."""
    stem = Path(db_path).stem.strip()
    return stem or "NSRL"


def rds_output_path(out_dir: Path, db_path: Path, kind: str, ext: str = "txt") -> Path:
    """e.g. RDS_2026.06.1_modern_minimal_NSRLFile.txt"""
    return Path(out_dir) / f"{db_output_stem(db_path)}_{kind}.{ext}"


def inspect_database(db_path: Path) -> dict:
    if not db_path.is_file():
        raise FileNotFoundError(f"Database not found: {db_path}")
    if not is_sqlite_file(db_path):
        raise ValueError(
            f"Not a SQLite database (missing 'SQLite format 3' header): {db_path}"
        )
    conn = open_readonly(db_path)
    try:
        objects = list_objects(conn)
        file_cols = columns_of(conn, "FILE") if "FILE" in objects else set()
        version = None
        if "VERSION" in objects:
            try:
                row = conn.execute(
                    "SELECT version, build_set, description FROM VERSION LIMIT 1"
                ).fetchone()
                if row:
                    version = {
                        "version": row[0],
                        "build_set": row[1],
                        "description": row[2],
                    }
            except sqlite3.Error:
                pass
        return {
            "path": str(db_path),
            "size_bytes": db_path.stat().st_size,
            "objects": objects,
            "file_columns": sorted(file_cols),
            "has_file": "FILE" in objects,
            "has_mfg": "MFG" in objects,
            "has_os": "OS" in objects,
            "has_pkg": "PKG" in objects,
            "has_crc32": "crc32" in file_cols,
            "has_sha256": "sha256" in file_cols,
            "version": version,
            "file_rows_estimate": estimate_rows(conn, "FILE") if "FILE" in objects else None,
        }
    finally:
        conn.close()


def export_nsrlfile(
    conn: sqlite3.Connection,
    out_path: Path,
    sort_rows: bool,
    progress: Optional[ProgressCb] = None,
    label: Optional[str] = None,
) -> int:
    cols = columns_of(conn, "FILE")
    if not cols:
        raise ValueError("Database has no FILE table/view.")

    sha1 = "sha1" if "sha1" in cols else None
    md5 = "md5" if "md5" in cols else None
    crc = "crc32" if "crc32" in cols else None
    name = "file_name" if "file_name" in cols else None
    size = "file_size" if "file_size" in cols else ("bytes" if "bytes" in cols else None)
    pkg = "package_id" if "package_id" in cols else None
    if not (sha1 and md5 and name and size and pkg):
        raise ValueError(
            "FILE is missing required columns. Found: " + ", ".join(sorted(cols))
        )

    select = (
        f'SELECT "{sha1}" AS sha1, "{md5}" AS md5, '
        + (f'"{crc}" AS crc32, ' if crc else "'' AS crc32, ")
        + f'"{name}" AS file_name, "{size}" AS file_size, "{pkg}" AS package_id '
        + "FROM FILE"
    )
    if sort_rows:
        select += " ORDER BY sha1"

    total = estimate_rows(conn, "FILE")
    written = 0
    status = f"Writing {label or out_path.name}"
    if progress:
        progress(status, 0, total)
    with QuotedCsvWriter(out_path) as writer:
        writer.write_header(NSRLFILE_HEADER)
        cur = conn.execute(select)
        while True:
            batch = cur.fetchmany(5_000)
            if not batch:
                break
            for row in batch:
                try:
                    file_size = int(row["file_size"] or 0)
                except (TypeError, ValueError):
                    file_size = 0
                try:
                    product = int(row["package_id"] or 0)
                except (TypeError, ValueError):
                    product = 0
                writer.write_row(
                    (
                        row["sha1"] or "",
                        row["md5"] or "",
                        row["crc32"] or "",
                        row["file_name"] or "",
                        file_size,
                        product,
                        "0",
                        "",
                    )
                )
            written = writer.rows
            if progress:
                progress(status, written, total)
    if progress:
        progress(status, written, written or total)
    return written


def export_nsrlmfg(
    conn: sqlite3.Connection,
    out_path: Path,
    sort_rows: bool,
    progress: Optional[ProgressCb] = None,
    label: Optional[str] = None,
) -> int:
    cols = columns_of(conn, "MFG")
    if not cols:
        raise ValueError("Database has no MFG table/view.")
    order = " ORDER BY manufacturer_id" if sort_rows else ""
    sql = f"SELECT manufacturer_id, name FROM MFG{order}"
    total = estimate_rows(conn, "MFG")
    status = f"Writing {label or out_path.name}"
    with QuotedCsvWriter(out_path) as writer:
        writer.write_header(NSRLMFG_HEADER)
        for row in conn.execute(sql):
            try:
                code = int(row["manufacturer_id"])
            except (TypeError, ValueError):
                code = row["manufacturer_id"]
            writer.write_row((code, row["name"] or ""))
            if progress and writer.rows % 1000 == 0:
                progress(status, writer.rows, total)
    if progress:
        progress(status, writer.rows, writer.rows)
    return writer.rows


def export_nsrlos(
    conn: sqlite3.Connection,
    out_path: Path,
    sort_rows: bool,
    progress: Optional[ProgressCb] = None,
    label: Optional[str] = None,
) -> int:
    cols = columns_of(conn, "OS")
    if not cols:
        raise ValueError("Database has no OS table/view.")
    order = " ORDER BY operating_system_id" if sort_rows else ""
    sql = (
        "SELECT operating_system_id, name, version, manufacturer_id "
        f"FROM OS{order}"
    )
    total = estimate_rows(conn, "OS")
    status = f"Writing {label or out_path.name}"
    with QuotedCsvWriter(out_path) as writer:
        writer.write_header(NSRLOS_HEADER)
        for row in conn.execute(sql):
            try:
                os_id = int(row["operating_system_id"])
            except (TypeError, ValueError):
                os_id = row["operating_system_id"]
            try:
                mfg = int(row["manufacturer_id"])
            except (TypeError, ValueError):
                mfg = row["manufacturer_id"]
            writer.write_row((os_id, row["name"] or "", row["version"] or "", mfg))
            if progress and writer.rows % 1000 == 0:
                progress(status, writer.rows, total)
    if progress:
        progress(status, writer.rows, writer.rows)
    return writer.rows


def export_nsrlprod(
    conn: sqlite3.Connection,
    out_path: Path,
    sort_rows: bool,
    progress: Optional[ProgressCb] = None,
    label: Optional[str] = None,
) -> int:
    cols = columns_of(conn, "PKG")
    if not cols:
        raise ValueError("Database has no PKG table/view.")
    order = " ORDER BY package_id" if sort_rows else ""
    sql = (
        "SELECT package_id, name, version, operating_system_id, "
        f"manufacturer_id, language, application_type FROM PKG{order}"
    )
    total = estimate_rows(conn, "PKG")
    status = f"Writing {label or out_path.name}"
    with QuotedCsvWriter(out_path) as writer:
        writer.write_header(NSRLPROD_HEADER)
        for row in conn.execute(sql):
            try:
                pkg = int(row["package_id"])
            except (TypeError, ValueError):
                pkg = row["package_id"]
            try:
                os_id = int(row["operating_system_id"])
            except (TypeError, ValueError):
                os_id = row["operating_system_id"]
            try:
                mfg = int(row["manufacturer_id"])
            except (TypeError, ValueError):
                mfg = row["manufacturer_id"]
            writer.write_row(
                (
                    pkg,
                    row["name"] or "",
                    row["version"] or "",
                    os_id,
                    mfg,
                    row["language"] or "",
                    row["application_type"] or "",
                )
            )
            if progress and writer.rows % 5000 == 0:
                progress(status, writer.rows, total)
    if progress:
        progress(status, writer.rows, writer.rows)
    return writer.rows


def convert_rds_v3(
    db_path: Path,
    out_dir: Path,
    *,
    write_file: bool = True,
    write_mfg: bool = True,
    write_os: bool = True,
    write_prod: bool = True,
    output_ext: str = "txt",
    sort_rows: bool = False,
    progress: Optional[ProgressCb] = None,
) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    db_path = resolve_nsrl_source(db_path, extract_dir=out_dir, progress=progress)
    info = inspect_database(db_path)
    ext = output_extension(output_ext)
    conn = open_readonly(db_path)
    results: dict = {"version": info.get("version"), "files": {}, "stem": db_output_stem(db_path)}
    try:
        if write_file:
            if not info["has_file"]:
                raise ValueError("This database has no FILE table/view.")
            dest = rds_output_path(out_dir, db_path, "NSRLFile", ext)
            if progress:
                progress(f"Writing {dest.name}", 0, info.get("file_rows_estimate"))
            count = export_nsrlfile(conn, dest, sort_rows, progress, label=dest.name)
            results["files"][dest.name] = {"path": str(dest), "rows": count}
        if write_mfg:
            if not info["has_mfg"]:
                raise ValueError("This database has no MFG table/view.")
            dest = rds_output_path(out_dir, db_path, "NSRLMfg", ext)
            count = export_nsrlmfg(conn, dest, sort_rows, progress, label=dest.name)
            results["files"][dest.name] = {"path": str(dest), "rows": count}
        if write_os:
            if not info["has_os"]:
                raise ValueError("This database has no OS table/view.")
            dest = rds_output_path(out_dir, db_path, "NSRLOS", ext)
            count = export_nsrlos(conn, dest, sort_rows, progress, label=dest.name)
            results["files"][dest.name] = {"path": str(dest), "rows": count}
        if write_prod:
            if not info["has_pkg"]:
                raise ValueError("This database has no PKG table/view.")
            dest = rds_output_path(out_dir, db_path, "NSRLProd", ext)
            count = export_nsrlprod(conn, dest, sort_rows, progress, label=dest.name)
            results["files"][dest.name] = {"path": str(dest), "rows": count}
    finally:
        conn.close()
    return results


def write_simple_hash_list(
    conn: sqlite3.Connection,
    out_path: Path,
    hash_type: str,
    *,
    dedup: bool = True,
    header_line: bool = False,
    progress: Optional[ProgressCb] = None,
    total: Optional[int] = None,
    label: Optional[str] = None,
) -> dict:
    """Write one uppercase hex hash per line for tools such as Magnet's forensic tools."""
    hash_type = hash_type.lower()
    if hash_type not in {"md5", "sha1", "sha256"}:
        raise ValueError("hash_type must be md5, sha1, or sha256")
    cols = columns_of(conn, "FILE")
    if hash_type not in cols:
        raise ValueError(f"FILE has no {hash_type} column.")
    if total is None:
        total = estimate_rows(conn, "FILE")
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    status = label or f"Writing {out_path.name}"
    written = 0
    skipped = 0
    seen: Optional[set[str]] = set() if dedup else None
    if progress:
        progress(status, 0, total)
    with out_path.open("w", encoding="utf-8", newline="\n") as fh:
        if header_line:
            fh.write(hash_type.upper() + "\n")
        cur = conn.execute(f'SELECT "{hash_type}" AS hv FROM FILE')
        while True:
            batch = cur.fetchmany(20_000)
            if not batch:
                break
            for row in batch:
                value = (row["hv"] or "").strip().upper()
                if not value:
                    continue
                if seen is not None:
                    if value in seen:
                        skipped += 1
                        continue
                    seen.add(value)
                fh.write(value + "\n")
                written += 1
            if progress:
                progress(status, written, total)
    if progress:
        progress(status, written, written or total)
    return {
        "path": str(out_path),
        "rows": written,
        "duplicates_skipped": skipped,
        "hash_type": hash_type,
    }


def export_hash_list(
    db_path: Path,
    out_path: Path,
    hash_type: str = "md5",
    dedup: bool = True,
    header_line: bool = False,
    progress: Optional[ProgressCb] = None,
) -> dict:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    db_path = resolve_nsrl_source(db_path, extract_dir=out_path.parent, progress=progress)
    conn = open_readonly(db_path)
    try:
        return write_simple_hash_list(
            conn,
            out_path,
            hash_type,
            dedup=dedup,
            header_line=header_line,
            progress=progress,
        )
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# GUI (Synchronoss Toolbox layout)
# ---------------------------------------------------------------------------


def hide_console_window() -> None:
    """Detach the extra console window on Windows when the GUI is running.

    Double-clicking a .py file starts python.exe with a command prompt behind
    the window. FreeConsole closes that prompt without affecting CLI mode.
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes

        ctypes.windll.kernel32.FreeConsole()
    except Exception:
        try:
            import ctypes

            hwnd = ctypes.windll.kernel32.GetConsoleWindow()
            if hwnd:
                ctypes.windll.user32.ShowWindow(hwnd, 0)
        except Exception:
            pass


def run_gui() -> None:
    hide_console_window()
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    root = tk.Tk()
    root.title(f"{APP_TITLE}  v{APP_VERSION}")
    root.minsize(920, 560)

    ico_path = find_resource("rds2txt.ico")
    if ico_path is not None:
        try:
            root.iconbitmap(str(ico_path))
        except Exception:
            pass

    logo_path = find_resource("Omega_header.png", "Omega_ui.png", "Omega.png")
    if logo_path is not None:
        try:
            logo_photo = tk.PhotoImage(file=str(logo_path))
            if logo_photo.width() > 32:
                factor = max(logo_photo.width() // 32, 1)
                logo_photo = logo_photo.subsample(factor, factor)
            root.iconphoto(True, logo_photo)
            root._logo_photo = logo_photo
        except Exception:
            pass

    frame = ttk.Frame(root, padding=8)
    frame.pack(fill="both", expand=True)
    frame.columnconfigure(1, weight=1)

    db_var = tk.StringVar()
    out_var = tk.StringVar()
    status_var = tk.StringVar()
    step_status_var = tk.StringVar(value="Current step")
    overall_status_var = tk.StringVar(value="Overall")
    info_var = tk.StringVar(
        value="Select the original NIST .zip or an already-extracted .db. "
        "Output defaults to that file's folder."
    )
    want_file = tk.BooleanVar(value=True)
    want_md5 = tk.BooleanVar(value=True)
    want_sha1 = tk.BooleanVar(value=True)
    want_mfg = tk.BooleanVar(value=False)
    want_os = tk.BooleanVar(value=False)
    want_prod = tk.BooleanVar(value=False)
    file_label = tk.StringVar(value="<db name>_NSRLFile.txt")
    md5_label = tk.StringVar(value="<db name>_MD5.txt")
    sha1_label = tk.StringVar(value="<db name>_SHA1.txt")
    mfg_label = tk.StringVar(value="<db name>_NSRLMfg.txt")
    os_label = tk.StringVar(value="<db name>_NSRLOS.txt")
    prod_label = tk.StringVar(value="<db name>_NSRLProd.txt")
    format_var = tk.StringVar(value="txt")
    want_sort = tk.BooleanVar(value=False)
    name_state = {"stem": None}
    want_delete_db = tk.BooleanVar(value=True)
    busy = {"flag": False}
    cancel_event = threading.Event()
    eta_var = tk.StringVar(value="")
    tracker = EtaTracker()
    source_kind = {"value": "db"}

    step_progress = ttk.Progressbar(frame, mode="determinate", maximum=100)
    overall_progress = ttk.Progressbar(frame, mode="determinate", maximum=100)

    workflow_frame = ttk.LabelFrame(frame, text="Workflow", padding=6)
    workflow_list = tk.Listbox(
        workflow_frame,
        height=8,
        activestyle="none",
        exportselection=False,
        font=("Segoe UI", 9),
    )
    workflow_list.pack(fill="x")
    workflow_state: dict = {"steps": [], "index": 0}

    def refresh_workflow_list(active_index: Optional[int] = None) -> None:
        workflow_list.delete(0, tk.END)
        for i, step in enumerate(workflow_state["steps"]):
            if step.get("done"):
                prefix = "[x]"
            elif active_index is not None and i == active_index:
                prefix = "[>]"
            else:
                prefix = "[ ]"
            workflow_list.insert(tk.END, f" {prefix}  {step['title']}")
        if active_index is not None and 0 <= active_index < workflow_list.size():
            workflow_list.selection_clear(0, tk.END)
            workflow_list.selection_set(active_index)
            workflow_list.see(active_index)

    def build_workflow(steps: list[tuple[str, str]]) -> None:
        workflow_state["steps"] = [
            {"key": key, "title": title, "done": False} for key, title in steps
        ]
        workflow_state["index"] = 0
        refresh_workflow_list()

    def paint_step(index: int, active: bool = False) -> None:
        for i, step in enumerate(workflow_state["steps"]):
            step["done"] = i < index
        refresh_workflow_list(active_index=index if active else None)

    def begin_step(index: int) -> None:
        workflow_state["index"] = index
        paint_step(index, active=True)
        step_progress["value"] = 0
        total = max(len(workflow_state["steps"]), 1)
        overall_progress["value"] = (index / total) * 100.0
        title = workflow_state["steps"][index]["title"] if workflow_state["steps"] else ""
        step_status_var.set(f"Current step: {title}")
        overall_status_var.set(f"Overall: step {index + 1} of {total}")

    def finish_step(index: int) -> None:
        if index < len(workflow_state["steps"]):
            workflow_state["steps"][index]["done"] = True
        paint_step(index + 1, active=False)
        total = max(len(workflow_state["steps"]), 1)
        overall_progress["value"] = ((index + 1) / total) * 100.0
        step_progress["value"] = 100
        overall_status_var.set(f"Overall: step {min(index + 1, total)} of {total}")

    def finish_all() -> None:
        for step in workflow_state["steps"]:
            step["done"] = True
        refresh_workflow_list()
        step_progress["value"] = 100
        overall_progress["value"] = 100
        eta_var.set("Estimated time remaining: 0s")
        step_status_var.set("Current step: complete")
        overall_status_var.set("Overall: complete")

    def current_ext() -> str:
        try:
            return output_extension(format_var.get())
        except ValueError:
            return "txt"

    def apply_output_names(stem: Optional[str] = None) -> None:
        if stem:
            name_state["stem"] = stem
        prefix = name_state["stem"] or "<db name>"
        ext = current_ext()
        file_label.set(f"{prefix}_NSRLFile.{ext}")
        md5_label.set(f"{prefix}_MD5.{ext}")
        sha1_label.set(f"{prefix}_SHA1.{ext}")
        mfg_label.set(f"{prefix}_NSRLMfg.{ext}")
        os_label.set(f"{prefix}_NSRLOS.{ext}")
        prod_label.set(f"{prefix}_NSRLProd.{ext}")

    def browse_db() -> None:
        path = filedialog.askopenfilename(
            title="Select NSRL .zip or .db",
            filetypes=[
                ("NSRL zip or database", "*.zip *.db"),
                ("Zip archives", "*.zip"),
                ("SQLite databases", "*.db"),
                ("SQLite files", "*.sqlite *.sqlite3"),
                ("All files", "*.*"),
            ],
        )
        if not path:
            return
        db_var.set(path)
        source = Path(path)
        out_var.set(str(source.parent))
        try:
            info = inspect_source(source)
            name_for_stem = info.get("zip_db_name") or source.name
            stem = db_output_stem(Path(name_for_stem))
            apply_output_names(stem)
            source_kind["value"] = info.get("kind") or "db"
            bits = [source.name]
            if info.get("kind") == "zip":
                bits.append(f"contains {info.get('zip_db_name')}")
                bits.append(f"{format_bytes(info['size_bytes'])} unpacked")
                if info.get("compressed_bytes"):
                    bits.append(f"{format_bytes(info['compressed_bytes'])} in zip")
                extra = (
                    "Zip selected — Convert will extract the .db into this same folder "
                    "unless it is already unzipped there."
                )
                info_var.set("  |  ".join(bits) + "\n" + extra)
            else:
                if info.get("version"):
                    ver = info["version"]
                    bits.append(f"RDS {ver.get('version') or ''}".strip())
                    if ver.get("build_set"):
                        bits.append(str(ver["build_set"]))
                bits.append(format_bytes(info["size_bytes"]))
                present = []
                if info["has_file"]:
                    est = info.get("file_rows_estimate")
                    present.append(f"FILE (~{est:,} rows)" if est else "FILE")
                if info["has_mfg"]:
                    present.append("MFG")
                if info["has_os"]:
                    present.append("OS")
                if info["has_pkg"]:
                    present.append("PKG")
                crc = "crc32 present" if info["has_crc32"] else "crc32 empty (full RDSv3 view)"
                info_var.set("  |  ".join(bits) + "\n" + ", ".join(present) + f"  —  {crc}")
        except Exception as exc:
            info_var.set(f"Could not inspect file: {exc}")

    def browse_out() -> None:
        path = filedialog.askdirectory(initialdir=out_var.get() or ".")
        if path:
            out_var.set(path)

    def set_progress(label: str, done: Optional[int], total: Optional[int]) -> None:
        if cancel_event.is_set():
            raise ConversionCancelled("Cancelled by user")
        snap = tracker.snapshot(done, total)
        if done is not None and not tracker.should_paint() and snap.get("eta") != 0.0:
            return
        line = label if done is None else format_progress_line(label, done, total, snap)
        idx = workflow_state["index"]
        nsteps = max(len(workflow_state["steps"]), 1)
        step_pct = snap.get("pct")
        if step_pct is None:
            step_pct = 0.0
        overall_pct = ((idx + (step_pct / 100.0)) / nsteps) * 100.0

        def _apply() -> None:
            step_progress["value"] = step_pct
            overall_progress["value"] = min(99.0, overall_pct)
            status_var.set(line)
            if snap.get("eta") is not None:
                eta_var.set(f"Estimated time remaining (this step): {format_hms(snap['eta'])}")
            elif done:
                eta_var.set("Estimated time remaining (this step): calculating…")
            else:
                eta_var.set("")
            step_status_var.set(f"Current step: {label}")
            overall_status_var.set(
                f"Overall: step {idx + 1} of {nsteps}  ({overall_pct:.1f}%)"
            )

        frame.after(0, _apply)

    def planned_steps(source: Path) -> list[tuple[str, str]]:
        steps: list[tuple[str, str]] = []
        is_zip = source.suffix.lower() == ".zip" or zipfile.is_zipfile(source)
        if is_zip:
            steps.append(("extract", "Extract .db from zip (skip if already extracted)"))
        steps.append(("open", "Open and inspect database"))
        if want_file.get():
            steps.append(("file", f"Write {file_label.get()}"))
        if want_md5.get():
            steps.append(("md5", f"Write {md5_label.get()}"))
        if want_sha1.get():
            steps.append(("sha1", f"Write {sha1_label.get()}"))
        if want_mfg.get():
            steps.append(("mfg", f"Write {mfg_label.get()}"))
        if want_os.get():
            steps.append(("os", f"Write {os_label.get()}"))
        if want_prod.get():
            steps.append(("prod", f"Write {prod_label.get()}"))
        if want_delete_db.get() and is_zip:
            steps.append(("cleanup", "Permanently delete extracted .db"))
        steps.append(("done", "Finish"))
        return steps

    def convert() -> None:
        if busy["flag"]:
            return
        if not db_var.get().strip():
            status_var.set("Choose an NSRL .zip or .db file.")
            return
        source = Path(db_var.get().strip())
        if not out_var.get().strip():
            out_var.set(str(source.parent))
        out_dir = Path(out_var.get().strip())
        if not any(
            (
                want_file.get(),
                want_md5.get(),
                want_sha1.get(),
                want_mfg.get(),
                want_os.get(),
                want_prod.get(),
            )
        ):
            status_var.set("Select at least one output file.")
            return

        steps = planned_steps(source)
        build_workflow(steps)
        cancel_event.clear()
        busy["flag"] = True
        convert_btn.state(["disabled"])
        cancel_btn.state(["!disabled"])
        step_progress["value"] = 0
        overall_progress["value"] = 0
        tracker.reset()
        eta_var.set("Estimated time remaining (this step): calculating…")
        status_var.set("Starting conversion...")

        def task() -> None:
            conn = None
            results: dict = {"files": {}}
            created_outputs: list[Path] = []
            extracted_this_run: Optional[Path] = None
            try:
                idx = 0
                db_path = source
                preexisting_dbs = set()
                if source_is_zip(source):
                    for item in list_zip_databases(source):
                        candidate = out_dir / item["name"]
                        if candidate.is_file():
                            preexisting_dbs.add(candidate.resolve())

                if steps[idx][0] == "extract":
                    tracker.reset()
                    frame.after(0, lambda i=idx: begin_step(i))
                    db_path = resolve_nsrl_source(source, extract_dir=out_dir, progress=set_progress)
                    frame.after(0, lambda i=idx: finish_step(i))
                    idx += 1
                else:
                    db_path = resolve_nsrl_source(source, extract_dir=out_dir, progress=set_progress)
                if (
                    source_is_zip(source)
                    and db_path.resolve() != source.resolve()
                    and db_path.resolve() not in preexisting_dbs
                ):
                    extracted_this_run = db_path

                tracker.reset()
                frame.after(0, lambda i=idx: begin_step(i))
                set_progress("Opening database", 0, 2)
                conn = open_readonly(db_path)
                set_progress("Reading schema", 1, 2)
                objects = list_objects(conn)
                set_progress("Database ready", 2, 2)
                frame.after(0, lambda i=idx: finish_step(i))
                idx += 1
                if not objects:
                    raise ValueError("Database has no tables or views.")

                sort_rows = want_sort.get()
                ext = current_ext()

                if want_file.get():
                    tracker.reset()
                    frame.after(0, lambda i=idx: begin_step(i))
                    dest = rds_output_path(out_dir, db_path, "NSRLFile", ext)
                    created_outputs.append(dest)
                    count = export_nsrlfile(conn, dest, sort_rows, set_progress, label=dest.name)
                    results["files"][dest.name] = {"path": str(dest), "rows": count}
                    frame.after(0, lambda i=idx: finish_step(i))
                    idx += 1
                if want_md5.get():
                    tracker.reset()
                    frame.after(0, lambda i=idx: begin_step(i))
                    dest = out_dir / md5_label.get()
                    created_outputs.append(dest)
                    result = write_simple_hash_list(
                        conn,
                        dest,
                        "md5",
                        dedup=True,
                        header_line=False,
                        progress=set_progress,
                        label=dest.name,
                    )
                    results["files"][dest.name] = {
                        "path": str(dest),
                        "rows": result["rows"],
                    }
                    frame.after(0, lambda i=idx: finish_step(i))
                    idx += 1
                if want_sha1.get():
                    tracker.reset()
                    frame.after(0, lambda i=idx: begin_step(i))
                    dest = out_dir / sha1_label.get()
                    created_outputs.append(dest)
                    result = write_simple_hash_list(
                        conn,
                        dest,
                        "sha1",
                        dedup=True,
                        header_line=False,
                        progress=set_progress,
                        label=dest.name,
                    )
                    results["files"][dest.name] = {
                        "path": str(dest),
                        "rows": result["rows"],
                    }
                    frame.after(0, lambda i=idx: finish_step(i))
                    idx += 1
                if want_mfg.get():
                    tracker.reset()
                    frame.after(0, lambda i=idx: begin_step(i))
                    dest = rds_output_path(out_dir, db_path, "NSRLMfg", ext)
                    created_outputs.append(dest)
                    count = export_nsrlmfg(conn, dest, sort_rows, set_progress, label=dest.name)
                    results["files"][dest.name] = {"path": str(dest), "rows": count}
                    frame.after(0, lambda i=idx: finish_step(i))
                    idx += 1
                if want_os.get():
                    tracker.reset()
                    frame.after(0, lambda i=idx: begin_step(i))
                    dest = rds_output_path(out_dir, db_path, "NSRLOS", ext)
                    created_outputs.append(dest)
                    count = export_nsrlos(conn, dest, sort_rows, set_progress, label=dest.name)
                    results["files"][dest.name] = {"path": str(dest), "rows": count}
                    frame.after(0, lambda i=idx: finish_step(i))
                    idx += 1
                if want_prod.get():
                    tracker.reset()
                    frame.after(0, lambda i=idx: begin_step(i))
                    dest = rds_output_path(out_dir, db_path, "NSRLProd", ext)
                    created_outputs.append(dest)
                    count = export_nsrlprod(conn, dest, sort_rows, set_progress, label=dest.name)
                    results["files"][dest.name] = {"path": str(dest), "rows": count}
                    frame.after(0, lambda i=idx: finish_step(i))
                    idx += 1

                deleted_note = ""
                should_delete = want_delete_db.get() and source_is_zip(source)
                if should_delete:
                    frame.after(0, lambda i=idx: begin_step(i))
                    if conn is not None:
                        try:
                            conn.close()
                        except Exception:
                            pass
                        conn = None
                    if db_path.resolve() == source.resolve():
                        deleted_note = (
                            "\nExtracted .db was not deleted because it is the file you selected."
                        )
                    else:
                        removed = permanently_delete_extracted_db(db_path)
                        if removed:
                            deleted_note = (
                                "\nPermanently deleted extracted database:\n  "
                                + "\n  ".join(removed)
                            )
                        else:
                            deleted_note = "\nNo extracted .db file was present to delete."
                    frame.after(0, lambda i=idx: finish_step(i))
                    idx += 1

                frame.after(0, lambda i=idx: begin_step(i))
                frame.after(0, lambda i=idx: finish_step(i))

                lines = ["Conversion complete."]
                for name, meta in results["files"].items():
                    lines.append(f"  {name}: {meta['rows']:,} rows")
                msg = "\n".join(lines) + deleted_note

                def _ok() -> None:
                    finish_all()
                    status_var.set(msg)
                    messagebox.showinfo(APP_TITLE, msg)

                frame.after(0, _ok)
            except ConversionCancelled:
                removed: list[str] = []
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        pass
                    conn = None
                for item in created_outputs:
                    try:
                        if item.is_file():
                            item.unlink()
                            removed.append(item.name)
                    except OSError:
                        pass
                if extracted_this_run is not None:
                    try:
                        removed.extend(
                            Path(p).name for p in permanently_delete_extracted_db(extracted_this_run)
                        )
                    except OSError:
                        pass
                for leftover in out_dir.glob("*.db.partial"):
                    try:
                        leftover.unlink()
                        removed.append(leftover.name)
                    except OSError:
                        pass
                note = "Conversion cancelled."
                if removed:
                    note += "\nRemoved incomplete files:\n  " + "\n  ".join(removed)
                else:
                    note += "\nNo incomplete output files were left behind."

                def _cancelled() -> None:
                    eta_var.set("")
                    step_status_var.set("Current step: cancelled")
                    overall_status_var.set("Overall: cancelled")
                    status_var.set(note)
                    messagebox.showinfo(APP_TITLE, note)

                frame.after(0, _cancelled)
            except Exception as exc:
                err = f"Error: {exc}"

                def _err() -> None:
                    status_var.set(err)
                    messagebox.showerror(APP_TITLE, err)

                frame.after(0, _err)
            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        pass
                busy["flag"] = False

                def _unlock() -> None:
                    convert_btn.state(["!disabled"])
                    cancel_btn.state(["disabled"])

                frame.after(0, _unlock)

        threading.Thread(target=task, daemon=True).start()

    def cancel() -> None:
        if not busy["flag"]:
            return
        cancel_event.set()
        status_var.set("Cancelling — waiting for the current step to stop...")
        cancel_btn.state(["disabled"])

    ttk.Label(frame, text="NSRL zip or .db:").grid(
        row=0, column=0, sticky="e", padx=5, pady=(5, 0)
    )
    ttk.Entry(frame, textvariable=db_var, width=58).grid(
        row=0, column=1, padx=5, pady=(5, 0), sticky="ew"
    )
    ttk.Button(frame, text="Browse", command=browse_db).grid(
        row=0, column=2, padx=5, pady=(5, 0)
    )
    ttk.Label(frame, textvariable=info_var, wraplength=720, justify="left").grid(
        row=1, column=1, columnspan=2, sticky="w", padx=5, pady=(2, 6)
    )

    ttk.Label(frame, text="Output folder:").grid(
        row=2, column=0, sticky="e", padx=5, pady=5
    )
    ttk.Entry(frame, textvariable=out_var, width=58).grid(
        row=2, column=1, padx=5, pady=5, sticky="ew"
    )
    ttk.Button(frame, text="Browse", command=browse_out).grid(
        row=2, column=2, padx=5, pady=5
    )

    opts = ttk.LabelFrame(frame, text="Files to write", padding=6)
    opts.grid(row=4, column=0, columnspan=3, sticky="ew", padx=5, pady=5)
    opts.columnconfigure(1, weight=0)
    opts.columnconfigure(2, weight=1)

    ttk.Checkbutton(opts, variable=want_file).grid(row=0, column=0, sticky="w", padx=(4, 2), pady=2)
    ttk.Label(opts, textvariable=file_label).grid(row=0, column=1, sticky="w", padx=4, pady=2)
    ttk.Label(opts, text="— RDS 2.xx quoted CSV. Tools that parse NSRL columns.").grid(
        row=0, column=2, sticky="w", padx=4, pady=2
    )

    ttk.Checkbutton(opts, variable=want_md5).grid(row=1, column=0, sticky="w", padx=(4, 2), pady=2)
    ttk.Label(opts, textvariable=md5_label).grid(row=1, column=1, sticky="w", padx=4, pady=2)
    ttk.Label(opts, text="— one MD5 per line, hex. Tools such as Magnet's forensic tools.").grid(
        row=1, column=2, sticky="w", padx=4, pady=2
    )

    ttk.Checkbutton(opts, variable=want_sha1).grid(row=2, column=0, sticky="w", padx=(4, 2), pady=2)
    ttk.Label(opts, textvariable=sha1_label).grid(row=2, column=1, sticky="w", padx=4, pady=2)
    ttk.Label(opts, text="— one SHA-1 per line, hex. Tools such as Magnet's forensic tools.").grid(
        row=2, column=2, sticky="w", padx=4, pady=2
    )

    ttk.Checkbutton(opts, variable=want_mfg).grid(row=3, column=0, sticky="w", padx=(4, 2), pady=2)
    ttk.Label(opts, textvariable=mfg_label).grid(row=3, column=1, sticky="w", padx=4, pady=2)
    ttk.Label(opts, text="— manufacturer lookup. Optional metadata.").grid(
        row=3, column=2, sticky="w", padx=4, pady=2
    )

    ttk.Checkbutton(opts, variable=want_os).grid(row=4, column=0, sticky="w", padx=(4, 2), pady=2)
    ttk.Label(opts, textvariable=os_label).grid(row=4, column=1, sticky="w", padx=4, pady=2)
    ttk.Label(opts, text="— operating-system lookup. Optional metadata.").grid(
        row=4, column=2, sticky="w", padx=4, pady=2
    )

    ttk.Checkbutton(opts, variable=want_prod).grid(row=5, column=0, sticky="w", padx=(4, 2), pady=2)
    ttk.Label(opts, textvariable=prod_label).grid(row=5, column=1, sticky="w", padx=4, pady=2)
    ttk.Label(opts, text="— product/package lookup. Optional metadata.").grid(
        row=5, column=2, sticky="w", padx=4, pady=2
    )

    extra = ttk.LabelFrame(frame, text="Options", padding=6)
    extra.grid(row=5, column=0, columnspan=3, sticky="ew", padx=5, pady=5)
    fmt_row = ttk.Frame(extra)
    fmt_row.grid(row=0, column=0, columnspan=2, sticky="w", padx=6, pady=(0, 2))
    ttk.Label(fmt_row, text="Output format:").pack(side="left")
    ttk.Radiobutton(
        fmt_row, text=".txt", value="txt", variable=format_var, command=apply_output_names
    ).pack(side="left", padx=(8, 4))
    ttk.Radiobutton(
        fmt_row, text=".csv", value="csv", variable=format_var, command=apply_output_names
    ).pack(side="left", padx=4)
    ttk.Checkbutton(
        extra,
        text="Sort rows to match NIST spec (much slower on large FILE tables)",
        variable=want_sort,
    ).grid(row=1, column=0, columnspan=2, sticky="w", padx=6)
    ttk.Checkbutton(
        extra,
        text="Permanently delete the extracted .db when finished (zip is kept; cannot undo)",
        variable=want_delete_db,
    ).grid(row=2, column=0, columnspan=2, sticky="w", padx=6)

    workflow_frame.grid(row=6, column=0, columnspan=3, sticky="ew", padx=5, pady=5)

    button_row = ttk.Frame(frame)
    button_row.grid(row=7, column=0, columnspan=3, pady=10)
    convert_btn = ttk.Button(button_row, text="Convert", command=convert)
    convert_btn.pack(side="left", padx=8)
    cancel_btn = ttk.Button(button_row, text="Cancel", command=cancel, state="disabled")
    cancel_btn.pack(side="left", padx=8)

    ttk.Label(frame, textvariable=step_status_var).grid(
        row=8, column=0, columnspan=3, sticky="w", padx=5, pady=(6, 0)
    )
    step_progress.grid(row=9, column=0, columnspan=3, sticky="ew", padx=5, pady=(2, 4))
    ttk.Label(frame, textvariable=overall_status_var).grid(
        row=10, column=0, columnspan=3, sticky="w", padx=5, pady=(2, 0)
    )
    overall_progress.grid(row=11, column=0, columnspan=3, sticky="ew", padx=5, pady=(2, 0))
    ttk.Label(frame, textvariable=eta_var, justify="left").grid(
        row=12, column=0, columnspan=3, sticky="w", padx=5, pady=(2, 0)
    )
    ttk.Label(frame, textvariable=status_var, wraplength=880, justify="left").grid(
        row=13, column=0, columnspan=3, sticky="w", padx=5, pady=5
    )

    workflow_list.insert(0, " Waiting to start…")
    root.update_idletasks()
    screen_w = root.winfo_screenwidth()
    screen_h = root.winfo_screenheight()
    width = min(max(root.winfo_reqwidth(), 960), max(screen_w - 40, 800))
    height = min(root.winfo_reqheight() + 8, max(screen_h - 80, 520))
    root.geometry(f"{width}x{height}+20+20")

    root.mainloop()

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Convert NSRL RDS v3 SQLite databases to RDS 2.xx text files."
    )
    parser.add_argument("--db", help="Path to the NSRL .db or original NIST .zip")
    parser.add_argument("--out", help="Output folder (RDS 2.xx) or file (hash list)")
    parser.add_argument(
        "--no-file", action="store_true", help="Skip NSRLFile.txt"
    )
    parser.add_argument("--no-mfg", action="store_true", help="Skip NSRLMfg.txt")
    parser.add_argument("--no-os", action="store_true", help="Skip NSRLOS.txt")
    parser.add_argument("--no-prod", action="store_true", help="Skip NSRLProd.txt")
    parser.add_argument(
        "--format",
        choices=["txt", "csv"],
        default="txt",
        dest="output_format",
        help="Write outputs as .txt or .csv (same content; default txt)",
    )
    parser.add_argument(
        "--sort",
        action="store_true",
        help="Sort rows to match the NIST document (slow on large FILE tables)",
    )
    parser.add_argument(
        "--hashes",
        choices=["md5", "sha1", "sha256"],
        help="Export a one-hash-per-line list instead of RDS 2.xx files",
    )
    parser.add_argument(
        "--no-dedup", action="store_true", help="Do not deduplicate hash-list output"
    )
    parser.add_argument(
        "--inspect", action="store_true", help="Print database info and exit"
    )
    return parser


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv[1:])

    if args.db is None:
        run_gui()
        return 0

    db_path = Path(args.db)
    if args.inspect:
        info = inspect_source(db_path)
        print(f"Kind: {info.get('kind')}")
        print(f"Path: {info['path']}")
        if info.get("kind") == "zip":
            print(f"DB inside zip: {info.get('zip_db_member')}")
            print(f"Unpacked size: {format_bytes(info['size_bytes'])}")
            print(f"Packed size: {format_bytes(info.get('compressed_bytes') or 0)}")
        else:
            print(f"Size: {format_bytes(info['size_bytes'])}")
            print(f"Version: {info.get('version')}")
            print(f"Objects: {', '.join(sorted(info['objects']))}")
            print(f"FILE columns: {', '.join(info['file_columns'])}")
            print(f"FILE rows (estimate): {info.get('file_rows_estimate')}")
        return 0

    if args.out is None:
        parser.error("--out is required when --db is set")

    cli_tracker = EtaTracker()

    def cli_progress(label: str, done: Optional[int], total: Optional[int]) -> None:
        snap = cli_tracker.snapshot(done, total)
        if done is not None and not cli_tracker.should_paint(0.5):
            return
        if done is None:
            print(label, flush=True)
        else:
            print(format_progress_line(label, done, total, snap), flush=True)

    if args.hashes:
        result = export_hash_list(
            db_path,
            Path(args.out),
            hash_type=args.hashes,
            dedup=not args.no_dedup,
            progress=cli_progress,
        )
        print(
            f"Wrote {result['rows']:,} {result['hash_type'].upper()} hashes to {result['path']}"
        )
        return 0

    result = convert_rds_v3(
        db_path,
        Path(args.out),
        write_file=not args.no_file,
        write_mfg=not args.no_mfg,
        write_os=not args.no_os,
        write_prod=not args.no_prod,
        output_ext=args.output_format,
        sort_rows=args.sort,
        progress=cli_progress,
    )
    for name, meta in result["files"].items():
        print(f"{name}: {meta['rows']:,} rows -> {meta['path']}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
