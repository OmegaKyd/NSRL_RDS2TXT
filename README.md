User Guide - NSRL RDS2TXT Converter
===============================

Version 1.0.0 (2026-08-26).

This converter takes NIST NSRL RDS v3 SQLite databases (the current `.db` / zip publications) and writes the legacy RDS 2.xx text files that a lot of forensic tools still expect. NIST moved the hash set to SQLite. Many tools still want `NSRLFile.txt` as quoted CSV.

The GUI layout follows the same pattern as the Synchronoss Toolbox: browse rows, Convert, a workflow list, and progress on a background thread.

This is not an official NIST project.

Requirements
===============================

- Windows is the intended target
- Python 3.8 or later, with Tkinter (the standard Windows installer includes it)
- No pip packages are required to run the converter
- PyInstaller is only needed if you want to build the `.exe`. `build_exe.py` will install it if it is missing

Run
===============================

    python nsrl_rds_converter.py

Or double-click `RDS2TXT.exe` if you have already built it.

Convert a hash set
===============================

1. Browse to the original NIST zip (`RDS_2026.03.1_android.zip`, `RDS_2026.03.1_ios.zip`, `RDS_2026.03.1_legacy.zip`, modern minimal, etc.) or to an already-extracted `.db`.
2. Output defaults to the same folder as that file. Change it if you want.
3. Leave `..._NSRLFile.txt`, `..._MD5.txt`, and `..._SHA1.txt` checked for tools such as Magnet's forensic tools.
4. Click Convert.

If you pointed at a zip, the tool finds the nested `.db` (for example `RDS_2026.03.1_android\RDS_2026.03.1_android.db`) and extracts only that file. SQLite cannot read the database from inside the zip. A full Android set is tens of gigabytes unpacked, so the first run needs that much free space.

The "Permanently delete the extracted .db when finished" option is on by default. After a successful conversion from a zip it deletes the extracted `.db` (not the zip, and not Recycle Bin). Uncheck it if you want to keep the database for another pass.

Output files
===============================

Names follow the database file:

    RDS_2026.03.1_android.db  →  RDS_2026.03.1_android_NSRLFile.txt

| File | What it is | Needed? |
| --- | --- | --- |
| `*_NSRLFile.txt` | SHA-1, MD5, CRC32, filename, size, product code | RDS 2.xx quoted CSV. Tools that parse NSRL columns. |
| `*_MD5.txt` | One uppercase MD5 per line, no header | Tools such as Magnet's forensic tools. Import as MD5 / Hex. |
| `*_SHA1.txt` | One uppercase SHA-1 per line, no header | Tools such as Magnet's forensic tools. Import as SHA1 / Hex. |
| `*_NSRLMfg.txt` | Manufacturer lookup | Only if the tool resolves vendor names. |
| `*_NSRLOS.txt` | Operating-system lookup | Metadata only. |
| `*_NSRLProd.txt` | Product / package lookup | Metadata only. |

Do not import `*_NSRLFile.txt` into a simple hash-list picker (tools such as Magnet's forensic tools). Those importers treat each line as one hash and will mis-detect the multi-column file as SHA-512 / Base64. Use the MD5 or SHA1 list instead.

RDS 2.xx content is quoted CSV. Choose `.txt` (official extension, default) or `.csv` in Options. The content is the same; only the extension changes. Hash lists use the same choice.

CRC32 is empty on some full RDS v3 publications because the FILE object is a view and has no CRC32 column. SHA-1 and MD5 are still written.

Command line
===============================

    python nsrl_rds_converter.py --db path\to\RDS_2026.03.1_android.zip --out path\to\folder
    python nsrl_rds_converter.py --db path\to\RDS.db --out path\to\folder --inspect
    python nsrl_rds_converter.py --db path\to\RDS.db --out path\to\hashes.txt --hashes md5

`--db` accepts either the zip or the `.db`. `--inspect` prints what is inside and exits. `--hashes md5|sha1|sha256` writes a one-hash-per-line list instead of the RDS 2.xx files.

Build the exe
===============================

From this folder:

    python build_exe.py

That is the same idea as the Synchronoss Toolbox builder. It runs PyInstaller with `nsrl_rds_converter.spec` and produces a windowed single-file exe:

    dist\RDS2TXT.exe
    RDS2TXT.exe

The exe uses `rds2txt.ico` (Omega mark with RDS2TXT under it). Build on Windows. Building on Linux will not give you an `.exe`.

Notes
===============================

- The source database is opened read-only. The converter does not write back into the NSRL `.db`.
- Large Modern / Android / iOS sets take a while. The current-step bar and ETA are estimates, especially when FILE is a view and the row count has to be guessed.
- Tools that parse RDS 2.xx columns read `NSRLFile.txt` by header name or by the fixed column order. Extra columns in that file are normal.

License
===============================

MIT. See `LICENSE.txt`.

NSRL and RDS are trademarks of NIST. This project is not affiliated with NIST.
