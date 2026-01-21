# Forensic Scout

A Bash-based DFIR utility that automates **repeatable, read-only triage and deleted-file recovery** from disk images using Sleuth Kit. It is designed for analysts who want consistent artifacts (hashes, filesystem metadata, deleted listings, recovered files, and lightweight static analysis) without mounting evidence.

## What it does

Given a disk image (for example, an NTFS image from removable media), Forensic Scout:

- Captures an environment snapshot for traceability
- Hashes the target image (MD5/SHA-256 where available)
- Identifies filesystem metadata (fsstat)
- Lists allocated and deleted entries (fls)
- Recovers selected deleted artifacts via metadata-based extraction (icat)
- Runs **static-only** checks on recovered/suspicious files:
  - file-type validation (magic/header)
  - strings extraction
  - keyword/IOC scanning for common red flags
  - "not what it seems" mismatch detection (extension vs file magic)
- Produces a structured run directory and optionally packages it for sharing

## Why this approach

- **Forensically safer by default:** the script reads directly from the image and does not mount evidence.
- **Operationally repeatable:** a single command produces consistent, reviewable artifacts.
- **Analyst-friendly outputs:** results are stored as plain text/CSV and can be easily cited in reports.
- **Static-only handling:** recovered executables are stored with a safe suffix (for example, `.exe_`) to reduce accidental execution risk.

## Requirements

- Bash (Linux recommended; WSL also works)
- Sleuth Kit: `mmls`, `fsstat`, `fls`, `icat`
- Common utilities: `file`, `strings`, `grep`, `awk`, `sed`, `sha256sum`, `md5sum`, `zip`

## Quick start

```bash
git clone https://github.com/titomazzetta/forensic-scout.git
cd forensic-scout
chmod +x forensic_scout.sh
```

Run on a volume image (filesystem starts at sector 0):

```bash
./forensic_scout.sh --target /path/to/evidence.img --case CASE001 --out /path/to/output
```

Run on a disk image with a partition table (specify the partition start sector):

```bash
mmls /path/to/evidence.img
./forensic_scout.sh --target /path/to/evidence.img --offset <START_SECTOR> --case CASE001 --out /path/to/output
```

## Understanding `--offset` (in plain language)

Some images are **entire disks** that contain a partition table. In that case, the filesystem does not start at the first byte of the image. The `--offset` value tells Sleuth Kit tools where the filesystem begins (in sectors).

- If the image is a **volume image** (filesystem begins immediately), use: `--offset 0`
- If the image is a **disk image with partitions**, use the **Start** sector from `mmls`

A wrong offset typically results in empty `fls` output, failed recovery, or tools reporting an unrecognized filesystem.

## Output structure

Each run creates a timestamped folder:

- `01_image_metadata/` - partition and filesystem details
- `02_file_lists/` - allocated and deleted listings
- `03_hashes/` - image and recovered-file hashes
- `04_recovered/` - recovered deleted artifacts + manifest CSV
- `05_static_analysis/` - file magic checks, strings, mismatch reports
- `06_redflags/` - IOC keyword hits summary
- `logs/` - full command log and run details
- `RUN_SUMMARY.md` - high-level summary for reporting

## Security notes

- Do not execute recovered files on your host.
- Prefer an isolated analysis VM for any deeper inspection or detonation.
- Keep evidence write-protected and maintain a hash log for chain-of-custody.

## Limitations

- This tool is not a full forensic suite; it targets quick, repeatable triage and basic recovery.
- Keyword/IOC scanning is heuristic and may generate false positives.
- Deeper malware analysis (dynamic analysis, deobfuscation, reverse engineering) should be performed with dedicated tooling in an isolated lab.

## License

MIT (or update as appropriate).
