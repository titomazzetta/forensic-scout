# Forensic Scout (Static Triage + Recovery Helper)

Forensic Scout is a UX-friendly Bash workflow for **static digital-forensics triage** on Windows/NTFS evidence. It is designed to satisfy common Unit-style rubrics (hashing, listing, deleted recovery, static analysis, documentation) while producing **portfolio-ready** outputs.

## Quick start (Debian)
```bash
sudo apt update
sudo apt install -y sleuthkit file binutils unzip
chmod +x forensic_scout.sh
./forensic_scout.sh --target /path/to/evidence.dd --case unit5
```

### Directory mode (mounted folder)
```bash
./forensic_scout.sh --target /mnt/evidence_mount --case unit5_dir
```

## What you get
Each run creates `output/<case>_run_<timestamp>/` including:
- `03_hashes/` (hashes/manifests)
- `02_file_lists/` (allocated + deleted listings, suspicious paths)
- `04_recovered/` (recovered deleted subset + manifest)
- `05_static_analysis/` (file reports, strings, zip inventory)
- `06_redflags/` (IOC hits summary + convenience folder)
- `RUN_SUMMARY.md` and `logs/run.log`

## Safety
Static-only workflow; do not execute recovered artifacts. Prefer an isolated VM for analysis.
