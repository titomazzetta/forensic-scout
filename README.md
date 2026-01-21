# Forensic Scout

**Forensic Scout** is a repeatable, audit-friendly CLI workflow for **static digital-forensics triage** of Windows/NTFS evidence. It automates common first-pass tasks—**evidence hashing, file-system identification, allocated/deleted listings, targeted recovery, and static artifact inspection**—and produces a clean, timestamped output bundle suitable for incident response notes, internal handoff, or portfolio demonstration.

This tool is intentionally **static-only**: it does **not** execute recovered artifacts.

---

## Capabilities

- **Evidence integrity**
  - Hashes the target image (MD5/SHA-256) and records an environment snapshot
  - Optional `--make-readonly` to remove write permissions on the image (`chmod a-w`)
- **File system & structure**
  - Detects partition offset with `mmls` when a partition table exists
  - Handles **NTFS volume images** (no partition table) gracefully: if `mmls` fails, it proceeds with **offset 0**
  - Outputs `fsstat` metadata and full `fls` listings (allocated + deleted)
- **Deleted artifact recovery**
  - Recovers a subset of deleted artifacts via `icat` with a manifest for auditability
  - Default “interesting only” recovery to avoid huge extractions
- **Static analysis**
  - `file` type checks, PE header proof (`hexdump`), and capped `strings` extraction
  - IOC keyword hit report over strings output
  - ZIP inventory (`zipinfo` / `unzip -t`) when applicable
  - Optional YARA and ClamAV hooks (off by default)

---

## Install (Debian/Kali)

```bash
sudo apt update
sudo apt install -y sleuthkit file binutils unzip
```

Optional:
```bash
sudo apt install -y yara clamav
```

Clone:
```bash
git clone https://github.com/titomazzetta/forensic-scout.git
cd forensic-scout
chmod +x forensic_scout.sh
```

---

## Recommended workflow (project-root layout)

This is the cleanest approach for repeatable runs and clean reporting.

```bash
# Create a project folder
mkdir -p ~/Documents/Unit5_Project_V2
cd ~/Documents/Unit5_Project_V2

# Standard structure
mkdir -p evidence hashes notes recovered screenshots tools

# Place image in evidence/ and make it read-only
mv fullstack_lab.img evidence/
chmod a-w evidence/fullstack_lab.img

# Clone tool under tools/
cd tools
git clone https://github.com/titomazzetta/forensic-scout.git
cd forensic-scout
chmod +x forensic_scout.sh

# Run (recommended flags)
cd ~/Documents/Unit5_Project_V2
./tools/forensic-scout/forensic_scout.sh   --project-root ~/Documents/Unit5_Project_V2   --target ~/Documents/Unit5_Project_V2/evidence/fullstack_lab.img   --case unit5   --recover interesting   --max-recover 200   --make-readonly
```

### Locate the latest run directory

```bash
LATEST_RUN="$(ls -1dt ~/Documents/Unit5_Project_V2/notes/unit5_run_* | head -n 1)"
echo "$LATEST_RUN"
```

---

## Usage reference

### Image mode (SleuthKit) — default
```bash
./forensic_scout.sh --target evidence.dd --case triage_case
```

### Provide a known offset (partitioned images)
```bash
./forensic_scout.sh --target evidence.dd --offset 2048 --case triage_case
```

### Directory mode (mounted/extracted evidence)
Directory mode skips deleted recovery (no `icat`).
```bash
./forensic_scout.sh --target /mnt/evidence_mount --case triage_dir
```

### Optional scanners
```bash
./forensic_scout.sh --target evidence.dd --case triage_case --yara ./rules
./forensic_scout.sh --target evidence.dd --case triage_case --clamav
```

---

## Output layout

Each run creates a timestamped folder:

`<out>/<case>_run_<YYYYMMDD_HHMMSS>/`

Key artifacts:

- `01_image_metadata/`
  - `00_environment.txt` (system + tool snapshot)
  - `file_type.txt` (boot sector signature via `file -s`)
  - `mmls.txt` (partition table listing when applicable)
  - `fsstat.txt` (file system metadata)
- `02_file_lists/`
  - `fls_allocated.txt` (allocated files)
  - `fls_deleted.txt` (deleted entries)
  - `suspicious_paths.txt` (extension-based triage)
- `03_hashes/`
  - `target_image.md5.txt`
  - `target_image.sha256.txt`
- `04_recovered/`
  - `deleted/` (recovered files)
  - `deleted_manifest.csv` (audit trail of recovered artifacts)
  - `deleted_manifest_failed.csv` (failed attempts)
- `05_static_analysis/`
  - `file_reports/` (per-file metadata + hashes + file magic)
  - `strings/` (capped strings output)
  - `zip_inventory.txt`
  - `file_magic_mismatch.csv` (when “extension vs magic” mismatch is detected)
- `06_redflags/`
  - `ioc_hits_summary.txt`
  - `potential_malware/` (convenience copies for review)
- `RUN_SUMMARY.md` (high-level run summary)
- `logs/run.log` (full command log for auditability)

---

## Operational safety

- **Do not execute recovered artifacts.** Treat recovered files as potentially malicious.
- Run in an **isolated analysis VM** with no host-only shares to production machines.
- Preserve evidence integrity: work from the original image (read-only), extract to a run folder, and record hashes.
- For higher assurance, use storage-level write blocking or immutable flags in addition to filesystem permissions.

---

## Notes on NTFS images (partitioned vs volume)

You will encounter two common disk-image styles:

1. **Partitioned image** (has a partition table)  
   - `mmls` succeeds and a non-zero offset (often 2048 sectors) may be required.

2. **NTFS volume image** (no partition table; the NTFS boot sector is at sector 0)  
   - `mmls` may fail. This is normal.
   - Forensic Scout will log a warning and proceed with **offset 0**.
   - `fsstat` is the authoritative confirmation (e.g., `File System Type: NTFS`).

---

## License

MIT (see `LICENSE`).
