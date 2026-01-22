# General Summary — Forensic Scout (Automated Image Triage + Deleted File Recovery)

## What this is
**Forensic Scout** is a Bash-based automation utility for performing **repeatable, forensically-sound triage** of disk/volume images and recovering deleted artifacts using **The Sleuth Kit (TSK)**. It is designed for quick, consistent collection of filesystem metadata, deleted-entry listings, targeted recovery via metadata extraction, basic static inspection of recovered artifacts, and packaging of results into a clean run directory for reporting or handoff.

This tool is intended for:
- **Digital forensics triage** (initial survey of an evidence image)
- **Deleted file discovery and recovery** (metadata-driven extraction)
- **Static-only** inspection of suspicious artifacts (no execution)
- **Repeatable case artifacts** generation (run folders, manifests, logs)

It is not intended to replace full forensic suites; it complements them by producing a consistent baseline set of artifacts and audit logs.

---

## Why this approach
In many forensic workflows, analysts repeat the same core steps across images:
1) validate integrity (hashes)
2) identify filesystem and layout (offset/partition context)
3) enumerate allocated/deleted entries
4) recover specific deleted artifacts without altering evidence
5) run a static-only inspection pass to identify obvious red flags
6) package outputs for reporting or handoff

Forensic Scout standardizes these steps into a single command that produces deterministic outputs, reduces manual error, and supports consistent documentation.

---

## Safety and forensic handling
Forensic Scout is built around conservative handling principles:
- **No mounting required**: analysis is performed directly against the image using TSK tooling.
- **Read-only evidence handling**: the source image should be stored with read-only permissions.
- **Static-only inspection**: recovered executables/scripts are never executed by the tool.
- **Auditability**: commands and results are logged to a per-run directory with a summary and run log.

---

## How it works (high level)
Forensic Scout orchestrates standard CLI tools and stores outputs in a structured run directory. Typical operations include:

### 1) Target hashing
Generates cryptographic hashes (e.g., SHA-256) of the target image to support integrity validation and repeatability.

### 2) Filesystem + layout context (offset selection)
Many images are either:
- **Disk images with partitions** (filesystem begins at a partition start sector), or
- **Volume images** (filesystem begins immediately at sector 0)

Forensic Scout supports both via `--offset`:

- If the image has partitions, determine the partition start sector (commonly via `mmls`) and pass that as `--offset`.
- If the image is a volume image, use `--offset 0`.

**Offset in plain terms:** it is the “starting point” (in 512-byte sectors) where the filesystem begins inside the image. If the offset is incorrect, filesystem structures may not parse correctly and results can appear empty or incomplete.

### 3) Filesystem statistics (`fsstat`)
Collects filesystem metadata (type, cluster size, MFT location for NTFS, etc.) to document the evidence structure.

### 4) Enumeration (`fls`)
Produces directory/file listings for:
- **Allocated entries** (what currently exists)
- **Deleted entries** (what was deleted but may still be recoverable)

### 5) Deleted file recovery (metadata-based extraction)
Performs targeted recovery of selected deleted artifacts using **metadata extraction** (e.g., `icat`) without modifying evidence. Output is written to a dedicated recovery folder with a manifest documenting what was recovered.

### 6) Static analysis (non-executing)
Performs basic static-only checks on recovered artifacts such as:
- file type identification (`file`)
- header validation (e.g., PE header checks)
- strings extraction and **IOC keyword scanning**
- simple mismatch checks (“not what it seems” cases where extension and magic differ)

This step is intentionally lightweight and designed for triage. Any suspicious findings should be escalated to controlled sandboxing or deeper reverse engineering workflows.

### 7) Packaging and summary
Generates a run summary and packages key outputs for easy submission or handoff.

---

## Output artifacts
Each run produces a timestamped directory (example structure):

- `01_image_metadata/`
  - filesystem stats (`fsstat`)
  - layout context notes (offset/partition context)
- `02_file_lists/`
  - allocated listing (`fls` output)
  - deleted listing (`fls -d` output)
- `03_hashes/`
  - image hash outputs (e.g., SHA-256)
- `04_recovered/`
  - recovered artifacts (stored safely; no execution)
  - `deleted_manifest.csv` (what was recovered, where it was written)
- `05_static_analysis/`
  - file magic results, strings excerpts, mismatch checks
- `06_redflags/`
  - IOC keyword scan outputs and hit summaries
- `logs/`
  - a full command/run log for auditability
- `RUN_SUMMARY.md`
  - concise summary of results and pointers to primary artifacts

---

## Example usage
```bash
./forensic_scout.sh --target /path/to/evidence.img --case example_case
```

If a partition offset is required (partitioned disk image):
```bash
mmls /path/to/evidence.img
./forensic_scout.sh --target /path/to/evidence.img --offset <START_SECTOR> --case example_case
```

If the filesystem begins at sector 0 (volume image), explicitly set:
```bash
./forensic_scout.sh --target /path/to/evidence.img --offset 0 --case example_case
```

---

## Interpreting results (quick guidance)
- **Deleted listing empty** can mean:
  - there truly are no deleted entries, or
  - the wrong offset/layout was used.
- **Recovery success = 0** can mean:
  - the deleted file’s content is overwritten/unrecoverable, or
  - an incorrect offset prevented correct metadata parsing.
- **IOC keyword hits** are triage indicators only:
  - Hits do not prove malware; they identify strings consistent with suspicious capability.
  - Escalate suspicious artifacts to controlled sandbox analysis when appropriate.

---

## Notes for production use
Forensic Scout is designed to be:
- lightweight and portable across Linux analysis hosts
- repeatable and audit-friendly (run directories + logs)
- safe by default (no mounting, no execution)

In sensitive environments, avoid publishing case outputs or recovered artifacts. Store only sanitized summaries and tool documentation in public repositories.
