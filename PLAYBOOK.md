# Forensic Scout Operational Playbook

This document is an analyst-facing runbook for using **Forensic Scout** to triage disk images and recover deleted artifacts while maintaining forensically-sound handling.

## 1) Evidence intake and safety controls

1. Store evidence in a dedicated case directory (read-only media or write-protected storage where possible).
2. Avoid mounting the image. Forensic Scout operates directly on the image file.
3. Apply read-only permissions as a local safeguard:

```bash
chmod a-w /path/to/evidence.img
ls -lah /path/to/evidence.img
```

## 2) Determine the correct offset (disk vs volume)

### A. Try partition discovery first

```bash
mmls /path/to/evidence.img
```

If `mmls` returns partitions, use the **Start** sector for the partition that contains the filesystem:
- Example: `--offset 2048`

### B. If `mmls` returns nothing useful

Some images are *volume images* where the filesystem begins at sector 0.

Confirm with:

```bash
file /path/to/evidence.img
fdisk -l /path/to/evidence.img
```

If output indicates NTFS directly (for example, OEM-ID "NTFS") and there are no partitions listed, run with:

- `--offset 0`

## 3) Run Forensic Scout

```bash
./forensic_scout.sh --target /path/to/evidence.img --offset 0 --case CASE001 --out /path/to/output
```

Recommended: capture the console output for auditability:

```bash
./forensic_scout.sh --target /path/to/evidence.img --offset 0 --case CASE001 --out /path/to/output | tee /path/to/output/forensic_scout_console.log
```

## 4) Validate recovery and integrity

After the run completes, cite these artifacts:

- `03_hashes/` - hashes for the image and recovered artifacts
- `01_image_metadata/fsstat.txt` - filesystem identification
- `02_file_lists/fls_deleted.txt` - deleted entries
- `04_recovered/deleted_manifest.csv` - recovery proof (what was recovered and where)
- `RUN_SUMMARY.md` - high-level summary suitable for reports

## 5) Static analysis and escalation

Forensic Scout performs **static-only** checks. If the recovered content is suspicious:

- Review `05_static_analysis/` and `06_redflags/`
- Keep executables non-runnable (for example, `.exe_`)
- Escalate to an isolated malware analysis workflow if required (Windows sandbox VM, dedicated tooling)

## 6) Common troubleshooting

- `permission denied`: run `chmod +x forensic_scout.sh`
- `zsh: no such file or directory: START_SECTOR`: replace placeholder text (`<START_SECTOR>`) with an actual integer value (for example, `2048`).
- Empty `fls` output: offset is likely wrong. Re-check `mmls` and confirm whether the image is a disk image or volume image.

## 7) Reporting guidance (what to include)

A minimal, defensible report typically documents:

- Evidence handling steps (read-only controls, no mounting)
- Filesystem identification (NTFS/ext/etc.)
- Deleted artifact discovery (deleted listing evidence)
- Recovery proof (manifest + recovered file path)
- Hash validation (integrity)
- Static analysis observations for suspicious artifacts (high-level indicators only)
