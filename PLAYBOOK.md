# Forensic Scout Playbook

This playbook provides an **operator-focused** procedure for static triage runs and evidence-grade documentation. It is written to be repeatable, auditable, and easy to translate into a formal report.

---

## 1) Setup a clean project workspace

```bash
mkdir -p ~/Documents/Case_Triage
cd ~/Documents/Case_Triage
mkdir -p evidence hashes notes recovered screenshots tools
```

Place your image in `evidence/` and remove write permissions:

```bash
mv /path/to/fullstack_lab.img evidence/
chmod a-w evidence/fullstack_lab.img
ls -lh evidence/fullstack_lab.img
```

---

## 2) Install dependencies (Debian/Kali)

```bash
sudo apt update
sudo apt install -y sleuthkit file binutils unzip
```

Optional:
```bash
sudo apt install -y yara clamav
```

---

## 3) Acquire/Update the tool

```bash
cd tools
git clone https://github.com/titomazzetta/forensic-scout.git
cd forensic-scout
chmod +x forensic_scout.sh
```

To update later:
```bash
cd ~/Documents/Case_Triage/tools/forensic-scout
git pull
```

---

## 4) Run Forensic Scout (recommended flags)

```bash
cd ~/Documents/Case_Triage

./tools/forensic-scout/forensic_scout.sh   --project-root ~/Documents/Case_Triage   --target ~/Documents/Case_Triage/evidence/fullstack_lab.img   --case unit5   --recover interesting   --max-recover 200   --make-readonly
```

---

## 5) Identify latest run directory

```bash
LATEST_RUN="$(ls -1dt ~/Documents/Case_Triage/notes/unit5_run_* | head -n 1)"
echo "$LATEST_RUN"
```

---

## 6) Post-run validation (operator proof points)

### Evidence permissions (read-only)
```bash
ls -lh ~/Documents/Case_Triage/evidence/fullstack_lab.img
```

### File system identification
```bash
sed -n '1,8p' "$LATEST_RUN/01_image_metadata/file_type.txt"
sed -n '1,40p' "$LATEST_RUN/01_image_metadata/fsstat.txt"
```

### Deleted file discovery
```bash
grep -nE "^\-\/r|\*|\.exe|\.zip" "$LATEST_RUN/02_file_lists/fls_deleted.txt" | head -n 60
```

### Recovery proof (manifest + recovered files)
```bash
sed -n '1,40p' "$LATEST_RUN/04_recovered/deleted_manifest.csv"
ls -lh "$LATEST_RUN/04_recovered/deleted" | head
```

### Hash validation of the recovered artifact(s)
```bash
DEL_EXE="$(cut -d, -f3 "$LATEST_RUN/04_recovered/deleted_manifest.csv")"
md5sum "$DEL_EXE"
sha1sum "$DEL_EXE"
sha256sum "$DEL_EXE"
```

### Static triage indicators (do NOT execute)
```bash
file "$DEL_EXE"
hexdump -C "$DEL_EXE" | head -n 12
sed -n '1,140p' "$LATEST_RUN/06_redflags/ioc_hits_summary.txt"
```

### Run summary (for reporting)
```bash
sed -n '1,160p' "$LATEST_RUN/RUN_SUMMARY.md"
```

---

## 7) Optional: export allocated artifacts for comparison (static-only)

If `fls_allocated.txt` shows allocated items you want to include in your analysis, you can extract them by inode using `icat`. Example:

```bash
mkdir -p "$LATEST_RUN/04_recovered/allocated"

# Example inodes (replace with your fls output)
icat -o 0 ~/Documents/Case_Triage/evidence/fullstack_lab.img 64-128-2 > "$LATEST_RUN/04_recovered/allocated/calc.exe"
icat -o 0 ~/Documents/Case_Triage/evidence/fullstack_lab.img 65-128-2 > "$LATEST_RUN/04_recovered/allocated/Marketing+Data.zip"

file "$LATEST_RUN/04_recovered/allocated/calc.exe"
file "$LATEST_RUN/04_recovered/allocated/Marketing+Data.zip"
zipinfo -1 "$LATEST_RUN/04_recovered/allocated/Marketing+Data.zip" | head -n 80
```

---

## 8) Screenshot checklist (report-ready)

Capture screenshots that demonstrate:

### Evidence handling / integrity
- `ls -lh evidence/fullstack_lab.img` showing read-only permissions
- `03_hashes/target_image.sha256.txt` and `03_hashes/target_image.md5.txt`

### File system identification
- `01_image_metadata/file_type.txt`
- First page of `01_image_metadata/fsstat.txt` showing **File System Type**

### Deleted file discovery + recovery
- Excerpt of `02_file_lists/fls_deleted.txt` showing deleted entries
- `04_recovered/deleted_manifest.csv`
- Directory listing of `04_recovered/deleted/` showing recovered files and sizes

### Validation + static triage
- `md5sum/sha1sum/sha256sum` output of the recovered file
- `file <recovered>` output
- `hexdump -C <recovered> | head` showing `MZ` / `PE` header
- `06_redflags/ioc_hits_summary.txt`
- `RUN_SUMMARY.md` excerpt

### Full run logging
- Terminal showing the run command and the final **Done** banner
- Optional: `logs/run.log` (first lines + tail) for audit trail

---

## 9) Troubleshooting

### A) `mmls` fails / `mmls.txt` is empty
- Many images are **NTFS volume images** (no partition table).
- This is normal; use **offset 0**.
- Confirm with:
  ```bash
  fsstat ~/Documents/Case_Triage/evidence/fullstack_lab.img | head -n 30
  ```

### B) `fls -o 2048` says “Cannot determine file system type”
- Offset likely incorrect.
- For volume images, use offset `0` or omit `--offset`.

### C) Zero recovered files
- Confirm deleted entries exist in:
  - `02_file_lists/fls_deleted.txt`
- Ensure the deleted line format includes `-/r` (deleted regular file).
- Increase `--max-recover` if needed and verify `--recover interesting` isn’t filtering out your target.

### D) Terminal paste “garbage” / stuck prompt
- Don’t paste your shell prompt characters (`┌── ...`) back into the terminal.
- If the terminal enters a continuation state, hit `Ctrl+C` to reset.

---

## 10) Re-run guidance

Prefer re-running (creates a new timestamped folder) rather than deleting prior outputs. This preserves auditability and supports comparing iterations (e.g., different offsets, keyword sets, recovery modes).
