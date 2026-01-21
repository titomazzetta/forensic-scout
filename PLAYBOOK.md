# Playbook (Rubric-Aligned) + Screenshot Checklist

## Run
```bash
./forensic_scout.sh --target /path/to/evidence.dd --case unit5
```

If offset is needed:
```bash
mmls /path/to/evidence.dd
./forensic_scout.sh --target /path/to/evidence.dd --offset <START_SECTORS> --case unit5
```

## Screenshot checklist (minimum)
- Hash outputs: `03_hashes/target_image.sha256.txt` and `.md5.txt`
- Partition + fsstat: `01_image_metadata/mmls.txt`, `01_image_metadata/fsstat.txt`
- Allocated + deleted listings: `02_file_lists/fls_allocated.txt`, `02_file_lists/fls_deleted.txt`
- Recovery proof: `04_recovered/deleted_manifest.csv`
- IOC hits summary: `06_redflags/ioc_hits_summary.txt`
- “Not what it seems”: `05_static_analysis/file_magic_mismatch.csv`
- Terminal showing the script command and the final “Done” banner

## Re-run guidance
Prefer re-running (creates new timestamped folder) rather than deleting outputs.
