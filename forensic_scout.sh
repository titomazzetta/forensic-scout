#!/usr/bin/env bash
# ==============================================================================
# Forensic Scout — Static Forensics Triage + Deleted-Artifact (Subset) Recovery
# License: MIT
#
# Purpose:
#   - Coursework/rubric-friendly, portfolio-ready CLI workflow.
#   - Static-only analysis (no execution of recovered artifacts).
#   - Disk image mode (NTFS) via SleuthKit OR directory mode (no deleted recovery).
#
# Debian/Kali installs:
#   sudo apt install -y sleuthkit file binutils unzip
# Optional (OFF by default):
#   sudo apt install -y yara clamav
# ==============================================================================

set -euo pipefail

BOLD="$(tput bold 2>/dev/null || true)"
RESET="$(tput sgr0 2>/dev/null || true)"

banner(){ echo; echo "${BOLD}==> $*${RESET}"; }
info(){ echo "    [*] $*"; }
warn(){ echo "    ${BOLD}[!]${RESET} $*" >&2; }
die(){ echo "    ${BOLD}[x]${RESET} $*" >&2; exit 1; }
have(){ command -v "$1" >/dev/null 2>&1; }

TARGET=""
OUTROOT="./output"
PROJECT_ROOT=""
CASE_NAME="case"
OFFSET_SECTORS=""             # SleuthKit sector offset
RECOVER_MODE="interesting"    # interesting|all|none
MAX_RECOVER=200
STR_CAP=4000000
KEYWORDS_FILE=""
MAKE_READONLY=0
RUN_YARA=0; YARA_RULES=""
RUN_CLAMAV=0

EXT_FILTER="exe|dll|sys|scr|ps1|bat|cmd|vbs|js|jse|wsf|lnk|zip|7z|rar|iso|img|pdf|docm|xlsm|pptm|csv"

usage(){
cat <<'USAGE'
Forensic Scout (static triage)

Usage:
  ./forensic_scout.sh --target <image_or_dir> [options]

Core:
  --project-root DIR       Create Unit5-style folders under DIR; default output -> DIR/notes
  --target PATH            Disk image file OR mounted/extracted directory (required)
  --out DIR                Output root directory (default: ./output)
  --case NAME              Case label used in output folder (default: case)
  --offset SECTORS         Partition offset in sectors (image mode); auto-detect if omitted
  --keywords FILE          IOC keyword list (one per line); built-in list if omitted

Recovery (image mode):
  --recover interesting    Recover only interesting deleted files (default)
  --recover all            Recover all deleted files (slow/huge)
  --recover none           Skip recovery
  --max-recover N          Cap recovered deleted files (default: 200)

Static analysis:
  --make-readonly          chmod a-w on image target (image mode only)
  --strings-cap-bytes N    Cap strings output per file (default: 4000000)
  --yara RULES_DIR         Optional YARA scan (requires yara)
  --clamav                 Optional ClamAV scan (requires clamscan)

Examples:
  ./forensic_scout.sh --target evidence.dd --case unit5
  ./forensic_scout.sh --target evidence.dd --offset 2048 --case unit5
  ./forensic_scout.sh --project-root ~/Documents/Unit5_Project --target ~/Documents/Unit5_Project/evidence/disk.img --case unit5 --make-readonly
USAGE
}

# Args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --project-root) PROJECT_ROOT="${2:-}"; shift 2;;
    --target) TARGET="${2:-}"; shift 2;;
    --out) OUTROOT="${2:-}"; shift 2;;
    --case) CASE_NAME="${2:-}"; shift 2;;
    --offset) OFFSET_SECTORS="${2:-}"; shift 2;;
    --keywords) KEYWORDS_FILE="${2:-}"; shift 2;;
    --recover) RECOVER_MODE="${2:-}"; shift 2;;
    --max-recover) MAX_RECOVER="${2:-}"; shift 2;;
    --strings-cap-bytes) STR_CAP="${2:-}"; shift 2;;
    --make-readonly) MAKE_READONLY=1; shift;;
    --yara) RUN_YARA=1; YARA_RULES="${2:-}"; shift 2;;
    --clamav) RUN_CLAMAV=1; shift;;
    -h|--help) usage; exit 0;;
    *) die "Unknown arg: $1 (use --help)";;
  esac
done

[[ -n "$TARGET" ]] || { usage; die "--target is required"; }
[[ -e "$TARGET" ]] || die "Target not found: $TARGET"
[[ "$RECOVER_MODE" =~ ^(interesting|all|none)$ ]] || die "--recover must be interesting|all|none"

if [[ -n "$PROJECT_ROOT" ]]; then
  mkdir -p "$PROJECT_ROOT"/{evidence,hashes,notes,recovered,screenshots,tools}
  if [[ "$OUTROOT" == "./output" ]]; then
    OUTROOT="$PROJECT_ROOT/notes"
  fi
fi

TS="$(date +"%Y%m%d_%H%M%S")"
RUN_DIR="${OUTROOT%/}/${CASE_NAME}_run_${TS}"
META_DIR="$RUN_DIR/01_image_metadata"
LIST_DIR="$RUN_DIR/02_file_lists"
HASH_DIR="$RUN_DIR/03_hashes"
REC_DIR="$RUN_DIR/04_recovered"
ANA_DIR="$RUN_DIR/05_static_analysis"
FLAG_DIR="$RUN_DIR/06_redflags"
LOG_DIR="$RUN_DIR/logs"

mkdir -p "$META_DIR" "$LIST_DIR" "$HASH_DIR" "$REC_DIR" "$ANA_DIR" "$FLAG_DIR" "$LOG_DIR"
LOG="$LOG_DIR/run.log"
exec > >(tee -a "$LOG") 2>&1

banner "Forensic Scout starting"
info "Run directory: $RUN_DIR"
info "Target: $TARGET"

# Save file signature early (useful when mmls fails on volume images)
if [[ -f "$TARGET" ]] && have file; then
  file -s "$TARGET" | tee "$META_DIR/file_type.txt" >/dev/null || true
fi

# Keywords
BUILTIN_KW="$FLAG_DIR/ioc_keywords_builtin.txt"
cat > "$BUILTIN_KW" <<'KWS'
powershell
cmd.exe
rundll32
regsvr32
schtasks
wmic
bitsadmin
certutil
mshta
wscript
cscript
base64
frombase64string
invoke-webrequest
downloadstring
webclient
http://
https://
pastebin
discord
telegram
tor
.onion
mimikatz
lsass
sam
psexec
keylogger
ransom
bitcoin
monero
xmrig
ntds.dit
KWS

if [[ -n "$KEYWORDS_FILE" ]]; then
  [[ -f "$KEYWORDS_FILE" ]] || die "Keywords file not found: $KEYWORDS_FILE"
  KEYWORDS="$KEYWORDS_FILE"
else
  KEYWORDS="$BUILTIN_KW"
fi

banner "Environment snapshot"
{
  echo "Timestamp: $(date -Is)"
  echo "Hostname: $(hostname)"
  echo "User: $(whoami)"
  echo "Kernel: $(uname -a)"
  echo "Target: $TARGET"
  echo "Tools:"
  for t in sha256sum md5sum file strings mmls fsstat fls icat unzip zipinfo yara clamscan; do
    if have "$t"; then echo "  - $t: $(command -v $t)"; else echo "  - $t: (missing)"; fi
  done
} | tee "$META_DIR/00_environment.txt" >/dev/null

banner "Hashing target"
if [[ -f "$TARGET" ]]; then
  have sha256sum && sha256sum "$TARGET" | tee "$HASH_DIR/target_image.sha256.txt" >/dev/null || warn "sha256sum missing"
  have md5sum && md5sum "$TARGET" | tee "$HASH_DIR/target_image.md5.txt" >/dev/null || warn "md5sum missing"
else
  if have sha256sum; then
    (cd "$TARGET" && find . -type f -print0 | sort -z | xargs -0 sha256sum) > "$HASH_DIR/target_directory_manifest.sha256.txt"
  else
    warn "sha256sum missing; skipping directory manifest"
  fi
fi

MODE="dir"; [[ -f "$TARGET" ]] && MODE="image"

auto_offset(){
  local img="$1" out="$2"
  have mmls || die "mmls missing (install sleuthkit)"
  if ! mmls "$img" > "$out" 2>&1; then
    return 1
  fi
  awk 'BEGIN{off=""} /^[0-9]+/{desc=""; for(i=6;i<=NF;i++) desc=desc $i " "; if(off=="" && (desc~/(NTFS|Basic data|Microsoft)/i)) off=$3} END{print off}' "$out"
}

if [[ "$MODE" == "image" ]]; then
  banner "Image mode (SleuthKit)"
  for t in fsstat fls icat; do have "$t" || die "$t missing (install sleuthkit)"; done

  if [[ $MAKE_READONLY -eq 1 ]]; then
    chmod a-w "$TARGET" 2>/dev/null || warn "Could not chmod a-w (permissions?)"
  fi

  if [[ -z "$OFFSET_SECTORS" ]]; then
    banner "Detecting partition offset (sectors) via mmls"
    if OFFSET_SECTORS="$(auto_offset "$TARGET" "$META_DIR/mmls.txt")"; then
      [[ -n "$OFFSET_SECTORS" ]] || { warn "Offset not detected; defaulting to 0"; OFFSET_SECTORS=0; }
    else
      warn "mmls failed (likely volume image, no partition table). Using offset 0."
      OFFSET_SECTORS=0
    fi
  else
    have mmls && mmls "$TARGET" | tee "$META_DIR/mmls.txt" >/dev/null || true
  fi
  info "Partition offset (sectors): $OFFSET_SECTORS"

  banner "fsstat"
  fsstat -o "$OFFSET_SECTORS" "$TARGET" | tee "$META_DIR/fsstat.txt" >/dev/null || true

  banner "fls (allocated)"
  fls -o "$OFFSET_SECTORS" -r -p "$TARGET" | tee "$LIST_DIR/fls_allocated.txt" >/dev/null

  banner "fls (deleted)"
  fls -o "$OFFSET_SECTORS" -r -p -d "$TARGET" | tee "$LIST_DIR/fls_deleted.txt" >/dev/null

  banner "Suspicious paths"
  {
    echo "# allocated"; grep -Eai "\.(${EXT_FILTER})$" "$LIST_DIR/fls_allocated.txt" || true
    grep -Eai "\.[a-z0-9]{1,5}\.(${EXT_FILTER})$" "$LIST_DIR/fls_allocated.txt" || true
    echo; echo "# deleted"; grep -Eai "\.(${EXT_FILTER})$" "$LIST_DIR/fls_deleted.txt" || true
    grep -Eai "\.[a-z0-9]{1,5}\.(${EXT_FILTER})$" "$LIST_DIR/fls_deleted.txt" || true
  } > "$LIST_DIR/suspicious_paths.txt"

  banner "Recovery (deleted) — $RECOVER_MODE"
  mkdir -p "$REC_DIR/deleted"
  : > "$REC_DIR/deleted_manifest.csv"; : > "$REC_DIR/deleted_manifest_failed.csv"

  parse_inode_path(){
    local line="$1" tok inode path
    tok="$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i~/:/){print $i; exit}}')"
    inode="${tok%%:*}"
    path="${line#*: }"; [[ "$path" == "$line" ]] && path="${line#*:}"; path="${path# }"
    echo "$inode|$path"
  }

  # Robust: matches r/r ... and -/r * ...
  is_file_line(){
    local t
    t="$(echo "$1" | awk '{print $1}')"
    [[ "$t" == */r ]]
  }

  is_interesting(){ echo "$1" | grep -Eai "(\.(${EXT_FILTER})$|\.[a-z0-9]{1,5}\.(${EXT_FILTER})$)" >/dev/null; }

  REC_ATTEMPTS=0
  REC_SUCCESS=0

  recover_one(){
    local inode="$1" path="$2"
    local safe out
    safe="$(echo "$path" | sed 's#^/##' | tr '/\\\n\r\t' '____' | tr -cd '[:alnum:]._-')"
    [[ -n "$safe" ]] || safe="inode_${inode}"
    out="$REC_DIR/deleted/${inode}__${safe}"
    [[ -f "$out" ]] && return 0
    if icat -o "$OFFSET_SECTORS" "$TARGET" "$inode" > "$out" 2>/dev/null; then
      echo "$inode,$path,$out" >> "$REC_DIR/deleted_manifest.csv"
      REC_SUCCESS=$((REC_SUCCESS+1))
    else
      rm -f "$out" 2>/dev/null || true
      echo "$inode,$path,(recover_failed)" >> "$REC_DIR/deleted_manifest_failed.csv"
    fi
  }

  if [[ "$RECOVER_MODE" == "none" ]]; then
    warn "Skipping recovery"
  else
    while IFS= read -r line; do
      is_file_line "$line" || continue
      rec="$(parse_inode_path "$line")"
      inode="${rec%%|*}"; path="${rec#*|}"
      if [[ "$RECOVER_MODE" == "interesting" ]]; then is_interesting "$path" || continue; fi
      recover_one "$inode" "$path"
      REC_ATTEMPTS=$((REC_ATTEMPTS+1))
      [[ $REC_ATTEMPTS -lt $MAX_RECOVER ]] || { warn "Reached cap ($MAX_RECOVER)"; break; }
    done < "$LIST_DIR/fls_deleted.txt"
    info "Recovered attempts: $REC_ATTEMPTS"
    info "Recovered success:  $REC_SUCCESS"
  fi

else
  banner "Directory mode (no deleted recovery)"
  find "$TARGET" -type f -print | tee "$LIST_DIR/find_all_files.txt" >/dev/null
  {
    grep -Eai "\.(${EXT_FILTER})$" "$LIST_DIR/find_all_files.txt" || true
    grep -Eai "\.[a-z0-9]{1,5}\.(${EXT_FILTER})$" "$LIST_DIR/find_all_files.txt" || true
  } > "$LIST_DIR/suspicious_paths.txt"
fi

banner "Static analysis (file magic, strings, IOC hits)"
mkdir -p "$ANA_DIR/file_reports" "$ANA_DIR/strings" "$FLAG_DIR/potential_malware"

CANDS="$ANA_DIR/candidates.txt"; : > "$CANDS"
[[ -d "$REC_DIR/deleted" ]] && find "$REC_DIR/deleted" -type f -print >> "$CANDS" || true
[[ "$MODE" == "dir" ]] && grep -Eai "\.(${EXT_FILTER})$" "$LIST_DIR/find_all_files.txt" >> "$CANDS" || true
sort -u "$CANDS" -o "$CANDS"

MISMATCH="$ANA_DIR/file_magic_mismatch.csv"
echo "path,extension,file_magic" > "$MISMATCH"
HITS="$FLAG_DIR/ioc_hits_summary.txt"; : > "$HITS"

cap_strings(){
  local f="$1" out="$2"
  if have strings; then
    strings -a -n 4 "$f" 2>/dev/null | head -c "$STR_CAP" > "$out" || true
  else
    warn "strings missing; skipping $f"
  fi
}

idx=0
while IFS= read -r f; do
  [[ -f "$f" ]] || continue
  idx=$((idx+1))
  bn="$(basename "$f")"
  rep="$ANA_DIR/file_reports/${idx}__${bn}.txt"
  {
    echo "Path: $f"
    echo "Size: $(stat -c%s "$f" 2>/dev/null || wc -c <"$f") bytes"
    have sha256sum && echo "SHA256: $(sha256sum "$f" | awk '{print $1}')" || true
    have md5sum && echo "MD5: $(md5sum "$f" | awk '{print $1}')" || true
    have file && echo "file: $(file -b "$f")" || true
  } > "$rep"

  if have file; then
    ext="${f##*.}"; ext="${ext,,}"
    magic="$(file -b "$f" | tr ',' ' ')"
    if [[ "$ext" =~ ^(csv|txt|pdf|jpg|jpeg|png)$ ]] && echo "$magic" | grep -Eai "PE32|MS-DOS|executable|ELF|Mach-O|DLL" >/dev/null; then
      echo "\"$f\",\"$ext\",\"$magic\"" >> "$MISMATCH"
    fi
  fi

  sfile="$ANA_DIR/strings/${idx}__${bn}.strings.txt"
  cap_strings "$f" "$sfile"

  if [[ -s "$sfile" ]]; then
    hits="$(grep -Ein -f "$KEYWORDS" "$sfile" || true)"
    if [[ -n "$hits" ]]; then
      {
        echo "=== IOC hits in: $f"
        echo "$hits"
        echo
      } >> "$HITS"
      cp -n "$f" "$FLAG_DIR/potential_malware/" 2>/dev/null || true
    fi
  fi
done < "$CANDS"

banner "ZIP inventory"
ZIPINV="$ANA_DIR/zip_inventory.txt"; : > "$ZIPINV"
if have zipinfo || have unzip; then
  while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    echo "$f" | grep -Eai "\.zip$" >/dev/null || continue
    {
      echo "=== ZIP: $f"
      have zipinfo && zipinfo -1 "$f" 2>/dev/null || true
      have unzip && unzip -t "$f" 2>/dev/null || true
      echo
    } >> "$ZIPINV"
  done < "$CANDS"
else
  warn "zipinfo/unzip missing"
fi

if [[ $RUN_YARA -eq 1 ]]; then
  banner "Optional: YARA"
  if have yara && [[ -d "$YARA_RULES" ]]; then
    yout="$ANA_DIR/yara_hits.txt"; : > "$yout"
    while IFS= read -r f; do
      [[ -f "$f" ]] || continue
      yara -r "$YARA_RULES" "$f" >> "$yout" 2>/dev/null || true
    done < "$CANDS"
  else
    warn "yara missing or rules dir not found"
  fi
fi

if [[ $RUN_CLAMAV -eq 1 ]]; then
  banner "Optional: ClamAV"
  if have clamscan; then
    clamscan -r --log="$ANA_DIR/clamav_scan.log" "$FLAG_DIR/potential_malware" 2>/dev/null || true
  else
    warn "clamscan missing"
  fi
fi

banner "Run summary"
IOC_COUNT=$(grep -c '^=== IOC hits in:' "$HITS" 2>/dev/null || true)
REC_COUNT=$(wc -l < "$REC_DIR/deleted_manifest.csv" 2>/dev/null || echo 0)
MIS_COUNT=$(( ( $(wc -l < "$MISMATCH" 2>/dev/null || echo 1) ) - 1 ))

cat > "$RUN_DIR/RUN_SUMMARY.md" <<EOF
# Forensic Scout Run Summary

- **Run ID:** ${CASE_NAME}_run_${TS}
- **Target:** \`${TARGET}\`
- **Mode:** \`${MODE}\`
- **Partition offset (sectors):** \`${OFFSET_SECTORS:-N/A}\`
- **Recovered deleted files (manifest rows):** \`${REC_COUNT}\`
- **"Not what it seems" mismatches:** \`${MIS_COUNT}\`
- **IOC-hit files:** \`${IOC_COUNT}\`

## Primary artifacts to cite / screenshot
- Hashes: \`03_hashes/\`
- Partition + FS stats: \`01_image_metadata/mmls.txt\`, \`01_image_metadata/fsstat.txt\` (image mode)
- Listings: \`02_file_lists/fls_allocated.txt\`, \`02_file_lists/fls_deleted.txt\`
- Recovery proof: \`04_recovered/deleted_manifest.csv\`
- IOC hits: \`06_redflags/ioc_hits_summary.txt\`
- Mismatch checks: \`05_static_analysis/file_magic_mismatch.csv\`
- Full command log: \`logs/run.log\`

## Static-only assurance
No recovered executable/script was executed during this run.
EOF

banner "Done"
info "Summary: $RUN_DIR/RUN_SUMMARY.md"
info "Log: $LOG"
