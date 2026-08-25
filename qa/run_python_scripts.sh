#!/usr/bin/env bash
# ============================================================================
# qa/run_python_scripts.sh
# ----------------------------------------------------------------------------
# Runs every standalone Python script in case_files/ that is known to be a
# "run on execution" analysis script (not a library module), patches its
# hardcoded INPUT_FILE / OUTPUT_XLSX paths to point at this run's workspace,
# and records pass/fail + tail-of-output into qa_reports/python_report.md.
#
# Add or remove filenames from SCRIPTS= below if the case file set changes.
# ============================================================================
set -uo pipefail

CASE_DIR="case_files"
WORK_DIR="qa_workspace"
REPORT_DIR="qa_reports"
mkdir -p "$WORK_DIR/outputs" "$WORK_DIR/output" "$REPORT_DIR"

WORKBOOK=$(ls "$CASE_DIR"/*.xlsx 2>/dev/null | head -n1)
if [ -z "$WORKBOOK" ]; then
  echo "[FATAL] No .xlsx workbook found in $CASE_DIR/"
  exit 1
fi
WORKBOOK_ABS="$(pwd)/$WORKBOOK"

SCRIPTS=(
  "Section2a_EDD_Customer_List_Analysis_Script.py"
  "Section4b_Typology_Analysis_Script.py"
  "Section4b_Suspect_Timeline_Script.py"
)
# Any file matching this pattern (e.g. a T10 self-merchant correction script)
# is added automatically so future renamed correction scripts are still caught.
shopt -s nullglob
for f in "$CASE_DIR"/TASK_7_4*.py; do
  SCRIPTS+=("$(basename "$f")")
done

REPORT="$REPORT_DIR/python_report.md"
echo "# Python Scripts QA Report" > "$REPORT"
echo "" >> "$REPORT"

FAIL_COUNT=0
TOTAL_COUNT=0

for script in "${SCRIPTS[@]}"; do
  SRC="$CASE_DIR/$script"
  if [ ! -f "$SRC" ]; then
    echo "[SKIP] $script not found in $CASE_DIR/"
    continue
  fi
  TOTAL_COUNT=$((TOTAL_COUNT+1))
  DEST="$WORK_DIR/$script"
  cp "$SRC" "$DEST"

  # Patch any hardcoded absolute input path to point at our workbook.
  python3 - "$DEST" "$WORKBOOK_ABS" <<'PYEOF'
import re, sys
dest, workbook = sys.argv[1], sys.argv[2]
with open(dest, encoding="utf-8") as f:
    content = f.read()
content = re.sub(r'INPUT_FILE\s*=\s*"[^"]*\.xlsx"', f'INPUT_FILE = "{workbook}"', content)
content = re.sub(r'"/mnt/user-data/outputs/', f'"{__import__("os").getcwd()}/qa_workspace/outputs/', content)
with open(dest, "w", encoding="utf-8") as f:
    f.write(content)
PYEOF

  echo "===== Running $script ====="
  LOG="$REPORT_DIR/${script%.py}.log"
  ( cd "$WORK_DIR" && python3 "$script" ) > "$LOG" 2>&1
  STATUS=$?

  if [ $STATUS -eq 0 ]; then
    echo "## ✅ $script — PASS" >> "$REPORT"
  else
    echo "## ❌ $script — FAIL (exit code $STATUS)" >> "$REPORT"
    FAIL_COUNT=$((FAIL_COUNT+1))
  fi
  echo '```' >> "$REPORT"
  tail -n 30 "$LOG" >> "$REPORT"
  echo '```' >> "$REPORT"
  echo "" >> "$REPORT"
done

echo "" >> "$REPORT"
echo "**Summary: $((TOTAL_COUNT-FAIL_COUNT))/$TOTAL_COUNT scripts passed**" >> "$REPORT"

echo ""
echo "Python scripts report written to $REPORT"
if [ $FAIL_COUNT -gt 0 ]; then
  exit 1
fi
