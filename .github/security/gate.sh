#!/usr/bin/env bash
# Consolidates SARIF results and enforces the Medium+ severity gate.
# Usage: gate.sh <sarif-dir> <allowlist-yaml> <out-json>
set -euo pipefail

sarif_dir="${1:?sarif dir required}"
allowlist="${2:?allowlist path required}"
out="${3:?output json required}"

# 1. Check for expired allowlist entries.
python3 - "$allowlist" <<'PY'
import sys, yaml
from datetime import date
path = sys.argv[1]
with open(path) as f:
    doc = yaml.safe_load(f) or {}
expired = []
for entry in doc.get("suppressions") or []:
    if entry.get("expires") and entry["expires"] < date.today():
        expired.append(entry["id"])
if expired:
    print(f"::error::Expired allowlist entries: {', '.join(expired)}")
    sys.exit(2)
PY

# 2. Collect all SARIF files.
mapfile -t sarifs < <(find "$sarif_dir" -type f -name '*.sarif' | sort)
if [[ ${#sarifs[@]} -eq 0 ]]; then
  echo "::error::No SARIF files found under $sarif_dir"
  exit 2
fi

# 3. Merge, count Medium+ findings (SARIF level in {error, warning}).
jq -s '{
  runs: (map(.runs) | add // []),
}' "${sarifs[@]}" > "$out"

count=$(jq '[.runs[].results[]? | select(.level=="error" or .level=="warning")] | length' "$out")
echo "medium_plus_findings=$count" >> "$GITHUB_OUTPUT"

echo "Medium+ findings: $count"

# 4. Emit a per-tool summary for the job summary tab.
jq -r '.runs[] | "\(.tool.driver.name): \([.results[]? | select(.level=="error" or .level=="warning")] | length) medium+ / \([.results[]?] | length) total"' \
   "$out" >> "$GITHUB_STEP_SUMMARY"

if (( count > 0 )); then
  echo "::error::Security gate failed: $count Medium+ findings"
  exit 1
fi
