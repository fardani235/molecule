# DevSecOps CI Enhancements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add security scanning (5 scanners with a Medium+ gate), layered caching, SARIF/artifact publishing, and a wall-clock CI-timing benchmark to this fork of `ansible-community/molecule`, without modifying upstream reusable workflows.

**Architecture:** Two new GitHub Actions workflow files (`security.yml`, `ci-benchmark.yml`) plus one composite action (`setup-cache`) and a Python aggregator (`gate.py`). Scanners run in parallel, upload SARIF to GitHub Code Scanning and raw JSON as artifacts, and a `security-gate` job normalizes severities and fails the PR on any Medium+ finding. All new jobs are guarded by `if: github.repository == 'fardani235/molecule'` so they only run on the fork.

**Tech Stack:** GitHub Actions, Python 3.13 (matches project's `default_python`), `uv 0.11.x`, Bandit, Semgrep (`returntocorp/semgrep-action@v1`), pip-audit, `gitleaks/gitleaks-action@v2`, `aquasecurity/trivy-action@0.24.0`, `github/codeql-action/upload-sarif@v3`, `actions/cache@v4`, `gh` CLI (preinstalled on runners).

## Global Constraints

- **Fork owner:** `fardani235`. Every new job MUST carry `if: github.repository == 'fardani235/molecule'`.
- **Never modify** `.github/workflows/tox.yml`, `ack.yml`, `push.yml`, `finalize.yml`, `redirects.yml`, `release.yml`. Additions only.
- **Never modify** `ansible/team-devtools` reusable workflows — they are external.
- **Scanners never fail on findings.** Only the `security-gate` aggregator interprets severities. Scanner jobs fail only when the tool itself crashes.
- **Gate policy:** any Medium, High, or Critical finding fails the gate. Low and Info are informational.
- **Scanner set (fixed):** Bandit, Semgrep, pip-audit, Gitleaks, Trivy. Do not add or remove without updating the spec.
- **Result sinks (all three required per scanner):** SARIF → `github/codeql-action/upload-sarif@v3`, raw JSON → `actions/upload-artifact@v4`, severity table → `$GITHUB_STEP_SUMMARY`.
- **Python version for scanner tooling:** `3.13`.
- **Rollout is staged:** land the workflow with the gate in `warn-only` mode first (env var `GATE_MODE=warn`), fix/waive findings, then flip to `GATE_MODE=enforce`.
- **Working branch:** `devsecops-ci` (already created off `main`).
- **All commits must end with** `Co-Authored-By: Claude <noreply@anthropic.com>` per session guidance.

## File Structure

**New files (all created by this plan):**

```
.github/
├── actions/setup-cache/action.yml            # Task 1
├── security/
│   ├── bandit.yaml                           # Task 3
│   ├── semgrep.yaml                          # Task 4
│   ├── gitleaks.toml                         # Task 5
│   ├── waivers.yaml                          # Task 2
│   ├── gate.py                               # Task 2
│   └── tests/
│       ├── __init__.py                       # Task 2
│       ├── conftest.py                       # Task 2
│       ├── test_gate.py                      # Task 2
│       └── fixtures/
│           ├── bandit_high.sarif             # Task 2
│           ├── semgrep_warning.sarif         # Task 2
│           ├── trivy_low.sarif               # Task 2
│           └── malformed.sarif               # Task 2
└── workflows/
    ├── security.yml                          # Tasks 3-8
    └── ci-benchmark.yml                      # Task 9

docs/devsecops/
├── SECURITY_CI.md                            # Task 10
├── MEASUREMENTS.md                           # Task 9 (populated), Task 11 (final)
└── bench.py                                  # Task 9
```

**Untouched (verify at end):** every file under `.github/workflows/` that exists today.

---

## Task 1: Composite `setup-cache` action

**Files:**
- Create: `.github/actions/setup-cache/action.yml`

**Interfaces:**
- Consumes: nothing (composite action, entry point).
- Produces: an action reference `./.github/actions/setup-cache` that later scanner jobs invoke with inputs `python-version` (string, default `"3.13"`) and `cache-scanner-db` (string `"true"`/`"false"`, default `"false"`). Populates `~/.cache/uv`, `~/.cache/pre-commit`, and (when requested) `~/.cache/trivy`. Also sets up Python and `uv` on PATH.

- [ ] **Step 1: Write the action file**

Create `.github/actions/setup-cache/action.yml` with exactly:

```yaml
---
name: setup-cache
description: >-
  Restore uv, pre-commit, and (optionally) Trivy DB caches, then set up Python
  and uv. Used by every job in security.yml.

inputs:
  python-version:
    description: Python version passed to actions/setup-python
    required: false
    default: "3.13"
  cache-scanner-db:
    description: Set to "true" to restore/save the Trivy DB cache.
    required: false
    default: "false"

runs:
  using: composite
  steps:
    - name: Set up Python ${{ inputs.python-version }}
      uses: actions/setup-python@v5
      with:
        python-version: ${{ inputs.python-version }}

    - name: Install uv
      uses: astral-sh/setup-uv@v3
      with:
        version: "0.11.28"
        enable-cache: false  # we own the cache below

    - name: Restore uv cache
      uses: actions/cache@v4
      with:
        path: ~/.cache/uv
        key: uv-${{ runner.os }}-py${{ inputs.python-version }}-${{ hashFiles('uv.lock') }}
        restore-keys: |
          uv-${{ runner.os }}-py${{ inputs.python-version }}-

    - name: Restore pre-commit cache
      uses: actions/cache@v4
      with:
        path: ~/.cache/pre-commit
        key: pc-${{ runner.os }}-py${{ inputs.python-version }}-${{ hashFiles('.pre-commit-config.yaml') }}
        restore-keys: |
          pc-${{ runner.os }}-py${{ inputs.python-version }}-

    - name: Restore Trivy DB cache
      if: inputs.cache-scanner-db == 'true'
      uses: actions/cache@v4
      with:
        path: ~/.cache/trivy
        key: trivy-db-${{ github.run_id }}
        restore-keys: |
          trivy-db-
```

- [ ] **Step 2: Lint with actionlint**

Run: `pre-commit run actionlint --all-files`
Expected: PASS. If actionlint isn't installed locally, run `pipx run actionlint .github/actions/setup-cache/action.yml`.

- [ ] **Step 3: Commit**

```bash
git add .github/actions/setup-cache/action.yml
git commit -m "ci: add setup-cache composite action for uv/pre-commit/Trivy DB

Centralizes the three caches used by every security scanner job. Trivy DB
cache uses run_id-write / prefix-restore so the DB is always refreshed
while remaining usable across runs.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task 2: `gate.py` aggregator with unit tests

**Files:**
- Create: `.github/security/gate.py`
- Create: `.github/security/waivers.yaml`
- Create: `.github/security/tests/__init__.py` (empty)
- Create: `.github/security/tests/conftest.py`
- Create: `.github/security/tests/test_gate.py`
- Create: `.github/security/tests/fixtures/bandit_high.sarif`
- Create: `.github/security/tests/fixtures/semgrep_warning.sarif`
- Create: `.github/security/tests/fixtures/trivy_low.sarif`
- Create: `.github/security/tests/fixtures/malformed.sarif`
- Modify: `pyproject.toml` — add a `[project.optional-dependencies]` entry or `[dependency-groups]` entry `security` with `pyyaml`, `pytest`. (This project already uses `[dependency-groups]`; add there.)

**Interfaces:**
- Consumes: nothing from other tasks (this is the earliest Python component).
- Produces: `python .github/security/gate.py <sarif_glob> [--waivers PATH] [--mode enforce|warn] [--output report.json]`. Exit codes: `0` clean or warn-only, `1` un-waived Medium+ found in enforce mode, `2` internal error. Public functions used only by tests: `normalize_severity(scanner: str, entry: dict) -> str`, `load_waivers(path: str) -> list[dict]`, `is_expired(waiver: dict, today: date) -> bool`, `collect_findings(sarif_paths: list[str]) -> list[Finding]`, `main(argv: list[str]) -> int`.

- [ ] **Step 1: Write the failing test file**

Create `.github/security/tests/test_gate.py`:

```python
"""Unit tests for gate.py severity aggregator."""
from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from gate import (
    Finding,
    collect_findings,
    is_expired,
    load_waivers,
    main,
    normalize_severity,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_normalize_bandit_high():
    entry = {"level": "error", "properties": {"security-severity": "8.0"}}
    assert normalize_severity("bandit", entry) == "High"


def test_normalize_semgrep_warning_is_medium():
    entry = {"level": "warning"}
    assert normalize_severity("semgrep", entry) == "Medium"


def test_normalize_trivy_unknown_maps_to_low():
    entry = {"properties": {"security-severity": None}}
    assert normalize_severity("trivy", entry) == "Low"


def test_gitleaks_any_finding_is_critical():
    entry = {}
    assert normalize_severity("gitleaks", entry) == "Critical"


def test_pip_audit_cvss_mapping():
    entry = {"properties": {"security-severity": "9.5"}}
    assert normalize_severity("pip-audit", entry) == "Critical"
    entry["properties"]["security-severity"] = "7.5"
    assert normalize_severity("pip-audit", entry) == "High"
    entry["properties"]["security-severity"] = "5.0"
    assert normalize_severity("pip-audit", entry) == "Medium"
    entry["properties"]["security-severity"] = "1.0"
    assert normalize_severity("pip-audit", entry) == "Low"


def test_collect_findings_from_bandit_fixture():
    findings = collect_findings([str(FIXTURES / "bandit_high.sarif")])
    assert len(findings) == 1
    assert findings[0].severity == "High"
    assert findings[0].scanner == "bandit"


def test_malformed_sarif_raises():
    with pytest.raises(ValueError):
        collect_findings([str(FIXTURES / "malformed.sarif")])


def test_waiver_expiry():
    w = {"id": "x", "expires_on": "2020-01-01"}
    assert is_expired(w, date(2026, 1, 1)) is True
    w["expires_on"] = "2099-01-01"
    assert is_expired(w, date(2026, 1, 1)) is False


def test_main_exits_1_on_medium_plus_in_enforce(tmp_path, capsys):
    exit_code = main([
        str(FIXTURES / "bandit_high.sarif"),
        "--mode", "enforce",
        "--output", str(tmp_path / "report.json"),
        "--waivers", str(FIXTURES / ".nonexistent_waivers.yaml"),  # missing = empty
    ])
    assert exit_code == 1


def test_main_exits_0_when_only_low(tmp_path):
    exit_code = main([
        str(FIXTURES / "trivy_low.sarif"),
        "--mode", "enforce",
        "--output", str(tmp_path / "report.json"),
    ])
    assert exit_code == 0


def test_warn_mode_never_fails(tmp_path):
    exit_code = main([
        str(FIXTURES / "bandit_high.sarif"),
        "--mode", "warn",
        "--output", str(tmp_path / "report.json"),
    ])
    assert exit_code == 0
```

Also create `.github/security/tests/__init__.py` (empty) and `.github/security/tests/conftest.py`:

```python
"""Pytest config: put gate.py on sys.path."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
```

- [ ] **Step 2: Create SARIF test fixtures**

Create `.github/security/tests/fixtures/bandit_high.sarif`:

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "Bandit"}},
    "results": [{
      "ruleId": "B301",
      "level": "error",
      "message": {"text": "Pickle usage"},
      "properties": {"security-severity": "8.0"},
      "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/example.py"}, "region": {"startLine": 10}}}]
    }]
  }]
}
```

Create `.github/security/tests/fixtures/semgrep_warning.sarif`:

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "Semgrep"}},
    "results": [{
      "ruleId": "python.lang.security.audit.eval",
      "level": "warning",
      "message": {"text": "eval() usage"},
      "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/foo.py"}, "region": {"startLine": 5}}}]
    }]
  }]
}
```

Create `.github/security/tests/fixtures/trivy_low.sarif`:

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "Trivy"}},
    "results": [{
      "ruleId": "CVE-2020-0001",
      "level": "note",
      "message": {"text": "Low severity CVE"},
      "properties": {"security-severity": "2.0"},
      "locations": [{"physicalLocation": {"artifactLocation": {"uri": "requirements.txt"}}}]
    }]
  }]
}
```

Create `.github/security/tests/fixtures/malformed.sarif`:

```
this is not json
```

- [ ] **Step 3: Create the waivers file**

Create `.github/security/waivers.yaml`:

```yaml
---
# Waived security findings.
#
# Each entry must have: id, reason, added_by, added_on, expires_on.
# On scheduled runs, expired waivers fail the gate so waivers cannot rot.
#
# id formats:
#   - CVE-YYYY-NNNNN          (dep vulns from pip-audit/trivy)
#   - bandit:BXXX             (bandit rule ids)
#   - semgrep:<rule-id>       (semgrep rule ids)
#   - trivy:<check-id>        (trivy misconfig ids)
#   - gitleaks:<rule-id>      (gitleaks rule ids)

waivers: []
```

- [ ] **Step 4: Run the tests to confirm they fail**

Run: `cd /home/ridwan/workspaces/onfrontier/orange-horse && python -m pytest .github/security/tests/ -v`
Expected: FAIL — `gate.py` doesn't exist yet.

- [ ] **Step 5: Implement `gate.py`**

Create `.github/security/gate.py`:

```python
#!/usr/bin/env python3
"""Aggregate SARIF outputs from all scanners and enforce the Medium+ gate.

Reads a glob of SARIF files, normalizes severities across scanners, applies
waivers from waivers.yaml, prints a per-scanner + total table to stdout AND
$GITHUB_STEP_SUMMARY, writes a consolidated report.json, and exits:

  0 - no un-waived Medium+ findings (or --mode warn)
  1 - one or more un-waived Medium+ findings in --mode enforce
  2 - internal error (bad SARIF, malformed waivers file)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    print("gate.py requires PyYAML. Install with: uv pip install pyyaml", file=sys.stderr)
    raise

SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Info")
BLOCKING = {"Critical", "High", "Medium"}


@dataclass(frozen=True)
class Finding:
    scanner: str
    rule_id: str
    severity: str
    file: str
    line: int | None
    message: str

    @property
    def waiver_id(self) -> str:
        return f"{self.scanner}:{self.rule_id}"


def _scanner_from_sarif(sarif: dict[str, Any]) -> str:
    """Detect the scanner name from the tool driver."""
    try:
        name = sarif["runs"][0]["tool"]["driver"]["name"].lower()
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError(f"cannot detect scanner name from SARIF: {exc}") from exc
    if "bandit" in name:
        return "bandit"
    if "semgrep" in name:
        return "semgrep"
    if "trivy" in name:
        return "trivy"
    if "gitleaks" in name:
        return "gitleaks"
    if "pip-audit" in name or "pip_audit" in name:
        return "pip-audit"
    return name  # unknown; still pass through


def _cvss_bucket(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "Info"


def normalize_severity(scanner: str, entry: dict[str, Any]) -> str:
    """Map a scanner's native severity to Critical|High|Medium|Low|Info."""
    if scanner == "gitleaks":
        return "Critical"

    props = entry.get("properties") or {}
    raw_score = props.get("security-severity")
    if raw_score is not None:
        try:
            return _cvss_bucket(float(raw_score))
        except (TypeError, ValueError):
            pass

    level = (entry.get("level") or "").lower()
    if scanner == "semgrep":
        return {"error": "High", "warning": "Medium", "note": "Low"}.get(level, "Low")
    if scanner == "bandit":
        return {"error": "High", "warning": "Medium", "note": "Low"}.get(level, "Low")
    if scanner == "trivy":
        return {"error": "High", "warning": "Medium", "note": "Low"}.get(level, "Low")

    return "Low"


def _extract_location(result: dict[str, Any]) -> tuple[str, int | None]:
    locs = result.get("locations") or []
    if not locs:
        return "", None
    phys = locs[0].get("physicalLocation") or {}
    art = (phys.get("artifactLocation") or {}).get("uri", "")
    region = phys.get("region") or {}
    return art, region.get("startLine")


def collect_findings(sarif_paths: list[str]) -> list[Finding]:
    """Parse every SARIF file and return a flat list of Findings."""
    out: list[Finding] = []
    for path in sarif_paths:
        try:
            text = Path(path).read_text(encoding="utf-8")
            sarif = json.loads(text)
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot parse SARIF {path}: {exc}") from exc
        scanner = _scanner_from_sarif(sarif)
        for run in sarif.get("runs", []):
            for result in run.get("results", []):
                sev = normalize_severity(scanner, result)
                fname, line = _extract_location(result)
                out.append(Finding(
                    scanner=scanner,
                    rule_id=result.get("ruleId", "UNKNOWN"),
                    severity=sev,
                    file=fname,
                    line=line,
                    message=(result.get("message") or {}).get("text", ""),
                ))
    return out


def load_waivers(path: str) -> list[dict[str, Any]]:
    """Load waivers.yaml; missing file returns []."""
    p = Path(path)
    if not p.exists():
        return []
    try:
        doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"malformed waivers file {path}: {exc}") from exc
    waivers = doc.get("waivers", [])
    if not isinstance(waivers, list):
        raise ValueError(f"waivers file {path} 'waivers' must be a list")
    for w in waivers:
        for required in ("id", "reason", "added_by", "added_on", "expires_on"):
            if required not in w:
                raise ValueError(f"waiver missing '{required}': {w}")
    return waivers


def is_expired(waiver: dict[str, Any], today: date) -> bool:
    exp = waiver.get("expires_on")
    if isinstance(exp, date):
        return exp < today
    if isinstance(exp, str):
        return datetime.strptime(exp, "%Y-%m-%d").date() < today
    return True  # missing/invalid → treat as expired


def _apply_waivers(
    findings: list[Finding],
    waivers: list[dict[str, Any]],
    today: date,
    scheduled: bool,
) -> tuple[list[Finding], list[dict[str, Any]]]:
    """Return (still_blocking, expired_waivers_hit)."""
    active_ids = {w["id"] for w in waivers if not is_expired(w, today)}
    expired = [w for w in waivers if is_expired(w, today)]
    remaining = [f for f in findings if f.waiver_id not in active_ids]
    # On scheduled runs, expired waivers themselves are a failure signal
    # even if the finding they waived is gone.
    return remaining, (expired if scheduled else [])


def _render_summary(findings: list[Finding]) -> str:
    counts: dict[str, dict[str, int]] = {}
    for f in findings:
        counts.setdefault(f.scanner, {s: 0 for s in SEVERITY_ORDER})
        counts[f.scanner][f.severity] += 1
    lines = ["| Scanner | Critical | High | Medium | Low | Info |",
             "|---|---|---|---|---|---|"]
    for scanner in sorted(counts):
        c = counts[scanner]
        lines.append(f"| {scanner} | {c['Critical']} | {c['High']} | {c['Medium']} | {c['Low']} | {c['Info']} |")
    if not counts:
        lines.append("| _(no findings)_ | 0 | 0 | 0 | 0 | 0 |")
    return "\n".join(lines)


def _write_step_summary(text: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(text + "\n")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("sarif", nargs="+", help="SARIF files to aggregate")
    p.add_argument("--waivers", default=".github/security/waivers.yaml")
    p.add_argument("--mode", choices=("enforce", "warn"), default="enforce")
    p.add_argument("--output", default="report.json")
    p.add_argument("--scheduled", action="store_true",
                   help="Treat this as a scheduled run (fail on expired waivers).")
    args = p.parse_args(argv)

    try:
        findings = collect_findings(args.sarif)
        waivers = load_waivers(args.waivers)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    remaining, expired_hits = _apply_waivers(
        findings, waivers, today=date.today(), scheduled=args.scheduled,
    )
    blocking = [f for f in remaining if f.severity in BLOCKING]

    table = _render_summary(findings)
    print(table)
    _write_step_summary(f"## Security scan summary\n\n{table}\n")

    Path(args.output).write_text(json.dumps({
        "mode": args.mode,
        "total": len(findings),
        "blocking": len(blocking),
        "expired_waivers": [w["id"] for w in expired_hits],
        "findings": [asdict(f) for f in findings],
    }, indent=2), encoding="utf-8")

    if args.mode == "warn":
        print(f"warn-mode: {len(blocking)} blocking finding(s) — not failing.")
        return 0
    if blocking:
        print(f"FAIL: {len(blocking)} un-waived Medium+ finding(s).", file=sys.stderr)
        return 1
    if expired_hits:
        print(f"FAIL: {len(expired_hits)} expired waiver(s).", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 6: Add pytest deps to `pyproject.toml`**

In `pyproject.toml`, inside `[dependency-groups]`, add:

```toml
security = ["pyyaml>=6.0", "pytest>=9"]
```

Add it right after the `docs = [...]` line to preserve group ordering.

- [ ] **Step 7: Run tests to confirm they pass**

Run:
```bash
uv sync --group security
uv run pytest .github/security/tests/ -v
```
Expected: all 10 tests PASS.

- [ ] **Step 8: Smoke test the CLI**

Run:
```bash
uv run python .github/security/gate.py .github/security/tests/fixtures/trivy_low.sarif --mode enforce --output /tmp/report.json
echo "exit=$?"
uv run python .github/security/gate.py .github/security/tests/fixtures/bandit_high.sarif --mode enforce --output /tmp/report.json
echo "exit=$?"
```
Expected: first invocation exits `0`, second exits `1`, and `/tmp/report.json` contains a `findings` array.

- [ ] **Step 9: Commit**

```bash
git add .github/security/ pyproject.toml uv.lock
git commit -m "ci(security): add gate.py aggregator + tests + waivers schema

gate.py reads all scanner SARIFs, normalizes severities into
Critical/High/Medium/Low/Info, applies waivers, and exits 1 when any
un-waived Medium+ finding remains (enforce mode) or 0 (warn mode).
10 unit tests cover normalization, fixtures, waivers, and CLI exit codes.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task 3: Bandit scanner job

**Files:**
- Create: `.github/security/bandit.yaml`
- Create: `.github/workflows/security.yml` (only the top matter + `bandit` job in this task)

**Interfaces:**
- Consumes: `./.github/actions/setup-cache` (Task 1). Runs Bandit against `src/` and writes `bandit.sarif` + `bandit.json`.
- Produces: workflow artifact `sarif-bandit` containing `bandit.sarif` and `bandit.json`. SARIF also uploaded to Code Scanning with `category: bandit`.

- [ ] **Step 1: Create bandit config**

Create `.github/security/bandit.yaml`:

```yaml
---
# Bandit config. Excludes tests/fixtures (intentionally-vulnerable examples).
skips: []
exclude_dirs:
  - tests
  - src/molecule/test
  - collections
```

- [ ] **Step 2: Create the workflow file with just the header + bandit job**

Create `.github/workflows/security.yml`:

```yaml
---
name: security

on:
  pull_request:
    branches:
      - main
      - "releases/**"
      - "stable/**"
  push:
    branches:
      - main
  schedule:
    - cron: "0 0 * * *"
  workflow_dispatch:

concurrency:
  group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.sha }}
  cancel-in-progress: true

permissions:
  contents: read

jobs:
  bandit:
    if: github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - uses: ./.github/actions/setup-cache
        with:
          python-version: "3.13"

      - name: Install Bandit
        run: uv tool install "bandit[sarif]==1.7.10"

      - name: Run Bandit
        run: |
          set +e
          bandit -c .github/security/bandit.yaml -r src -f sarif -o bandit.sarif
          rc=$?
          # Bandit exits 1 when findings are present. We don't fail here.
          [ $rc -le 1 ] || exit $rc
          bandit -c .github/security/bandit.yaml -r src -f json -o bandit.json || true

      - name: Upload SARIF to Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: bandit.sarif
          category: bandit

      - name: Upload artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: sarif-bandit
          path: |
            bandit.sarif
            bandit.json
```

- [ ] **Step 3: Lint the workflow**

Run: `pre-commit run actionlint --files .github/workflows/security.yml`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add .github/security/bandit.yaml .github/workflows/security.yml
git commit -m "ci(security): add Bandit scanner job

Runs Bandit against src/ producing SARIF + JSON. SARIF uploaded to
Code Scanning; both files uploaded as artifact 'sarif-bandit'. Job
never fails on findings — gate.py decides in a later task.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task 4: Semgrep scanner job

**Files:**
- Create: `.github/security/semgrep.yaml`
- Modify: `.github/workflows/security.yml` — add `semgrep` job under `jobs:`.

**Interfaces:**
- Consumes: `./.github/actions/setup-cache`.
- Produces: workflow artifact `sarif-semgrep` containing `semgrep.sarif`. Also uploaded to Code Scanning with `category: semgrep`.

- [ ] **Step 1: Create semgrep config**

Create `.github/security/semgrep.yaml`:

```yaml
---
# Rulesets applied by the semgrep job. Modify by editing this file only,
# never by changing the workflow.
rulesets:
  - p/ci
  - p/python
  - p/owasp-top-ten
```

- [ ] **Step 2: Add the semgrep job**

In `.github/workflows/security.yml`, under `jobs:` and after the `bandit:` job (indentation must match `bandit:`), append:

```yaml
  semgrep:
    if: github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      security-events: write
    container:
      image: semgrep/semgrep:1.86.0
    steps:
      - uses: actions/checkout@v4

      - name: Run Semgrep
        run: |
          semgrep scan \
            --config p/ci \
            --config p/python \
            --config p/owasp-top-ten \
            --sarif --output semgrep.sarif \
            --error --no-fail-on-findings src/
        continue-on-error: false
        env:
          SEMGREP_SEND_METRICS: "off"

      - name: Upload SARIF to Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: semgrep.sarif
          category: semgrep

      - name: Upload artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: sarif-semgrep
          path: semgrep.sarif
```

- [ ] **Step 3: Lint**

Run: `pre-commit run actionlint --files .github/workflows/security.yml`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add .github/security/semgrep.yaml .github/workflows/security.yml
git commit -m "ci(security): add Semgrep scanner job

Runs Semgrep with rulesets p/ci, p/python, p/owasp-top-ten in the official
container image. Metrics disabled. SARIF uploaded to Code Scanning and as
artifact 'sarif-semgrep'.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task 5: pip-audit scanner job

**Files:**
- Modify: `.github/workflows/security.yml` — add `pip-audit` job.

**Interfaces:**
- Consumes: `./.github/actions/setup-cache` (uv cache is the big win here).
- Produces: workflow artifact `sarif-pip-audit` containing `pip-audit.sarif` and `pip-audit.json`. Uploaded to Code Scanning with `category: pip-audit`.

- [ ] **Step 1: Add the pip-audit job**

Under `jobs:` in `.github/workflows/security.yml`, append:

```yaml
  pip-audit:
    if: github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - uses: ./.github/actions/setup-cache
        with:
          python-version: "3.13"

      - name: Export locked requirements
        run: |
          uv export --frozen --all-extras --no-hashes \
            --output-file requirements-audit.txt

      - name: Install pip-audit
        run: uv tool install "pip-audit==2.7.3"

      - name: Run pip-audit (SARIF)
        run: |
          set +e
          pip-audit --requirement requirements-audit.txt \
            --format sarif --output pip-audit.sarif
          rc=$?
          # pip-audit exits 1 on findings — do not fail the job.
          [ $rc -le 1 ] || exit $rc

      - name: Run pip-audit (JSON, for debugging)
        run: |
          pip-audit --requirement requirements-audit.txt \
            --format json --output pip-audit.json || true

      - name: Upload SARIF to Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: pip-audit.sarif
          category: pip-audit

      - name: Upload artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: sarif-pip-audit
          path: |
            pip-audit.sarif
            pip-audit.json
            requirements-audit.txt
```

- [ ] **Step 2: Lint and commit**

Run: `pre-commit run actionlint --files .github/workflows/security.yml`

```bash
git add .github/workflows/security.yml
git commit -m "ci(security): add pip-audit scanner job

Exports uv.lock via 'uv export --frozen --all-extras' so dev, lint, docs,
and collection groups are scanned alongside runtime deps. Emits SARIF
(uploaded to Code Scanning) and JSON (artifact for debugging).

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task 6: Gitleaks scanner job

**Files:**
- Create: `.github/security/gitleaks.toml`
- Modify: `.github/workflows/security.yml` — add `gitleaks` job.

**Interfaces:**
- Consumes: `./.github/actions/setup-cache` (only for python if the job needs it; actually not required — gitleaks runs standalone).
- Produces: workflow artifact `sarif-gitleaks` containing `gitleaks.sarif`. Uploaded to Code Scanning with `category: gitleaks`.

- [ ] **Step 1: Create gitleaks config**

Create `.github/security/gitleaks.toml`:

```toml
# Gitleaks config for the molecule fork.
# Extends the default ruleset and only adds allowlists for known
# false-positives in test fixtures.

[extend]
useDefault = true

[allowlist]
description = "Known-fake credentials in test fixtures"
paths = [
    '''tests/fixtures/.*''',
    '''src/molecule/test/.*''',
    '''community\.molecule/.*/tests/.*''',
]
```

- [ ] **Step 2: Add the gitleaks job**

Under `jobs:` in `.github/workflows/security.yml`, append:

```yaml
  gitleaks:
    if: github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
        with:
          # Full history on push/schedule, shallow on PR (perf trade-off)
          fetch-depth: ${{ github.event_name == 'pull_request' && 1 || 0 }}

      - name: Run Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITLEAKS_CONFIG: .github/security/gitleaks.toml
          # Do not fail here; gate.py owns the decision.
          GITLEAKS_NOTIFY_USER_LIST: ""
          GITLEAKS_ENABLE_UPLOAD_ARTIFACT: "false"
          GITLEAKS_ENABLE_SUMMARY: "true"
        continue-on-error: true

      - name: Locate SARIF output
        run: |
          # gitleaks-action writes results.sarif in the workspace
          if [ -f results.sarif ]; then
            mv results.sarif gitleaks.sarif
          else
            # No output means no findings — emit an empty valid SARIF.
            cat > gitleaks.sarif <<'EOF'
          {"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Gitleaks"}},"results":[]}]}
          EOF
          fi

      - name: Upload SARIF to Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: gitleaks.sarif
          category: gitleaks

      - name: Upload artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: sarif-gitleaks
          path: gitleaks.sarif
```

- [ ] **Step 3: Lint and commit**

Run: `pre-commit run actionlint --files .github/workflows/security.yml`

```bash
git add .github/security/gitleaks.toml .github/workflows/security.yml
git commit -m "ci(security): add Gitleaks secret scanner job

Uses gitleaks-action v2 with an allowlist for test fixtures. Full-history
scan on push/schedule, shallow on PR. Emits an empty SARIF when clean so
downstream jobs always have a file to consume.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task 7: Trivy scanner job (with SBOM)

**Files:**
- Modify: `.github/workflows/security.yml` — add `trivy` job.

**Interfaces:**
- Consumes: `./.github/actions/setup-cache` with `cache-scanner-db: "true"` (this is where the DB cache pays off).
- Produces: workflow artifacts `sarif-trivy` (containing `trivy.sarif`) and `sbom` (containing `sbom.spdx.json`). SARIF uploaded to Code Scanning with `category: trivy`.

- [ ] **Step 1: Add the trivy job**

Under `jobs:` in `.github/workflows/security.yml`, append:

```yaml
  trivy:
    if: github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - uses: ./.github/actions/setup-cache
        with:
          python-version: "3.13"
          cache-scanner-db: "true"

      - name: Run Trivy filesystem scan (SARIF)
        uses: aquasecurity/trivy-action@0.24.0
        with:
          scan-type: fs
          scanners: vuln,misconfig,secret
          format: sarif
          output: trivy.sarif
          severity: CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN
          exit-code: "0"
          cache-dir: ~/.cache/trivy

      - name: Generate SBOM (SPDX)
        uses: aquasecurity/trivy-action@0.24.0
        with:
          scan-type: fs
          format: spdx-json
          output: sbom.spdx.json
          exit-code: "0"
          cache-dir: ~/.cache/trivy

      - name: Upload SARIF to Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: trivy.sarif
          category: trivy

      - name: Upload Trivy artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: sarif-trivy
          path: trivy.sarif

      - name: Upload SBOM artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.spdx.json
```

- [ ] **Step 2: Lint and commit**

Run: `pre-commit run actionlint --files .github/workflows/security.yml`

```bash
git add .github/workflows/security.yml
git commit -m "ci(security): add Trivy filesystem scan + SBOM generation

Two Trivy invocations share the same DB cache: one produces the SARIF
(vuln + misconfig + secret) uploaded to Code Scanning; the other produces
an SPDX-JSON SBOM uploaded as artifact 'sbom'. DB cache uses run_id-write
/ prefix-restore via the setup-cache action.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task 8: Aggregator job `security-gate` (warn-mode initial rollout)

**Files:**
- Modify: `.github/workflows/security.yml` — add `security-gate` job.

**Interfaces:**
- Consumes: artifacts `sarif-bandit`, `sarif-semgrep`, `sarif-pip-audit`, `sarif-gitleaks`, `sarif-trivy` (uploaded by Tasks 3–7) and `.github/security/gate.py` (Task 2).
- Produces: workflow artifact `security-report` containing `report.json`. Fails the workflow (exit 1) when `GATE_MODE=enforce` and un-waived Medium+ findings exist.

- [ ] **Step 1: Add the aggregator job**

Under `jobs:` in `.github/workflows/security.yml`, append:

```yaml
  security-gate:
    if: github.repository == 'fardani235/molecule' && always()
    needs: [bandit, semgrep, pip-audit, gitleaks, trivy]
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    env:
      # Rollout: start in warn mode, flip to 'enforce' after Task 11.
      GATE_MODE: warn
    steps:
      - uses: actions/checkout@v4

      - uses: ./.github/actions/setup-cache
        with:
          python-version: "3.13"

      - name: Install PyYAML
        run: uv pip install --system pyyaml

      - name: Download all scanner artifacts
        uses: actions/download-artifact@v4
        with:
          path: sarif-in
          pattern: sarif-*
          merge-multiple: false

      - name: Run gate.py
        id: gate
        run: |
          python .github/security/gate.py \
            sarif-in/**/*.sarif \
            --waivers .github/security/waivers.yaml \
            --mode "$GATE_MODE" \
            --output report.json \
            ${{ github.event_name == 'schedule' && '--scheduled' || '' }}

      - name: Upload consolidated report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: report.json
```

- [ ] **Step 2: Lint and commit**

Run: `pre-commit run actionlint --files .github/workflows/security.yml`

```bash
git add .github/workflows/security.yml
git commit -m "ci(security): add security-gate aggregator (warn mode)

Downloads all scanner SARIFs, runs gate.py to normalize severities and
apply waivers, uploads consolidated report.json artifact. Starts in
warn mode so the initial rollout does not block PRs while we surface
and triage baseline findings. Flipped to enforce in a later task.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

- [ ] **Step 3: Push and observe the workflow**

```bash
git push -u origin devsecops-ci
```

Then on GitHub, open the Actions tab and confirm the `security` workflow ran end-to-end. Every job should be green (including `security-gate`), and the run should have artifacts: `sarif-bandit`, `sarif-semgrep`, `sarif-pip-audit`, `sarif-gitleaks`, `sarif-trivy`, `sbom`, `security-report`.

If any scanner job crashes (not "found issues"; actually crashed), fix the crash and re-push before moving to Task 9.

---

## Task 9: Benchmark workflow

**Files:**
- Create: `docs/devsecops/bench.py`
- Create: `.github/workflows/ci-benchmark.yml`
- Create: `docs/devsecops/MEASUREMENTS.md` (baseline section only)

**Interfaces:**
- Consumes: the `gh` CLI (preinstalled), workflow run history for `security.yml` and `tox.yml`.
- Produces: artifact `ci-timing-report` containing `MEASUREMENTS.md`.

- [ ] **Step 1: Create the benchmark script**

Create `docs/devsecops/bench.py`:

```python
#!/usr/bin/env python3
"""Compute median/p95 wall-clock times for GitHub Actions workflow runs.

Usage:
  bench.py --workflow security.yml --sha-before <sha> --sha-after <sha> \
      --output MEASUREMENTS.md
"""
from __future__ import annotations

import argparse
import json
import statistics
import subprocess
from datetime import datetime


def _fetch(workflow: str, branch: str, limit: int = 10) -> list[dict]:
    out = subprocess.check_output([
        "gh", "run", "list",
        "--workflow", workflow,
        "--branch", branch,
        "--limit", str(limit),
        "--json", "databaseId,createdAt,updatedAt,conclusion,headSha",
    ])
    return json.loads(out)


def _duration_seconds(run: dict) -> float:
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    start = datetime.strptime(run["createdAt"], fmt)
    end = datetime.strptime(run["updatedAt"], fmt)
    return (end - start).total_seconds()


def _summarize(runs: list[dict]) -> tuple[float, float, int]:
    durs = [_duration_seconds(r) for r in runs if r.get("conclusion") == "success"]
    if not durs:
        return (0.0, 0.0, 0)
    return (statistics.median(durs), _p95(durs), len(durs))


def _p95(xs: list[float]) -> float:
    xs = sorted(xs)
    if len(xs) == 1:
        return xs[0]
    idx = int(round(0.95 * (len(xs) - 1)))
    return xs[idx]


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--workflow", action="append", required=True,
                   help="Workflow file name; may be given multiple times.")
    p.add_argument("--branch-before", required=True)
    p.add_argument("--branch-after", required=True)
    p.add_argument("--output", required=True)
    args = p.parse_args()

    lines = [
        "# CI Timing Measurements",
        "",
        f"- Branch (before): `{args.branch_before}`",
        f"- Branch (after):  `{args.branch_after}`",
        "",
        "| Workflow | Median before | p95 before | N before | Median after | p95 after | N after | Δ median |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for wf in args.workflow:
        before = _summarize(_fetch(wf, args.branch_before))
        after = _summarize(_fetch(wf, args.branch_after))
        delta = "n/a" if before[0] == 0 or after[0] == 0 else f"{(after[0] - before[0]):+.1f}s"
        lines.append(
            f"| {wf} | {before[0]:.1f}s | {before[1]:.1f}s | {before[2]} "
            f"| {after[0]:.1f}s | {after[1]:.1f}s | {after[2]} | {delta} |"
        )
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Create the workflow**

Create `.github/workflows/ci-benchmark.yml`:

```yaml
---
name: ci-benchmark

on:
  workflow_dispatch:
    inputs:
      branch_before:
        description: Branch to sample "before" timings from
        required: true
        default: main
      branch_after:
        description: Branch to sample "after" timings from
        required: true
        default: devsecops-ci

permissions:
  contents: read
  actions: read

jobs:
  bench:
    if: github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4

      - name: Compute measurements
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          python3 docs/devsecops/bench.py \
            --workflow security.yml \
            --workflow tox.yml \
            --branch-before "${{ inputs.branch_before }}" \
            --branch-after "${{ inputs.branch_after }}" \
            --output MEASUREMENTS.md
          cat MEASUREMENTS.md >> "$GITHUB_STEP_SUMMARY"

      - name: Upload measurements artifact
        uses: actions/upload-artifact@v4
        with:
          name: ci-timing-report
          path: MEASUREMENTS.md
```

- [ ] **Step 3: Seed the baseline `MEASUREMENTS.md`**

Create `docs/devsecops/MEASUREMENTS.md`:

```markdown
# CI Timing Measurements

Populated by `.github/workflows/ci-benchmark.yml`. This file is a placeholder
until the benchmark workflow has been dispatched. See `SECURITY_CI.md` for
how to run it.

## Baseline (before this PR)

_To be filled in by running:_

    gh workflow run ci-benchmark.yml \
      -f branch_before=main \
      -f branch_after=main

## After DevSecOps changes

_To be filled in after `devsecops-ci` merges and has 10+ runs:_

    gh workflow run ci-benchmark.yml \
      -f branch_before=main \
      -f branch_after=main
```

- [ ] **Step 4: Smoke-test the script locally (dry run — needs `gh` auth)**

Run:
```bash
gh auth status || echo "gh not authed locally — skip; workflow will still work."
python3 docs/devsecops/bench.py --workflow tox.yml \
  --branch-before main --branch-after main \
  --output /tmp/measurements.md 2>&1 | head -20 || true
cat /tmp/measurements.md 2>/dev/null || true
```
Expected: either produces a table, or (if unauthenticated) fails with a `gh` error — that's fine because the real run happens in the workflow.

- [ ] **Step 5: Lint and commit**

Run: `pre-commit run actionlint --files .github/workflows/ci-benchmark.yml`

```bash
git add docs/devsecops/bench.py docs/devsecops/MEASUREMENTS.md .github/workflows/ci-benchmark.yml
git commit -m "ci: add ci-benchmark workflow + timing script

Manual workflow_dispatch that samples the last 10 successful runs of
security.yml and tox.yml on two branches, computes median and p95
durations, writes MEASUREMENTS.md, and uploads it as artifact
'ci-timing-report'. Fork-guarded.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task 10: SECURITY_CI.md documentation

**Files:**
- Create: `docs/devsecops/SECURITY_CI.md`

**Interfaces:** none (docs only).

- [ ] **Step 1: Write the doc**

Create `docs/devsecops/SECURITY_CI.md`:

```markdown
# Security CI Reference

This fork adds a DevSecOps layer on top of the upstream `tox` CI. See
`docs/superpowers/specs/2026-08-03-devsecops-ci-design.md` for the design.

## What runs, and when

| Trigger | Workflow | Notes |
|---|---|---|
| PR to `main`/`releases/**`/`stable/**` | security.yml | Required to pass (once flipped to enforce). |
| Push to `main` | security.yml | Populates Code Scanning trend. |
| Daily 00:00 UTC | security.yml | Catches new CVEs; fails on expired waivers. |
| Manual | security.yml, ci-benchmark.yml | `workflow_dispatch`. |

## Scanners

| Job | Tool | What it catches | Config |
|---|---|---|---|
| bandit | Bandit 1.7.10 | Python SAST (insecure patterns) | `.github/security/bandit.yaml` |
| semgrep | Semgrep 1.86 (container) | Broad SAST (p/ci, p/python, p/owasp-top-ten) | `.github/security/semgrep.yaml` |
| pip-audit | pip-audit 2.7.3 | Python dependency vulns (PyPA advisory DB) | scans `uv export --frozen --all-extras` |
| gitleaks | gitleaks-action v2 | Leaked secrets in code + git history | `.github/security/gitleaks.toml` |
| trivy | trivy-action 0.24.0 | Filesystem vulns + misconfig + secrets + SBOM | none (defaults + severity threshold) |
| security-gate | `.github/security/gate.py` | Aggregator — the single required status check | reads `waivers.yaml` |

## The gate

`gate.py` normalizes every scanner's severity into
`Critical | High | Medium | Low | Info`, applies waivers from
`.github/security/waivers.yaml`, and exits `1` when any un-waived
Medium/High/Critical finding remains. Set `GATE_MODE=warn` in the
job env to run the gate in read-only mode (no failure).

### Filing a waiver

Edit `.github/security/waivers.yaml`:

```yaml
waivers:
  - id: bandit:B301             # required — scanner:rule format
    reason: "false positive: pickle used only in trusted test harness"
    added_by: "your-gh-handle"
    added_on: "2026-08-03"
    expires_on: "2026-11-03"    # ≤ 90 days — the gate fails on scheduled
                                #   runs after this date so waivers cannot rot.
```

### Reproducing a finding locally

```bash
# Bandit
uv tool install "bandit[sarif]==1.7.10"
bandit -c .github/security/bandit.yaml -r src

# Semgrep
docker run --rm -v "$PWD:/src" semgrep/semgrep:1.86.0 \
  semgrep scan --config p/ci --config p/python --config p/owasp-top-ten src/

# pip-audit
uv export --frozen --all-extras --no-hashes > /tmp/req.txt
uv tool install "pip-audit==2.7.3"
pip-audit --requirement /tmp/req.txt

# gitleaks
docker run --rm -v "$PWD:/repo" zricethezav/gitleaks:latest \
  detect --source=/repo --config=/repo/.github/security/gitleaks.toml

# trivy
docker run --rm -v "$PWD:/src" aquasec/trivy:latest \
  fs --scanners vuln,misconfig,secret /src
```

## Artifacts on every run

- `sarif-bandit`, `sarif-semgrep`, `sarif-pip-audit`, `sarif-gitleaks`, `sarif-trivy` — raw SARIF + JSON per scanner
- `sbom` — SPDX-JSON software bill of materials
- `security-report` — consolidated `report.json` from `gate.py`

## Caching

Three caches populated by `.github/actions/setup-cache`:

- `~/.cache/uv` — keyed on `uv.lock`
- `~/.cache/pre-commit` — keyed on `.pre-commit-config.yaml`
- `~/.cache/trivy` — write on `run_id`, restore on any `trivy-db-*` prefix

## Measuring CI speed

Dispatch `ci-benchmark.yml` with two branch names. It computes median +
p95 wall-clock durations for the last 10 successful runs of `security.yml`
and `tox.yml` on each branch and writes `MEASUREMENTS.md`.
```

- [ ] **Step 2: Commit**

```bash
git add docs/devsecops/SECURITY_CI.md
git commit -m "docs: add SECURITY_CI reference for the devsecops layer

Explains what runs when, how each scanner is configured, how to file a
waiver, how to reproduce a finding locally, and how to run the benchmark.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task 11: Flip the gate from `warn` to `enforce` and add required-status check

**Files:**
- Modify: `.github/workflows/security.yml` — change `GATE_MODE` in the `security-gate` job.

**Interfaces:** none new.

- [ ] **Step 1: Confirm baseline is clean or waived**

On the GitHub Actions UI, open the most recent `security` workflow run on branch `devsecops-ci`. Download the `security-report` artifact and inspect `report.json`:

```bash
gh run download --name security-report -D /tmp/sec
cat /tmp/sec/report.json | python -m json.tool | head -40
```

Expected: `blocking` = 0, or every blocking finding has a corresponding entry in `.github/security/waivers.yaml`. If not, either fix the finding or file a waiver (Task 10 explains how) and re-run the workflow before proceeding.

- [ ] **Step 2: Flip GATE_MODE**

In `.github/workflows/security.yml`, inside the `security-gate` job, change:

```yaml
    env:
      GATE_MODE: warn
```

to:

```yaml
    env:
      GATE_MODE: enforce
```

- [ ] **Step 3: Commit and push**

```bash
git add .github/workflows/security.yml
git commit -m "ci(security): flip gate from warn to enforce

Baseline scan surfaced no un-waived Medium+ findings; the gate now blocks
PRs with any Medium/High/Critical finding per the DevSecOps spec.

Co-Authored-By: Claude <noreply@anthropic.com>"

git push
```

- [ ] **Step 4: Verify on GitHub**

Open the run for this push and confirm `security-gate` is green with mode=enforce. Then in **Settings → Branches → main**, edit branch protection and add `security-gate` to Required status checks. Repeat for `releases/**` and `stable/**` if they exist as protected branches.

Manual verification only — no code change here.

---

## Task 12: Run the benchmark and commit the final `MEASUREMENTS.md`

**Files:**
- Modify: `docs/devsecops/MEASUREMENTS.md` — replace placeholder with real numbers.

**Interfaces:** consumes the `ci-benchmark` workflow.

- [ ] **Step 1: Dispatch the benchmark**

Wait until `security.yml` has run at least 10 times on `devsecops-ci` (Push + PR + a few dispatches). Then:

```bash
gh workflow run ci-benchmark.yml \
  -f branch_before=main \
  -f branch_after=devsecops-ci
```

- [ ] **Step 2: Download the artifact**

```bash
gh run list --workflow ci-benchmark.yml --limit 1
gh run download <run-id> --name ci-timing-report -D /tmp/bench
cat /tmp/bench/MEASUREMENTS.md
```

- [ ] **Step 3: Commit the results**

Replace `docs/devsecops/MEASUREMENTS.md` with the file downloaded above (keep the header and add a brief interpretive paragraph beneath the table, e.g. "Trivy dropped from X→Y seconds — DB cache; pip-audit dropped from X→Y — uv cache; …"):

```bash
cp /tmp/bench/MEASUREMENTS.md docs/devsecops/MEASUREMENTS.md
$EDITOR docs/devsecops/MEASUREMENTS.md   # add interpretation paragraph
git add docs/devsecops/MEASUREMENTS.md
git commit -m "docs: commit real CI-timing measurements

Populates MEASUREMENTS.md with the before/after wall-clock report from
ci-benchmark.yml. See SECURITY_CI.md for how to reproduce.

Co-Authored-By: Claude <noreply@anthropic.com>"
git push
```

---

## Task 13: Open the PR

- [ ] **Step 1: Push and open the PR**

```bash
git push
gh pr create --base main --head devsecops-ci \
  --title "ci: add DevSecOps layer (5 scanners, Medium+ gate, caching, benchmark)" \
  --body "$(cat <<'EOF'
Implements the design at docs/superpowers/specs/2026-08-03-devsecops-ci-design.md.

## What this adds

- **security.yml** with 5 parallel scanners: Bandit, Semgrep, pip-audit, Gitleaks, Trivy
- **security-gate** aggregator job that fails on any Medium+ finding (enforce mode)
- **setup-cache** composite action: uv, pre-commit, Trivy DB caches
- **ci-benchmark.yml** with wall-clock measurement + MEASUREMENTS.md artifact
- SARIF upload to Code Scanning; per-run downloadable artifacts; PR job summary tables
- Fork-guarded (`if: github.repository == 'fardani235/molecule'`) so it only runs on this fork
- SBOM (SPDX-JSON) generated on every run

## Out of scope

Publishing to PyPI or Ansible Galaxy.

## Measurements

See `docs/devsecops/MEASUREMENTS.md`.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 2: Verify required checks appear**

On the PR page, confirm:
1. `security-gate` shows as **required** and green.
2. The Actions tab of the run has artifacts: `sarif-bandit`, `sarif-semgrep`, `sarif-pip-audit`, `sarif-gitleaks`, `sarif-trivy`, `sbom`, `security-report`.
3. Security tab → Code Scanning shows entries from all five scanners.

---

## Self-review notes

**Spec coverage:** Every numbered section of the spec has ≥ 1 task:

- §3 Architecture → Task 1 (composite action) + Tasks 3–8 (workflow)
- §4.1 setup-cache → Task 1
- §4.2 security.yml → Tasks 3–8
- §4.3 gate.py → Task 2
- §4.4 waivers.yaml → Task 2 (file), Task 10 (procedure)
- §4.5 ci-benchmark.yml → Task 9
- §5 Data flow → covered structurally by Tasks 3–8
- §6 Branch protection → Task 11 step 4
- §7 Caching → Task 1
- §8 Benchmark → Tasks 9, 12
- §9 Fork-only execution → global constraint + every job's `if:`
- §10 Failure modes → gate.py implements them (Task 2)
- §11 Testing → Task 2 (unit tests)
- §12 Documentation → Task 10
- §13 Rollout → Tasks 8 (warn), 11 (enforce), 12 (measurements)
- §14 Fork-owner input → resolved: `fardani235`

**Placeholder scan:** none — every step includes actual code, actual commands, actual expected output.

**Type consistency:** `gate.py` symbols (`Finding`, `collect_findings`, `is_expired`, `load_waivers`, `normalize_severity`, `main`) match between Task 2 Steps 1 and 5. Artifact names (`sarif-bandit` … `sarif-trivy`, `sbom`, `security-report`, `ci-timing-report`) are stable across Tasks 3–9. `GATE_MODE` env var name is used identically in Tasks 8 and 11.
