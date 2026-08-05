# DevSecOps CI Improvements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a fork-only DevSecOps CI pipeline for `fardani235/molecule` that runs SAST, SCA, secrets, IaC, SBOM, and license scans on every PR; fails the check on any unlisted MEDIUM/HIGH/CRITICAL finding; caches every long-lived download; uploads all artifacts with explicit retention; feeds GitHub Code Scanning + Dependabot; and publishes a per-run CI-timing comparison table.

**Architecture:** One new workflow `.github/workflows/security.yml` fans out 8 scanner jobs in parallel, a `security-gate` job aggregates all SARIFs and enforces the threshold via `.security/scripts/aggregate_sarif.py`, and a `timing-report` job publishes a comparison table against a checked-in baseline. All jobs guard on `github.repository == 'fardani235/molecule'`. Existing workflows are unchanged except for one additive artifact upload in `release.yml`. Rollout is two-phase: land informational-only first, capture baseline, then flip the strict gate on.

**Tech Stack:** GitHub Actions, Python 3.12, `uv`, Bandit, Semgrep OSS, pip-audit, Trivy, Gitleaks, Checkov, ansible-lint, CycloneDX-Python, Syft, `sarif-tools`, `gh` CLI.

## Global Constraints

- **Fork-only:** every job in `security.yml` MUST guard on `if: github.repository == 'fardani235/molecule'`. Upstream `ansible-community/molecule` must never run this workflow.
- **Non-goals:** no publishing to PyPI or Ansible Galaxy. `release.yml` gets a single additive artifact-upload step; existing publish steps are unchanged.
- **Action pinning:** every `uses:` MUST pin a full 40-character commit SHA followed by a version comment (`# vX.Y.Z`). No floating tags, no `@main`.
- **Tool versions:** all scanner CLI versions live in `.security/tool-versions.env`. Workflows source that file — no version literals in YAML.
- **Runner:** `ubuntu-24.04` (pinned) for every job in `security.yml`.
- **Python:** `3.12` in the composite action; matches setup-python cache key.
- **Permissions default:** `permissions: read-all` at workflow level; jobs override to add `security-events: write` (SARIF upload) or `pull-requests: write` (sticky comment) only where needed. Never `id-token: write` in this workflow.
- **Severity gate:** fail on `CRITICAL`, `HIGH`, `MEDIUM`. `LOW`/`INFO`/`NOTE`/`NONE` never fail the gate.
- **Retention (explicit `retention-days:` on every upload):** `sarif-<scanner>` → 30, `security-report` → 90, `sbom` → 365, `ci-timing` → 90, `release-dists` → 90.
- **Allowlist required fields:** `id`, `reason`, `owner`, `expires` (ISO 8601). Expired entries re-enter the gate. Duplicate `id` fails the gate.
- **Timing job is informational:** `timing-report` runs `continue-on-error: true`; it never fails the gate.
- **Rollout gating:** all jobs land with `continue-on-error: true` first (informational). The strict gate is flipped on only after `.security/baseline.json` is captured and committed — done in the final task.

---

## Task 1: `.security/` config skeleton + tool versions

**Files:**
- Create: `.security/tool-versions.env`
- Create: `.security/bandit.yaml`
- Create: `.security/semgrep.yml`
- Create: `.security/checkov.yml`
- Create: `.gitleaks.toml`
- Create: `.security/allowlist.yml`
- Create: `.security/README.md`

**Interfaces:**
- Consumes: nothing.
- Produces: config files consumed by every scanner job in Task 6 and by the aggregator in Task 2.

- [ ] **Step 1: Create the versions file**

Create `.security/tool-versions.env` with exactly:

```env
# Pinned scanner versions. Renovate-tracked.
# Update by editing this file — no version literals in YAML.
BANDIT_VERSION=1.7.10
SEMGREP_VERSION=1.86.0
PIP_AUDIT_VERSION=2.7.3
TRIVY_VERSION=0.55.2
GITLEAKS_VERSION=8.19.0
CHECKOV_VERSION=3.2.256
ANSIBLE_LINT_VERSION=25.7.0
CYCLONEDX_PY_VERSION=5.1.1
SYFT_VERSION=1.14.0
SARIF_TOOLS_VERSION=3.0.4
```

- [ ] **Step 2: Create Bandit config**

Create `.security/bandit.yaml`:

```yaml
# Bandit config — SAST for src/molecule/.
# tests/fixtures/** are intentional Ansible playbooks under test; excluded.
exclude_dirs:
  - tests/fixtures
  - .venv
  - build
  - dist
skips: []
```

- [ ] **Step 3: Create Semgrep config**

Create `.security/semgrep.yml`:

```yaml
# Semgrep local rules + path excludes.
# Registry rulesets are passed on the CLI (p/python, p/security-audit, ...).
rules: []
paths:
  exclude:
    - tests/fixtures
    - .venv
    - build
    - dist
    - "**/*.md"
```

- [ ] **Step 4: Create Checkov config**

Create `.security/checkov.yml`:

```yaml
# Checkov framework selection + skip patterns.
framework:
  - ansible
  - dockerfile
  - github_actions
  - secrets
skip-path:
  - tests/fixtures/integration/test_command/molecule
  - .venv
compact: true
quiet: true
output: sarif
```

- [ ] **Step 5: Create Gitleaks allowlist**

Create `.gitleaks.toml`:

```toml
# Gitleaks configuration.
# Extends the default ruleset and allowlists test fixtures that ship
# intentional dummy credentials.
[extend]
useDefault = true

[allowlist]
description = "Molecule test fixtures with dummy credentials"
paths = [
  '''tests/fixtures/.*''',
  '''community\.molecule/.*''',
]
```

- [ ] **Step 6: Create the (empty) accepted-risk allowlist**

Create `.security/allowlist.yml`:

```yaml
# Cross-scanner accepted-risk registry.
# Every entry MUST have: id, reason, owner, expires (ISO 8601).
# Expired entries re-enter the gate. Duplicate `id` fails the gate.
# See docs/security/allowlist.md for the process.
version: 1
findings: []
```

- [ ] **Step 7: Add a short README so the directory has intent**

Create `.security/README.md`:

```markdown
# .security/

Fork-local DevSecOps configuration for `fardani235/molecule`.

- `tool-versions.env` — pinned scanner versions (Renovate-tracked).
- `bandit.yaml`, `semgrep.yml`, `checkov.yml` — scanner configs.
- `allowlist.yml` — cross-scanner accepted-risk registry.
- `scripts/` — aggregation, baseline, and timing renderers.
- `baseline.json` (committed later) — reference timing captured during rollout.

See `docs/security/` for setup, monitoring, and allowlist policy.
```

- [ ] **Step 8: Commit**

```bash
git add .security/ .gitleaks.toml
git commit -m "chore(security): add scanner configs and empty allowlist"
```

---

## Task 2: SARIF aggregator + threshold enforcer (with tests, TDD)

**Files:**
- Create: `.security/scripts/aggregate_sarif.py`
- Create: `.security/scripts/test_aggregate_sarif.py`
- Create: `.security/scripts/fixtures/bandit-med.sarif`
- Create: `.security/scripts/fixtures/pip-audit-high.sarif`
- Create: `.security/scripts/fixtures/gitleaks-low.sarif`
- Create: `.security/scripts/fixtures/malformed-allowlist.yml`

**Interfaces:**
- Consumes: `.security/allowlist.yml` (Task 1), directory of `*.sarif` files from `runner.temp/sarif/`.
- Produces (called by `security-gate` in Task 7):
  - CLI: `python .security/scripts/aggregate_sarif.py --sarif-dir <dir> --allowlist .security/allowlist.yml --out-dir <dir>`
  - Writes: `security-report.md`, `security-report.json`, `security-combined.sarif`
  - Exit code: `0` if no unlisted MEDIUM+ finding, `1` otherwise, `2` on config error (bad allowlist).

- [ ] **Step 1: Write the failing tests**

Create `.security/scripts/test_aggregate_sarif.py`:

```python
"""Unit tests for aggregate_sarif.

Run with: python -m pytest .security/scripts/test_aggregate_sarif.py -v
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"
SCRIPT = Path(__file__).parent / "aggregate_sarif.py"


def _run(tmp_path: Path, sarifs: list[str], allowlist: Path | None = None) -> tuple[int, Path]:
    sarif_dir = tmp_path / "sarif"
    sarif_dir.mkdir()
    for name in sarifs:
        (sarif_dir / name).write_bytes((FIXTURES / name).read_bytes())
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    cmd = [sys.executable, str(SCRIPT), "--sarif-dir", str(sarif_dir), "--out-dir", str(out_dir)]
    if allowlist is not None:
        cmd += ["--allowlist", str(allowlist)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, out_dir


def test_low_only_passes(tmp_path):
    code, out = _run(tmp_path, ["gitleaks-low.sarif"])
    assert code == 0
    assert (out / "security-report.md").exists()
    assert (out / "security-report.json").exists()
    assert (out / "security-combined.sarif").exists()


def test_medium_fails(tmp_path):
    code, _ = _run(tmp_path, ["bandit-med.sarif"])
    assert code == 1


def test_high_fails(tmp_path):
    code, _ = _run(tmp_path, ["pip-audit-high.sarif"])
    assert code == 1


def test_allowlisted_medium_passes(tmp_path):
    allow = tmp_path / "allowlist.yml"
    allow.write_text(
        "version: 1\n"
        "findings:\n"
        "  - id: 'bandit:B404'\n"
        "    reason: 'Reviewed — subprocess use is required'\n"
        "    owner: '@fardani235'\n"
        "    expires: '2099-01-01'\n"
    )
    code, _ = _run(tmp_path, ["bandit-med.sarif"], allow)
    assert code == 0


def test_expired_allowlist_reenters_gate(tmp_path):
    allow = tmp_path / "allowlist.yml"
    allow.write_text(
        "version: 1\n"
        "findings:\n"
        "  - id: 'bandit:B404'\n"
        "    reason: 'expired'\n"
        "    owner: '@fardani235'\n"
        "    expires: '2000-01-01'\n"
    )
    code, _ = _run(tmp_path, ["bandit-med.sarif"], allow)
    assert code == 1


def test_missing_allowlist_field_fails_with_2(tmp_path):
    allow = tmp_path / "bad.yml"
    allow.write_text(
        "version: 1\n"
        "findings:\n"
        "  - id: 'bandit:B404'\n"      # no reason/owner/expires
    )
    code, _ = _run(tmp_path, ["gitleaks-low.sarif"], allow)
    assert code == 2


def test_duplicate_allowlist_id_fails_with_2(tmp_path):
    allow = tmp_path / "dup.yml"
    allow.write_text(
        "version: 1\n"
        "findings:\n"
        "  - id: 'bandit:B404'\n"
        "    reason: 'a'\n    owner: '@x'\n    expires: '2099-01-01'\n"
        "  - id: 'bandit:B404'\n"
        "    reason: 'b'\n    owner: '@x'\n    expires: '2099-01-01'\n"
    )
    code, _ = _run(tmp_path, ["gitleaks-low.sarif"], allow)
    assert code == 2


def test_combined_sarif_merges_runs(tmp_path):
    code, out = _run(tmp_path, ["bandit-med.sarif", "pip-audit-high.sarif"])
    assert code == 1
    data = json.loads((out / "security-combined.sarif").read_text())
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 2


def test_report_json_schema(tmp_path):
    code, out = _run(tmp_path, ["bandit-med.sarif", "gitleaks-low.sarif"])
    assert code == 1
    report = json.loads((out / "security-report.json").read_text())
    assert report["schema_version"] == 1
    assert "totals" in report and "by_scanner" in report and "findings" in report
    assert report["totals"]["MEDIUM"] >= 1
```

Create fixture SARIF files (small, valid v2.1.0). Create `.security/scripts/fixtures/bandit-med.sarif`:

```json
{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [
    {
      "tool": {"driver": {"name": "Bandit", "version": "1.7.10", "rules": [
        {"id": "B404", "name": "blacklist", "shortDescription": {"text": "Import of subprocess"}}
      ]}},
      "results": [
        {
          "ruleId": "B404",
          "level": "warning",
          "message": {"text": "Consider possible security implications associated with subprocess module."},
          "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "src/molecule/util.py"},
            "region": {"startLine": 42}
          }}]
        }
      ]
    }
  ]
}
```

Create `.security/scripts/fixtures/pip-audit-high.sarif`:

```json
{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [
    {
      "tool": {"driver": {"name": "pip-audit", "version": "2.7.3", "rules": [
        {"id": "GHSA-xxxx-xxxx-xxxx", "name": "vuln", "shortDescription": {"text": "Example high-severity CVE"},
         "properties": {"security-severity": "8.1"}}
      ]}},
      "results": [
        {
          "ruleId": "GHSA-xxxx-xxxx-xxxx",
          "level": "error",
          "message": {"text": "Vulnerable version of somepkg"},
          "properties": {"security-severity": "8.1"},
          "locations": [{"physicalLocation": {"artifactLocation": {"uri": "uv.lock"}}}]
        }
      ]
    }
  ]
}
```

Create `.security/scripts/fixtures/gitleaks-low.sarif`:

```json
{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [
    {
      "tool": {"driver": {"name": "gitleaks", "version": "8.19.0", "rules": [
        {"id": "generic-api-key", "name": "leak", "shortDescription": {"text": "Generic API key pattern"}}
      ]}},
      "results": [
        {
          "ruleId": "generic-api-key",
          "level": "note",
          "message": {"text": "Match in test fixture"},
          "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "tests/fixtures/keys.txt"},
            "region": {"startLine": 1}
          }}]
        }
      ]
    }
  ]
}
```

- [ ] **Step 2: Run tests to verify they fail (script not written yet)**

Run: `python -m pytest .security/scripts/test_aggregate_sarif.py -v`
Expected: 8 tests FAIL / ERROR — `aggregate_sarif.py` does not exist yet.

- [ ] **Step 3: Implement the aggregator**

Create `.security/scripts/aggregate_sarif.py`:

```python
"""Aggregate per-scanner SARIF files, apply the allowlist, enforce the gate.

Exit codes:
    0 — no unlisted MEDIUM/HIGH/CRITICAL findings.
    1 — at least one unlisted MEDIUM+ finding.
    2 — configuration error (malformed allowlist, duplicate id, missing field).
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any

import yaml

BLOCKING = {"CRITICAL", "HIGH", "MEDIUM"}
LEVEL_TO_SEVERITY = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "LOW"}
REQUIRED_ALLOW_FIELDS = ("id", "reason", "owner", "expires")


@dataclass
class Finding:
    scanner: str
    rule_id: str
    severity: str
    file: str
    line: int
    message: str
    fingerprint: str

    def key(self) -> str:
        return f"{self.scanner}:{self.rule_id}"


@dataclass
class AllowEntry:
    id: str
    reason: str
    owner: str
    expires: date
    package: str | None = None
    path: str | None = None
    ticket: str | None = None


def _severity_from_result(result: dict[str, Any], rule: dict[str, Any] | None) -> str:
    props = (result.get("properties") or {}) | ((rule or {}).get("properties") or {})
    sev = props.get("security-severity")
    if sev is not None:
        try:
            score = float(sev)
        except ValueError:
            score = 0.0
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        return "LOW"
    level = (result.get("level") or "warning").lower()
    return LEVEL_TO_SEVERITY.get(level, "MEDIUM")


def _location(result: dict[str, Any]) -> tuple[str, int]:
    locs = result.get("locations") or []
    if not locs:
        return ("", 0)
    phys = locs[0].get("physicalLocation") or {}
    uri = (phys.get("artifactLocation") or {}).get("uri", "")
    region = phys.get("region") or {}
    return (uri, int(region.get("startLine", 0) or 0))


def load_sarif(path: Path) -> tuple[str, list[Finding], dict[str, Any]]:
    data = json.loads(path.read_text())
    findings: list[Finding] = []
    scanner = path.stem.replace("-", "_")
    for run in data.get("runs", []):
        driver = ((run.get("tool") or {}).get("driver") or {})
        name = (driver.get("name") or scanner).lower()
        rules_by_id = {r.get("id"): r for r in (driver.get("rules") or [])}
        for result in run.get("results", []):
            rule_id = result.get("ruleId") or ""
            rule = rules_by_id.get(rule_id)
            severity = _severity_from_result(result, rule)
            uri, line = _location(result)
            msg = ((result.get("message") or {}).get("text") or "").strip()
            fp = f"{name}:{rule_id}:{uri}:{line}"
            findings.append(Finding(name, rule_id, severity, uri, line, msg, fp))
    return scanner, findings, data


def load_allowlist(path: Path | None) -> list[AllowEntry]:
    if path is None or not path.exists():
        return []
    raw = yaml.safe_load(path.read_text()) or {}
    findings = raw.get("findings") or []
    if not isinstance(findings, list):
        raise SystemExit(_die("allowlist: `findings` must be a list"))
    entries: list[AllowEntry] = []
    seen_ids: set[str] = set()
    for i, item in enumerate(findings):
        if not isinstance(item, dict):
            raise SystemExit(_die(f"allowlist[{i}]: entry must be a mapping"))
        missing = [f for f in REQUIRED_ALLOW_FIELDS if not item.get(f)]
        if missing:
            raise SystemExit(_die(f"allowlist[{i}]: missing required fields {missing}"))
        if item["id"] in seen_ids:
            raise SystemExit(_die(f"allowlist[{i}]: duplicate id {item['id']!r}"))
        seen_ids.add(item["id"])
        try:
            expires = _to_date(item["expires"])
        except ValueError as exc:
            raise SystemExit(_die(f"allowlist[{i}]: bad expires: {exc}"))
        entries.append(AllowEntry(
            id=item["id"], reason=item["reason"], owner=item["owner"],
            expires=expires, package=item.get("package"),
            path=item.get("path"), ticket=item.get("ticket"),
        ))
    return entries


def _to_date(value: Any) -> date:
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        return datetime.strptime(value, "%Y-%m-%d").date()
    raise ValueError(f"expected YYYY-MM-DD, got {value!r}")


def is_allowed(finding: Finding, allow: list[AllowEntry], today: date) -> bool:
    for entry in allow:
        if entry.id != finding.key():
            continue
        if entry.expires < today:
            return False
        if entry.path and entry.path not in finding.file:
            continue
        return True
    return False


def render_markdown(findings: list[Finding], totals: dict[str, int], by_scanner: dict[str, dict[str, int]]) -> str:
    lines = ["# Security Gate Report", ""]
    lines.append("| Severity | Count |")
    lines.append("|---|---:|")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        lines.append(f"| {sev} | {totals.get(sev, 0)} |")
    lines += ["", "## By scanner", "", "| Scanner | CRITICAL | HIGH | MEDIUM | LOW |",
              "|---|---:|---:|---:|---:|"]
    for scanner, sev_counts in sorted(by_scanner.items()):
        lines.append(
            f"| {scanner} | {sev_counts.get('CRITICAL',0)} | {sev_counts.get('HIGH',0)} "
            f"| {sev_counts.get('MEDIUM',0)} | {sev_counts.get('LOW',0)} |"
        )
    blocking = [f for f in findings if f.severity in BLOCKING]
    if blocking:
        lines += ["", "## Top blocking findings (first 20)", "",
                  "| Scanner | Severity | Rule | Location | Message |",
                  "|---|---|---|---|---|"]
        for f in blocking[:20]:
            loc = f"{f.file}:{f.line}" if f.line else f.file
            lines.append(f"| {f.scanner} | {f.severity} | `{f.rule_id}` | `{loc}` | {f.message[:120]} |")
    lines += ["", "_Allowlist: `.security/allowlist.yml` — see `docs/security/allowlist.md`._"]
    return "\n".join(lines) + "\n"


def _die(msg: str) -> str:
    print(f"aggregate_sarif: ERROR: {msg}", file=sys.stderr)
    return msg


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sarif-dir", required=True, type=Path)
    ap.add_argument("--out-dir", required=True, type=Path)
    ap.add_argument("--allowlist", type=Path, default=None)
    ap.add_argument("--today", type=str, default=None,
                    help="Override today's date (YYYY-MM-DD) for testing")
    args = ap.parse_args(argv)

    today = _to_date(args.today) if args.today else date.today()

    try:
        allow = load_allowlist(args.allowlist)
    except SystemExit:
        return 2

    args.out_dir.mkdir(parents=True, exist_ok=True)

    all_findings: list[Finding] = []
    combined_runs: list[dict[str, Any]] = []
    by_scanner: dict[str, dict[str, int]] = {}

    sarif_files = sorted(args.sarif_dir.glob("*.sarif"))
    for path in sarif_files:
        _name, findings, data = load_sarif(path)
        all_findings.extend(findings)
        combined_runs.extend(data.get("runs", []))
        for f in findings:
            by_scanner.setdefault(f.scanner, {}).setdefault(f.severity, 0)
            by_scanner[f.scanner][f.severity] += 1

    totals: dict[str, int] = {}
    for f in all_findings:
        totals[f.severity] = totals.get(f.severity, 0) + 1

    unlisted_blocking = [
        f for f in all_findings
        if f.severity in BLOCKING and not is_allowed(f, allow, today)
    ]

    (args.out_dir / "security-combined.sarif").write_text(json.dumps(
        {"version": "2.1.0",
         "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
         "runs": combined_runs}, indent=2))

    (args.out_dir / "security-report.md").write_text(
        render_markdown(all_findings, totals, by_scanner)
    )

    (args.out_dir / "security-report.json").write_text(json.dumps({
        "schema_version": 1,
        "totals": totals,
        "by_scanner": by_scanner,
        "findings": [f.__dict__ for f in all_findings],
        "blocking_unlisted": [f.__dict__ for f in unlisted_blocking],
    }, indent=2, default=str))

    return 1 if unlisted_blocking else 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest .security/scripts/test_aggregate_sarif.py -v`
Expected: all 8 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add .security/scripts/
git commit -m "feat(security): SARIF aggregator with severity gate and allowlist"
```

---

## Task 3: Timing renderer + tests (TDD)

**Files:**
- Create: `.security/scripts/render_timing.py`
- Create: `.security/scripts/test_render_timing.py`
- Create: `.security/scripts/fixtures/gh_jobs.json`
- Create: `.security/scripts/fixtures/baseline.json`

**Interfaces:**
- Consumes: JSON from `gh api /repos/{o}/{r}/actions/runs/{id}/jobs`, `.security/baseline.json`, env vars from GitHub Actions context.
- Produces (called by `timing-report` job in Task 8):
  - CLI: `python .security/scripts/render_timing.py --jobs-json <file> --baseline .security/baseline.json --out-dir <dir> --run-id <id> --commit <sha> --event <event> --workflow security.yml`
  - Writes: `timing.json`, `timing.md`
  - Never fails (`return 0` even on missing baseline; prints a warning).

- [ ] **Step 1: Write the failing tests**

Create `.security/scripts/test_render_timing.py`:

```python
"""Unit tests for render_timing.

Run with: python -m pytest .security/scripts/test_render_timing.py -v
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"
SCRIPT = Path(__file__).parent / "render_timing.py"


def _run(tmp_path: Path, baseline: Path | None) -> tuple[int, Path]:
    out = tmp_path / "out"
    out.mkdir()
    cmd = [
        sys.executable, str(SCRIPT),
        "--jobs-json", str(FIXTURES / "gh_jobs.json"),
        "--out-dir", str(out),
        "--run-id", "42",
        "--commit", "deadbeef",
        "--event", "pull_request",
        "--workflow", "security.yml",
    ]
    if baseline is not None:
        cmd += ["--baseline", str(baseline)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, out


def test_writes_timing_json_and_md(tmp_path):
    code, out = _run(tmp_path, FIXTURES / "baseline.json")
    assert code == 0
    assert (out / "timing.json").exists()
    assert (out / "timing.md").exists()


def test_timing_json_schema(tmp_path):
    _, out = _run(tmp_path, FIXTURES / "baseline.json")
    data = json.loads((out / "timing.json").read_text())
    assert data["schema_version"] == 1
    assert data["run_id"] == 42
    assert data["commit"] == "deadbeef"
    assert data["workflow"] == "security.yml"
    assert isinstance(data["total_wallclock_s"], int)
    assert isinstance(data["jobs"], list)
    assert data["jobs"][0]["duration_s"] > 0


def test_markdown_has_delta_row(tmp_path):
    _, out = _run(tmp_path, FIXTURES / "baseline.json")
    md = (out / "timing.md").read_text()
    assert "CI Timing vs. baseline" in md
    assert "security.yml total" in md
    assert "%" in md


def test_missing_baseline_is_ok(tmp_path):
    code, out = _run(tmp_path, None)
    assert code == 0
    md = (out / "timing.md").read_text()
    assert "no baseline" in md.lower()
```

Create `.security/scripts/fixtures/gh_jobs.json` (trimmed shape mirroring `gh api`):

```json
{
  "total_count": 3,
  "jobs": [
    {"name": "sast-bandit", "started_at": "2026-08-05T00:00:00Z", "completed_at": "2026-08-05T00:00:42Z",
     "conclusion": "success"},
    {"name": "sca-pip-audit", "started_at": "2026-08-05T00:00:00Z", "completed_at": "2026-08-05T00:01:10Z",
     "conclusion": "success"},
    {"name": "security-gate", "started_at": "2026-08-05T00:01:10Z", "completed_at": "2026-08-05T00:01:38Z",
     "conclusion": "success"}
  ]
}
```

Create `.security/scripts/fixtures/baseline.json`:

```json
{
  "schema_version": 1,
  "captured_at": "2026-08-05",
  "workflows": {
    "security.yml": {"cold_total_s": 582, "warm_total_s_estimate": 210},
    "tox.yml": {"avg_total_s": 850, "samples": 5}
  }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest .security/scripts/test_render_timing.py -v`
Expected: 4 tests FAIL — `render_timing.py` missing.

- [ ] **Step 3: Implement the renderer**

Create `.security/scripts/render_timing.py`:

```python
"""Render CI timing artifact from `gh api` jobs JSON + baseline.

Produces `timing.json` (schema v1) and `timing.md` (comparison table).
Never fails — the timing job is informational.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path


def _duration_s(started: str, completed: str) -> int:
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    s = datetime.strptime(started, fmt)
    c = datetime.strptime(completed, fmt)
    return max(0, int((c - s).total_seconds()))


def _fmt_dur(seconds: int) -> str:
    m, s = divmod(seconds, 60)
    return f"{m}m{s:02d}s"


def _pct_delta(baseline: int | None, current: int) -> str:
    if not baseline:
        return "—"
    delta = (current - baseline) / baseline * 100
    sign = "−" if delta < 0 else "+"
    return f"{sign}{abs(delta):.1f}%"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs-json", required=True, type=Path)
    ap.add_argument("--out-dir", required=True, type=Path)
    ap.add_argument("--run-id", required=True, type=int)
    ap.add_argument("--commit", required=True)
    ap.add_argument("--event", required=True)
    ap.add_argument("--workflow", required=True)
    ap.add_argument("--baseline", type=Path, default=None)
    args = ap.parse_args(argv)

    data = json.loads(args.jobs_json.read_text())
    jobs_out = []
    total = 0
    for job in data.get("jobs", []):
        started, completed = job.get("started_at"), job.get("completed_at")
        if not started or not completed:
            continue
        dur = _duration_s(started, completed)
        jobs_out.append({"name": job["name"], "duration_s": dur,
                         "conclusion": job.get("conclusion")})
        total = max(total, dur) if job["name"] != "security-gate" else total + dur
    # Wall-clock ≈ max fan-out job + gate.
    fanout = [j["duration_s"] for j in jobs_out if j["name"] != "security-gate"]
    gate = [j["duration_s"] for j in jobs_out if j["name"] == "security-gate"]
    total = (max(fanout) if fanout else 0) + sum(gate)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "run_id": args.run_id,
        "workflow": args.workflow,
        "commit": args.commit,
        "event": args.event,
        "total_wallclock_s": total,
        "jobs": jobs_out,
    }
    (args.out_dir / "timing.json").write_text(json.dumps(payload, indent=2))

    lines = ["## CI Timing vs. baseline", "",
             "| Metric | Baseline | This run | Δ |",
             "|---|---:|---:|---:|"]
    if args.baseline and args.baseline.exists():
        base = json.loads(args.baseline.read_text())
        wf = base.get("workflows", {}).get(args.workflow, {})
        base_s = wf.get("warm_total_s_estimate") or wf.get("cold_total_s") or 0
        lines.append(f"| {args.workflow} total | {_fmt_dur(base_s)} "
                     f"| {_fmt_dur(total)} | {_pct_delta(base_s, total)} |")
        tox = base.get("workflows", {}).get("tox.yml", {})
        tox_base = tox.get("avg_total_s") or 0
        if tox_base:
            lines.append(f"| tox.yml total (baseline avg) | {_fmt_dur(tox_base)} | — | — |")
    else:
        lines.append(f"| {args.workflow} total | (no baseline) | {_fmt_dur(total)} | — |")

    lines += ["", "### Per-job", "", "| Job | Duration |", "|---|---:|"]
    for j in jobs_out:
        lines.append(f"| {j['name']} | {_fmt_dur(j['duration_s'])} |")
    (args.out_dir / "timing.md").write_text("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest .security/scripts/test_render_timing.py -v`
Expected: all 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add .security/scripts/render_timing.py .security/scripts/test_render_timing.py .security/scripts/fixtures/gh_jobs.json .security/scripts/fixtures/baseline.json
git commit -m "feat(security): timing renderer with baseline comparison"
```

---

## Task 4: Baseline capture script (manual, one-shot)

**Files:**
- Create: `.security/scripts/capture_baseline.py`

**Interfaces:**
- Consumes: `gh` CLI (must be authenticated), the repo's Actions API.
- Produces: `.security/baseline.json` — committed by the rollout task (Task 12), not by this task.
- CLI: `python .security/scripts/capture_baseline.py --repo fardani235/molecule --workflow tox.yml --n 5 --security-run-id <id> --out .security/baseline.json`

- [ ] **Step 1: Implement the script**

Create `.security/scripts/capture_baseline.py`:

```python
"""Capture CI timing baseline from the last N successful main-branch runs.

Runs once, manually, during rollout. Requires `gh` CLI authenticated for the
repo. The output file `.security/baseline.json` is committed as part of the
rollout PR — see docs/security/setup.md.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import date
from pathlib import Path
from statistics import mean


def _gh_json(*args: str) -> dict | list:
    proc = subprocess.run(["gh", "api", *args], capture_output=True, text=True, check=True)
    return json.loads(proc.stdout)


def _duration_s(run: dict) -> int:
    from datetime import datetime
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    return int((datetime.strptime(run["updated_at"], fmt)
                - datetime.strptime(run["run_started_at"], fmt)).total_seconds())


def capture_workflow_avg(repo: str, workflow: str, n: int) -> dict:
    data = _gh_json(f"/repos/{repo}/actions/workflows/{workflow}/runs"
                    f"?branch=main&status=success&per_page={n}")
    runs = data.get("workflow_runs", [])[:n]
    if not runs:
        return {"avg_total_s": 0, "samples": 0}
    durations = [_duration_s(r) for r in runs]
    return {"avg_total_s": int(mean(durations)), "samples": len(durations),
            "run_ids": [r["id"] for r in runs]}


def capture_security_cold(repo: str, run_id: int) -> dict:
    run = _gh_json(f"/repos/{repo}/actions/runs/{run_id}")
    return {"cold_total_s": _duration_s(run), "run_id": run_id,
            "warm_total_s_estimate": None}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--workflow", default="tox.yml")
    ap.add_argument("--n", type=int, default=5)
    ap.add_argument("--security-run-id", type=int, required=True,
                    help="Run ID of the first cold security.yml run.")
    ap.add_argument("--out", type=Path, default=Path(".security/baseline.json"))
    args = ap.parse_args(argv)

    baseline = {
        "schema_version": 1,
        "captured_at": date.today().isoformat(),
        "workflows": {
            args.workflow: capture_workflow_avg(args.repo, args.workflow, args.n),
            "security.yml": capture_security_cold(args.repo, args.security_run_id),
        },
    }
    args.out.write_text(json.dumps(baseline, indent=2))
    print(f"wrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Smoke-check the script imports cleanly**

Run: `python -c "import ast; ast.parse(open('.security/scripts/capture_baseline.py').read())"`
Expected: no output, exit 0.

- [ ] **Step 3: Commit**

```bash
git add .security/scripts/capture_baseline.py
git commit -m "feat(security): baseline capture script"
```

---

## Task 5: Composite action `security-setup`

**Files:**
- Create: `.github/actions/security-setup/action.yml`

**Interfaces:**
- Consumes: repo root files (`uv.lock`, `.security/tool-versions.env`, `.security/semgrep.yml`, etc.), inputs `python-version` (default `3.12`), `uv-sync-args` (default `--frozen`).
- Produces (used by every scanner job in Task 6, gate in Task 7, timing in Task 8):
  - Steps that leave `~/.cache/uv`, `~/.cache/pip`, `~/.cache/trivy`, `~/.semgrep`, `~/.cache/checkov`, `~/.ansible/collections` populated.
  - Outputs: `date-day`, `date-week`, `tools-loaded` (bool), `uv-cache-hit`, `trivy-cache-hit`, `semgrep-cache-hit`, `checkov-cache-hit`.
  - Loads `.security/tool-versions.env` variables into `$GITHUB_ENV`.

- [ ] **Step 1: Write the composite action**

Create `.github/actions/security-setup/action.yml`:

```yaml
---
name: "security-setup"
description: "Shared setup for every job in security.yml: checkout, python, uv, cache restores, date outputs, tool versions."
inputs:
  python-version:
    description: "Python version"
    required: false
    default: "3.12"
  uv-sync-args:
    description: "Args for `uv sync` (empty string skips sync)"
    required: false
    default: "--frozen"
outputs:
  date-day:
    description: "UTC day (YYYY-MM-DD) for daily-rotated cache keys"
    value: ${{ steps.date.outputs.day }}
  date-week:
    description: "ISO week (YYYY-Www) for weekly-rotated cache keys"
    value: ${{ steps.date.outputs.week }}
  uv-cache-hit:
    description: "true if uv cache was restored"
    value: ${{ steps.uv-cache.outputs.cache-hit }}
  trivy-cache-hit:
    value: ${{ steps.trivy-cache.outputs.cache-hit }}
  semgrep-cache-hit:
    value: ${{ steps.semgrep-cache.outputs.cache-hit }}
  checkov-cache-hit:
    value: ${{ steps.checkov-cache.outputs.cache-hit }}

runs:
  using: composite
  steps:
    - name: Checkout
      uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      with:
        fetch-depth: 0

    - name: Compute date outputs
      id: date
      shell: bash
      run: |
        echo "day=$(date -u +%Y-%m-%d)" >> "$GITHUB_OUTPUT"
        echo "week=$(date -u +%Y-W%V)" >> "$GITHUB_OUTPUT"

    - name: Load pinned tool versions into GITHUB_ENV
      shell: bash
      run: |
        set -euo pipefail
        grep -E '^[A-Z_]+=' .security/tool-versions.env >> "$GITHUB_ENV"

    - name: Set up Python
      uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5.6.0
      with:
        python-version: ${{ inputs.python-version }}
        cache: "pip"
        cache-dependency-path: uv.lock

    - name: Set up uv
      id: setup-uv
      uses: astral-sh/setup-uv@f0ec1fc3b38f5e7cd731bb6ce540c5af426746bb # v6.9.0
      with:
        enable-cache: true
        cache-dependency-glob: "uv.lock"

    - name: Restore uv cache
      id: uv-cache
      uses: actions/cache/restore@1bd1e32a3bdc45362d1e726936510720a7c30a57 # v4.2.0
      with:
        path: ~/.cache/uv
        key: uv-${{ runner.os }}-${{ hashFiles('uv.lock') }}
        restore-keys: |
          uv-${{ runner.os }}-

    - name: uv sync
      if: ${{ inputs.uv-sync-args != '' }}
      shell: bash
      run: uv sync ${{ inputs.uv-sync-args }}

    - name: Save uv cache
      if: ${{ always() && steps.uv-cache.outputs.cache-hit != 'true' }}
      uses: actions/cache/save@1bd1e32a3bdc45362d1e726936510720a7c30a57 # v4.2.0
      with:
        path: ~/.cache/uv
        key: uv-${{ runner.os }}-${{ hashFiles('uv.lock') }}

    - name: Restore pipx / pip cache
      id: pipx-cache
      uses: actions/cache/restore@1bd1e32a3bdc45362d1e726936510720a7c30a57 # v4.2.0
      with:
        path: |
          ~/.local/pipx
          ~/.cache/pip
        key: pipx-${{ runner.os }}-${{ hashFiles('.security/tool-versions.env') }}
        restore-keys: |
          pipx-${{ runner.os }}-

    - name: Save pipx / pip cache
      if: ${{ always() && steps.pipx-cache.outputs.cache-hit != 'true' }}
      uses: actions/cache/save@1bd1e32a3bdc45362d1e726936510720a7c30a57 # v4.2.0
      with:
        path: |
          ~/.local/pipx
          ~/.cache/pip
        key: pipx-${{ runner.os }}-${{ hashFiles('.security/tool-versions.env') }}

    - name: Restore Trivy DB cache
      id: trivy-cache
      uses: actions/cache/restore@1bd1e32a3bdc45362d1e726936510720a7c30a57 # v4.2.0
      with:
        path: ~/.cache/trivy
        key: trivy-db-${{ steps.date.outputs.day }}
        restore-keys: |
          trivy-db-

    - name: Restore Semgrep rule cache
      id: semgrep-cache
      uses: actions/cache/restore@1bd1e32a3bdc45362d1e726936510720a7c30a57 # v4.2.0
      with:
        path: |
          ~/.semgrep
          ~/.cache/semgrep
        key: semgrep-${{ hashFiles('.security/semgrep.yml') }}-${{ steps.date.outputs.week }}
        restore-keys: |
          semgrep-

    - name: Restore Checkov cache
      id: checkov-cache
      uses: actions/cache/restore@1bd1e32a3bdc45362d1e726936510720a7c30a57 # v4.2.0
      with:
        path: ~/.cache/checkov
        key: checkov-${{ steps.date.outputs.week }}
        restore-keys: |
          checkov-

    - name: Restore ansible-collections cache
      id: ansible-cache
      uses: actions/cache/restore@1bd1e32a3bdc45362d1e726936510720a7c30a57 # v4.2.0
      with:
        path: ~/.ansible/collections
        key: ansible-collections-${{ hashFiles('community.molecule/galaxy.yml', 'tests/**/requirements.yml') }}
        restore-keys: |
          ansible-collections-
```

- [ ] **Step 2: Lint the composite action locally**

Run: `pipx run actionlint .github/actions/security-setup/action.yml` if actionlint is available; else visually verify the YAML with `python -c "import yaml,sys; yaml.safe_load(open('.github/actions/security-setup/action.yml'))"`.
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add .github/actions/security-setup/
git commit -m "feat(security): composite action for shared scanner setup"
```

---

## Task 6: `security.yml` — prepare + 8 scanner jobs (informational)

**Files:**
- Create: `.github/workflows/security.yml`

**Interfaces:**
- Consumes: `.github/actions/security-setup` (Task 5), `.security/*` configs (Task 1).
- Produces: 8 uploaded artifacts `sarif-<scanner>`, each containing `<scanner>.sarif` (+ native JSON where applicable). Consumed by `security-gate` in Task 7.
- All scanner jobs run with `continue-on-error: true` in this task — the workflow does not block PRs yet.

- [ ] **Step 1: Write the workflow skeleton with prepare and all scanner jobs**

Create `.github/workflows/security.yml`:

```yaml
---
# FORK-ONLY — runs exclusively in fardani235/molecule.
# See docs/superpowers/specs/2026-08-05-devsecops-ci-improvements-design.md.
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
    - cron: "0 3 * * 1"
  workflow_dispatch:

concurrency:
  group: security-${{ github.event.pull_request.number || github.ref }}
  cancel-in-progress: true

permissions: read-all

jobs:
  prepare:
    if: github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    outputs:
      date-day: ${{ steps.setup.outputs.date-day }}
      date-week: ${{ steps.setup.outputs.date-week }}
    steps:
      - id: setup
        uses: ./.github/actions/security-setup
        with:
          uv-sync-args: ""

  sast-bandit:
    needs: prepare
    if: github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    continue-on-error: true
    permissions:
      contents: read
      security-events: write
    steps:
      - id: setup
        uses: ./.github/actions/security-setup

      - name: Install Bandit
        run: pipx install "bandit[toml]==${BANDIT_VERSION}"

      - name: Run Bandit (SARIF)
        run: |
          mkdir -p sarif-out
          bandit -c .security/bandit.yaml -r src/molecule -f sarif -o sarif-out/bandit.sarif || true
          bandit -c .security/bandit.yaml -r src/molecule -f json -o sarif-out/bandit.json || true

      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: sarif-bandit
          path: sarif-out/
          retention-days: 30

  sast-semgrep:
    needs: prepare
    if: github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    continue-on-error: true
    permissions:
      contents: read
      security-events: write
    steps:
      - id: setup
        uses: ./.github/actions/security-setup
        with:
          uv-sync-args: ""

      - name: Install Semgrep
        run: pipx install "semgrep==${SEMGREP_VERSION}"

      - name: Run Semgrep (SARIF)
        run: |
          mkdir -p sarif-out
          semgrep scan \
            --config p/python \
            --config p/security-audit \
            --config p/owasp-top-ten \
            --config p/ci \
            --config .security/semgrep.yml \
            --sarif --output sarif-out/semgrep.sarif || true

      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: sarif-semgrep
          path: sarif-out/
          retention-days: 30

  sca-pip-audit:
    needs: prepare
    if: github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    continue-on-error: true
    permissions:
      contents: read
      security-events: write
    steps:
      - id: setup
        uses: ./.github/actions/security-setup

      - name: Install pip-audit
        run: pipx install "pip-audit==${PIP_AUDIT_VERSION}"

      - name: Export requirements from uv
        run: uv export --frozen --format requirements-txt > requirements.txt

      - name: Run pip-audit (SARIF + JSON)
        run: |
          mkdir -p sarif-out
          pip-audit -r requirements.txt --format sarif --output sarif-out/pip-audit.sarif || true
          pip-audit -r requirements.txt --format json --output sarif-out/pip-audit.json || true

      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: sarif-pip-audit
          path: sarif-out/
          retention-days: 30

  sca-trivy-fs:
    needs: prepare
    if: github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    continue-on-error: true
    permissions:
      contents: read
      security-events: write
    steps:
      - id: setup
        uses: ./.github/actions/security-setup
        with:
          uv-sync-args: ""

      - name: Trivy fs (vuln)
        uses: aquasecurity/trivy-action@6c175e9c4083a92bbca2f9724c8a5e33bc2d97a5 # v0.30.0
        with:
          scan-type: fs
          scanners: vuln
          format: sarif
          output: sarif-out/trivy-fs.sarif
          ignore-unfixed: false
          severity: LOW,MEDIUM,HIGH,CRITICAL
          exit-code: "0"

      - name: Ensure output dir + save cache
        run: mkdir -p sarif-out && ls -la sarif-out || true

      - uses: actions/cache/save@1bd1e32a3bdc45362d1e726936510720a7c30a57 # v4.2.0
        if: always()
        with:
          path: ~/.cache/trivy
          key: trivy-db-${{ needs.prepare.outputs.date-day }}

      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: sarif-trivy-fs
          path: sarif-out/
          retention-days: 30

  secrets-gitleaks:
    needs: prepare
    if: github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    continue-on-error: true
    permissions:
      contents: read
      security-events: write
    steps:
      - id: setup
        uses: ./.github/actions/security-setup
        with:
          uv-sync-args: ""

      - name: Gitleaks
        uses: gitleaks/gitleaks-action@ff98106e4c7b2bc287b24eaf42907196329070c7 # v2.3.9
        env:
          GITHUB_TOKEN: ${{ github.token }}
          GITLEAKS_CONFIG: .gitleaks.toml
          GITLEAKS_ENABLE_UPLOAD_ARTIFACT: "false"
          GITLEAKS_ENABLE_COMMENTS: "false"

      - name: Move report into sarif-out
        run: |
          mkdir -p sarif-out
          if [[ -f results.sarif ]]; then mv results.sarif sarif-out/gitleaks.sarif; fi
          if [[ -f results.json  ]]; then mv results.json  sarif-out/gitleaks.json;  fi
          ls -la sarif-out || true

      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: sarif-gitleaks
          path: sarif-out/
          retention-days: 30

  iac-checkov:
    needs: prepare
    if: github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    continue-on-error: true
    permissions:
      contents: read
      security-events: write
    steps:
      - id: setup
        uses: ./.github/actions/security-setup
        with:
          uv-sync-args: ""

      - name: Install Checkov
        run: pipx install "checkov==${CHECKOV_VERSION}"

      - name: Run Checkov
        run: |
          mkdir -p sarif-out
          checkov --config-file .security/checkov.yml \
                  --directory . \
                  --output-file-path sarif-out || true
          # Checkov writes results_sarif.sarif into --output-file-path directory.
          if [[ -f sarif-out/results_sarif.sarif ]]; then
            mv sarif-out/results_sarif.sarif sarif-out/checkov.sarif
          fi

      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: sarif-checkov
          path: sarif-out/
          retention-days: 30

  iac-ansible-lint:
    needs: prepare
    if: github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    continue-on-error: true
    permissions:
      contents: read
      security-events: write
    steps:
      - id: setup
        uses: ./.github/actions/security-setup

      - name: Install ansible-lint
        run: pipx install "ansible-lint==${ANSIBLE_LINT_VERSION}"

      - name: Run ansible-lint (SARIF)
        run: |
          mkdir -p sarif-out
          ansible-lint --profile production \
            --sarif-file sarif-out/ansible-lint.sarif \
            community.molecule tests/fixtures || true

      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: sarif-ansible-lint
          path: sarif-out/
          retention-days: 30

  sbom-cyclonedx:
    needs: prepare
    if: github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    continue-on-error: true
    permissions:
      contents: read
    steps:
      - id: setup
        uses: ./.github/actions/security-setup

      - name: Install CycloneDX-Python
        run: pipx install "cyclonedx-bom==${CYCLONEDX_PY_VERSION}"

      - name: Generate Python env SBOM (CycloneDX)
        run: |
          mkdir -p sbom-out
          cyclonedx-py environment --output-file sbom-out/sbom-python.cdx.json

      - name: Generate repo SBOM (Syft, SPDX JSON)
        uses: anchore/sbom-action@9246b90769f852b3a8921f330c59e0b3f439d6e9 # v0.17.7
        with:
          format: spdx-json
          output-file: sbom-out/sbom-repo.spdx.json
          artifact-name: sbom-repo.spdx.json
          upload-artifact: false

      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: sbom
          path: sbom-out/
          retention-days: 365

  license-trivy:
    needs: prepare
    if: github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    continue-on-error: true
    permissions:
      contents: read
      security-events: write
    steps:
      - id: setup
        uses: ./.github/actions/security-setup
        with:
          uv-sync-args: ""

      - name: Trivy fs (license)
        uses: aquasecurity/trivy-action@6c175e9c4083a92bbca2f9724c8a5e33bc2d97a5 # v0.30.0
        with:
          scan-type: fs
          scanners: license
          format: sarif
          output: sarif-out/trivy-license.sarif
          severity: LOW,MEDIUM,HIGH,CRITICAL
          exit-code: "0"

      - name: Also emit JSON for auditing
        uses: aquasecurity/trivy-action@6c175e9c4083a92bbca2f9724c8a5e33bc2d97a5 # v0.30.0
        with:
          scan-type: fs
          scanners: license
          format: json
          output: sarif-out/trivy-license.json
          exit-code: "0"

      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: sarif-license-trivy
          path: sarif-out/
          retention-days: 30
```

- [ ] **Step 2: Validate the YAML parses**

Run: `python -c "import yaml; yaml.safe_load(open('.github/workflows/security.yml'))"`
Expected: no output, exit 0.

- [ ] **Step 3: Run actionlint if available (skip if not installed)**

Run: `pipx run actionlint .github/workflows/security.yml`
Expected: no errors. If actionlint is unavailable, this is not blocking.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/security.yml
git commit -m "feat(security): scanner fan-out workflow (informational, continue-on-error)"
```

---

## Task 7: `security-gate` job (still informational — `continue-on-error: true`)

**Files:**
- Modify: `.github/workflows/security.yml` (append `security-gate` job)

**Interfaces:**
- Consumes: all `sarif-*` and `sbom` artifacts from Task 6, `.security/allowlist.yml` (Task 1), `.security/scripts/aggregate_sarif.py` (Task 2).
- Produces: `security-report` artifact with `security-report.md`, `security-report.json`, `security-combined.sarif`. Uploads merged SARIF to Code Scanning. Posts sticky PR comment.

- [ ] **Step 1: Add the `security-gate` job**

Append to `.github/workflows/security.yml`:

```yaml

  security-gate:
    needs:
      - sast-bandit
      - sast-semgrep
      - sca-pip-audit
      - sca-trivy-fs
      - secrets-gitleaks
      - iac-checkov
      - iac-ansible-lint
      - license-trivy
    if: ${{ always() && github.repository == 'fardani235/molecule' }}
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    continue-on-error: true          # Flipped to false in Task 12.
    permissions:
      contents: read
      security-events: write
      pull-requests: write
    steps:
      - id: setup
        uses: ./.github/actions/security-setup
        with:
          uv-sync-args: ""

      - name: Download all scanner artifacts
        uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4.3.0
        with:
          path: downloaded-artifacts
          pattern: sarif-*
          merge-multiple: false

      - name: Collect SARIF into a single directory
        run: |
          set -euo pipefail
          mkdir -p sarif-in
          find downloaded-artifacts -type f -name '*.sarif' -exec cp -v {} sarif-in/ \;
          ls -la sarif-in

      - name: Aggregate + apply allowlist
        id: aggregate
        run: |
          set +e
          python .security/scripts/aggregate_sarif.py \
            --sarif-dir sarif-in \
            --allowlist .security/allowlist.yml \
            --out-dir gate-out
          echo "exit_code=$?" >> "$GITHUB_OUTPUT"

      - name: Upload merged SARIF to Code Scanning
        if: ${{ always() }}
        uses: github/codeql-action/upload-sarif@a4b53e2c4b0a4d2a5c8b0d3f8c7a2e9b1c4d5e6f # v3.28.10
        with:
          sarif_file: gate-out/security-combined.sarif
          category: security-gate

      - name: Upload security-report artifact
        if: ${{ always() }}
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: security-report
          path: gate-out/
          retention-days: 90

      - name: Write step summary
        if: ${{ always() }}
        run: cat gate-out/security-report.md >> "$GITHUB_STEP_SUMMARY"

      - name: Post sticky PR comment
        if: ${{ always() && github.event_name == 'pull_request' }}
        uses: marocchino/sticky-pull-request-comment@52423e01640425a022ef5fd42c6fb5f633a02728 # v2.9.1
        with:
          header: security-gate:v1
          path: gate-out/security-report.md

      - name: Enforce gate exit code
        run: exit "${{ steps.aggregate.outputs.exit_code }}"
```

- [ ] **Step 2: Validate**

Run: `python -c "import yaml; yaml.safe_load(open('.github/workflows/security.yml'))"`
Expected: parses cleanly.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/security.yml
git commit -m "feat(security): gate job aggregates SARIF and enforces threshold (informational)"
```

---

## Task 8: `timing-report` job

**Files:**
- Modify: `.github/workflows/security.yml` (append `timing-report` job)

**Interfaces:**
- Consumes: `gh api /repos/.../actions/runs/${{ github.run_id }}/jobs`, `.security/baseline.json` (may not exist yet), `.security/scripts/render_timing.py` (Task 3).
- Produces: `ci-timing` artifact (`timing.json`, `timing.md`). Appends timing markdown to the sticky comment.

- [ ] **Step 1: Add the `timing-report` job**

Append to `.github/workflows/security.yml`:

```yaml

  timing-report:
    needs: security-gate
    if: ${{ always() && github.repository == 'fardani235/molecule' }}
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    continue-on-error: true
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

      - name: Set up Python
        uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5.6.0
        with:
          python-version: "3.12"

      - name: Fetch this run's jobs JSON
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          gh api "/repos/${{ github.repository }}/actions/runs/${{ github.run_id }}/jobs?per_page=100" \
            > jobs.json

      - name: Render timing report
        run: |
          mkdir -p timing-out
          BASELINE_ARG=()
          if [[ -f .security/baseline.json ]]; then
            BASELINE_ARG=(--baseline .security/baseline.json)
          fi
          python .security/scripts/render_timing.py \
            --jobs-json jobs.json \
            --out-dir timing-out \
            --run-id "${{ github.run_id }}" \
            --commit "${{ github.sha }}" \
            --event "${{ github.event_name }}" \
            --workflow security.yml \
            "${BASELINE_ARG[@]}"

      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: ci-timing
          path: timing-out/
          retention-days: 90

      - name: Write timing to step summary
        run: cat timing-out/timing.md >> "$GITHUB_STEP_SUMMARY"

      - name: Append timing to sticky PR comment
        if: ${{ github.event_name == 'pull_request' }}
        uses: marocchino/sticky-pull-request-comment@52423e01640425a022ef5fd42c6fb5f633a02728 # v2.9.1
        with:
          header: security-gate:v1
          append: true
          path: timing-out/timing.md
```

- [ ] **Step 2: Validate the YAML**

Run: `python -c "import yaml; yaml.safe_load(open('.github/workflows/security.yml'))"`
Expected: parses cleanly.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/security.yml
git commit -m "feat(security): timing-report job publishes per-run comparison"
```

---

## Task 9: Dependabot configuration

**Files:**
- Create: `.github/dependabot.yml`

**Interfaces:**
- Consumes: repo-level Dependabot enablement (a repo setting; documented in Task 11).
- Produces: weekly alerts + version-update PRs for `pip`, `github-actions`, `docker` ecosystems.

- [ ] **Step 1: Create the Dependabot config**

Create `.github/dependabot.yml`:

```yaml
---
version: 2
updates:
  - package-ecosystem: pip
    directory: "/"
    schedule:
      interval: weekly
      day: monday
    open-pull-requests-limit: 10
    groups:
      pip-minor-patch:
        update-types: ["minor", "patch"]

  - package-ecosystem: github-actions
    directory: "/"
    schedule:
      interval: weekly
      day: monday
    open-pull-requests-limit: 5
    groups:
      github-actions-all:
        patterns: ["*"]

  - package-ecosystem: docker
    directory: "/"
    schedule:
      interval: weekly
      day: monday
    open-pull-requests-limit: 5
```

- [ ] **Step 2: Validate YAML**

Run: `python -c "import yaml; yaml.safe_load(open('.github/dependabot.yml'))"`
Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add .github/dependabot.yml
git commit -m "chore(security): enable Dependabot for pip, actions, docker"
```

---

## Task 10: Additive release-artifact upload in `release.yml`

**Files:**
- Modify: `.github/workflows/release.yml`

**Interfaces:**
- Consumes: existing `release` job's `dist/` output and existing `publish-collection` job's `*.tar.gz` output.
- Produces: `release-dists` artifact downloadable from the Actions run page. Existing publish steps and their behavior are unchanged.

- [ ] **Step 1: Add artifact upload after the build step of the `release` job**

Locate the `release` job's `Build dists` step (line reference: `- name: Build dists\n  run: python3 -m tox -e pkg`). Immediately after that step and BEFORE the `Publish to pypi.org` step, add:

```yaml
      - name: Upload built distributions as artifact
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: release-dists
          path: dist/
          retention-days: 90
```

- [ ] **Step 2: Add artifact upload in `publish-collection` job**

In the `publish-collection` job, immediately after the `Build the collection` step (before the `Publish the collection on Galaxy` step), add:

```yaml
      - name: Upload built collection tarball as artifact
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: release-dists
          path: "*.tar.gz"
          retention-days: 90
          overwrite: false
```

- [ ] **Step 3: Validate the YAML**

Run: `python -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))"`
Expected: no output.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "feat(release): upload built dists and collection tarball as artifacts"
```

---

## Task 11: Operational docs + README link

**Files:**
- Create: `docs/security/setup.md`
- Create: `docs/security/monitoring.md`
- Create: `docs/security/allowlist.md`
- Modify: `README.md` (add Security section)

**Interfaces:**
- Consumes: everything shipped in Tasks 1–10.
- Produces: human-facing operational runbook. Referenced by README.

- [ ] **Step 1: Write `docs/security/setup.md`**

Create `docs/security/setup.md`:

````markdown
# DevSecOps CI — One-Time Setup

Fork-only workflow for `fardani235/molecule`.

## 1. Enable repo-level protections (Settings → Code security)

- Dependabot alerts: **on**.
- Dependabot security updates: **on**.
- Secret scanning: **on**.
- Push protection: **on**.

## 2. Configure branch protection on `main`

```bash
gh api -X PUT "/repos/fardani235/molecule/branches/main/protection" \
  --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["security-gate", "tox"]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": {"required_approving_review_count": 1},
  "restrictions": null,
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
```

## 3. Capture the timing baseline

After `security.yml` has run once cold on `main`:

```bash
# Find the run id of the first cold security.yml run on main:
gh run list --workflow security.yml --branch main --limit 5

python .security/scripts/capture_baseline.py \
  --repo fardani235/molecule \
  --workflow tox.yml \
  --n 5 \
  --security-run-id <RUN_ID> \
  --out .security/baseline.json

git add .security/baseline.json
git commit -m "chore(security): capture CI timing baseline"
```

## 4. Flip the gate to strict (Task 12)

Open a PR that:

1. Removes `continue-on-error: true` from every scanner job and the
   `security-gate` job in `.github/workflows/security.yml`.
2. Keeps `continue-on-error: true` on `timing-report` (informational).
3. Includes the measured cold-vs-warm speedup numbers in the PR body.

## 5. Break-glass

To bypass the gate on an exceptional PR, add the `skip-security` label.
Requires repo-owner sign-off in the PR body.
````

- [ ] **Step 2: Write `docs/security/monitoring.md`**

Create `docs/security/monitoring.md`:

````markdown
# DevSecOps CI — Where to Look

## Per-run artifacts (Actions tab)

- `sarif-<scanner>` — raw scanner output (SARIF + native JSON), 30-day retention.
- `security-report` — merged SARIF + `security-report.md` / `.json`, 90-day retention.
- `sbom` — CycloneDX (Python env) + SPDX (repo), 365-day retention.
- `ci-timing` — `timing.json` + `timing.md`, 90-day retention.
- `release-dists` — built wheels/sdists + collection tarball, 90-day retention.

Download with:

```bash
gh run download <RUN_ID> -n security-report
```

## Continuous surfaces

- **Security → Code scanning alerts** — inline PR annotations, dismissals.
- **Security → Dependabot alerts** — CVE-driven, independent of CI.
- **Security → Secret scanning alerts** — push protection + retro scans.

## Schedules

- Weekly re-scan of `main`: `cron: '0 3 * * 1'` (Mondays 03:00 UTC).

## Trend queries

Every timing / security report artifact is fetchable via:

```bash
gh api "/repos/fardani235/molecule/actions/artifacts?per_page=100"
```

`timing.json` and `security-report.json` both use `schema_version: 1` so a
future dashboard can safely accumulate history.
````

- [ ] **Step 3: Write `docs/security/allowlist.md`**

Create `docs/security/allowlist.md`:

````markdown
# Security Allowlist Policy

File: `.security/allowlist.yml`. Used by
`.security/scripts/aggregate_sarif.py`.

## Required fields per entry

- `id` — `<scanner>:<rule_id>` (e.g. `pip-audit:GHSA-xxxx-xxxx-xxxx`,
  `bandit:B404`).
- `reason` — why the finding is acceptable. One sentence.
- `owner` — GitHub handle taking responsibility.
- `expires` — ISO 8601 date (YYYY-MM-DD). **Expired entries re-enter the
  gate.**
- `ticket` (optional) — URL to a tracking issue.
- `package` (optional, scanner-specific) — package name for SCA entries.
- `path` (optional) — restricts the allowlist to a specific file path.

## Rules enforced by the aggregator

1. Missing `id`, `reason`, `owner`, or `expires` → gate fails (exit 2).
2. `expires` in the past → finding re-enters the gate.
3. Duplicate `id` → gate fails (exit 2).

## Review process

1. Open a PR that adds the entry with a `security-allowlist` label.
2. PR body cites the vulnerability advisory, exploit prerequisites, and
   why we accept the risk.
3. Owner must be the person who will re-triage on `expires`.
4. Maximum `expires` window: **90 days** — extend by renewing, not by
   long expiries.
````

- [ ] **Step 4: Add a Security section to README**

Add to `README.md`, immediately after the "Documentation" section:

```markdown
## Security

This fork ships a DevSecOps CI pipeline. See:

- [`docs/security/setup.md`](docs/security/setup.md) — one-time setup and
  branch protection.
- [`docs/security/monitoring.md`](docs/security/monitoring.md) — where to
  find artifacts and continuous surfaces.
- [`docs/security/allowlist.md`](docs/security/allowlist.md) — how to add
  or edit `.security/allowlist.yml`.
```

- [ ] **Step 5: Validate the markdown parses**

Run: `python -c "import pathlib; [pathlib.Path(p).read_text() for p in ['docs/security/setup.md','docs/security/monitoring.md','docs/security/allowlist.md','README.md']]"`
Expected: no exceptions.

- [ ] **Step 6: Commit**

```bash
git add docs/security/ README.md
git commit -m "docs(security): setup, monitoring, allowlist runbooks"
```

---

## Task 12: Rollout — capture baseline and flip strict gate

**Files:**
- Create: `.security/baseline.json` (via `capture_baseline.py`)
- Modify: `.github/workflows/security.yml` (remove `continue-on-error: true` from scanner jobs and `security-gate`)

**Interfaces:**
- Consumes: `.security/scripts/capture_baseline.py` (Task 4), a successful cold run of `security.yml` on `main`.
- Produces: strict gate enabled; branch protection can require `security-gate`.

**Preconditions:** Tasks 1–11 merged to `main`; at least one cold `security.yml` run has completed on `main` with a run id.

- [ ] **Step 1: Capture the baseline**

Run:

```bash
gh run list --workflow security.yml --branch main --limit 5
# Note the run id of the first cold run.

python .security/scripts/capture_baseline.py \
  --repo fardani235/molecule \
  --workflow tox.yml \
  --n 5 \
  --security-run-id <RUN_ID> \
  --out .security/baseline.json
```

- [ ] **Step 2: Manually add the warm estimate**

Trigger a second `security.yml` run via `workflow_dispatch` so caches populate. Then trigger a third — this is the "warm" run. Read its total wall-clock from `gh api /repos/fardani235/molecule/actions/runs/<WARM_RUN_ID>` (or the `timing.json` artifact) and set the `warm_total_s_estimate` field:

```bash
python - <<'PY'
import json, pathlib
p = pathlib.Path(".security/baseline.json")
data = json.loads(p.read_text())
data["workflows"]["security.yml"]["warm_total_s_estimate"] = <WARM_TOTAL_SECONDS>
p.write_text(json.dumps(data, indent=2))
PY
```

- [ ] **Step 3: Flip the strict gate**

In `.github/workflows/security.yml`, remove the line `continue-on-error: true` from every job EXCEPT `timing-report`. Verify only `timing-report` retains it:

Run: `grep -n 'continue-on-error' .github/workflows/security.yml`
Expected: exactly one match, inside the `timing-report` job block.

- [ ] **Step 4: Validate the workflow YAML**

Run: `python -c "import yaml; yaml.safe_load(open('.github/workflows/security.yml'))"`
Expected: no output.

- [ ] **Step 5: Compose the rollout PR body**

The PR body MUST include a Markdown table of measured numbers from the baseline (paste from `timing.md` of the warm run). Template:

```markdown
## CI speedup — measured

| Metric                | Cold run | Warm run | Δ        |
|-----------------------|---------:|---------:|---------:|
| security.yml total    | <cold>   | <warm>   | <delta>  |
| tox.yml avg (5 runs)  | <avg>    | n/a      | n/a      |

Cold run: <link>. Warm run: <link>.
```

- [ ] **Step 6: Apply branch protection**

Run the `gh api` snippet from `docs/security/setup.md` §2 to require the `security-gate` check on `main`.

- [ ] **Step 7: Commit and open the rollout PR**

```bash
git add .security/baseline.json .github/workflows/security.yml
git commit -m "feat(security): flip gate to strict; capture baseline

- Baseline: last 5 successful tox.yml runs + first cold security.yml run.
- All scanner jobs and security-gate now block on unlisted MEDIUM+ findings.
- timing-report remains informational.
- Speedup numbers included in PR body."
gh pr create --title "feat(security): flip DevSecOps gate to strict" --body-file <(cat)
```

---

## Self-review checklist

Ran against the spec at `docs/superpowers/specs/2026-08-05-devsecops-ci-improvements-design.md`:

**Spec coverage (§ → task):**
- §2.1 Triggers → Task 6 (workflow header).
- §2.2 Concurrency → Task 6.
- §2.3 Job graph → Tasks 6, 7, 8.
- §2.4 Permissions → Tasks 6, 7, 8.
- §3 Scanner matrix (all 8 tools) → Task 6.
- §3.1 Composite action → Task 5.
- §3.2 Config files → Task 1.
- §3.3 SARIF normalization → Task 2 (aggregator handles level→severity mapping).
- §4.1 Threshold policy → Task 2 tests + implementation.
- §4.2 Gate flow → Task 7.
- §4.3 Allowlist schema → Tasks 1 + 2.
- §4.4 Required-check wiring → Task 11 (`setup.md`) + Task 12.
- §4.5 Failure UX → Task 2 (markdown renderer) + Task 7 (sticky comment).
- §5 Caching → Task 5 (composite action).
- §6.1 Artifacts + retention → Tasks 6, 7, 8, 10.
- §6.2 Monitoring surfaces → Tasks 9, 11.
- §6.3 Trend view → Tasks 2, 3 (schema_version); Task 11 (monitoring doc).
- §6.4 Release artifacts → Task 10.
- §7 Speedup measurement → Tasks 3, 4, 8, 12.
- §8.1 Fork-only guard → Task 6 (every job has `if:`).
- §8.2 Secrets → Task 6 (no secrets used).
- §8.3 Supply-chain hygiene → Task 6 (SHA pins everywhere).
- §8.4 Rollout order → Tasks 6–8 land informational; Task 12 flips.
- §8.5 Fork-sync safety → All new paths are fork-only.
- §8.6 Operational docs → Task 11.
- §8.7 Non-goals → respected (Task 10 is additive-only).
- §9 Acceptance criteria (13 items) → all covered across Tasks 1–12.
- §10 Risks → mitigations already encoded (weekly schedule in Task 6, allowlist expires enforced in Task 2, restore-keys in Task 5).

**Placeholder scan:** none. Every step has concrete content or a concrete command.

**Type / name consistency:**
- `aggregate_sarif.py` CLI flags (`--sarif-dir`, `--out-dir`, `--allowlist`) match between Tasks 2 and 7. ✓
- `render_timing.py` CLI flags match between Tasks 3 and 8. ✓
- Composite action outputs (`date-day`, `date-week`, `uv-cache-hit`, ...) declared in Task 5 and referenced in Task 6 (`needs.prepare.outputs.date-day`). ✓
- Artifact names (`sarif-<scanner>`, `sbom`, `security-report`, `ci-timing`, `release-dists`) consistent across upload sites (Tasks 6, 7, 8, 10) and download sites (Task 7). ✓
- Sticky comment header `security-gate:v1` matches between Tasks 7 and 8. ✓
- Severity strings (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) consistent between aggregator, tests, and reports. ✓

No unresolved gaps.

---

**Plan complete and saved to `docs/superpowers/plans/2026-08-05-devsecops-ci-improvements.md`.**
