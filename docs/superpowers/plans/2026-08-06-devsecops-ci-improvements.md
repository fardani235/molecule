# DevSecOps CI Improvements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add SAST/SCA/Secrets/IaC/SBOM security scanning with a PR-blocking gate on medium/high/critical findings, add caching for Python/pre-commit/scanner-DB/Ansible layers, produce downloadable artifacts for scans and packaged builds, and provide a workflow that measures CI speedup — all fork-only, without touching the delegated upstream `tox.yml`.

**Architecture:** Three new workflows (`security.yml`, `build-artifacts.yml`, `benchmark.yml`) live alongside existing ones. A `.github/security/` config tree holds per-tool waivers, and a `gate.py` script aggregates SARIF and enforces the severity threshold. Two composite actions (`.github/actions/cache-python`, `.github/actions/cache-scanners`) centralize caching. Every new job is guarded by `if: github.repository == 'fardani235/molecule'`.

**Tech Stack:** GitHub Actions, Python 3.10+, Bandit, Semgrep, pip-audit, Trivy, Gitleaks, KICS, CycloneDX, `actions/cache@v4`, `actions/upload-artifact@v4`, `github/codeql-action/upload-sarif@v3`.

## Global Constraints

- **Fork guard:** every job carries `if: github.repository == 'fardani235/molecule'`.
- **Least-privilege permissions:** workflow-level `permissions: {}`; per-job elevation only.
- **PR gate:** any *unwaived* finding at severity `medium`, `high`, or `critical` fails the `gate` job.
- **Artifact retention:** 90 days on every `actions/upload-artifact` call.
- **Do not modify `.github/workflows/tox.yml` or `.github/workflows/release.yml`** — out of scope.
- **Trigger set for all new workflows:** `pull_request` (branches: `main`, `releases/**`, `stable/**`), `push` (branches: `main`), `workflow_dispatch`. Concurrency group cancels superseded PR runs.
- **Action pinning:** major-tag pins (`@v4`, `@v3`, `@v2`) except Trivy pinned to `@0.24.0` (minor). Renovate keeps them current.
- **Working branch:** `orange-horse-rework` (already checked out).
- **Working directory:** `/home/ridwan/workspaces/onfrontier/orange-horse`.
- **Waiver comment convention:** ``# waived <YYYY-MM-DD> by <handle> — <reason>; re-review <YYYY-MM-DD>``. `gate.py` fails on entries lacking this or with expired re-review dates.

---

## File Structure

**New files (created):**

```
.github/actions/cache-python/action.yml         # composite: pip+uv+tox+precommit+ansible caches
.github/actions/cache-scanners/action.yml       # composite: Trivy DB, Semgrep, KICS caches
.github/scripts/gate.py                         # SARIF aggregator + waiver enforcer
.github/scripts/benchmark_collect.py            # reads Actions API, renders ci-benchmark.md
.github/scripts/requirements.txt                # pinned deps for the two scripts
.github/scripts/tests/test_gate.py              # unit tests for gate.py
.github/scripts/tests/test_benchmark_collect.py # unit tests for benchmark_collect.py
.github/scripts/tests/fixtures/                 # sample SARIFs + Actions API JSON
.github/security/README.md                      # waiver convention + review cadence
.github/security/gate-policy.yml                # thresholds
.github/security/bandit.yaml                    # Bandit config
.github/security/.gitleaks.toml                 # Gitleaks rules + allowlist
.github/security/pip-audit-ignore.txt           # CVE waivers
.github/security/.trivyignore                   # Trivy waivers
.github/security/kics-exclusions.json           # KICS query/path exclusions
.github/security/semgrep-rules.yml              # enabled rulesets (used for cache key)
.github/workflows/security.yml                  # SAST/SCA/Secrets/IaC/SBOM + gate
.github/workflows/build-artifacts.yml           # wheel/sdist/collection + SBOMs
.github/workflows/benchmark.yml                 # workflow_dispatch — timing runs
```

**Modified files:**

```
.pre-commit-config.yaml                         # add gitleaks + bandit local hooks
```

**Untouched (explicit):**

```
.github/workflows/tox.yml
.github/workflows/release.yml
.github/workflows/ack.yml
.github/workflows/push.yml
.github/workflows/finalize.yml
.github/workflows/redirects.yml
```

Task boundaries follow file responsibility. Config-and-tests tasks come before workflow tasks so each workflow task's steps can reference already-existing files.

---

### Task 1: Security config tree scaffolding

**Files:**
- Create: `.github/security/README.md`
- Create: `.github/security/gate-policy.yml`
- Create: `.github/security/bandit.yaml`
- Create: `.github/security/.gitleaks.toml`
- Create: `.github/security/pip-audit-ignore.txt`
- Create: `.github/security/.trivyignore`
- Create: `.github/security/kics-exclusions.json`
- Create: `.github/security/semgrep-rules.yml`

**Interfaces:**
- Consumes: nothing.
- Produces: `.github/security/gate-policy.yml` schema `{threshold: str, overrides: {<scanner>: {threshold: str}}}` consumed by Task 3 (`gate.py`). Waiver files consumed by scanner jobs in Task 6.

- [ ] **Step 1: Create `.github/security/gate-policy.yml`**

```yaml
# Severity threshold at which the gate FAILS the PR.
# Values: low | medium | high | critical
# A finding at or above the effective threshold, if not waived, fails the gate.
threshold: medium

# Per-scanner overrides.
overrides:
  gitleaks:
    # Any leaked secret is critical regardless of scanner category.
    threshold: critical
  kics:
    threshold: medium
```

- [ ] **Step 2: Create `.github/security/bandit.yaml`**

```yaml
# Bandit configuration.
# Skips are DOCUMENTED with waiver comments — see .github/security/README.md.
skips: []
tests: []
# Scan only production source; tests intentionally excluded.
exclude_dirs:
  - tests
  - community.molecule/tests
```

- [ ] **Step 3: Create `.github/security/.gitleaks.toml`**

```toml
title = "molecule fork gitleaks config"

# Inherit the default ruleset:
[extend]
useDefault = true

# Allowlist — every entry MUST be justified with a waiver comment:
#   # waived <YYYY-MM-DD> by <handle> — <reason>; re-review <YYYY-MM-DD>
[allowlist]
description = "Global allowlist"
paths = [
  # Test fixtures deliberately contain fake credentials for offline tests.
  # waived 2026-08-06 by ridwan — Ansible test fixtures; re-review 2027-02-06
  '''tests/fixtures/.*''',
  '''community.molecule/tests/.*''',
]
```

- [ ] **Step 4: Create `.github/security/pip-audit-ignore.txt`**

```
# One CVE id per line. Every entry MUST carry a waiver comment on the line
# above:
#   # waived <YYYY-MM-DD> by <handle> — <reason>; re-review <YYYY-MM-DD>
```

- [ ] **Step 5: Create `.github/security/.trivyignore`**

```
# One CVE id per line. Every entry MUST carry a waiver comment on the line
# above:
#   # waived <YYYY-MM-DD> by <handle> — <reason>; re-review <YYYY-MM-DD>
```

- [ ] **Step 6: Create `.github/security/kics-exclusions.json`**

```json
{
  "exclude_paths": [
    "tests/fixtures",
    "community.molecule/tests"
  ],
  "exclude_queries": [],
  "_waivers": [
    "Waivers for exclude_queries entries MUST be recorded in .github/security/README.md with re-review date."
  ]
}
```

- [ ] **Step 7: Create `.github/security/semgrep-rules.yml`**

```yaml
# Rulesets loaded by Semgrep. This file's hash is the cache key, so any
# change here invalidates the Semgrep cache automatically.
rulesets:
  - p/python
  - p/security-audit
  - p/secrets
```

- [ ] **Step 8: Create `.github/security/README.md`**

````markdown
# Security config

This directory holds configuration and waivers for the DevSecOps gate
defined in `.github/workflows/security.yml`.

## Waiver convention

Every waiver — in any of these files — MUST be preceded by a comment in
this exact form:

```
# waived <YYYY-MM-DD> by <handle> — <reason>; re-review <YYYY-MM-DD>
```

`gate.py` fails the workflow if any waiver entry is missing a comment or
has an expired `re-review` date.

## Files

| File | Purpose |
|---|---|
| `gate-policy.yml` | Severity threshold + per-scanner overrides |
| `bandit.yaml` | Bandit SAST config |
| `.gitleaks.toml` | Gitleaks rules and path allowlist |
| `pip-audit-ignore.txt` | CVE waivers for pip-audit |
| `.trivyignore` | CVE waivers for Trivy filesystem scan |
| `kics-exclusions.json` | KICS query and path exclusions |
| `semgrep-rules.yml` | Rulesets Semgrep will load (its hash is the cache key) |

## Downloading scan artifacts

Every workflow run uploads scan reports as artifacts (90-day retention).
Download with:

```
gh run download <run-id> -n sast-reports
gh run download <run-id> -n sca-reports
gh run download <run-id> -n secrets-reports
gh run download <run-id> -n iac-reports
gh run download <run-id> -n sbom
gh run download <run-id> -n gate-summary
```

Or view findings inline in the repository's **Security** tab (SARIF is
uploaded there for every scanner).

## Review cadence

CODEOWNERS review waivers **quarterly**. Any entry whose `re-review` date
has passed fails the gate on the next run.
````

- [ ] **Step 9: Commit**

```bash
git add .github/security/
git commit -m "chore(security): scaffold .github/security config tree"
```

---

### Task 2: `gate.py` — write the failing tests

**Files:**
- Create: `.github/scripts/tests/__init__.py`
- Create: `.github/scripts/tests/fixtures/bandit-clean.sarif`
- Create: `.github/scripts/tests/fixtures/bandit-med.sarif`
- Create: `.github/scripts/tests/fixtures/gitleaks-hit.sarif`
- Create: `.github/scripts/tests/test_gate.py`
- Create: `.github/scripts/requirements.txt`

**Interfaces:**
- Consumes: nothing.
- Produces: test fixtures + failing tests that drive Task 3.
  - `gate.load_sarif_dir(path: pathlib.Path) -> list[Finding]`
  - `gate.apply_waivers(findings, waiver_files: dict[str, pathlib.Path]) -> tuple[list[Finding], list[Finding]]`  (unwaived, waived)
  - `gate.evaluate(findings, policy: dict) -> GateResult`
  - `Finding` dataclass fields: `scanner: str`, `rule_id: str`, `severity: str` (one of `critical|high|medium|low`), `file: str`, `line: int`, `message: str`, `waiver: str | None`.
  - `GateResult` fields: `failed: bool`, `counts: dict[str, dict[str, int]]` (per-scanner→per-severity), `waived: int`, `summary_md: str`.

- [ ] **Step 1: Create `.github/scripts/requirements.txt`**

```
# Pinned so CI is reproducible.
pyyaml==6.0.2
```

- [ ] **Step 2: Create empty `.github/scripts/tests/__init__.py`**

```python
```

- [ ] **Step 3: Create fixture `bandit-clean.sarif`**

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {"driver": {"name": "Bandit", "rules": []}},
      "results": []
    }
  ]
}
```

- [ ] **Step 4: Create fixture `bandit-med.sarif`**

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {"driver": {"name": "Bandit", "rules": [
        {"id": "B101", "defaultConfiguration": {"level": "warning"}}
      ]}},
      "results": [
        {
          "ruleId": "B101",
          "level": "warning",
          "message": {"text": "assert_used"},
          "locations": [
            {"physicalLocation": {
              "artifactLocation": {"uri": "src/molecule/util.py"},
              "region": {"startLine": 42}
            }}
          ]
        }
      ]
    }
  ]
}
```

- [ ] **Step 5: Create fixture `gitleaks-hit.sarif`**

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {"driver": {"name": "Gitleaks", "rules": [
        {"id": "aws-access-key", "defaultConfiguration": {"level": "error"}}
      ]}},
      "results": [
        {
          "ruleId": "aws-access-key",
          "level": "error",
          "message": {"text": "AWS access key detected"},
          "locations": [
            {"physicalLocation": {
              "artifactLocation": {"uri": "src/molecule/config.py"},
              "region": {"startLine": 7}
            }}
          ]
        }
      ]
    }
  ]
}
```

- [ ] **Step 6: Create `.github/scripts/tests/test_gate.py`**

```python
"""Unit tests for gate.py."""
from __future__ import annotations

import json
import pathlib
import sys
import textwrap

# Make the sibling gate.py importable regardless of pytest CWD.
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import gate  # noqa: E402


FIXTURES = HERE / "fixtures"


def test_load_sarif_dir_reads_all_sarifs(tmp_path):
    (tmp_path / "bandit.sarif").write_text((FIXTURES / "bandit-med.sarif").read_text())
    (tmp_path / "gitleaks.sarif").write_text((FIXTURES / "gitleaks-hit.sarif").read_text())
    findings = gate.load_sarif_dir(tmp_path)
    assert len(findings) == 2
    scanners = {f.scanner for f in findings}
    assert scanners == {"bandit", "gitleaks"}


def test_bandit_warning_maps_to_medium(tmp_path):
    (tmp_path / "bandit.sarif").write_text((FIXTURES / "bandit-med.sarif").read_text())
    findings = gate.load_sarif_dir(tmp_path)
    assert findings[0].severity == "medium"


def test_gitleaks_finding_forced_to_critical(tmp_path):
    (tmp_path / "gitleaks.sarif").write_text((FIXTURES / "gitleaks-hit.sarif").read_text())
    findings = gate.load_sarif_dir(tmp_path)
    assert findings[0].severity == "critical"


def test_clean_sarif_produces_no_findings(tmp_path):
    (tmp_path / "bandit.sarif").write_text((FIXTURES / "bandit-clean.sarif").read_text())
    findings = gate.load_sarif_dir(tmp_path)
    assert findings == []


def test_evaluate_fails_on_medium_when_threshold_medium():
    findings = [gate.Finding("bandit", "B101", "medium", "x.py", 1, "m", None)]
    policy = {"threshold": "medium", "overrides": {}}
    result = gate.evaluate(findings, policy)
    assert result.failed is True
    assert result.counts["bandit"]["medium"] == 1


def test_evaluate_passes_on_low_when_threshold_medium():
    findings = [gate.Finding("bandit", "B101", "low", "x.py", 1, "m", None)]
    result = gate.evaluate(findings, {"threshold": "medium", "overrides": {}})
    assert result.failed is False


def test_evaluate_respects_per_scanner_override():
    # kics override says medium; a medium finding must fail.
    findings = [gate.Finding("kics", "Q1", "medium", "x.yml", 1, "m", None)]
    policy = {"threshold": "high", "overrides": {"kics": {"threshold": "medium"}}}
    result = gate.evaluate(findings, policy)
    assert result.failed is True


def test_apply_waivers_marks_matching_finding_waived(tmp_path):
    ignore = tmp_path / "trivy-ignore.txt"
    ignore.write_text(textwrap.dedent("""\
        # waived 2026-08-06 by ridwan — upstream fix pending; re-review 2027-02-06
        CVE-2025-9999
    """))
    finding = gate.Finding("trivy", "CVE-2025-9999", "high", "requirements.txt", 0, "m", None)
    unwaived, waived = gate.apply_waivers([finding], {"trivy": ignore})
    assert unwaived == []
    assert len(waived) == 1
    assert "ridwan" in waived[0].waiver


def test_apply_waivers_rejects_uncommented_entry(tmp_path):
    ignore = tmp_path / "trivy-ignore.txt"
    ignore.write_text("CVE-2025-9999\n")
    finding = gate.Finding("trivy", "CVE-2025-9999", "high", "r.txt", 0, "m", None)
    try:
        gate.apply_waivers([finding], {"trivy": ignore})
    except gate.WaiverFormatError as exc:
        assert "waiver comment" in str(exc)
    else:
        raise AssertionError("Expected WaiverFormatError")


def test_apply_waivers_rejects_expired_review_date(tmp_path):
    ignore = tmp_path / "trivy-ignore.txt"
    ignore.write_text(textwrap.dedent("""\
        # waived 2024-01-01 by ridwan — old; re-review 2024-06-01
        CVE-2025-9999
    """))
    finding = gate.Finding("trivy", "CVE-2025-9999", "high", "r.txt", 0, "m", None)
    try:
        gate.apply_waivers([finding], {"trivy": ignore})
    except gate.WaiverExpiredError as exc:
        assert "2024-06-01" in str(exc)
    else:
        raise AssertionError("Expected WaiverExpiredError")


def test_summary_md_contains_table_and_gate_outcome():
    findings = [gate.Finding("bandit", "B101", "medium", "x.py", 1, "m", None)]
    result = gate.evaluate(findings, {"threshold": "medium", "overrides": {}})
    assert "| Scanner" in result.summary_md
    assert "FAIL" in result.summary_md
```

- [ ] **Step 7: Run the tests to verify they fail**

```bash
cd /home/ridwan/workspaces/onfrontier/orange-horse
python3 -m pip install --user -r .github/scripts/requirements.txt pytest
python3 -m pytest .github/scripts/tests/test_gate.py -v
```

Expected: **ModuleNotFoundError: No module named 'gate'** (gate.py doesn't exist yet).

- [ ] **Step 8: Commit**

```bash
git add .github/scripts/requirements.txt .github/scripts/tests/
git commit -m "test(security): add failing tests for gate.py SARIF aggregator"
```

---

### Task 3: `gate.py` — implement until tests pass

**Files:**
- Create: `.github/scripts/gate.py`

**Interfaces:**
- Consumes: SARIF files on disk, waiver files listed in Task 1, `gate-policy.yml`.
- Produces: `gate-summary.md`, `gate-report.json`, and process exit code (0 pass / 1 fail). CLI entry:
  `python3 .github/scripts/gate.py --sarif-dir <path> --policy <policy.yml> --waivers <scanner>=<path> [--waivers ...] --out-md <path> --out-json <path>`

- [ ] **Step 1: Create `.github/scripts/gate.py`**

```python
"""SARIF aggregator + waiver enforcer for the DevSecOps gate.

Reads every *.sarif file under --sarif-dir, normalizes findings, applies
waiver files, evaluates them against gate-policy.yml, writes a Markdown
summary and JSON report, and exits nonzero if any unwaived finding is at
or above the effective severity threshold.
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as _dt
import json
import pathlib
import re
import sys
from typing import Iterable

import yaml


SEVERITY_ORDER = ["low", "medium", "high", "critical"]
SEV_INDEX = {s: i for i, s in enumerate(SEVERITY_ORDER)}


class WaiverFormatError(RuntimeError):
    """A waiver entry is missing the required comment."""


class WaiverExpiredError(RuntimeError):
    """A waiver entry's re-review date has passed."""


@dataclasses.dataclass
class Finding:
    scanner: str
    rule_id: str
    severity: str  # low|medium|high|critical
    file: str
    line: int
    message: str
    waiver: str | None = None


@dataclasses.dataclass
class GateResult:
    failed: bool
    counts: dict          # {scanner: {severity: n}}
    waived: int
    summary_md: str
    findings: list        # remaining unwaived findings (for JSON report)


# ---------- SARIF loading ----------

_SEV_MAP_DEFAULT = {"error": "high", "warning": "medium", "note": "low", "none": "low"}
_SEV_MAP_BANDIT = {"error": "high", "warning": "medium", "note": "low"}
_SCANNER_ALIASES = {
    "bandit": "bandit",
    "semgrep": "semgrep",
    "pip-audit": "pip-audit",
    "trivy": "trivy",
    "gitleaks": "gitleaks",
    "kics": "kics",
}


def _map_severity(scanner: str, level: str, properties: dict | None) -> str:
    scanner = scanner.lower()
    # pip-audit and Trivy encode CVSS numeric in properties.security-severity.
    if properties and "security-severity" in properties:
        try:
            score = float(properties["security-severity"])
        except (TypeError, ValueError):
            score = 0.0
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        return "low"
    if scanner == "gitleaks":
        return "critical"
    if scanner == "bandit":
        return _SEV_MAP_BANDIT.get((level or "").lower(), "medium")
    return _SEV_MAP_DEFAULT.get((level or "").lower(), "medium")


def load_sarif_dir(path: pathlib.Path) -> list[Finding]:
    findings: list[Finding] = []
    for sarif_path in sorted(pathlib.Path(path).glob("*.sarif")):
        data = json.loads(sarif_path.read_text())
        for run in data.get("runs", []):
            driver = run.get("tool", {}).get("driver", {})
            scanner_raw = (driver.get("name") or sarif_path.stem).lower()
            scanner = _SCANNER_ALIASES.get(scanner_raw, scanner_raw)
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "")
                level = result.get("level") or ""
                message = (result.get("message") or {}).get("text", "")
                properties = result.get("properties") or {}
                locations = result.get("locations") or []
                file_uri = ""
                line = 0
                if locations:
                    ploc = locations[0].get("physicalLocation") or {}
                    file_uri = (ploc.get("artifactLocation") or {}).get("uri", "")
                    line = (ploc.get("region") or {}).get("startLine", 0) or 0
                findings.append(Finding(
                    scanner=scanner,
                    rule_id=rule_id,
                    severity=_map_severity(scanner, level, properties),
                    file=file_uri,
                    line=int(line),
                    message=message,
                ))
    return findings


# ---------- Waivers ----------

_WAIVER_LINE_RE = re.compile(
    r"^\s*#\s*waived\s+(?P<waived_on>\d{4}-\d{2}-\d{2})\s+by\s+(?P<by>\S+)\s+"
    r"[—-]\s+(?P<reason>.+?)\s*;\s*re-review\s+(?P<review>\d{4}-\d{2}-\d{2})\s*$",
    re.IGNORECASE,
)


def _parse_waiver_file(path: pathlib.Path) -> list[tuple[str, str]]:
    """Return list of (id, waiver_string) pairs.

    Raises WaiverFormatError if a non-comment line is not immediately
    preceded by a valid waiver comment. Raises WaiverExpiredError if the
    re-review date has passed.
    """
    pairs: list[tuple[str, str]] = []
    if not path.exists():
        return pairs
    lines = path.read_text().splitlines()
    last_waiver_comment: str | None = None
    today = _dt.date.today()
    for raw in lines:
        line = raw.strip()
        if not line:
            last_waiver_comment = None
            continue
        if line.startswith("#"):
            match = _WAIVER_LINE_RE.match(raw)
            if match:
                review = _dt.date.fromisoformat(match.group("review"))
                if review < today:
                    raise WaiverExpiredError(
                        f"{path}: waiver re-review date {review.isoformat()} has passed"
                    )
                last_waiver_comment = raw.strip()
            # non-waiver comments (informational) reset nothing.
            continue
        # non-comment line = a waiver entry (CVE-id, path glob, etc.).
        if not last_waiver_comment:
            raise WaiverFormatError(
                f"{path}: entry '{line}' has no preceding waiver comment"
            )
        pairs.append((line, last_waiver_comment))
        last_waiver_comment = None
    return pairs


def apply_waivers(
    findings: Iterable[Finding], waiver_files: dict[str, pathlib.Path]
) -> tuple[list[Finding], list[Finding]]:
    """Return (unwaived, waived). Scanner name is the dict key."""
    unwaived: list[Finding] = []
    waived: list[Finding] = []
    parsed = {scanner: _parse_waiver_file(p) for scanner, p in waiver_files.items()}
    for f in findings:
        pairs = parsed.get(f.scanner, [])
        match = next(
            (comment for entry_id, comment in pairs if entry_id == f.rule_id),
            None,
        )
        if match:
            waived.append(dataclasses.replace(f, waiver=match))
        else:
            unwaived.append(f)
    return unwaived, waived


# ---------- Evaluation ----------

def _effective_threshold(policy: dict, scanner: str) -> str:
    default = policy.get("threshold", "medium")
    overrides = (policy.get("overrides") or {}).get(scanner) or {}
    return overrides.get("threshold", default)


def evaluate(findings: list[Finding], policy: dict) -> GateResult:
    counts: dict[str, dict[str, int]] = {}
    failed = False
    for f in findings:
        counts.setdefault(f.scanner, {s: 0 for s in SEVERITY_ORDER})
        counts[f.scanner][f.severity] += 1
        if SEV_INDEX[f.severity] >= SEV_INDEX[_effective_threshold(policy, f.scanner)]:
            failed = True
    summary_md = _render_summary(counts, failed)
    return GateResult(
        failed=failed, counts=counts, waived=0, summary_md=summary_md, findings=findings
    )


def _render_summary(counts: dict, failed: bool) -> str:
    lines = [
        "## 🛡 Security Gate",
        "",
        "| Scanner | Critical | High | Medium | Low |",
        "|---|---:|---:|---:|---:|",
    ]
    for scanner in sorted(counts):
        c = counts[scanner]
        lines.append(
            f"| {scanner} | {c['critical']} | {c['high']} | {c['medium']} | {c['low']} |"
        )
    if not counts:
        lines.append("| _(no findings)_ | 0 | 0 | 0 | 0 |")
    lines.extend([
        "",
        f"**Gate: {'❌ FAIL' if failed else '✅ PASS'}**",
    ])
    return "\n".join(lines) + "\n"


# ---------- CLI ----------

def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sarif-dir", type=pathlib.Path, required=True)
    p.add_argument("--policy", type=pathlib.Path, required=True)
    p.add_argument(
        "--waivers",
        action="append",
        default=[],
        metavar="SCANNER=PATH",
        help="e.g. --waivers trivy=.github/security/.trivyignore",
    )
    p.add_argument("--out-md", type=pathlib.Path, required=True)
    p.add_argument("--out-json", type=pathlib.Path, required=True)
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    policy = yaml.safe_load(args.policy.read_text()) or {}
    waiver_files = {}
    for pair in args.waivers:
        if "=" not in pair:
            print(f"invalid --waivers value: {pair}", file=sys.stderr)
            return 2
        scanner, path = pair.split("=", 1)
        waiver_files[scanner] = pathlib.Path(path)
    findings = load_sarif_dir(args.sarif_dir)
    unwaived, waived = apply_waivers(findings, waiver_files)
    result = evaluate(unwaived, policy)
    result.waived = len(waived)
    args.out_md.write_text(result.summary_md)
    args.out_json.write_text(
        json.dumps(
            {
                "failed": result.failed,
                "counts": result.counts,
                "waived": result.waived,
                "findings": [dataclasses.asdict(f) for f in result.findings],
            },
            indent=2,
        )
    )
    return 1 if result.failed else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
```

- [ ] **Step 2: Run the unit tests**

```bash
python3 -m pytest .github/scripts/tests/test_gate.py -v
```

Expected: **all 10 tests PASS**.

- [ ] **Step 3: Smoke-test the CLI**

```bash
mkdir -p /tmp/sarif && cp .github/scripts/tests/fixtures/bandit-med.sarif /tmp/sarif/
python3 .github/scripts/gate.py \
  --sarif-dir /tmp/sarif \
  --policy .github/security/gate-policy.yml \
  --out-md /tmp/gate.md \
  --out-json /tmp/gate.json
echo "exit=$?"
cat /tmp/gate.md
```

Expected: `exit=1` and the Markdown table shows `bandit | 0 | 0 | 1 | 0` with **Gate: ❌ FAIL**.

- [ ] **Step 4: Commit**

```bash
git add .github/scripts/gate.py
git commit -m "feat(security): implement gate.py SARIF aggregator and waiver enforcer"
```

---

### Task 4: `benchmark_collect.py` — tests + implementation

**Files:**
- Create: `.github/scripts/tests/fixtures/runs-jobs-sample.json`
- Create: `.github/scripts/tests/test_benchmark_collect.py`
- Create: `.github/scripts/benchmark_collect.py`

**Interfaces:**
- Consumes: GitHub REST API JSON for `/repos/{owner}/{repo}/actions/runs/{id}/jobs` (or an offline sample). No network calls in tests.
- Produces: `ci-benchmark.md`, `ci-benchmark.json`. CLI:
  `python3 .github/scripts/benchmark_collect.py --baseline <dir> --optimized <dir> --out-md <path> --out-json <path>`
  Each `<dir>` contains one or more `run-<n>.json` files (the raw jobs listing JSON).
  Public functions:
  - `benchmark_collect.load_runs(dir: pathlib.Path) -> list[Run]` — `Run` has `jobs: list[Job]`, `Job` has `name: str`, `duration_s: float`, `cache_hits: int`, `cache_total: int`.
  - `benchmark_collect.aggregate(runs: list[Run]) -> dict[str, JobStat]` — median duration and cache-hit ratio per job.
  - `benchmark_collect.render_md(baseline_stats, optimized_stats) -> str`.

- [ ] **Step 1: Create fixture `runs-jobs-sample.json`**

```json
{
  "total_count": 2,
  "jobs": [
    {
      "name": "sast",
      "status": "completed",
      "conclusion": "success",
      "started_at": "2026-08-06T02:00:00Z",
      "completed_at": "2026-08-06T02:03:40Z",
      "steps": [
        {"name": "restore py cache", "status": "completed",
         "started_at": "2026-08-06T02:00:05Z", "completed_at": "2026-08-06T02:00:07Z"},
        {"name": "Cache restored from key py-linux-3.10-abc",
         "started_at": "2026-08-06T02:00:07Z", "completed_at": "2026-08-06T02:00:08Z"}
      ]
    },
    {
      "name": "sca",
      "status": "completed",
      "conclusion": "success",
      "started_at": "2026-08-06T02:00:00Z",
      "completed_at": "2026-08-06T02:04:05Z",
      "steps": [
        {"name": "Cache not found for input keys trivy-db-xyz",
         "started_at": "2026-08-06T02:00:07Z", "completed_at": "2026-08-06T02:00:08Z"}
      ]
    }
  ]
}
```

- [ ] **Step 2: Create `.github/scripts/tests/test_benchmark_collect.py`**

```python
"""Unit tests for benchmark_collect.py."""
from __future__ import annotations

import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import benchmark_collect as bc  # noqa: E402

FIXTURES = HERE / "fixtures"


def _write_run(dir_: pathlib.Path, i: int) -> None:
    (dir_ / f"run-{i}.json").write_text((FIXTURES / "runs-jobs-sample.json").read_text())


def test_load_runs_reads_all_json(tmp_path):
    _write_run(tmp_path, 1)
    _write_run(tmp_path, 2)
    runs = bc.load_runs(tmp_path)
    assert len(runs) == 2
    assert {j.name for j in runs[0].jobs} == {"sast", "sca"}


def test_job_duration_computed_from_timestamps(tmp_path):
    _write_run(tmp_path, 1)
    runs = bc.load_runs(tmp_path)
    sast = next(j for j in runs[0].jobs if j.name == "sast")
    # 02:00:00 -> 02:03:40 is 220 seconds.
    assert sast.duration_s == 220


def test_cache_hits_detected_from_step_names(tmp_path):
    _write_run(tmp_path, 1)
    runs = bc.load_runs(tmp_path)
    sast = next(j for j in runs[0].jobs if j.name == "sast")
    sca = next(j for j in runs[0].jobs if j.name == "sca")
    assert sast.cache_hits == 1 and sast.cache_total == 1
    assert sca.cache_hits == 0 and sca.cache_total == 1


def test_aggregate_computes_median(tmp_path):
    _write_run(tmp_path, 1)
    _write_run(tmp_path, 2)
    _write_run(tmp_path, 3)
    stats = bc.aggregate(bc.load_runs(tmp_path))
    assert stats["sast"].median_duration_s == 220
    assert stats["sast"].cache_hit_pct == 100.0
    assert stats["sca"].cache_hit_pct == 0.0


def test_render_md_shows_delta(tmp_path):
    _write_run(tmp_path, 1)
    baseline = bc.aggregate(bc.load_runs(tmp_path))
    # Force optimized to half duration for comparison.
    optimized = {
        name: bc.JobStat(median_duration_s=s.median_duration_s / 2,
                         cache_hit_pct=100.0)
        for name, s in baseline.items()
    }
    md = bc.render_md(baseline, optimized)
    assert "-50%" in md
    assert "| sast" in md
```

- [ ] **Step 3: Run the tests to verify they fail**

```bash
python3 -m pytest .github/scripts/tests/test_benchmark_collect.py -v
```

Expected: **ModuleNotFoundError: No module named 'benchmark_collect'**.

- [ ] **Step 4: Create `.github/scripts/benchmark_collect.py`**

```python
"""CI benchmark aggregator.

Reads jobs-listing JSON produced by the GitHub REST API for a set of
runs, computes median wall-clock durations per job, and renders a
Markdown before/after table.

The two input directories (baseline, optimized) each hold one JSON file
per run. Each file is the response body of
GET /repos/{owner}/{repo}/actions/runs/{run_id}/jobs.
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as _dt
import json
import pathlib
import statistics
import sys


CACHE_HIT_MARKER = "cache restored from key"
CACHE_MISS_MARKER = "cache not found"


@dataclasses.dataclass
class Job:
    name: str
    duration_s: float
    cache_hits: int
    cache_total: int


@dataclasses.dataclass
class Run:
    jobs: list[Job]


@dataclasses.dataclass
class JobStat:
    median_duration_s: float
    cache_hit_pct: float


def _parse_ts(s: str) -> _dt.datetime:
    return _dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def _count_cache_steps(steps: list[dict]) -> tuple[int, int]:
    hits = 0
    total = 0
    for step in steps or []:
        name = (step.get("name") or "").lower()
        if CACHE_HIT_MARKER in name:
            hits += 1
            total += 1
        elif CACHE_MISS_MARKER in name:
            total += 1
    return hits, total


def load_runs(dir_: pathlib.Path) -> list[Run]:
    runs: list[Run] = []
    for path in sorted(pathlib.Path(dir_).glob("*.json")):
        data = json.loads(path.read_text())
        jobs: list[Job] = []
        for j in data.get("jobs", []):
            started = _parse_ts(j["started_at"])
            completed = _parse_ts(j["completed_at"])
            hits, total = _count_cache_steps(j.get("steps", []))
            jobs.append(Job(
                name=j["name"],
                duration_s=(completed - started).total_seconds(),
                cache_hits=hits,
                cache_total=total,
            ))
        runs.append(Run(jobs=jobs))
    return runs


def aggregate(runs: list[Run]) -> dict[str, JobStat]:
    by_name: dict[str, list[Job]] = {}
    for run in runs:
        for job in run.jobs:
            by_name.setdefault(job.name, []).append(job)
    stats: dict[str, JobStat] = {}
    for name, jobs in by_name.items():
        median = statistics.median(j.duration_s for j in jobs)
        total = sum(j.cache_total for j in jobs)
        hits = sum(j.cache_hits for j in jobs)
        pct = (hits / total * 100.0) if total else 0.0
        stats[name] = JobStat(median_duration_s=median, cache_hit_pct=pct)
    return stats


def _fmt_duration(seconds: float) -> str:
    minutes, secs = divmod(int(round(seconds)), 60)
    return f"{minutes}m {secs:02d}s"


def render_md(baseline: dict[str, JobStat], optimized: dict[str, JobStat]) -> str:
    names = sorted(set(baseline) | set(optimized))
    lines = [
        "# CI benchmark",
        "",
        "| Job | Baseline (median) | Optimized (median) | Δ | Cache hit % |",
        "|---|---:|---:|---:|---:|",
    ]
    total_base = 0.0
    total_opt = 0.0
    for name in names:
        b = baseline.get(name)
        o = optimized.get(name)
        bd = b.median_duration_s if b else 0.0
        od = o.median_duration_s if o else 0.0
        total_base += bd
        total_opt += od
        delta_pct = ((od - bd) / bd * 100.0) if bd else 0.0
        hit_pct = o.cache_hit_pct if o else 0.0
        lines.append(
            f"| {name} | {_fmt_duration(bd)} | {_fmt_duration(od)} "
            f"| {delta_pct:+.0f}% | {hit_pct:.0f}% |"
        )
    total_delta = ((total_opt - total_base) / total_base * 100.0) if total_base else 0.0
    lines.append(
        f"| **Total** | **{_fmt_duration(total_base)}** | "
        f"**{_fmt_duration(total_opt)}** | **{total_delta:+.0f}%** | |"
    )
    return "\n".join(lines) + "\n"


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--baseline", type=pathlib.Path, required=True)
    p.add_argument("--optimized", type=pathlib.Path, required=True)
    p.add_argument("--out-md", type=pathlib.Path, required=True)
    p.add_argument("--out-json", type=pathlib.Path, required=True)
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    baseline = aggregate(load_runs(args.baseline))
    optimized = aggregate(load_runs(args.optimized))
    args.out_md.write_text(render_md(baseline, optimized))
    args.out_json.write_text(json.dumps({
        "baseline": {n: dataclasses.asdict(s) for n, s in baseline.items()},
        "optimized": {n: dataclasses.asdict(s) for n, s in optimized.items()},
    }, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
python3 -m pytest .github/scripts/tests/test_benchmark_collect.py -v
```

Expected: **all 5 tests PASS**.

- [ ] **Step 6: Commit**

```bash
git add .github/scripts/benchmark_collect.py .github/scripts/tests/fixtures/runs-jobs-sample.json .github/scripts/tests/test_benchmark_collect.py
git commit -m "feat(ci): add benchmark_collect.py for before/after timing reports"
```

---

### Task 5: Composite actions for caching

**Files:**
- Create: `.github/actions/cache-python/action.yml`
- Create: `.github/actions/cache-scanners/action.yml`

**Interfaces:**
- Consumes: nothing.
- Produces: two composite actions callable from any workflow job:
  - `./.github/actions/cache-python` — inputs `python-version` (required), `ansible` (default `false`), `pre-commit` (default `true`).
  - `./.github/actions/cache-scanners` — inputs `trivy` (default `true`), `semgrep` (default `true`), `kics` (default `false`), and `kics-version` (default `2.1.3`).

- [ ] **Step 1: Create `.github/actions/cache-python/action.yml`**

```yaml
name: cache-python
description: >-
  Composite cache action for pip, uv, tox venvs, pre-commit hooks, and
  optionally Ansible collections/roles. Every layer uses restore-keys so a
  lockfile bump still restores an 80%-warm cache.

inputs:
  python-version:
    description: Python version (used in the cache key)
    required: true
  ansible:
    description: Also cache ~/.ansible/collections and ~/.ansible/roles
    required: false
    default: "false"
  pre-commit:
    description: Also cache ~/.cache/pre-commit
    required: false
    default: "true"

runs:
  using: composite
  steps:
    - name: Cache pip + uv + tox venvs
      uses: actions/cache@v4
      with:
        path: |
          ~/.cache/pip
          ~/.cache/uv
          .tox
        key: py-${{ runner.os }}-${{ inputs.python-version }}-${{ hashFiles('pyproject.toml', 'tox.ini', '.pre-commit-config.yaml') }}
        restore-keys: |
          py-${{ runner.os }}-${{ inputs.python-version }}-

    - name: Cache pre-commit hooks
      if: inputs.pre-commit == 'true'
      uses: actions/cache@v4
      with:
        path: ~/.cache/pre-commit
        key: pc-${{ runner.os }}-${{ hashFiles('.pre-commit-config.yaml') }}
        restore-keys: |
          pc-${{ runner.os }}-

    - name: Cache Ansible collections and roles
      if: inputs.ansible == 'true'
      uses: actions/cache@v4
      with:
        path: |
          ~/.ansible/collections
          ~/.ansible/roles
        key: ansible-${{ runner.os }}-${{ hashFiles('community.molecule/galaxy.yml', 'community.molecule/requirements.yml', 'requirements.yml') }}
        restore-keys: |
          ansible-${{ runner.os }}-
```

- [ ] **Step 2: Create `.github/actions/cache-scanners/action.yml`**

```yaml
name: cache-scanners
description: >-
  Composite cache action for security-scanner databases and rulesets.
  Trivy's DB is time-versioned via the run_id so a stale DB is always
  refreshed on top of the restored floor.

inputs:
  trivy:
    description: Cache Trivy vuln DB
    required: false
    default: "true"
  semgrep:
    description: Cache Semgrep rules
    required: false
    default: "true"
  kics:
    description: Cache KICS queries
    required: false
    default: "false"
  kics-version:
    description: KICS version tag (used in the cache key)
    required: false
    default: "2.1.3"

runs:
  using: composite
  steps:
    - name: Cache Trivy vuln DB
      if: inputs.trivy == 'true'
      uses: actions/cache@v4
      with:
        path: ~/.cache/trivy
        key: trivy-db-${{ github.run_id }}
        restore-keys: |
          trivy-db-

    - name: Cache Semgrep rules
      if: inputs.semgrep == 'true'
      uses: actions/cache@v4
      with:
        path: ~/.semgrep
        key: semgrep-${{ hashFiles('.github/security/semgrep-rules.yml') }}
        restore-keys: |
          semgrep-

    - name: Cache KICS queries
      if: inputs.kics == 'true'
      uses: actions/cache@v4
      with:
        path: ~/.cache/kics
        key: kics-${{ inputs.kics-version }}
        restore-keys: |
          kics-
```

- [ ] **Step 3: Lint YAML locally**

```bash
python3 -c "import yaml, pathlib; [yaml.safe_load(p.read_text()) for p in pathlib.Path('.github/actions').rglob('action.yml')]; print('ok')"
```

Expected: `ok`.

- [ ] **Step 4: Commit**

```bash
git add .github/actions/
git commit -m "feat(ci): add cache-python and cache-scanners composite actions"
```

---

### Task 6: `security.yml` — the main scanning workflow

**Files:**
- Create: `.github/workflows/security.yml`

**Interfaces:**
- Consumes: composite actions from Task 5, `gate.py` from Task 3, `.github/security/*` from Task 1.
- Produces:
  - Artifacts: `sast-reports`, `sca-reports`, `secrets-reports`, `iac-reports`, `sbom`, `gate-summary` (all 90d retention).
  - SARIF uploads to Security tab with categories: `sast-bandit`, `sast-semgrep`, `sca-pip-audit`, `sca-trivy`, `secrets-gitleaks`, `iac-kics`.
  - Sticky PR comment via `marocchino/sticky-pull-request-comment@v2`.
  - Exit code 1 from the `gate` job when the gate fails.

- [ ] **Step 1: Create `.github/workflows/security.yml`**

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
  workflow_dispatch:

concurrency:
  group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.sha }}
  cancel-in-progress: true

permissions: {}

env:
  PYTHON_VERSION: "3.11"

jobs:

  sast:
    if: github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ env.PYTHON_VERSION }}
      - uses: ./.github/actions/cache-python
        with:
          python-version: ${{ env.PYTHON_VERSION }}
      - uses: ./.github/actions/cache-scanners
        with:
          trivy: "false"
          semgrep: "true"

      - name: Install Bandit
        run: python3 -m pip install --user "bandit[toml]==1.8.*"
      - name: Run Bandit
        run: |
          mkdir -p reports
          bandit -r src \
            -c .github/security/bandit.yaml \
            -f sarif -o reports/bandit.sarif || true
          bandit -r src \
            -c .github/security/bandit.yaml \
            -f json -o reports/bandit.json || true

      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: "p/python p/security-audit p/secrets"
          sarifFile: reports/semgrep.sarif
          generateSarif: "1"
        continue-on-error: true

      - name: Upload SARIF (Bandit) to code scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: reports/bandit.sarif
          category: sast-bandit
      - name: Upload SARIF (Semgrep) to code scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: reports/semgrep.sarif
          category: sast-semgrep

      - name: Upload SAST artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: sast-reports
          path: reports/
          retention-days: 90
          if-no-files-found: warn

  sca:
    if: github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ env.PYTHON_VERSION }}
      - uses: ./.github/actions/cache-python
        with:
          python-version: ${{ env.PYTHON_VERSION }}
      - uses: ./.github/actions/cache-scanners
        with:
          trivy: "true"
          semgrep: "false"

      - name: Run pip-audit
        uses: pypa/gh-action-pip-audit@v1
        with:
          inputs: pyproject.toml
          format: sarif
          output: reports/pip-audit.sarif
          ignore-vulns-file: .github/security/pip-audit-ignore.txt
        continue-on-error: true
      - name: Run pip-audit (JSON)
        uses: pypa/gh-action-pip-audit@v1
        with:
          inputs: pyproject.toml
          format: json
          output: reports/pip-audit.json
          ignore-vulns-file: .github/security/pip-audit-ignore.txt
        continue-on-error: true

      - name: Run Trivy fs (SARIF)
        uses: aquasecurity/trivy-action@0.24.0
        with:
          scan-type: fs
          scan-ref: .
          format: sarif
          output: reports/trivy-fs.sarif
          severity: MEDIUM,HIGH,CRITICAL
          ignorefile: .github/security/.trivyignore
      - name: Run Trivy fs (JSON)
        uses: aquasecurity/trivy-action@0.24.0
        with:
          scan-type: fs
          scan-ref: .
          format: json
          output: reports/trivy-fs.json
          severity: MEDIUM,HIGH,CRITICAL
          ignorefile: .github/security/.trivyignore

      - name: Upload SARIF (pip-audit) to code scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: reports/pip-audit.sarif
          category: sca-pip-audit
      - name: Upload SARIF (Trivy fs) to code scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: reports/trivy-fs.sarif
          category: sca-trivy

      - name: Upload SCA artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: sca-reports
          path: reports/
          retention-days: 90
          if-no-files-found: warn

  secrets:
    if: github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITLEAKS_CONFIG: .github/security/.gitleaks.toml
          GITLEAKS_ENABLE_UPLOAD_ARTIFACT: "false"
          GITLEAKS_ENABLE_SUMMARY: "true"

      - name: Rename output for consistency
        if: always()
        run: |
          mkdir -p reports
          [ -f results.sarif ] && mv results.sarif reports/gitleaks.sarif || true
          [ -f results.json ]  && mv results.json  reports/gitleaks.json  || true

      - name: Upload SARIF (Gitleaks) to code scanning
        if: always() && hashFiles('reports/gitleaks.sarif') != ''
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: reports/gitleaks.sarif
          category: secrets-gitleaks

      - name: Upload secrets artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: secrets-reports
          path: reports/
          retention-days: 90
          if-no-files-found: warn

  iac:
    if: github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/cache-scanners
        with:
          trivy: "false"
          semgrep: "false"
          kics: "true"
      - name: Run KICS
        uses: Checkmarx/kics-github-action@v2
        with:
          path: "community.molecule,tests"
          output_path: reports
          output_formats: sarif,json,html
          exclude_paths: "tests/fixtures,community.molecule/tests"
          fail_on: none
        continue-on-error: true
      - name: Rename KICS output for consistency
        if: always()
        run: |
          [ -f reports/results.sarif ] && mv reports/results.sarif reports/kics.sarif || true
          [ -f reports/results.json ]  && mv reports/results.json  reports/kics.json  || true
          [ -f reports/results.html ]  && mv reports/results.html  reports/kics-results.html || true
      - name: Upload SARIF (KICS) to code scanning
        if: always() && hashFiles('reports/kics.sarif') != ''
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: reports/kics.sarif
          category: iac-kics
      - name: Upload IaC artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: iac-reports
          path: reports/
          retention-days: 90
          if-no-files-found: warn

  sbom:
    if: github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ env.PYTHON_VERSION }}
      - uses: ./.github/actions/cache-python
        with:
          python-version: ${{ env.PYTHON_VERSION }}

      - name: Install CycloneDX generator
        run: python3 -m pip install --user "cyclonedx-bom==5.*"
      - name: Generate SBOM for Python deps
        run: |
          mkdir -p reports
          python3 -m cyclonedx_py environment \
            --output-file reports/sbom-python.cdx.json \
            --output-format json || true
          python3 -m cyclonedx_py requirements pyproject.toml \
            --output-file reports/sbom-project.cdx.json \
            --output-format json || true
      - name: Upload SBOM artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: reports/
          retention-days: 90
          if-no-files-found: warn

  gate:
    if: github.repository == 'fardani235/molecule'
    needs: [sast, sca, secrets, iac, sbom]
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      pull-requests: write
      security-events: read
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ env.PYTHON_VERSION }}
      - name: Install script deps
        run: python3 -m pip install --user -r .github/scripts/requirements.txt

      - name: Download all scan artifacts
        uses: actions/download-artifact@v4
        with:
          path: all-reports
          pattern: "*-reports"
          merge-multiple: false

      - name: Collect all SARIF into one dir
        run: |
          mkdir -p sarifs
          find all-reports -name "*.sarif" -exec cp {} sarifs/ \;
          ls -la sarifs

      - name: Run gate
        id: gate
        run: |
          python3 .github/scripts/gate.py \
            --sarif-dir sarifs \
            --policy .github/security/gate-policy.yml \
            --waivers trivy=.github/security/.trivyignore \
            --waivers pip-audit=.github/security/pip-audit-ignore.txt \
            --out-md gate-summary.md \
            --out-json gate-report.json
        continue-on-error: true

      - name: Publish gate summary to step summary
        if: always()
        run: cat gate-summary.md >> "$GITHUB_STEP_SUMMARY"

      - name: Upload gate artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: gate-summary
          path: |
            gate-summary.md
            gate-report.json
          retention-days: 90

      - name: Sticky PR comment
        if: always() && github.event_name == 'pull_request'
        uses: marocchino/sticky-pull-request-comment@v2
        with:
          header: security-gate
          path: gate-summary.md

      - name: Fail if gate failed
        if: steps.gate.outcome == 'failure'
        run: |
          echo "::error::Security gate failed — see gate-summary artifact."
          exit 1
```

- [ ] **Step 2: Validate the YAML parses**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/security.yml'))" && echo OK
```

Expected: `OK`.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/security.yml
git commit -m "feat(ci): add security.yml — SAST/SCA/secrets/IaC/SBOM + gate"
```

---

### Task 7: `build-artifacts.yml` — packaged builds + SBOMs

**Files:**
- Create: `.github/workflows/build-artifacts.yml`

**Interfaces:**
- Consumes: `.github/actions/cache-python` from Task 5.
- Produces: `dist` artifact containing `molecule-*.whl`, `molecule-*.tar.gz`, `community-molecule-*.tar.gz`, `*.sha256`, and per-artifact CycloneDX SBOMs. 90d retention.

- [ ] **Step 1: Create `.github/workflows/build-artifacts.yml`**

```yaml
---
name: build-artifacts

on:
  pull_request:
    branches:
      - main
      - "releases/**"
      - "stable/**"
  push:
    branches:
      - main
  workflow_dispatch:

concurrency:
  group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.sha }}
  cancel-in-progress: true

permissions: {}

jobs:
  build:
    if: github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      id-token: write   # reserved for future SBOM attestation
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # setuptools-scm needs full history
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - uses: ./.github/actions/cache-python
        with:
          python-version: "3.11"
          ansible: "true"

      - name: Install build tooling
        run: |
          python3 -m pip install --user "build==1.*" "cyclonedx-bom==5.*"

      - name: Build wheel and sdist
        run: |
          mkdir -p dist
          python3 -m build --outdir dist .

      - name: Build community.molecule collection tarball
        run: |
          python3 -m pip install --user "ansible-core>=2.15,<2.18"
          cd community.molecule
          ansible-galaxy collection build -v --force --output-path ../dist

      - name: SHA-256 sums
        run: |
          cd dist
          sha256sum *.whl *.tar.gz > SHA256SUMS.txt

      - name: SBOM for built distributions
        run: |
          python3 -m cyclonedx_py requirements pyproject.toml \
            --output-file dist/sbom-wheel.cdx.json \
            --output-format json
          # Same content applies to sdist (same project); duplicate for clarity.
          cp dist/sbom-wheel.cdx.json dist/sbom-sdist.cdx.json
          python3 -m cyclonedx_py requirements community.molecule/requirements.txt \
            --output-file dist/sbom-collection.cdx.json \
            --output-format json || true

      - name: Upload dist artifact
        uses: actions/upload-artifact@v4
        with:
          name: dist
          path: dist/
          retention-days: 90
          if-no-files-found: error
```

- [ ] **Step 2: Validate YAML**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/build-artifacts.yml'))" && echo OK
```

Expected: `OK`.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/build-artifacts.yml
git commit -m "feat(ci): add build-artifacts.yml producing wheel/sdist/collection + SBOMs"
```

---

### Task 8: `benchmark.yml` — before/after CI timing

**Files:**
- Create: `.github/workflows/benchmark.yml`

**Interfaces:**
- Consumes: `benchmark_collect.py` from Task 4; GitHub REST API `/repos/…/actions/runs/{id}/jobs`.
- Produces: `benchmark` artifact containing `ci-benchmark.md` and `ci-benchmark.json`.

Approach: run `security.yml` N times via `gh workflow run`, once with a cache-busting variable to force baseline and once normally. This workflow orchestrates that inside a single job using the `gh` CLI (installed by default on GitHub-hosted runners).

- [ ] **Step 1: Create `.github/workflows/benchmark.yml`**

```yaml
---
name: benchmark

on:
  workflow_dispatch:
    inputs:
      mode:
        description: "baseline (no caches) or optimized (with caches)"
        type: choice
        options: [baseline, optimized]
        default: optimized
      runs:
        description: "How many runs of security.yml to average"
        type: number
        default: 3

permissions: {}

jobs:
  benchmark:
    if: github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      actions: read
    env:
      GH_TOKEN: ${{ github.token }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Install script deps
        run: python3 -m pip install --user -r .github/scripts/requirements.txt

      - name: Dispatch N runs of security.yml and record run IDs
        id: dispatch
        run: |
          set -euo pipefail
          mkdir -p runs-json
          RUNS_INPUT="${{ github.event.inputs.runs }}"
          MODE="${{ github.event.inputs.mode }}"
          run_ids=()
          for i in $(seq 1 "$RUNS_INPUT"); do
            echo "Dispatching run $i ($MODE) ..."
            gh workflow run security.yml \
              --ref "${{ github.ref_name }}" \
              -f benchmark_mode="$MODE"
            sleep 5
            # Poll for the most recent run of security.yml on this ref
            RID=$(gh run list --workflow=security.yml \
              --branch "${{ github.ref_name }}" \
              --limit 1 --json databaseId --jq '.[0].databaseId')
            run_ids+=("$RID")
            echo "  run id: $RID"
            gh run watch "$RID" --exit-status || true
          done
          printf '%s\n' "${run_ids[@]}" > run_ids.txt
          cat run_ids.txt

      - name: Fetch per-run jobs JSON
        run: |
          mkdir -p ${{ github.event.inputs.mode }}
          i=0
          while read RID; do
            i=$((i+1))
            gh api "repos/${{ github.repository }}/actions/runs/${RID}/jobs?per_page=100" \
              > "${{ github.event.inputs.mode }}/run-$i.json"
          done < run_ids.txt

      - name: Aggregate (only when both modes' data is present)
        run: |
          # If the counterpart mode's directory doesn't exist yet, create an empty JSON so render_md still works.
          OTHER="$([ "${{ github.event.inputs.mode }}" = "baseline" ] && echo optimized || echo baseline)"
          mkdir -p "$OTHER"
          python3 .github/scripts/benchmark_collect.py \
            --baseline baseline \
            --optimized optimized \
            --out-md ci-benchmark.md \
            --out-json ci-benchmark.json

      - name: Upload benchmark artifact
        uses: actions/upload-artifact@v4
        with:
          name: benchmark
          path: |
            ci-benchmark.md
            ci-benchmark.json
          retention-days: 90
```

Note: `benchmark_mode` is an unused input from `security.yml`'s perspective (added below in Step 2) — its **presence** in the cache key is what forces a miss when `mode=baseline`.

- [ ] **Step 2: Add `benchmark_mode` cache-busting input to `security.yml`**

Modify `.github/workflows/security.yml`:

Add a `workflow_dispatch.inputs` block:

```yaml
on:
  pull_request:
    ...
  push:
    ...
  workflow_dispatch:
    inputs:
      benchmark_mode:
        description: "Set to 'baseline' to force cache misses"
        type: string
        default: ""
```

And in the `cache-python` and `cache-scanners` composite calls in every job, add a suffix to the key so baseline runs miss. The cleanest way is to append the input to env var `CACHE_SALT`:

At the top of the workflow:

```yaml
env:
  PYTHON_VERSION: "3.11"
  CACHE_SALT: ${{ github.event.inputs.benchmark_mode == 'baseline' && github.run_id || 'default' }}
```

Then update the composite actions to take a `salt` input, and pass `${{ env.CACHE_SALT }}` to every call.

**Update `.github/actions/cache-python/action.yml`** — add an input:

```yaml
inputs:
  ...
  salt:
    description: Extra string mixed into every cache key (for benchmarks)
    required: false
    default: default
```

And change every `key:` line to append `-${{ inputs.salt }}` and every `restore-keys:` to append it too. For example:

```yaml
        key: py-${{ runner.os }}-${{ inputs.python-version }}-${{ hashFiles('pyproject.toml', 'tox.ini', '.pre-commit-config.yaml') }}-${{ inputs.salt }}
        restore-keys: |
          py-${{ runner.os }}-${{ inputs.python-version }}-${{ inputs.salt }}-
```

**Update `.github/actions/cache-scanners/action.yml`** — same pattern: add `salt` input, append to each `key:` and `restore-keys:`.

**Update every use in `security.yml` and `build-artifacts.yml`** to pass `salt: ${{ env.CACHE_SALT }}`.

- [ ] **Step 3: Re-validate all YAML**

```bash
for f in .github/workflows/*.yml .github/actions/**/action.yml; do
  python3 -c "import yaml, sys; yaml.safe_load(open('$f'))" && echo "  ok: $f"
done
```

Expected: every file prints `ok`.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/security.yml .github/workflows/build-artifacts.yml .github/workflows/benchmark.yml .github/actions/
git commit -m "feat(ci): add benchmark.yml and cache-salt wiring for baseline runs"
```

---

### Task 9: Mirror lightweight scans into pre-commit

**Files:**
- Modify: `.pre-commit-config.yaml`

**Interfaces:**
- Consumes: nothing.
- Produces: two additional local pre-commit hooks (Gitleaks and Bandit) that developers run before push. These do not replace the CI gate.

- [ ] **Step 1: Show current tail of `.pre-commit-config.yaml`**

```bash
tail -20 .pre-commit-config.yaml
```

- [ ] **Step 2: Append two hooks**

Add to `.pre-commit-config.yaml` (at the end, before any final comment):

```yaml
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.21.2
    hooks:
      - id: gitleaks
        args:
          - "--config=.github/security/.gitleaks.toml"
  - repo: https://github.com/PyCQA/bandit
    rev: "1.8.0"
    hooks:
      - id: bandit
        name: bandit (src/ only)
        args:
          - "-r"
          - "src"
          - "-c"
          - ".github/security/bandit.yaml"
        files: ^src/
        pass_filenames: false
```

- [ ] **Step 3: Verify pre-commit parses the file**

```bash
python3 -m pip install --user pre-commit
pre-commit validate-config .pre-commit-config.yaml && echo OK
```

Expected: `OK`.

- [ ] **Step 4: Commit**

```bash
git add .pre-commit-config.yaml
git commit -m "chore(pre-commit): add gitleaks and bandit local hooks"
```

---

### Task 10: End-to-end smoke test

**Files:**
- None created. Verifies the whole pipeline against the fork.

**Interfaces:**
- Consumes: everything from Tasks 1–9.
- Produces: verification that the workflows run green on a real PR and produce every promised artifact.

- [ ] **Step 1: Push the branch**

```bash
git push -u origin orange-horse-rework
```

- [ ] **Step 2: Open a draft PR against `main`**

```bash
gh pr create --draft --title "DevSecOps CI improvements" \
  --body "Implements docs/superpowers/specs/2026-08-06-devsecops-ci-design.md" \
  --base main --head orange-horse-rework
```

- [ ] **Step 3: Watch the security workflow**

```bash
gh run watch $(gh run list --workflow=security.yml --branch orange-horse-rework --limit 1 --json databaseId --jq '.[0].databaseId') --exit-status
```

Expected: five scan jobs complete, gate job runs, sticky PR comment appears.

- [ ] **Step 4: Verify all artifacts are downloadable**

```bash
RUN_ID=$(gh run list --workflow=security.yml --branch orange-horse-rework --limit 1 --json databaseId --jq '.[0].databaseId')
for name in sast-reports sca-reports secrets-reports iac-reports sbom gate-summary; do
  gh run download "$RUN_ID" -n "$name" -D /tmp/verify/"$name" && echo "  ok: $name"
done
```

Expected: every artifact downloads without error and contains at least one non-empty file.

- [ ] **Step 5: Verify build-artifacts run**

```bash
BID=$(gh run list --workflow=build-artifacts.yml --branch orange-horse-rework --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch "$BID" --exit-status
gh run download "$BID" -n dist -D /tmp/verify/dist
ls /tmp/verify/dist
```

Expected: contains at least one `.whl`, one `.tar.gz` for the Python package, one `community-molecule-*.tar.gz`, `SHA256SUMS.txt`, and three `sbom-*.cdx.json`.

- [ ] **Step 6: Verify SARIF is visible in the Security tab**

Open the fork's **Security → Code scanning alerts** page in a browser; confirm categories `sast-bandit`, `sast-semgrep`, `sca-pip-audit`, `sca-trivy`, `secrets-gitleaks`, `iac-kics` each show at least one entry (or an empty successful scan).

- [ ] **Step 7: Run the benchmark**

```bash
gh workflow run benchmark.yml -f mode=baseline -f runs=3
gh run watch $(gh run list --workflow=benchmark.yml --branch orange-horse-rework --limit 1 --json databaseId --jq '.[0].databaseId') --exit-status
gh workflow run benchmark.yml -f mode=optimized -f runs=3
gh run watch $(gh run list --workflow=benchmark.yml --branch orange-horse-rework --limit 1 --json databaseId --jq '.[0].databaseId') --exit-status
gh run download $(gh run list --workflow=benchmark.yml --branch orange-horse-rework --limit 1 --json databaseId --jq '.[0].databaseId') -n benchmark -D /tmp/verify/benchmark
cat /tmp/verify/benchmark/ci-benchmark.md
```

Expected: the Markdown table renders with per-job medians, a total row, and a negative-percentage delta on the optimized column.

- [ ] **Step 8: Paste the benchmark table into the PR body and mark ready-for-review**

```bash
gh pr edit --add-label "ready-for-review" \
  --body "$(cat <<'EOF'
Implements docs/superpowers/specs/2026-08-06-devsecops-ci-design.md

## CI benchmark
$(cat /tmp/verify/benchmark/ci-benchmark.md)
EOF
)"
gh pr ready
```

- [ ] **Step 9: No commit needed** — smoke test verifies existing commits.

---

## Self-review notes

Spec coverage:
- §2 Goals #1–#7 → Tasks 1, 6 (scanning + gate), 5 (caching), 6/7 (artifacts), 6 (three monitoring surfaces), 4/8 (benchmark), all tasks (fork guard).
- §3 Architecture file list → Tasks 1, 3, 4, 5, 6, 7, 8.
- §4 Tool selection → Task 6 (all six scanners) + Task 7 (CycloneDX).
- §5 Triggers/permissions/fork guard → Tasks 6, 7, 8.
- §6 Gate policy + waiver convention → Tasks 1, 3.
- §7 Caching strategy → Task 5, wired in Tasks 6, 7.
- §8 Artifacts table → Tasks 6, 7, 8.
- §9 Monitoring surfaces → Task 6.
- §10 Benchmark method → Task 8 + orchestration wiring in Task 6.
- §11 Pre-commit mirror → Task 9.
- §12 Rollout plan → follows task order.

Types checked: `Finding`/`GateResult`/`Run`/`Job`/`JobStat` names match across test and impl. CLI arg names for `gate.py` and `benchmark_collect.py` match between definition and calling workflows.

Placeholders: none.
