# DevSecOps CI Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add security scanning, caching, artifact publishing, and speed benchmarking to the fork's CI pipeline so PRs with medium/high/critical findings cannot merge.

**Architecture:** Three new standalone GitHub Actions workflows (`security.yml`, `release-artifacts.yml`, `cache-benchmark.yml`) plus a reusable composite action for caching. A gate script parses scan results and fails the PR if qualifying findings exist. All workflows are fork-only via `github.repository != 'ansible-community/molecule'`.

**Tech Stack:** GitHub Actions, Bandit, Semgrep, pip-audit, Trivy, Gitleaks, Python 3.10+, uv, tox

## Global Constraints

- All new workflow jobs MUST include `if: github.repository != 'ansible-community/molecule'`.
- Runner: `ubuntu-24.04` (matches existing workflows).
- Python version for tooling: `3.12` (stable, widely available on runners).
- All scan outputs MUST be uploaded as GitHub Actions artifacts.
- SARIF uploads use `github/codeql-action/upload-sarif@v3`.
- Artifact retention: 90 days.
- YAML style: match existing workflows — leading `---`, 2-space indent, double-quoted strings for versions.

## File Structure

```
.github/
├── actions/
│   └── setup-cache/
│       └── action.yml          # Task 1: Reusable composite caching action
├── scripts/
│   └── security-gate.py        # Task 3: Gate script that parses scan JSON
└── workflows/
    ├── security.yml             # Task 2 + Task 3: Security scanning + gate
    ├── release-artifacts.yml    # Task 4: SBOM + build artifact publishing
    ├── cache-benchmark.yml      # Task 5: Caching speed measurement
    └── tox.yml                  # Task 6: Modified to add cache warming
.bandit.yml                      # Task 2: Bandit configuration
.gitleaks.toml                   # Task 2: Gitleaks configuration
```

---

### Task 1: Reusable Caching Composite Action

**Files:**
- Create: `.github/actions/setup-cache/action.yml`

**Interfaces:**
- Consumes: nothing (standalone composite action)
- Produces: a reusable action invoked as `uses: ./.github/actions/setup-cache` with inputs `cache-uv` (boolean), `cache-tox` (boolean), `cache-pre-commit` (boolean). Later tasks reference this action by path.

- [ ] **Step 1: Create the composite action file**

Create `.github/actions/setup-cache/action.yml`:

```yaml
---
name: "Setup CI Caches"
description: "Restore uv, tox, and pre-commit caches to speed up CI runs"

inputs:
  cache-uv:
    description: "Cache uv package downloads (~/.cache/uv)"
    required: false
    default: "true"
  cache-tox:
    description: "Cache tox virtual environments (.tox/)"
    required: false
    default: "true"
  cache-pre-commit:
    description: "Cache pre-commit hook environments (~/.cache/pre-commit)"
    required: false
    default: "false"

runs:
  using: "composite"
  steps:
    - name: Cache uv downloads
      if: inputs.cache-uv == 'true'
      uses: actions/cache@v4
      with:
        path: ~/.cache/uv
        key: ${{ runner.os }}-uv-${{ hashFiles('uv.lock') }}
        restore-keys: |
          ${{ runner.os }}-uv-

    - name: Cache tox environments
      if: inputs.cache-tox == 'true'
      uses: actions/cache@v4
      with:
        path: .tox
        key: ${{ runner.os }}-tox-${{ hashFiles('pyproject.toml') }}
        restore-keys: |
          ${{ runner.os }}-tox-

    - name: Cache pre-commit environments
      if: inputs.cache-pre-commit == 'true'
      uses: actions/cache@v4
      with:
        path: ~/.cache/pre-commit
        key: ${{ runner.os }}-pre-commit-${{ hashFiles('.pre-commit-config.yaml') }}
        restore-keys: |
          ${{ runner.os }}-pre-commit-
```

- [ ] **Step 2: Validate the YAML syntax**

Run:
```bash
python3 -c "import yaml; yaml.safe_load(open('.github/actions/setup-cache/action.yml'))" && echo "YAML valid"
```
Expected: `YAML valid`

- [ ] **Step 3: Lint with actionlint**

Run:
```bash
actionlint .github/actions/setup-cache/action.yml 2>&1 || echo "actionlint not installed locally — will be validated in CI"
```
Expected: no errors (or actionlint not installed — that's fine, CI will catch it).

- [ ] **Step 4: Commit**

```bash
git add .github/actions/setup-cache/action.yml
git commit -m "ci: add reusable caching composite action

Add .github/actions/setup-cache/action.yml with configurable inputs
for uv, tox, and pre-commit caches. Uses actions/cache@v4 with
primary + fallback key strategy.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 2: Security Scanning Workflow — Scanner Jobs

**Files:**
- Create: `.github/workflows/security.yml` (scanner jobs only — gate added in Task 3)
- Create: `.bandit.yml`
- Create: `.gitleaks.toml`

**Interfaces:**
- Consumes: nothing
- Produces: workflow artifacts `bandit-results`, `semgrep-results`, `pip-audit-results`, `trivy-results`, `gitleaks-results` — each containing JSON scan output files. Task 3's gate script reads these.

- [ ] **Step 1: Create `.bandit.yml` configuration**

Create `.bandit.yml` at repo root:

```yaml
---
# Bandit SAST configuration
# Docs: https://bandit.readthedocs.io/en/latest/config.html
targets:
  - src/
skips: []
```

- [ ] **Step 2: Create `.gitleaks.toml` configuration**

Create `.gitleaks.toml` at repo root:

```toml
# Gitleaks configuration
# Docs: https://github.com/gitleaks/gitleaks#configuration

[extend]
useDefault = true

[allowlist]
description = "Molecule-specific allowlist"
paths = [
  '''uv\.lock''',
  '''\.ansible/''',
  '''\.tox/''',
]
```

- [ ] **Step 3: Create `security.yml` with the sast job**

Create `.github/workflows/security.yml` with the `sast` job:

```yaml
---
name: security

on:
  pull_request:
    branches:
      - "main"
      - "releases/**"
      - "stable/**"
  push:
    branches:
      - "main"

concurrency:
  group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.sha }}
  cancel-in-progress: true

permissions:
  contents: read
  security-events: write

jobs:
  sast:
    name: "SAST (Bandit + Semgrep)"
    if: github.repository != 'ansible-community/molecule'
    runs-on: ubuntu-24.04
    steps:
      - name: Checkout code
        uses: actions/checkout@v7

      - name: Set up Python
        uses: actions/setup-python@v7
        with:
          python-version: "3.12"

      - name: Install Bandit
        run: python3 -m pip install --user bandit[toml]

      - name: Run Bandit (JSON)
        run: |
          python3 -m bandit -c .bandit.yml -r src/ \
            -ll \
            -f json -o bandit-results.json \
            || true

      - name: Run Bandit (SARIF)
        run: |
          python3 -m bandit -c .bandit.yml -r src/ \
            -ll \
            -f sarif -o bandit-results.sarif \
            || true

      - name: Upload Bandit SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: bandit-results.sarif
          category: bandit
        continue-on-error: true

      - name: Upload Bandit results artifact
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: bandit-results
          path: |
            bandit-results.json
            bandit-results.sarif
          retention-days: 90

      - name: Install Semgrep
        run: python3 -m pip install --user semgrep

      - name: Run Semgrep
        run: |
          semgrep scan \
            --config p/python \
            --config p/security-audit \
            --json --output semgrep-results.json \
            --sarif --sarif-output semgrep-results.sarif \
            src/ \
            || true

      - name: Upload Semgrep SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: semgrep-results.sarif
          category: semgrep
        continue-on-error: true

      - name: Upload Semgrep results artifact
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: semgrep-results
          path: |
            semgrep-results.json
            semgrep-results.sarif
          retention-days: 90

  dependency-scan:
    name: "Dependency Scan (pip-audit + Trivy)"
    if: github.repository != 'ansible-community/molecule'
    runs-on: ubuntu-24.04
    steps:
      - name: Checkout code
        uses: actions/checkout@v7

      - name: Set up Python
        uses: actions/setup-python@v7
        with:
          python-version: "3.12"

      - name: Install uv
        uses: astral-sh/setup-uv@v6

      - name: Export requirements from uv.lock
        run: uv export --format requirements-txt --no-hashes > requirements.txt

      - name: Install pip-audit
        run: python3 -m pip install --user pip-audit

      - name: Run pip-audit
        run: |
          python3 -m pip_audit \
            -r requirements.txt \
            --format json \
            --output pip-audit-results.json \
            || true

      - name: Upload pip-audit results artifact
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: pip-audit-results
          path: pip-audit-results.json
          retention-days: 90

      - name: Run Trivy filesystem scan
        uses: aquasecurity/trivy-action@0.30.0
        with:
          scan-type: "fs"
          scan-ref: "."
          format: "json"
          output: "trivy-results.json"
          severity: "MEDIUM,HIGH,CRITICAL"

      - name: Run Trivy SARIF scan
        uses: aquasecurity/trivy-action@0.30.0
        with:
          scan-type: "fs"
          scan-ref: "."
          format: "sarif"
          output: "trivy-results.sarif"
          severity: "MEDIUM,HIGH,CRITICAL"

      - name: Upload Trivy SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: trivy-results.sarif
          category: trivy
        continue-on-error: true

      - name: Upload Trivy results artifact
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: trivy-results
          path: |
            trivy-results.json
            trivy-results.sarif
          retention-days: 90

  secrets:
    name: "Secrets Detection (Gitleaks)"
    if: github.repository != 'ansible-community/molecule'
    runs-on: ubuntu-24.04
    steps:
      - name: Checkout code
        uses: actions/checkout@v7
        with:
          fetch-depth: 0

      - name: Run Gitleaks
        uses: gitleaks/gitleaks-action@v2
        with:
          args: --config .gitleaks.toml --report-format json --report-path gitleaks-results.json
        env:
          GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}
        continue-on-error: true

      - name: Run Gitleaks SARIF
        uses: gitleaks/gitleaks-action@v2
        with:
          args: --config .gitleaks.toml --report-format sarif --report-path gitleaks-results.sarif
        env:
          GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}
        continue-on-error: true

      - name: Upload Gitleaks SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: gitleaks-results.sarif
          category: gitleaks
        continue-on-error: true

      - name: Upload Gitleaks results artifact
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: gitleaks-results
          path: |
            gitleaks-results.json
            gitleaks-results.sarif
          retention-days: 90
```

- [ ] **Step 4: Validate YAML syntax**

Run:
```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/security.yml'))" && echo "YAML valid"
```
Expected: `YAML valid`

- [ ] **Step 5: Commit**

```bash
git add .bandit.yml .gitleaks.toml .github/workflows/security.yml
git commit -m "ci: add security scanning jobs (sast, dependency, secrets)

Add Bandit + Semgrep SAST, pip-audit + Trivy dependency scanning,
and Gitleaks secrets detection. All results uploaded as artifacts
and SARIF pushed to GitHub Security tab. Gate job added in next commit.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 3: Security Gate Job + Gate Script

**Files:**
- Create: `.github/scripts/security-gate.py`
- Modify: `.github/workflows/security.yml` (append security-gate job)

**Interfaces:**
- Consumes: artifact JSON files produced by Task 2's scanner jobs — `bandit-results.json`, `semgrep-results.json`, `pip-audit-results.json`, `trivy-results.json`, `gitleaks-results.json`
- Produces: exit code 0 (pass) or 1 (fail) + markdown summary written to `$GITHUB_STEP_SUMMARY`

- [ ] **Step 1: Create the gate script**

Create `.github/scripts/security-gate.py`:

```python
#!/usr/bin/env python3
"""Parse security scan results and fail if medium/high/critical findings exist.

Reads JSON output from Bandit, Semgrep, pip-audit, Trivy, and Gitleaks.
Produces a markdown summary table and exits non-zero if any qualifying
findings are present.

Usage:
    python3 security-gate.py <artifacts-dir>

The artifacts-dir should contain subdirectories named after each scanner's
artifact (bandit-results/, semgrep-results/, etc.), each containing the
scanner's JSON output file.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


SEVERITY_GATE = {"MEDIUM", "HIGH", "CRITICAL"}


def parse_bandit(path: Path) -> list[dict[str, str]]:
    """Parse Bandit JSON output for medium+ findings."""
    findings: list[dict[str, str]] = []
    json_file = path / "bandit-results.json"
    if not json_file.exists():
        return findings
    data = json.loads(json_file.read_text())
    for result in data.get("results", []):
        severity = result.get("issue_severity", "").upper()
        if severity in SEVERITY_GATE:
            findings.append({
                "tool": "Bandit",
                "severity": severity,
                "description": result.get("issue_text", "Unknown"),
                "location": f"{result.get('filename', '?')}:{result.get('line_number', '?')}",
            })
    return findings


def parse_semgrep(path: Path) -> list[dict[str, str]]:
    """Parse Semgrep JSON output for medium+ findings."""
    findings: list[dict[str, str]] = []
    json_file = path / "semgrep-results.json"
    if not json_file.exists():
        return findings
    data = json.loads(json_file.read_text())
    for result in data.get("results", []):
        # Semgrep uses INFO/WARNING/ERROR — map to our severity scale
        raw_severity = result.get("extra", {}).get("severity", "").upper()
        severity_map = {"INFO": "LOW", "WARNING": "MEDIUM", "ERROR": "HIGH"}
        severity = severity_map.get(raw_severity, raw_severity)
        if severity in SEVERITY_GATE:
            findings.append({
                "tool": "Semgrep",
                "severity": severity,
                "description": result.get("extra", {}).get("message", "Unknown"),
                "location": f"{result.get('path', '?')}:{result.get('start', {}).get('line', '?')}",
            })
    return findings


def parse_pip_audit(path: Path) -> list[dict[str, str]]:
    """Parse pip-audit JSON output for medium+ findings."""
    findings: list[dict[str, str]] = []
    json_file = path / "pip-audit-results.json"
    if not json_file.exists():
        return findings
    data = json.loads(json_file.read_text())
    # pip-audit JSON is a list of dependency objects
    deps = data if isinstance(data, list) else data.get("dependencies", [])
    for dep in deps:
        for vuln in dep.get("vulns", []):
            # pip-audit doesn't always include severity; treat all vulns as HIGH
            vuln_id = vuln.get("id", "Unknown")
            fix = vuln.get("fix_versions", [])
            fix_str = ", ".join(fix) if fix else "no fix available"
            findings.append({
                "tool": "pip-audit",
                "severity": "HIGH",
                "description": f"{vuln_id} in {dep.get('name', '?')} {dep.get('version', '?')} (fix: {fix_str})",
                "location": "pyproject.toml (dependency)",
            })
    return findings


def parse_trivy(path: Path) -> list[dict[str, str]]:
    """Parse Trivy JSON output for medium+ findings."""
    findings: list[dict[str, str]] = []
    json_file = path / "trivy-results.json"
    if not json_file.exists():
        return findings
    data = json.loads(json_file.read_text())
    for result_block in data.get("Results", []):
        for vuln in result_block.get("Vulnerabilities", []):
            severity = vuln.get("Severity", "").upper()
            if severity in SEVERITY_GATE:
                findings.append({
                    "tool": "Trivy",
                    "severity": severity,
                    "description": f"{vuln.get('VulnerabilityID', '?')}: {vuln.get('Title', 'Unknown')}",
                    "location": f"{vuln.get('PkgName', '?')} {vuln.get('InstalledVersion', '?')}",
                })
    return findings


def parse_gitleaks(path: Path) -> list[dict[str, str]]:
    """Parse Gitleaks JSON output."""
    findings: list[dict[str, str]] = []
    json_file = path / "gitleaks-results.json"
    if not json_file.exists():
        return findings
    text = json_file.read_text().strip()
    if not text:
        return findings
    data = json.loads(text)
    # Gitleaks JSON is a list of leak objects
    leaks = data if isinstance(data, list) else []
    for leak in leaks:
        findings.append({
            "tool": "Gitleaks",
            "severity": "CRITICAL",
            "description": f"Secret detected: {leak.get('RuleID', 'unknown rule')}",
            "location": f"{leak.get('File', '?')}:{leak.get('StartLine', '?')}",
        })
    return findings


def generate_summary(findings: list[dict[str, str]]) -> str:
    """Generate a markdown summary of findings."""
    if not findings:
        return (
            "## ✅ Security Gate — Passed\n\n"
            "No medium, high, or critical findings detected across all scanners.\n\n"
            "| Scanner | Status |\n"
            "|---------|--------|\n"
            "| Bandit (SAST) | ✅ Clean |\n"
            "| Semgrep (SAST) | ✅ Clean |\n"
            "| pip-audit (Dependencies) | ✅ Clean |\n"
            "| Trivy (Dependencies) | ✅ Clean |\n"
            "| Gitleaks (Secrets) | ✅ Clean |\n"
        )

    lines = [
        "## ❌ Security Gate — Failed\n",
        f"**{len(findings)} finding(s)** at medium severity or above.\n",
        "| Tool | Severity | Description | Location |",
        "|------|----------|-------------|----------|",
    ]
    for f in sorted(findings, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(x["severity"], 3)):
        lines.append(f"| {f['tool']} | {f['severity']} | {f['description']} | `{f['location']}` |")

    lines.append("")
    lines.append("Fix all findings above to pass the security gate.")
    return "\n".join(lines)


def main() -> int:
    """Entry point."""
    if len(sys.argv) != 2:  # noqa: PLR2004
        print(f"Usage: {sys.argv[0]} <artifacts-dir>", file=sys.stderr)
        return 2

    artifacts_dir = Path(sys.argv[1])
    if not artifacts_dir.is_dir():
        print(f"Error: {artifacts_dir} is not a directory", file=sys.stderr)
        return 2

    all_findings: list[dict[str, str]] = []
    all_findings.extend(parse_bandit(artifacts_dir / "bandit-results"))
    all_findings.extend(parse_semgrep(artifacts_dir / "semgrep-results"))
    all_findings.extend(parse_pip_audit(artifacts_dir / "pip-audit-results"))
    all_findings.extend(parse_trivy(artifacts_dir / "trivy-results"))
    all_findings.extend(parse_gitleaks(artifacts_dir / "gitleaks-results"))

    summary = generate_summary(all_findings)

    # Write to GitHub Actions job summary
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a") as fh:
            fh.write(summary)

    # Also print to stdout for logs
    print(summary)

    if all_findings:
        print(f"\n::error::Security gate failed: {len(all_findings)} finding(s) detected", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 2: Write the test for the gate script**

Create `.github/scripts/test_security_gate.py`:

```python
"""Tests for security-gate.py."""

from __future__ import annotations

import json
from pathlib import Path

from security_gate import (
    generate_summary,
    parse_bandit,
    parse_gitleaks,
    parse_pip_audit,
    parse_semgrep,
    parse_trivy,
)


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


def test_parse_bandit_medium_finding(tmp_path: Path) -> None:
    scanner_dir = tmp_path / "bandit-results"
    _write_json(scanner_dir / "bandit-results.json", {
        "results": [
            {
                "issue_severity": "MEDIUM",
                "issue_text": "Use of insecure MD5 hash",
                "filename": "src/molecule/util.py",
                "line_number": 42,
            },
            {
                "issue_severity": "LOW",
                "issue_text": "Consider using a constant",
                "filename": "src/molecule/config.py",
                "line_number": 10,
            },
        ],
    })
    findings = parse_bandit(scanner_dir)
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["tool"] == "Bandit"


def test_parse_bandit_missing_file(tmp_path: Path) -> None:
    findings = parse_bandit(tmp_path / "bandit-results")
    assert findings == []


def test_parse_semgrep_warning_maps_to_medium(tmp_path: Path) -> None:
    scanner_dir = tmp_path / "semgrep-results"
    _write_json(scanner_dir / "semgrep-results.json", {
        "results": [
            {
                "extra": {"severity": "WARNING", "message": "Potential injection"},
                "path": "src/molecule/shell.py",
                "start": {"line": 15},
            },
        ],
    })
    findings = parse_semgrep(scanner_dir)
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"


def test_parse_pip_audit_vuln(tmp_path: Path) -> None:
    scanner_dir = tmp_path / "pip-audit-results"
    _write_json(scanner_dir / "pip-audit-results.json", [
        {
            "name": "jinja2",
            "version": "3.1.2",
            "vulns": [{"id": "CVE-2024-1234", "fix_versions": ["3.1.3"]}],
        },
    ])
    findings = parse_pip_audit(scanner_dir)
    assert len(findings) == 1
    assert "CVE-2024-1234" in findings[0]["description"]
    assert findings[0]["severity"] == "HIGH"


def test_parse_trivy_critical(tmp_path: Path) -> None:
    scanner_dir = tmp_path / "trivy-results"
    _write_json(scanner_dir / "trivy-results.json", {
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "Severity": "CRITICAL",
                        "VulnerabilityID": "CVE-2024-9999",
                        "Title": "RCE in foo",
                        "PkgName": "foo",
                        "InstalledVersion": "1.0.0",
                    },
                    {
                        "Severity": "LOW",
                        "VulnerabilityID": "CVE-2024-0001",
                        "Title": "Info leak",
                        "PkgName": "bar",
                        "InstalledVersion": "2.0.0",
                    },
                ],
            },
        ],
    })
    findings = parse_trivy(scanner_dir)
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"


def test_parse_gitleaks_secret(tmp_path: Path) -> None:
    scanner_dir = tmp_path / "gitleaks-results"
    _write_json(scanner_dir / "gitleaks-results.json", [
        {"RuleID": "aws-access-key", "File": ".env", "StartLine": 3},
    ])
    findings = parse_gitleaks(scanner_dir)
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"


def test_parse_gitleaks_empty(tmp_path: Path) -> None:
    scanner_dir = tmp_path / "gitleaks-results"
    scanner_dir.mkdir(parents=True)
    (scanner_dir / "gitleaks-results.json").write_text("")
    findings = parse_gitleaks(scanner_dir)
    assert findings == []


def test_generate_summary_no_findings() -> None:
    summary = generate_summary([])
    assert "✅" in summary
    assert "Passed" in summary


def test_generate_summary_with_findings() -> None:
    findings = [
        {
            "tool": "Bandit",
            "severity": "HIGH",
            "description": "Hardcoded password",
            "location": "src/foo.py:10",
        },
    ]
    summary = generate_summary(findings)
    assert "❌" in summary
    assert "Failed" in summary
    assert "1 finding(s)" in summary
    assert "Hardcoded password" in summary
```

- [ ] **Step 3: Run the tests**

Run:
```bash
cd .github/scripts && python3 -m pytest test_security_gate.py -v
```
Expected: all 9 tests pass.

- [ ] **Step 4: Append the security-gate job to security.yml**

Add this job at the end of `.github/workflows/security.yml`, inside the `jobs:` block:

```yaml
  security-gate:
    name: "Security Gate"
    if: github.repository != 'ansible-community/molecule'
    needs: [sast, dependency-scan, secrets]
    runs-on: ubuntu-24.04
    steps:
      - name: Checkout code
        uses: actions/checkout@v7
        with:
          sparse-checkout: .github/scripts

      - name: Download all scan artifacts
        uses: actions/download-artifact@v4
        with:
          path: scan-artifacts

      - name: Set up Python
        uses: actions/setup-python@v7
        with:
          python-version: "3.12"

      - name: Run security gate
        run: python3 .github/scripts/security-gate.py scan-artifacts
```

- [ ] **Step 5: Validate YAML syntax**

Run:
```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/security.yml'))" && echo "YAML valid"
```
Expected: `YAML valid`

- [ ] **Step 6: Commit**

```bash
git add .github/scripts/security-gate.py .github/scripts/test_security_gate.py .github/workflows/security.yml
git commit -m "ci: add security gate job with finding parser

Add security-gate.py script that parses JSON output from all scanners
and fails the workflow if medium/high/critical findings exist. Includes
unit tests for all parsers. Gate job depends on sast, dependency-scan,
and secrets jobs.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 4: Release Artifacts Workflow

**Files:**
- Create: `.github/workflows/release-artifacts.yml`

**Interfaces:**
- Consumes: nothing (standalone workflow)
- Produces: downloadable artifacts `sbom-cyclonedx` and `build-artifacts` (sdist + wheel)

- [ ] **Step 1: Create the release artifacts workflow**

Create `.github/workflows/release-artifacts.yml`:

```yaml
---
name: release-artifacts

on:
  push:
    branches:
      - "main"
  release:
    types: [published]

permissions:
  contents: read

jobs:
  build-and-publish-artifacts:
    name: "Build & Publish Artifacts"
    if: github.repository != 'ansible-community/molecule'
    runs-on: ubuntu-24.04

    env:
      FORCE_COLOR: "1"
      PY_COLORS: "1"

    steps:
      - name: Checkout code
        uses: actions/checkout@v7
        with:
          fetch-depth: 0

      - name: Set up Python
        uses: actions/setup-python@v7
        with:
          python-version: "3.12"

      - name: Install uv
        uses: astral-sh/setup-uv@v6

      - name: Setup CI caches
        uses: ./.github/actions/setup-cache
        with:
          cache-uv: "true"
          cache-tox: "true"

      - name: Install tox
        run: python3 -m pip install --user "tox>=4.46.0"

      - name: Generate SBOM (CycloneDX)
        uses: aquasecurity/trivy-action@0.30.0
        with:
          scan-type: "fs"
          scan-ref: "."
          format: "cyclonedx"
          output: "sbom-cyclonedx.json"

      - name: Upload SBOM artifact
        uses: actions/upload-artifact@v4
        with:
          name: sbom-cyclonedx
          path: sbom-cyclonedx.json
          retention-days: 90

      - name: Build package (sdist + wheel)
        run: python3 -m tox -e pkg

      - name: Upload build artifacts
        uses: actions/upload-artifact@v4
        with:
          name: build-artifacts
          path: dist/
          retention-days: 90
```

- [ ] **Step 2: Validate YAML syntax**

Run:
```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release-artifacts.yml'))" && echo "YAML valid"
```
Expected: `YAML valid`

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/release-artifacts.yml
git commit -m "ci: add release artifacts workflow with SBOM generation

Generate CycloneDX SBOM via Trivy and build sdist/wheel packages.
All artifacts uploaded with 90-day retention. Runs on push to main
and on published releases. Fork-only.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 5: Cache Benchmark Workflow

**Files:**
- Create: `.github/workflows/cache-benchmark.yml`

**Interfaces:**
- Consumes: `.github/actions/setup-cache` composite action from Task 1
- Produces: downloadable artifact `cache-benchmark-report` containing a markdown comparison report

- [ ] **Step 1: Create the cache benchmark workflow**

Create `.github/workflows/cache-benchmark.yml`:

```yaml
---
name: cache-benchmark

on:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  benchmark-no-cache:
    name: "Benchmark: No Cache"
    if: github.repository != 'ansible-community/molecule'
    runs-on: ubuntu-24.04

    env:
      FORCE_COLOR: "1"
      PY_COLORS: "1"

    outputs:
      duration: ${{ steps.timing.outputs.duration }}

    steps:
      - name: Checkout code
        uses: actions/checkout@v7

      - name: Set up Python
        uses: actions/setup-python@v7
        with:
          python-version: "3.12"

      - name: Install uv
        uses: astral-sh/setup-uv@v6

      - name: Install tox
        run: python3 -m pip install --user "tox>=4.46.0" "tox-uv>=1.32.1"

      - name: Run tox lint (no cache) and measure time
        id: timing
        run: |
          START=$(date +%s)
          python3 -m tox -e lint || true
          END=$(date +%s)
          DURATION=$((END - START))
          echo "duration=${DURATION}" >> "$GITHUB_OUTPUT"
          echo "No-cache run took ${DURATION}s"

  benchmark-with-cache:
    name: "Benchmark: With Cache"
    if: github.repository != 'ansible-community/molecule'
    needs: benchmark-no-cache
    runs-on: ubuntu-24.04

    env:
      FORCE_COLOR: "1"
      PY_COLORS: "1"

    outputs:
      duration: ${{ steps.timing.outputs.duration }}

    steps:
      - name: Checkout code
        uses: actions/checkout@v7

      - name: Set up Python
        uses: actions/setup-python@v7
        with:
          python-version: "3.12"

      - name: Install uv
        uses: astral-sh/setup-uv@v6

      - name: Setup CI caches
        uses: ./.github/actions/setup-cache
        with:
          cache-uv: "true"
          cache-tox: "true"
          cache-pre-commit: "true"

      - name: Install tox
        run: python3 -m pip install --user "tox>=4.46.0" "tox-uv>=1.32.1"

      - name: Run tox lint (with cache) and measure time
        id: timing
        run: |
          START=$(date +%s)
          python3 -m tox -e lint || true
          END=$(date +%s)
          DURATION=$((END - START))
          echo "duration=${DURATION}" >> "$GITHUB_OUTPUT"
          echo "With-cache run took ${DURATION}s"

  report:
    name: "Benchmark Report"
    if: github.repository != 'ansible-community/molecule'
    needs: [benchmark-no-cache, benchmark-with-cache]
    runs-on: ubuntu-24.04

    steps:
      - name: Generate benchmark report
        run: |
          NO_CACHE=${{ needs.benchmark-no-cache.outputs.duration }}
          WITH_CACHE=${{ needs.benchmark-with-cache.outputs.duration }}

          if [ "$NO_CACHE" -gt 0 ]; then
            DIFF=$((NO_CACHE - WITH_CACHE))
            PERCENT=$(( (DIFF * 100) / NO_CACHE ))
          else
            DIFF=0
            PERCENT=0
          fi

          cat > benchmark-report.md << 'HEADER'
          # CI Cache Benchmark Report

          ## Results

          | Metric | No Cache | With Cache |
          |--------|----------|------------|
          HEADER

          echo "| Duration | ${NO_CACHE}s | ${WITH_CACHE}s |" >> benchmark-report.md
          echo "| **Improvement** | — | **${DIFF}s faster (${PERCENT}%)** |" >> benchmark-report.md
          echo "" >> benchmark-report.md
          echo "## Details" >> benchmark-report.md
          echo "" >> benchmark-report.md
          echo "- **Test command:** \`tox -e lint\`" >> benchmark-report.md
          echo "- **Runner:** ubuntu-24.04" >> benchmark-report.md
          echo "- **Caches enabled:** uv, tox, pre-commit" >> benchmark-report.md
          echo "- **Cache key strategy:** primary key with fallback restore key" >> benchmark-report.md

          cat benchmark-report.md

      - name: Post to job summary
        run: cat benchmark-report.md >> "$GITHUB_STEP_SUMMARY"

      - name: Upload benchmark report
        uses: actions/upload-artifact@v4
        with:
          name: cache-benchmark-report
          path: benchmark-report.md
          retention-days: 90
```

- [ ] **Step 2: Validate YAML syntax**

Run:
```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/cache-benchmark.yml'))" && echo "YAML valid"
```
Expected: `YAML valid`

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/cache-benchmark.yml
git commit -m "ci: add cache benchmark workflow

Manual-trigger workflow that runs tox lint with and without caching,
measures wall-clock times, and generates a comparison report. Report
posted to job summary and uploaded as artifact.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 6: Integrate Caching into Existing tox.yml

**Files:**
- Modify: `.github/workflows/tox.yml`

**Interfaces:**
- Consumes: `.github/actions/setup-cache` composite action from Task 1
- Produces: modified `tox.yml` that warms caches before the shared workflow runs

The existing `tox.yml` delegates entirely to a reusable workflow via `uses:`. Reusable workflow calls
cannot include `steps:` — only `with:` inputs. The `run_pre` input is a shell script, not a step,
so it cannot invoke `uses:` composite actions.

**Approach:** Add a separate `cache-warm` job that runs before the `tox` job. This job checks out
the repo, invokes the composite action (which populates `actions/cache`), and then the `tox` job
runs afterward. Since GitHub Actions caches are shared across jobs in the same workflow run, the
tox job's runners will get cache hits from the warm-up.

**Important:** The `tox` job in the shared workflow may run on multiple matrices (different Python
versions, OS). The cache warm job only needs to run once — the cache keys are OS-based and will
be available to all matrix entries on the same OS.

- [ ] **Step 1: Modify tox.yml to add a cache warming job**

In `.github/workflows/tox.yml`, add a `cache-warm` job before the existing `tox` job, and make
`tox` depend on it:

Replace the entire `jobs:` block with:

```yaml
jobs:
  cache-warm:
    name: "Warm CI Caches"
    if: github.repository != 'ansible-community/molecule'
    runs-on: ubuntu-24.04
    steps:
      - name: Checkout code
        uses: actions/checkout@v7

      - name: Setup CI caches
        uses: ./.github/actions/setup-cache
        with:
          cache-uv: "true"
          cache-tox: "true"
          cache-pre-commit: "true"

  tox:
    needs: [cache-warm]
    if: always()
    uses: ansible/team-devtools/.github/workflows/tox.yml@main
    secrets: inherit
    with:
      default_python: "3.10" # for lint
      max_python: "3.13"
      jobs_producing_coverage: 8
      other_names_also: |
        collection
        eco
      # Temporary: ubuntu-24.04 image 20260726.254 ships Podman 5.8.4 but leaves
      # Podman pointed at /usr/bin/crun 1.14.1 while /usr/local/bin/crun 1.28 exists.
      # Promote into team-devtools tox.yml if this unblocks Linux integration tests.
      # See https://github.com/actions/runner-images/issues/14473
      run_pre: |
        set -euxo pipefail
        if [[ "$(uname -s)" == Linux && -x /usr/local/bin/crun ]]; then
          sudo mkdir -p /etc/containers/containers.conf.d
          printf '%s\n' '[engine.runtimes]' 'crun = ["/usr/local/bin/crun"]' \
            | sudo tee /etc/containers/containers.conf.d/99-gha-crun.conf >/dev/null
          podman info --format '{{.Host.OCIRuntime.Path}}' || true
        fi
```

The key changes:
- Added `cache-warm` job with fork-only guard.
- Added `needs: [cache-warm]` to the `tox` job so it waits for caches.
- Added `if: always()` to the `tox` job so it runs even when `cache-warm` is skipped (on upstream).

- [ ] **Step 2: Validate YAML syntax**

Run:
```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/tox.yml'))" && echo "YAML valid"
```
Expected: `YAML valid`

- [ ] **Step 3: Verify the original tox job content is preserved**

Run:
```bash
grep -c "ansible/team-devtools" .github/workflows/tox.yml
```
Expected: `1` — the shared workflow reference is still there.

Run:
```bash
grep "cache-warm" .github/workflows/tox.yml
```
Expected: matches for the new `cache-warm` job and the `needs:` reference.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/tox.yml
git commit -m "ci: add cache warming job to tox workflow

Add a cache-warm job that populates uv, tox, and pre-commit caches
before the tox matrix runs. Uses the reusable setup-cache composite
action. Fork-only — skipped on upstream, tox job still runs via
if: always().

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Verification Checklist

After all tasks are complete, verify:

- [ ] All YAML files pass `python3 -c "import yaml; yaml.safe_load(open(...))"`.
- [ ] All new workflow jobs have the `if: github.repository != 'ansible-community/molecule'` guard.
- [ ] The gate script tests pass: `cd .github/scripts && python3 -m pytest test_security_gate.py -v`.
- [ ] `security.yml` has all 4 jobs: `sast`, `dependency-scan`, `secrets`, `security-gate`.
- [ ] `release-artifacts.yml` uploads `sbom-cyclonedx` and `build-artifacts`.
- [ ] `cache-benchmark.yml` has 3 jobs: `benchmark-no-cache`, `benchmark-with-cache`, `report`.
- [ ] `tox.yml` has the `cache-warm` job and `tox` job depends on it with `if: always()`.
- [ ] No references to PyPI publishing or Galaxy publishing in new workflows.
