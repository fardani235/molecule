# DevSecOps CI Improvements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add fork-owned security scanning (SAST, SCA, secrets, SBOM/artifact scan) with a PR gate that fails on medium/high/critical findings, plus cached build-artifact workflows and a measured CI speedup report.

**Architecture:** Two new fork-owned GitHub Actions workflows (`security.yml`, `build-artifacts.yml`) run alongside the existing upstream-delegated workflows without modifying them. Each scan reports (never hard-exits) and uploads SARIF + JSON; a single `security-gate` job evaluates severities and is the required status check. A build workflow produces the Python package, Ansible collection, and CycloneDX SBOM with fork-owned caching. A `gh`-based timing script and a docs report measure the caching speedup.

**Tech Stack:** GitHub Actions, Bandit, Trivy, Gitleaks, CycloneDX (cyclonedx-py), uv, tox, ansible-galaxy, `gh` CLI, jq.

## Global Constraints

- Fork guard on every new job: `if: github.repository == 'fardani235/molecule'` (exact slug, verbatim).
- Out of scope: publishing to PyPI or Ansible Galaxy. Build only, never publish.
- Do NOT modify `.github/workflows/tox.yml`, `push.yml`, `finalize.yml`, `release.yml` (upstream-delegated / release).
- Least-privilege per-job `permissions`; `security-events: write` only on jobs uploading SARIF.
- Action pin convention already in repo: `actions/checkout@v7`, `actions/setup-python@v7`.
- Python source lives in `src/molecule`. Supported Python `>=3.10`; use `3.11` for tooling.
- Collection source dir: `community.molecule` (built via `ansible-galaxy collection build`).
- Python package built via `tox -e pkg` → outputs to `dist/`.
- Gate severity policy: fail on any `MEDIUM`/`HIGH`/`CRITICAL` finding, or any secret leak.
- Artifact retention: 30 days. Artifact names: `python-dist`, `ansible-collection`, `sbom`, `security-reports`.

---

### Task 1: Bandit SAST job + config

**Files:**
- Create: `.github/workflows/security.yml`
- Modify: `pyproject.toml` (add `[tool.bandit]` section)

**Interfaces:**
- Produces: workflow file `security.yml` with a `bandit` job that uploads artifact `bandit-report` containing `bandit.sarif` and `bandit.json`. Later tasks add sibling jobs (`trivy-deps`, `gitleaks`, `trivy-artifact`) and the `security-gate` job into this same file.

- [ ] **Step 1: Add Bandit config to pyproject.toml**

Append to `pyproject.toml`:

```toml
[tool.bandit]
exclude_dirs = ["tests", ".tox", ".venv", "build", "dist"]
```

- [ ] **Step 2: Create security.yml with the bandit job**

```yaml
---
name: security
on:
  pull_request:
    branches: ["main"]
  push:
    branches: ["main"]

concurrency:
  group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.sha }}
  cancel-in-progress: true

permissions: {}

jobs:
  bandit:
    if: github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v7
        with:
          python-version: "3.11"
      - name: Install Bandit
        run: python -m pip install --user "bandit==1.8.6" "bandit-sarif-formatter==1.1.1"
      - name: Run Bandit (SARIF)
        run: bandit -c pyproject.toml -r src/molecule -f sarif -o bandit.sarif || true
      - name: Run Bandit (JSON for gate)
        run: bandit -c pyproject.toml -r src/molecule -f json -o bandit.json || true
      - name: Upload Bandit reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: bandit-report
          path: |
            bandit.sarif
            bandit.json
          retention-days: 30
```

- [ ] **Step 3: Validate workflow syntax**

Run: `python -c "import yaml,sys; yaml.safe_load(open('.github/workflows/security.yml'))" && echo OK`
Expected: `OK`

- [ ] **Step 4: Verify Bandit runs locally**

Run: `python -m pip install --user "bandit==1.8.6" "bandit-sarif-formatter==1.1.1" && bandit -c pyproject.toml -r src/molecule -f json -o /tmp/bandit.json; jq '.results | length' /tmp/bandit.json`
Expected: a number (0 or more) — command exits cleanly and JSON is well-formed.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/security.yml pyproject.toml
git commit -m "ci: add Bandit SAST scan job"
```

---

### Task 2: Trivy dependency (SCA) job with DB cache

**Files:**
- Modify: `.github/workflows/security.yml` (add `trivy-deps` job)

**Interfaces:**
- Consumes: `security.yml` from Task 1.
- Produces: `trivy-deps` job uploading artifact `trivy-deps-report` with `trivy-deps.sarif` and `trivy-deps.json`. Caches Trivy DB at `~/.cache/trivy`.

- [ ] **Step 1: Add trivy-deps job to security.yml**

Add under `jobs:` in `.github/workflows/security.yml`:

```yaml
  trivy-deps:
    if: github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v7
      - name: Cache Trivy vulnerability DB
        uses: actions/cache@v4
        with:
          path: ~/.cache/trivy
          key: trivy-db-${{ github.run_id }}
          restore-keys: |
            trivy-db-
      - name: Trivy filesystem scan (SARIF)
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: fs
          scan-ref: .
          scanners: vuln
          format: sarif
          output: trivy-deps.sarif
          severity: MEDIUM,HIGH,CRITICAL
          cache-dir: ~/.cache/trivy
      - name: Trivy filesystem scan (JSON for gate)
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: fs
          scan-ref: .
          scanners: vuln
          format: json
          output: trivy-deps.json
          severity: MEDIUM,HIGH,CRITICAL
          cache-dir: ~/.cache/trivy
      - name: Upload Trivy deps reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: trivy-deps-report
          path: |
            trivy-deps.sarif
            trivy-deps.json
          retention-days: 30
```

- [ ] **Step 2: Validate workflow syntax**

Run: `python -c "import yaml; yaml.safe_load(open('.github/workflows/security.yml'))" && echo OK`
Expected: `OK`

- [ ] **Step 3: Lint the workflow with actionlint (already a pre-commit hook)**

Run: `pre-commit run actionlint --files .github/workflows/security.yml`
Expected: `Passed` (or actionlint reports no errors)

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/security.yml
git commit -m "ci: add Trivy dependency (SCA) scan with DB cache"
```

---

### Task 3: Gitleaks secrets job

**Files:**
- Modify: `.github/workflows/security.yml` (add `gitleaks` job)

**Interfaces:**
- Consumes: `security.yml` from Task 2.
- Produces: `gitleaks` job uploading artifact `gitleaks-report` with `gitleaks.sarif` and `gitleaks.json`.

- [ ] **Step 1: Add gitleaks job to security.yml**

Add under `jobs:` in `.github/workflows/security.yml`:

```yaml
  gitleaks:
    if: github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0   # full history so secret scanning sees all commits
      - name: Install gitleaks
        run: |
          curl -sSfL -o /tmp/gitleaks.tar.gz \
            https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz
          tar -xzf /tmp/gitleaks.tar.gz -C /tmp gitleaks
          sudo install /tmp/gitleaks /usr/local/bin/gitleaks
      - name: Run gitleaks (SARIF)
        run: gitleaks detect --source . --report-format sarif --report-path gitleaks.sarif --exit-code 0
      - name: Run gitleaks (JSON for gate)
        run: gitleaks detect --source . --report-format json --report-path gitleaks.json --exit-code 0
      - name: Upload gitleaks reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: gitleaks-report
          path: |
            gitleaks.sarif
            gitleaks.json
          retention-days: 30
```

- [ ] **Step 2: Validate workflow syntax**

Run: `python -c "import yaml; yaml.safe_load(open('.github/workflows/security.yml'))" && echo OK`
Expected: `OK`

- [ ] **Step 3: Verify gitleaks JSON shape locally (array of findings)**

Run: `curl -sSfL -o /tmp/gl.tar.gz https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz && tar -xzf /tmp/gl.tar.gz -C /tmp gitleaks && /tmp/gitleaks detect --source . --report-format json --report-path /tmp/gl.json --exit-code 0; jq 'type' /tmp/gl.json`
Expected: `"array"` (empty `[]` is a pass — no leaks).

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/security.yml
git commit -m "ci: add gitleaks secret scanning job"
```

---

### Task 4: Build-artifacts workflow (package + collection + SBOM) with uv cache

**Files:**
- Create: `.github/workflows/build-artifacts.yml`

**Interfaces:**
- Produces: workflow `build-artifacts.yml` with jobs `build-python` (artifact `python-dist`), `build-collection` (artifact `ansible-collection`), `sbom` (artifact `sbom` containing `sbom-cyclonedx.json`). Task 5's `trivy-artifact` job downloads `python-dist` and `sbom`.

- [ ] **Step 1: Create build-artifacts.yml**

```yaml
---
name: build-artifacts
on:
  pull_request:
    branches: ["main"]
  push:
    branches: ["main"]
  workflow_dispatch:

concurrency:
  group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.sha }}
  cancel-in-progress: true

permissions: {}

jobs:
  build-python:
    if: github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0   # setuptools-scm needs tags
      - uses: actions/setup-python@v7
        with:
          python-version: "3.11"
      - uses: astral-sh/setup-uv@v5
        with:
          enable-cache: true
          cache-dependency-glob: "uv.lock"
      - name: Install tox
        run: uv tool install "tox>=4.46.0" --with tox-uv
      - name: Build Python package
        run: tox -e pkg
      - name: Upload Python dist
        uses: actions/upload-artifact@v4
        with:
          name: python-dist
          path: dist/*
          retention-days: 30

  build-collection:
    if: github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v7
        with:
          python-version: "3.11"
      - name: Install ansible-core
        run: python -m pip install --user "ansible-core>=2.15.0"
      - name: Build collection
        run: ansible-galaxy collection build -v --force community.molecule --output-path dist-collection
      - name: Upload collection
        uses: actions/upload-artifact@v4
        with:
          name: ansible-collection
          path: dist-collection/*.tar.gz
          retention-days: 30

  sbom:
    if: github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v7
        with:
          python-version: "3.11"
      - uses: astral-sh/setup-uv@v5
        with:
          enable-cache: true
          cache-dependency-glob: "uv.lock"
      - name: Generate CycloneDX SBOM
        run: |
          uvx --from cyclonedx-bom cyclonedx-py poetry --help >/dev/null 2>&1 || true
          uvx --from cyclonedx-bom cyclonedx-py requirements <(uv export --format requirements-txt --no-hashes) \
            -o sbom-cyclonedx.json
      - name: Upload SBOM
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom-cyclonedx.json
          retention-days: 30
```

- [ ] **Step 2: Validate workflow syntax**

Run: `python -c "import yaml; yaml.safe_load(open('.github/workflows/build-artifacts.yml'))" && echo OK`
Expected: `OK`

- [ ] **Step 3: Verify tox pkg + collection build locally**

Run: `tox -e pkg && ls dist/*.whl dist/*.tar.gz && ansible-galaxy collection build -v --force community.molecule --output-path /tmp/coll && ls /tmp/coll/*.tar.gz`
Expected: wheel, sdist, and a `community-molecule-*.tar.gz` all listed.

- [ ] **Step 4: Verify SBOM generation locally**

Run: `uv export --format requirements-txt --no-hashes -o /tmp/reqs.txt && uvx --from cyclonedx-bom cyclonedx-py requirements /tmp/reqs.txt -o /tmp/sbom.json && jq '.bomFormat' /tmp/sbom.json`
Expected: `"CycloneDX"`

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/build-artifacts.yml
git commit -m "ci: add build-artifacts workflow (package, collection, SBOM) with uv cache"
```

---

### Task 5: Trivy artifact scan job (consumes built dist + SBOM)

**Files:**
- Modify: `.github/workflows/security.yml` (add `trivy-artifact` job)

**Interfaces:**
- Consumes: `security.yml` from Task 3; downloads artifacts `sbom` (from Task 4). Note: `build-artifacts.yml` and `security.yml` are separate workflows, so `trivy-artifact` rebuilds the SBOM locally to stay self-contained rather than crossing workflow boundaries.
- Produces: `trivy-artifact` job uploading artifact `trivy-artifact-report` with `trivy-artifact.sarif` and `trivy-artifact.json`.

- [ ] **Step 1: Add trivy-artifact job to security.yml**

Add under `jobs:` in `.github/workflows/security.yml`:

```yaml
  trivy-artifact:
    if: github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v7
        with:
          python-version: "3.11"
      - uses: astral-sh/setup-uv@v5
        with:
          enable-cache: true
          cache-dependency-glob: "uv.lock"
      - name: Generate CycloneDX SBOM for scanning
        run: |
          uv export --format requirements-txt --no-hashes -o requirements.txt
          uvx --from cyclonedx-bom cyclonedx-py requirements requirements.txt -o sbom-cyclonedx.json
      - name: Cache Trivy vulnerability DB
        uses: actions/cache@v4
        with:
          path: ~/.cache/trivy
          key: trivy-db-${{ github.run_id }}
          restore-keys: |
            trivy-db-
      - name: Trivy scan SBOM (SARIF)
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: sbom
          scan-ref: sbom-cyclonedx.json
          format: sarif
          output: trivy-artifact.sarif
          severity: MEDIUM,HIGH,CRITICAL
          cache-dir: ~/.cache/trivy
      - name: Trivy scan SBOM (JSON for gate)
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: sbom
          scan-ref: sbom-cyclonedx.json
          format: json
          output: trivy-artifact.json
          severity: MEDIUM,HIGH,CRITICAL
          cache-dir: ~/.cache/trivy
      - name: Upload Trivy artifact reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: trivy-artifact-report
          path: |
            trivy-artifact.sarif
            trivy-artifact.json
          retention-days: 30
```

- [ ] **Step 2: Validate workflow syntax**

Run: `python -c "import yaml; yaml.safe_load(open('.github/workflows/security.yml'))" && echo OK`
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/security.yml
git commit -m "ci: add Trivy artifact/SBOM scan job"
```

---

### Task 6: Gate evaluation script

**Files:**
- Create: `tools/security-gate.py`
- Test: `tests/tools/test_security_gate.py`

**Interfaces:**
- Consumes: report JSON files produced by Tasks 1-3, 5.
- Produces: `tools/security-gate.py` with CLI `python tools/security-gate.py <reports_dir>`; exits `1` if any MEDIUM/HIGH/CRITICAL finding or any secret leak exists, `0` otherwise; writes a Markdown summary table to the path in env `GITHUB_STEP_SUMMARY` if set. Parser functions: `count_bandit(path) -> dict[str,int]`, `count_trivy(path) -> dict[str,int]`, `count_gitleaks(path) -> int`, `evaluate(reports_dir) -> tuple[bool, str]` (returns `(failed, markdown_summary)`).

- [ ] **Step 1: Write the failing test**

Create `tests/tools/test_security_gate.py`:

```python
import json
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "security_gate", Path(__file__).parent.parent.parent / "tools" / "security-gate.py"
)
sg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sg)


def test_count_bandit_medium_high(tmp_path):
    report = {"results": [
        {"issue_severity": "LOW"},
        {"issue_severity": "MEDIUM"},
        {"issue_severity": "HIGH"},
    ]}
    p = tmp_path / "bandit.json"
    p.write_text(json.dumps(report))
    counts = sg.count_bandit(p)
    assert counts == {"LOW": 1, "MEDIUM": 1, "HIGH": 1, "CRITICAL": 0}


def test_count_trivy_severities(tmp_path):
    report = {"Results": [
        {"Vulnerabilities": [
            {"Severity": "HIGH"}, {"Severity": "CRITICAL"}, {"Severity": "LOW"},
        ]}
    ]}
    p = tmp_path / "trivy.json"
    p.write_text(json.dumps(report))
    counts = sg.count_trivy(p)
    assert counts["HIGH"] == 1
    assert counts["CRITICAL"] == 1
    assert counts["LOW"] == 1


def test_count_gitleaks(tmp_path):
    p = tmp_path / "gitleaks.json"
    p.write_text(json.dumps([{"RuleID": "x"}, {"RuleID": "y"}]))
    assert sg.count_gitleaks(p) == 2


def test_evaluate_fails_on_high(tmp_path):
    (tmp_path / "bandit.json").write_text(json.dumps({"results": [{"issue_severity": "HIGH"}]}))
    failed, summary = sg.evaluate(tmp_path)
    assert failed is True
    assert "HIGH" in summary


def test_evaluate_passes_when_clean(tmp_path):
    (tmp_path / "bandit.json").write_text(json.dumps({"results": []}))
    (tmp_path / "gitleaks.json").write_text(json.dumps([]))
    failed, summary = sg.evaluate(tmp_path)
    assert failed is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/tools/test_security_gate.py -v`
Expected: FAIL — file `tools/security-gate.py` not found / import error.

- [ ] **Step 3: Write the implementation**

Create `tools/security-gate.py`:

```python
#!/usr/bin/env python3
"""Evaluate security scan reports and fail on MEDIUM/HIGH/CRITICAL findings.

Usage: python tools/security-gate.py <reports_dir>
Exit code 1 if the gate fails, 0 otherwise. Writes a Markdown summary to
$GITHUB_STEP_SUMMARY when set.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

BLOCKING = ("MEDIUM", "HIGH", "CRITICAL")
_EMPTY = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}


def _load(path: Path):
    if not path.exists():
        return None
    return json.loads(path.read_text() or "null")


def count_bandit(path: Path) -> dict[str, int]:
    counts = dict(_EMPTY)
    data = _load(path)
    if not data:
        return counts
    for result in data.get("results", []):
        sev = (result.get("issue_severity") or "").upper()
        if sev in counts:
            counts[sev] += 1
    return counts


def count_trivy(path: Path) -> dict[str, int]:
    counts = dict(_EMPTY)
    data = _load(path)
    if not data:
        return counts
    for result in data.get("Results", []) or []:
        for vuln in result.get("Vulnerabilities", []) or []:
            sev = (vuln.get("Severity") or "").upper()
            if sev in counts:
                counts[sev] += 1
    return counts


def count_gitleaks(path: Path) -> int:
    data = _load(path)
    if not data:
        return 0
    return len(data)


def evaluate(reports_dir: Path) -> tuple[bool, str]:
    tools: dict[str, dict[str, int]] = {}
    tools["bandit"] = count_bandit(reports_dir / "bandit.json")
    tools["trivy-deps"] = count_trivy(reports_dir / "trivy-deps.json")
    tools["trivy-artifact"] = count_trivy(reports_dir / "trivy-artifact.json")
    secrets = count_gitleaks(reports_dir / "gitleaks.json")

    failed = secrets > 0 or any(
        counts[s] > 0 for counts in tools.values() for s in BLOCKING
    )

    lines = ["## Security Gate", "", "| Tool | LOW | MEDIUM | HIGH | CRITICAL |", "|---|---|---|---|---|"]
    for name, c in tools.items():
        lines.append(f"| {name} | {c['LOW']} | {c['MEDIUM']} | {c['HIGH']} | {c['CRITICAL']} |")
    lines.append(f"| gitleaks (secrets) | - | - | - | {secrets} |")
    lines.append("")
    lines.append(f"**Result: {'❌ FAILED' if failed else '✅ PASSED'}** "
                 "(blocks on MEDIUM/HIGH/CRITICAL or any secret)")
    summary = "\n".join(lines)
    return failed, summary


def main() -> int:
    reports_dir = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    failed, summary = evaluate(reports_dir)
    print(summary)
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write(summary + "\n")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/tools/test_security_gate.py -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add tools/security-gate.py tests/tools/test_security_gate.py
git commit -m "feat: add security gate severity evaluation script"
```

---

### Task 7: Wire the security-gate job + SARIF upload into security.yml

**Files:**
- Modify: `.github/workflows/security.yml` (add `security-gate` job; add SARIF-upload steps)

**Interfaces:**
- Consumes: all scan jobs from Tasks 1-3, 5 and `tools/security-gate.py` from Task 6.
- Produces: `security-gate` job that `needs` all four scan jobs, downloads their report artifacts, runs the gate script, uploads a combined `security-reports` artifact, and uploads each SARIF to the Security tab.

- [ ] **Step 1: Add SARIF upload to each scan job**

In `.github/workflows/security.yml`, add `security-events: write` to the `permissions` of `bandit`, `trivy-deps`, `gitleaks`, and `trivy-artifact`, and add this step at the end of each (adjust `sarif_file` per job: `bandit.sarif`, `trivy-deps.sarif`, `gitleaks.sarif`, `trivy-artifact.sarif`):

```yaml
      - name: Upload SARIF to Security tab
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: bandit.sarif
          category: bandit
```

- [ ] **Step 2: Add the security-gate job**

Add under `jobs:` in `.github/workflows/security.yml`:

```yaml
  security-gate:
    if: github.repository == 'fardani235/molecule'
    needs: [bandit, trivy-deps, gitleaks, trivy-artifact]
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v7
        with:
          python-version: "3.11"
      - name: Download all scan reports
        uses: actions/download-artifact@v4
        with:
          path: reports
          merge-multiple: true
      - name: Consolidate reports
        run: |
          mkdir -p gate-reports
          find reports -type f -name '*.json' -exec cp {} gate-reports/ \;
          find reports -type f -name '*.sarif' -exec cp {} gate-reports/ \;
          ls -la gate-reports
      - name: Evaluate security gate
        run: python tools/security-gate.py gate-reports
      - name: Upload consolidated security reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-reports
          path: gate-reports/*
          retention-days: 30
```

- [ ] **Step 3: Validate workflow syntax**

Run: `python -c "import yaml; yaml.safe_load(open('.github/workflows/security.yml'))" && echo OK`
Expected: `OK`

- [ ] **Step 4: Lint with actionlint**

Run: `pre-commit run actionlint --files .github/workflows/security.yml`
Expected: passes with no errors.

- [ ] **Step 5: Verify the gate script end-to-end with a synthetic HIGH finding**

Run: `mkdir -p /tmp/gr && echo '{"results":[{"issue_severity":"HIGH"}]}' > /tmp/gr/bandit.json && python tools/security-gate.py /tmp/gr; echo "exit=$?"`
Expected: prints the table with `❌ FAILED` and `exit=1`.

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/security.yml
git commit -m "ci: wire security-gate job and SARIF upload to Security tab"
```

---

### Task 8: CI timing capture script

**Files:**
- Create: `tools/ci-timing.sh`

**Interfaces:**
- Produces: `tools/ci-timing.sh <workflow-file> [branch]` that uses `gh run list`/`gh run view --json jobs` to print each job's duration (seconds) as a Markdown table for the latest run of the given workflow.

- [ ] **Step 1: Create tools/ci-timing.sh**

```bash
#!/usr/bin/env bash
# Capture per-job durations for the latest run of a workflow.
# Usage: tools/ci-timing.sh <workflow-file-name> [branch]
# Example: tools/ci-timing.sh build-artifacts.yml main
set -euo pipefail

WORKFLOW="${1:?usage: ci-timing.sh <workflow-file> [branch]}"
BRANCH="${2:-main}"

RUN_ID="$(gh run list --workflow "$WORKFLOW" --branch "$BRANCH" \
  --limit 1 --json databaseId --jq '.[0].databaseId')"

if [[ -z "$RUN_ID" || "$RUN_ID" == "null" ]]; then
  echo "No runs found for $WORKFLOW on $BRANCH" >&2
  exit 1
fi

echo "Run: $RUN_ID ($WORKFLOW @ $BRANCH)"
echo
echo "| Job | Duration (s) |"
echo "|---|---|"
gh run view "$RUN_ID" --json jobs --jq '
  .jobs[]
  | select(.startedAt != null and .completedAt != null)
  | "| \(.name) | \(((.completedAt | fromdateiso8601) - (.startedAt | fromdateiso8601))) |"
'
```

- [ ] **Step 2: Make it executable**

Run: `chmod +x tools/ci-timing.sh`

- [ ] **Step 3: Shellcheck it (shellcheck is a pre-commit hook)**

Run: `pre-commit run shellcheck --files tools/ci-timing.sh`
Expected: passes (no shellcheck errors).

- [ ] **Step 4: Commit**

```bash
git add tools/ci-timing.sh
git commit -m "tools: add CI per-job timing capture script"
```

---

### Task 9: DevSecOps docs (README + performance report template)

**Files:**
- Create: `docs/devsecops/README.md`
- Create: `docs/devsecops/ci-performance.md`

**Interfaces:**
- Consumes: everything above (references workflows, gate, timing script).
- Produces: operator docs and a performance-report template to be filled with real cold-vs-warm numbers after the first Actions runs.

- [ ] **Step 1: Create docs/devsecops/README.md**

```markdown
# DevSecOps CI

Fork-owned security scanning and build/artifact workflows for `fardani235/molecule`.
These run only on the fork (guarded by `github.repository == 'fardani235/molecule'`)
and do not modify the upstream-delegated `tox`/`push`/`finalize` workflows.

## Workflows

- **`.github/workflows/security.yml`** — four parallel scans, then a gate:
  - `bandit` — SAST over `src/molecule`
  - `trivy-deps` — dependency (SCA) scan of `uv.lock`/`pyproject.toml`
  - `gitleaks` — secret scanning over full git history
  - `trivy-artifact` — scans a CycloneDX SBOM of the resolved dependencies
  - `security-gate` — fails the PR on any MEDIUM/HIGH/CRITICAL finding or any secret
- **`.github/workflows/build-artifacts.yml`** — builds the Python package
  (`python-dist`), the Ansible collection (`ansible-collection`), and an SBOM (`sbom`).

## Downloading artifacts

From the GitHub Actions run page, download: `python-dist`, `ansible-collection`,
`sbom`, `security-reports` (all reports + SARIF), and per-tool `*-report` bundles.
Retention is 30 days.

## Monitoring findings

Each scan uploads SARIF to the **Security → Code scanning alerts** tab, so findings
are tracked over time per tool category (`bandit`, `trivy-deps`, `gitleaks`,
`trivy-artifact`). The `security-gate` job also writes a severity table to the run's
Step Summary.

## Required setup (one-time, manual)

To actually block merges, make `security-gate` a **required status check**:

1. Fork repo → **Settings → Branches → Add branch protection rule** for `main`.
2. Enable **Require status checks to pass before merging**.
3. Select **`security-gate`** from the checks list.

## Measuring CI speedup

Run `tools/ci-timing.sh <workflow.yml> <branch>` after a run to capture per-job
durations. See `ci-performance.md` for the cold-vs-warm comparison method and results.
```

- [ ] **Step 2: Create docs/devsecops/ci-performance.md (template)**

```markdown
# CI Performance: Caching Impact

Fork-owned caching (uv cache, Trivy DB cache) added to `security.yml` and
`build-artifacts.yml`. This measures wall-clock impact by comparing a
**cache-cold** run (caches cleared) with a **cache-warm** run (immediate rerun).

## Method

1. Clear caches: **Actions → Caches → delete all** (or `gh cache delete --all`).
2. Trigger the workflow (`workflow_dispatch` or a no-op commit) → this is the **cold** run.
3. Re-trigger immediately → this is the **warm** run.
4. Capture durations: `tools/ci-timing.sh build-artifacts.yml <branch>` and
   `tools/ci-timing.sh security.yml <branch>` for each run.

## Results

> Fill in after the first cold + warm runs complete in the fork.

### build-artifacts.yml

| Job | Cold (s) | Warm (s) | Speedup |
|---|---|---|---|
| build-python | _TBD_ | _TBD_ | _TBD_ |
| sbom | _TBD_ | _TBD_ | _TBD_ |

### security.yml

| Job | Cold (s) | Warm (s) | Speedup |
|---|---|---|---|
| trivy-deps | _TBD_ | _TBD_ | _TBD_ |
| trivy-artifact | _TBD_ | _TBD_ | _TBD_ |

**Total wall-clock:** cold _TBD_ → warm _TBD_ ( _TBD_ % faster).
```

Note: the `_TBD_` markers here are intentional data placeholders in a report
awaiting real Actions runs — they are filled during execution Task 10, not left in code.

- [ ] **Step 3: Commit**

```bash
git add docs/devsecops/README.md docs/devsecops/ci-performance.md
git commit -m "docs: add DevSecOps operator guide and CI performance report template"
```

---

### Task 10: Push, run, capture real timings, fill the report

**Files:**
- Modify: `docs/devsecops/ci-performance.md` (real numbers)

**Interfaces:**
- Consumes: all prior tasks; requires the branch pushed to the fork and Actions enabled.

- [ ] **Step 1: Push the branch to the fork**

```bash
git push -u origin blue-iguana-rework
```

- [ ] **Step 2: Trigger cold run, then warm run**

Clear caches, then dispatch `build-artifacts.yml` and `security.yml` twice (cold then warm):

```bash
gh cache delete --all || true
gh workflow run build-artifacts.yml --ref blue-iguana-rework
gh workflow run security.yml --ref blue-iguana-rework
# wait for completion, then re-run for warm:
gh workflow run build-artifacts.yml --ref blue-iguana-rework
gh workflow run security.yml --ref blue-iguana-rework
```

- [ ] **Step 3: Capture timings**

```bash
tools/ci-timing.sh build-artifacts.yml blue-iguana-rework
tools/ci-timing.sh security.yml blue-iguana-rework
```

- [ ] **Step 4: Fill real numbers into ci-performance.md and verify the gate ran**

Replace every `_TBD_` with captured durations and computed speedups. Confirm on the
Actions run page that `security-gate` executed and SARIF appears under Security →
Code scanning.

- [ ] **Step 5: Commit**

```bash
git add docs/devsecops/ci-performance.md
git commit -m "docs: record measured cold-vs-warm CI cache speedup"
```

---

## Self-Review

**1. Spec coverage:**
- Fork-only CI → Global Constraints + `if:` guard in every job (Tasks 1-7). ✓
- SAST → Task 1 (Bandit). ✓
- Dependency/SCA → Task 2 (Trivy fs). ✓
- Secrets → Task 3 (gitleaks). ✓
- SBOM + artifact scan → Task 4 (SBOM) + Task 5 (Trivy sbom scan). ✓
- Gate fails on MEDIUM/HIGH/CRITICAL → Task 6 (script) + Task 7 (job). ✓
- Downloadable artifacts → upload-artifact in Tasks 1-5, 7; names match spec. ✓
- Security-tab monitoring → SARIF upload in Task 7. ✓
- Caching in fork jobs → uv cache (Task 4, 5), Trivy DB cache (Task 2, 5). ✓
- Measure speedup (cold-vs-warm + doc) → Task 8 (script) + Task 9 (template) + Task 10 (numbers). ✓
- Out of scope: no publish steps anywhere. ✓

**2. Placeholder scan:** No "add appropriate X" / "similar to Task N" placeholders. The `_TBD_` in Task 9 is report *data* filled in Task 10, explicitly annotated. ✓

**3. Type consistency:** Gate script function names (`count_bandit`, `count_trivy`, `count_gitleaks`, `evaluate`) match between the Interfaces block, the test (Task 6 Step 1), and the implementation (Task 6 Step 3). Artifact names (`python-dist`, `ansible-collection`, `sbom`, `security-reports`) consistent across Tasks 4, 7, 9. SARIF categories match tool names. ✓
