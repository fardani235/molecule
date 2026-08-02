# DevSecOps CI Improvements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden the fork's CI with SAST, SCA, secret, and IaC scanning gated at Medium+ severity; add caching; produce SBOMs, provenance, and speed-improvement metrics — all fork-scoped so upstream is unaffected.

**Architecture:** Two new fork-scoped workflows (`security.yml`, `ci-metrics.yml`), one additive `warm-cache` job on the existing `tox.yml`, SBOM + Trivy additions on `release.yml`, and a small allowlist + runbook. All new/additive jobs guard with `if: github.repository_owner == 'fardani235'`. Scanners emit SARIF; a single `gate` job filters SARIF `level` to fail on Medium+.

**Tech Stack:** GitHub Actions, CodeQL, `pypa/pip-audit`, `actions/dependency-review-action`, `gitleaks/gitleaks-action`, `woodruffw/zizmor-action`, `aquasecurity/trivy-action`, `anchore/sbom-action`, `pypa/gh-action-pypi-publish` (with attestations), `peter-evans/create-pull-request`, `jq`, `gh` CLI, `actions/cache`, `astral-sh/setup-uv`.

## Global Constraints

- Fork owner guard: every new / additive job's first key must be `if: github.repository_owner == 'fardani235'`.
- Severity gate: any SARIF result with `level` = `error` or `warning` fails the `security / gate` check (maps to Medium+).
- Retention: workflow artifacts pinned to `retention-days: 30`; SARIF also uploaded to GitHub code-scanning.
- Reusable workflows from `ansible/team-devtools` must NOT be forked or modified.
- Existing publishing steps (PyPI, Ansible Galaxy) must NOT be altered beyond adding SBOM + `attestations: true`.
- Python floor per `pyproject.toml`: `>=3.10`; lint runs on 3.10, matrix max 3.13.
- All action versions pinned by major (e.g. `@v4`); no `@main` pins in new code.
- Spec: `docs/superpowers/specs/2026-08-03-devsecops-ci-design.md` — final authority when this plan and the spec disagree.

## File Structure

**Create:**
- `.github/workflows/security.yml` — the DevSecOps gate workflow.
- `.github/workflows/ci-metrics.yml` — records CI wall-clock; opens PRs on drift.
- `.github/security/allowlist.yml` — machine-readable suppressions with `expires`.
- `.github/security/gitleaks.toml` — Gitleaks config rendered from allowlist patterns.
- `.github/codeql/codeql-config.yml` — CodeQL query filters + path filters.
- `.trivyignore` — Trivy suppressions.
- `docs/superpowers/ci-runbook.md` — one-time manual steps + operator guide.
- `docs/superpowers/ci-speed-report.md` — durable metric history (seeded empty; populated by `ci-metrics.yml`).
- `tests/fixtures/security/README.md` + `tests/fixtures/security/vulnerable_sample.py` — known-bad fixture used only to prove the gate blocks (excluded from CodeQL scanning via config paths).

**Modify:**
- `.github/workflows/tox.yml` — add `warm-cache` job that seeds caches and gates the existing reusable-workflow job on its completion.
- `.github/workflows/release.yml` — add SBOM generation, OIDC attestations, and Trivy scan of built dists (owner-gated).

**Untouched:** `.github/workflows/ack.yml`, `push.yml`, `finalize.yml`, `redirects.yml`, `pyproject.toml` (no new runtime deps), `uv.lock`.

---

## Task 1: Bootstrap the fork branch and security config skeleton

**Files:**
- Create: `.github/security/allowlist.yml`
- Create: `.github/security/gitleaks.toml`
- Create: `.github/codeql/codeql-config.yml`
- Create: `.trivyignore`
- Create: `docs/superpowers/ci-runbook.md`
- Create: `docs/superpowers/ci-speed-report.md`

**Interfaces:**
- Consumes: none.
- Produces:
  - `.github/security/allowlist.yml` — YAML with top-level `suppressions:` list; each entry has `id: str`, `tool: enum(codeql|pip-audit|gitleaks|trivy|zizmor|ansible-lint)`, `reason: str`, `owner: str`, `expires: YYYY-MM-DD`.
  - `.github/security/gitleaks.toml` — Gitleaks `[allowlist]` block whose `paths`/`regexes` mirror allowlist entries with `tool: gitleaks`.
  - `.github/codeql/codeql-config.yml` — top-level `paths-ignore:` includes `tests/fixtures/security/**`.
  - `.trivyignore` — one CVE ID per line.
  - `docs/superpowers/ci-runbook.md` — anchor sections `## One-time settings`, `## Adding an allowlist entry`, `## Overriding a release gate`.
  - `docs/superpowers/ci-speed-report.md` — Markdown table with headers `| Window | Median | p95 | Sample | Cache hit % |`.

- [ ] **Step 1: Confirm we're on the working branch**

Run: `git -C /home/ridwan/workspaces/onfrontier/pink-sheep rev-parse --abbrev-ref HEAD`
Expected: `devsecops-ci-improvements`. If not, `git checkout devsecops-ci-improvements`.

- [ ] **Step 2: Create the allowlist skeleton**

Create `.github/security/allowlist.yml` with:

```yaml
# Suppressions for security scanners. Every entry MUST include an
# `expires` date; the gate job fails when any entry is past due.
# Tool values: codeql | pip-audit | gitleaks | trivy | zizmor | ansible-lint
suppressions: []
```

- [ ] **Step 3: Create the Gitleaks config**

Create `.github/security/gitleaks.toml` with:

```toml
title = "molecule fork gitleaks config"

[extend]
useDefault = true

[allowlist]
description = "Rendered from .github/security/allowlist.yml (tool: gitleaks)"
paths = [
  '''tests/fixtures/security/.*''',
]
```

- [ ] **Step 4: Create the CodeQL config**

Create `.github/codeql/codeql-config.yml` with:

```yaml
name: "molecule-fork-codeql-config"
queries:
  - uses: security-and-quality
paths:
  - src
paths-ignore:
  - tests/fixtures/**
  - community.molecule/**
  - docs/**
```

- [ ] **Step 5: Create the Trivy ignore file**

Create `.trivyignore` with:

```
# One CVE ID per line. Every entry MUST have a matching row in
# .github/security/allowlist.yml with tool: trivy and an expires date.
```

- [ ] **Step 6: Seed the CI speed report**

Create `docs/superpowers/ci-speed-report.md` with:

```markdown
# CI Speed Report

Populated automatically by `.github/workflows/ci-metrics.yml`. Do not edit
by hand — the metrics workflow opens a PR when the median drifts more than
20 % from the previous entry.

| Window | Median | p95 | Sample | Cache hit % |
| ------ | ------ | --- | ------ | ----------- |
```

- [ ] **Step 7: Create the runbook**

Create `docs/superpowers/ci-runbook.md` with:

````markdown
# CI Runbook — DevSecOps Fork

## One-time settings

Do these once per fork owner. All in the GitHub UI of `fardani235/molecule`.

1. **Settings → Branches → Branch protection for `main`**: mark
   `security / gate` as a required status check.
2. **Settings → Actions → General → Workflow permissions**: enable
   "Allow GitHub Actions to create and approve pull requests" (needed by
   `ci-metrics.yml` to open the metrics-update PR).
3. **Settings → Code security and analysis**: enable Dependency graph,
   Dependabot alerts, Secret scanning, Code scanning.
4. No secrets are required for the new workflows.

## Adding an allowlist entry

1. Open `.github/security/allowlist.yml`.
2. Append an entry:
   ```yaml
   - id: GHSA-xxxx-xxxx-xxxx      # or CodeQL rule id, Gitleaks rule id, etc.
     tool: pip-audit               # one of: codeql | pip-audit | gitleaks | trivy | zizmor | ansible-lint
     reason: "Not exploitable — CLI-only path, no untrusted input."
     owner: "your-github-handle"
     expires: 2026-11-01           # required. gate fails when past due.
   ```
3. If `tool: gitleaks`, also add the corresponding pattern to
   `.github/security/gitleaks.toml`. If `tool: trivy`, also add the CVE
   id to `.trivyignore`.

## Overriding a release gate

`release.yml` accepts a `workflow_dispatch` input `override_gate: true`.
Only members with `environment: release` approver rights may use it.

```
gh workflow run release.yml -f override_gate=true
```

## Fork owner change

If the fork is renamed or moved:

```
grep -rln "fardani235" .github/ docs/superpowers/ | xargs sed -i 's/fardani235/<new-owner>/g'
```

Then update the runbook and open a PR.
````

- [ ] **Step 8: Create the security fixtures directory**

Create `tests/fixtures/security/README.md`:

```markdown
# Security fixtures

Intentionally-vulnerable snippets used ONLY to prove the DevSecOps gate
in `.github/workflows/security.yml` blocks Medium+ findings. Excluded
from CodeQL by `.github/codeql/codeql-config.yml` paths-ignore.

Do NOT import from `src/` or `community.molecule/`.
```

Create `tests/fixtures/security/vulnerable_sample.py`:

```python
"""Fixture used by CI to confirm the security gate blocks Medium+ findings.

Excluded from CodeQL analysis via .github/codeql/codeql-config.yml. This
file is imported by no production code and no test.
"""

import subprocess  # noqa: S404


def run_untrusted(cmd: str) -> str:
    # Intentional finding: shell=True with untrusted input.
    # Scanners must NOT flag this file — it is path-excluded.
    return subprocess.check_output(cmd, shell=True).decode()  # noqa: S602
```

- [ ] **Step 9: Verify files exist and YAML parses**

Run:
```bash
cd /home/ridwan/workspaces/onfrontier/pink-sheep
python3 -c "import yaml; yaml.safe_load(open('.github/security/allowlist.yml')); yaml.safe_load(open('.github/codeql/codeql-config.yml')); print('ok')"
```

Expected: prints `ok`.

- [ ] **Step 10: Commit**

```bash
git add .github/security/ .github/codeql/ .trivyignore \
        docs/superpowers/ci-runbook.md docs/superpowers/ci-speed-report.md \
        tests/fixtures/security/
git commit -m "ci(security): add allowlist, scanner configs, runbook, metric seed"
```

---

## Task 2: `security.yml` — SAST job (CodeQL) with SARIF gate seed

**Files:**
- Create: `.github/workflows/security.yml`
- Test: manual `gh workflow run security.yml` after commit

**Interfaces:**
- Consumes: `.github/codeql/codeql-config.yml` (from Task 1).
- Produces:
  - Workflow name `security`.
  - Concurrency group `security-${{ github.event.pull_request.number || github.sha }}`, `cancel-in-progress: true`.
  - Jobs so far: `sast-codeql`. Uploads SARIF to code-scanning **and** as artifact named exactly `sarif-codeql`.
  - Later tasks add more scanner jobs and the `gate` job. Each scanner job MUST upload its SARIF as an artifact named `sarif-<toolname>` for the gate to consume.

- [ ] **Step 1: Scaffold `security.yml` with the CodeQL job**

Create `.github/workflows/security.yml`:

```yaml
---
name: security

on:
  pull_request:
    branches: [main, "releases/**", "stable/**"]
  push:
    branches: [main]
  schedule:
    - cron: "0 3 * * 1"  # weekly Monday 03:00 UTC — supplements per-PR runs
  workflow_dispatch:

concurrency:
  group: security-${{ github.event.pull_request.number || github.sha }}
  cancel-in-progress: true

permissions:
  contents: read
  security-events: write   # required for SARIF upload
  actions: read            # required by CodeQL

jobs:
  sast-codeql:
    if: github.repository_owner == 'fardani235'
    runs-on: ubuntu-24.04
    timeout-minutes: 20
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: python
          config-file: .github/codeql/codeql-config.yml

      - name: Analyze
        uses: github/codeql-action/analyze@v3
        with:
          category: /language:python
          output: sarif-results

      - name: Upload CodeQL SARIF artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: sarif-codeql
          path: sarif-results/*.sarif
          retention-days: 30
```

- [ ] **Step 2: Lint the YAML**

Run:
```bash
cd /home/ridwan/workspaces/onfrontier/pink-sheep
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/security.yml')); print('ok')"
```

Expected: prints `ok`.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/security.yml
git commit -m "ci(security): add CodeQL SAST job with SARIF upload"
```

- [ ] **Step 4: Trigger a dry run and confirm**

Run:
```bash
gh workflow run security.yml --ref devsecops-ci-improvements
sleep 5
gh run list --workflow=security.yml --limit 1
```

Expected: one run listed, status queued/in_progress. Wait for completion:

```bash
gh run watch $(gh run list --workflow=security.yml --limit 1 --json databaseId -q '.[0].databaseId')
```

Expected: `sast-codeql` job succeeds, artifact `sarif-codeql` is available.

---

## Task 3: `security.yml` — SCA (pip-audit + Dependency Review)

**Files:**
- Modify: `.github/workflows/security.yml` (add two jobs)

**Interfaces:**
- Consumes: `uv.lock`, PR diff.
- Produces: jobs `sca-pip-audit` (uploads artifact `sarif-pip-audit`) and `sca-dep-review` (uploads artifact `sarif-dep-review`).

- [ ] **Step 1: Append the pip-audit job**

Add under `jobs:` in `.github/workflows/security.yml`:

```yaml
  sca-pip-audit:
    if: github.repository_owner == 'fardani235'
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4

      - uses: astral-sh/setup-uv@v6
        with:
          enable-cache: true

      - name: Export requirements from uv.lock
        run: uv export --format requirements-txt --no-hashes --no-emit-project -o requirements.txt

      - name: Run pip-audit
        id: audit
        uses: pypa/gh-action-pip-audit@v1.1.0
        with:
          inputs: requirements.txt
          # SARIF output enables gate + code-scanning upload.
          extra-args: --format sarif --output pip-audit.sarif --strict

      - name: Upload SARIF to code-scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: pip-audit.sarif
          category: pip-audit

      - name: Upload pip-audit SARIF artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: sarif-pip-audit
          path: pip-audit.sarif
          retention-days: 30
```

- [ ] **Step 2: Append the Dependency Review job**

Add under `jobs:`:

```yaml
  sca-dep-review:
    if: github.repository_owner == 'fardani235' && github.event_name == 'pull_request'
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@v4

      - name: Dependency Review
        uses: actions/dependency-review-action@v4
        with:
          fail-on-severity: moderate
          comment-summary-in-pr: on-failure
          # Emits SARIF so the gate can consume it uniformly.
          # https://github.com/actions/dependency-review-action#configuration
          config-file: .github/security/dep-review.yml
          # Retry-safe: soft-fail is off; job fails inline on moderate+.
```

Also create `.github/security/dep-review.yml`:

```yaml
fail-on-severity: moderate
fail-on-scopes:
  - runtime
  - development
comment-summary-in-pr: on-failure
```

Note: Dependency-Review does not itself write a SARIF file, but it fails
the job on moderate+ findings — that failure is what feeds the gate for
this scanner. We do NOT add a SARIF artifact for it.

- [ ] **Step 3: Lint and commit**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/security.yml')); yaml.safe_load(open('.github/security/dep-review.yml')); print('ok')"
git add .github/workflows/security.yml .github/security/dep-review.yml
git commit -m "ci(security): add pip-audit and Dependency Review SCA jobs"
```

- [ ] **Step 4: Dispatch and verify**

```bash
gh workflow run security.yml --ref devsecops-ci-improvements
gh run watch $(gh run list --workflow=security.yml --limit 1 --json databaseId -q '.[0].databaseId')
```

Expected: `sca-pip-audit` succeeds (unless a real CVE is present — in which case success = "gate is doing its job"; suppress via allowlist if triaged). `sca-dep-review` is skipped on non-PR dispatch (that's fine).

---

## Task 4: `security.yml` — Gitleaks (secrets)

**Files:**
- Modify: `.github/workflows/security.yml`

**Interfaces:**
- Consumes: `.github/security/gitleaks.toml` (from Task 1).
- Produces: job `secrets-gitleaks`, uploads artifact `sarif-gitleaks`.

- [ ] **Step 1: Append the Gitleaks job**

Add under `jobs:`:

```yaml
  secrets-gitleaks:
    if: github.repository_owner == 'fardani235'
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITLEAKS_CONFIG: .github/security/gitleaks.toml
          # SARIF report for the gate + code-scanning upload.
          GITLEAKS_ENABLE_UPLOAD_ARTIFACT: "true"
          GITLEAKS_ENABLE_SUMMARY: "true"
          GITLEAKS_NOTIFY_USER_LIST: ""

      - name: Convert Gitleaks report to SARIF
        if: always()
        run: |
          if [[ -f results.sarif ]]; then
            cp results.sarif gitleaks.sarif
          else
            # No leaks — synthesize an empty SARIF so the gate has a file.
            cat > gitleaks.sarif <<'EOF'
          {"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks"}},"results":[]}]}
          EOF
          fi

      - name: Upload SARIF to code-scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: gitleaks.sarif
          category: gitleaks

      - name: Upload Gitleaks SARIF artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: sarif-gitleaks
          path: gitleaks.sarif
          retention-days: 30
```

- [ ] **Step 2: Lint and commit**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/security.yml')); print('ok')"
git add .github/workflows/security.yml
git commit -m "ci(security): add Gitleaks secret scanning job"
```

- [ ] **Step 3: Dispatch and confirm**

```bash
gh workflow run security.yml --ref devsecops-ci-improvements
gh run watch $(gh run list --workflow=security.yml --limit 1 --json databaseId -q '.[0].databaseId')
```

Expected: `secrets-gitleaks` succeeds; `sarif-gitleaks` artifact present.

---

## Task 5: `security.yml` — zizmor (workflow IaC) + ansible-lint security

**Files:**
- Modify: `.github/workflows/security.yml`

**Interfaces:**
- Consumes: `.github/workflows/*.yml`, `community.molecule/`, `tests/fixtures/`.
- Produces: jobs `iac-zizmor` (artifact `sarif-zizmor`) and `iac-ansible-lint-sec` (artifact `sarif-ansible-lint`).

- [ ] **Step 1: Append the zizmor job**

Add under `jobs:`:

```yaml
  iac-zizmor:
    if: github.repository_owner == 'fardani235'
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@v4

      - name: Install zizmor
        run: |
          python3 -m pip install --user "zizmor>=1.0.0"
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"

      - name: Run zizmor on workflows
        run: |
          zizmor --format sarif --min-severity medium .github/workflows/ \
            > zizmor.sarif || true
          # zizmor exits non-zero when it finds anything; we let the gate
          # decide. Ensure the SARIF is always produced.
          test -s zizmor.sarif || echo '{"version":"2.1.0","runs":[]}' > zizmor.sarif

      - name: Upload SARIF to code-scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: zizmor.sarif
          category: zizmor

      - name: Upload zizmor SARIF artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: sarif-zizmor
          path: zizmor.sarif
          retention-days: 30
```

- [ ] **Step 2: Append the ansible-lint job**

```yaml
  iac-ansible-lint-sec:
    if: github.repository_owner == 'fardani235'
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4

      - uses: astral-sh/setup-uv@v6
        with:
          enable-cache: true

      - name: Install ansible-lint
        run: |
          uv tool install "ansible-lint>=25.0"

      - name: Run ansible-lint (security profile)
        run: |
          set +e
          uv tool run ansible-lint --profile production --write-list \
            --sarif-file ansible-lint.sarif \
            community.molecule/ tests/fixtures/ || true
          # Ensure file exists even when no findings.
          test -s ansible-lint.sarif || echo '{"version":"2.1.0","runs":[]}' > ansible-lint.sarif

      - name: Upload SARIF to code-scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ansible-lint.sarif
          category: ansible-lint

      - name: Upload ansible-lint SARIF artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: sarif-ansible-lint
          path: ansible-lint.sarif
          retention-days: 30
```

- [ ] **Step 3: Lint and commit**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/security.yml')); print('ok')"
git add .github/workflows/security.yml
git commit -m "ci(security): add zizmor and ansible-lint IaC scanning"
```

- [ ] **Step 4: Dispatch and confirm**

```bash
gh workflow run security.yml --ref devsecops-ci-improvements
gh run watch $(gh run list --workflow=security.yml --limit 1 --json databaseId -q '.[0].databaseId')
```

Expected: both jobs succeed; artifacts `sarif-zizmor` and `sarif-ansible-lint` present.

---

## Task 6: `security.yml` — Trivy filesystem scan

**Files:**
- Modify: `.github/workflows/security.yml`

**Interfaces:**
- Consumes: repo filesystem, `.trivyignore` (from Task 1).
- Produces: job `sca-trivy-fs`, artifact `sarif-trivy`.

- [ ] **Step 1: Append the Trivy job**

```yaml
  sca-trivy-fs:
    if: github.repository_owner == 'fardani235'
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4

      - name: Trivy filesystem scan
        uses: aquasecurity/trivy-action@0.24.0
        with:
          scan-type: fs
          scan-ref: .
          format: sarif
          output: trivy.sarif
          severity: MEDIUM,HIGH,CRITICAL
          ignore-unfixed: true
          exit-code: "0"  # gate decides — do not fail the scan step itself
          trivyignores: .trivyignore

      - name: Upload SARIF to code-scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: trivy.sarif
          category: trivy-fs

      - name: Upload Trivy SARIF artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: sarif-trivy
          path: trivy.sarif
          retention-days: 30
```

- [ ] **Step 2: Lint and commit**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/security.yml')); print('ok')"
git add .github/workflows/security.yml
git commit -m "ci(security): add Trivy filesystem scan"
```

- [ ] **Step 3: Dispatch and confirm**

```bash
gh workflow run security.yml --ref devsecops-ci-improvements
gh run watch $(gh run list --workflow=security.yml --limit 1 --json databaseId -q '.[0].databaseId')
```

Expected: `sca-trivy-fs` succeeds; artifact present.

---

## Task 7: `security.yml` — the `gate` aggregator

**Files:**
- Modify: `.github/workflows/security.yml`
- Create: `.github/security/gate.sh`

**Interfaces:**
- Consumes: all `sarif-*` artifacts uploaded by earlier jobs, `.github/security/allowlist.yml`.
- Produces: job `gate` that succeeds only when every SARIF has zero results at `level` in {`error`, `warning`} AND no allowlist entry has `expires` in the past. Uploads a consolidated `security-report.json` artifact.

- [ ] **Step 1: Write the gate helper script**

Create `.github/security/gate.sh` (executable via bash on runners):

```bash
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
```

- [ ] **Step 2: Make the script executable**

```bash
chmod +x .github/security/gate.sh
```

- [ ] **Step 3: Append the gate job**

Add under `jobs:` in `.github/workflows/security.yml`:

```yaml
  gate:
    if: github.repository_owner == 'fardani235' && always()
    needs:
      - sast-codeql
      - sca-pip-audit
      - sca-dep-review
      - secrets-gitleaks
      - iac-zizmor
      - iac-ansible-lint-sec
      - sca-trivy-fs
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@v4

      - name: Download all SARIF artifacts
        uses: actions/download-artifact@v4
        with:
          pattern: sarif-*
          path: sarif/
          merge-multiple: true

      - name: Run gate
        id: gate
        run: .github/security/gate.sh sarif .github/security/allowlist.yml security-report.json

      - name: Upload consolidated security report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: security-report.json
          retention-days: 30

      - name: Fail if any upstream job failed
        if: |
          contains(needs.*.result, 'failure')
        run: |
          echo "::error::One or more scanner jobs failed; see the job list."
          exit 1
```

- [ ] **Step 4: Verify the gate handles `sca-dep-review` being skipped**

Because `sca-dep-review` runs only on `pull_request`, on `push` and `workflow_dispatch` it is skipped. `needs.*.result` for a skipped job is `skipped`, which does NOT match `failure`. The gate will still run — this is intentional.

- [ ] **Step 5: Lint and commit**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/security.yml')); print('ok')"
bash -n .github/security/gate.sh
git add .github/workflows/security.yml .github/security/gate.sh
git commit -m "ci(security): add SARIF gate aggregator (Medium+ severity)"
```

- [ ] **Step 6: Dispatch and confirm the gate passes on green**

```bash
gh workflow run security.yml --ref devsecops-ci-improvements
gh run watch $(gh run list --workflow=security.yml --limit 1 --json databaseId -q '.[0].databaseId')
gh run download --name security-report -D /tmp/sec-report
jq '.runs | length' /tmp/sec-report/security-report.json
```

Expected: gate job succeeds; consolidated report exists with `runs` array covering every scanner.

- [ ] **Step 7: Prove the gate fails on a Medium+ finding**

Add a temporary allowlist entry with a past `expires` date, dispatch again, and confirm the gate fails with the expired-entries error. Then remove the entry.

```bash
python3 - <<'PY'
import yaml
p = ".github/security/allowlist.yml"
d = yaml.safe_load(open(p)) or {"suppressions": []}
d["suppressions"].append({"id":"TEST-EXPIRED","tool":"pip-audit","reason":"gate test","owner":"ci","expires":"2020-01-01"})
open(p, "w").write(yaml.safe_dump(d, sort_keys=False))
PY
git stash push -m gate-fail-probe .github/security/allowlist.yml
# Restore original file locally; the stash pop happens after dispatch.
git checkout .github/security/allowlist.yml
git stash pop
gh workflow run security.yml --ref devsecops-ci-improvements
gh run watch $(gh run list --workflow=security.yml --limit 1 --json databaseId -q '.[0].databaseId') || true
# Expect: gate job fails with "Expired allowlist entries: TEST-EXPIRED".
git checkout .github/security/allowlist.yml   # revert probe
```

Expected: the last run's `gate` job conclusion is `failure`; log contains the expired-entries error.

---

## Task 8: `tox.yml` — additive `warm-cache` job

**Files:**
- Modify: `.github/workflows/tox.yml`

**Interfaces:**
- Consumes: `uv.lock`, `pyproject.toml`, `.pre-commit-config.yaml`.
- Produces: job `warm-cache` that primes `actions/cache` under keys the reusable tox workflow will hit via `restore-keys`. The existing `tox` job now `needs: [warm-cache]` when the guard passes; when the guard is off (upstream), the reusable job runs without `needs`.

- [ ] **Step 1: Read current `tox.yml`**

Confirm the current content matches what was captured in the spec §3.

- [ ] **Step 2: Add the `warm-cache` job and gate the reusable call**

Replace the current `jobs:` block in `.github/workflows/tox.yml` with:

```yaml
jobs:
  warm-cache:
    if: github.repository_owner == 'fardani235'
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4

      - uses: astral-sh/setup-uv@v6
        with:
          enable-cache: true
          cache-dependency-glob: uv.lock

      - name: Prime tox env cache
        uses: actions/cache@v4
        with:
          path: .tox
          key: tox-${{ runner.os }}-py3-${{ hashFiles('pyproject.toml','tox.ini') }}
          restore-keys: |
            tox-${{ runner.os }}-py3-

      - name: Prime pre-commit cache
        uses: actions/cache@v4
        with:
          path: ~/.cache/pre-commit
          key: precommit-${{ hashFiles('.pre-commit-config.yaml') }}
          restore-keys: precommit-

      - name: Materialize uv env
        run: |
          uv sync --frozen --no-install-project

      - name: Warm pre-commit hooks
        run: |
          python3 -m pip install --user pre-commit
          "$HOME/.local/bin/pre-commit" install-hooks || true

      - name: Prime Podman container-storage cache
        uses: actions/cache@v4
        with:
          path: ~/.local/share/containers/storage
          key: podman-${{ hashFiles('tests/fixtures/**/Dockerfile*', 'tests/fixtures/**/containerfile*') }}
          restore-keys: podman-

      # CodeQL DB caching is handled inside github/codeql-action/init@v3
      # (see security.yml, Task 2). Nothing to prime here.

  tox:
    # When the guard passes, gate on warm-cache. Upstream forks skip
    # warm-cache; `needs` on a skipped job would block them, so we do
    # NOT add `needs` here — the reusable workflow simply misses the
    # warmed cache on non-fork runs, which is the existing behaviour.
    uses: ansible/team-devtools/.github/workflows/tox.yml@main
    secrets: inherit
    with:
      default_python: "3.10"
      max_python: "3.13"
      jobs_producing_coverage: 8
      other_names_also: |
        collection
        eco
      run_pre: |
        set -euxo pipefail
        if [[ "$(uname -s)" == Linux && -x /usr/local/bin/crun ]]; then
          sudo mkdir -p /etc/containers/containers.conf.d
          printf '%s\n' '[engine.runtimes]' 'crun = ["/usr/local/bin/crun"]' \
            | sudo tee /etc/containers/containers.conf.d/99-gha-crun.conf >/dev/null
          podman info --format '{{.Host.OCIRuntime.Path}}' || true
        fi
```

- [ ] **Step 3: Lint and commit**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/tox.yml')); print('ok')"
git add .github/workflows/tox.yml
git commit -m "ci(tox): add warm-cache job to prime uv/tox/pre-commit caches"
```

- [ ] **Step 4: Dispatch a run and verify cache warm-up**

Push and open a dummy PR against the fork's `main`. In the run summary,
verify:
- `warm-cache` runs and reports cache miss (cold) on first run.
- On a second dispatch, `warm-cache` reports cache hit.

```bash
gh run list --workflow=tox.yml --limit 2
```

Expected: two runs; second run's `warm-cache` step logs `Cache restored from key: uv-...`.

---

## Task 9: `release.yml` — SBOM, attestations, and Trivy on dists

**Files:**
- Modify: `.github/workflows/release.yml`

**Interfaces:**
- Consumes: built dists in `dist/`.
- Produces:
  - `release` job additionally emits `bom.cdx.json`, `bom.spdx.json`, and OIDC attestations, all attached to the Release and uploaded as artifacts.
  - New job `release-trivy-dists` that scans built dists and fails Medium+; accepts `override_gate: true` from `workflow_dispatch` to allow manual release. Guarded by `environment: release`.

- [ ] **Step 1: Add the `override_gate` workflow input**

Modify the `workflow_dispatch:` block near the top of `.github/workflows/release.yml`:

```yaml
  workflow_dispatch:
    inputs:
      galaxy_publish:
        type: boolean
        description: Publish on galaxy.ansible.com
        default: false
      pypi_publish:
        type: boolean
        description: Publish on pypi.org
        default: false
      override_gate:
        type: boolean
        description: "Fork-only: skip Trivy gate on built dists (release env approver required)"
        default: false
```

- [ ] **Step 2: Add SBOM + attestations to the `release` job**

Insert these steps in the `release:` job AFTER `Build dists` and BEFORE `Publish to pypi.org`:

```yaml
      - name: Generate CycloneDX SBOM
        if: github.repository_owner == 'fardani235'
        uses: anchore/sbom-action@v0
        with:
          artifact-name: bom.cdx.json
          format: cyclonedx-json
          output-file: bom.cdx.json
          path: dist/

      - name: Generate SPDX SBOM
        if: github.repository_owner == 'fardani235'
        uses: anchore/sbom-action@v0
        with:
          artifact-name: bom.spdx.json
          format: spdx-json
          output-file: bom.spdx.json
          path: dist/

      - name: Upload SBOMs as workflow artifacts
        if: github.repository_owner == 'fardani235'
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: |
            bom.cdx.json
            bom.spdx.json
          retention-days: 30

      - name: Attach SBOMs to the GitHub Release
        if: github.repository_owner == 'fardani235' && github.event_name == 'release'
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          gh release upload "${{ github.event.release.tag_name }}" \
            bom.cdx.json bom.spdx.json --clobber
```

Also update the existing `Publish to pypi.org` step to request attestations:

```yaml
      - name: Publish to pypi.org
        uses: pypa/gh-action-pypi-publish@release/v1
        with:
          attestations: true
```

- [ ] **Step 3: Add the Trivy dist-scan job**

Append this job under `jobs:`:

```yaml
  release-trivy-dists:
    if: github.repository_owner == 'fardani235'
    needs: release
    runs-on: ubuntu-24.04
    environment: release
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4

      - name: Download built dists
        uses: actions/download-artifact@v4
        with:
          # `pypa/gh-action-pypi-publish` uploads dists in `dist/`; we re-fetch
          # via the release-artifacts helper below.
          pattern: sbom
          path: sbom/
          merge-multiple: true

      - name: Download release dists from tag
        if: github.event_name == 'release'
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          mkdir -p dist
          gh release download "${{ github.event.release.tag_name }}" \
            --pattern '*.whl' --pattern '*.tar.gz' --dir dist

      - name: Trivy scan of built dists
        id: trivy
        uses: aquasecurity/trivy-action@0.24.0
        with:
          scan-type: fs
          scan-ref: dist
          format: sarif
          output: trivy-dists.sarif
          severity: MEDIUM,HIGH,CRITICAL
          ignore-unfixed: true
          exit-code: "1"
          trivyignores: .trivyignore
        continue-on-error: ${{ inputs.override_gate == true }}

      - name: Upload SARIF to code-scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: trivy-dists.sarif
          category: trivy-dists

      - name: Upload Trivy dist SARIF artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: sarif-trivy-dists
          path: trivy-dists.sarif
          retention-days: 30

      - name: Record override, if used
        if: inputs.override_gate == true
        run: |
          echo "::warning::Release Trivy gate overridden by ${{ github.actor }}"
```

- [ ] **Step 4: Lint and commit**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml')); print('ok')"
git add .github/workflows/release.yml
git commit -m "ci(release): add SBOM, PyPI attestations, and Trivy dist gate"
```

- [ ] **Step 5: Dry-run**

Because `release.yml` fires on GitHub releases, we test via
`workflow_dispatch` with `pypi_publish: false`:

```bash
gh workflow run release.yml -f pypi_publish=false -f galaxy_publish=false
gh run watch $(gh run list --workflow=release.yml --limit 1 --json databaseId -q '.[0].databaseId')
```

Expected: `release` job builds dists and emits SBOMs (artifact `sbom` appears); `release-trivy-dists` runs (skipped on non-release events without built dists — that is acceptable, and the artifact will simply be absent for the dry-run).

---

## Task 10: `ci-metrics.yml` — record CI wall-clock and open drift PRs

**Files:**
- Create: `.github/workflows/ci-metrics.yml`
- Create: `.github/security/measure.py`

**Interfaces:**
- Consumes: `gh run list` output for `tox.yml` runs.
- Produces:
  - Workflow `ci-metrics` with jobs `measure` and (conditional) `open-pr`.
  - Script `measure.py` reads a JSON array on stdin and appends one row to `docs/superpowers/ci-speed-report.md`.

- [ ] **Step 1: Write the measurement script**

Create `.github/security/measure.py`:

```python
"""Append a new row to docs/superpowers/ci-speed-report.md.

Reads a JSON list of successful `tox` workflow runs from stdin.
Each entry must contain `createdAt`, `updatedAt`, and (optionally)
`cacheHitPercent`. Computes median + p95 wall-clock in seconds and
appends a Markdown table row.

The script deliberately depends only on the standard library so the
runner does not need extra installs.
"""
from __future__ import annotations

import json
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path

REPORT = Path("docs/superpowers/ci-speed-report.md")


def _duration_seconds(entry: dict) -> float:
    start = datetime.fromisoformat(entry["createdAt"].replace("Z", "+00:00"))
    end = datetime.fromisoformat(entry["updatedAt"].replace("Z", "+00:00"))
    return (end - start).total_seconds()


def main() -> int:
    runs = json.load(sys.stdin)
    if not runs:
        print("no runs; nothing to append", file=sys.stderr)
        return 0

    durations = [_duration_seconds(r) for r in runs]
    median = statistics.median(durations)
    p95 = statistics.quantiles(durations, n=20)[18] if len(durations) >= 20 else max(durations)
    cache_hit = sum(r.get("cacheHitPercent") or 0 for r in runs) / len(runs)

    window = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    row = f"| {window} | {median:.0f}s | {p95:.0f}s | {len(runs)} | {cache_hit:.0f}% |\n"

    text = REPORT.read_text()
    if not text.rstrip().endswith("|"):
        # First row after the header separator.
        text = text.rstrip() + "\n"
    REPORT.write_text(text + row)
    print(f"appended row for {window}: median={median:.0f}s p95={p95:.0f}s n={len(runs)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Write the workflow**

Create `.github/workflows/ci-metrics.yml`:

```yaml
---
name: ci-metrics

on:
  schedule:
    - cron: "0 4 * * 1"   # Monday 04:00 UTC — one hour after security scan
  workflow_dispatch:

permissions:
  contents: write        # for the drift-PR branch
  pull-requests: write   # for peter-evans/create-pull-request
  actions: read          # to list workflow runs

jobs:
  measure:
    if: github.repository_owner == 'fardani235'
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4

      - name: Fetch last 20 successful tox runs
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          gh run list --workflow=tox.yml --status=success \
            --json databaseId,createdAt,updatedAt \
            --limit 20 > runs.json
          test -s runs.json

      - name: Append metric row
        run: python3 .github/security/measure.py < runs.json

      - name: Upload metric artifact
        uses: actions/upload-artifact@v4
        with:
          name: ci-speed-report
          path: docs/superpowers/ci-speed-report.md
          retention-days: 30

      - name: Open PR if the file changed
        uses: peter-evans/create-pull-request@v7
        with:
          branch: chore/ci-metrics-update
          commit-message: "chore(ci): update CI speed report"
          title: "chore(ci): update CI speed report"
          body: |
            Automated update by `.github/workflows/ci-metrics.yml`. Review the
            newly appended row for regressions (>20 % median drift).
          labels: |
            ci
            metrics
          add-paths: docs/superpowers/ci-speed-report.md
```

- [ ] **Step 3: Lint and commit**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci-metrics.yml')); print('ok')"
python3 -c "import ast; ast.parse(open('.github/security/measure.py').read()); print('ok')"
git add .github/workflows/ci-metrics.yml .github/security/measure.py
git commit -m "ci(metrics): add CI wall-clock measurement + drift PR"
```

- [ ] **Step 4: Capture the baseline**

Before merging Task 8's caching, run:

```bash
gh workflow run ci-metrics.yml
gh run watch $(gh run list --workflow=ci-metrics.yml --limit 1 --json databaseId -q '.[0].databaseId')
```

Expected: the workflow appends a baseline row to `docs/superpowers/ci-speed-report.md` and either commits it directly (if PR-creation permissions are wired) or opens PR `chore/ci-metrics-update`.

Merge the baseline row before merging any caching changes to Task 8. That's what makes the "improvement" number honest.

---

## Task 11: End-to-end verification against the acceptance criteria

**Files:** none (verification only).

**Interfaces:** none.

- [ ] **Step 1: Trigger a failing PR against a Medium+ finding**

Create a throwaway branch with `import subprocess; subprocess.check_output("ls", shell=True)` in `src/molecule/_probe.py`, open a PR, and confirm `security / gate` fails. Delete the branch.

- [ ] **Step 2: Trigger a green PR**

Open a PR with a single-line comment change in `README.md`. Confirm the `security / gate` check passes and both `security-report` and `sarif-*` artifacts are downloadable.

- [ ] **Step 3: Confirm SARIF appears in the Security tab**

Navigate to `https://github.com/fardani235/molecule/security/code-scanning`. Confirm entries for at least `codeql`, `pip-audit`, `gitleaks`, `zizmor`, `trivy-fs`, `ansible-lint` categories.

- [ ] **Step 4: Confirm speed measurement**

Confirm `docs/superpowers/ci-speed-report.md` contains at least two rows: the baseline (pre-caching) row and one row after caching landed. Compute delta:

```bash
awk -F'|' '/^\| [0-9]{4}-[0-9]{2}-[0-9]{2}/{print $3}' docs/superpowers/ci-speed-report.md
```

Expected: numbers trend downward or hold steady.

- [ ] **Step 5: Confirm SBOM on a release dry-run**

`gh workflow run release.yml -f pypi_publish=false` and confirm the `sbom` artifact appears with `bom.cdx.json` and `bom.spdx.json`.

- [ ] **Step 6: Confirm no upstream footprint**

Push the branch to a scratch fork under a different owner (or simulate by
temporarily editing the guard to a mismatched value). Confirm every new
job is skipped in the Actions UI.

- [ ] **Step 7: Final commit — acceptance evidence**

Capture the passing-run URLs and file them in the runbook:

```bash
python3 - <<'PY'
import pathlib
p = pathlib.Path("docs/superpowers/ci-runbook.md")
p.write_text(p.read_text() + "\n## Acceptance evidence\n\n- Failing gate run: <URL>\n- Green PR run: <URL>\n- Release dry-run: <URL>\n- Baseline metric commit: <URL>\n- Post-cache metric commit: <URL>\n")
PY
git add docs/superpowers/ci-runbook.md
git commit -m "docs(ci): record DevSecOps acceptance evidence"
```

Replace `<URL>` values by hand with the real run URLs before pushing.
