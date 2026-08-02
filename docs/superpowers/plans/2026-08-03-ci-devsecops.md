# CI DevSecOps Improvements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a fork-owned security-scanning PR gate (fails on medium/high/critical findings), a cached CI job with measured speedup, and downloadable security + release artifacts — without modifying the upstream-delegated `tox.yml`.

**Architecture:** Two new GitHub Actions workflows (`security.yml`, `ci-cached.yml`) plus an additive edit to `release.yml`. Security scanners run in parallel using a two-pass "report + gate" pattern: a report pass always uploads SARIF/artifacts, a gate pass fails the job at the medium+ threshold. An aggregation job `security-gate` is the single required status check. Caching (uv/tox/mypy/ruff) is measured cold-vs-warm and written to step summaries + a benchmarks doc.

**Tech Stack:** GitHub Actions, Bandit (Python SAST), Trivy (SCA + config/IaC), Gitleaks (secrets), uv, tox (`uv-venv-runner`), `github/codeql-action/upload-sarif`, `actions/upload-artifact`.

## Global Constraints

- Every new job MUST be guarded with `if: github.repository == 'fardani235/molecule'` (fork-only execution).
- Do **NOT** modify `tox.yml` (delegates to `ansible/team-devtools`, upstream-owned).
- Do **NOT** add or change any publish steps in `release.yml` (publishing to Galaxy/PyPI is out of scope). Only add artifact uploads.
- Security gate MUST fail on `MEDIUM`, `HIGH`, `CRITICAL` findings; secrets gate fails on any leak.
- All scan results MUST be both uploaded to the GitHub Security tab (SARIF) AND uploaded as downloadable artifacts.
- Findings MUST remain visible even when the gate fails (report pass uses `if: always()` / `continue-on-error`).
- Least-privilege `permissions:` per job (`contents: read`; add `security-events: write` only for SARIF-uploading jobs).
- Pin third-party actions to a tag already trusted in the ecosystem; match existing repo versions where present (`actions/checkout@v7`, `actions/setup-python@v7`).
- Validate all workflow YAML with `yamllint` (repo-configured via `.yamllint`) and `actionlint` before committing.
- Tox env config lives in `pyproject.toml` under `[tool.tox]`; the `lint` env runs `prek run --all-files`, the `pkg` env builds dists. Runner is `uv-venv-runner`.

---

### Task 1: Security workflow skeleton + secrets scanning (Gitleaks)

Establishes `security.yml` with triggers, fork guard, concurrency, and the first scanner (Gitleaks) end-to-end (report + gate + SARIF + artifact). Proves the two-pass pattern before adding more scanners.

**Files:**

- Create: `.github/workflows/security.yml`

**Interfaces:**

- Produces: workflow `security` with jobs `secrets` (and later `sast`, `sca`, `config`, `security-gate`). Artifact naming convention: `<tool>-report.<ext>`. SARIF category per tool.

- [ ] **Step 1: Create the workflow with triggers, guard, and the secrets job**

```yaml
---
name: security
on:
  pull_request:
    branches: ["main"]
  push:
    branches: ["main"]
  schedule:
    - cron: "0 3 * * *" # nightly drift monitoring
  workflow_dispatch:

concurrency:
  group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.sha }}
  cancel-in-progress: true

permissions:
  contents: read

jobs:
  secrets:
    if: github.repository == 'fardani235/molecule'
    name: secrets (gitleaks)
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      security-events: write
    env:
      GITLEAKS_VERSION: "8.21.2"
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0 # full history so gitleaks scans all commits

      # Install the gitleaks CLI directly (the gitleaks-action wrapper is
      # env-var driven, only emits SARIF when secrets are found, and needs a
      # license for orgs). The CLI gives full control over report path + exit code.
      - name: Install gitleaks
        run: |
          set -euo pipefail
          curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
            -o gitleaks.tar.gz
          tar -xzf gitleaks.tar.gz gitleaks
          sudo install gitleaks /usr/local/bin/gitleaks
          gitleaks version

      # Report pass: scan full history, always produce SARIF, never fail here.
      - name: Gitleaks (report)
        run: |
          gitleaks detect --source=. --redact --no-git=false \
            --report-format=sarif --report-path=gitleaks-report.sarif \
            --exit-code=0 --verbose || true
          # Guarantee the SARIF file exists even if gitleaks wrote nothing.
          test -f gitleaks-report.sarif || \
            gitleaks detect --source=. --redact --report-format=sarif \
              --report-path=gitleaks-report.sarif --exit-code=0 || true

      - name: Upload Gitleaks SARIF to Security tab
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: gitleaks-report.sarif
          category: gitleaks

      - name: Upload Gitleaks report artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: gitleaks-report
          path: gitleaks-report.sarif
          retention-days: 30

      # Gate pass: any leak fails the job.
      - name: Gitleaks (gate)
        run: |
          gitleaks detect --source=. --redact --no-git=false --exit-code=1 --verbose
```

- [ ] **Step 2: Validate the YAML**

Run: `yamllint .github/workflows/security.yml && actionlint .github/workflows/security.yml`
(If `actionlint` is not installed: `bash <(curl -s https://raw.githubusercontent.com/rhysd/actionlint/main/scripts/download-actionlint.bash) && ./actionlint .github/workflows/security.yml`)
Expected: no errors. Fix any reported issues before continuing.

- [ ] **Step 3: (Optional) local dry-run**

Run (if `gitleaks` installed): `gitleaks detect --source=. --redact --no-git=false --exit-code=0 -v`
Expected: command completes; note whether any leaks are reported (informational).
Note: the workflow installs the gitleaks CLI (v8.21.2) rather than the
`gitleaks-action` wrapper, so it fully controls `--report-path` and `--exit-code`.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/security.yml
git commit -m "ci: add security workflow skeleton with gitleaks secrets scan

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 2: Python SAST (Bandit)

Adds the `sast` job. Bandit scans `src/` and collection plugins, gates at medium+ severity & confidence, excludes `tests/` from the gate (still reported).

**Files:**

- Modify: `.github/workflows/security.yml` (add `sast` job)
- Create: `.bandit` (config)

**Interfaces:**

- Consumes: workflow structure from Task 1.
- Produces: job `sast`, artifact `bandit-report`, SARIF category `bandit`.

- [ ] **Step 1: Create the Bandit config**

```yaml
# .bandit — exclude test trees from the gate; report pass scans everything.
exclude_dirs:
  - ./tests
  - ./community.molecule/tests
  - ./.tox
  - ./.venv
  - ./build
```

- [ ] **Step 2: Add the `sast` job to `security.yml`** (insert under `jobs:`, sibling to `secrets`)

```yaml
  sast:
    if: github.repository == 'fardani235/molecule'
    name: sast (bandit)
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v7
        with:
          python-version: "3.13"
      - name: Install Bandit
        run: python3 -m pip install --user "bandit[sarif,toml]>=1.8.0"

      # Report pass: scan everything, emit SARIF, never fail here.
      - name: Bandit (report)
        run: |
          python3 -m bandit -r src community.molecule/plugins \
            -f sarif -o bandit-report.sarif || true

      - name: Upload Bandit SARIF to Security tab
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: bandit-report.sarif
          category: bandit

      - name: Upload Bandit report artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: bandit-report
          path: bandit-report.sarif
          retention-days: 30

      # Gate pass: fail on MEDIUM+ severity AND MEDIUM+ confidence, honoring .bandit excludes.
      - name: Bandit (gate)
        run: |
          python3 -m bandit -c .bandit -r src community.molecule/plugins \
            --severity-level medium --confidence-level medium
```

- [ ] **Step 3: Validate the YAML**

Run: `yamllint .github/workflows/security.yml && actionlint .github/workflows/security.yml`
Expected: no errors.

- [ ] **Step 4: (Optional) local dry-run**

Run (if installed): `pip install 'bandit[sarif,toml]' && bandit -c .bandit -r src community.molecule/plugins --severity-level medium --confidence-level medium`
Expected: exits 0 (no medium+ findings) or lists findings. Informational — do not fix source here.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/security.yml .bandit
git commit -m "ci: add bandit python SAST scan to security gate

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 3: Dependency SCA (Trivy filesystem/vuln) with DB caching

Adds the `sca` job scanning the dependency lockfile for CVEs, gating at medium+, with Trivy DB caching.

**Files:**

- Modify: `.github/workflows/security.yml` (add `sca` job)

**Interfaces:**

- Consumes: workflow structure from Task 1.
- Produces: job `sca`, artifact `trivy-sca-report`, SARIF category `trivy-sca`. Establishes the reusable Trivy cache step (`~/.cache/trivy`) reused by Task 4.

- [ ] **Step 1: Add the `sca` job to `security.yml`**

```yaml
  sca:
    if: github.repository == 'fardani235/molecule'
    name: sca (trivy vuln)
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v7

      - name: Cache Trivy DB
        uses: actions/cache@v4
        with:
          path: ~/.cache/trivy
          key: trivy-db-${{ github.run_id }}
          restore-keys: |
            trivy-db-

      # Report pass: all severities, SARIF, never fails.
      - name: Trivy SCA (report)
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: fs
          scanners: vuln
          scan-ref: .
          format: sarif
          output: trivy-sca-report.sarif
          severity: UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL
          exit-code: "0"
          cache-dir: ~/.cache/trivy

      - name: Upload Trivy SCA SARIF to Security tab
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: trivy-sca-report.sarif
          category: trivy-sca

      - name: Upload Trivy SCA report artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: trivy-sca-report
          path: trivy-sca-report.sarif
          retention-days: 30

      # Gate pass: fail on medium+.
      - name: Trivy SCA (gate)
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: fs
          scanners: vuln
          scan-ref: .
          format: table
          severity: MEDIUM,HIGH,CRITICAL
          exit-code: "1"
          cache-dir: ~/.cache/trivy
```

- [ ] **Step 2: Validate the YAML**

Run: `yamllint .github/workflows/security.yml && actionlint .github/workflows/security.yml`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/security.yml
git commit -m "ci: add trivy dependency SCA scan with DB caching

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 4: IaC/config & filesystem misconfig (Trivy config)

Adds the `config` job scanning Ansible YAML and config files for misconfigurations, gating at medium+.

**Files:**

- Modify: `.github/workflows/security.yml` (add `config` job)

**Interfaces:**

- Consumes: workflow structure + Trivy cache pattern from Task 3.
- Produces: job `config`, artifact `trivy-config-report`, SARIF category `trivy-config`.

- [ ] **Step 1: Add the `config` job to `security.yml`**

```yaml
  config:
    if: github.repository == 'fardani235/molecule'
    name: config (trivy misconfig)
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v7

      - name: Cache Trivy DB
        uses: actions/cache@v4
        with:
          path: ~/.cache/trivy
          key: trivy-db-${{ github.run_id }}
          restore-keys: |
            trivy-db-

      # Report pass: all severities, SARIF, never fails.
      - name: Trivy config (report)
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: config
          scan-ref: .
          format: sarif
          output: trivy-config-report.sarif
          severity: UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL
          exit-code: "0"
          cache-dir: ~/.cache/trivy

      - name: Upload Trivy config SARIF to Security tab
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: trivy-config-report.sarif
          category: trivy-config

      - name: Upload Trivy config report artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: trivy-config-report
          path: trivy-config-report.sarif
          retention-days: 30

      # Gate pass: fail on medium+.
      - name: Trivy config (gate)
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: config
          scan-ref: .
          format: table
          severity: MEDIUM,HIGH,CRITICAL
          exit-code: "1"
          cache-dir: ~/.cache/trivy
```

- [ ] **Step 2: Validate the YAML**

Run: `yamllint .github/workflows/security.yml && actionlint .github/workflows/security.yml`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/security.yml
git commit -m "ci: add trivy IaC/config misconfig scan

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 5: Aggregation gate job (`security-gate`)

Adds the single job that `needs:` all four scanners — the required status check for branch protection.

**Files:**

- Modify: `.github/workflows/security.yml` (add `security-gate` job)

**Interfaces:**

- Consumes: jobs `secrets`, `sast`, `sca`, `config`.
- Produces: job `security-gate` — the name to mark as required in branch protection.

- [ ] **Step 1: Add the `security-gate` job to `security.yml`**

```yaml
  security-gate:
    if: always() && github.repository == 'fardani235/molecule'
    name: security-gate
    needs: [secrets, sast, sca, config]
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - name: Verify all scanners passed
        run: |
          results="${{ join(needs.*.result, ',') }}"
          echo "Scanner results: $results"
          if echo "$results" | grep -qE 'failure|cancelled'; then
            echo "::error::Security gate failed — one or more scanners reported medium+ findings."
            exit 1
          fi
          echo "All scanners passed. Security gate OK."
```

- [ ] **Step 2: Validate the YAML**

Run: `yamllint .github/workflows/security.yml && actionlint .github/workflows/security.yml`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/security.yml
git commit -m "ci: add security-gate aggregation job (required check)

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 6: Cached CI job with speedup measurement (`ci-cached.yml`)

Creates the fork-owned cached lint job and writes cache-hit + timing metrics to the step summary and a timing artifact.

**Files:**

- Create: `.github/workflows/ci-cached.yml`

**Interfaces:**

- Produces: workflow `ci-cached`, job `lint-cached`, artifact `ci-timing`, step-summary timing table.

- [ ] **Step 1: Create the workflow**

```yaml
---
name: ci-cached
on:
  pull_request:
    branches: ["main"]
  push:
    branches: ["main"]
  workflow_dispatch:

concurrency:
  group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.sha }}
  cancel-in-progress: true

permissions:
  contents: read

jobs:
  lint-cached:
    if: github.repository == 'fardani235/molecule'
    name: lint (cached)
    runs-on: ubuntu-24.04
    env:
      FORCE_COLOR: 1
    steps:
      - uses: actions/checkout@v7

      - name: Install uv (with built-in cache)
        id: setup-uv
        uses: astral-sh/setup-uv@v6
        with:
          enable-cache: true
          cache-dependency-glob: "uv.lock"

      - name: Set up Python
        run: uv python install 3.13

      - name: Cache tox + tool caches
        id: toolcache
        uses: actions/cache@v4
        with:
          path: |
            .tox
            .cache
          key: toolcache-${{ runner.os }}-${{ hashFiles('pyproject.toml', 'uv.lock') }}
          restore-keys: |
            toolcache-${{ runner.os }}-

      - name: Record start time
        id: t0
        run: echo "start=$(date +%s)" >> "$GITHUB_OUTPUT"

      - name: Install tox
        run: uv tool install "tox>=4.46.0" --with tox-uv

      - name: Run lint (cached tox env)
        run: uv tool run --from tox tox -e lint

      - name: Record end time + emit metrics
        if: always()
        id: t1
        run: |
          end=$(date +%s)
          start='${{ steps.t0.outputs.start }}'
          duration=$(( end - start ))
          uv_hit='${{ steps.setup-uv.outputs.cache-hit }}'
          tool_hit='${{ steps.toolcache.outputs.cache-hit }}'
          echo "uv cache hit: ${uv_hit:-false}"
          [ "$tool_hit" = "true" ] && warm="warm (cache hit)" || warm="cold (cache miss)"
          {
            echo "## CI Cache Benchmark"
            echo ""
            echo "| Metric | Value |"
            echo "|--------|-------|"
            echo "| Run state | $warm |"
            echo "| tox/tool cache hit | ${tool_hit:-false} |"
            echo "| Install + lint duration | ${duration}s |"
          } >> "$GITHUB_STEP_SUMMARY"
          echo "run_state=$warm" >> ci-timing.txt
          echo "tool_cache_hit=${tool_hit:-false}" >> ci-timing.txt
          echo "duration_seconds=$duration" >> ci-timing.txt

      - name: Upload timing artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: ci-timing-${{ github.run_id }}-${{ github.run_attempt }}
          path: ci-timing.txt
          retention-days: 30
```

- [ ] **Step 2: Validate the YAML**

Run: `yamllint .github/workflows/ci-cached.yml && actionlint .github/workflows/ci-cached.yml`
Expected: no errors. In particular confirm `actionlint` does not flag the step-output expressions.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci-cached.yml
git commit -m "ci: add fork-owned cached lint job with speedup metrics

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 7: Release artifact uploads (additive edit to `release.yml`)

Adds `upload-artifact` steps for built dists and the collection tarball. No publish step is changed.

**Files:**

- Modify: `.github/workflows/release.yml`

**Interfaces:**

- Consumes: existing `release` and `publish-collection` jobs.
- Produces: artifacts `python-dist` and `collection-tarball`.

- [ ] **Step 1: In the `release` job, add an upload step immediately AFTER `Build dists` and BEFORE `Publish to pypi.org`**

```yaml
      - name: Upload built dists artifact
        uses: actions/upload-artifact@v4
        with:
          name: python-dist
          path: dist/*
          retention-days: 30
```

- [ ] **Step 2: In the `publish-collection` job, add an upload step immediately AFTER `Build the collection` and BEFORE `Publish the collection on Galaxy`**

```yaml
      - name: Upload collection tarball artifact
        uses: actions/upload-artifact@v4
        with:
          name: collection-tarball
          path: "*.tar.gz"
          retention-days: 30
```

- [ ] **Step 3: Confirm no publish step was modified**

Run: `git diff .github/workflows/release.yml`
Expected: diff shows ONLY the two added `Upload ...` steps. `Publish to pypi.org` and `Publish the collection on Galaxy` steps are byte-for-byte unchanged.

- [ ] **Step 4: Validate the YAML**

Run: `yamllint .github/workflows/release.yml && actionlint .github/workflows/release.yml`
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: upload release dist and collection artifacts (no publish change)

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 8: Documentation (gate usage + benchmarks)

Documents how to read findings, set up the required check, and the cold-vs-warm caching results.

**Files:**

- Create: `docs/superpowers/ci-devsecops.md`
- Create: `docs/superpowers/ci-benchmarks.md`

**Interfaces:**

- Consumes: everything above (job names, artifact names).

- [ ] **Step 1: Write `docs/superpowers/ci-devsecops.md`**

```markdown
# CI DevSecOps Guide

## Security Gate (`security.yml`)

Runs on every PR to `main`, on push to `main`, nightly (drift), and manually.
Fork-guarded to `fardani235/molecule`.

### Scanners (all gate on MEDIUM/HIGH/CRITICAL; secrets on any leak)

| Job       | Tool     | Scope                          | SARIF category |
|-----------|----------|--------------------------------|----------------|
| `secrets` | Gitleaks | Full git history               | `gitleaks`     |
| `sast`    | Bandit   | `src/`, collection plugins     | `bandit`       |
| `sca`     | Trivy    | Dependency CVEs (uv.lock)      | `trivy-sca`    |
| `config`  | Trivy    | Ansible/YAML/config misconfig  | `trivy-config` |

Each scanner runs a **report pass** (always uploads SARIF + artifact, never
fails) and a **gate pass** (fails at the medium+ threshold). So findings are
always visible even on a failing build.

### Where to see findings

- **GitHub Security tab → Code scanning** — all SARIF, tracked over time,
  annotated on PRs.
- **Workflow run → Artifacts** — downloadable raw reports: `gitleaks-report`,
  `bandit-report`, `trivy-sca-report`, `trivy-config-report`.

### Making it a required check

Repo Settings → Branches → branch protection rule for `main` → **Require status
checks to pass** → add **`security-gate`**. PRs then cannot merge with medium+
findings.

## Cached CI (`ci-cached.yml`)

Fork-owned cached lint job (uv + tox + mypy/ruff caches). Each run prints a
cache-benchmark table to the run summary and uploads a `ci-timing-*` artifact.
See `ci-benchmarks.md` for measured cold-vs-warm results.
```

- [ ] **Step 2: Write `docs/superpowers/ci-benchmarks.md`** (fill the numbers after running Task 9)

```markdown
# CI Cache Benchmarks

Measured on `ci-cached.yml` (`lint-cached` job), comparing a cold run (cache
miss) against a subsequent warm run (cache hit).

## How to reproduce

1. Trigger `ci-cached` via **workflow_dispatch** with cold caches (first run of
   the day, or after cache eviction) → records "cold (cache miss)".
2. Trigger it again immediately → records "warm (cache hit)".
3. Download both `ci-timing-*` artifacts, or read each run's summary table.

## Results

| Run   | State            | tool cache hit | Install + lint duration |
|-------|------------------|----------------|-------------------------|
| Cold  | cache miss       | false          | _<fill from run>_ s     |
| Warm  | cache hit        | true           | _<fill from run>_ s     |

**Speedup:** _<cold − warm>_ s saved (_<pct>_% faster) on the install + lint
phase with warm caches.
```

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/ci-devsecops.md docs/superpowers/ci-benchmarks.md
git commit -m "docs: add DevSecOps CI guide and cache benchmarks template

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 9: End-to-end validation on the fork

Push the branch, open a PR on the fork, confirm scanners run, SARIF lands in the Security tab, artifacts download, and record real benchmark numbers.

**Files:** none (verification + benchmark fill-in via Task 8 doc).

- [ ] **Step 1: Push the branch and open a PR on the fork**

```bash
git push -u origin ci-devsecops
gh pr create --repo fardani235/molecule --base main --head ci-devsecops \
  --title "CI: DevSecOps security gate + caching" \
  --body "Adds security.yml gate (bandit/trivy/gitleaks), cached CI job with speedup metrics, and release artifact uploads. See docs/superpowers/ci-devsecops.md."
```

- [ ] **Step 2: Watch the runs**

Run: `gh run watch --repo fardani235/molecule` (or `gh run list --repo fardani235/molecule`)
Expected: `security` and `ci-cached` workflows execute; jobs `secrets`, `sast`, `sca`, `config`, `security-gate`, `lint-cached` appear.

- [ ] **Step 3: Verify Security tab + artifacts**

- Confirm SARIF appears under the repo **Security → Code scanning** with categories `gitleaks`, `bandit`, `trivy-sca`, `trivy-config`.
- Run: `gh run download --repo fardani235/molecule <run-id>` and confirm the four security report artifacts + `ci-timing-*` download.

- [ ] **Step 4: Record benchmark numbers**

- Re-trigger `ci-cached` via `gh workflow run ci-cached.yml --repo fardani235/molecule` to get a warm run.
- Read both run summaries (cold vs warm), fill the table in `docs/superpowers/ci-benchmarks.md`.

- [ ] **Step 5: Commit the filled-in benchmarks**

```bash
git add docs/superpowers/ci-benchmarks.md
git commit -m "docs: record measured cold-vs-warm CI cache speedup

Co-Authored-By: Claude <noreply@anthropic.com>"
git push
```

- [ ] **Step 6: Enable the required check**

Follow `docs/superpowers/ci-devsecops.md` → mark `security-gate` as a required status check in branch protection for `main`.

---

## Self-Review

**Spec coverage:**

- SAST/SCA/secrets/IaC scanning → Tasks 1–4. ✓
- Gate fails on medium/high/critical → gate passes (Tasks 2–4) + aggregation (Task 5). ✓
- SARIF → Security tab + downloadable artifacts → every scanner task. ✓
- Runs in fork, not upstream → fork guard in Global Constraints + every job. ✓
- Caching + measure speedup → Task 6 (metrics) + Task 9 (real numbers) + benchmarks doc (Task 8). ✓
- Release artifacts downloadable, no publish change → Task 7 (+ explicit diff check). ✓
- Out of scope (Galaxy/PyPI publish) → untouched; constraint enforced in Task 7 Step 3. ✓
- `tox.yml` untouched → Global Constraints; no task modifies it. ✓

**Placeholder scan:** Benchmark numbers in Task 8 Step 2 are intentionally filled by Task 9 (measured at runtime) — flagged as `_<fill from run>_`, not a plan gap. No other placeholders.

**Type/name consistency:** Job names (`secrets`, `sast`, `sca`, `config`, `security-gate`, `lint-cached`), artifact names, and SARIF categories are consistent across tasks and the docs table in Task 8.

---

## Post-Implementation Amendments

The final whole-branch code review produced four improvements applied on top of
the tasks above. The workflow files in `.github/workflows/` are the source of
truth; this note records the deltas from the task text:

1. **`security-gate` requires all-success.** The gate now fails unless every
   `needs.*.result` is exactly `success` (a `skipped` result no longer passes the
   gate silently), instead of only matching `failure|cancelled`.
2. **Empty-SARIF fallback for bandit/trivy.** Each of the `sast`, `sca`, and
   `config` jobs writes a valid minimal empty SARIF
   (`{"version":"2.1.0",...,"runs":[]}`) if the scanner produced no file, so a
   scanner *error* never breaks the `upload-sarif` step (mirrors the gitleaks
   fallback).
3. **`ci-cached` timer moved before cache restore.** The `t0` start-time capture
   now runs right after checkout, so the measured window includes uv + tox/tool
   cache restore — the delta the cold-vs-warm benchmark is meant to show.
4. **Bandit report/gate consistency.** The bandit report pass also uses
   `-c .bandit`, so report and gate scan the same configured target set.

Deferred to Task 9 (live validation): confirm Trivy parses `uv.lock` for SCA;
decide whether the Trivy config gate needs a `.trivyignore` if it is too chatty
on Ansible content.
