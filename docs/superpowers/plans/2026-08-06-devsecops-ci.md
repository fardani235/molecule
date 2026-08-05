# DevSecOps CI Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add security scanning, caching, and CI speed measurement to the forked Molecule repository's GitHub Actions pipelines.

**Architecture:** Three workflow files deliver the changes: a new `security.yml` runs Trivy, Bandit, and pip-audit in parallel with a gating aggregator job; the existing `tox.yml` gains four caching layers and inline timing; a new `ci-benchmark.yml` fires after `tox.yml` to collect and report performance metrics. All jobs carry a fork guard (`github.repository == 'fardani235/molecule'`).

**Tech Stack:** GitHub Actions, Trivy, Bandit, pip-audit, actions/cache@v4, actions/upload-artifact@v4, github/codeql-action/upload-sarif@v3

## Global Constraints

- Fork guard on every job: `if: github.repository == 'fardani235/molecule'`
- Security gate severity: MEDIUM, HIGH, CRITICAL — any finding fails the PR
- SARIF uploads require `security-events: write` permission
- Cache action version: `actions/cache@v4` with `save-always: true`
- Artifact action version: `actions/upload-artifact@v4`
- Artifact retention: 90 days
- Runner: `ubuntu-24.04`
- Python: `3.10` (minimum for this project)

---

### Task 1: Create the Trivy Scan Job in `security.yml`

**Files:**
- Create: `.github/workflows/security.yml`

**Interfaces:**
- Produces: The `trivy-scan` job that later tasks (`bandit-sast`, `pip-audit`, `security-gate`) sit alongside in the same workflow file.

This task creates the workflow file with triggers, permissions, and the first scan job. Subsequent tasks append jobs to this file.

- [ ] **Step 1: Create the workflow file with triggers and the trivy-scan job**

Create `.github/workflows/security.yml` with the following content:

```yaml
---
name: security

on:
  pull_request:
    branches:
      - "main"
  push:
    branches:
      - "main"
  schedule:
    - cron: "0 6 * * 1" # Weekly Monday 06:00 UTC

concurrency:
  group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.sha }}
  cancel-in-progress: true

jobs:
  trivy-scan:
    name: Trivy Security Scan
    if: github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      security-events: write

    steps:
      - name: Record start time
        id: timer
        run: echo "start=$(date +%s)" >> "$GITHUB_OUTPUT"

      - name: Check out repository
        uses: actions/checkout@v4

      - name: Run Trivy filesystem scan (SARIF)
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: "fs"
          scan-ref: "."
          format: "sarif"
          output: "trivy-results.sarif"
          severity: "MEDIUM,HIGH,CRITICAL"
          exit-code: "1"

      - name: Upload Trivy SARIF to GitHub Security tab
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: "trivy-results.sarif"
          category: "trivy"

      - name: Run Trivy filesystem scan (JSON)
        if: always()
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: "fs"
          scan-ref: "."
          format: "json"
          output: "trivy-results.json"
          severity: "MEDIUM,HIGH,CRITICAL"

      - name: Upload Trivy JSON artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: trivy-results
          path: trivy-results.json
          retention-days: 90

      - name: Write timing summary
        if: always()
        run: |
          end=$(date +%s)
          duration=$(( end - ${{ steps.timer.outputs.start }} ))
          {
            echo "## 🔍 Trivy Scan"
            echo "| Metric | Value |"
            echo "|--------|-------|"
            echo "| Duration | ${duration}s |"
            echo "| Severity Filter | MEDIUM, HIGH, CRITICAL |"
          } >> "$GITHUB_STEP_SUMMARY"
```

- [ ] **Step 2: Validate the YAML syntax**

Run:
```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/security.yml'))" && echo "YAML OK"
```

Expected: `YAML OK` — no parse errors.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/security.yml
git commit -m "ci: add Trivy security scan job in security.yml"
```

---

### Task 2: Add Bandit SAST Job to `security.yml`

**Files:**
- Modify: `.github/workflows/security.yml`

**Interfaces:**
- Consumes: The workflow file created in Task 1.
- Produces: The `bandit-sast` job alongside `trivy-scan`.

- [ ] **Step 1: Append the bandit-sast job to security.yml**

Add the following job after the `trivy-scan` job in `.github/workflows/security.yml`:

```yaml
  bandit-sast:
    name: Bandit SAST
    if: github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      security-events: write

    steps:
      - name: Record start time
        id: timer
        run: echo "start=$(date +%s)" >> "$GITHUB_OUTPUT"

      - name: Check out repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.10"

      - name: Install Bandit
        run: pip install bandit[sarif]

      - name: Run Bandit scan
        run: |
          bandit -r src/ \
            --severity-level medium \
            --confidence-level medium \
            -f sarif \
            -o bandit-results.sarif || true

      - name: Upload Bandit SARIF to GitHub Security tab
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: "bandit-results.sarif"
          category: "bandit"

      - name: Run Bandit scan (JSON)
        run: |
          bandit -r src/ \
            --severity-level medium \
            --confidence-level medium \
            -f json \
            -o bandit-results.json || true

      - name: Check Bandit findings and fail if any
        run: |
          count=$(python3 -c "
          import json, sys
          data = json.load(open('bandit-results.json'))
          results = data.get('results', [])
          print(len(results))
          ")
          echo "Bandit findings: $count"
          if [ "$count" -gt 0 ]; then
            echo "::error::Bandit found $count issue(s) at MEDIUM+ severity/confidence"
            exit 1
          fi

      - name: Upload Bandit JSON artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: bandit-results
          path: bandit-results.json
          retention-days: 90

      - name: Write timing summary
        if: always()
        run: |
          end=$(date +%s)
          duration=$(( end - ${{ steps.timer.outputs.start }} ))
          {
            echo "## 🐍 Bandit SAST"
            echo "| Metric | Value |"
            echo "|--------|-------|"
            echo "| Duration | ${duration}s |"
            echo "| Target | src/ |"
            echo "| Severity | MEDIUM+ |"
          } >> "$GITHUB_STEP_SUMMARY"
```

- [ ] **Step 2: Validate the YAML syntax**

Run:
```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/security.yml'))" && echo "YAML OK"
```

Expected: `YAML OK`.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/security.yml
git commit -m "ci: add Bandit SAST job to security.yml"
```

---

### Task 3: Add pip-audit Job and Security Gate to `security.yml`

**Files:**
- Modify: `.github/workflows/security.yml`

**Interfaces:**
- Consumes: The workflow file with `trivy-scan` and `bandit-sast` from Tasks 1–2.
- Produces: The `pip-audit` job and `security-gate` aggregator. `security-gate` is the name used for branch protection required status checks.

- [ ] **Step 1: Append the pip-audit job**

Add the following job after `bandit-sast` in `.github/workflows/security.yml`:

```yaml
  pip-audit:
    name: pip-audit Dependency Scan
    if: github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04
    permissions:
      contents: read

    steps:
      - name: Record start time
        id: timer
        run: echo "start=$(date +%s)" >> "$GITHUB_OUTPUT"

      - name: Check out repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.10"

      - name: Install pip-audit
        run: pip install pip-audit

      - name: Install project dependencies
        run: pip install .

      - name: Run pip-audit
        run: |
          pip-audit \
            --format json \
            --output pip-audit-results.json \
            --desc

      - name: Upload pip-audit JSON artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: pip-audit-results
          path: pip-audit-results.json
          retention-days: 90

      - name: Write timing summary
        if: always()
        run: |
          end=$(date +%s)
          duration=$(( end - ${{ steps.timer.outputs.start }} ))
          vulns=$(python3 -c "
          import json
          data = json.load(open('pip-audit-results.json'))
          print(sum(1 for d in data if d.get('vulns')))
          " 2>/dev/null || echo "N/A")
          {
            echo "## 📦 pip-audit"
            echo "| Metric | Value |"
            echo "|--------|-------|"
            echo "| Duration | ${duration}s |"
            echo "| Vulnerable packages | ${vulns} |"
          } >> "$GITHUB_STEP_SUMMARY"
```

- [ ] **Step 2: Append the security-gate aggregator job**

Add the following job after `pip-audit` in `.github/workflows/security.yml`:

```yaml
  security-gate:
    name: Security Gate
    if: always() && github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04
    needs: [trivy-scan, bandit-sast, pip-audit]
    permissions: {}

    steps:
      - name: Evaluate scan results
        run: |
          echo "## 🚦 Security Gate Summary" >> "$GITHUB_STEP_SUMMARY"
          echo "" >> "$GITHUB_STEP_SUMMARY"
          echo "| Scanner | Result |" >> "$GITHUB_STEP_SUMMARY"
          echo "|---------|--------|" >> "$GITHUB_STEP_SUMMARY"

          failed=0

          for job_result in \
            "Trivy:${{ needs.trivy-scan.result }}" \
            "Bandit:${{ needs.bandit-sast.result }}" \
            "pip-audit:${{ needs.pip-audit.result }}"; do
            name="${job_result%%:*}"
            result="${job_result##*:}"
            if [ "$result" = "success" ]; then
              echo "| $name | ✅ Passed |" >> "$GITHUB_STEP_SUMMARY"
            else
              echo "| $name | ❌ Failed ($result) |" >> "$GITHUB_STEP_SUMMARY"
              failed=1
            fi
          done

          if [ "$failed" -eq 1 ]; then
            echo "" >> "$GITHUB_STEP_SUMMARY"
            echo "**❌ Security gate FAILED — PR cannot be merged.**" >> "$GITHUB_STEP_SUMMARY"
            echo "::error::One or more security scans failed. Fix findings before merging."
            exit 1
          fi

          echo "" >> "$GITHUB_STEP_SUMMARY"
          echo "**✅ All security scans passed.**" >> "$GITHUB_STEP_SUMMARY"
```

- [ ] **Step 3: Validate the YAML syntax**

Run:
```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/security.yml'))" && echo "YAML OK"
```

Expected: `YAML OK`.

- [ ] **Step 4: Verify the complete workflow structure**

Run:
```bash
python3 -c "
import yaml
with open('.github/workflows/security.yml') as f:
    wf = yaml.safe_load(f)
jobs = list(wf['jobs'].keys())
print('Jobs:', jobs)
assert 'trivy-scan' in jobs, 'Missing trivy-scan'
assert 'bandit-sast' in jobs, 'Missing bandit-sast'
assert 'pip-audit' in jobs, 'Missing pip-audit'
assert 'security-gate' in jobs, 'Missing security-gate'
gate = wf['jobs']['security-gate']
assert set(gate['needs']) == {'trivy-scan', 'bandit-sast', 'pip-audit'}, 'Gate needs wrong'
print('All jobs present, gate dependencies correct')
"
```

Expected: `All jobs present, gate dependencies correct`.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/security.yml
git commit -m "ci: add pip-audit job and security gate to security.yml"
```

---

### Task 4: Add Caching Layers to `tox.yml`

**Files:**
- Modify: `.github/workflows/tox.yml`

**Interfaces:**
- Consumes: The existing `tox.yml` that delegates to `ansible/team-devtools` reusable workflow.
- Produces: Updated `tox.yml` with four caching layers and inline timing annotations.

The existing `tox.yml` delegates to a reusable workflow via `uses: ansible/team-devtools/.github/workflows/tox.yml@main`. Because we cannot inject cache steps into a reusable workflow we don't control, we restructure: add a `cache-deps` job that warms caches before the tox reusable workflow runs, and a `timing-report` job that runs after to summarize performance.

- [ ] **Step 1: Read the current tox.yml to confirm state**

Run:
```bash
cat .github/workflows/tox.yml
```

Confirm it matches the structure: a single `tox` job that uses the team-devtools reusable workflow.

- [ ] **Step 2: Replace tox.yml with caching and timing additions**

Replace the contents of `.github/workflows/tox.yml` with:

```yaml
---
name: tox

on:
  merge_group:
    branches:
      - "main"
  push:
    branches:
      - "main"
  pull_request:
    branches:
      - "main"
      - "releases/**"
      - "stable/**"
  schedule:
    - cron: "0 0 * * *"
  workflow_call:

concurrency:
  group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.sha }}
  cancel-in-progress: true

jobs:
  cache-deps:
    name: Warm dependency caches
    if: github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04
    strategy:
      matrix:
        python-version: ["3.10", "3.11", "3.12", "3.13"]

    steps:
      - name: Record start time
        id: timer
        run: echo "start=$(date +%s)" >> "$GITHUB_OUTPUT"

      - name: Check out repository
        uses: actions/checkout@v4

      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}

      - name: Cache UV/pip downloads
        id: cache-uv
        uses: actions/cache@v4
        with:
          path: ~/.cache/uv
          key: uv-${{ runner.os }}-py${{ matrix.python-version }}-${{ hashFiles('uv.lock') }}
          restore-keys: |
            uv-${{ runner.os }}-py${{ matrix.python-version }}-
          save-always: true

      - name: Cache tox environments
        id: cache-tox
        uses: actions/cache@v4
        with:
          path: .tox
          key: tox-${{ runner.os }}-py${{ matrix.python-version }}-${{ hashFiles('pyproject.toml', 'uv.lock') }}
          restore-keys: |
            tox-${{ runner.os }}-py${{ matrix.python-version }}-
          save-always: true

      - name: Cache pre-commit hooks
        id: cache-precommit
        uses: actions/cache@v4
        with:
          path: ~/.cache/pre-commit
          key: pre-commit-${{ runner.os }}-${{ hashFiles('.pre-commit-config.yaml') }}
          restore-keys: |
            pre-commit-${{ runner.os }}-
          save-always: true

      - name: Cache mypy
        id: cache-mypy
        uses: actions/cache@v4
        with:
          path: .cache/.mypy
          key: mypy-${{ runner.os }}-py${{ matrix.python-version }}-${{ hashFiles('src/**/*.py') }}
          restore-keys: |
            mypy-${{ runner.os }}-py${{ matrix.python-version }}-
          save-always: true

      - name: Write cache summary
        if: always()
        run: |
          end=$(date +%s)
          duration=$(( end - ${{ steps.timer.outputs.start }} ))
          {
            echo "## 📦 Cache Warm (Python ${{ matrix.python-version }})"
            echo "| Cache Layer | Hit? |"
            echo "|-------------|------|"
            echo "| UV/pip | ${{ steps.cache-uv.outputs.cache-hit == 'true' && '✅ Hit' || '❌ Miss' }} |"
            echo "| Tox envs | ${{ steps.cache-tox.outputs.cache-hit == 'true' && '✅ Hit' || '❌ Miss' }} |"
            echo "| Pre-commit | ${{ steps.cache-precommit.outputs.cache-hit == 'true' && '✅ Hit' || '❌ Miss' }} |"
            echo "| Mypy | ${{ steps.cache-mypy.outputs.cache-hit == 'true' && '✅ Hit' || '❌ Miss' }} |"
            echo "| **Warm duration** | **${duration}s** |"
          } >> "$GITHUB_STEP_SUMMARY"

  tox:
    needs: cache-deps
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

  timing-report:
    name: CI Timing Report
    if: always() && github.repository == 'fardani235/molecule'
    needs: [cache-deps, tox]
    runs-on: ubuntu-24.04
    permissions: {}

    steps:
      - name: Generate timing summary
        run: |
          {
            echo "## ⏱️ tox Workflow Timing Report"
            echo ""
            echo "| Job | Result |"
            echo "|-----|--------|"
            echo "| Cache warm | ${{ needs.cache-deps.result }} |"
            echo "| Tox tests | ${{ needs.tox.result }} |"
            echo ""
            echo "*(Per-step durations visible in each job's logs and summary)*"
          } >> "$GITHUB_STEP_SUMMARY"
```

- [ ] **Step 3: Validate the YAML syntax**

Run:
```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/tox.yml'))" && echo "YAML OK"
```

Expected: `YAML OK`.

- [ ] **Step 4: Verify the job dependency chain**

Run:
```bash
python3 -c "
import yaml
with open('.github/workflows/tox.yml') as f:
    wf = yaml.safe_load(f)
jobs = list(wf['jobs'].keys())
print('Jobs:', jobs)
assert 'cache-deps' in jobs, 'Missing cache-deps'
assert 'tox' in jobs, 'Missing tox'
assert 'timing-report' in jobs, 'Missing timing-report'
assert wf['jobs']['tox']['needs'] == 'cache-deps', 'tox should depend on cache-deps'
print('Job chain valid: cache-deps → tox → timing-report')
"
```

Expected: `Job chain valid: cache-deps → tox → timing-report`.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/tox.yml
git commit -m "ci: add 4-layer caching and timing to tox.yml"
```

---

### Task 5: Create CI Benchmark Workflow (`ci-benchmark.yml`)

**Files:**
- Create: `.github/workflows/ci-benchmark.yml`

**Interfaces:**
- Consumes: Triggers after `tox` workflow completes via `workflow_run`.
- Produces: A downloadable Markdown benchmark report artifact and job summary.

- [ ] **Step 1: Create the benchmark workflow file**

Create `.github/workflows/ci-benchmark.yml` with:

```yaml
---
name: ci-benchmark

on:
  workflow_run:
    workflows:
      - tox
    types:
      - completed

permissions:
  actions: read

jobs:
  benchmark:
    name: CI Performance Report
    if: github.repository == 'fardani235/molecule'
    runs-on: ubuntu-24.04

    steps:
      - name: Collect workflow run metrics
        uses: actions/github-script@v7
        id: metrics
        with:
          script: |
            const run = context.payload.workflow_run;
            const runId = run.id;

            // Fetch jobs for the completed workflow run
            const { data: jobsData } = await github.rest.actions.listJobsForWorkflowRun({
              owner: context.repo.owner,
              repo: context.repo.repo,
              run_id: runId,
            });

            const jobs = jobsData.jobs;
            const report = [];

            report.push('# ⏱️ CI Performance Benchmark Report');
            report.push('');
            report.push(`**Workflow:** ${run.name}`);
            report.push(`**Run ID:** ${runId}`);
            report.push(`**Branch:** ${run.head_branch}`);
            report.push(`**Commit:** \`${run.head_sha.substring(0, 8)}\``);
            report.push(`**Trigger:** ${run.event}`);
            report.push(`**Conclusion:** ${run.conclusion}`);
            report.push('');

            // Workflow-level timing
            const wfStart = new Date(run.run_started_at);
            const wfEnd = new Date(run.updated_at);
            const wfDuration = Math.round((wfEnd - wfStart) / 1000);
            report.push(`**Total wall-clock time:** ${wfDuration}s (${Math.round(wfDuration / 60)}m ${wfDuration % 60}s)`);
            report.push('');

            // Per-job timing table
            report.push('## Per-Job Breakdown');
            report.push('');
            report.push('| Job | Status | Duration | Started | Completed |');
            report.push('|-----|--------|----------|---------|-----------|');

            for (const job of jobs) {
              if (!job.started_at || !job.completed_at) continue;
              const start = new Date(job.started_at);
              const end = new Date(job.completed_at);
              const duration = Math.round((end - start) / 1000);
              const status = job.conclusion === 'success' ? '✅' : job.conclusion === 'skipped' ? '⏭️' : '❌';
              report.push(`| ${job.name} | ${status} ${job.conclusion} | ${duration}s | ${start.toISOString()} | ${end.toISOString()} |`);
            }

            report.push('');

            // Cache analysis — look for cache-deps jobs
            const cacheJobs = jobs.filter(j => j.name.includes('Cache') || j.name.includes('cache'));
            if (cacheJobs.length > 0) {
              report.push('## Cache Performance');
              report.push('');
              report.push('Cache hit/miss details are available in each Cache Warm job summary.');
              report.push('Check the individual job logs for per-layer cache status.');
              report.push('');
            }

            // Performance notes
            report.push('## Notes');
            report.push('');
            report.push('- First run after dependency changes will show cache misses (expected).');
            report.push('- Subsequent runs on the same branch should show cache hits and faster times.');
            report.push('- Compare total wall-clock time across runs to measure caching impact.');
            report.push('');

            const reportText = report.join('\n');
            core.setOutput('report', reportText);
            return reportText;

      - name: Write benchmark to job summary
        run: |
          cat << 'REPORT_EOF' >> "$GITHUB_STEP_SUMMARY"
          ${{ steps.metrics.outputs.report }}
          REPORT_EOF

      - name: Save benchmark artifact
        run: |
          mkdir -p benchmark
          cat << 'REPORT_EOF' > benchmark/ci-benchmark-report.md
          ${{ steps.metrics.outputs.report }}
          REPORT_EOF

      - name: Upload benchmark report
        uses: actions/upload-artifact@v4
        with:
          name: ci-benchmark-report
          path: benchmark/ci-benchmark-report.md
          retention-days: 90
```

- [ ] **Step 2: Validate the YAML syntax**

Run:
```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci-benchmark.yml'))" && echo "YAML OK"
```

Expected: `YAML OK`.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci-benchmark.yml
git commit -m "ci: add CI benchmark workflow for performance tracking"
```

---

### Task 6: Validate All Workflows and Final Commit

**Files:**
- Verify: `.github/workflows/security.yml`
- Verify: `.github/workflows/tox.yml`
- Verify: `.github/workflows/ci-benchmark.yml`

**Interfaces:**
- Consumes: All files from Tasks 1–5.
- Produces: Validated, complete workflow suite ready for PR.

- [ ] **Step 1: Validate all YAML files parse correctly**

Run:
```bash
python3 -c "
import yaml, pathlib
for f in sorted(pathlib.Path('.github/workflows').glob('*.yml')):
    try:
        yaml.safe_load(f.read_text())
        print(f'✅ {f.name}')
    except Exception as e:
        print(f'❌ {f.name}: {e}')
"
```

Expected: All files show ✅.

- [ ] **Step 2: Verify fork guard on all new/modified jobs**

Run:
```bash
python3 -c "
import yaml

for fname in ['security.yml', 'tox.yml', 'ci-benchmark.yml']:
    with open(f'.github/workflows/{fname}') as f:
        wf = yaml.safe_load(f)
    for job_name, job_def in wf['jobs'].items():
        # Reusable workflows (uses:) don't support if conditions
        if 'uses' in job_def and 'steps' not in job_def:
            print(f'⏭️  {fname}/{job_name} — reusable workflow (skip)')
            continue
        cond = job_def.get('if', '')
        if 'fardani235/molecule' in str(cond):
            print(f'✅ {fname}/{job_name} — fork guard present')
        else:
            print(f'❌ {fname}/{job_name} — MISSING fork guard')
"
```

Expected: All jobs show ✅ or ⏭️ (for reusable workflow calls that cannot carry `if`).

- [ ] **Step 3: Verify security.yml structure is complete**

Run:
```bash
python3 -c "
import yaml
with open('.github/workflows/security.yml') as f:
    wf = yaml.safe_load(f)
jobs = wf['jobs']

# Check all 4 jobs exist
expected = ['trivy-scan', 'bandit-sast', 'pip-audit', 'security-gate']
for j in expected:
    assert j in jobs, f'Missing job: {j}'
    print(f'✅ {j} present')

# Check gate depends on all scan jobs
gate_needs = set(jobs['security-gate']['needs'])
assert gate_needs == {'trivy-scan', 'bandit-sast', 'pip-audit'}
print('✅ security-gate depends on all scan jobs')

# Check SARIF upload steps exist in trivy and bandit
for j in ['trivy-scan', 'bandit-sast']:
    step_names = [s.get('name', '') for s in jobs[j]['steps']]
    sarif_steps = [n for n in step_names if 'SARIF' in n and 'Security' in n]
    assert sarif_steps, f'{j} missing SARIF upload step'
    print(f'✅ {j} has SARIF upload')

# Check artifact upload in all scan jobs
for j in ['trivy-scan', 'bandit-sast', 'pip-audit']:
    step_names = [s.get('name', '') for s in jobs[j]['steps']]
    artifact_steps = [n for n in step_names if 'artifact' in n.lower() or 'Upload' in n]
    assert artifact_steps, f'{j} missing artifact upload step'
    print(f'✅ {j} has artifact upload')

print('All checks passed!')
"
```

Expected: All checks passed.

- [ ] **Step 4: Verify tox.yml cache structure**

Run:
```bash
python3 -c "
import yaml
with open('.github/workflows/tox.yml') as f:
    wf = yaml.safe_load(f)
jobs = wf['jobs']

# Check cache-deps job exists with cache steps
assert 'cache-deps' in jobs, 'Missing cache-deps job'
cache_steps = [s for s in jobs['cache-deps']['steps'] if s.get('uses', '').startswith('actions/cache')]
cache_ids = [s['id'] for s in cache_steps]
expected_caches = ['cache-uv', 'cache-tox', 'cache-precommit', 'cache-mypy']
for c in expected_caches:
    assert c in cache_ids, f'Missing cache: {c}'
    print(f'✅ Cache layer: {c}')

# Check tox job depends on cache-deps
assert jobs['tox']['needs'] == 'cache-deps', 'tox should need cache-deps'
print('✅ tox depends on cache-deps')
print('All cache checks passed!')
"
```

Expected: All cache checks passed.

- [ ] **Step 5: List all workflow files to confirm nothing was accidentally deleted**

Run:
```bash
ls -la .github/workflows/
```

Expected: All 8 files present — `ack.yml`, `ci-benchmark.yml`, `finalize.yml`, `push.yml`, `redirects.yml`, `release.yml`, `security.yml`, `tox.yml`.

- [ ] **Step 6: Review full git log for this branch**

Run:
```bash
git log --oneline violet-panther-rework --not main
```

Expected: 4 commits (one per task):
1. `ci: add Trivy security scan job in security.yml`
2. `ci: add Bandit SAST job to security.yml`
3. `ci: add pip-audit job and security gate to security.yml`
4. `ci: add 4-layer caching and timing to tox.yml`
5. `ci: add CI benchmark workflow for performance tracking`
