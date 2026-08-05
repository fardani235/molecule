# DevSecOps CI Pipeline Improvements — Design Spec

**Date:** 2026-08-06
**Status:** Approved
**Repository:** fardani235/molecule (fork of ansible-community/molecule)

## 1. Overview

Improve the CI pipelines for the forked Molecule repository to meet DevSecOps best
practices. The changes introduce security scanning, caching strategies, PR gating on
security findings, downloadable artifacts, and CI speed measurement.

**Out of scope:** Publishing packages to Ansible Galaxy or PyPI.

## 2. Goals

1. Add security scanning (SAST, dependency audit, secret detection) to CI pipelines.
2. Gate PR submissions — fail if any MEDIUM, HIGH, or CRITICAL findings are detected.
3. Add multi-layer caching to speed up CI pipelines.
4. Ensure all CI runs happen on the fork (`fardani235/molecule`), not upstream.
5. Make all security scanning and package-related artifacts downloadable and monitorable.
6. Measure and report how caching improvements speed up CI pipelines.

## 3. Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Security tools | Trivy + Bandit + pip-audit | Open-source, free, well-maintained, GitHub-native |
| Gate behavior | Hard fail + SARIF upload | PR check fails AND findings appear inline in GitHub Security tab |
| Cache scope | All layers | UV cache, tox envs, pre-commit hooks, mypy cache |
| CI structure | Integrated (Approach A) | New `security.yml` + caching in `tox.yml` + `ci-benchmark.yml` |
| Fork guard | Repository owner condition | `if: github.repository == 'fardani235/molecule'` on each job |
| Speed measurement | Workflow timing annotations | Step-level durations + cache hit/miss + summary artifact |

## 4. Architecture

### 4.1 New Workflow: `security.yml`

**Triggers:**
- `pull_request` targeting `main`
- `push` to `main`
- `schedule` — weekly (`cron: '0 6 * * 1'`) for drift detection

**Fork guard:** `if: github.repository == 'fardani235/molecule'` on every job.

**Jobs (run in parallel):**

#### Job 1: `trivy-scan`
- **Tool:** Trivy (aquasecurity/trivy-action)
- **Mode:** Filesystem scan against the full repo
- **Scan types:** Vulnerabilities (OS + language packages), secrets, misconfigurations, licenses
- **Severity filter:** MEDIUM, HIGH, CRITICAL
- **Outputs:**
  - SARIF file → uploaded to GitHub Security tab via `github/codeql-action/upload-sarif@v3`
  - JSON report → uploaded as artifact via `actions/upload-artifact@v4`
- **Gate:** Job fails if any finding at MEDIUM or above exists
- **Exit code:** `exit-code: '1'` in Trivy action to fail on findings

#### Job 2: `bandit-sast`
- **Tool:** Bandit (Python SAST scanner)
- **Target:** `src/` directory (recursive)
- **Severity filter:** Medium+ severity, Medium+ confidence
- **Outputs:**
  - SARIF file → uploaded to GitHub Security tab
  - JSON report → uploaded as artifact
- **Gate:** Non-zero exit code on findings fails the job
- **Configuration:** Use `--severity-level medium --confidence-level medium`

#### Job 3: `pip-audit`
- **Tool:** pip-audit (pypa/gh-action-pip-audit)
- **Source:** Project dependencies from `pyproject.toml` via the locked `uv.lock`
- **Database:** PyPI Advisory DB + OSV
- **Outputs:**
  - JSON report → uploaded as artifact
- **Gate:** Non-zero exit code on any known vulnerability
- **Note:** pip-audit does not produce SARIF; JSON artifact is the primary output

#### Job 4: `security-gate`
- **Purpose:** Single aggregation point for branch protection
- **Dependencies:** `needs: [trivy-scan, bandit-sast, pip-audit]`
- **Logic:** Passes only if all three scan jobs pass
- **Branch protection:** This job name is the required status check on `main`

### 4.2 Caching Strategy (Modifications to `tox.yml`)

Four caching layers added to the existing test workflow:

| Layer | Cache Path | Key | Restore Keys | Expected Savings |
|-------|-----------|-----|-------------|-----------------|
| UV/pip downloads | `~/.cache/uv` | `uv-{runner.os}-{python-version}-{hash(uv.lock)}` | `uv-{runner.os}-{python-version}-` | ~30–60s/job |
| Tox environments | `.tox/` | `tox-{runner.os}-{python-version}-{hash(pyproject.toml, uv.lock)}` | `tox-{runner.os}-{python-version}-` | ~60–120s/job |
| Pre-commit hooks | `~/.cache/pre-commit` | `pre-commit-{runner.os}-{hash(.pre-commit-config.yaml)}` | `pre-commit-{runner.os}-` | ~30–45s on lint |
| Mypy cache | `.cache/.mypy` | `mypy-{runner.os}-{python-version}-{hash(src/**/*.py)}` | `mypy-{runner.os}-{python-version}-` | ~15–30s |

**Cache invalidation:** File-hash-based keys ensure automatic invalidation on dependency or
source changes. Prefix-based restore keys allow partial cache hits.

**Implementation:** `actions/cache@v4` with `save-always: true` to persist caches even on
job failure (warms caches on first run or after cache miss).

### 4.3 CI Speed Benchmarking (`ci-benchmark.yml`)

A **standalone workflow** triggered on `workflow_run` (after `tox.yml` completes) that
collects and reports CI performance metrics.

**Mechanism:**
1. Fetches the completed workflow run's timing data via the GitHub API.
2. Collects:
   - Per-job wall-clock durations
   - Cache hit/miss status (read from the run logs or inline step outputs)
   - Total workflow duration
3. Generates a **Markdown summary** written to `$GITHUB_STEP_SUMMARY`.
4. Uploads the summary as a **downloadable artifact** (`ci-benchmark-report`).

**Inline timing in `tox.yml` and `security.yml`:**
- Each workflow also embeds lightweight timing steps that record start/end timestamps
  and write per-job duration summaries directly to `$GITHUB_STEP_SUMMARY`.
- Cache hit/miss is captured from the `actions/cache` output (`cache-hit`) and reported
  inline in each job's summary.

### 4.4 Fork Guard

All new and modified workflows include the repository check at the **job level**:

```yaml
jobs:
  example-job:
    if: github.repository == 'fardani235/molecule'
```

This is applied at the job level rather than the workflow level so the workflow file can be
synced from upstream without triggering runs. Each job independently checks the condition.

### 4.5 Artifact Strategy

| Source | Format | Destination | Retention |
|--------|--------|-------------|-----------|
| Trivy scan | SARIF | GitHub Security tab | Managed by GitHub |
| Trivy scan | JSON | Actions artifact (`trivy-results`) | 90 days |
| Bandit scan | SARIF | GitHub Security tab | Managed by GitHub |
| Bandit scan | JSON | Actions artifact (`bandit-results`) | 90 days |
| pip-audit | JSON | Actions artifact (`pip-audit-results`) | 90 days |
| CI benchmark | Markdown | Job Summary + artifact (`ci-benchmark-report`) | 90 days |

All artifacts are downloadable from the GitHub Actions run page.
SARIF results are viewable in the repository's Security → Code scanning alerts tab.

## 5. Files Changed

| File | Action | Purpose |
|------|--------|---------|
| `.github/workflows/security.yml` | **Create** | Security scanning workflow |
| `.github/workflows/tox.yml` | **Modify** | Add caching layers + timing annotations |
| `.github/workflows/ci-benchmark.yml` | **Create** | CI speed measurement reusable workflow |

## 6. PR Gating

For the fork's branch protection rules on `main`, the following status checks should be
marked as **required**:

- `security-gate` (from `security.yml`) — blocks merge if any MEDIUM+ security finding
- Existing test checks (from `tox.yml`) — unchanged

## 7. Success Criteria

1. Security scans run on every PR and push to main in the fork.
2. PRs with MEDIUM/HIGH/CRITICAL findings cannot be merged.
3. Security findings appear as inline annotations on PR diffs (via SARIF).
4. All scan reports are downloadable as artifacts from the Actions tab.
5. CI pipelines are measurably faster due to caching (target: 30–50% reduction in setup time).
6. CI workflows do not trigger when the repo is the upstream `ansible-community/molecule`.
7. Weekly scheduled scans catch dependency drift between PRs.

## 8. Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| SARIF upload requires GitHub Advanced Security | Free for public repos; if private, fall back to artifact-only |
| Cache size exceeds GitHub's 10 GB limit | Use granular keys; caches auto-evict LRU |
| Trivy false positives block PRs | Maintain `.trivyignore` for acknowledged findings |
| Bandit false positives block PRs | Use `# nosec` inline or `.bandit` config for acknowledged findings |
| pip-audit flags transitive dependencies | Document known-safe transitives; use `--ignore-vuln` for acknowledged |
| Fork guard bypassed if repo is renamed | Guard uses exact string match; update if repo is renamed |
