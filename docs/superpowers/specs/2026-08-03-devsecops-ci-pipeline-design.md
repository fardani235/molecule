# DevSecOps CI Pipeline Improvements — Design Spec

**Date:** 2026-08-03
**Status:** Approved
**Repository:** fardani235/molecule (fork of ansible-community/molecule)

## Problem

The forked Molecule repository has no security scanning in its CI pipeline and
no caching strategies. PRs can merge with known vulnerabilities, hardcoded
secrets, or insecure code patterns. CI runs are slower than necessary due to
repeated dependency downloads.

## Goals

1. Add security scanning (SAST, dependency scanning, secrets detection) to CI.
2. Gate PR merges — fail if medium/high/critical findings exist.
3. Add caching strategies to speed up CI pipelines.
4. Make all security artifacts downloadable and monitorable.
5. Measure the caching improvement with a dedicated benchmark.
6. Run only on the fork, never on upstream.

## Non-Goals

- Publishing packages to Ansible Galaxy or PyPI.
- Modifying upstream shared workflows at `ansible/team-devtools`.
- Container image scanning (no Dockerfile in this repo).
- Runtime/DAST scanning.

## Architecture

Three new standalone GitHub Actions workflows plus a reusable composite action,
independent of the upstream `ansible/team-devtools` shared workflows.

### Workflow Overview

| Workflow File               | Trigger                     | Purpose                          |
|-----------------------------|-----------------------------|----------------------------------|
| `security.yml`              | PR + push to main           | Security scanning gate           |
| `release-artifacts.yml`     | push to main + release      | SBOM generation & artifact upload|
| `cache-benchmark.yml`       | `workflow_dispatch`          | Measure caching speedup          |

### Fork-Only Enforcement

Every new workflow job includes:

```yaml
if: github.repository != 'ansible-community/molecule'
```

This ensures nothing runs if the code is synced back to upstream.

## Security Scanning (`security.yml`)

### Trigger

```yaml
on:
  pull_request:
    branches: [main, "releases/**", "stable/**"]
  push:
    branches: [main]
```

### Jobs

Three parallel scanning jobs, plus a gate job:

#### Job 1: `sast` — Static Application Security Testing

**Tools:** Bandit + Semgrep

- **Bandit** scans `src/` for Python-specific security issues (SQL injection,
  hardcoded passwords, insecure function calls, etc.).
  - Configured via `.bandit.yml` at repo root.
  - Severity threshold: medium and above.
  - Output formats: JSON (for gate parsing) + SARIF (for GitHub Security tab).
  - Uploaded as artifact: `bandit-results`.

- **Semgrep** runs community rulesets (`p/python`, `p/security-audit`) against
  `src/`.
  - Output format: JSON + SARIF.
  - Uploaded as artifact: `semgrep-results`.

#### Job 2: `dependency-scan` — Supply Chain Scanning

**Tools:** pip-audit + Trivy

- **pip-audit** checks resolved dependencies against the OSV/PyPI advisory
  database.
  - Uses `uv` to export `requirements.txt` from `uv.lock` for scanning.
  - Output format: JSON.
  - Uploaded as artifact: `pip-audit-results`.

- **Trivy** scans the filesystem for known CVEs.
  - Scan type: `fs` (filesystem).
  - Generates SBOM in CycloneDX format.
  - Output formats: JSON table + SARIF.
  - Uploaded as artifact: `trivy-results`.

#### Job 3: `secrets` — Secrets Detection

**Tool:** Gitleaks

- Scans the entire repository for hardcoded secrets, API keys, tokens, and
  private keys.
- Output format: SARIF (for GitHub Security tab) + JSON (for gate parsing).
- Uploaded as artifact: `gitleaks-results`.

#### Job 4: `security-gate` — Merge Gate

- **Depends on:** all three scanning jobs (`needs: [sast, dependency-scan, secrets]`).
- Downloads all scan result artifacts.
- Parses JSON outputs for findings at severity medium, high, or critical.
- Produces a consolidated summary in the GitHub Actions job summary (markdown
  table with tool, severity, finding description, file/line).
- **Fails the workflow if any qualifying findings exist**, blocking PR merge.
- When no findings exist, posts a green summary confirming all checks passed.

### PR Merge Protection

After the workflow is in place, the repository branch protection rule for `main`
should require the `security-gate` job to pass before merging.

## Caching Strategy

### What We Cache

| Cache Target         | Path                     | Key Components                           |
|----------------------|--------------------------|------------------------------------------|
| uv package cache     | `~/.cache/uv`           | `runner.os`, `hashFiles('uv.lock')`      |
| tox environments     | `.tox/`                 | `runner.os`, `hashFiles('pyproject.toml')`|
| pre-commit envs      | `~/.cache/pre-commit`   | `runner.os`, `hashFiles('.pre-commit-config.yaml')` |

### Cache Key Strategy

```
primary:   {runner.os}-{tool}-{hashFiles(...)}
fallback:  {runner.os}-{tool}-
```

The fallback key allows partial cache hits when lock files change slightly.

### Implementation: Reusable Composite Action

File: `.github/actions/setup-cache/action.yml`

A composite action that accepts inputs for which caches to enable. This keeps
caching logic DRY across all workflows. Inputs:

- `cache-uv` (boolean, default true) — cache uv downloads.
- `cache-tox` (boolean, default true) — cache tox environments.
- `cache-pre-commit` (boolean, default false) — cache pre-commit environments.

### Integration with Existing `tox.yml`

The existing `tox.yml` delegates to `ansible/team-devtools/.github/workflows/tox.yml`.
We cannot inject caching into that shared workflow directly.

**Approach:** Add a `with: run_pre` block to the existing `tox.yml` call that
sets up caching before tox runs, using the composite action. The `run_pre` input
is already used in the current workflow for the Podman/crun workaround, so we
extend it.

If the shared workflow does not support composite action invocation in `run_pre`,
we add a separate preparatory job that warms the cache before the tox job runs.

## Artifact Publishing (`release-artifacts.yml`)

### Trigger

```yaml
on:
  push:
    branches: [main]
  release:
    types: [published]
```

### Jobs

#### Job 1: `build-and-publish-artifacts`

Steps:
1. Checkout code with full history (`fetch-depth: 0`).
2. Set up Python and uv.
3. Generate SBOM via Trivy (CycloneDX JSON format).
4. Build the package via `tox -e pkg` (sdist + wheel).
5. Upload artifacts:
   - `sbom-cyclonedx.json` — software bill of materials.
   - `dist/` — built packages (sdist + wheel).
6. Artifact retention: 90 days.

The security scan results from `security.yml` are separately downloadable from
that workflow's run artifacts.

## Speed Benchmark (`cache-benchmark.yml`)

### Trigger

```yaml
on:
  workflow_dispatch:
```

Manual trigger only — run when you want a measurement.

### Jobs

#### Job 1: `benchmark-no-cache`

- Runs `tox -e lint` on a clean runner with no caching.
- Records wall-clock time for the full job.

#### Job 2: `benchmark-with-cache`

- Runs `tox -e lint` using the composite caching action.
- Records wall-clock time for the full job.
- Depends on `benchmark-no-cache` to ensure cache is warm from that run.

#### Job 3: `report`

- Depends on both benchmark jobs.
- Computes time difference and percentage speedup.
- Generates a markdown comparison report.
- Posts the report to the GitHub Actions job summary.
- Uploads the report as artifact: `cache-benchmark-report`.

## Configuration Files

### `.bandit.yml`

```yaml
skips: []
targets:
  - src/
severity: medium
confidence: medium
```

### `.gitleaks.toml`

```toml
[extend]
useDefault = true

[allowlist]
description = "Molecule-specific allowlist"
paths = [
  '''uv\.lock''',
  '''\.ansible/''',
]
```

## Files to Create/Modify

| File                                      | Action     | Purpose                            |
|-------------------------------------------|------------|------------------------------------|
| `.github/workflows/security.yml`          | Create     | Security scanning gate             |
| `.github/workflows/release-artifacts.yml` | Create     | SBOM + artifact publishing         |
| `.github/workflows/cache-benchmark.yml`   | Create     | Caching speed measurement          |
| `.github/actions/setup-cache/action.yml`  | Create     | Reusable caching composite action  |
| `.github/workflows/tox.yml`               | Modify     | Add caching via composite action   |
| `.bandit.yml`                             | Create     | Bandit SAST configuration          |
| `.gitleaks.toml`                          | Create     | Gitleaks secrets scan configuration|

## Success Criteria

1. PRs with medium/high/critical security findings cannot be merged.
2. All scan results (SAST, dependency, secrets) are downloadable as artifacts.
3. SBOM is generated on every push to main and every release.
4. CI pipeline runs faster with caching enabled (measurable via benchmark).
5. No workflows trigger on the upstream `ansible-community/molecule` repo.
6. Package build artifacts (sdist + wheel) are downloadable without publishing.
