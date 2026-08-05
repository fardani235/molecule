# DevSecOps CI Pipeline Improvements — Design

- **Date:** 2026-08-06
- **Repository:** `fardani235/molecule` (fork of `ansible-community/molecule`)
- **Author:** ridwan
- **Status:** Approved for implementation planning

## 1. Problem statement

The current CI on this fork delegates almost entirely to reusable workflows in
`ansible/team-devtools`. There is:

- **No security scanning** (SAST, SCA, secrets, IaC, SBOM).
- **No PR-blocking gate** on medium/high/critical findings.
- **No explicit caching** (all caching is whatever the upstream reusable
  workflow happens to do, which we cannot tune here).
- **No downloadable, monitorable artifacts** for security reports or
  release-adjacent build products.
- **No measurement** of pipeline duration or the effect of improvements.

The task is to add all of the above, on the fork only (never running upstream),
without touching the delegated `tox.yml` and without publishing packages to
PyPI or Ansible Galaxy (out of scope).

## 2. Goals & non-goals

### Goals

1. Add SAST + SCA + Secrets + IaC + SBOM scanning on every PR and push to main.
2. Fail the PR when any unwaived finding of severity **medium/high/critical**
   is detected.
3. Cache Python deps, pre-commit hooks, security scanner databases, and
   Ansible collections to speed CI.
4. Produce downloadable artifacts for every scan result (SARIF + JSON + HTML
   where available), the SBOM, the built wheel/sdist, and the built
   collection tarball, all with 90-day retention.
5. Surface findings in **three** places: GitHub Security tab (SARIF), a
   sticky PR comment summary, and the workflow step summary.
6. Provide a benchmark workflow that produces a before/after wall-clock
   comparison suitable for pasting into the PR description.
7. Guarantee nothing runs upstream: every job carries an explicit fork
   repository guard.

### Non-goals

- Publishing packages to PyPI or Ansible Galaxy (explicitly out of scope).
- Modifying `tox.yml` (delegated to `ansible/team-devtools`).
- SBOM signing / cosign attestation (documented as future work).
- Runtime / dynamic security testing (DAST). This is a library, not a
  service.
- Continuous per-run metrics dashboarding — a point-in-time
  before/after table is sufficient (per user answer).

## 3. Architecture

Three new workflow files, plus a small support tree. No existing workflow is
deleted or edited.

```
.github/workflows/
  security.yml              (NEW)  SAST / SCA / Secrets / IaC / SBOM + gate
  build-artifacts.yml       (NEW)  wheel, sdist, collection tarball + SBOMs
  benchmark.yml             (NEW)  workflow_dispatch — before/after timings

  tox.yml                   (unchanged — upstream reusable)
  release.yml               (unchanged — out of scope)
  ack.yml, push.yml,
  finalize.yml, redirects.yml (unchanged)

.github/actions/
  cache-python/action.yml   (NEW)  composite: pip + uv + tox venv cache
  cache-scanners/action.yml (NEW)  composite: Trivy DB, Semgrep, KICS caches

.github/security/
  bandit.yaml               (NEW)  Bandit config + baseline skips
  .gitleaks.toml            (NEW)  Gitleaks rules + allowlist
  pip-audit-ignore.txt      (NEW)  CVE waivers with justification comments
  .trivyignore              (NEW)  Trivy waivers with justification comments
  kics-exclusions.json      (NEW)  KICS query and path exclusions
  semgrep-rules.yml         (NEW)  Enabled Semgrep rulesets
  gate-policy.yml           (NEW)  Severity thresholds per scanner
  README.md                 (NEW)  Waiver conventions and review cadence

.github/scripts/
  gate.py                   (NEW)  ~120 LOC — aggregates SARIF, applies
                                   waivers, emits gate-summary.md and exit
                                   code.
  benchmark_collect.py      (NEW)  Pulls per-job timings from the GitHub
                                   REST API, computes medians, renders
                                   ci-benchmark.md and .json.
```

### Flow on a pull request

1. `security.yml` fires on `pull_request`, `push` to `main`, or
   `workflow_dispatch`.
2. Every job carries `if: github.repository == 'fardani235/molecule'` so the
   workflow no-ops if the file ever lands upstream.
3. A `setup` job restores caches via the two composite actions.
4. Five scan jobs run in parallel: `sast`, `sca`, `secrets`, `iac`, `sbom`.
5. Each scanner uploads SARIF to the Security tab
   (`github/codeql-action/upload-sarif@v3` with a per-scanner `category:`),
   uploads JSON/HTML reports as workflow artifacts (90d retention), and
   writes a severity-count row to `$GITHUB_STEP_SUMMARY`.
6. A `gate` job aggregates all SARIF, applies waivers from the
   `.github/security/` ignore files, and fails when any unwaived finding at
   or above the configured threshold survives. It also posts a sticky PR
   comment with counts and links.
7. `build-artifacts.yml` builds the wheel, sdist, and the
   `community.molecule` collection tarball, generates a CycloneDX SBOM for
   each, and uploads them as the `dist` artifact.
8. `benchmark.yml` is manually dispatched to produce the before/after
   timing table.

## 4. Tool selection

Every tool is pinned to a major version tag (Renovate handles bumps).

| Layer | Tool | Version | Rationale |
|---|---|---|---|
| SAST — Python | Bandit | `bandit[toml]==1.8.*` | Standard for Python; SARIF via `--format sarif`. |
| SAST — cross-cutting | Semgrep | `returntocorp/semgrep-action@v1` with `p/python`, `p/security-audit`, `p/secrets` | Catches taint patterns Bandit misses; native SARIF. |
| SCA — Python | pip-audit | `pypa/gh-action-pip-audit@v1` | Reads pyproject.toml; PyPI + OSV. |
| SCA — filesystem | Trivy | `aquasecurity/trivy-action@0.24.0` (`fs` mode) | Defense-in-depth; catches non-Python and OS-level CVEs. |
| Secrets | Gitleaks | `gitleaks/gitleaks-action@v2` | Fast; SARIF; diff-based on PR, full repo on push. |
| IaC — Ansible | KICS | `Checkmarx/kics-github-action@v2` | Strong Ansible/YAML coverage; SARIF. |
| SBOM | CycloneDX | `CycloneDX/gh-python-generate-sbom@v2` + `anchore/sbom-action@v0` | CycloneDX JSON for wheel/sdist/collection. |
| PR comment | `marocchino/sticky-pull-request-comment@v2` | — | Idempotent; single comment updated across pushes. |
| Cache | `actions/cache@v4` | — | Wrapped in composite actions. |
| Gate aggregator | Custom `gate.py` | — | ~120 LOC; SARIF-in, exit-code-out. |

### Severity mapping

| Scanner | Native levels | Mapped to |
|---|---|---|
| Bandit | HIGH / MEDIUM / LOW | high / medium / low |
| Semgrep | ERROR / WARNING / INFO | high / medium / low |
| pip-audit | CVSS numeric | CVSS ≥ 9.0 critical, ≥ 7.0 high, ≥ 4.0 medium, else low |
| Trivy | CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN | direct |
| Gitleaks | (n/a) | every finding treated as **critical** |
| KICS | HIGH / MEDIUM / LOW | high / medium / low |

The gate fails on any unwaived **medium, high, or critical** finding.

## 5. Triggers, permissions, fork guard

### Triggers (all new workflows)

```yaml
on:
  pull_request:
    branches: [main, "releases/**", "stable/**"]
  push:
    branches: [main]
  workflow_dispatch:

concurrency:
  group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.sha }}
  cancel-in-progress: true
```

No `schedule:` (per user answer). No `merge_group:` — merge-queue coverage
comes from the existing `tox.yml`; the security suite runs on the
`pull_request` event pre-merge.

### Fork guard

Every job in the new workflows includes:

```yaml
if: github.repository == 'fardani235/molecule'
```

If a security workflow file ever gets PR'd to upstream, its jobs no-op there.
PRs from third-party forks into `fardani235/molecule` still run (the value
is the *target* repository).

### Permissions — least privilege

```yaml
permissions: {}   # workflow-level deny-all

jobs:
  <scan-job>:
    permissions:
      contents: read
      security-events: write
  gate:
    permissions:
      contents: read
      pull-requests: write
      security-events: read
  build-artifacts:
    permissions:
      contents: read
      id-token: write   # reserved for future SBOM attestation
```

## 6. Gate policy and waivers

### `.github/security/gate-policy.yml`

```yaml
# Fail the gate if any UNWAIVED finding at or above this severity survives.
threshold: medium
overrides:
  gitleaks:
    threshold: critical
  kics:
    threshold: medium
```

### Waiver conventions

- Every ignore-file entry MUST carry a comment:
  ``# waived <YYYY-MM-DD> by <handle> — <reason>; re-review <YYYY-MM-DD>``
- `gate.py` fails the run if any waiver entry lacks a comment or has an
  expired `re-review` date.
- `.github/security/README.md` documents this convention and states the
  review cadence (**quarterly**, owned by CODEOWNERS).

## 7. Caching strategy

Two composite actions centralize cache definitions.

### `.github/actions/cache-python/action.yml`

Inputs:

- `python-version` (required) — used in the cache key.
- `ansible` (optional, default `false`) — when `true`, also caches the
  Ansible collections/roles layer.
- `pre-commit` (optional, default `true`) — when `true`, also caches the
  pre-commit hooks layer.

| Path | Key | Gated by input |
|---|---|---|
| `~/.cache/pip`, `~/.cache/uv`, `.tox` | `py-${{ runner.os }}-${{ inputs.python-version }}-${{ hashFiles('pyproject.toml', 'tox.ini', '.pre-commit-config.yaml') }}` | always on |
| `~/.cache/pre-commit` | `pc-${{ runner.os }}-${{ hashFiles('.pre-commit-config.yaml') }}` | `pre-commit: true` |
| `~/.ansible/collections`, `~/.ansible/roles` | `ansible-${{ runner.os }}-${{ hashFiles('community.molecule/galaxy.yml', 'community.molecule/requirements.yml', 'requirements.yml') }}` | `ansible: true` |

### `.github/actions/cache-scanners/action.yml`

| Path | Key |
|---|---|
| `~/.cache/trivy` | `trivy-db-${{ github.run_id }}` with `restore-keys: trivy-db-` (auto-refresh floor, not ceiling — Trivy still updates if >24h stale) |
| `~/.semgrep` | `semgrep-${{ hashFiles('.github/security/semgrep-rules.yml') }}` |
| `~/.cache/kics` | `kics-${{ env.KICS_VERSION }}` |

Restore-keys are always set so a lockfile bump still restores an 80%-warm
cache.

## 8. Artifacts

All uploads use `actions/upload-artifact@v4` with `if: always()` and
`retention-days: 90`.

| Artifact | Contents | Producer |
|---|---|---|
| `sast-reports` | `bandit.sarif`, `bandit.json`, `semgrep.sarif`, `semgrep.json` | `sast` job |
| `sca-reports` | `pip-audit.sarif`, `pip-audit.json`, `trivy-fs.sarif`, `trivy-fs.json` | `sca` job |
| `secrets-reports` | `gitleaks.sarif`, `gitleaks.json` | `secrets` job |
| `iac-reports` | `kics.sarif`, `kics.json`, `kics-results.html` | `iac` job |
| `sbom` | `sbom-wheel.cdx.json`, `sbom-sdist.cdx.json`, `sbom-collection.cdx.json` | `sbom` job |
| `gate-summary` | `gate-summary.md`, `gate-report.json` | `gate` job |
| `dist` | `.whl`, `.tar.gz`, `community-molecule-*.tar.gz`, `*.sha256` | `build-artifacts` workflow |
| `benchmark` | `ci-benchmark.md`, `ci-benchmark.json` | `benchmark.yml` (manual) |

Discoverable from the Actions UI and via `gh run download <run-id> -n <name>`.

## 9. Monitoring surfaces

1. **GitHub Security tab** — SARIF from every scanner via
   `github/codeql-action/upload-sarif@v3` with a distinct `category:`
   (`sast-bandit`, `sast-semgrep`, `sca-pip-audit`, `sca-trivy`,
   `secrets-gitleaks`, `iac-kics`).
2. **PR sticky comment** — one comment per PR (updated in place) with a
   severity-count table, gate outcome, links to artifacts, and a link to the
   Security tab filtered to this run.
3. **`$GITHUB_STEP_SUMMARY`** — same table rendered inline in each run's
   Actions UI page.

## 10. Benchmark method

`.github/workflows/benchmark.yml`, `workflow_dispatch`-only, inputs:

- `mode`: `baseline` | `optimized` (default `optimized`)
- `runs`: number, default `3`

`baseline` disables **all** caching (empty `restore-keys`, cache key
prefixed with `${{ github.run_id }}` so no key matches). `optimized`
runs normally.

`benchmark_collect.py` reads per-step timings via the GitHub REST API
(`/repos/{owner}/{repo}/actions/runs/{id}/jobs`) for the N runs, computes
per-job medians, extracts cache hit/miss from step logs, and writes:

- `ci-benchmark.json` — machine-readable
- `ci-benchmark.md` — the before/after table meant to be pasted into the PR
  description

Both go into the `benchmark` artifact.

### Success criteria (target — measured, not asserted)

- Total wall-clock: **≥ 35%** faster on warm cache.
- SCA + SAST jobs individually: **≥ 50%** faster on warm cache.
- Cold-cache (Renovate bump) regression vs. today: **< 10%**.

## 11. Pre-commit mirror

Add lightweight scans to `.pre-commit-config.yaml` so developers catch
issues locally before push:

- `gitleaks/gitleaks` local hook (diff mode).
- `PyCQA/bandit` hook scoped to `src/`.

These do not replace the CI gate; they shorten the feedback loop.

## 12. Rollout plan (high-level, filled out by writing-plans)

1. Land scaffolding (`.github/security/`, `.github/actions/*`, `gate.py`)
   in a first PR.
2. Land `security.yml` with each scanner behind `continue-on-error: true`;
   verify the gate reports correctly but does not yet block.
3. Enable the gate hard-fail once the initial waiver set is captured and
   reviewed by CODEOWNERS.
4. Land `build-artifacts.yml`.
5. Land `benchmark.yml`; run baseline + optimized dispatches; paste the
   table into the design PR body.

## 13. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Scanner API/action deprecation | Renovate already configured; monthly review of pinned versions. |
| False positives blocking all PRs | Waiver files with justification comments + expiry dates. |
| Cache poisoning / stale DB | Trivy `restore-keys` are best-effort; Trivy auto-updates DB if >24h stale. |
| Fork guard bypass on rename | Guard uses literal `fardani235/molecule`; a repo rename intentionally breaks the guard so the workflow noisily needs an update — safer than silently running. |
| Secrets in fork PR from a third party | `pull_request` (not `pull_request_target`) is used; secrets are unavailable to third-party PR runs, so no exfiltration risk. Gitleaks still runs read-only on diff. |
| Benchmark variance | 3-run median; identical runner OS and Python matrix; only caching is toggled between modes. |

## 14. Open questions

None at spec-approval time.
