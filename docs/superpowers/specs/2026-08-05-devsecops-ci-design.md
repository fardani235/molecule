# DevSecOps CI Improvements — Design Spec

**Date:** 2026-08-05
**Repo:** `fardani235/molecule` (fork of `ansible-community/molecule`)
**Status:** Approved

## Problem

The `molecule` project (a Python package + Ansible collection `community.molecule`,
used to test Ansible collections, playbooks, and roles) has functioning CI/CD but
**no security scanning** and **no fork-controllable caching strategy**. We must
bring the CI up to DevSecOps best practices:

- A PR gate that **fails on medium/high/critical** security findings.
- Security-scanning and package-release artifacts that are **downloadable and monitorable**.
- Fork-owned **caching** to speed up CI, with a **measured** before/after improvement.

## Constraints

- **Fork, not upstream.** All new CI must run only on the fork
  (`github.repository == 'fardani235/molecule'`) and must not affect upstream.
- **Upstream-delegated CI is off-limits.** Core test/lint runs via
  `ansible/team-devtools` reusable workflows (`tox.yml`, `push.yml`,
  `finalize.yml`). We do not modify these; the reusable `tox.yml` owns its own
  caching, which we cannot tune from the fork.
- **Out of scope:** publishing packages to Ansible Galaxy or PyPI. We *build*
  artifacts but do not publish them.

## Architecture

Add **two new fork-owned workflows** that run alongside the existing delegated ones.
Every new job is guarded with `if: github.repository == 'fardani235/molecule'` and
uses least-privilege, per-job `permissions`.

```
existing (untouched):  tox.yml → team-devtools   push.yml → team-devtools   finalize.yml
new (fork-owned):      security.yml              build-artifacts.yml
```

### Workflow 1 — `security.yml` (the DevSecOps gate)

Triggers: `pull_request` → `main`, `push` → `main`.

Four scan jobs run in parallel. Each is configured to **report, not hard-exit**, so
all four always complete and always upload their reports/SARIF even when findings
exist. A final `security-gate` job evaluates severities and is the **required
status check**.

| Layer            | Tool     | Target                          | Gate signal              |
|------------------|----------|---------------------------------|--------------------------|
| SAST (code)      | Bandit   | `src/` Python source            | severity MEDIUM+         |
| Dependency / SCA | Trivy fs | `uv.lock` + `pyproject.toml`    | MEDIUM/HIGH/CRITICAL     |
| Secrets          | Gitleaks | PR commit range / full history  | any leak = fail          |
| SBOM + artifact  | Trivy    | built dist + CycloneDX SBOM     | MEDIUM+                  |

```
bandit ────────┐
trivy-deps ────┤
gitleaks ──────┼──> security-gate (severity policy) ──> pass/fail   ← required check
trivy-artifact ┘
```

- **Bandit** emits SARIF via `bandit-sarif-formatter`; JSON report for the gate.
- **Trivy** (deps) runs in `fs` mode over the repo; SARIF + JSON.
- **Gitleaks** scans the PR commit range on PRs, full history on push to main.
- **Trivy (artifact)** scans the built package/collection produced by
  `build-artifacts.yml` and consumes the CycloneDX SBOM.

**Why report-then-gate** (rather than per-tool `--exit-code`): guarantees every
report/SARIF is uploaded for download and the Security tab even on failure, and
keeps the severity policy in one readable place.

### Workflow 2 — `build-artifacts.yml`

Triggers: `pull_request` → `main`, `push` → `main`, `workflow_dispatch`.

```
setup (uv + cache)
   ├─> build-python      → dist/*.whl, dist/*.tar.gz   (tox -e pkg)
   ├─> build-collection  → community-molecule-*.tar.gz (ansible-galaxy collection build)
   └─> sbom              → sbom-cyclonedx.json (from uv.lock, whole project)
        └─> consumed by trivy-artifact in security.yml
```

## Caching (fork-owned — where speedup is measured)

Applied only to the new security/build jobs (upstream tox caching untouched).

| Cache                  | Key                              | Saves                          |
|------------------------|----------------------------------|--------------------------------|
| uv (`~/.cache/uv`)     | hash of `uv.lock`                | dep resolution + downloads     |
| pre-commit             | hash of `.pre-commit-config.yaml`| hook env setup (if fast-lint)  |
| Trivy vuln DB          | date-rotated key                 | ~40s DB download per run       |

`astral-sh/setup-uv` with `enable-cache: true` handles the uv layer natively;
Trivy DB and pre-commit use `actions/cache` with `restore-keys` fallback.

## Artifacts & Monitoring

- **Downloadable artifacts** (`actions/upload-artifact`, retention 30d):
  `python-dist`, `ansible-collection`, `sbom`, `security-reports`.
- **Security tab**: each scan uploads SARIF via
  `github/codeql-action/upload-sarif` → code-scanning alerts, tracked over time.
- **Step Summary**: `security-gate` writes a Markdown table (finding counts by
  severity per tool) to `$GITHUB_STEP_SUMMARY` for a readable per-run verdict.

## Measuring the speedup (cold vs warm + doc)

- `tools/ci-timing.sh` uses `gh run view --json jobs` to capture per-job durations.
- Trigger the workflow **cache-cold** (caches cleared) then **cache-warm** (rerun),
  capture durations, and write `docs/devsecops/ci-performance.md` with a before/after
  table and % speedup.
- **Dependency:** real numbers can only be filled in after the workflows run on
  GitHub Actions in the fork. The harness + doc template are built now; numbers are
  captured after the first pushed runs complete.

## Deliverables

- `.github/workflows/security.yml` — 4 scans + gate
- `.github/workflows/build-artifacts.yml` — build + SBOM + caching
- `tools/ci-timing.sh` — timing capture via `gh`
- `docs/devsecops/ci-performance.md` — speedup report (template + real numbers later)
- `docs/devsecops/README.md` — how to read reports; branch-protection setup for the
  required `security-gate` check

## Branch-protection note (manual, one-time)

The gate only blocks merges once `security-gate` is set as a **required status
check** on the fork's `main` branch protection. Documented in
`docs/devsecops/README.md`.
