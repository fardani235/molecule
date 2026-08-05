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
