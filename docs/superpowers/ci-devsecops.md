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
