# Security CI Reference

This fork adds a DevSecOps layer on top of the upstream `tox` CI. See
`docs/superpowers/specs/2026-08-03-devsecops-ci-design.md` for the design.

## What runs, and when

| Trigger | Workflow | Notes |
|---|---|---|
| PR to `main`/`releases/**`/`stable/**` | security.yml | Required to pass (once flipped to enforce). |
| Push to `main` | security.yml | Populates Code Scanning trend. |
| Daily 00:00 UTC | security.yml | Catches new CVEs; fails on expired waivers. |
| Manual | security.yml, ci-benchmark.yml | `workflow_dispatch`. |

## Scanners

| Job | Tool | What it catches | Config |
|---|---|---|---|
| bandit | Bandit 1.7.10 | Python SAST (insecure patterns) | `.github/security/bandit.yaml` |
| semgrep | Semgrep 1.86 (container) | Broad SAST (p/ci, p/python, p/owasp-top-ten) | `.github/security/semgrep.yaml` |
| pip-audit | pip-audit 2.7.3 | Python dependency vulns (PyPA advisory DB) | scans `uv export --frozen --all-extras` |
| gitleaks | gitleaks-action v2 | Leaked secrets in code + git history | `.github/security/gitleaks.toml` |
| trivy | trivy-action 0.24.0 | Filesystem vulns + misconfig + secrets + SBOM | none (defaults + severity threshold) |
| security-gate | `.github/security/gate.py` | Aggregator — the single required status check | reads `waivers.yaml` |

## The gate

`gate.py` normalizes every scanner's severity into
`Critical | High | Medium | Low | Info`, applies waivers from
`.github/security/waivers.yaml`, and exits `1` when any un-waived
Medium/High/Critical finding remains. Set `GATE_MODE=warn` in the
job env to run the gate in read-only mode (no failure).

### Filing a waiver

Edit `.github/security/waivers.yaml`:

```yaml
waivers:
  - id: bandit:B301             # required — scanner:rule format
    reason: "false positive: pickle used only in trusted test harness"
    added_by: "your-gh-handle"
    added_on: "2026-08-03"
    expires_on: "2026-11-03"    # ≤ 90 days — the gate fails on scheduled
                                #   runs after this date so waivers cannot rot.
```

### Reproducing a finding locally

```bash
# Bandit
uv tool install "bandit[sarif]==1.7.10"
bandit -c .github/security/bandit.yaml -r src

# Semgrep
docker run --rm -v "$PWD:/src" semgrep/semgrep:1.86.0 \
  semgrep scan --config p/ci --config p/python --config p/owasp-top-ten src/

# pip-audit
uv export --frozen --all-extras --no-hashes > /tmp/req.txt
uv tool install "pip-audit==2.7.3"
pip-audit --requirement /tmp/req.txt

# gitleaks
docker run --rm -v "$PWD:/repo" zricethezav/gitleaks:latest \
  detect --source=/repo --config=/repo/.github/security/gitleaks.toml

# trivy
docker run --rm -v "$PWD:/src" aquasec/trivy:latest \
  fs --scanners vuln,misconfig,secret /src
```

## Artifacts on every run

- `sarif-bandit`, `sarif-semgrep`, `sarif-pip-audit`, `sarif-gitleaks`, `sarif-trivy` — raw SARIF + JSON per scanner
- `sbom` — SPDX-JSON software bill of materials
- `security-report` — consolidated `report.json` from `gate.py`

## Caching

Three caches populated by `.github/actions/setup-cache`:

- `~/.cache/uv` — keyed on `uv.lock`
- `~/.cache/pre-commit` — keyed on `.pre-commit-config.yaml`
- `~/.cache/trivy` — write on `run_id`, restore on any `trivy-db-*` prefix

## Measuring CI speed

Dispatch `ci-benchmark.yml` with two branch names. It computes median +
p95 wall-clock durations for the last 10 successful runs of `security.yml`
and `tox.yml` on each branch and writes `MEASUREMENTS.md`.
