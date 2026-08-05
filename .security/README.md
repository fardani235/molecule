# .security/

Fork-local DevSecOps configuration for `fardani235/molecule`.

- `tool-versions.env` — pinned scanner versions (Renovate-tracked).
- `bandit.yaml`, `semgrep.yml`, `checkov.yml` — scanner configs.
- `allowlist.yml` — cross-scanner accepted-risk registry.
- `scripts/` — aggregation, baseline, and timing renderers.
- `baseline.json` (committed later) — reference timing captured during rollout.

See `docs/security/` for setup, monitoring, and allowlist policy.
