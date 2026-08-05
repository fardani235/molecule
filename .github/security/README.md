# Security config

This directory holds configuration and waivers for the DevSecOps gate
defined in `.github/workflows/security.yml`.

## Waiver convention

Every waiver — in any of these files — MUST be preceded by a comment in
this exact form:

```
# waived <YYYY-MM-DD> by <handle> — <reason>; re-review <YYYY-MM-DD>
```

`gate.py` fails the workflow if any waiver entry is missing a comment or
has an expired `re-review` date.

## Files

| File | Purpose |
|---|---|
| `gate-policy.yml` | Severity threshold + per-scanner overrides |
| `bandit.yaml` | Bandit SAST config |
| `.gitleaks.toml` | Gitleaks rules and path allowlist |
| `pip-audit-ignore.txt` | CVE waivers for pip-audit |
| `.trivyignore` | CVE waivers for Trivy filesystem scan |
| `kics-exclusions.json` | KICS query and path exclusions |
| `semgrep-rules.yml` | Rulesets Semgrep will load (its hash is the cache key) |

## Downloading scan artifacts

Every workflow run uploads scan reports as artifacts (90-day retention).
Download with:

```
gh run download <run-id> -n sast-reports
gh run download <run-id> -n sca-reports
gh run download <run-id> -n secrets-reports
gh run download <run-id> -n iac-reports
gh run download <run-id> -n sbom
gh run download <run-id> -n gate-summary
```

Or view findings inline in the repository's **Security** tab (SARIF is
uploaded there for every scanner).

## Review cadence

CODEOWNERS review waivers **quarterly**. Any entry whose `re-review` date
has passed fails the gate on the next run.
