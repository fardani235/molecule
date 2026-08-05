# DevSecOps CI — Where to Look

## Per-run artifacts (Actions tab)

- `sarif-<scanner>` — raw scanner output (SARIF + native JSON), 30-day retention.
- `security-report` — merged SARIF + `security-report.md` / `.json`, 90-day retention.
- `sbom` — CycloneDX (Python env) + SPDX (repo), 365-day retention.
- `ci-timing` — `timing.json` + `timing.md`, 90-day retention.
- `release-dists` — built wheels/sdists + collection tarball, 90-day retention.

Download with:

```bash
gh run download <RUN_ID> -n security-report
```

## Continuous surfaces

- **Security → Code scanning alerts** — inline PR annotations, dismissals.
- **Security → Dependabot alerts** — CVE-driven, independent of CI.
- **Security → Secret scanning alerts** — push protection + retro scans.

## Schedules

- Weekly re-scan of `main`: `cron: '0 3 * * 1'` (Mondays 03:00 UTC).

## Trend queries

Every timing / security report artifact is fetchable via:

```bash
gh api "/repos/fardani235/molecule/actions/artifacts?per_page=100"
```

`timing.json` and `security-report.json` both use `schema_version: 1` so a
future dashboard can safely accumulate history.
