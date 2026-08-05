# DevSecOps CI Improvements — Design Spec

- **Date:** 2026-08-05
- **Owner:** @fardani235
- **Repository:** `fardani235/molecule` (fork of `ansible-community/molecule`)
- **Status:** Design approved, ready for implementation planning
- **Non-goals:** Publishing to PyPI or Ansible Galaxy; changes to upstream `ansible-community/molecule`

## 1. Motivation & Goals

The fork inherits `ansible-community/molecule`'s CI which delegates functional
testing to `ansible/team-devtools` reusable workflows. It has no security
scanning, no explicit dependency caching in the fork, no artifact retention
strategy for security reports, and no visibility into CI timing.

This spec adds a DevSecOps pipeline that:

1. Runs SAST, SCA, secret, IaC, SBOM, and license scans on every pull request
   and on `main`.
2. **Fails PR checks on any MEDIUM / HIGH / CRITICAL finding** unless the
   finding is explicitly accepted in `.security/allowlist.yml`.
3. Makes every artifact (SARIF, SBOM, JSON reports, timing data, release
   build outputs) downloadable from the Actions run page and surfaced in
   GitHub-native monitoring (Code Scanning, Dependabot, Secret Scanning).
4. Measures CI wall-clock before vs. after via a per-run timing artifact and
   PR-body table.
5. Runs **only in the fork** (`fardani235/molecule`), never upstream.

## 2. Architecture Overview

Additive workflow `.github/workflows/security.yml` — existing workflows
(`tox.yml`, `ack.yml`, `finalize.yml`, `release.yml`, `push.yml`,
`redirects.yml`) are untouched except for one additive artifact upload in
`release.yml` to expose build outputs as downloadable artifacts.

### 2.1 Triggers

- `pull_request` on branches `main`, `releases/**`, `stable/**` — blocking gate.
- `push` on `main` — populate caches, feed Code Scanning + Dependabot.
- `schedule: '0 3 * * 1'` — weekly re-scan of `main` for newly published CVEs.
- `workflow_dispatch` — manual re-run for triage.

### 2.2 Concurrency

```yaml
concurrency:
  group: security-${{ github.event.pull_request.number || github.ref }}
  cancel-in-progress: true
```

### 2.3 Job Graph (fan-out + gate)

```
                        ┌── sast-bandit ─────────┐
                        ├── sast-semgrep ────────┤
   prepare ─────────────┤── sca-pip-audit ───────┤
   (checkout, uv cache, ├── sca-trivy-fs ────────┼──► security-gate ──► post-comment
    tool versions, ts0) ├── secrets-gitleaks ────┤     (aggregate,       (PR body table,
                        ├── iac-checkov ─────────┤      threshold check,  step-summary)
                        ├── iac-ansible-lint ────┤      SARIF upload,
                        ├── sbom-cyclonedx ──────┤      allowlist apply)
                        └── license-trivy ───────┘
                                                        │
                                                        └──► timing-report
                                                             (baseline vs. current)
```

### 2.4 Runner & Permissions

- Runner: `ubuntu-24.04` (pinned; matches existing `release.yml`).
- Default `permissions: read-all`.
- `security-events: write` on scanner jobs uploading SARIF.
- `pull-requests: write` on `security-gate` (sticky comment).
- No `id-token: write` — the security workflow needs no OIDC.

## 3. Scanner Matrix

All third-party actions are pinned by full commit SHA with a version comment.
Tool versions live in `.security/tool-versions.env` and are Renovate-tracked.

| Category | Job | Tool | Emits | Scans |
|---|---|---|---|---|
| SAST | `sast-bandit` | Bandit | `bandit.sarif`, `bandit.json` | `src/molecule/` |
| SAST | `sast-semgrep` | Semgrep OSS (`p/python`, `p/security-audit`, `p/owasp-top-ten`, `p/ci`) | `semgrep.sarif` | `src/`, `tests/` (excludes `tests/fixtures/`) |
| SCA | `sca-pip-audit` | pip-audit fed by `uv export --frozen --format requirements-txt` | `pip-audit.sarif`, `pip-audit.json` | resolved deps from `uv.lock` |
| SCA | `sca-trivy-fs` | Trivy `fs` (`scanners: vuln`) | `trivy-fs.sarif` | repo root |
| Secrets | `secrets-gitleaks` | Gitleaks | `gitleaks.sarif`, `gitleaks.json` | full history on `push`, PR diff on `pull_request` |
| IaC | `iac-checkov` | Checkov (`ansible,dockerfile,github_actions,secrets`) | `checkov.sarif` | `community.molecule/`, `tests/fixtures/`, `.github/` |
| IaC | `iac-ansible-lint` | `ansible-lint --profile production --sarif-file …` | `ansible-lint.sarif` | `community.molecule/`, `tests/fixtures/` |
| SBOM | `sbom-cyclonedx` | CycloneDX Python + Syft | `sbom-python.cdx.json`, `sbom-repo.spdx.json` | env + repo |
| License | `license-trivy` | Trivy `fs --scanners license` | `trivy-license.sarif`, `trivy-license.json` | repo |

Timeout: `timeout-minutes: 15` per scanner.

### 3.1 Shared Setup — Composite Action

`.github/actions/security-setup/action.yml` bundles:

1. `actions/checkout@<sha>` with `fetch-depth: 0`.
2. `actions/setup-python@<sha>` pinned to `3.12`.
3. `astral-sh/setup-uv@<sha>` with `enable-cache: true`.
4. `uv sync --frozen` (`--all-groups` when scanner needs dev deps).
5. Restore Trivy / Semgrep / Checkov / ansible-collections caches (Section 5).
6. Emit `date` outputs (day, week) used in cache keys.

### 3.2 Config Files Added

- `.security/tool-versions.env` — pinned scanner versions.
- `.security/bandit.yaml` — excludes `tests/fixtures/**`.
- `.security/semgrep.yml` — local rules + path excludes.
- `.security/checkov.yml` — framework list + skip patterns.
- `.gitleaks.toml` — allowlist for known-dummy credentials in fixtures.
- `.security/allowlist.yml` — cross-scanner accepted-risk registry (Section 4).
- `.security/scripts/aggregate_sarif.py` — merger + threshold enforcer.
- `.security/scripts/capture_baseline.py` — one-shot baseline capture.

### 3.3 SARIF Normalization

Every scanner writes SARIF v2.1.0 to `${{ runner.temp }}/sarif/<scanner>.sarif`.
Non-native emitters are configured with `--format sarif`; anything remaining is
converted via `pipx run sarif-tools`.

## 4. Gate Logic & Allowlist

### 4.1 Threshold Policy

- **Fail on CRITICAL, HIGH, MEDIUM.**
- Non-fail: LOW, INFO, NOTE, NONE (still visible in Code Scanning + summary).
- Severity source: SARIF `properties.security-severity` (CVSS) when present,
  else `level` mapped:
  - `error` → HIGH, `warning` → MEDIUM, `note`/`none` → LOW.
- Native scanner severity preserved verbatim; mapping is centralized in
  `.security/scripts/aggregate_sarif.py`.

### 4.2 `security-gate` Job Flow

1. `actions/download-artifact` all `sarif-*` artifacts into
   `${{ runner.temp }}/sarif/`.
2. Run `aggregate_sarif.py`:
   - Load every `.sarif`.
   - Fingerprint each result as `(scanner, rule_id, file, line, severity)`.
   - Apply `.security/allowlist.yml`.
   - Emit `security-report.md`, `security-report.json`,
     `security-combined.sarif`.
   - Exit `0` if no unlisted MEDIUM+, else `1`.
3. `github/codeql-action/upload-sarif@<sha>` uploads
   `security-combined.sarif` with `category: security-gate`.
4. `actions/upload-artifact` uploads report + raw SARIF (retention per §5).
5. Sticky PR comment (marker `<!-- security-gate:v1 -->`) via
   `marocchino/sticky-pull-request-comment@<sha>` and always writes to
   `$GITHUB_STEP_SUMMARY`.
6. `exit "$AGG_EXIT"` — failure turns the required check red.

### 4.3 `.security/allowlist.yml` Schema

```yaml
version: 1
findings:
  - id: "pip-audit:GHSA-xxxx-xxxx-xxxx"    # <scanner>:<rule_id>
    package: "some-transitive-dep"         # optional, scanner-specific extras
    reason: "No fix available; not exploitable — used only in test fixtures."
    owner: "@fardani235"
    expires: "2026-11-01"                  # ISO 8601, hard-required
    ticket: "https://github.com/fardani235/molecule/issues/NN"
```

Aggregator enforces on the allowlist itself:

- Missing `reason` / `owner` / `expires` → gate fails.
- `expires` in the past → finding re-enters the gate.
- Duplicate `id` → gate fails.

### 4.4 Required-Check Wiring

Branch protection on `main` (applied manually via `gh api`, snippet in
`docs/security/setup.md`) requires:

- `security-gate` (new)
- existing `tox` checks

### 4.5 Failure UX

When the gate fails, the sticky comment includes: severity counts per
scanner, top 20 findings with `file:line`/rule/severity/snippet URL, a
one-liner pointing at `.security/allowlist.yml`, and a link to the Code
Scanning tab.

## 5. Caching Strategy

Every long-lived download gets an explicit `actions/cache` layer with a
deterministic key + one restore-key fallback.

| Layer | Key | Restore-keys | Paths |
|---|---|---|---|
| uv package cache | `uv-${{ runner.os }}-${{ hashFiles('uv.lock') }}` | `uv-${{ runner.os }}-` | `~/.cache/uv` |
| pipx / pip cache | `pipx-${{ runner.os }}-${{ hashFiles('.security/tool-versions.env') }}` | `pipx-${{ runner.os }}-` | `~/.local/pipx`, `~/.cache/pip` |
| pre-commit | `precommit-${{ hashFiles('.pre-commit-config.yaml') }}` | `precommit-` | `~/.cache/pre-commit` |
| Trivy DB | `trivy-db-${{ github.run_id }}-daily-${{ steps.date.outputs.day }}` | `trivy-db-` | `~/.cache/trivy` |
| Semgrep rules | `semgrep-${{ hashFiles('.security/semgrep.yml') }}-${{ steps.date.outputs.week }}` | `semgrep-` | `~/.semgrep`, `~/.cache/semgrep` |
| Checkov | `checkov-${{ steps.date.outputs.week }}` | `checkov-` | `~/.cache/checkov` |
| Ansible collections | `ansible-collections-${{ hashFiles('community.molecule/galaxy.yml','tests/**/requirements.yml') }}` | `ansible-collections-` | `~/.ansible/collections` |
| setup-python pip cache | built-in via `cache: 'pip'` + `cache-dependency-path: uv.lock` | n/a | pip wheel cache |

### 5.1 Cache Hygiene

- PRs from forks are read-only for caches (GitHub-enforced); `main` runs
  populate.
- `actions/cache/restore` + `actions/cache/save` split with `if: always()`
  so failed scanners still save their cache.
- Rely on GitHub 7-day LRU + 10 GB per-repo quota; document that weekly-
  rotated caches naturally expire.

### 5.2 Expected Impact (to be validated in §6)

- Cold: ~9–11 min end-to-end (bounded by slowest job, Semgrep).
- Warm: ~2.5–3.5 min.

## 6. Artifacts, Retention & Monitoring

### 6.1 Per-run Artifacts

| Artifact | Contents | Retention | Emitter |
|---|---|---|---|
| `sarif-<scanner>` (one per scanner) | Raw per-scanner SARIF + native JSON | 30 d | Each scanner |
| `security-report` | `security-report.md`, `security-report.json`, `security-combined.sarif` | 90 d | `security-gate` |
| `sbom` | `sbom-python.cdx.json`, `sbom-repo.spdx.json`, `sbom-diff.md` | 365 d | `sbom-cyclonedx` |
| `ci-timing` | `timing.json`, `timing.md` | 90 d | `timing-report` |
| `release-dists` (additive to `release.yml`) | wheels/sdists + collection tarball | 90 d | `release` job |

Retention set explicitly via `retention-days:` on every upload.

### 6.2 Monitoring Surfaces

1. **GitHub Code Scanning** — merged SARIF uploaded with
   `category: security-gate`; inline PR annotations.
2. **Dependabot alerts + version updates** — new `.github/dependabot.yml`:
   - `pip` (weekly, groups minor/patch)
   - `github-actions` (weekly, single group)
   - `docker` (weekly)
3. **Secret Scanning + Push Protection** — enabled at repo level; Gitleaks in
   CI is defense-in-depth.
4. **Sticky PR comment** — primary developer UX per run.
5. **`$GITHUB_STEP_SUMMARY`** — per-scanner summary block + gate aggregate.
6. **Weekly schedule** — `cron: '0 3 * * 1'` on `main`.

### 6.3 Trend / Historical View

Artifacts are queryable via `gh api /repos/{owner}/{repo}/actions/artifacts`.
Schemas versioned (`schema_version: 1`). No dashboard built in this scope;
future dashboards can consume history without changes.

### 6.4 Release Artifacts (Downloadable, Not Published)

`release.yml` gets one additive step: `actions/upload-artifact` on the
built dists + collection tarball, so they're downloadable from the Actions
run page. Existing PyPI / Galaxy publish steps are unchanged.

## 7. Speedup Measurement

### 7.1 Per-run Timing Capture

The `timing-report` job:

1. Calls `gh api /repos/${{ github.repository }}/actions/runs/${{ github.run_id }}/jobs`.
2. Reads `cache-hit` outputs from every scanner.
3. Writes `timing.json`:

   ```json
   {
     "schema_version": 1,
     "run_id": 1234,
     "workflow": "security.yml",
     "commit": "abc123",
     "event": "pull_request",
     "total_wallclock_s": 178,
     "jobs": [
       {"name": "sast-bandit", "duration_s": 42,
        "cache_hits": {"uv": true, "pipx": true}}
     ]
   }
   ```

4. Renders `timing.md`.
5. Uploads both as the `ci-timing` artifact.

### 7.2 Baseline Capture (One-shot)

`.security/scripts/capture_baseline.py`:

- Fetches last 5 successful `tox.yml` runs on `main` via `gh api`.
- Averages total wall-clock + each named job's duration.
- Captures the first cold `security.yml` run as the "no-cache" baseline.
- Writes `.security/baseline.json`.

Immutable except by intentional refresh (documented in
`docs/security/setup.md`).

### 7.3 PR-body Comparison Table

`timing-report` appends to the sticky comment:

```
### CI Timing vs. baseline
| Metric                | Baseline | This run | Δ        |
|-----------------------|---------:|---------:|---------:|
| security.yml total    |    9m42s |    2m58s | −69.4%   |
| tox.yml total (avg)   |   14m10s |   11m30s | −18.8%   |
| uv cache hit rate     |      —   |   8/8    |          |
| Trivy DB cache hit    |      —   |   ✅     |          |
```

### 7.4 Tox Measurement Without Editing tox.yml

`tox.yml` delegates to `ansible/team-devtools` and cannot be modified.
`timing-report` queries tox runs on the same SHA via `gh api` and includes
them in the comparison; if none exist on the SHA, the tox row shows
"no tox run on this commit".

### 7.5 Guardrail

`timing-report` runs `continue-on-error: true` — informational only.

## 8. Fork-Only Guard & Operational Notes

### 8.1 Guard Layers

1. **Repo condition** on every job:
   `if: github.repository == 'fardani235/molecule'`.
2. **`FORK-ONLY` banner** at the top of `security.yml` linking to this spec.
3. **Break-glass label (optional, on by default)** — a PR labelled
   `skip-security` bypasses the gate
   (`if: !contains(github.event.pull_request.labels.*.name, 'skip-security')`).
   Applying the label requires repo-owner sign-off in the PR body. Can be
   disabled by removing the label check from `security.yml` if the repo
   policy is "no bypass, ever".
4. **Branch protection** on `fardani235/molecule:main` requires
   `security-gate` and existing `tox` checks.

### 8.2 Secrets

Security workflow needs no secrets. `GITHUB_TOKEN` is the only credential
used (artifact upload, SARIF upload, PR comment). Explicit `permissions:`
block per job.

### 8.3 Supply-Chain Hygiene

- Every `uses:` pins a full commit SHA + version comment.
- Renovate config gets a rule grouping GitHub Actions updates and requiring
  review before merge.

### 8.4 Rollout Order

1. Land composite action + `.security/` config files (no gate yet).
2. Land `security.yml` with every scanner job and the `security-gate` job
   on `continue-on-error: true`. The first PR is informational-only: SARIF
   uploads and Code Scanning entries populate, but no check goes red.
3. Capture baseline: run `capture_baseline.py`, commit
   `.security/baseline.json`, and record first cold `security.yml` run.
4. Enable strict gate — remove `continue-on-error`; enable branch
   protection.
5. Enable Dependabot + Secret Scanning + Push Protection in repo settings
   (checklist in `docs/security/setup.md`).

### 8.5 Fork-Sync Safety

`.github/workflows/security.yml`, `.github/actions/security-setup/`,
`.security/`, and `docs/security/` never exist upstream — merges are
conflict-free. If upstream ever adds files at those paths, the fork keeps
its version (documented merge strategy in `.gitattributes`).

### 8.6 Operational Docs

- `docs/security/setup.md` — one-time setup (branch protection, Dependabot,
  Secret Scanning, baseline capture).
- `docs/security/monitoring.md` — where to find artifacts, Code Scanning,
  Dependabot alerts, weekly scan schedule.
- `docs/security/allowlist.md` — how to add/remove entries and the review
  policy.

### 8.7 Explicit Non-Goals

- No publishing to PyPI or Ansible Galaxy. `release.yml` is unchanged
  except for the additive artifact upload for downloadable builds.
- No changes to `tox.yml` semantics — the fork continues delegating to
  `ansible/team-devtools`.
- No external SIEM / DefectDojo integration — GitHub-native only.

## 9. Acceptance Criteria

The implementation is done when all of the following are true:

1. `.github/workflows/security.yml` exists and runs on every PR to `main`,
   `releases/**`, `stable/**`, plus `push` on `main`, `schedule` weekly,
   and `workflow_dispatch`.
2. All eight scanner jobs run in parallel, each emitting a SARIF file to
   the `sarif-<scanner>` artifact.
3. The `security-gate` job aggregates all SARIFs, applies
   `.security/allowlist.yml`, and fails the check if any unlisted
   MEDIUM/HIGH/CRITICAL finding exists.
4. Merged SARIF appears in the GitHub Code Scanning tab under category
   `security-gate`.
5. `.github/dependabot.yml` is present and Dependabot alerts / version
   updates are enabled at the repo level.
6. Secret Scanning + Push Protection are enabled at the repo level.
7. Every scanner, gate, and release job uploads its artifacts with an
   explicit `retention-days:` value matching §6.1.
8. `timing-report` publishes `timing.json` + `timing.md` per run and the
   PR sticky comment shows the comparison table.
9. `.security/baseline.json` is checked in.
10. Every job in `security.yml` guards on
    `github.repository == 'fardani235/molecule'`.
11. Branch protection on `main` requires the `security-gate` check.
12. All three operational docs (`setup.md`, `monitoring.md`,
    `allowlist.md`) exist and are linked from the repo README under a
    "Security" section.
13. The rollout PR body publishes the measured cold-vs-warm speedup
    numbers for `security.yml` and the observed delta on `tox.yml`.

## 10. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Semgrep / Checkov rule updates introduce new MEDIUM+ findings after merge | Weekly scheduled scan surfaces them; allowlist with `expires` forces triage |
| Trivy DB day-scoped cache misses across midnight UTC | Restore-key `trivy-db-` still hits the previous day's cache; only cost is ~30 s DB refresh |
| Third-party action SHA drift when Renovate bumps | PR review + pinned SHA + grouped Actions updates |
| Upstream merge accidentally imports the workflow | Fork-only `if:` guard on every job |
| Allowlist becomes a dumping ground | Required `expires` field + gate refuses past-expiry entries |
| `tox.yml` timing not captured on some PRs | Gracefully omit the row rather than fail `timing-report` |

## 11. Open Questions

None at spec time — all decisions from brainstorming are recorded above.

## 12. References

- Existing workflows: `.github/workflows/tox.yml`, `release.yml`,
  `push.yml`, `ack.yml`, `finalize.yml`, `redirects.yml`.
- Upstream reusable workflow:
  `ansible/team-devtools/.github/workflows/tox.yml@main`.
- Repo config: `pyproject.toml`, `uv.lock`, `.pre-commit-config.yaml`,
  `renovate.json`.
