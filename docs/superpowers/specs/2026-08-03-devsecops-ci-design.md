# DevSecOps CI Enhancements — Design Spec

- **Date:** 2026-08-03
- **Repository:** fork of `ansible-community/molecule`
- **Scope:** Add security scanning, caching, and CI-timing measurement to the fork's CI. **Out of scope:** publishing packages to PyPI or Ansible Galaxy.
- **Author:** ridwan (via Claude Code brainstorming session)

## 1. Goals

1. Every pull request opened against this fork is scanned for security defects across five dimensions: Python SAST (Bandit), broad SAST (Semgrep), Python dependency vulnerabilities (pip-audit), leaked secrets (Gitleaks), and filesystem/IaC/SBOM (Trivy).
2. A PR is **blocked from merging** if any scanner reports one or more findings of severity **Medium, High, or Critical**.
3. Scanner results are (a) uploaded to GitHub Code Scanning (SARIF), (b) available as downloadable artifacts per run, and (c) summarized in the workflow's Job Summary markdown for the reviewer.
4. CI runs faster after the change than before. The improvement is quantified in a `MEASUREMENTS.md` artifact.
5. All new workflows execute **only on the fork**, not on upstream, even if the workflow files are ever pulled upstream.

## 2. Non-Goals

- Publishing to PyPI or Ansible Galaxy (existing `release.yml` continues to handle this out of scope of this change).
- Modifying upstream reusable workflows in `ansible/team-devtools`.
- Removing or rewriting existing workflows (`tox.yml`, `ack.yml`, `push.yml`, `finalize.yml`, `redirects.yml`, `release.yml`).
- Runtime protections (WAF, IDS, RASP) — this spec is CI-only.

## 3. Architecture

Two new workflow files and one composite action are added. All existing files are untouched behaviorally.

```
.github/
├── actions/
│   └── setup-cache/action.yml     # composite action: uv + pre-commit + trivy DB caches
├── workflows/
│   ├── security.yml               # NEW — 5 scanners + gate (this spec's centerpiece)
│   ├── ci-benchmark.yml           # NEW — manual before/after wall-clock timing
│   └── (existing files unchanged)
├── security/
│   ├── bandit.yaml
│   ├── semgrep.yaml
│   ├── gitleaks.toml
│   ├── waivers.yaml               # opt-in list of waived finding IDs with expiry
│   └── gate.py                    # aggregator that decides PR pass/fail
docs/
└── devsecops/
    ├── MEASUREMENTS.md            # before/after wall-clock report (committed)
    └── SECURITY_CI.md             # what runs, how to reproduce locally, waiver flow
```

**Design principle: scanners never fail on findings.** Each scanner job succeeds as long as the tool itself ran. Findings are then read by a dedicated `security-gate` aggregator job, which is the single point where the Medium+ policy is enforced. This means:

- GitHub Code Scanning receives complete SARIF even when the PR is blocked.
- Severity normalization lives in exactly one file (`gate.py`).
- One required status check protects the branch, not five.

## 4. Components

### 4.1 `.github/actions/setup-cache/action.yml` (composite action)

Inputs: `python-version` (string, default `3.13`), `cache-scanner-db` (bool, default `false`).

Restores three caches:

| Cache | Path | Key | Restore-keys |
|---|---|---|---|
| uv | `~/.cache/uv` | `uv-${{ runner.os }}-${{ hashFiles('uv.lock') }}` | `uv-${{ runner.os }}-` |
| pre-commit | `~/.cache/pre-commit` | `pc-${{ runner.os }}-${{ hashFiles('.pre-commit-config.yaml') }}` | `pc-${{ runner.os }}-` |
| Trivy DB (only when `cache-scanner-db: true`) | `~/.cache/trivy` | `trivy-db-${{ github.run_id }}` | `trivy-db-` |

The Trivy DB cache uses `run_id` for the *write* key so the newest DB is always saved, but *reads* fall back to any previous `trivy-db-*` — this avoids the "SHA-256 exact-match" trap that makes vulnerability-DB caches useless in practice.

### 4.2 `.github/workflows/security.yml`

Triggers:

| Event | Notes |
|---|---|
| `pull_request` targeting `main`, `releases/**`, `stable/**` | required for gate |
| `push` to `main` | populates Code Scanning trend |
| `schedule` daily at `0 0 * * *` UTC | catches new CVEs against unchanged code |
| `workflow_dispatch` | manual re-run |

Fork guard on every job: `if: github.repository == '<fork-owner>/molecule'`. The exact fork-owner slug is filled in during implementation (it must match `github.repository` for the fork; upstream would evaluate to `ansible-community/molecule` and skip). If run on upstream, all jobs skip; the aggregator therefore also skips, so no false-red is produced.

Concurrency: `${{ github.workflow }}-${{ github.event.pull_request.number || github.sha }}` with `cancel-in-progress: true`.

Permissions per job: `contents: read`, `security-events: write` (for SARIF upload). No secrets are needed by any scanner job.

Jobs:

1. **`bandit`** — installs Bandit via `uv tool install`, runs against `src/`, writes `bandit.sarif` and `bandit.json`, uploads both, appends severity counts to Job Summary.
2. **`semgrep`** — uses `returntocorp/semgrep-action@v1` with rulesets `p/ci`, `p/python`, `p/owasp-top-ten`; outputs SARIF; uploads.
3. **`pip-audit`** — runs `pip-audit --format sarif --output pip-audit.sarif` against `uv export --format requirements-txt --all-extras --frozen` output; also emits JSON for the gate. `--all-extras` ensures dev/lint/collection groups are scanned, not just runtime deps.
4. **`gitleaks`** — uses `gitleaks/gitleaks-action@v2` with `.github/security/gitleaks.toml`; scans full history on `push`/schedule, shallow scan on PRs; SARIF upload.
5. **`trivy`** — uses `aquasecurity/trivy-action@0.24.0` with `scan-type: fs`, `scanners: vuln,misconfig,secret`; also generates an SBOM (`spdx-json`) as a separate artifact.
6. **`security-gate`** — `needs: [bandit, semgrep, pip-audit, gitleaks, trivy]`, `if: always()`. Downloads all SARIF artifacts, runs `python .github/security/gate.py *.sarif`, uploads consolidated `report.json`, sets exit code.

### 4.3 `.github/security/gate.py`

Reads a glob of SARIF files, normalizes severity per the table below, applies waivers from `waivers.yaml`, prints a per-scanner + total table to stdout (also to `$GITHUB_STEP_SUMMARY`), writes `report.json` next to the SARIFs, and exits:

- `0` — no un-waived Medium+ findings.
- `1` — one or more un-waived Medium+ findings.
- `2` — internal error (bad SARIF, missing file, waiver-file schema error).

Severity normalization:

| Scanner | Native field | Mapped severities |
|---|---|---|
| Bandit | `issue_severity` (HIGH/MEDIUM/LOW) | direct |
| Semgrep | `extra.severity` (ERROR/WARNING/INFO) | ERROR→High, WARNING→Medium, INFO→Low |
| pip-audit | none per-finding; CVSS from advisory | ≥9.0 Critical, ≥7.0 High, ≥4.0 Medium, else Low |
| Gitleaks | binary | any finding → Critical |
| Trivy | `Severity` (CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN) | direct; UNKNOWN treated as Low |

### 4.4 `.github/security/waivers.yaml`

Schema:

```yaml
waivers:
  - id: "CVE-2024-XXXXX"         # or scanner-specific rule id (e.g., "bandit:B101")
    reason: "false positive in test fixture"
    added_by: "<gh-handle>"
    added_on: "2026-08-01"
    expires_on: "2026-11-01"     # gate FAILS on schedule runs after this date
```

Expired waivers block scheduled runs even when no PR is open — this prevents silent rot.

### 4.5 `.github/workflows/ci-benchmark.yml`

Trigger: `workflow_dispatch` only. Inputs: `baseline_sha` (before change), `current_sha` (after change).

Steps:

1. Use `gh run list --workflow=security.yml --branch=<sha>... --json databaseId,createdAt,updatedAt,conclusion` to gather up to 10 most recent runs for each side.
2. Also gather runs for `tox.yml` (to show pre-commit cache gains on the pre-existing workflow).
3. Compute median and p95 duration per job.
4. Emit a Markdown table (`MEASUREMENTS.md`) to the artifact and to Job Summary.
5. Upload `MEASUREMENTS.md` as a workflow artifact named `ci-timing-report`.

The tool used for the calculation is a small Python script (`docs/devsecops/bench.py`) — no external dependencies beyond `gh` and stdlib.

## 5. Data Flow

Per scanner job:

```
checkout → setup-cache → install tool → run tool → normalize output to SARIF
        → upload-sarif to Code Scanning
        → upload-artifact (SARIF + raw JSON)
        → append severity table to $GITHUB_STEP_SUMMARY
```

Aggregation:

```
security-gate (needs=all, if=always)
  → download all *.sarif artifacts to a temp dir
  → python .github/security/gate.py <dir>/*.sarif
       ↳ read + normalize + apply waivers
       ↳ write report.json
       ↳ append summary to $GITHUB_STEP_SUMMARY
       ↳ exit 0 or 1
  → upload report.json as artifact `security-report`
```

## 6. Branch Protection

After the first successful run on the fork's `main`:

- Add `security-gate` as a **required** status check on `main`, `releases/**`, `stable/**`.
- Existing `tox` required check remains.
- No other new checks are required (individual scanner jobs are informational — the aggregator is the gate).

## 7. Caching Strategy

- **uv cache** — biggest single win. Keyed on `uv.lock` hash; changes to that lockfile invalidate everyone downstream, which is the correct behavior. Restore-key fallback lets a lockfile bump still benefit from most of the previous cache.
- **pre-commit / prek cache** — used by `tox.yml`'s lint environment as well as the `security.yml` scanners that shell out to pre-commit hooks. Keyed on `.pre-commit-config.yaml`.
- **Trivy DB cache** — the DB is ~90 MB. Downloading it on every run dominates Trivy's runtime. `run_id`-write / prefix-restore pattern keeps it always-fresh-when-there-is-something-newer and always-usable-when-not.

Not cached (with reason):

- `.tox/` — mixed-reputation cache; environment-poisoning risk outweighs the marginal gain now that `uv` handles dependency resolution.
- Container image layers — image pulls do not dominate wall-clock time on the scanner workflow. Revisit only if a future scanner needs a heavy base image.

## 8. Benchmark & Measurement

**Baseline capture:** before merging this spec's implementation, run `ci-benchmark.yml` against the latest 10 runs of `tox.yml` on the fork (there is no `security.yml` yet, so its baseline is zero). Commit the resulting `MEASUREMENTS.md` to `docs/devsecops/`.

**Post-change capture:** after `security.yml` has run at least 10 times on the fork, run `ci-benchmark.yml` again and commit the updated `MEASUREMENTS.md`.

**Expected improvements (hypotheses, to be verified):**

| Job | Baseline (est.) | Post-cache (est.) | Mechanism |
|---|---|---|---|
| bandit | ~40s | ~15s | uv cache skips dep install |
| semgrep | ~90s | ~55s | uv cache + ruleset cache |
| pip-audit | ~50s | ~20s | uv cache |
| gitleaks | ~30s | ~25s | mostly download; small gain |
| trivy | ~120s | ~35s | DB cache (~90 MB) |
| tox lint stage | ~180s | ~90s | pre-commit env cache (not `.tox/` itself — see §7) |

Real numbers replace this table when the benchmark job runs.

## 9. Fork-Only Execution

Every new job carries:

```yaml
if: github.repository == '<fork-owner>/molecule'
```

Additionally, `security.yml` and `ci-benchmark.yml` are opt-in in the sense that their trigger events (`pull_request` on this fork, `workflow_dispatch`) do not fire on upstream unless the fork's owner explicitly pushes them upstream. The `if:` guard is defense-in-depth for that case.

## 10. Failure Modes & Error Handling

| Scenario | Behavior |
|---|---|
| Scanner tool crashes | scanner job fails; aggregator still runs (`if: always()`); PR blocked with clear "tool crashed" message in Job Summary. |
| Cache miss | fresh download; no failure, only slower run. |
| SARIF upload fails (Code Scanning quota) | job continues; artifact is still uploaded; aggregator still works from artifacts. |
| Waiver file syntax error | `gate.py` exits with code 2 and a clear error; aggregator job fails. |
| Waiver expired | scheduled run fails; PR runs are unaffected until the waiver is renewed or the finding is fixed. |
| Unknown severity in SARIF | mapped to Low with a warning line in Job Summary — never silently ignored. |

## 11. Testing

- `gate.py` has unit tests under `.github/security/tests/` covering: no findings, only Low findings, mixed severities, waived-out Medium, expired waiver on scheduled event, unparseable SARIF.
- Tests run in an existing tox environment (`tox -e security-tests`, added to `pyproject.toml`).
- The workflows themselves are validated by `actionlint` (already configured in `.pre-commit-config.yaml`).

## 12. Documentation

- `docs/devsecops/SECURITY_CI.md` — for contributors: what runs, how to reproduce a finding locally, how to file a waiver, how to interpret Code Scanning results.
- `docs/devsecops/MEASUREMENTS.md` — the timing report artifact, committed alongside the implementation.

## 13. Rollout Plan (summary — full plan lives in the implementation plan)

1. Land the composite action + `gate.py` + tests. No workflow yet — nothing runs.
2. Add `security.yml` with the gate policy set to **warn-only** for one week (Medium+ findings shown but don't fail). This creates the baseline signal.
3. Fix or waive existing findings surfaced in step 2.
4. Flip the gate to **fail on Medium+** and add `security-gate` as a required status check.
5. Run `ci-benchmark.yml`, commit `MEASUREMENTS.md`, close out.

## 14. Implementation-Time Inputs

The following must be filled in during implementation and are marked as placeholders in this spec:

- `<fork-owner>` — the GitHub organization or user that owns this fork. Substituted into every `if: github.repository == '<fork-owner>/molecule'` guard. The implementation plan MUST resolve this from `git remote get-url origin` before generating any workflow file.

## 15. Open Questions

None — all clarifying questions were answered during brainstorming (2026-08-03):

- Scanner set: Bandit + Semgrep + pip-audit + Gitleaks + Trivy.
- Gate policy: fail PR on any Medium+ finding.
- Caching: uv + pre-commit + scanner DBs.
- Benchmark: one-shot before/after wall-clock artifact.
- Workflow layout: single `security.yml` with parallel jobs + aggregator.
- Result sinks: SARIF to Code Scanning + downloadable artifacts + Job Summary table.
