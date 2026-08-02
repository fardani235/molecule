# DevSecOps CI Improvements — Design

- **Date:** 2026-08-03
- **Author:** ridwan
- **Repo:** `fardani235/molecule` (fork of `ansible-community/molecule`)
- **Status:** Approved for planning
- **Scope:** CI pipeline hardening in the fork only. Out of scope: publishing to Ansible Galaxy or PyPI.

## 1. Problem

The fork inherits `ansible-community/molecule`'s CI, which lacks security scanning, dependency review, secret scanning, IaC/workflow scanning, SBOM generation, an explicit caching layer, and a severity-based PR gate. This design adds those capabilities while keeping the fork's workflows compatible with upstream (guarded jobs no-op when run under any owner other than `fardani235`).

## 2. Goals & Non-Goals

**Goals**
- Add SAST, SCA, secret, and IaC scanning to every PR and to `main`.
- Fail PR checks on any Medium/High/Critical finding.
- Publish SARIF results to the GitHub Security tab; retain raw reports 30 days.
- Generate CycloneDX + SPDX SBOMs on release builds.
- Add caching (uv, tox, pre-commit, CodeQL, container layers).
- Produce a durable, in-repo record of pre/post CI wall-clock times.
- All new jobs must run in the fork only.

**Non-Goals**
- Publishing to Ansible Galaxy or PyPI (kept as-is).
- Forking or modifying `ansible/team-devtools` reusable workflows.
- Replacing the existing tox test matrix.
- Long-term telemetry export (Prometheus/OTel).

## 3. Baseline (current state)

`.github/workflows/` today:

| File | Trigger | Purpose |
|---|---|---|
| `tox.yml` | PR / push main / nightly | Reusable `ansible/team-devtools/.github/workflows/tox.yml@main` — lint + matrix tests. |
| `push.yml` | push main | Reusable team-devtools push handler. |
| `ack.yml` | pull_request_target | PR acknowledgement automation. |
| `finalize.yml` | workflow_run after tox | Coverage finalize. |
| `release.yml` | GitHub release / manual | Build sdist+wheel via `tox -e pkg`; publish PyPI + Galaxy. |
| `redirects.yml` | docs paths | RTD redirects sync. |

Gaps: no SAST, SCA, secret, IaC scan; no SBOM; no explicit cache layer; no severity gate; nothing scopes to the fork.

## 4. Architecture

Two new workflows, one additive job on `tox.yml`, and SBOM/provenance steps added to `release.yml`.

```
.github/workflows/
├── tox.yml               (existing + additive `warm-cache` job — owner-gated)
├── release.yml           (existing + SBOM + provenance + Trivy — owner-gated additions)
├── security.yml          (NEW — DevSecOps gate; owner-gated)
├── ci-metrics.yml        (NEW — records CI wall-clock; owner-gated)
├── ack.yml / push.yml / finalize.yml / redirects.yml   (unchanged)
```

All new / additive jobs begin with:

```yaml
if: github.repository_owner == 'fardani235'
```

That single guard ensures the same file, if it ever reaches upstream via PR, is inert there.

### 4.1 `security.yml` job graph

```
                        ┌── sast-codeql (Python)
   pull_request  ───────┼── sca-pip-audit (uv.lock)
   push:main            ├── sca-dep-review (PR-only, diff-scoped)
   schedule (weekly)    ├── secrets-gitleaks
   workflow_dispatch    ├── iac-zizmor  (.github/workflows/*)
                        └── iac-ansible-lint-sec (community.molecule + fixtures)
                                        │
                                        ▼
                         gate  (aggregates SARIF; fail if any Medium+)
                                        │
                                        ▼
                         upload-artifacts (JSON + consolidated report, 30-day)
```

Every scanner emits SARIF and uploads it to code-scanning via `github/codeql-action/upload-sarif@v3`. The `gate` job downloads all SARIF artifacts and evaluates them with a single `jq` predicate. The `gate` check is the PR-required check (branch protection setup is documented in §10 as a one-time manual step).

### 4.2 Scanner → severity mapping

| Tool | Scope | Fails PR when | SARIF |
|---|---|---|---|
| CodeQL | Python source | `error` or `warning` (≥ Medium) | native |
| pip-audit | `uv.lock` → PyPI advisories | Any Medium+ (OSV/GHSA-scored) | `--format sarif` |
| GitHub Dependency Review Action | PR diff dependency deltas | `fail-on-severity: moderate` | native |
| Gitleaks | Full repo history on PR head | Any finding (secrets ⇒ high) | `--report-format sarif` |
| zizmor | `.github/workflows/*.yml` | `--min-severity medium` | native |
| Trivy fs | Repo filesystem + built dists on release | `--severity MEDIUM,HIGH,CRITICAL --exit-code 1` | native |
| ansible-lint (security profile) | Ansible content in `community.molecule/` and fixtures | Rules in `security` tag at `warning` and above | via `--sarif-file` |

The single gate expression:

```bash
jq -e '[.runs[].results[]? | select(.level=="error" or .level=="warning")] | length == 0' *.sarif
```

SARIF `warning` maps to ≥ Medium under CodeQL/GHSA conventions, so one predicate covers every scanner.

### 4.3 False-positive & suppression handling

- `.github/security/allowlist.yml` holds documented suppressions with `owner`, `reason`, `expires` fields.
- Each scanner consults it via its own mechanism:
  - Gitleaks: `--config .github/security/gitleaks.toml` (generated from the allowlist).
  - pip-audit: `--ignore-vuln` list rendered from allowlist.
  - CodeQL: query filters in `.github/codeql/codeql-config.yml`.
  - Trivy: `.trivyignore`.
- Expired entries fail the gate (a dedicated check in the gate job runs `jq` over the allowlist file itself).

### 4.4 Triggers

`security.yml`:
- `pull_request` (branches: `main`, `releases/**`, `stable/**`)
- `push` to `main`
- `schedule: 0 3 * * 1` (weekly Monday 03:00 UTC — catches new CVEs against unchanged code)
- `workflow_dispatch`

`ci-metrics.yml`:
- `schedule: 0 4 * * 1` (Monday 04:00 UTC, one hour after security to avoid overlap)
- `workflow_dispatch`

Concurrency group scoped to workflow + PR number for cancel-in-progress.

## 5. Caching strategy

Adds an additive `warm-cache` job that runs before the existing reusable `tox` call and primes `actions/cache` under keys the reusable workflow will restore from.

| Cache | Path | Key | Restore-keys |
|---|---|---|---|
| uv | `~/.cache/uv` | `uv-${{ runner.os }}-${{ hashFiles('uv.lock') }}` | `uv-${{ runner.os }}-` |
| tox envs | `.tox/` | `tox-${{ runner.os }}-${{ matrix.python }}-${{ hashFiles('pyproject.toml','tox.ini') }}` | `tox-${{ runner.os }}-${{ matrix.python }}-` |
| pre-commit | `~/.cache/pre-commit` | `precommit-${{ hashFiles('.pre-commit-config.yaml') }}` | `precommit-` |
| CodeQL DB | action-managed | via `github/codeql-action/init@v3` input | n/a |
| Podman layers | `~/.local/share/containers/storage` | `podman-${{ hashFiles('tests/fixtures/**/Dockerfile*') }}` | `podman-` |

Podman-layer caching is enabled behind a flag and validated by `ci-metrics.yml`; kept only if the measured delta is ≥ 60 s on cold runs.

Rejected: forking `ansible/team-devtools/.github/workflows/tox.yml`. Maintenance burden too high; the warm-cache shim gives us the same effect for the caches that dominate wall-clock.

## 6. Speed measurement

`ci-metrics.yml` runs on schedule + dispatch. It:

1. Uses `gh run list --workflow=tox.yml --json databaseId,createdAt,updatedAt,conclusion --limit 20` to compute the median wall-clock of the last 20 successful `tox` runs.
2. Writes / updates `docs/superpowers/ci-speed-report.md` with a table:

   | Window | Median | p95 | Sample | Cache hit % |
   | --- | --- | --- | --- | --- |
   | Baseline (pre-caching)   | … | … | 20 | 0 % |
   | Week 1 post-caching      | … | … | 20 | … |
   | Week N                   | … | … | 20 | … |

3. Uploads the same report as a workflow artifact (30-day retention).
4. Opens a PR with the updated file when the median drifts more than 20 % from the previous entry (uses `peter-evans/create-pull-request`).

The very first run (before caching lands) captures the baseline row; that's the reference the "improvement number" is computed against.

## 7. Artifacts, SBOM, provenance

**Per `security.yml` run:**
- `*.sarif` per scanner → uploaded to code-scanning **and** as artifact `security-sarif-${{ github.run_id }}` (30-day).
- `security-report.json` — jq-merged summary — as artifact.

**Per `release.yml` run (owner-gated additions):**
- `anchore/sbom-action@v0` produces CycloneDX (`bom.cdx.json`) + SPDX (`bom.spdx.json`) SBOMs of the built wheel.
- SBOMs attached to the GitHub Release **and** uploaded as artifacts.
- `pypa/gh-action-pypi-publish@release/v1` invoked with `attestations: true` (SLSA-style OIDC attestation, free with GitHub OIDC).
- Trivy scan of the built `dist/*.whl` and `*.tar.gz` collection tarball → SARIF into Security tab; the Medium+ gate applies. Release fails if the shipped artifact has a Medium+ CVE.

## 8. Downloadable & monitorable set

| Item | Where | Retention |
|---|---|---|
| SARIF per scanner | Security tab + workflow artifact | Permanent in Security tab / 30 days artifact |
| `security-report.json` | Workflow artifact | 30 days |
| SBOM (CycloneDX + SPDX) | Release assets + workflow artifact | Release: permanent / artifact: 30 days |
| Built dists (sdist, wheel, collection tarball) | Release assets | Release: permanent |
| `ci-speed-report.md` | Committed in-repo under `docs/superpowers/` + workflow artifact | Permanent in repo / 30 days artifact |

Monitoring surfaces:
- **GitHub Security tab** — code-scanning + secret-scanning + dependency-graph.
- **Actions → Insights** — workflow duration trend graphs.
- **In-repo `docs/superpowers/ci-speed-report.md`** — durable, PR-reviewable metric history.

## 9. Fork-only scoping

- Every new/additive job's first key is `if: github.repository_owner == 'fardani235'`.
- Both `security.yml` and `ci-metrics.yml` are safe to exist in an upstream PR (they no-op there).
- If the fork is ever moved to a different owner, one search-replace across `.github/workflows/*.yml` and `.github/security/*` is sufficient.

## 10. One-time manual steps (documented, not scripted)

These are captured in `docs/superpowers/ci-runbook.md` (created by the implementation plan) so nothing is discovered post-merge:

1. In fork settings → Branch protection for `main`: mark `security / gate` as a required check.
2. In fork settings → Actions permissions: enable "Allow GitHub Actions to create and approve pull requests" (required by `ci-metrics.yml` when it opens the metrics-update PR).
3. In fork settings → Code security & analysis: enable Dependency graph, Dependabot alerts, Secret scanning, Code scanning.
4. No new secrets required for the security or metrics workflows — CodeQL, Gitleaks (OSS), zizmor, pip-audit, Trivy, and Dependency-Review all run without tokens.

## 11. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Warm-cache job's cache keys drift from what the upstream reusable workflow expects. | Pin cache paths and `restore-keys` prefixes that match the reusable workflow's published behavior. `ci-metrics.yml` will show if cache hit rate collapses. |
| Medium-severity noise blocks legitimate PRs. | Documented `allowlist.yml` process with expiring entries. |
| Trivy on release fails on a transient CVE and blocks a hotfix. | `workflow_dispatch` on `release.yml` accepts `override_gate: true` input, guarded by `environment: release` protection rules (manual approver required). |
| `pull_request_target` in existing `ack.yml` runs untrusted code paths. | Out of scope — untouched. New security workflow uses `pull_request` only. |
| Fork owner renamed. | One search-replace; documented in runbook. |

## 12. Testing plan

- Each scanner invoked once on a known-bad fixture (added under `tests/fixtures/security/`) to prove the gate blocks and SARIF uploads succeed.
- A "green" PR from a throwaway branch confirms the happy path.
- `ci-metrics.yml` dry-run via `workflow_dispatch` before caching lands, again after — deltas recorded in `ci-speed-report.md`.
- Documentation smoke: `mkdocs build` continues to pass (spec + runbook are Markdown under `docs/`).

## 13. Acceptance criteria

1. A PR that introduces a Medium+ CVE, secret, or CodeQL finding fails the `security / gate` check.
2. A PR with no findings passes and produces downloadable SARIF + `security-report.json` artifacts.
3. `docs/superpowers/ci-speed-report.md` contains at least a baseline row and one post-caching row, with a median wall-clock delta ≥ 0 (regression alarms flag the opposite).
4. Every new / additive job carries the fork-owner guard and demonstrably no-ops when the guard fails (verified by pushing the branch under a different owner in a sandbox, or by inspecting the workflow run summary).
5. A release build produces SBOMs (CycloneDX + SPDX) and OIDC attestations, all downloadable from the Release page.
6. No changes to the Ansible Galaxy or PyPI publishing steps beyond the additive SBOM + provenance metadata.
