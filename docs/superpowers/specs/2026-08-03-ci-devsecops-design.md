# CI DevSecOps Improvements — Design

**Date:** 2026-08-03
**Repo:** `fardani235/molecule` (a fork of `ansible-community/molecule`)
**Author:** ridwan (with Claude)

## Goal

Improve the fork's CI pipeline to meet DevSecOps best practices and repository
policy. Concretely:

1. Add security scanning (SAST, SCA, secrets, IaC/config) as a **PR gate** that
   **fails on medium/high/critical findings**.
2. Add a caching strategy and **measure** the CI speedup it produces.
3. Ensure security-scan and package-release artifacts are **downloadable and
   monitorable**.
4. All new CI must run in the **fork**, not upstream.

**Out of scope:** publishing packages to Ansible Galaxy or PyPI. (We may build
and upload release artifacts, but must not change publish steps.)

## Constraints & Context

- The main test workflow `tox.yml` delegates to the reusable workflow
  `ansible/team-devtools/.github/workflows/tox.yml@main`, which we **cannot
  modify**. All new logic lives in **fork-owned** workflows so fork↔upstream
  syncs stay clean.
- Package manager is `uv` (`uv.lock` present); orchestration via `tox`.
- No Dockerfiles in the repo; scan surface is Python (`src/`,
  `community.molecule/plugins`) and Ansible/YAML/config files.
- Existing workflows: `tox.yml`, `release.yml`, `ack.yml`, `push.yml`,
  `finalize.yml`, `redirects.yml`.

## Architecture

Two new fork-owned workflows plus a small additive change to `release.yml`:

```
.github/workflows/
├── security.yml   (NEW)  ← DevSecOps gate: 4 scanners, blocks on medium+
├── ci-cached.yml  (NEW)  ← fork-owned cached lint/test job + speedup measurement
├── release.yml    (edited: add artifact upload only — NO publish changes)
├── tox.yml        (unchanged — upstream reusable workflow)
└── ack/push/finalize/redirects (unchanged)
```

**Fork-only guard:** every new job is guarded with
`if: github.repository == 'fardani235/molecule'` so the workflows never run
upstream or on a fork-of-fork.

## Component 1 — Security Gate (`security.yml`)

**Triggers:** `pull_request → main`, `push → main`, `schedule` (nightly cron for
drift monitoring), `workflow_dispatch`.
**Concurrency:** cancel-in-progress per PR/ref.
**Permissions:** least-privilege per job (`contents: read`,
`security-events: write` only where SARIF is uploaded).

Four scanner jobs run **in parallel**. Each emits SARIF → uploaded to the GitHub
**Security tab** (`github/codeql-action/upload-sarif`) **and** as a downloadable
**artifact** (raw JSON/SARIF).

| Job       | Tool     | Covers                                             | Gate threshold                  |
|-----------|----------|----------------------------------------------------|---------------------------------|
| `sast`    | Bandit   | Python SAST (`src/`, collection plugins)           | MEDIUM+ severity & confidence   |
| `sca`     | Trivy fs | Dependency CVEs (uv.lock / pyproject)              | MEDIUM, HIGH, CRITICAL          |
| `config`  | Trivy    | Ansible YAML / config / filesystem misconfig       | MEDIUM, HIGH, CRITICAL          |
| `secrets` | Gitleaks | Committed secrets                                  | Any leak (secrets are binary)   |

### Two-pass pattern (report + gate)

To satisfy both "monitor everything" and "block on medium+", each scanner runs:

1. **Report pass** — scan with **no** failure threshold; always upload SARIF +
   artifact (`if: always()`), so *all* findings stay visible/downloadable even
   when the build fails.
2. **Gate pass** — re-evaluate at the medium+ threshold with `exit-code: 1`, so
   the job fails when qualifying findings exist.

A final **`security-gate`** job `needs:` all four scanners and succeeds only if
all pass. **This aggregation job is the required status check** in branch
protection — it is what blocks PR submission on medium/high/critical findings.

### Notes

- `tests/` is excluded from the Bandit **gate** (still reported) to avoid
  assert-in-test noise.
- Trivy misconfig on Ansible is chatty; gate strictly at medium+, keep
  low/unknown in the report artifact only.
- **Trivy DB caching:** cache `~/.cache/trivy` keyed by date; nightly refresh,
  PR reuse — avoids slow DB downloads / rate limits.

## Component 2 — Cached CI Job & Speedup Measurement (`ci-cached.yml`)

**Purpose:** demonstrate and measure real caching speedup on the actual uv+tox
toolchain, independent of the upstream-delegated `tox.yml`.

**Triggers:** `pull_request → main`, `push → main`, `workflow_dispatch`.
Fork-guarded.

**Caching:**
- `astral-sh/setup-uv` built-in cache keyed on `uv.lock`.
- Explicit caches: `~/.cache/uv`, `.tox/` (keyed on `pyproject.toml`+`uv.lock`),
  `.cache/` (mypy/ruff, already configured to live there via `pyproject.toml`).

**Representative job:** `tox -e lint` plus a light unit slice — meaningful but
not a full matrix (the real matrix stays in `tox.yml`).

**Measurement:**
- Each run records **cache hit/miss** (cache action outputs) and **wall-clock**
  of setup+install, written to `$GITHUB_STEP_SUMMARY` as a table
  (*cache hit? / install time / total time*).
- Committed `docs/superpowers/ci-benchmarks.md` captures a **cold vs warm**
  comparison (first run = cache miss, second = cache hit) with the measured
  delta. Reproducible via two `workflow_dispatch` runs.
- Timing summaries uploaded as artifacts (downloadable/monitorable).

**Honesty note:** we do **not** claim caching speeds up upstream `tox.yml`
(not ours; it has its own caching). Measurement is scoped to this fork-owned job.

## Component 3 — Release Artifacts (`release.yml`, additive edit only)

Add `actions/upload-artifact` steps for the built `dist/*` (wheel/sdist) and the
built collection tarball. **No publish steps change** — publishing to Galaxy/PyPI
stays exactly as-is (out of scope). This makes release artifacts downloadable
without publishing.

## Artifacts Summary (downloadable & monitorable)

- **Security:** SARIF → Security tab + raw report artifacts
  (`bandit-report.json`, `trivy-sca.sarif`, `trivy-config.sarif`,
  `gitleaks-report.sarif`), 30-day retention.
- **Release:** built `dist/*` and collection tarball as artifacts.
- **CI benchmarks:** step-summary tables + timing artifact.

## Error Handling

- Report pass uses `continue-on-error`/`|| true`; gate pass is the failing one —
  findings are never hidden by a failed build.
- SARIF uploads use `if: always()`.
- Fork guard prevents accidental upstream/fork-of-fork runs.
- Least-privilege `permissions:` per job.

## Testing / Validation

- `actionlint` + `yamllint` on all workflow YAML.
- Local dry-run of Bandit, Trivy, Gitleaks against this repo to confirm they
  parse and emit valid SARIF before committing.
- Verify `security-gate` fails when any scanner fails (trigger-condition logic).

## Docs Deliverables

- `docs/superpowers/ci-devsecops.md` — the gate, reading findings (Security tab +
  artifacts), branch-protection setup, marking `security-gate` as a required
  check.
- `docs/superpowers/ci-benchmarks.md` — cold-vs-warm caching results.
