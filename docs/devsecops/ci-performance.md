# CI Performance: Caching Impact

Fork-owned caching (uv cache, Trivy DB cache) added to `security.yml` and
`build-artifacts.yml`. This measures wall-clock impact by comparing a
**cache-cold** run (caches empty) with a **cache-warm** run (caches populated
from the prior run).

## Method

1. Clear caches: **Actions → Caches → delete all** (or `gh cache delete --all`).
2. Trigger the workflow (open/update the PR, or `workflow_dispatch`) → this is
   the **cold** run.
3. Re-trigger with caches now populated → this is the **warm** run.
4. Capture durations: `tools/ci-timing.sh build-artifacts.yml <branch>` and
   `tools/ci-timing.sh security.yml <branch>` for each run.

Measured on `fardani235/molecule` PR #5, branch `blue-iguana-rework`,
`ubuntu-24.04` runners, 2026-08-05.

## Results

### build-artifacts.yml (uv cache)

| Job | Cold (s) | Warm (s) | Speedup |
|---|---|---|---|
| build-python | 22 | 20 | 9% |
| build-collection | 13 | 12 | 8% |
| sbom | 17 | 13 | 24% |

Cold run `30993884751`, warm run `30994296587`.

The uv cache (`~/.cache/uv`, keyed on `uv.lock`) removes dependency
re-download/resolution on warm runs. The `sbom` job — which runs `uv export`
plus `cyclonedx-py` and is dominated by dependency handling — shows the
clearest gain (24%). The build jobs improve modestly because compilation and
packaging, not dependency fetching, dominate their wall-clock.

### security.yml (Trivy DB cache)

| Job | Cold (s) | Warm (s) | Delta |
|---|---|---|---|
| trivy-deps | 24 | 31 | +7 (within noise) |
| trivy-artifact | 39 | 35 | -4 (within noise) |

Cold run `30994296701` (first successful run — Trivy DB downloaded fresh),
warm run = in-place re-run of `30994296701` (DB restored from cache).

**Honest reading:** the Trivy DB cache did **not** produce a measurable
speedup here. These jobs are dominated by SBOM generation (`uv export` +
`cyclonedx-py`) and the vulnerability scan itself; the vuln-DB download the
cache targets is a small fraction of the total, so runner-to-runner variance
(±5–7s) swamps the saving. The cache is still correct and worth keeping (it
avoids a ~40s DB download when the upstream mirror is slow or rate-limited),
but on these runs it was not the bottleneck.

## Summary

- **uv cache (build-artifacts):** real, consistent improvement — up to **24%**
  on the dependency-bound `sbom` job; ~8–9% on build jobs.
- **Trivy DB cache (security):** correct but not rate-limiting on these runs;
  no reliable wall-clock win, dominated by scan/SBOM time and runner variance.
- Biggest available speedup lever going forward is the four security scans
  running **in parallel** (already the case) rather than caching — the
  workflow's wall-clock is the slowest single scan (~35–39s for
  `trivy-artifact`), not the sum.

## Note on the first runs

The initial CI runs surfaced a real bug: `aquasecurity/trivy-action` was
pinned as `@0.28.0` (no `v` prefix, unresolvable) and then `@v0.29.0` (whose
transitive `setup-trivy@v0.2.2` tag had been deleted upstream). Both failed at
"Set up job". Fixed by pinning `@v0.36.0`, which references `setup-trivy` by
commit SHA. See commits `0c5e7af` and `1d39124`.
