# CI Performance: Caching Impact

Fork-owned caching (uv cache, Trivy DB cache) added to `security.yml` and
`build-artifacts.yml`. This measures wall-clock impact by comparing a
**cache-cold** run (caches cleared) with a **cache-warm** run (immediate rerun).

## Method

1. Clear caches: **Actions → Caches → delete all** (or `gh cache delete --all`).
2. Trigger the workflow (`workflow_dispatch` or a no-op commit) → this is the **cold** run.
3. Re-trigger immediately → this is the **warm** run.
4. Capture durations: `tools/ci-timing.sh build-artifacts.yml <branch>` and
   `tools/ci-timing.sh security.yml <branch>` for each run.

## Results

> Fill in after the first cold + warm runs complete in the fork.

### build-artifacts.yml

| Job | Cold (s) | Warm (s) | Speedup |
|---|---|---|---|
| build-python | _TBD_ | _TBD_ | _TBD_ |
| sbom | _TBD_ | _TBD_ | _TBD_ |

### security.yml

| Job | Cold (s) | Warm (s) | Speedup |
|---|---|---|---|
| trivy-deps | _TBD_ | _TBD_ | _TBD_ |
| trivy-artifact | _TBD_ | _TBD_ | _TBD_ |

**Total wall-clock:** cold _TBD_ → warm _TBD_ ( _TBD_ % faster).
