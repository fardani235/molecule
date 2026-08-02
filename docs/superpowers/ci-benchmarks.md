# CI Cache Benchmarks

Measured on `ci-cached.yml` (`lint-cached` job), comparing a cold run (cache
miss) against a subsequent warm run (cache hit).

## How to reproduce

1. Trigger `ci-cached` via **workflow_dispatch** with cold caches (first run of
   the day, or after cache eviction) → records "cold (cache miss)".
2. Trigger it again immediately → records "warm (cache hit)".
3. Download both `ci-timing-*` artifacts, or read each run's summary table.

## Results

Measured on the fork's GitHub-hosted `ubuntu-24.04` runners across three
consecutive `ci-cached` runs on the `ci-devsecops` branch (run IDs
30771354889 → 30771739917 → 30772529761):

| Run       | State            | tool cache hit | Install + lint duration |
|-----------|------------------|----------------|-------------------------|
| Cold      | cache miss       | false          | 83 s                    |
| Warm (1)  | cache hit        | true           | 80 s                    |
| Warm (2)  | cache hit        | true           | 73 s                    |

**Speedup:** ~10 s saved (~12% faster) on the install + lint phase once the
uv + tox/tool caches are warm (83 s cold → 73 s warm).

### Interpretation

The delta is modest because on this job the `prek`/`tox -e lint` execution
dominates wall-clock, while the cached portion is dependency resolution and
tool download. The caching removes the uv download + tox environment rebuild on
every subsequent run; the saving grows on runners with slower network or when
the dependency set changes less often than the code. The measurement is
scoped to this fork-owned job and does not attempt to speed up the
upstream-delegated `tox.yml` (which we do not control and which has its own
caching).

### How the numbers are produced

Each `ci-cached` run writes a benchmark table to its **run summary** and uploads
a `ci-timing-<run_id>-<attempt>` artifact containing:

```text
run_state=<cold|warm>
tool_cache_hit=<true|false>
duration_seconds=<N>
```

To refresh: re-run `ci-cached` (via `workflow_dispatch` or a new commit) and read
the summary / download the artifact.
