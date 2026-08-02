# CI Cache Benchmarks

Measured on `ci-cached.yml` (`lint-cached` job), comparing a cold run (cache
miss) against a subsequent warm run (cache hit).

## How to reproduce

1. Trigger `ci-cached` via **workflow_dispatch** with cold caches (first run of
   the day, or after cache eviction) → records "cold (cache miss)".
2. Trigger it again immediately → records "warm (cache hit)".
3. Download both `ci-timing-*` artifacts, or read each run's summary table.

## Results

| Run   | State            | tool cache hit | Install + lint duration |
|-------|------------------|----------------|-------------------------|
| Cold  | cache miss       | false          | _<fill from run>_ s     |
| Warm  | cache hit        | true           | _<fill from run>_ s     |

**Speedup:** _<cold − warm>_ s saved (_<pct>_% faster) on the install + lint
phase with warm caches.
