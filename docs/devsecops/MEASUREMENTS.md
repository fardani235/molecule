# CI Timing Measurements

Populated by `.github/workflows/ci-benchmark.yml`. This file is a placeholder
until the benchmark workflow has been dispatched. See `SECURITY_CI.md` for
how to run it.

## Baseline (before this PR)

_To be filled in by running:_

    gh workflow run ci-benchmark.yml \
      -f branch_before=main \
      -f branch_after=main

## After DevSecOps changes

_To be filled in after `devsecops-ci` merges and has 10+ runs:_

    gh workflow run ci-benchmark.yml \
      -f branch_before=main \
      -f branch_after=main
