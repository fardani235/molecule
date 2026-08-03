#!/usr/bin/env python3
"""Compute median/p95 wall-clock times for GitHub Actions workflow runs.

Usage:
  bench.py --workflow security.yml --sha-before <sha> --sha-after <sha> \
      --output MEASUREMENTS.md
"""
from __future__ import annotations

import argparse
import json
import statistics
import subprocess
from datetime import datetime


def _fetch(workflow: str, branch: str, limit: int = 10) -> list[dict]:
    out = subprocess.check_output([
        "gh", "run", "list",
        "--workflow", workflow,
        "--branch", branch,
        "--limit", str(limit),
        "--json", "databaseId,createdAt,updatedAt,conclusion,headSha",
    ])
    return json.loads(out)


def _duration_seconds(run: dict) -> float:
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    start = datetime.strptime(run["createdAt"], fmt)
    end = datetime.strptime(run["updatedAt"], fmt)
    return (end - start).total_seconds()


def _summarize(runs: list[dict]) -> tuple[float, float, int]:
    durs = [_duration_seconds(r) for r in runs if r.get("conclusion") == "success"]
    if not durs:
        return (0.0, 0.0, 0)
    return (statistics.median(durs), _p95(durs), len(durs))


def _p95(xs: list[float]) -> float:
    xs = sorted(xs)
    if len(xs) == 1:
        return xs[0]
    idx = int(round(0.95 * (len(xs) - 1)))
    return xs[idx]


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--workflow", action="append", required=True,
                   help="Workflow file name; may be given multiple times.")
    p.add_argument("--branch-before", required=True)
    p.add_argument("--branch-after", required=True)
    p.add_argument("--output", required=True)
    args = p.parse_args()

    lines = [
        "# CI Timing Measurements",
        "",
        f"- Branch (before): `{args.branch_before}`",
        f"- Branch (after):  `{args.branch_after}`",
        "",
        "| Workflow | Median before | p95 before | N before | Median after | p95 after | N after | Δ median |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for wf in args.workflow:
        before = _summarize(_fetch(wf, args.branch_before))
        after = _summarize(_fetch(wf, args.branch_after))
        delta = "n/a" if before[0] == 0 or after[0] == 0 else f"{(after[0] - before[0]):+.1f}s"
        lines.append(
            f"| {wf} | {before[0]:.1f}s | {before[1]:.1f}s | {before[2]} "
            f"| {after[0]:.1f}s | {after[1]:.1f}s | {after[2]} | {delta} |"
        )
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
