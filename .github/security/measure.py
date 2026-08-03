"""Append a new row to docs/superpowers/ci-speed-report.md.

Reads a JSON list of successful `tox` workflow runs from stdin.
Each entry must contain `createdAt`, `updatedAt`, and (optionally)
`cacheHitPercent`. Computes median + p95 wall-clock in seconds and
appends a Markdown table row.

The script deliberately depends only on the standard library so the
runner does not need extra installs.
"""
from __future__ import annotations

import json
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path

REPORT = Path("docs/superpowers/ci-speed-report.md")


def _duration_seconds(entry: dict) -> float:
    start = datetime.fromisoformat(entry["createdAt"].replace("Z", "+00:00"))
    end = datetime.fromisoformat(entry["updatedAt"].replace("Z", "+00:00"))
    return (end - start).total_seconds()


def main() -> int:
    runs = json.load(sys.stdin)
    if not runs:
        print("no runs; nothing to append", file=sys.stderr)
        return 0

    durations = [_duration_seconds(r) for r in runs]
    median = statistics.median(durations)
    p95 = statistics.quantiles(durations, n=20)[18] if len(durations) >= 20 else max(durations)
    cache_hit = sum(r.get("cacheHitPercent") or 0 for r in runs) / len(runs)

    window = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    row = f"| {window} | {median:.0f}s | {p95:.0f}s | {len(runs)} | {cache_hit:.0f}% |\n"

    text = REPORT.read_text()
    if not text.rstrip().endswith("|"):
        # First row after the header separator.
        text = text.rstrip() + "\n"
    REPORT.write_text(text + row)
    print(f"appended row for {window}: median={median:.0f}s p95={p95:.0f}s n={len(runs)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
