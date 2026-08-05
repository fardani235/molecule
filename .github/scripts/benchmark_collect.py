"""CI benchmark aggregator.

Reads jobs-listing JSON produced by the GitHub REST API for a set of
runs, computes median wall-clock durations per job, and renders a
Markdown before/after table.

The two input directories (baseline, optimized) each hold one JSON file
per run. Each file is the response body of
GET /repos/{owner}/{repo}/actions/runs/{run_id}/jobs.
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as _dt
import json
import pathlib
import statistics
import sys


CACHE_HIT_MARKER = "cache restored from key"
CACHE_MISS_MARKER = "cache not found"


@dataclasses.dataclass
class Job:
    name: str
    duration_s: float
    cache_hits: int
    cache_total: int


@dataclasses.dataclass
class Run:
    jobs: list[Job]


@dataclasses.dataclass
class JobStat:
    median_duration_s: float
    cache_hit_pct: float


def _parse_ts(s: str) -> _dt.datetime:
    return _dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def _count_cache_steps(steps: list[dict]) -> tuple[int, int]:
    hits = 0
    total = 0
    for step in steps or []:
        name = (step.get("name") or "").lower()
        if CACHE_HIT_MARKER in name:
            hits += 1
            total += 1
        elif CACHE_MISS_MARKER in name:
            total += 1
    return hits, total


def load_runs(dir_: pathlib.Path) -> list[Run]:
    runs: list[Run] = []
    for path in sorted(pathlib.Path(dir_).glob("*.json")):
        data = json.loads(path.read_text())
        jobs: list[Job] = []
        for j in data.get("jobs", []):
            started = _parse_ts(j["started_at"])
            completed = _parse_ts(j["completed_at"])
            hits, total = _count_cache_steps(j.get("steps", []))
            jobs.append(Job(
                name=j["name"],
                duration_s=(completed - started).total_seconds(),
                cache_hits=hits,
                cache_total=total,
            ))
        runs.append(Run(jobs=jobs))
    return runs


def aggregate(runs: list[Run]) -> dict[str, JobStat]:
    by_name: dict[str, list[Job]] = {}
    for run in runs:
        for job in run.jobs:
            by_name.setdefault(job.name, []).append(job)
    stats: dict[str, JobStat] = {}
    for name, jobs in by_name.items():
        median = statistics.median(j.duration_s for j in jobs)
        total = sum(j.cache_total for j in jobs)
        hits = sum(j.cache_hits for j in jobs)
        pct = (hits / total * 100.0) if total else 0.0
        stats[name] = JobStat(median_duration_s=median, cache_hit_pct=pct)
    return stats


def _fmt_duration(seconds: float) -> str:
    minutes, secs = divmod(int(round(seconds)), 60)
    return f"{minutes}m {secs:02d}s"


def render_md(baseline: dict[str, JobStat], optimized: dict[str, JobStat]) -> str:
    names = sorted(set(baseline) | set(optimized))
    lines = [
        "# CI benchmark",
        "",
        "| Job | Baseline (median) | Optimized (median) | Δ | Cache hit % |",
        "|---|---:|---:|---:|---:|",
    ]
    total_base = 0.0
    total_opt = 0.0
    for name in names:
        b = baseline.get(name)
        o = optimized.get(name)
        bd = b.median_duration_s if b else 0.0
        od = o.median_duration_s if o else 0.0
        total_base += bd
        total_opt += od
        delta_pct = ((od - bd) / bd * 100.0) if bd else 0.0
        hit_pct = o.cache_hit_pct if o else 0.0
        lines.append(
            f"| {name} | {_fmt_duration(bd)} | {_fmt_duration(od)} "
            f"| {delta_pct:+.0f}% | {hit_pct:.0f}% |"
        )
    total_delta = ((total_opt - total_base) / total_base * 100.0) if total_base else 0.0
    lines.append(
        f"| **Total** | **{_fmt_duration(total_base)}** | "
        f"**{_fmt_duration(total_opt)}** | **{total_delta:+.0f}%** | |"
    )
    return "\n".join(lines) + "\n"


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--baseline", type=pathlib.Path, required=True)
    p.add_argument("--optimized", type=pathlib.Path, required=True)
    p.add_argument("--out-md", type=pathlib.Path, required=True)
    p.add_argument("--out-json", type=pathlib.Path, required=True)
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    baseline = aggregate(load_runs(args.baseline))
    optimized = aggregate(load_runs(args.optimized))
    args.out_md.write_text(render_md(baseline, optimized))
    args.out_json.write_text(json.dumps({
        "baseline": {n: dataclasses.asdict(s) for n, s in baseline.items()},
        "optimized": {n: dataclasses.asdict(s) for n, s in optimized.items()},
    }, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
