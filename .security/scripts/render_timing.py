"""Render CI timing artifact from `gh api` jobs JSON + baseline.

Produces `timing.json` (schema v1) and `timing.md` (comparison table).
Never fails — the timing job is informational.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path


def _duration_s(started: str, completed: str) -> int:
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    s = datetime.strptime(started, fmt)
    c = datetime.strptime(completed, fmt)
    return max(0, int((c - s).total_seconds()))


def _fmt_dur(seconds: int) -> str:
    m, s = divmod(seconds, 60)
    return f"{m}m{s:02d}s"


def _pct_delta(baseline: int | None, current: int) -> str:
    if not baseline:
        return "—"
    delta = (current - baseline) / baseline * 100
    sign = "−" if delta < 0 else "+"
    return f"{sign}{abs(delta):.1f}%"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs-json", required=True, type=Path)
    ap.add_argument("--out-dir", required=True, type=Path)
    ap.add_argument("--run-id", required=True, type=int)
    ap.add_argument("--commit", required=True)
    ap.add_argument("--event", required=True)
    ap.add_argument("--workflow", required=True)
    ap.add_argument("--baseline", type=Path, default=None)
    args = ap.parse_args(argv)

    data = json.loads(args.jobs_json.read_text())
    jobs_out = []
    total = 0
    for job in data.get("jobs", []):
        started, completed = job.get("started_at"), job.get("completed_at")
        if not started or not completed:
            continue
        dur = _duration_s(started, completed)
        jobs_out.append({"name": job["name"], "duration_s": dur,
                         "conclusion": job.get("conclusion")})
        total = max(total, dur) if job["name"] != "security-gate" else total + dur
    # Wall-clock ≈ max fan-out job + gate.
    fanout = [j["duration_s"] for j in jobs_out if j["name"] != "security-gate"]
    gate = [j["duration_s"] for j in jobs_out if j["name"] == "security-gate"]
    total = (max(fanout) if fanout else 0) + sum(gate)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "run_id": args.run_id,
        "workflow": args.workflow,
        "commit": args.commit,
        "event": args.event,
        "total_wallclock_s": total,
        "jobs": jobs_out,
    }
    (args.out_dir / "timing.json").write_text(json.dumps(payload, indent=2))

    lines = ["## CI Timing vs. baseline", "",
             "| Metric | Baseline | This run | Δ |",
             "|---|---:|---:|---:|"]
    if args.baseline and args.baseline.exists():
        base = json.loads(args.baseline.read_text())
        wf = base.get("workflows", {}).get(args.workflow, {})
        base_s = wf.get("warm_total_s_estimate") or wf.get("cold_total_s") or 0
        lines.append(f"| {args.workflow} total | {_fmt_dur(base_s)} "
                     f"| {_fmt_dur(total)} | {_pct_delta(base_s, total)} |")
        tox = base.get("workflows", {}).get("tox.yml", {})
        tox_base = tox.get("avg_total_s") or 0
        if tox_base:
            lines.append(f"| tox.yml total (baseline avg) | {_fmt_dur(tox_base)} | — | — |")
    else:
        lines.append(f"| {args.workflow} total | (no baseline) | {_fmt_dur(total)} | — |")

    lines += ["", "### Per-job", "", "| Job | Duration |", "|---|---:|"]
    for j in jobs_out:
        lines.append(f"| {j['name']} | {_fmt_dur(j['duration_s'])} |")
    (args.out_dir / "timing.md").write_text("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
