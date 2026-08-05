"""Capture CI timing baseline from the last N successful main-branch runs.

Runs once, manually, during rollout. Requires `gh` CLI authenticated for the
repo. The output file `.security/baseline.json` is committed as part of the
rollout PR — see docs/security/setup.md.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import date
from pathlib import Path
from statistics import mean


def _gh_json(*args: str) -> dict | list:
    proc = subprocess.run(["gh", "api", *args], capture_output=True, text=True, check=True)
    return json.loads(proc.stdout)


def _duration_s(run: dict) -> int:
    from datetime import datetime
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    return int((datetime.strptime(run["updated_at"], fmt)
                - datetime.strptime(run["run_started_at"], fmt)).total_seconds())


def capture_workflow_avg(repo: str, workflow: str, n: int) -> dict:
    data = _gh_json(f"/repos/{repo}/actions/workflows/{workflow}/runs"
                    f"?branch=main&status=success&per_page={n}")
    runs = data.get("workflow_runs", [])[:n]
    if not runs:
        return {"avg_total_s": 0, "samples": 0}
    durations = [_duration_s(r) for r in runs]
    return {"avg_total_s": int(mean(durations)), "samples": len(durations),
            "run_ids": [r["id"] for r in runs]}


def capture_security_cold(repo: str, run_id: int) -> dict:
    run = _gh_json(f"/repos/{repo}/actions/runs/{run_id}")
    return {"cold_total_s": _duration_s(run), "run_id": run_id,
            "warm_total_s_estimate": None}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--workflow", default="tox.yml")
    ap.add_argument("--n", type=int, default=5)
    ap.add_argument("--security-run-id", type=int, required=True,
                    help="Run ID of the first cold security.yml run.")
    ap.add_argument("--out", type=Path, default=Path(".security/baseline.json"))
    args = ap.parse_args(argv)

    baseline = {
        "schema_version": 1,
        "captured_at": date.today().isoformat(),
        "workflows": {
            args.workflow: capture_workflow_avg(args.repo, args.workflow, args.n),
            "security.yml": capture_security_cold(args.repo, args.security_run_id),
        },
    }
    args.out.write_text(json.dumps(baseline, indent=2))
    print(f"wrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
