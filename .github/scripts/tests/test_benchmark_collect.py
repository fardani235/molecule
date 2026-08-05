"""Unit tests for benchmark_collect.py."""
from __future__ import annotations

import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import benchmark_collect as bc  # noqa: E402

FIXTURES = HERE / "fixtures"


def _write_run(dir_: pathlib.Path, i: int) -> None:
    (dir_ / f"run-{i}.json").write_text((FIXTURES / "runs-jobs-sample.json").read_text())


def test_load_runs_reads_all_json(tmp_path):
    _write_run(tmp_path, 1)
    _write_run(tmp_path, 2)
    runs = bc.load_runs(tmp_path)
    assert len(runs) == 2
    assert {j.name for j in runs[0].jobs} == {"sast", "sca"}


def test_job_duration_computed_from_timestamps(tmp_path):
    _write_run(tmp_path, 1)
    runs = bc.load_runs(tmp_path)
    sast = next(j for j in runs[0].jobs if j.name == "sast")
    # 02:00:00 -> 02:03:40 is 220 seconds.
    assert sast.duration_s == 220


def test_cache_hits_detected_from_step_names(tmp_path):
    _write_run(tmp_path, 1)
    runs = bc.load_runs(tmp_path)
    sast = next(j for j in runs[0].jobs if j.name == "sast")
    sca = next(j for j in runs[0].jobs if j.name == "sca")
    assert sast.cache_hits == 1 and sast.cache_total == 1
    assert sca.cache_hits == 0 and sca.cache_total == 1


def test_aggregate_computes_median(tmp_path):
    _write_run(tmp_path, 1)
    _write_run(tmp_path, 2)
    _write_run(tmp_path, 3)
    stats = bc.aggregate(bc.load_runs(tmp_path))
    assert stats["sast"].median_duration_s == 220
    assert stats["sast"].cache_hit_pct == 100.0
    assert stats["sca"].cache_hit_pct == 0.0


def test_render_md_shows_delta(tmp_path):
    _write_run(tmp_path, 1)
    baseline = bc.aggregate(bc.load_runs(tmp_path))
    # Force optimized to half duration for comparison.
    optimized = {
        name: bc.JobStat(median_duration_s=s.median_duration_s / 2,
                         cache_hit_pct=100.0)
        for name, s in baseline.items()
    }
    md = bc.render_md(baseline, optimized)
    assert "-50%" in md
    assert "| sast" in md
