"""Unit tests for render_timing.

Run with: python -m pytest .security/scripts/test_render_timing.py -v
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"
SCRIPT = Path(__file__).parent / "render_timing.py"


def _run(tmp_path: Path, baseline: Path | None) -> tuple[int, Path]:
    out = tmp_path / "out"
    out.mkdir()
    cmd = [
        sys.executable, str(SCRIPT),
        "--jobs-json", str(FIXTURES / "gh_jobs.json"),
        "--out-dir", str(out),
        "--run-id", "42",
        "--commit", "deadbeef",
        "--event", "pull_request",
        "--workflow", "security.yml",
    ]
    if baseline is not None:
        cmd += ["--baseline", str(baseline)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, out


def test_writes_timing_json_and_md(tmp_path):
    code, out = _run(tmp_path, FIXTURES / "baseline.json")
    assert code == 0
    assert (out / "timing.json").exists()
    assert (out / "timing.md").exists()


def test_timing_json_schema(tmp_path):
    _, out = _run(tmp_path, FIXTURES / "baseline.json")
    data = json.loads((out / "timing.json").read_text())
    assert data["schema_version"] == 1
    assert data["run_id"] == 42
    assert data["commit"] == "deadbeef"
    assert data["workflow"] == "security.yml"
    assert isinstance(data["total_wallclock_s"], int)
    assert isinstance(data["jobs"], list)
    assert data["jobs"][0]["duration_s"] > 0


def test_markdown_has_delta_row(tmp_path):
    _, out = _run(tmp_path, FIXTURES / "baseline.json")
    md = (out / "timing.md").read_text()
    assert "CI Timing vs. baseline" in md
    assert "security.yml total" in md
    assert "%" in md


def test_missing_baseline_is_ok(tmp_path):
    code, out = _run(tmp_path, None)
    assert code == 0
    md = (out / "timing.md").read_text()
    assert "no baseline" in md.lower()
