"""Unit tests for aggregate_sarif.

Run with: python -m pytest .security/scripts/test_aggregate_sarif.py -v
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"
SCRIPT = Path(__file__).parent / "aggregate_sarif.py"


def _run(tmp_path: Path, sarifs: list[str], allowlist: Path | None = None) -> tuple[int, Path]:
    sarif_dir = tmp_path / "sarif"
    sarif_dir.mkdir()
    for name in sarifs:
        (sarif_dir / name).write_bytes((FIXTURES / name).read_bytes())
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    cmd = [sys.executable, str(SCRIPT), "--sarif-dir", str(sarif_dir), "--out-dir", str(out_dir)]
    if allowlist is not None:
        cmd += ["--allowlist", str(allowlist)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, out_dir


def test_low_only_passes(tmp_path):
    code, out = _run(tmp_path, ["gitleaks-low.sarif"])
    assert code == 0
    assert (out / "security-report.md").exists()
    assert (out / "security-report.json").exists()
    assert (out / "security-combined.sarif").exists()


def test_medium_fails(tmp_path):
    code, _ = _run(tmp_path, ["bandit-med.sarif"])
    assert code == 1


def test_high_fails(tmp_path):
    code, _ = _run(tmp_path, ["pip-audit-high.sarif"])
    assert code == 1


def test_allowlisted_medium_passes(tmp_path):
    allow = tmp_path / "allowlist.yml"
    allow.write_text(
        "version: 1\n"
        "findings:\n"
        "  - id: 'bandit:B404'\n"
        "    reason: 'Reviewed — subprocess use is required'\n"
        "    owner: '@fardani235'\n"
        "    expires: '2099-01-01'\n"
    )
    code, _ = _run(tmp_path, ["bandit-med.sarif"], allow)
    assert code == 0


def test_expired_allowlist_reenters_gate(tmp_path):
    allow = tmp_path / "allowlist.yml"
    allow.write_text(
        "version: 1\n"
        "findings:\n"
        "  - id: 'bandit:B404'\n"
        "    reason: 'expired'\n"
        "    owner: '@fardani235'\n"
        "    expires: '2000-01-01'\n"
    )
    code, _ = _run(tmp_path, ["bandit-med.sarif"], allow)
    assert code == 1


def test_missing_allowlist_field_fails_with_2(tmp_path):
    allow = tmp_path / "bad.yml"
    allow.write_text(
        "version: 1\n"
        "findings:\n"
        "  - id: 'bandit:B404'\n"      # no reason/owner/expires
    )
    code, _ = _run(tmp_path, ["gitleaks-low.sarif"], allow)
    assert code == 2


def test_duplicate_allowlist_id_fails_with_2(tmp_path):
    allow = tmp_path / "dup.yml"
    allow.write_text(
        "version: 1\n"
        "findings:\n"
        "  - id: 'bandit:B404'\n"
        "    reason: 'a'\n    owner: '@x'\n    expires: '2099-01-01'\n"
        "  - id: 'bandit:B404'\n"
        "    reason: 'b'\n    owner: '@x'\n    expires: '2099-01-01'\n"
    )
    code, _ = _run(tmp_path, ["gitleaks-low.sarif"], allow)
    assert code == 2


def test_combined_sarif_merges_runs(tmp_path):
    code, out = _run(tmp_path, ["bandit-med.sarif", "pip-audit-high.sarif"])
    assert code == 1
    data = json.loads((out / "security-combined.sarif").read_text())
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 2


def test_report_json_schema(tmp_path):
    code, out = _run(tmp_path, ["bandit-med.sarif", "gitleaks-low.sarif"])
    assert code == 1
    report = json.loads((out / "security-report.json").read_text())
    assert report["schema_version"] == 1
    assert "totals" in report and "by_scanner" in report and "findings" in report
    assert report["totals"]["MEDIUM"] >= 1
