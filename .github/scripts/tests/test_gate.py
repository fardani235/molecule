"""Unit tests for gate.py."""
from __future__ import annotations

import json
import pathlib
import sys
import textwrap

# Make the sibling gate.py importable regardless of pytest CWD.
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import gate  # noqa: E402


FIXTURES = HERE / "fixtures"


def test_load_sarif_dir_reads_all_sarifs(tmp_path):
    (tmp_path / "bandit.sarif").write_text((FIXTURES / "bandit-med.sarif").read_text())
    (tmp_path / "gitleaks.sarif").write_text((FIXTURES / "gitleaks-hit.sarif").read_text())
    findings = gate.load_sarif_dir(tmp_path)
    assert len(findings) == 2
    scanners = {f.scanner for f in findings}
    assert scanners == {"bandit", "gitleaks"}


def test_bandit_warning_maps_to_medium(tmp_path):
    (tmp_path / "bandit.sarif").write_text((FIXTURES / "bandit-med.sarif").read_text())
    findings = gate.load_sarif_dir(tmp_path)
    assert findings[0].severity == "medium"


def test_gitleaks_finding_forced_to_critical(tmp_path):
    (tmp_path / "gitleaks.sarif").write_text((FIXTURES / "gitleaks-hit.sarif").read_text())
    findings = gate.load_sarif_dir(tmp_path)
    assert findings[0].severity == "critical"


def test_clean_sarif_produces_no_findings(tmp_path):
    (tmp_path / "bandit.sarif").write_text((FIXTURES / "bandit-clean.sarif").read_text())
    findings = gate.load_sarif_dir(tmp_path)
    assert findings == []


def test_evaluate_fails_on_medium_when_threshold_medium():
    findings = [gate.Finding("bandit", "B101", "medium", "x.py", 1, "m", None)]
    policy = {"threshold": "medium", "overrides": {}}
    result = gate.evaluate(findings, policy)
    assert result.failed is True
    assert result.counts["bandit"]["medium"] == 1


def test_evaluate_passes_on_low_when_threshold_medium():
    findings = [gate.Finding("bandit", "B101", "low", "x.py", 1, "m", None)]
    result = gate.evaluate(findings, {"threshold": "medium", "overrides": {}})
    assert result.failed is False


def test_evaluate_respects_per_scanner_override():
    # kics override says medium; a medium finding must fail.
    findings = [gate.Finding("kics", "Q1", "medium", "x.yml", 1, "m", None)]
    policy = {"threshold": "high", "overrides": {"kics": {"threshold": "medium"}}}
    result = gate.evaluate(findings, policy)
    assert result.failed is True


def test_apply_waivers_marks_matching_finding_waived(tmp_path):
    ignore = tmp_path / "trivy-ignore.txt"
    ignore.write_text(textwrap.dedent("""\
        # waived 2026-08-06 by ridwan — upstream fix pending; re-review 2027-02-06
        CVE-2025-9999
    """))
    finding = gate.Finding("trivy", "CVE-2025-9999", "high", "requirements.txt", 0, "m", None)
    unwaived, waived = gate.apply_waivers([finding], {"trivy": ignore})
    assert unwaived == []
    assert len(waived) == 1
    assert "ridwan" in waived[0].waiver


def test_apply_waivers_rejects_uncommented_entry(tmp_path):
    ignore = tmp_path / "trivy-ignore.txt"
    ignore.write_text("CVE-2025-9999\n")
    finding = gate.Finding("trivy", "CVE-2025-9999", "high", "r.txt", 0, "m", None)
    try:
        gate.apply_waivers([finding], {"trivy": ignore})
    except gate.WaiverFormatError as exc:
        assert "waiver comment" in str(exc)
    else:
        raise AssertionError("Expected WaiverFormatError")


def test_apply_waivers_rejects_expired_review_date(tmp_path):
    ignore = tmp_path / "trivy-ignore.txt"
    ignore.write_text(textwrap.dedent("""\
        # waived 2024-01-01 by ridwan — old; re-review 2024-06-01
        CVE-2025-9999
    """))
    finding = gate.Finding("trivy", "CVE-2025-9999", "high", "r.txt", 0, "m", None)
    try:
        gate.apply_waivers([finding], {"trivy": ignore})
    except gate.WaiverExpiredError as exc:
        assert "2024-06-01" in str(exc)
    else:
        raise AssertionError("Expected WaiverExpiredError")


def test_summary_md_contains_table_and_gate_outcome():
    findings = [gate.Finding("bandit", "B101", "medium", "x.py", 1, "m", None)]
    result = gate.evaluate(findings, {"threshold": "medium", "overrides": {}})
    assert "| Scanner" in result.summary_md
    assert "FAIL" in result.summary_md
