"""Unit tests for gate.py severity aggregator."""
from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from gate import (
    Finding,
    collect_findings,
    is_expired,
    load_waivers,
    main,
    normalize_severity,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_normalize_bandit_high():
    entry = {"level": "error", "properties": {"security-severity": "8.0"}}
    assert normalize_severity("bandit", entry) == "High"


def test_normalize_semgrep_warning_is_medium():
    entry = {"level": "warning"}
    assert normalize_severity("semgrep", entry) == "Medium"


def test_normalize_trivy_unknown_maps_to_low():
    entry = {"properties": {"security-severity": None}}
    assert normalize_severity("trivy", entry) == "Low"


def test_gitleaks_any_finding_is_critical():
    entry = {}
    assert normalize_severity("gitleaks", entry) == "Critical"


def test_pip_audit_cvss_mapping():
    entry = {"properties": {"security-severity": "9.5"}}
    assert normalize_severity("pip-audit", entry) == "Critical"
    entry["properties"]["security-severity"] = "7.5"
    assert normalize_severity("pip-audit", entry) == "High"
    entry["properties"]["security-severity"] = "5.0"
    assert normalize_severity("pip-audit", entry) == "Medium"
    entry["properties"]["security-severity"] = "1.0"
    assert normalize_severity("pip-audit", entry) == "Low"


def test_collect_findings_from_bandit_fixture():
    findings = collect_findings([str(FIXTURES / "bandit_high.sarif")])
    assert len(findings) == 1
    assert findings[0].severity == "High"
    assert findings[0].scanner == "bandit"


def test_malformed_sarif_raises():
    with pytest.raises(ValueError):
        collect_findings([str(FIXTURES / "malformed.sarif")])


def test_waiver_expiry():
    w = {"id": "x", "expires_on": "2020-01-01"}
    assert is_expired(w, date(2026, 1, 1)) is True
    w["expires_on"] = "2099-01-01"
    assert is_expired(w, date(2026, 1, 1)) is False


def test_main_exits_1_on_medium_plus_in_enforce(tmp_path, capsys):
    exit_code = main([
        str(FIXTURES / "bandit_high.sarif"),
        "--mode", "enforce",
        "--output", str(tmp_path / "report.json"),
        "--waivers", str(FIXTURES / ".nonexistent_waivers.yaml"),  # missing = empty
    ])
    assert exit_code == 1


def test_main_exits_0_when_only_low(tmp_path):
    exit_code = main([
        str(FIXTURES / "trivy_low.sarif"),
        "--mode", "enforce",
        "--output", str(tmp_path / "report.json"),
    ])
    assert exit_code == 0


def test_warn_mode_never_fails(tmp_path):
    exit_code = main([
        str(FIXTURES / "bandit_high.sarif"),
        "--mode", "warn",
        "--output", str(tmp_path / "report.json"),
    ])
    assert exit_code == 0
