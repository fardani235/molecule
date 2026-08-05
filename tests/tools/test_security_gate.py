import json
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "security_gate", Path(__file__).parent.parent.parent / "tools" / "security-gate.py"
)
sg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sg)


def test_count_bandit_medium_high(tmp_path):
    report = {"results": [
        {"issue_severity": "LOW"},
        {"issue_severity": "MEDIUM"},
        {"issue_severity": "HIGH"},
    ]}
    p = tmp_path / "bandit.json"
    p.write_text(json.dumps(report))
    counts = sg.count_bandit(p)
    assert counts == {"LOW": 1, "MEDIUM": 1, "HIGH": 1, "CRITICAL": 0}


def test_count_trivy_severities(tmp_path):
    report = {"Results": [
        {"Vulnerabilities": [
            {"Severity": "HIGH"}, {"Severity": "CRITICAL"}, {"Severity": "LOW"},
        ]}
    ]}
    p = tmp_path / "trivy.json"
    p.write_text(json.dumps(report))
    counts = sg.count_trivy(p)
    assert counts["HIGH"] == 1
    assert counts["CRITICAL"] == 1
    assert counts["LOW"] == 1


def test_count_gitleaks(tmp_path):
    p = tmp_path / "gitleaks.json"
    p.write_text(json.dumps([{"RuleID": "x"}, {"RuleID": "y"}]))
    assert sg.count_gitleaks(p) == 2


def test_evaluate_fails_on_high(tmp_path):
    (tmp_path / "bandit.json").write_text(json.dumps({"results": [{"issue_severity": "HIGH"}]}))
    failed, summary = sg.evaluate(tmp_path)
    assert failed is True
    assert "HIGH" in summary


def test_evaluate_passes_when_clean(tmp_path):
    (tmp_path / "bandit.json").write_text(json.dumps({"results": []}))
    (tmp_path / "gitleaks.json").write_text(json.dumps([]))
    failed, summary = sg.evaluate(tmp_path)
    assert failed is False
