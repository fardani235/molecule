"""Tests for security-gate.py."""

from __future__ import annotations

import json
from pathlib import Path

from security_gate import (
    generate_summary,
    parse_bandit,
    parse_gitleaks,
    parse_pip_audit,
    parse_semgrep,
    parse_trivy,
)


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


def test_parse_bandit_medium_finding(tmp_path: Path) -> None:
    scanner_dir = tmp_path / "bandit-results"
    _write_json(scanner_dir / "bandit-results.json", {
        "results": [
            {
                "issue_severity": "MEDIUM",
                "issue_text": "Use of insecure MD5 hash",
                "filename": "src/molecule/util.py",
                "line_number": 42,
            },
            {
                "issue_severity": "LOW",
                "issue_text": "Consider using a constant",
                "filename": "src/molecule/config.py",
                "line_number": 10,
            },
        ],
    })
    findings = parse_bandit(scanner_dir)
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["tool"] == "Bandit"


def test_parse_bandit_missing_file(tmp_path: Path) -> None:
    findings = parse_bandit(tmp_path / "bandit-results")
    assert findings == []


def test_parse_semgrep_warning_maps_to_medium(tmp_path: Path) -> None:
    scanner_dir = tmp_path / "semgrep-results"
    _write_json(scanner_dir / "semgrep-results.json", {
        "results": [
            {
                "extra": {"severity": "WARNING", "message": "Potential injection"},
                "path": "src/molecule/shell.py",
                "start": {"line": 15},
            },
        ],
    })
    findings = parse_semgrep(scanner_dir)
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"


def test_parse_pip_audit_vuln(tmp_path: Path) -> None:
    scanner_dir = tmp_path / "pip-audit-results"
    _write_json(scanner_dir / "pip-audit-results.json", [
        {
            "name": "jinja2",
            "version": "3.1.2",
            "vulns": [{"id": "CVE-2024-1234", "fix_versions": ["3.1.3"]}],
        },
    ])
    findings = parse_pip_audit(scanner_dir)
    assert len(findings) == 1
    assert "CVE-2024-1234" in findings[0]["description"]
    assert findings[0]["severity"] == "HIGH"


def test_parse_trivy_critical(tmp_path: Path) -> None:
    scanner_dir = tmp_path / "trivy-results"
    _write_json(scanner_dir / "trivy-results.json", {
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "Severity": "CRITICAL",
                        "VulnerabilityID": "CVE-2024-9999",
                        "Title": "RCE in foo",
                        "PkgName": "foo",
                        "InstalledVersion": "1.0.0",
                    },
                    {
                        "Severity": "LOW",
                        "VulnerabilityID": "CVE-2024-0001",
                        "Title": "Info leak",
                        "PkgName": "bar",
                        "InstalledVersion": "2.0.0",
                    },
                ],
            },
        ],
    })
    findings = parse_trivy(scanner_dir)
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"


def test_parse_gitleaks_secret(tmp_path: Path) -> None:
    scanner_dir = tmp_path / "gitleaks-results"
    _write_json(scanner_dir / "gitleaks-results.json", [
        {"RuleID": "aws-access-key", "File": ".env", "StartLine": 3},
    ])
    findings = parse_gitleaks(scanner_dir)
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"


def test_parse_gitleaks_empty(tmp_path: Path) -> None:
    scanner_dir = tmp_path / "gitleaks-results"
    scanner_dir.mkdir(parents=True)
    (scanner_dir / "gitleaks-results.json").write_text("")
    findings = parse_gitleaks(scanner_dir)
    assert findings == []


def test_generate_summary_no_findings() -> None:
    summary = generate_summary([])
    assert "✅" in summary
    assert "Passed" in summary


def test_generate_summary_with_findings() -> None:
    findings = [
        {
            "tool": "Bandit",
            "severity": "HIGH",
            "description": "Hardcoded password",
            "location": "src/foo.py:10",
        },
    ]
    summary = generate_summary(findings)
    assert "❌" in summary
    assert "Failed" in summary
    assert "1 finding(s)" in summary
    assert "Hardcoded password" in summary
