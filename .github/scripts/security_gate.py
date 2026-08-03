#!/usr/bin/env python3
"""Parse security scan results and fail if medium/high/critical findings exist.

Reads JSON output from Bandit, Semgrep, pip-audit, Trivy, and Gitleaks.
Produces a markdown summary table and exits non-zero if any qualifying
findings are present.

Usage:
    python3 security-gate.py <artifacts-dir>

The artifacts-dir should contain subdirectories named after each scanner's
artifact (bandit-results/, semgrep-results/, etc.), each containing the
scanner's JSON output file.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


SEVERITY_GATE = {"MEDIUM", "HIGH", "CRITICAL"}


def parse_bandit(path: Path) -> list[dict[str, str]]:
    """Parse Bandit JSON output for medium+ findings."""
    findings: list[dict[str, str]] = []
    json_file = path / "bandit-results.json"
    if not json_file.exists():
        return findings
    data = json.loads(json_file.read_text())
    for result in data.get("results", []):
        severity = result.get("issue_severity", "").upper()
        if severity in SEVERITY_GATE:
            findings.append({
                "tool": "Bandit",
                "severity": severity,
                "description": result.get("issue_text", "Unknown"),
                "location": f"{result.get('filename', '?')}:{result.get('line_number', '?')}",
            })
    return findings


def parse_semgrep(path: Path) -> list[dict[str, str]]:
    """Parse Semgrep JSON output for medium+ findings."""
    findings: list[dict[str, str]] = []
    json_file = path / "semgrep-results.json"
    if not json_file.exists():
        return findings
    data = json.loads(json_file.read_text())
    for result in data.get("results", []):
        # Semgrep uses INFO/WARNING/ERROR — map to our severity scale
        raw_severity = result.get("extra", {}).get("severity", "").upper()
        severity_map = {"INFO": "LOW", "WARNING": "MEDIUM", "ERROR": "HIGH"}
        severity = severity_map.get(raw_severity, raw_severity)
        if severity in SEVERITY_GATE:
            findings.append({
                "tool": "Semgrep",
                "severity": severity,
                "description": result.get("extra", {}).get("message", "Unknown"),
                "location": f"{result.get('path', '?')}:{result.get('start', {}).get('line', '?')}",
            })
    return findings


def parse_pip_audit(path: Path) -> list[dict[str, str]]:
    """Parse pip-audit JSON output for medium+ findings."""
    findings: list[dict[str, str]] = []
    json_file = path / "pip-audit-results.json"
    if not json_file.exists():
        return findings
    data = json.loads(json_file.read_text())
    # pip-audit JSON is a list of dependency objects
    deps = data if isinstance(data, list) else data.get("dependencies", [])
    for dep in deps:
        for vuln in dep.get("vulns", []):
            # pip-audit doesn't always include severity; treat all vulns as HIGH
            vuln_id = vuln.get("id", "Unknown")
            fix = vuln.get("fix_versions", [])
            fix_str = ", ".join(fix) if fix else "no fix available"
            findings.append({
                "tool": "pip-audit",
                "severity": "HIGH",
                "description": f"{vuln_id} in {dep.get('name', '?')} {dep.get('version', '?')} (fix: {fix_str})",
                "location": "pyproject.toml (dependency)",
            })
    return findings


def parse_trivy(path: Path) -> list[dict[str, str]]:
    """Parse Trivy JSON output for medium+ findings."""
    findings: list[dict[str, str]] = []
    json_file = path / "trivy-results.json"
    if not json_file.exists():
        return findings
    data = json.loads(json_file.read_text())
    for result_block in data.get("Results", []):
        for vuln in result_block.get("Vulnerabilities", []):
            severity = vuln.get("Severity", "").upper()
            if severity in SEVERITY_GATE:
                findings.append({
                    "tool": "Trivy",
                    "severity": severity,
                    "description": f"{vuln.get('VulnerabilityID', '?')}: {vuln.get('Title', 'Unknown')}",
                    "location": f"{vuln.get('PkgName', '?')} {vuln.get('InstalledVersion', '?')}",
                })
    return findings


def parse_gitleaks(path: Path) -> list[dict[str, str]]:
    """Parse Gitleaks JSON output."""
    findings: list[dict[str, str]] = []
    json_file = path / "gitleaks-results.json"
    if not json_file.exists():
        return findings
    text = json_file.read_text().strip()
    if not text:
        return findings
    data = json.loads(text)
    # Gitleaks JSON is a list of leak objects
    leaks = data if isinstance(data, list) else []
    for leak in leaks:
        findings.append({
            "tool": "Gitleaks",
            "severity": "CRITICAL",
            "description": f"Secret detected: {leak.get('RuleID', 'unknown rule')}",
            "location": f"{leak.get('File', '?')}:{leak.get('StartLine', '?')}",
        })
    return findings


def generate_summary(findings: list[dict[str, str]]) -> str:
    """Generate a markdown summary of findings."""
    if not findings:
        return (
            "## ✅ Security Gate — Passed\n\n"
            "No medium, high, or critical findings detected across all scanners.\n\n"
            "| Scanner | Status |\n"
            "|---------|--------|\n"
            "| Bandit (SAST) | ✅ Clean |\n"
            "| Semgrep (SAST) | ✅ Clean |\n"
            "| pip-audit (Dependencies) | ✅ Clean |\n"
            "| Trivy (Dependencies) | ✅ Clean |\n"
            "| Gitleaks (Secrets) | ✅ Clean |\n"
        )

    lines = [
        "## ❌ Security Gate — Failed\n",
        f"**{len(findings)} finding(s)** at medium severity or above.\n",
        "| Tool | Severity | Description | Location |",
        "|------|----------|-------------|----------|",
    ]
    for f in sorted(findings, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(x["severity"], 3)):
        lines.append(f"| {f['tool']} | {f['severity']} | {f['description']} | `{f['location']}` |")

    lines.append("")
    lines.append("Fix all findings above to pass the security gate.")
    return "\n".join(lines)


def main() -> int:
    """Entry point."""
    if len(sys.argv) != 2:  # noqa: PLR2004
        print(f"Usage: {sys.argv[0]} <artifacts-dir>", file=sys.stderr)
        return 2

    artifacts_dir = Path(sys.argv[1])
    if not artifacts_dir.is_dir():
        print(f"Error: {artifacts_dir} is not a directory", file=sys.stderr)
        return 2

    all_findings: list[dict[str, str]] = []
    all_findings.extend(parse_bandit(artifacts_dir / "bandit-results"))
    all_findings.extend(parse_semgrep(artifacts_dir / "semgrep-results"))
    all_findings.extend(parse_pip_audit(artifacts_dir / "pip-audit-results"))
    all_findings.extend(parse_trivy(artifacts_dir / "trivy-results"))
    all_findings.extend(parse_gitleaks(artifacts_dir / "gitleaks-results"))

    summary = generate_summary(all_findings)

    # Write to GitHub Actions job summary
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a") as fh:
            fh.write(summary)

    # Also print to stdout for logs
    print(summary)

    if all_findings:
        print(f"\n::error::Security gate failed: {len(all_findings)} finding(s) detected", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
