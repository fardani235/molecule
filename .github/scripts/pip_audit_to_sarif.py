#!/usr/bin/env python3
"""Convert pip-audit JSON output to SARIF 2.1.0.

pip-audit does not emit SARIF natively; this converter maps its JSON
findings to a minimal SARIF document the gate script and GitHub Code
Scanning can consume.

Usage: python3 pip_audit_to_sarif.py <pip-audit.json>   # prints SARIF to stdout
"""
from __future__ import annotations

import json
import sys


def convert(data: dict) -> dict:
    rules: list[dict] = []
    results: list[dict] = []
    seen_rules: set[str] = set()
    for dep in data.get("dependencies", []) or []:
        name = dep.get("name", "unknown")
        version = dep.get("version", "unknown")
        for vuln in dep.get("vulns", []) or []:
            rule_id = vuln.get("id", "PIP-AUDIT-UNKNOWN")
            description = vuln.get("description", "")
            aliases = vuln.get("aliases", []) or []
            # Prefer CVE alias as SARIF rule id if present — matches Trivy.
            display_id = next((a for a in aliases if a.startswith("CVE-")), rule_id)
            severity_score = _severity_score(vuln)
            if display_id not in seen_rules:
                rules.append({
                    "id": display_id,
                    "name": display_id,
                    "shortDescription": {"text": rule_id},
                    "fullDescription": {"text": description or rule_id},
                    "helpUri": _help_uri(vuln),
                    "properties": {
                        "security-severity": f"{severity_score:.1f}",
                    },
                })
                seen_rules.add(display_id)
            results.append({
                "ruleId": display_id,
                "level": _sarif_level(severity_score),
                "message": {
                    "text": f"{name} {version}: {description or rule_id}",
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "pyproject.toml"},
                            "region": {"startLine": 1},
                        }
                    }
                ],
                "properties": {
                    "package": name,
                    "version": version,
                    "security-severity": f"{severity_score:.1f}",
                },
            })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pip-audit",
                        "informationUri": "https://pypi.org/project/pip-audit/",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def _severity_score(vuln: dict) -> float:
    # pip-audit doesn't always carry CVSS. Look in vuln["severity"] or default to medium.
    sev = (vuln.get("severity") or "").lower()
    return {
        "critical": 9.5,
        "high": 8.0,
        "medium": 5.5,
        "moderate": 5.5,
        "low": 3.0,
    }.get(sev, 5.5)


def _sarif_level(score: float) -> str:
    if score >= 7.0:
        return "error"
    if score >= 4.0:
        return "warning"
    return "note"


def _help_uri(vuln: dict) -> str:
    aliases = vuln.get("aliases", []) or []
    cve = next((a for a in aliases if a.startswith("CVE-")), None)
    if cve:
        return f"https://nvd.nist.gov/vuln/detail/{cve}"
    ghsa = next((a for a in aliases if a.startswith("GHSA-")), None)
    if ghsa:
        return f"https://github.com/advisories/{ghsa}"
    return "https://pypi.org/project/pip-audit/"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    path = argv[1]
    try:
        data = json.loads(open(path).read())
    except FileNotFoundError:
        # No findings file → emit an empty valid SARIF so upload-sarif is happy.
        data = {}
    json.dump(convert(data), sys.stdout, indent=2)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main(sys.argv))
