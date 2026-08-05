#!/usr/bin/env python3
"""Evaluate security scan reports and fail on MEDIUM/HIGH/CRITICAL findings.

Usage: python tools/security-gate.py <reports_dir>
Exit code 1 if the gate fails, 0 otherwise. Writes a Markdown summary to
$GITHUB_STEP_SUMMARY when set.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

BLOCKING = ("MEDIUM", "HIGH", "CRITICAL")
_EMPTY = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}


def _load(path: Path):
    if not path.exists():
        return None
    return json.loads(path.read_text() or "null")


def count_bandit(path: Path) -> dict[str, int]:
    counts = dict(_EMPTY)
    data = _load(path)
    if not data:
        return counts
    for result in data.get("results", []):
        sev = (result.get("issue_severity") or "").upper()
        if sev in counts:
            counts[sev] += 1
    return counts


def count_trivy(path: Path) -> dict[str, int]:
    counts = dict(_EMPTY)
    data = _load(path)
    if not data:
        return counts
    for result in data.get("Results", []) or []:
        for vuln in result.get("Vulnerabilities", []) or []:
            sev = (vuln.get("Severity") or "").upper()
            if sev in counts:
                counts[sev] += 1
    return counts


def count_gitleaks(path: Path) -> int:
    data = _load(path)
    if not data:
        return 0
    return len(data)


def evaluate(reports_dir: Path) -> tuple[bool, str]:
    tools: dict[str, dict[str, int]] = {}
    tools["bandit"] = count_bandit(reports_dir / "bandit.json")
    tools["trivy-deps"] = count_trivy(reports_dir / "trivy-deps.json")
    tools["trivy-artifact"] = count_trivy(reports_dir / "trivy-artifact.json")
    secrets = count_gitleaks(reports_dir / "gitleaks.json")

    failed = secrets > 0 or any(
        counts[s] > 0 for counts in tools.values() for s in BLOCKING
    )

    lines = ["## Security Gate", "", "| Tool | LOW | MEDIUM | HIGH | CRITICAL |", "|---|---|---|---|---|"]
    for name, c in tools.items():
        lines.append(f"| {name} | {c['LOW']} | {c['MEDIUM']} | {c['HIGH']} | {c['CRITICAL']} |")
    lines.append(f"| gitleaks (secrets) | - | - | - | {secrets} |")
    lines.append("")
    lines.append(f"**Result: {'❌ FAILED' if failed else '✅ PASSED'}** "
                 "(blocks on MEDIUM/HIGH/CRITICAL or any secret)")
    summary = "\n".join(lines)
    return failed, summary


def main() -> int:
    reports_dir = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    failed, summary = evaluate(reports_dir)
    print(summary)
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write(summary + "\n")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
