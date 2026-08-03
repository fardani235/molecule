#!/usr/bin/env python3
"""Aggregate SARIF outputs from all scanners and enforce the Medium+ gate.

Reads a glob of SARIF files, normalizes severities across scanners, applies
waivers from waivers.yaml, prints a per-scanner + total table to stdout AND
$GITHUB_STEP_SUMMARY, writes a consolidated report.json, and exits:

  0 - no un-waived Medium+ findings (or --mode warn)
  1 - one or more un-waived Medium+ findings in --mode enforce
  2 - internal error (bad SARIF, malformed waivers file)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    print(
        "gate.py requires PyYAML. Install with: uv pip install pyyaml "
        "(or: pip install pyyaml)",
        file=sys.stderr,
    )
    raise

SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Info")
BLOCKING = {"Critical", "High", "Medium"}

# SARIF `level` -> normalized severity, for scanners that do not emit a
# numeric security-severity property.
_LEVEL_MAP = {"error": "High", "warning": "Medium", "note": "Low"}
_LEVEL_SCANNERS = ("semgrep", "bandit", "trivy")


@dataclass(frozen=True)
class Finding:
    scanner: str
    rule_id: str
    severity: str
    file: str
    line: int | None
    message: str

    @property
    def waiver_id(self) -> str:
        return f"{self.scanner}:{self.rule_id}"


def _scanner_from_sarif(sarif: dict[str, Any]) -> str:
    """Detect the scanner name from the tool driver."""
    try:
        name = sarif["runs"][0]["tool"]["driver"]["name"].lower()
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError(f"cannot detect scanner name from SARIF: {exc}") from exc
    if "bandit" in name:
        return "bandit"
    if "semgrep" in name:
        return "semgrep"
    if "trivy" in name:
        return "trivy"
    if "gitleaks" in name:
        return "gitleaks"
    if "pip-audit" in name or "pip_audit" in name:
        return "pip-audit"
    return name  # unknown; still pass through


def _cvss_bucket(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "Info"


def normalize_severity(scanner: str, entry: dict[str, Any]) -> str:
    """Map a scanner's native severity to Critical|High|Medium|Low|Info."""
    if scanner == "gitleaks":
        # A leaked credential is always treated as the worst case.
        return "Critical"

    props = entry.get("properties") or {}
    raw_score = props.get("security-severity")
    if raw_score is not None:
        try:
            return _cvss_bucket(float(raw_score))
        except (TypeError, ValueError):
            pass

    level = (entry.get("level") or "").lower()
    if scanner in _LEVEL_SCANNERS:
        return _LEVEL_MAP.get(level, "Low")

    return "Low"


def _extract_location(result: dict[str, Any]) -> tuple[str, int | None]:
    locs = result.get("locations") or []
    if not locs:
        return "", None
    phys = locs[0].get("physicalLocation") or {}
    art = (phys.get("artifactLocation") or {}).get("uri", "")
    region = phys.get("region") or {}
    return art, region.get("startLine")


def collect_findings(sarif_paths: list[str]) -> list[Finding]:
    """Parse every SARIF file and return a flat list of Findings."""
    out: list[Finding] = []
    for path in sarif_paths:
        try:
            text = Path(path).read_text(encoding="utf-8")
            sarif = json.loads(text)
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot parse SARIF {path}: {exc}") from exc
        scanner = _scanner_from_sarif(sarif)
        for run in sarif.get("runs", []):
            for result in run.get("results", []):
                sev = normalize_severity(scanner, result)
                fname, line = _extract_location(result)
                out.append(Finding(
                    scanner=scanner,
                    rule_id=result.get("ruleId", "UNKNOWN"),
                    severity=sev,
                    file=fname,
                    line=line,
                    message=(result.get("message") or {}).get("text", ""),
                ))
    return out


def load_waivers(path: str) -> list[dict[str, Any]]:
    """Load waivers.yaml; missing file returns []."""
    p = Path(path)
    if not p.exists():
        return []
    try:
        doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"malformed waivers file {path}: {exc}") from exc
    waivers = doc.get("waivers", [])
    if not isinstance(waivers, list):
        raise ValueError(f"waivers file {path} 'waivers' must be a list")
    for w in waivers:
        if not isinstance(w, dict):
            raise ValueError(f"waiver entry must be a mapping, got: {w!r}")
        for required in ("id", "reason", "added_by", "added_on", "expires_on"):
            if required not in w:
                raise ValueError(f"waiver missing '{required}': {w}")
    return waivers


def is_expired(waiver: dict[str, Any], today: date) -> bool:
    """Return True when the waiver's expires_on is before today."""
    exp = waiver.get("expires_on")
    if isinstance(exp, date):
        return exp < today
    if isinstance(exp, str):
        return datetime.strptime(exp, "%Y-%m-%d").date() < today
    return True  # missing/invalid -> treat as expired


def _apply_waivers(
    findings: list[Finding],
    waivers: list[dict[str, Any]],
    today: date,
    scheduled: bool,
) -> tuple[list[Finding], list[dict[str, Any]]]:
    """Return (still_blocking, expired_waivers_hit)."""
    active_ids = {w["id"] for w in waivers if not is_expired(w, today)}
    expired = [w for w in waivers if is_expired(w, today)]
    remaining = [f for f in findings if f.waiver_id not in active_ids]
    # On scheduled runs, expired waivers themselves are a failure signal
    # even if the finding they waived is gone.
    return remaining, (expired if scheduled else [])


def _render_summary(findings: list[Finding]) -> str:
    counts: dict[str, dict[str, int]] = {}
    for f in findings:
        counts.setdefault(f.scanner, {s: 0 for s in SEVERITY_ORDER})
        counts[f.scanner][f.severity] += 1
    lines = ["| Scanner | Critical | High | Medium | Low | Info |",
             "|---|---|---|---|---|---|"]
    for scanner in sorted(counts):
        c = counts[scanner]
        lines.append(
            f"| {scanner} | {c['Critical']} | {c['High']} | "
            f"{c['Medium']} | {c['Low']} | {c['Info']} |"
        )
    if not counts:
        lines.append("| _(no findings)_ | 0 | 0 | 0 | 0 | 0 |")
    return "\n".join(lines)


def _write_step_summary(text: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(text + "\n")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("sarif", nargs="+", help="SARIF files to aggregate")
    p.add_argument("--waivers", default=".github/security/waivers.yaml")
    p.add_argument("--mode", choices=("enforce", "warn"), default="enforce")
    p.add_argument("--output", default="report.json")
    p.add_argument("--scheduled", action="store_true",
                   help="Treat this as a scheduled run (fail on expired waivers).")
    args = p.parse_args(argv)

    try:
        findings = collect_findings(args.sarif)
        waivers = load_waivers(args.waivers)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    remaining, expired_hits = _apply_waivers(
        findings, waivers, today=date.today(), scheduled=args.scheduled,
    )
    blocking = [f for f in remaining if f.severity in BLOCKING]

    table = _render_summary(findings)
    print(table)
    _write_step_summary(f"## Security scan summary\n\n{table}\n")

    Path(args.output).write_text(json.dumps({
        "mode": args.mode,
        "total": len(findings),
        "blocking": len(blocking),
        "expired_waivers": [w["id"] for w in expired_hits],
        "findings": [asdict(f) for f in findings],
    }, indent=2), encoding="utf-8")

    if args.mode == "warn":
        print(f"warn-mode: {len(blocking)} blocking finding(s) - not failing.")
        return 0
    if blocking:
        print(f"FAIL: {len(blocking)} un-waived Medium+ finding(s).", file=sys.stderr)
        return 1
    if expired_hits:
        print(f"FAIL: {len(expired_hits)} expired waiver(s).", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
