"""Aggregate per-scanner SARIF files, apply the allowlist, enforce the gate.

Exit codes:
    0 — no unlisted MEDIUM/HIGH/CRITICAL findings.
    1 — at least one unlisted MEDIUM+ finding.
    2 — configuration error (malformed allowlist, duplicate id, missing field).
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any

import yaml

BLOCKING = {"CRITICAL", "HIGH", "MEDIUM"}
LEVEL_TO_SEVERITY = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "LOW"}
REQUIRED_ALLOW_FIELDS = ("id", "reason", "owner", "expires")


@dataclass
class Finding:
    scanner: str
    rule_id: str
    severity: str
    file: str
    line: int
    message: str
    fingerprint: str

    def key(self) -> str:
        return f"{self.scanner}:{self.rule_id}"


@dataclass
class AllowEntry:
    id: str
    reason: str
    owner: str
    expires: date
    package: str | None = None
    path: str | None = None
    ticket: str | None = None


def _severity_from_result(result: dict[str, Any], rule: dict[str, Any] | None) -> str:
    props = (result.get("properties") or {}) | ((rule or {}).get("properties") or {})
    sev = props.get("security-severity")
    if sev is not None:
        try:
            score = float(sev)
        except ValueError:
            score = 0.0
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        return "LOW"
    level = (result.get("level") or "warning").lower()
    return LEVEL_TO_SEVERITY.get(level, "MEDIUM")


def _location(result: dict[str, Any]) -> tuple[str, int]:
    locs = result.get("locations") or []
    if not locs:
        return ("", 0)
    phys = locs[0].get("physicalLocation") or {}
    uri = (phys.get("artifactLocation") or {}).get("uri", "")
    region = phys.get("region") or {}
    return (uri, int(region.get("startLine", 0) or 0))


def load_sarif(path: Path) -> tuple[str, list[Finding], dict[str, Any]]:
    data = json.loads(path.read_text())
    findings: list[Finding] = []
    scanner = path.stem.replace("-", "_")
    for run in data.get("runs", []):
        driver = ((run.get("tool") or {}).get("driver") or {})
        name = (driver.get("name") or scanner).lower()
        rules_by_id = {r.get("id"): r for r in (driver.get("rules") or [])}
        for result in run.get("results", []):
            rule_id = result.get("ruleId") or ""
            rule = rules_by_id.get(rule_id)
            severity = _severity_from_result(result, rule)
            uri, line = _location(result)
            msg = ((result.get("message") or {}).get("text") or "").strip()
            fp = f"{name}:{rule_id}:{uri}:{line}"
            findings.append(Finding(name, rule_id, severity, uri, line, msg, fp))
    return scanner, findings, data


def load_allowlist(path: Path | None) -> list[AllowEntry]:
    if path is None or not path.exists():
        return []
    raw = yaml.safe_load(path.read_text()) or {}
    findings = raw.get("findings") or []
    if not isinstance(findings, list):
        raise SystemExit(_die("allowlist: `findings` must be a list"))
    entries: list[AllowEntry] = []
    seen_ids: set[str] = set()
    for i, item in enumerate(findings):
        if not isinstance(item, dict):
            raise SystemExit(_die(f"allowlist[{i}]: entry must be a mapping"))
        missing = [f for f in REQUIRED_ALLOW_FIELDS if not item.get(f)]
        if missing:
            raise SystemExit(_die(f"allowlist[{i}]: missing required fields {missing}"))
        if item["id"] in seen_ids:
            raise SystemExit(_die(f"allowlist[{i}]: duplicate id {item['id']!r}"))
        seen_ids.add(item["id"])
        try:
            expires = _to_date(item["expires"])
        except ValueError as exc:
            raise SystemExit(_die(f"allowlist[{i}]: bad expires: {exc}"))
        entries.append(AllowEntry(
            id=item["id"], reason=item["reason"], owner=item["owner"],
            expires=expires, package=item.get("package"),
            path=item.get("path"), ticket=item.get("ticket"),
        ))
    return entries


def _to_date(value: Any) -> date:
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        return datetime.strptime(value, "%Y-%m-%d").date()
    raise ValueError(f"expected YYYY-MM-DD, got {value!r}")


def is_allowed(finding: Finding, allow: list[AllowEntry], today: date) -> bool:
    for entry in allow:
        if entry.id != finding.key():
            continue
        if entry.expires < today:
            return False
        if entry.path and entry.path not in finding.file:
            continue
        return True
    return False


def render_markdown(findings: list[Finding], totals: dict[str, int], by_scanner: dict[str, dict[str, int]]) -> str:
    lines = ["# Security Gate Report", ""]
    lines.append("| Severity | Count |")
    lines.append("|---|---:|")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        lines.append(f"| {sev} | {totals.get(sev, 0)} |")
    lines += ["", "## By scanner", "", "| Scanner | CRITICAL | HIGH | MEDIUM | LOW |",
              "|---|---:|---:|---:|---:|"]
    for scanner, sev_counts in sorted(by_scanner.items()):
        lines.append(
            f"| {scanner} | {sev_counts.get('CRITICAL',0)} | {sev_counts.get('HIGH',0)} "
            f"| {sev_counts.get('MEDIUM',0)} | {sev_counts.get('LOW',0)} |"
        )
    blocking = [f for f in findings if f.severity in BLOCKING]
    if blocking:
        lines += ["", "## Top blocking findings (first 20)", "",
                  "| Scanner | Severity | Rule | Location | Message |",
                  "|---|---|---|---|---|"]
        for f in blocking[:20]:
            loc = f"{f.file}:{f.line}" if f.line else f.file
            lines.append(f"| {f.scanner} | {f.severity} | `{f.rule_id}` | `{loc}` | {f.message[:120]} |")
    lines += ["", "_Allowlist: `.security/allowlist.yml` — see `docs/security/allowlist.md`._"]
    return "\n".join(lines) + "\n"


def _die(msg: str) -> str:
    print(f"aggregate_sarif: ERROR: {msg}", file=sys.stderr)
    return msg


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sarif-dir", required=True, type=Path)
    ap.add_argument("--out-dir", required=True, type=Path)
    ap.add_argument("--allowlist", type=Path, default=None)
    ap.add_argument("--today", type=str, default=None,
                    help="Override today's date (YYYY-MM-DD) for testing")
    args = ap.parse_args(argv)

    today = _to_date(args.today) if args.today else date.today()

    try:
        allow = load_allowlist(args.allowlist)
    except SystemExit:
        return 2

    args.out_dir.mkdir(parents=True, exist_ok=True)

    all_findings: list[Finding] = []
    combined_runs: list[dict[str, Any]] = []
    by_scanner: dict[str, dict[str, int]] = {}

    sarif_files = sorted(args.sarif_dir.glob("*.sarif"))
    for path in sarif_files:
        _name, findings, data = load_sarif(path)
        all_findings.extend(findings)
        combined_runs.extend(data.get("runs", []))
        for f in findings:
            by_scanner.setdefault(f.scanner, {}).setdefault(f.severity, 0)
            by_scanner[f.scanner][f.severity] += 1

    totals: dict[str, int] = {}
    for f in all_findings:
        totals[f.severity] = totals.get(f.severity, 0) + 1

    unlisted_blocking = [
        f for f in all_findings
        if f.severity in BLOCKING and not is_allowed(f, allow, today)
    ]

    (args.out_dir / "security-combined.sarif").write_text(json.dumps(
        {"version": "2.1.0",
         "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
         "runs": combined_runs}, indent=2))

    (args.out_dir / "security-report.md").write_text(
        render_markdown(all_findings, totals, by_scanner)
    )

    (args.out_dir / "security-report.json").write_text(json.dumps({
        "schema_version": 1,
        "totals": totals,
        "by_scanner": by_scanner,
        "findings": [f.__dict__ for f in all_findings],
        "blocking_unlisted": [f.__dict__ for f in unlisted_blocking],
    }, indent=2, default=str))

    return 1 if unlisted_blocking else 0


if __name__ == "__main__":
    sys.exit(main())
