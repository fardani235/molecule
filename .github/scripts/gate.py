"""SARIF aggregator + waiver enforcer for the DevSecOps gate.

Reads every *.sarif file under --sarif-dir, normalizes findings, applies
waiver files, evaluates them against gate-policy.yml, writes a Markdown
summary and JSON report, and exits nonzero if any unwaived finding is at
or above the effective severity threshold.
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as _dt
import json
import pathlib
import re
import sys
from typing import Iterable

import yaml


SEVERITY_ORDER = ["low", "medium", "high", "critical"]
SEV_INDEX = {s: i for i, s in enumerate(SEVERITY_ORDER)}


class WaiverFormatError(RuntimeError):
    """A waiver entry is missing the required comment."""


class WaiverExpiredError(RuntimeError):
    """A waiver entry's re-review date has passed."""


@dataclasses.dataclass
class Finding:
    scanner: str
    rule_id: str
    severity: str  # low|medium|high|critical
    file: str
    line: int
    message: str
    waiver: str | None = None


@dataclasses.dataclass
class GateResult:
    failed: bool
    counts: dict          # {scanner: {severity: n}}
    waived: int
    summary_md: str
    findings: list        # remaining unwaived findings (for JSON report)


# ---------- SARIF loading ----------

_SEV_MAP_DEFAULT = {"error": "high", "warning": "medium", "note": "low", "none": "low"}
_SEV_MAP_BANDIT = {"error": "high", "warning": "medium", "note": "low"}
_SCANNER_ALIASES = {
    "bandit": "bandit",
    "semgrep": "semgrep",
    "pip-audit": "pip-audit",
    "trivy": "trivy",
    "gitleaks": "gitleaks",
    "kics": "kics",
}


def _map_severity(scanner: str, level: str, properties: dict | None) -> str:
    scanner = scanner.lower()
    # pip-audit and Trivy encode CVSS numeric in properties.security-severity.
    if properties and "security-severity" in properties:
        try:
            score = float(properties["security-severity"])
        except (TypeError, ValueError):
            score = 0.0
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        return "low"
    if scanner == "gitleaks":
        return "critical"
    if scanner == "bandit":
        return _SEV_MAP_BANDIT.get((level or "").lower(), "medium")
    return _SEV_MAP_DEFAULT.get((level or "").lower(), "medium")


def load_sarif_dir(path: pathlib.Path) -> list[Finding]:
    findings: list[Finding] = []
    for sarif_path in sorted(pathlib.Path(path).glob("*.sarif")):
        data = json.loads(sarif_path.read_text())
        for run in data.get("runs", []):
            driver = run.get("tool", {}).get("driver", {})
            scanner_raw = (driver.get("name") or sarif_path.stem).lower()
            scanner = _SCANNER_ALIASES.get(scanner_raw, scanner_raw)
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "")
                level = result.get("level") or ""
                message = (result.get("message") or {}).get("text", "")
                properties = result.get("properties") or {}
                locations = result.get("locations") or []
                file_uri = ""
                line = 0
                if locations:
                    ploc = locations[0].get("physicalLocation") or {}
                    file_uri = (ploc.get("artifactLocation") or {}).get("uri", "")
                    line = (ploc.get("region") or {}).get("startLine", 0) or 0
                findings.append(Finding(
                    scanner=scanner,
                    rule_id=rule_id,
                    severity=_map_severity(scanner, level, properties),
                    file=file_uri,
                    line=int(line),
                    message=message,
                ))
    return findings


# ---------- Waivers ----------

_WAIVER_LINE_RE = re.compile(
    r"^\s*#\s*waived\s+(?P<waived_on>\d{4}-\d{2}-\d{2})\s+by\s+(?P<by>\S+)\s+"
    r"[—-]\s+(?P<reason>.+?)\s*;\s*re-review\s+(?P<review>\d{4}-\d{2}-\d{2})\s*$",
    re.IGNORECASE,
)


def _parse_waiver_file(path: pathlib.Path) -> list[tuple[str, str]]:
    """Return list of (id, waiver_string) pairs.

    Raises WaiverFormatError if a non-comment line is not immediately
    preceded by a valid waiver comment. Raises WaiverExpiredError if the
    re-review date has passed.
    """
    pairs: list[tuple[str, str]] = []
    if not path.exists():
        return pairs
    lines = path.read_text().splitlines()
    last_waiver_comment: str | None = None
    today = _dt.date.today()
    for raw in lines:
        line = raw.strip()
        if not line:
            last_waiver_comment = None
            continue
        if line.startswith("#"):
            match = _WAIVER_LINE_RE.match(raw)
            if match:
                review = _dt.date.fromisoformat(match.group("review"))
                if review < today:
                    raise WaiverExpiredError(
                        f"{path}: waiver re-review date {review.isoformat()} has passed"
                    )
                last_waiver_comment = raw.strip()
            # non-waiver comments (informational) reset nothing.
            continue
        # non-comment line = a waiver entry (CVE-id, path glob, etc.).
        if not last_waiver_comment:
            raise WaiverFormatError(
                f"{path}: entry '{line}' has no preceding waiver comment"
            )
        pairs.append((line, last_waiver_comment))
        last_waiver_comment = None
    return pairs


def apply_waivers(
    findings: Iterable[Finding], waiver_files: dict[str, pathlib.Path]
) -> tuple[list[Finding], list[Finding]]:
    """Return (unwaived, waived). Scanner name is the dict key."""
    unwaived: list[Finding] = []
    waived: list[Finding] = []
    parsed = {scanner: _parse_waiver_file(p) for scanner, p in waiver_files.items()}
    for f in findings:
        pairs = parsed.get(f.scanner, [])
        match = next(
            (comment for entry_id, comment in pairs if entry_id == f.rule_id),
            None,
        )
        if match:
            waived.append(dataclasses.replace(f, waiver=match))
        else:
            unwaived.append(f)
    return unwaived, waived


# ---------- Evaluation ----------

def _effective_threshold(policy: dict, scanner: str) -> str:
    default = policy.get("threshold", "medium")
    overrides = (policy.get("overrides") or {}).get(scanner) or {}
    return overrides.get("threshold", default)


def evaluate(findings: list[Finding], policy: dict) -> GateResult:
    counts: dict[str, dict[str, int]] = {}
    failed = False
    for f in findings:
        counts.setdefault(f.scanner, {s: 0 for s in SEVERITY_ORDER})
        counts[f.scanner][f.severity] += 1
        if SEV_INDEX[f.severity] >= SEV_INDEX[_effective_threshold(policy, f.scanner)]:
            failed = True
    summary_md = _render_summary(counts, failed)
    return GateResult(
        failed=failed, counts=counts, waived=0, summary_md=summary_md, findings=findings
    )


def _render_summary(counts: dict, failed: bool) -> str:
    lines = [
        "## 🛡 Security Gate",
        "",
        "| Scanner | Critical | High | Medium | Low |",
        "|---|---:|---:|---:|---:|",
    ]
    for scanner in sorted(counts):
        c = counts[scanner]
        lines.append(
            f"| {scanner} | {c['critical']} | {c['high']} | {c['medium']} | {c['low']} |"
        )
    if not counts:
        lines.append("| _(no findings)_ | 0 | 0 | 0 | 0 |")
    lines.extend([
        "",
        f"**Gate: {'❌ FAIL' if failed else '✅ PASS'}**",
    ])
    return "\n".join(lines) + "\n"


# ---------- CLI ----------

def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sarif-dir", type=pathlib.Path, required=True)
    p.add_argument("--policy", type=pathlib.Path, required=True)
    p.add_argument(
        "--waivers",
        action="append",
        default=[],
        metavar="SCANNER=PATH",
        help="e.g. --waivers trivy=.github/security/.trivyignore",
    )
    p.add_argument("--out-md", type=pathlib.Path, required=True)
    p.add_argument("--out-json", type=pathlib.Path, required=True)
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    policy = yaml.safe_load(args.policy.read_text()) or {}
    waiver_files = {}
    for pair in args.waivers:
        if "=" not in pair:
            print(f"invalid --waivers value: {pair}", file=sys.stderr)
            return 2
        scanner, path = pair.split("=", 1)
        waiver_files[scanner] = pathlib.Path(path)
    findings = load_sarif_dir(args.sarif_dir)
    unwaived, waived = apply_waivers(findings, waiver_files)
    result = evaluate(unwaived, policy)
    result.waived = len(waived)
    args.out_md.write_text(result.summary_md)
    args.out_json.write_text(
        json.dumps(
            {
                "failed": result.failed,
                "counts": result.counts,
                "waived": result.waived,
                "findings": [dataclasses.asdict(f) for f in result.findings],
            },
            indent=2,
        )
    )
    return 1 if result.failed else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
