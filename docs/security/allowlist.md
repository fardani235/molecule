# Security Allowlist Policy

File: `.security/allowlist.yml`. Used by
`.security/scripts/aggregate_sarif.py`.

## Required fields per entry

- `id` — `<scanner>:<rule_id>` (e.g. `pip-audit:GHSA-xxxx-xxxx-xxxx`,
  `bandit:B404`).
- `reason` — why the finding is acceptable. One sentence.
- `owner` — GitHub handle taking responsibility.
- `expires` — ISO 8601 date (YYYY-MM-DD). **Expired entries re-enter the
  gate.**
- `ticket` (optional) — URL to a tracking issue.
- `package` (optional, scanner-specific) — package name for SCA entries.
- `path` (optional) — restricts the allowlist to a specific file path.

## Rules enforced by the aggregator

1. Missing `id`, `reason`, `owner`, or `expires` → gate fails (exit 2).
2. `expires` in the past → finding re-enters the gate.
3. Duplicate `id` → gate fails (exit 2).

## Review process

1. Open a PR that adds the entry with a `security-allowlist` label.
2. PR body cites the vulnerability advisory, exploit prerequisites, and
   why we accept the risk.
3. Owner must be the person who will re-triage on `expires`.
4. Maximum `expires` window: **90 days** — extend by renewing, not by
   long expiries.
