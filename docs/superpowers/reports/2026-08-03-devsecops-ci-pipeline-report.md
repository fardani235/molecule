# DevSecOps CI Pipeline Improvement — Final Report

**Date:** 2026-08-03
**PR:** [#3 — ci: add DevSecOps security scanning, caching, and artifact publishing](https://github.com/fardani235/molecule/pull/3)
**Branch:** `devsecops-ci-improvements-v2`
**Repository:** fardani235/molecule (fork of ansible-community/molecule)

---

## Executive Summary

Successfully implemented a comprehensive DevSecOps CI pipeline for the
forked Molecule repository. The pipeline adds security scanning across 5
tools, a merge gate that blocks PRs with medium/high/critical findings,
caching strategies to speed up CI, SBOM generation, and a benchmark
workflow to measure caching improvements. All workflows run exclusively on
the fork — never on upstream.

**CI Status:** ✅ All 4 security checks passing on PR #3.

---

## What Was Delivered

### 1. Security Scanning (`security.yml`)

Three parallel scanner jobs plus a gate:

| Scanner | Tool | Category | Runtime |
|---------|------|----------|---------|
| SAST | Bandit + Semgrep | Static code analysis | 22s |
| Dependency Scan | pip-audit + Trivy | Supply chain / CVE | 54s |
| Secrets Detection | Gitleaks | Hardcoded secrets | 9s |
| **Security Gate** | Custom Python script | **Merge blocker** | 9s |

**Total security pipeline time: ~1 min 34s** (scanners run in parallel,
gate runs after all complete).

**Gate behavior:**
- Parses JSON output from all 5 scanners
- Blocks PR merge on any medium, high, or critical finding
- Posts a markdown summary to the GitHub Actions job summary
- Handles edge cases: missing files, corrupted JSON, malformed output

### 2. Caching Strategy

| Cache Target | Path | Key Strategy |
|---|---|---|
| uv packages | `~/.cache/uv` | `{os}-uv-{hash(uv.lock)}` |
| tox environments | `.tox/` | `{os}-tox-{hash(pyproject.toml)}` |
| pre-commit hooks | `~/.cache/pre-commit` | `{os}-pre-commit-{hash(.pre-commit-config.yaml)}` |

**Implementation:**
- Reusable composite action (`.github/actions/setup-cache/action.yml`)
  with configurable inputs for each cache target
- Cache warming job added to existing `tox.yml` — runs before the shared
  upstream workflow, uses `if: always()` so tox runs even when cache-warm
  is skipped on upstream

### 3. Artifact Publishing (`release-artifacts.yml`)

On push to main and published releases:
- **SBOM** (CycloneDX JSON) generated via Trivy — downloadable as `sbom-cyclonedx`
- **Build artifacts** (sdist + wheel) via `tox -e pkg` — downloadable as `build-artifacts`
- 90-day retention on all artifacts

### 4. Speed Benchmarking (`cache-benchmark.yml`)

Manual-trigger workflow that:
1. Runs `tox -e lint` without cache (baseline)
2. Runs `tox -e lint` with cache (comparison)
3. Generates a markdown report with timing and percentage improvement
4. Uploads report as `cache-benchmark-report` artifact

**To measure improvement:** Go to Actions → cache-benchmark → Run workflow.

### 5. Fork-Only Enforcement

Every new workflow job includes:
```yaml
if: github.repository != 'ansible-community/molecule'
```
Verified across all jobs. The existing `tox` job is NOT guarded (it must
run on upstream) — only new jobs are guarded.

---

## Files Created / Modified

| File | Lines | Action | Purpose |
|------|-------|--------|---------|
| `.github/actions/setup-cache/action.yml` | 47 | Created | Reusable caching composite action |
| `.github/workflows/security.yml` | 242 | Created | Security scanning + gate |
| `.github/scripts/security_gate.py` | 226 | Created | Gate script (5 parsers + summary) |
| `.github/scripts/test_security_gate.py` | 216 | Created | 17 unit tests for gate script |
| `.github/workflows/release-artifacts.yml` | 70 | Created | SBOM + build artifact publishing |
| `.github/workflows/cache-benchmark.yml` | 142 | Created | Caching speed measurement |
| `.github/workflows/tox.yml` | +17 | Modified | Added cache warming job |
| `.bandit.yml` | 6 | Created | Bandit SAST configuration |
| `.gitleaks.toml` | 13 | Created | Gitleaks secrets scan configuration |
| **Total** | **2,530** | | |

---

## Test Results

### Security Gate Script — 17/17 tests passing

```
test_parse_bandit_medium_finding           PASSED
test_parse_bandit_missing_file             PASSED
test_parse_semgrep_warning_maps_to_medium  PASSED
test_parse_pip_audit_vuln                  PASSED
test_parse_trivy_critical                  PASSED
test_parse_gitleaks_secret                 PASSED
test_parse_gitleaks_empty                  PASSED
test_generate_summary_no_findings          PASSED
test_generate_summary_with_findings        PASSED
test_parse_bandit_invalid_json             PASSED
test_parse_semgrep_invalid_json            PASSED
test_parse_pip_audit_invalid_json          PASSED
test_parse_trivy_invalid_json              PASSED
test_parse_gitleaks_invalid_json           PASSED
test_parse_pip_audit_malformed_string      PASSED
test_parse_pip_audit_malformed_int         PASSED
test_parse_pip_audit_malformed_null        PASSED
```

### CI Pipeline — All checks passing

```
SAST (Bandit + Semgrep)                    ✅ pass (22s)
Dependency Scan (pip-audit + Trivy)        ✅ pass (54s)
Secrets Detection (Gitleaks)               ✅ pass (9s)
Security Gate                              ✅ pass (9s)
```

---

## Downloadable Artifacts

After CI runs, these artifacts are available from the Actions tab:

| Artifact | Contents | Retention |
|----------|----------|-----------|
| `bandit-results` | SAST JSON + SARIF | 90 days |
| `semgrep-results` | SAST JSON + SARIF | 90 days |
| `pip-audit-results` | Dependency scan JSON | 90 days |
| `trivy-results` | Dependency scan JSON + SARIF | 90 days |
| `gitleaks-results` | Secrets scan JSON + SARIF | 90 days |
| `sbom-cyclonedx` | CycloneDX SBOM (JSON) | 90 days |
| `build-artifacts` | sdist + wheel packages | 90 days |
| `cache-benchmark-report` | Timing comparison (markdown) | 90 days |

SARIF results are also pushed to the **GitHub Security tab** for Bandit,
Semgrep, Trivy, and Gitleaks.

---

## Post-Merge Action Required

After merging this PR, enable the security gate as a required status check:

1. Go to **Settings → Branches → Branch protection rules** for `main`
2. Enable **Require status checks to pass before merging**
3. Add **Security Gate** as a required check

This ensures PRs with security findings cannot be merged.

---

## Commits (12)

| Hash | Message |
|------|---------|
| `16994ce1` | docs: add DevSecOps CI pipeline design spec |
| `2057c05a` | docs: add DevSecOps CI pipeline implementation plan |
| `7fd2ace8` | ci: add reusable caching composite action |
| `83bd2f94` | ci: add security scanning jobs (sast, dependency, secrets) |
| `bd09fbdc` | ci: add security gate job with finding parser |
| `2e8d6fb9` | fix: add JSONDecodeError handling to security gate parser |
| `01b8c848` | ci: add release artifacts workflow with SBOM generation |
| `e24d5983` | ci: add cache benchmark workflow |
| `a293616b` | ci: add cache warming job to tox workflow |
| `9c8cce39` | fix: add type safety to parse_pip_audit for malformed output |
| `70619f21` | fix: use correct trivy-action tag with v prefix |
| `8edb2387` | fix: upgrade trivy-action to v0.36.0 |
