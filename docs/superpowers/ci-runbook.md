# CI Runbook — DevSecOps Fork

## One-time settings

Do these once per fork owner. All in the GitHub UI of `fardani235/molecule`.

1. **Settings → Branches → Branch protection for `main`**: mark
   `security / gate` as a required status check.
2. **Settings → Actions → General → Workflow permissions**: enable
   "Allow GitHub Actions to create and approve pull requests" (needed by
   `ci-metrics.yml` to open the metrics-update PR).
3. **Settings → Code security and analysis**: enable Dependency graph,
   Dependabot alerts, Secret scanning, Code scanning.
4. No secrets are required for the new workflows.

## Adding an allowlist entry

1. Open `.github/security/allowlist.yml`.
2. Append an entry:
   ```yaml
   - id: GHSA-xxxx-xxxx-xxxx      # or CodeQL rule id, Gitleaks rule id, etc.
     tool: pip-audit               # one of: codeql | pip-audit | gitleaks | trivy | zizmor | ansible-lint
     reason: "Not exploitable — CLI-only path, no untrusted input."
     owner: "your-github-handle"
     expires: 2026-11-01           # required. gate fails when past due.
   ```
3. If `tool: gitleaks`, also add the corresponding pattern to
   `.github/security/gitleaks.toml`. If `tool: trivy`, also add the CVE
   id to `.trivyignore`.

## Overriding a release gate

`release.yml` accepts a `workflow_dispatch` input `override_gate: true`.
Only members with `environment: release` approver rights may use it.

```
gh workflow run release.yml -f override_gate=true
```

## Fork owner change

If the fork is renamed or moved:

```
grep -rln "fardani235" .github/ docs/superpowers/ | xargs sed -i 's/fardani235/<new-owner>/g'
```

Then update the runbook and open a PR.

## Verification runbook

After each workflow commit, verify locally with the commands below, then push. Each task includes specific commands.

### Task 2 — CodeQL SAST

After pushing to remote:

```bash
gh workflow run security.yml --ref devsecops-ci-improvements
sleep 5
gh run list --workflow=security.yml --limit 1
```

Then watch for completion:

```bash
gh run watch $(gh run list --workflow=security.yml --limit 1 --json databaseId -q '.[0].databaseId')
```

Expected: `sast-codeql` job succeeds, artifact `sarif-codeql` is available.

### Task 3 — SCA (pip-audit + Dependency Review)

After pushing to remote:

```bash
gh workflow run security.yml --ref devsecops-ci-improvements
sleep 5
gh run list --workflow=security.yml --limit 1
```

Then watch for completion:

```bash
gh run watch $(gh run list --workflow=security.yml --limit 1 --json databaseId -q '.[0].databaseId')
```

Expected: `sca-pip-audit` succeeds (unless a real CVE is present — in which case success = "gate is doing its job"; suppress via allowlist if triaged). `sca-dep-review` is skipped on non-PR dispatch (that's fine).

### Task 4 — Gitleaks (secrets scanning)

After pushing to remote:

```bash
gh workflow run security.yml --ref devsecops-ci-improvements
sleep 5
gh run list --workflow=security.yml --limit 1
```

Then watch for completion:

```bash
gh run watch $(gh run list --workflow=security.yml --limit 1 --json databaseId -q '.[0].databaseId')
```

Expected: `secrets-gitleaks` job succeeds, artifact `sarif-gitleaks` is available.

### Task 5 — IaC (zizmor + ansible-lint)

After pushing to remote:

```bash
gh workflow run security.yml --ref devsecops-ci-improvements
sleep 5
gh run list --workflow=security.yml --limit 1
```

Then watch for completion:

```bash
gh run watch $(gh run list --workflow=security.yml --limit 1 --json databaseId -q '.[0].databaseId')
```

Expected: `iac-zizmor` and `iac-ansible-lint-sec` jobs succeed, artifacts `sarif-zizmor` and `sarif-ansible-lint` are available.

### Task 6 — Trivy filesystem

After pushing to remote:

```bash
gh workflow run security.yml --ref devsecops-ci-improvements
sleep 5
gh run list --workflow=security.yml --limit 1
```

Then watch for completion:

```bash
gh run watch $(gh run list --workflow=security.yml --limit 1 --json databaseId -q '.[0].databaseId')
```

Expected: `sca-trivy-fs` job succeeds, artifact `sarif-trivy` is available.

### Task 7 — SARIF gate

After pushing to remote:

```bash
gh workflow run security.yml --ref devsecops-ci-improvements
sleep 5
gh run list --workflow=security.yml --limit 1
```

Then watch for completion:

```bash
gh run watch $(gh run list --workflow=security.yml --limit 1 --json databaseId -q '.[0].databaseId')
```

Expected: `gate` job succeeds when all upstream scanners have zero Medium+ findings and no allowlist entries are expired; consolidated artifact `security-report` is available.

To verify the gate fails on an expired allowlist entry (requires push access):

```bash
git checkout -b probe-expired-allowlist
python3 - <<'PY'
import yaml
p = ".github/security/allowlist.yml"
d = yaml.safe_load(open(p)) or {"suppressions": []}
d["suppressions"].append({"id":"TEST-EXPIRED","tool":"pip-audit","reason":"gate test","owner":"ci","expires":"2020-01-01"})
open(p, "w").write(yaml.safe_dump(d, sort_keys=False))
PY
git add .github/security/allowlist.yml
git commit -m "probe: add expired allowlist entry (do not merge)"
git push origin probe-expired-allowlist
gh workflow run security.yml --ref probe-expired-allowlist
gh run watch $(gh run list --workflow=security.yml --branch probe-expired-allowlist --limit 1 --json databaseId -q '.[0].databaseId') || true
gh run view $(gh run list --workflow=security.yml --branch probe-expired-allowlist --limit 1 --json databaseId -q '.[0].databaseId') --log-failed | grep -F "TEST-EXPIRED"

# Clean up.
git checkout devsecops-ci-improvements
git branch -D probe-expired-allowlist
git push origin --delete probe-expired-allowlist
```

Expected: the `gate` job conclusion is `failure`; log contains the expired-entries error.

### Task 8 — warm-cache

After pushing to remote:

```bash
gh workflow run tox.yml --ref devsecops-ci-improvements
sleep 5
gh run list --workflow=tox.yml --limit 1
```

Then watch for completion:

```bash
gh run watch $(gh run list --workflow=tox.yml --limit 1 --json databaseId -q '.[0].databaseId')
```

Expected: `warm-cache` job succeeds and reports cache miss on first run. On a second dispatch, `warm-cache` reports cache hit:

```bash
gh run list --workflow=tox.yml --limit 2
```

Second run's `warm-cache` step logs `Cache restored from key: uv-...` or similar for other caches.

### Task 9 — Release SBOM + Trivy

After pushing to remote:

```bash
gh workflow run release.yml -f pypi_publish=false -f galaxy_publish=false
sleep 5
gh run list --workflow=release.yml --limit 1
```

Then watch for completion:

```bash
gh run watch $(gh run list --workflow=release.yml --limit 1 --json databaseId -q '.[0].databaseId')
```

Expected: `release` job builds dists and emits SBOMs (artifact `sbom` appears); `release-trivy-dists` runs (skipped on non-release events without built dists — that is acceptable, and the artifact will simply be absent for the dry-run).
