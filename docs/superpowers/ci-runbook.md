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
