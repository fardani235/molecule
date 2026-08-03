# CI Runbook — DevSecOps Fork

## One-time settings

Do these once per fork owner. All in the GitHub UI of `fardani235/molecule`.

1. **Settings → Branches → Branch protection for `main`**: mark
   `security / gate` as a required status check.
2. **Settings → Actions → General → Workflow permissions**: enable
   "Allow GitHub Actions to create and approve pull requests" (needed by
   `ci-metrics.yml` to open the metrics-update PR).
3. **Settings → Code security and analysis** (`https://github.com/fardani235/molecule/settings/security_analysis`): enable
   Dependency graph, Dependabot alerts, Secret scanning, Code scanning.
   **This is required** — the `sca-dep-review` job WILL fail with
   `Dependency review is not supported on this repository` until Dependency
   graph is turned on.
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

### Task 10 — CI metrics

Before merging Task 8's caching, run:

```bash
gh workflow run ci-metrics.yml
gh run watch $(gh run list --workflow=ci-metrics.yml --limit 1 --json databaseId -q '.[0].databaseId')
```

Expected: the workflow appends a baseline row to `docs/superpowers/ci-speed-report.md` and either commits it directly (if PR-creation permissions are wired) or opens PR `chore/ci-metrics-update`.

Merge the baseline row before merging any caching changes to Task 8. That's what makes the "improvement" number honest.

### Task 11 — End-to-end acceptance verification

This section documents the human-executable verification steps for all DevSecOps CI acceptance criteria. Each subsection includes exact commands to run and expected outcomes.

#### Step 1: Failing PR probe

Create a throwaway branch with a Medium+ security finding (Bandit-style `subprocess.check_output` with `shell=True`) and verify the `security / gate` check fails.

```bash
# Create a new branch for the probe
git checkout -b probe-failing-gate

# Create the probe file with a Bandit-detected vulnerability
mkdir -p src/molecule
cat > src/molecule/_probe_gate.py <<'EOF'
import subprocess

# This should trigger Bandit B602 (shell=True)
result = subprocess.check_output("ls", shell=True)
EOF

# Commit the change
git add src/molecule/_probe_gate.py
git commit -m "probe: add security finding to test gate failure (do not merge)"

# Push to remote
git push origin probe-failing-gate

# Create a PR and capture the PR number
PR_NUM=$(gh pr create --title "probe: gate failure test" --body "Testing that security/gate correctly fails on Medium+ findings" --head probe-failing-gate --base main --json number -q)
echo "PR #$PR_NUM created"

# Watch the PR checks to confirm security/gate fails
gh run watch $(gh run list --workflow=security.yml --branch probe-failing-gate --limit 1 --json databaseId -q '.[0].databaseId') || true

# Verify the security/gate check failed
gh pr view $PR_NUM --json statusCheckRollup

# Clean up after verification
git checkout devsecops-ci-improvements
git branch -D probe-failing-gate
git push origin --delete probe-failing-gate
gh pr close $PR_NUM
```

Expected outcome: The `security / gate` check should report `failure` or `failure` status on the PR, indicating that the Bandit Medium+ finding was correctly detected and blocked.

#### Step 2: Green PR

Open a PR with a benign single-line README change, verify `security / gate` passes, and confirm artifacts are downloadable.

```bash
# Create a new branch for the clean PR
git checkout -b test-clean-pr

# Make a benign change (README comment)
echo "" >> README.md
echo "<!-- Clean test commit for CI verification -->" >> README.md

# Commit and push
git add README.md
git commit -m "docs: add test comment to verify clean CI run"
git push origin test-clean-pr

# Create a PR
PR_NUM=$(gh pr create --title "test: verify clean CI run" --body "Benign README change to test that security/gate passes with no findings" --head test-clean-pr --base main --json number -q)
echo "PR #$PR_NUM created"

# Wait for the security workflow to complete
sleep 10
gh run watch $(gh run list --workflow=security.yml --branch test-clean-pr --limit 1 --json databaseId -q '.[0].databaseId')

# Verify security/gate passed
gh pr view $PR_NUM --json statusCheckRollup

# Download the security report and SARIF artifacts
gh run download $(gh run list --workflow=security.yml --branch test-clean-pr --limit 1 --json databaseId -q '.[0].databaseId') -n security-report
gh run download $(gh run list --workflow=security.yml --branch test-clean-pr --limit 1 --json databaseId -q '.[0].databaseId') -n sarif-codeql 2>/dev/null || echo "sarif-codeql artifact not found (expected on benign PR)"
gh run download $(gh run list --workflow=security.yml --branch test-clean-pr --limit 1 --json databaseId -q '.[0].databaseId') -n sarif-gitleaks 2>/dev/null || echo "sarif-gitleaks artifact not found (expected on benign PR)"

# Verify artifacts exist
ls -la security-report/ 2>/dev/null && echo "security-report artifact downloaded successfully"

# Clean up
git checkout devsecops-ci-improvements
git branch -D test-clean-pr
git push origin --delete test-clean-pr
gh pr close $PR_NUM
```

Expected outcome:
- The `security / gate` check reports `success` or `passed` status.
- Artifacts `security-report` are downloadable via `gh run download`.
- Additional SARIF artifacts may be present depending on which scanners detected content to report.

#### Step 3: Security tab confirmation

Verify that security findings appear in the GitHub Security tab under Code scanning and match expected scanner categories.

Navigate to:
```
https://github.com/fardani235/molecule/security/code-scanning
```

Expected categories to appear (after at least one successful run of `security.yml`):
- `codeql` — CodeQL SAST findings
- `pip-audit` — Python dependency vulnerabilities
- `gitleaks` — Secrets and sensitive patterns
- `zizmor` — Infrastructure-as-Code security (Terraform-style)
- `trivy-fs` — Filesystem and dependency scanning
- `ansible-lint` — Ansible playbook security rules

Note: Categories will only appear if the respective scanner found at least one issue or reported results in its run. Check that at least the enabled scanners have results entries in the Security tab.

#### Step 4: Speed measurement

Trigger the CI metrics workflow, verify a new row is added to the speed report, and compute the delta from baseline.

```bash
# Trigger the CI metrics collection workflow
gh workflow run ci-metrics.yml --ref devsecops-ci-improvements
sleep 5

# Watch for completion
gh run watch $(gh run list --workflow=ci-metrics.yml --limit 1 --json databaseId -q '.[0].databaseId')

# Verify the metrics report was updated
git pull origin devsecops-ci-improvements
cat docs/superpowers/ci-speed-report.md

# Extract and display the timing column (column 3 after |)
echo "Timing measurements (should trend downward or hold steady):"
awk -F'|' '/^\| [0-9]{4}-[0-9]{2}-[0-9]{2}/{print $3}' docs/superpowers/ci-speed-report.md
```

Expected outcome:
- The `ci-metrics.yml` workflow completes successfully.
- A new row appears in `docs/superpowers/ci-speed-report.md` with today's date.
- The timing column (column 3) shows measurement(s); subsequent runs should show equal or improved (lower) numbers.

#### Step 5: Release dry-run SBOM

Execute a release dry-run and verify the SBOM artifact is generated with both CycloneDX and SPDX formats.

```bash
# Trigger a release workflow dry-run (no PyPI or Galaxy publish)
gh workflow run release.yml -f pypi_publish=false -f galaxy_publish=false
sleep 5

# Watch for completion
gh run watch $(gh run list --workflow=release.yml --limit 1 --json databaseId -q '.[0].databaseId')

# Download the SBOM artifact
RUN_ID=$(gh run list --workflow=release.yml --limit 1 --json databaseId -q '.[0].databaseId')
gh run download $RUN_ID -n sbom

# Verify both SBOM formats are present
echo "Verifying SBOM artifacts..."
ls -la sbom/
test -f sbom/bom.cdx.json && echo "✓ CycloneDX SBOM found (bom.cdx.json)"
test -f sbom/bom.spdx.json && echo "✓ SPDX SBOM found (bom.spdx.json)"
```

Expected outcome:
- The `release` workflow job completes successfully.
- An artifact named `sbom` is downloadable.
- The artifact contains both `bom.cdx.json` (CycloneDX format) and `bom.spdx.json` (SPDX format).

#### Step 6: No upstream footprint

Verify that the DevSecOps workflows are guarded to prevent running on forks or non-upstream branches by confirming job skips when conditions are not met.

```bash
# Option A: Simulate by creating a branch on a local fork (requires push access to a different owner)
# Requires: forking to a different GitHub account and pushing the branch there.
# Then check the Actions UI for the branch and confirm new jobs are skipped.

# Option B: Simulate the guard locally by temporarily editing the workflow guard condition
# and verifying no jobs would run (this is local-only, no push needed):

# First, examine the current guard condition in ci-metrics.yml
grep -A 3 "if: github.repository" .github/workflows/ci-metrics.yml

# The guard should check: github.repository == 'fardani235/molecule'
# Expected: If the guard condition evaluates to false, all downstream jobs will be skipped.

# To verify this works after a real upstream push to a different fork:
# 1. Create a fork under a different owner (e.g., testuser/molecule)
# 2. Push the devsecops-ci-improvements branch to that fork
# 3. Check the Actions tab of the fork — all new jobs (ci-metrics, release, security) should skip
# 4. The skip message should indicate: "This step was skipped"

echo "Current workflow guards:"
grep -rn "github.repository" .github/workflows/ | grep -E "(ci-metrics|release|security)" | head -5
```

Expected outcome:
- All workflows have a repository guard: `if: github.repository == 'fardani235/molecule'`.
- When the branch is pushed to a different fork or owner, the Actions UI shows every new job with status `skipped`.
- Job logs include the reason: "This step was skipped" or "Skipped due to filter" (exact wording varies by GitHub UI version).

#### Acceptance evidence

After all six verification steps pass, record the run URLs and commit evidence in the section below. Fill in the template fields with real URLs from your GitHub Actions runs and commits.

## Acceptance evidence

- Failing gate run: <URL>
- Green PR run: <URL>
- Release dry-run: <URL>
- Baseline metric commit: <URL>
- Post-cache metric commit: <URL>
