# DevSecOps CI — One-Time Setup

Fork-only workflow for `fardani235/molecule`.

## 1. Enable repo-level protections (Settings → Code security)

- Dependabot alerts: **on**.
- Dependabot security updates: **on**.
- Secret scanning: **on**.
- Push protection: **on**.

## 2. Configure branch protection on `main`

```bash
gh api -X PUT "/repos/fardani235/molecule/branches/main/protection" \
  --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["security-gate", "tox"]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": {"required_approving_review_count": 1},
  "restrictions": null,
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
```

## 3. Capture the timing baseline

After `security.yml` has run once cold on `main`:

```bash
# Find the run id of the first cold security.yml run on main:
gh run list --workflow security.yml --branch main --limit 5

python .security/scripts/capture_baseline.py \
  --repo fardani235/molecule \
  --workflow tox.yml \
  --n 5 \
  --security-run-id <RUN_ID> \
  --out .security/baseline.json

git add .security/baseline.json
git commit -m "chore(security): capture CI timing baseline"
```

## 4. Flip the gate to strict (Task 12)

Open a PR that:

1. Removes `continue-on-error: true` from every scanner job and the
   `security-gate` job in `.github/workflows/security.yml`.
2. Keeps `continue-on-error: true` on `timing-report` (informational).
3. Includes the measured cold-vs-warm speedup numbers in the PR body.

## 5. Break-glass

To bypass the gate on an exceptional PR, add the `skip-security` label.
Requires repo-owner sign-off in the PR body.
