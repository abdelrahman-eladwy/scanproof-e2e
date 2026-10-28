# Read-only GitHub protected-gate preflight

This E2E capability supports ScanProof [core #26](https://github.com/abdelrahman-eladwy/scanproof/issues/26), [#45](https://github.com/abdelrahman-eladwy/scanproof/issues/45) and [E2E #17](https://github.com/abdelrahman-eladwy/scanproof-e2e/issues/17). It does **not** enable a GitHub ruleset, change a policy, publish a deployment, or claim release readiness.

## What the preflight can prove

The standard-library script `scripts/audit_github_gate.py` queries GitHub's read-only repository metadata and rulesets endpoints, including inherited rulesets. It returns one of:

- `PASS_STATIC_PREFLIGHT` (exit 0): at least one *active, branch-applicable* ruleset independently requires the exact expected ScanProof status context from the expected GitHub App, strict up-to-date required checks, one or more approving reviews, CODEOWNER review, stale dismissal or last-push review, no bypass actors and no force push or deletion.
- `FAIL_STATIC_PREFLIGHT` (exit 1): the observed rulesets do not satisfy **all** conditions in one ruleset. This is conservative: effective controls spread across separate rulesets may require human review.
- `INDETERMINATE` (exit 2): GitHub API access was refused, inconsistent, malformed, potentially paginated beyond the preflight limit or unavailable. Never interpret exit 2 as a pass.

Every run produces machine-readable JSON with the inspected ruleset IDs, missing controls, check context and branch. No token is included. Network requests refuse redirects; token authentication is only passed to api.github.com; responses are capped. The result is an observation **at query time**. The actual protection could change afterward, and the API result alone cannot prove a negative bypass attempt was blocked.

## Run locally or through GitHub Actions

Run the offline self-tests (no network):

```sh
python -m unittest -q scripts/test_audit_github_gate.py
```

Audit a *sacrificial staging repository* (not the core project's six generic CI jobs):

```sh
GH_TOKEN="<read-only token if required>" python scripts/audit_github_gate.py \
  --repo OWNER/SACRIFICIAL-REPO --branch main \
  --check "ScanProof verification" --app-id 15368 \
  --output preflight.json
```

The token is optional for a public repository; private repositories need a read-capable token. Never pass the token via command-line arguments, URLs or artifacts. For manual GitHub execution, use the [github-protection-preflight workflow](../.github/workflows/github-protection-preflight.yml): **Actions → github-protection-preflight → Run workflow** on a reviewed branch, then enter the sacrificial repository, branch and *actual* ScanProof status context. Its workflow token has `contents: read` only; it cannot read arbitrary private staging repositories. A private target returning `INDETERMINATE` is not a failed/weak ruleset claim. For private repos, run the script from a trusted admin environment with a separately granted read-only token.

The self-test job runs on PRs/changes to this preflight and must stay green. Only explicit manual dispatch runs the **audit** job. An audit job failing before an environment is protected is expected; do **not** make it a required merge status check. Avoid dispatching workflows with privileged audit tokens on untrusted branches.

See also [negative PR observation protocol](github-protected-trial-evidence.md) for a read-only collector that inspects four real staging PRs. It cannot replace actual blocked merge/deploy trials.

## Required staging/admin actions before protected-gate GO

1. Have an administrator configure a sacrificial GitHub repo and a distinct security CODEOWNER/reviewer who can approve protected policy and workflow changes. Require at least one review; use stale review dismissal or last-push approval. Avoid setting a sole author as the only reviewer and locking out legitimate changes.
2. Make the *real* ScanProof verification check mandatory on the target branch, from a trusted app, with strict status checks. Protect branch deletion/force push and remove broad bypass exceptions.
3. Independently control the mandatory ScanProof workflow and policy. Protect the staging deployment environment separately; the script **does not audit environments**.
4. Run this preflight. Save its JSON, the ruleset URL and repository settings as evidence, bound to the repository/branch and time.
5. Conduct **live negative trials in sacrificial repos**: contributor removes/skips the check, weakens the policy or removes a scanner, uses masked scanner failures, replays signed evidence from another attempt, and loses access to artifacts. Capture the PR/run URLs and verify the platform actually prevents merge *and* staging deployment. Exercise a valid, current-attempt signed scan that does release.
6. Repeat for a centrally managed GitLab pipeline execution policy. GitHub ruleset preflight does **not** validate GitLab enforcement.

## Observed baseline, October 28, 2026

Read-only GitHub API observation:
- `abdelrahman-eladwy/scanproof` has active [ruleset 25947920](https://github.com/abdelrahman-eladwy/scanproof/rules/25947920), with six generic CI checks required, but **0 approving reviews** and **CODEOWNER review disabled**. These checks are not the independently required ScanProof deployment gate.
- `abdelrahman-eladwy/scanproof-e2e` repository rulesets endpoint returned **no repository rulesets**. This does not determine whether older branch protection or environments exist; it is **not** a deployment bypass experiment.

**Release gate status: NOT QUALIFIED.** A passing static preflight is one necessary configuration check, not the Phase 2 exit gate or a production-ready claim.
