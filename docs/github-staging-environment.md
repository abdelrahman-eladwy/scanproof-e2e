# Protected GitHub staging environment — read-only audit

This complements the [GitHub ruleset preflight](github-protected-gate.md) and the
[negative PR observation protocol](github-protected-trial-evidence.md). It advances
[core #45](https://github.com/abdelrahman-eladwy/scanproof/issues/45) but is
**not a release-gate qualification**. This capability only reads GitHub
environment settings. It cannot assert that the application workflow *uses*
the environment, that a valid ScanProof run is the deployment's prerequisite,
that reviewers actually denied a malicious attempt, or that GitLab policies
are enforced.

## Protect the staging deployment (administrator)

Use a sacrificial repository and a staging-only environment with no production
credentials. GitHub **Settings → Environments → staging**:

1. Configure at least one **required reviewer** who is independent of the
   application author's review path, and enable **Prevent self-review**.
   Reviewers are separate from code-owner approval on a pull request.
2. Under **Deployment branches and tags**, select **Protected branches only**.
   Independently verify that the intended branch is in fact protected by an
   active ruleset requiring the trusted ScanProof check; this audit alone
   does not prove that branch-protection condition.
3. Disable administrator bypass for deployment protection rules where
   available. The read-only API must explicitly report
   `can_admins_bypass: false`; if the field is hidden/unavailable, the
   static audit returns FAIL, not assumed protection.
4. Independently own the release workflow and release policy. A developer can
   simply remove an editable `environment: staging` key or deployment
   `needs: [scanproof]` edge: environment settings themselves never stop
   an unauthorized change to the workflow. Required platform checks and
   policy ownership must also prevent that change from reaching the branch.
5. Keep the environment in staging. Use a second, non-bypass contributor to
   try removing/skipping the gate, weakening the policy and the deploy
   dependency, replaying old attestations and making artifacts unreadable.
   Record actual rejected merges **and** denied staging deployments. An API
   observation of a blocked PR is not causal proof.

GitHub availability varies by repository visibility and plan; see
[GitHub's environment documentation](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments).

## Evidence command

Run the standard-library audit on a trusted machine or through
**Actions → github-protection-preflight → Run workflow**:

~~~sh
GH_TOKEN="$READ_ONLY_GITHUB_TOKEN" \
python scripts/audit_github_environment.py \
  --repo OWNER/SACRIFICIAL --branch main --environment staging \
  --output evidence/environment.json
~~~

The token is optional on public repositories and must be passed through a
secure environment variable, never CLI arguments. Private repositories may
require Actions/read access. The script makes a single GET request to
`api.github.com`, refuses redirects via the shared GitHub preflight
transport, caps the response at 1 MiB, and never writes credentials to
JSON evidence.

The audit enforces **all four observable conditions**:

| Check | Fail/unknown semantics |
|---|---|
| One required-reviewers protection rule with valid reviewer identities | Missing/malformed reviewer list is **FAIL**; an unreadable response is **INDETERMINATE** |
| `prevent_self_review: true` | False or omitted is **FAIL** |
| `deployment_branch_policy.protected_branches: true` and `custom_branch_policies: false` | Missing or custom branch restrictions are **FAIL**; custom policies may in fact be secure but need a separate audit |
| `can_admins_bypass: false` | True or omitted is **FAIL**, not silently accepted |

`PASS_STATIC_ENVIRONMENT` (exit 0) means these settings were observed at
that instant, **not** that a deployment is protected end-to-end.
`FAIL_STATIC_ENVIRONMENT` (exit 1) means at least one required control is
missing or cannot be proven from fields returned. `INDETERMINATE` (exit 2)
means the API read was unavailable, denied or malformed. The workflow
uploads both `audit/result.json` (rulesets) and `audit/environment.json`
(environment) on manual runs even if one audit fails, and its normal push/PR
self-tests do not audit arbitrary deployment targets.

**Next required acceptance:** Bind both JSON files to exact staging repo,
branch, ScanProof commit and run; add the four sacrificial PR URLs, explicit
contributor merge-denial and staging deploy-denial evidence, and the
independently owned policy/workflow approval records. GitLab's separately
managed pipeline execution policy and protected artifacts are still required.
