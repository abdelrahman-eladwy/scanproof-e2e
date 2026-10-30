# GitLab policy-project protected-branch preflight (read-only)

This is a source-control trust-boundary check for [ScanProof core #25](https://github.com/abdelrahman-eladwy/scanproof/issues/25), [#26](https://github.com/abdelrahman-eladwy/scanproof/issues/26) and [#45](https://github.com/abdelrahman-eladwy/scanproof/issues/45). **It does not prove that a GitLab pipeline execution policy is installed, linked or enforced.** No release GO decision may be based on a successful static preflight.

Official GitLab guidance: [security policy projects](https://docs.gitlab.com/user/application_security/policies/enforcement/security_policy_projects/), [pipeline execution policies](https://docs.gitlab.com/user/application_security/policies/pipeline_execution_policies/), [protected branches API](https://docs.gitlab.com/api/protected_branches/). Centrally enforced pipeline execution policies require an appropriate GitLab Ultimate setup and a security-controlled policy project; including a protected template from app-editable CI YAML alone is insufficient.

## Admin-owned staging setup

1. In a GitLab Ultimate test group, create **two separate projects**: application under an application team, and a security policy project controlled by an **independent security group**. Do not use any live production deployment credentials.
2. Secure the policy project default branch. Allow push, merge and unprotect actions **only to the specific security group ID**. Prohibit force pushes and require CODEOWNER approval. Ensure the security group membership excludes the app contributors under test.
3. In the security policy project, put the security policy YAML under `.gitlab/security-policies/policy.yml`. Configure a **pipeline execution policy** with `enabled: true`, a reviewed independent CI configuration `content.include`, and an explicit `skip_ci: - allowed: false` (or equivalent documented default that ignores skip directives). Use ScanProof's `assurance.profile: production` with independently reviewed scanner requirements. Set up CI config permissions according to GitLab's policy-project access requirements.
4. **Link the security policy project to the application group/project through GitLab Secure → Policies.** Verify the effective policy scope, enabling, ownership, and inherited/group configuration manually. This audit does **not** query policy linkage or parse policy YAML.
5. Configure protected application branches, approvers, and a staging-only deploy. Run two real pipelines: valid current evidence allows a controlled staging deploy; removing/changing/skipping the gate or app CI pipeline cannot bypass externally injected policy jobs. Check `[skip ci]`, `allow_failure`, forged evidence, a removed deploy dependency, new run attempts, private artifact permission failures, and the positive release separately. Keep malicious MRs unmerged.
6. Retain project/group/branch IDs, policy commit SHA, API observations, merge-request/pipeline URLs, and actual denied merge/deployment evidence. Record GitLab version and tier. Repeat required cases for GitHub separately.

## Offline tests and read-only audit

The audit has no third-party Python dependencies. Run:

~~~sh
python -m unittest -q scripts/test_audit_gitlab_policy_project.py
GITLAB_TOKEN="$READ_ONLY_GITLAB_TOKEN" \
python scripts/audit_gitlab_policy_project.py \
  --url https://gitlab.com --project GROUP/SECURITY-POLICY-PROJECT \
  --branch main --security-group-id 1729 \
  --output evidence/gitlab-policy-branch.json
~~~

Replace 1729 with the **real** security group ID. Never paste a real token in a CLI argument. Use a token with **read-only API scope and permission to inspect the security policy project**. On GitHub, **Actions → gitlab-policy-preflight → Run workflow** makes the same read-only check: its optional `GITLAB_POLICY_AUDIT_TOKEN` repository secret is used only by the manually dispatched audit job. Ordinary PR/push runs execute only the offline self-tests; a green self-test is not a green target audit. This workflow cannot access private GitLab policy projects unless a maintainer has separately configured the read-only secret.

The script makes two GETs (project metadata and exact protected branch) using a specified HTTPS origin, never follows redirects, uses 20-second timeouts, refuses payloads above 1 MiB, and records no response bodies, usernames or access tokens in the evidence output. It cannot change settings.

It verifies that the project and branch match the requested exact names **and the protected branch is the project's actual default branch**; the branch prohibits force push and requires CODEOWNER approval; and **each** reported push, merge and unprotect actor is identified as the expected security group, with no generic role, other group, individual, or deploy key allowance. This is intentionally stricter than GitLab permits: a securely governed policy using another configuration may be flagged for manual review.

| Result | Meaning |
|---|---|
| `PASS_STATIC_POLICY_BRANCH` (exit 0) | Those specific project-level protected-branch settings appeared in the API at observation time |
| `FAIL_STATIC_POLICY_BRANCH` (exit 1) | Broad or missing actors, absent CODEOWNER protection, force push, or another observable violation |
| `INDETERMINATE` (exit 2) | Unauthorized/missing API access, malformed or mismatched project/branch response, oversized response, redirect, or network error |

**Known limitations:** The REST data may omit `unprotect_access_levels` for some user permissions or GitLab versions; absence deliberately fails rather than assuming protection. Parent group/instance owners and administrators may retain powers not exposed by project-level lists, so a positive result does not establish complete administrator separation. An application author who can reconfigure the policy link might still bypass enforcement. Nothing in this audit verifies policy YAML semantics or that the injecting pipeline actually executes ScanProof. Only explicit **live staging negative trials** can close Phase 2.

Retain this audit JSON with the [GitHub ruleset and staging environment observations](github-protected-gate.md) and the separate protected-deploy acceptance evidence. Keep #25/#26/#45 open until real provider rejection is demonstrated.
