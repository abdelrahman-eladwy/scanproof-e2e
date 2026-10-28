# Protected GitHub gate: negative PR evidence

This documents the read-only observational audit for [E2E #19](https://github.com/abdelrahman-eladwy/scanproof-e2e/issues/19) and [ScanProof #45](https://github.com/abdelrahman-eladwy/scanproof/issues/45). The new script never merges a PR, changes rulesets, alters a policy or deploys.

**OBSERVATIONAL, NOT A LIVE BYPASS PROOF:** GitHub mergeability may be blocked for unrelated reasons. Even a complete CONSISTENT_WITH_PROTECTION result cannot establish that ScanProof independently caused the block. To qualify the release gate, a contributor account must separately attempt the malicious merge and staging deployment, observe the platform reject them, and record the evidence.

## Administrator setup (sacrificial repository only)

1. Use a throwaway GitHub repository and a distinct security reviewer/CODEOWNER. Require the exact ScanProof verification check from a trusted app, strict status checking, mandatory review/CODEOWNER approval, no broad bypass and no force push/deletion. The security workflow and policy must be independently controlled. Protect a staging-only environment and use no production credentials.
2. Run the existing [read-only ruleset preflight](github-protected-gate.md), binding its JSON to the target repository/branch and actual check context. A green self-test job is NOT a passed live audit.
3. Create four independent sacrificial PRs into the protected branch, without unrelated merge conflicts:

| Case | PR content | Expected gate state |
|---|---|---|
| positive | Correct policy, current evidence, normal scan | successful |
| missing | Contributor deletes the expected gate/workflow | exact check absent |
| failed | Scan reports invalid/missing evidence; gate fails without continue-on-error | failure |
| skipped | Contributor skips the job or workflow | skipped |

4. Keep negative PRs unmerged. With a contributor identity lacking bypass authority, attempt actual merges and verify rejection; inspect staging environment and confirm deploy never executed. Also separately test policy weakening, removed deploy dependency, wrong check context, replayed signed evidence and inaccessible artifacts.

## Collect read-only PR/check observations

Run from a trusted checkout:

~~~sh
GH_TOKEN="$READ_ONLY_GITHUB_TOKEN" python scripts/audit_github_gate_trials.py \
  --repo OWNER/STAGING --branch main --check "ScanProof verification" \
  --app-id 15368 \
  --positive-pr 101 --missing-pr 102 --failed-pr 103 --skipped-pr 104 \
  --output evidence/github-gate-trials.json
~~~

Or use **Actions → github-gate-trials → Run workflow**. Four different PR numbers are required. The workflow has only contents:read; it can observe public staging PRs, but may receive permission errors on private targets. For private repositories use a separate token with read access to pull requests and checks from a trusted admin workstation. Never pass tokens via command-line arguments, URLs, or artifacts; never dispatch privileged audit tokens using unreviewed script changes.

The script checks exact PR number/target branch/head SHA, gate context/source GitHub App and completion status, missing or duplicate check runs, and the PR's reported mergeability. Missing permissions or more than 100 check runs produce INDETERMINATE rather than an accidental success.

## Interpret results

| Result | Interpretation |
|---|---|
| OBSERVED_ELIGIBLE | Positive PR has a successful gate and is clean/mergeable according to GitHub |
| OBSERVED_BLOCKED | Negative PR has the specified bad gate and GitHub currently reports blocked; **causal attribution is unproven** |
| POTENTIAL_BYPASS | Negative PR has the specified bad gate but merged or is reported clean/mergeable; immediate investigation required |
| INDETERMINATE | API incomplete/denied, unexpected source or check state, invalid metadata, or ambiguous mergeability |
| CONSISTENT_WITH_PROTECTION | All four observations match expected advisory states; **not release GO** |
| NOT_QUALIFIED | At least one observation did not satisfy the advisory contract |

Required final evidence: staging repository and branch, exact core SHA, policy/workflow ownership, ruleset ID/settings, all PR links, check-run and observation JSON, an actual rejected merge attempt by a contributor, blocked staging deploy and reviewer separation. GitLab pipeline-execution policy enforcement remains a separate requirement.

**Current gap (2026-10-28):** Core ScanProof's ruleset has six generic CI required checks but no CODEOWNER review or approving review, and no independently required ScanProof gate. The E2E repo has no repository rulesets. Neither is a qualified protected-gate target until an administrator configures sacrificial controls. See [preflight baseline](github-protected-gate.md).
