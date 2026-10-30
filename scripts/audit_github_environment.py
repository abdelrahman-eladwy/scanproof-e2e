"""Read-only GitHub staging environment protection preflight.

This checks an environment's *settings*, not whether an actual deployment
depends on ScanProof or a contributor was denied a bypass. It never mutates
a repository or requests a privileged token.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import urllib.error
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

from audit_github_gate import API, _fetch_json

LIMITS = (
    "Static environment settings only. Does not prove protected job dependencies, "
    "independent policy ownership, a denied staging deployment, or GitLab enforcement."
)


def evaluate(
    repo: str, branch: str, name: str, data: dict, *, classic_protection: bool | None
) -> dict:
    """Fail closed on missing, weak or unrecognizable environment controls.

    ``classic_protection`` must be exactly True for a "protected branches only"
    policy to count. GitHub documents that policy in terms of branch protection
    rules (all branches may deploy when none exist); rulesets are not documented
    to qualify, so a ruleset-only branch is not accepted as a restriction.
    """
    if not isinstance(data, dict) or data.get("name") != name:
        raise ValueError("GitHub environment metadata does not match the requested environment")

    problems: list[str] = []
    rules = data.get("protection_rules")
    if not isinstance(rules, list):
        raise ValueError("Environment protection_rules are missing or malformed")
    approvals = [r for r in rules if isinstance(r, dict) and r.get("type") == "required_reviewers"]
    if len(approvals) != 1:
        problems.append("exactly one required_reviewers protection rule must be present")
    else:
        rule = approvals[0]
        if rule.get("prevent_self_review") is not True:
            problems.append("deployment initiator is allowed to self-approve")
        reviewers = rule.get("reviewers")
        if not isinstance(reviewers, list) or not reviewers or not all(
            isinstance(item, dict)
            and item.get("type") in ("User", "Team")
            and isinstance(item.get("reviewer"), dict)
            and type(item["reviewer"].get("id")) is int
            and item["reviewer"]["id"] > 0
            for item in reviewers
        ):
            problems.append("independently accountable required reviewers are missing or invalid")

    branch_policy = data.get("deployment_branch_policy")
    if not isinstance(branch_policy, dict):
        problems.append("deployment branch restriction is missing")
    elif branch_policy.get("protected_branches") is not True or (
        branch_policy.get("custom_branch_policies") is not False
    ):
        # A custom-policy environment can also be secure, but cannot be established
        # without separately inspecting its policy patterns and active branch rules.
        problems.append("deployment is not restricted to branches with branch protection")
    elif classic_protection is not True:
        problems.append(
            "protected-branches deployment policy relies on classic branch protection, "
            "which is absent or unverified on the audited branch; rulesets alone are not "
            "documented to restrict environment deployments"
        )

    # Omission is unknown. A false PASS is worse than a conservative blocker.
    if data.get("can_admins_bypass") is not False:
        problems.append("administrator environment bypass is allowed or unverified")

    return {
        "repository": repo,
        "branch": branch,
        "environment": name,
        "observed_at_utc": datetime.now(UTC).isoformat(),
        "result": "PASS_STATIC_ENVIRONMENT" if not problems else "FAIL_STATIC_ENVIRONMENT",
        "problems": problems,
        "required_reviewer_count": (
            len(approvals[0].get("reviewers", []))
            if len(approvals) == 1 and isinstance(approvals[0].get("reviewers"), list)
            else 0
        ),
        "protected_branches_only": isinstance(branch_policy, dict)
        and branch_policy.get("protected_branches") is True
        and branch_policy.get("custom_branch_policies") is False,
        "classic_branch_protection": classic_protection,
        "limits": LIMITS,
    }


def classic_branch_protection(repo: str, branch: str, token: str | None) -> bool:
    """Return True/False only on an unambiguous answer; raise otherwise.

    Requires Administration read. A 403, or any 404 other than GitHub's explicit
    "Branch not protected", is unknown and propagates as INDETERMINATE.
    """
    url = f"{API}/repos/{repo}/branches/{quote(branch, safe='/')}/protection"
    try:
        data = _fetch_json(url, token)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            try:
                body = json.loads(exc.read(4096) or b"{}")
            except (ValueError, OSError):
                body = {}
            if isinstance(body, dict) and body.get("message") == "Branch not protected":
                return False
        raise
    if not isinstance(data, dict) or not isinstance(data.get("url"), str):
        raise ValueError("Branch protection response is malformed")
    return True


def collect(repo: str, branch: str, name: str, token: str | None) -> dict:
    # quote(..., safe="") prevents slashes or spaces in environment names from
    # being interpreted as new URL path segments. Only fixed GitHub endpoints.
    data = _fetch_json(f"{API}/repos/{repo}/environments/{quote(name, safe='')}", token)
    classic = classic_branch_protection(repo, branch, token)
    return evaluate(repo, branch, name, data, classic_protection=classic)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--branch", default="main")
    parser.add_argument("--environment", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if (
        not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repo)
        or not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", args.branch)
        or ".." in args.branch
        or not 1 <= len(args.environment) <= 100
        or any(ord(char) < 32 or char == "\x7f" for char in args.environment)
        or args.environment in (".", "..")
    ):
        parser.error("invalid repository, branch or staging environment")
    try:
        result = collect(args.repo, args.branch, args.environment, os.environ.get("GH_TOKEN"))
        status = 0 if result["result"] == "PASS_STATIC_ENVIRONMENT" else 1
    except (urllib.error.HTTPError, urllib.error.URLError, ValueError, KeyError, TypeError, OSError) as exc:
        code = exc.code if isinstance(exc, urllib.error.HTTPError) else None
        result = {
            "repository": args.repo,
            "branch": args.branch,
            "environment": args.environment,
            "result": "INDETERMINATE",
            "reason": f"Could not establish protected environment: HTTP {code or 'unavailable/invalid'}",
            "limits": LIMITS,
        }
        status = 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
