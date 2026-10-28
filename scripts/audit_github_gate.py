"""Read-only GitHub protected-gate preflight for sacrificial staging repositories.

This verifies a CONSERVATIVE single-ruleset minimum, not a real bypass test.
A result of PASS_STATIC_PREFLIGHT is never ScanProof's VERIFIED decision and
does not establish protected environments, signing provenance or GitLab policy.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

MAX_JSON_BYTES = 1024 * 1024
API = "https://api.github.com"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never forward a GitHub bearer token to an arbitrary redirect destination."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "GitHub API redirect refused", headers, fp)


_OPENER = urllib.request.build_opener(_NoRedirect())


def _branch_covered(ruleset: dict, branch: str, default_branch: str) -> bool:
    conditions = ruleset.get("conditions", {}).get("ref_name", {})
    includes = conditions.get("include", [])
    excludes = conditions.get("exclude", [])
    if not isinstance(includes, list) or not isinstance(excludes, list):
        return False
    ref = f"refs/heads/{branch}"

    def matches(pattern: str) -> bool:
        if pattern == "~ALL":
            return True
        if pattern == "~DEFAULT_BRANCH":
            return branch == default_branch
        return fnmatch.fnmatchcase(ref, pattern)

    return any(isinstance(p, str) and matches(p) for p in includes) and not any(
        isinstance(p, str) and matches(p) for p in excludes
    )


def _evaluate_one(detail: dict, check: str, app_id: int) -> list[str]:
    problems: list[str] = []
    rules = {r.get("type"): r for r in detail.get("rules", []) if isinstance(r, dict)}
    status = rules.get("required_status_checks", {}).get("parameters", {})
    checks = status.get("required_status_checks", [])
    if status.get("strict_required_status_checks_policy") is not True:
        problems.append("strict_required_status_checks_policy is not true")
    if not isinstance(checks, list) or not any(
        isinstance(c, dict)
        and c.get("context") == check
        and c.get("integration_id") == app_id
        for c in checks
    ):
        problems.append(f"trusted required status check {check!r} (app {app_id}) is missing")
    pull = rules.get("pull_request", {}).get("parameters", {})
    if not isinstance(pull.get("required_approving_review_count"), int) or (
        pull["required_approving_review_count"] < 1
    ):
        problems.append("at least one independent approving review is not required")
    if pull.get("require_code_owner_review") is not True:
        problems.append("CODEOWNER approval is not required")
    if not (
        pull.get("dismiss_stale_reviews_on_push") is True
        or pull.get("require_last_push_approval") is True
    ):
        problems.append("approval can remain valid after the proposed changes")
    if "deletion" not in rules or "non_fast_forward" not in rules:
        problems.append("branch deletion or non-fast-forward updates are not prohibited")
    if detail.get("bypass_actors") != []:
        problems.append("ruleset has bypass actors or their absence is unverified")
    return problems


def evaluate(
    repository: str,
    branch: str,
    default_branch: str,
    check: str,
    app_id: int,
    details: list[dict],
) -> dict:
    inspected = []
    for detail in details:
        if detail.get("target") != "branch" or detail.get("enforcement") != "active":
            continue
        if not _branch_covered(detail, branch, default_branch):
            continue
        problems = _evaluate_one(detail, check, app_id)
        inspected.append(
            {
                "ruleset_id": detail.get("id"),
                "name": detail.get("name"),
                "problems": problems,
            }
        )
    qualified = [item for item in inspected if not item["problems"]]
    return {
        "repository": repository,
        "branch": branch,
        "default_branch": default_branch,
        "required_check": check,
        "expected_integration_id": app_id,
        "result": "PASS_STATIC_PREFLIGHT" if qualified else "FAIL_STATIC_PREFLIGHT",
        "qualified_ruleset_ids": [item["ruleset_id"] for item in qualified],
        "inspected_rulesets": inspected,
        "limits": (
            "Static ruleset API evidence only: does not prove an independently enforced "
            "deployment environment, workflow/policy ownership, or negative bypass trials."
        ),
    }


def _fetch_json(url: str, token: str | None) -> dict | list:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "scanproof-protected-gate-preflight",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with _OPENER.open(request, timeout=20) as response:
        payload = response.read(MAX_JSON_BYTES + 1)
    if len(payload) > MAX_JSON_BYTES:
        raise ValueError("GitHub ruleset API response exceeded 1 MiB")
    return json.loads(payload)


def collect(repo: str, branch: str, check: str, app_id: int, token: str | None) -> dict:
    meta = _fetch_json(f"{API}/repos/{repo}", token)
    if not isinstance(meta, dict) or not isinstance(meta.get("default_branch"), str):
        raise ValueError("Repository metadata did not include a default branch")
    summaries = _fetch_json(
        f"{API}/repos/{repo}/rulesets?includes_parents=true&per_page=100", token
    )
    if not isinstance(summaries, list):
        raise ValueError("GitHub ruleset list is not a JSON array")
    if len(summaries) >= 100:
        raise ValueError("GitHub ruleset list may be truncated (100+); review pagination")
    details = []
    for summary in summaries:
        if not isinstance(summary, dict) or not isinstance(summary.get("id"), int):
            raise ValueError("GitHub ruleset list contains an invalid ID")
        detail = _fetch_json(f"{API}/repos/{repo}/rulesets/{summary['id']}", token)
        if not isinstance(detail, dict) or detail.get("id") != summary["id"]:
            raise ValueError("GitHub ruleset details are inconsistent with the index")
        details.append(detail)
    return evaluate(repo, branch, meta["default_branch"], check, app_id, details)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="GitHub owner/repo to audit")
    parser.add_argument("--branch", default="main")
    parser.add_argument("--check", required=True, help="Exact mandatory ScanProof check context")
    parser.add_argument("--app-id", type=int, default=15368, help="Trusted check app integration ID")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if (
        not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repo)
        or not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", args.branch)
        or ".." in args.branch
        or not args.check.strip()
        or args.app_id < 1
    ):
        parser.error("invalid repository, branch, check context or trusted app ID")
    try:
        result = collect(
            args.repo, args.branch, args.check, args.app_id, os.environ.get("GH_TOKEN")
        )
        exit_code = 0 if result["result"] == "PASS_STATIC_PREFLIGHT" else 1
    except (urllib.error.HTTPError, urllib.error.URLError, ValueError, KeyError, TypeError, AttributeError) as exc:
        # Never print an Authorization header or token. URL and numerical status only.
        status = exc.code if isinstance(exc, urllib.error.HTTPError) else None
        result = {
            "repository": args.repo,
            "branch": args.branch,
            "result": "INDETERMINATE",
            "problem": f"Could not establish effective ruleset: HTTP {status or 'unavailable/invalid'}",
        }
        exit_code = 2
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
