"""Read-only acceptance observations for protected ScanProof staging PRs.

This CANNOT prove that an attempted merge or deployment was denied: it only
checks GitHub's reported PR mergeability and the exact gate check-run outcome.
A qualified release gate still requires independently owned protections and a
human-recorded negative merge/deploy trial.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path

API = "https://api.github.com"
MAX_BYTES = 1024 * 1024
CASES = ("positive", "missing", "failed", "skipped")


class RefusedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "Redirect refused", headers, fp)


OPENER = urllib.request.build_opener(RefusedRedirect())


def fetch_json(url: str, token: str | None) -> dict:
    if not url.startswith(f"{API}/repos/"):
        raise ValueError("Refused non-GitHub API URL")
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "scanproof-gate-trial-observer",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    with OPENER.open(urllib.request.Request(url, headers=headers), timeout=20) as resp:
        data = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("API payload too large")
    parsed = json.loads(data)
    if not isinstance(parsed, dict):
        raise ValueError("API response must be an object")
    return parsed


def observe_pr(repo: str, branch: str, case: str, number: int, check: str, app_id: int,
               token: str | None) -> dict:
    pr = fetch_json(f"{API}/repos/{repo}/pulls/{number}", token)
    base = pr.get("base", {})
    head = pr.get("head", {})
    sha = head.get("sha")
    if (
        not isinstance(base, dict) or base.get("ref") != branch
        or not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha)
        or pr.get("number") != number
    ):
        raise ValueError("PR branch/number/head metadata does not match requested target")
    checks = fetch_json(
        f"{API}/repos/{repo}/commits/{sha}/check-runs?per_page=100", token
    )
    all_runs = checks.get("check_runs")
    if not isinstance(all_runs, list) or checks.get("total_count") != len(all_runs):
        raise ValueError("Incomplete or malformed check-run inventory; pagination required")
    matching = [
        r for r in all_runs if isinstance(r, dict) and r.get("name") == check
    ]
    if len(matching) > 1:
        raise ValueError("Ambiguous duplicate gate check runs at same commit")
    found = matching[0] if matching else None
    if found:
        app = found.get("app")
        if not isinstance(app, dict) or app.get("id") != app_id:
            raise ValueError("Gate check has unexpected GitHub App source")
        if found.get("head_sha") != sha:
            raise ValueError("Gate check belongs to an unexpected head commit")
        if found.get("status") != "completed":
            raise ValueError("Gate check is not completed")
        if found.get("conclusion") not in (
            "success", "failure", "skipped", "cancelled", "timed_out", "neutral",
            "action_required", "stale",
        ):
            raise ValueError("Completed gate check has unrecognized conclusion")
    conclusion = found.get("conclusion") if found else None
    merge_state = pr.get("mergeable_state")
    if merge_state not in ("clean", "blocked", "dirty", "behind", "unstable", "draft", "unknown"):
        raise ValueError("Unknown PR mergeability state")
    if pr.get("state") not in ("open", "closed"):
        raise ValueError("Unknown PR state")
    merged = pr.get("merged_at") is not None
    expected = {
        "positive": "success",
        "missing": None,
        "failed": "failure",
        "skipped": "skipped",
    }[case]
    result = "INDETERMINATE"
    if case == "positive":
        if conclusion == "success" and merge_state == "clean" and pr.get("mergeable") is True:
            result = "OBSERVED_ELIGIBLE"
    elif merged:
        result = "POTENTIAL_BYPASS" if conclusion == expected else "INDETERMINATE"
    elif conclusion == expected and pr.get("state") == "open":
        if merge_state == "blocked":
            result = "OBSERVED_BLOCKED"
        elif merge_state == "clean" and pr.get("mergeable") is True:
            result = "POTENTIAL_BYPASS"

    return {
        "case": case,
        "pr": number,
        "pr_url": f"https://github.com/{repo}/pull/{number}",
        "target_branch": branch,
        "head_sha": sha,
        "gate_context": check,
        "gate_app_id": app_id if found else None,
        "gate_conclusion": conclusion if found else "ABSENT",
        "mergeable_state": merge_state,
        "mergeable": pr.get("mergeable"),
        "merged": merged,
        "observation": result,
        "caveat": (
            "Mergeable state is advisory and may be blocked for unrelated reasons. "
            "This observation is not an attempted-merge rejection, deployment denial, "
            "or proof of workflow/policy independence."
        ),
    }


def collect(repo: str, branch: str, check: str, app_id: int, cases: dict[str, int],
            token: str | None) -> dict:
    observations = []
    for kind in CASES:
        observations.append(observe_pr(repo, branch, kind, cases[kind], check, app_id, token))
    positive = observations[0]["observation"] == "OBSERVED_ELIGIBLE"
    negative = all(x["observation"] == "OBSERVED_BLOCKED" for x in observations[1:])
    return {
        "repository": repo,
        "branch": branch,
        "check": check,
        "app_id": app_id,
        "observed_at_utc": datetime.now(UTC).isoformat(),
        "result": "CONSISTENT_WITH_PROTECTION" if positive and negative else "NOT_QUALIFIED",
        "observations": observations,
        "limits": (
            "Read-only observation. An administrator must separately capture the actual "
            "denied merge, staging deployment and independently enforced rules/ownership."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", required=True)
    p.add_argument("--branch", default="main")
    p.add_argument("--check", required=True)
    p.add_argument("--app-id", type=int, default=15368)
    for case in CASES:
        p.add_argument(f"--{case}-pr", type=int, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args(argv)
    numbers = {case: getattr(args, f"{case}_pr") for case in CASES}
    if (
        not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repo)
        or not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", args.branch)
        or ".." in args.branch or not args.check.strip() or args.app_id < 1
        or any(n <= 0 for n in numbers.values())
        or len(set(numbers.values())) != len(numbers)
    ):
        p.error("Invalid repository/branch/check/app or duplicate/invalid PR numbers")
    try:
        result = collect(
            args.repo, args.branch, args.check, args.app_id, numbers, os.environ.get("GH_TOKEN")
        )
        status = 0 if result["result"] == "CONSISTENT_WITH_PROTECTION" else 1
    except (urllib.error.HTTPError, urllib.error.URLError, ValueError, KeyError, TypeError,
            AttributeError, OSError) as exc:
        # Never include the token, API body, PR title or provider error message.
        code = exc.code if isinstance(exc, urllib.error.HTTPError) else None
        result = {
            "repository": args.repo,
            "branch": args.branch,
            "result": "INDETERMINATE",
            "reason": f"Could not establish evidence: HTTP {code or 'unavailable/invalid'}",
        }
        status = 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
