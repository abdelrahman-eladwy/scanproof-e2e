"""Read-only GitLab security policy project *branch* preflight.

The result is a conservative snapshot of who can change the policy project.
It never establishes that a consumer project is linked to a pipeline execution
policy, or that an unauthorized staging deployment is denied.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

MAX_RESPONSE_BYTES = 1024 * 1024
TIMEOUT_SECONDS = 20
LIMITATIONS = (
    "Policy-project branch settings only; does not prove linked/active pipeline "
    "execution policy, enabled YAML, effective group inheritance, or denied "
    "merge and staging deployments."
)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "Redirect refused", headers, fp)


_OPENER = urllib.request.build_opener(_NoRedirect())


def _base_url(value: str) -> str:
    parts = urllib.parse.urlsplit(value)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
        or any(ord(c) < 33 for c in value)
    ):
        raise ValueError("GitLab URL must be a single HTTPS origin without credentials or paths")
    # IDNA and IPv6 hosts are accepted, provided urllib itself accepts the origin.
    return f"https://{parts.netloc}"


def _get_json(url: str, origin: str, token: str | None) -> dict:
    if not url.startswith(origin + "/api/v4/projects/"):
        raise ValueError("Refusing a non-project GitLab API URL")
    headers = {
        "Accept": "application/json",
        "User-Agent": "scanproof-gitlab-policy-branch-preflight",
    }
    if token:
        headers["PRIVATE-TOKEN"] = token
    req = urllib.request.Request(url, headers=headers, method="GET")
    with _OPENER.open(req, timeout=TIMEOUT_SECONDS) as resp:
        data = resp.read(MAX_RESPONSE_BYTES + 1)
    if len(data) > MAX_RESPONSE_BYTES:
        raise ValueError("GitLab API response exceeds 1 MiB")
    payload = json.loads(data)
    if not isinstance(payload, dict):
        raise ValueError("GitLab API must return a JSON object")
    return payload


def _group_only(entries: object, group_id: int, permission: str) -> list[str]:
    if not isinstance(entries, list) or not entries:
        return [f"{permission} access is missing or unverifiable"]
    issues: list[str] = []
    for item in entries:
        if not isinstance(item, dict) or (
            type(item.get("group_id")) is not int
            or item["group_id"] != group_id
            or item.get("access_level") is not None
            or item.get("user_id") is not None
            or item.get("deploy_key_id") is not None
            or item.get("member_role_id") is not None
        ):
            issues.append(f"{permission} allows an unapproved or unidentified actor")
            break
    return issues


def evaluate(project: str, branch: str, group_id: int, meta: dict, rule: dict) -> dict:
    if meta.get("path_with_namespace") != project or type(meta.get("id")) is not int:
        raise ValueError("Project path/ID could not be confirmed")
    if rule.get("name") != branch:
        raise ValueError("Protected branch rule did not match requested branch")
    problems: list[str] = []
    if rule.get("allow_force_push") is not False:
        problems.append("force push is allowed or unspecified")
    if rule.get("code_owner_approval_required") is not True:
        problems.append("CODEOWNER approval not required or unverified")
    for field in ("push_access_levels", "merge_access_levels", "unprotect_access_levels"):
        problems.extend(_group_only(rule.get(field), group_id, field.removesuffix("_access_levels")))
    return {
        "project": project,
        "project_id": meta["id"],
        "branch": branch,
        "expected_security_group_id": group_id,
        "observed_at_utc": datetime.now(UTC).isoformat(),
        "result": "PASS_STATIC_POLICY_BRANCH" if not problems else "FAIL_STATIC_POLICY_BRANCH",
        "problems": problems,
        "limits": LIMITATIONS,
    }


def collect(origin: str, project: str, branch: str, group_id: int, token: str | None) -> dict:
    base = _base_url(origin)
    pid = urllib.parse.quote(project, safe="")
    b = urllib.parse.quote(branch, safe="")
    meta = _get_json(f"{base}/api/v4/projects/{pid}", base, token)
    rule = _get_json(f"{base}/api/v4/projects/{pid}/protected_branches/{b}", base, token)
    return evaluate(project, branch, group_id, meta, rule)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--url", default="https://gitlab.com")
    p.add_argument("--project", required=True, help="Separate security policy project path")
    p.add_argument("--branch", default="main")
    p.add_argument("--security-group-id", type=int, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args(argv)
    if (
        not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+", args.project)
        or not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", args.branch)
        or ".." in args.project
        or ".." in args.branch
        or args.security_group_id < 1
    ):
        p.error("invalid policy project, branch, or independent security group ID")
    try:
        result = collect(
            args.url, args.project, args.branch, args.security_group_id, os.environ.get("GITLAB_TOKEN")
        )
        exit_code = 0 if result["result"] == "PASS_STATIC_POLICY_BRANCH" else 1
    except (
        urllib.error.HTTPError,
        urllib.error.URLError,
        ValueError,
        TypeError,
        KeyError,
        OSError,
    ) as exc:
        status = exc.code if isinstance(exc, urllib.error.HTTPError) else None
        result = {
            "project": args.project,
            "branch": args.branch,
            "result": "INDETERMINATE",
            "problem": f"Could not establish policy branch protections: HTTP {status or 'unavailable/invalid'}",
            "limits": LIMITATIONS,
        }
        exit_code = 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
