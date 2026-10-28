"""Live GitLab half of the copies contract (scanproof#65): real child pipelines on gitlab.com.

The public project named by GITLAB_COPIES_PROJECT (setup: docs/gitlab-copies.md) has two
branches whose scheduled pipelines are the scenarios:

- `main`:         'svc-a > copy-sast' and 'svc-b > copy-sast' (two child pipelines);
- `inaccessible`: the same, plus 'svc-private', a child in a private project the token's
                  account is not a member of (unreadable: 404 to a non-member).

For each branch this picks the latest *successful* pipeline, refuses one older than
MAX_AGE_DAYS (a contract must not keep passing on a pipeline from months ago), and runs that
branch's scenarios through verify_contract.py with the pipeline's own commit as provenance.
Reads are authenticated with GITLAB_TOKEN, a read_api token of an account that is NOT a member
of the private project (docs/gitlab-copies.md). Anonymous reads are not an option: since
19 October 2026 gitlab.com allows 60 unauthenticated API requests per hour per IP, and one run
needs about 66. The token is sent only in a header to the gitlab.com API, never printed.
If the token could read the private child, the `inaccessible` scenarios fail, so a token with
too much access can't make the contract pass.

Usage: GITLAB_COPIES_PROJECT=group/scanproof-copies GITLAB_TOKEN=... \
           python scripts/gitlab_copies_contract.py
"""

from __future__ import annotations

import json
import os
import sys
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import verify_contract  # noqa: E402

API = os.environ.get("GITLAB_URL", "https://gitlab.com").rstrip("/") + "/api/v4"
SCENARIOS = {
    "main": "policies/copies/gitlab-main-scenarios.json",
    "inaccessible": "policies/copies/gitlab-inaccessible-scenarios.json",
}


class ContractError(Exception):
    pass


def get_json(url: str):
    headers = {"Accept": "application/json"}
    token = os.environ.get("GITLAB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 - fixed https API
            return json.loads(resp.read(2_000_000))
    except (OSError, ValueError) as exc:
        raise ContractError(f"GET {url}: {exc}") from exc


def latest_pipeline(project: str, ref: str, max_age: timedelta, now: datetime) -> dict:
    path = urllib.parse.quote(project, safe="")
    query = urllib.parse.urlencode(
        {"ref": ref, "status": "success", "order_by": "id", "sort": "desc", "per_page": 1}
    )
    found = get_json(f"{API}/projects/{path}/pipelines?{query}")
    if not isinstance(found, list) or not found:
        raise ContractError(f"no successful pipeline on '{ref}' in {project}")
    pipeline = found[0]
    try:
        pid, sha = int(pipeline["id"]), str(pipeline["sha"])
        created = datetime.fromisoformat(pipeline["created_at"].replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise ContractError(f"unexpected pipeline payload for '{ref}': {exc}") from exc
    if now - created > max_age:
        raise ContractError(
            f"latest successful '{ref}' pipeline {pid} is from {created:%Y-%m-%d}, older than "
            f"{max_age.days} days: check the pipeline schedule in {project}"
        )
    return {"id": pid, "sha": sha}


def main(argv: list[str] | None = None) -> int:
    project = os.environ.get("GITLAB_COPIES_PROJECT", "").strip()
    if not project:
        print("::error title=copies gitlab::GITLAB_COPIES_PROJECT is not set")
        return 1
    if not os.environ.get("GITLAB_TOKEN", "").strip():
        print(
            "::error title=copies gitlab::GITLAB_TOKEN is not set: add the repository secret "
            "GITLAB_COPIES_TOKEN (docs/gitlab-copies.md). Anonymous gitlab.com access allows "
            "60 requests per hour per IP, fewer than one run needs"
        )
        return 1
    max_age = timedelta(days=int(os.environ.get("MAX_AGE_DAYS", "8")))
    now = datetime.now(UTC)
    failed = False
    for ref, scenarios in SCENARIOS.items():
        try:
            pipeline = latest_pipeline(project, ref, max_age, now)
        except ContractError as exc:
            print(f"::error title=copies gitlab {ref}::{exc}")
            failed = True
            continue
        print(f"::notice title=copies gitlab {ref}::pipeline {pipeline['id']} @ {pipeline['sha'][:12]}")
        rc = verify_contract.main(
            [scenarios, "--provider", "gitlab", "--project", project,
             "--pipeline", str(pipeline["id"]), "--sha", pipeline["sha"],
             "--out-dir", f"copies-gitlab/{ref}", "--title", f"copies gitlab {ref}"]  # fmt: skip
        )
        failed |= rc != 0
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
