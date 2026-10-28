"""Adversarial, offline tests of read-only staging environment audit."""

from __future__ import annotations

import copy
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
import audit_github_environment as audit  # noqa: E402
import audit_github_gate as core  # noqa: E402

REPO = "acme/sacrificial"


def protected() -> dict:
    return {
        "name": "staging",
        "can_admins_bypass": False,
        "protection_rules": [
            {
                "id": 11,
                "type": "required_reviewers",
                "prevent_self_review": True,
                "reviewers": [
                    {"type": "Team", "reviewer": {"id": 42, "slug": "security-reviewers"}}
                ],
            },
            {"id": 12, "type": "branch_policy"},
        ],
        "deployment_branch_policy": {
            "protected_branches": True,
            "custom_branch_policies": False,
        },
    }


def check(data: dict) -> dict:
    return audit.evaluate(REPO, "main", "staging", data)


class EnvironmentContract(unittest.TestCase):
    def test_protected_environment_passes_static_preflight_only(self):
        result = check(protected())
        self.assertEqual(result["result"], "PASS_STATIC_ENVIRONMENT")
        self.assertEqual(result["required_reviewer_count"], 1)
        self.assertTrue(result["protected_branches_only"])
        self.assertIn("does not prove", result["limits"].lower())

    def test_no_reviewers_or_no_protection_is_not_pass(self):
        for rules in ([], [{"type": "wait_timer", "wait_timer": 10}]):
            with self.subTest(rules=rules):
                env = protected()
                env["protection_rules"] = rules
                self.assertEqual(check(env)["result"], "FAIL_STATIC_ENVIRONMENT")

    def test_self_review_allowed_is_not_pass(self):
        env = protected()
        env["protection_rules"][0]["prevent_self_review"] = False
        result = check(env)
        self.assertEqual(result["result"], "FAIL_STATIC_ENVIRONMENT")
        self.assertTrue(any("self-approve" in p for p in result["problems"]))

    def test_invalid_reviewer_list_never_counts_as_independent_approval(self):
        variants = [
            [], None, [{"type": "User", "reviewer": {"id": 0}}],
            [{"type": "User", "reviewer": {"id": True}}],
            [{"type": "Bot", "reviewer": {"id": 9}}],
            [{"type": "Team", "reviewer": {}}],
        ]
        for reviewers in variants:
            with self.subTest(reviewers=reviewers):
                env = protected()
                env["protection_rules"][0]["reviewers"] = reviewers
                self.assertEqual(check(env)["result"], "FAIL_STATIC_ENVIRONMENT")

    def test_duplicate_review_protection_is_not_ambiguous_pass(self):
        env = protected()
        env["protection_rules"].append(copy.deepcopy(env["protection_rules"][0]))
        self.assertEqual(check(env)["result"], "FAIL_STATIC_ENVIRONMENT")

    def test_branch_restriction_must_require_protected_branches(self):
        for branch_policy in (
            None,
            {"protected_branches": False, "custom_branch_policies": True},
            {"protected_branches": False, "custom_branch_policies": False},
            {"protected_branches": True},
        ):
            with self.subTest(branch_policy=branch_policy):
                env = protected()
                env["deployment_branch_policy"] = branch_policy
                result = check(env)
                self.assertEqual(result["result"], "FAIL_STATIC_ENVIRONMENT")

    def test_admin_bypass_enabled_or_unknown_blocks_static_attestation(self):
        for state in (True, None, "false"):
            with self.subTest(state=state):
                env = protected()
                env["can_admins_bypass"] = state
                self.assertEqual(check(env)["result"], "FAIL_STATIC_ENVIRONMENT")
        env = protected()
        del env["can_admins_bypass"]
        self.assertEqual(check(env)["result"], "FAIL_STATIC_ENVIRONMENT")

    def test_inconsistent_or_missing_environment_data_is_indeterminate(self):
        for bad in (None, [], {}, {"name": "production"}, {"name": "staging"}):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    check(bad)

    def test_fetch_is_read_only_and_escapes_environment_name(self):
        env = protected()
        env["name"] = "staging/review"
        with mock.patch.object(audit, "_fetch_json", return_value=env) as fetch:
            result = audit.collect(REPO, "main", "staging/review", "read-only")
        self.assertEqual(result["result"], "PASS_STATIC_ENVIRONMENT")
        fetch.assert_called_once_with(
            "https://api.github.com/repos/acme/sacrificial/environments/staging%2Freview",
            "read-only",
        )

    def test_unauthorized_read_is_indeterminate_and_token_not_printed(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "audit.json"
            with (
                mock.patch.object(
                    audit, "collect",
                    side_effect=urllib.error.HTTPError(
                        "https://api.github.com/repos/acme/sacrificial/environments/staging",
                        403, "secret details", {}, None,
                    ),
                ),
                mock.patch.dict(os.environ, {"GH_TOKEN": "private-auth-token"}),
            ):
                exit_status = audit.main(
                    ["--repo", REPO, "--environment", "staging", "--output", str(path)]
                )
            evidence = path.read_text()
            self.assertEqual(exit_status, 2)
            self.assertEqual(json.loads(evidence)["result"], "INDETERMINATE")
            self.assertNotIn("private-auth-token", evidence)
            self.assertNotIn("secret details", evidence)

    def test_missing_environment_fails_closed_as_unknown(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "audit.json"
            with mock.patch.object(
                audit, "collect",
                side_effect=urllib.error.HTTPError(
                    "https://api.github.com/repos/acme/sacrificial/environments/staging",
                    404, "Not Found", {}, None,
                ),
            ):
                status = audit.main(
                    ["--repo", REPO, "--environment", "staging", "--output", str(path)]
                )
            self.assertEqual(status, 2)
            self.assertEqual(json.loads(path.read_text())["result"], "INDETERMINATE")

    def test_token_safe_redirect_refusal_and_bounded_payload_are_reused(self):
        req = core.urllib.request.Request(
            "https://api.github.com/repos/acme/sacrificial/environments/staging",
            headers={"Authorization": "Bearer private"},
        )
        with self.assertRaises(urllib.error.HTTPError):
            core._NoRedirect().redirect_request(
                req, None, 302, "Found", {}, "https://foreign.invalid/collect"
            )
        with mock.patch.object(
            core._OPENER, "open", return_value=io.BytesIO(b"x" * (core.MAX_JSON_BYTES + 1))
        ):
            with self.assertRaises(ValueError):
                core._fetch_json(req.full_url, "private")
        self.assertNotIn("private", req.full_url)

    def test_malformed_json_is_indeterminate(self):
        with mock.patch.object(core._OPENER, "open", return_value=io.BytesIO(b"not-json")):
            with self.assertRaises(ValueError):
                audit.collect(REPO, "main", "staging", None)


if __name__ == "__main__":
    unittest.main()
