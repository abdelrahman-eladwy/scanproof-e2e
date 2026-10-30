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


def check(data: dict, classic: bool | None = True) -> dict:
    return audit.evaluate(REPO, "main", "staging", data, classic_protection=classic)


def http_error(code: int, body: bytes) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        "https://api.github.com/repos/acme/sacrificial/branches/main/protection",
        code, "err", {}, io.BytesIO(body),
    )


PROTECTION = {"url": "https://api.github.com/repos/acme/sacrificial/branches/main/protection"}


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
        with mock.patch.object(audit, "_fetch_json", side_effect=[env, PROTECTION]) as fetch:
            result = audit.collect(REPO, "main", "staging/review", "read-only")
        self.assertEqual(result["result"], "PASS_STATIC_ENVIRONMENT")
        self.assertEqual(
            [c.args for c in fetch.call_args_list],
            [
                ("https://api.github.com/repos/acme/sacrificial/environments/staging%2Freview",
                 "read-only"),
                ("https://api.github.com/repos/acme/sacrificial/branches/main/protection",
                 "read-only"),
            ],
        )

    def test_ruleset_only_branch_never_satisfies_protected_branches_policy(self):
        # Regression for #35: gate-lab main had a ruleset but no classic rule.
        for classic in (False, None):
            with self.subTest(classic=classic):
                result = check(protected(), classic)
                self.assertEqual(result["result"], "FAIL_STATIC_ENVIRONMENT")
                self.assertTrue(any("classic branch protection" in p for p in result["problems"]))
                self.assertIsNot(result["classic_branch_protection"], True)

    def test_classic_protection_is_a_required_explicit_input(self):
        with self.assertRaises(TypeError):
            audit.evaluate(REPO, "main", "staging", protected())  # type: ignore[call-arg]

    def test_explicit_not_protected_404_is_absent(self):
        env = protected()
        with mock.patch.object(
            audit, "_fetch_json",
            side_effect=[env, http_error(404, b'{"message": "Branch not protected"}')],
        ):
            result = audit.collect(REPO, "main", "staging", "t")
        self.assertEqual(result["result"], "FAIL_STATIC_ENVIRONMENT")
        self.assertIs(result["classic_branch_protection"], False)

    def test_unauthorized_or_ambiguous_protection_read_is_unknown_not_absent(self):
        for err in (
            http_error(403, b'{"message": "Resource not accessible by integration"}'),
            http_error(404, b'{"message": "Not Found"}'),
            http_error(404, b"not-json"),
            http_error(500, b""),
        ):
            with self.subTest(code=err.code):
                with mock.patch.object(audit, "_fetch_json", side_effect=[protected(), err]):
                    with self.assertRaises(urllib.error.HTTPError):
                        audit.collect(REPO, "main", "staging", "t")

    def selected(self) -> dict:
        env = protected()
        env["deployment_branch_policy"] = {
            "protected_branches": False,
            "custom_branch_policies": True,
        }
        return env

    def test_exact_single_main_branch_policy_passes(self):
        # #37: gate-lab staging = Selected branches -> one literal `main` rule.
        rules = [{"id": 1, "name": "main", "type": "branch"}]
        result = audit.evaluate(
            REPO, "main", "staging", self.selected(),
            classic_protection=None, branch_policies=rules,
        )
        self.assertEqual(result["result"], "PASS_STATIC_ENVIRONMENT")
        self.assertTrue(result["exact_branch_policy_only"])

    def test_any_broader_or_ambiguous_custom_policy_fails(self):
        cases = {
            "unread": None,
            "empty": [],
            "wildcard": [{"name": "*", "type": "branch"}],
            "glob": [{"name": "ma*n", "type": "branch"}],
            "other branch": [{"name": "release", "type": "branch"}],
            "tag named main": [{"name": "main", "type": "tag"}],
            "missing type": [{"name": "main"}],
            "two rules": [
                {"name": "main", "type": "branch"},
                {"name": "lab/env-probe", "type": "branch"},
            ],
            "non-str name": [{"name": ["main"], "type": "branch"}],
            "case": [{"name": "Main", "type": "branch"}],
            "not a dict": ["main"],
        }
        for label, rules in cases.items():
            with self.subTest(label):
                result = audit.evaluate(
                    REPO, "main", "staging", self.selected(),
                    classic_protection=None, branch_policies=rules,
                )
                self.assertEqual(result["result"], "FAIL_STATIC_ENVIRONMENT")
                self.assertFalse(result["exact_branch_policy_only"])

    def test_custom_policy_collect_reads_rules_not_classic_protection(self):
        listing = {"total_count": 1, "branch_policies": [{"name": "main", "type": "branch"}]}
        with mock.patch.object(
            audit, "_fetch_json", side_effect=[self.selected(), listing]
        ) as fetch:
            result = audit.collect(REPO, "main", "staging", "t")
        self.assertEqual(result["result"], "PASS_STATIC_ENVIRONMENT")
        urls = [c.args[0] for c in fetch.call_args_list]
        self.assertEqual(
            urls[1],
            "https://api.github.com/repos/acme/sacrificial/environments/staging"
            "/deployment-branch-policies?per_page=100",
        )
        self.assertFalse(any("/protection" in u for u in urls))

    def test_incomplete_or_malformed_rule_listing_is_indeterminate(self):
        for listing in (
            {"total_count": 2, "branch_policies": [{"name": "main", "type": "branch"}]},
            {"branch_policies": [{"name": "main", "type": "branch"}]},
            {"total_count": 1},
            [],
            {"total_count": True, "branch_policies": [{"name": "main", "type": "branch"}]},
        ):
            with self.subTest(listing=listing):
                with mock.patch.object(
                    audit, "_fetch_json", side_effect=[self.selected(), listing]
                ):
                    with self.assertRaises(ValueError):
                        audit.collect(REPO, "main", "staging", "t")

    def test_unreadable_rule_listing_is_indeterminate(self):
        with mock.patch.object(
            audit, "_fetch_json",
            side_effect=[self.selected(), http_error(403, b'{"message": "Forbidden"}')],
        ):
            with self.assertRaises(urllib.error.HTTPError):
                audit.collect(REPO, "main", "staging", "t")

    def test_malformed_protection_payload_is_indeterminate(self):
        for bad in ([], {}, {"url": 1}):
            with self.subTest(bad=bad):
                with mock.patch.object(audit, "_fetch_json", side_effect=[protected(), bad]):
                    with self.assertRaises(ValueError):
                        audit.collect(REPO, "main", "staging", "t")

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
