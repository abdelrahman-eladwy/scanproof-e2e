"""Offline security contract for the read-only protected GitHub gate audit."""

from __future__ import annotations

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
import audit_github_gate as audit  # noqa: E402


def protected_ruleset() -> dict:
    return {
        "id": 17,
        "name": "staging protected release",
        "target": "branch",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "bypass_actors": [],
        "rules": [
            {"type": "deletion"},
            {"type": "non_fast_forward"},
            {
                "type": "pull_request",
                "parameters": {
                    "required_approving_review_count": 1,
                    "require_code_owner_review": True,
                    "dismiss_stale_reviews_on_push": True,
                },
            },
            {
                "type": "required_status_checks",
                "parameters": {
                    "strict_required_status_checks_policy": True,
                    "required_status_checks": [
                        {"context": "ScanProof verification", "integration_id": 15368},
                    ],
                },
            },
        ],
    }


def evaluate(rulesets: list[dict], *, branch: str = "main") -> dict:
    return audit.evaluate(
        "acme/staging", branch, "main", "ScanProof verification", 15368, rulesets
    )


class RulesetContract(unittest.TestCase):
    def test_independently_protected_required_gate_passes_static_preflight(self):
        result = evaluate([protected_ruleset()])
        self.assertEqual(result["result"], "PASS_STATIC_PREFLIGHT")
        self.assertEqual(result["qualified_ruleset_ids"], [17])
        self.assertIn("does not prove", result["limits"])

    def test_no_rulesets_is_not_verified(self):
        result = evaluate([])
        self.assertEqual(result["result"], "FAIL_STATIC_PREFLIGHT")
        self.assertEqual(result["qualified_ruleset_ids"], [])

    def test_no_review_and_no_codeowner_are_blockers(self):
        rule = protected_ruleset()
        pull = next(x["parameters"] for x in rule["rules"] if x["type"] == "pull_request")
        pull.update(required_approving_review_count=0, require_code_owner_review=False)
        result = evaluate([rule])
        self.assertEqual(result["result"], "FAIL_STATIC_PREFLIGHT")
        problems = result["inspected_rulesets"][0]["problems"]
        self.assertTrue(any("approving review" in x for x in problems))
        self.assertTrue(any("CODEOWNER" in x for x in problems))

    def test_review_must_not_survive_unreviewed_push(self):
        rule = protected_ruleset()
        pull = next(x["parameters"] for x in rule["rules"] if x["type"] == "pull_request")
        pull["dismiss_stale_reviews_on_push"] = False
        result = evaluate([rule])
        self.assertEqual(result["result"], "FAIL_STATIC_PREFLIGHT")
        pull["require_last_push_approval"] = True
        self.assertEqual(evaluate([rule])["result"], "PASS_STATIC_PREFLIGHT")

    def test_missing_or_wrong_app_status_does_not_satisfy_gate(self):
        for mismatch in ("context", "integration_id"):
            with self.subTest(mismatch=mismatch):
                rule = protected_ruleset()
                status = next(
                    x["parameters"] for x in rule["rules"]
                    if x["type"] == "required_status_checks"
                )
                status["required_status_checks"][0][mismatch] = "ci" if mismatch == "context" else 42
                self.assertEqual(evaluate([rule])["result"], "FAIL_STATIC_PREFLIGHT")

    def test_non_strict_checks_and_bypass_actor_both_fail(self):
        rule = protected_ruleset()
        status = next(
            x["parameters"] for x in rule["rules"]
            if x["type"] == "required_status_checks"
        )
        status["strict_required_status_checks_policy"] = False
        rule["bypass_actors"] = [{"actor_id": 1, "actor_type": "Team", "bypass_mode": "always"}]
        self.assertEqual(evaluate([rule])["result"], "FAIL_STATIC_PREFLIGHT")

    def test_branch_deletion_and_force_push_are_not_acceptable(self):
        rule = protected_ruleset()
        rule["rules"] = [x for x in rule["rules"] if x["type"] != "non_fast_forward"]
        self.assertEqual(evaluate([rule])["result"], "FAIL_STATIC_PREFLIGHT")

    def test_branch_target_and_exclusions_must_match(self):
        rule = protected_ruleset()
        self.assertEqual(evaluate([rule], branch="release/next")["result"], "FAIL_STATIC_PREFLIGHT")
        rule["conditions"]["ref_name"]["exclude"] = ["refs/heads/main"]
        self.assertEqual(evaluate([rule])["result"], "FAIL_STATIC_PREFLIGHT")
        rule["conditions"]["ref_name"]["exclude"] = []
        rule["conditions"]["ref_name"]["include"] = ["refs/heads/release/*"]
        self.assertEqual(evaluate([rule], branch="release/next")["result"], "PASS_STATIC_PREFLIGHT")

    def test_disabled_ruleset_is_not_effective(self):
        rule = protected_ruleset()
        rule["enforcement"] = "evaluate"
        self.assertEqual(evaluate([rule])["result"], "FAIL_STATIC_PREFLIGHT")

    def test_two_partial_rulesets_do_not_create_unproven_single_rule_claim(self):
        one = protected_ruleset()
        two = protected_ruleset()
        one["rules"] = [x for x in one["rules"] if x["type"] != "pull_request"]
        two["rules"] = [x for x in two["rules"] if x["type"] != "required_status_checks"]
        self.assertEqual(evaluate([one, two])["result"], "FAIL_STATIC_PREFLIGHT")

    def test_collect_uses_read_only_metadata_and_exact_ruleset_ids(self):
        rule = protected_ruleset()
        with mock.patch.object(
            audit, "_fetch_json",
            side_effect=[
                {"default_branch": "main"},
                [{"id": 17}],
                rule,
            ],
        ) as f:
            result = audit.collect("acme/staging", "main", "ScanProof verification", 15368, None)
        self.assertEqual(result["result"], "PASS_STATIC_PREFLIGHT")
        urls = [c.args[0] for c in f.call_args_list]
        self.assertEqual(urls, [
            "https://api.github.com/repos/acme/staging",
            "https://api.github.com/repos/acme/staging/rulesets?includes_parents=true&per_page=100",
            "https://api.github.com/repos/acme/staging/rulesets/17",
        ])

    def test_inconsistent_api_details_fail_not_pass(self):
        with mock.patch.object(
            audit, "_fetch_json",
            side_effect=[{"default_branch": "main"}, [{"id": 17}], {"id": 18}],
        ):
            with self.assertRaises(ValueError):
                audit.collect("acme/staging", "main", "ScanProof verification", 15368, None)

    def test_potentially_truncated_ruleset_index_fails_closed(self):
        with mock.patch.object(
            audit, "_fetch_json",
            side_effect=[{"default_branch": "main"}, [{"id": i} for i in range(100)]],
        ):
            with self.assertRaisesRegex(ValueError, "truncated"):
                audit.collect("acme/staging", "main", "ScanProof verification", 15368, None)

    def test_authenticated_api_does_not_follow_redirects(self):
        self.assertIn(type(audit._NoRedirect()), [type(x) for x in audit._OPENER.handlers])
        req = audit.urllib.request.Request(
            "https://api.github.com/repos/acme/staging",
            headers={"Authorization": "Bearer secret"},
        )
        with self.assertRaises(urllib.error.HTTPError):
            audit._NoRedirect().redirect_request(
                req, None, 302, "Found", {}, "https://foreign.example/steal"
            )
        self.assertNotIn("secret", req.full_url)

    def test_api_token_stays_in_header_and_size_is_bounded(self):
        with mock.patch.object(audit._OPENER, "open", return_value=io.BytesIO(b'{"ok":true}')) as op:
            self.assertEqual(audit._fetch_json("https://api.github.com/repos/acme/app", "secret"),
                             {"ok": True})
            request = op.call_args.args[0]
            self.assertEqual(request.get_header("Authorization"), "Bearer secret")
            self.assertNotIn("secret", request.full_url)
        with mock.patch.object(
            audit._OPENER, "open", return_value=io.BytesIO(b"x" * (audit.MAX_JSON_BYTES + 1))
        ):
            with self.assertRaises(ValueError):
                audit._fetch_json("https://api.github.com/repos/acme/app", None)

    def test_permission_denied_yields_indeterminate_and_no_secret_in_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / "result.json"
            with (
                mock.patch.object(
                    audit,
                    "collect",
                    side_effect=urllib.error.HTTPError(
                        "https://api.github.com/repos/acme/staging", 403, "Forbidden", {}, None
                    ),
                ),
                mock.patch.dict(os.environ, {"GH_TOKEN": "private-secret"}),
            ):
                self.assertEqual(
                    audit.main([
                        "--repo", "acme/staging", "--check", "ScanProof verification",
                        "--output", str(output),
                    ]),
                    2,
                )
            evidence = output.read_text(encoding="utf-8")
            self.assertEqual(json.loads(evidence)["result"], "INDETERMINATE")
            self.assertNotIn("private-secret", evidence)


if __name__ == "__main__":
    unittest.main()
