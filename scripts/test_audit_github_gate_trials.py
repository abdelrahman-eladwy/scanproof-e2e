"""Offline fault-injection tests for read-only protected-gate PR observations."""

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
import audit_github_gate_trials as audit  # noqa: E402

REPO = "acme/throwaway"
SHA = "a" * 40
CHECK = "ScanProof verification"
APP = 15368


def make_pr(n=1, *, branch="main", merge_state="blocked", mergeable=False,
            merged=False):
    return {
        "number": n,
        "base": {"ref": branch},
        "head": {"sha": SHA},
        "state": "closed" if merged else "open",
        "merged_at": "2026-10-28T00:00:00Z" if merged else None,
        "mergeable_state": merge_state,
        "mergeable": mergeable,
    }


def make_checks(outcome=None, *, context=CHECK, app=APP, total=None, duplicates=False):
    runs = [] if outcome is None else [{
        "name": context,
        "app": {"id": app},
        "status": "completed",
        "conclusion": outcome,
        "head_sha": SHA,
    }]
    if duplicates:
        runs = runs + runs
    return {"check_runs": runs, "total_count": len(runs) if total is None else total}


def observe(case, *, outcome=None, merge_state="blocked", mergeable=False,
            merged=False, checks=None):
    p = make_pr(17, merge_state=merge_state, mergeable=mergeable, merged=merged)
    c = checks if checks is not None else make_checks(outcome)
    with mock.patch.object(audit, "fetch_json", side_effect=[p, c]) as fetch:
        value = audit.observe_pr(REPO, "main", case, 17, CHECK, APP, None)
    self_url = fetch.call_args_list[0].args[0]
    return value, self_url


class TrialContract(unittest.TestCase):
    def test_positive_check_and_mergable_pr_are_only_observed(self):
        result, url = observe("positive", outcome="success", merge_state="clean", mergeable=True)
        self.assertEqual(result["observation"], "OBSERVED_ELIGIBLE")
        self.assertEqual(url, "https://api.github.com/repos/acme/throwaway/pulls/17")
        self.assertIn("not an attempted-merge rejection", result["caveat"])

    def test_unmodified_release_blocked_by_unrelated_control_is_inconclusive(self):
        result, _ = observe("positive", outcome="success")
        self.assertEqual(result["observation"], "INDETERMINATE")

    def test_removed_gate_and_blocked_pr_consistent_with_protection(self):
        result, _ = observe("missing", outcome=None)
        self.assertEqual(result["observation"], "OBSERVED_BLOCKED")
        self.assertEqual(result["gate_conclusion"], "ABSENT")

    def test_failing_gate_and_blocked_pr_consistent_with_protection(self):
        result, _ = observe("failed", outcome="failure")
        self.assertEqual(result["observation"], "OBSERVED_BLOCKED")

    def test_skipped_required_gate_is_not_accepted_as_success(self):
        result, _ = observe("skipped", outcome="skipped")
        self.assertEqual(result["observation"], "OBSERVED_BLOCKED")
        result, _ = observe("skipped", outcome="skipped", merge_state="clean", mergeable=True)
        self.assertEqual(result["observation"], "POTENTIAL_BYPASS")

    def test_removed_or_failing_gate_with_clean_pr_is_potential_bypass(self):
        for case, conclusion in (("missing", None), ("failed", "failure")):
            with self.subTest(case=case):
                result, _ = observe(case, outcome=conclusion, merge_state="clean",
                                    mergeable=True)
                self.assertEqual(result["observation"], "POTENTIAL_BYPASS")

    def test_negative_pr_that_merged_must_trigger_bypass_warning(self):
        result, _ = observe("failed", outcome="failure", merged=True)
        self.assertEqual(result["observation"], "POTENTIAL_BYPASS")

    def test_missing_required_check_with_another_context_is_still_absent(self):
        result, _ = observe("missing", checks=make_checks("success", context="test (3.12)"))
        self.assertEqual(result["gate_conclusion"], "ABSENT")
        self.assertEqual(result["observation"], "OBSERVED_BLOCKED")

    def test_wrong_app_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "unexpected GitHub App"):
            observe("failed", checks=make_checks("failure", app=22))

    def test_ambiguous_duplicate_gate_checks_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "Ambiguous"):
            observe("positive", checks=make_checks("success", duplicates=True))

    def test_gate_check_must_match_head_and_be_completed(self):
        for mutation in (
            {"head_sha": "b" * 40},
            {"status": "in_progress"},
        ):
            with self.subTest(mutation=mutation):
                checks = make_checks("success")
                checks["check_runs"][0].update(mutation)
                with self.assertRaises(ValueError):
                    observe("positive", checks=checks)

    def test_paginated_inventory_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "pagination"):
            observe("missing", checks=make_checks(total=101))

    def test_branch_and_commit_identity_are_required(self):
        for bad in (
            make_pr(branch="releases"),
            {**make_pr(), "head": {"sha": "not-a-sha"}},
            make_pr(n=999),
        ):
            with self.subTest(bad=bad):
                with mock.patch.object(audit, "fetch_json", side_effect=[bad, make_checks(None)]):
                    with self.assertRaisesRegex(ValueError, "metadata"):
                        audit.observe_pr(REPO, "main", "missing", 17, CHECK, APP, None)

    def test_unexpected_merge_state_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "Unknown PR mergeability"):
            observe("missing", checks=make_checks(None), merge_state="magic")

    def test_complete_matrix_is_observational_not_qualification(self):
        cases = {"positive": 1, "missing": 2, "failed": 3, "skipped": 4}
        observations = [
            {"observation": "OBSERVED_ELIGIBLE"},
            {"observation": "OBSERVED_BLOCKED"},
            {"observation": "OBSERVED_BLOCKED"},
            {"observation": "OBSERVED_BLOCKED"},
        ]
        with mock.patch.object(audit, "observe_pr", side_effect=observations):
            value = audit.collect(REPO, "main", CHECK, APP, cases, None)
        self.assertEqual(value["result"], "CONSISTENT_WITH_PROTECTION")
        self.assertIn("actual denied merge", value["limits"])
        observations[-1] = {"observation": "POTENTIAL_BYPASS"}
        with mock.patch.object(audit, "observe_pr", side_effect=observations):
            self.assertEqual(audit.collect(REPO, "main", CHECK, APP, cases, None)["result"],
                             "NOT_QUALIFIED")

    def test_api_403_leaves_only_sanitized_indeterminate_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            result = Path(temp) / "evidence.json"
            with (
                mock.patch.object(audit, "collect",
                    side_effect=urllib.error.HTTPError(
                        "https://api.github.com/repos/acme/throwaway", 403, "Forbidden", {}, None,
                    )),
                mock.patch.dict(os.environ, {"GH_TOKEN": "super-secret"}),
            ):
                status = audit.main([
                    "--repo", REPO, "--check", CHECK,
                    "--positive-pr", "1", "--missing-pr", "2",
                    "--failed-pr", "3", "--skipped-pr", "4",
                    "--output", str(result),
                ])
            self.assertEqual(status, 2)
            raw = result.read_text()
            self.assertEqual(json.loads(raw)["result"], "INDETERMINATE")
            self.assertNotIn("super-secret", raw)

    def test_no_cross_domain_token_redirect_or_unbounded_download(self):
        req = audit.urllib.request.Request(
            "https://api.github.com/repos/acme/throwaway",
            headers={"Authorization": "Bearer private"},
        )
        with self.assertRaises(urllib.error.HTTPError):
            audit.RefusedRedirect().redirect_request(
                req, None, 302, "Found", {}, "https://attacker.invalid/steal"
            )
        with mock.patch.object(
            audit.OPENER, "open", return_value=io.BytesIO(b"x" * (audit.MAX_BYTES + 1))
        ):
            with self.assertRaises(ValueError):
                audit.fetch_json("https://api.github.com/repos/acme/throwaway", "secret")


if __name__ == "__main__":
    unittest.main()
