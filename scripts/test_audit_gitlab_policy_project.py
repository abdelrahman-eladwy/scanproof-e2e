"""Negative and positive cases for GitLab security-owned policy branch audit."""

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
import audit_gitlab_policy_project as audit  # noqa: E402

PROJECT = "security/policy-project"
GROUP = 1729


def meta():
    return {"id": 92, "path_with_namespace": PROJECT}


def rule():
    group = {"group_id": GROUP, "access_level": None, "user_id": None}
    return {
        "id": 1,
        "name": "main",
        "allow_force_push": False,
        "code_owner_approval_required": True,
        "push_access_levels": [dict(group)],
        "merge_access_levels": [dict(group)],
        "unprotect_access_levels": [dict(group)],
    }


class GitLabPolicyAuditTests(unittest.TestCase):
    def test_strict_security_owned_branch_is_static_pass_only(self):
        result = audit.evaluate(PROJECT, "main", GROUP, meta(), rule())
        self.assertEqual(result["result"], "PASS_STATIC_POLICY_BRANCH")
        self.assertIn("does not prove linked", result["limits"])

    def test_all_roles_must_be_pinned_to_independent_group(self):
        for key in ("push_access_levels", "merge_access_levels", "unprotect_access_levels"):
            for extra in (
                {"access_level": 30, "group_id": None},
                {"access_level": 40},
                {"user_id": 42, "access_level": None},
                {"group_id": 2000, "access_level": None},
                {"member_role_id": 7},
                {"deploy_key_id": 8},
                {},
            ):
                with self.subTest(key=key, extra=extra):
                    x = rule()
                    x[key].append(extra)
                    result = audit.evaluate(PROJECT, "main", GROUP, meta(), x)
                    self.assertEqual(result["result"], "FAIL_STATIC_POLICY_BRANCH")

    def test_missing_or_unidentifiable_permissions_fail_closed(self):
        for key in ("push_access_levels", "merge_access_levels", "unprotect_access_levels"):
            for entry in (None, [], "all", [{}]):
                with self.subTest(key=key, entry=entry):
                    x = rule()
                    x[key] = entry
                    self.assertEqual(
                        audit.evaluate(PROJECT, "main", GROUP, meta(), x)["result"],
                        "FAIL_STATIC_POLICY_BRANCH",
                    )

    def test_force_push_and_code_owner_approval_are_mandatory(self):
        for key, val in (
            ("allow_force_push", True),
            ("allow_force_push", None),
            ("code_owner_approval_required", False),
            ("code_owner_approval_required", None),
        ):
            with self.subTest(key=key, value=val):
                x = rule()
                x[key] = val
                self.assertEqual(
                    audit.evaluate(PROJECT, "main", GROUP, meta(), x)["result"],
                    "FAIL_STATIC_POLICY_BRANCH",
                )

    def test_wrong_branch_or_project_identity_never_passes(self):
        x = rule()
        x["name"] = "release"
        with self.assertRaises(ValueError):
            audit.evaluate(PROJECT, "main", GROUP, meta(), x)
        with self.assertRaises(ValueError):
            audit.evaluate(PROJECT, "main", GROUP, {"id": 1, "path_with_namespace": "app"}, rule())
        with self.assertRaises(ValueError):
            audit.evaluate(PROJECT, "main", GROUP, {"id": True, "path_with_namespace": PROJECT}, rule())

    def test_api_uses_encoded_project_and_branch_with_exact_https_origin(self):
        with mock.patch.object(audit, "_get_json", side_effect=[meta(), rule()]) as fetch:
            x = audit.collect("https://gitlab.com", PROJECT, "main", GROUP, "secret")
        self.assertEqual(x["result"], "PASS_STATIC_POLICY_BRANCH")
        self.assertEqual([c.args[0] for c in fetch.call_args_list], [
            "https://gitlab.com/api/v4/projects/security%2Fpolicy-project",
            "https://gitlab.com/api/v4/projects/security%2Fpolicy-project/protected_branches/main",
        ])
        self.assertTrue(all(c.args[1:] == ("https://gitlab.com", "secret") for c in fetch.call_args_list))

    def test_url_validation_never_allows_downgrade_credentials_or_unpinned_base(self):
        for url in (
            "http://gitlab.com",
            "https://user:pass@gitlab.com",
            "https://gitlab.com/other",
            "https://gitlab.com?token=x",
            "https://gitlab.com#fragment",
            "https://gitlab.com\nX-Header: bad",
        ):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    audit._base_url(url)

    def test_redirect_is_denied_and_token_header_not_copied_to_evidence(self):
        req = audit.urllib.request.Request(
            "https://gitlab.com/api/v4/projects/security%2Fpolicy-project",
            headers={"PRIVATE-TOKEN": "top-secret"},
        )
        with self.assertRaises(urllib.error.HTTPError):
            audit._NoRedirect().redirect_request(
                req, None, 302, "Found", {}, "https://evil.example/token",
            )
        self.assertNotIn("top-secret", req.full_url)

    def test_api_token_is_header_only_and_response_is_bounded(self):
        with mock.patch.object(audit._OPENER, "open", return_value=io.BytesIO(b'{"ok":true}')) as op:
            self.assertEqual(
                audit._get_json(
                    "https://gitlab.com/api/v4/projects/security", "https://gitlab.com", "secret"
                ), {"ok": True}
            )
            req = op.call_args.args[0]
            self.assertEqual(req.get_header("Private-token"), "secret")
            self.assertEqual(req.get_method(), "GET")
            self.assertNotIn("secret", req.full_url)
        with mock.patch.object(
            audit._OPENER, "open",
            return_value=io.BytesIO(b"x" * (audit.MAX_RESPONSE_BYTES + 1)),
        ):
            with self.assertRaises(ValueError):
                audit._get_json(
                    "https://gitlab.com/api/v4/projects/security", "https://gitlab.com", None
                )

    def test_unauthorized_api_and_missing_branch_are_indeterminate_not_pass(self):
        for status in (401, 403, 404):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / "audit.json"
                with (
                    mock.patch.object(
                        audit, "collect",
                        side_effect=urllib.error.HTTPError(
                            "https://gitlab.com/api/v4/projects/hidden",
                            status, "super-secret", {}, None,
                        ),
                    ),
                    mock.patch.dict(os.environ, {"GITLAB_TOKEN": "super-secret"}),
                ):
                    code = audit.main(
                        [
                            "--project", PROJECT, "--security-group-id", str(GROUP),
                            "--output", str(path),
                        ]
                    )
                self.assertEqual(code, 2)
                data = path.read_text()
                self.assertEqual(json.loads(data)["result"], "INDETERMINATE")
                self.assertNotIn("super-secret", data)

    def test_malformed_payload_fails_closed(self):
        for data in (b"[1]", b"not-json", b"null", b"42"):
            with self.subTest(data=data), mock.patch.object(
                audit._OPENER, "open", return_value=io.BytesIO(data)
            ):
                with self.assertRaises(ValueError):
                    audit._get_json(
                        "https://gitlab.com/api/v4/projects/security", "https://gitlab.com", None
                    )

    def test_invalid_branch_and_security_group_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            for args in (
                ["--branch", "../main"],
                ["--security-group-id", "0"],
                ["--project", "security/../application"],
            ):
                base = [
                    "--project", PROJECT, "--security-group-id", str(GROUP),
                    "--output", str(Path(folder) / "x.json"),
                ]
                with self.subTest(args=args), self.assertRaises(SystemExit):
                    audit.main(base + args)


if __name__ == "__main__":
    unittest.main()
