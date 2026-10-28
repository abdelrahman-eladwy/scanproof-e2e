"""Offline tests for gitlab_copies_contract.py: pipeline selection must fail closed.

Run: python -m unittest scripts/test_gitlab_copies_contract.py
"""

from __future__ import annotations

import contextlib
import io
import os
import sys
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
import gitlab_copies_contract as gcc  # noqa: E402

NOW = datetime.now(UTC)


def pipeline(pid: int, age_days: float = 1, sha: str = "c" * 40) -> list[dict]:
    created = (NOW - timedelta(days=age_days)).isoformat().replace("+00:00", "Z")
    return [{"id": pid, "sha": sha, "created_at": created, "status": "success"}]


class Contract(unittest.TestCase):
    def run_with(self, responses: dict[str, object], verify_rc: int = 0, env=None):
        """responses: ref -> JSON body (or an exception to raise). Returns (rc, verify calls)."""
        calls: list[list[str]] = []

        def fake_get(url: str):
            ref = next(r for r in gcc.SCENARIOS if f"ref={r}&" in url)
            body = responses[ref]
            if isinstance(body, Exception):
                raise body
            return body

        def fake_verify(argv):
            calls.append(argv)
            return verify_rc

        if env is None:
            env = {"GITLAB_COPIES_PROJECT": "grp/scanproof-copies", "GITLAB_TOKEN": "glpat-test"}
        with (
            mock.patch.object(gcc, "get_json", fake_get),
            mock.patch.object(gcc.verify_contract, "main", fake_verify),
            mock.patch.dict(os.environ, env, clear=False),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            for key in ("GITLAB_COPIES_PROJECT", "GITLAB_TOKEN"):
                if not env.get(key):
                    os.environ.pop(key, None)
            return gcc.main(), calls

    def test_both_branches_verified_with_their_own_pipeline_and_commit(self) -> None:
        rc, calls = self.run_with({"main": pipeline(1, sha="a" * 40), "inaccessible": pipeline(2, sha="b" * 40)})
        self.assertEqual(rc, 0)
        self.assertEqual(len(calls), 2)
        by_file = {c[0]: c for c in calls}
        main = by_file[gcc.SCENARIOS["main"]]
        self.assertEqual(main[main.index("--pipeline") + 1], "1")
        self.assertEqual(main[main.index("--sha") + 1], "a" * 40)
        self.assertNotIn("--anonymous", main)  # gitlab.com allows 60 anonymous requests/hour
        other = by_file[gcc.SCENARIOS["inaccessible"]]
        self.assertEqual(other[other.index("--pipeline") + 1], "2")

    def test_no_successful_pipeline_fails(self) -> None:
        rc, calls = self.run_with({"main": [], "inaccessible": pipeline(2)})
        self.assertEqual(rc, 1)
        self.assertEqual(len(calls), 1)  # the other branch is still checked

    def test_stale_pipeline_fails(self) -> None:
        rc, calls = self.run_with({"main": pipeline(1, age_days=30), "inaccessible": pipeline(2)})
        self.assertEqual(rc, 1)

    def test_api_error_fails(self) -> None:
        rc, _ = self.run_with({"main": gcc.ContractError("HTTP 404"), "inaccessible": pipeline(2)})
        self.assertEqual(rc, 1)

    def test_malformed_pipeline_fails(self) -> None:
        rc, _ = self.run_with({"main": [{"id": "x"}], "inaccessible": pipeline(2)})
        self.assertEqual(rc, 1)

    def test_scenario_failure_fails(self) -> None:
        rc, _ = self.run_with({"main": pipeline(1), "inaccessible": pipeline(2)}, verify_rc=1)
        self.assertEqual(rc, 1)

    def test_unset_project_fails(self) -> None:
        rc, calls = self.run_with({}, env={"GITLAB_COPIES_PROJECT": ""})
        self.assertEqual((rc, calls), (1, []))

    def test_unset_token_fails_before_any_request(self) -> None:
        rc, calls = self.run_with({}, env={"GITLAB_COPIES_PROJECT": "grp/p", "GITLAB_TOKEN": " "})
        self.assertEqual((rc, calls), (1, []))

    def test_token_is_sent_as_header_and_not_in_url_or_errors(self) -> None:
        seen = []

        def fake_urlopen(req, timeout):
            seen.append(req)
            raise OSError("HTTP Error 401: Unauthorized")

        with (
            mock.patch.dict(os.environ, {"GITLAB_TOKEN": "glpat-secret"}),
            mock.patch.object(gcc.urllib.request, "urlopen", fake_urlopen),
        ):
            with self.assertRaises(gcc.ContractError) as err:
                gcc.get_json("https://gitlab.com/api/v4/projects/x/pipelines")
        self.assertEqual(seen[0].get_header("Authorization"), "Bearer glpat-secret")
        self.assertNotIn("glpat-secret", seen[0].full_url)
        self.assertNotIn("glpat-secret", str(err.exception))

    def test_scenario_files_exist_and_name_their_policies(self) -> None:
        import json

        root = Path(__file__).parent.parent
        for path in gcc.SCENARIOS.values():
            scenarios = json.loads((root / path).read_text())
            self.assertTrue(scenarios)
            for s in scenarios:
                self.assertTrue((root / s["policy"]).exists(), s["policy"])


if __name__ == "__main__":
    unittest.main()
