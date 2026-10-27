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

        env = {"GITLAB_COPIES_PROJECT": "grp/scanproof-copies"} if env is None else env
        with (
            mock.patch.object(gcc, "get_json", fake_get),
            mock.patch.object(gcc.verify_contract, "main", fake_verify),
            mock.patch.dict(os.environ, env, clear=False),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            if not env.get("GITLAB_COPIES_PROJECT"):
                os.environ.pop("GITLAB_COPIES_PROJECT", None)
            return gcc.main(), calls

    def test_both_branches_verified_with_their_own_pipeline_and_commit(self) -> None:
        rc, calls = self.run_with({"main": pipeline(1, sha="a" * 40), "inaccessible": pipeline(2, sha="b" * 40)})
        self.assertEqual(rc, 0)
        self.assertEqual(len(calls), 2)
        by_file = {c[0]: c for c in calls}
        main = by_file[gcc.SCENARIOS["main"]]
        self.assertEqual(main[main.index("--pipeline") + 1], "1")
        self.assertEqual(main[main.index("--sha") + 1], "a" * 40)
        self.assertIn("--anonymous", main)
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
