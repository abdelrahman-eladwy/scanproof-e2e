"""Offline regression test for gitlab_matrix_contract.py (scanproof-e2e#4).

The contract must fail whenever `scanproof verify` does not prove what it claims: a non-zero
exit in the `exact` case, or no report written in either case. Stdlib only, no network:
`subprocess.run` is replaced by a fake `scanproof` that writes a chosen report.

Run: python -m unittest scripts/test_gitlab_matrix_contract.py
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
import gitlab_matrix_contract as contract  # noqa: E402

BASE = "build_windows"
LABELS = ["amd64", "arm64"]
REMOVED_CHECK = f"job_present [{BASE}: [{contract.REMOVED}]]"


def absent_report(checks: list[str]) -> dict:
    return {
        "requirements": [
            {"checks": [{"check": c, "code": "REQUIRED_INSTANCE_ABSENT"} for c in checks]}
        ]
    }


class Contract(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
        (self.root / "summary.json").write_text(
            json.dumps([{"project": "gitlab-org/cli", "pipeline_id": 1}]), encoding="utf-8"
        )
        (self.root / "cli").mkdir()
        jobs = [{"name": f"{BASE}: [{label}]"} for label in LABELS]
        (self.root / "cli/inspection.json").write_text(json.dumps({"jobs": jobs}))

    def run_with(self, exact: tuple[int, dict | None], removed: tuple[int, dict | None]) -> int:
        """Run main() with a fake scanproof; each tuple is (exit code, report or None)."""
        results = {"exact": exact, "removed": removed}

        def fake_run(cmd, check=False):
            out = Path(cmd[cmd.index("-o") + 1])
            rc, report = results["removed" if "removed" in out.name else "exact"]
            if report is not None:
                out.write_text(json.dumps(report), encoding="utf-8")
            return subprocess.CompletedProcess(cmd, rc)

        with mock.patch.object(contract.subprocess, "run", fake_run):
            return contract.main(str(self.root))

    GOOD_REMOVED = (1, absent_report([REMOVED_CHECK]))

    def test_expected_results_pass(self) -> None:
        self.assertEqual(self.run_with((0, absent_report([])), self.GOOD_REMOVED), 0)

    def test_exact_indeterminate_fails(self) -> None:
        """The bug: exit 2 with no absent leg passed, because rc was ignored."""
        self.assertEqual(self.run_with((2, absent_report([])), self.GOOD_REMOVED), 1)

    def test_exact_blocked_fails(self) -> None:
        self.assertEqual(self.run_with((1, absent_report([])), self.GOOD_REMOVED), 1)

    def test_exact_without_report_fails(self) -> None:
        """The bug: a crash that wrote no report read as 'nothing absent'."""
        self.assertEqual(self.run_with((0, None), self.GOOD_REMOVED), 1)

    def test_exact_with_absent_leg_fails(self) -> None:
        self.assertEqual(self.run_with((1, absent_report(["x"])), self.GOOD_REMOVED), 1)

    def test_removed_without_report_fails(self) -> None:
        self.assertEqual(self.run_with((0, absent_report([])), (1, None)), 1)

    def test_removed_wrong_exit_fails(self) -> None:
        self.assertEqual(self.run_with((0, absent_report([])), (2, self.GOOD_REMOVED[1])), 1)

    def test_stale_report_is_not_reused(self) -> None:
        """A report left by an earlier run must not stand in for a run that wrote none."""
        (self.root / "cli/matrix-exact.json").write_text(json.dumps(absent_report([])))
        self.assertEqual(self.run_with((0, None), self.GOOD_REMOVED), 1)


if __name__ == "__main__":
    unittest.main()
