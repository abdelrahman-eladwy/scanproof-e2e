"""Offline tests for verify_contract.py: every guard must reject the case it exists for.

Stdlib only; `subprocess.run` is replaced by a fake `scanproof` that writes a chosen report.
Run: python -m unittest scripts/test_verify_contract.py
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
import verify_contract as vc  # noqa: E402

PROJECT, PIPELINE, SHA = "owner/repo", 42, "a" * 40
GOOD = {
    "decision": "BLOCKED",
    "exit_code": 1,
    "provider": "github",
    "project": PROJECT,
    "policy": "removed",
    "pipeline": {"id": PIPELINE, "sha": SHA},
    "requirements": [
        {
            "job_name": "copy-sast",
            "job_id": None,
            "instances": ["copy-api / copy-sast", "copy-web / copy-sast", "copy-mobile / copy-sast"],
            "checks": [
                {"check": "job_success [copy-api / copy-sast]", "outcome": "PASS", "code": "OK"},
                {
                    "check": "job_present [copy-mobile / copy-sast]",
                    "outcome": "FAIL",
                    "code": "REQUIRED_COPY_ABSENT",
                },
            ],
        }
    ],
    "warnings": [],
}
SCENARIO = {
    "policy": "policies/x/removed.yaml",
    "policy_name": "removed",
    "exit": 1,
    "codes": ["job_present [copy-mobile / copy-sast]=REQUIRED_COPY_ABSENT"],
    "jobs": ["copy-api / copy-sast", "copy-web / copy-sast"],
}


class Harness(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp())
        self.scenarios = self.dir / "s.json"

    def run_with(self, scenario: dict, rc: int, report: dict | None, stderr: str = "") -> int:
        self.scenarios.write_text(json.dumps([scenario]))

        def fake_run(cmd, check=False, capture_output=True, text=True):
            if report is not None:
                body = dict(report)
                body.setdefault("generated_at", datetime.now(UTC).isoformat())
                Path(cmd[cmd.index("-o") + 1]).write_text(json.dumps(body))
            return subprocess.CompletedProcess(cmd, rc, "", stderr)

        argv = [str(self.scenarios), "--provider", "github", "--project", PROJECT,
                "--pipeline", str(PIPELINE), "--sha", SHA, "--out-dir", str(self.dir / "o")]  # fmt: skip
        with (
            mock.patch.object(vc.subprocess, "run", fake_run),
            contextlib.redirect_stdout(io.StringIO()),  # keep '::error' out of CI annotations
        ):
            return vc.main(argv)

    def mutated(self, **changes) -> dict:
        report = copy.deepcopy(GOOD)
        report.update(changes)
        return report

    def test_good_report_passes(self) -> None:
        self.assertEqual(self.run_with(SCENARIO, 1, GOOD), 0)

    def test_wrong_exit_fails(self) -> None:
        self.assertEqual(self.run_with(SCENARIO, 2, self.mutated(exit_code=2, decision="INDETERMINATE")), 1)

    def test_missing_report_fails(self) -> None:
        self.assertEqual(self.run_with(SCENARIO, 1, None), 1)

    def test_stale_report_is_deleted_first(self) -> None:
        out = self.dir / "o"
        out.mkdir()
        (out / "removed.json").write_text(json.dumps(GOOD | {"generated_at": datetime.now(UTC).isoformat()}))
        self.assertEqual(self.run_with(SCENARIO, 1, None), 1)

    def test_old_generated_at_fails(self) -> None:
        old = (datetime.now(UTC) - timedelta(days=2)).isoformat()
        self.assertEqual(self.run_with(SCENARIO, 1, self.mutated(generated_at=old)), 1)

    def test_provider_error_report_fails(self) -> None:
        """Even with every other field right, the error shape is never a verification result."""
        self.assertEqual(self.run_with(SCENARIO, 1, self.mutated(error={"kind": "auth"})), 1)

    def test_exit_and_report_disagree_fails(self) -> None:
        self.assertEqual(self.run_with(SCENARIO, 1, self.mutated(exit_code=0)), 1)

    def test_decision_and_exit_disagree_fails(self) -> None:
        self.assertEqual(self.run_with(SCENARIO, 1, self.mutated(decision="VERIFIED")), 1)

    def test_wrong_pipeline_fails(self) -> None:
        self.assertEqual(self.run_with(SCENARIO, 1, self.mutated(pipeline={"id": 7, "sha": SHA})), 1)

    def test_wrong_commit_fails(self) -> None:
        self.assertEqual(self.run_with(SCENARIO, 1, self.mutated(pipeline={"id": PIPELINE, "sha": "b" * 40})), 1)

    def test_wrong_project_fails(self) -> None:
        self.assertEqual(self.run_with(SCENARIO, 1, self.mutated(project="other/repo")), 1)

    def test_wrong_policy_fails(self) -> None:
        self.assertEqual(self.run_with(SCENARIO, 1, self.mutated(policy="other")), 1)

    def test_extra_code_fails(self) -> None:
        report = copy.deepcopy(GOOD)
        report["requirements"][0]["checks"].append(
            {"check": "job_success [copy-web / copy-sast]", "outcome": "UNKNOWN", "code": "X"}
        )
        self.assertEqual(self.run_with(SCENARIO, 1, report), 1)

    def test_copy_not_evaluated_fails(self) -> None:
        report = copy.deepcopy(GOOD)
        report["requirements"][0]["instances"] = ["copy-api / copy-sast"]
        self.assertEqual(self.run_with(SCENARIO, 1, report), 1)

    def test_required_warning_missing_fails(self) -> None:
        self.assertEqual(self.run_with(SCENARIO | {"warning": "declares no `copies`"}, 1, GOOD), 1)

    def test_unexpected_unreadable_fails(self) -> None:
        w = ["Downstream pipeline of trigger 'x' could not be read (auth); jobs ..."]
        self.assertEqual(self.run_with(SCENARIO, 1, self.mutated(warnings=w)), 1)
        self.assertEqual(self.run_with(SCENARIO | {"unreadable_ok": True}, 1, self.mutated(warnings=w)), 0)

    def test_load_error_needs_exact_codes_and_no_report(self) -> None:
        s = {"policy": "policies/x/waiver.yaml", "exit": 3, "load_errors": ["WAIVER_HIDES_UNDECLARED_COPIES"]}
        err = "waivers[0] (SAST/copies_declared): ... [WAIVER_HIDES_UNDECLARED_COPIES]"
        self.assertEqual(self.run_with(s, 3, None, err), 0)
        self.assertEqual(self.run_with(s, 3, None, err + " [WAIVER_UNBOUNDED]"), 1)  # extra code
        self.assertEqual(self.run_with(s, 3, None, "error: something else"), 1)  # wrong reason
        self.assertEqual(self.run_with(s, 0, GOOD, err), 1)  # not rejected
        self.assertEqual(self.run_with(s, 3, GOOD, err), 1)  # rejected but wrote a report

    def test_empty_scenarios_fail(self) -> None:
        self.scenarios.write_text("[]")
        with contextlib.redirect_stdout(io.StringIO()):
            rc = vc.main([str(self.scenarios), "--provider", "github", "--project", PROJECT, "--pipeline", "1"])
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
