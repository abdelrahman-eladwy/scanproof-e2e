"""Offline regressions for .github/workflows/github-protection-preflight.yml (#25).

Guards against the preflight self-test silently not running: every GitHub
protection auditor and its tests must trigger the workflow on both pull
requests and pushes to main, and every auditor test must actually execute in
the self-test job. Stdlib only, because CI runs on a bare setup-python.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "github-protection-preflight.yml"
SELF = "scripts/test_github_protection_workflow.py"
AUDITOR_GLOBS = ("audit_github_*.py", "test_audit_github_*.py")
PINNED_USES = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}(\s+#.*)?$")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _clean(value: str) -> str:
    return value.split(" #")[0].strip().strip('"').strip("'")


def block(lines: list[str], key: str, start: int = 0, end: int | None = None):
    """Return (first, last) line indices of the body under `key:`."""
    end = len(lines) if end is None else end
    for i in range(start, end):
        line = lines[i]
        if line.strip() == f"{key}:" or line.strip().startswith(f"{key}: "):
            base = _indent(line)
            j = i + 1
            while j < end and (not lines[j].strip() or _indent(lines[j]) > base):
                j += 1
            return i + 1, j
    raise KeyError(key)


def list_under(lines: list[str], key: str, start: int, end: int) -> list[str]:
    first, last = block(lines, key, start, end)
    return [_clean(l.strip()[2:]) for l in lines[first:last]
            if l.strip().startswith("- ")]


def trigger_paths(text: str, event: str) -> list[str]:
    lines = text.splitlines()
    on_first, on_last = block(lines, "on")
    ev_first, ev_last = block(lines, event, on_first, on_last)
    return list_under(lines, "paths", ev_first, ev_last)


def push_branches(text: str) -> list[str]:
    lines = text.splitlines()
    on_first, on_last = block(lines, "on")
    ev_first, ev_last = block(lines, "push", on_first, on_last)
    for line in lines[ev_first:ev_last]:
        if line.strip().startswith("branches:"):
            raw = line.split(":", 1)[1].strip()
            return [_clean(b) for b in raw.strip("[]").split(",") if b.strip()]
    return []


def job_body(text: str, job: str) -> str:
    lines = text.splitlines()
    jobs_first, jobs_last = block(lines, "jobs")
    first, last = block(lines, job, jobs_first, jobs_last)
    return "\n".join(lines[first:last])


def selftest_modules(text: str) -> list[str]:
    body = job_body(text, "self-test")
    return re.findall(r"scripts/test_[\w]+\.py", body)


def required_paths(root: Path = ROOT) -> set[str]:
    found = {f"scripts/{p.name}" for g in AUDITOR_GLOBS
             for p in (root / "scripts").glob(g)}
    return found | {
        SELF,
        ".github/workflows/github-protection-preflight.yml",
        ".github/workflows/github-gate-trials.yml",
    }


def coverage_gaps(text: str, required: set[str]) -> dict[str, list[str]]:
    gaps = {}
    for event in ("pull_request", "push"):
        missing = sorted(required - set(trigger_paths(text, event)))
        if missing:
            gaps[event] = missing
    return gaps


class WorkflowTriggerCoverage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text(encoding="utf-8")

    def test_every_auditor_triggers_on_pr_and_main_push(self):
        self.assertEqual(coverage_gaps(self.text, required_paths()), {})

    def test_pr_and_push_paths_are_identical(self):
        self.assertEqual(sorted(trigger_paths(self.text, "pull_request")),
                         sorted(trigger_paths(self.text, "push")))

    def test_no_duplicate_trigger_paths(self):
        for event in ("pull_request", "push"):
            paths = trigger_paths(self.text, event)
            dupes = sorted({p for p in paths if paths.count(p) > 1})
            self.assertEqual(dupes, [], f"duplicate {event} paths")

    def test_every_trigger_path_exists(self):
        for event in ("pull_request", "push"):
            for p in trigger_paths(self.text, event):
                self.assertTrue((ROOT / p).is_file(), f"{event}: {p} missing")

    def test_push_trigger_is_limited_to_main(self):
        self.assertEqual(push_branches(self.text), ["main"])


class SelfTestJobCoverage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text(encoding="utf-8")

    def test_every_auditor_test_runs_in_self_test(self):
        expected = {f"scripts/{p.name}"
                    for p in (ROOT / "scripts").glob("test_audit_github_*.py")}
        expected.add(SELF)
        self.assertEqual(expected - set(selftest_modules(self.text)), set())

    def test_self_test_modules_exist(self):
        for m in selftest_modules(self.text):
            self.assertTrue((ROOT / m).is_file(), m)


class WorkflowSafety(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text(encoding="utf-8")

    def test_top_level_permissions_read_only(self):
        lines = self.text.splitlines()
        first, last = block(lines, "permissions")
        body = [l.strip() for l in lines[first:last] if l.strip()]
        self.assertEqual(body, ["contents: read"])

    def test_live_audit_only_on_manual_dispatch(self):
        body = job_body(self.text, "audit")
        self.assertIn("if: ${{ github.event_name == 'workflow_dispatch' }}", body)
        self.assertIn("needs: [self-test]", body)

    def test_self_test_has_no_token(self):
        body = job_body(self.text, "self-test")
        self.assertNotIn("GH_TOKEN", body)
        self.assertNotIn("secrets.", body)

    def test_checkouts_do_not_persist_credentials(self):
        n_checkout = self.text.count("uses: actions/checkout@")
        self.assertGreater(n_checkout, 0)
        self.assertEqual(self.text.count("persist-credentials: false"), n_checkout)

    def test_actions_pinned_to_full_sha(self):
        for line in self.text.splitlines():
            s = line.strip().lstrip("- ").strip()
            if s.startswith("uses:"):
                ref = s.split(":", 1)[1].strip()
                if ref.startswith("./"):
                    continue
                self.assertRegex(ref, PINNED_USES)


SYNTHETIC = """\
on:
  pull_request:
    paths:
      - "scripts/a.py"
      - "scripts/b.py"
  push:
    branches: [main]
    paths:
      - "scripts/a.py"
  workflow_dispatch:
    inputs:
      x:
        type: string
jobs:
  self-test:
    steps:
      - run: python -m unittest scripts/test_a.py
"""


class CheckerFaultInjection(unittest.TestCase):
    """The checker itself must catch the exact #25 regression class."""

    def test_detects_auditor_missing_from_push(self):
        gaps = coverage_gaps(SYNTHETIC, {"scripts/a.py", "scripts/b.py"})
        self.assertEqual(gaps, {"push": ["scripts/b.py"]})

    def test_detects_missing_from_both_events(self):
        gaps = coverage_gaps(SYNTHETIC, {"scripts/c.py"})
        self.assertEqual(set(gaps), {"pull_request", "push"})

    def test_paths_do_not_leak_across_events(self):
        self.assertEqual(trigger_paths(SYNTHETIC, "push"), ["scripts/a.py"])

    def test_parses_branches_and_selftest(self):
        self.assertEqual(push_branches(SYNTHETIC), ["main"])
        self.assertEqual(selftest_modules(SYNTHETIC), ["scripts/test_a.py"])

    def test_missing_event_raises(self):
        with self.assertRaises(KeyError):
            trigger_paths(SYNTHETIC.replace("  push:", "  push_x:"), "push")

    def test_reverting_57c1589_is_caught(self):
        # Pre-fix workflow: push paths lacked the environment auditor.
        reverted = WORKFLOW.read_text(encoding="utf-8")
        push_start = reverted.index("  push:")
        head, tail = reverted[:push_start], reverted[push_start:]
        tail = tail.replace('      - "scripts/audit_github_environment.py"\n', "", 1)
        gaps = coverage_gaps(head + tail, required_paths())
        self.assertEqual(gaps, {"push": ["scripts/audit_github_environment.py"]})


if __name__ == "__main__":
    unittest.main()
