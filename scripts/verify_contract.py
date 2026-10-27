"""Run `scanproof verify` scenarios against one real pipeline and check every claim it makes.

Used by copies-contract.yml (scanproof#65) for GitHub runs and GitLab pipelines. A scenario
passes only if ALL of these hold, so a crash, a stale file or a provider error can never pass:

- the output file was deleted first, and `verify` wrote a fresh one (generated in the last hour);
- it is a verification report, not the error report `verify` writes on a provider error;
- its `exit_code` and `decision` agree with the process exit code, which is the expected one;
- provenance: provider, project, pipeline id (and commit, when given) are the ones verified;
- the non-passing checks are exactly the expected 'check=CODE' pairs;
- the expected jobs were evaluated (they appear as the requirement's job or instances);
- an expected warning is present; unreadable / not-started downstream warnings appear only
  when the scenario allows them.

Exit 3 scenarios (policy rejected at load) must write no report and print exactly the expected
rejection codes.

Stdlib only. Usage:
  python scripts/verify_contract.py <scenarios.json> --provider github --project owner/repo \
      --pipeline <id> [--sha <commit>] [--out-dir DIR] [--anonymous]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

DECISION = {0: "VERIFIED", 1: "BLOCKED", 2: "INDETERMINATE"}
UNREADABLE = ("could not be read", "has not started its downstream pipeline")
LOAD_CODE = re.compile(r"\[([A-Z][A-Z0-9_]+)\]")
MAX_AGE = timedelta(hours=1)


def non_passing(report: dict) -> list[str]:
    return sorted(
        f"{c['check']}={c['code']}"
        for r in report.get("requirements", [])
        for c in r.get("checks", [])
        if c.get("outcome") not in ("PASS", "NOT_APPLICABLE")
    )


def evaluated_jobs(report: dict) -> set[str]:
    names: set[str] = set()
    for r in report.get("requirements", []):
        names.update(r.get("instances") or [])
        if r.get("job_id") is not None:
            names.add(r.get("job_name", ""))
    return names


def judge(scenario: dict, rc: int, stderr: str, out: Path, args, now: datetime) -> list[str]:
    """Every way the result differs from the scenario; [] means it passed."""
    want = scenario["exit"]
    problems: list[str] = []
    if rc != want:
        problems.append(f"exit {rc}, expected {want}")

    if want == 3:
        if out.exists():
            problems.append("a rejected policy must not produce a report")
        got = sorted(set(LOAD_CODE.findall(stderr)))
        if got != sorted(scenario["load_errors"]):
            problems.append(f"load errors {got}, expected {sorted(scenario['load_errors'])}")
        return problems

    if not out.exists():
        return [*problems, "no report written"]
    try:
        report = json.loads(out.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [*problems, f"report is not JSON: {exc}"]
    if "error" in report:
        return [*problems, f"provider error report: {json.dumps(report['error'])[:300]}"]

    if report.get("exit_code") != rc:
        problems.append(f"report exit_code {report.get('exit_code')} != process exit {rc}")
    if report.get("decision") != DECISION.get(rc):
        problems.append(f"decision {report.get('decision')} does not match exit {rc}")
    try:
        generated = datetime.fromisoformat(report["generated_at"])
        if not now - MAX_AGE <= generated <= now + timedelta(minutes=5):
            problems.append(f"report generated at {generated}, not by this run")
    except (KeyError, TypeError, ValueError):
        problems.append("report has no valid generated_at")

    pipeline = report.get("pipeline") or {}
    provenance = {
        "provider": (report.get("provider"), args.provider),
        "project": (report.get("project"), args.project),
        "pipeline.id": (pipeline.get("id"), args.pipeline),
    }
    if args.sha:
        provenance["pipeline.sha"] = ((pipeline.get("sha") or "").lower(), args.sha.lower())
    if scenario.get("policy_name"):
        provenance["policy"] = (report.get("policy"), scenario["policy_name"])
    for field, (got, expected) in provenance.items():
        if got != expected:
            problems.append(f"{field} is {got!r}, expected {expected!r}")

    codes = non_passing(report)
    if codes != sorted(scenario.get("codes", [])):
        problems.append(f"codes {codes}, expected {sorted(scenario.get('codes', []))}")

    missing_jobs = sorted(set(scenario.get("jobs", [])) - evaluated_jobs(report))
    if missing_jobs:
        problems.append(f"jobs not evaluated: {missing_jobs}")

    warnings = report.get("warnings", [])
    if scenario.get("warning") and not any(scenario["warning"] in w for w in warnings):
        problems.append(f"no warning containing {scenario['warning']!r}")
    if not scenario.get("unreadable_ok"):
        bad = [w for w in warnings if any(u in w for u in UNREADABLE)]
        if bad:
            problems.append(f"unexpected unreadable downstream: {bad}")
    return problems


def run(scenario: dict, args, out_dir: Path) -> list[str]:
    policy = Path(scenario["policy"])
    out = out_dir / f"{policy.stem}.json"
    out.unlink(missing_ok=True)  # never judge a report left by an earlier run
    cmd = ["scanproof", "verify", "--provider", args.provider, "-P", str(policy),
           "-p", args.project, "--pipeline", str(args.pipeline), "-o", str(out)]  # fmt: skip
    if args.anonymous:
        cmd.append("--anonymous")
    proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
    return judge(scenario, proc.returncode, proc.stderr or "", out, args, datetime.now(UTC))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("scenarios")
    ap.add_argument("--provider", required=True)
    ap.add_argument("--project", required=True)
    ap.add_argument("--pipeline", required=True, type=int)
    ap.add_argument("--sha")
    ap.add_argument("--out-dir", default="contract-out")
    ap.add_argument("--anonymous", action="store_true")
    ap.add_argument("--title", default="copies")
    args = ap.parse_args(argv)

    scenarios = json.loads(Path(args.scenarios).read_text(encoding="utf-8"))
    if not scenarios:
        print(f"::error title={args.title}::no scenarios in {args.scenarios}")
        return 1
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    failed = 0
    for scenario in scenarios:
        name = Path(scenario["policy"]).stem
        problems = run(scenario, args, out_dir)
        if problems:
            failed += 1
            print(f"::error title={args.title} {name}::{'; '.join(problems)}"[:4000])
        else:
            print(f"::notice title={args.title} {name}::ok (exit {scenario['exit']})")
    print(f"{len(scenarios) - failed}/{len(scenarios)} scenarios passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
