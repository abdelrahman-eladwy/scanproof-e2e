"""Live contract for ScanProof issue #60 against REAL gitlab.com `parallel: matrix:` job names.

Run by .github/workflows/gitlab-contract.yml after `scanproof inspect` has written
<out>/<slug>/inspection.json for each public pipeline in <out>/summary.json.

This repository has no GitLab project of its own, so it cannot remove a leg from a real
matrix. It does the equivalent from the policy side, on real names:

1. Pick the matrix with the most legs ('name: [label]') in each inspected pipeline.
2. `exact`:   declare exactly the labels that ran. Expected: exit 0 and no
              REQUIRED_INSTANCE_ABSENT: every real label (multi-variable 'a, b', values with
              spaces, unexpanded '${VAR}') must be parsed and matched.
3. `removed`: declare one more label that no job carries, i.e. a leg the pipeline no longer
              runs. Expected: exit 1, with exactly that leg as REQUIRED_INSTANCE_ABSENT.

A run that writes no report never passes either case (scanproof-e2e#4).

Only job results are judged (no report is read), so anonymous access is enough.
Usage: python scripts/gitlab_matrix_contract.py <out dir>
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

LEG = re.compile(r"^(?P<base>.+): \[(?P<label>.+)\]$")
REMOVED = "scanproof-removed-leg"


def largest_matrix(inspection: dict) -> tuple[str, list[str]] | None:
    legs: dict[str, list[str]] = defaultdict(list)
    for job in inspection["jobs"]:
        name = job["name"]
        if " > " in name:  # downstream copies are told apart by their prefix, not a label
            continue
        m = LEG.match(name)
        if m:
            legs[m.group("base")].append(m.group("label"))
    if not legs:
        return None
    base = max(sorted(legs), key=lambda b: len(legs[b]))
    return base, sorted(set(legs[base]))


def verify(
    out: Path, project: str, pipeline: int, base: str, labels: list[str], tag: str
) -> tuple[int, list[str] | None]:
    """(exit code, sorted REQUIRED_INSTANCE_ABSENT checks); None when no report was written."""
    policy = {
        "apiVersion": "scanproof.dev/v1alpha1",
        "kind": "PipelineAssurancePolicy",
        "metadata": {"name": f"gitlab-live-matrix-{tag}"},
        "project": {"provider": "gitlab", "id": project},
        "requirements": [
            {
                "id": "MATRIX",
                "tool": "semgrep",
                "job_name": base,
                "report_path": "none.json",
                "instances": labels,
                # Only the job set is under test; their results and reports are not.
                "checks": {"report_required": False, "job_success": False},
            }
        ],
    }
    policy_path = out / f"matrix-{tag}.policy.json"  # JSON is valid YAML
    policy_path.write_text(json.dumps(policy, indent=2), encoding="utf-8")
    result_path = out / f"matrix-{tag}.json"
    cmd = ["scanproof", "verify", "--anonymous", "-P", str(policy_path),
           "--pipeline", str(pipeline), "-o", str(result_path)]  # fmt: skip
    result_path.unlink(missing_ok=True)  # never judge a report left by an earlier run
    rc = subprocess.run(cmd, check=False).returncode
    if not result_path.exists():
        return rc, None
    report = json.loads(result_path.read_text(encoding="utf-8"))
    absent = sorted(
        c["check"]
        for r in report.get("requirements", [])
        for c in r["checks"]
        if c["code"] == "REQUIRED_INSTANCE_ABSENT"
    )
    return rc, absent


def main(out_dir: str) -> int:
    root = Path(out_dir)
    summary = json.loads((root / "summary.json").read_text(encoding="utf-8"))
    tested = 0
    failed = False
    for entry in (e for e in summary if "pipeline_id" in e):
        slug = entry["project"].split("/")[-1]
        path = root / slug / "inspection.json"
        if not path.exists():
            continue
        found = largest_matrix(json.loads(path.read_text(encoding="utf-8")))
        if found is None:
            print(f"{entry['project']}: no parallel: matrix jobs")
            continue
        base, labels = found
        out = root / slug
        print(f"::notice title=matrix {slug}::{base}: {len(labels)} legs {labels}")

        rc, absent = verify(out, entry["project"], entry["pipeline_id"], base, labels, "exact")
        ok = rc == 0 and absent == []
        print(f"::notice title=matrix {slug} exact::exit {rc}, absent {absent}")
        if not ok:
            print(f"::error title=matrix {slug} exact::expected exit 0 and no absent leg")

        rc2, absent2 = verify(
            out, entry["project"], entry["pipeline_id"], base, [*labels, REMOVED], "removed"
        )
        expected = [f"job_present [{base}: [{REMOVED}]]"]
        ok2 = rc2 == 1 and absent2 == expected
        print(f"::notice title=matrix {slug} removed::exit {rc2}, absent {absent2}")
        if not ok2:
            print(f"::error title=matrix {slug} removed::expected exit 1 and {expected}")
        failed |= not (ok and ok2)
        tested += 1
    if tested == 0:
        print("::error title=matrix::no inspected pipeline has parallel: matrix jobs; "
              "update CANDIDATES in collect_gitlab_contract.py")  # fmt: skip
        return 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
