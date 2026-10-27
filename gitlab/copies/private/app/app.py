"""Tiny scan target for the ScanProof copies contract. Deliberately trivial; never deploy."""

import subprocess


def run(cmd: str) -> str:
    return subprocess.check_output(cmd, shell=True, text=True)  # a finding for Semgrep
