"""Run a gate command and classify the result. Spec §5.5.

`classify` checks LIVENESS FIRST. That ordering is the whole point of #644:
a mutation that did not run and a mutation that ran without reddening any
test produce the same gate output, and reporting them identically is what
converted "this test is non-vacuous" into an unfounded claim.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from mutation_harness.liveness import python_env
from mutation_harness.types import GateResult, LivenessResult, MutationSpec, Outcome


def run_gate(cmd: str, repo_root: Path, timeout: int = 3600) -> GateResult:
    """Run `cmd` through a shell, capturing stdout and stderr TOGETHER.

    Combined because `expect_red` matches by substring across both: cargo
    writes test names to stdout, and a failing `conformance.py` section can
    surface on either stream depending on the caller.
    """
    try:
        proc = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            cwd=str(repo_root),
            env=python_env(),
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return GateResult(exit_code=124, output=f"gate timed out after {timeout}s")
    return GateResult(exit_code=proc.returncode, output=proc.stdout + proc.stderr)


def classify(
    spec: MutationSpec, gate: GateResult, liveness: LivenessResult
) -> tuple[Outcome, tuple[str, ...]]:
    """Return the row's outcome and any `expect_red` names that were absent."""
    if not liveness.live:
        # Deliberately BEFORE any gate reasoning. A row that measured nothing
        # must never be reported as a row that measured a green.
        return Outcome.NOT_LIVE, ()

    if spec.expects_red:
        if not gate.is_red:
            return Outcome.UNEXPECTED_GREEN, ()
        missing = tuple(name for name in spec.expect_red if name not in gate.output)
        if missing:
            return Outcome.WRONG_TESTS_RED, missing
        return Outcome.RED_AS_EXPECTED, ()

    if gate.is_red:
        return Outcome.UNEXPECTED_RED, ()
    return Outcome.GREEN_AS_EXPECTED, ()
