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
    except subprocess.TimeoutExpired as exc:
        # `TimeoutExpired.stdout`/`.stderr` may be `None` (nothing was
        # captured before the kill) and may be `bytes` even though we asked
        # for `text=True` — `subprocess.run` only decodes the successful
        # path, not the exception's partial buffers — so decode defensively.
        # Preserved AHEAD of the "timed out" line: a timeout with no
        # diagnostic output is hard to act on, and whatever the child did
        # print (e.g. failing test names before a slower test hung) is the
        # only evidence a caller gets.
        partial = _decode(exc.stdout) + _decode(exc.stderr)
        timeout_line = f"gate timed out after {timeout}s"
        output = f"{partial}{timeout_line}" if partial else timeout_line
        return GateResult(exit_code=124, output=output, timed_out=True)
    return GateResult(exit_code=proc.returncode, output=proc.stdout + proc.stderr)


def _decode(chunk: bytes | str | None) -> str:
    """`TimeoutExpired`'s partial buffers are not reliably decoded for us."""
    if chunk is None:
        return ""
    if isinstance(chunk, bytes):
        return chunk.decode(errors="replace")
    return chunk


def classify(
    spec: MutationSpec, gate: GateResult, liveness: LivenessResult
) -> tuple[Outcome, tuple[str, ...]]:
    """Return the row's outcome and any `expect_red` names that were absent."""
    if not liveness.live:
        # Deliberately BEFORE any gate reasoning. A row that measured nothing
        # must never be reported as a row that measured a green.
        return Outcome.NOT_LIVE, ()

    if gate.timed_out:
        # Deliberately BEFORE the red/green branch, for the same reason as
        # the liveness check above: a gate that did not finish measured
        # nothing, and `GateResult.is_red` is true for a timeout's exit_code
        # (124) exactly as it would be for a real caught mutation. Without
        # this check first, an `expect="red"` row with an empty `expect_red`
        # — a legitimate, common shape — would read the timeout's exit code
        # as a catch and report `RED_AS_EXPECTED`, laundering "the gate did
        # not finish" into "the mutation was caught". That is #644's own
        # failure class, one level below where the liveness check guards it.
        return Outcome.GATE_TIMEOUT, ()

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
