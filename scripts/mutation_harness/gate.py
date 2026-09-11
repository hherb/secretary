"""Run a gate command and classify the result. Spec §5.5.

Separating "did not run" from "ran and reddened nothing" is the whole point
of #644: the two produce the same gate output, and reporting them
identically is what converted "this test is non-vacuous" into an unfounded
claim. That separation is enforced in TWO places, and only one of them is
reachable in the real pipeline — say so, rather than letting this file's
comment claim the work:

* `runner.run_mutations` short-circuits: a row whose liveness comparison
  failed never reaches `run_gate` at all. That is the live enforcement, and
  it is what stops a dead row burning the run's most expensive step. Pinned
  by `test_runner.py::test_a_not_live_row_never_executes_its_gate`, which
  asserts the gate command is NEVER EXECUTED for a not-live row — an
  assertion on the ORDERING rather than on the outcome, because the outcome
  is what `classify` below independently preserves.
* `classify`'s own `if not liveness.live` is therefore DEFENCE IN DEPTH for
  any future caller that hands it a dead row directly, and is what
  `test_gate.py`'s unit tests exercise.

**`expect_red` names a test that must be reported RED, not merely
mentioned** (PR #652 review). The first version tested `name in gate.output`,
and libtest prints `test answer_is_42 ... ok` for every PASSING test, so an
`expect="red"` row whose named test passed while some other test failed
classified `RED_AS_EXPECTED` — "caught by the test this row claims" with the
claimed test green. `WRONG_TESTS_RED` could not fire at all for a `cargo
test` gate, the repo's primary gate. A name now counts only on an output LINE
that also carries a failure marker (`FAIL`, matched case-sensitively, which
covers libtest's `... FAILED`, pytest's `FAILED`, and `conformance.py`'s
`FAIL:` lines while never matching a passing `... ok` line). `controls.C14`
is the control for exactly this shape. The NAME must be a whole token on that
line — not adjacent to an identifier character, a dot, a slash or a hyphen —
so a sibling `…_names_that_key_at_the_top_level` failing does not satisfy
`…_names_that_key`, and a file path `tests/test_bravo.py` does not satisfy
`test_bravo` (fix-wave review: the first line-scoped version still matched
the name as a bare substring). A module prefix (`mod::name`) and a pytest
parameter suffix (`name[case]`) are both still accepted.

LIMIT: under `cargo test -q` (or `--quiet`) libtest prints dots instead of
per-test lines, and the only place a failing name then appears is the bare
`failures:` block, which carries no marker — a genuine catch reports
`WRONG_TESTS_RED`. That is the safe direction (a re-run without `-q` fixes
it), but a spec author should know why a red gate was not credited.
"""

from __future__ import annotations

import re
from pathlib import Path

from mutation_harness.liveness import python_env
from mutation_harness.subproc import run_bounded
from mutation_harness.types import (
    DEFAULT_GATE_TIMEOUT_SECONDS, TIMEOUT_EXIT_CODE, GateResult, LivenessResult,
    MutationSpec, Outcome,
)

RED_MARKER = "FAIL"


def run_gate(
    cmd: str, repo_root: Path, timeout: int = DEFAULT_GATE_TIMEOUT_SECONDS
) -> GateResult:
    """Run `cmd` under `bash -o pipefail`, capturing stdout and stderr
    TOGETHER.

    Combined because `expect_red` matches by line across both: cargo writes
    test names to stdout, and a failing `conformance.py` section can surface
    on either stream depending on the caller.

    `pipefail` because a gate written as a pipeline (`cargo test | tee log`)
    otherwise reports the LAST stage's status, so a red `cargo test` reads as
    green — this repo's own notes record `cargo test | grep` returning grep's
    status. The whole process group is killed on timeout (see `subproc.py`),
    so a `cargo test` that outlives its budget does not leave `rustc` and
    test binaries running while the tree is restored underneath them.
    """
    run = run_bounded(
        ["bash", "-o", "pipefail", "-c", cmd],
        cwd=repo_root,
        env=python_env(),
        timeout=timeout,
    )
    output = run.stdout + run.stderr
    if run.timed_out:
        # Preserved AHEAD of the "timed out" line: a timeout with no
        # diagnostic output is hard to act on, and whatever the child did
        # print (e.g. failing test names before a slower test hung) is the
        # only evidence a caller gets.
        timeout_line = f"gate timed out after {timeout}s"
        output = f"{output}{timeout_line}" if output else timeout_line
        return GateResult(exit_code=TIMEOUT_EXIT_CODE, output=output, timed_out=True)
    assert run.returncode is not None
    return GateResult(exit_code=run.returncode, output=output)


# What may NOT touch either end of a matched name: identifier characters
# (a sibling test with a longer name), and the path/version punctuation that
# would otherwise let `tests/test_bravo.py` satisfy `test_bravo`.
_NOT_A_TOKEN_EDGE = r"[\w./-]"


def names_a_red(output: str, name: str) -> bool:
    """`name` appears as a whole token on a line that also carries
    `RED_MARKER`. See the module docstring for what "whole token" admits."""
    pattern = re.compile(rf"(?<!{_NOT_A_TOKEN_EDGE}){re.escape(name)}(?!{_NOT_A_TOKEN_EDGE})")
    return any(
        RED_MARKER in line and pattern.search(line) is not None
        for line in output.splitlines()
    )


def classify(
    spec: MutationSpec, gate: GateResult, liveness: LivenessResult
) -> tuple[Outcome, tuple[str, ...]]:
    """Return the row's outcome and any `expect_red` names that were absent."""
    if not liveness.live:
        # Deliberately BEFORE any gate reasoning. A row that measured nothing
        # must never be reported as a row that measured a green. Defence in
        # depth: `run_mutations` never calls this with a dead row, because it
        # never runs the gate for one — see the module docstring for which of
        # the two is the live enforcement and what pins each.
        return Outcome.NOT_LIVE, ()

    if gate.timed_out:
        # Deliberately BEFORE the red/green branch, for the same reason as
        # the liveness check above: a gate that did not finish measured
        # nothing. `GateResult.is_red` now REFUSES to answer for a timed-out
        # result, so reading it first would be a loud error rather than a
        # silent catch — but the ordering is kept explicit because the
        # outcome, not an exception, is the contract.
        return Outcome.GATE_TIMEOUT, ()

    if spec.expects_red:
        if not gate.is_red:
            return Outcome.UNEXPECTED_GREEN, ()
        missing = tuple(name for name in spec.expect_red if not names_a_red(gate.output, name))
        if missing:
            return Outcome.WRONG_TESTS_RED, missing
        return Outcome.RED_AS_EXPECTED, ()

    if gate.is_red:
        return Outcome.UNEXPECTED_RED, ()
    return Outcome.GREEN_AS_EXPECTED, ()
