"""`run_mutations`' step ORDERING, as distinct from its outcomes.

Spec §5.6 puts the liveness comparison (step 3) before the gate run (step 4),
and `runner.py` short-circuits on a dead row rather than running the gate and
letting `classify` discard the result. Every outcome-shaped assertion in this
tree is blind to that: `classify` carries its OWN `if not liveness.live` arm,
so deleting the runner's short-circuit leaves every control and every unit
test green — the row still reports `NOT_LIVE`, just after burning the run's
most expensive step (final whole-branch review, Finding 3; measured on the
merge-base: self-test 18/18, pytest 63/63 with the short-circuit removed).

So this file asserts the gate is NEVER EXECUTED for a not-live row, which is
a property of the ordering and nothing else.
"""

from pathlib import Path

from mutation_harness.runner import run_mutations
from mutation_harness.types import Lang, MutationSpec, Outcome, PythonProbe

# The C2 shape: a splice after the class header, silently overridden by the
# real assignment below the docstring. The file changes, the interpreter binds
# the original value, so the before/after comparison finds no movement.
_DEAD_SPLICE_SOURCE = '''\
class Rejection:
    """A docstring, exactly as in conformance_lib."""

    TOKEN = "real"
'''


def _runs_recorded(log: Path) -> int:
    return log.read_text().count("ran\n") if log.exists() else 0


def test_a_not_live_row_never_executes_its_gate(tmp_path):
    """Pins step 4 before step 5.

    The gate APPENDS to a log rather than touching a sentinel, because
    `run_mutations` also runs this same command once as the clean-tree
    BASELINE (step 1) — a bare existence check could not tell the baseline
    run apart from a post-mutation run that should never have happened. One
    recorded run means the baseline only; two means the short-circuit is
    gone.
    """
    (tmp_path / "m.py").write_text(_DEAD_SPLICE_SOURCE)
    log = tmp_path / "gate-runs.log"
    spec = MutationSpec(
        id="ORD1", lang=Lang.PYTHON, path="m.py",
        old="class Rejection:",
        new='class Rejection:\n    TOKEN = "mutated"',
        gate=f"echo ran >> {log}", expect="red",
        probe=PythonProbe("m", "Rejection.TOKEN", "mutated", "."),
    )

    (result,) = run_mutations((spec,), tmp_path, tmp_path / ".journal")

    assert result.outcome is Outcome.NOT_LIVE, (
        f"fixture no longer reproduces a dead mutation: {result.outcome.value} "
        f"({result.liveness.detail if result.liveness else 'no liveness'})"
    )
    assert _runs_recorded(log) == 1, (
        "the gate ran again AFTER the mutation was proven dead — spec §5.6's "
        "step 3-before-step 4 ordering is gone, and every remaining assertion "
        "in this tree would still be green"
    )


def test_a_live_row_does_execute_its_gate(tmp_path):
    """The negative control for the test above: without it, a `run_mutations`
    that never ran ANY gate — or one whose baseline was skipped — would
    satisfy the assertion above just as well as the correct ordering does."""
    (tmp_path / "m.py").write_text('TOKEN = "real"\n')
    log = tmp_path / "gate-runs.log"
    spec = MutationSpec(
        id="ORD2", lang=Lang.PYTHON, path="m.py",
        old='"real"', new='"mutated"',
        gate=f"echo ran >> {log}", expect="green",
        probe=PythonProbe("m", "TOKEN", "mutated", "."),
    )

    (result,) = run_mutations((spec,), tmp_path, tmp_path / ".journal")

    assert result.outcome is Outcome.GREEN_AS_EXPECTED
    assert _runs_recorded(log) == 2, "expected a baseline run and a post-mutation run"


def test_a_baseline_that_timed_out_is_not_reported_as_a_dirty_baseline(tmp_path):
    """Finding 7, at unit scale — `controls.C13` is the same claim driven
    through `--self-test`. A baseline that did not FINISH is not a baseline
    that FAILED: `BASELINE_DIRTY` reads as "your tests are already red" and
    sends a reader to fix tests that may be perfectly green."""
    (tmp_path / "m.py").write_text('TOKEN = "real"\n')
    spec = MutationSpec(
        id="ORD3", lang=Lang.PYTHON, path="m.py",
        old='"real"', new='"mutated"', gate="sleep 5", expect="red", timeout=1,
        probe=PythonProbe("m", "TOKEN", "mutated", "."),
    )

    (result,) = run_mutations((spec,), tmp_path, tmp_path / ".journal")

    assert result.outcome is Outcome.GATE_TIMEOUT
    assert result.outcome is not Outcome.BASELINE_DIRTY
    assert result.gate is not None and result.gate.timed_out is True
