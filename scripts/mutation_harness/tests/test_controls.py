import pytest

from mutation_harness.controls import NEGATIVE_CONTROLS, POSITIVE_CONTROLS
from mutation_harness.selftest import (
    check_clean_baseline, check_journal_refusal, check_no_bytecode_written,
    check_restore_failed_is_observable, run_control,
)
from mutation_harness.types import Outcome

ALL = POSITIVE_CONTROLS + NEGATIVE_CONTROLS


@pytest.mark.parametrize("control", ALL, ids=[c.label for c in ALL])
def test_control_reaches_its_declared_outcome(control):
    ok, detail = run_control(control)
    assert ok, f"{control.label} ({control.why}): {detail}"


def test_journal_refusal_is_visible_to_the_next_invocation():
    ok, detail = check_journal_refusal()
    assert ok, detail


def test_a_clean_baseline_is_not_reported_dirty():
    ok, detail = check_clean_baseline()
    assert ok, detail


def test_no_bytecode_is_written_by_any_probe_or_gate_subprocess():
    ok, detail = check_no_bytecode_written()
    assert ok, detail


def test_restore_failed_is_observable_through_mutate_main():
    ok, detail = check_restore_failed_is_observable()
    assert ok, detail


def test_every_outcome_but_restore_failed_has_a_control():
    """Spec §9 criterion 1: every outcome in §5.5 needs at least one control.
    `RESTORE_FAILED` is the sole outcome with none — it needs a backup
    corrupted BEHIND the harness, which no `Control` fixture can drive (a
    `run_mutations`-pointed fixture has no failure path of its own for it).
    It is still covered, by `check_restore_failed_is_observable` above and
    by `selftest.run_self_test`'s own coverage set — just not by a row in
    either `Control` tuple, which is what this assertion is scoped to.
    Also proves the post-brief `GATE_TIMEOUT` addition is a real table
    entry: it is a distinct `Outcome` from `RESTORE_FAILED`, so its presence
    in `covered` here is exactly what makes this assertion — rather than a
    wider one — pass."""
    covered = {c.expect for c in POSITIVE_CONTROLS} | {c.expect for c in NEGATIVE_CONTROLS}
    uncovered = {o for o in Outcome if o not in covered}
    assert uncovered == {Outcome.RESTORE_FAILED}, (
        f"unexpected outcome coverage gap: {sorted(o.value for o in uncovered)}"
    )
