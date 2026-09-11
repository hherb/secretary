import pytest

from mutation_harness.controls import NEGATIVE_CONTROLS, POSITIVE_CONTROLS
from mutation_harness.selftest import (
    check_clean_baseline, check_journal_refusal, run_control,
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


def test_every_outcome_but_restore_failed_has_a_control():
    """Spec §9 criterion 1: every outcome in §5.5 needs at least one control.
    `RESTORE_FAILED` is the sole, deliberate exception — it needs a backup
    corrupted BEHIND the harness, which `test_journal.py` covers instead."""
    covered = {c.expect for c in POSITIVE_CONTROLS} | {c.expect for c in NEGATIVE_CONTROLS}
    uncovered = {o for o in Outcome if o not in covered}
    assert uncovered == {Outcome.RESTORE_FAILED}, (
        f"unexpected outcome coverage gap: {sorted(o.value for o in uncovered)}"
    )


def test_gate_timeout_is_covered_by_a_control_not_excused():
    """Reconciliation for the post-brief GATE_TIMEOUT addition: this must be
    a real entry in the table, not a name added to an excuse list."""
    assert any(c.expect is Outcome.GATE_TIMEOUT for c in POSITIVE_CONTROLS)
