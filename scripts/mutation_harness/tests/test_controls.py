import pytest

from mutation_harness import selftest
from mutation_harness.controls import NEGATIVE_CONTROLS, POSITIVE_CONTROLS
from mutation_harness.selftest import STANDALONE_CHECKS, run_control
from mutation_harness.types import Outcome

ALL = POSITIVE_CONTROLS + NEGATIVE_CONTROLS


@pytest.mark.parametrize("control", ALL, ids=[c.label for c in ALL])
def test_control_reaches_its_declared_outcome(control):
    ok, detail = run_control(control)
    assert ok, f"{control.label} ({control.why}): {detail}"


@pytest.mark.parametrize(
    "check", STANDALONE_CHECKS, ids=[c.label for c in STANDALONE_CHECKS]
)
def test_standalone_check_passes(check):
    """Parametrized over the REGISTRY rather than written out as one test per
    check, so pytest coverage of the standalone checks cannot drift from what
    `--self-test` runs. Four named test functions used to stand here; a check
    added to the registry and not to that list was invisible to pytest."""
    ok, detail = check.run()
    assert ok, f"{check.label} ({check.why}): {detail}"


def test_every_check_function_in_selftest_is_registered():
    """The dual of Finding 2, and the same shape as `conformance.py`'s Section
    REG: Finding 2 was a check that is INVOKED but not counted; this is a
    check that EXISTS but is never invoked, which produces no output and no
    failure. Discovery is by SHAPE (a module-level `check_*` callable defined
    in `selftest` itself), compared against the registry as a set."""
    discovered = {
        name
        for name, obj in vars(selftest).items()
        if name.startswith("check_")
        and callable(obj)
        and getattr(obj, "__module__", None) == selftest.__name__
    }
    registered = {check.run.__name__ for check in STANDALONE_CHECKS}

    assert discovered == registered, (
        f"unregistered: {sorted(discovered - registered)}; "
        f"registered but not found: {sorted(registered - discovered)}"
    )


def test_the_declared_label_set_is_the_union_of_the_three_tables():
    """Finding 2's other half: the printed total is `len(declared_labels())`,
    so this is what the denominator is made of. A table that stops being
    consulted here stops being counted — which is the intended signal, and is
    only safe because `execution_census` separately proves the declared set
    was actually RUN."""
    declared = selftest.declared_labels()

    assert set(declared) == (
        {c.label for c in POSITIVE_CONTROLS}
        | {c.label for c in NEGATIVE_CONTROLS}
        | {c.label for c in STANDALONE_CHECKS}
    )
    assert len(declared) == len(set(declared)), f"duplicate label in {declared}"


def test_the_execution_census_catches_a_dropped_invocation():
    """The fail-open that deriving the total does NOT close, measured during
    the fix: with `total` derived and the whole `STANDALONE_CHECKS` loop
    deleted, `--self-test` printed "19/19 checks passed", exit 0, having run
    14. A denominator read off a declaration says nothing about what ran."""
    declared = ("C1", "C2", "N1")

    ok, detail = selftest.execution_census(declared, ["C1", "N1"])

    assert ok is False
    assert "declared but never ran" in detail and "C2" in detail


def test_the_execution_census_passes_on_a_complete_run():
    ok, detail = selftest.execution_census(("C1", "C2"), ["C1", "C2"])

    assert ok is True
    assert "each exactly once" in detail


@pytest.mark.parametrize(
    "executed, wanted",
    [
        (["C1", "C2", "X9"], "ran but is not declared"),
        (["C1", "C2", "C2"], "ran more than once"),
    ],
    ids=["undeclared", "repeated"],
)
def test_the_execution_census_rejects_a_miscounted_run(executed, wanted):
    """A repeat is not cosmetic: the census compares SETS, so one label run
    twice while another never ran would otherwise cancel out."""
    ok, detail = selftest.execution_census(("C1", "C2"), executed)

    assert ok is False
    assert wanted in detail


def test_every_outcome_but_restore_failed_has_a_control():
    """Spec §9 criterion 1: every outcome in §5.5 needs at least one control.
    `RESTORE_FAILED` is the sole outcome with none — it needs a backup
    corrupted BEHIND the harness, which no `Control` fixture can drive (a
    `run_mutations`-pointed fixture has no failure path of its own for it).
    It is still covered, by the `RESTORE_FAILED` row in `STANDALONE_CHECKS`,
    whose `covers` field is what puts it into `check_outcome_coverage`'s
    derived set — just not by a row in either `Control` tuple, which is what
    this assertion is scoped to.
    Also proves the post-brief `GATE_TIMEOUT` addition is a real table
    entry: it is a distinct `Outcome` from `RESTORE_FAILED`, so its presence
    in `covered` here is exactly what makes this assertion — rather than a
    wider one — pass."""
    covered = {c.expect for c in POSITIVE_CONTROLS} | {c.expect for c in NEGATIVE_CONTROLS}
    uncovered = {o for o in Outcome if o not in covered}
    assert uncovered == {Outcome.RESTORE_FAILED}, (
        f"unexpected outcome coverage gap: {sorted(o.value for o in uncovered)}"
    )


def test_the_registry_is_the_sole_cover_for_restore_failed():
    """`check_outcome_coverage` derives its set from `Control.expect` plus
    `Check.covers`. Dropping the `covers=Outcome.RESTORE_FAILED` field would
    make the coverage line red — which is the intended signal — but nothing
    else in this file would notice which check lost it."""
    covering = {c.label for c in STANDALONE_CHECKS if c.covers is Outcome.RESTORE_FAILED}
    assert covering == {"RESTORE_FAILED"}
