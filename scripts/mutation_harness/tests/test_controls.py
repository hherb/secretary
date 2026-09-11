import pytest

from mutation_harness import selftest
from mutation_harness.controls import NEGATIVE_CONTROLS, POSITIVE_CONTROLS, Control, _build_n2
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
    so this is what the denominator is made of."""
    declared = selftest.declared_labels()

    assert set(declared) == (
        {c.label for c in POSITIVE_CONTROLS}
        | {c.label for c in NEGATIVE_CONTROLS}
        | {c.label for c in STANDALONE_CHECKS}
    )
    assert len(declared) == len(set(declared)), f"duplicate label in {declared}"


def test_the_declared_labels_are_exactly_these():
    """The test above compares the tables to THEMSELVES, so dropping a row
    and its function left both layers green with "16/16 checks passed", exit
    0 (PR #652 review, measured). A count that moves silently is not a
    signal; this pins the set by name, the way the Rust corpora pin
    `want_re_encode == 17`. Adding a check means editing this tuple, on
    purpose."""
    assert selftest.declared_labels() == (
        "C1", "C2", "C4", "C5", "C6", "C8", "C9", "C14", "C10", "C11", "C12", "C13",
        "C3", "N3", "no-bytecode", "RESTORE_FAILED", "outcome coverage",
        "N1", "N2", "N4",
    )


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
    this assertion is scoped to."""
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


# --- PR #652 review: `run_self_test` itself, which no pytest exercised -----
#
# `return 1 if failures else 0` -> `return 0` left the whole suite green.
# These drive the real loop over a one-row table each.


def _quiet(monkeypatch, capsys, positive=(), standalone=(), negative=()):
    monkeypatch.setattr(selftest, "POSITIVE_CONTROLS", tuple(positive))
    monkeypatch.setattr(selftest, "STANDALONE_CHECKS", tuple(standalone))
    monkeypatch.setattr(selftest, "NEGATIVE_CONTROLS", tuple(negative))
    code = selftest.run_self_test()
    return code, capsys.readouterr().out


def test_run_self_test_exits_1_when_a_control_misses_its_declared_outcome(monkeypatch, capsys):
    wrong = Control("W1", "expects the wrong outcome", _build_n2, Outcome.NOT_LIVE)

    code, out = _quiet(monkeypatch, capsys, positive=(wrong,))

    assert code == 1
    assert "[FAIL] W1" in out and "0/1 checks passed" in out


def test_run_self_test_exits_0_when_every_check_passes(monkeypatch, capsys):
    fine = Control("F1", "a by-design green", _build_n2, Outcome.GREEN_AS_EXPECTED)

    code, out = _quiet(monkeypatch, capsys, negative=(fine,))

    assert code == 0
    assert "1/1 checks passed" in out


def test_a_check_that_raises_is_a_named_fail_and_the_run_continues(monkeypatch, capsys):
    """An exception used to escape the loop: every later check went unrun
    and the census never executed."""
    def boom():
        raise RuntimeError("fixture exploded")

    def fine():
        return True, "ok"

    checks = (selftest.Check("X1", "raises", boom), selftest.Check("X2", "fine", fine))

    code, out = _quiet(monkeypatch, capsys, standalone=checks)

    assert code == 1
    assert "[FAIL] X1" in out and "RuntimeError: fixture exploded" in out
    assert "[PASS] X2" in out
    assert "1/2 checks passed" in out


def test_run_self_test_censuses_what_ran_against_what_is_declared(monkeypatch, capsys):
    """The disclosed "terminal turtle": nothing inside `run_self_test`
    verified that it CALLS `execution_census`. This does, by recording the
    call."""
    calls = []

    def recording_census(declared, executed):
        calls.append((tuple(declared), tuple(executed)))
        return True, "recorded"

    monkeypatch.setattr(selftest, "execution_census", recording_census)
    fine = Control("F1", "a by-design green", _build_n2, Outcome.GREEN_AS_EXPECTED)

    _quiet(monkeypatch, capsys, negative=(fine,))

    assert calls == [(("F1",), ("F1",))]


def test_a_failed_census_is_reported_beside_the_count_not_inside_it(monkeypatch, capsys):
    """Folding the census into `failures` let the numerator go NEGATIVE when
    every check and the census failed ("-1/19 checks passed")."""
    monkeypatch.setattr(selftest, "execution_census", lambda d, e: (False, "planted"))
    wrong = Control("W1", "expects the wrong outcome", _build_n2, Outcome.NOT_LIVE)

    code, out = _quiet(monkeypatch, capsys, positive=(wrong,))

    assert code == 1
    assert "0/1 checks passed; census FAILED" in out
    assert "-1/" not in out
