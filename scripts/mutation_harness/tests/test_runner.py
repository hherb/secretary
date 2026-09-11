"""`run_mutations`' step ORDERING, its restore guarantee, and its abort path.

Spec §5.6 puts the liveness comparison (step 3) before the gate run (step 4),
and `runner.py` short-circuits on a dead row rather than running the gate and
letting `classify` discard the result. Every outcome-shaped assertion in this
tree is blind to that: `classify` carries its OWN `if not liveness.live` arm,
so deleting the runner's short-circuit leaves every control and every unit
test green — the row still reports `NOT_LIVE`, just after burning the run's
most expensive step (final whole-branch review, Finding 3; measured on the
merge-base: self-test 18/18, pytest 63/63 with the short-circuit removed).

The RESTORE guarantee had no assertion in either test layer until the PR #652
review: with `journal.record` moved AFTER `apply_substitution`, every control
still reported its declared outcome and the journal reported itself clean —
it had recorded the mutated bytes as the original. The bytes of the target
after a run are now asserted here and in `selftest.run_control`.
"""

import signal
from pathlib import Path

import pytest

from mutation_harness.runner import RunAborted, apply_substitution, run_mutations
from mutation_harness.types import Expect, Lang, MutationSpec, Outcome, PythonProbe

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


def _live_spec(tmp_path, **overrides) -> MutationSpec:
    fields = dict(
        id="LIVE", lang=Lang.PYTHON, path="m.py", old='"real"', new='"mutated"',
        gate="true", expect=Expect.GREEN, probe=PythonProbe("m", "TOKEN", "mutated", "."),
    )
    fields.update(overrides)
    return MutationSpec(**fields)


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
        gate=f"echo ran >> {log}", expect=Expect.RED,
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
    spec = _live_spec(tmp_path, id="ORD2", gate=f"echo ran >> {log}")

    (result,) = run_mutations((spec,), tmp_path, tmp_path / ".journal")

    assert result.outcome is Outcome.GREEN_AS_EXPECTED
    assert _runs_recorded(log) == 2, "expected a baseline run and a post-mutation run"


def test_a_baseline_that_timed_out_is_not_reported_as_a_dirty_baseline(tmp_path):
    """Finding 7, at unit scale — `controls.C13` is the same claim driven
    through `--self-test`. A baseline that did not FINISH is not a baseline
    that FAILED: `BASELINE_DIRTY` reads as "your tests are already red" and
    sends a reader to fix tests that may be perfectly green."""
    (tmp_path / "m.py").write_text('TOKEN = "real"\n')
    spec = _live_spec(tmp_path, id="ORD3", gate="sleep 5", expect=Expect.RED, timeout=1)

    (result,) = run_mutations((spec,), tmp_path, tmp_path / ".journal")

    assert result.outcome is Outcome.GATE_TIMEOUT
    assert result.gate is not None and result.gate.timed_out is True


# --- PR #652 review: the restore guarantee, asserted on the BYTES ------------


@pytest.mark.parametrize(
    "old, wanted",
    [('"real"', Outcome.GREEN_AS_EXPECTED), ("not-present-anywhere", Outcome.NOT_APPLIED)],
    ids=["live-row", "not-applied-row"],
)
def test_the_target_is_byte_identical_after_a_run(tmp_path, old, wanted):
    original = b'TOKEN = "real"\r\n# CRLF and a non-ascii byte: \xe9\n'
    (tmp_path / "m.py").write_bytes(original)
    spec = _live_spec(tmp_path, id="RESTORE", old=old)

    (result,) = run_mutations((spec,), tmp_path, tmp_path / ".journal")

    assert result.outcome is wanted, result.liveness
    assert (tmp_path / "m.py").read_bytes() == original


def test_apply_substitution_edits_bytes_and_preserves_the_rest_of_the_file(tmp_path):
    """`read_text()`/`write_text()` normalised CRLF and used the locale
    encoding, so every line of a CRLF file changed and a non-UTF-8 file
    raised out of the run."""
    target = tmp_path / "f.rs"
    target.write_bytes(b"a = 1;\r\nb = 2;\r\n\xff\n")

    assert apply_substitution(target, "b = 2", "b = 3") is True

    assert target.read_bytes() == b"a = 1;\r\nb = 3;\r\n\xff\n"


# --- PR #652 review: every abort carries the partial table --------------------


def test_a_harness_error_mid_run_aborts_with_the_rows_measured_so_far(tmp_path):
    """A spec whose `path` does not exist used to escape as a bare
    `FileNotFoundError` — no table, exit 1 — dropping every row measured
    before it. `parse_spec` now rejects that at parse time, but a spec built
    directly (the control tables, the tests) can still carry one, and any
    OTHER harness error takes the same path."""
    (tmp_path / "m.py").write_text('TOKEN = "real"\n')
    good = _live_spec(tmp_path, id="GOOD")
    bad = _live_spec(tmp_path, id="BAD", path="does-not-exist.py")

    with pytest.raises(RunAborted) as info:
        run_mutations((good, bad), tmp_path, tmp_path / ".journal")

    aborted = info.value
    assert aborted.restore_failed is False
    assert [r.spec.id for r in aborted.partial_results] == ["GOOD"]
    assert "BAD" in str(aborted) and "FileNotFoundError" in str(aborted)
    assert isinstance(aborted.__cause__, FileNotFoundError)
    assert (tmp_path / "m.py").read_text() == 'TOKEN = "real"\n'


def test_the_baseline_cache_is_keyed_on_the_timeout_too(tmp_path):
    """Keyed on the command alone, a spec with `timeout = 1` that timed out
    poisoned a later spec sharing the command but allowing the full budget
    into `GATE_TIMEOUT`."""
    (tmp_path / "m.py").write_text('TOKEN = "real"\n')
    short = _live_spec(tmp_path, id="SHORT", gate="sleep 2", timeout=1)
    long = _live_spec(tmp_path, id="LONG", gate="sleep 2", timeout=10)

    short_result, long_result = run_mutations((short, long), tmp_path, tmp_path / ".journal")

    assert short_result.outcome is Outcome.GATE_TIMEOUT
    assert long_result.outcome is Outcome.GREEN_AS_EXPECTED


def test_signal_dispositions_are_handed_back_after_a_run(tmp_path):
    """Every run used to leave its own handler installed; in a pytest
    process a SIGTERM then landed in whichever `Journal` had installed last,
    whose temp directory was gone, and became an in-test `SystemExit`."""
    (tmp_path / "m.py").write_text('TOKEN = "real"\n')
    before = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}

    run_mutations((_live_spec(tmp_path),), tmp_path, tmp_path / ".journal")

    assert {sig: signal.getsignal(sig) for sig in before} == before


# --- fix-wave review, I3 and S7: the abort paths past `journal.record` ------


def test_a_restore_failure_keeps_the_rows_own_measurement(tmp_path):
    """A four-hour gate's verdict is not thrown away because the restore
    after it failed: `partial_results` carries the measured row AND the
    `RESTORE_FAILED` row for the same spec, in that order."""
    import hashlib

    original = 'TOKEN = "real"\n'
    (tmp_path / "m.py").write_text(original)
    digest = hashlib.sha256(original.encode()).hexdigest()
    backup = tmp_path / ".journal" / f"{digest[:16]}-m.py.orig"
    spec = _live_spec(tmp_path, id="RF", gate=f"rm -f {backup}")

    try:
        with pytest.raises(RunAborted) as info:
            run_mutations((spec,), tmp_path, tmp_path / ".journal")
    finally:
        # This journal is dirty BY DESIGN (its backup is gone), so its
        # atexit drain would otherwise print at interpreter shutdown — the
        # same cleanup `selftest.check_restore_failed_is_observable` does.
        from mutation_harness.journal import Journal
        installed = Journal.installed_for(tmp_path / ".journal")
        if installed is not None:
            installed.uninstall_handlers()

    aborted = info.value
    assert aborted.restore_failed is True
    assert [(r.spec.id, r.outcome) for r in aborted.partial_results] == [
        ("RF", Outcome.GREEN_AS_EXPECTED), ("RF", Outcome.RESTORE_FAILED),
    ]


def test_a_gate_that_cannot_be_spawned_after_the_mutation_is_restored_and_reported(
    tmp_path, monkeypatch
):
    """S7: the abort path AFTER `journal.record` — the `finally` restore,
    then the outer handler — exercised by an `OSError` out of the
    post-mutation gate (the baseline gate, called first, succeeds)."""
    from mutation_harness import runner as runner_module
    from mutation_harness.types import GateResult

    calls = []

    def flaky_run_gate(cmd, repo_root, timeout):
        calls.append(cmd)
        if len(calls) == 1:
            return GateResult(0, "baseline ok")
        raise OSError("bash vanished")

    monkeypatch.setattr(runner_module, "run_gate", flaky_run_gate)
    (tmp_path / "m.py").write_text('TOKEN = "real"\n')
    spec = _live_spec(tmp_path, id="OSE")

    with pytest.raises(RunAborted) as info:
        run_mutations((spec,), tmp_path, tmp_path / ".journal")

    assert info.value.restore_failed is False
    assert info.value.partial_results == ()
    assert "OSError" in str(info.value) and "bash vanished" in str(info.value)
    assert (tmp_path / "m.py").read_text() == 'TOKEN = "real"\n'
    from mutation_harness.journal import Journal
    assert not Journal(tmp_path / ".journal").is_dirty()
