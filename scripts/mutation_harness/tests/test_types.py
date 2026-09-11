"""The invalid states the value types refuse to represent (PR #652 review).

Every one of these used to construct silently. `MutationResult` had no
`__post_init__`, so a `NO | UNEXPECTED_GREEN` row — the one pairing the whole
design says can never render — was representable and `render_markdown`
printed it. `MutationSpec.expect` was a free string, so `expect="Red"` built a
spec whose `expects_red` was False and a live green classified as
`GREEN_AS_EXPECTED` (exit 0): the fail-open direction, reachable by every
control and every test that builds the dataclass directly and so never passes
through `spec.py`'s validation. `GateResult(exit_code=0, timed_out=True)`
constructed, and `is_red` read `exit_code` without consulting the flag.
"""

import pytest

from mutation_harness.types import (
    Expect, GateResult, Lang, LivenessResult, MutationResult, MutationSpec, Outcome,
    PythonProbe, RustObservation, RustProbe, RustReadingKind, TIMEOUT_EXIT_CODE,
)

PY_PROBE = PythonProbe(module="m", expr="TOKEN", equals="mutated", syspath=".")
RS_PROBE = RustProbe(package="p")


def _spec(**overrides) -> MutationSpec:
    fields = dict(
        id="M1", lang=Lang.PYTHON, path="m.py", old="a", new="b", gate="true",
        expect=Expect.RED, probe=PY_PROBE,
    )
    fields.update(overrides)
    return MutationSpec(**fields)


# --- MutationSpec -----------------------------------------------------------


def test_expect_is_an_enum_not_a_string():
    with pytest.raises(ValueError, match="Expect"):
        _spec(expect="red")


def test_a_python_row_must_carry_a_python_probe_and_a_rust_row_a_rust_probe():
    with pytest.raises(ValueError, match="probe"):
        _spec(lang=Lang.PYTHON, probe=RS_PROBE)
    with pytest.raises(ValueError, match="probe"):
        _spec(lang=Lang.RUST, probe=PY_PROBE)
    assert _spec(lang=Lang.RUST, probe=RS_PROBE).expects_red is True


def test_expect_red_is_only_meaningful_on_a_red_row():
    with pytest.raises(ValueError, match="expect_red"):
        _spec(expect=Expect.GREEN, expect_red=("t",))


@pytest.mark.parametrize("timeout", [0, -5, True], ids=["zero", "negative", "bool"])
def test_timeout_must_be_a_positive_integer(timeout):
    with pytest.raises(ValueError, match="timeout"):
        _spec(timeout=timeout)


# --- GateResult -------------------------------------------------------------


def test_a_timed_out_gate_carries_the_timeout_exit_code_and_no_verdict():
    with pytest.raises(ValueError, match="timed_out"):
        GateResult(exit_code=0, output="", timed_out=True)
    gate = GateResult(exit_code=TIMEOUT_EXIT_CODE, output="", timed_out=True)
    with pytest.raises(ValueError, match="timed_out"):
        gate.is_red  # noqa: B018 - the property itself is under test


def test_a_finished_gate_that_happens_to_exit_124_is_still_a_verdict():
    assert GateResult(exit_code=TIMEOUT_EXIT_CODE, output="").is_red is True


# --- RustObservation --------------------------------------------------------


def test_a_non_measurement_reading_must_say_why_and_carries_no_hashes():
    with pytest.raises(ValueError):
        RustObservation(RustReadingKind.BUILD_FAILED, {}, "")
    with pytest.raises(ValueError):
        RustObservation(RustReadingKind.BUILD_FAILED, {"a": "b"}, "cargo exited 101")
    assert RustObservation(RustReadingKind.ARTIFACTS, {"a": "b"}).is_measurement


# --- MutationResult ---------------------------------------------------------

LIVE = LivenessResult(True, "changed")
DEAD = LivenessResult(False, "unchanged")
GREEN = GateResult(0, "")
RED = GateResult(1, "test x ... FAILED")
HUNG = GateResult(TIMEOUT_EXIT_CODE, "", timed_out=True)


@pytest.mark.parametrize(
    "outcome, liveness, gate, missing",
    [
        (Outcome.UNEXPECTED_GREEN, DEAD, GREEN, ()),
        (Outcome.UNEXPECTED_GREEN, None, GREEN, ()),
        (Outcome.GREEN_AS_EXPECTED, LIVE, None, ()),
        (Outcome.RED_AS_EXPECTED, LIVE, HUNG, ()),
        (Outcome.RED_AS_EXPECTED, LIVE, RED, ("x",)),
        (Outcome.WRONG_TESTS_RED, LIVE, RED, ()),
        (Outcome.NOT_LIVE, LIVE, None, ()),
        (Outcome.NOT_LIVE, DEAD, RED, ()),
        (Outcome.GATE_TIMEOUT, LIVE, RED, ()),
        (Outcome.BASELINE_DIRTY, None, GREEN, ()),
        (Outcome.BASELINE_DIRTY, LIVE, RED, ()),
        (Outcome.NOT_APPLIED, LIVE, None, ()),
        (Outcome.RESTORE_FAILED, None, RED, ()),
    ],
    ids=[
        "green-verdict-on-dead-row", "green-verdict-without-probe",
        "verdict-without-gate", "verdict-on-hung-gate", "missing-without-wrong-tests",
        "wrong-tests-without-missing", "not-live-but-live", "not-live-with-gate",
        "timeout-without-timeout", "dirty-on-green", "dirty-after-probe",
        "not-applied-with-probe", "restore-failed-with-gate",
    ],
)
def test_a_self_contradictory_row_is_unrepresentable(outcome, liveness, gate, missing):
    with pytest.raises(ValueError):
        MutationResult(_spec(), outcome, liveness=liveness, gate=gate, missing_reds=missing)


@pytest.mark.parametrize(
    "outcome, liveness, gate, missing",
    [
        (Outcome.RED_AS_EXPECTED, LIVE, RED, ()),
        (Outcome.GREEN_AS_EXPECTED, LIVE, GREEN, ()),
        (Outcome.UNEXPECTED_GREEN, LIVE, GREEN, ()),
        (Outcome.UNEXPECTED_RED, LIVE, RED, ()),
        (Outcome.WRONG_TESTS_RED, LIVE, RED, ("x",)),
        (Outcome.NOT_LIVE, DEAD, None, ()),
        (Outcome.GATE_TIMEOUT, LIVE, HUNG, ()),
        (Outcome.GATE_TIMEOUT, None, HUNG, ()),
        (Outcome.BASELINE_DIRTY, None, RED, ()),
        (Outcome.NOT_APPLIED, None, None, ()),
        (Outcome.RESTORE_FAILED, None, None, ()),
    ],
    ids=[
        "red", "green", "unexpected-green", "unexpected-red", "wrong-tests",
        "not-live", "post-mutation-timeout", "baseline-timeout", "dirty",
        "not-applied", "restore-failed",
    ],
)
def test_every_row_the_runner_builds_is_representable(outcome, liveness, gate, missing):
    row = MutationResult(_spec(), outcome, liveness=liveness, gate=gate, missing_reds=missing)
    assert row.outcome is outcome


def test_a_rust_observation_is_hashable_despite_its_dict_field():
    """A frozen dataclass synthesises `__hash__` over every field; a dict
    field made that raise at the first `set` rather than fail to type-check."""
    reading = RustObservation(RustReadingKind.ARTIFACTS, {"a": "b"})
    assert len({reading, reading}) == 1
