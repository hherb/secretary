from mutation_harness.gate import classify, run_gate
from mutation_harness.types import (
    GateResult, Lang, LivenessResult, MutationSpec, Outcome, RustProbe,
)

LIVE = LivenessResult(True, "interpreter", "observed")
DEAD = LivenessResult(False, "interpreter", "unchanged")


def _spec(expect="red", expect_red=()):
    return MutationSpec(
        id="M1", lang=Lang.RUST, path="a.rs", old="a", new="b",
        gate="true", expect=expect, probe=RustProbe(package="p"),
        expect_red=tuple(expect_red),
    )


def test_a_dead_mutation_is_not_live_regardless_of_the_gate():
    """The pair that matters: NOT_LIVE must never render as UNEXPECTED_GREEN."""
    outcome, _ = classify(_spec(), GateResult(0, ""), DEAD)
    assert outcome is Outcome.NOT_LIVE
    outcome, _ = classify(_spec(), GateResult(1, ""), DEAD)
    assert outcome is Outcome.NOT_LIVE


def test_expected_red_that_goes_red_passes():
    outcome, missing = classify(_spec(), GateResult(1, "boom"), LIVE)
    assert outcome is Outcome.RED_AS_EXPECTED
    assert missing == ()


def test_expected_red_that_stays_green_is_a_finding():
    outcome, _ = classify(_spec(), GateResult(0, ""), LIVE)
    assert outcome is Outcome.UNEXPECTED_GREEN


def test_expected_green_that_stays_green_passes():
    outcome, _ = classify(_spec(expect="green"), GateResult(0, ""), LIVE)
    assert outcome is Outcome.GREEN_AS_EXPECTED


def test_expected_green_that_goes_red_is_reported():
    outcome, _ = classify(_spec(expect="green"), GateResult(1, ""), LIVE)
    assert outcome is Outcome.UNEXPECTED_RED


def test_red_with_a_missing_expected_test_name_is_wrong_tests_red():
    """Passing on 'something red' is not the claim a mutation table makes."""
    spec = _spec(expect_red=["wanted_test", "other_test"])
    outcome, missing = classify(spec, GateResult(1, "... other_test ... FAILED"), LIVE)
    assert outcome is Outcome.WRONG_TESTS_RED
    assert missing == ("wanted_test",)


def test_red_with_every_expected_test_name_present_passes():
    spec = _spec(expect_red=["wanted_test"])
    outcome, missing = classify(spec, GateResult(1, "wanted_test FAILED"), LIVE)
    assert outcome is Outcome.RED_AS_EXPECTED
    assert missing == ()


def test_run_gate_captures_exit_code_and_combined_output(tmp_path):
    ok = run_gate("echo hello", tmp_path)
    assert ok.exit_code == 0 and "hello" in ok.output
    bad = run_gate("echo oops >&2; exit 3", tmp_path)
    assert bad.exit_code == 3 and "oops" in bad.output and bad.is_red
