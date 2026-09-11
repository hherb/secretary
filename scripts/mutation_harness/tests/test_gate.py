import os
import time

import pytest

from mutation_harness.gate import classify, names_a_red, run_gate
from mutation_harness.spec import SpecError, parse_spec
from mutation_harness.types import (
    Expect, GateResult, Lang, LivenessResult, MutationSpec, Outcome, RustProbe,
    TIMEOUT_EXIT_CODE,
)

LIVE = LivenessResult(True, "observed")
DEAD = LivenessResult(False, "unchanged")


def _spec(expect=Expect.RED, expect_red=()):
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
    outcome, _ = classify(_spec(expect=Expect.GREEN), GateResult(0, ""), LIVE)
    assert outcome is Outcome.GREEN_AS_EXPECTED


def test_expected_green_that_goes_red_is_reported():
    outcome, _ = classify(_spec(expect=Expect.GREEN), GateResult(1, ""), LIVE)
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


# --- PR #652 review: a name on a PASSING line is not a catch -----------------


def test_a_claimed_test_that_passes_while_another_fails_is_wrong_tests_red():
    """libtest prints `test <name> ... ok` for every PASSING test, so a whole-
    output substring match found the claimed name and reported
    `RED_AS_EXPECTED` with the claimed test green. `WRONG_TESTS_RED` could
    not fire at all for a `cargo test` gate. `controls.C14` drives the same
    shape end to end."""
    spec = _spec(expect_red=["answer_is_42"])
    output = "test answer_is_42 ... ok\ntest other_test ... FAILED\n"
    outcome, missing = classify(spec, GateResult(1, output), LIVE)
    assert outcome is Outcome.WRONG_TESTS_RED
    assert missing == ("answer_is_42",)


@pytest.mark.parametrize(
    "line",
    ["test answer_is_42 ... FAILED", "FAILED tests/test_x.py::answer_is_42", "FAIL: answer_is_42"],
    ids=["libtest", "pytest", "conformance"],
)
def test_every_gate_family_in_this_repo_names_a_red_on_one_line(line):
    assert names_a_red(line, "answer_is_42") is True


def test_a_name_and_a_marker_on_different_lines_do_not_pair():
    assert names_a_red("test answer_is_42 ... ok\nFAILED: other", "answer_is_42") is False


def test_run_gate_captures_exit_code_and_combined_output(tmp_path):
    ok = run_gate("echo hello", tmp_path)
    assert ok.exit_code == 0 and "hello" in ok.output
    bad = run_gate("echo oops >&2; exit 3", tmp_path)
    assert bad.exit_code == 3 and "oops" in bad.output and bad.is_red


def test_run_gate_records_a_timeout(tmp_path):
    result = run_gate("sleep 5", tmp_path, timeout=1)
    assert result.timed_out is True
    assert result.exit_code == TIMEOUT_EXIT_CODE


def test_a_timed_out_gate_is_not_credited_as_a_catch(tmp_path):
    """Regression for the Important finding (fix round 1): `run_gate`'s
    timeout handler records exit_code 124, which a naive `is_red` read as a
    failure — so for an `expect="red"` row with an empty `expect_red` (a
    legitimate, common shape; `_spec()`'s default), a naive `classify` read
    the timeout as a catch and reported `RED_AS_EXPECTED`. "The gate did not
    finish" must never render as "the mutation was caught"; it must be
    `GATE_TIMEOUT` instead.
    """
    result = run_gate("sleep 5", tmp_path, timeout=1)
    outcome, missing = classify(_spec(), result, LIVE)
    assert outcome is Outcome.GATE_TIMEOUT
    assert missing == ()


def test_a_genuine_exit_code_124_without_a_timeout_still_classifies_as_caught(tmp_path):
    """The outcome must key on `GateResult.timed_out`, never on `exit_code ==
    124` by itself — a real gate command is free to exit 124 on its own
    (nothing reserves it), and inferring a timeout from the exit code alone
    would be the same collapse `GATE_TIMEOUT` exists to prevent, in a new
    place.
    """
    result = run_gate("exit 124", tmp_path)
    assert result.exit_code == 124
    assert result.timed_out is False
    outcome, missing = classify(_spec(), result, LIVE)
    assert outcome is Outcome.RED_AS_EXPECTED
    assert missing == ()


# --- PR #652 review: the subprocess boundary ---------------------------------


def test_invalid_utf8_in_gate_output_does_not_abort_the_run(tmp_path):
    """`text=True` decoded strictly, so one bad byte — a Rust test printing
    raw bytes on failure, i.e. precisely when the gate is red — raised
    `UnicodeDecodeError` out of the run with no table rendered."""
    result = run_gate("printf 'ok\\xff\\n'; exit 1", tmp_path)
    assert result.is_red
    assert "ok" in result.output


def test_a_pipeline_gate_reports_the_failing_stage_not_the_last_one(tmp_path):
    """Without `pipefail`, `cargo test | tee log` reports `tee`'s status and a
    red gate reads as green."""
    assert run_gate("false | true", tmp_path).is_red


def test_a_timed_out_gate_takes_its_children_with_it(tmp_path):
    """Killing only the shell left a `cargo test`'s `rustc` and test binaries
    running while the tree was restored underneath them."""
    pid_file = tmp_path / "child.pid"
    result = run_gate(f"sleep 30 & echo $! > {pid_file}; wait", tmp_path, timeout=1)
    assert result.timed_out
    child = int(pid_file.read_text())
    for _ in range(40):
        try:
            os.kill(child, 0)
        except ProcessLookupError:
            break
        # A zombie answers `kill(pid, 0)` until it is reaped; give init a
        # moment. Only a LIVE sleeper would survive the whole loop.
        time.sleep(0.05)
    else:
        os.kill(child, 9)
        pytest.fail(f"child {child} of the timed-out gate survived the group kill")


def test_parse_spec_rejects_expect_red_on_a_green_row(tmp_path):
    """`classify` only ever consults `expect_red` when `expect == 'red'`; a
    non-empty list on a `green` row is silently inert at runtime, so it must
    be rejected at parse time instead."""
    (tmp_path / "a.rs").write_text("a\n")
    text = """
[[mutation]]
id = "M1"
lang = "rust"
path = "a.rs"
old = "a"
new = "b"
gate = "true"
expect = "green"
expect_red = ["some_test"]
probe = { package = "p" }
"""
    with pytest.raises(SpecError, match="expect_red is meaningless"):
        parse_spec(text, tmp_path)


# --- fix-wave review, I2: the NAME is a whole token, not a substring --------


@pytest.mark.parametrize(
    "line, name",
    [
        ("test a_manifest_missing_any_required_key_names_that_key_at_the_top_level ... FAILED",
         "a_manifest_missing_any_required_key_names_that_key"),
        ("FAILED tests/test_bravo.py::test_alpha - AssertionError", "test_bravo"),
    ],
    ids=["sibling-with-longer-name", "file-path"],
)
def test_a_name_embedded_in_another_token_does_not_count(line, name):
    """A sibling test with a LONGER name failing credited the claimed test
    (`_names_that_key` is a substring of `_names_that_key_at_the_top_level`),
    which is C14's fail-open one narrowing down."""
    assert names_a_red(line, name) is False


@pytest.mark.parametrize(
    "line, name",
    [
        ("test decode::tests::rejects_it ... FAILED", "rejects_it"),
        ("FAILED tests/test_x.py::test_alpha[case-1] - AssertionError", "test_alpha"),
        ("FAIL: Section RTV (rule token vocabulary)", "Section RTV"),
    ],
    ids=["module-prefix", "pytest-param-suffix", "phrase"],
)
def test_a_whole_token_name_still_counts(line, name):
    assert names_a_red(line, name) is True
