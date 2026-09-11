import json
import re

from mutation_harness.report import render_diagnostics, render_json, render_markdown
from mutation_harness.types import (
    Expect, GateResult, Lang, LivenessResult, MutationResult, MutationSpec, Outcome,
    PythonProbe, RustProbe, TIMEOUT_EXIT_CODE,
)

# The header line plus its separator line always precede the first data row.
_DATA_ROW_INDEX = 2


def _spec(lang=Lang.RUST, note="", old="a", new="b"):
    probe = RustProbe(package="p") if lang is Lang.RUST else PythonProbe("m", "X", "b", ".")
    return MutationSpec(
        id="M1", lang=lang, path="a.rs", old=old, new=new, gate="true",
        expect=Expect.RED, probe=probe, note=note,
    )


def _red(outcome=Outcome.RED_AS_EXPECTED, **spec_kw):
    """A live row with a finished red gate — the shape every gate-decided
    outcome shares."""
    return MutationResult(
        spec=_spec(**spec_kw), outcome=outcome,
        liveness=LivenessResult(True, "changed: lib.rlib"),
        gate=GateResult(1, "boom\ntest x ... FAILED"),
    )


def _dead(**spec_kw):
    return MutationResult(
        spec=_spec(**spec_kw), outcome=Outcome.NOT_LIVE,
        liveness=LivenessResult(False, "the bound value did NOT change"),
    )


def _unescaped_pipe_count(line: str) -> int:
    """Count only the pipes that would be read as column delimiters —
    i.e. not a `\\|` that `_cell` produced to escape a literal pipe in the
    mutated text."""
    return len(re.findall(r"(?<!\\)\|", line))


def test_markdown_names_the_liveness_mechanism_from_the_language():
    """The Rust and Python proofs differ in strength; the table must say
    which — derived from `spec.lang`, not stored beside it."""
    out = render_markdown([_red()])
    assert "| M1 |" in out
    assert "yes (artifact)" in out
    assert "RED_AS_EXPECTED" in out
    assert "yes (interpreter)" in render_markdown([_red(lang=Lang.PYTHON)])


def test_markdown_marks_a_row_that_measured_nothing():
    """`_live_cell` must distinguish a dead row from a live one.

    The old version of this test asserted `"no" in out.lower()`, which
    passed regardless of what `_live_cell` did: the OUTCOME name `NOT_LIVE`
    itself contains the substring "no" (`not_live`.lower()) — proven
    vacuous by monkeypatching `_live_cell` to always return `"yes (...)"`
    and watching the assertion stay green. This version reads the actual
    Live-column cell out of the rendered row and pins the distinction, not
    a presence.
    """
    dead_out = render_markdown([_dead(lang=Lang.PYTHON)])
    dead_cells = [c.strip() for c in dead_out.splitlines()[_DATA_ROW_INDEX].split("|")]
    assert dead_cells[3] == "NO"

    live_out = render_markdown([_red()])
    live_cells = [c.strip() for c in live_out.splitlines()[_DATA_ROW_INDEX].split("|")]
    assert live_cells[3] != "NO"


def test_a_pipe_in_old_does_not_increase_the_rendered_row_column_count():
    """A pipe in a mutated value is realistic here: `|` is both Rust's
    bitwise-or and its match-arm-alternation operator. Left unescaped it
    would read as an extra column separator."""
    out = render_markdown([_red(old="a | b")])
    lines = out.splitlines()
    assert _unescaped_pipe_count(lines[_DATA_ROW_INDEX]) == _unescaped_pipe_count(lines[0])


def test_a_newline_in_old_produces_exactly_one_table_row():
    out = render_markdown([_red(old="a\nb\nc")])
    # header line + separator line + exactly one data row
    assert len(out.splitlines()) == 3


def test_a_backtick_in_old_renders_without_breaking_the_fence():
    """`_code_span` refuses to wrap backtick-bearing content in backticks
    (rather than compute a CommonMark-longer fence around it), so the value
    appears unfenced — and the row must still have exactly as many
    unescaped pipes as the header, i.e. no column was gained or lost."""
    out = render_markdown([_red(old="a`b", new="c")])
    lines = out.splitlines()
    data_row = lines[_DATA_ROW_INDEX]
    assert "a`b" in data_row
    assert "`a`b`" not in data_row
    assert _unescaped_pipe_count(data_row) == _unescaped_pipe_count(lines[0])


def test_json_round_trips_every_field():
    result = _red(Outcome.UNEXPECTED_RED, note="why")
    payload = json.loads(render_json([result]))[0]
    assert payload == {
        "id": "M1",
        "lang": "rust",
        "path": "a.rs",
        "expect": "red",
        "note": "why",
        "outcome": "UNEXPECTED_RED",
        "success": False,
        "live": True,
        "mechanism": "artifact",
        "liveness_detail": "changed: lib.rlib",
        "exit_code": 1,
        "timed_out": False,
        "gate_output_tail": "boom\ntest x ... FAILED",
        "missing_reds": [],
    }


def test_json_carries_the_timeout_flag_beside_the_exit_code():
    """Without it a `--json` consumer reading `exit_code` got back exactly
    the 124 ambiguity the markdown path removes (PR #652 review)."""
    hung = MutationResult(
        spec=_spec(), outcome=Outcome.GATE_TIMEOUT,
        liveness=LivenessResult(True, "changed"),
        gate=GateResult(TIMEOUT_EXIT_CODE, "partial", timed_out=True),
    )
    payload = json.loads(render_json([hung]))[0]
    assert payload["exit_code"] == TIMEOUT_EXIT_CODE
    assert payload["timed_out"] is True


# --- PR #652 review: the diagnostics a reader needs to ACT on a row ----------


def test_diagnostics_are_empty_for_an_all_success_run():
    assert render_diagnostics([_red(), _red(Outcome.RED_AS_EXPECTED)]) == ""


def test_diagnostics_carry_the_liveness_detail_for_a_dead_row():
    """Every `NOT_LIVE` row rendered as `NO | NOT_LIVE` with none of the four
    reasons `compare_python_probe` composes."""
    out = render_diagnostics([_dead(lang=Lang.PYTHON)])
    assert "M1: NOT_LIVE" in out
    assert "liveness (interpreter): the bound value did NOT change" in out


def test_diagnostics_carry_the_gate_tail_for_a_red_row():
    out = render_diagnostics([_red(Outcome.UNEXPECTED_RED)])
    assert "gate exit 1" in out
    assert "test x ... FAILED" in out


def test_diagnostics_name_a_baseline_timeout_as_the_baseline_stage():
    """`GATE_TIMEOUT` is one outcome for two stages; the diagnostic says
    which — the only place a reader can see it."""
    baseline_hung = MutationResult(
        spec=_spec(), outcome=Outcome.GATE_TIMEOUT,
        gate=GateResult(TIMEOUT_EXIT_CODE, "gate timed out after 1s", timed_out=True),
    )
    out = render_diagnostics([baseline_hung])
    assert "baseline gate timed out" in out
