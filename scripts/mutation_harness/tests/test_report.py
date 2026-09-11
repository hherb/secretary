import json
import re

from mutation_harness.report import render_json, render_markdown
from mutation_harness.types import (
    GateResult, Lang, LivenessResult, MutationResult, MutationSpec, Outcome, RustProbe,
)

# The header line plus its separator line always precede the first data row.
_DATA_ROW_INDEX = 2


def _result(outcome, mechanism="artifact", note="", live=True, old="a", new="b"):
    spec = MutationSpec(
        id="M1", lang=Lang.RUST, path="a.rs", old=old, new=new, gate="true",
        expect="red", probe=RustProbe(package="p"), note=note,
    )
    return MutationResult(
        spec=spec,
        outcome=outcome,
        liveness=LivenessResult(live, mechanism, "changed: lib.rlib"),
        gate=GateResult(1, "boom"),
    )


def _unescaped_pipe_count(line: str) -> int:
    """Count only the pipes that would be read as column delimiters —
    i.e. not a `\\|` that `_cell` produced to escape a literal pipe in the
    mutated text."""
    return len(re.findall(r"(?<!\\)\|", line))


def test_markdown_names_the_liveness_mechanism():
    """The Rust and Python proofs differ in strength; the table must say which."""
    out = render_markdown([_result(Outcome.RED_AS_EXPECTED)])
    assert "| M1 |" in out
    assert "artifact" in out
    assert "RED_AS_EXPECTED" in out


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
    dead_out = render_markdown([_result(Outcome.NOT_LIVE, mechanism="interpreter", live=False)])
    dead_cells = [c.strip() for c in dead_out.splitlines()[_DATA_ROW_INDEX].split("|")]
    assert dead_cells[3] == "NO"

    live_out = render_markdown([_result(Outcome.RED_AS_EXPECTED, live=True)])
    live_cells = [c.strip() for c in live_out.splitlines()[_DATA_ROW_INDEX].split("|")]
    assert live_cells[3] != "NO"


def test_a_pipe_in_old_does_not_increase_the_rendered_row_column_count():
    """A pipe in a mutated value is realistic here: `|` is both Rust's
    bitwise-or and its match-arm-alternation operator. Left unescaped it
    would read as an extra column separator."""
    out = render_markdown([_result(Outcome.RED_AS_EXPECTED, old="a | b")])
    lines = out.splitlines()
    assert _unescaped_pipe_count(lines[_DATA_ROW_INDEX]) == _unescaped_pipe_count(lines[0])


def test_a_newline_in_old_produces_exactly_one_table_row():
    out = render_markdown([_result(Outcome.RED_AS_EXPECTED, old="a\nb\nc")])
    # header line + separator line + exactly one data row
    assert len(out.splitlines()) == 3


def test_a_backtick_in_old_renders_without_breaking_the_fence():
    """`_code_span` refuses to wrap backtick-bearing content in backticks
    (rather than compute a CommonMark-longer fence around it), so the value
    appears unfenced — and the row must still have exactly as many
    unescaped pipes as the header, i.e. no column was gained or lost."""
    out = render_markdown([_result(Outcome.RED_AS_EXPECTED, old="a`b", new="c")])
    lines = out.splitlines()
    data_row = lines[_DATA_ROW_INDEX]
    assert "a`b" in data_row
    assert "`a`b`" not in data_row
    assert _unescaped_pipe_count(data_row) == _unescaped_pipe_count(lines[0])


def test_json_round_trips_every_field():
    result = _result(Outcome.UNEXPECTED_GREEN, mechanism="artifact", note="why")
    payload = json.loads(render_json([result]))[0]
    assert payload == {
        "id": "M1",
        "lang": "rust",
        "path": "a.rs",
        "expect": "red",
        "note": "why",
        "outcome": "UNEXPECTED_GREEN",
        "success": False,
        "live": True,
        "mechanism": "artifact",
        "liveness_detail": "changed: lib.rlib",
        "exit_code": 1,
        "missing_reds": [],
    }
