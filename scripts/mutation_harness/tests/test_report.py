import json

from mutation_harness.report import render_json, render_markdown
from mutation_harness.types import (
    GateResult, Lang, LivenessResult, MutationResult, MutationSpec, Outcome, RustProbe,
)


def _result(outcome, mechanism="artifact", note=""):
    spec = MutationSpec(
        id="M1", lang=Lang.RUST, path="a.rs", old="a", new="b", gate="true",
        expect="red", probe=RustProbe(package="p"), note=note,
    )
    return MutationResult(
        spec=spec,
        outcome=outcome,
        liveness=LivenessResult(True, mechanism, "changed: lib.rlib"),
        gate=GateResult(1, "boom"),
    )


def test_markdown_names_the_liveness_mechanism():
    """The Rust and Python proofs differ in strength; the table must say which."""
    out = render_markdown([_result(Outcome.RED_AS_EXPECTED)])
    assert "| M1 |" in out
    assert "artifact" in out
    assert "RED_AS_EXPECTED" in out


def test_markdown_marks_a_row_that_measured_nothing():
    out = render_markdown([_result(Outcome.NOT_LIVE, mechanism="interpreter")])
    assert "NOT_LIVE" in out
    assert "no" in out.lower()


def test_json_round_trips_every_field():
    payload = json.loads(render_json([_result(Outcome.UNEXPECTED_GREEN, note="why")]))
    assert payload[0]["id"] == "M1"
    assert payload[0]["outcome"] == "UNEXPECTED_GREEN"
    assert payload[0]["live"] is True
    assert payload[0]["note"] == "why"
