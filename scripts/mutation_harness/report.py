"""Render results. Spec §7.

The table is emitted so a handoff pastes GENERATED evidence. Every mutation
table in every handoff before #644 was hand-transcribed from scrollback — an
unverified step between the measurement and the published claim, invisible to
review because the scrollback is gone by the time anyone reads the table.

The table stays FIVE columns so the pasted evidence keeps its shape; the
diagnostics a reader needs to ACT on a non-success row go to stderr through
`render_diagnostics` (PR #652 review). Until then every `NOT_LIVE` row rendered
as `NO | NOT_LIVE` with none of the four reasons `compare_python_probe`
composes, and gate output was rendered by nothing at all — the handoff's own
`UNEXPECTED_RED` (#651) had to be re-diagnosed by re-running the gate by hand.
"""

from __future__ import annotations

import json

from mutation_harness.types import Lang, MutationResult

_HEADER = "| # | Mutation | Live | Outcome | Reds |\n|---|---|---|---|---|"

# Which proof a `LivenessResult` came from is a function of the spec's
# language, rendered here rather than stored on the result beside `lang`.
MECHANISM = {Lang.PYTHON: "interpreter", Lang.RUST: "artifact"}

# Lines of gate output a diagnostic carries. The tail, because a test
# runner's summary — the failing test names, the panic message — comes last.
GATE_TAIL_LINES = 30


def _cell(text: str) -> str:
    """Make `text` safe to interpolate into one markdown table cell.

    Every run of whitespace, INCLUDING a newline, collapses to a single
    space — otherwise a multi-line `old`/`new` value would split one result
    row into several malformed table lines. A literal `|` is escaped: left
    bare it reads as a column separator and silently adds a column to
    whatever row carries it, and `|` is a realistic mutated value in this
    repo (Rust's bitwise-or, and match-arm alternation, which is everywhere
    in the manifest/conformance decoders this harness mutates). Empty or
    whitespace-only input renders as `—` so a cell is never blank — a blank
    cell next to a real pipe is itself ambiguous table syntax.
    """
    collapsed = " ".join(text.split())
    if not collapsed:
        return "—"
    return collapsed.replace("|", "\\|")


def _code_span(text: str) -> str:
    """Wrap already-`_cell`-safe `text` as CommonMark inline code.

    CommonMark's rule for a backtick INSIDE a code span is a fence longer
    than the longest backtick run in the content; rather than computing
    that, a value containing a backtick is left UNFENCED instead — it has
    already been through `_cell`, so it is still a single-line, pipe-escaped
    table cell, just not monospaced. Simpler than a variable-length fence,
    and correctness (no broken fence, no swallowed table structure) does not
    depend on which choice is made — only the styling does.
    """
    return text if "`" in text else f"`{text}`"


def _live_cell(result: MutationResult) -> str:
    if result.liveness is None:
        return "not probed"
    if not result.liveness.live:
        return "NO"
    return f"yes ({MECHANISM[result.spec.lang]})"


def _reds_cell(result: MutationResult) -> str:
    if result.missing_reds:
        return "missing: " + ", ".join(_cell(name) for name in result.missing_reds)
    if result.spec.expect_red:
        return ", ".join(_cell(name) for name in result.spec.expect_red)
    return "—"


def _describe(result: MutationResult) -> str:
    if result.spec.note:
        return _cell(result.spec.note)
    old = _cell(result.spec.old)
    new = _cell(result.spec.new)
    return f"{_code_span(old)} -> {_code_span(new)}"


def render_markdown(results: list[MutationResult]) -> str:
    rows = [
        f"| {_cell(r.spec.id)} | {_describe(r)} | {_live_cell(r)} "
        f"| {r.outcome.value} | {_reds_cell(r)} |"
        for r in results
    ]
    return "\n".join([_HEADER, *rows])


def _gate_tail(output: str) -> str:
    lines = output.splitlines()
    return "\n".join(lines[-GATE_TAIL_LINES:])


def render_diagnostics(results: list[MutationResult]) -> str:
    """One block per NON-success row: why liveness failed, or what the gate
    printed. Empty when every row succeeded, so a green run adds nothing to
    stderr."""
    blocks = []
    for r in results:
        if r.outcome.is_success:
            continue
        lines = [f"{r.spec.id}: {r.outcome.value}"]
        if r.liveness is not None:
            lines.append(f"  liveness ({MECHANISM[r.spec.lang]}): {r.liveness.detail}")
        if r.gate is not None:
            stage = "baseline gate" if r.liveness is None else "gate"
            status = "timed out" if r.gate.timed_out else f"exit {r.gate.exit_code}"
            lines.append(f"  {stage} {status}; last {GATE_TAIL_LINES} lines of output:")
            lines.extend(f"    {line}" for line in _gate_tail(r.gate.output).splitlines())
        blocks.append("\n".join(lines))
    return "\n".join(blocks)


def render_json(results: list[MutationResult]) -> str:
    payload = [
        {
            "id": r.spec.id,
            "lang": r.spec.lang.value,
            "path": r.spec.path,
            "expect": r.spec.expect.value,
            "note": r.spec.note,
            "outcome": r.outcome.value,
            "success": r.outcome.is_success,
            "live": None if r.liveness is None else r.liveness.live,
            "mechanism": None if r.liveness is None else MECHANISM[r.spec.lang],
            "liveness_detail": None if r.liveness is None else r.liveness.detail,
            "exit_code": None if r.gate is None else r.gate.exit_code,
            # Without this a `--json` consumer reading `exit_code` gets back
            # exactly the 124 ambiguity the markdown path removes.
            "timed_out": None if r.gate is None else r.gate.timed_out,
            "gate_output_tail": None if r.gate is None else _gate_tail(r.gate.output),
            "missing_reds": list(r.missing_reds),
        }
        for r in results
    ]
    return json.dumps(payload, indent=2)
