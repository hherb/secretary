"""Render results. Spec §7.

The table is emitted so a handoff pastes GENERATED evidence. Every mutation
table in every handoff before #644 was hand-transcribed from scrollback — an
unverified step between the measurement and the published claim, invisible to
review because the scrollback is gone by the time anyone reads the table.
"""

from __future__ import annotations

import json

from mutation_harness.types import MutationResult

_HEADER = "| # | Mutation | Live | Outcome | Reds |\n|---|---|---|---|---|"


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
    return f"yes ({_cell(result.liveness.mechanism)})"


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


def render_json(results: list[MutationResult]) -> str:
    payload = [
        {
            "id": r.spec.id,
            "lang": r.spec.lang.value,
            "path": r.spec.path,
            "expect": r.spec.expect,
            "note": r.spec.note,
            "outcome": r.outcome.value,
            "success": r.outcome.is_success,
            "live": None if r.liveness is None else r.liveness.live,
            "mechanism": None if r.liveness is None else r.liveness.mechanism,
            "liveness_detail": None if r.liveness is None else r.liveness.detail,
            "exit_code": None if r.gate is None else r.gate.exit_code,
            "missing_reds": list(r.missing_reds),
        }
        for r in results
    ]
    return json.dumps(payload, indent=2)
