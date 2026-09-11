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


def _live_cell(result: MutationResult) -> str:
    if result.liveness is None:
        return "not probed"
    return f"yes ({result.liveness.mechanism})" if result.liveness.live else "NO"


def _reds_cell(result: MutationResult) -> str:
    if result.missing_reds:
        return "missing: " + ", ".join(result.missing_reds)
    if result.spec.expect_red:
        return ", ".join(result.spec.expect_red)
    return "—"


def _describe(result: MutationResult) -> str:
    if result.spec.note:
        return result.spec.note
    return f"`{result.spec.old}` -> `{result.spec.new}`"


def render_markdown(results: list[MutationResult]) -> str:
    rows = [
        f"| {r.spec.id} | {_describe(r)} | {_live_cell(r)} "
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
