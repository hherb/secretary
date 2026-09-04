"""Section MUQ's WRITER half -- §4.2's repeated-value rules for the encoder.

Split out of `manifest_uniqueness_kat.py` in the #608 review, which pushed
that module past this repo's 500-line split threshold. This file defines no
`section*` function, so `completeness.py`'s shape-based discovery does not
see a driver here and Section REG stays green; it is listed in that module's
`_NON_DRIVER_MODULES` for the reader.

§4.2 binds writers as well as readers -- "writers MUST NOT emit them and
readers MUST reject them" -- and until #600 neither this package nor `core`
enforced the writer half. The reader rows are frozen fixture bytes; these
cases cannot be, because a body the writer must refuse is by construction a
body the writer cannot produce. They are driven off the control row's
decoded manifest instead.
"""

from __future__ import annotations

from typing import Callable

import copy

from conformance_lib.codec.array_uniqueness import first_repeated_value
from conformance_lib.codec.manifest_decode import py_decode_manifest
from conformance_lib.codec.manifest_encode import (
    ENCODER_REFUSAL_PREFIX,
    py_encode_manifest,
)
from conformance_lib.rejection import _REJECTION_EXCEPTIONS


# ---------------------------------------------------------------------------
# The WRITER half (#600)
# ---------------------------------------------------------------------------
#
# §4.2's repeated-value paragraph binds both directions -- "writers MUST NOT
# emit them and readers MUST reject them" -- and until #600 neither this
# package nor `core` enforced the writer half. The rows above pin the reader
# on frozen bytes; these pin the writer on the manifest those bytes decode
# to, which is the only way to state the rule at all (a body the writer must
# refuse is, by construction, a body the writer cannot produce for a
# fixture).
#
# Mirrors the Rust corpus's `mutate` / `expect_encode_err` columns exactly:
# the same five edits, applied to the decoded CONTROL manifest.


def _repeat_block_uuid(m: dict) -> None:
    m["blocks"][2]["block_uuid"] = m["blocks"][1]["block_uuid"]


def _repeat_trash_uuid(m: dict) -> None:
    m["trash"][1]["block_uuid"] = m["trash"][0]["block_uuid"]


def _repeat_vector_clock_device(m: dict) -> None:
    m["vector_clock"][2]["device_uuid"] = m["vector_clock"][1]["device_uuid"]


def _repeat_summary_device(m: dict) -> None:
    # `blocks[1]`, not `blocks[0]` -- same reasoning as the reader row.
    summary = m["blocks"][1]["vector_clock_summary"]
    summary[1]["device_uuid"] = summary[0]["device_uuid"]


def _repeat_summary_device_first_block(m: dict) -> None:
    # `blocks[0]`, the DUAL of the case above. Every summary fixture in
    # this corpus planted into `blocks[1]` to catch a writer scoped to the
    # first block; nothing caught a writer that SKIPS the first block. A
    # `[1:]` slice on the walk left this section printing its full PASS
    # line while checking no block at all for a one-block manifest
    # (#608 review). A two-sided property needs a fixture at each end.
    summary = m["blocks"][0]["vector_clock_summary"]
    summary[1]["device_uuid"] = summary[0]["device_uuid"]


def _repeat_recipient(m: dict) -> None:
    recipients = m["blocks"][1]["recipients"]
    recipients[2] = recipients[1]


# (where, edit, message fragment the refusal must carry -- or None if §4.2
# requires the writer to EMIT it).
_WRITER_CASES: tuple[tuple[str, Callable[[dict], None], str | None], ...] = (
    ("blocks[].block_uuid", _repeat_block_uuid, "blocks has a repeated block_uuid"),
    ("trash[].block_uuid", _repeat_trash_uuid, "trash has a repeated block_uuid"),
    (
        "vector_clock[].device_uuid",
        _repeat_vector_clock_device,
        "vector_clock has a repeated device_uuid",
    ),
    (
        "blocks[1].vector_clock_summary[].device_uuid",
        _repeat_summary_device,
        "blocks[1].vector_clock_summary has a repeated device_uuid",
    ),
    (
        "blocks[0].vector_clock_summary[].device_uuid",
        _repeat_summary_device_first_block,
        "blocks[0].vector_clock_summary has a repeated device_uuid",
    ),
    # §4.2's EXPLICIT exception, and the row that stops the four above from
    # being satisfied by a writer that refuses every repeat anywhere.
    ("blocks[1].recipients", _repeat_recipient, None),
)


def _shared_helper_issues() -> list[str]:
    """Pin `first_repeated_value`'s SORT, which no other check reaches.

    Both callers hand it an already-sorted list -- the reader has checked
    sortedness before calling, and the writer only ever sees
    `py_decode_manifest` output -- so replacing its `sorted(ids)` with
    `list(ids)` left this whole section green (#608 review, measured). The
    Rust twin has had `has_repeat_finds_a_repeat_the_input_order_separates`
    pinning exactly this since #600; the Python side got the shared helper
    without the test.

    `[a, b, a]` has no equal ADJACENT pair as given, so it separates a
    sort-then-scan from a bare adjacent scan. The second case is the
    control: without it a helper that reported a repeat unconditionally
    would satisfy the first.
    """
    a, b = b"\x01" * 16, b"\x02" * 16
    issues: list[str] = []
    if first_repeated_value([a, b, a]) != a:
        issues.append(
            "shared helper: first_repeated_value missed a repeat that the input "
            "order separates -- its `sorted()` is load-bearing and adjacency is "
            "exhaustive only after it"
        )
    if first_repeated_value([a, b]) is not None:
        issues.append(
            "shared helper: first_repeated_value reported a repeat in a distinct "
            "list, so the case above proves nothing"
        )
    return issues


def _writer_half_issues(control_body: bytes) -> list[str]:
    """Assert the ENCODER applies the same four rules, and the exception.

    Driven off the control row's bytes rather than off a hand-built dict so
    the manifest under test is the same one the reader rows replay -- a
    writer case built from its own fixture could drift from the corpus
    without anything noticing.
    """
    try:
        base = py_decode_manifest(control_body)
    except _REJECTION_EXCEPTIONS as e:
        return [
            f"writer half: the all-distinct control row does not decode "
            f"({type(e).__name__}: {e}), so no writer case can be built from it"
        ]

    issues: list[str] = []
    try:
        py_encode_manifest(base)
    except _REJECTION_EXCEPTIONS as e:
        issues.append(
            f"writer half: the all-distinct control must ENCODE, got "
            f"{type(e).__name__}: {e} -- every case below would then pass "
            "against a writer that refuses everything"
        )

    for where, edit, want in _WRITER_CASES:
        mutated = copy.deepcopy(base)
        try:
            edit(mutated)
        except (IndexError, KeyError, TypeError) as e:
            # The edits hard-index (`m["blocks"][2]`, `m["trash"][1]`, ...),
            # and `IndexError`/`TypeError` are NOT in `_REJECTION_EXCEPTIONS`
            # -- so before #608's review this line raised straight out of
            # `main()`, which does not guard `section.run()`. That is a
            # traceback with NO `FAIL:` line, and every section registered
            # after MUQ (RC, DET, REG) never runs. Fail-closed on the exit
            # code, fail-SILENT on the diagnosis.
            #
            # This is the same guard the reader half already carries for the
            # same reason (#599 review); the writer half was written outside
            # it.
            issues.append(
                f"writer half: the edit for {where} could not be applied to the "
                f"control manifest ({type(e).__name__}: {e}) -- the corpus's control "
                "row no longer has the shape these cases assume, so this case tested "
                "nothing"
            )
            continue
        if mutated == base:
            # The trap this repo keeps re-finding: a mutation that did not
            # apply is indistinguishable from a mutation nothing caught.
            issues.append(f"writer half: the edit for {where} planted nothing")
            continue
        try:
            py_encode_manifest(mutated)
            emitted, detail = True, ""
        except _REJECTION_EXCEPTIONS as e:
            emitted, detail = False, str(e)

        if want is None:
            if not emitted:
                issues.append(
                    f"writer half: a repeat in {where} is §4.2's documented "
                    f"exception, but the encoder refused it ({detail!r}) -- that "
                    "narrows the set of bodies a v1 writer may emit"
                )
        elif emitted:
            issues.append(
                f"writer half: the encoder EMITTED a body repeating {where}, which "
                "its own decoder rejects -- §4.2 binds writers as well as readers"
            )
        elif want not in detail or not detail.startswith(ENCODER_REFUSAL_PREFIX):
            issues.append(
                f"writer half: {where} was refused, but not by the encoder's own "
                f"repeated-value rule -- expected a message starting "
                f"{ENCODER_REFUSAL_PREFIX!r} and naming {want!r}, got {detail!r}"
            )
    return issues
