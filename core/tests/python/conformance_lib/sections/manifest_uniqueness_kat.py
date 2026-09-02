"""Section MUQ -- `manifest_uniqueness_kat.json` §4.2 repeated-value replay.

Six rows against §4.2's repeated-value rules: four arrays in which a repeat
is forbidden, plus the `recipients` exception and an all-distinct control.
Replayed cross-language against the verdicts `decode_manifest` recorded.

Carries a NON-VACUITY CONTROL that is a direct property of the fixture
bytes rather than a second decoder: every rejecting row's array must be
SORTED and must CONTAIN a repeat, and the rejection MESSAGE must name the
repeated-value rule. Sortedness and distinctness are independent -- `[x, x]`
is sorted -- so a row that is sorted and repeating cannot be rejected by the
sort discipline; asserting the message is what rules out the ~30 OTHER ways
this decoder can reject a body (shape, required-key, outer canonicality, the
§4.3 step-4 re-encode). Without both halves, a corpus whose rows happened to
be out of order, or malformed in some unrelated way, would pass here against
a reader that implements no distinctness check at all -- which is exactly
the reader `py_decode_manifest` was until #594.
"""

from __future__ import annotations

from typing import Callable

from conformance_lib.codec.manifest_decode import py_decode_manifest
from conformance_lib.fixtures import load_json_fixture, manifest_uniqueness_kat_path
from conformance_lib.rejection import _REJECTION_EXCEPTIONS

# Where each rejecting row plants its repeat, as an extractor over the
# loosely-decoded body, plus the fragment its rejection message must carry.
# Keyed by row label so a renamed or dropped fixture row is a hard failure
# here rather than a silently unchecked one.
#
# The message fragments mirror `_check_sorted_and_distinct`'s own wording.
# Asserting on them is the practice section MAS already follows and states
# the reason for: a bare "it was rejected" credits the row to whichever
# check happened to fire first.
_REPEAT_POSITIONS: dict[str, tuple[str, Callable[[dict], list], str]] = {
    "blocks__duplicate_block_uuid": (
        "blocks[].block_uuid",
        lambda b: [e["block_uuid"] for e in b["blocks"]],
        "blocks has a repeated block_uuid",
    ),
    "trash__duplicate_block_uuid": (
        "trash[].block_uuid",
        lambda b: [e["block_uuid"] for e in b["trash"]],
        "trash has a repeated block_uuid",
    ),
    "vector_clock__duplicate_device_uuid": (
        "vector_clock[].device_uuid",
        lambda b: [e["device_uuid"] for e in b["vector_clock"]],
        "vector_clock has a repeated device_uuid",
    ),
    # NOTE the index: this row plants its repeat in the SECOND block, so a
    # reader that checks only `blocks[0].vector_clock_summary` diverges here.
    # It used to be `blocks[0]`, and wrapping the check in `if i == 0:` left
    # the whole suite green (#599 review).
    "vector_clock_summary__duplicate_device_uuid": (
        "blocks[1].vector_clock_summary[].device_uuid",
        lambda b: [e["device_uuid"] for e in b["blocks"][1]["vector_clock_summary"]],
        "blocks[1].vector_clock_summary has a repeated device_uuid",
    ),
}

# The ACCEPT rows, and what each must look like to be worth carrying. The
# `recipients` row must genuinely exercise §4.2's exception (sorted, with a
# repeat); the control must genuinely be repeat-free everywhere.
_RECIPIENTS_ROW = "recipients__duplicate_contact_uuid"
_CONTROL_ROW = "control__all_distinct"

# Which block the `recipients` row plants its repeat in -- same reasoning as
# the `vector_clock_summary` row above.
_RECIPIENTS_BLOCK = 1

_EXPECTED_LABELS = frozenset(_REPEAT_POSITIONS) | {_RECIPIENTS_ROW, _CONTROL_ROW}


def _all_arrays(body: dict) -> list[tuple[str, list]]:
    """Every array §4.2 names, across EVERY block -- for the control row.

    §4.2 constrains "**each** block's `recipients`" and "**each** block's
    `vector_clock_summary`", and the baseline carries three blocks, so a
    census that reads `blocks[0]` only leaves two thirds of the control's
    claim unchecked. It did exactly that until #599's review.
    """
    out: list[tuple[str, list]] = [
        ("vector_clock[].device_uuid", [e["device_uuid"] for e in body["vector_clock"]]),
        ("blocks[].block_uuid", [e["block_uuid"] for e in body["blocks"]]),
        ("trash[].block_uuid", [e["block_uuid"] for e in body["trash"]]),
    ]
    for i, blk in enumerate(body["blocks"]):
        out.append((f"blocks[{i}].recipients", list(blk["recipients"])))
        out.append(
            (
                f"blocks[{i}].vector_clock_summary[].device_uuid",
                [e["device_uuid"] for e in blk["vector_clock_summary"]],
            )
        )
    return out


def _has_repeat(ids: list) -> bool:
    """True if any two ADJACENT entries are equal.

    Adjacent-only is sufficient ONLY on a sorted list, where adjacency is
    the whole of the repeat question, and every caller below establishes
    sortedness first -- including the control row, whose branch checks it
    for exactly this reason. That last clause is not decoration: the
    control uses this function to assert the ABSENCE of a repeat, so on an
    unsorted list a non-adjacent repeat (`[a, b, a]`) would return `False`
    and the all-distinct floor -- the row that keeps the four rejecting
    rows from proving nothing -- would pass vacuously (#599 review).

    It also mirrors the check `py_decode_manifest` performs, so the control
    and the code under test are answering the same question about the same
    bytes.
    """
    return any(a == b for a, b in zip(ids, ids[1:]))


def section_manifest_uniqueness_kat() -> tuple[bool, list[str]]:
    """Replay `manifest_uniqueness_kat.json` -- §4.2's repeated-value rules.

    Three things are asserted, and the second and third are what keep the
    first from being vacuous:

    1. `py_decode_manifest` agrees with the recorded Rust verdict on all
       six rows. As with every corpus in this file, that is EVIDENCE for
       the "two conformant readers accept the same set" property, not a
       proof of it: what it establishes is agreement on these six bodies.
    2. Each of the four rejecting rows is SORTED at the position it plants
       its repeat, does contain that repeat, and is rejected by a message
       NAMING that repeat. Sortedness rules out the sort discipline as the
       cause; the message rules out every other check in the reader. A
       `_check_sorted_and_distinct` reduced to its sortedness half fails
       all three.
    3. The two accepting rows are what they claim: the `recipients` row
       carries a real repeat (so §4.2's exception is exercised rather than
       assumed), and the control carries none in any array of any block.

    §4.3 step 4's re-encode cannot see any of this. A body carrying
    `[x, x]` parses to `[x, x]` and re-encodes to `[x, x]` byte for byte,
    which is why these rules need a corpus of their own rather than falling
    out of the round-trip the way rules 2 and 3 do.
    """
    import cbor2

    path = manifest_uniqueness_kat_path()
    doc = load_json_fixture(path, "manifest_uniqueness_kat.json")
    rows = doc["rows"]
    issues: list[str] = []
    if not rows:
        return False, ["corpus is empty"]

    labels = {r["label"] for r in rows}
    if labels != _EXPECTED_LABELS:
        issues.append(
            f"corpus label set mismatch: missing {sorted(_EXPECTED_LABELS - labels)}, "
            f"unexpected {sorted(labels - _EXPECTED_LABELS)}"
        )

    n_accept = sum(1 for r in rows if r["expect_accept"])
    n_reject = len(rows) - n_accept
    if n_accept == 0:
        issues.append("corpus has no ACCEPT rows -- it would pass by rejecting everything")
    if n_reject == 0:
        issues.append("corpus has no REJECT rows -- it would pass by accepting everything")

    for row in rows:
        label, body = row["label"], bytes.fromhex(row["manifest_body_hex"])
        expected = row["expect_accept"]

        try:
            py_decode_manifest(body)
            strict, detail = True, ""
        except _REJECTION_EXCEPTIONS as e:
            # NARROW on purpose, for the reason section MCK states about its
            # own arm: 4 of these 6 rows expect a REJECT, so a bare
            # `except Exception` would let a NameError/AttributeError inside
            # `py_decode_manifest` satisfy them for the wrong reason.
            #
            # `KeyError` IS in that tuple, though, so this arm is narrower
            # than "no programming error can satisfy a REJECT row" -- see
            # `rejection.py`. That is why the message assertion below exists
            # rather than a bare accept/reject compare: a stray `KeyError`
            # renders as `"'somekey'"` and carries none of the fragments the
            # rejecting rows require.
            strict, detail = False, str(e)
        if strict != expected:
            issues.append(
                f"row {label!r}: strict reader accept={strict}, Rust recorded {expected}"
            )

        # The fixture's own shape, checked against what the row claims to
        # be. `cbor2.loads` is deliberate here and is NOT the reader under
        # test -- it is the loose parse used to look at the arrays.
        #
        # The extractors run INSIDE this guard. They used to sit after it,
        # so a body that parsed to a non-mapping -- `cbor2.loads(b"\x00")`
        # returns the int `0`, no exception -- raised an UNCAUGHT
        # `TypeError` from `0["blocks"]` one line later. That aborted the
        # whole run with a traceback instead of failing this section, and
        # the sections registered after MUQ never ran (#599 review).
        try:
            decoded = cbor2.loads(body)
            if not isinstance(decoded, dict):
                raise TypeError(f"manifest body decoded to {type(decoded).__name__}, not a map")
            if label in _REPEAT_POSITIONS:
                where, extract, want = _REPEAT_POSITIONS[label]
                ids = extract(decoded)
                if ids != sorted(ids):
                    issues.append(
                        f"row {label!r}: {where} is NOT sorted, so this row's rejection "
                        "could be the sort discipline rather than the repeated-value "
                        "rule -- the row proves nothing about distinctness"
                    )
                if not _has_repeat(ids):
                    issues.append(
                        f"row {label!r}: {where} carries no repeated value, so the row "
                        "does not exercise the rule it is named for"
                    )
                if want not in detail:
                    issues.append(
                        f"row {label!r}: rejected, but not by the repeated-value rule -- "
                        f"expected a message naming {want!r}, got {detail!r}"
                    )
            elif label == _RECIPIENTS_ROW:
                where = f"blocks[{_RECIPIENTS_BLOCK}].recipients"
                recips = list(decoded["blocks"][_RECIPIENTS_BLOCK]["recipients"])
                if recips != sorted(recips):
                    issues.append(f"row {label!r}: {where} is not sorted")
                if not _has_repeat(recips):
                    issues.append(
                        f"row {label!r}: {where} carries no repeated contact_uuid, so "
                        "§4.2's documented exception is asserted rather than exercised"
                    )
            elif label == _CONTROL_ROW:
                for where, ids in _all_arrays(decoded):
                    if ids != sorted(ids):
                        issues.append(
                            f"row {label!r}: {where} is not sorted, so the repeat-free "
                            "check below cannot rely on adjacency"
                        )
                    elif _has_repeat(ids):
                        issues.append(
                            f"row {label!r}: {where} carries a repeat, so it is not the "
                            "all-distinct baseline the accept floor relies on"
                        )
        except (
            cbor2.CBORError,
            ValueError,
            TypeError,
            KeyError,
            IndexError,
            # Deeply nested body; `wire/golden_vault_verify.py` catches this
            # explicitly for the same reason. Unreachable from a
            # generator-produced fixture, but an uncaught one aborts the
            # whole run rather than failing this section.
            RecursionError,
        ) as e:
            issues.append(
                f"row {label!r}: fixture body is not the shape this row claims "
                f"({type(e).__name__}: {e})"
            )
            continue

    if issues:
        return False, issues
    return True, [
        f"PASS  manifest uniqueness corpus: {len(rows)} rows replayed "
        f"({n_accept} accept / {n_reject} reject); all {len(_REPEAT_POSITIONS)} "
        "rejecting rows are sorted-with-a-repeat and rejected by a message naming "
        "the repeat, so neither the sort discipline nor any other check can "
        "account for them"
    ]
