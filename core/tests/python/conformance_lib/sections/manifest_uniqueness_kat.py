"""Section MUQ -- `manifest_uniqueness_kat.json` §4.2 repeated-value replay.

Six rows against §4.2's repeated-value rules: four arrays in which a repeat
is forbidden, plus the `recipients` exception and an all-distinct control.
Replayed cross-language against the verdicts `decode_manifest` recorded.

Carries a NON-VACUITY CONTROL that is a direct property of the fixture
bytes rather than a second decoder: every rejecting row's array must be
SORTED and must CONTAIN a repeat. Sortedness and distinctness are
independent -- `[x, x]` is sorted -- so a row that is sorted and repeating
can only be rejected by a distinctness check. Without that, a corpus whose
rows happened to be out of order would pass here against a reader that
implements the sort disciplines and nothing else, which is exactly the
reader `py_decode_manifest` was until #594.
"""

from __future__ import annotations

from typing import Callable

from conformance_lib.codec.manifest_decode import py_decode_manifest
from conformance_lib.fixtures import load_json_fixture, manifest_uniqueness_kat_path
from conformance_lib.rejection import _REJECTION_EXCEPTIONS

# Where each rejecting row plants its repeat, as an extractor over the
# loosely-decoded body. Keyed by row label so a renamed or dropped fixture
# row is a hard failure here rather than a silently unchecked one.
_REPEAT_POSITIONS: dict[str, tuple[str, Callable[[dict], list]]] = {
    "blocks__duplicate_block_uuid": (
        "blocks[].block_uuid",
        lambda b: [e["block_uuid"] for e in b["blocks"]],
    ),
    "trash__duplicate_block_uuid": (
        "trash[].block_uuid",
        lambda b: [e["block_uuid"] for e in b["trash"]],
    ),
    "vector_clock__duplicate_device_uuid": (
        "vector_clock[].device_uuid",
        lambda b: [e["device_uuid"] for e in b["vector_clock"]],
    ),
    "vector_clock_summary__duplicate_device_uuid": (
        "blocks[0].vector_clock_summary[].device_uuid",
        lambda b: [e["device_uuid"] for e in b["blocks"][0]["vector_clock_summary"]],
    ),
}

# The ACCEPT rows, and what each must look like to be worth carrying. The
# `recipients` row must genuinely exercise §4.2's exception (sorted, with a
# repeat); the control must genuinely be repeat-free everywhere.
_RECIPIENTS_ROW = "recipients__duplicate_contact_uuid"
_CONTROL_ROW = "control__all_distinct"

# Every array §4.2 names, for the control row's repeat-free assertion.
_ALL_ARRAYS: dict[str, Callable[[dict], list]] = {
    "vector_clock[].device_uuid": lambda b: [e["device_uuid"] for e in b["vector_clock"]],
    "blocks[].block_uuid": lambda b: [e["block_uuid"] for e in b["blocks"]],
    "trash[].block_uuid": lambda b: [e["block_uuid"] for e in b["trash"]],
    "blocks[0].recipients": lambda b: list(b["blocks"][0]["recipients"]),
    "blocks[0].vector_clock_summary[].device_uuid": (
        lambda b: [e["device_uuid"] for e in b["blocks"][0]["vector_clock_summary"]]
    ),
}

_EXPECTED_LABELS = frozenset(_REPEAT_POSITIONS) | {_RECIPIENTS_ROW, _CONTROL_ROW}


def _has_repeat(ids: list) -> bool:
    """True if any two ADJACENT entries are equal.

    Adjacent-only is sufficient here and deliberate: every caller has
    already established the list is sorted, and on a sorted list adjacency
    is the whole of the repeat question. It also mirrors the check
    `py_decode_manifest` performs, so the control and the code under test
    are answering the same question about the same bytes.
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
       its repeat, and does contain that repeat. A rejection could
       otherwise be credited to the sort discipline, leaving the
       distinctness check untested -- and a `_check_sorted_and_distinct`
       reduced to its sortedness half would still pass.
    3. The two accepting rows are what they claim: the `recipients` row
       carries a real repeat (so §4.2's exception is exercised rather than
       assumed), and the control carries none in any of the five arrays.

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
            strict = True
        except _REJECTION_EXCEPTIONS:
            # NARROW on purpose, for the reason section MCK states about its
            # own arm: 4 of these 6 rows expect a REJECT, so a bare
            # `except Exception` would let a NameError/AttributeError inside
            # `py_decode_manifest` satisfy them for the wrong reason.
            strict = False
        if strict != expected:
            issues.append(
                f"row {label!r}: strict reader accept={strict}, Rust recorded {expected}"
            )

        # The fixture's own shape, checked against what the row claims to
        # be. `cbor2.loads` is deliberate here and is NOT the reader under
        # test -- it is the loose parse used to look at the arrays.
        try:
            decoded = cbor2.loads(body)
        except (cbor2.CBORError, ValueError, TypeError) as e:
            issues.append(f"row {label!r}: fixture body is not loosely parseable: {e}")
            continue

        if label in _REPEAT_POSITIONS:
            where, extract = _REPEAT_POSITIONS[label]
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
        elif label == _RECIPIENTS_ROW:
            recips = list(decoded["blocks"][0]["recipients"])
            if recips != sorted(recips):
                issues.append(f"row {label!r}: blocks[0].recipients is not sorted")
            if not _has_repeat(recips):
                issues.append(
                    f"row {label!r}: blocks[0].recipients carries no repeated "
                    "contact_uuid, so §4.2's documented exception is asserted "
                    "rather than exercised"
                )
        elif label == _CONTROL_ROW:
            for where, extract in _ALL_ARRAYS.items():
                ids = extract(decoded)
                if _has_repeat(ids):
                    issues.append(
                        f"row {label!r}: {where} carries a repeat, so it is not the "
                        "all-distinct baseline the accept floor relies on"
                    )

    if issues:
        return False, issues
    return True, [
        f"PASS  manifest uniqueness corpus: {len(rows)} rows replayed "
        f"({n_accept} accept / {n_reject} reject); all {len(_REPEAT_POSITIONS)} "
        "rejecting rows are sorted-with-a-repeat, so only a distinctness check "
        "can reject them"
    ]
