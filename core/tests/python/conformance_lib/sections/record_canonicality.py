"""Section RC -- record `unknown`-subtree canonicality at both nesting levels.

The record itself and each field carry an `unknown` bag, and §4.2's rules
apply identically at both. Testing only the outer level would miss the
level a v2 client is most likely to extend.
"""

from __future__ import annotations

from conformance_lib.codec.record import py_decode_record, py_encode_record
from conformance_lib.rejection import _REJECTION_EXCEPTIONS

def section_record_unknown_subtree_canonicality() -> tuple[bool, list[str]]:
    """`py_decode_record`'s ground truth is `record.rs`'s
    `unknown_subtree_tolerates_key_order_and_duplicates_but_not_encoding_at_both_levels`
    (#592): a record's forward-compat `unknown` bag -- at BOTH the record
    level (`Record::unknown`) and the per-field level (`RecordField::unknown`)
    -- must ACCEPT a subtree carrying a duplicate key or keys out of
    canonical order, and REJECT every encoding-level departure (indefinite
    length, non-shortest-form integer/length prefix). Mirrors
    `section_cbor_scanner_units`'s per-rule assertions but end to end
    through `py_decode_record`/`py_encode_record`, at the two nesting
    levels a `Record` actually has (the manifest has a third, the
    block/trash entry level, which is why `section_manifest_canonicality_kat`
    replays a 3-level corpus and this one does not need one).

    Built with the exact same splice technique as the Rust ground-truth
    test: start from a record encoded with one small canonical subtree
    (`{"a": 1}`) planted in `Record.unknown` and a distinct one
    (`{"b": 2}`) planted in a field's own `RecordField.unknown`, locate
    each subtree's unique byte span, and splice in one shape at a time.
    """
    import cbor2

    # `{"a": 1}` / `{"b": 2}` -- distinct subtrees, one per level, so the
    # byte-offset search below cannot confuse the two (mirrors
    # `record.rs`'s `RECORD_BASE` / `FIELD_BASE` constants).
    record_base = bytes([0xA1, 0x61, 0x61, 0x01])  # map(1){"a": 1}
    field_base = bytes([0xA1, 0x61, 0x62, 0x02])  # map(1){"b": 2}

    record_dict = {
        "record_uuid": b"\xab" * 16,
        "record_type": "login",
        "fields": {
            "username": {
                "value": "alice",
                "last_mod": 1,
                "device_uuid": b"\x01" * 16,
                "unknown": {"zzz_future_field": field_base},
            },
        },
        "created_at_ms": 1_714_060_800_000,
        "last_mod_ms": 1_714_060_800_001,
        "unknown": {"zzz_future": record_base},
    }
    baseline = py_encode_record(record_dict)

    issues: list[str] = []
    try:
        py_decode_record(baseline)
    except Exception as e:
        return False, [f"baseline fixture must decode: {e}"]

    def find_one(needle: bytes) -> int:
        hits = [
            i
            for i in range(len(baseline) - len(needle) + 1)
            if baseline[i : i + len(needle)] == needle
        ]
        if len(hits) != 1:
            raise AssertionError(
                f"needle {needle!r} occurs {len(hits)} times in the baseline "
                "fixture, expected exactly 1 -- the splice below would "
                "overwrite something else"
            )
        return hits[0]

    record_at = find_one(record_base)
    field_at = find_one(field_base)

    # One splice closure serves both sites only because both needles are the
    # same width. The Rust ground-truth twin asserts this
    # (`assert_eq!(RECORD_BASE.len(), FIELD_BASE.len())` in
    # `core/src/vault/record.rs`); assert it here too so the hardcoded width
    # below cannot drift from the needles it is meant to match (#595).
    assert len(record_base) == len(field_base), (
        "both needles must be the same width, or one splice closure cannot "
        "serve both sites"
    )
    needle_len = len(record_base)

    def splice(at: int, repl: bytes) -> bytes:
        return baseline[:at] + repl + baseline[at + needle_len :]

    # REJECTED: every encoding-level departure from the deterministic
    # profile, at either level's unknown subtree. `record_base` /
    # `field_base` are both 4 bytes, so every replacement below is spliced
    # over exactly that span regardless of which site it targets.
    reject_shapes: list[tuple[str, bytes]] = [
        ("indefinite-length map", bytes([0xBF, 0x61, 0x61, 0x01, 0xFF])),
        ("non-shortest-form integer", bytes([0xA1, 0x61, 0x61, 0x18, 0x01])),
        ("indefinite-length text string", bytes([0xA1, 0x61, 0x61, 0x7F, 0x61, 0x78, 0xFF])),
        ("indefinite-length byte string", bytes([0xA1, 0x61, 0x61, 0x5F, 0x41, 0xAA, 0xFF])),
        ("indefinite-length array", bytes([0xA1, 0x61, 0x61, 0x9F, 0x01, 0xFF])),
        ("non-shortest-form map length", bytes([0xB8, 0x01, 0x61, 0x61, 0x01])),
    ]
    # ACCEPTED: the two order-carrying shapes -- exactly the residual
    # crypto-design §6.2's rules 1/5 leave unenforced inside an unknown
    # subtree, and the whole point of #592.
    accept_shapes: list[tuple[str, bytes]] = [
        ("duplicate key", bytes([0xA2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02])),
        ("keys out of canonical order", bytes([0xA2, 0x62, 0x7A, 0x7A, 0x01, 0x61, 0x61, 0x02])),
    ]

    for level, at in [("record-level", record_at), ("field-level", field_at)]:
        for what, repl in reject_shapes:
            try:
                py_decode_record(splice(at, repl))
                issues.append(
                    f"{what} inside {level} unknown subtree must be REJECTED, was accepted"
                )
            except _REJECTION_EXCEPTIONS as e:
                # Narrow, and assert on CONTENT: this loop guards 12
                # assertions (6 shapes x 2 levels), and as a bare
                # `except Exception: pass` it proved only that
                # `py_decode_record` threw SOMETHING. Verified by
                # mutation: replacing every rejection with a `NameError`
                # left the section green (#595).
                if "rule" not in str(e) and "canonical" not in str(e):
                    issues.append(
                        f"{what} inside {level} unknown subtree was rejected, "
                        f"but not by a canonicality check: {e!r}"
                    )
        for what, repl in accept_shapes:
            try:
                py_decode_record(splice(at, repl))
            except Exception as e:  # noqa: BLE001 - reported, never swallowed
                # Broad is correct HERE: this arm reports rather than
                # classifies, so any exception is a finding either way.
                issues.append(
                    f"{what} inside {level} unknown subtree must still decode, "
                    f"got {type(e).__name__}: {e}"
                )

    # `cbor2.loads`, straight through with no span retention, is the naive
    # reader crypto-design §6.2 currently points an implementer at -- and
    # this section exists BECAUSE it diverges on the two ACCEPT rows above.
    # Positive control (#592): assert that divergence, so a corpus/fixture
    # change that accidentally stopped exercising the gap would show up
    # here as a control failure rather than a silently-vacuous pass.
    def naive_accepts(body: bytes) -> bool:
        # Narrowed to the exception types cbor2 and the comparison can
        # legitimately raise -- same fix as `section_manifest_canonicality_kat`'s
        # sibling helper and for the same reason (Finding C): a bare
        # `except Exception` would silently treat a `NameError`/
        # `AttributeError` programming error as "rejected" and satisfy the
        # divergence assertion below for the wrong reason.
        try:
            decoded = cbor2.loads(body)
            return cbor2.dumps(decoded, canonical=True) == body
        except (cbor2.CBORError, ValueError, TypeError):
            return False

    for level, at in [("record-level", record_at), ("field-level", field_at)]:
        for what, repl in accept_shapes:
            spliced = splice(at, repl)
            if naive_accepts(spliced):
                issues.append(
                    f"positive control failed: the naive cbor2.loads reader did "
                    f"NOT diverge on {what!r} inside {level} unknown subtree, so "
                    "this fixture cannot distinguish a byte-retaining reader "
                    "from a dict-based one there (#592)"
                )

    if issues:
        return False, issues
    return True, [
        f"PASS  record unknown-subtree canonicality: "
        f"{len(reject_shapes)} reject + {len(accept_shapes)} accept shapes "
        "at both the record and field levels"
    ]
