"""Section CS -- span-recording CBOR scanner unit coverage (§4.2, #592).

Unit coverage for `conformance_lib.codec.scanner`, whose correctness every
forward-compat `unknown` subtree path depends on.
"""

from __future__ import annotations

from conformance_lib.codec.scanner import (
    NonCanonicalItem,
    _check_canonical_item,
    _scan_item,
    _scan_map_entries,
)

def section_cbor_scanner_units() -> tuple[bool, list[str]]:
    """Unit coverage for the span-recording CBOR scanner (§4.2 support).

    The scanner exists because `cbor2.loads` collapses duplicate map keys
    into a `dict` and therefore cannot reproduce them, while
    `docs/vault-format.md` §4.2 part (1) requires a reader to reproduce an
    unknown subtree's entry order AND its repeated entries. See #592.
    """
    import cbor2

    issues: list[str] = []

    # --- _scan_item consumes exactly one item, for every shape cbor2 emits
    for label, value in [
        ("uint", 1),
        ("large uint", 10**12),
        ("negative", -5000),
        ("bstr", b"\xaa" * 300),
        ("tstr", "hello" * 100),
        ("array", [1, [2, 3], "x"]),
        ("map", {"a": 1, "b": [1, 2]}),
        ("nested map", {"a": {"b": {"c": [1, 2, 3]}}}),
        ("simple values", [True, False, None]),
    ]:
        enc = cbor2.dumps(value)
        end = _scan_item(enc, 0)
        if end != len(enc):
            issues.append(f"_scan_item {label}: consumed {end} of {len(enc)} bytes")

    # --- indefinite-length forms SCAN (structure); canonicality is a
    # --- separate rule checked by _check_canonical_item below.
    for label, raw in [
        ("indefinite map", bytes([0xBF, 0x61, 0x61, 0x01, 0xFF])),
        ("indefinite array", bytes([0x9F, 0x01, 0x02, 0xFF])),
        ("indefinite tstr", bytes([0x7F, 0x61, 0x78, 0xFF])),
        ("indefinite bstr", bytes([0x5F, 0x41, 0xAA, 0xFF])),
    ]:
        end = _scan_item(raw, 0)
        if end != len(raw):
            issues.append(f"_scan_item {label}: consumed {end} of {len(raw)} bytes")

    # --- RFC 8949 §3.2: ai=31 (indefinite) is only valid for majors 2/3/4/5
    # --- (plus major 7, the break code). Major 0 with ai=31 is not a legal
    # --- head at all and must be REJECTED, not scanned as a bare 1-byte item.
    try:
        _scan_item(bytes([0x1F]), 0)
        issues.append("_scan_item major-0 ai=31 must be REJECTED, was accepted")
    except ValueError:
        pass

    # `NonCanonicalItem`'s base class is a cross-cutting contract, and
    # nothing tested it: `conformance_lib.rejection`'s allowlist and
    # `diff_replay.py`'s reject-vs-error split both key on `ValueError`.
    # Dropping the base aborts the whole run at this section with a raw
    # traceback and no `FAIL:` line, taking all 14 later sections with it --
    # MCK, MCC, MUQ, RC, DET and REG among them (#614 review).
    if not issubclass(NonCanonicalItem, ValueError):
        issues.append(
            "NonCanonicalItem must subclass ValueError -- conformance_lib.rejection's "
            "allowlist and diff_replay's reject/error split both key on it, so losing "
            "the base reclassifies every scanner rejection as a harness failure"
        )

    # --- THE point: duplicates and wire order survive the scan
    dup = bytes([0xA2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02])   # {"a":1,"a":2}
    entries, end = _scan_map_entries(dup, 0)
    if len(entries) != 2:
        issues.append(f"duplicate-key map: {len(entries)} entries, expected 2 (a dict gives 1)")
    if end != len(dup):
        issues.append(f"duplicate-key map: end {end}, expected {len(dup)}")

    noncanon = bytes([0xA2, 0x62, 0x7A, 0x7A, 0x01, 0x61, 0x61, 0x02])  # {"zz":1,"a":2}
    entries, _ = _scan_map_entries(noncanon, 0)
    keys = [noncanon[ks:ke] for (ks, ke), _ in entries]
    if keys != [b"\x62zz", b"\x61a"]:
        issues.append(f"wire order not preserved: {keys!r}")

    # --- _check_canonical_item: the §4.2 five-rule table, row by row.
    # Rules 1 and 5 are NOT enforced inside an unknown subtree; 2, 3, 4 are.
    for label, raw in [("rule 1 key order", noncanon), ("rule 5 duplicate key", dup)]:
        try:
            _check_canonical_item(raw, 0)
        except ValueError as e:
            issues.append(f"{label} must be ACCEPTED inside an unknown subtree, got: {e}")

    # Each row carries the §4.2-table rule number it must report, or
    # `None` for the four properties that carry no number. Before #614's
    # review this loop asserted only "some ValueError" while every label
    # already spelled its rule out, so the numbers were prose: demoting
    # `NonCanonicalItem(4, "CBOR tag")` to rule 2 left the ENTIRE suite at
    # exit 0 with all 26 sections green. Four of these shapes -- both
    # indefinite tstr/bstr/array rows and the non-shortest map length --
    # appear in no corpus, so this is the only place their rule number is
    # pinned at all.
    for label, raw, want_rule in [
        ("rule 2 indefinite map", bytes([0xBF, 0x61, 0x61, 0x01, 0xFF]), 2),
        (
            "rule 2 indefinite tstr",
            bytes([0xA1, 0x61, 0x61, 0x7F, 0x61, 0x78, 0xFF]),
            2,
        ),
        (
            "rule 2 indefinite bstr",
            bytes([0xA1, 0x61, 0x61, 0x5F, 0x41, 0xAA, 0xFF]),
            2,
        ),
        ("rule 2 indefinite array", bytes([0xA1, 0x61, 0x61, 0x9F, 0x01, 0xFF]), 2),
        ("rule 3 non-shortest int", bytes([0xA1, 0x61, 0x61, 0x18, 0x01]), 3),
        ("rule 3 non-shortest map length", bytes([0xB8, 0x01, 0x61, 0x61, 0x01]), 3),
        ("rule 4 float", cbor2.dumps({"a": 1.5}), 4),
        ("rule 4 tag", cbor2.dumps(cbor2.CBORTag(24, b"x")), 4),
        # 0x63 = major 3 (tstr), length 3 -- but only 2 bytes follow. An
        # oversized length claim must not silently return a bogus
        # out-of-buffer offset (the bug Finding 1 fixed).
        ("bounds-check truncated tstr", bytes([0x63, 0x61, 0x62]), None),
        # 0x61 = major 3 (tstr), length 1; 0xFF is never a valid standalone
        # UTF-8 byte (RFC 3629) -- regression pin for Finding A: this used
        # to reach `cbor2.loads`, which raised on it, before this scanner
        # took over the `unknown`-subtree path and stopped checking it.
        ("invalid-UTF-8 text string", bytes([0x61, 0xFF]), None),
        # 0xF8 0x14 = major 7 (simple value), ai=24 (one-byte argument
        # follows), argument byte 0x14 = 20 -- the extended-form, redundant
        # re-encoding of `false` (canonical form is the single byte 0xF4).
        # Regression pin for Finding B.
        ("non-canonical extended-form false (0xF8 0x14)", bytes([0xF8, 0x14]), None),
        # 0xF7 = major 7, ai=23 = "undefined". An ordinary CBOR item a
        # future writer could emit; Rust's major-7 value space is limited
        # to false/true/null. Pin for Finding B.
        ("major-7 undefined (0xF7)", bytes([0xF7]), None),
    ]:
        try:
            _check_canonical_item(raw, 0)
            issues.append(f"{label} must be REJECTED, was accepted")
        except NonCanonicalItem as e:
            if want_rule is None:
                issues.append(
                    f"{label} carries no §6.2/§4.2 rule number, but was raised as "
                    f"NonCanonicalItem(rule={e.rule}) -- only the five numbered-rule "
                    "checks may use that type"
                )
            elif e.rule != want_rule:
                issues.append(f"{label}: expected rule {want_rule}, got {e.rule}: {e}")
        except ValueError as e:
            if want_rule is not None:
                issues.append(
                    f"{label}: expected NonCanonicalItem(rule={want_rule}), got a "
                    f"non-numbered {type(e).__name__}: {e}"
                )

    # --- Positive controls for the major-7 restriction above: false/true/
    # --- null must each still be ACCEPTED, so the restriction added for
    # --- Finding B could not have been over-tightened without this catching it.
    for label, raw in [
        ("false (0xF4)", bytes([0xF4])),
        ("true (0xF5)", bytes([0xF5])),
        ("null (0xF6)", bytes([0xF6])),
    ]:
        try:
            _check_canonical_item(raw, 0)
        except ValueError as e:
            issues.append(f"{label} must be ACCEPTED, got: {e}")

    if issues:
        return False, issues
    return True, ["PASS  CBOR scanner unit coverage"]


# `_check_no_duplicate_keys` (a `pass`-bodied no-op asserting that the
# canonical re-encode check alone provides duplicate-key protection) was
# deleted here (#592). Every sentence in its docstring was true and the
# conclusion was still wrong for an `unknown` subtree: collapse-then-mismatch
# is a REJECTION mechanism, while §4.2 requires ACCEPTANCE plus verbatim
# reproduction of a duplicate key inside such a subtree. Its two call sites
# (`py_decode_record`, `py_decode_contact_card`) relied on nothing it did --
# removing the call changes no behaviour in either decoder. The actual
# duplicate-key protection now comes from two different places depending on
# the decoder: `py_decode_record`'s span-list `seen`-set checks (this file,
# above) reject a duplicate KNOWN key at every level that decoder interprets
# structurally, while `py_decode_contact_card` (which has no `unknown` bag at
# all -- it rejects every unrecognised key outright) is still protected by
# its own re-encode-and-compare, exactly as the deleted docstring argued --
# correctly, in that one decoder's case.
