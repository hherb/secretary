"""Sections MD, MDN, MRK and MERF -- manifest-body SCHEMA strictness.

Duplicate keys in nested maps, nested block/trash unknown bags, all nine
top-level required keys, and per-entry required fields.
"""

from __future__ import annotations

from typing import Any

from conformance_lib.codec.manifest_decode import py_decode_manifest
from conformance_lib.codec.manifest_encode import _encode_array_header, py_encode_manifest
from conformance_lib.codec.manifest_schema import MANIFEST_REQUIRED_KEYS
from conformance_lib.sections.manifest_body_fixtures import _build_test_block_entry_bytes, _build_test_manifest_bytes, _build_test_trash_entry_bytes, _dup_key_inner_map_bytes

def section_manifest_body_duplicate_key_guard() -> tuple[bool, list[str]]:
    """Pin the pre-flight amendment to `py_decode_manifest` (progress.md
    Ruling 1, #585): a duplicate key inside a NESTED KNOWN map -- a block
    entry, a trash entry, `kdf_params`, or a vector-clock entry -- must be
    REJECTED, not silently collapsed by `cbor2.loads` and accepted. Without
    this row the amendment's `py_encode_manifest(out) != data` re-encode
    check inside `py_decode_manifest` is unpinned: the golden vault has no
    duplicate keys anywhere, so section 2 alone cannot exercise it.
    """
    import cbor2

    issues: list[str] = []

    vault_uuid = b"\x11" * 16
    owner_uuid = b"\x22" * 16
    salt = b"\x33" * 32

    top: dict[str, Any] = {
        "manifest_version": 1,
        "vault_uuid": vault_uuid,
        "format_version": 1,
        "suite_id": 1,
        "owner_user_uuid": owner_uuid,
        "vector_clock": [],
        "blocks": [],
        "trash": [],
        "kdf_params": {
            "memory_kib": 262144,
            "iterations": 3,
            "parallelism": 1,
            "salt": salt,
        },
    }
    good = cbor2.dumps(top, canonical=True)

    # Positive control: a well-formed manifest body decodes and round-trips
    # byte-identically, so the negative control below is known to be
    # testing the duplicate key and nothing else.
    try:
        decoded = py_decode_manifest(good)
        if py_encode_manifest(decoded) != good:
            issues.append(
                "manifest body fixture: well-formed body did not round-trip "
                "byte-identically (positive control failed)"
            )
    except ValueError as e:
        issues.append(f"manifest body fixture: well-formed body was REJECTED: {e}")

    # Hand-build a `kdf_params` sub-map with its "iterations" key written
    # TWICE -- the exact #573 divergence: `cbor2.loads` collapses the wire
    # entry list [memory_kib, iterations, iterations, parallelism, salt]
    # (5 entries) into a 4-key dict, so a decoder that never re-encodes
    # would silently ACCEPT this. Key order here need not be canonical --
    # the point under test is the ENTRY COUNT collapse, and
    # `py_encode_manifest` re-sorts on the way back out regardless.
    kdf_dup_pairs = [
        (cbor2.dumps("memory_kib"), cbor2.dumps(262144, canonical=True)),
        (cbor2.dumps("iterations"), cbor2.dumps(3, canonical=True)),
        (cbor2.dumps("iterations"), cbor2.dumps(3, canonical=True)),  # duplicate
        (cbor2.dumps("parallelism"), cbor2.dumps(1, canonical=True)),
        (cbor2.dumps("salt"), cbor2.dumps(salt, canonical=True)),
    ]
    n = len(kdf_dup_pairs)
    assert n < 24  # RFC 8949 §3.1: major type 5 (map), short-form count.
    kdf_dup_bytes = bytearray([0xA0 | n])
    for k, v in kdf_dup_pairs:
        kdf_dup_bytes += k
        kdf_dup_bytes += v

    good_kdf_bytes = cbor2.dumps(top["kdf_params"], canonical=True)
    if good.count(good_kdf_bytes) != 1:
        issues.append(
            "manifest body fixture: kdf_params splice point is not unique "
            "in the well-formed body"
        )
    else:
        idx = good.find(good_kdf_bytes)
        tampered = good[:idx] + bytes(kdf_dup_bytes) + good[idx + len(good_kdf_bytes):]
        try:
            py_decode_manifest(tampered)
            issues.append(
                "duplicate key inside a nested KNOWN map "
                "(kdf_params.iterations, written twice) was ACCEPTED -- "
                "must be REJECTED to match decode_manifest's #573 "
                "DuplicateKey guards (progress.md Ruling 1)"
            )
        except ValueError:
            pass  # expected: the §4.3 step-4 re-encode compare rejects it

    if issues:
        return False, issues
    return True, ["PASS  manifest body duplicate-key-in-nested-map guard"]


def section_manifest_body_nested_entry_guard() -> tuple[bool, list[str]]:
    """Pin the #585 fix round 1, Finding 1 fix: byte retention must reach
    ONE nesting level deeper than the design originally scoped it to.

    `BlockEntry` and `TrashEntry` each carry their OWN forward-compat
    `unknown` bag (`manifest/types.rs`); the pre-fix `py_decode_manifest`
    handled `blocks`/`trash` wholesale through `cbor2.loads`, so a
    duplicate key inside a BLOCK- or TRASH-entry's own unknown subtree was
    silently collapsed and then REJECTED by the top-level §4.3 re-encode
    check -- the opposite verdict to Rust, which tolerates it (§4.2's
    unenforced rules 1/5 apply at every nesting level, not only the top
    one). Four rows:

    1. Positive control: block + trash entries each carrying a
       WELL-FORMED (non-duplicate) unknown field round-trip byte-identically.
    2. A duplicate key inside a BLOCK-entry unknown subtree must be
       ACCEPTED.
    3. A duplicate key inside a TRASH-entry unknown subtree must be
       ACCEPTED.
    4. A duplicate KNOWN key (`suite_id` written twice) within a block
       entry must still be REJECTED.
    """
    import cbor2

    issues: list[str] = []

    # --- Row 1: positive control -- well-formed unknown fields at both
    # nesting levels round-trip byte-identically.
    block_ok = _build_test_block_entry_bytes(
        extra_unknown=("future_field", cbor2.dumps({"a": 1, "b": 2}, canonical=True))
    )
    trash_ok = _build_test_trash_entry_bytes(
        extra_unknown=("future_field2", cbor2.dumps({"c": 3}, canonical=True))
    )
    good = _build_test_manifest_bytes(
        _encode_array_header(1) + block_ok, _encode_array_header(1) + trash_ok
    )
    try:
        decoded = py_decode_manifest(good)
        if py_encode_manifest(decoded) != good:
            issues.append(
                "manifest body fixture: well-formed per-entry unknown "
                "fields did not round-trip byte-identically (positive "
                "control failed)"
            )
    except ValueError as e:
        issues.append(
            f"manifest body fixture: well-formed per-entry unknown fields "
            f"were REJECTED: {e}"
        )

    # --- Row 2: duplicate key inside a BLOCK-entry unknown subtree ->
    # must be ACCEPTED.
    block_dup_unknown = _build_test_block_entry_bytes(
        extra_unknown=("future_field", _dup_key_inner_map_bytes("dup"))
    )
    trash_plain = _build_test_trash_entry_bytes()
    tampered_block = _build_test_manifest_bytes(
        _encode_array_header(1) + block_dup_unknown, _encode_array_header(1) + trash_plain
    )
    try:
        py_decode_manifest(tampered_block)
    except ValueError as e:
        issues.append(
            "duplicate key inside a BLOCK-entry unknown subtree was "
            f"REJECTED -- must be ACCEPTED (Rust tolerates it): {e}"
        )

    # --- Row 3: duplicate key inside a TRASH-entry unknown subtree ->
    # must be ACCEPTED.
    block_plain = _build_test_block_entry_bytes()
    trash_dup_unknown = _build_test_trash_entry_bytes(
        extra_unknown=("future_field2", _dup_key_inner_map_bytes("dup2"))
    )
    tampered_trash = _build_test_manifest_bytes(
        _encode_array_header(1) + block_plain, _encode_array_header(1) + trash_dup_unknown
    )
    try:
        py_decode_manifest(tampered_trash)
    except ValueError as e:
        issues.append(
            "duplicate key inside a TRASH-entry unknown subtree was "
            f"REJECTED -- must be ACCEPTED (Rust tolerates it): {e}"
        )

    # --- Row 4: duplicate KNOWN key (`suite_id` twice) within a block
    # entry -> must be REJECTED.
    block_dup_known = _build_test_block_entry_bytes(dup_known=True)
    tampered_known = _build_test_manifest_bytes(
        _encode_array_header(1) + block_dup_known, _encode_array_header(1) + trash_plain
    )
    try:
        py_decode_manifest(tampered_known)
        issues.append(
            "duplicate KNOWN key (suite_id, written twice) within a "
            "block entry was ACCEPTED -- must be REJECTED to match "
            "parse_block_entry's #573 DuplicateKey guard"
        )
    except ValueError:
        pass  # expected

    if issues:
        return False, issues
    return True, ["PASS  manifest body nested block/trash unknown-bag guard"]


def section_manifest_body_required_keys_guard() -> tuple[bool, list[str]]:
    """Pin the #585 fix round 1, Finding 2 fix: all NINE known top-level
    manifest body keys are required, matching `manifest/types.rs::Manifest`
    (no `Option` among them) -- not just the three (`manifest_version`,
    `vault_uuid`, `owner_user_uuid`) the pre-fix decoder hard-required.
    The §4.3 step-4 re-encode-and-compare does NOT catch a missing key on
    its own: a body simply missing a key re-encodes to itself byte for
    byte, so this needs its own row per previously-unchecked key.
    """
    import cbor2

    issues: list[str] = []

    vault_uuid = b"\x11" * 16
    owner_uuid = b"\x22" * 16
    salt = b"\x33" * 32
    full: dict[str, Any] = {
        "manifest_version": 1,
        "vault_uuid": vault_uuid,
        "format_version": 1,
        "suite_id": 1,
        "owner_user_uuid": owner_uuid,
        "vector_clock": [],
        "blocks": [],
        "trash": [],
        "kdf_params": {
            "memory_kib": 262144,
            "iterations": 3,
            "parallelism": 1,
            "salt": salt,
        },
    }

    # Positive control: the full 9-key body decodes fine.
    good = cbor2.dumps(full, canonical=True)
    try:
        py_decode_manifest(good)
    except (ValueError, KeyError) as e:
        issues.append(f"manifest body fixture: full 9-key body was REJECTED: {e}")

    # ALL 9 keys, not just the 6 the pre-fix decoder failed to hard-require:
    # `Manifest` has no `Option` among them, so dropping any one must be a
    # rejection. Scoping the loop to the 6 was a point-in-time framing that
    # left the other 3 covered by nothing (#595).
    for missing in sorted(MANIFEST_REQUIRED_KEYS):
        partial = {k: v for k, v in full.items() if k != missing}
        body = cbor2.dumps(partial, canonical=True)
        try:
            py_decode_manifest(body)
            issues.append(
                f"manifest body missing required key {missing!r} was "
                "ACCEPTED -- must be REJECTED (Manifest has no Option "
                "among its 9 known fields)"
            )
        except ValueError as e:
            # Assert on message CONTENT, not just type: every guard in this
            # file raises `ValueError`, so a bare type check would be
            # satisfied by an unrelated rejection two checks further on and
            # this loop would pass without ever exercising the presence test.
            if "missing required field" not in str(e) or missing not in str(e):
                issues.append(
                    f"manifest body missing required key {missing!r} was "
                    f"rejected, but not by the presence check: {e}"
                )

    if issues:
        return False, issues
    return True, ["PASS  manifest body required-keys guard: all 9 top-level keys checked"]


def section_manifest_body_entry_required_fields_guard() -> tuple[bool, list[str]]:
    """Pin the #585 fix round 2, Finding 4 fix: `_decode_manifest_entry_map`
    now validates that every `BlockEntry`/`TrashEntry` required field is
    present, raising `ValueError` (not `KeyError`) naming the missing
    field. Before this fix, a block entry missing e.g. `block_uuid`
    surfaced only as a raw, uncaught `KeyError` -- verified by execution
    (mutation-verified below) to come from `_check_sorted`'s `r[key]`
    indexing inside `py_decode_manifest`'s own array-sort-discipline loop,
    which runs BEFORE the final re-encode-and-compare and so is the
    earliest crash site, not (as an earlier draft of this comment
    guessed) `_encode_manifest_block_entry`'s dict indexing during that
    later re-encode -- both would crash the same way if reached, but only
    the former is actually reached first. Caught at the
    `verify_block_and_manifest` call site (which catches both
    `ValueError` and `KeyError`), but NOT by this module's own
    `except ValueError` guard sections, which crash instead of reporting a
    clean FAIL.
    """
    issues: list[str] = []

    empty_trash = _encode_array_header(0)

    # Positive control: a complete block entry is accepted (proves the
    # omission below, not some unrelated fixture bug, is what triggers
    # the rejection).
    block_full = _build_test_block_entry_bytes()
    good = _build_test_manifest_bytes(_encode_array_header(1) + block_full, empty_trash)
    try:
        py_decode_manifest(good)
    except ValueError as e:
        issues.append(f"manifest body fixture: complete block entry was REJECTED: {e}")

    # A block entry missing a required field ("block_uuid") -> REJECTED
    # with ValueError, caught cleanly by this narrow `except ValueError`
    # (no broader except here on purpose: if a regression reintroduced the
    # raw KeyError, this block would NOT catch it and the test would crash
    # loudly rather than silently pass).
    block_missing = _build_test_block_entry_bytes(omit_field="block_uuid")
    tampered = _build_test_manifest_bytes(_encode_array_header(1) + block_missing, empty_trash)
    try:
        py_decode_manifest(tampered)
        issues.append(
            "a block entry missing its required 'block_uuid' field was "
            "ACCEPTED -- must be REJECTED (BlockEntry has no Option field)"
        )
    except ValueError as e:
        if "block_uuid" not in str(e):
            issues.append(
                f"block entry missing-field rejection did not name the "
                f"field: {e}"
            )

    if issues:
        return False, issues
    return True, ["PASS  manifest body entry required-fields guard"]
