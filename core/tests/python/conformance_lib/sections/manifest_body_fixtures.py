"""Hand-built manifest-body byte fixtures shared by the guard sections.

These construct CBOR bytes directly rather than via the encoder, which is
the point: a guard that built its input with the encoder under test could
not express a body the encoder refuses to emit.
"""

from __future__ import annotations

from conformance_lib.canonical import encode_canonical_map_raw

def _dup_key_inner_map_bytes(key_name: str) -> bytes:
    """Raw CBOR bytes for a 2-entry map with `key_name` written TWICE.

    Tolerated by Rust anywhere inside a forward-compat unknown subtree
    (§4.2's unenforced rules 1/5, at every nesting level -- #585 fix round
    1, Finding 1), so splicing this in as an unknown field's VALUE must be
    ACCEPTED, not rejected, by `py_decode_manifest`.
    """
    import cbor2

    return (
        bytes([0xA2])  # RFC 8949 §3.1: major type 5 (map), 2 entries, short form.
        + cbor2.dumps(key_name)
        + cbor2.dumps(1, canonical=True)
        + cbor2.dumps(key_name)
        + cbor2.dumps(2, canonical=True)
    )


def _build_test_block_entry_bytes(
    extra_unknown: tuple[str, bytes] | None = None,
    dup_known: bool = False,
    vector_clock_summary_bytes: bytes | None = None,
    omit_field: str | None = None,
) -> bytes:
    """Raw CBOR bytes for one `blocks[i]` entry, for section MDN's fixtures.

    All 8 known fields use fixed literal test values (structural CBOR test
    data, not a cryptographic secret -- same convention as
    `section_manifest_body_duplicate_key_guard`'s fixture). `dup_known`
    appends a SECOND `suite_id` entry (a duplicate KNOWN key, which must be
    REJECTED); `extra_unknown`, when given, appends one more `(key, raw
    value bytes)` pair as a forward-compat entry-level unknown field;
    `vector_clock_summary_bytes`, when given, REPLACES the default
    well-formed `vector_clock_summary` value bytes (for #585 fix round 2,
    Finding 3's tampered-entry fixtures); `omit_field`, when given, drops
    that one known field entirely (for Finding 4's missing-required-field
    fixture). Built via `encode_canonical_map_raw` -- the same sort this
    repo's own `_encode_manifest_block_entry` re-encode uses -- so a
    fixture with no duplicate keys round-trips byte-identically regardless
    of the order these entries are listed in below.
    """
    import cbor2

    vcs_bytes = (
        vector_clock_summary_bytes
        if vector_clock_summary_bytes is not None
        else cbor2.dumps([{"device_uuid": b"\x44" * 16, "counter": 1}], canonical=True)
    )
    entries: list[tuple[str, bytes]] = [
        ("block_uuid", cbor2.dumps(b"\xaa" * 16, canonical=True)),
        ("block_name", cbor2.dumps("block-one", canonical=True)),
        ("fingerprint", cbor2.dumps(b"\xbb" * 32, canonical=True)),
        ("recipients", cbor2.dumps([b"\x22" * 16], canonical=True)),
        ("vector_clock_summary", vcs_bytes),
        ("suite_id", cbor2.dumps(1, canonical=True)),
        ("created_at_ms", cbor2.dumps(1000, canonical=True)),
        ("last_mod_ms", cbor2.dumps(1000, canonical=True)),
    ]
    if omit_field is not None:
        entries = [(k, v) for k, v in entries if k != omit_field]
    if dup_known:
        entries.append(("suite_id", cbor2.dumps(2, canonical=True)))  # duplicate KNOWN key
    if extra_unknown is not None:
        entries.append(extra_unknown)
    return encode_canonical_map_raw(entries)


def _build_test_trash_entry_bytes(
    extra_unknown: tuple[str, bytes] | None = None, dup_known: bool = False
) -> bytes:
    """Raw CBOR bytes for one `trash[i]` entry, for section MDN's fixtures.

    Only the 3 required `TrashEntry` fields are populated (`fingerprint` /
    `purged_at_ms` omitted, per §7/§7.2's optional-field semantics).
    `dup_known` / `extra_unknown` mirror `_build_test_block_entry_bytes`.
    """
    import cbor2

    entries: list[tuple[str, bytes]] = [
        ("block_uuid", cbor2.dumps(b"\xcc" * 16, canonical=True)),
        ("tombstoned_at_ms", cbor2.dumps(2000, canonical=True)),
        ("tombstoned_by", cbor2.dumps(b"\x44" * 16, canonical=True)),
    ]
    if dup_known:
        entries.append(("tombstoned_at_ms", cbor2.dumps(3000, canonical=True)))  # duplicate
    if extra_unknown is not None:
        entries.append(extra_unknown)
    return encode_canonical_map_raw(entries)


def _build_test_manifest_bytes(
    blocks_bytes: bytes,
    trash_bytes: bytes,
    kdf_params_bytes: bytes | None = None,
    vector_clock_bytes: bytes | None = None,
) -> bytes:
    """Full manifest-body bytes for section MDN/MSS's fixtures, given
    already-encoded `blocks`/`trash` array bytes, with the other 7 known
    top-level fields filled in as fixed literal test values (same values
    `section_manifest_body_duplicate_key_guard` uses). `kdf_params_bytes` /
    `vector_clock_bytes`, when given, REPLACE the default well-formed
    values (for #585 fix round 2, Finding 3's tampered-subshape fixtures).
    """
    import cbor2

    vault_uuid = b"\x11" * 16
    owner_uuid = b"\x22" * 16
    salt = b"\x33" * 32
    kdf_bytes = (
        kdf_params_bytes
        if kdf_params_bytes is not None
        else cbor2.dumps(
            {"memory_kib": 262144, "iterations": 3, "parallelism": 1, "salt": salt},
            canonical=True,
        )
    )
    vc_bytes = (
        vector_clock_bytes if vector_clock_bytes is not None else cbor2.dumps([], canonical=True)
    )
    entries: list[tuple[str, bytes]] = [
        ("manifest_version", cbor2.dumps(1, canonical=True)),
        ("vault_uuid", cbor2.dumps(vault_uuid, canonical=True)),
        ("format_version", cbor2.dumps(1, canonical=True)),
        ("suite_id", cbor2.dumps(1, canonical=True)),
        ("owner_user_uuid", cbor2.dumps(owner_uuid, canonical=True)),
        ("vector_clock", vc_bytes),
        ("blocks", blocks_bytes),
        ("trash", trash_bytes),
        ("kdf_params", kdf_bytes),
    ]
    return encode_canonical_map_raw(entries)
