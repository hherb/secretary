"""Sections MSS and MSH -- manifest-body SHAPE strictness.

Strict sub-shapes for `kdf_params` and `vector_clock`, and the known-field
type/range/version checks. MSH is the section added by #595 after
`py_decode_manifest` was found fail-OPEN on every known scalar field.
"""

from __future__ import annotations

from conformance_lib.fixtures import manifest_body_seed


from conformance_lib.canonical import encode_canonical_map_raw
from conformance_lib.codec.manifest_decode import py_decode_manifest
from conformance_lib.codec.manifest_encode import _encode_array_header, py_encode_manifest
from conformance_lib.sections.manifest_body_fixtures import _build_test_block_entry_bytes, _build_test_manifest_bytes

def section_manifest_body_strict_subshapes_guard() -> tuple[bool, list[str]]:
    """Pin the #585 fix round 2, Finding 3 fix: `kdf_params`, `vector_clock`
    entries, and `vector_clock_summary` entries each have a FIXED shape in
    Rust with NO forward-compat `unknown` bag -- `parse_kdf_params` and
    `parse_vector_clock_entry` (`manifest/decode/entries.rs`) each end in a
    catch-all match arm that REJECTS any key outside their known set as
    `WrongType`. The pre-fix Python decoder routed all three through
    blanket `cbor2.loads`/`cbor2.dumps`, silently accepting and
    round-tripping an extra key where Rust rejects it -- the OPPOSITE
    polarity to Finding 1 (there an unrecognised key is retained and
    accepted; here it must be rejected), because `KdfParamsRef` and
    `VectorClockEntry` have no `unknown` bag at all, unlike `BlockEntry`/
    `TrashEntry`. Four rows:

    1. Positive control: a valid, complete `kdf_params` (and empty
       `blocks`/`trash`/`vector_clock`) is ACCEPTED and round-trips
       byte-identically.
    2. An extra unrecognised key inside `kdf_params` must be REJECTED.
    3. An extra unrecognised key inside a `vector_clock` entry must be
       REJECTED.
    4. An extra unrecognised key inside a `vector_clock_summary` entry
       (nested inside a block entry) must be REJECTED.
    """
    import cbor2

    issues: list[str] = []

    empty_blocks = _encode_array_header(0)
    empty_trash = _encode_array_header(0)

    # --- Row 1: positive control.
    good = _build_test_manifest_bytes(empty_blocks, empty_trash)
    try:
        decoded = py_decode_manifest(good)
        if py_encode_manifest(decoded) != good:
            issues.append(
                "manifest body fixture: valid kdf_params did not "
                "round-trip byte-identically (positive control failed)"
            )
    except ValueError as e:
        issues.append(f"manifest body fixture: valid kdf_params was REJECTED: {e}")

    # --- Row 2: extra unrecognised key inside kdf_params -> REJECTED.
    salt = b"\x33" * 32
    kdf_extra = encode_canonical_map_raw([
        ("memory_kib", cbor2.dumps(262144, canonical=True)),
        ("iterations", cbor2.dumps(3, canonical=True)),
        ("parallelism", cbor2.dumps(1, canonical=True)),
        ("salt", cbor2.dumps(salt, canonical=True)),
        ("extra_field", cbor2.dumps("nope", canonical=True)),
    ])
    tampered_kdf = _build_test_manifest_bytes(
        empty_blocks, empty_trash, kdf_params_bytes=kdf_extra
    )
    try:
        py_decode_manifest(tampered_kdf)
        issues.append(
            "kdf_params with an unrecognised extra key was ACCEPTED -- "
            "must be REJECTED (KdfParamsRef has no unknown bag)"
        )
    except ValueError:
        pass  # expected

    # --- Row 3: extra unrecognised key inside a vector_clock entry ->
    # REJECTED.
    vc_entry_extra = encode_canonical_map_raw([
        ("device_uuid", cbor2.dumps(b"\x44" * 16, canonical=True)),
        ("counter", cbor2.dumps(1, canonical=True)),
        ("extra_field", cbor2.dumps("nope", canonical=True)),
    ])
    tampered_vc = _build_test_manifest_bytes(
        empty_blocks,
        empty_trash,
        vector_clock_bytes=_encode_array_header(1) + vc_entry_extra,
    )
    try:
        py_decode_manifest(tampered_vc)
        issues.append(
            "a vector_clock entry with an unrecognised extra key was "
            "ACCEPTED -- must be REJECTED (VectorClockEntry has no "
            "unknown bag)"
        )
    except ValueError:
        pass  # expected

    # --- Row 4: extra unrecognised key inside a vector_clock_summary
    # entry (nested inside a block entry) -> REJECTED.
    vcs_entry_extra = encode_canonical_map_raw([
        ("device_uuid", cbor2.dumps(b"\x44" * 16, canonical=True)),
        ("counter", cbor2.dumps(1, canonical=True)),
        ("extra_field", cbor2.dumps("nope", canonical=True)),
    ])
    block_bad_vcs = _build_test_block_entry_bytes(
        vector_clock_summary_bytes=_encode_array_header(1) + vcs_entry_extra
    )
    tampered_vcs = _build_test_manifest_bytes(
        _encode_array_header(1) + block_bad_vcs, empty_trash
    )
    try:
        py_decode_manifest(tampered_vcs)
        issues.append(
            "a vector_clock_summary entry with an unrecognised extra key "
            "was ACCEPTED -- must be REJECTED (VectorClockEntry has no "
            "unknown bag, regardless of which array it appears in)"
        )
    except ValueError:
        pass  # expected

    if issues:
        return False, issues
    return True, ["PASS  manifest body strict-subshape guard"]


def section_manifest_body_shape_guard() -> tuple[bool, list[str]]:
    """Pin the #595 fix: `py_decode_manifest` type-, range- and
    version-checks every KNOWN field, so it does not ACCEPT bodies
    `decode_manifest` REJECTS.

    Before this, the decoder pulled the known scalars out with a bare
    `cbor2.loads` and never inspected them. `manifest_version = 999`, a
    text `manifest_version`, a 5-byte `vault_uuid` and a 3-byte salt all
    decoded cleanly here and are all rejected by Rust -- a fail-OPEN
    divergence in a file whose whole purpose is proving `docs/` alone is
    sufficient to build a CONFORMANT reader.

    Nothing else in this file can see this class, which is why it needs its
    own section: the §4.3 step-4 re-encode compares BYTES and every row
    below re-encodes to itself, and the 21-row canonicality corpus mutates
    only `unknown` subtrees. Each row asserts on message CONTENT as well as
    on rejection, so a row cannot be satisfied by an unrelated `ValueError`
    raised further down the decoder.
    """
    import cbor2

    issues: list[str] = []
    seed = manifest_body_seed("block__control_canonical.bin")
    if not seed.is_file():
        return False, [f"fixture missing: {seed}"]
    base = seed.read_bytes()

    # Positive control: the unmutated body must still decode. Without it a
    # decoder that rejected EVERYTHING would satisfy every row below.
    try:
        py_decode_manifest(base)
    except Exception as e:  # noqa: BLE001 - reported, not swallowed
        return False, [f"positive control: unmutated seed was REJECTED: {e!r}"]

    def top(key, val):
        def f(d):
            d[key] = val
        return f

    def kdf(key, val):
        def f(d):
            d["kdf_params"][key] = val
        return f

    def blk(key, val):
        def f(d):
            d["blocks"][0][key] = val
        return f

    # (label, mutation, substring the rejection message must contain)
    rows = [
        ("manifest_version out of range", top("manifest_version", 999), "manifest_version"),
        ("manifest_version wrong type", top("manifest_version", "1"), "manifest_version"),
        ("manifest_version as bool", top("manifest_version", True), "manifest_version"),
        ("manifest_version negative", top("manifest_version", -1), "manifest_version"),
        ("format_version unsupported", top("format_version", 999), "format_version"),
        ("suite_id unsupported", top("suite_id", 999), "suite_id"),
        ("suite_id null", top("suite_id", None), "suite_id"),
        ("vault_uuid short", top("vault_uuid", b"\x01" * 5), "vault_uuid"),
        ("owner_user_uuid wrong type", top("owner_user_uuid", "x" * 16), "owner_user_uuid"),
        ("kdf salt short", kdf("salt", b"\x02" * 3), "salt"),
        ("kdf memory_kib wrong type", kdf("memory_kib", "1"), "memory_kib"),
        ("kdf iterations negative", kdf("iterations", -3), "iterations"),
        ("block fingerprint short", blk("fingerprint", b"\x03" * 31), "fingerprint"),
        ("block_name wrong type", blk("block_name", 7), "block_name"),
        ("block created_at_ms negative", blk("created_at_ms", -1), "created_at_ms"),
    ]

    for label, mutate, want in rows:
        d = cbor2.loads(base)
        mutate(d)
        body = cbor2.dumps(d, canonical=True)
        try:
            py_decode_manifest(body)
            issues.append(f"{label}: ACCEPTED -- Rust rejects this body")
        except ValueError as e:
            if want not in str(e):
                issues.append(
                    f"{label}: rejected, but not by the shape check "
                    f"(message lacks {want!r}): {e}"
                )

    if issues:
        return False, issues
    return True, [
        f"PASS  manifest body shape guard: {len(rows)} mutations rejected, "
        "unmutated control accepted"
    ]
