"""§4.2 manifest-body schema: the known/required key sets and the strict
sub-map decoders that enforce them.

`*_KNOWN_KEYS` is what the decoder INTERPRETS; anything else goes to the
`unknown` bag. `*_REQUIRED_KEYS` is what must be present. The two differ
only for `trash`, whose `fingerprint` and `purged_at_ms` are
additive-optional.
"""

from __future__ import annotations

from typing import Any

from conformance_lib.codec.scanner import _check_canonical_item, _decode_head, _scan_array_items, _scan_map_entries

# ---------------------------------------------------------------------------
# §4.2/§4.3 manifest BODY decoder/encoder (#585)
# ---------------------------------------------------------------------------
# Distinct from `py_decode_manifest_file`/`py_encode_manifest_file` above,
# which handle the §4.1 outer signed envelope (header + AEAD blob +
# signatures). This pair operates on the AEAD-DECRYPTED CBOR body -- the
# plaintext `manifest_pt_bytes` that comes out of `verify_block_and_manifest`
# step 8 -- and consumes the span-recording scanner primitives
# (`_decode_head` / `_scan_item` / `_scan_map_entries` / `_check_canonical_item`)
# defined above so a forward-compat `unknown` subtree's raw bytes, entry
# order and repeats survive a decode/re-encode round trip (#592).

# Known top-level manifest body keys (§4.2). Anything else is a
# forward-compat unknown and is retained as raw bytes.
# Fixed widths the Rust decoder pins via `take_fixed_bytes::<N>`
# (`manifest/mod.rs`: `UUID_LEN`, `BLOCK_FINGERPRINT_LEN`, `SALT_LEN`), and
# the `manifest_version` sentinel (`MANIFEST_VERSION_V1`). `FORMAT_VERSION`
# and `SUITE_ID` are already defined at the top of this file.
UUID_LEN = 16
BLOCK_FINGERPRINT_LEN = 32
SALT_LEN = 32
MANIFEST_VERSION_V1 = 1

MANIFEST_KNOWN_KEYS = frozenset({
    "manifest_version", "vault_uuid", "format_version", "suite_id",
    "owner_user_uuid", "vector_clock", "blocks", "trash", "kdf_params",
})

# All nine are required -- `manifest/types.rs::Manifest` has no `Option`
# among them, so `decode_manifest` requires every one (#585 fix round 1,
# Finding 2). A prior version of this decoder only hard-required three;
# the re-encode-and-compare does NOT catch that gap on its own, because a
# body simply missing a key re-encodes to itself byte-for-byte.
MANIFEST_REQUIRED_KEYS = MANIFEST_KNOWN_KEYS

# `BlockEntry`'s own known wire keys (`manifest/types.rs`), verified against
# `manifest/decode/entries.rs::parse_block_entry`. All eight are required
# there (no `Option` field on `BlockEntry`).
BLOCK_ENTRY_KNOWN_KEYS = frozenset({
    "block_uuid", "block_name", "fingerprint", "recipients",
    "vector_clock_summary", "suite_id", "created_at_ms", "last_mod_ms",
})

# `TrashEntry`'s own known wire keys, verified against
# `manifest/decode/entries.rs::parse_trash_entry`. `fingerprint` and
# `purged_at_ms` are `Option` on `TrashEntry` and each omitted-key decodes
# to `None` (§7/§7.2); the other three are required.
TRASH_ENTRY_KNOWN_KEYS = frozenset({
    "block_uuid", "tombstoned_at_ms", "tombstoned_by",
    "fingerprint", "purged_at_ms",
})

# Required subsets of the two entry-known-key sets above (#585 fix round 2,
# Finding 4). `BlockEntry` has no `Option` field at all, so all 8 known
# keys are required; `TrashEntry` has exactly 2 (`fingerprint`,
# `purged_at_ms`), so its required set excludes them.
BLOCK_ENTRY_REQUIRED_KEYS = BLOCK_ENTRY_KNOWN_KEYS
TRASH_ENTRY_REQUIRED_KEYS = frozenset({"block_uuid", "tombstoned_at_ms", "tombstoned_by"})

# `KdfParamsRef`'s known wire keys, verified against
# `manifest/decode/entries.rs::parse_kdf_params`: its catch-all
# match arm returns `WrongType` for any key outside this set -- unlike
# `BlockEntry`/`TrashEntry`, `KdfParamsRef` has NO `unknown` bag (#585 fix
# round 2, Finding 3). All four are required (no `Option` field).
KDF_PARAMS_KNOWN_KEYS = frozenset({"memory_kib", "iterations", "parallelism", "salt"})

# Every `KdfParamsRef` field is mandatory: `parse_kdf_params` ends by
# `ok_or(ManifestError::MissingField)`-ing all four
# (`manifest/decode/entries.rs`, `parse_kdf_params`).
KDF_PARAMS_REQUIRED_KEYS = KDF_PARAMS_KNOWN_KEYS

# `VectorClockEntry`'s known wire keys, verified against
# `manifest/decode/entries.rs::parse_vector_clock_entry`: same
# catch-all `WrongType` shape as `parse_kdf_params` -- no `unknown` bag
# (#585 fix round 2, Finding 3). Serves BOTH the top-level `vector_clock`
# array and each block entry's `vector_clock_summary` array: Rust's
# `parse_vector_clock` is one function taking only an error-message
# `field: &'static str`, called with `KEY_VECTOR_CLOCK` at the top level
# and `KEY_VECTOR_CLOCK_SUMMARY` inside `parse_block_entry` -- the entry
# shape itself never varies. Both keys are required (no `Option` field).
VECTOR_CLOCK_ENTRY_KNOWN_KEYS = frozenset({"device_uuid", "counter"})

# Both `VectorClockEntry` fields are mandatory, same construction as
# `KDF_PARAMS_REQUIRED_KEYS` above (`parse_vector_clock_entry`).
VECTOR_CLOCK_ENTRY_REQUIRED_KEYS = VECTOR_CLOCK_ENTRY_KNOWN_KEYS


def _decode_strict_entry_map(
    data: bytes,
    pos: int,
    end: int,
    known_keys: frozenset,
    required_keys: frozenset,
    label: str,
) -> dict:
    """Decode one CBOR map with a FIXED shape and NO forward-compat
    `unknown` bag (#585 fix round 2, Finding 3) -- the OPPOSITE polarity to
    `_decode_manifest_entry_map` below. `KdfParamsRef` and
    `VectorClockEntry` have no `unknown` field, unlike `BlockEntry`/
    `TrashEntry`: `parse_kdf_params` / `parse_vector_clock_entry` each end
    in a catch-all match arm that REJECTS any key outside their known set
    as `ManifestError::WrongType`, where the block/trash entry parsers
    instead absorb it into their own `unknown` bag. The distinguishing
    fact is whether the Rust struct HAS an `unknown` bag at all -- do not
    generalise this helper's rejection behaviour onto
    `_decode_manifest_entry_map`'s entries, or vice versa.

    Also rejects a duplicate of a KNOWN key, mirroring each Rust parser's
    own per-field `DuplicateKey` check, AND a MISSING one: both Rust
    parsers end by `ok_or(ManifestError::MissingField)`-ing every field
    (`parse_kdf_params`, `parse_vector_clock_entry`). Absence cannot be
    caught by the caller's §4.3 step-4 re-encode -- a body simply missing
    a key re-encodes to itself byte-for-byte -- which is why it is checked
    here, the same reasoning `MANIFEST_REQUIRED_KEYS` records one level up.
    """
    import cbor2

    entries, entry_end = _scan_map_entries(data, pos)
    if entry_end != end:
        raise ValueError(f"{label} entry map span mismatch at offset {pos}")

    out: dict[str, Any] = {}
    for (ks, ke), (vs, ve) in entries:
        kmaj, _, _, _ = _decode_head(data, ks)
        if kmaj != 3:
            raise ValueError(f"{label} entry map key at offset {ks} is not a text string")
        key = cbor2.loads(data[ks:ke])
        if key not in known_keys:
            raise ValueError(
                f"{label} has no forward-compat bag -- unrecognised key {key!r}"
            )
        if key in out:
            raise ValueError(f"duplicate {label} key: {key!r}")

        _check_canonical_item(data, vs)

        out[key] = cbor2.loads(data[vs:ve])

    for required in sorted(required_keys):
        if required not in out:
            raise ValueError(f"{label} entry missing required field: {required!r}")
    return out


def _decode_strict_array(
    data: bytes,
    pos: int,
    end: int,
    known_keys: frozenset,
    required_keys: frozenset,
    label: str,
) -> list:
    """Decode an array of `_decode_strict_entry_map` entries -- the
    `vector_clock` / `vector_clock_summary` shape (#585 fix round 2,
    Finding 3).
    """
    items, arr_end = _scan_array_items(data, pos)
    if arr_end != end:
        raise ValueError(f"{label} array span mismatch at offset {pos}")
    return [
        _decode_strict_entry_map(data, s, e, known_keys, required_keys, label)
        for s, e in items
    ]


def _decode_manifest_entry_map(
    data: bytes,
    pos: int,
    end: int,
    known_keys: frozenset,
    required_keys: frozenset,
    label: str,
) -> dict:
    """Decode one manifest-array entry map (a `blocks[i]` or `trash[i]`),
    matching the corresponding Rust `parse_block_entry` / `parse_trash_entry`
    (#585 fix round 1, Finding 1): the design originally scoped span-based
    byte retention to the manifest body's TOP-LEVEL `unknown` bag only, but
    `BlockEntry` and `TrashEntry` each carry their OWN forward-compat
    `unknown` bag one level deeper (`manifest/types.rs`) -- so a duplicate
    key inside e.g. a block entry's unknown subtree was being collapsed by
    `cbor2.loads` (Rust tolerates it; §4.2's unknown-subtree exemption for
    rules 1/5 applies at every nesting level, not just the top one).

    Dispatches KNOWN entry keys through `cbor2.loads` on their value span
    -- EXCEPT `vector_clock_summary`, routed through `_decode_strict_array`
    (#585 fix round 2, Finding 3), since a `VectorClockEntry` has no
    `unknown` bag of its own and must reject any key outside its fixed
    shape, unlike this entry itself. Retains UNKNOWN values as raw bytes;
    rejects a duplicate key -- known or unknown -- within this one entry
    (mirrors Rust's per-arm `DuplicateKey` / `BTreeMap::insert` duplicate
    check). Every value, known or unknown, is checked for §6.2 rules 2/3/4
    via `_check_canonical_item`, exactly as `py_decode_manifest`'s own
    top-level loop does one level up (redundant with the top-level call
    that already walked this whole subtree structurally, but kept for
    exact symmetry with that loop and so this helper is correct if ever
    called on its own).

    Finally, asserts every key in `required_keys` is present, raising
    `ValueError` (not `KeyError`) naming the missing field (#585 fix round
    2, Finding 4) -- `BlockEntry` has no `Option` field (all 8 known keys
    required) and `TrashEntry` excludes its 2 `Option` fields
    (`fingerprint`, `purged_at_ms`) from its required set. `ValueError` is
    deliberate: a `KeyError` here would still be caught cleanly at the
    `verify_block_and_manifest` call site (which catches both), but this
    module's own `section_manifest_body_*_guard` test sections use the
    narrower `except ValueError`, and a corpus fixture exercising this gap
    would otherwise crash the verifier instead of reporting a clean FAIL.
    """
    import cbor2

    entries, entry_end = _scan_map_entries(data, pos)
    if entry_end != end:
        raise ValueError(f"{label} entry map span mismatch at offset {pos}")

    out: dict[str, Any] = {}
    unknown: dict[str, bytes] = {}
    seen: set[str] = set()

    for (ks, ke), (vs, ve) in entries:
        kmaj, _, _, _ = _decode_head(data, ks)
        if kmaj != 3:
            raise ValueError(f"{label} entry map key at offset {ks} is not a text string")
        key = cbor2.loads(data[ks:ke])
        if key in seen:
            raise ValueError(f"duplicate {label} entry key: {key!r}")
        seen.add(key)

        _check_canonical_item(data, vs)

        if key in known_keys:
            if key == "vector_clock_summary":
                out[key] = _decode_strict_array(
                    data,
                    vs,
                    ve,
                    VECTOR_CLOCK_ENTRY_KNOWN_KEYS,
                    VECTOR_CLOCK_ENTRY_REQUIRED_KEYS,
                    "vector_clock_summary",
                )
            else:
                out[key] = cbor2.loads(data[vs:ve])
        else:
            unknown[key] = data[vs:ve]

    for required in sorted(required_keys):
        if required not in out:
            raise ValueError(f"{label} entry missing required field: {required!r}")

    out["unknown"] = unknown
    return out


def _decode_manifest_array(
    data: bytes,
    pos: int,
    end: int,
    known_keys: frozenset,
    required_keys: frozenset,
    label: str,
) -> list:
    """Decode a manifest `blocks`/`trash` array at `pos` into a list of
    per-entry dicts via `_scan_array_items` + `_decode_manifest_entry_map`,
    one nesting level below `py_decode_manifest`'s own top-level loop
    (#585 fix round 1, Finding 1).
    """
    items, arr_end = _scan_array_items(data, pos)
    if arr_end != end:
        raise ValueError(f"{label} array span mismatch at offset {pos}")
    return [
        _decode_manifest_entry_map(data, s, e, known_keys, required_keys, label)
        for s, e in items
    ]
