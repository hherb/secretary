"""§4.2 manifest BODY encoder.

Sorts on output -- `vector_clock`, `blocks`, `trash`, and per-block
`recipients` and `vector_clock_summary`. Because the decoder re-encodes and
compares, those sort disciplines are what make an out-of-order array a
REJECTION rather than a silent normalisation.
"""

from __future__ import annotations

from conformance_lib.canonical import encode_canonical_map_raw
from conformance_lib.codec.array_uniqueness import first_repeated_value


# The four arrays §4.2 forbids a repeat in, as (array key, id key) pairs.
# `recipients` is the EXPLICIT exception and is absent by design -- a
# repeated `contact_uuid` denotes no additional grant, is accepted by both
# decoders, and round-trips. Adding it here would make this encoder refuse
# a body the v1-frozen Rust encoder emits, which is the divergence this
# package exists to detect, pointing the wrong way.
_FLAT_UNIQUE_ARRAYS: tuple[tuple[str, str], ...] = (
    ("vector_clock", "device_uuid"),
    ("blocks", "block_uuid"),
    ("trash", "block_uuid"),
)


def check_no_repeated_array_values(parsed: dict) -> None:
    """Reject a manifest whose §4.2-constrained arrays repeat a value.

    §4.2's repeated-value paragraph binds BOTH directions -- "writers MUST
    NOT emit them and readers MUST reject them" -- and this package
    enforced only the reader half until #600, exactly as `core`'s
    `encode_manifest` did. An encoder that can emit a body its own decoder
    refuses is a divergence a clean-room implementation should not have to
    discover for itself.

    Mirrors `core/src/vault/manifest/uniqueness.rs`'s
    `check_no_repeated_array_values`, including the per-block walk: §4.2
    constrains "**each** block's" `vector_clock_summary`, so a writer that
    checked only `blocks[0]` would diverge on the corpus row that plants
    its repeat in `blocks[1]`.
    """
    for array, id_key in _FLAT_UNIQUE_ARRAYS:
        repeat = first_repeated_value([row[id_key] for row in parsed.get(array, [])])
        if repeat is not None:
            raise ValueError(
                f"cannot encode: {array} has a repeated {id_key}: {repeat.hex()}"
            )
    for i, blk in enumerate(parsed.get("blocks", [])):
        summary = blk.get("vector_clock_summary", [])
        repeat = first_repeated_value([row["device_uuid"] for row in summary])
        if repeat is not None:
            raise ValueError(
                f"cannot encode: blocks[{i}].vector_clock_summary has a "
                f"repeated device_uuid: {repeat.hex()}"
            )

def _encode_array_header(n: int) -> bytes:
    """RFC 8949 §3.1: major type 4 (array) head byte is `0x80 |
    additional-info`, with the shortest-form encodings for the element
    count `n` (§4.2.1) -- the array-header analogue of
    `encode_canonical_map_raw`'s map-header construction.
    """
    if n < 24:
        return bytes([0x80 | n])
    if n < 0x100:
        return bytes([0x98, n])
    if n < 0x10000:
        return bytes([0x99]) + n.to_bytes(2, "big")
    return bytes([0x9A]) + n.to_bytes(4, "big")


def _encode_manifest_array(items: list, entry_encoder) -> bytes:
    """Encode a `blocks`/`trash` array from already-decoded entry dicts,
    each rebuilt to raw bytes by `entry_encoder` (`_encode_manifest_block_entry`
    or `_encode_manifest_trash_entry`). Array ELEMENT order is never
    resorted here -- `py_decode_manifest` already validated the incoming
    order against the §4.2 sort discipline, and canonical CBOR only
    constrains map KEY order, never array element order.
    """
    out = bytearray(_encode_array_header(len(items)))
    for item in items:
        out += entry_encoder(item)
    return bytes(out)


def _encode_manifest_block_entry(entry: dict) -> bytes:
    """Re-encode one `blocks[i]` entry dict (from `_decode_manifest_entry_map`)
    to canonical CBOR. All eight known fields are required (`BlockEntry` has
    no `Option` field); `unknown` values are spliced verbatim from their
    retained raw bytes, never re-encoded.
    """
    import cbor2

    entries: list[tuple[str, bytes]] = [
        ("block_uuid", cbor2.dumps(entry["block_uuid"], canonical=True)),
        ("block_name", cbor2.dumps(entry["block_name"], canonical=True)),
        ("fingerprint", cbor2.dumps(entry["fingerprint"], canonical=True)),
        ("recipients", cbor2.dumps(entry["recipients"], canonical=True)),
        (
            "vector_clock_summary",
            cbor2.dumps(entry["vector_clock_summary"], canonical=True),
        ),
        ("suite_id", cbor2.dumps(entry["suite_id"], canonical=True)),
        ("created_at_ms", cbor2.dumps(entry["created_at_ms"], canonical=True)),
        ("last_mod_ms", cbor2.dumps(entry["last_mod_ms"], canonical=True)),
    ]
    entries.extend(entry.get("unknown", {}).items())
    return encode_canonical_map_raw(entries)


def _encode_manifest_trash_entry(entry: dict) -> bytes:
    """Re-encode one `trash[i]` entry dict (from `_decode_manifest_entry_map`)
    to canonical CBOR. `fingerprint` and `purged_at_ms` are each omitted
    entirely when absent/`None` -- never an explicit CBOR null -- matching
    `TrashEntry`'s §7/§7.2 optional-field semantics
    (`manifest/encode.rs::trash_entry_to_canonical`); `unknown` values are
    spliced verbatim from their retained raw bytes.
    """
    import cbor2

    entries: list[tuple[str, bytes]] = [
        ("block_uuid", cbor2.dumps(entry["block_uuid"], canonical=True)),
        ("tombstoned_at_ms", cbor2.dumps(entry["tombstoned_at_ms"], canonical=True)),
        ("tombstoned_by", cbor2.dumps(entry["tombstoned_by"], canonical=True)),
    ]
    if entry.get("fingerprint") is not None:
        entries.append(("fingerprint", cbor2.dumps(entry["fingerprint"], canonical=True)))
    if entry.get("purged_at_ms") is not None:
        entries.append(("purged_at_ms", cbor2.dumps(entry["purged_at_ms"], canonical=True)))
    entries.extend(entry.get("unknown", {}).items())
    return encode_canonical_map_raw(entries)


def py_encode_manifest(parsed: dict) -> bytes:
    """Re-encode a `py_decode_manifest` result to canonical CBOR.

    Known values go through `cbor2.dumps(..., canonical=True)`, EXCEPT
    `blocks`/`trash`, each of which is rebuilt entry-by-entry through
    `_encode_manifest_array` so a per-entry `unknown` subtree is spliced
    from its retained raw bytes rather than collapsed through `cbor2`
    (#585 fix round 1, Finding 1). Top-level unknown subtrees are spliced
    from their retained bytes the same way, never re-encoded.

    Refuses a manifest violating §4.2's repeated-value rules before
    emitting anything (#600) -- see `check_no_repeated_array_values`.
    Observably a no-op for every caller in this package today: the only
    routes here are `py_decode_manifest`'s §4.3 step-4 re-encode and
    `--diff-replay`'s accept path, and both run AFTER the reader has
    already rejected such a body. It is the writer half of a normative
    rule, not a check on the decode path, and Section MUQ exercises it
    directly for that reason.
    """
    import cbor2

    check_no_repeated_array_values(parsed)

    entries: list[tuple[str, bytes]] = []
    for k, v in parsed.items():
        if k == "unknown":
            continue
        if k == "blocks":
            entries.append((k, _encode_manifest_array(v, _encode_manifest_block_entry)))
        elif k == "trash":
            entries.append((k, _encode_manifest_array(v, _encode_manifest_trash_entry)))
        else:
            entries.append((k, cbor2.dumps(v, canonical=True)))
    entries.extend(parsed.get("unknown", {}).items())
    return encode_canonical_map_raw(entries)
