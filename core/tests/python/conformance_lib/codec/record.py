"""§6.3 record BODY decoder/encoder with forward-compat `unknown`-bag retention.

Mirrors `conformance_lib.codec.manifest_decode` one nesting level down. Two
levels carry an `unknown` bag -- the record itself and each field -- and
both must round-trip byte-identically for the differential replay to agree
with Rust.
"""

from __future__ import annotations

from typing import Any

from conformance_lib.canonical import encode_canonical_map_raw
from conformance_lib.codec.scanner import _check_canonical_item, _decode_head, _scan_map_entries

# ---------------------------------------------------------------------------
# §6.3 record BODY decoder/encoder -- forward-compat unknown-bag retention
# ---------------------------------------------------------------------------
# Mirrors the manifest body decoder/encoder pair further down this file
# (`py_decode_manifest` / `py_encode_manifest`), one nesting level
# shallower: a `Record` has a forward-compat `unknown` bag at exactly TWO
# levels -- the record itself (`Record::unknown`) and each field's own
# sub-map (`RecordField::unknown`) -- unlike the manifest's three (top
# level, block entry, trash entry). `cbor2.loads` collapses a duplicate key
# and re-sorts key order inside either bag, rejecting records
# `record.rs::decode` accepts (#592; ground truth pinned by `record.rs`'s
# `unknown_subtree_tolerates_key_order_and_duplicates_but_not_encoding_at_both_levels`).
# These two helpers plus the span-recording scanner primitives defined
# further down this file (`_scan_map_entries` / `_decode_head` /
# `_check_canonical_item`) are what let `py_decode_record` retain both
# bags' raw bytes instead of collapsing them through `cbor2.loads`. Being
# referenced here before their own definitions further down is fine --
# Python resolves a module-level name at CALL time, not at `def` time, and
# the whole module has finished loading before any of these are invoked.

RECORD_KNOWN_KEYS = frozenset({
    "record_uuid", "record_type", "fields", "tags",
    "created_at_ms", "last_mod_ms", "tombstone", "tombstoned_at_ms",
})
# All five are required -- `record.rs::Record` has no `Option` among them;
# `tags`/`tombstone`/`tombstoned_at_ms` are the three optional (absent-on-
# wire-means-default) keys.
RECORD_REQUIRED_KEYS = frozenset({
    "record_uuid", "record_type", "fields", "created_at_ms", "last_mod_ms",
})

# `RecordField`'s own known wire keys (`record.rs::RecordField`). All three
# are required -- `RecordField` has no `Option` field of its own, only its
# separate `unknown` bag.
RECORD_FIELD_KNOWN_KEYS = frozenset({"value", "last_mod", "device_uuid"})


def _decode_record_field_map(data: bytes, pos: int, end: int) -> dict:
    """Decode one `fields[name]` sub-map (`RecordField`, §6.3.2): the three
    known keys dispatch through `cbor2.loads`; any other key is retained as
    raw bytes under `"unknown"`, mirroring `RecordField::unknown` -- the
    SECOND (and last) of the two levels a `Record` has an unknown bag at
    (#592). Rejects a duplicate key -- known or unknown -- within this one
    field's own map (mirrors `RecordError::DuplicateKey { field: "<field>",
    .. }`); required-key presence and value-type checks are left to
    `_validate_record_field`, called by `py_decode_record` once this dict
    is built, so that behaviour is unchanged by this rework.
    """
    import cbor2

    entries, entry_end = _scan_map_entries(data, pos)
    if entry_end != end:
        raise ValueError(f"record field map span mismatch at offset {pos}")

    out: dict[str, Any] = {}
    unknown: dict[str, bytes] = {}
    seen: set[str] = set()

    for (ks, ke), (vs, ve) in entries:
        kmaj, _, _, _ = _decode_head(data, ks)
        if kmaj != 3:
            raise ValueError(f"record field map key at offset {ks} is not a text string")
        key = cbor2.loads(data[ks:ke])
        if key in seen:
            raise ValueError(f"duplicate record field-level key: {key!r}")
        seen.add(key)

        # Rules 2/3/4 apply to every value, known or unknown; rules 1/5
        # (key order, duplicate keys) do not -- see `_check_canonical_item`.
        _check_canonical_item(data, vs)

        if key in RECORD_FIELD_KNOWN_KEYS:
            out[key] = cbor2.loads(data[vs:ve])
        else:
            unknown[key] = data[vs:ve]

    out["unknown"] = unknown
    return out


def _decode_record_fields_map(data: bytes, pos: int, end: int) -> dict:
    """Decode the record's `fields` map at `pos`: each VALUE is a
    `RecordField` sub-map decoded via `_decode_record_field_map`. The
    `fields` map itself carries no forward-compat bag of its own --
    `Record.fields` is a plain `BTreeMap<String, RecordField>`, not a
    struct with an `unknown` field (`record.rs`'s module doc) -- so an
    unrecognised field NAME is simply another field, never
    retained-but-uninterpreted bytes; only each field's VALUE gets that
    treatment, one level down. Rejects a duplicate field name (mirrors
    `RecordError::DuplicateKey { field: "fields", .. }`).
    """
    import cbor2

    entries, entry_end = _scan_map_entries(data, pos)
    if entry_end != end:
        raise ValueError(f"record fields map span mismatch at offset {pos}")

    out: dict[str, dict] = {}
    seen: set[str] = set()
    for (ks, ke), (vs, ve) in entries:
        kmaj, _, _, _ = _decode_head(data, ks)
        if kmaj != 3:
            raise ValueError(f"record fields map key at offset {ks} is not a text string")
        fname = cbor2.loads(data[ks:ke])
        if fname in seen:
            raise ValueError(f"duplicate record field name: {fname!r}")
        seen.add(fname)

        _check_canonical_item(data, vs)
        out[fname] = _decode_record_field_map(data, vs, ve)
    return out


def py_decode_record(data: bytes) -> dict:
    """Strict §6.3 canonical-CBOR record decoder matching record.rs::decode.

    Validates:
    - Top-level item is a CBOR map with text-string keys.
    - No duplicate key at the top level, in the `fields` map, or within
      any one field's own sub-map -- checked on the SPAN list (a `dict`
      would silently collapse a repeat) (#592).
    - No floats, no CBOR tags anywhere in the tree (`_check_canonical_item`
      rule 4, applied to every top-level value's whole subtree).
    - Required fields: record_uuid (16-byte bstr), record_type (tstr),
      fields (map), created_at_ms (uint), last_mod_ms (uint).
    - Optional: tags (array of tstr), tombstone (bool), tombstoned_at_ms (uint).
    - Input is already canonical (re-encode == input).

    Unknown record-level keys AND unknown per-field keys are RETAINED as
    raw bytes rather than decoded through `cbor2.loads`: §4.2/§6.2 rules 1
    (map-key order) and 5 (duplicate keys) are deliberately unenforced
    inside either forward-compat `unknown` bag, mirroring
    `record.rs::decode`'s own tolerance (ground truth:
    `unknown_subtree_tolerates_key_order_and_duplicates_but_not_encoding_at_both_levels`
    in `record.rs`'s `mod tests`). A `Record` has exactly two such levels;
    there is no third the way the manifest has a block/trash-entry level
    below its own top level.

    Returns a dict of parsed fields, with `"unknown"` mapping to
    `{key: raw_bytes}` at BOTH the record level and inside each
    `fields[name]` sub-dict. Raises on any violation.
    """
    entries, end = _scan_map_entries(data, 0)
    if end != len(data):
        raise ValueError(f"trailing bytes after record map: {len(data) - end}")

    import cbor2

    out: dict[str, Any] = {}
    unknown: dict[str, bytes] = {}
    seen: set[str] = set()

    for (ks, ke), (vs, ve) in entries:
        kmaj, _, _, _ = _decode_head(data, ks)
        if kmaj != 3:
            raise ValueError(f"record map key at offset {ks} is not a text string")
        key = cbor2.loads(data[ks:ke])
        if key in seen:
            raise ValueError(f"duplicate record key: {key!r}")
        seen.add(key)

        # Rules 2/3/4 apply to every value, known or unknown; rules 1/5 do
        # not -- see `_check_canonical_item`'s own doc for why.
        _check_canonical_item(data, vs)

        if key == "fields":
            out[key] = _decode_record_fields_map(data, vs, ve)
        elif key in RECORD_KNOWN_KEYS:
            out[key] = cbor2.loads(data[vs:ve])
        else:
            unknown[key] = data[vs:ve]

    for required in sorted(RECORD_REQUIRED_KEYS):
        if required not in out:
            raise KeyError(f"record missing required field: {required!r}")

    rec_uuid = out["record_uuid"]
    if not isinstance(rec_uuid, bytes) or len(rec_uuid) != 16:
        raise ValueError(f"record_uuid must be 16-byte bstr, got {type(rec_uuid).__name__}")

    rec_type = out["record_type"]
    if not isinstance(rec_type, str):
        raise ValueError("record_type must be tstr")

    # `out["fields"]` is already guaranteed to be a dict of str -> dict by
    # `_decode_record_fields_map`'s own scanning, so only the per-field
    # required-key-presence and value-type checks remain to do here.
    for fname, fval in out["fields"].items():
        _validate_record_field(fname, fval)

    cat = out["created_at_ms"]
    if not isinstance(cat, int) or cat < 0:
        raise ValueError(f"created_at_ms must be uint, got {cat!r}")

    lmm = out["last_mod_ms"]
    if not isinstance(lmm, int) or lmm < 0:
        raise ValueError(f"last_mod_ms must be uint, got {lmm!r}")

    # Optional: tags
    if "tags" in out:
        tags_val = out["tags"]
        if not isinstance(tags_val, list):
            raise ValueError("record tags must be array")
        for t in tags_val:
            if not isinstance(t, str):
                raise ValueError("record tags entries must be tstr")

    # Optional: tombstone
    if "tombstone" in out:
        if not isinstance(out["tombstone"], bool):
            raise ValueError("record tombstone must be bool")

    # Optional: tombstoned_at_ms
    if "tombstoned_at_ms" in out:
        tam = out["tombstoned_at_ms"]
        if not isinstance(tam, int) or tam < 0:
            raise ValueError(f"tombstoned_at_ms must be uint, got {tam!r}")

    out["unknown"] = unknown

    # Canonical-input check: re-encode and compare. Retained unknown
    # subtrees -- record-level AND per-field -- are spliced verbatim by
    # `py_encode_record` and compare equal, so this does not undo the
    # byte-retention above.
    #
    # What it does and does NOT catch (#595). It catches KEY ORDER inside a
    # nested KNOWN map. It does NOT catch a DUPLICATE key there: those are
    # rejected earlier and explicitly, by the `seen`-set checks in
    # `_decode_record_fields_map` / `_decode_record_field_map`, which raise
    # before this line runs. Since #592 those maps do not go through
    # `cbor2.loads` at all -- `_scan_map_entries` preserves a repeat, so it
    # would survive the round trip and compare EQUAL. Attributing duplicate
    # rejection to the re-encode is the exact reasoning this slice deleted
    # from `_check_no_duplicate_keys`; do not remove a `seen` set as
    # redundant with this check.
    reencoded = py_encode_record(out)
    if reencoded != data:
        raise ValueError("record is not in canonical CBOR form")

    return out


def _validate_record_field(fname: str, fval: dict) -> None:
    """Validate a single §6.3 RecordField sub-map."""
    REQUIRED_FIELD_KEYS = {"value", "last_mod", "device_uuid"}
    for k in REQUIRED_FIELD_KEYS:
        if k not in fval:
            raise KeyError(f"record field {fname!r} missing {k!r}")
    v = fval["value"]
    if not isinstance(v, (str, bytes)):
        raise ValueError(f"field {fname!r} value must be tstr or bstr")
    lm = fval["last_mod"]
    if not isinstance(lm, int) or lm < 0:
        raise ValueError(f"field {fname!r} last_mod must be uint")
    du = fval["device_uuid"]
    if not isinstance(du, bytes) or len(du) != 16:
        raise ValueError(f"field {fname!r} device_uuid must be 16-byte bstr")


def _reject_floats_and_tags_py(v: Any) -> None:
    """Walk a cbor2-decoded value tree and raise on float or CBOR tag.

    Mirrors vault::canonical::reject_floats_and_tags.
    """
    import cbor2
    if isinstance(v, float):
        raise ValueError("float values are not permitted")
    if isinstance(v, cbor2.CBORTag):
        raise ValueError("CBOR tags are not permitted")
    if isinstance(v, dict):
        for k, val in v.items():
            _reject_floats_and_tags_py(k)
            _reject_floats_and_tags_py(val)
    elif isinstance(v, list):
        for item in v:
            _reject_floats_and_tags_py(item)


def _encode_record_field(field: dict) -> bytes:
    """Re-encode one `fields[name]` sub-map (`RecordField`) to canonical
    CBOR. All three known keys are required; `unknown` values are spliced
    verbatim from their retained raw bytes -- never re-encoded through
    `cbor2` -- mirroring `_encode_manifest_block_entry` one nesting level
    up (#592).
    """
    import cbor2

    entries: list[tuple[str, bytes]] = [
        ("value", cbor2.dumps(field["value"], canonical=True)),
        ("last_mod", cbor2.dumps(field["last_mod"], canonical=True)),
        ("device_uuid", cbor2.dumps(field["device_uuid"], canonical=True)),
    ]
    entries.extend(field.get("unknown", {}).items())
    return encode_canonical_map_raw(entries)


def _encode_record_fields_map(fields: dict) -> bytes:
    """Re-encode the record's `fields` map: each VALUE goes through
    `_encode_record_field`. The map itself has no unknown bag of its own
    -- only per-field bags do -- so its keys are exactly the caller's
    field names; `encode_canonical_map_raw` imposes the canonical key
    order regardless of the order given here.
    """
    entries = [(name, _encode_record_field(f)) for name, f in fields.items()]
    return encode_canonical_map_raw(entries)


def py_encode_record(record: dict) -> bytes:
    """Re-encode a `py_decode_record` result to canonical CBOR.

    Known values go through `cbor2.dumps(..., canonical=True)`, EXCEPT
    `fields`, rebuilt entry-by-entry through `_encode_record_fields_map` so
    a per-field `unknown` subtree is spliced from its retained raw bytes
    rather than collapsed through `cbor2` (#592, mirroring
    `py_encode_manifest`'s `blocks`/`trash` treatment one nesting level
    up). Top-level unknown subtrees are spliced from their retained bytes
    the same way, never re-encoded.

    `record` is expected to carry exactly the shape `py_decode_record`
    produces: `tags`/`tombstone`/`tombstoned_at_ms` keys are present only
    when they were present on the wire, so §6.3's "absent on the wire"
    rule for each of the three is automatic here -- this function does not
    special-case any of them, it simply encodes whichever keys `record`
    has -- and `"unknown"` maps to `{key: raw_bytes}` rather than being
    flattened into the same level as the known keys (the pre-#592 shape
    this function used to require).
    """
    import cbor2

    entries: list[tuple[str, bytes]] = []
    for k, v in record.items():
        if k == "unknown":
            continue
        if k == "fields":
            entries.append((k, _encode_record_fields_map(v)))
        else:
            entries.append((k, cbor2.dumps(v, canonical=True)))
    entries.extend(record.get("unknown", {}).items())
    return encode_canonical_map_raw(entries)
