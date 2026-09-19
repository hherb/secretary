"""§6.3 record BODY decoder/encoder with forward-compat `unknown`-bag retention.

Mirrors `conformance_lib.codec.manifest_decode` one nesting level down. Two
levels carry an `unknown` bag -- the record itself and each field -- and
both must round-trip byte-identically for the differential replay to agree
with Rust.
"""

from __future__ import annotations

from typing import Any

from conformance_lib.canonical import encode_canonical_map_raw
from conformance_lib.codec.record_rules import (
    RecordDuplicateKey,
    RecordMissingField,
    RecordNonCanonical,
    RecordWrongType,
    check_field_value,
    check_record_value,
)
from conformance_lib.codec.required_keys import first_missing_key_in_sorted_order
from conformance_lib.codec.scanner import NonCanonicalItem, _check_canonical_item, _decode_head, _scan_map_entries
from conformance_lib.codec.well_formed import MAJOR_MAP, MAJOR_TEXT, walk_body

# ---------------------------------------------------------------------------
# §6.3 record BODY decoder/encoder -- forward-compat unknown-bag retention
# ---------------------------------------------------------------------------
# Mirrors the manifest body decoder/encoder pair (`codec/manifest_decode.py`'s
# `py_decode_manifest`, `codec/manifest_encode.py`'s `py_encode_manifest`),
# one nesting level shallower: a `Record` has a forward-compat `unknown` bag
# at exactly TWO levels -- the record itself (`Record::unknown`) and each
# field's own sub-map (`RecordField::unknown`) -- unlike the manifest's three
# (top level, block entry, trash entry). `cbor2.loads` collapses a duplicate
# key and re-sorts key order inside either bag, rejecting records
# `record.rs::decode` accepts (#592; ground truth pinned by `record.rs`'s
# `unknown_subtree_tolerates_key_order_and_duplicates_but_not_encoding_at_both_levels`).
# The two map decoders below plus the span-recording scanner primitives
# imported above (`_scan_map_entries` / `_decode_head` /
# `_check_canonical_item`) are what let `py_decode_record` retain both bags'
# raw bytes instead of collapsing them through `cbor2.loads`.

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

# vault-format §6.3 (#670): a default value is written by omission. The three
# optional keys and their defaults, exactly as `record.rs`'s
# `record_to_canonical` omits them (`tags` when empty, `tombstone` when false,
# `tombstoned_at_ms` when 0).
RECORD_OPTIONAL_DEFAULTS: dict[str, object] = {
    "tags": [],
    "tombstone": False,
    "tombstoned_at_ms": 0,
}


def _is_omitted_default(key: str, value: object) -> bool:
    """True when `key` is an optional record key holding its default.

    The TYPE is compared as well as the value: in Python `False == 0`, so a
    value-only test would drop a (wrong-typed) `tombstoned_at_ms: False` and
    silently change what the encoder was asked to emit.
    """
    if key not in RECORD_OPTIONAL_DEFAULTS:
        return False
    default = RECORD_OPTIONAL_DEFAULTS[key]
    return type(value) is type(default) and value == default


# The crypto-design §6.2 rules `record::decode` meets only at its re-encode
# comparison, as the fieldless `NonCanonicalEncoding`: definite lengths (2)
# and shortest-form heads (3).  Only a `NonCanonicalItem` carrying one of
# these becomes `RecordNonCanonical`.  Rule 4 belongs to step 1's walk, and a
# rule-4 item reaching step 5 must surface as itself, not be relabelled.
_RE_ENCODE_RULES = (2, 3)


def _decode_record_field_map(data: bytes, pos: int, fname: str) -> dict:
    """Decode one `fields[fname]` sub-map (`RecordField`, §6.3.2) in
    `parse_field_map`'s order: per entry in wire order, the key's type, then a
    repeat, then the value checked the moment it is read; this field's missing
    keys last.  Unknown keys are retained as raw bytes under `"unknown"`, the
    second of the two levels a `Record` has an unknown bag at (#592).
    """
    import cbor2

    major, _, _, _ = _decode_head(data, pos)
    if major != MAJOR_MAP:
        raise RecordWrongType(f"record field {fname!r} value must be a map, got major type {major}")
    entries, _ = _scan_map_entries(data, pos)
    out: dict[str, Any] = {}
    unknown: dict[str, bytes] = {}
    seen: set[str] = set()
    for (ks, ke), (vs, ve) in entries:
        kmaj, _, _, _ = _decode_head(data, ks)
        if kmaj != MAJOR_TEXT:
            raise RecordWrongType(f"record field map key at offset {ks} is not a text string")
        key = cbor2.loads(data[ks:ke])
        if key in seen:
            raise RecordDuplicateKey(f"duplicate record field-level key: {key!r}")
        seen.add(key)
        if key in RECORD_FIELD_KNOWN_KEYS:
            out[key] = check_field_value(fname, key, cbor2.loads(data[vs:ve]))
        else:
            unknown[key] = data[vs:ve]
    _validate_record_field(fname, out)
    out["unknown"] = unknown
    return out


def _decode_record_fields_map(data: bytes, pos: int) -> dict:
    """Decode the record's `fields` map at `pos` in `take_fields_map`'s order:
    per entry, the key's type, then a repeated field name, then that field's
    own sub-map in full.  `fields` has no unknown bag of its own -- an
    unrecognised field NAME is simply another field (`record.rs`'s module doc).
    """
    import cbor2

    major, _, _, _ = _decode_head(data, pos)
    if major != MAJOR_MAP:
        raise RecordWrongType(f"record fields must be a map, got major type {major}")
    entries, _ = _scan_map_entries(data, pos)
    out: dict[str, dict] = {}
    for (ks, ke), (vs, _ve) in entries:
        kmaj, _, _, _ = _decode_head(data, ks)
        if kmaj != MAJOR_TEXT:
            raise RecordWrongType(f"record fields map key at offset {ks} is not a text string")
        fname = cbor2.loads(data[ks:ke])
        if fname in out:
            raise RecordDuplicateKey(f"duplicate record field name: {fname!r}")
        out[fname] = _decode_record_field_map(data, vs, fname)
    return out


def py_decode_record(data: bytes) -> dict:
    """Strict §6.3 canonical-CBOR record decoder, in `record.rs::decode`'s phase
    order (#641), so that a body breaking several rules names the same one in
    both languages:

      1. `walk_body`: well-formed CBOR, then no tag or float anywhere (rule 4).
      2. The top-level item is a map.
      3. Entries in wire order: key type, then a repeat, then the value checked
         the moment it is read (`fields` recursing in the same order, each
         field's missing keys at the end of that field).
      4. Missing required top-level keys.
      5. Canonical form, last: §6.2 rules 2/3 per value, trailing bytes, then
         the re-encode comparison -- all `RecordNonCanonical`, because Rust's
         fieldless `NonCanonicalEncoding` cannot tell them apart.

    Unknown record-level and per-field keys are RETAINED as raw bytes rather
    than decoded through `cbor2.loads`: §4.2/§6.2 rules 1 and 5 are deliberately
    unenforced inside either forward-compat `unknown` bag (ground truth:
    `unknown_subtree_tolerates_key_order_and_duplicates_but_not_encoding_at_both_levels`
    in `record.rs`'s tests).

    Returns a dict of parsed fields, with `"unknown"` mapping to
    `{key: raw_bytes}` at BOTH the record level and inside each
    `fields[name]` sub-dict.
    """
    import cbor2

    end = walk_body(data)
    major, _, _, _ = _decode_head(data, 0)
    if major != MAJOR_MAP:
        raise RecordWrongType(f"expected a CBOR map at offset 0, got major type {major}")
    entries, _ = _scan_map_entries(data, 0)

    out: dict[str, Any] = {}
    unknown: dict[str, bytes] = {}
    seen: set[str] = set()
    for (ks, ke), (vs, ve) in entries:
        kmaj, _, _, _ = _decode_head(data, ks)
        if kmaj != MAJOR_TEXT:
            raise RecordWrongType(f"record map key at offset {ks} is not a text string")
        key = cbor2.loads(data[ks:ke])
        if key in seen:
            raise RecordDuplicateKey(f"duplicate record key: {key!r}")
        seen.add(key)
        if key == "fields":
            out[key] = _decode_record_fields_map(data, vs)
        elif key in RECORD_KNOWN_KEYS:
            out[key] = check_record_value(key, cbor2.loads(data[vs:ve]))
        else:
            unknown[key] = data[vs:ve]

    absent = first_missing_key_in_sorted_order(out, RECORD_REQUIRED_KEYS)
    if absent is not None:
        raise RecordMissingField(f"record missing required field: {absent!r}")
    out["unknown"] = unknown

    for _key_span, (vs, _ve) in entries:
        try:
            _check_canonical_item(data, vs)
        except NonCanonicalItem as exc:
            if exc.rule not in _RE_ENCODE_RULES:
                raise
            raise RecordNonCanonical(str(exc)) from exc
    if end != len(data):
        raise RecordNonCanonical(f"trailing bytes after record map: {len(data) - end}")
    # What this comparison does and does NOT catch (#595): it catches KEY
    # ORDER inside a nested known map, and map-head non-canonicality. It does
    # NOT catch a DUPLICATE key: those are rejected earlier by the repeat
    # checks (a `seen` set at the record and field levels, `fname in out` at
    # the `fields` level), and a repeat would survive `_scan_map_entries` and
    # compare EQUAL. Do not remove a repeat check as redundant with this one.
    if py_encode_record(out) != data:
        raise RecordNonCanonical("record is not in canonical CBOR form")
    return out


def _validate_record_field(fname: str, fval: dict) -> None:
    """The per-field required-key check, run once `fields[fname]`'s map has
    been read -- `parse_field_map` requires its three keys only after its loop.
    Value types are checked as each key is read (`check_field_value`)."""
    REQUIRED_FIELD_KEYS = {"value", "last_mod", "device_uuid"}
    absent = first_missing_key_in_sorted_order(fval, REQUIRED_FIELD_KEYS)
    if absent is not None:
        raise RecordMissingField(f"record field {fname!r} missing {absent!r}")


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

    `record` is expected to carry the shape `py_decode_record` produces, with
    `"unknown"` mapping to `{key: raw_bytes}` rather than flattened into the
    known keys (the pre-#592 shape). The three optional keys are omitted when
    they hold their defaults (vault-format §6.3, #670), as
    `record_to_canonical` omits them, so a decoded body that spelled a default
    out fails the re-encode comparison in `py_decode_record` -- the same phase
    and the same token (`non_canonical_unclassified`) as `record::decode`.
    """
    import cbor2

    entries: list[tuple[str, bytes]] = []
    for k, v in record.items():
        if k == "unknown" or _is_omitted_default(k, v):
            continue
        if k == "fields":
            entries.append((k, _encode_record_fields_map(v)))
        else:
            entries.append((k, cbor2.dumps(v, canonical=True)))
    entries.extend(record.get("unknown", {}).items())
    return encode_canonical_map_raw(entries)
