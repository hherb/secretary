"""Strict contact-card decode/encode pair behind `--diff-replay`'s
`contact_card` target.

This decoder has no `unknown` bag at all -- it rejects every unrecognised
key outright -- so its duplicate-key protection comes from a span-list scan
over the map entries (see `_scan_map_entries` / the "WHY SPANS AND NOT A
`cbor2` DICT" comment below), not from the re-encode-and-compare: a `cbor2`
dict destroys repeats before this decoder ever sees them, so it cannot see a
duplicate key at all through that route.
"""

from __future__ import annotations

from typing import Any

from conformance_lib.canonical import encode_canonical_map
from conformance_lib.codec.card_rules import (
    CardDisplayNameTooLong, CardDuplicateKey,
    CardMissingField, CardNonCanonical, CardUnknownField, CardUnsupportedVersion,
    CardWrongType,
)
from conformance_lib.codec.cbor_faults import MalformedCbor
from conformance_lib.codec.integer_rules import is_integer
from conformance_lib.codec.record_rules import UncheckedKnownKey
from conformance_lib.codec.required_keys import first_missing_key_in_sorted_order
from conformance_lib.codec.scanner import _decode_head, _scan_map_entries
from conformance_lib.codec.well_formed import walk_body

# crypto-design §6, the source of this figure. Never a bare literal at a call
# site -- the spec states it and `core/src/identity/card.rs` holds the Rust
# constant, so a third spelling is a third thing to keep in step.
MAX_DISPLAY_NAME_BYTES = 4096

# §6 fixed-size fields, in bytes.
_FIXED_BYTE_LENGTHS = {
    "contact_uuid": 16,
    "x25519_pk": 32,
    "ml_kem_768_pk": 1184,
    "ed25519_pk": 32,
    "ml_dsa_65_pk": 1952,
    "self_sig_ed": 64,
    "self_sig_pq": 3309,
}

KNOWN_CARD_KEYS = {
    "card_version", "contact_uuid", "display_name", "x25519_pk",
    "ml_kem_768_pk", "ed25519_pk", "ml_dsa_65_pk", "created_at",
    "self_sig_ed", "self_sig_pq",
}
REQUIRED_CARD_FIELDS = KNOWN_CARD_KEYS  # all 10 are required


def check_card_value(key: str, value: Any) -> None:
    """Type- and range-check ONE §6 value, the moment its key is read.

    Total over `KNOWN_CARD_KEYS`: the fall-through raises `UncheckedKnownKey`,
    a bug in this package and never a verdict, so a key added to the schema
    without a check here fails loudly (#641's M8).  A totality check over the
    keys that exist proves nothing about that fall-through, and nothing in
    this package currently probes it with an undeclared key -- Section VT's
    check 4b is scoped to `record.py` only.
    """
    if key in _FIXED_BYTE_LENGTHS:
        want = _FIXED_BYTE_LENGTHS[key]
        if not isinstance(value, bytes) or len(value) != want:
            raise CardWrongType(f"{key} must be {want}-byte bstr")
        return
    if key == "card_version":
        # The SPLIT is the point: a wrong TYPE is not an unsupported version.
        # `card.rs` runs `take_u8` before comparing to CARD_VERSION_V1 -- but
        # `take_u8` is ALL this arm does. The `!= CARD_VERSION_V1` comparison
        # is not inline in `parse_card_map`'s loop at all: it runs once,
        # after the ENTIRE loop, right after `card_version.ok_or(..)`, ahead
        # of every other field's `.ok_or(..)`. Folding the comparison in
        # here would report `unsupported_version` for a body carrying a
        # wrong-VALUE `card_version` *and* a later-wire-order type fault on
        # another key -- `card.rs` reports that other key's fault instead,
        # since it never reaches the deferred comparison. See the check
        # below the entry loop, which runs in that same post-loop position.
        if not is_integer(value):
            raise CardWrongType(f"card_version must be a uint, got {value!r}")
        if value < 0 or value > 255:
            # `take_u8`'s own range, checked inline same as the type: a
            # negative value is Malformed("expected non-negative integer"),
            # one over 255 is InvalidFieldLength. Both map to `wrong_type`,
            # same as the bare-type fault above.
            raise CardWrongType(f"card_version must fit in a u8, got {value!r}")
        return
    if key == "display_name":
        if not isinstance(value, str):
            raise CardWrongType("display_name must be tstr")
        if len(value.encode("utf-8")) > MAX_DISPLAY_NAME_BYTES:
            raise CardDisplayNameTooLong(
                f"display_name exceeds crypto-design §6's "
                f"{MAX_DISPLAY_NAME_BYTES}-byte bound"
            )
        return
    if key == "created_at":
        # `is_integer` excludes `bool`, which subclasses `int` (#669 M1).
        if not is_integer(value):
            raise CardWrongType(f"created_at must be uint, got {value!r}")
        # `card.rs`'s `take_u64` says Malformed("integer outside u64 range")
        # for a negative value -- and `CardError` has NO variant mapping to
        # `integer_out_of_range` at all (`rule_tokens/card.rs`'s exhaustive
        # match sends every `Malformed(_)` arm, this one included, to
        # `RuleToken::WrongType`). A plain major-0 CBOR uint can never exceed
        # u64::MAX (RFC 8949 caps its argument at 8 bytes), so a negative
        # value -- major 1 -- is the only way this arm is reached, and it is
        # `wrong_type`, same as the type fault above, not a distinct token.
        if value < 0:
            raise CardWrongType(f"created_at must be non-negative, got {value!r}")
        return
    raise UncheckedKnownKey(f"no value check for known card key {key!r}")


def py_decode_contact_card(data: bytes) -> dict:
    """Strict §6 contact card decoder matching card.rs::from_canonical_cbor.

    Validates:
    - Top-level item is a CBOR map with text-string keys.
    - No unknown keys (card.rs returns UnknownField error on unknown fields).
    - Required fields: card_version (uint == 1), contact_uuid (16-byte bstr),
      display_name (tstr), x25519_pk (32-byte bstr), ml_kem_768_pk (1184-byte bstr),
      ed25519_pk (32-byte bstr), ml_dsa_65_pk (1952-byte bstr), created_at (uint),
      self_sig_ed (64-byte bstr), self_sig_pq (3309-byte bstr).
    - Input is already canonical (re-encode == input).

    Does NOT verify self-signatures (matching from_canonical_cbor which
    separates parsing from signature verification).
    Returns the decoded dict. Raises on any violation.
    """
    import cbor2

    # crypto-design §6.2 rules 4 and 6 before cbor2 parses anything, and
    # `docs/vault-format.md` §4.2's well-formedness precondition ahead of both
    # (#641, #691).  `walk_body`, not the content-BLIND `reject_excessive_nesting`
    # this decoder used until #641: that pass reported no UTF-8, simple-value
    # or rule-4 fault, so `cbor2` folded a bignum to an int and re-emitted it as
    # a bignum, round-tripping the re-encode comparison and ACCEPTING a tag
    # §6.2 rule 4 forbids.
    walk_body(data)

    # WHY SPANS AND NOT A `cbor2` DICT (#641).  A dict destroys repeats, so it
    # cannot see a duplicate key at all; `card.rs::set_once` reports one.  And
    # the duplicate check cannot be a PRE-PASS: `from_canonical_cbor`
    # interleaves, so a wrong-typed key at entry 0 and a repeat at entry 5 is a
    # type fault, and a pre-pass would answer "duplicate" -- a NEW divergence
    # introduced by the fix.  Same shape `codec/manifest_decode.py` uses.
    # A non-map top-level item is a wrong TYPE ("expected top-level CBOR
    # map", `card.rs`'s own wording) -- `_scan_map_entries` raises a bare,
    # untokened `ValueError` for this, which must be translated here rather
    # than left to propagate as a harness failure.
    #
    # Trailing bytes are deliberately NOT checked here. `from_canonical_cbor`
    # never checks for them either -- `ciborium::de::from_reader` performs no
    # EOF check, so Rust processes the map's own entries first and meets
    # trailing bytes only where this decoder now meets them too: the
    # canonical-form re-encode comparison at the end, which naturally
    # mismatches whenever trailing bytes are present. Checking `end` up
    # front, ahead of the entry loop, made a body carrying both an entry
    # fault AND trailing bytes report `non_canonical_unclassified` in Python
    # while Rust reported the entry fault -- a live, measured divergence
    # (20 of the corpus's 88 pre-fix disagreements) that `contact_card`'s
    # strict (non-phase-dependent-tolerant) comparison does not excuse.
    # `MalformedCbor` is itself a `ValueError` subclass carrying its own
    # token ("malformed_cbor", never tolerated against anything) -- it must
    # propagate UNCHANGED, not be re-tokened as `wrong_type` by the catch
    # below, which exists for exactly one shape: a non-map top-level item.
    # `_scan_map_entries` can also raise `MalformedCbor` itself (a truncated
    # argument, a reserved additional-info, an unterminated indefinite map),
    # and that path is latent only because `walk_body` above already rejects
    # every such body first -- nothing asserts that overlap, so the catch is
    # scoped rather than relied on to stay unreachable.
    try:
        entries, _ = _scan_map_entries(data, 0)
    except MalformedCbor:
        raise
    except ValueError as e:
        raise CardWrongType(str(e)) from e

    decoded: dict[str, Any] = {}
    for (ks, ke), (vs, ve) in entries:
        kmaj, _, _, _ = _decode_head(data, ks)
        # A non-text key is a wrong TYPE, tested BEFORE the unknown-key test.
        # `card.rs` matches `Value::Text` first; the full-corpus measurement
        # found 39 inputs where this decoder called such a key an unknown
        # field (design §1.1).
        if kmaj != 3:
            raise CardWrongType(f"contact_card map key at offset {ks} is not a text string")
        key = cbor2.loads(data[ks:ke])
        # UNKNOWN-key test precedes the value read, same as `card.rs`'s
        # `match key.as_str() { .. _ => Err(UnknownField) }`: the wildcard
        # arm returns without ever calling a `take_*` on the value, so an
        # unknown key's value is never interpreted at all.
        if key not in KNOWN_CARD_KEYS:
            raise CardUnknownField(f"contact_card unknown field: {key!r}")
        value = cbor2.loads(data[vs:ve])
        # The value is checked the MOMENT its key is read, in wire order, and
        # a missing key is reported only after the loop -- `parse_card_map`'s
        # order.  Checking presence first made a body carrying both faults
        # name a different rule in each language.
        check_card_value(key, value)
        # DUPLICATE check runs AFTER the value check, not before -- the
        # INVERSE of the manifest's `Once::set` precedence (CLAUDE.md's #589
        # note), because the two decoders genuinely differ here. `card.rs`
        # writes every arm as `set_once(&mut slot, take_u8(v)?, KEY)?`: the
        # argument is evaluated (`take_u8(v)?`) BEFORE `set_once` ever tests
        # `slot.is_some()`, so a repeated key whose SECOND copy fails its own
        # type/length check reports that fault, not `DuplicateField`.
        # Checking `key in decoded` before reading the value answered
        # `duplicate_map_key` instead -- measured on all 10 keys.
        if key in decoded:
            raise CardDuplicateKey(f"contact_card repeats key {key!r}")
        decoded[key] = value

    # `card_version`'s presence, THEN its value, checked in that order,
    # before any other field's presence -- `parse_card_map`'s own sequence:
    # `card_version.ok_or(MissingField)?` then `if card_version != 1
    # { return InvalidVersion }`, both ahead of every other `.ok_or(..)` in
    # the struct literal. A wrong-VALUE `card_version` therefore outranks
    # another field's ABSENCE, the same way an ordinary entry-loop type
    # fault outranks it.
    if "card_version" not in decoded:
        raise CardMissingField("contact_card missing required field: 'card_version'")
    if decoded["card_version"] != 1:
        raise CardUnsupportedVersion(f"card_version must be 1, got {decoded['card_version']!r}")

    absent = first_missing_key_in_sorted_order(decoded, REQUIRED_CARD_FIELDS)
    if absent is not None:
        raise CardMissingField(f"contact_card missing required field: {absent!r}")

    # Canonical-input check
    reencoded = py_encode_contact_card(decoded)
    if reencoded != data:
        raise CardNonCanonical("contact_card is not in canonical CBOR form")

    return decoded


def py_encode_contact_card(card: dict) -> bytes:
    """Re-encode a parsed contact card dict to canonical CBOR.

    Mirrors card.rs::to_canonical_cbor: all 10 fields in a canonical map.
    Field order in the entry list doesn't matter; encode_canonical_map
    sorts by encoded key bytes.
    """
    entries: list[tuple[Any, Any]] = [
        ("card_version", card["card_version"]),
        ("contact_uuid", card["contact_uuid"]),
        ("display_name", card["display_name"]),
        ("x25519_pk", card["x25519_pk"]),
        ("ml_kem_768_pk", card["ml_kem_768_pk"]),
        ("ed25519_pk", card["ed25519_pk"]),
        ("ml_dsa_65_pk", card["ml_dsa_65_pk"]),
        ("created_at", card["created_at"]),
        ("self_sig_ed", card["self_sig_ed"]),
        ("self_sig_pq", card["self_sig_pq"]),
    ]
    return encode_canonical_map(entries)
