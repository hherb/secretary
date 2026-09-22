"""§8 contact-card parse + hybrid-verify.

Verification is Ed25519 AND ML-DSA-65 -- both must hold. The card's
fingerprint is re-derived from its canonical bytes and cross-checked
against its filename.
"""

from __future__ import annotations

from typing import Any

from conformance_lib.canonical import encode_canonical_map, encode_pk_bundle
from conformance_lib.codec.card import FIXED_BYTE_LENGTHS, MAX_DISPLAY_NAME_BYTES
from conformance_lib.codec.integer_rules import is_integer
from conformance_lib.constants import TAG_CARD_SIG
from conformance_lib.cursor import ParseError
from conformance_lib.derivations import card_fingerprint, hybrid_verify

# crypto-design §6's `display_name` bound and fixed field widths, IMPORTED
# from `codec/card.py` rather than respelled. This reader is a separate §8
# parse+verify path from that strict `--diff-replay` decoder, but a §6 MUST
# binds every conformant card reader, this one included -- "wire/ is a
# different reader" was already rejected once as an excuse for the same gap
# on `display_name` (#669, fixed in the #679 review) and is not available
# here either.
#
# The bare `_MAX_DISPLAY_NAME_BYTES = 4096` this replaces was a THIRD
# spelling of the bound, added in the same slice whose `codec/card.py` says
# in as many words that a third spelling is a third thing to keep in step
# (#698 review). There is no layering reason for a copy: this module already
# imports `codec.integer_rules`, and `wire/golden_vault_verify.py` imports
# `codec.manifest_decode`.

# ---------------------------------------------------------------------------
# §2.5 Contact-card parse + verify
# ---------------------------------------------------------------------------


def parse_and_verify_card(card_bytes: bytes) -> dict[str, Any]:
    """Parse a canonical-CBOR Contact Card and verify its self-signature.

    Returns a dict carrying the parsed fields plus the recomputed
    16-byte fingerprint. Raises ParseError on any structural or
    cryptographic failure.
    """
    import cbor2

    try:
        decoded = cbor2.loads(card_bytes)
    except cbor2.CBORDecodeError as e:
        raise ParseError(f"card CBOR decode failed: {e}") from e
    if not isinstance(decoded, dict):
        raise ParseError("card top-level CBOR is not a map")

    required = {
        "card_version",
        "contact_uuid",
        "display_name",
        "x25519_pk",
        "ml_kem_768_pk",
        "ed25519_pk",
        "ml_dsa_65_pk",
        "created_at",
        "self_sig_ed",
        "self_sig_pq",
    }
    missing = required - set(decoded.keys())
    if missing:
        raise ParseError(f"card missing fields: {sorted(missing)}")
    # `is_integer` BEFORE the value comparison, and a type check on
    # `created_at`, which had none at all. Python's `bool` subclasses `int`, so
    # `True != 1` is `False` and a CBOR `true` parsed here as v1 while
    # `identity/card.rs`'s `take_u8` matches `Value::Integer` alone and rejects
    # it. The same defect as #669's `codec/` sites, in the same two shapes:
    # a bare `!= 1` comparison (M1) and a position with no check at all (M2).
    if not is_integer(decoded["card_version"]) or decoded["card_version"] != 1:
        raise ParseError(f"card_version {decoded['card_version']!r}")
    if not is_integer(decoded["created_at"]) or decoded["created_at"] < 0:
        raise ParseError(f"created_at {decoded['created_at']!r}")
    # crypto-design §6: display_name is a tstr bounded at
    # `MAX_DISPLAY_NAME_BYTES`. Neither check existed on this path before
    # (#691, final whole-branch review, I7): `cbor2` alone would happily
    # decode any text-string length or hand back a non-`str` value for a
    # malformed `display_name`, so a golden vault carrying either was
    # accepted by a §8 card reader inside the one script that exists to
    # prove docs/ alone is sufficient to decrypt it.
    display_name = decoded["display_name"]
    if not isinstance(display_name, str):
        raise ParseError(f"display_name is not a text string: {display_name!r}")
    if len(display_name.encode("utf-8")) > MAX_DISPLAY_NAME_BYTES:
        raise ParseError(
            f"display_name exceeds the {MAX_DISPLAY_NAME_BYTES}-byte bound"
        )
    # §6's fixed-width byte strings. NONE of these was checked on this path
    # before (#698 review, C1), and for three of them nothing else on this
    # path checks them either: `contact_uuid`, `x25519_pk` and
    # `ml_kem_768_pk` are not consumed by `hybrid_verify`, so the signature
    # does not backstop them. `card.rs`'s `take_fixed_bytes::<N>` rejects a
    # wrong width; this reader ACCEPTED one, returning the decoded dict and a
    # pk_bundle to `golden_vault_verify.py` -- an acceptance divergence
    # inside the one script that exists to prove docs/ alone is sufficient.
    # Checked as one table rather than three fields: the three unbacked ones
    # are unbacked by today's call sites, which is the posture this repo
    # retires rather than relies on.
    for _key, _want in sorted(FIXED_BYTE_LENGTHS.items()):
        _value = decoded[_key]
        if not isinstance(_value, bytes):
            raise ParseError(f"{_key} is not a byte string: {type(_value).__name__}")
        if len(_value) != _want:
            raise ParseError(
                f"{_key} must be {_want} bytes, got {len(_value)}"
            )

    # Recompute the canonical bytes that the self-signature commits to
    # (§6 -- everything except the two self_sig_* fields).
    pre_sig_entries = [
        ("card_version", decoded["card_version"]),
        ("contact_uuid", decoded["contact_uuid"]),
        ("display_name", decoded["display_name"]),
        ("x25519_pk", decoded["x25519_pk"]),
        ("ml_kem_768_pk", decoded["ml_kem_768_pk"]),
        ("ed25519_pk", decoded["ed25519_pk"]),
        ("ml_dsa_65_pk", decoded["ml_dsa_65_pk"]),
        ("created_at", decoded["created_at"]),
    ]
    signed_bytes = encode_canonical_map(pre_sig_entries)

    ok, reason = hybrid_verify(
        TAG_CARD_SIG,
        signed_bytes,
        decoded["self_sig_ed"],
        decoded["self_sig_pq"],
        decoded["ed25519_pk"],
        decoded["ml_dsa_65_pk"],
    )
    if not ok:
        raise ParseError(f"card self-signature: {reason}")

    fp = card_fingerprint(card_bytes)
    return {
        "decoded": decoded,
        "fingerprint": fp,
        "pk_bundle": encode_pk_bundle(
            decoded["x25519_pk"],
            decoded["ml_kem_768_pk"],
            decoded["ed25519_pk"],
            decoded["ml_dsa_65_pk"],
        ),
    }
