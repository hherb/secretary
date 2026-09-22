"""§8 contact-card parse + hybrid-verify.

Verification is Ed25519 AND ML-DSA-65 -- both must hold. The card's
fingerprint is re-derived from its canonical bytes and cross-checked
against its filename.
"""

from __future__ import annotations

from typing import Any

from conformance_lib.canonical import encode_canonical_map, encode_pk_bundle
from conformance_lib.codec.integer_rules import is_integer
from conformance_lib.constants import TAG_CARD_SIG
from conformance_lib.cursor import ParseError
from conformance_lib.derivations import card_fingerprint, hybrid_verify

# crypto-design §6's `display_name` bound. This reader is a separate §8
# parse+verify path from `codec/card.py`'s strict `--diff-replay` decoder
# (which carries its own copy, `codec.card.MAX_DISPLAY_NAME_BYTES`), but a
# §6 MUST binds every conformant card reader, this one included -- "wire/ is
# a different reader" was already rejected once as an excuse for the same
# gap on `display_name` (#669, fixed in the #679 review) and is not
# available here either.
_MAX_DISPLAY_NAME_BYTES = 4096

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
    # `_MAX_DISPLAY_NAME_BYTES`. Neither check existed on this path before
    # (#691, final whole-branch review, I7): `cbor2` alone would happily
    # decode any text-string length or hand back a non-`str` value for a
    # malformed `display_name`, so a golden vault carrying either was
    # accepted by a §8 card reader inside the one script that exists to
    # prove docs/ alone is sufficient to decrypt it.
    display_name = decoded["display_name"]
    if not isinstance(display_name, str):
        raise ParseError(f"display_name is not a text string: {display_name!r}")
    if len(display_name.encode("utf-8")) > _MAX_DISPLAY_NAME_BYTES:
        raise ParseError(
            f"display_name exceeds the {_MAX_DISPLAY_NAME_BYTES}-byte bound"
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
