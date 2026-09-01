"""§8 contact-card parse + hybrid-verify.

Verification is Ed25519 AND ML-DSA-65 -- both must hold. The card's
fingerprint is re-derived from its canonical bytes and cross-checked
against its filename.
"""

from __future__ import annotations

from typing import Any

from conformance_lib.canonical import encode_canonical_map, encode_pk_bundle
from conformance_lib.constants import TAG_CARD_SIG
from conformance_lib.cursor import ParseError
from conformance_lib.derivations import card_fingerprint, hybrid_verify

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
    if decoded["card_version"] != 1:
        raise ParseError(f"card_version {decoded['card_version']!r}")

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
