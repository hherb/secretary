"""Strict contact-card decode/encode pair behind `--diff-replay`'s
`contact_card` target.

This decoder has no `unknown` bag at all -- it rejects every unrecognised
key outright -- so its duplicate-key protection comes from its own
re-encode-and-compare rather than from span-list checks.
"""

from __future__ import annotations

from typing import Any

from conformance_lib.canonical import encode_canonical_map

def py_decode_contact_card(data: bytes) -> dict:
    """Strict §6 contact card decoder matching card.rs::from_canonical_cbor.

    Validates:
    - Top-level item is a CBOR map with text-string keys.
    - No unknown keys (card.rs returns CborDecode error on unknown fields).
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

    try:
        decoded = cbor2.loads(data)
    except cbor2.CBORDecodeError as e:
        raise ValueError(f"contact_card CBOR decode: {e}") from e

    if not isinstance(decoded, dict):
        raise ValueError("contact_card top-level CBOR is not a map")

    # Duplicate-key detection: `contact_card` has no forward-compat
    # `unknown` bag at all (every unrecognised key is rejected outright,
    # below) and its own re-encode-and-compare check further down
    # collapses-then-mismatches a duplicate KNOWN key just as a dedicated
    # duplicate-key scan would. A separate `_check_no_duplicate_keys` call
    # here was a no-op (#592) and has been removed.

    KNOWN_CARD_KEYS = {
        "card_version", "contact_uuid", "display_name", "x25519_pk",
        "ml_kem_768_pk", "ed25519_pk", "ml_dsa_65_pk", "created_at",
        "self_sig_ed", "self_sig_pq",
    }
    for k in decoded:
        if k not in KNOWN_CARD_KEYS:
            raise ValueError(f"contact_card unknown field: {k!r}")

    REQUIRED_CARD_FIELDS = KNOWN_CARD_KEYS  # all 10 are required
    for f in REQUIRED_CARD_FIELDS:
        if f not in decoded:
            raise KeyError(f"contact_card missing required field: {f!r}")

    cv = decoded["card_version"]
    if not isinstance(cv, int) or cv != 1:
        raise ValueError(f"card_version must be 1, got {cv!r}")

    cu = decoded["contact_uuid"]
    if not isinstance(cu, bytes) or len(cu) != 16:
        raise ValueError("contact_uuid must be 16-byte bstr")

    dn = decoded["display_name"]
    if not isinstance(dn, str):
        raise ValueError("display_name must be tstr")

    x25519 = decoded["x25519_pk"]
    if not isinstance(x25519, bytes) or len(x25519) != 32:
        raise ValueError("x25519_pk must be 32-byte bstr")

    mlkem = decoded["ml_kem_768_pk"]
    if not isinstance(mlkem, bytes) or len(mlkem) != 1184:
        raise ValueError(f"ml_kem_768_pk must be 1184-byte bstr, got {len(mlkem) if isinstance(mlkem, bytes) else type(mlkem).__name__}")

    ed = decoded["ed25519_pk"]
    if not isinstance(ed, bytes) or len(ed) != 32:
        raise ValueError("ed25519_pk must be 32-byte bstr")

    mldsa = decoded["ml_dsa_65_pk"]
    if not isinstance(mldsa, bytes) or len(mldsa) != 1952:
        raise ValueError(f"ml_dsa_65_pk must be 1952-byte bstr, got {len(mldsa) if isinstance(mldsa, bytes) else type(mldsa).__name__}")

    cat = decoded["created_at"]
    if not isinstance(cat, int) or cat < 0:
        raise ValueError(f"created_at must be uint, got {cat!r}")

    sig_ed = decoded["self_sig_ed"]
    if not isinstance(sig_ed, bytes) or len(sig_ed) != 64:
        raise ValueError("self_sig_ed must be 64-byte bstr")

    sig_pq = decoded["self_sig_pq"]
    if not isinstance(sig_pq, bytes) or len(sig_pq) != 3309:
        raise ValueError(f"self_sig_pq must be 3309-byte bstr, got {len(sig_pq) if isinstance(sig_pq, bytes) else type(sig_pq).__name__}")

    # Canonical-input check
    reencoded = py_encode_contact_card(decoded)
    if reencoded != data:
        raise ValueError("contact_card is not in canonical CBOR form")

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
