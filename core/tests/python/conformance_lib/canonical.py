"""§2.3 canonical-CBOR encoding helpers.

`encode_canonical_map` sorts by (key length, key bytes) per
crypto-design.md §6.2 rule 1. `encode_canonical_map_raw` does the same over
already-encoded value bytes, which is what the forward-compat `unknown`
subtree paths need: a subtree must be re-emitted VERBATIM, so its bytes can
never be round-tripped through a Python object.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# §2.3 Canonical CBOR encoding helpers
# ---------------------------------------------------------------------------


def _canonical_key_sort(entries: list[tuple[Any, Any]]) -> list[tuple[Any, Any]]:
    """Sort `(key, value)` pairs by their canonical-CBOR-encoded key
    bytes. RFC 8949 §4.2.1 deterministic-encoding rule.
    """
    import cbor2

    return sorted(entries, key=lambda kv: cbor2.dumps(kv[0], canonical=True))


def encode_canonical_map(entries: list[tuple[Any, Any]]) -> bytes:
    """Encode `entries` as a canonical CBOR map.

    `cbor2.dumps(..., canonical=True)` already emits map keys sorted
    by their canonical encoded form for `dict` inputs, BUT we need to
    feed an *ordered* dict so equal keys never collide. We sort
    ourselves and then build a dict (Python 3.7+ preserves insertion
    order); cbor2 then walks that dict in order and emits the same
    bytes.
    """
    import cbor2

    sorted_entries = _canonical_key_sort(entries)
    d: dict[Any, Any] = {}
    for k, v in sorted_entries:
        if k in d:
            raise ValueError(f"duplicate canonical CBOR key: {k!r}")
        d[k] = v
    return cbor2.dumps(d, canonical=True)


def encode_canonical_map_raw(entries: list[tuple[str, bytes]]) -> bytes:
    """Encode a canonical CBOR map from PRE-ENCODED value bytes.

    `encode_canonical_map` cannot serve this: it builds a `dict` and hands
    it to `cbor2.dumps(..., canonical=True)`, which re-sorts every nested
    map.  A retained forward-compat subtree must be emitted EXACTLY as it
    arrived (§4.2 part 1), so its bytes are spliced rather than re-encoded.

    Keys are text strings sorted by RFC 8949 §4.2.1 order -- length first,
    then bytewise -- computed on the encoded key, which for a text key is
    equivalent to `(len(utf8), utf8)`.
    """
    import cbor2

    encoded = [(cbor2.dumps(k), v) for k, v in entries]
    encoded.sort(key=lambda kv: (len(kv[0]), kv[0]))

    n = len(encoded)
    # RFC 8949 §3.1: major type 5 (map) head byte is 0xA0 | additional-info,
    # with the shortest-form encodings for the entry count `n` (§4.2.1).
    if n < 24:
        head = bytes([0xA0 | n])
    elif n < 0x100:
        head = bytes([0xB8, n])
    elif n < 0x10000:
        head = bytes([0xB9]) + n.to_bytes(2, "big")
    else:
        head = bytes([0xBA]) + n.to_bytes(4, "big")

    out = bytearray(head)
    for k, v in encoded:
        out += k
        out += v
    return bytes(out)


def encode_pk_bundle(
    x25519_pk: bytes,
    ml_kem_768_pk: bytes,
    ed25519_pk: bytes,
    ml_dsa_65_pk: bytes,
) -> bytes:
    """Canonical-CBOR pk bundle as per `card::pk_bundle_bytes`
    (card.rs:228-249). Map with the four §6 pk-field text keys.
    """
    return encode_canonical_map(
        [
            ("x25519_pk", x25519_pk),
            ("ml_kem_768_pk", ml_kem_768_pk),
            ("ed25519_pk", ed25519_pk),
            ("ml_dsa_65_pk", ml_dsa_65_pk),
        ]
    )
