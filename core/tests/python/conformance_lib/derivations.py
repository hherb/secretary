"""§2.2 domain-specific derivations built on `conformance_lib.primitives`.

Fingerprints, AAD composition, the §7 hybrid-KEM transcript, and the two
halves-must-both-hold constructions: `hybrid_decap` (X25519 XOR ML-KEM-768)
and `hybrid_verify` (Ed25519 AND ML-DSA-65).
"""

from __future__ import annotations

import hashlib

from conformance_lib.constants import BLOCK_CONTENT_KEY_LEN, TAG_BLOCK_CONTENT_KEY_WRAP, TAG_BLOCK_KEY_WRAP, TAG_FINGERPRINT, TAG_HYBRID_KEM, TAG_HYBRID_KEM_TRANSCRIPT
from conformance_lib.primitives import aead_decrypt, blake3_keyed_16, ed25519_verify, hkdf_sha256, ml_dsa_65_verify, ml_kem_768_decap, x25519_dh

# ---------------------------------------------------------------------------
# §2.2 Domain-specific helpers
# ---------------------------------------------------------------------------


def fingerprint_key() -> bytes:
    """The 32-byte BLAKE3-keyed-hash key used for §6.1 fingerprints.

    Mirrors `identity::fingerprint::fingerprint` (fingerprint.rs:45):
    `key = SHA-256(TAG_FINGERPRINT)`, truncated to 32 bytes. (SHA-256
    output IS 32 bytes, so the truncation is a no-op for SHA-256.)
    """
    return hashlib.sha256(TAG_FINGERPRINT).digest()


def card_fingerprint(canonical_card_bytes: bytes) -> bytes:
    """16-byte fingerprint of a fully-signed canonical-CBOR card."""
    return blake3_keyed_16(fingerprint_key(), canonical_card_bytes)


def compose_aad(tag: bytes, vault_uuid: bytes) -> bytes:
    """`tag || vault_uuid` -- the §3 / §5 AAD shape used by every
    identity-bundle AEAD call (`unlock::compose_aad`, mod.rs:279).
    """
    return tag + vault_uuid


def hybrid_kem_transcript(
    sender_fp: bytes,
    recipient_fp: bytes,
    ct_x: bytes,
    ct_pq: bytes,
) -> bytes:
    """§7 step 3 — BLAKE3 transcript hash binding both fingerprints
    and both ciphertexts.

    Mirrors `crypto::kem::transcript` (kem.rs:206): sequential update
    with TAG_HYBRID_KEM_TRANSCRIPT || sender_fp || recipient_fp ||
    ct_x || ct_pq.
    """
    import blake3

    h = blake3.blake3()
    h.update(TAG_HYBRID_KEM_TRANSCRIPT)
    h.update(sender_fp)
    h.update(recipient_fp)
    h.update(ct_x)
    h.update(ct_pq)
    return h.digest(32)


def derive_wrap_key(
    ss_x: bytes,
    ss_pq: bytes,
    ct_x: bytes,
    ct_pq: bytes,
    sender_pk_bundle: bytes,
    recipient_pk_bundle: bytes,
    transcript_hash: bytes,
) -> bytes:
    """§7 steps 4-5 — HKDF-SHA-256 over the §7 IKM ordering.

    Mirrors `crypto::kem::derive_wrap_key` (kem.rs:233-273) bit-for-bit.
    The Rust order is normative (see kem.rs:225-227):

        salt = TAG_HYBRID_KEM
        ikm  = ss_x || ss_pq || ct_x || ct_pq
                     || sender_pk_bundle || recipient_pk_bundle
        info = TAG_BLOCK_CONTENT_KEY_WRAP || transcript_hash

    """
    ikm = (
        ss_x
        + ss_pq
        + ct_x
        + ct_pq
        + sender_pk_bundle
        + recipient_pk_bundle
    )
    info = TAG_BLOCK_CONTENT_KEY_WRAP + transcript_hash
    return hkdf_sha256(TAG_HYBRID_KEM, ikm, info, 32)


def hybrid_decap(
    *,
    ct_x: bytes,
    ct_pq: bytes,
    nonce_w: bytes,
    ct_w_with_tag: bytes,
    sender_fp: bytes,
    recipient_fp: bytes,
    sender_pk_bundle: bytes,
    recipient_pk_bundle: bytes,
    recipient_x_sk: bytes,
    recipient_pq_sk: bytes,
    block_uuid: bytes,
) -> bytes:
    """§7.1 hybrid decap. Returns the recovered 32-byte BCK.

    Mirrors `crypto::kem::decap` (kem.rs:408-468) -- both halves
    independently, then HKDF-combiner, then AEAD-unwrap with the
    transcript-and-block-uuid AAD (`build_aead_aad`, kem.rs:314-320).
    """
    ss_x = x25519_dh(recipient_x_sk, ct_x)
    ss_pq = ml_kem_768_decap(recipient_pq_sk, ct_pq)
    t = hybrid_kem_transcript(sender_fp, recipient_fp, ct_x, ct_pq)
    wrap_key = derive_wrap_key(
        ss_x, ss_pq, ct_x, ct_pq, sender_pk_bundle, recipient_pk_bundle, t
    )
    aad = TAG_BLOCK_KEY_WRAP + block_uuid + t
    pt = aead_decrypt(wrap_key, nonce_w, aad, ct_w_with_tag)
    if len(pt) != BLOCK_CONTENT_KEY_LEN:
        raise ValueError(
            f"BCK plaintext length {len(pt)} != {BLOCK_CONTENT_KEY_LEN}"
        )
    return pt


def hybrid_verify(
    role_tag: bytes,
    message: bytes,
    sig_ed: bytes,
    sig_pq: bytes,
    pk_ed: bytes,
    pk_pq: bytes,
) -> tuple[bool, str]:
    """§8 hybrid verify. *Both* primitives must succeed.

    Returns (ok, reason). On failure, `reason` names which half
    rejected so the FAIL diagnostic is specific (mirrors the Rust
    side's distinct `Ed25519VerifyFailed` / `MlDsa65VerifyFailed`
    variants -- sig.rs:225-249).
    """
    signed_msg = role_tag + message
    if not ed25519_verify(pk_ed, sig_ed, signed_msg):
        return False, "Ed25519 verify rejected"
    if not ml_dsa_65_verify(pk_pq, sig_pq, signed_msg):
        return False, "ML-DSA-65 verify rejected"
    return True, ""
