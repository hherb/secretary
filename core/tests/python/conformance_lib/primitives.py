"""§2.1 crypto primitives -- thin wrappers over the external libraries.

Every external-library call the conformance path makes goes through this
module, so a future swap (PyNaCl -> hand-rolled XChaCha, say) touches one
site. Third-party imports are LAZY, inside each function: the package's
top-level import graph stays stdlib-only, which is what lets
`--diff-replay` start without paying for crypto libraries it never calls.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# §2.1 Crypto primitives (thin wrappers over external libs)
# ---------------------------------------------------------------------------


def hkdf_sha256(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA-256 extract-and-expand.

    Mirrors `crypto::kdf::hkdf_sha256_extract_and_expand` (kdf.rs:267).
    """
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    kdf = HKDF(algorithm=SHA256(), length=length, salt=salt, info=info)
    return kdf.derive(ikm)


def aead_decrypt(key: bytes, nonce: bytes, aad: bytes, ct_with_tag: bytes) -> bytes:
    """XChaCha20-Poly1305-IETF decrypt.

    `key` is 32 bytes, `nonce` is 24 bytes, `ct_with_tag` is
    `ct || tag(16)`. Mirrors `crypto::aead::decrypt` (aead.rs:96)
    which is what `crypto::kem::decap` and the manifest / block body
    AEAD calls use.

    Raises ValueError on auth-tag failure (the AEAD security model
    collapses every "wrong input" case into a single failure mode --
    same discipline as the Rust side's `AeadError::Decryption`).
    """
    from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt
    from nacl.exceptions import CryptoError

    if len(key) != 32:
        raise ValueError(f"AEAD key length: {len(key)} (expected 32)")
    if len(nonce) != 24:
        raise ValueError(f"AEAD nonce length: {len(nonce)} (expected 24)")
    if len(ct_with_tag) < 16:
        raise ValueError("AEAD ct_with_tag shorter than 16-byte tag")
    try:
        return crypto_aead_xchacha20poly1305_ietf_decrypt(
            ct_with_tag, aad, nonce, key
        )
    except CryptoError as e:
        raise ValueError(f"AEAD decryption failed: {e}") from e


def aead_encrypt(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
    """XChaCha20-Poly1305-IETF encrypt -- inverse of `aead_decrypt`.

    Returns `ct || tag(16)`. Same primitive (`crypto_aead_xchacha20poly1305_ietf`)
    the decrypt path uses; reused here for the §5a device-slot enrol round-trip
    so the clean-room proof never reaches for a second AEAD construction.
    """
    from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt

    if len(key) != 32:
        raise ValueError(f"AEAD key length: {len(key)} (expected 32)")
    if len(nonce) != 24:
        raise ValueError(f"AEAD nonce length: {len(nonce)} (expected 24)")
    return crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)


def x25519_dh(sk: bytes, pk: bytes) -> bytes:
    """X25519 Diffie-Hellman: scalar `sk` * point `pk`.

    Returns the 32-byte shared secret. `cryptography`'s X25519 API
    works on opaque key objects; we round-trip raw bytes so this
    function stays a pure transform.
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )

    priv = X25519PrivateKey.from_private_bytes(sk)
    pub = X25519PublicKey.from_public_bytes(pk)
    return priv.exchange(pub)


def ml_kem_768_decap(sk: bytes, ct: bytes) -> bytes:
    """ML-KEM-768 decapsulation. Returns the 32-byte shared secret.

    The `pqcrypto` package names the operation `decrypt`/`encrypt`
    rather than `decap`/`encap`, but they're the FIPS-203 KEM ops --
    same construction as `core/src/crypto/kem.rs` calls via
    `ml_kem::kem::DecapsulationKey::decapsulate`.
    """
    from pqcrypto.kem import ml_kem_768

    return ml_kem_768.decrypt(sk, ct)


def ed25519_verify(pk: bytes, sig: bytes, message: bytes) -> bool:
    """Ed25519 verify. Returns True iff the signature is valid."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def ml_dsa_65_verify(pk: bytes, sig: bytes, message: bytes) -> bool:
    """ML-DSA-65 verify. Returns True iff the signature is valid.

    `pqcrypto.sign.ml_dsa_65.verify(public_key, message, signature)`
    returns True/False on a well-formed input pair (a tampered or
    invalid signature returns False — it does NOT raise), and raises
    `TypeError` / `ValueError` only when the inputs are mis-typed or
    wrong-length. The previous implementation discarded the return
    value and reported "no exception" as success, which silently
    accepted invalid signatures; the Ed25519 path is unaffected
    because `cryptography` raises `InvalidSignature` on bad sigs.

    We propagate the boolean and narrow the except to the two
    documented input-format exceptions, matching the Rust side's
    typed-error → bool collapse.
    """
    from pqcrypto.sign import ml_dsa_65

    try:
        return ml_dsa_65.verify(pk, message, sig)
    except (TypeError, ValueError):
        return False


def argon2id_raw(
    password: bytes,
    salt: bytes,
    *,
    memory_kib: int,
    iterations: int,
    parallelism: int,
    hash_len: int = 32,
) -> bytes:
    """Argon2id raw-hash wrapper.

    Mirrors `crypto::kdf::derive_master_kek` (kdf.rs:188): Argon2id
    algorithm, version 0x13 (1.3), output length `hash_len`. The
    parameter ordering matches `Argon2idParams` -- memory in KiB,
    iterations (= passes / time_cost), and parallelism (= lanes).
    """
    from argon2.low_level import Type, hash_secret_raw

    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=iterations,
        memory_cost=memory_kib,
        parallelism=parallelism,
        hash_len=hash_len,
        type=Type.ID,
        version=0x13,
    )


def blake3_keyed_16(key: bytes, data: bytes) -> bytes:
    """BLAKE3-keyed-hash truncated to 16 bytes -- §6.1 fingerprint."""
    import blake3

    return blake3.blake3(data, key=key).digest(16)


def blake3_256(data: bytes) -> bytes:
    """BLAKE3-256 of `data`. §4.2 block fingerprint."""
    import blake3

    return blake3.blake3(data).digest(32)
