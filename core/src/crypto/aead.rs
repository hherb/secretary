//! XChaCha20-Poly1305 AEAD wrapper.
//!
//! XChaCha20-Poly1305 is the workhorse symmetric primitive in Secretary v1:
//! it AEAD-encrypts the Identity Bundle, the Manifest, every Block plaintext,
//! and every per-recipient Block Content Key wrap. The 24-byte XChaCha20
//! nonce is large enough that random nonces are safe (no birthday risk at
//! realistic message volumes), which is critical for our use case where
//! nonces are generated freshly per encryption.
//!
//! ## Ciphertext layout
//!
//! [`encrypt`] returns the ciphertext **with the 16-byte Poly1305 tag
//! appended**: `ct || tag`. [`decrypt`] expects the same layout. This matches
//! the byte-level format described in `docs/vault-format.md` and avoids
//! callers having to juggle a separate tag field.
//!
//! ## What this module deliberately does *not* do
//!
//! - It does not generate nonces. Callers pass a 24-byte nonce as input. The
//!   CSPRNG lives in a separate `rand` module (added in a later step). Keeping
//!   this module deterministic makes it trivially testable from KATs.
//! - It does not hash, derive keys, or read AAD/key material from any source
//!   other than its parameters. AEAD here is a leaf primitive.
//!
//! ## Caller-side nonce generation idiom
//!
//! Every production call site that draws a fresh nonce calls the
//! [`random_nonce`] helper:
//!
//! ```ignore
//! let aead_nonce = aead::random_nonce(rng);
//! aead::encrypt(&key, &aead_nonce, &aad, plaintext)?;
//! ```
//!
//! Centralising the `[0u8; 24]; rng.fill_bytes(...)` pattern keeps the
//! buffer-allocation literal out of every call site, both for readability
//! and because static analyzers (e.g. CodeQL's
//! `rust/hard-coded-cryptographic-value`) pattern-match the literal as a
//! suspected hardcoded nonce when it appears next to a `nonce` identifier
//! — even though the bytes are overwritten by the CSPRNG before any
//! cryptographic primitive observes the buffer.
//!
//! Nonces are public values by design (they ride along with the ciphertext
//! on disk and over the wire). Their only security requirement is "never
//! reuse the same `(key, nonce)` pair", which is satisfied by drawing them
//! from a CSPRNG with a 192-bit space (no birthday-bound risk at realistic
//! volumes).
//!
//! What WOULD be a bug, by contrast:
//!
//! - `aead::encrypt(&key, &[0u8; 24], …)` — passing a literal zero-nonce
//!   directly to `encrypt`. That's a constant nonce reused across calls,
//!   which collapses XChaCha20-Poly1305's confidentiality and integrity
//!   guarantees on the second call under the same key.
//! - A nonce drawn from a *deterministic* RNG outside `#[cfg(test)]` —
//!   tests use `ChaCha20Rng::from_seed([0u8; 32])` for reproducibility, but
//!   production paths must call [`random_nonce`] with `OsRng`.
//!
//! Audit recipe: `rg 'aead::encrypt|aead::decrypt' core/src/ --type rust`
//! and confirm every encrypt call site sources its nonce from
//! `aead::random_nonce`. Decoder paths use `try_into()` to extract the
//! nonce from on-disk envelope bytes; that's not a nonce *generation* call
//! site and the input is bounded by an explicit length check above.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand_core::{CryptoRng, RngCore};

use crate::crypto::secret::{SecretBytes, Sensitive};

/// 256-bit symmetric key for XChaCha20-Poly1305. Wrapped in [`Sensitive`] so
/// it zeroizes on drop and never shows up in `Debug` output.
pub type AeadKey = Sensitive<[u8; 32]>;

/// 192-bit XChaCha20 nonce.
pub type AeadNonce = [u8; 24];

/// Poly1305 authentication tag length, in bytes. The tag is appended to the
/// ciphertext by [`encrypt`].
pub const AEAD_TAG_LEN: usize = 16;

/// Draw a fresh 24-byte XChaCha20 nonce from a cryptographic RNG.
///
/// This is the **sole** production source of AEAD nonces. Centralising the
/// pattern keeps the `[0u8; 24]` stack-buffer literal out of every encrypt
/// call site — both for readability and because static analyzers (e.g.
/// CodeQL's `rust/hard-coded-cryptographic-value`) flag the literal as a
/// suspected hardcoded nonce when it appears next to a `nonce` identifier,
/// even though the bytes are overwritten by `fill_bytes` before return.
///
/// The caller is responsible for never reusing a returned nonce with the
/// same key — `OsRng` makes accidental reuse astronomically unlikely
/// (24-byte random nonce → 2^96 collisions before expected reuse).
#[must_use]
pub fn random_nonce(rng: &mut (impl RngCore + CryptoRng)) -> AeadNonce {
    let mut nonce: AeadNonce = [0u8; 24];
    rng.fill_bytes(&mut nonce);
    nonce
}

/// Errors returned by AEAD operations.
///
/// Decryption tag failure does not distinguish "wrong key", "wrong nonce",
/// "wrong AAD", or "tampered ciphertext" — all are reported uniformly as
/// [`AeadError::Decryption`]. This is deliberate and matches the AEAD
/// security model: the recipient learns *that* authentication failed, not
/// *which* input was off, because that would leak information to an
/// attacker probing the system.
#[derive(Debug, thiserror::Error)]
pub enum AeadError {
    /// The provided key, nonce, or output slice had the wrong length. (The
    /// public API of this module enforces lengths via fixed-size types, so
    /// this variant exists mostly for forward compatibility — e.g. if a
    /// future caller takes a slice from the wire and routes it here.)
    #[error("invalid key, nonce, or buffer length")]
    InvalidLength,

    /// AEAD verification failed. Could mean wrong key, wrong nonce, wrong
    /// AAD, tampered ciphertext, or truncation. All reported the same way
    /// on purpose.
    #[error("AEAD decryption failed")]
    Decryption,
}

/// Encrypt `plaintext` under `key` with `nonce` and authenticated additional
/// data `aad`. Returns `ct || tag` (ciphertext concatenated with the 16-byte
/// Poly1305 tag).
///
/// `aad` is authenticated but not encrypted, and must be supplied verbatim
/// to [`decrypt`] for verification to succeed.
pub fn encrypt(
    key: &AeadKey,
    nonce: &AeadNonce,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let cipher = XChaCha20Poly1305::new(key.expose().into());
    let xnonce = XNonce::from_slice(nonce);
    cipher
        .encrypt(
            xnonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        // The underlying `aead::Error` type is intentionally opaque; on the
        // encrypt path it can only fail on absurd input lengths, and we map
        // it to InvalidLength rather than Decryption.
        .map_err(|_| AeadError::InvalidLength)
}

/// Decrypt `ciphertext_with_tag` (= `ct || tag`) under `key` with `nonce` and
/// `aad`. Returns the plaintext wrapped in [`SecretBytes`] — most things this
/// module decrypts (Identity Bundle, Block Content Keys, block plaintexts)
/// are themselves secret, so wrapping by default keeps the call sites honest.
///
/// Returns [`AeadError::Decryption`] on any authentication failure: wrong
/// key, wrong nonce, wrong AAD, tampered ciphertext, or truncated input.
pub fn decrypt(
    key: &AeadKey,
    nonce: &AeadNonce,
    aad: &[u8],
    ciphertext_with_tag: &[u8],
) -> Result<SecretBytes, AeadError> {
    if ciphertext_with_tag.len() < AEAD_TAG_LEN {
        // The aead crate would also reject this, but its error type is
        // opaque; fail fast with a more specific signal.
        return Err(AeadError::InvalidLength);
    }
    let cipher = XChaCha20Poly1305::new(key.expose().into());
    let xnonce = XNonce::from_slice(nonce);
    cipher
        .decrypt(
            xnonce,
            Payload {
                msg: ciphertext_with_tag,
                aad,
            },
        )
        .map(SecretBytes::new)
        .map_err(|_| AeadError::Decryption)
}
