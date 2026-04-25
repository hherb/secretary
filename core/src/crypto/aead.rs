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

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};

use crate::crypto::secret::{SecretBytes, Sensitive};

/// 256-bit symmetric key for XChaCha20-Poly1305. Wrapped in [`Sensitive`] so
/// it zeroizes on drop and never shows up in `Debug` output.
pub type AeadKey = Sensitive<[u8; 32]>;

/// 192-bit XChaCha20 nonce.
pub type AeadNonce = [u8; 24];

/// Poly1305 authentication tag length, in bytes. The tag is appended to the
/// ciphertext by [`encrypt`].
pub const AEAD_TAG_LEN: usize = 16;

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
        .encrypt(xnonce, Payload { msg: plaintext, aad })
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
