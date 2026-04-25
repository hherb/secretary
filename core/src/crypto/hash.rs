//! Hash function wrappers.
//!
//! - **BLAKE3**: general-purpose hashing and the keyed-hash mode used by §6.1
//!   (Contact Card fingerprint) and §7 (hybrid-KEM transcript).
//! - **SHA-3-256**: kept available because some normative spec layers ask for
//!   it explicitly.
//! - **SHA-256**: only because HKDF-SHA-256 (see [`crate::crypto::kdf`])
//!   instantiates over it. Exposing it as a typed wrapper here keeps the KDF
//!   module focused on key derivation rather than primitive plumbing.
//!
//! Hash *outputs* are not secret material — two equal hashes can be compared
//! with `==`; no constant-time comparison is needed and no `Sensitive` wrapper
//! is used.

use sha2::Digest as _;

/// Full 32-byte BLAKE3 output.
///
/// `Copy` is fine: this is a hash digest, not a key. The newtype exists so
/// that fingerprint code reads `Blake3Hash` rather than `[u8; 32]` and so the
/// shape of an API surface is self-documenting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Blake3Hash([u8; 32]);

impl Blake3Hash {
    /// Borrow the raw 32 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Plain BLAKE3 hash of `data`.
#[must_use]
pub fn hash(data: &[u8]) -> Blake3Hash {
    Blake3Hash(*blake3::hash(data).as_bytes())
}

/// Keyed BLAKE3 hash. Used by:
///   - §6.1 Contact Card fingerprint (key derived from a SHA-256 of a tag);
///   - §7 hybrid-KEM transcript hashing.
#[must_use]
pub fn keyed_hash(key: &[u8; 32], data: &[u8]) -> Blake3Hash {
    Blake3Hash(*blake3::keyed_hash(key, data).as_bytes())
}

/// SHA-3-256 of `data`. Returned as a plain `[u8; 32]` because SHA-3-256
/// outputs only appear inside transcripts in this protocol; they are not
/// passed around as standalone values.
#[must_use]
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// SHA-256 of `data`. Same reasoning as [`sha3_256`] for the lack of newtype.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}
