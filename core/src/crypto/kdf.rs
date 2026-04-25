//! Key derivation: Argon2id (Master KEK, §3) and HKDF-SHA-256 (Recovery KEK
//! §4 and the hybrid-KEM combiner §7).
//!
//! Two flavours of derivation live here because they serve different threat
//! models:
//!
//! - **Argon2id** stretches a low-entropy human-chosen password into a
//!   uniformly distributed 256-bit key. The cost parameters are deliberately
//!   expensive — see `docs/crypto-design.md` §1.2 and §3.
//! - **HKDF-SHA-256** *expands* high-entropy input keying material into one
//!   or more derived keys. It is *not* a password hash and intentionally
//!   does no stretching: the recovery mnemonic already carries 256 bits of
//!   CSPRNG entropy (§4), and the hybrid-KEM combiner output (§7) is the
//!   concatenation of two algorithm shared secrets.
//!
//! ## Domain-separation tags
//!
//! All KDF / signature / AEAD constructions in v1 are domain-separated by
//! ASCII tags listed in `docs/crypto-design.md` §1.3. They live as `pub const`
//! byte strings in this module so other modules import them by name rather
//! than re-typing string literals.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::crypto::secret::{SecretBytes, Sensitive};

// ---------------------------------------------------------------------------
// Domain-separation tags (§1.3 of crypto-design.md).
//
// These are the exact ASCII byte strings, no NUL terminator, no length
// prefix. They are concatenated directly with the bytes they
// domain-separate.
// ---------------------------------------------------------------------------

/// HKDF info for Recovery KEK derivation (§4).
pub const TAG_RECOVERY_KEK: &[u8] = b"secretary-v1-recovery-kek";

/// AEAD AAD prefix for wrapping the Identity Block Key under the Master KEK (§5).
pub const TAG_ID_WRAP_PW: &[u8] = b"secretary-v1-id-wrap-pw";

/// AEAD AAD prefix for wrapping the Identity Block Key under the Recovery KEK (§5).
pub const TAG_ID_WRAP_REC: &[u8] = b"secretary-v1-id-wrap-rec";

/// AEAD AAD prefix for the Identity Bundle ciphertext (§5).
pub const TAG_ID_BUNDLE: &[u8] = b"secretary-v1-id-bundle";

/// HKDF salt for the hybrid-KEM combiner (§7).
pub const TAG_HYBRID_KEM: &[u8] = b"secretary-v1-hybrid-kem";

/// BLAKE3 prefix for the hybrid-KEM transcript hash (§7).
pub const TAG_HYBRID_KEM_TRANSCRIPT: &[u8] = b"secretary-v1-hybrid-kem-transcript";

/// HKDF info for deriving the per-recipient block-key wrap key from the
/// hybrid-KEM combiner output (§7).
pub const TAG_BLOCK_CONTENT_KEY_WRAP: &[u8] = b"secretary-v1-block-content-key-wrap";

/// AEAD AAD prefix for wrapping a Block Content Key for one recipient (§7).
pub const TAG_BLOCK_KEY_WRAP: &[u8] = b"secretary-v1-block-key-wrap";

/// Signature message prefix for hybrid signature on a block file (§8).
pub const TAG_BLOCK_SIG: &[u8] = b"secretary-v1-block-sig";

/// Signature message prefix for hybrid signature on a manifest file (§8).
pub const TAG_MANIFEST_SIG: &[u8] = b"secretary-v1-manifest-sig";

/// Signature message prefix for the self-signature on a Contact Card (§6).
pub const TAG_CARD_SIG: &[u8] = b"secretary-v1-card-sig";

/// BLAKE3 keyed-hash key source for Contact Card fingerprints (§6.1). The
/// fingerprint key itself is `SHA-256(TAG_FINGERPRINT)[..32]`, computed at
/// the call site.
pub const TAG_FINGERPRINT: &[u8] = b"secretary-v1-fingerprint";

/// Maximum HKDF-SHA-256 output length, in bytes. RFC 5869: `255 * HashLen`,
/// which for SHA-256 is `255 * 32 = 8160`. (§14.)
pub const HKDF_SHA256_MAX_OUTPUT: usize = 8160;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors returned by KDF operations.
#[derive(Debug, thiserror::Error)]
pub enum KdfError {
    /// Argon2id parameters were below the v1 floors (memory ≥ 64 MiB,
    /// iterations ≥ 1, parallelism ≥ 1).
    #[error("Argon2id parameters below v1 floors")]
    ParamsBelowV1Floor,
}

// ---------------------------------------------------------------------------
// Argon2id parameters (§1.2, §3)
// ---------------------------------------------------------------------------

/// Argon2id cost parameters. The defaults for suite v1 are
/// [`Argon2idParams::V1_DEFAULT`] (256 MiB / 3 iterations / parallelism 1).
///
/// `serde` derives are present because these parameters are recorded in
/// `vault.toml` so that a vault is portable across devices regardless of
/// which device created it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Argon2idParams {
    /// Memory cost in KiB. v1 floor is 65536 (64 MiB); v1 default is
    /// 262144 (256 MiB).
    pub memory_kib: u32,
    /// Number of passes. v1 floor is 1; v1 default is 3.
    pub iterations: u32,
    /// Parallelism (lanes). v1 floor and default are both 1.
    pub parallelism: u32,
}

impl Argon2idParams {
    /// v1 default parameters: 256 MiB memory, 3 iterations, 1 lane (§1.2).
    pub const V1_DEFAULT: Self = Self {
        memory_kib: 262144,
        iterations: 3,
        parallelism: 1,
    };

    /// v1 floor on memory cost: 64 MiB. Memory may be reduced to this floor
    /// on memory-constrained devices but never lower (§1.2).
    pub const V1_MIN_MEMORY_KIB: u32 = 65536;

    /// Construct without v1-floor validation. Use this when reading
    /// parameters from an existing vault (which may have been written by an
    /// older spec revision with different floors), when porting to v2, or in
    /// tests that need fast parameters.
    #[must_use]
    pub const fn new(memory_kib: u32, iterations: u32, parallelism: u32) -> Self {
        Self {
            memory_kib,
            iterations,
            parallelism,
        }
    }

    /// Construct, enforcing the v1 floors (memory ≥ 64 MiB, iterations ≥ 1,
    /// parallelism ≥ 1). Use for parameters that will be persisted into a
    /// new v1 vault.
    pub fn try_new_v1(
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
    ) -> Result<Self, KdfError> {
        if memory_kib < Self::V1_MIN_MEMORY_KIB || iterations < 1 || parallelism < 1 {
            return Err(KdfError::ParamsBelowV1Floor);
        }
        Ok(Self::new(memory_kib, iterations, parallelism))
    }
}

// ---------------------------------------------------------------------------
// Master KEK (§3) and Recovery KEK (§4)
// ---------------------------------------------------------------------------

/// Derive the 32-byte Master KEK from a password and salt under the given
/// Argon2id parameters (§3). Argon2 algorithm = Argon2id, version = 0x13.
///
/// Panics only if Argon2id rejects the parameters internally — which cannot
/// happen for valid `Argon2idParams` constructed via [`Argon2idParams::new`]
/// or [`Argon2idParams::try_new_v1`] because their u32 ranges sit safely
/// inside the underlying crate's accepted bounds.
#[must_use]
pub fn derive_master_kek(
    password: &SecretBytes,
    salt: &[u8; 32],
    params: &Argon2idParams,
) -> Sensitive<[u8; 32]> {
    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .expect("Argon2idParams already satisfy crate-level bounds");

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(password.expose(), salt, &mut out)
        .expect("hash_password_into only fails on invalid params or output length");
    Sensitive::new(out)
}

/// Derive the 32-byte Recovery KEK from BIP-39 mnemonic entropy (§4).
///
/// Per spec: HKDF-SHA-256 with `salt = [0u8; 32]` and
/// `info = "secretary-v1-recovery-kek"`. The mnemonic itself carries 256
/// bits of CSPRNG entropy, so no password stretching is performed
/// (Argon2id would only slow legitimate use here).
#[must_use]
pub fn derive_recovery_kek(entropy: &Sensitive<[u8; 32]>) -> Sensitive<[u8; 32]> {
    let salt = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(&salt), entropy.expose());
    let mut out = [0u8; 32];
    hk.expand(TAG_RECOVERY_KEK, &mut out)
        .expect("32 bytes is well within HKDF-SHA-256 output limits");
    Sensitive::new(out)
}

// ---------------------------------------------------------------------------
// HKDF-SHA-256 primitive (§7 hybrid-KEM combiner)
// ---------------------------------------------------------------------------

/// HKDF-SHA-256 extract-and-expand. Used by §7 to derive a per-recipient
/// block-key wrap key from the concatenated classical/PQ shared secrets.
///
/// Returns plain bytes — the caller wraps in [`Sensitive`] or [`SecretBytes`]
/// when the output is sensitive (it usually is, in this codebase). This
/// asymmetry is deliberate: the named [`derive_master_kek`] and
/// [`derive_recovery_kek`] return `Sensitive` because their semantics are
/// fixed; this primitive is composed inside larger constructions that
/// already manage their own zeroization boundary.
///
/// # Panics
///
/// Panics if `len` exceeds [`HKDF_SHA256_MAX_OUTPUT`] (8160 bytes per
/// RFC 5869). The hybrid-KEM combiner asks for 32 bytes; this is a
/// programmer-error guard, not a runtime input check.
#[must_use]
pub fn hkdf_sha256_extract_and_expand(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    len: usize,
) -> Vec<u8> {
    assert!(
        len <= HKDF_SHA256_MAX_OUTPUT,
        "HKDF-SHA-256 output capped at {HKDF_SHA256_MAX_OUTPUT} bytes (RFC 5869)",
    );
    // Per RFC 5869 §2.2: passing salt = empty is equivalent to salt = HashLen
    // zero bytes. The hkdf crate accepts `Some(&[])` and handles this
    // internally; we always pass `Some(salt)` so the caller controls the
    // distinction explicitly.
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = vec![0u8; len];
    hk.expand(info, &mut out)
        .expect("output length already validated against HKDF-SHA-256 maximum");
    out
}
