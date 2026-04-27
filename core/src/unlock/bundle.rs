//! IdentityBundle plaintext (`docs/crypto-design.md` §5).
//!
//! The §5 record carries the four `(sk, pk)` pairs that constitute a user's
//! cryptographic identity, plus a 16-byte UUID, a display name, and a
//! creation timestamp (Unix milliseconds). The wire form is canonical CBOR
//! per §6.2 (RFC 8949 §4.2.1 deterministic encoding) — implemented in the
//! follow-up commit; this commit lands the struct and `generate`.
//!
//! ## ML-DSA-65 secret-key representation (deviation from §5)
//!
//! The §5 listing pins `ml_dsa_65_sk` at 4032 bytes, the FIPS 204 expanded
//! signing-key encoding. We instead store the 32-byte FIPS 204 seed (`xi` in
//! KeyGen_internal), matching what [`crate::crypto::sig`] returns from
//! [`crate::crypto::sig::generate_ml_dsa_65`] (and what the upstream
//! `ml-dsa` 0.1.0-rc.8 crate now considers canonical — the 4032-byte
//! encoding is `#[deprecated]` there). The two representations are
//! information-equivalent: the expanded form is a deterministic function of
//! the seed. See `crate::crypto::sig` module docs. This is a deliberate
//! departure from `docs/crypto-design.md` §5 wording; the §5 spec
//! antedates the upstream crate's seed-only direction. The on-disk byte
//! length for the `ml_dsa_65_sk` CBOR field is therefore 32 in this
//! implementation.

use core::fmt;

use rand_core::{CryptoRng, RngCore};

use crate::crypto::kem::{
    generate_ml_kem_768, generate_x25519, ML_KEM_768_PK_LEN, ML_KEM_768_SK_LEN, X25519_PK_LEN,
    X25519_SK_LEN,
};
use crate::crypto::secret::Sensitive;
use crate::crypto::sig::{
    generate_ed25519, generate_ml_dsa_65, ED25519_PK_LEN, ED25519_SK_LEN, ML_DSA_65_PK_LEN,
    ML_DSA_65_SEED_LEN,
};

// ---------------------------------------------------------------------------
// Constants (§14)
// ---------------------------------------------------------------------------

/// User UUID length, in bytes (§5).
pub const USER_UUID_LEN: usize = 16;

/// Re-export of [`crate::crypto::kem::X25519_SK_LEN`] for callers consuming
/// the bundle without pulling in the `kem` module directly.
pub const BUNDLE_X25519_SK_LEN: usize = X25519_SK_LEN;
/// Re-export of [`crate::crypto::kem::X25519_PK_LEN`].
pub const BUNDLE_X25519_PK_LEN: usize = X25519_PK_LEN;
/// Re-export of [`crate::crypto::kem::ML_KEM_768_SK_LEN`].
pub const BUNDLE_ML_KEM_768_SK_LEN: usize = ML_KEM_768_SK_LEN;
/// Re-export of [`crate::crypto::kem::ML_KEM_768_PK_LEN`].
pub const BUNDLE_ML_KEM_768_PK_LEN: usize = ML_KEM_768_PK_LEN;
/// Re-export of [`crate::crypto::sig::ED25519_SK_LEN`].
pub const BUNDLE_ED25519_SK_LEN: usize = ED25519_SK_LEN;
/// Re-export of [`crate::crypto::sig::ED25519_PK_LEN`].
pub const BUNDLE_ED25519_PK_LEN: usize = ED25519_PK_LEN;
/// ML-DSA-65 secret-key length as stored in the bundle, in bytes.
///
/// This is the FIPS 204 seed length (32), not the §5 spec's 4032-byte
/// expanded encoding. See module docs for the rationale.
pub const BUNDLE_ML_DSA_65_SK_LEN: usize = ML_DSA_65_SEED_LEN;
/// Re-export of [`crate::crypto::sig::ML_DSA_65_PK_LEN`].
pub const BUNDLE_ML_DSA_65_PK_LEN: usize = ML_DSA_65_PK_LEN;

// ---------------------------------------------------------------------------
// IdentityBundle
// ---------------------------------------------------------------------------

/// IdentityBundle plaintext per `docs/crypto-design.md` §5.
///
/// Carries the four `(sk, pk)` pairs of the v1 hybrid suite, plus the
/// 16-byte user UUID, a display name, and a creation timestamp.
///
/// Secret-key fields are wrapped in [`Sensitive`] so they zeroize on drop.
/// The bundle does not derive `Clone`, `Debug`, or `PartialEq`: cloning
/// would silently duplicate secret material; a derived `Debug` would leak
/// it (a manual redacted impl is provided below); equality is only ever
/// asked of test code, which compares exposed contents field-by-field.
pub struct IdentityBundle {
    /// 128-bit user UUID, the same bytes as `contact_uuid` on the §6
    /// Contact Card.
    pub user_uuid: [u8; USER_UUID_LEN],
    /// User-facing label. UTF-8; no length cap enforced here.
    pub display_name: String,
    /// X25519 secret key, 32 bytes.
    pub x25519_sk: Sensitive<[u8; X25519_SK_LEN]>,
    /// X25519 public key, 32 bytes.
    pub x25519_pk: [u8; X25519_PK_LEN],
    /// ML-KEM-768 secret (decapsulation) key, 2400 bytes (FIPS 203). Stored
    /// as `Sensitive<Vec<u8>>` because the upstream `ml-kem` type is
    /// runtime-sized via const generics.
    pub ml_kem_768_sk: Sensitive<Vec<u8>>,
    /// ML-KEM-768 public (encapsulation) key, 1184 bytes (FIPS 203).
    pub ml_kem_768_pk: Vec<u8>,
    /// Ed25519 secret key, 32 bytes.
    pub ed25519_sk: Sensitive<[u8; ED25519_SK_LEN]>,
    /// Ed25519 public key, 32 bytes.
    pub ed25519_pk: [u8; ED25519_PK_LEN],
    /// ML-DSA-65 signing-key seed, 32 bytes (FIPS 204 `xi`). Stored as
    /// `Sensitive<Vec<u8>>` for symmetry with [`Self::ml_kem_768_sk`] —
    /// the future suite-migration path will replace this with a different
    /// PQC scheme whose seed length may differ. See module docs for the
    /// deviation from §5's 4032-byte expanded encoding.
    pub ml_dsa_65_sk: Sensitive<Vec<u8>>,
    /// ML-DSA-65 public key, 1952 bytes (FIPS 204).
    pub ml_dsa_65_pk: Vec<u8>,
    /// Creation timestamp, Unix milliseconds. Encoded under the §5 CBOR key
    /// `"created_at"`; the struct field name is more descriptive of the unit.
    pub created_at_ms: u64,
}

/// Redacted debug representation. The four secret-key fields are sensitive;
/// the only externally observable structure is the public-key shapes,
/// metadata fields, and a `<redacted>` placeholder for each secret. Mirrors
/// the policy on [`crate::unlock::mnemonic::Mnemonic`] — a derived `Debug`
/// would defeat the zeroize-on-drop discipline by leaking through
/// formatting.
impl fmt::Debug for IdentityBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityBundle")
            .field("user_uuid", &self.user_uuid)
            .field("display_name", &self.display_name)
            .field("x25519_sk", &"<redacted>")
            .field("x25519_pk", &self.x25519_pk)
            .field("ml_kem_768_sk", &"<redacted>")
            .field("ml_kem_768_pk_len", &self.ml_kem_768_pk.len())
            .field("ed25519_sk", &"<redacted>")
            .field("ed25519_pk", &self.ed25519_pk)
            .field("ml_dsa_65_sk", &"<redacted>")
            .field("ml_dsa_65_pk_len", &self.ml_dsa_65_pk.len())
            .field("created_at_ms", &self.created_at_ms)
            .finish()
    }
}

/// Generate a fresh IdentityBundle using the provided CSPRNG.
///
/// Draws a fresh `user_uuid` and four keypairs (X25519, ML-KEM-768,
/// Ed25519, ML-DSA-65). The caller supplies `display_name` and
/// `created_at_ms`; both are cleartext public material in the §5 record.
///
/// In production, `rng` is `rand_core::OsRng` (per
/// `docs/crypto-design.md` §13). Tests pin determinism by passing a seeded
/// `ChaCha20Rng` instead.
pub fn generate(
    display_name: &str,
    created_at_ms: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> IdentityBundle {
    let mut user_uuid = [0u8; USER_UUID_LEN];
    rng.fill_bytes(&mut user_uuid);

    let (x25519_sk, x25519_pk) = generate_x25519(rng);
    let (ml_kem_768_sk_owned, ml_kem_768_pk_owned) = generate_ml_kem_768(rng);
    let (ed25519_sk, ed25519_pk) = generate_ed25519(rng);
    let (ml_dsa_65_sk_owned, ml_dsa_65_pk_owned) = generate_ml_dsa_65(rng);

    // The kem/sig modules wrap their PQC secrets in module-private newtypes
    // (`MlKem768Secret`, `MlDsa65Secret`) that own a `SecretBytes`. The
    // bundle stores a `Sensitive<Vec<u8>>` so callers see one uniform
    // expose-style accessor across all four secret keys. We copy the bytes
    // through `expose()` (the only public read accessor) — this is one
    // visible secret read at construction time, and the original wrapper is
    // dropped (and its `SecretBytes` zeroized) at the end of this function.
    let ml_kem_768_sk = Sensitive::new(ml_kem_768_sk_owned.expose().to_vec());
    let ml_dsa_65_sk = Sensitive::new(ml_dsa_65_sk_owned.expose().to_vec());

    IdentityBundle {
        user_uuid,
        display_name: display_name.to_string(),
        x25519_sk,
        x25519_pk,
        ml_kem_768_sk,
        ml_kem_768_pk: ml_kem_768_pk_owned.as_bytes().to_vec(),
        ed25519_sk,
        ed25519_pk,
        ml_dsa_65_sk,
        ml_dsa_65_pk: ml_dsa_65_pk_owned.as_bytes().to_vec(),
        created_at_ms,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    #[test]
    fn generate_produces_consistent_keypairs() {
        let mut rng = ChaCha20Rng::from_seed([5u8; 32]);
        let b = generate("Alice", 1_714_060_800_000, &mut rng);

        assert_eq!(b.display_name, "Alice");
        assert_eq!(b.created_at_ms, 1_714_060_800_000);
        assert_eq!(b.x25519_sk.expose().len(), X25519_SK_LEN);
        assert_eq!(b.x25519_pk.len(), X25519_PK_LEN);
        assert_eq!(b.ml_kem_768_sk.expose().len(), ML_KEM_768_SK_LEN);
        assert_eq!(b.ml_kem_768_pk.len(), ML_KEM_768_PK_LEN);
        assert_eq!(b.ed25519_sk.expose().len(), ED25519_SK_LEN);
        assert_eq!(b.ed25519_pk.len(), ED25519_PK_LEN);
        // Per module docs: bundle stores the FIPS 204 seed (32 B), not the
        // §5-spec'd 4032-byte expanded encoding.
        assert_eq!(b.ml_dsa_65_sk.expose().len(), ML_DSA_65_SEED_LEN);
        assert_eq!(b.ml_dsa_65_pk.len(), ML_DSA_65_PK_LEN);
    }
}
