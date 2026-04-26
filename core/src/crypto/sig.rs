//! Hybrid signature: Ed25519 (classical) + ML-DSA-65 (post-quantum).
//!
//! Implements `docs/crypto-design.md` §8. The construction:
//!
//! 1. Both primitives sign the same byte string
//!    `signed_message = "secretary-v1-{role}-sig" || canonical_bytes(m)`,
//!    where `{role}` is one of `block`, `manifest`, `card`. The role tag
//!    constants live in [`crate::crypto::kdf`] (see `TAG_BLOCK_SIG`,
//!    `TAG_MANIFEST_SIG`, `TAG_CARD_SIG`).
//! 2. The hybrid signature is the pair `(sig_ed, sig_pq)` — there is no
//!    combiner. An attacker who breaks one algorithm still has to break
//!    the other; that simplicity is the point.
//! 3. Verification requires both primitives to succeed.
//!
//! Failures are surfaced as **distinct** variants
//! ([`SigError::Ed25519VerifyFailed`] vs [`SigError::MlDsa65VerifyFailed`]).
//! Unlike the AEAD case (where collapsing protects against side channels),
//! here the caller benefits from knowing which half rejected: it's diagnostic
//! information about which primitive is broken or being attacked, not
//! key-recovery information.
//!
//! ## What this module deliberately does *not* do
//!
//! - It does not serialize [`HybridSig`] to its on-disk length-prefixed form
//!   (`sig_len_ed || sig_ed || sig_len_pq || sig_pq`, §8 final paragraph).
//!   That belongs with the vault on-disk module.
//! - It does not abstract over "the signature scheme" with a trait. Concrete
//!   Ed25519 + ML-DSA-65 only; suite migration (§12) is a future concern.
//!
//! ## ML-DSA-65 secret-key representation
//!
//! `ml-dsa` 0.1.0-rc.8 represents the ML-DSA-65 signing key as a 32-byte
//! FIPS 204 seed (`Seed = B32`) plus an in-memory expanded form derived from
//! it. The 4032-byte `ExpandedSigningKey` byte encoding is `#[deprecated]` in
//! favour of the seed; we follow the crate's recommendation and store the
//! 32-byte seed in [`MlDsa65Secret`]. The §14 sk-size of 4032 bytes refers to
//! the FIPS 204 expanded encoding, which we never persist.
//!
//! ## Determinism
//!
//! Both `ed25519-dalek` and `ml-dsa` produce deterministic signatures by
//! default (RFC 8032 deterministic Ed25519, ML-DSA hedged-but-deterministic
//! mode). [`sign`] therefore takes no RNG. Keypair generators take an
//! `RngCore + CryptoRng` from `rand_core` 0.6, matching [`crate::crypto::kem`].

use ed25519_dalek::ed25519::signature::{Signer as _, Verifier as _};
use ed25519_dalek::{
    Signature as EdSignature, SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey,
};
use ml_dsa::signature::{Keypair as _, Signer as _, Verifier as _};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, KeyGen as _, MlDsa65, Signature as MlDsaSignature,
    VerifyingKey as MlDsaVerifyingKey, B32,
};
use rand_core::{CryptoRng, RngCore};

use crate::crypto::kdf::{TAG_BLOCK_SIG, TAG_CARD_SIG, TAG_MANIFEST_SIG};
use crate::crypto::secret::{SecretBytes, Sensitive};

// ---------------------------------------------------------------------------
// Sizes (§14)
// ---------------------------------------------------------------------------

/// Ed25519 secret key length, in bytes.
pub const ED25519_SK_LEN: usize = 32;
/// Ed25519 public key length, in bytes.
pub const ED25519_PK_LEN: usize = 32;
/// Ed25519 signature length, in bytes.
pub const ED25519_SIG_LEN: usize = 64;

/// ML-DSA-65 public key length, in bytes (FIPS 204 §14).
pub const ML_DSA_65_PK_LEN: usize = 1952;
/// ML-DSA-65 signing-key seed length, in bytes (FIPS 204 KeyGen_internal `xi`).
///
/// This is the canonical sk representation for `ml-dsa` 0.1.0-rc.8 — the
/// 4032-byte ExpandedSigningKey byte encoding is `#[deprecated]`. The §14
/// "sk = 4032 B" entry refers to the FIPS 204 expanded form, which we never
/// persist.
pub const ML_DSA_65_SEED_LEN: usize = 32;
/// ML-DSA-65 signature length, in bytes (FIPS 204 §14).
pub const ML_DSA_65_SIG_LEN: usize = 3309;

// ---------------------------------------------------------------------------
// Public key types
// ---------------------------------------------------------------------------

/// Ed25519 secret key, 32 bytes. Zeroize-on-drop via [`Sensitive`].
pub type Ed25519Secret = Sensitive<[u8; ED25519_SK_LEN]>;
/// Ed25519 public key, 32 bytes. Not secret.
pub type Ed25519Public = [u8; ED25519_PK_LEN];

/// ML-DSA-65 public key, 1952 bytes (FIPS 204 encoding).
///
/// Heap-allocated because it's far too large for an idiomatic stack value.
/// Not secret material — derives `Debug` etc. normally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlDsa65Public(Vec<u8>);

impl MlDsa65Public {
    /// Borrow the encoded bytes (FIPS 204 byte string format).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Construct from a byte slice. Returns [`SigError::InvalidKeyLength`] if
    /// the slice is not exactly [`ML_DSA_65_PK_LEN`] bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SigError> {
        if bytes.len() != ML_DSA_65_PK_LEN {
            return Err(SigError::InvalidKeyLength);
        }
        Ok(Self(bytes.to_vec()))
    }
}

/// ML-DSA-65 signing-key seed, 32 bytes. Wraps [`SecretBytes`] for
/// zeroize-on-drop and redacted `Debug`. See module docs for why this stores
/// the 32-byte seed rather than the 4032-byte expanded form.
pub struct MlDsa65Secret(SecretBytes);

impl MlDsa65Secret {
    /// Borrow the encoded seed bytes. As with all `expose`-style accessors in
    /// this crate, every line that calls this is reading secret material —
    /// keep them visible to review.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.0.expose()
    }

    /// Construct from a byte slice. Returns [`SigError::InvalidKeyLength`] if
    /// the slice is not exactly [`ML_DSA_65_SEED_LEN`] bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SigError> {
        if bytes.len() != ML_DSA_65_SEED_LEN {
            return Err(SigError::InvalidKeyLength);
        }
        Ok(Self(SecretBytes::new(bytes.to_vec())))
    }
}

impl core::fmt::Debug for MlDsa65Secret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MlDsa65Secret")
            .field("len", &self.0.len())
            .finish()
    }
}

/// ML-DSA-65 signature, 3309 bytes. Stored as a `Vec` so the type is forward
/// compatible with future suites whose PQ signatures may be a different size
/// (this is also why §8's on-disk form is length-prefixed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlDsa65Sig(Vec<u8>);

impl MlDsa65Sig {
    /// Borrow the encoded signature bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Construct from a byte slice. Returns [`SigError::InvalidSignatureLength`]
    /// if the slice is not exactly [`ML_DSA_65_SIG_LEN`] bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SigError> {
        if bytes.len() != ML_DSA_65_SIG_LEN {
            return Err(SigError::InvalidSignatureLength);
        }
        Ok(Self(bytes.to_vec()))
    }
}

/// Ed25519 signature alias — fixed 64 bytes.
pub type Ed25519Sig = [u8; ED25519_SIG_LEN];

// ---------------------------------------------------------------------------
// HybridSig: in-memory result of one §8 sign
// ---------------------------------------------------------------------------

/// One §8 hybrid signature. Holds the two byte strings that go into the
/// signature-pair fields on disk. Wire-form serialization (length-prefixed,
/// §8 final paragraph) belongs with the vault on-disk module — same boundary
/// as [`crate::crypto::kem::HybridWrap`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridSig {
    /// Ed25519 signature over `signed_message(role, m)`. 64 bytes.
    pub sig_ed: Ed25519Sig,
    /// ML-DSA-65 signature over the same `signed_message(role, m)`. 3309 bytes.
    pub sig_pq: MlDsa65Sig,
}

// ---------------------------------------------------------------------------
// Roles (§8) — domain-separation tag selector
// ---------------------------------------------------------------------------

/// Role prefix selector for §8 message construction. Maps each variant to
/// the corresponding `TAG_*_SIG` byte string in [`crate::crypto::kdf`]:
/// - [`SigRole::Block`] → [`TAG_BLOCK_SIG`]
/// - [`SigRole::Manifest`] → [`TAG_MANIFEST_SIG`]
/// - [`SigRole::Card`] → [`TAG_CARD_SIG`]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigRole {
    /// A block file (§9).
    Block,
    /// A manifest file (§10).
    Manifest,
    /// A Contact Card self-signature (§6).
    Card,
}

impl SigRole {
    /// The role-prefix tag bytes (no NUL terminator, no length prefix).
    #[must_use]
    pub const fn tag(self) -> &'static [u8] {
        match self {
            Self::Block => TAG_BLOCK_SIG,
            Self::Manifest => TAG_MANIFEST_SIG,
            Self::Card => TAG_CARD_SIG,
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors returned by hybrid-signature operations.
///
/// Verify failures are deliberately *not* collapsed into a single variant:
/// the §8 construction is "both must succeed", and a caller learning *which*
/// primitive rejected gets diagnostic information about which half is broken
/// or under attack — not key-recovery information.
#[derive(Debug, thiserror::Error)]
pub enum SigError {
    /// Ed25519 signature verification rejected.
    #[error("Ed25519 signature verification failed")]
    Ed25519VerifyFailed,

    /// ML-DSA-65 signature verification rejected.
    #[error("ML-DSA-65 signature verification failed")]
    MlDsa65VerifyFailed,

    /// A key passed in by the caller had the wrong length for its declared
    /// algorithm.
    #[error("invalid key length")]
    InvalidKeyLength,

    /// A signature passed to [`MlDsa65Sig::from_bytes`] had the wrong length.
    #[error("invalid signature length")]
    InvalidSignatureLength,
}

// ---------------------------------------------------------------------------
// Pure helper — §8 step 1
// ---------------------------------------------------------------------------

/// §8 step 1 — prepend the role tag to the canonical message bytes. This is
/// the byte string that *both* primitives sign / verify against.
///
/// Pure function: no secrets, no randomness. Useful for KAT pinning of the
/// role-prefix logic and for callers that want to see the exact bytes a
/// signature commits to.
#[must_use]
pub fn signed_message(role: SigRole, message: &[u8]) -> Vec<u8> {
    let tag = role.tag();
    let mut out = Vec::with_capacity(tag.len() + message.len());
    out.extend_from_slice(tag);
    out.extend_from_slice(message);
    out
}

// ---------------------------------------------------------------------------
// Keypair generation
// ---------------------------------------------------------------------------

/// Generate a fresh Ed25519 keypair using the provided CSPRNG.
///
/// In production, callers should pass `rand_core::OsRng` (per
/// `docs/crypto-design.md` §13). Tests pin determinism by passing a seeded
/// `ChaCha20Rng` instead.
pub fn generate_ed25519<R: RngCore + CryptoRng>(rng: &mut R) -> (Ed25519Secret, Ed25519Public) {
    let sk = EdSigningKey::generate(rng);
    let pk = sk.verifying_key().to_bytes();
    let mut sk_bytes = sk.to_bytes();
    let secret = Sensitive::new(sk_bytes);
    // `Sensitive::new` copied `sk_bytes` (which is `[u8; 32]: Copy`); zeroize
    // the stack copy so the secret only lives inside `secret`.
    use zeroize::Zeroize as _;
    sk_bytes.zeroize();
    (secret, pk)
}

/// Generate a fresh ML-DSA-65 keypair using the provided CSPRNG.
///
/// We read 32 bytes from the caller-supplied RNG ourselves and pass the seed
/// to `MlDsa65::from_seed`, rather than calling `MlDsa65::key_gen(rng)`. The
/// reason is dependency-version isolation: `ml-dsa` 0.1.0-rc.8's `key_gen`
/// requires a `signature::rand_core::CryptoRng` (`rand_core` 0.10), whereas
/// the rest of this crate (and the existing `kem` module) is on `rand_core`
/// 0.6. Driving `from_seed` from our own RNG read keeps the public API
/// uniform across modules and avoids pulling in a second `rand_core` major.
pub fn generate_ml_dsa_65<R: RngCore + CryptoRng>(rng: &mut R) -> (MlDsa65Secret, MlDsa65Public) {
    let mut seed_bytes = [0u8; ML_DSA_65_SEED_LEN];
    rng.fill_bytes(&mut seed_bytes);
    let seed: B32 = B32::from(seed_bytes);
    let kp = MlDsa65::from_seed(&seed);
    let pk_bytes = kp.verifying_key().encode();
    let secret = MlDsa65Secret(SecretBytes::new(seed_bytes.to_vec()));
    // Original stack copy of the seed is no longer needed; zeroize before
    // dropping to limit lifetime of the cleartext seed in this stack frame.
    {
        use zeroize::Zeroize as _;
        seed_bytes.zeroize();
    }
    (secret, MlDsa65Public(pk_bytes.as_slice().to_vec()))
}

// ---------------------------------------------------------------------------
// Hybrid sign (§8) and verify
// ---------------------------------------------------------------------------

/// §8 — sign `message` under role `role` with both keys. Both primitives are
/// deterministic by default (RFC 8032 Ed25519, hedged-deterministic ML-DSA),
/// so no RNG is consumed.
pub fn sign(
    role: SigRole,
    message: &[u8],
    ed_sk: &Ed25519Secret,
    pq_sk: &MlDsa65Secret,
) -> Result<HybridSig, SigError> {
    let m = signed_message(role, message);

    // --- Ed25519 half. ---
    let ed_signing = EdSigningKey::from_bytes(ed_sk.expose());
    let sig_ed: EdSignature = ed_signing.sign(&m);

    // --- ML-DSA-65 half. ---
    if pq_sk.expose().len() != ML_DSA_65_SEED_LEN {
        return Err(SigError::InvalidKeyLength);
    }
    let mut seed_arr = [0u8; ML_DSA_65_SEED_LEN];
    seed_arr.copy_from_slice(pq_sk.expose());
    let seed: B32 = B32::from(seed_arr);
    // The stack copy is no longer needed once `seed` owns it; zeroize it to
    // keep the cleartext seed off the stack. `seed` itself ends up inside
    // `pq_kp`, whose `ExpandedSigningKey` zeroizes on drop.
    {
        use zeroize::Zeroize as _;
        seed_arr.zeroize();
    }
    let pq_kp = MlDsa65::from_seed(&seed);
    let pq_signing = pq_kp.signing_key();
    let sig_pq_obj = pq_signing.sign(&m);
    let sig_pq_bytes = sig_pq_obj.encode();

    Ok(HybridSig {
        sig_ed: sig_ed.to_bytes(),
        sig_pq: MlDsa65Sig(sig_pq_bytes.as_slice().to_vec()),
    })
}

/// §8 — verify a hybrid signature. *Both* primitives must succeed.
///
/// On failure, the variant identifies which primitive rejected (see
/// [`SigError`] for why we expose this rather than collapsing).
pub fn verify(
    role: SigRole,
    message: &[u8],
    sig: &HybridSig,
    ed_pk: &Ed25519Public,
    pq_pk: &MlDsa65Public,
) -> Result<(), SigError> {
    let m = signed_message(role, message);

    // --- Ed25519 half. ---
    let ed_verifying = EdVerifyingKey::from_bytes(ed_pk).map_err(|_| SigError::InvalidKeyLength)?;
    let ed_sig = EdSignature::from_bytes(&sig.sig_ed);
    ed_verifying
        .verify(&m, &ed_sig)
        .map_err(|_| SigError::Ed25519VerifyFailed)?;

    // --- ML-DSA-65 half. Errors here are not key-recovery; report which
    // primitive rejected. ---
    let pq_pk_arr: EncodedVerifyingKey<MlDsa65> = pq_pk
        .as_bytes()
        .try_into()
        .map_err(|_| SigError::InvalidKeyLength)?;
    let pq_verifying = MlDsaVerifyingKey::<MlDsa65>::decode(&pq_pk_arr);

    let pq_sig_arr: EncodedSignature<MlDsa65> = sig
        .sig_pq
        .as_bytes()
        .try_into()
        .map_err(|_| SigError::InvalidSignatureLength)?;
    let pq_sig =
        MlDsaSignature::<MlDsa65>::decode(&pq_sig_arr).ok_or(SigError::MlDsa65VerifyFailed)?;
    pq_verifying
        .verify(&m, &pq_sig)
        .map_err(|_| SigError::MlDsa65VerifyFailed)?;

    Ok(())
}
