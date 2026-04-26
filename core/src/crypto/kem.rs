//! Hybrid KEM: X25519 (classical) + ML-KEM-768 (post-quantum).
//!
//! Implements the per-recipient block-key wrap from
//! `docs/crypto-design.md` §7. The construction:
//!
//! 1. Sender runs both KEMs against the recipient's hybrid public key,
//!    yielding two independent shared secrets and two ciphertexts.
//! 2. The two shared secrets are mixed by HKDF-SHA-256, with the HKDF input
//!    binding *both* ciphertexts and *both* parties' canonical public-key
//!    bundles (§7.2 — defends against KEM-sneak attacks where an active MITM
//!    rewrites one half of the hybrid).
//! 3. The 32-byte HKDF output is used as an XChaCha20-Poly1305 wrap key for a
//!    32-byte Block Content Key, with `block_uuid` and the BLAKE3 transcript
//!    bound as AAD.
//!
//! Decap is the symmetric reverse and surfaces every failure mode (wrong
//! recipient, tampered ciphertext, tampered pk-bundle, wrong block UUID,
//! tampered wrap ciphertext) as the same generic AEAD-failure variant — same
//! discipline as [`crate::crypto::aead`].
//!
//! ## What this module deliberately does *not* do
//!
//! - It does not parse the pk-bundle: callers pass the canonical-CBOR
//!   `(x25519_pk, ml_kem_768_pk, ed25519_pk, ml_dsa_65_pk)` bytes opaquely.
//!   The bundle module lives later in the build sequence and ML-DSA / Ed25519
//!   keys do not exist yet.
//! - It does not serialize [`HybridWrap`] to its 1208-byte on-disk form
//!   (`docs/vault-format.md` §6.2). That belongs with the vault on-disk
//!   module, also later.
//! - It does not abstract over "the KEM" with a trait. Concrete X25519 +
//!   ML-KEM-768 only; suite migration (§12) is a future concern.

use blake3::Hasher as Blake3Hasher;
use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768, MlKem768Params};
use rand_core::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};
use zeroize::Zeroize as _;

use crate::crypto::aead::{self, AeadError, AeadKey, AeadNonce};
use crate::crypto::kdf::{
    hkdf_sha256_extract_and_expand, TAG_BLOCK_CONTENT_KEY_WRAP, TAG_BLOCK_KEY_WRAP, TAG_HYBRID_KEM,
    TAG_HYBRID_KEM_TRANSCRIPT,
};
use crate::crypto::secret::{SecretBytes, Sensitive};

// ---------------------------------------------------------------------------
// Sizes (§14)
// ---------------------------------------------------------------------------

/// X25519 public key length, in bytes.
pub const X25519_PK_LEN: usize = 32;
/// X25519 secret key length, in bytes.
pub const X25519_SK_LEN: usize = 32;
/// X25519 shared-secret length, in bytes.
pub const X25519_SS_LEN: usize = 32;

/// ML-KEM-768 public key (encapsulation key) length, in bytes.
pub const ML_KEM_768_PK_LEN: usize = 1184;
/// ML-KEM-768 secret key (decapsulation key) length, in bytes.
pub const ML_KEM_768_SK_LEN: usize = 2400;
/// ML-KEM-768 ciphertext length, in bytes.
pub const ML_KEM_768_CT_LEN: usize = 1088;
/// ML-KEM-768 shared-secret length, in bytes.
pub const ML_KEM_768_SS_LEN: usize = 32;

/// Block Content Key length, in bytes (§14).
pub const BLOCK_CONTENT_KEY_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Public key types
// ---------------------------------------------------------------------------

/// X25519 secret key (32 bytes), zeroize-on-drop.
pub type X25519Secret = Sensitive<[u8; X25519_SK_LEN]>;

/// X25519 public key (32 bytes). Not secret.
pub type X25519Public = [u8; X25519_PK_LEN];

/// ML-KEM-768 public (encapsulation) key, 1184 bytes.
///
/// Heap-allocated because it's far too large for an idiomatic stack value.
/// Not secret material — derives `Debug` etc. normally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlKem768Public(Vec<u8>);

impl MlKem768Public {
    /// Borrow the encoded bytes (FIPS 203 byte string format).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Construct from a byte slice. Returns [`KemError::InvalidKeyLength`]
    /// if the slice is not exactly [`ML_KEM_768_PK_LEN`] bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KemError> {
        if bytes.len() != ML_KEM_768_PK_LEN {
            return Err(KemError::InvalidKeyLength);
        }
        Ok(Self(bytes.to_vec()))
    }
}

/// ML-KEM-768 secret (decapsulation) key, 2400 bytes. Wraps [`SecretBytes`]
/// for zeroize-on-drop and redacted `Debug`.
pub struct MlKem768Secret(SecretBytes);

impl MlKem768Secret {
    /// Borrow the encoded secret-key bytes.
    ///
    /// As with all `expose`-style accessors in this crate, every line that
    /// calls this is reading secret material — keep them visible to review.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.0.expose()
    }

    /// Construct from a byte slice. Returns [`KemError::InvalidKeyLength`]
    /// if the slice is not exactly [`ML_KEM_768_SK_LEN`] bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KemError> {
        if bytes.len() != ML_KEM_768_SK_LEN {
            return Err(KemError::InvalidKeyLength);
        }
        Ok(Self(SecretBytes::new(bytes.to_vec())))
    }
}

impl core::fmt::Debug for MlKem768Secret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MlKem768Secret")
            .field("len", &self.0.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// HybridWrap: in-memory result of one §7 wrap
// ---------------------------------------------------------------------------

/// One §7 hybrid-KEM wrap. Holds the four byte fields that go into a
/// per-recipient entry of the block file's recipients table (minus the
/// recipient fingerprint, which the caller knows independently).
///
/// Wire-form serialization (`docs/vault-format.md` §6.2) lives with the
/// vault on-disk module, not here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridWrap {
    /// X25519 ephemeral public key the sender just generated. 32 bytes.
    pub ct_x: [u8; X25519_PK_LEN],
    /// ML-KEM-768 ciphertext. 1088 bytes.
    pub ct_pq: Vec<u8>,
    /// XChaCha20 nonce used to wrap the Block Content Key. 24 bytes.
    pub nonce_w: AeadNonce,
    /// AEAD ciphertext of the Block Content Key, with the Poly1305 tag
    /// appended. 32 + 16 = 48 bytes.
    pub ct_w: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors returned by hybrid-KEM operations.
///
/// Note that wrong-recipient-key, tampered-ciphertext, tampered-pk-bundle,
/// wrong-block-UUID, and tampered-wrap-ciphertext all surface as
/// [`KemError::AeadFailure`]. This collapsing is intentional: the underlying
/// AEAD verification must not leak *which* input was wrong, because that
/// information is useful to an attacker probing the construction.
#[derive(Debug, thiserror::Error)]
pub enum KemError {
    /// ML-KEM-768 encapsulation failed. The underlying crate models this as
    /// infallible in practice; this variant exists for forward compatibility.
    #[error("ML-KEM-768 encapsulation failed")]
    MlKemEncapsFailed,

    /// ML-KEM-768 decapsulation failed. ML-KEM is implicit-rejection by
    /// design (a malformed ciphertext yields a pseudorandom secret, not an
    /// error), so seeing this variant in practice means an unexpected
    /// internal failure of the underlying crate.
    #[error("ML-KEM-768 decapsulation failed")]
    MlKemDecapsFailed,

    /// AEAD wrap or unwrap failed. On the decap path, this is the catch-all
    /// surface for any §7 input being wrong.
    #[error("AEAD failure")]
    AeadFailure(#[from] AeadError),

    /// A key passed in by the caller had the wrong length for its declared
    /// algorithm.
    #[error("invalid key length")]
    InvalidKeyLength,
}

// ---------------------------------------------------------------------------
// Pure helpers (deterministic — pinned by KATs)
// ---------------------------------------------------------------------------

/// §7 step 3 — BLAKE3 transcript hash binding the prefix tag, both card
/// fingerprints, and both KEM ciphertexts.
///
/// Pure function: no secrets, no randomness. Streaming via
/// [`blake3::Hasher`] avoids a 1.1 KiB intermediate `Vec` for `ct_pq`.
#[must_use]
pub fn transcript(
    sender_card_fingerprint: &[u8; 16],
    recipient_card_fingerprint: &[u8; 16],
    ct_x: &[u8; X25519_PK_LEN],
    ct_pq: &[u8],
) -> [u8; 32] {
    let mut hasher = Blake3Hasher::new();
    hasher.update(TAG_HYBRID_KEM_TRANSCRIPT);
    hasher.update(sender_card_fingerprint);
    hasher.update(recipient_card_fingerprint);
    hasher.update(ct_x);
    hasher.update(ct_pq);
    *hasher.finalize().as_bytes()
}

/// §7 steps 4–5 — HKDF-SHA-256 extract-and-expand to produce the 32-byte
/// AEAD wrap key.
///
/// - `salt` is [`TAG_HYBRID_KEM`].
/// - `ikm` is `ss_x || ss_pq || ct_x || ct_pq || sender_pk_bundle ||
///   recipient_pk_bundle` (the order in §7 is normative — both ciphertexts
///   are bound here as well as in `transcript`, see §7.2 for why).
/// - `info` is [`TAG_BLOCK_CONTENT_KEY_WRAP`] `|| transcript`.
///
/// The intermediate `ikm` buffer contains both shared secrets in cleartext
/// and is zeroized after the HKDF call returns.
#[must_use]
pub fn derive_wrap_key(
    ss_x: &Sensitive<[u8; X25519_SS_LEN]>,
    ss_pq: &Sensitive<[u8; ML_KEM_768_SS_LEN]>,
    ct_x: &[u8; X25519_PK_LEN],
    ct_pq: &[u8],
    sender_pk_bundle: &[u8],
    recipient_pk_bundle: &[u8],
    transcript_hash: &[u8; 32],
) -> AeadKey {
    let mut ikm = Vec::with_capacity(
        X25519_SS_LEN
            + ML_KEM_768_SS_LEN
            + X25519_PK_LEN
            + ct_pq.len()
            + sender_pk_bundle.len()
            + recipient_pk_bundle.len(),
    );
    ikm.extend_from_slice(ss_x.expose());
    ikm.extend_from_slice(ss_pq.expose());
    ikm.extend_from_slice(ct_x);
    ikm.extend_from_slice(ct_pq);
    ikm.extend_from_slice(sender_pk_bundle);
    ikm.extend_from_slice(recipient_pk_bundle);

    let mut info = Vec::with_capacity(TAG_BLOCK_CONTENT_KEY_WRAP.len() + 32);
    info.extend_from_slice(TAG_BLOCK_CONTENT_KEY_WRAP);
    info.extend_from_slice(transcript_hash);

    let mut okm = hkdf_sha256_extract_and_expand(TAG_HYBRID_KEM, &ikm, &info, 32);
    ikm.zeroize();

    let mut key = [0u8; 32];
    key.copy_from_slice(&okm);
    okm.zeroize();
    let s = Sensitive::new(key);
    // `Sensitive::new` copied `key` (which is `[u8; 32]: Copy`); the original
    // stack slot still holds the wrap key bytes until the frame is reused.
    // Zeroize the stack copy so the secret only lives inside `s`.
    key.zeroize();
    s
}

// ---------------------------------------------------------------------------
// Keypair generation
// ---------------------------------------------------------------------------

/// Generate a fresh X25519 keypair using the provided CSPRNG.
///
/// In production, callers should pass `rand_core::OsRng` (per
/// `docs/crypto-design.md` §13). Tests pin determinism by passing a seeded
/// `ChaCha20Rng` instead.
pub fn generate_x25519<R: RngCore + CryptoRng>(rng: &mut R) -> (X25519Secret, X25519Public) {
    let sk = XStaticSecret::random_from_rng(&mut *rng);
    let pk = XPublicKey::from(&sk);
    let mut sk_bytes = sk.to_bytes();
    let secret = Sensitive::new(sk_bytes);
    sk_bytes.zeroize();
    (secret, pk.to_bytes())
}

/// Generate a fresh ML-KEM-768 keypair using the provided CSPRNG.
///
/// Same RNG conventions as [`generate_x25519`].
pub fn generate_ml_kem_768<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (MlKem768Secret, MlKem768Public) {
    let (dk, ek) = MlKem768::generate(rng);
    let sk_bytes = dk.as_bytes();
    let pk_bytes = ek.as_bytes();
    (
        MlKem768Secret(SecretBytes::new(sk_bytes.as_slice().to_vec())),
        MlKem768Public(pk_bytes.as_slice().to_vec()),
    )
}

// ---------------------------------------------------------------------------
// Hybrid encap (§7) and decap (§7.1)
// ---------------------------------------------------------------------------

/// AAD for the AEAD wrap. The transcript is bound here (in addition to the
/// HKDF info) so a wrap can't be replayed under a different transcript.
fn build_aead_aad(block_uuid: &[u8; 16], transcript_hash: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(TAG_BLOCK_KEY_WRAP.len() + 16 + 32);
    aad.extend_from_slice(TAG_BLOCK_KEY_WRAP);
    aad.extend_from_slice(block_uuid);
    aad.extend_from_slice(transcript_hash);
    aad
}

/// §7 — wrap a 32-byte Block Content Key for one recipient.
///
/// `sender_pk_bundle` and `recipient_pk_bundle` are the canonical CBOR
/// encodings of the two parties' `(x25519_pk, ml_kem_768_pk, ed25519_pk,
/// ml_dsa_65_pk)` tuples as they appear in their Contact Cards. The KEM
/// module accepts them opaquely so it stays decoupled from the bundle and
/// signature modules; the caller is responsible for canonical CBOR encoding.
///
/// Internally consumes `rng` for: the X25519 ephemeral, the ML-KEM
/// encapsulation message, and the 24-byte XChaCha20 nonce. The order of
/// consumption is implementation-internal — KATs that fix the RNG should
/// not depend on it.
#[allow(clippy::too_many_arguments)] // §7 construction inputs are inherent.
pub fn encap<R: RngCore + CryptoRng>(
    rng: &mut R,
    sender_card_fingerprint: &[u8; 16],
    recipient_card_fingerprint: &[u8; 16],
    sender_pk_bundle: &[u8],
    recipient_pk_bundle: &[u8],
    recipient_x_pk: &X25519Public,
    recipient_pq_pk: &MlKem768Public,
    block_uuid: &[u8; 16],
    block_content_key: &Sensitive<[u8; BLOCK_CONTENT_KEY_LEN]>,
) -> Result<HybridWrap, KemError> {
    // --- X25519 half: ephemeral encap. ---
    let eph_sk = XStaticSecret::random_from_rng(&mut *rng);
    let eph_pk = XPublicKey::from(&eph_sk);
    let recipient_xpk = XPublicKey::from(*recipient_x_pk);
    // diffie_hellman consumes the static-secret-style key by reference and
    // returns a Zeroize-on-drop SharedSecret.
    let ss_x_raw = eph_sk.diffie_hellman(&recipient_xpk);
    let ss_x = Sensitive::new(ss_x_raw.to_bytes());
    let ct_x = eph_pk.to_bytes();

    // --- ML-KEM-768 half: encap against recipient's pq pk. ---
    type Ek = ml_kem::kem::EncapsulationKey<MlKem768Params>;
    let ek_arr: Encoded<Ek> =
        Array::try_from(recipient_pq_pk.as_bytes()).map_err(|_| KemError::InvalidKeyLength)?;
    let ek = Ek::from_bytes(&ek_arr);
    let (ct_pq_arr, ss_pq_arr) = ek
        .encapsulate(rng)
        .map_err(|_| KemError::MlKemEncapsFailed)?;
    let ct_pq: Vec<u8> = ct_pq_arr.as_slice().to_vec();
    let mut ss_pq_bytes = [0u8; ML_KEM_768_SS_LEN];
    ss_pq_bytes.copy_from_slice(ss_pq_arr.as_slice());
    let ss_pq = Sensitive::new(ss_pq_bytes);
    ss_pq_bytes.zeroize();

    // --- Combiner: transcript + HKDF wrap key (§7 steps 3–5). ---
    let t = transcript(
        sender_card_fingerprint,
        recipient_card_fingerprint,
        &ct_x,
        &ct_pq,
    );
    let wrap_key = derive_wrap_key(
        &ss_x,
        &ss_pq,
        &ct_x,
        &ct_pq,
        sender_pk_bundle,
        recipient_pk_bundle,
        &t,
    );

    // --- AEAD wrap of the Block Content Key (§7 steps 6–7). ---
    let mut nonce_w: AeadNonce = [0u8; 24];
    rng.fill_bytes(&mut nonce_w);
    let aad = build_aead_aad(block_uuid, &t);
    let ct_w = aead::encrypt(&wrap_key, &nonce_w, &aad, block_content_key.expose())?;

    Ok(HybridWrap {
        ct_x,
        ct_pq,
        nonce_w,
        ct_w,
    })
}

/// §7.1 — unwrap a [`HybridWrap`] using the recipient's secret keys.
///
/// On success, returns the 32-byte Block Content Key. On any failure
/// (wrong recipient secret keys, tampered ciphertext, tampered pk-bundle,
/// wrong block UUID, tampered wrap), returns [`KemError::AeadFailure`] —
/// the variants are deliberately not distinguishable, see [`KemError`].
#[allow(clippy::too_many_arguments)] // §7.1 construction inputs are inherent.
pub fn decap(
    wrap: &HybridWrap,
    sender_card_fingerprint: &[u8; 16],
    recipient_card_fingerprint: &[u8; 16],
    sender_pk_bundle: &[u8],
    recipient_pk_bundle: &[u8],
    recipient_x_sk: &X25519Secret,
    recipient_pq_sk: &MlKem768Secret,
    block_uuid: &[u8; 16],
) -> Result<Sensitive<[u8; BLOCK_CONTENT_KEY_LEN]>, KemError> {
    // --- X25519 half: recipient sk * sender's ephemeral pk. ---
    let sk_x = XStaticSecret::from(*recipient_x_sk.expose());
    let pk_x_eph = XPublicKey::from(wrap.ct_x);
    let ss_x_raw = sk_x.diffie_hellman(&pk_x_eph);
    let ss_x = Sensitive::new(ss_x_raw.to_bytes());

    // --- ML-KEM-768 half: rehydrate the typed dk and decapsulate. ---
    type Dk = ml_kem::kem::DecapsulationKey<MlKem768Params>;
    let dk_arr: Encoded<Dk> =
        Array::try_from(recipient_pq_sk.expose()).map_err(|_| KemError::InvalidKeyLength)?;
    let dk = Dk::from_bytes(&dk_arr);

    type CtPq = ml_kem::Ciphertext<MlKem768>;
    let ct_pq_arr: CtPq =
        Array::try_from(wrap.ct_pq.as_slice()).map_err(|_| KemError::InvalidKeyLength)?;
    let ss_pq_arr = dk
        .decapsulate(&ct_pq_arr)
        .map_err(|_| KemError::MlKemDecapsFailed)?;
    let mut ss_pq_bytes = [0u8; ML_KEM_768_SS_LEN];
    ss_pq_bytes.copy_from_slice(ss_pq_arr.as_slice());
    let ss_pq = Sensitive::new(ss_pq_bytes);
    ss_pq_bytes.zeroize();

    // --- Recompute transcript and wrap key, then unwrap. ---
    let t = transcript(
        sender_card_fingerprint,
        recipient_card_fingerprint,
        &wrap.ct_x,
        &wrap.ct_pq,
    );
    let wrap_key = derive_wrap_key(
        &ss_x,
        &ss_pq,
        &wrap.ct_x,
        &wrap.ct_pq,
        sender_pk_bundle,
        recipient_pk_bundle,
        &t,
    );
    let aad = build_aead_aad(block_uuid, &t);
    let plaintext = aead::decrypt(&wrap_key, &wrap.nonce_w, &aad, &wrap.ct_w)?;

    if plaintext.len() != BLOCK_CONTENT_KEY_LEN {
        return Err(KemError::AeadFailure(AeadError::InvalidLength));
    }
    let mut k = [0u8; BLOCK_CONTENT_KEY_LEN];
    k.copy_from_slice(plaintext.expose());
    let out = Sensitive::new(k);
    k.zeroize();
    Ok(out)
}
