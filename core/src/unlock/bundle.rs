//! IdentityBundle plaintext (`docs/crypto-design.md` §5).
//!
//! The §5 record carries the four `(sk, pk)` pairs that constitute a user's
//! cryptographic identity, plus a 16-byte UUID, a display name, and a
//! creation timestamp (Unix milliseconds). The wire form is canonical CBOR
//! per §6.2 (RFC 8949 §4.2.1 deterministic encoding).
//!
//! ## Canonical CBOR
//!
//! Mirrors the rules also documented in [`crate::identity::card`]:
//!
//! 1. Map shape with text-string keys.
//! 2. Map keys sorted bytewise lexicographically by their canonical encoded
//!    form. For all-tstr keys this reduces to: shorter key first; among
//!    equal-length keys, bytewise UTF-8 compare. The §5 listing order is
//!    descriptive, not normative for byte order.
//! 3. Shortest-form lengths and integers (default for `ciborium`'s `Value`
//!    serializer).
//! 4. Definite-length, no tags, no floats, no indefinite-length items.
//! 5. Duplicate keys rejected on parse.
//!
//! ## Strict canonical-input rule
//!
//! [`IdentityBundle::from_canonical_cbor`] rejects any input that is not in
//! RFC 8949 §4.2.1 canonical form. Unlike the contact-card case, the bundle
//! plaintext is never directly fingerprinted; the strictness is about
//! defending against suite drift. Anything other than the exact §5 byte
//! shape signals either an out-of-spec encoder or a deliberately malformed
//! file, and is rejected so a future suite migration can rely on the v1
//! reader recognising v1 inputs only.
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

use ciborium::Value;
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

// CBOR map keys (§5). String literals only used here; centralised so a typo
// becomes a compile-time fix rather than a silent encoding drift.
const KEY_USER_UUID: &str = "user_uuid";
const KEY_DISPLAY_NAME: &str = "display_name";
const KEY_X25519_SK: &str = "x25519_sk";
const KEY_X25519_PK: &str = "x25519_pk";
const KEY_ML_KEM_768_SK: &str = "ml_kem_768_sk";
const KEY_ML_KEM_768_PK: &str = "ml_kem_768_pk";
const KEY_ED25519_SK: &str = "ed25519_sk";
const KEY_ED25519_PK: &str = "ed25519_pk";
const KEY_ML_DSA_65_SK: &str = "ml_dsa_65_sk";
const KEY_ML_DSA_65_PK: &str = "ml_dsa_65_pk";
const KEY_CREATED_AT: &str = "created_at";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from bundle CBOR encode and decode.
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    /// CBOR encoding produced an I/O or serialization error from `ciborium`,
    /// or the byte stream did not contain a top-level map, or trailing bytes
    /// followed the map.
    #[error("CBOR encode/decode error: {0}")]
    CborDecode(String),

    /// Input parsed but was not in RFC 8949 §4.2.1 canonical form (e.g. keys
    /// not in bytewise lexicographic order, non-shortest length prefixes,
    /// indefinite-length items). Strictness defends against suite drift —
    /// the v1 bundle plaintext is fully specified, and any deviation in
    /// shape signals an out-of-spec writer or tampering.
    #[error("input was not in canonical CBOR form")]
    NonCanonicalCbor,

    /// A map key was present that the v1 spec does not define. The bundle is
    /// fully-specified; an unknown field signals suite drift and is rejected.
    #[error("unknown bundle field: {0}")]
    UnknownField(String),

    /// A map key appeared more than once. RFC 8949 §5.4 forbids duplicates
    /// in canonical input.
    #[error("duplicate field: {0}")]
    DuplicateField(String),

    /// A fixed-size byte string field arrived with an unexpected length.
    #[error("wrong key size for {field}: expected {expected}, got {got}")]
    WrongKeySize {
        /// The §5 CBOR key whose value had the wrong length.
        field: &'static str,
        /// Expected byte length per §5 / `BUNDLE_*_LEN`.
        expected: usize,
        /// Actual byte length seen on the wire.
        got: usize,
    },

    /// `user_uuid` was present but not the required 16 bytes.
    #[error("invalid UUID")]
    InvalidUuid,

    /// `created_at` was present but did not fit a `u64` Unix-millisecond
    /// timestamp.
    #[error("invalid timestamp")]
    InvalidTimestamp,
}

// ---------------------------------------------------------------------------
// IdentityBundle
// ---------------------------------------------------------------------------

/// IdentityBundle plaintext per `docs/crypto-design.md` §5.
///
/// Carries the four `(sk, pk)` pairs of the v1 hybrid suite, plus the
/// 16-byte user UUID, a display name, and a creation timestamp.
///
/// Secret-key fields are wrapped in [`Sensitive`] (or [`SecretBytes`] for
/// runtime-sized PQC keys) so they zeroize on drop. The bundle does not
/// derive `Clone`, `Debug`, or `PartialEq`: cloning would silently
/// duplicate secret material; a derived `Debug` would leak it; equality is
/// only ever asked of test code, which compares exposed contents
/// field-by-field.
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

impl IdentityBundle {
    /// Canonical CBOR encoding of the §5 plaintext map. Output is
    /// deterministic: encoding twice produces identical bytes, and any
    /// conformant RFC 8949 §4.2.1 encoder produces the same output.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, BundleError> {
        // Build the 11 entries; they will be sorted bytewise by canonical
        // key encoding before serialisation. The order in this `vec!` is
        // therefore not load-bearing — the sort step is.
        let entries: Vec<(Value, Value)> = vec![
            (
                Value::Text(KEY_USER_UUID.into()),
                Value::Bytes(self.user_uuid.to_vec()),
            ),
            (
                Value::Text(KEY_DISPLAY_NAME.into()),
                Value::Text(self.display_name.clone()),
            ),
            (
                Value::Text(KEY_X25519_SK.into()),
                Value::Bytes(self.x25519_sk.expose().to_vec()),
            ),
            (
                Value::Text(KEY_X25519_PK.into()),
                Value::Bytes(self.x25519_pk.to_vec()),
            ),
            (
                Value::Text(KEY_ML_KEM_768_SK.into()),
                Value::Bytes(self.ml_kem_768_sk.expose().clone()),
            ),
            (
                Value::Text(KEY_ML_KEM_768_PK.into()),
                Value::Bytes(self.ml_kem_768_pk.clone()),
            ),
            (
                Value::Text(KEY_ED25519_SK.into()),
                Value::Bytes(self.ed25519_sk.expose().to_vec()),
            ),
            (
                Value::Text(KEY_ED25519_PK.into()),
                Value::Bytes(self.ed25519_pk.to_vec()),
            ),
            (
                Value::Text(KEY_ML_DSA_65_SK.into()),
                Value::Bytes(self.ml_dsa_65_sk.expose().clone()),
            ),
            (
                Value::Text(KEY_ML_DSA_65_PK.into()),
                Value::Bytes(self.ml_dsa_65_pk.clone()),
            ),
            (
                Value::Text(KEY_CREATED_AT.into()),
                Value::Integer(self.created_at_ms.into()),
            ),
        ];
        encode_map(&entries)
    }

    /// Inverse of [`to_canonical_cbor`]. Validates that every required field
    /// is present, fixed-size fields have the correct byte length, no
    /// unknown fields appear, no duplicates appear, and the input was
    /// already in RFC 8949 §4.2.1 canonical form.
    ///
    /// The strict canonical-input rule defends against suite drift: a v1
    /// reader must recognise v1 inputs only, so a future v2 writer (or a
    /// tampered file) is rejected loudly rather than silently accepted.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, BundleError> {
        let value: Value = ciborium::de::from_reader(bytes)
            .map_err(|e| BundleError::CborDecode(e.to_string()))?;
        let map = match value {
            Value::Map(m) => m,
            _ => {
                return Err(BundleError::CborDecode(
                    "expected top-level CBOR map".into(),
                ))
            }
        };

        let mut user_uuid: Option<[u8; USER_UUID_LEN]> = None;
        let mut display_name: Option<String> = None;
        let mut x25519_sk_bytes: Option<[u8; X25519_SK_LEN]> = None;
        let mut x25519_pk: Option<[u8; X25519_PK_LEN]> = None;
        let mut ml_kem_768_sk_bytes: Option<Vec<u8>> = None;
        let mut ml_kem_768_pk: Option<Vec<u8>> = None;
        let mut ed25519_sk_bytes: Option<[u8; ED25519_SK_LEN]> = None;
        let mut ed25519_pk: Option<[u8; ED25519_PK_LEN]> = None;
        let mut ml_dsa_65_sk_bytes: Option<Vec<u8>> = None;
        let mut ml_dsa_65_pk: Option<Vec<u8>> = None;
        let mut created_at_ms: Option<u64> = None;

        for (k, v) in map {
            let Value::Text(key) = k else {
                return Err(BundleError::CborDecode("non-string map key".into()));
            };
            match key.as_str() {
                KEY_USER_UUID => set_once(
                    &mut user_uuid,
                    take_uuid(v)?,
                    &key,
                )?,
                KEY_DISPLAY_NAME => set_once(&mut display_name, take_text(v)?, &key)?,
                KEY_X25519_SK => set_once(
                    &mut x25519_sk_bytes,
                    take_fixed_bytes::<X25519_SK_LEN>(v, KEY_X25519_SK)?,
                    &key,
                )?,
                KEY_X25519_PK => set_once(
                    &mut x25519_pk,
                    take_fixed_bytes::<X25519_PK_LEN>(v, KEY_X25519_PK)?,
                    &key,
                )?,
                KEY_ML_KEM_768_SK => set_once(
                    &mut ml_kem_768_sk_bytes,
                    take_sized_bytes(v, KEY_ML_KEM_768_SK, ML_KEM_768_SK_LEN)?,
                    &key,
                )?,
                KEY_ML_KEM_768_PK => set_once(
                    &mut ml_kem_768_pk,
                    take_sized_bytes(v, KEY_ML_KEM_768_PK, ML_KEM_768_PK_LEN)?,
                    &key,
                )?,
                KEY_ED25519_SK => set_once(
                    &mut ed25519_sk_bytes,
                    take_fixed_bytes::<ED25519_SK_LEN>(v, KEY_ED25519_SK)?,
                    &key,
                )?,
                KEY_ED25519_PK => set_once(
                    &mut ed25519_pk,
                    take_fixed_bytes::<ED25519_PK_LEN>(v, KEY_ED25519_PK)?,
                    &key,
                )?,
                KEY_ML_DSA_65_SK => set_once(
                    &mut ml_dsa_65_sk_bytes,
                    take_sized_bytes(v, KEY_ML_DSA_65_SK, ML_DSA_65_SEED_LEN)?,
                    &key,
                )?,
                KEY_ML_DSA_65_PK => set_once(
                    &mut ml_dsa_65_pk,
                    take_sized_bytes(v, KEY_ML_DSA_65_PK, ML_DSA_65_PK_LEN)?,
                    &key,
                )?,
                KEY_CREATED_AT => set_once(&mut created_at_ms, take_u64(v)?, &key)?,
                other => {
                    return Err(BundleError::UnknownField(other.to_string()));
                }
            }
        }

        let bundle = IdentityBundle {
            user_uuid: user_uuid
                .ok_or_else(|| BundleError::CborDecode(format!("missing field {KEY_USER_UUID}")))?,
            display_name: display_name.ok_or_else(|| {
                BundleError::CborDecode(format!("missing field {KEY_DISPLAY_NAME}"))
            })?,
            x25519_sk: Sensitive::new(x25519_sk_bytes.ok_or_else(|| {
                BundleError::CborDecode(format!("missing field {KEY_X25519_SK}"))
            })?),
            x25519_pk: x25519_pk
                .ok_or_else(|| BundleError::CborDecode(format!("missing field {KEY_X25519_PK}")))?,
            ml_kem_768_sk: Sensitive::new(ml_kem_768_sk_bytes.ok_or_else(|| {
                BundleError::CborDecode(format!("missing field {KEY_ML_KEM_768_SK}"))
            })?),
            ml_kem_768_pk: ml_kem_768_pk.ok_or_else(|| {
                BundleError::CborDecode(format!("missing field {KEY_ML_KEM_768_PK}"))
            })?,
            ed25519_sk: Sensitive::new(ed25519_sk_bytes.ok_or_else(|| {
                BundleError::CborDecode(format!("missing field {KEY_ED25519_SK}"))
            })?),
            ed25519_pk: ed25519_pk
                .ok_or_else(|| BundleError::CborDecode(format!("missing field {KEY_ED25519_PK}")))?,
            ml_dsa_65_sk: Sensitive::new(ml_dsa_65_sk_bytes.ok_or_else(|| {
                BundleError::CborDecode(format!("missing field {KEY_ML_DSA_65_SK}"))
            })?),
            ml_dsa_65_pk: ml_dsa_65_pk.ok_or_else(|| {
                BundleError::CborDecode(format!("missing field {KEY_ML_DSA_65_PK}"))
            })?,
            created_at_ms: created_at_ms
                .ok_or_else(|| BundleError::CborDecode(format!("missing field {KEY_CREATED_AT}")))?,
        };

        // Reject non-canonical input. Cheapest reliable check: re-encode
        // and compare; passes iff the input was already canonical. Same
        // pattern as `card.rs::from_canonical_cbor`.
        let canonical = bundle.to_canonical_cbor()?;
        if canonical.as_slice() != bytes {
            // Drop the partially-decoded bundle (zeroizing its sensitive
            // fields) before returning the error; the caller never sees
            // these bytes.
            drop(bundle);
            return Err(BundleError::NonCanonicalCbor);
        }

        Ok(bundle)
    }
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

fn encode_map(entries: &[(Value, Value)]) -> Result<Vec<u8>, BundleError> {
    // RFC 8949 §4.2.1: map keys must be sorted bytewise lexicographically by
    // their deterministic CBOR encoding. We materialize each key's encoded
    // bytes and sort by that — robust against any future key shape (text,
    // byte, integer) without a separate code path per type.
    let mut sorted: Vec<(Vec<u8>, (Value, Value))> = entries
        .iter()
        .map(|pair| {
            let mut key_bytes = Vec::new();
            ciborium::ser::into_writer(&pair.0, &mut key_bytes)
                .map_err(|e| BundleError::CborDecode(e.to_string()))?;
            Ok((key_bytes, pair.clone()))
        })
        .collect::<Result<_, BundleError>>()?;
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    let value = Value::Map(sorted.into_iter().map(|(_, pair)| pair).collect());
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&value, &mut buf)
        .map_err(|e| BundleError::CborDecode(e.to_string()))?;
    Ok(buf)
}

/// Compute the canonical CBOR sort order for two map keys. Test-only: lets
/// the test module build deliberately non-canonical maps that are then
/// sorted (or deliberately not sorted) to exercise the strict-decoder
/// branches. Production encode does the sorting itself in [`encode_map`]
/// against materialised key bytes.
#[cfg(test)]
pub(super) fn canonical_key_cmp(a: &Value, b: &Value) -> std::cmp::Ordering {
    let mut a_buf = Vec::new();
    let mut b_buf = Vec::new();
    let _ = ciborium::ser::into_writer(a, &mut a_buf);
    let _ = ciborium::ser::into_writer(b, &mut b_buf);
    a_buf.cmp(&b_buf)
}

fn set_once<T>(slot: &mut Option<T>, v: T, key: &str) -> Result<(), BundleError> {
    if slot.is_some() {
        return Err(BundleError::DuplicateField(key.to_string()));
    }
    *slot = Some(v);
    Ok(())
}

fn take_text(v: Value) -> Result<String, BundleError> {
    match v {
        Value::Text(s) => Ok(s),
        _ => Err(BundleError::CborDecode("expected text string".into())),
    }
}

fn take_u64(v: Value) -> Result<u64, BundleError> {
    let i = match v {
        Value::Integer(i) => i,
        _ => return Err(BundleError::InvalidTimestamp),
    };
    i.try_into().map_err(|_| BundleError::InvalidTimestamp)
}

fn take_uuid(v: Value) -> Result<[u8; USER_UUID_LEN], BundleError> {
    let bytes = match v {
        Value::Bytes(b) => b,
        _ => return Err(BundleError::InvalidUuid),
    };
    bytes.try_into().map_err(|_: Vec<u8>| BundleError::InvalidUuid)
}

fn take_fixed_bytes<const N: usize>(
    v: Value,
    field: &'static str,
) -> Result<[u8; N], BundleError> {
    let bytes = match v {
        Value::Bytes(b) => b,
        _ => return Err(BundleError::CborDecode("expected byte string".into())),
    };
    let got = bytes.len();
    bytes.try_into().map_err(|_: Vec<u8>| BundleError::WrongKeySize {
        field,
        expected: N,
        got,
    })
}

fn take_sized_bytes(
    v: Value,
    field: &'static str,
    expected: usize,
) -> Result<Vec<u8>, BundleError> {
    let bytes = match v {
        Value::Bytes(b) => b,
        _ => return Err(BundleError::CborDecode("expected byte string".into())),
    };
    if bytes.len() != expected {
        return Err(BundleError::WrongKeySize {
            field,
            expected,
            got: bytes.len(),
        });
    }
    Ok(bytes)
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

    #[test]
    fn canonical_cbor_roundtrip() {
        let mut rng = ChaCha20Rng::from_seed([6u8; 32]);
        let b = generate("Bob", 1_714_060_800_001, &mut rng);
        let bytes = b.to_canonical_cbor().expect("encode");
        let parsed = IdentityBundle::from_canonical_cbor(&bytes).expect("decode");
        // `Sensitive` does not impl PartialEq (see crypto::secret docs), so
        // compare exposed contents explicitly.
        assert_eq!(parsed.user_uuid, b.user_uuid);
        assert_eq!(parsed.display_name, b.display_name);
        assert_eq!(parsed.x25519_sk.expose(), b.x25519_sk.expose());
        assert_eq!(parsed.x25519_pk, b.x25519_pk);
        assert_eq!(parsed.ml_kem_768_sk.expose(), b.ml_kem_768_sk.expose());
        assert_eq!(parsed.ml_kem_768_pk, b.ml_kem_768_pk);
        assert_eq!(parsed.ed25519_sk.expose(), b.ed25519_sk.expose());
        assert_eq!(parsed.ed25519_pk, b.ed25519_pk);
        assert_eq!(parsed.ml_dsa_65_sk.expose(), b.ml_dsa_65_sk.expose());
        assert_eq!(parsed.ml_dsa_65_pk, b.ml_dsa_65_pk);
        assert_eq!(parsed.created_at_ms, b.created_at_ms);
    }

    #[test]
    fn canonical_cbor_is_byte_stable() {
        let mut rng = ChaCha20Rng::from_seed([6u8; 32]);
        let b = generate("Bob", 1_714_060_800_001, &mut rng);
        let bytes_1 = b.to_canonical_cbor().expect("encode");
        let bytes_2 = b.to_canonical_cbor().expect("encode");
        assert_eq!(bytes_1, bytes_2, "canonical encoding must be deterministic");
    }

    #[test]
    fn parse_rejects_unknown_field() {
        // Build a minimal map that is canonical-shaped (keys sorted) but
        // contains a key the spec doesn't define. The decoder must reject
        // before the missing-field check has a chance to fire.
        let mut entries = vec![
            (Value::Text(KEY_USER_UUID.into()), Value::Bytes(vec![0u8; 16])),
            (Value::Text("rogue".into()), Value::Text("payload".into())),
        ];
        entries.sort_by(|a, b| super::canonical_key_cmp(&a.0, &b.0));
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&Value::Map(entries), &mut buf).unwrap();
        let err = IdentityBundle::from_canonical_cbor(&buf).unwrap_err();
        assert!(
            matches!(err, BundleError::UnknownField(ref s) if s == "rogue"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn parse_rejects_duplicate_field() {
        // Two identical text keys. ciborium accepts duplicates on encode (it
        // does not police map invariants for `Value::Map`); our decoder must
        // reject them.
        let entries = vec![
            (
                Value::Text(KEY_DISPLAY_NAME.into()),
                Value::Text("Alice".into()),
            ),
            (
                Value::Text(KEY_DISPLAY_NAME.into()),
                Value::Text("Bob".into()),
            ),
        ];
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&Value::Map(entries), &mut buf).unwrap();
        let err = IdentityBundle::from_canonical_cbor(&buf).unwrap_err();
        assert!(
            matches!(err, BundleError::DuplicateField(ref s) if s == "display_name"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn parse_rejects_wrong_x25519_pk_size() {
        // Build a full-shape valid bundle, then mutate `x25519_pk` to 30
        // bytes. Re-encoding (without the canonical-key sort) is fine here
        // because the original bundle was canonical and we are not changing
        // any keys.
        let mut rng = ChaCha20Rng::from_seed([8u8; 32]);
        let b = generate("X", 0, &mut rng);
        let bytes = b.to_canonical_cbor().unwrap();
        let value: Value = ciborium::de::from_reader(&bytes[..]).unwrap();
        let Value::Map(mut entries) = value else { panic!() };
        for (k, v) in entries.iter_mut() {
            if let Value::Text(s) = k {
                if s == KEY_X25519_PK {
                    *v = Value::Bytes(vec![0u8; 30]);
                }
            }
        }
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&Value::Map(entries), &mut buf).unwrap();
        let err = IdentityBundle::from_canonical_cbor(&buf).unwrap_err();
        assert!(
            matches!(
                err,
                BundleError::WrongKeySize {
                    field: "x25519_pk",
                    expected: 32,
                    got: 30,
                }
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn parse_rejects_non_canonical_key_order() {
        // Emit fields in §5 listing order (which is NOT canonical: e.g.
        // "user_uuid" sorts after "ml_*" because of length). The decoder
        // must catch this via re-encode-and-compare.
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        let b = generate("X", 0, &mut rng);
        let entries: Vec<(Value, Value)> = vec![
            (
                Value::Text(KEY_USER_UUID.into()),
                Value::Bytes(b.user_uuid.to_vec()),
            ),
            (
                Value::Text(KEY_DISPLAY_NAME.into()),
                Value::Text(b.display_name.clone()),
            ),
            (
                Value::Text(KEY_X25519_SK.into()),
                Value::Bytes(b.x25519_sk.expose().to_vec()),
            ),
            (
                Value::Text(KEY_X25519_PK.into()),
                Value::Bytes(b.x25519_pk.to_vec()),
            ),
            (
                Value::Text(KEY_ML_KEM_768_SK.into()),
                Value::Bytes(b.ml_kem_768_sk.expose().clone()),
            ),
            (
                Value::Text(KEY_ML_KEM_768_PK.into()),
                Value::Bytes(b.ml_kem_768_pk.clone()),
            ),
            (
                Value::Text(KEY_ED25519_SK.into()),
                Value::Bytes(b.ed25519_sk.expose().to_vec()),
            ),
            (
                Value::Text(KEY_ED25519_PK.into()),
                Value::Bytes(b.ed25519_pk.to_vec()),
            ),
            (
                Value::Text(KEY_ML_DSA_65_SK.into()),
                Value::Bytes(b.ml_dsa_65_sk.expose().clone()),
            ),
            (
                Value::Text(KEY_ML_DSA_65_PK.into()),
                Value::Bytes(b.ml_dsa_65_pk.clone()),
            ),
            (
                Value::Text(KEY_CREATED_AT.into()),
                Value::Integer(b.created_at_ms.into()),
            ),
        ];
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&Value::Map(entries), &mut buf).unwrap();
        let err = IdentityBundle::from_canonical_cbor(&buf).unwrap_err();
        assert!(
            matches!(err, BundleError::NonCanonicalCbor),
            "unexpected error: {err:?}"
        );
    }
}
