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

use crate::cbor::{classify_de, CborFault, SecretEntries};
use crate::crypto::kem::{
    generate_ml_kem_768, generate_x25519, ML_KEM_768_PK_LEN, ML_KEM_768_SK_LEN, X25519_PK_LEN,
    X25519_SK_LEN,
};
use crate::crypto::secret::{SecretBytes, Sensitive};
use crate::crypto::sig::{
    generate_ed25519, generate_ml_dsa_65, ED25519_PK_LEN, ED25519_SK_LEN, ML_DSA_65_PK_LEN,
    ML_DSA_65_SEED_LEN,
};
use crate::vault::canonical::CanonicalError;

// ---------------------------------------------------------------------------
// Constants (§14)
// ---------------------------------------------------------------------------

/// User UUID length, in bytes (§5).
pub const USER_UUID_LEN: usize = 16;

// BUNDLE_ML_DSA_65_SK_LEN intentionally re-exposes the seed-length constant under a bundle-prefixed name to make the spec/seed semantic explicit at the bundle layer.
/// ML-DSA-65 secret-key length as stored in the bundle, in bytes.
///
/// This is the FIPS 204 seed length (32), not the §5 spec's 4032-byte
/// expanded encoding. The bundle-prefixed name makes the seed-vs-expanded
/// distinction explicit at the bundle layer, where the on-disk encoding
/// is fixed at 32 B regardless of any future renaming in `crypto::sig`.
/// See module docs for the full rationale.
pub const BUNDLE_ML_DSA_65_SK_LEN: usize = ML_DSA_65_SEED_LEN;

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
    /// `ciborium` failed at the byte level. Carries a classified fault, never
    /// the upstream message (#474 — see [`crate::cbor`]).
    #[error("CBOR error: {0}")]
    CborFault(CborFault),

    /// The bytes parsed as CBOR but did not match the §5 bundle shape.
    /// A fixed structural description from a closed set of literals.
    #[error("malformed identity bundle: {0}")]
    Malformed(&'static str),

    /// Input parsed but was not in RFC 8949 §4.2.1 canonical form (e.g. keys
    /// not in bytewise lexicographic order, non-shortest length prefixes,
    /// indefinite-length items). Strictness defends against suite drift —
    /// the v1 bundle plaintext is fully specified, and any deviation in
    /// shape signals an out-of-spec writer or tampering.
    #[error("input was not in canonical CBOR form")]
    NonCanonicalCbor,

    /// A map key was present that the v1 spec does not define. The bundle is
    /// fully-specified; an unknown field signals suite drift and is rejected.
    ///
    /// Carries the entry's 0-based ordinal, never the key: this map is the
    /// DECRYPTED identity bundle, so an unrecognised key is unreviewed
    /// plaintext (#474).
    #[error("unknown bundle field at entry #{}", .index + 1)]
    UnknownField {
        /// 0-based ordinal of the offending entry.
        index: usize,
    },

    /// A known §5 field appeared more than once. RFC 8949 §5.4 forbids
    /// duplicates in canonical input. `field` is a spec key name — this is
    /// raised from `set_once`, reached only after the unknown-key arm has
    /// rejected anything not in the §5 set.
    #[error("duplicate bundle field: {0}")]
    DuplicateField(&'static str),

    /// A required field was absent from the parsed top-level CBOR map. The
    /// payload is the §5 CBOR key name (e.g. "user_uuid", "x25519_pk") to keep
    /// errors machine-readable; sibling errors include `UnknownField` and
    /// `WrongKeySize` for the same field-shape concerns.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// A fixed-size byte string field arrived with an unexpected length.
    #[error("wrong key size for {field}: expected {expected}, got {got}")]
    WrongKeySize {
        /// The §5 CBOR key whose value had the wrong length.
        field: &'static str,
        /// Expected byte length per §5 (see `crypto::kem` / `crypto::sig`
        /// length constants and [`BUNDLE_ML_DSA_65_SK_LEN`]).
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
/// Secret-key fields are wrapped in [`Sensitive`] (or
/// [`SecretBytes`] for
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
        let entries = SecretEntries::new(vec![
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
        ]);
        // `entries` holds a cleartext clone of all four long-term secret keys.
        // `SecretEntries::drop` wipes them at the end of this expression, on
        // the error path as well as the success path (#542) — the shared
        // type `crate::cbor::secret_tree` also uses for the record/block
        // decode paths (#547) and this file's own read side (#548, see
        // `from_canonical_cbor` below). This file no longer owns a private
        // copy of the wrapper.
        //
        // One deliberate behaviour difference from the retired
        // `ZeroizingEntries`: `SecretEntries::wipe` also zeroizes
        // `Value::Text`, which `ZeroizingEntries` did not. The bundle's only
        // text value is `display_name`, which `IdentityBundle` itself holds
        // as an unwrapped `String` — wiping the CLONE here is neither
        // harmful nor load-bearing, just a side effect of using the shared
        // type instead of a bundle-specific one.
        crate::vault::canonical::encode_canonical_map(entries.as_slice())
            .map_err(canonical_error_to_bundle_error)
    }

    /// Inverse of [`Self::to_canonical_cbor`]. Validates that every required field
    /// is present, fixed-size fields have the correct byte length, no
    /// unknown fields appear, no duplicates appear, and the input was
    /// already in RFC 8949 §4.2.1 canonical form.
    ///
    /// The strict canonical-input rule defends against suite drift: a v1
    /// reader must recognise v1 inputs only, so a future v2 writer (or a
    /// tampered file) is rejected loudly rather than silently accepted.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, BundleError> {
        let value: Value = ciborium::de::from_reader(bytes)
            .map_err(|e| BundleError::CborFault(classify_de(&e)))?;
        let Value::Map(m) = value else {
            return Err(BundleError::Malformed("expected top-level CBOR map"));
        };
        // #548: the parsed entry list holds cleartext copies of all four
        // long-term secret keys. The loop below consumes them one at a
        // time via `take_next`, and every `?` inside it — `Malformed` on a
        // non-string key, `DuplicateField` via `set_once`, `WrongKeySize`,
        // `UnknownField` — used to drop the remainder (a bare
        // `Vec<(Value, Value)>`'s `into_iter()`) unwiped. `SecretEntries`'s
        // `Drop` covers every exit: whatever `take_next` has not yet handed
        // out stays owned by `map` until it does.
        let mut map = SecretEntries::new(m);

        let mut user_uuid: Option<[u8; USER_UUID_LEN]> = None;
        let mut display_name: Option<String> = None;
        // #518: all FOUR secret-key slots are wrapped in `Sensitive` at
        // decode time, not held as a plain local and wiped after the fact
        // below. That makes each slot `ZeroizeOnDrop`-covered from the
        // moment the loop populates it — including the
        // `.ok_or(BundleError::MissingField(_))?` early-return paths in the
        // struct construction below, and any earlier `?` return later in
        // this loop (e.g. `UnknownField`, `DuplicateField`). The old plain
        // `Option<[u8; N]>` locals left no such coverage: `Option<[u8; N]>`
        // is `Copy`, so the struct construction below copied rather than
        // moved them out, leaving whichever key was already decoded sitting
        // on the stack when a later field's `?` returned early. See the
        // wipe block at the end of this function for what remains covered
        // there.
        //
        // The two `Vec`-typed ML-KEM / ML-DSA slots were missed by #518's
        // first pass and are covered here for the same reason. They are a
        // DIFFERENT defect from the `Copy` one above, which is why the
        // idiom-census grep could not see them: they never had a wipe to
        // find. Being `Vec`, they are moved rather than copied out — but
        // only on the path that REACHES the move. On any earlier `?` they
        // were still `Some(..)`, and a plain `Vec<u8>` frees its heap
        // buffer without zeroizing, so the ML-KEM-768 decapsulation key
        // (2400 bytes) and the ML-DSA-65 secret key were released to the
        // allocator intact.
        let mut x25519_sk_bytes: Option<Sensitive<[u8; X25519_SK_LEN]>> = None;
        let mut x25519_pk: Option<[u8; X25519_PK_LEN]> = None;
        let mut ml_kem_768_sk_bytes: Option<Sensitive<Vec<u8>>> = None;
        let mut ml_kem_768_pk: Option<Vec<u8>> = None;
        // Same rationale as `x25519_sk_bytes` above.
        let mut ed25519_sk_bytes: Option<Sensitive<[u8; ED25519_SK_LEN]>> = None;
        let mut ed25519_pk: Option<[u8; ED25519_PK_LEN]> = None;
        let mut ml_dsa_65_sk_bytes: Option<Sensitive<Vec<u8>>> = None;
        let mut ml_dsa_65_pk: Option<Vec<u8>> = None;
        let mut created_at_ms: Option<u64> = None;

        // `enumerate()`'s index is reconstructed by hand: `take_next` drains
        // the front one entry at a time, in the same order `into_iter()`
        // would have yielded them, so a plain counter reproduces the same
        // 0-based ordinal the pre-#548 code got from `enumerate()` — error
        // messages (`UnknownField`) cite this index, so it must match
        // exactly.
        let mut index = 0usize;
        while let Some((k, mut v)) = map.take_next() {
            // `v` has just left `SecretEntries`' protection (see
            // `SecretEntries::take_next`'s doc) — from this point it is
            // this loop's job to fold it into a zeroizing wrapper via one
            // of the `match` arms below, or wipe it explicitly on any path
            // that returns without doing so. The non-string-key check below
            // is exactly such a path: `k` failing the shape check says
            // nothing about `v`, which may still be a secret-key-shaped
            // `Value::Bytes` (#548 fix-round-1 G1).
            let Value::Text(key) = k else {
                crate::cbor::wipe_leaked_value(&mut v);
                return Err(BundleError::Malformed("non-string map key"));
            };
            match key.as_str() {
                KEY_USER_UUID => set_once(&mut user_uuid, take_uuid(v)?, KEY_USER_UUID)?,
                KEY_DISPLAY_NAME => set_once(&mut display_name, take_text(v)?, KEY_DISPLAY_NAME)?,
                KEY_X25519_SK => set_once(
                    &mut x25519_sk_bytes,
                    Sensitive::try_build([0u8; X25519_SK_LEN], |slot| {
                        take_fixed_bytes_into(v, KEY_X25519_SK, slot)
                    })?,
                    KEY_X25519_SK,
                )?,
                KEY_X25519_PK => set_once(
                    &mut x25519_pk,
                    {
                        // Bare `[u8; N]`, deliberately: this is a PUBLIC key,
                        // and `IdentityBundle` stores it unwrapped. The
                        // by-value shape is correct here and a visible choice —
                        // see `take_fixed_bytes_into`'s doc on why its absence
                        // for secrets is a nudge rather than a gate.
                        let mut pk = [0u8; X25519_PK_LEN];
                        take_fixed_bytes_into(v, KEY_X25519_PK, &mut pk)?;
                        pk
                    },
                    KEY_X25519_PK,
                )?,
                KEY_ML_KEM_768_SK => set_once(
                    &mut ml_kem_768_sk_bytes,
                    take_sized_secret(v, KEY_ML_KEM_768_SK, ML_KEM_768_SK_LEN)?,
                    KEY_ML_KEM_768_SK,
                )?,
                KEY_ML_KEM_768_PK => set_once(
                    &mut ml_kem_768_pk,
                    take_sized_public(v, KEY_ML_KEM_768_PK, ML_KEM_768_PK_LEN)?,
                    KEY_ML_KEM_768_PK,
                )?,
                KEY_ED25519_SK => set_once(
                    &mut ed25519_sk_bytes,
                    Sensitive::try_build([0u8; ED25519_SK_LEN], |slot| {
                        take_fixed_bytes_into(v, KEY_ED25519_SK, slot)
                    })?,
                    KEY_ED25519_SK,
                )?,
                KEY_ED25519_PK => set_once(
                    &mut ed25519_pk,
                    {
                        // Bare `[u8; N]`, deliberately: this is a PUBLIC key,
                        // and `IdentityBundle` stores it unwrapped. The
                        // by-value shape is correct here and a visible choice —
                        // see `take_fixed_bytes_into`'s doc on why its absence
                        // for secrets is a nudge rather than a gate.
                        let mut pk = [0u8; ED25519_PK_LEN];
                        take_fixed_bytes_into(v, KEY_ED25519_PK, &mut pk)?;
                        pk
                    },
                    KEY_ED25519_PK,
                )?,
                KEY_ML_DSA_65_SK => set_once(
                    &mut ml_dsa_65_sk_bytes,
                    take_sized_secret(v, KEY_ML_DSA_65_SK, ML_DSA_65_SEED_LEN)?,
                    KEY_ML_DSA_65_SK,
                )?,
                KEY_ML_DSA_65_PK => set_once(
                    &mut ml_dsa_65_pk,
                    take_sized_public(v, KEY_ML_DSA_65_PK, ML_DSA_65_PK_LEN)?,
                    KEY_ML_DSA_65_PK,
                )?,
                KEY_CREATED_AT => set_once(&mut created_at_ms, take_u64(v)?, KEY_CREATED_AT)?,
                _ => {
                    // Same seam as the non-string-key check above: an
                    // unrecognised key means `v` is never examined by any
                    // arm above, so it must be wiped explicitly here rather
                    // than falling through to a bare, unwiped `Value` drop
                    // (#548 fix-round-1 G1) — a forward-compatible v2
                    // bundle carrying a new secret-key field, opened by a
                    // v1 reader, is exactly the non-hypothetical case.
                    crate::cbor::wipe_leaked_value(&mut v);
                    return Err(BundleError::UnknownField { index });
                }
            }
            index += 1;
        }

        let bundle = IdentityBundle {
            user_uuid: user_uuid.ok_or(BundleError::MissingField(KEY_USER_UUID))?,
            display_name: display_name.ok_or(BundleError::MissingField(KEY_DISPLAY_NAME))?,
            // Already `Sensitive`-wrapped by the decode loop above (#518) —
            // no `Sensitive::new` needed here, and none of the leak this
            // fixed depended on where in this struct literal these two
            // fields sit.
            x25519_sk: x25519_sk_bytes.ok_or(BundleError::MissingField(KEY_X25519_SK))?,
            x25519_pk: x25519_pk.ok_or(BundleError::MissingField(KEY_X25519_PK))?,
            ml_kem_768_sk: ml_kem_768_sk_bytes
                .ok_or(BundleError::MissingField(KEY_ML_KEM_768_SK))?,
            ml_kem_768_pk: ml_kem_768_pk.ok_or(BundleError::MissingField(KEY_ML_KEM_768_PK))?,
            ed25519_sk: ed25519_sk_bytes.ok_or(BundleError::MissingField(KEY_ED25519_SK))?,
            ed25519_pk: ed25519_pk.ok_or(BundleError::MissingField(KEY_ED25519_PK))?,
            ml_dsa_65_sk: ml_dsa_65_sk_bytes.ok_or(BundleError::MissingField(KEY_ML_DSA_65_SK))?,
            ml_dsa_65_pk: ml_dsa_65_pk.ok_or(BundleError::MissingField(KEY_ML_DSA_65_PK))?,
            created_at_ms: created_at_ms.ok_or(BundleError::MissingField(KEY_CREATED_AT))?,
        };

        // Reject non-canonical input. Cheapest reliable check: re-encode
        // and compare; passes iff the input was already canonical. Same
        // pattern as `card.rs::from_canonical_cbor`.
        let mut canonical = bundle.to_canonical_cbor()?;
        let is_canonical = canonical.as_slice() == bytes;
        {
            use zeroize::Zeroize as _;
            // `canonical` is a full cleartext CBOR copy of every secret key;
            // wipe it before returning on either branch. See #357.
            //
            // The `x25519_sk_bytes` / `ed25519_sk_bytes` locals that used to
            // be wiped here explicitly are gone by this point regardless:
            // they are `Option<Sensitive<[u8; N]>>` now (see the
            // declarations above), so `.ok_or(...)?` in the struct
            // construction above MOVED each one — `Sensitive` is not
            // `Copy` — either into the `bundle` field it became, or, on an
            // early return from a field further down the struct literal,
            // into a temporary that is then dropped (and zeroized) right
            // there. This is a borrow-checker claim, not a memory one:
            // the move is a memcpy, and the source stack slot still holds
            // the bytes — the compiler only forbids NAMING that slot again
            // (E0382), which is why the old trailing `.zeroize()` call on
            // it had to be deleted rather than kept (#518). That residual
            // slot is not a regression (the pre-#518 code left an
            // equivalent unwiped temporary at the same point) — it is just
            // not the "nothing left to wipe" completeness this comment used
            // to claim; the wrapper's own `Drop` is what actually reclaims
            // it, on whichever of the two paths above the value ends up on.
            // The Vec-typed `ml_kem_768_sk_bytes` / `ml_dsa_65_sk_bytes`
            // locals are moved rather than copied, so on the path that
            // REACHES the move they need no wipe here. That is not the whole
            // story, and an earlier version of this comment stopped there:
            // on any `?` BEFORE their field in the struct literal they were
            // never moved at all, and a plain `Vec<u8>` frees its heap
            // buffer without zeroizing. They are now `Sensitive<Vec<u8>>`
            // (see the declarations above), so that path is covered by the
            // wrapper's `Drop` like the other two.
            canonical.zeroize();
        }
        if !is_canonical {
            // `bundle` drops here at scope exit, zeroizing its sensitive
            // fields; the caller never sees the partially-decoded value.
            return Err(BundleError::NonCanonicalCbor);
        }

        Ok(bundle)
    }
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

/// Lift a [`CanonicalError`] from the shared [`crate::vault::canonical`]
/// helpers into the bundle-layer error surface. Same pattern as
/// `identity::card::canonical_error_to_card_error` — a free function rather
/// than a `From` impl, since nothing in this crate matches over `BundleError`
/// exhaustively (unlike `RecordError` / `BlockError`, which gained a
/// dedicated `CanonicalSizeBoundExceeded` variant when they wired in the same
/// module) — so folding every arm into the two variants `BundleError`
/// already had is the smaller surface change.
///
/// `to_canonical_cbor`'s only call into the shared module is
/// [`crate::vault::canonical::encode_canonical_map`], which never itself
/// calls [`crate::vault::canonical::reject_floats_and_tags`] — so
/// `FloatRejected` / `TagRejected` are structurally unreachable from this
/// file's own call site today. They still need a match arm: `CanonicalError`
/// is one type shared across every caller of the module, not scoped per
/// function, so this `match` must stay exhaustive regardless of which arms
/// THIS caller can actually trigger.
fn canonical_error_to_bundle_error(e: CanonicalError) -> BundleError {
    match e {
        CanonicalError::CborEncode(fault) => BundleError::CborFault(fault),
        CanonicalError::FloatRejected { .. } => {
            BundleError::Malformed("float values are not permitted in canonical CBOR")
        }
        CanonicalError::TagRejected { .. } => {
            BundleError::Malformed("CBOR tags are not permitted in canonical CBOR")
        }
        // `actual`/`bound` are discarded rather than threaded through:
        // `BundleError::Malformed` only carries a fixed `&'static str`
        // literal (#474 — the bundle plaintext is decrypted content, so no
        // producer here interpolates a runtime value into an error
        // message), and this is a post-hoc tripwire for a future
        // `ciborium::Value` variant the shared module's size bound cannot
        // name, not a routine error path worth a richer payload.
        CanonicalError::CapacityBoundExceeded { .. } => {
            BundleError::Malformed("canonical CBOR encode exceeded its reserved size bound")
        }
    }
}

/// Compute the canonical CBOR sort order for two map keys. Test-only: lets
/// the test module build deliberately non-canonical maps that are then
/// sorted (or deliberately not sorted) to exercise the strict-decoder
/// branches. Production encode does the sorting itself inside
/// [`crate::vault::canonical::encode_canonical_map`] against materialised
/// key bytes.
#[cfg(test)]
pub(super) fn canonical_key_cmp(a: &Value, b: &Value) -> std::cmp::Ordering {
    let mut a_buf = Vec::new();
    let mut b_buf = Vec::new();
    let _ = ciborium::ser::into_writer(a, &mut a_buf);
    let _ = ciborium::ser::into_writer(b, &mut b_buf);
    a_buf.cmp(&b_buf)
}

fn set_once<T>(slot: &mut Option<T>, v: T, key: &'static str) -> Result<(), BundleError> {
    if slot.is_some() {
        return Err(BundleError::DuplicateField(key));
    }
    *slot = Some(v);
    Ok(())
}

fn take_text(v: Value) -> Result<String, BundleError> {
    match v {
        Value::Text(s) => Ok(s),
        _ => Err(BundleError::Malformed("expected text string")),
    }
}

fn take_u64(v: Value) -> Result<u64, BundleError> {
    // Mirror `card.rs::take_u64`'s split: a non-integer value is a type
    // error (Malformed), while an integer that doesn't fit `u64` is a
    // value error (InvalidTimestamp — `created_at` is the only u64 field
    // in the §5 record, so the variant name still describes the failure).
    let i = match v {
        Value::Integer(i) => i,
        _ => return Err(BundleError::Malformed("expected unsigned integer")),
    };
    i.try_into().map_err(|_| BundleError::InvalidTimestamp)
}

fn take_uuid(v: Value) -> Result<[u8; USER_UUID_LEN], BundleError> {
    let bytes = match v {
        Value::Bytes(b) => b,
        _ => return Err(BundleError::InvalidUuid),
    };
    bytes
        .try_into()
        .map_err(|_: Vec<u8>| BundleError::InvalidUuid)
}

/// Write-through fixed-size byte extractor.
///
/// The destination is supplied by the caller — which for every secret-key
/// site is a slot already wrapper-covered by `Sensitive::try_build` — so no
/// unwrapped `[u8; N]` is materialised in THIS frame or returned by value.
/// The by-value predecessor (`take_fixed_bytes`) left one copy here and
/// another in the caller's return temporary (#522); it is deleted rather
/// than kept alongside this, in the spirit of #503's move on both binding
/// crates.
///
/// **That deletion makes the shape ABSENT, not unrepresentable**, and an
/// earlier version of this comment claimed it made the shape "awkward to
/// write". It does not: reconstructing it takes three lines, and the two
/// PUBLIC-key call sites in `from_canonical_cbor` are exactly those three
/// lines (`let mut pk = [0u8; N]; take_fixed_bytes_into(..)?; pk`). That is
/// correct for a public key and clearly commented at both sites — but a
/// contributor copying the nearest neighbour gets the by-value shape for
/// free, so the deletion is a nudge, not a gate. Contrast #503/#500, which
/// this cited: there the unsafe shape stopped TYPECHECKING.
///
/// The source `Vec` is WRAPPED rather than wiped after the fact.
/// `Vec::try_into` reaches its array via `set_len(0)` + `ptr::read` — a COPY,
/// not a move-out — so the CBOR byte string's heap buffer would otherwise be
/// deallocated with the secret key still in it. That is the 2026-07-02
/// audit's finding C-4, and it was its last live sub-item.
/// `SecretBytes::new` MOVES the buffer, so `Drop` covers every exit below,
/// including the wrong-length `return`, with no trailing statement for
/// control flow to skip.
fn take_fixed_bytes_into<const N: usize>(
    v: Value,
    field: &'static str,
    out: &mut [u8; N],
) -> Result<(), BundleError> {
    let Value::Bytes(b) = v else {
        return Err(BundleError::Malformed("expected byte string"));
    };
    let bytes = SecretBytes::new(b);
    let got = bytes.len();
    if got != N {
        return Err(BundleError::WrongKeySize {
            field,
            expected: N,
            got,
        });
    }
    out.copy_from_slice(bytes.expose());
    Ok(())
}

/// Runtime-sized SECRET byte-string extractor.
///
/// Returns the wrapper, not its contents. That is the whole point: the buffer
/// is covered from before the length check — so the reject path cannot free a
/// secret-key-shaped byte string unwiped (audit C-4) — and the success path
/// hands back the SAME wrapper, so the heap buffer is never copied.
///
/// An intermediate version of this function returned `Result<Vec<u8>, _>` via
/// `bytes.expose().to_vec()` while its comment claimed "ownership of the same
/// heap buffer transfers and no copy is made". `expose()` yields `&[u8]` and
/// `to_vec()` allocates, so that was the opposite of what the line did: it
/// added a second live cleartext copy of the 2400-byte ML-KEM-768
/// decapsulation key on every unlock. Returning the wrapper removes both the
/// copy and the need for the claim.
fn take_sized_secret(
    v: Value,
    field: &'static str,
    expected: usize,
) -> Result<Sensitive<Vec<u8>>, BundleError> {
    let Value::Bytes(b) = v else {
        return Err(BundleError::Malformed("expected byte string"));
    };
    // `Sensitive::new` MOVES the `Vec`, so this is a wrap, not a copy.
    let bytes = Sensitive::new(b);
    let got = bytes.expose().len();
    if got != expected {
        return Err(BundleError::WrongKeySize {
            field,
            expected,
            got,
        });
    }
    Ok(bytes)
}

/// Runtime-sized PUBLIC byte-string extractor.
///
/// Deliberately a separate function from [`take_sized_secret`] rather than a
/// flag on it. Public keys need no wrapper, and naming the two apart means
/// reaching for the by-value shape on a secret is a visible choice at the call
/// site instead of the path of least resistance — the same reason the by-value
/// `take_fixed_bytes` was deleted rather than kept beside
/// [`take_fixed_bytes_into`].
fn take_sized_public(
    v: Value,
    field: &'static str,
    expected: usize,
) -> Result<Vec<u8>, BundleError> {
    let Value::Bytes(b) = v else {
        return Err(BundleError::Malformed("expected byte string"));
    };
    if b.len() != expected {
        return Err(BundleError::WrongKeySize {
            field,
            expected,
            got: b.len(),
        });
    }
    Ok(b)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    // --- take_fixed_bytes_into (#522, audit C-4) ----------------------------

    #[test]
    fn take_fixed_bytes_into_writes_through_on_the_happy_path() {
        let mut out = [0u8; 4];
        take_fixed_bytes_into(Value::Bytes(vec![1, 2, 3, 4]), "field", &mut out)
            .expect("exact length must be accepted");
        assert_eq!(out, [1, 2, 3, 4]);
    }

    #[test]
    fn take_fixed_bytes_into_rejects_a_wrong_length_and_reports_both_sizes() {
        let mut out = [0u8; 4];
        let err = take_fixed_bytes_into(Value::Bytes(vec![1, 2, 3]), "x25519_sk", &mut out)
            .expect_err("short input must be rejected");
        match err {
            BundleError::WrongKeySize {
                field,
                expected,
                got,
            } => {
                assert_eq!(field, "x25519_sk");
                assert_eq!(expected, 4);
                assert_eq!(got, 3);
            }
            other => panic!("expected WrongKeySize, got {other:?}"),
        }
    }

    #[test]
    fn take_fixed_bytes_into_leaves_the_destination_untouched_on_a_wrong_length() {
        // The destination is caller-owned and, at every production call site,
        // already wrapper-covered by `Sensitive::try_build`. A rejected decode
        // must not half-fill it. Seeded non-zero so "untouched" is
        // distinguishable from "zeroed", which a zero-seeded assertion could
        // not tell apart (a #513 review finding).
        let mut out = [0xAAu8; 4];
        let _ = take_fixed_bytes_into(Value::Bytes(vec![1, 2, 3]), "field", &mut out);
        assert_eq!(out, [0xAAu8; 4]);
    }

    #[test]
    fn take_fixed_bytes_into_rejects_a_too_long_input() {
        // The short case alone leaves `got > N` untested, and the two are not
        // symmetric in consequence: if `if got != N` ever regressed to
        // `if got < N`, an over-long CBOR byte string would reach
        // `copy_from_slice` and PANIC on the length mismatch. That input is
        // attacker-controlled (a tampered `identity.bundle.enc`), so the
        // regression would be a decode-path DoS, not a cosmetic slip.
        let mut out = [0xAAu8; 4];
        let err = take_fixed_bytes_into(Value::Bytes(vec![1, 2, 3, 4, 5]), "x25519_sk", &mut out)
            .expect_err("over-long input must be rejected, not truncated");
        assert!(matches!(
            err,
            BundleError::WrongKeySize {
                field: "x25519_sk",
                expected: 4,
                got: 5,
            }
        ));
        assert_eq!(out, [0xAAu8; 4], "rejected decode must not touch the slot");
    }

    #[test]
    fn take_fixed_bytes_into_rejects_an_empty_input() {
        let mut out = [0xAAu8; 4];
        let err = take_fixed_bytes_into(Value::Bytes(Vec::new()), "field", &mut out)
            .expect_err("empty input is not 4 bytes");
        assert!(matches!(err, BundleError::WrongKeySize { got: 0, .. }));
        assert_eq!(out, [0xAAu8; 4]);
    }

    // --- take_sized_secret / take_sized_public (#522) -----------------------

    #[test]
    fn take_sized_secret_accepts_the_exact_length_and_keeps_it_wrapped() {
        let got = take_sized_secret(Value::Bytes(vec![7u8; 5]), "ml_kem_768_sk", 5)
            .expect("exact length must be accepted");
        assert_eq!(got.expose().as_slice(), &[7u8; 5]);
    }

    #[test]
    fn take_sized_secret_rejects_a_wrong_length_and_reports_both_sizes() {
        // This arm had no test at all: `take_sized_bytes` covered the two
        // largest secrets in the bundle (the 2400-byte ML-KEM-768 key and the
        // ML-DSA-65 seed) and only its `take_fixed_bytes_into` sibling was
        // exercised.
        let err = take_sized_secret(Value::Bytes(vec![0u8; 3]), "ml_dsa_65_sk", 32)
            .expect_err("short input must be rejected");
        assert!(matches!(
            err,
            BundleError::WrongKeySize {
                field: "ml_dsa_65_sk",
                expected: 32,
                got: 3,
            }
        ));
    }

    #[test]
    fn take_sized_secret_rejects_a_non_bytes_cbor_value() {
        let err = take_sized_secret(Value::Text("nope".into()), "ml_kem_768_sk", 5)
            .expect_err("a text value is not a byte string");
        assert!(matches!(err, BundleError::Malformed(_)));
    }

    #[test]
    fn take_sized_public_round_trips_and_rejects_a_wrong_length() {
        let ok = take_sized_public(Value::Bytes(vec![1, 2, 3]), "ml_kem_768_pk", 3)
            .expect("exact length must be accepted");
        assert_eq!(ok, vec![1, 2, 3]);

        let err = take_sized_public(Value::Bytes(vec![1, 2]), "ml_kem_768_pk", 3)
            .expect_err("short input must be rejected");
        assert!(matches!(
            err,
            BundleError::WrongKeySize {
                field: "ml_kem_768_pk",
                expected: 3,
                got: 2,
            }
        ));
    }

    #[test]
    fn take_fixed_bytes_into_rejects_a_non_bytes_cbor_value() {
        let mut out = [0u8; 4];
        let err = take_fixed_bytes_into(Value::Text("nope".into()), "field", &mut out)
            .expect_err("a text value is not a byte string");
        assert!(matches!(err, BundleError::Malformed(_)));
    }

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

    // --- SecretEntries wipe-on-drop (#542 write side, #548 read side) ------
    //
    // `ZeroizingEntries` (bundle-private) and its own `wipe_calls()` counter
    // are gone — both are now `crate::cbor::SecretEntries` /
    // `crate::cbor::wipe_calls()`, shared with the record/block decode
    // paths. `SecretEntries::wipe` is private to `cbor::secret_tree` (not
    // `pub(crate)`), so unlike `ZeroizingEntries` it cannot be called
    // directly from here — the effect-based coverage the deleted
    // `zeroizing_entries_wipe_clears_every_byte_string` test had now lives
    // in `crate::cbor::secret_tree::tests::secret_entries_wipe_reaches_every_entry_including_keys`,
    // which has the same access `SecretEntries`'s own module does. What
    // stays here, ported onto the shared counter, is the DROP-invokes-wipe
    // regression check and the end-to-end production-path check.

    fn wipe_fixture() -> SecretEntries {
        SecretEntries::new(vec![
            (
                Value::Text("x25519_sk".into()),
                Value::Bytes(vec![0x42; 32]),
            ),
            (Value::Text("created_at".into()), Value::Integer(7.into())),
            (
                Value::Text("ed25519_sk".into()),
                Value::Bytes(vec![0x99; 64]),
            ),
        ])
    }

    #[test]
    fn secret_entries_drop_runs_wipe() {
        // The security claim (#542/#548) is specifically that `Drop` covers
        // the unwinding and early-return paths a trailing sweep would skip.
        // Ported from `zeroizing_entries_drop_runs_wipe` onto the shared
        // `crate::cbor::wipe_calls()` counter now that the wrapper moved.
        let before = crate::cbor::wipe_calls();
        {
            let _entries = wipe_fixture();
        }
        assert_eq!(
            crate::cbor::wipe_calls(),
            before + 1,
            "scope exit did not call wipe — is `impl Drop for SecretEntries` still there?"
        );
    }

    #[test]
    fn to_canonical_cbor_wipes_its_entry_list() {
        // The end-to-end version of the above: the production encode path must
        // wipe, without any test calling `wipe` itself.
        let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
        let b = generate("wipe-check", 1_714_060_800_000, &mut rng);
        let before = crate::cbor::wipe_calls();
        let _bytes = b.to_canonical_cbor().expect("encode");
        assert_eq!(
            crate::cbor::wipe_calls(),
            before + 1,
            "to_canonical_cbor left its entry list unwiped"
        );
    }

    /// #548 — the C-4 read side, and the audit's own FIRST-named sub-item.
    ///
    /// `from_canonical_cbor` used to destructure the parsed top level into a
    /// bare `Vec<(Value, Value)>` and consume it via `into_iter().enumerate()`.
    /// The wipe happened on the HAPPY path only: any early `?` inside the
    /// field loop dropped the iterator's remaining entries — including
    /// not-yet-consumed `Value::Bytes` secret-key payloads — unwiped.
    ///
    /// The wipe is not observable from safe Rust, so this pins the
    /// mechanism: taking an early-return path must still have invoked the
    /// wipe. The fixture puts a THIRD entry (`ed25519_sk`) after the
    /// duplicate so there is a genuinely not-yet-consumed secret key still
    /// inside `SecretEntries` when `DuplicateField` fires and `map` drops —
    /// not just a counter increment on an already-empty container.
    #[test]
    fn an_early_return_inside_the_field_loop_still_wipes() {
        let bytes = duplicate_field_bundle_cbor_for_test();

        let before = crate::cbor::wipe_calls();
        let err = IdentityBundle::from_canonical_cbor(&bytes)
            .expect_err("duplicate field must be rejected");
        assert!(
            matches!(err, BundleError::DuplicateField(s) if s == KEY_X25519_SK),
            "expected DuplicateField(\"x25519_sk\"), got {err:?}"
        );
        assert!(
            crate::cbor::wipe_calls() > before,
            "the early-return path did not wipe the not-yet-consumed entries (#548)"
        );
    }

    /// A CBOR map whose first entry is a valid `x25519_sk`, whose second
    /// entry duplicates the same key (so `set_once` fires `DuplicateField`
    /// right after the first secret key has been consumed via `take_next`),
    /// and whose third entry (`ed25519_sk`) is never reached — it is still
    /// sitting inside `SecretEntries` when the `?` on the duplicate
    /// propagates. All three keys use runtime-random bytes, not literals.
    fn duplicate_field_bundle_cbor_for_test() -> Vec<u8> {
        let mut rng = ChaCha20Rng::from_seed([77u8; 32]);
        let mut first = [0u8; X25519_SK_LEN];
        rng.fill_bytes(&mut first);
        let mut duplicate = [0u8; X25519_SK_LEN];
        rng.fill_bytes(&mut duplicate);
        let mut third = [0u8; ED25519_SK_LEN];
        rng.fill_bytes(&mut third);

        let entries = vec![
            (
                Value::Text(KEY_X25519_SK.into()),
                Value::Bytes(first.to_vec()),
            ),
            (
                Value::Text(KEY_X25519_SK.into()),
                Value::Bytes(duplicate.to_vec()),
            ),
            (
                Value::Text(KEY_ED25519_SK.into()),
                Value::Bytes(third.to_vec()),
            ),
        ];
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&Value::Map(entries), &mut buf).unwrap();
        buf
    }

    /// #548 fix-round-1 G1 — the non-string-key early return.
    ///
    /// `k` failing the `Value::Text` shape check says nothing about `v`:
    /// before the G1 fix, `v` was simply dropped as a bare, unwiped
    /// `ciborium::Value` on this path. The value here is deliberately
    /// secret-key-shaped (32 runtime-random bytes under a non-string key)
    /// to stand in for the failure scenario reviewer G1 named: a
    /// forward-compatible v2 bundle field whose KEY encoding a v1 reader
    /// cannot even interpret as text.
    ///
    /// **The assertion must be an EXACT count, not `> before`.** A first
    /// draft of this test used `> before` and passed even with
    /// `wipe_leaked_value` deleted (verified by mutation): `map`
    /// (`SecretEntries`) still drops at function exit either way, and
    /// `SecretEntries::wipe` increments the shared counter UNCONDITIONALLY
    /// at its top, before it even looks at whether anything remains to
    /// wipe. That one tick is a constant here, present with or without the
    /// G1 fix, and `> before` cannot tell "map's own drop fired" apart from
    /// "map's own drop fired AND `wipe_leaked_value` also ran". Exactly two
    /// ticks (`SecretEntries::drop` + `wipe_leaked_value`) is what the fix
    /// actually adds; one entry means one `take_next` call, so nothing else
    /// on this path can tick the counter a third time.
    #[test]
    fn non_string_map_key_wipes_its_value() {
        let mut rng = ChaCha20Rng::from_seed([88u8; 32]);
        let mut secret_shaped = [0u8; X25519_SK_LEN];
        rng.fill_bytes(&mut secret_shaped);

        let entries = vec![(
            Value::Integer(0.into()),
            Value::Bytes(secret_shaped.to_vec()),
        )];
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&Value::Map(entries), &mut bytes).unwrap();

        let before = crate::cbor::wipe_calls();
        let err = IdentityBundle::from_canonical_cbor(&bytes)
            .expect_err("a non-string map key must be rejected");
        assert!(
            matches!(err, BundleError::Malformed("non-string map key")),
            "expected Malformed(\"non-string map key\"), got {err:?}"
        );
        assert_eq!(
            crate::cbor::wipe_calls(),
            before + 2,
            "expected 2 wipes (SecretEntries::drop on the now-empty map, plus \
             wipe_leaked_value on `v`) — the non-string-key early return did \
             not wipe its value (#548 fix-round-1 G1)"
        );
    }

    /// #548 fix-round-1 G1 — the `UnknownField` early return.
    ///
    /// An unrecognised key means no `match` arm ever examines `v`; before
    /// the G1 fix it fell through to a bare, unwiped `ciborium::Value`
    /// drop, same as the non-string-key case above. This is the reviewer's
    /// own named failure scenario, not a hypothetical: a v2 bundle carrying
    /// a new secret-key field, opened by a v1 client, hits exactly this
    /// arm with that field's `Value::Bytes` still populated.
    ///
    /// Exact-count assertion for the same reason as the non-string-key test
    /// above — see that test's doc for why `> before` does not pin this.
    #[test]
    fn unknown_field_wipes_its_value() {
        let mut rng = ChaCha20Rng::from_seed([99u8; 32]);
        let mut secret_shaped = [0u8; X25519_SK_LEN];
        rng.fill_bytes(&mut secret_shaped);

        let entries = vec![(
            Value::Text("rogue".into()),
            Value::Bytes(secret_shaped.to_vec()),
        )];
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&Value::Map(entries), &mut bytes).unwrap();

        let before = crate::cbor::wipe_calls();
        let err = IdentityBundle::from_canonical_cbor(&bytes)
            .expect_err("an unrecognised field must be rejected");
        assert!(
            matches!(err, BundleError::UnknownField { index: 0 }),
            "expected UnknownField {{ index: 0 }}, got {err:?}"
        );
        assert_eq!(
            crate::cbor::wipe_calls(),
            before + 2,
            "expected 2 wipes (SecretEntries::drop on the now-empty map, plus \
             wipe_leaked_value on `v`) — the UnknownField early return did \
             not wipe its value (#548 fix-round-1 G1)"
        );
    }

    // --- canonical_error_to_bundle_error (#548 fix-round-1 G2) -------------
    //
    // Zero coverage before this section: three of its four arms are
    // structurally unreachable from `to_canonical_cbor`'s own call into
    // `encode_canonical_map` (see that function's doc), so swapping any of
    // the `FloatRejected` / `TagRejected` / `CapacityBoundExceeded` message
    // literals, or mis-mapping one to the wrong `BundleError` variant, left
    // every test in the workspace green. Modelled on
    // `identity::card::canonical_error_capacity_bound_exceeded_maps_to_card_error`
    // — construct each `CanonicalError` arm directly rather than driving it
    // through the shared encoder, since three of the four cannot be reached
    // that way at all.

    #[test]
    fn canonical_error_cbor_encode_maps_to_cbor_fault() {
        let fault = crate::cbor::CborFault {
            kind: crate::cbor::CborErrorKind::Syntax,
            offset: Some(7),
        };
        match canonical_error_to_bundle_error(CanonicalError::CborEncode(fault)) {
            BundleError::CborFault(got) => assert_eq!(got, fault),
            other => panic!("expected CborFault, got {other:?}"),
        }
    }

    #[test]
    fn canonical_error_float_rejected_maps_to_bundle_error() {
        let err = CanonicalError::FloatRejected { field: "<root>" };
        match canonical_error_to_bundle_error(err) {
            BundleError::Malformed(msg) => {
                assert_eq!(msg, "float values are not permitted in canonical CBOR");
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn canonical_error_tag_rejected_maps_to_bundle_error() {
        let err = CanonicalError::TagRejected { field: "<root>" };
        match canonical_error_to_bundle_error(err) {
            BundleError::Malformed(msg) => {
                assert_eq!(msg, "CBOR tags are not permitted in canonical CBOR");
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn canonical_error_capacity_bound_exceeded_maps_to_bundle_error() {
        let err = CanonicalError::CapacityBoundExceeded {
            actual: 42,
            bound: 17,
        };
        match canonical_error_to_bundle_error(err) {
            BundleError::Malformed(msg) => {
                assert_eq!(
                    msg,
                    "canonical CBOR encode exceeded its reserved size bound"
                );
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
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

    // #518: the `.ok_or(BundleError::MissingField(_))?` chain in the struct
    // construction returns BEFORE the explicit wipe block below it, leaving
    // whichever secret keys were already decoded on the stack.
    // `Option<[u8; N]>` is `Copy`, so struct construction copied rather than
    // moved them out.
    //
    // As in mnemonic.rs, this pins the path and its error variant, not the
    // wipe itself — a dead stack frame is not observable from safe Rust
    // (spec §5.4). Do not read a passing error-variant match here as
    // evidence the memory was zeroed. No pre-existing test in this file or
    // in `core/tests/` covered `MissingField` before this one (checked via
    // `grep -rn MissingField core/tests/ core/src/unlock/bundle.rs`).
    #[test]
    fn from_canonical_cbor_reports_the_missing_field_and_takes_the_early_return() {
        // Build a valid, full-shape bundle, then drop `ed25519_sk` from its
        // encoded map. `x25519_sk` (sorted earlier under canonical CBOR key
        // order) is still present and gets decoded successfully into the
        // now-`Sensitive`-wrapped `x25519_sk_bytes` local before the loop
        // finishes; the missing `ed25519_sk` then makes the struct
        // construction's `ed25519_sk_bytes.ok_or(MissingField(..))?` return
        // early. Pre-fix, that early return skipped the explicit wipe block
        // entirely, leaving the already-decoded `x25519_sk_bytes` Copy-typed
        // stack slot behind — exactly the path this test pins.
        let err = IdentityBundle::from_canonical_cbor(&bundle_bytes_without(KEY_ED25519_SK))
            .expect_err("ed25519_sk is a required field");
        assert!(
            matches!(err, BundleError::MissingField(s) if s == KEY_ED25519_SK),
            "expected MissingField(\"ed25519_sk\"), got {err:?}"
        );
    }

    // The `Vec`-typed sibling of the test above, and the reason the two are
    // separate. Dropping `x25519_pk` returns at the SECOND field of the
    // struct literal, so BOTH `ml_kem_768_sk_bytes` and `ml_dsa_65_sk_bytes`
    // are still `Some(..)` and still unmoved when the `?` fires — the ML-KEM
    // key is not reachable in that state by removing `ed25519_sk`, because
    // by then it has already been moved into the struct.
    //
    // Those two slots were `Option<Vec<u8>>` until this fix, so the early
    // return freed a 2400-byte ML-KEM-768 decapsulation key and an ML-DSA-65
    // secret key to the allocator without zeroizing. The idiom census could
    // not see them: it greps for `.zeroize()` calls, and these never had one.
    //
    // Same disclaimer as above — this pins that the path is reached and
    // keeps its error variant. It does NOT observe the wipe.
    #[test]
    // Named for what it ASSERTS, not for the memory property it sits beside.
    // The previous name — `..._leaves_both_pq_secret_keys_wrapped` — promised
    // a wrappedness check the body does not make (and could not: wrappedness
    // is not observable from safe Rust). The two PQ keys being `Sensitive` is
    // enforced by their declared types, not here.
    fn from_canonical_cbor_reports_the_missing_pk_before_reading_the_pq_keys() {
        let err = IdentityBundle::from_canonical_cbor(&bundle_bytes_without(KEY_X25519_PK))
            .expect_err("x25519_pk is a required field");
        assert!(
            matches!(err, BundleError::MissingField(s) if s == KEY_X25519_PK),
            "expected MissingField(\"x25519_pk\"), got {err:?}"
        );
    }

    /// Encode a valid full-shape bundle, then drop exactly one key from its
    /// CBOR map. Removing one entry from an already-canonically-sorted map
    /// leaves the remainder sorted, so no re-sort is needed before
    /// re-encoding.
    fn bundle_bytes_without(omit: &str) -> Vec<u8> {
        let mut rng = ChaCha20Rng::from_seed([44u8; 32]);
        let b = generate("Carol", 1_714_060_800_002, &mut rng);
        let bytes = b.to_canonical_cbor().expect("encode");

        let value: Value = ciborium::de::from_reader(&bytes[..]).expect("re-decode as CBOR");
        let Value::Map(entries) = value else {
            panic!("expected top-level map")
        };
        let before = entries.len();
        let truncated: Vec<(Value, Value)> = entries
            .into_iter()
            .filter(|(k, _)| !matches!(k, Value::Text(s) if s == omit))
            .collect();
        // Non-vacuity: without this, a typo'd or renamed `omit` would remove
        // nothing, the bundle would decode cleanly, and the caller's
        // `expect_err` would fail with a confusing message far from the
        // cause. Derived from `before` rather than hardcoded so adding a
        // bundle field doesn't turn this into a false failure.
        assert_eq!(
            truncated.len(),
            before - 1,
            "expected exactly one key ({omit}) to be removed from the {before}-field bundle"
        );
        let mut truncated_bytes = Vec::new();
        ciborium::ser::into_writer(&Value::Map(truncated), &mut truncated_bytes)
            .expect("re-encode");
        truncated_bytes
    }

    /// Build a minimal, canonical-shaped CBOR bundle map containing exactly
    /// the required `user_uuid` field plus an out-of-spec key `extra_key`.
    /// Shared by both unknown-field tests below: the fixture shape is
    /// identical, only the offending key text differs, which is exactly the
    /// axis `unknown_bundle_field_reports_an_index_not_the_key` (#474)
    /// exercises.
    fn bundle_bytes_with_extra_field(extra_key: &str) -> Vec<u8> {
        let mut entries = vec![
            (
                Value::Text(KEY_USER_UUID.into()),
                Value::Bytes(vec![0u8; 16]),
            ),
            (Value::Text(extra_key.into()), Value::Text("payload".into())),
        ];
        entries.sort_by(|a, b| super::canonical_key_cmp(&a.0, &b.0));
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&Value::Map(entries), &mut buf).unwrap();
        buf
    }

    #[test]
    fn parse_rejects_unknown_field() {
        // Contains a key the spec doesn't define. The decoder must reject
        // before the missing-field check has a chance to fire. `"rogue"`
        // (5 bytes) sorts before `"user_uuid"` (9 bytes) under canonical
        // CBOR key order, so the offending entry is index 0 — stronger than
        // the pre-#474 assertion (which matched the key text itself) since
        // it pins the reported ordinal to the fixture's actual layout rather
        // than merely checking the variant shape.
        let bytes = bundle_bytes_with_extra_field("rogue");
        let err = IdentityBundle::from_canonical_cbor(&bytes).unwrap_err();
        assert!(
            matches!(err, BundleError::UnknownField { index: 0 }),
            "unexpected error: {err:?}"
        );
    }

    /// `bundle.rs:435` carries an arbitrary map key from the DECRYPTED
    /// identity bundle. It must become an ordinal (#474).
    #[test]
    fn unknown_bundle_field_reports_an_index_not_the_key() {
        const ROGUE: &str = "rogue-secret-looking-key";
        // Reuse the shared fixture builder from `parse_rejects_unknown_field`.
        let bytes = bundle_bytes_with_extra_field(ROGUE);

        let err = IdentityBundle::from_canonical_cbor(&bytes)
            .expect_err("unknown field must be rejected");

        assert!(
            matches!(err, BundleError::UnknownField { .. }),
            "expected UnknownField, got {err:?}"
        );
        assert!(
            !format!("{err}").contains(ROGUE),
            "the decrypted bundle key leaked into the message: {err}"
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
            matches!(err, BundleError::DuplicateField(s) if s == "display_name"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn parse_rejects_a_wrong_size_on_every_rewritten_extraction_site() {
        // #522 hand-rewrote six extraction sites; end-to-end coverage existed
        // for exactly one (`x25519_pk`, below). That matters more than usual
        // here because the length constants collide:
        //
        //     X25519_PK_LEN == ED25519_PK_LEN == 32
        //     X25519_SK_LEN == ED25519_SK_LEN == 32
        //
        // so a copy-paste slip between sibling sites — the new inline
        // `{ let mut pk = ...; take_fixed_bytes_into(v, KEY_X25519_PK, ..) }`
        // block retaining the wrong KEY_ constant, say — is invisible to a
        // round-trip test AND to a length check. Asserting that the reported
        // `field` is the key we actually corrupted is what pins it.
        let sites: &[(&str, usize)] = &[
            (KEY_X25519_SK, X25519_SK_LEN),
            (KEY_X25519_PK, X25519_PK_LEN),
            (KEY_ED25519_SK, ED25519_SK_LEN),
            (KEY_ED25519_PK, ED25519_PK_LEN),
            (KEY_ML_KEM_768_SK, ML_KEM_768_SK_LEN),
            (KEY_ML_DSA_65_SK, BUNDLE_ML_DSA_65_SK_LEN),
        ];

        let mut rng = ChaCha20Rng::from_seed([21u8; 32]);
        let b = generate("Y", 0, &mut rng);
        let canonical = b.to_canonical_cbor().unwrap();

        for (key, expected) in sites {
            let value: Value = ciborium::de::from_reader(&canonical[..]).unwrap();
            let Value::Map(mut entries) = value else {
                panic!("bundle is a map")
            };
            let mut corrupted = false;
            for (k, v) in entries.iter_mut() {
                if matches!(k, Value::Text(s) if s == key) {
                    *v = Value::Bytes(vec![0u8; expected + 1]);
                    corrupted = true;
                }
            }
            assert!(corrupted, "{key} not present in the encoded bundle");

            let mut buf = Vec::new();
            ciborium::ser::into_writer(&Value::Map(entries), &mut buf).unwrap();
            let err = IdentityBundle::from_canonical_cbor(&buf)
                .expect_err("an over-long {key} must be rejected");
            match err {
                BundleError::WrongKeySize {
                    field,
                    expected: e,
                    got,
                } => {
                    assert_eq!(field, *key, "wrong field reported for {key}");
                    assert_eq!(e, *expected, "wrong expected length for {key}");
                    assert_eq!(got, expected + 1, "wrong got length for {key}");
                }
                other => panic!("expected WrongKeySize for {key}, got {other:?}"),
            }
        }
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
        let Value::Map(mut entries) = value else {
            panic!()
        };
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
    fn parse_distinguishes_created_at_type_mismatch_from_range() {
        // A `created_at` set to a text string must report a structural
        // Malformed literal ("expected unsigned integer"), not the
        // misleading `InvalidTimestamp` (which is reserved for "is an
        // integer but doesn't fit u64").
        let mut rng = ChaCha20Rng::from_seed([10u8; 32]);
        let b = generate("X", 0, &mut rng);
        let bytes = b.to_canonical_cbor().unwrap();
        let value: Value = ciborium::de::from_reader(&bytes[..]).unwrap();
        let Value::Map(mut entries) = value else {
            panic!()
        };
        for (k, v) in entries.iter_mut() {
            if let Value::Text(s) = k {
                if s == KEY_CREATED_AT {
                    *v = Value::Text("not a timestamp".into());
                }
            }
        }
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&Value::Map(entries), &mut buf).unwrap();
        let err = IdentityBundle::from_canonical_cbor(&buf).unwrap_err();
        assert!(
            matches!(err, BundleError::Malformed("expected unsigned integer")),
            "expected Malformed(\"expected unsigned integer\") for non-integer created_at, got: {err:?}"
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
