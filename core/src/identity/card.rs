//! Contact Card (`docs/crypto-design.md` §6).
//!
//! A Contact Card is the public, self-signed CBOR record a user shares to
//! identify themselves to others. It carries the four public keys (X25519,
//! ML-KEM-768, Ed25519, ML-DSA-65) plus a contact UUID, display name, and a
//! creation timestamp; the two self-signature fields commit the rest of the
//! card under §8's hybrid-signature construction with role
//! [`crate::crypto::sig::SigRole::Card`].
//!
//! ## Canonical CBOR encoding
//!
//! §6 specifies the wire form as a CBOR map. Both the self-signature
//! ([`signed_bytes`]) and the fingerprint (`fingerprint::fingerprint`) commit
//! to *bytes*, not to a logical record, so the encoding has to be
//! deterministic: the same logical card must always produce the same bytes
//! across implementations. This module pins the rules used here:
//!
//! 1. **Map shape** — the card is encoded as a CBOR map with text-string
//!    keys, never an array. (This is the §6 wire form.)
//! 2. **Field order** — keys appear in §6's listed order, *not* RFC 8949
//!    §4.2 lexicographic order. We treat the §6 listing as normative for
//!    canonicalization. A CBOR-canonical (RFC 8949 §4.2) consumer that
//!    reorders keys produces different bytes and therefore a different
//!    fingerprint, breaking interop. The byte form is pinned by KAT
//!    (`canonical_cbor_byte_kat`) and cross-verified against the Python
//!    `cbor2` reference; clean-room implementations must match byte-for-byte.
//! 3. **Shortest-form lengths and integers** — every length prefix and every
//!    integer is encoded in CBOR's shortest valid form. `ciborium`'s default
//!    `Value` serializer enforces this for both. No floats, no
//!    indefinite-length items, no tags.
//! 4. **Duplicate keys** — rejected on parse (RFC 8949 §5.4).
//!
//! ## Parse leniency
//!
//! [`ContactCard::from_canonical_cbor`] tolerates inputs that arrive with
//! keys in arbitrary order so long as no key is duplicated and every
//! required field is present with the right type and length. Re-encoding
//! through [`ContactCard::to_canonical_cbor`] then yields the canonical
//! byte form. This means a non-canonical peer can be re-canonicalized
//! locally, but the locally-produced fingerprint will differ from the
//! peer's if the peer was non-canonical to start with — which is correct
//! behaviour: the protocol's interop contract is canonical bytes.
//!
//! ## Field naming
//!
//! The Rust struct field `created_at_ms` carries `u64` Unix-millisecond
//! timestamps; the CBOR map key in §6 is `"created_at"`. The struct name
//! is more descriptive of the unit; the CBOR key follows the spec.

use ciborium::Value;

use crate::crypto::sig::{
    self, Ed25519Public, Ed25519Secret, Ed25519Sig, HybridSig, MlDsa65Public, MlDsa65Secret,
    MlDsa65Sig, SigError, SigRole, ED25519_PK_LEN, ED25519_SIG_LEN, ML_DSA_65_PK_LEN,
    ML_DSA_65_SIG_LEN,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Current Contact Card schema version. v1 vaults pin this to 1.
pub const CARD_VERSION_V1: u8 = 1;

/// X25519 public-key length, in bytes (§14). Re-exported here for the card
/// struct's invariants — keeps callers from importing across module
/// boundaries when they only need the card.
pub const X25519_PK_LEN: usize = 32;

/// ML-KEM-768 public-key length, in bytes (§14).
pub const ML_KEM_768_PK_LEN: usize = 1184;

/// Contact UUID length, in bytes (§14).
pub const CONTACT_UUID_LEN: usize = 16;

// CBOR map keys (§6). String literals only used here; centralised so a typo
// becomes a compile-time fix rather than a silent encoding drift.
const KEY_CARD_VERSION: &str = "card_version";
const KEY_CONTACT_UUID: &str = "contact_uuid";
const KEY_DISPLAY_NAME: &str = "display_name";
const KEY_X25519_PK: &str = "x25519_pk";
const KEY_ML_KEM_768_PK: &str = "ml_kem_768_pk";
const KEY_ED25519_PK: &str = "ed25519_pk";
const KEY_ML_DSA_65_PK: &str = "ml_dsa_65_pk";
const KEY_CREATED_AT: &str = "created_at";
const KEY_SELF_SIG_ED: &str = "self_sig_ed";
const KEY_SELF_SIG_PQ: &str = "self_sig_pq";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from card encode, parse, sign, and verify.
#[derive(Debug, thiserror::Error)]
pub enum CardError {
    /// CBOR encoding produced an I/O or serialization error from `ciborium`.
    /// In practice this only fires on encoder bugs — the in-memory writer
    /// can't run out of space.
    #[error("CBOR encode failure: {0}")]
    CborEncode(String),

    /// CBOR decoding produced an I/O or deserialization error from
    /// `ciborium`, or the byte stream did not contain a top-level map, or
    /// trailing bytes followed the map.
    #[error("CBOR decode failure: {0}")]
    CborDecode(String),

    /// `card_version` was not 1. v1 implementations reject any other value;
    /// future suites may relax this on a per-suite basis.
    #[error("invalid card version (expected {CARD_VERSION_V1})")]
    InvalidVersion,

    /// A fixed-size field arrived with an unexpected length, or a required
    /// field was missing, duplicated, or had the wrong CBOR type.
    #[error("invalid field length")]
    InvalidFieldLength,

    /// A signature on the card did not verify. Variants of [`SigError`] —
    /// [`SigError::Ed25519VerifyFailed`] and [`SigError::MlDsa65VerifyFailed`]
    /// — distinguish which half rejected.
    #[error("signature verification failed")]
    SigVerifyFailed(#[from] SigError),
}

// ---------------------------------------------------------------------------
// Card
// ---------------------------------------------------------------------------

/// Contact Card. The CBOR shape and field order are normative — see
/// `docs/crypto-design.md` §6.
///
/// All fields are public material plus signatures; nothing in this struct is
/// secret. `Debug` is therefore derived normally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactCard {
    /// Schema version. v1 == [`CARD_VERSION_V1`]; other values reject on
    /// parse.
    pub card_version: u8,
    /// 128-bit owner UUID, the same bytes as `user_uuid` in the Identity
    /// Bundle (§5).
    pub contact_uuid: [u8; CONTACT_UUID_LEN],
    /// User-facing label. UTF-8; no length cap enforced here (the cap, if
    /// any, is a UI / vault-config concern).
    pub display_name: String,
    /// X25519 public key, 32 bytes.
    pub x25519_pk: [u8; X25519_PK_LEN],
    /// ML-KEM-768 public (encapsulation) key, 1184 bytes (FIPS 203).
    pub ml_kem_768_pk: Vec<u8>,
    /// Ed25519 public key, 32 bytes.
    pub ed25519_pk: Ed25519Public,
    /// ML-DSA-65 public key, 1952 bytes (FIPS 204).
    pub ml_dsa_65_pk: Vec<u8>,
    /// Creation timestamp, Unix milliseconds. Encoded under the §6 CBOR key
    /// `"created_at"`; the struct name is more descriptive of the unit.
    pub created_at_ms: u64,
    /// Ed25519 self-signature over [`signed_bytes`]. 64 bytes.
    pub self_sig_ed: Ed25519Sig,
    /// ML-DSA-65 self-signature over [`signed_bytes`]. 3309 bytes.
    pub self_sig_pq: Vec<u8>,
}

impl ContactCard {
    /// Canonical-CBOR encoding of the card *excluding* `self_sig_ed` and
    /// `self_sig_pq`. This is the byte string the §8 hybrid signature
    /// commits to; the role-prefix tag [`crate::crypto::kdf::TAG_CARD_SIG`]
    /// is prepended by [`crate::crypto::sig::sign`] when called with
    /// [`SigRole::Card`].
    pub fn signed_bytes(&self) -> Result<Vec<u8>, CardError> {
        let mut entries: Vec<(Value, Value)> = Vec::with_capacity(8);
        self.push_pre_sig_entries(&mut entries);
        encode_map(&entries)
    }

    /// Canonical-CBOR encoding of the complete card *including* both
    /// signature fields. This is what `fingerprint::fingerprint` hashes and
    /// what the §6 wire form on disk contains.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, CardError> {
        let mut entries: Vec<(Value, Value)> = Vec::with_capacity(10);
        self.push_pre_sig_entries(&mut entries);
        entries.push((
            Value::Text(KEY_SELF_SIG_ED.into()),
            Value::Bytes(self.self_sig_ed.to_vec()),
        ));
        entries.push((
            Value::Text(KEY_SELF_SIG_PQ.into()),
            Value::Bytes(self.self_sig_pq.clone()),
        ));
        encode_map(&entries)
    }

    /// Inverse of [`to_canonical_cbor`]. Validates that `card_version == 1`
    /// and that every fixed-size field has the correct byte length.
    /// Tolerates inputs whose map keys arrive in non-§6 order; canonical
    /// re-encoding via [`to_canonical_cbor`] then yields the spec byte form
    /// — see module docs.
    ///
    /// Does **not** verify signatures. Call [`verify_self`] for that.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, CardError> {
        let value: Value = ciborium::de::from_reader(bytes)
            .map_err(|e| CardError::CborDecode(e.to_string()))?;
        let map = match value {
            Value::Map(m) => m,
            _ => return Err(CardError::CborDecode("expected top-level CBOR map".into())),
        };

        let mut card_version: Option<u8> = None;
        let mut contact_uuid: Option<[u8; CONTACT_UUID_LEN]> = None;
        let mut display_name: Option<String> = None;
        let mut x25519_pk: Option<[u8; X25519_PK_LEN]> = None;
        let mut ml_kem_768_pk: Option<Vec<u8>> = None;
        let mut ed25519_pk: Option<[u8; ED25519_PK_LEN]> = None;
        let mut ml_dsa_65_pk: Option<Vec<u8>> = None;
        let mut created_at_ms: Option<u64> = None;
        let mut self_sig_ed: Option<[u8; ED25519_SIG_LEN]> = None;
        let mut self_sig_pq: Option<Vec<u8>> = None;

        for (k, v) in map {
            let Value::Text(key) = k else {
                return Err(CardError::CborDecode("non-string map key".into()));
            };
            match key.as_str() {
                KEY_CARD_VERSION => set_once(&mut card_version, take_u8(v)?, &key)?,
                KEY_CONTACT_UUID => set_once(
                    &mut contact_uuid,
                    take_fixed_bytes::<CONTACT_UUID_LEN>(v)?,
                    &key,
                )?,
                KEY_DISPLAY_NAME => set_once(&mut display_name, take_text(v)?, &key)?,
                KEY_X25519_PK => set_once(
                    &mut x25519_pk,
                    take_fixed_bytes::<X25519_PK_LEN>(v)?,
                    &key,
                )?,
                KEY_ML_KEM_768_PK => set_once(
                    &mut ml_kem_768_pk,
                    take_sized_bytes(v, ML_KEM_768_PK_LEN)?,
                    &key,
                )?,
                KEY_ED25519_PK => set_once(
                    &mut ed25519_pk,
                    take_fixed_bytes::<ED25519_PK_LEN>(v)?,
                    &key,
                )?,
                KEY_ML_DSA_65_PK => set_once(
                    &mut ml_dsa_65_pk,
                    take_sized_bytes(v, ML_DSA_65_PK_LEN)?,
                    &key,
                )?,
                KEY_CREATED_AT => set_once(&mut created_at_ms, take_u64(v)?, &key)?,
                KEY_SELF_SIG_ED => set_once(
                    &mut self_sig_ed,
                    take_fixed_bytes::<ED25519_SIG_LEN>(v)?,
                    &key,
                )?,
                KEY_SELF_SIG_PQ => set_once(
                    &mut self_sig_pq,
                    take_sized_bytes(v, ML_DSA_65_SIG_LEN)?,
                    &key,
                )?,
                other => {
                    return Err(CardError::CborDecode(format!(
                        "unknown card field: {other}"
                    )));
                }
            }
        }

        let card_version = card_version
            .ok_or_else(|| CardError::CborDecode(format!("missing field {KEY_CARD_VERSION}")))?;
        if card_version != CARD_VERSION_V1 {
            return Err(CardError::InvalidVersion);
        }

        Ok(ContactCard {
            card_version,
            contact_uuid: contact_uuid.ok_or_else(|| {
                CardError::CborDecode(format!("missing field {KEY_CONTACT_UUID}"))
            })?,
            display_name: display_name.ok_or_else(|| {
                CardError::CborDecode(format!("missing field {KEY_DISPLAY_NAME}"))
            })?,
            x25519_pk: x25519_pk
                .ok_or_else(|| CardError::CborDecode(format!("missing field {KEY_X25519_PK}")))?,
            ml_kem_768_pk: ml_kem_768_pk.ok_or_else(|| {
                CardError::CborDecode(format!("missing field {KEY_ML_KEM_768_PK}"))
            })?,
            ed25519_pk: ed25519_pk
                .ok_or_else(|| CardError::CborDecode(format!("missing field {KEY_ED25519_PK}")))?,
            ml_dsa_65_pk: ml_dsa_65_pk.ok_or_else(|| {
                CardError::CborDecode(format!("missing field {KEY_ML_DSA_65_PK}"))
            })?,
            created_at_ms: created_at_ms
                .ok_or_else(|| CardError::CborDecode(format!("missing field {KEY_CREATED_AT}")))?,
            self_sig_ed: self_sig_ed
                .ok_or_else(|| CardError::CborDecode(format!("missing field {KEY_SELF_SIG_ED}")))?,
            self_sig_pq: self_sig_pq
                .ok_or_else(|| CardError::CborDecode(format!("missing field {KEY_SELF_SIG_PQ}")))?,
        })
    }

    /// Self-sign: build [`signed_bytes`], hand to
    /// [`crate::crypto::sig::sign`] with [`SigRole::Card`], and stash the
    /// resulting two signatures into [`Self::self_sig_ed`] and
    /// [`Self::self_sig_pq`].
    ///
    /// The `pk_*` fields on `self` must already match the keypairs whose
    /// secret halves are passed here — the card commits to the embedded
    /// public keys, so a mismatch goes undetected by `sign` but is caught
    /// by [`verify_self`].
    pub fn sign(
        &mut self,
        ed_sk: &Ed25519Secret,
        pq_sk: &MlDsa65Secret,
    ) -> Result<(), CardError> {
        let m = self.signed_bytes()?;
        let HybridSig { sig_ed, sig_pq } = sig::sign(SigRole::Card, &m, ed_sk, pq_sk)?;
        self.self_sig_ed = sig_ed;
        self.self_sig_pq = sig_pq.as_bytes().to_vec();
        Ok(())
    }

    /// Verify both self-signatures against the card's *own* embedded public
    /// keys. Returns `Ok(())` only if both Ed25519 and ML-DSA-65 verify.
    ///
    /// On failure, the variant of [`SigError`] inside the returned
    /// [`CardError::SigVerifyFailed`] identifies which half rejected.
    pub fn verify_self(&self) -> Result<(), CardError> {
        let m = self.signed_bytes()?;
        let pq_pk = MlDsa65Public::from_bytes(&self.ml_dsa_65_pk)?;
        let pq_sig = MlDsa65Sig::from_bytes(&self.self_sig_pq)?;
        let sig = HybridSig {
            sig_ed: self.self_sig_ed,
            sig_pq: pq_sig,
        };
        sig::verify(SigRole::Card, &m, &sig, &self.ed25519_pk, &pq_pk)?;
        Ok(())
    }

    /// Push the eight pre-signature entries (everything except the two
    /// `self_sig_*` fields) in the §6 listed order. The single source of
    /// truth for both [`signed_bytes`] and [`to_canonical_cbor`].
    fn push_pre_sig_entries(&self, entries: &mut Vec<(Value, Value)>) {
        entries.push((
            Value::Text(KEY_CARD_VERSION.into()),
            Value::Integer(u64::from(self.card_version).into()),
        ));
        entries.push((
            Value::Text(KEY_CONTACT_UUID.into()),
            Value::Bytes(self.contact_uuid.to_vec()),
        ));
        entries.push((
            Value::Text(KEY_DISPLAY_NAME.into()),
            Value::Text(self.display_name.clone()),
        ));
        entries.push((
            Value::Text(KEY_X25519_PK.into()),
            Value::Bytes(self.x25519_pk.to_vec()),
        ));
        entries.push((
            Value::Text(KEY_ML_KEM_768_PK.into()),
            Value::Bytes(self.ml_kem_768_pk.clone()),
        ));
        entries.push((
            Value::Text(KEY_ED25519_PK.into()),
            Value::Bytes(self.ed25519_pk.to_vec()),
        ));
        entries.push((
            Value::Text(KEY_ML_DSA_65_PK.into()),
            Value::Bytes(self.ml_dsa_65_pk.clone()),
        ));
        entries.push((
            Value::Text(KEY_CREATED_AT.into()),
            Value::Integer(self.created_at_ms.into()),
        ));
    }
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

fn encode_map(entries: &[(Value, Value)]) -> Result<Vec<u8>, CardError> {
    let value = Value::Map(entries.to_vec());
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&value, &mut buf)
        .map_err(|e| CardError::CborEncode(e.to_string()))?;
    Ok(buf)
}

fn set_once<T>(slot: &mut Option<T>, v: T, key: &str) -> Result<(), CardError> {
    if slot.is_some() {
        return Err(CardError::CborDecode(format!("duplicate field: {key}")));
    }
    *slot = Some(v);
    Ok(())
}

fn take_u8(v: Value) -> Result<u8, CardError> {
    let i = match v {
        Value::Integer(i) => i,
        _ => return Err(CardError::CborDecode("expected unsigned integer".into())),
    };
    let n: u64 = i
        .try_into()
        .map_err(|_| CardError::CborDecode("expected non-negative integer".into()))?;
    u8::try_from(n).map_err(|_| CardError::InvalidFieldLength)
}

fn take_u64(v: Value) -> Result<u64, CardError> {
    let i = match v {
        Value::Integer(i) => i,
        _ => return Err(CardError::CborDecode("expected unsigned integer".into())),
    };
    i.try_into()
        .map_err(|_| CardError::CborDecode("integer outside u64 range".into()))
}

fn take_text(v: Value) -> Result<String, CardError> {
    match v {
        Value::Text(s) => Ok(s),
        _ => Err(CardError::CborDecode("expected text string".into())),
    }
}

fn take_fixed_bytes<const N: usize>(v: Value) -> Result<[u8; N], CardError> {
    let bytes = match v {
        Value::Bytes(b) => b,
        _ => return Err(CardError::CborDecode("expected byte string".into())),
    };
    bytes.try_into().map_err(|_: Vec<u8>| CardError::InvalidFieldLength)
}

fn take_sized_bytes(v: Value, expected: usize) -> Result<Vec<u8>, CardError> {
    let bytes = match v {
        Value::Bytes(b) => b,
        _ => return Err(CardError::CborDecode("expected byte string".into())),
    };
    if bytes.len() != expected {
        return Err(CardError::InvalidFieldLength);
    }
    Ok(bytes)
}
