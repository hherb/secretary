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
//! ([`ContactCard::signed_bytes`]) and the fingerprint
//! ([`super::fingerprint::fingerprint`]) commit to *bytes*, not to a logical
//! record, so the encoding has to be deterministic: the same logical card
//! must always produce the same bytes across implementations. The rules are
//! the deterministic-encoding profile of **RFC 8949 §4.2.1** (also restated
//! as `docs/crypto-design.md` §6.2):
//!
//! 1. **Map shape** — the card is encoded as a CBOR map with text-string
//!    keys, never an array. (This is the §6 wire form.)
//! 2. **Map keys sorted bytewise lexicographically by their canonical
//!    encoded form.** For the all-tstr keys in this spec, that reduces to:
//!    shorter keys first; among keys of equal length, bytewise UTF-8
//!    compare. A consumer passing `canonical=True` to a conformant CBOR
//!    encoder (e.g., Python `cbor2`) produces bit-identical bytes — which
//!    is what `canonical_cbor_byte_kat` cross-verifies. The §6 spec listing
//!    order is descriptive of *which* fields exist, not normative for byte
//!    order.
//! 3. **Shortest-form lengths and integers.** Every length prefix and every
//!    integer is encoded in CBOR's shortest valid form. `ciborium`'s default
//!    `Value` serializer already enforces this for both.
//! 4. **Definite-length, no tags, no floats, no indefinite-length items.**
//! 5. **Duplicate keys** — rejected on parse (RFC 8949 §5.4).
//!
//! ## Strict canonical-input rule
//!
//! [`ContactCard::from_canonical_cbor`] rejects any input that is not in the
//! RFC 8949 §4.2.1 canonical form (key order, shortest-form lengths,
//! definite-length items, no tags/floats). The §6.1 fingerprint commits to
//! bytes — accepting non-canonical input would silently desynchronize a
//! peer's published fingerprint from a locally-recomputed one (parse →
//! re-canonicalize → fingerprint differs). Producers must canonicalize on
//! the way out; consumers must re-canonicalize on the way in only by
//! refusing input that wasn't already canonical.
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

    /// Input parsed but was not in the RFC 8949 §4.2.1 canonical form (e.g.
    /// keys not in bytewise lexicographic order, non-shortest length
    /// prefixes, indefinite-length items). The §6.1 fingerprint contract is
    /// over canonical bytes, so non-canonical input is rejected to keep
    /// peer-to-peer fingerprints in sync.
    #[error("CBOR is not in RFC 8949 §4.2.1 canonical form")]
    NonCanonicalCbor,

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

    /// Canonical-CBOR encoding of just the four-pk tuple
    /// `(x25519_pk, ml_kem_768_pk, ed25519_pk, ml_dsa_65_pk)` —
    /// `docs/crypto-design.md` §7's `sender_pk_bundle` /
    /// `recipient_pk_bundle` HKDF input.
    ///
    /// ## Encoding shape
    ///
    /// A CBOR **map** with the four §6 pk-field text keys (`"x25519_pk"`,
    /// `"ml_kem_768_pk"`, `"ed25519_pk"`, `"ml_dsa_65_pk"`), encoded under
    /// the same RFC 8949 §4.2.1 deterministic profile that the rest of the
    /// card uses. §6.2 lists `sender_pk_bundle` / `recipient_pk_bundle`
    /// among the byte strings produced by `canonical_cbor(...)`, so a
    /// CBOR map (not raw concat or array) is the only spec-correct shape.
    /// Sharing the four key names with [`Self::to_canonical_cbor`] also
    /// means a cross-impl re-decode of those four fields produces
    /// byte-identical output — see the `pk_bundle_matches_card_subset`
    /// test.
    ///
    /// Existing call sites under `core/src/vault/block.rs` smoke tests,
    /// `core/tests/vault.rs::pk_bundle_for`, and `core/tests/proptest.rs`
    /// currently form `pk_bundle` by raw byte-concat in the same field
    /// order. Migrating those to this method is a follow-up commit; the
    /// raw-concat output is **not** byte-equal to this method's output
    /// (raw concat omits the CBOR framing), so the migration is a
    /// behaviour change that has to be coordinated with the encrypt /
    /// decrypt sides at once.
    pub fn pk_bundle_bytes(&self) -> Result<Vec<u8>, CardError> {
        let entries: Vec<(Value, Value)> = vec![
            (
                Value::Text(KEY_X25519_PK.into()),
                Value::Bytes(self.x25519_pk.to_vec()),
            ),
            (
                Value::Text(KEY_ML_KEM_768_PK.into()),
                Value::Bytes(self.ml_kem_768_pk.clone()),
            ),
            (
                Value::Text(KEY_ED25519_PK.into()),
                Value::Bytes(self.ed25519_pk.to_vec()),
            ),
            (
                Value::Text(KEY_ML_DSA_65_PK.into()),
                Value::Bytes(self.ml_dsa_65_pk.clone()),
            ),
        ];
        crate::vault::canonical::encode_canonical_map(&entries)
            .map_err(|e| CardError::CborEncode(e.to_string()))
    }

    /// Inverse of [`to_canonical_cbor`]. Validates that `card_version == 1`
    /// and that every fixed-size field has the correct byte length.
    /// Tolerates inputs whose map keys arrive in non-§6 order; canonical
    /// re-encoding via [`to_canonical_cbor`] then yields the spec byte form
    /// — see module docs.
    ///
    /// Does **not** verify signatures. Call [`verify_self`] for that.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, CardError> {
        let value: Value =
            ciborium::de::from_reader(bytes).map_err(|e| CardError::CborDecode(e.to_string()))?;
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
                KEY_X25519_PK => {
                    set_once(&mut x25519_pk, take_fixed_bytes::<X25519_PK_LEN>(v)?, &key)?
                }
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

        let card = ContactCard {
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
        };

        // Reject non-canonical input. The §6.1 fingerprint contract is over
        // canonical bytes, so a peer's fingerprint and ours can only agree
        // when both encode canonically. Cheapest reliable check: re-encode
        // and compare; passes iff the input was already canonical.
        let canonical = card.to_canonical_cbor()?;
        if canonical.as_slice() != bytes {
            return Err(CardError::NonCanonicalCbor);
        }

        Ok(card)
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
    pub fn sign(&mut self, ed_sk: &Ed25519Secret, pq_sk: &MlDsa65Secret) -> Result<(), CardError> {
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
    // RFC 8949 §4.2.1: map keys must be sorted bytewise lexicographically by
    // their deterministic CBOR encoding. We materialize each key's encoded
    // bytes and sort by that — robust against any future key shape (text,
    // byte, integer) without a separate code path per type.
    let mut sorted: Vec<(Vec<u8>, (Value, Value))> = entries
        .iter()
        .map(|pair| {
            let mut key_bytes = Vec::new();
            ciborium::ser::into_writer(&pair.0, &mut key_bytes)
                .map_err(|e| CardError::CborEncode(e.to_string()))?;
            Ok((key_bytes, pair.clone()))
        })
        .collect::<Result<_, CardError>>()?;
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    let value = Value::Map(sorted.into_iter().map(|(_, pair)| pair).collect());
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
    bytes
        .try_into()
        .map_err(|_: Vec<u8>| CardError::InvalidFieldLength)
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a card with a fully deterministic, hand-pinned shape: every pk
    /// field is filled with a single repeating byte (the pattern below) so
    /// the canonical-CBOR output has no dependence on RNG state. The
    /// `display_name` / `created_at_ms` / signature fields are intentionally
    /// chosen to be ignorable from `pk_bundle_bytes`'s perspective — the
    /// determinism test mutates them.
    fn fixture_card(
        display_name: &str,
        created_at_ms: u64,
        sig_ed_fill: u8,
        sig_pq_fill: u8,
    ) -> ContactCard {
        ContactCard {
            card_version: CARD_VERSION_V1,
            contact_uuid: [0xaa; CONTACT_UUID_LEN],
            display_name: display_name.to_string(),
            x25519_pk: [0x11; X25519_PK_LEN],
            ml_kem_768_pk: vec![0x22; ML_KEM_768_PK_LEN],
            ed25519_pk: [0x33; ED25519_PK_LEN],
            ml_dsa_65_pk: vec![0x44; ML_DSA_65_PK_LEN],
            created_at_ms,
            self_sig_ed: [sig_ed_fill; ED25519_SIG_LEN],
            self_sig_pq: vec![sig_pq_fill; ML_DSA_65_SIG_LEN],
        }
    }

    /// Stability test: hex-pinned expected prefix and total length for a
    /// hand-pinned card. The expected prefix was generated once via the
    /// bootstrap pattern (run the test, paste the printed hex back here) —
    /// see `pk_bundle_bytes` doc comment for the encoding shape.
    ///
    /// Pinning the full byte string would burn ~3.2 KiB of inline hex on
    /// the ml_kem and ml_dsa pk fields (each is 1184 + 1952 bytes of
    /// repeating filler); pinning the *header* (map prefix + first key +
    /// first pk's CBOR length tag and first 8 fill bytes) catches the two
    /// failure modes that matter — wrong key order, wrong CBOR framing —
    /// without exploding the test source. The total-length check pins the
    /// rest.
    #[test]
    fn pk_bundle_bytes_is_byte_pinned() {
        let card = fixture_card("Alice", 1_714_060_800_000, 0x55, 0x66);
        let bytes = card.pk_bundle_bytes().expect("encode");
        // Canonical key order is length-then-bytewise on the encoded keys.
        // All four keys are text strings; text-CBOR-len byte is 0x60 + len
        // for len < 24. Lengths: "x25519_pk"=9, "ed25519_pk"=10,
        // "ml_dsa_65_pk"=12, "ml_kem_768_pk"=13. So canonical order is:
        //   x25519_pk (9) -> ed25519_pk (10) -> ml_dsa_65_pk (12) -> ml_kem_768_pk (13).
        // Map header: 0xa4 (definite-length map, 4 entries).
        // First key: 0x69 'x' '2' '5' '5' '1' '9' '_' 'p' 'k'
        // First value: byte-string len 32: 0x58 0x20, then 0x11 * 32.
        let expected_prefix = "a469783235353139\
                               5f706b582011111111\
                               11111111";
        let prefix_bytes = hex_decode(expected_prefix);
        assert_eq!(
            &bytes[..prefix_bytes.len()],
            prefix_bytes.as_slice(),
            "pk_bundle prefix drifted: got {}",
            hex_encode(&bytes[..prefix_bytes.len()])
        );
        // Sanity: total length = 1B map header
        //   + (1B key-len + 9B "x25519_pk")    + (2B byte-str len + 32B   pk) = 44
        //   + (1B key-len + 10B "ed25519_pk")  + (2B byte-str len + 32B   pk) = 45
        //   + (1B key-len + 12B "ml_dsa_65_pk")  + (3B byte-str len + 1952B pk) = 1968
        //   + (1B key-len + 13B "ml_kem_768_pk") + (3B byte-str len + 1184B pk) = 1201
        // = 1 + 44 + 45 + 1968 + 1201 = 3259.
        assert_eq!(bytes.len(), 3259, "unexpected total pk_bundle length");
    }

    /// Determinism: two cards with identical pk material but different
    /// metadata + signatures produce the same `pk_bundle_bytes`. Pins the
    /// "pk_bundle is purely a function of the four pk fields" contract so
    /// §7's HKDF input does not silently depend on display_name etc.
    #[test]
    fn pk_bundle_bytes_is_deterministic_across_metadata() {
        let a = fixture_card("Alice", 1_714_060_800_000, 0x01, 0x02);
        let b = fixture_card("Bob", 9_999_999_999_999, 0xff, 0xee);
        assert_eq!(
            a.pk_bundle_bytes().unwrap(),
            b.pk_bundle_bytes().unwrap(),
            "pk_bundle_bytes must depend only on the four pk fields"
        );
    }

    /// Cross-check: the four pk fields parsed back out of
    /// `to_canonical_cbor()` and re-encoded via `pk_bundle_bytes` on a
    /// freshly-built card with the same pk values yields byte-identical
    /// output. Pins the "same key names, same canonical profile" contract
    /// against drift in either direction.
    #[test]
    fn pk_bundle_matches_card_subset() {
        let card = fixture_card("Carol", 1_714_060_800_000, 0x77, 0x88);
        let full = card.to_canonical_cbor().expect("encode card");
        let parsed: Value = ciborium::de::from_reader(full.as_slice()).expect("decode");
        let Value::Map(entries) = parsed else {
            panic!("expected top-level map");
        };
        let mut x25519 = None;
        let mut ml_kem = None;
        let mut ed25519 = None;
        let mut ml_dsa = None;
        for (k, v) in entries {
            let Value::Text(key) = k else { continue };
            let Value::Bytes(b) = v else { continue };
            match key.as_str() {
                "x25519_pk" => x25519 = Some(b),
                "ml_kem_768_pk" => ml_kem = Some(b),
                "ed25519_pk" => ed25519 = Some(b),
                "ml_dsa_65_pk" => ml_dsa = Some(b),
                _ => {}
            }
        }
        let rebuilt = ContactCard {
            x25519_pk: x25519.unwrap().try_into().unwrap(),
            ml_kem_768_pk: ml_kem.unwrap(),
            ed25519_pk: ed25519.unwrap().try_into().unwrap(),
            ml_dsa_65_pk: ml_dsa.unwrap(),
            ..fixture_card("Other", 0, 0, 0)
        };
        assert_eq!(
            card.pk_bundle_bytes().unwrap(),
            rebuilt.pk_bundle_bytes().unwrap(),
            "pk_bundle_bytes must round-trip through to_canonical_cbor's pk subset"
        );
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    fn hex_encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }
}
