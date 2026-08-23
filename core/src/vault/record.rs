//! Record / RecordField in-memory types and canonical CBOR codec
//! (`docs/vault-format.md` §6.3).
//!
//! A block's plaintext (the content of `aead_ct` in §6.1) is a CBOR map
//! whose `"records"` array is a list of records in the shape defined in
//! §6.3:
//!
//! ```cbor
//! {
//!   "record_uuid":     <bstr 16>,
//!   "record_type":     <tstr>,                ; §6.3.1 standard or custom
//!   "fields":          { <fname>: { "value": <text or bstr>,
//!                                    "last_mod": <u64>,
//!                                    "device_uuid": <bstr 16> }, ... },
//!   "tags":            [<tstr>, ...],         ; optional
//!   "created_at_ms":   <u64>,
//!   "last_mod_ms":     <u64>,
//!   "tombstone":       <bool, optional>       ; absent or false = live
//! }
//! ```
//!
//! ## Canonical CBOR
//!
//! All bytes flowing in and out of [`encode`] / [`decode`] follow the
//! deterministic encoding profile of RFC 8949 §4.2.1 (also pinned in
//! `docs/crypto-design.md` §6.2):
//!
//! 1. Map keys sorted bytewise lexicographically by their canonical
//!    encoded form. For all-tstr keys this reduces to: shorter key first;
//!    among equal-length keys, bytewise UTF-8 compare. The §6.3 listing
//!    order is descriptive, **not** normative for byte order.
//! 2. Definite-length encoding for every map, array, and byte/text string.
//! 3. Shortest-form integer and length prefixes (the default for
//!    `ciborium::Value`).
//! 4. **No tags, no floats, no indefinite-length items** anywhere in v1
//!    records. The decoder rejects any of these — including inside
//!    forward-compat unknown values (§6.3.2).
//! 5. Duplicate map keys are forbidden (RFC 8949 §5.4); the decoder
//!    rejects them.
//!
//! ## Forward compatibility (§6.3.2)
//!
//! Decoders preserve unknown record-level and field-level keys verbatim
//! into [`Record::unknown`] / [`RecordField::unknown`]. A v1 client
//! receiving a v2 record (with new top-level or per-field keys) stores
//! the unrecognised material verbatim; on `decode → encode` round-trip,
//! the produced bytes are bit-identical to the input, because:
//!
//! - We collect every unrecognised key into the `unknown` map.
//! - On re-encode, `record_to_canonical` splices unknown entries (borrowed
//!   via `UnknownValue::as_value`, never cloned) into the same
//!   [`CanonicalMap`] as the known entries; its `Serialize` impl sorts every
//!   key — known and unknown alike — into canonical order at serialise
//!   time. Since that sort is total, deterministic, and depends only on the
//!   key bytes, the resulting byte layout matches the input exactly when
//!   the input was itself canonical.
//!
//! The decoder's strict canonical-input check (re-encode the parsed
//! representation and compare to the input bytes) makes the round-trip
//! property a runtime invariant: if the check passes, a subsequent
//! `encode(decode(bytes)?)?` is guaranteed to equal `bytes`.
//!
//! ## Pure-function API
//!
//! [`encode`] and [`decode`] are free functions, not methods on
//! [`Record`]. The module follows the codebase convention of pure
//! functions in reusable modules: I/O lives at the edges, structs hold
//! state but do not own their own serialisation.

use std::collections::{BTreeMap, BTreeSet};

use ciborium::Value;

use crate::cbor::{classify_de, classify_ser, CborFault};
use crate::crypto::secret::{SecretBytes, SecretString};

use super::canonical::{
    reject_floats_and_tags, to_canonical_vec, CanonicalError, CanonicalMap, CanonicalValue,
};

// ---------------------------------------------------------------------------
// Constants — record-level CBOR keys (§6.3)
// ---------------------------------------------------------------------------

const KEY_RECORD_UUID: &str = "record_uuid";
const KEY_RECORD_TYPE: &str = "record_type";
const KEY_FIELDS: &str = "fields";
const KEY_TAGS: &str = "tags";
const KEY_CREATED_AT_MS: &str = "created_at_ms";
const KEY_LAST_MOD_MS: &str = "last_mod_ms";
const KEY_TOMBSTONE: &str = "tombstone";
const KEY_TOMBSTONED_AT_MS: &str = "tombstoned_at_ms";

// ---------------------------------------------------------------------------
// Constants — field-level CBOR keys (§6.3)
// ---------------------------------------------------------------------------

const KEY_VALUE: &str = "value";
const KEY_LAST_MOD: &str = "last_mod";
const KEY_DEVICE_UUID: &str = "device_uuid";

/// UUID byte length (§6.3 — both `record_uuid` and per-field `device_uuid`).
pub const RECORD_UUID_LEN: usize = 16;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from record CBOR encode and decode.
#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    /// `ciborium` returned an I/O or serialisation error during encode.
    ///
    /// Carries a classified [`CborFault`] rather than the upstream message:
    /// `ciborium`'s `Display` is its `Debug` form, so stringifying it copies
    /// `ser::Error::Value(String)` verbatim — a `serde` custom message that can
    /// embed the offending value (#474). The generic-source problem that
    /// originally forced a `String` (`ciborium::ser::Error<E>` is generic over
    /// the writer's I/O error, so `#[from]` does not apply) is solved by
    /// [`crate::cbor::classify_ser`] projecting to a non-generic type.
    #[error("CBOR encode error: {0}")]
    CborEncode(CborFault),

    /// `ciborium` returned a parse error during decode (e.g. truncated
    /// input, type mismatch at the byte level). Carries a classified
    /// [`CborFault`] for the same reason as [`Self::CborEncode`].
    #[error("CBOR decode error: {0}")]
    CborDecode(CborFault),

    /// Top-level CBOR item was not a map. Records and field values are
    /// always maps in §6.3.
    #[error("expected top-level CBOR map")]
    NotAMap,

    /// A map key was not a text string. §6.3 maps use `tstr` keys
    /// throughout.
    #[error("non-string CBOR map key")]
    NonTextKey,

    /// A required field was absent from the parsed CBOR map. The payload
    /// is the §6.3 CBOR key name (e.g. `"record_uuid"`, `"fields"`) so
    /// errors stay machine-readable.
    #[error("missing required field: {field}")]
    MissingField { field: &'static str },

    /// A field had the wrong CBOR type. `expected` describes the spec
    /// shape (e.g. `"text string"`, `"unsigned integer"`, `"array"`).
    #[error("wrong type for field {field}: expected {expected}")]
    WrongType {
        field: &'static str,
        expected: &'static str,
    },

    /// A 16-byte UUID field arrived with the wrong length. `field` is the
    /// §6.3 CBOR key name; `length` is the byte count actually seen on
    /// the wire.
    #[error("invalid UUID for {field}: expected {RECORD_UUID_LEN} bytes, got {length}")]
    InvalidUuid { field: &'static str, length: usize },

    /// An integer field's value did not fit a `u64`. §6.3 timestamps and
    /// counters are all unsigned 64-bit.
    #[error("integer for field {field} does not fit u64")]
    IntegerOverflow { field: &'static str },

    /// A duplicate map key appeared. RFC 8949 §5.4 forbids duplicates in
    /// canonical input; the codebase enforces this on every CBOR map we
    /// parse.
    ///
    /// Carries the map LEVEL and the offending entry's ordinal, never the
    /// key itself: at the `"fields"` level the key is a decrypted user field
    /// name, which must never reach a log, a crash reporter, or a platform
    /// UI (#474). Same discipline as
    /// [`crate::unlock::mnemonic::MnemonicError::UnknownWord`], which
    /// carries a word index rather than the word.
    ///
    /// `field` identifies which map raised it — `"<record>"` (record-level
    /// map), `"fields"` (the record's field map), or `"<field>"` (a single
    /// field's map) — following the coarse entry-point-hint convention
    /// already used by [`Self::FloatRejected`]. `index` is 0-based and
    /// rendered 1-based.
    #[error("duplicate map key at entry #{} of {field}", .index + 1)]
    DuplicateKey {
        /// Which map level raised the error. A compile-time constant.
        field: &'static str,
        /// 0-based ordinal of the duplicate entry within that map.
        index: usize,
    },

    /// Floats are forbidden in v1 records (canonical CBOR rule, §6.2 #4).
    /// `field` is `"<root>"` for floats found inside a record decoded via
    /// [`decode`], or `"<unknown>"` for floats found inside a value
    /// parsed via [`UnknownValue::from_canonical_cbor`]. The walker does
    /// not thread per-key hints into nested subtrees, so the field hint
    /// is coarse-grained: it identifies which entry-point caught the
    /// violation, not which §6.3 key's subtree contained it.
    #[error("float values are not permitted in v1 records (in field {field})")]
    FloatRejected { field: &'static str },

    /// CBOR tags are forbidden in v1 records (canonical CBOR rule,
    /// §6.2 #4). All v1 byte / text strings are untagged.
    #[error("CBOR tags are not permitted in v1 records")]
    TagRejected,

    /// The decoded byte stream was not in canonical form: re-encoding the
    /// parsed representation produced different bytes. Most commonly
    /// caused by:
    ///
    /// - Indefinite-length maps, arrays, byte strings or text strings
    ///   (§6.2 rule 4 — `ciborium`'s `Value` reader normalises these to
    ///   definite-length on parse, so the only signal is the re-encode
    ///   diverging from the input).
    /// - Map keys not in canonical bytewise lexicographic order.
    /// - Non-shortest-form integer or length prefixes.
    ///
    /// The variant name highlights the most common cause; the doc above
    /// covers the full set.
    #[error("non-canonical CBOR encoding (e.g. indefinite-length item, key disorder, or non-shortest length)")]
    NonCanonicalEncoding,

    /// `crate::vault::canonical::to_canonical_vec`'s pre-reserved output
    /// buffer (sized from `CanonicalMap::size_bound`, not
    /// `encode_canonical_map`'s `cbor_size_bound` — the two are different
    /// formulas over different input shapes) needed more bytes than
    /// expected (lifted from `CanonicalError::CapacityBoundExceeded`, an
    /// internal `pub(crate)` type not reachable from public docs). This is
    /// a post-hoc tripwire for a future `ciborium::Value` variant the size
    /// bound cannot name, not a routine error path.
    #[error("canonical CBOR encode exceeded its reserved size bound ({actual} > {bound})")]
    CanonicalSizeBoundExceeded { actual: usize, bound: usize },
}

/// Lift a [`CanonicalError`] from the shared
/// [`crate::vault::canonical`] helpers into the record-layer error
/// surface, preserving the pre-extraction variant shape verbatim. The
/// public [`RecordError`] surface stays bit-identical to its
/// pre-refactor shape so that existing pattern-matches on
/// [`RecordError::FloatRejected`] / [`RecordError::TagRejected`] /
/// [`RecordError::CborEncode`] keep matching after the helpers were
/// pulled out into the shared module. The `field` hint on
/// `CanonicalError::TagRejected` is intentionally discarded here because
/// the original `RecordError::TagRejected` did not carry one — the
/// `From` is a behaviour-preserving bridge, not a surface enrichment.
///
/// That "bit-identical" claim is no longer exactly true, and deliberately
/// so: the surface has since gained exactly one variant beyond the
/// pre-refactor shape, [`RecordError::CanonicalSizeBoundExceeded`],
/// because [`CanonicalError::CapacityBoundExceeded`] did not exist before
/// this module did (see its doc). `RecordError` is not `#[non_exhaustive]`,
/// so this is a real, compiler-checked surface change, not a documentation
/// gap: `manifest.rs`'s `record_error_to_cbor_fault` — an exhaustive match
/// over every `RecordError` variant with no wildcard, by design — needed
/// (and got) a matching arm added in the same commit that added this
/// variant.
impl From<CanonicalError> for RecordError {
    fn from(e: CanonicalError) -> Self {
        match e {
            CanonicalError::CborEncode(fault) => RecordError::CborEncode(fault),
            CanonicalError::FloatRejected { field } => RecordError::FloatRejected { field },
            CanonicalError::TagRejected { .. } => RecordError::TagRejected,
            CanonicalError::CapacityBoundExceeded { actual, bound } => {
                RecordError::CanonicalSizeBoundExceeded { actual, bound }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// In-memory types
// ---------------------------------------------------------------------------

/// Opaque container for forward-compat CBOR values from unknown
/// record-level or field-level keys (§6.3.2).
///
/// Wraps [`ciborium::Value`] so that `ciborium` is not part of this
/// crate's public API. Consumers that just round-trip values through
/// [`encode`] / [`decode`] never need to construct or inspect an
/// `UnknownValue` directly; consumers that need to *construct* unknown
/// entries (e.g., tests, FFI clients) can use
/// [`UnknownValue::from_canonical_cbor`] and
/// [`UnknownValue::to_canonical_cbor`].
///
/// The [`PartialEq`] impl compares the wrapped CBOR values structurally,
/// which is enough for round-trip equality checks because [`decode`]
/// rejects floats — the only `Value` variant that breaks `Eq`.
#[derive(Debug, Clone, PartialEq)]
pub struct UnknownValue(Value);

impl UnknownValue {
    /// Parse `bytes` as a single canonical CBOR item, rejecting floats
    /// and tags per §6.2 / §6.3.2.
    ///
    /// Note: this does not enforce the byte-identical re-encode check
    /// that [`decode`] applies at the record level. The full canonical
    /// invariant on a record is dispositive at the record boundary;
    /// individual unknown values constructed in isolation are validated
    /// only for the no-float / no-tag rules.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, RecordError> {
        let parsed: Value = ciborium::de::from_reader(bytes)
            .map_err(|e| RecordError::CborDecode(classify_de(&e)))?;
        reject_floats_and_tags(&parsed, "<unknown>")?;
        Ok(UnknownValue(parsed))
    }

    /// Serialise back to canonical CBOR.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, RecordError> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&self.0, &mut buf)
            .map_err(|e| RecordError::CborEncode(classify_ser(&e)))?;
        Ok(buf)
    }

    /// Borrow the wrapped CBOR value.
    ///
    /// `pub(crate)` deliberately: the wrapped `ciborium::Value` is a private
    /// implementation detail of the public API (that is why `UnknownValue`
    /// exists at all), and this accessor is only for the canonical encoder,
    /// which needs to emit the subtree verbatim WITHOUT cloning it. The
    /// previous encode path did `v.0.clone()`, a deep clone of a forward-compat
    /// subtree that could carry a future version's secret content (#547).
    pub(crate) fn as_value(&self) -> &Value {
        &self.0
    }
}

/// Per-field value: human-readable text or opaque bytes (§6.3).
///
/// §6.3 says: "A field's `value` is `tstr` for human-readable values and
/// `bstr` for binary values (e.g., a parsed TOTP seed)."
///
/// Both variants wrap zeroize-on-drop secret types: this is the user's
/// actual passwords, secret notes, API keys and TOTP seeds — the most
/// sensitive data in the system. Equality is constant-time. Cloning is
/// supported (conflict resolution and proptest shrinking need it) and
/// produces an independently-zeroized allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordFieldValue {
    /// `tstr` value — UTF-8 string, e.g. a username or password.
    Text(SecretString),
    /// `bstr` value — opaque bytes, e.g. a parsed TOTP seed.
    Bytes(SecretBytes),
}

/// One field within a record (§6.3 — value of an entry in `fields`).
///
/// The CRDT-relevant metadata (`last_mod`, `device_uuid`) lives on each
/// field rather than only on the record so per-field merge can detect
/// concurrent edits to different fields without false conflict.
///
/// Only [`PartialEq`] (not [`Eq`]) is implemented: the [`UnknownValue`]
/// payload wraps a [`ciborium::Value`] which does not implement [`Eq`]
/// because it can carry `f64` floats. Records reject floats on decode
/// (see [`RecordError::FloatRejected`]) so any `RecordField` produced by
/// [`decode`] is float-free in practice; the type contract is the
/// conservative one.
#[derive(Debug, Clone, PartialEq)]
pub struct RecordField {
    /// The field's payload.
    pub value: RecordFieldValue,
    /// Per-field last-mod timestamp, Unix milliseconds.
    pub last_mod: u64,
    /// 16-byte UUID of the device that performed the last modification.
    pub device_uuid: [u8; RECORD_UUID_LEN],
    /// Unknown field-level keys preserved verbatim per §6.3.2 forward
    /// compatibility. A v1 client that receives a v2 field with extra
    /// per-field keys round-trips them bit-identically.
    ///
    /// Stored in a [`BTreeMap`] keyed by the unknown key's text so the
    /// re-encode path produces a deterministic ordering before the
    /// canonical-CBOR sort (which is then dispositive). Values are
    /// wrapped in [`UnknownValue`] so any v2 shape — sub-maps, arrays,
    /// nested bytes — survives untouched without leaking the underlying
    /// CBOR library type into this crate's public API.
    pub unknown: BTreeMap<String, UnknownValue>,
}

/// One record within a block (§6.3).
///
/// `tombstone` defaults to `false` and is encoded as absent on the wire
/// when `false` (§6.3: "absent or false = live; true = deleted"). The
/// in-memory representation is always present for ergonomic field
/// access.
///
/// `tags` is always present in-memory but encoded as absent when empty
/// (§6.3: "optional cross-cutting labels"). Decoding an absent `tags`
/// field yields `Vec::new()`.
///
/// Only [`PartialEq`] (not [`Eq`]) is implemented for the same reason
/// as [`RecordField`]: the [`UnknownValue`] payload in `unknown` wraps
/// a [`ciborium::Value`] which cannot be `Eq`.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    /// 16-byte record UUID. Stable across edits and across devices.
    pub record_uuid: [u8; RECORD_UUID_LEN],
    /// Open-ended record-type discriminator. Standard values listed in
    /// §6.3.1; any string is permitted (custom types render as
    /// generic key/value lists).
    pub record_type: String,
    /// Field name → field. [`BTreeMap`] for in-memory iteration
    /// determinism only; the wire ordering is decided by [`CanonicalMap`]'s
    /// `Serialize` impl, which compares keys directly as `(byte length,
    /// bytes)` — an ALLOCATION-FREE comparison, deliberately: a field name
    /// here is user-authored, decrypted plaintext (the same class of data
    /// `RecordError::DuplicateKey` used to leak by formatting one, #474), so
    /// the encoder must never materialise a key into an owned,
    /// CBOR-encoded sort buffer. Do not "restore" a materialise-then-sort
    /// step to make this doc's old wording true again — that would reopen
    /// the leak this ordering exists to close (see `canonical/value.rs`'s
    /// module doc for the full rationale). This ordering differs from
    /// `BTreeMap`'s `String` ordering for keys of differing UTF-8 byte
    /// lengths (e.g. `"z"` sorts before `"ab"` in canonical CBOR but after
    /// it in `BTreeMap<String, _>`); the two orders coincide only for keys
    /// of equal byte length. (`IndexMap` would preserve insertion order,
    /// which is the wrong invariant for a canonical encoder.)
    pub fields: BTreeMap<String, RecordField>,
    /// Cross-cutting tags. Empty `Vec` = absent on the wire.
    pub tags: Vec<String>,
    /// Record creation timestamp, Unix milliseconds.
    pub created_at_ms: u64,
    /// Last-mod timestamp at the record level, Unix milliseconds. Distinct
    /// from per-field `last_mod` so a record-level rename or whole-record
    /// edit has its own merge clock.
    pub last_mod_ms: u64,
    /// `false` = live (or wire-absent); `true` = deleted (`fields` may be
    /// cleared but the record's presence prevents resurrection on merge,
    /// per §7).
    pub tombstone: bool,
    /// Death clock — the high-water mark of every tombstone observation
    /// on this record (`docs/crypto-design.md` §11.3). Encoded as
    /// absent on the wire when zero (the never-tombstoned default).
    ///
    /// Invariants on well-formed records:
    /// - `tombstoned_at_ms ≤ last_mod_ms` always.
    /// - `tombstone == true ⇒ tombstoned_at_ms == last_mod_ms`
    ///   (a currently-tombstoned record was tombstoned at its most
    ///   recent edit).
    /// - On resurrection (live edit at `T_r > tombstoned_at_ms`):
    ///   `tombstone = false`, `last_mod_ms = T_r`,
    ///   `tombstoned_at_ms` is preserved unchanged.
    ///
    /// On merge: `merged.tombstoned_at_ms = max(local, remote)`. Drives
    /// the staleness filter that drops fields with
    /// `field.last_mod ≤ merged.tombstoned_at_ms`, making the merge
    /// associative across arbitrary tombstone histories (§11.3).
    pub tombstoned_at_ms: u64,
    /// Unknown record-level keys preserved verbatim per §6.3.2 forward
    /// compatibility. See [`RecordField::unknown`] for the storage
    /// rationale.
    pub unknown: BTreeMap<String, UnknownValue>,
}

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

/// Canonical CBOR encoding of a record (§6.3 + canonical-CBOR rules from
/// §6.2). Output is deterministic: `encode(r)` produces the same bytes on
/// every call, and any conformant RFC 8949 §4.2.1 encoder produces the
/// same bytes.
///
/// Empty `tags` and `tombstone == false` are omitted from the CBOR map
/// per §6.3's "absent on the wire" rules. Forward-compat unknown keys
/// (§6.3.2) are spliced in alongside known keys; the canonical-key sort
/// imposes the deterministic ordering.
///
/// Cannot fail on the borrow side — `record_to_canonical` has no fallible
/// step — so the only error source left is the crate-internal canonical
/// encoder's own CBOR-encode / capacity-bound checks, lifted to
/// [`RecordError::CborEncode`] / [`RecordError::CanonicalSizeBoundExceeded`]
/// by the `From<CanonicalError>` impl above.
pub fn encode(record: &Record) -> Result<Vec<u8>, RecordError> {
    Ok(to_canonical_vec(&record_to_canonical(record))?)
}

/// Build the borrowed canonical map for a record (§6.3).
///
/// Every value BORROWS: a [`RecordFieldValue::Text`] serialises straight out
/// of its [`SecretString`], where the previous path did
/// `s.expose().to_owned()` and then deep-cloned that copy two more times on
/// the way to the wire, once per `canonical_sort_entries` call
/// (inner field-map sort, then outer record-map sort) (#547).
///
/// Key push order is irrelevant here — [`CanonicalMap`]'s `Serialize` imposes
/// the RFC 8949 §4.2.1 order, recursively, at serialise time.
pub(crate) fn record_to_canonical(record: &Record) -> CanonicalMap<'_> {
    // 5 always-pushed keys + up to 3 conditional ones (`tags`, `tombstone`,
    // `tombstoned_at_ms`) + one slot per forward-compat unknown. `push`
    // handles any mismatch correctly either way — this is a size hint, not
    // an invariant.
    let mut map = CanonicalMap::with_capacity(8 + record.unknown.len());

    map.push(KEY_RECORD_UUID, CanonicalValue::Bytes(&record.record_uuid));
    map.push(KEY_RECORD_TYPE, CanonicalValue::Text(&record.record_type));

    let mut fields = CanonicalMap::with_capacity(record.fields.len());
    for (name, f) in &record.fields {
        fields.push(name, CanonicalValue::Map(field_to_canonical(f)));
    }
    map.push(KEY_FIELDS, CanonicalValue::Map(fields));

    // §6.3: empty `tags` is absent on the wire.
    if !record.tags.is_empty() {
        map.push(
            KEY_TAGS,
            CanonicalValue::Array(
                record
                    .tags
                    .iter()
                    .map(|t| CanonicalValue::Text(t))
                    .collect(),
            ),
        );
    }
    map.push(
        KEY_CREATED_AT_MS,
        CanonicalValue::Uint(record.created_at_ms),
    );
    map.push(KEY_LAST_MOD_MS, CanonicalValue::Uint(record.last_mod_ms));
    // §6.3: `tombstone == false` is absent on the wire.
    if record.tombstone {
        map.push(KEY_TOMBSTONE, CanonicalValue::Bool(true));
    }
    // §11.3: the never-tombstoned default (0) is absent on the wire.
    if record.tombstoned_at_ms != 0 {
        map.push(
            KEY_TOMBSTONED_AT_MS,
            CanonicalValue::Uint(record.tombstoned_at_ms),
        );
    }

    // Forward-compat (§6.3.2): splice unknowns alongside known keys. Emitted
    // verbatim as a BORROW — the previous path cloned the subtree, which for
    // a v1 client holding a v2 record could be secret content this version
    // cannot recognise.
    for (k, v) in &record.unknown {
        map.push(k, CanonicalValue::Borrowed(v.as_value()));
    }

    map
}

/// Build the borrowed canonical map for one field (§6.3.2).
fn field_to_canonical(field: &RecordField) -> CanonicalMap<'_> {
    let mut map = CanonicalMap::with_capacity(3 + field.unknown.len());
    let value = match &field.value {
        // The whole point of #547: a borrow where there was a copy.
        RecordFieldValue::Text(s) => CanonicalValue::Text(s.expose()),
        RecordFieldValue::Bytes(b) => CanonicalValue::Bytes(b.expose()),
    };
    map.push(KEY_VALUE, value);
    map.push(KEY_LAST_MOD, CanonicalValue::Uint(field.last_mod));
    map.push(KEY_DEVICE_UUID, CanonicalValue::Bytes(&field.device_uuid));
    for (k, v) in &field.unknown {
        map.push(k, CanonicalValue::Borrowed(v.as_value()));
    }
    map
}

// `to_canonical_vec` and `CanonicalMap`/`CanonicalValue` live in
// [`crate::vault::canonical`] so block / record / manifest can share one
// borrowing-encoder implementation as each migrates onto it. The shared
// [`CanonicalError`] is lifted to the existing record-layer variants by the
// `From<CanonicalError> for RecordError` impl above, so the public surface
// stays unchanged.
//
// The pre-#547 owned encoder this function replaces (`record_to_entries` +
// `fields_to_value` + `field_to_entries`) is kept, `#[cfg(test)]`, as
// `owned_record_entries_for_test` in the test module below — both as the
// differential byte-identity oracle for
// `record_to_canonical_matches_the_owned_encoder_byte_for_byte` and as the
// entries-list builder the pre-existing negative-path decode tests already
// depended on before this rewrite. Do not delete it as dead code.

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

/// Strict canonical-CBOR decoder for a record (§6.3).
///
/// Validates:
///
/// 1. Top-level item is a map.
/// 2. All map keys are text strings.
/// 3. No floats anywhere in the tree (canonical CBOR rule).
/// 4. No CBOR tags anywhere in the tree (canonical CBOR rule).
/// 5. No duplicate map keys at any level.
/// 6. All required §6.3 fields are present with their spec types.
/// 7. The bytes are themselves canonical (re-encode-and-compare): rejects
///    indefinite-length items, non-canonical key order, and non-shortest
///    length / integer prefixes.
///
/// Forward-compat unknown keys are preserved into [`Record::unknown`]
/// and [`RecordField::unknown`] verbatim.
pub fn decode(bytes: &[u8]) -> Result<Record, RecordError> {
    let parsed: Value =
        ciborium::de::from_reader(bytes).map_err(|e| RecordError::CborDecode(classify_de(&e)))?;

    // Walk the tree to enforce the no-float and no-tag rules everywhere
    // (including inside forward-compat unknown values). Doing this once
    // up front means the per-field decoders don't need to re-check.
    reject_floats_and_tags(&parsed, "<root>")?;

    let map = match parsed {
        Value::Map(m) => m,
        _ => return Err(RecordError::NotAMap),
    };

    let record = parse_record_map(map)?;

    // Strict canonical-input check: re-encode the parsed representation
    // and require byte-identical match. Same pattern as
    // `unlock::bundle::IdentityBundle::from_canonical_cbor`. This catches
    // indefinite-length items (which `ciborium::Value` reads but
    // normalises on re-emit), non-canonical map key order, and non-
    // shortest length prefixes.
    let re_encoded = encode(&record)?;
    if re_encoded.as_slice() != bytes {
        return Err(RecordError::NonCanonicalEncoding);
    }

    Ok(record)
}

// `reject_floats_and_tags` lives in [`crate::vault::canonical`]; see the
// `From<CanonicalError> for RecordError` impl above for how its
// `FloatRejected` / `TagRejected` errors map back to the record-layer
// variants without changing the public surface.

/// Parse a top-level CBOR map (already extracted from `Value::Map`) into
/// a [`Record`]. Unknown record-level keys land in [`Record::unknown`].
fn parse_record_map(map: Vec<(Value, Value)>) -> Result<Record, RecordError> {
    let mut record_uuid: Option<[u8; RECORD_UUID_LEN]> = None;
    let mut record_type: Option<String> = None;
    let mut fields: Option<BTreeMap<String, RecordField>> = None;
    let mut tags: Option<Vec<String>> = None;
    let mut created_at_ms: Option<u64> = None;
    let mut last_mod_ms: Option<u64> = None;
    let mut tombstone: Option<bool> = None;
    let mut tombstoned_at_ms: Option<u64> = None;
    let mut unknown: BTreeMap<String, UnknownValue> = BTreeMap::new();
    // `seen_keys` tracks every textual key we have observed at this map
    // level so duplicates (RFC 8949 §5.4) are caught even when both
    // copies fall into the unknown bucket.
    let mut seen_keys: BTreeSet<String> = BTreeSet::new();

    for (index, (k, v)) in map.into_iter().enumerate() {
        let key = match k {
            Value::Text(s) => s,
            _ => return Err(RecordError::NonTextKey),
        };
        if !seen_keys.insert(key.clone()) {
            return Err(RecordError::DuplicateKey {
                field: "<record>",
                index,
            });
        }
        match key.as_str() {
            KEY_RECORD_UUID => {
                record_uuid = Some(take_uuid(v, KEY_RECORD_UUID)?);
            }
            KEY_RECORD_TYPE => {
                record_type = Some(take_text(v, KEY_RECORD_TYPE)?);
            }
            KEY_FIELDS => {
                fields = Some(take_fields_map(v)?);
            }
            KEY_TAGS => {
                tags = Some(take_tags(v)?);
            }
            KEY_CREATED_AT_MS => {
                created_at_ms = Some(take_u64(v, KEY_CREATED_AT_MS)?);
            }
            KEY_LAST_MOD_MS => {
                last_mod_ms = Some(take_u64(v, KEY_LAST_MOD_MS)?);
            }
            KEY_TOMBSTONE => {
                tombstone = Some(take_bool(v, KEY_TOMBSTONE)?);
            }
            KEY_TOMBSTONED_AT_MS => {
                tombstoned_at_ms = Some(take_u64(v, KEY_TOMBSTONED_AT_MS)?);
            }
            _ => {
                // Forward-compat: any other key is preserved verbatim.
                // The float/tag walker at the top of decode() has
                // already vetted v's subtree.
                unknown.insert(key, UnknownValue(v));
            }
        }
    }

    Ok(Record {
        record_uuid: record_uuid.ok_or(RecordError::MissingField {
            field: KEY_RECORD_UUID,
        })?,
        record_type: record_type.ok_or(RecordError::MissingField {
            field: KEY_RECORD_TYPE,
        })?,
        fields: fields.ok_or(RecordError::MissingField { field: KEY_FIELDS })?,
        tags: tags.unwrap_or_default(),
        created_at_ms: created_at_ms.ok_or(RecordError::MissingField {
            field: KEY_CREATED_AT_MS,
        })?,
        last_mod_ms: last_mod_ms.ok_or(RecordError::MissingField {
            field: KEY_LAST_MOD_MS,
        })?,
        tombstone: tombstone.unwrap_or(false),
        tombstoned_at_ms: tombstoned_at_ms.unwrap_or(0),
        unknown,
    })
}

fn take_fields_map(v: Value) -> Result<BTreeMap<String, RecordField>, RecordError> {
    let entries = match v {
        Value::Map(m) => m,
        _ => {
            return Err(RecordError::WrongType {
                field: KEY_FIELDS,
                expected: "map",
            })
        }
    };
    let mut out: BTreeMap<String, RecordField> = BTreeMap::new();
    for (index, (k, val)) in entries.into_iter().enumerate() {
        let fname = match k {
            Value::Text(s) => s,
            _ => return Err(RecordError::NonTextKey),
        };
        if out.contains_key(&fname) {
            return Err(RecordError::DuplicateKey {
                field: "fields",
                index,
            });
        }
        let field = parse_field_map(val)?;
        out.insert(fname, field);
    }
    Ok(out)
}

fn parse_field_map(v: Value) -> Result<RecordField, RecordError> {
    let entries = match v {
        Value::Map(m) => m,
        _ => {
            return Err(RecordError::WrongType {
                field: KEY_FIELDS,
                expected: "map (field value)",
            })
        }
    };

    let mut value: Option<RecordFieldValue> = None;
    let mut last_mod: Option<u64> = None;
    let mut device_uuid: Option<[u8; RECORD_UUID_LEN]> = None;
    let mut unknown: BTreeMap<String, UnknownValue> = BTreeMap::new();
    let mut seen_keys: BTreeSet<String> = BTreeSet::new();

    for (index, (k, val)) in entries.into_iter().enumerate() {
        let key = match k {
            Value::Text(s) => s,
            _ => return Err(RecordError::NonTextKey),
        };
        if !seen_keys.insert(key.clone()) {
            return Err(RecordError::DuplicateKey {
                field: "<field>",
                index,
            });
        }
        match key.as_str() {
            KEY_VALUE => {
                value = Some(match val {
                    Value::Text(s) => RecordFieldValue::Text(SecretString::new(s)),
                    Value::Bytes(b) => RecordFieldValue::Bytes(SecretBytes::new(b)),
                    _ => {
                        return Err(RecordError::WrongType {
                            field: KEY_VALUE,
                            expected: "text or byte string",
                        })
                    }
                });
            }
            KEY_LAST_MOD => {
                last_mod = Some(take_u64(val, KEY_LAST_MOD)?);
            }
            KEY_DEVICE_UUID => {
                device_uuid = Some(take_uuid(val, KEY_DEVICE_UUID)?);
            }
            _ => {
                unknown.insert(key, UnknownValue(val));
            }
        }
    }

    Ok(RecordField {
        value: value.ok_or(RecordError::MissingField { field: KEY_VALUE })?,
        last_mod: last_mod.ok_or(RecordError::MissingField {
            field: KEY_LAST_MOD,
        })?,
        device_uuid: device_uuid.ok_or(RecordError::MissingField {
            field: KEY_DEVICE_UUID,
        })?,
        unknown,
    })
}

fn take_tags(v: Value) -> Result<Vec<String>, RecordError> {
    let items = match v {
        Value::Array(a) => a,
        _ => {
            return Err(RecordError::WrongType {
                field: KEY_TAGS,
                expected: "array",
            })
        }
    };
    items
        .into_iter()
        .map(|item| match item {
            Value::Text(s) => Ok(s),
            _ => Err(RecordError::WrongType {
                field: KEY_TAGS,
                expected: "array of text strings",
            }),
        })
        .collect()
}

fn take_text(v: Value, field: &'static str) -> Result<String, RecordError> {
    match v {
        Value::Text(s) => Ok(s),
        _ => Err(RecordError::WrongType {
            field,
            expected: "text string",
        }),
    }
}

fn take_u64(v: Value, field: &'static str) -> Result<u64, RecordError> {
    let i = match v {
        Value::Integer(i) => i,
        _ => {
            return Err(RecordError::WrongType {
                field,
                expected: "unsigned integer",
            })
        }
    };
    i.try_into()
        .map_err(|_| RecordError::IntegerOverflow { field })
}

fn take_bool(v: Value, field: &'static str) -> Result<bool, RecordError> {
    match v {
        Value::Bool(b) => Ok(b),
        _ => Err(RecordError::WrongType {
            field,
            expected: "boolean",
        }),
    }
}

fn take_uuid(v: Value, field: &'static str) -> Result<[u8; RECORD_UUID_LEN], RecordError> {
    let bytes = match v {
        Value::Bytes(b) => b,
        _ => {
            return Err(RecordError::WrongType {
                field,
                expected: "byte string",
            })
        }
    };
    let length = bytes.len();
    bytes
        .try_into()
        .map_err(|_: Vec<u8>| RecordError::InvalidUuid { field, length })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    // `canonical_sort_entries` / `encode_canonical_map` have no production
    // caller left in THIS file after #547 Task 4 (they still back
    // `manifest.rs` / `block.rs` / `sync/state.rs`, which is why they stay
    // `pub` on `crate::vault::canonical` rather than being deleted) — the
    // production `use super::canonical::{...}` above deliberately no longer
    // names them, so a plain `cargo build --release --workspace` (no
    // `#[cfg(test)]` code compiled) does not warn `unused_imports`. Test code
    // still needs both, for the retained owned-encoder oracle below and for
    // the many negative-path decode tests that build a canonical entries
    // list by hand.
    use crate::vault::canonical::{canonical_sort_entries, encode_canonical_map};

    // ---- Construction helpers --------------------------------------------

    /// All-zeros 16-byte device UUID — deterministic for round-trip
    /// equality checks.
    const ZERO_DEVICE_UUID: [u8; RECORD_UUID_LEN] = [0u8; RECORD_UUID_LEN];

    /// Build a `RecordField` with a deterministic device UUID. Used as the
    /// base for both straight-through round-trip tests and for negative-
    /// path tests that mutate one piece of the encoded form.
    fn dummy_field(value: RecordFieldValue, last_mod: u64) -> RecordField {
        RecordField {
            value,
            last_mod,
            device_uuid: ZERO_DEVICE_UUID,
            unknown: BTreeMap::new(),
        }
    }

    /// Minimal valid record — empty `fields`, empty `tags`, live (no
    /// tombstone). Useful as a base for tests that mutate one aspect.
    fn dummy_record() -> Record {
        Record {
            record_uuid: [0xab; RECORD_UUID_LEN],
            record_type: "login".to_string(),
            fields: BTreeMap::new(),
            tags: Vec::new(),
            created_at_ms: 1_714_060_800_000,
            last_mod_ms: 1_714_060_800_001,
            tombstone: false,
            tombstoned_at_ms: 0,
            unknown: BTreeMap::new(),
        }
    }

    /// Original sample record — full-shape, used by the smoke test (kept
    /// because `roundtrip_full_record` constructs its own and the smoke
    /// covers a slightly different shape).
    fn sample_record() -> Record {
        let mut fields = BTreeMap::new();
        fields.insert(
            "username".to_string(),
            RecordField {
                value: RecordFieldValue::Text("alice".into()),
                last_mod: 1_714_060_800_000,
                device_uuid: [1u8; RECORD_UUID_LEN],
                unknown: BTreeMap::new(),
            },
        );
        fields.insert(
            "totp_seed".to_string(),
            RecordField {
                value: RecordFieldValue::Bytes(vec![0xde, 0xad, 0xbe, 0xef].into()),
                last_mod: 1_714_060_800_001,
                device_uuid: [1u8; RECORD_UUID_LEN],
                unknown: BTreeMap::new(),
            },
        );
        Record {
            record_uuid: [0xab; RECORD_UUID_LEN],
            record_type: "login".to_string(),
            fields,
            tags: vec!["work".to_string()],
            created_at_ms: 1_714_060_800_000,
            last_mod_ms: 1_714_060_800_002,
            tombstone: false,
            tombstoned_at_ms: 0,
            unknown: BTreeMap::new(),
        }
    }

    /// Encode a single CBOR `Value` to bytes via ciborium directly. Used
    /// by negative-path tests that need to splice raw CBOR fragments into
    /// hand-built maps without going through `encode_canonical_map` (which
    /// would re-sort them).
    fn cbor_value_bytes(v: &Value) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(v, &mut buf).expect("ciborium encode of test Value");
        buf
    }

    /// Encode a list of `(key, value)` entries as a definite-length CBOR
    /// map *without* canonical sorting. Length prefix uses ciborium's
    /// shortest-form rules (so the only non-canonical aspect is key
    /// order). For maps with up to 23 entries this produces `0xa0 + n`
    /// followed by entries in the order given.
    fn cbor_map_bytes_unsorted(entries: &[(Value, Value)]) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&Value::Map(entries.to_vec()), &mut buf)
            .expect("ciborium encode of unsorted map");
        buf
    }

    /// Build a baseline canonical record-map entry list (the exact
    /// `(key, value)` pairs the encoder would emit for `record`,
    /// pre-canonical-sort). Used by tests that want to mutate one entry
    /// (e.g. swap a u64 for a float) and re-emit canonically.
    ///
    /// Built via [`owned_record_entries_for_test`], not the production
    /// `record_to_canonical` — for two reasons, not one:
    ///
    /// 1. **Type mismatch.** `record_to_canonical` returns a borrowing
    ///    [`CanonicalMap`], and these `Vec<(Value, Value)>`-mutating
    ///    negative-path tests need an OWNED, `ciborium::Value`-based entry
    ///    list to splice a hand-built float / tag / duplicate-key fragment
    ///    into — `CanonicalValue` has no arm for either forbidden node
    ///    type, by design (that is what makes it a canonical-CBOR-only
    ///    mirror). There is no `CanonicalMap`-based way to build these
    ///    fixtures at all, not merely an inconvenient one.
    /// 2. **It is still the right baseline, not a fallback.** These callers
    ///    are DECODE-path tests: they assert that `decode` rejects a
    ///    specific malformed byte sequence, and the sequence's malformed
    ///    part is what the test cares about — the surrounding well-formed
    ///    entries only need to be SOME valid canonical encoding of
    ///    `record`, not specifically today's production encoding.
    ///    `record_to_canonical_matches_the_owned_encoder_byte_for_byte`
    ///    (below) is the test that carries the burden of proving
    ///    `owned_record_entries_for_test` and `record_to_canonical` agree
    ///    byte-for-byte on every well-formed record; once that holds, using
    ///    the oracle here is not a weaker substitute for production, it is
    ///    an equally valid witness of "a canonical encoding of `record`" —
    ///    the only property these tests need from it.
    fn record_entries_canonical(record: &Record) -> Vec<(Value, Value)> {
        let entries = owned_record_entries_for_test(record);
        canonical_sort_entries(&entries).expect("canonical_sort_entries")
    }

    /// Re-encode a list of entries as a canonical CBOR map (sorted).
    fn encode_entries_canonical(entries: &[(Value, Value)]) -> Vec<u8> {
        encode_canonical_map(entries).expect("encode_canonical_map")
    }

    // ---- #547 differential oracle: the pre-change owned encoder ----------
    //
    // A verbatim copy of the pre-Task-4 production trio
    // (`record_to_entries` + `fields_to_value` + `field_to_entries`),
    // deliberately kept `#[cfg(test)]` rather than deleted. It serves two
    // purposes: (1) the byte-identity oracle for
    // `record_to_canonical_matches_the_owned_encoder_byte_for_byte` below,
    // proving the borrowing rewrite changed no bytes; (2) the entries-list
    // builder `record_entries_canonical` (above) needs, since that helper
    // and the many negative-path decode tests built on it predate the
    // borrowing rewrite and still need an owned, mutable `Vec<(Value,
    // Value)>` to splice hand-built CBOR fragments into — something the
    // production `record_to_canonical`'s borrowing `CanonicalMap` cannot
    // provide. Do not delete this as dead code.
    //
    // Differs from the original only in error handling: `?` becomes
    // `.expect(...)` on the two fallible `canonical_sort_entries` calls,
    // because this is now a test-fixture builder called with well-formed
    // `Record`s that cannot make those calls fail, not a fallible library
    // function whose caller needs to propagate the error.

    /// A verbatim copy of the pre-#547 `record_to_entries`. See the module
    /// note above.
    fn owned_record_entries_for_test(record: &Record) -> Vec<(Value, Value)> {
        let mut entries: Vec<(Value, Value)> = Vec::new();

        entries.push((
            Value::Text(KEY_RECORD_UUID.into()),
            Value::Bytes(record.record_uuid.to_vec()),
        ));
        entries.push((
            Value::Text(KEY_RECORD_TYPE.into()),
            Value::Text(record.record_type.clone()),
        ));
        entries.push((
            Value::Text(KEY_FIELDS.into()),
            owned_fields_to_value_for_test(&record.fields),
        ));
        if !record.tags.is_empty() {
            entries.push((
                Value::Text(KEY_TAGS.into()),
                Value::Array(record.tags.iter().map(|t| Value::Text(t.clone())).collect()),
            ));
        }
        entries.push((
            Value::Text(KEY_CREATED_AT_MS.into()),
            Value::Integer(record.created_at_ms.into()),
        ));
        entries.push((
            Value::Text(KEY_LAST_MOD_MS.into()),
            Value::Integer(record.last_mod_ms.into()),
        ));
        if record.tombstone {
            entries.push((Value::Text(KEY_TOMBSTONE.into()), Value::Bool(true)));
        }
        if record.tombstoned_at_ms != 0 {
            entries.push((
                Value::Text(KEY_TOMBSTONED_AT_MS.into()),
                Value::Integer(record.tombstoned_at_ms.into()),
            ));
        }

        // Forward-compat: splice unknowns alongside known keys. The
        // canonical sort step in encode_canonical_map decides the final
        // byte order, so it does not matter whether unknowns are pushed
        // before or after the known entries.
        for (k, v) in &record.unknown {
            entries.push((Value::Text(k.clone()), v.0.clone()));
        }

        entries
    }

    /// A verbatim copy of the pre-#547 `fields_to_value`. See the module
    /// note above `owned_record_entries_for_test`.
    fn owned_fields_to_value_for_test(fields: &BTreeMap<String, RecordField>) -> Value {
        let mut outer: Vec<(Value, Value)> = Vec::with_capacity(fields.len());
        for (fname, f) in fields {
            let inner = owned_field_entries_for_test(f);
            let sorted_inner =
                canonical_sort_entries(&inner).expect("canonical_sort_entries inner");
            outer.push((Value::Text(fname.clone()), Value::Map(sorted_inner)));
        }
        let sorted_outer = canonical_sort_entries(&outer).expect("canonical_sort_entries outer");
        Value::Map(sorted_outer)
    }

    /// A verbatim copy of the pre-#547 `field_to_entries` — including the
    /// `s.expose().to_owned()` copy Task 4 exists to remove from
    /// production. See the module note above
    /// `owned_record_entries_for_test`.
    fn owned_field_entries_for_test(field: &RecordField) -> Vec<(Value, Value)> {
        let mut entries: Vec<(Value, Value)> = Vec::new();

        let value = match &field.value {
            RecordFieldValue::Text(s) => Value::Text(s.expose().to_owned()),
            RecordFieldValue::Bytes(b) => Value::Bytes(b.expose().to_vec()),
        };
        entries.push((Value::Text(KEY_VALUE.into()), value));
        entries.push((
            Value::Text(KEY_LAST_MOD.into()),
            Value::Integer(field.last_mod.into()),
        ));
        entries.push((
            Value::Text(KEY_DEVICE_UUID.into()),
            Value::Bytes(field.device_uuid.to_vec()),
        ));

        for (k, v) in &field.unknown {
            entries.push((Value::Text(k.clone()), v.0.clone()));
        }

        entries
    }

    /// The three well-formed states of `(tombstone, tombstoned_at_ms)` —
    /// see `Record::tombstoned_at_ms`'s doc for the invariants that make
    /// this an enum rather than two independent bools. `tombstone == true`
    /// FORCES `tombstoned_at_ms == last_mod_ms`, so only three of the four
    /// `(bool, bool)` combinations are ever well-formed; naming them
    /// instead of exposing two raw bools makes the fourth, invalid one
    /// unconstructible by a caller of `random_record` rather than merely
    /// undocumented.
    #[derive(Clone, Copy, Debug)]
    enum TombstoneState {
        /// Never tombstoned: `tombstone == false`, `tombstoned_at_ms == 0`
        /// (both omitted from the wire — §6.3 / §11.3 defaults).
        Live,
        /// Tombstoned, then resurrected by a later live edit:
        /// `tombstone == false` (omitted) but `tombstoned_at_ms != 0`
        /// (present — the death clock survives resurrection, §11.3). A
        /// REAL CRDT state, and the one a fixture that only ever couples
        /// `tombstone` and `tombstoned_at_ms` to the same flag can never
        /// reach: it needs `tombstone == false` and
        /// `tombstoned_at_ms != 0` simultaneously.
        Resurrected,
        /// Currently tombstoned: `tombstone == true` and
        /// `tombstoned_at_ms == last_mod_ms` (both present on the wire).
        Tombstoned,
    }

    /// A record with randomly-generated content in every field, including a
    /// forward-compat unknown at both record and field level.
    ///
    /// `tags_present` and `tombstone_state` are independent parameters —
    /// deliberately not a single coupled flag. Each of `tags`, `tombstone`
    /// and `tombstoned_at_ms` has its own §6.3 "absent on the wire when
    /// default" conditional in `record_to_canonical`, and a fixture that
    /// only ever drives them together cannot catch a bug where one guard
    /// is cross-wired to another's field (e.g. gating `tombstone` on
    /// `tombstoned_at_ms != 0` instead of on `record.tombstone` itself) —
    /// under a coupled fixture the two conditions are always equal, so the
    /// swap is byte-invisible. The differential test below loops over
    /// every `(tags_present, tombstone_state)` combination for exactly
    /// this reason; see its own doc and the mutation check recorded in
    /// `task-4-report.md`'s fix-round-1 section.
    ///
    /// Random rather than literal per the repo's test convention: hardcoded
    /// crypto-shaped byte arrays trip CodeQL. Uses `rand_core::OsRng` (a
    /// direct, non-dev `secretary-core` dependency) rather than the `rand`
    /// crate's own `OsRng`, which in the resolved `rand` 0.9 /
    /// `rand_core` 0.9 implements only `TryRngCore`, not `RngCore` — see
    /// `secret_panic_safety.rs`'s `getrandom_fill` for the same
    /// already-documented substitution.
    fn random_record(
        rng: &mut impl rand_core::RngCore,
        tags_present: bool,
        tombstone_state: TombstoneState,
    ) -> Record {
        let mut record_uuid = [0u8; RECORD_UUID_LEN];
        rng.fill_bytes(&mut record_uuid);
        let mut device_uuid = [0u8; RECORD_UUID_LEN];
        rng.fill_bytes(&mut device_uuid);
        let mut other_device_uuid = [0u8; RECORD_UUID_LEN];
        rng.fill_bytes(&mut other_device_uuid);
        let mut secret_bytes = vec![0u8; 64];
        rng.fill_bytes(&mut secret_bytes);
        let mut record_unknown_bytes = vec![0u8; 8];
        rng.fill_bytes(&mut record_unknown_bytes);
        let mut field_unknown_bytes = vec![0u8; 5];
        rng.fill_bytes(&mut field_unknown_bytes);

        let mut fields = BTreeMap::new();
        // "password": 8 bytes — a field name whose byte length differs from
        // "k" below, so the canonical length-then-lex key sort is actually
        // exercised (it differs from `BTreeMap`'s `String` order only for
        // keys of unequal byte length).
        let mut password_unknown = BTreeMap::new();
        password_unknown.insert(
            "x_field_ext".to_string(),
            UnknownValue(Value::Bytes(field_unknown_bytes)),
        );
        fields.insert(
            "password".to_string(),
            RecordField {
                value: RecordFieldValue::Text(SecretString::new(format!(
                    "pw-{:016x}",
                    rng.next_u64()
                ))),
                last_mod: rng.next_u64() >> 16,
                device_uuid,
                unknown: password_unknown,
            },
        );
        // "k": 1 byte — deliberately a different byte length from
        // "password" (8 bytes), and `RecordFieldValue::Bytes` where the
        // first field is `::Text`, so both value arms round-trip through
        // the differential.
        fields.insert(
            "k".to_string(),
            RecordField {
                value: RecordFieldValue::Bytes(SecretBytes::new(secret_bytes)),
                last_mod: rng.next_u64() >> 16,
                device_uuid: other_device_uuid,
                unknown: BTreeMap::new(),
            },
        );
        // A 2-byte ASCII field name. On its own this would prove nothing
        // about byte-vs-char sorting — it is the PAIRING with "日" just
        // below that matters; see that field's comment.
        fields.insert(
            "ab".to_string(),
            RecordField {
                value: RecordFieldValue::Text(SecretString::new(format!(
                    "ab-{:x}",
                    rng.next_u64()
                ))),
                last_mod: rng.next_u64() >> 16,
                device_uuid,
                unknown: BTreeMap::new(),
            },
        );
        // A multi-byte UTF-8 field name ("日" — 1 char, 3 bytes). Paired
        // with "ab" above (2 bytes, 2 chars), this is what actually proves
        // the sort compares BYTE length, not char count: under byte length,
        // "ab"(2) < "日"(3); under char COUNT, "日"(1 char) < "ab"(2 chars)
        // — a genuine order flip, which the differential test's
        // independently-implemented oracle sort would then disagree with
        // byte-for-byte. Without "ab", this field alone does NOT pin the
        // property: "k" above (1 byte, 1 char) and "日" (3 bytes, 1 char)
        // TIE under char-count and fall through to the same bytewise
        // tie-break either comparator reaches, so a char-count regression
        // would have been invisible to a fixture containing only "k" and
        // "日" (a defect an earlier version of this comment did not
        // notice — the property IS separately pinned at
        // `canonical_value_equivalence.rs`'s
        // `map_key_sort_crosses_head_length_boundary_and_uses_byte_not_char_length`,
        // which is where the earlier version's claim actually held).
        fields.insert(
            "\u{65e5}".to_string(),
            RecordField {
                value: RecordFieldValue::Text(SecretString::new(format!(
                    "note-{:x}",
                    rng.next_u64()
                ))),
                last_mod: rng.next_u64() >> 16,
                device_uuid,
                unknown: BTreeMap::new(),
            },
        );
        // A 24-byte field name, crossing the CBOR text-head 23→24 boundary
        // (one-byte head vs. two-byte head), paired with a 23-byte name so
        // both sides of the boundary are present in one record.
        fields.insert(
            "b".repeat(23),
            RecordField {
                value: RecordFieldValue::Text(SecretString::new(format!(
                    "v23-{:x}",
                    rng.next_u64()
                ))),
                last_mod: rng.next_u64() >> 16,
                device_uuid,
                unknown: BTreeMap::new(),
            },
        );
        fields.insert(
            "c".repeat(24),
            RecordField {
                value: RecordFieldValue::Text(SecretString::new(format!(
                    "v24-{:x}",
                    rng.next_u64()
                ))),
                last_mod: rng.next_u64() >> 16,
                device_uuid,
                unknown: BTreeMap::new(),
            },
        );

        let mut record_unknown = BTreeMap::new();
        record_unknown.insert(
            "x_record_ext".to_string(),
            UnknownValue(Value::Text(format!("ext-{:x}", rng.next_u64()))),
        );
        record_unknown.insert(
            "x_record_ext_bytes".to_string(),
            UnknownValue(Value::Bytes(record_unknown_bytes)),
        );

        let last_mod_ms = rng.next_u64() >> 16;
        // Invariants from `Record::tombstoned_at_ms`'s doc: `tombstone ==
        // true` forces `tombstoned_at_ms == last_mod_ms`; the `Resurrected`
        // arm picks a nonzero value strictly before `last_mod_ms`, matching
        // "preserved unchanged" across a resurrecting edit (§11.3).
        let (tombstone, tombstoned_at_ms) = match tombstone_state {
            TombstoneState::Live => (false, 0),
            TombstoneState::Resurrected => {
                let earlier = last_mod_ms
                    .saturating_sub(1 + (rng.next_u64() % 1_000_000))
                    .max(1);
                (false, earlier)
            }
            TombstoneState::Tombstoned => (true, last_mod_ms),
        };
        Record {
            record_uuid,
            record_type: "login".to_string(),
            fields,
            tags: if tags_present {
                vec!["work".to_string(), "a".to_string()]
            } else {
                Vec::new()
            },
            created_at_ms: rng.next_u64() >> 16,
            last_mod_ms,
            tombstone,
            tombstoned_at_ms,
            unknown: record_unknown,
        }
    }

    /// #547: encoding a record must not copy its field plaintext out of the
    /// `SecretString` wrapper. The copy is not directly observable, so this
    /// test pins the OBSERVABLE consequence of the borrowing encoder: the
    /// bytes are unchanged from what the owned encoder produced.
    ///
    /// Runs against every `(tags_present, tombstone_state)` combination —
    /// six in total, `tags_present ∈ {false, true}` crossed with all three
    /// `TombstoneState` arms. `tags`, `tombstone` and `tombstoned_at_ms`
    /// each have their OWN independent §6.3 "absent on the wire when
    /// default" rule in `record_to_canonical`, and driving them from a
    /// single coupled flag (an earlier version of this fixture did exactly
    /// that) leaves two classes of bug invisible: a plain omission bug
    /// (never observing the "present" or the "absent" side of one
    /// conditional) AND a CROSS-WIRING bug, where one guard is
    /// accidentally gated on a DIFFERENT field's default-ness — under a
    /// coupled fixture `record.tombstone` and `record.tombstoned_at_ms !=
    /// 0` are always equal, so swapping which one gates the `tombstone`
    /// wire-emission is byte-invisible. `TombstoneState::Resurrected`
    /// (`tombstone == false`, `tombstoned_at_ms != 0`) is what makes that
    /// swap visible; see the mutation check recorded in
    /// `task-4-report.md`'s fix-round-1 section, which planted exactly
    /// this cross-wiring bug and confirmed this loop catches it where the
    /// single-flag version could not have.
    ///
    /// Uses a runtime-random record (see `random_record`) rather than a
    /// pasted literal expectation, so this test does not itself become
    /// stale documentation the moment either encoder changes.
    #[test]
    fn record_to_canonical_matches_the_owned_encoder_byte_for_byte() {
        let mut rng = rand_core::OsRng;

        for tags_present in [false, true] {
            for tombstone_state in [
                TombstoneState::Live,
                TombstoneState::Resurrected,
                TombstoneState::Tombstoned,
            ] {
                let record = random_record(&mut rng, tags_present, tombstone_state);

                let via_canonical = encode(&record).expect("encode");

                // Rebuild the same map the OWNED path built, and encode it
                // the old way. Both must agree, which is what makes the
                // borrowing encoder a safe substitution rather than a
                // format change.
                let owned_entries = owned_record_entries_for_test(&record);
                let via_owned = encode_canonical_map(&owned_entries).expect("owned encode");

                assert_eq!(
                    via_canonical, via_owned,
                    "the borrowing encoder changed the bytes — the on-disk \
                     format moved (tags_present={tags_present}, \
                     tombstone_state={tombstone_state:?})"
                );
            }
        }
    }

    // ---- Round-trip / encode-decode equivalence --------------------------

    #[test]
    fn smoke_encode_decode_roundtrip() {
        let r = sample_record();
        let bytes = encode(&r).expect("encode");
        let parsed = decode(&bytes).expect("decode");
        assert_eq!(parsed, r);
        let bytes_again = encode(&parsed).expect("re-encode");
        assert_eq!(bytes, bytes_again, "encode is deterministic");
    }

    #[test]
    fn roundtrip_full_record() {
        // Every field populated: two `fields` (one Text, one Bytes),
        // multiple tags, tombstone = true.
        let mut fields = BTreeMap::new();
        fields.insert(
            "username".to_string(),
            dummy_field(RecordFieldValue::Text("alice".into()), 1_714_060_800_000),
        );
        fields.insert(
            "totp_seed".to_string(),
            dummy_field(
                RecordFieldValue::Bytes(vec![0x11; 32].into()),
                1_714_060_800_001,
            ),
        );
        let record = Record {
            record_uuid: [0x42; RECORD_UUID_LEN],
            record_type: "login".to_string(),
            fields,
            tags: vec!["work".into(), "secret".into()],
            created_at_ms: 1_714_060_800_000,
            last_mod_ms: 1_714_060_800_010,
            tombstone: true,
            // §11.5 invariant: tombstone == true ⇒ tombstoned_at_ms ==
            // last_mod_ms. The wire-form round-trip exercises the
            // explicit-u64 encode path for tombstoned_at_ms; the
            // absent-when-zero path is covered by the dedicated
            // round-trip tests on `dummy_record`.
            tombstoned_at_ms: 1_714_060_800_010,
            unknown: BTreeMap::new(),
        };

        let bytes = encode(&record).expect("encode full record");
        let parsed = decode(&bytes).expect("decode full record");
        assert_eq!(parsed, record);
        let bytes_again = encode(&parsed).expect("re-encode");
        assert_eq!(bytes, bytes_again, "round-trip is bit-identical");
    }

    #[test]
    fn roundtrip_minimal_record() {
        // Empty fields, empty tags, tombstone = false.
        let r = dummy_record();
        let bytes = encode(&r).expect("encode minimal");
        let parsed = decode(&bytes).expect("decode minimal");
        assert_eq!(parsed, r);
        let bytes_again = encode(&parsed).expect("re-encode minimal");
        assert_eq!(
            bytes, bytes_again,
            "minimal record round-trips bit-identically"
        );
    }

    #[test]
    fn roundtrip_custom_record_type() {
        let mut r = dummy_record();
        r.record_type = "weird_future_type".to_string();
        let bytes = encode(&r).expect("encode custom type");
        let parsed = decode(&bytes).expect("decode custom type");
        assert_eq!(parsed, r);
        let bytes_again = encode(&parsed).expect("re-encode");
        assert_eq!(bytes, bytes_again);
    }

    #[test]
    fn roundtrip_bytes_value() {
        // A non-empty 32-byte payload (e.g. a parsed TOTP seed).
        let mut r = dummy_record();
        let mut fields = BTreeMap::new();
        let totp_seed: Vec<u8> = (0..32).collect();
        fields.insert(
            "totp_seed".to_string(),
            dummy_field(RecordFieldValue::Bytes(totp_seed.clone().into()), 7),
        );
        r.fields = fields;

        let bytes = encode(&r).expect("encode bytes value");
        let parsed = decode(&bytes).expect("decode bytes value");
        assert_eq!(parsed, r);
        match parsed
            .fields
            .get("totp_seed")
            .expect("totp_seed present")
            .value
            .clone()
        {
            RecordFieldValue::Bytes(b) => assert_eq!(b.expose(), totp_seed.as_slice()),
            other => panic!("expected Bytes, got {other:?}"),
        }
        let bytes_again = encode(&parsed).expect("re-encode");
        assert_eq!(bytes, bytes_again);
    }

    #[test]
    fn roundtrip_text_value_with_unicode() {
        let mut r = dummy_record();
        let mut fields = BTreeMap::new();
        // Multi-byte UTF-8: emoji + CJK + Latin-1 supplements.
        let payload = "пароль-🔐-密码-naïve";
        fields.insert(
            "password".to_string(),
            dummy_field(RecordFieldValue::Text(payload.into()), 9),
        );
        r.fields = fields;

        let bytes = encode(&r).expect("encode unicode");
        let parsed = decode(&bytes).expect("decode unicode");
        assert_eq!(parsed, r);
        match parsed
            .fields
            .get("password")
            .expect("password present")
            .value
            .clone()
        {
            RecordFieldValue::Text(s) => assert_eq!(s.expose(), payload),
            other => panic!("expected Text, got {other:?}"),
        }
        let bytes_again = encode(&parsed).expect("re-encode");
        assert_eq!(bytes, bytes_again);
    }

    // ---- Absent-vs-default semantics -------------------------------------

    #[test]
    fn decode_omits_tombstone_treated_as_false() {
        // Encode a Record (with tombstone=false → wire-absent), decode,
        // verify the in-memory representation has tombstone == false.
        let r = dummy_record();
        assert!(!r.tombstone);
        let bytes = encode(&r).expect("encode");
        let parsed = decode(&bytes).expect("decode");
        assert!(
            !parsed.tombstone,
            "absent tombstone key on the wire decodes to false"
        );
    }

    #[test]
    fn decode_explicit_tombstone_false_round_trips_as_absent() {
        // Encoding `tombstone = false` MUST omit the "tombstone" key from
        // the wire (canonical absence-equals-default per §6.3).
        let r = dummy_record();
        assert!(!r.tombstone);
        let bytes = encode(&r).expect("encode");

        // Re-parse via ciborium directly (bypassing decode()) so we can
        // inspect the raw map keys without depending on Record's view.
        let value: Value =
            ciborium::de::from_reader(&bytes[..]).expect("ciborium parse of canonical record");
        let entries = match value {
            Value::Map(e) => e,
            _ => panic!("encoded record is not a CBOR map"),
        };
        let has_tombstone_key = entries.iter().any(|(k, _)| match k {
            Value::Text(s) => s == "tombstone",
            _ => false,
        });
        assert!(
            !has_tombstone_key,
            "tombstone=false MUST be wire-absent (one canonical form)"
        );
    }

    #[test]
    fn decode_omits_tombstoned_at_ms_treated_as_zero() {
        // Encode a Record (with tombstoned_at_ms=0 → wire-absent), decode,
        // verify the in-memory representation has tombstoned_at_ms == 0.
        let r = dummy_record();
        assert_eq!(r.tombstoned_at_ms, 0);
        let bytes = encode(&r).expect("encode");
        let parsed = decode(&bytes).expect("decode");
        assert_eq!(
            parsed.tombstoned_at_ms, 0,
            "absent tombstoned_at_ms key on the wire decodes to 0"
        );
    }

    #[test]
    fn decode_explicit_tombstoned_at_ms_zero_round_trips_as_absent() {
        // Encoding `tombstoned_at_ms = 0` MUST omit the "tombstoned_at_ms"
        // key from the wire (canonical absence-equals-default per §6.3).
        let r = dummy_record();
        assert_eq!(r.tombstoned_at_ms, 0);
        let bytes = encode(&r).expect("encode");
        let value: Value =
            ciborium::de::from_reader(&bytes[..]).expect("ciborium parse of canonical record");
        let entries = match value {
            Value::Map(e) => e,
            _ => panic!("encoded record is not a CBOR map"),
        };
        let has_key = entries.iter().any(|(k, _)| match k {
            Value::Text(s) => s == "tombstoned_at_ms",
            _ => false,
        });
        assert!(
            !has_key,
            "tombstoned_at_ms=0 MUST be wire-absent (one canonical form)"
        );
    }

    #[test]
    fn roundtrip_preserves_nonzero_tombstoned_at_ms() {
        // A non-zero tombstoned_at_ms is encoded as an explicit u64 key
        // and decodes back to the same value.
        let mut r = dummy_record();
        r.tombstone = true;
        r.last_mod_ms = 1_714_060_800_500;
        r.tombstoned_at_ms = 1_714_060_800_500;
        let bytes = encode(&r).expect("encode");
        let parsed = decode(&bytes).expect("decode");
        assert!(parsed.tombstone);
        assert_eq!(parsed.tombstoned_at_ms, 1_714_060_800_500);
        // Re-encode is bit-identical (canonical-CBOR round-trip invariant).
        let bytes2 = encode(&parsed).expect("encode parsed");
        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn decode_omits_tags_treated_as_empty() {
        // Hand-build a CBOR map missing the "tags" key. The encoder also
        // omits empty tags, so we can just rely on encode() of a record
        // with empty tags and verify decode round-trips to Vec::new().
        let r = dummy_record();
        assert!(r.tags.is_empty());
        let bytes = encode(&r).expect("encode");
        let parsed = decode(&bytes).expect("decode");
        assert!(parsed.tags.is_empty(), "absent tags key decodes to empty");
    }

    #[test]
    fn decode_empty_tags_round_trips_as_absent() {
        let r = dummy_record();
        assert!(r.tags.is_empty());
        let bytes = encode(&r).expect("encode");

        let value: Value = ciborium::de::from_reader(&bytes[..]).expect("ciborium parse");
        let entries = match value {
            Value::Map(e) => e,
            _ => panic!("encoded record is not a CBOR map"),
        };
        let has_tags_key = entries.iter().any(|(k, _)| match k {
            Value::Text(s) => s == "tags",
            _ => false,
        });
        assert!(
            !has_tags_key,
            "empty tags MUST be wire-absent (one canonical form)"
        );
    }

    // ---- Forward-compat (§6.3.2) -----------------------------------------

    #[test]
    fn roundtrip_preserves_unknown_record_level_key() {
        // Build a record-level map by hand: take a canonical record's
        // entry list, splice in a forward-compat key, sort, encode.
        let r = dummy_record();
        let mut entries = record_entries_canonical(&r);
        entries.push((
            Value::Text("future_meta".into()),
            Value::Text("v2-extra".into()),
        ));
        let bytes = encode_entries_canonical(&entries);

        let parsed = decode(&bytes).expect("decode with unknown record-level key");
        assert!(
            parsed.unknown.contains_key("future_meta"),
            "unknown record-level key landed in record.unknown"
        );

        let bytes_again = encode(&parsed).expect("re-encode with preserved unknown");
        assert_eq!(
            bytes, bytes_again,
            "unknown record-level key round-trips bit-identically"
        );
    }

    #[test]
    fn roundtrip_preserves_unknown_field_level_key() {
        // Build a single field's map by hand with one extra key, splice
        // it into a record's "fields" map, and verify the record-level
        // round-trip is bit-identical.
        let r = dummy_record();
        let mut entries = record_entries_canonical(&r);

        // Construct a hand-built field map: known keys + one unknown.
        let inner_field_entries: Vec<(Value, Value)> = vec![
            (Value::Text(KEY_VALUE.into()), Value::Text("alice".into())),
            (
                Value::Text(KEY_LAST_MOD.into()),
                Value::Integer(11u64.into()),
            ),
            (
                Value::Text(KEY_DEVICE_UUID.into()),
                Value::Bytes(ZERO_DEVICE_UUID.to_vec()),
            ),
            (Value::Text("future_attr".into()), Value::Text("xyz".into())),
        ];
        let sorted_inner = canonical_sort_entries(&inner_field_entries)
            .expect("canonical_sort_entries inner field");

        let outer_fields_entries: Vec<(Value, Value)> =
            vec![(Value::Text("username".into()), Value::Map(sorted_inner))];
        let sorted_fields = canonical_sort_entries(&outer_fields_entries)
            .expect("canonical_sort_entries outer fields");

        // Replace the existing "fields" entry in the record-level entry
        // list (it currently points at an empty inner map).
        for (k, v) in entries.iter_mut() {
            if let Value::Text(s) = k {
                if s == KEY_FIELDS {
                    *v = Value::Map(sorted_fields.clone());
                }
            }
        }
        let bytes = encode_entries_canonical(&entries);

        let parsed = decode(&bytes).expect("decode with unknown field-level key");
        let username = parsed
            .fields
            .get("username")
            .expect("username field present");
        assert!(
            username.unknown.contains_key("future_attr"),
            "unknown field-level key landed in field.unknown"
        );

        let bytes_again = encode(&parsed).expect("re-encode preserves unknown field key");
        assert_eq!(
            bytes, bytes_again,
            "unknown field-level key round-trips bit-identically"
        );
    }

    #[test]
    fn roundtrip_preserves_both_levels() {
        // Record-level unknown + field-level unknown simultaneously.
        let r = dummy_record();
        let mut entries = record_entries_canonical(&r);

        // Record-level unknown
        entries.push((
            Value::Text("future_meta".into()),
            Value::Text("v2-record".into()),
        ));

        // Field-level unknown: build a fields-map containing one known
        // field with one unknown key.
        let inner_field_entries: Vec<(Value, Value)> = vec![
            (Value::Text(KEY_VALUE.into()), Value::Text("alice".into())),
            (
                Value::Text(KEY_LAST_MOD.into()),
                Value::Integer(13u64.into()),
            ),
            (
                Value::Text(KEY_DEVICE_UUID.into()),
                Value::Bytes(ZERO_DEVICE_UUID.to_vec()),
            ),
            (
                Value::Text("future_attr".into()),
                Value::Text("v2-field".into()),
            ),
        ];
        let sorted_inner = canonical_sort_entries(&inner_field_entries).expect("sort inner field");
        let outer_fields_entries: Vec<(Value, Value)> =
            vec![(Value::Text("username".into()), Value::Map(sorted_inner))];
        let sorted_fields =
            canonical_sort_entries(&outer_fields_entries).expect("sort outer fields");
        for (k, v) in entries.iter_mut() {
            if let Value::Text(s) = k {
                if s == KEY_FIELDS {
                    *v = Value::Map(sorted_fields.clone());
                }
            }
        }

        let bytes = encode_entries_canonical(&entries);
        let parsed = decode(&bytes).expect("decode both-level unknowns");

        assert!(parsed.unknown.contains_key("future_meta"));
        let username = parsed.fields.get("username").expect("username present");
        assert!(username.unknown.contains_key("future_attr"));

        let bytes_again = encode(&parsed).expect("re-encode");
        assert_eq!(bytes, bytes_again);
    }

    #[test]
    fn unknown_value_with_nested_map_or_array() {
        // Unknown record-level key whose value is a non-leaf CBOR
        // structure: a map containing both a primitive and a sub-array.
        let nested_inner = vec![
            (Value::Text("a".into()), Value::Integer(1u64.into())),
            (
                Value::Text("b".into()),
                Value::Array(vec![
                    Value::Integer(2u64.into()),
                    Value::Integer(3u64.into()),
                ]),
            ),
        ];
        let sorted_nested = canonical_sort_entries(&nested_inner).expect("sort nested map");

        let r = dummy_record();
        let mut entries = record_entries_canonical(&r);
        entries.push((
            Value::Text("future_struct".into()),
            Value::Map(sorted_nested),
        ));
        let bytes = encode_entries_canonical(&entries);

        let parsed = decode(&bytes).expect("decode nested unknown");
        assert!(parsed.unknown.contains_key("future_struct"));
        let bytes_again = encode(&parsed).expect("re-encode nested unknown");
        assert_eq!(
            bytes, bytes_again,
            "nested-map unknown value round-trips bit-identically"
        );
    }

    // ---- Strict canonical-input rejection --------------------------------

    #[test]
    fn reject_float_in_known_field() {
        // Replace `created_at_ms`'s u64 with a float. The float walker at
        // the top of decode() catches it before parse_record_map runs.
        let r = dummy_record();
        let mut entries = record_entries_canonical(&r);
        for (k, v) in entries.iter_mut() {
            if let Value::Text(s) = k {
                if s == KEY_CREATED_AT_MS {
                    *v = Value::Float(1.0);
                }
            }
        }
        let bytes = encode_entries_canonical(&entries);
        let err = decode(&bytes).expect_err("float in known field must be rejected");
        assert!(
            matches!(err, RecordError::FloatRejected { field: "<root>" }),
            "expected FloatRejected {{ field: \"<root>\" }}, got {err:?}"
        );
    }

    #[test]
    fn reject_float_inside_unknown_value() {
        // Unknown key whose value is a map that contains a float deeper
        // in the tree. The float walker recurses into unknown subtrees.
        let inner = vec![(
            Value::Text("nested".into()),
            Value::Array(vec![Value::Float(2.5)]),
        )];
        let r = dummy_record();
        let mut entries = record_entries_canonical(&r);
        entries.push((Value::Text("future_struct".into()), Value::Map(inner)));
        let bytes = encode_entries_canonical(&entries);
        let err = decode(&bytes).expect_err("float inside unknown must be rejected");
        assert!(
            matches!(err, RecordError::FloatRejected { field: "<root>" }),
            "expected FloatRejected {{ field: \"<root>\" }} (decode walker uses a single coarse hint), got {err:?}"
        );
    }

    #[test]
    fn reject_cbor_tag_anywhere() {
        // A tagged value (tag 0 = RFC 3339 datetime) appears as the value
        // of an unknown key. The tag walker catches it.
        let tagged = Value::Tag(0, Box::new(Value::Text("2024-04-25T00:00:00Z".into())));
        let r = dummy_record();
        let mut entries = record_entries_canonical(&r);
        entries.push((Value::Text("future_when".into()), tagged));
        let bytes = encode_entries_canonical(&entries);
        let err = decode(&bytes).expect_err("CBOR tag must be rejected");
        assert!(
            matches!(err, RecordError::TagRejected),
            "expected TagRejected, got {err:?}"
        );
    }

    #[test]
    fn reject_indefinite_length_map() {
        // Hand-craft an indefinite-length CBOR map containing one entry
        // (`record_uuid` → 16 zero bytes). Initial byte 0xBF starts the
        // indefinite map; 0xFF closes it. The whole thing is shaped like
        // a (very incomplete) record map; ciborium's Value reader accepts
        // the indefinite form, parse_record_map will fail with
        // MissingField, BUT the decode pipeline's first failure is the
        // re-encode-and-compare step *only if* parse_record_map succeeds.
        // To exercise NonCanonicalEncoding specifically, build a map
        // whose KNOWN-field set is complete, just wrapped in an
        // indefinite-length frame.
        let mut buf: Vec<u8> = Vec::new();
        buf.push(0xbf); // indefinite-length map start
                        // Build the entries by hand: take a canonical record's map bytes,
                        // strip the leading map-header byte, and append before our 0xFF.
        let r = dummy_record();
        let canonical = encode(&r).expect("baseline encode");
        // The first byte of the canonical map is 0xa0 + n (n entries
        // since dummy_record encodes 5 keys: record_uuid, record_type,
        // fields, created_at_ms, last_mod_ms). Sanity-check then strip.
        assert_eq!(
            canonical[0], 0xa5,
            "dummy_record encodes to a 5-entry definite-length map"
        );
        buf.extend_from_slice(&canonical[1..]);
        buf.push(0xff); // break -> closes the indefinite map

        let err = decode(&buf).expect_err("indefinite-length map must be rejected");
        assert!(
            matches!(err, RecordError::NonCanonicalEncoding),
            "expected NonCanonicalEncoding, got {err:?}"
        );
    }

    #[test]
    fn reject_indefinite_length_array() {
        // Build a record whose `tags` is an indefinite-length array. The
        // canonical-input gate rejects on re-encode mismatch.
        let mut r = dummy_record();
        r.tags = vec!["work".into()];
        let canonical = encode(&r).expect("baseline encode");

        // ciborium parses the canonical bytes back to a Value tree, then
        // we substitute the tags array with a hand-crafted indefinite
        // array and emit by hand.
        // Strategy: take the canonical bytes, locate the `tags` key
        // sequence, and rewrite the array prefix from definite (0x81 for
        // 1-element array) to indefinite (0x9f ... 0xff).
        // The `tags` value is encoded as: 0x81 0x64 'w' 'o' 'r' 'k'.
        // Replace with: 0x9f 0x64 'w' 'o' 'r' 'k' 0xff. The new bytes
        // are 1 byte longer, so the surrounding map header byte (0xa? +
        // n) is unchanged (entry count same), but we must emit a fresh
        // wrapper.
        //
        // Easier: build the whole thing from scratch by emitting each
        // entry by hand. Use ciborium for everything except the tags
        // value, which we splice in raw.
        //
        // Take the canonical map and extract its (k, v) entries via
        // ciborium, then re-emit the map header followed by the entries,
        // substituting the tags entry's value with raw indefinite-array
        // bytes.
        let value: Value =
            ciborium::de::from_reader(&canonical[..]).expect("parse canonical record");
        let entries = match value {
            Value::Map(e) => e,
            _ => panic!("not a map"),
        };
        let n = entries.len();
        assert!(n < 24, "test assumes single-byte map header");
        let mut buf: Vec<u8> = Vec::new();
        buf.push(0xa0 + (n as u8)); // definite-length map header
        for (k, v) in &entries {
            buf.extend_from_slice(&cbor_value_bytes(k));
            if let Value::Text(s) = k {
                if s == "tags" {
                    // Indefinite-length array containing one tstr "work"
                    buf.push(0x9f); // indefinite array start
                    buf.push(0x64); // tstr length 4
                    buf.extend_from_slice(b"work");
                    buf.push(0xff); // break
                    continue;
                }
            }
            buf.extend_from_slice(&cbor_value_bytes(v));
        }

        let err = decode(&buf).expect_err("indefinite-length array must be rejected");
        assert!(
            matches!(err, RecordError::NonCanonicalEncoding),
            "expected NonCanonicalEncoding, got {err:?}"
        );
    }

    #[test]
    fn reject_non_canonical_key_order() {
        // Emit a record map with the spec's listing order (NOT canonical
        // length-then-bytewise order) and verify the canonical-input
        // gate catches it.
        //
        // Listing order from §6.3:
        //   record_uuid, record_type, fields, created_at_ms, last_mod_ms
        //
        // Canonical order (length-then-bytewise):
        //   fields (6), record_type (11), record_uuid (11),
        //   created_at_ms (13), last_mod_ms (11)
        // Length-sorted: fields, last_mod_ms, record_type, record_uuid,
        // created_at_ms. So the listing order differs.
        let r = dummy_record();
        let entries: Vec<(Value, Value)> = vec![
            (
                Value::Text(KEY_RECORD_UUID.into()),
                Value::Bytes(r.record_uuid.to_vec()),
            ),
            (
                Value::Text(KEY_RECORD_TYPE.into()),
                Value::Text(r.record_type.clone()),
            ),
            (Value::Text(KEY_FIELDS.into()), Value::Map(Vec::new())),
            (
                Value::Text(KEY_CREATED_AT_MS.into()),
                Value::Integer(r.created_at_ms.into()),
            ),
            (
                Value::Text(KEY_LAST_MOD_MS.into()),
                Value::Integer(r.last_mod_ms.into()),
            ),
        ];
        let bytes = cbor_map_bytes_unsorted(&entries);

        let err = decode(&bytes).expect_err("non-canonical key order must be rejected");
        assert!(
            matches!(err, RecordError::NonCanonicalEncoding),
            "expected NonCanonicalEncoding, got {err:?}"
        );
    }

    #[test]
    fn reject_non_shortest_length_prefix() {
        // Take a canonical record whose `record_type` is "login" (5
        // bytes, encoded as `0x65` + the 5 ASCII bytes — a single
        // initial byte with the length packed inline). Replace that
        // prefix with the non-shortest 1-byte form: `0x78 0x05` + same
        // payload.
        let r = dummy_record();
        let canonical = encode(&r).expect("baseline encode");

        // Locate the byte sequence: 0x65 'l' 'o' 'g' 'i' 'n'
        let needle: [u8; 6] = [0x65, b'l', b'o', b'g', b'i', b'n'];
        let pos = canonical
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("login tstr present in canonical encoding");

        // Build new bytes with the non-shortest length prefix.
        let mut mutated: Vec<u8> = Vec::with_capacity(canonical.len() + 1);
        mutated.extend_from_slice(&canonical[..pos]);
        mutated.push(0x78); // tstr, 1-byte length follows
        mutated.push(0x05); // length = 5 (non-shortest: should be inline)
        mutated.extend_from_slice(b"login");
        mutated.extend_from_slice(&canonical[pos + needle.len()..]);

        let err = decode(&mutated).expect_err("non-shortest length must be rejected");
        assert!(
            matches!(err, RecordError::NonCanonicalEncoding),
            "expected NonCanonicalEncoding, got {err:?}"
        );
    }

    #[test]
    fn reject_duplicate_keys() {
        // Two entries with the same text key. ciborium accepts this on
        // encode; parse_record_map's seen_keys check catches it before
        // the canonical-input gate runs.
        let r = dummy_record();
        let mut entries = record_entries_canonical(&r);
        // Append a second copy of "record_type". (We don't need to keep
        // canonical sort because the duplicate-key check fires inside
        // parse_record_map, before the re-encode-and-compare step.)
        entries.push((
            Value::Text(KEY_RECORD_TYPE.into()),
            Value::Text("imposter".into()),
        ));
        let bytes = cbor_map_bytes_unsorted(&entries);

        // `record_entries_canonical` returns the 5 mandatory dummy-record
        // entries already canonically sorted by key: fields (len 6),
        // last_mod_ms / record_type / record_uuid (len 11, lexicographic:
        // 'l' < 'r', then "record_type" < "record_uuid" at the 't'/'u'
        // byte), created_at_ms (len 13). That's indices 0..4; the
        // appended duplicate "record_type" copy above lands at index 5,
        // which is where the second (matching) key is observed and the
        // error fires — not index 1, which is where the FIRST, legitimate
        // "record_type" entry sits in the sorted prefix.
        let err = decode(&bytes).expect_err("duplicate key must be rejected");
        assert!(
            matches!(
                err,
                RecordError::DuplicateKey { field: "<record>", index } if index == 5
            ),
            "expected DuplicateKey {{ field: \"<record>\", index: 5 }}, got {err:?}"
        );
        // The decrypted key name must not survive into the message.
        assert!(
            !format!("{err}").contains(KEY_RECORD_TYPE),
            "the map key leaked into the message: {err}"
        );
    }

    /// `record.rs` — the `fields` map. THE site the issue names: `key`
    /// here is a decrypted user field name, not a spec constant.
    #[test]
    fn duplicate_key_in_fields_map_reports_index_not_the_field_name() {
        const SECRET_FIELD_NAME: &str = "amex-cvv";

        // The `take_fields_map` duplicate check (`out.contains_key`) only
        // fires once the FIRST occurrence of the field name has been
        // fully parsed and inserted into `out`, so — unlike the brief's
        // sketch — the first entry's inner map must be a complete,
        // well-formed field map (value + last_mod + device_uuid), or
        // `parse_field_map` rejects it with `MissingField` before the
        // second occurrence is ever reached. The second (duplicate)
        // entry's inner map is never parsed, so its contents don't matter.
        let field_entries: Vec<(Value, Value)> = vec![
            (
                Value::Text(SECRET_FIELD_NAME.into()),
                Value::Map(vec![
                    (
                        Value::Text(KEY_VALUE.into()),
                        Value::Text("4111111111111111".into()),
                    ),
                    (Value::Text(KEY_LAST_MOD.into()), Value::Integer(1.into())),
                    (
                        Value::Text(KEY_DEVICE_UUID.into()),
                        Value::Bytes(vec![0u8; RECORD_UUID_LEN]),
                    ),
                ]),
            ),
            (
                Value::Text(SECRET_FIELD_NAME.into()),
                Value::Map(vec![(
                    Value::Text(KEY_VALUE.into()),
                    Value::Text("duplicate".into()),
                )]),
            ),
        ];

        let err = take_fields_map(Value::Map(field_entries))
            .expect_err("duplicate field name must be rejected");

        assert!(
            matches!(
                err,
                RecordError::DuplicateKey { field: "fields", index } if index == 1
            ),
            "expected DuplicateKey {{ field: \"fields\", index: 1 }}, got {err:?}"
        );
        assert!(
            !format!("{err}").contains(SECRET_FIELD_NAME),
            "THE #474 leak: decrypted field name in the message: {err}"
        );
    }

    /// `record.rs` — the field-level map.
    #[test]
    fn duplicate_key_in_field_map_reports_index_and_field_hint() {
        let entries: Vec<(Value, Value)> = vec![
            (Value::Text(KEY_VALUE.into()), Value::Text("a".into())),
            (Value::Text(KEY_VALUE.into()), Value::Text("b".into())),
        ];

        let err = parse_field_map(Value::Map(entries))
            .expect_err("duplicate field-level key must be rejected");

        assert!(
            matches!(
                err,
                RecordError::DuplicateKey { field: "<field>", index } if index == 1
            ),
            "expected DuplicateKey {{ field: \"<field>\", index: 1 }}, got {err:?}"
        );
        // The map key must not survive into the message. At this map level
        // the keys are normally the fixed constants `value` / `last_mod` /
        // `device_uuid`, but the `unknown` forward-compat bucket can carry
        // arbitrary caller-supplied key strings, so this level is a real
        // leak channel too, not just a theoretical one.
        assert!(
            !format!("{err}").contains(KEY_VALUE),
            "the map key leaked into the message: {err}"
        );
    }

    #[test]
    fn reject_wrong_type_for_known_field() {
        // last_mod_ms as a text string.
        let r = dummy_record();
        let mut entries = record_entries_canonical(&r);
        for (k, v) in entries.iter_mut() {
            if let Value::Text(s) = k {
                if s == KEY_LAST_MOD_MS {
                    *v = Value::Text("not-a-number".into());
                }
            }
        }
        let bytes = encode_entries_canonical(&entries);
        let err = decode(&bytes).expect_err("text for u64 field must be rejected");
        assert!(
            matches!(
                err,
                RecordError::WrongType {
                    field: "last_mod_ms",
                    expected: "unsigned integer",
                }
            ),
            "expected WrongType {{ field: \"last_mod_ms\", expected: \"unsigned integer\" }}, got {err:?}"
        );
    }

    #[test]
    fn reject_invalid_uuid_length() {
        // record_uuid = 15 bytes instead of 16.
        let r = dummy_record();
        let mut entries = record_entries_canonical(&r);
        for (k, v) in entries.iter_mut() {
            if let Value::Text(s) = k {
                if s == KEY_RECORD_UUID {
                    *v = Value::Bytes(vec![0u8; 15]);
                }
            }
        }
        let bytes = encode_entries_canonical(&entries);
        let err = decode(&bytes).expect_err("15-byte record_uuid must be rejected");
        assert!(
            matches!(
                err,
                RecordError::InvalidUuid {
                    field: "record_uuid",
                    length: 15,
                }
            ),
            "expected InvalidUuid {{ field: \"record_uuid\", length: 15 }}, got {err:?}"
        );
    }

    #[test]
    fn reject_missing_required_field() {
        // Drop record_uuid entirely.
        let r = dummy_record();
        let entries: Vec<(Value, Value)> = record_entries_canonical(&r)
            .into_iter()
            .filter(|(k, _)| match k {
                Value::Text(s) => s != KEY_RECORD_UUID,
                _ => true,
            })
            .collect();
        let bytes = encode_entries_canonical(&entries);
        let err = decode(&bytes).expect_err("missing record_uuid must be rejected");
        assert!(
            matches!(
                err,
                RecordError::MissingField {
                    field: "record_uuid"
                }
            ),
            "expected MissingField {{ field: \"record_uuid\" }}, got {err:?}"
        );
    }

    #[test]
    fn reject_non_text_key_in_record_map() {
        // Build a top-level record map with one integer key alongside
        // the standard text keys. The float/tag walker accepts integer
        // keys; parse_record_map's text-key check catches it.
        let r = dummy_record();
        let mut entries = record_entries_canonical(&r);
        entries.push((Value::Integer(7u64.into()), Value::Text("oops".into())));
        let bytes = cbor_map_bytes_unsorted(&entries);
        let err = decode(&bytes).expect_err("integer key must be rejected");
        assert!(
            matches!(err, RecordError::NonTextKey),
            "expected NonTextKey, got {err:?}"
        );
    }

    #[test]
    fn reject_top_level_not_a_map() {
        // A CBOR array instead of a map.
        let array = Value::Array(vec![
            Value::Integer(1u64.into()),
            Value::Integer(2u64.into()),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&array, &mut buf).expect("encode array");
        let err = decode(&buf).expect_err("non-map top level must be rejected");
        assert!(
            matches!(err, RecordError::NotAMap),
            "expected NotAMap, got {err:?}"
        );
    }

    // ---- Direct UnknownValue API -----------------------------------------

    #[test]
    fn unknown_value_round_trip() {
        // Construct from a small canonical CBOR map, then re-emit; bytes
        // must match.
        let entries = vec![
            (Value::Text("a".into()), Value::Integer(1u64.into())),
            (Value::Text("b".into()), Value::Text("two".into())),
        ];
        let sorted = canonical_sort_entries(&entries).expect("sort");
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&Value::Map(sorted), &mut bytes).expect("encode test map");

        let uv = UnknownValue::from_canonical_cbor(&bytes)
            .expect("from_canonical_cbor accepts canonical map");
        let bytes_again = uv.to_canonical_cbor().expect("to_canonical_cbor");
        assert_eq!(
            bytes, bytes_again,
            "UnknownValue round-trip is bit-identical for canonical input"
        );
    }

    #[test]
    fn unknown_value_rejects_floats() {
        // A CBOR float value at the top level.
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&Value::Float(1.5), &mut bytes).expect("encode float");
        let err =
            UnknownValue::from_canonical_cbor(&bytes).expect_err("UnknownValue must reject floats");
        assert!(
            matches!(err, RecordError::FloatRejected { field: "<unknown>" }),
            "expected FloatRejected {{ field: \"<unknown>\" }}, got {err:?}"
        );
    }

    #[test]
    fn unknown_value_rejects_tags() {
        // A tagged value at the top level.
        let tagged = Value::Tag(0, Box::new(Value::Text("2024-04-25T00:00:00Z".into())));
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&tagged, &mut bytes).expect("encode tagged");
        let err =
            UnknownValue::from_canonical_cbor(&bytes).expect_err("UnknownValue must reject tags");
        assert!(
            matches!(err, RecordError::TagRejected),
            "expected TagRejected, got {err:?}"
        );
    }

    /// The ciborium message must not survive into a core error. Today it does:
    /// ciborium's Display is its Debug form, so `Semantic(_, msg)` prints `msg`.
    #[test]
    fn cbor_decode_error_carries_a_classified_fault_not_upstream_text() {
        // Truncated CBOR: a map header promising two entries, with none.
        let truncated: &[u8] = &[0xA2];

        let err = decode(truncated).expect_err("truncated CBOR must be rejected");

        let RecordError::CborDecode(fault) = err else {
            panic!("expected CborDecode, got {err:?}");
        };
        // A syntax/EOF failure classifies as Io or Syntax depending on how
        // ciborium surfaces a short read; both are data-free. Assert the
        // property that matters rather than pinning the arm.
        assert!(
            matches!(
                fault.kind,
                crate::cbor::CborErrorKind::Io | crate::cbor::CborErrorKind::Syntax
            ),
            "unexpected kind {:?}",
            fault.kind
        );

        // Shape alone (a `CborFault` payload) does not prove the upstream
        // message was discarded — a `CborFault` could theoretically be
        // built from a stringified source elsewhere. Assert on rendered
        // content: neither Display nor Debug of the resulting `RecordError`
        // may contain ciborium's Debug-form variant names, which is the
        // observable signature of a passthrough (`ciborium`'s `Display` is
        // its `Debug` form, so a leaked message would show up as one of
        // these substrings).
        let rendered_display = format!("{err}");
        let rendered_debug = format!("{err:?}");
        for leak_marker in ["Semantic(", "Syntax(", "RecursionLimitExceeded", "Io("] {
            assert!(
                !rendered_display.contains(leak_marker),
                "Display leaked ciborium's Debug-form marker {leak_marker:?}: {rendered_display}"
            );
            assert!(
                !rendered_debug.contains(leak_marker),
                "Debug leaked ciborium's Debug-form marker {leak_marker:?}: {rendered_debug}"
            );
        }
    }

    /// `From<CanonicalError> for RecordError` must preserve both fields of
    /// `CapacityBoundExceeded` unchanged (#547 round 2, N4). The error path
    /// itself is unreachable by construction on today's `Value` variant set
    /// (see `size.rs`'s tests), which is why this constructs the
    /// `CanonicalError` directly rather than driving it through
    /// `encode_canonical_map` — but the `From` mapping is ordinary code with
    /// no such excuse, and had zero coverage before this test.
    #[test]
    fn canonical_error_capacity_bound_exceeded_maps_to_record_error() {
        let err = CanonicalError::CapacityBoundExceeded {
            actual: 42,
            bound: 17,
        };
        match RecordError::from(err) {
            RecordError::CanonicalSizeBoundExceeded { actual, bound } => {
                assert_eq!(actual, 42);
                assert_eq!(bound, 17);
            }
            other => panic!("expected CanonicalSizeBoundExceeded, got {other:?}"),
        }
    }
}
