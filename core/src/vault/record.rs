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
//! - On re-encode we splice unknown entries back alongside the known
//!   entries and let [`encode_canonical_map`] re-sort them by canonical
//!   CBOR-encoded key. Since canonical sort is total and stable, the
//!   resulting byte layout matches the input exactly when the input was
//!   itself canonical.
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

use super::canonical::{
    canonical_sort_entries, encode_canonical_map, reject_floats_and_tags, CanonicalError,
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
    /// Carries the formatted error message because the underlying
    /// `ciborium::ser::Error<E>` is generic over the writer's I/O error
    /// (`std::io::Error` / `core::convert::Infallible`) and so cannot be
    /// uniformly captured as a `#[from]` source.
    #[error("CBOR encode error: {0}")]
    CborEncode(String),

    /// `ciborium` returned a parse error during decode (e.g. truncated
    /// input, type mismatch at the byte level). Carries the formatted
    /// error message for the same generic-source reason as
    /// [`Self::CborEncode`].
    #[error("CBOR decode error: {0}")]
    CborDecode(String),

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
    InvalidUuid {
        field: &'static str,
        length: usize,
    },

    /// An integer field's value did not fit a `u64`. §6.3 timestamps and
    /// counters are all unsigned 64-bit.
    #[error("integer for field {field} does not fit u64")]
    IntegerOverflow { field: &'static str },

    /// A duplicate map key appeared. RFC 8949 §5.4 forbids duplicates in
    /// canonical input; the codebase enforces this on every CBOR map we
    /// parse.
    #[error("duplicate map key: {key}")]
    DuplicateKey { key: String },

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
impl From<CanonicalError> for RecordError {
    fn from(e: CanonicalError) -> Self {
        match e {
            CanonicalError::CborEncode(s) => RecordError::CborEncode(s),
            CanonicalError::FloatRejected { field } => RecordError::FloatRejected { field },
            CanonicalError::TagRejected { .. } => RecordError::TagRejected,
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
            .map_err(|e| RecordError::CborDecode(e.to_string()))?;
        reject_floats_and_tags(&parsed, "<unknown>")?;
        Ok(UnknownValue(parsed))
    }

    /// Serialise back to canonical CBOR.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, RecordError> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&self.0, &mut buf)
            .map_err(|e| RecordError::CborEncode(e.to_string()))?;
        Ok(buf)
    }
}

/// Per-field value: human-readable text or opaque bytes (§6.3).
///
/// §6.3 says: "A field's `value` is `tstr` for human-readable values and
/// `bstr` for binary values (e.g., a parsed TOTP seed)."
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordFieldValue {
    /// `tstr` value — UTF-8 string, e.g. a username or password.
    Text(String),
    /// `bstr` value — opaque bytes, e.g. a parsed TOTP seed.
    Bytes(Vec<u8>),
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
    /// determinism only; the wire ordering is decided by
    /// [`canonical_sort_entries`] against materialised CBOR-encoded key
    /// bytes (length-then-bytewise), which differs from `BTreeMap`'s
    /// `String` ordering for keys of differing UTF-8 lengths (e.g. `"z"`
    /// sorts before `"ab"` in canonical CBOR but after it in
    /// `BTreeMap<String, _>`). The two orders coincide only for keys of
    /// equal byte-length. (`IndexMap` would preserve insertion order,
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
pub fn encode(record: &Record) -> Result<Vec<u8>, RecordError> {
    let entries = record_to_entries(record)?;
    Ok(encode_canonical_map(&entries)?)
}

/// Build the unsorted `(key, value)` list for a record. Sorting happens
/// inside [`encode_canonical_map`].
fn record_to_entries(record: &Record) -> Result<Vec<(Value, Value)>, RecordError> {
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
        fields_to_value(&record.fields)?,
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

    // Forward-compat: splice unknowns alongside known keys. The canonical
    // sort step in encode_canonical_map decides the final byte order, so
    // it does not matter whether unknowns are pushed before or after the
    // known entries.
    for (k, v) in &record.unknown {
        entries.push((Value::Text(k.clone()), v.0.clone()));
    }

    Ok(entries)
}

/// Build the inner `fields` CBOR map. Each entry is itself a canonical
/// sub-map.
fn fields_to_value(fields: &BTreeMap<String, RecordField>) -> Result<Value, RecordError> {
    // We construct the outer map's entries here but defer canonical
    // sorting to the outer encode pass. Each inner field-map IS sorted
    // here because we have to materialise its bytes for the parent's
    // canonical encoding step.
    //
    // Equivalently: we could leave inner maps unsorted and let the
    // top-level `encode_canonical_map` recurse — but ciborium's
    // serialiser walks the Value tree once and emits whatever order is
    // there, with no recursive sort. So the sort must happen here, by
    // building each inner map's entries and immediately turning them
    // into a `Value::Map` whose entries are already canonically ordered.
    let mut outer: Vec<(Value, Value)> = Vec::with_capacity(fields.len());
    for (fname, f) in fields {
        let inner = field_to_entries(f);
        let sorted_inner = canonical_sort_entries(&inner)?;
        outer.push((Value::Text(fname.clone()), Value::Map(sorted_inner)));
    }
    let sorted_outer = canonical_sort_entries(&outer)?;
    Ok(Value::Map(sorted_outer))
}

/// Build the unsorted `(key, value)` list for one field.
fn field_to_entries(field: &RecordField) -> Vec<(Value, Value)> {
    let mut entries: Vec<(Value, Value)> = Vec::new();

    let value = match &field.value {
        RecordFieldValue::Text(s) => Value::Text(s.clone()),
        RecordFieldValue::Bytes(b) => Value::Bytes(b.clone()),
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

// `encode_canonical_map` and `canonical_sort_entries` live in
// [`crate::vault::canonical`] so block / record / manifest share one
// implementation. The shared helpers return a [`CanonicalError`]; the
// `From<CanonicalError> for RecordError` impl above lifts those errors
// to the existing record-layer variants so the public surface stays
// unchanged.

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
    let parsed: Value = ciborium::de::from_reader(bytes)
        .map_err(|e| RecordError::CborDecode(e.to_string()))?;

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
    let mut unknown: BTreeMap<String, UnknownValue> = BTreeMap::new();
    // `seen_keys` tracks every textual key we have observed at this map
    // level so duplicates (RFC 8949 §5.4) are caught even when both
    // copies fall into the unknown bucket.
    let mut seen_keys: BTreeSet<String> = BTreeSet::new();

    for (k, v) in map {
        let key = match k {
            Value::Text(s) => s,
            _ => return Err(RecordError::NonTextKey),
        };
        if !seen_keys.insert(key.clone()) {
            return Err(RecordError::DuplicateKey { key });
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
    for (k, val) in entries {
        let fname = match k {
            Value::Text(s) => s,
            _ => return Err(RecordError::NonTextKey),
        };
        if out.contains_key(&fname) {
            return Err(RecordError::DuplicateKey { key: fname });
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

    for (k, val) in entries {
        let key = match k {
            Value::Text(s) => s,
            _ => return Err(RecordError::NonTextKey),
        };
        if !seen_keys.insert(key.clone()) {
            return Err(RecordError::DuplicateKey { key });
        }
        match key.as_str() {
            KEY_VALUE => {
                value = Some(match val {
                    Value::Text(s) => RecordFieldValue::Text(s),
                    Value::Bytes(b) => RecordFieldValue::Bytes(b),
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
                value: RecordFieldValue::Text("alice".to_string()),
                last_mod: 1_714_060_800_000,
                device_uuid: [1u8; RECORD_UUID_LEN],
                unknown: BTreeMap::new(),
            },
        );
        fields.insert(
            "totp_seed".to_string(),
            RecordField {
                value: RecordFieldValue::Bytes(vec![0xde, 0xad, 0xbe, 0xef]),
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
    fn record_entries_canonical(record: &Record) -> Vec<(Value, Value)> {
        let entries = record_to_entries(record).expect("record_to_entries");
        canonical_sort_entries(&entries).expect("canonical_sort_entries")
    }

    /// Re-encode a list of entries as a canonical CBOR map (sorted).
    fn encode_entries_canonical(entries: &[(Value, Value)]) -> Vec<u8> {
        encode_canonical_map(entries).expect("encode_canonical_map")
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
                RecordFieldValue::Bytes(vec![0x11; 32]),
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
        assert_eq!(bytes, bytes_again, "minimal record round-trips bit-identically");
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
            dummy_field(RecordFieldValue::Bytes(totp_seed.clone()), 7),
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
            RecordFieldValue::Bytes(b) => assert_eq!(b, totp_seed),
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
            RecordFieldValue::Text(s) => assert_eq!(s, payload),
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
        let value: Value = ciborium::de::from_reader(&bytes[..])
            .expect("ciborium parse of canonical record");
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

        let value: Value = ciborium::de::from_reader(&bytes[..])
            .expect("ciborium parse");
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

        let outer_fields_entries: Vec<(Value, Value)> = vec![(
            Value::Text("username".into()),
            Value::Map(sorted_inner),
        )];
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
        let sorted_inner = canonical_sort_entries(&inner_field_entries)
            .expect("sort inner field");
        let outer_fields_entries: Vec<(Value, Value)> = vec![(
            Value::Text("username".into()),
            Value::Map(sorted_inner),
        )];
        let sorted_fields = canonical_sort_entries(&outer_fields_entries)
            .expect("sort outer fields");
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
        let sorted_nested = canonical_sort_entries(&nested_inner)
            .expect("sort nested map");

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
        let inner = vec![
            (
                Value::Text("nested".into()),
                Value::Array(vec![Value::Float(2.5)]),
            ),
        ];
        let r = dummy_record();
        let mut entries = record_entries_canonical(&r);
        entries.push((
            Value::Text("future_struct".into()),
            Value::Map(inner),
        ));
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
        let value: Value = ciborium::de::from_reader(&canonical[..])
            .expect("parse canonical record");
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

        let err = decode(&bytes).expect_err("duplicate key must be rejected");
        assert!(
            matches!(err, RecordError::DuplicateKey { ref key } if key == KEY_RECORD_TYPE),
            "expected DuplicateKey {{ key: \"record_type\" }}, got {err:?}"
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
        ciborium::ser::into_writer(&Value::Map(sorted), &mut bytes)
            .expect("encode test map");

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
        let err = UnknownValue::from_canonical_cbor(&bytes)
            .expect_err("UnknownValue must reject floats");
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
        let err = UnknownValue::from_canonical_cbor(&bytes)
            .expect_err("UnknownValue must reject tags");
        assert!(
            matches!(err, RecordError::TagRejected),
            "expected TagRejected, got {err:?}"
        );
    }
}
