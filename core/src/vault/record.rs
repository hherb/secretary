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

use std::collections::BTreeMap;

use ciborium::Value;

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
    /// `field` is the deepest §6.3 key whose subtree contained the
    /// float, or `"<unknown>"` if the float lived under a forward-compat
    /// key.
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
    encode_canonical_map(&entries)
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

/// Encode an entry list as a top-level canonical-CBOR map.
///
/// Implements RFC 8949 §4.2.1 sort: each key is materialised to its
/// canonical CBOR encoding, the entries are sorted bytewise on those
/// encodings, and the result is serialised as a single definite-length
/// map. Robust against any future key shape (text, byte, integer)
/// without per-type code paths.
fn encode_canonical_map(entries: &[(Value, Value)]) -> Result<Vec<u8>, RecordError> {
    let sorted = canonical_sort_entries(entries)?;
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&Value::Map(sorted), &mut buf)
        .map_err(|e| RecordError::CborEncode(e.to_string()))?;
    Ok(buf)
}

/// Sort a list of `(key, value)` entries by the canonical CBOR encoding
/// of their keys. Used both at the top level and recursively for inner
/// maps (`fields` outer + each per-field inner).
///
/// Mirrors `unlock::bundle::encode_map`'s discipline: the
/// `ciborium::ser::into_writer` call is structurally infallible against
/// a `Vec<u8>` writer, but propagating the typed error keeps this
/// function defensible against a future ciborium signature change
/// without a panic-or-empty-key footgun.
fn canonical_sort_entries(
    entries: &[(Value, Value)],
) -> Result<Vec<(Value, Value)>, RecordError> {
    let mut materialised: Vec<(Vec<u8>, (Value, Value))> = entries
        .iter()
        .map(|pair| {
            let mut key_bytes = Vec::new();
            ciborium::ser::into_writer(&pair.0, &mut key_bytes)
                .map_err(|e| RecordError::CborEncode(e.to_string()))?;
            Ok((key_bytes, pair.clone()))
        })
        .collect::<Result<_, RecordError>>()?;
    materialised.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(materialised.into_iter().map(|(_, pair)| pair).collect())
}

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

/// Walk a `Value` tree and reject floats and tags. `field_hint` gives
/// the deepest §6.3 key the caller knows about; it ends up in the
/// emitted error so the user sees which subtree contained the
/// disallowed item.
///
/// Recurses without an explicit depth bound. Termination relies on
/// `ciborium`'s default `from_reader` recursion limit (256), which has
/// already capped the input tree depth before we walk it. If a future
/// contributor switches the parser to
/// `from_reader_with_recursion_limit(.., usize::MAX)` or similar, add
/// an explicit `depth` parameter here to prevent stack overflow on
/// adversarial input.
fn reject_floats_and_tags(v: &Value, field_hint: &'static str) -> Result<(), RecordError> {
    match v {
        Value::Float(_) => Err(RecordError::FloatRejected { field: field_hint }),
        Value::Tag(_, _) => Err(RecordError::TagRejected),
        Value::Array(items) => {
            for item in items {
                reject_floats_and_tags(item, field_hint)?;
            }
            Ok(())
        }
        Value::Map(entries) => {
            for (k, val) in entries {
                reject_floats_and_tags(k, field_hint)?;
                reject_floats_and_tags(val, field_hint)?;
            }
            Ok(())
        }
        // Integer / Bytes / Text / Bool / Null are all permitted in v1.
        _ => Ok(()),
    }
}

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
    let mut seen_keys: BTreeMap<String, ()> = BTreeMap::new();

    for (k, v) in map {
        let key = match k {
            Value::Text(s) => s,
            _ => return Err(RecordError::NonTextKey),
        };
        if seen_keys.insert(key.clone(), ()).is_some() {
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
    let mut seen_keys: BTreeMap<String, ()> = BTreeMap::new();

    for (k, val) in entries {
        let key = match k {
            Value::Text(s) => s,
            _ => return Err(RecordError::NonTextKey),
        };
        if seen_keys.insert(key.clone(), ()).is_some() {
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
// Tests — smoke-level sanity. Comprehensive coverage lands in Task 2.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn smoke_encode_decode_roundtrip() {
        let r = sample_record();
        let bytes = encode(&r).expect("encode");
        let parsed = decode(&bytes).expect("decode");
        assert_eq!(parsed, r);
        let bytes_again = encode(&parsed).expect("re-encode");
        assert_eq!(bytes, bytes_again, "encode is deterministic");
    }
}
