//! Manifest CBOR body schema and codec (`docs/vault-format.md` §4.2).
//!
//! The manifest is the top-level vault index: it enumerates blocks, their
//! fingerprints and recipients, the vault-level vector clock, the trash
//! list, and a copy of the KDF params (mirrored from `vault.toml` so the
//! manifest signature attests to them — §4.2 line 205).
//!
//! This module ships **only the CBOR body**: types, canonical encode,
//! canonical decode, and the layer-local error enum. The surrounding
//! binary file header (§4.1), AEAD encrypt/decrypt, hybrid signature
//! suffix (§8), rollback resistance (§10), and orchestrators land in
//! subsequent build-sequence steps.
//!
//! ## Canonical CBOR
//!
//! Same profile as [`record`](super::record) and [`block`](super::block):
//!
//! 1. Map keys sorted bytewise lexicographically by their canonical
//!    encoded form (RFC 8949 §4.2.1, length-then-bytewise).
//! 2. Definite-length encoding for every map, array, and byte/text string.
//! 3. Shortest-form integer and length prefixes.
//! 4. **No tags, no floats, no indefinite-length items** anywhere.
//! 5. Duplicate map keys forbidden (RFC 8949 §5.4).
//!
//! Arrays additionally have explicit sort disciplines:
//!
//! - `vector_clock` and every `vector_clock_summary`: ascending by
//!   `device_uuid` (16-byte bytewise compare).
//! - `blocks`: ascending by `block_uuid`.
//! - `trash`: ascending by `block_uuid`.
//! - per-block `recipients`: ascending by 16-byte contact_uuid.
//!
//! ## Forward compatibility
//!
//! Mirrors [`record`](super::record)'s discipline: every struct that maps
//! to a CBOR object carries an `unknown` [`BTreeMap<String, UnknownValue>`]
//! that captures unrecognised keys on decode and round-trips them
//! verbatim on encode. A v1 client receiving a v2 manifest preserves the
//! v2 material so a v2 device that subsequently reads the file still sees
//! its extra fields.
//!
//! ## Pure-function API
//!
//! [`encode_manifest`] and [`decode_manifest`] are free functions, not
//! methods, per the codebase convention (pure functions in reusable
//! modules; structs hold state but do not own their own serialisation).

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use ciborium::Value;

use crate::crypto::aead::{self, AeadKey, AeadNonce, AEAD_TAG_LEN};
use crate::crypto::sig::{
    self, Ed25519Public, Ed25519Secret, Ed25519Sig, HybridSig, MlDsa65Public, MlDsa65Secret,
    MlDsa65Sig, SigError, SigRole, ED25519_SIG_LEN, ML_DSA_65_SIG_LEN,
};
use crate::identity::fingerprint::Fingerprint;
use crate::version::{FILE_KIND_MANIFEST, FORMAT_VERSION, MAGIC, SUITE_ID};

use super::canonical::{
    canonical_sort_entries, encode_canonical_map, reject_floats_and_tags, CanonicalError,
};
use super::record::UnknownValue;

// Re-use the block-layer VectorClockEntry: §4.2's vector_clock entries are
// byte-identical in shape and purpose to a block's vector_clock entries.
// See block.rs::VectorClockEntry — same `device_uuid: [u8; 16]` +
// `counter: u64`, same `Eq + Clone + PartialEq`. Re-using is the right
// call: one canonical type for vector clocks across the format.
pub use super::block::VectorClockEntry;

// ---------------------------------------------------------------------------
// Constants — manifest-level CBOR keys (§4.2)
// ---------------------------------------------------------------------------

const KEY_MANIFEST_VERSION: &str = "manifest_version";
const KEY_VAULT_UUID: &str = "vault_uuid";
const KEY_FORMAT_VERSION: &str = "format_version";
const KEY_SUITE_ID: &str = "suite_id";
const KEY_OWNER_USER_UUID: &str = "owner_user_uuid";
const KEY_VECTOR_CLOCK: &str = "vector_clock";
const KEY_BLOCKS: &str = "blocks";
const KEY_TRASH: &str = "trash";
const KEY_KDF_PARAMS: &str = "kdf_params";

// Vector-clock entry keys
const KEY_DEVICE_UUID: &str = "device_uuid";
const KEY_COUNTER: &str = "counter";

// Block-entry keys
const KEY_BLOCK_UUID: &str = "block_uuid";
const KEY_BLOCK_NAME: &str = "block_name";
const KEY_FINGERPRINT: &str = "fingerprint";
const KEY_RECIPIENTS: &str = "recipients";
const KEY_VECTOR_CLOCK_SUMMARY: &str = "vector_clock_summary";
const KEY_CREATED_AT_MS: &str = "created_at_ms";
const KEY_LAST_MOD_MS: &str = "last_mod_ms";

// Trash-entry keys
const KEY_TOMBSTONED_AT_MS: &str = "tombstoned_at_ms";
const KEY_TOMBSTONED_BY: &str = "tombstoned_by";

// kdf_params keys
const KEY_MEMORY_KIB: &str = "memory_kib";
const KEY_ITERATIONS: &str = "iterations";
const KEY_PARALLELISM: &str = "parallelism";
const KEY_SALT: &str = "salt";

// Byte lengths for the §4.2 `bstr N` fields.
const UUID_LEN: usize = 16;
const FINGERPRINT_LEN: usize = 32;
const SALT_LEN: usize = 32;

// v1 sentinels.
const MANIFEST_VERSION_V1: u8 = 1;
const FORMAT_VERSION_V1: u16 = crate::version::FORMAT_VERSION;
const SUITE_ID_V1: u16 = crate::version::SUITE_ID;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors emitted by the manifest CBOR encode and decode paths.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    /// `ciborium` returned an I/O or serialisation error during encode.
    /// String payload because `ciborium::ser::Error<E>` is generic over
    /// the writer's I/O error and so cannot be uniformly captured as a
    /// `#[from]` source. Same justification as `RecordError::CborEncode`.
    #[error("CBOR encode error: {0}")]
    CborEncode(String),

    /// `ciborium` returned a parse error during decode.
    #[error("CBOR decode error: {0}")]
    CborDecode(String),

    /// Top-level CBOR item was not a map.
    #[error("manifest body must be a CBOR map")]
    NotAMap,

    /// A map key was not a text string. §4.2 keys are all `tstr`.
    #[error("manifest map keys must be text strings")]
    NonTextKey,

    /// A required §4.2 field was absent from the parsed CBOR map. The
    /// payload is the §4.2 CBOR key name.
    #[error("missing required field: {field}")]
    MissingField { field: &'static str },

    /// A field had the wrong CBOR type. `expected` describes the spec
    /// shape (e.g. `"text string"`, `"unsigned integer"`, `"array"`).
    #[error("field {field} has wrong type (expected {expected})")]
    WrongType {
        field: &'static str,
        expected: &'static str,
    },

    /// A `bstr N` field arrived with the wrong length.
    #[error("field {field}: invalid byte-string length {length} (expected {expected})")]
    InvalidByteLength {
        field: &'static str,
        expected: usize,
        length: usize,
    },

    /// An integer field overflowed its declared width. `value` is the
    /// offending decoded integer rendered as i128 so both `u64::MAX + 1`
    /// (impossible in CBOR major type 0 but possible via major type 1)
    /// and negative values fit a single accessor.
    #[error("integer field {field} out of range: {value}")]
    IntegerOutOfRange { field: &'static str, value: i128 },

    /// Manifest body declared a `manifest_version` we don't speak.
    #[error("unsupported manifest_version: {0}")]
    UnsupportedManifestVersion(u8),

    /// Manifest body declared a `format_version` that doesn't match
    /// [`crate::version::FORMAT_VERSION`].
    #[error("unsupported format_version: {0}")]
    UnsupportedFormatVersion(u16),

    /// Manifest body declared a `suite_id` that doesn't match
    /// [`crate::version::SUITE_ID`].
    #[error("unsupported suite_id: {0}")]
    UnsupportedSuiteId(u16),

    /// Two or more vector_clock entries shared the same `device_uuid`.
    /// CRDT vector clocks are per-device, so duplicates are nonsensical
    /// and a sign of corruption or attack.
    #[error("vector clock contains duplicate device_uuid")]
    VectorClockDuplicateDevice,

    /// Two or more `blocks` entries shared the same `block_uuid`.
    #[error("blocks array contains duplicate block_uuid")]
    DuplicateBlockUuid,

    /// A canonical-CBOR rule was violated (float, tag, …). Lifted from
    /// the shared [`crate::vault::canonical`] helpers.
    #[error("canonical CBOR violation: {0}")]
    Canonical(#[from] CanonicalError),

    /// Manifest binary header (§4.1) `magic` field did not match
    /// [`crate::version::MAGIC`] (`"SECR"` big-endian). The `expected`
    /// payload is included so the surface error renders both halves and
    /// callers don't need to look up the constant. Same shape as
    /// `BlockError::BadMagic` modulo the extra `expected` field.
    #[error("bad magic: expected 0x{expected:08x}, got 0x{got:08x}")]
    BadMagic { expected: u32, got: u32 },

    /// Manifest binary header (§4.1) declared a `file_kind` other than
    /// [`crate::version::FILE_KIND_MANIFEST`]. Catches mistaken attempts
    /// to parse an identity bundle (0x0001) or a block (0x0003) as a
    /// manifest. The §4.1 spec property: file_kind is bound into the
    /// AEAD AAD, so a tampered or cross-typed file fails authentication
    /// — but we reject early with a typed error so callers can
    /// distinguish "wrong file" from "AEAD verification failed".
    #[error("unsupported file_kind: 0x{got:04x} (expected 0x{expected:04x})")]
    UnsupportedFileKind { expected: u16, got: u16 },

    /// Manifest binary header (§4.1) input was shorter than
    /// [`MANIFEST_HEADER_LEN`]. Distinguished from CBOR-body truncation
    /// by carrying the binary-header expected/actual length pair.
    #[error("manifest header truncated: need {need} bytes, got {got}")]
    HeaderTruncated { need: usize, got: usize },

    /// AEAD verification failed during manifest body decrypt (§4.1).
    /// Could mean a tampered header (AAD mismatch), a tampered
    /// ciphertext or tag, the wrong Identity Block Key, or a wrong
    /// nonce — all reported uniformly per the AEAD security model
    /// (see [`crate::crypto::aead::AeadError::Decryption`]).
    #[error("AEAD verification failed")]
    AeadFailure,

    /// Manifest file (§4.1) input was shorter than expected at a named
    /// section. Distinguished from the binary-header-specific
    /// [`Self::HeaderTruncated`] by carrying the section name so a
    /// caller can pinpoint *which* part of the §4.1 envelope is short
    /// (aead_nonce, aead_ct_len, aead_ct, aead_tag, author_fingerprint,
    /// sig_ed_len, sig_ed, sig_pq_len, sig_pq).
    #[error("manifest file truncated at {section}: need at least {need} bytes, got {got}")]
    SectionTruncated {
        section: &'static str,
        need: usize,
        got: usize,
    },

    /// On-disk `aead_ct_len` (the u32 BE length prefix immediately
    /// before the AEAD ciphertext) declared a length that does not match
    /// the bytes available between it and the trailing signature suffix
    /// (after subtracting the fixed 16-byte AEAD tag). Position-specific
    /// to the §4.1 manifest file format; the block layer uses the
    /// generic `Truncated` variant for the equivalent failure mode but
    /// the manifest layer emits a typed mismatch error so callers can
    /// distinguish "wrong length declared" from "input cut off mid-way".
    #[error("aead_ct_len ({declared}) does not match remaining body ({remaining})")]
    AeadCtLenMismatch { declared: u32, remaining: usize },

    /// [`decode_manifest_file`] found bytes after the trailing `sig_pq`.
    /// The §4.1 file format has a fixed-length suffix; any bytes after
    /// the last byte of `sig_pq` are corruption (or wire-format
    /// extension by a future suite that the v1 reader does not
    /// understand). Strict reject — the v1 spec defines no forward-
    /// compat trailing fields. Mirrors `BlockError::TrailingBytes`.
    #[error("trailing bytes after manifest file: {0} extra")]
    TrailingBytes(usize),

    /// On-disk `sig_ed_len` (the u16 BE length prefix immediately
    /// before the Ed25519 signature bytes) was not [`ED25519_SIG_LEN`]
    /// (64). §4.1 / §14 fix the Ed25519 signature length; this variant
    /// catches wire-format violations. Mirrors
    /// `BlockError::SigEdWrongLength`.
    #[error("sig_ed_len wrong: expected {expected}, got {got}")]
    SigEdWrongLength { expected: u16, got: u16 },

    /// On-disk `sig_pq_len` was not [`ML_DSA_65_SIG_LEN`] (3309). §4.1
    /// / §14 fix the ML-DSA-65 signature length under suite
    /// `secretary-v1-pq-hybrid`. Mirrors `BlockError::SigPqWrongLength`:
    /// a wire-format length violation is a parse error, not a sign /
    /// verify failure, and gets its own variant rather than being
    /// collapsed.
    #[error("sig_pq_len wrong: expected {expected}, got {got}")]
    SigPqWrongLength { expected: u16, got: u16 },

    /// Ed25519 half of the §8 hybrid signature on the manifest file
    /// rejected. Position-specific to the manifest signature. Mirrors
    /// `BlockError::Sig(SigError::Ed25519VerifyFailed)` but is its own
    /// typed variant so a caller can distinguish "manifest signature
    /// invalid" from "block signature invalid".
    #[error("Ed25519 signature invalid")]
    Ed25519SignatureInvalid,

    /// ML-DSA-65 half of the §8 hybrid signature on the manifest file
    /// rejected. Same position-specific discipline as
    /// [`Self::Ed25519SignatureInvalid`].
    #[error("ML-DSA-65 signature invalid")]
    MlDsa65SignatureInvalid,

    /// `sign_manifest` could not produce a valid signature (e.g. the
    /// underlying [`crate::crypto::sig::sign`] rejected the secret-key
    /// bytes). Wraps the inner [`SigError`] for diagnostics. Decode-
    /// side length mismatches do NOT flow through this variant — they
    /// have their own typed `SigEdWrongLength` / `SigPqWrongLength` /
    /// `*SignatureInvalid` variants.
    #[error("manifest sign internal error: {0}")]
    SignInternal(SigError),
}

// ---------------------------------------------------------------------------
// In-memory types
// ---------------------------------------------------------------------------

/// KDF parameters mirrored from `vault.toml` so the manifest signature
/// attests to them (§4.2 line 205).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdfParamsRef {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt: [u8; SALT_LEN],
}

/// One block entry within the manifest's `blocks` array (§4.2).
///
/// Only [`PartialEq`] (not [`Eq`]) is implemented — see [`Manifest`] for
/// the full justification.
#[derive(Debug, Clone, PartialEq)]
pub struct BlockEntry {
    /// 16-byte block UUID. Identifies the block file on disk.
    pub block_uuid: [u8; UUID_LEN],
    /// User-visible block name, plaintext within the encrypted manifest.
    pub block_name: String,
    /// BLAKE3-256 of the complete block file bytes.
    pub fingerprint: [u8; FINGERPRINT_LEN],
    /// Contact UUIDs of each recipient (always includes owner). Encoded
    /// in ascending lex order.
    pub recipients: Vec<[u8; UUID_LEN]>,
    /// The block's own vector clock at last manifest update. Encoded in
    /// ascending `device_uuid` order.
    pub vector_clock_summary: Vec<VectorClockEntry>,
    /// Cipher suite the block file is encrypted under.
    pub suite_id: u16,
    pub created_at_ms: u64,
    pub last_mod_ms: u64,
    /// Forward-compat unknown keys preserved verbatim per the §6.3.2
    /// pattern, applied here at the manifest layer.
    pub unknown: BTreeMap<String, UnknownValue>,
}

/// One trash entry (tombstoned block) within `manifest.trash` (§4.2).
///
/// Only [`PartialEq`] (not [`Eq`]) is implemented — see [`Manifest`] for
/// the full justification.
#[derive(Debug, Clone, PartialEq)]
pub struct TrashEntry {
    pub block_uuid: [u8; UUID_LEN],
    pub tombstoned_at_ms: u64,
    /// `device_uuid` that performed the deletion.
    pub tombstoned_by: [u8; UUID_LEN],
    pub unknown: BTreeMap<String, UnknownValue>,
}

/// Top-level manifest body (§4.2 — the canonical CBOR plaintext that
/// goes inside `aead_ct`).
///
/// Only [`PartialEq`] (not [`Eq`]) is implemented: the [`UnknownValue`]
/// payload in `unknown` (and in nested `BlockEntry`/`TrashEntry`) wraps
/// a [`ciborium::Value`] which does not implement [`Eq`] (the `Float`
/// variant breaks reflexivity for NaN). The decoder rejects floats, so
/// any [`Manifest`] produced by [`decode_manifest`] is float-free in
/// practice; the type contract is the conservative one. Same reasoning
/// as [`super::record::Record`].
#[derive(Debug, Clone, PartialEq)]
pub struct Manifest {
    /// Manifest schema version. Reserved for future incompatible manifest
    /// changes; v1 is the only value v1 clients accept.
    pub manifest_version: u8,
    pub vault_uuid: [u8; UUID_LEN],
    pub format_version: u16,
    pub suite_id: u16,
    pub owner_user_uuid: [u8; UUID_LEN],
    /// Vault-level vector clock. Encoded in ascending `device_uuid` order.
    pub vector_clock: Vec<VectorClockEntry>,
    /// Block list. Encoded in ascending `block_uuid` order.
    pub blocks: Vec<BlockEntry>,
    /// Tombstoned blocks. Encoded in ascending `block_uuid` order.
    pub trash: Vec<TrashEntry>,
    /// KDF params duplicated from `vault.toml` so the manifest signature
    /// attests to them.
    pub kdf_params: KdfParamsRef,
    /// Forward-compat unknown top-level keys, preserved verbatim.
    pub unknown: BTreeMap<String, UnknownValue>,
}

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

/// Canonical CBOR encoding of a manifest body (§4.2). Output is
/// deterministic: any conformant RFC 8949 §4.2.1 encoder produces the
/// same bytes.
///
/// All arrays (`vector_clock`, every `vector_clock_summary`, `blocks`,
/// `trash`, every block's `recipients`) are sorted on output per the
/// §4.2 sort disciplines. Forward-compat unknown keys are spliced in
/// alongside known keys at the canonical-sort step.
pub fn encode_manifest(manifest: &Manifest) -> Result<Vec<u8>, ManifestError> {
    let entries = manifest_to_entries(manifest)?;
    Ok(encode_canonical_map(&entries)?)
}

fn manifest_to_entries(m: &Manifest) -> Result<Vec<(Value, Value)>, ManifestError> {
    let mut entries: Vec<(Value, Value)> = vec![
        (
            Value::Text(KEY_MANIFEST_VERSION.into()),
            Value::Integer(u64::from(m.manifest_version).into()),
        ),
        (
            Value::Text(KEY_VAULT_UUID.into()),
            Value::Bytes(m.vault_uuid.to_vec()),
        ),
        (
            Value::Text(KEY_FORMAT_VERSION.into()),
            Value::Integer(u64::from(m.format_version).into()),
        ),
        (
            Value::Text(KEY_SUITE_ID.into()),
            Value::Integer(u64::from(m.suite_id).into()),
        ),
        (
            Value::Text(KEY_OWNER_USER_UUID.into()),
            Value::Bytes(m.owner_user_uuid.to_vec()),
        ),
        (
            Value::Text(KEY_VECTOR_CLOCK.into()),
            vector_clock_to_value(&m.vector_clock)?,
        ),
        (Value::Text(KEY_BLOCKS.into()), blocks_to_value(&m.blocks)?),
        (Value::Text(KEY_TRASH.into()), trash_to_value(&m.trash)?),
        (
            Value::Text(KEY_KDF_PARAMS.into()),
            kdf_params_to_value(&m.kdf_params)?,
        ),
    ];

    for (k, v) in &m.unknown {
        entries.push((Value::Text(k.clone()), unknown_value_inner(v)?));
    }

    Ok(entries)
}

/// Encode a vector clock array sorted ascending by `device_uuid`.
fn vector_clock_to_value(vc: &[VectorClockEntry]) -> Result<Value, ManifestError> {
    let mut sorted: Vec<&VectorClockEntry> = vc.iter().collect();
    sorted.sort_by(|a, b| a.device_uuid.cmp(&b.device_uuid));

    let items: Result<Vec<Value>, ManifestError> = sorted
        .into_iter()
        .map(|entry| {
            let inner = vec![
                (
                    Value::Text(KEY_DEVICE_UUID.into()),
                    Value::Bytes(entry.device_uuid.to_vec()),
                ),
                (
                    Value::Text(KEY_COUNTER.into()),
                    Value::Integer(entry.counter.into()),
                ),
            ];
            let sorted_inner = canonical_sort_entries(&inner)?;
            Ok(Value::Map(sorted_inner))
        })
        .collect();
    Ok(Value::Array(items?))
}

fn blocks_to_value(blocks: &[BlockEntry]) -> Result<Value, ManifestError> {
    let mut sorted: Vec<&BlockEntry> = blocks.iter().collect();
    sorted.sort_by(|a, b| a.block_uuid.cmp(&b.block_uuid));

    let items: Result<Vec<Value>, ManifestError> = sorted
        .into_iter()
        .map(block_entry_to_value)
        .collect();
    Ok(Value::Array(items?))
}

fn block_entry_to_value(entry: &BlockEntry) -> Result<Value, ManifestError> {
    // Recipients sorted ascending by 16-byte lex compare.
    let mut recipients: Vec<&[u8; UUID_LEN]> = entry.recipients.iter().collect();
    recipients.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
    let recipients_value = Value::Array(
        recipients
            .into_iter()
            .map(|r| Value::Bytes(r.to_vec()))
            .collect(),
    );

    let mut inner: Vec<(Value, Value)> = vec![
        (
            Value::Text(KEY_BLOCK_UUID.into()),
            Value::Bytes(entry.block_uuid.to_vec()),
        ),
        (
            Value::Text(KEY_BLOCK_NAME.into()),
            Value::Text(entry.block_name.clone()),
        ),
        (
            Value::Text(KEY_FINGERPRINT.into()),
            Value::Bytes(entry.fingerprint.to_vec()),
        ),
        (Value::Text(KEY_RECIPIENTS.into()), recipients_value),
        (
            Value::Text(KEY_VECTOR_CLOCK_SUMMARY.into()),
            vector_clock_to_value(&entry.vector_clock_summary)?,
        ),
        (
            Value::Text(KEY_SUITE_ID.into()),
            Value::Integer(u64::from(entry.suite_id).into()),
        ),
        (
            Value::Text(KEY_CREATED_AT_MS.into()),
            Value::Integer(entry.created_at_ms.into()),
        ),
        (
            Value::Text(KEY_LAST_MOD_MS.into()),
            Value::Integer(entry.last_mod_ms.into()),
        ),
    ];
    for (k, v) in &entry.unknown {
        inner.push((Value::Text(k.clone()), unknown_value_inner(v)?));
    }
    let sorted = canonical_sort_entries(&inner)?;
    Ok(Value::Map(sorted))
}

fn trash_to_value(trash: &[TrashEntry]) -> Result<Value, ManifestError> {
    let mut sorted: Vec<&TrashEntry> = trash.iter().collect();
    sorted.sort_by(|a, b| a.block_uuid.cmp(&b.block_uuid));

    let items: Result<Vec<Value>, ManifestError> = sorted
        .into_iter()
        .map(trash_entry_to_value)
        .collect();
    Ok(Value::Array(items?))
}

fn trash_entry_to_value(entry: &TrashEntry) -> Result<Value, ManifestError> {
    let mut inner: Vec<(Value, Value)> = vec![
        (
            Value::Text(KEY_BLOCK_UUID.into()),
            Value::Bytes(entry.block_uuid.to_vec()),
        ),
        (
            Value::Text(KEY_TOMBSTONED_AT_MS.into()),
            Value::Integer(entry.tombstoned_at_ms.into()),
        ),
        (
            Value::Text(KEY_TOMBSTONED_BY.into()),
            Value::Bytes(entry.tombstoned_by.to_vec()),
        ),
    ];
    for (k, v) in &entry.unknown {
        inner.push((Value::Text(k.clone()), unknown_value_inner(v)?));
    }
    let sorted = canonical_sort_entries(&inner)?;
    Ok(Value::Map(sorted))
}

fn kdf_params_to_value(k: &KdfParamsRef) -> Result<Value, ManifestError> {
    let inner = vec![
        (
            Value::Text(KEY_MEMORY_KIB.into()),
            Value::Integer(u64::from(k.memory_kib).into()),
        ),
        (
            Value::Text(KEY_ITERATIONS.into()),
            Value::Integer(u64::from(k.iterations).into()),
        ),
        (
            Value::Text(KEY_PARALLELISM.into()),
            Value::Integer(u64::from(k.parallelism).into()),
        ),
        (
            Value::Text(KEY_SALT.into()),
            Value::Bytes(k.salt.to_vec()),
        ),
    ];
    let sorted = canonical_sort_entries(&inner)?;
    Ok(Value::Map(sorted))
}

/// Extract the underlying CBOR `Value` from an [`UnknownValue`] for
/// splicing into a parent map. We round-trip via canonical CBOR bytes so
/// the call site does not need access to `UnknownValue`'s inner field.
fn unknown_value_inner(u: &UnknownValue) -> Result<Value, ManifestError> {
    let bytes = u
        .to_canonical_cbor()
        .map_err(|e| ManifestError::CborEncode(e.to_string()))?;
    let v: Value = ciborium::de::from_reader(bytes.as_slice())
        .map_err(|e| ManifestError::CborDecode(e.to_string()))?;
    Ok(v)
}

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

/// Strict canonical-CBOR decoder for a manifest body (§4.2).
///
/// Validates:
/// 1. Top-level item is a map.
/// 2. All map keys are text strings.
/// 3. No floats, no tags anywhere in the tree (canonical CBOR rule).
/// 4. All required §4.2 fields are present with their spec types.
/// 5. Every byte-string field has the expected length (UUIDs, fingerprint,
///    salt).
/// 6. Every integer fits its declared width (u8 / u16 / u32 / u64).
/// 7. `manifest_version`, `format_version`, `suite_id` match v1 sentinels.
/// 8. `vector_clock` and every `vector_clock_summary` have no duplicate
///    `device_uuid`.
/// 9. `blocks` has no duplicate `block_uuid`.
///
/// Forward-compat unknown keys are preserved into the relevant `unknown`
/// bag verbatim.
pub fn decode_manifest(bytes: &[u8]) -> Result<Manifest, ManifestError> {
    let parsed: Value = ciborium::de::from_reader(bytes)
        .map_err(|e| ManifestError::CborDecode(e.to_string()))?;

    // Walk the tree once up front to enforce no-float / no-tag everywhere
    // (including inside forward-compat unknown values).
    reject_floats_and_tags(&parsed, "<root>")?;

    let map = match parsed {
        Value::Map(m) => m,
        _ => return Err(ManifestError::NotAMap),
    };

    parse_manifest_map(map)
}

fn parse_manifest_map(map: Vec<(Value, Value)>) -> Result<Manifest, ManifestError> {
    let mut manifest_version: Option<u8> = None;
    let mut vault_uuid: Option<[u8; UUID_LEN]> = None;
    let mut format_version: Option<u16> = None;
    let mut suite_id: Option<u16> = None;
    let mut owner_user_uuid: Option<[u8; UUID_LEN]> = None;
    let mut vector_clock: Option<Vec<VectorClockEntry>> = None;
    let mut blocks: Option<Vec<BlockEntry>> = None;
    let mut trash: Option<Vec<TrashEntry>> = None;
    let mut kdf_params: Option<KdfParamsRef> = None;
    let mut unknown: BTreeMap<String, UnknownValue> = BTreeMap::new();

    for (k, v) in map {
        let key = take_text_key(k)?;
        match key.as_str() {
            KEY_MANIFEST_VERSION => {
                manifest_version = Some(take_u8(v, KEY_MANIFEST_VERSION)?);
            }
            KEY_VAULT_UUID => {
                vault_uuid = Some(take_fixed_bytes::<UUID_LEN>(v, KEY_VAULT_UUID)?);
            }
            KEY_FORMAT_VERSION => {
                format_version = Some(take_u16(v, KEY_FORMAT_VERSION)?);
            }
            KEY_SUITE_ID => {
                suite_id = Some(take_u16(v, KEY_SUITE_ID)?);
            }
            KEY_OWNER_USER_UUID => {
                owner_user_uuid = Some(take_fixed_bytes::<UUID_LEN>(v, KEY_OWNER_USER_UUID)?);
            }
            KEY_VECTOR_CLOCK => {
                vector_clock = Some(parse_vector_clock(v, KEY_VECTOR_CLOCK)?);
            }
            KEY_BLOCKS => {
                blocks = Some(parse_blocks(v)?);
            }
            KEY_TRASH => {
                trash = Some(parse_trash(v)?);
            }
            KEY_KDF_PARAMS => {
                kdf_params = Some(parse_kdf_params(v)?);
            }
            _ => {
                unknown.insert(key, value_to_unknown(v)?);
            }
        }
    }

    let manifest_version = manifest_version.ok_or(ManifestError::MissingField {
        field: KEY_MANIFEST_VERSION,
    })?;
    if manifest_version != MANIFEST_VERSION_V1 {
        return Err(ManifestError::UnsupportedManifestVersion(manifest_version));
    }
    let format_version = format_version.ok_or(ManifestError::MissingField {
        field: KEY_FORMAT_VERSION,
    })?;
    if format_version != FORMAT_VERSION_V1 {
        return Err(ManifestError::UnsupportedFormatVersion(format_version));
    }
    let suite_id = suite_id.ok_or(ManifestError::MissingField { field: KEY_SUITE_ID })?;
    if suite_id != SUITE_ID_V1 {
        return Err(ManifestError::UnsupportedSuiteId(suite_id));
    }

    Ok(Manifest {
        manifest_version,
        vault_uuid: vault_uuid.ok_or(ManifestError::MissingField {
            field: KEY_VAULT_UUID,
        })?,
        format_version,
        suite_id,
        owner_user_uuid: owner_user_uuid.ok_or(ManifestError::MissingField {
            field: KEY_OWNER_USER_UUID,
        })?,
        vector_clock: vector_clock.ok_or(ManifestError::MissingField {
            field: KEY_VECTOR_CLOCK,
        })?,
        blocks: blocks.ok_or(ManifestError::MissingField { field: KEY_BLOCKS })?,
        trash: trash.ok_or(ManifestError::MissingField { field: KEY_TRASH })?,
        kdf_params: kdf_params.ok_or(ManifestError::MissingField {
            field: KEY_KDF_PARAMS,
        })?,
        unknown,
    })
}

fn parse_vector_clock(
    v: Value,
    field: &'static str,
) -> Result<Vec<VectorClockEntry>, ManifestError> {
    let items = match v {
        Value::Array(a) => a,
        _ => {
            return Err(ManifestError::WrongType {
                field,
                expected: "array of vector_clock entries",
            })
        }
    };
    let mut out: Vec<VectorClockEntry> = Vec::with_capacity(items.len());
    for item in items {
        out.push(parse_vector_clock_entry(item)?);
    }
    // Reject duplicate device_uuids in either of the two vector_clock
    // arrays. Sort a copy of the device_uuids and check adjacent equality
    // — O(n log n) and avoids allocating a HashSet for what is typically
    // a handful of entries.
    let mut ids: Vec<[u8; UUID_LEN]> = out.iter().map(|e| e.device_uuid).collect();
    ids.sort();
    if ids.windows(2).any(|w| w[0] == w[1]) {
        return Err(ManifestError::VectorClockDuplicateDevice);
    }
    Ok(out)
}

fn parse_vector_clock_entry(v: Value) -> Result<VectorClockEntry, ManifestError> {
    let entries = match v {
        Value::Map(m) => m,
        _ => {
            return Err(ManifestError::WrongType {
                field: KEY_VECTOR_CLOCK,
                expected: "map (vector_clock entry)",
            })
        }
    };
    let mut device_uuid: Option<[u8; UUID_LEN]> = None;
    let mut counter: Option<u64> = None;
    for (k, val) in entries {
        let key = take_text_key(k)?;
        match key.as_str() {
            KEY_DEVICE_UUID => {
                device_uuid = Some(take_fixed_bytes::<UUID_LEN>(val, KEY_DEVICE_UUID)?);
            }
            KEY_COUNTER => {
                counter = Some(take_u64(val, KEY_COUNTER)?);
            }
            // Vector clock entries don't carry an unknown bag in v1 —
            // they're a fixed two-field shape per §4.2. Unknown keys here
            // would be out of scope for the spec and should not be
            // silently absorbed; reject as WrongType-equivalent. Treat as
            // a missing-field semantic by ignoring (see §6.3.2 forward-
            // compat principle: no extension surface here means strict).
            // We choose the conservative path: reject.
            _ => {
                return Err(ManifestError::WrongType {
                    field: KEY_VECTOR_CLOCK,
                    expected: "map with only device_uuid and counter keys",
                })
            }
        }
    }
    Ok(VectorClockEntry {
        device_uuid: device_uuid.ok_or(ManifestError::MissingField {
            field: KEY_DEVICE_UUID,
        })?,
        counter: counter.ok_or(ManifestError::MissingField { field: KEY_COUNTER })?,
    })
}

fn parse_blocks(v: Value) -> Result<Vec<BlockEntry>, ManifestError> {
    let items = match v {
        Value::Array(a) => a,
        _ => {
            return Err(ManifestError::WrongType {
                field: KEY_BLOCKS,
                expected: "array of block entries",
            })
        }
    };
    let mut out: Vec<BlockEntry> = Vec::with_capacity(items.len());
    for item in items {
        out.push(parse_block_entry(item)?);
    }
    let mut ids: Vec<[u8; UUID_LEN]> = out.iter().map(|b| b.block_uuid).collect();
    ids.sort();
    if ids.windows(2).any(|w| w[0] == w[1]) {
        return Err(ManifestError::DuplicateBlockUuid);
    }
    Ok(out)
}

fn parse_block_entry(v: Value) -> Result<BlockEntry, ManifestError> {
    let entries = match v {
        Value::Map(m) => m,
        _ => {
            return Err(ManifestError::WrongType {
                field: KEY_BLOCKS,
                expected: "map (block entry)",
            })
        }
    };
    let mut block_uuid: Option<[u8; UUID_LEN]> = None;
    let mut block_name: Option<String> = None;
    let mut fingerprint: Option<[u8; FINGERPRINT_LEN]> = None;
    let mut recipients: Option<Vec<[u8; UUID_LEN]>> = None;
    let mut vector_clock_summary: Option<Vec<VectorClockEntry>> = None;
    let mut suite_id: Option<u16> = None;
    let mut created_at_ms: Option<u64> = None;
    let mut last_mod_ms: Option<u64> = None;
    let mut unknown: BTreeMap<String, UnknownValue> = BTreeMap::new();

    for (k, val) in entries {
        let key = take_text_key(k)?;
        match key.as_str() {
            KEY_BLOCK_UUID => {
                block_uuid = Some(take_fixed_bytes::<UUID_LEN>(val, KEY_BLOCK_UUID)?);
            }
            KEY_BLOCK_NAME => {
                block_name = Some(take_text(val, KEY_BLOCK_NAME)?);
            }
            KEY_FINGERPRINT => {
                fingerprint = Some(take_fixed_bytes::<FINGERPRINT_LEN>(val, KEY_FINGERPRINT)?);
            }
            KEY_RECIPIENTS => {
                recipients = Some(parse_recipients(val)?);
            }
            KEY_VECTOR_CLOCK_SUMMARY => {
                vector_clock_summary =
                    Some(parse_vector_clock(val, KEY_VECTOR_CLOCK_SUMMARY)?);
            }
            KEY_SUITE_ID => {
                suite_id = Some(take_u16(val, KEY_SUITE_ID)?);
            }
            KEY_CREATED_AT_MS => {
                created_at_ms = Some(take_u64(val, KEY_CREATED_AT_MS)?);
            }
            KEY_LAST_MOD_MS => {
                last_mod_ms = Some(take_u64(val, KEY_LAST_MOD_MS)?);
            }
            _ => {
                unknown.insert(key, value_to_unknown(val)?);
            }
        }
    }

    Ok(BlockEntry {
        block_uuid: block_uuid.ok_or(ManifestError::MissingField {
            field: KEY_BLOCK_UUID,
        })?,
        block_name: block_name.ok_or(ManifestError::MissingField {
            field: KEY_BLOCK_NAME,
        })?,
        fingerprint: fingerprint.ok_or(ManifestError::MissingField {
            field: KEY_FINGERPRINT,
        })?,
        recipients: recipients.ok_or(ManifestError::MissingField {
            field: KEY_RECIPIENTS,
        })?,
        vector_clock_summary: vector_clock_summary.ok_or(ManifestError::MissingField {
            field: KEY_VECTOR_CLOCK_SUMMARY,
        })?,
        suite_id: suite_id.ok_or(ManifestError::MissingField { field: KEY_SUITE_ID })?,
        created_at_ms: created_at_ms.ok_or(ManifestError::MissingField {
            field: KEY_CREATED_AT_MS,
        })?,
        last_mod_ms: last_mod_ms.ok_or(ManifestError::MissingField {
            field: KEY_LAST_MOD_MS,
        })?,
        unknown,
    })
}

fn parse_recipients(v: Value) -> Result<Vec<[u8; UUID_LEN]>, ManifestError> {
    let items = match v {
        Value::Array(a) => a,
        _ => {
            return Err(ManifestError::WrongType {
                field: KEY_RECIPIENTS,
                expected: "array of contact_uuids",
            })
        }
    };
    items
        .into_iter()
        .map(|item| take_fixed_bytes::<UUID_LEN>(item, KEY_RECIPIENTS))
        .collect()
}

fn parse_trash(v: Value) -> Result<Vec<TrashEntry>, ManifestError> {
    let items = match v {
        Value::Array(a) => a,
        _ => {
            return Err(ManifestError::WrongType {
                field: KEY_TRASH,
                expected: "array of trash entries",
            })
        }
    };
    items.into_iter().map(parse_trash_entry).collect()
}

fn parse_trash_entry(v: Value) -> Result<TrashEntry, ManifestError> {
    let entries = match v {
        Value::Map(m) => m,
        _ => {
            return Err(ManifestError::WrongType {
                field: KEY_TRASH,
                expected: "map (trash entry)",
            })
        }
    };
    let mut block_uuid: Option<[u8; UUID_LEN]> = None;
    let mut tombstoned_at_ms: Option<u64> = None;
    let mut tombstoned_by: Option<[u8; UUID_LEN]> = None;
    let mut unknown: BTreeMap<String, UnknownValue> = BTreeMap::new();

    for (k, val) in entries {
        let key = take_text_key(k)?;
        match key.as_str() {
            KEY_BLOCK_UUID => {
                block_uuid = Some(take_fixed_bytes::<UUID_LEN>(val, KEY_BLOCK_UUID)?);
            }
            KEY_TOMBSTONED_AT_MS => {
                tombstoned_at_ms = Some(take_u64(val, KEY_TOMBSTONED_AT_MS)?);
            }
            KEY_TOMBSTONED_BY => {
                tombstoned_by = Some(take_fixed_bytes::<UUID_LEN>(val, KEY_TOMBSTONED_BY)?);
            }
            _ => {
                unknown.insert(key, value_to_unknown(val)?);
            }
        }
    }

    Ok(TrashEntry {
        block_uuid: block_uuid.ok_or(ManifestError::MissingField {
            field: KEY_BLOCK_UUID,
        })?,
        tombstoned_at_ms: tombstoned_at_ms.ok_or(ManifestError::MissingField {
            field: KEY_TOMBSTONED_AT_MS,
        })?,
        tombstoned_by: tombstoned_by.ok_or(ManifestError::MissingField {
            field: KEY_TOMBSTONED_BY,
        })?,
        unknown,
    })
}

fn parse_kdf_params(v: Value) -> Result<KdfParamsRef, ManifestError> {
    let entries = match v {
        Value::Map(m) => m,
        _ => {
            return Err(ManifestError::WrongType {
                field: KEY_KDF_PARAMS,
                expected: "map",
            })
        }
    };
    let mut memory_kib: Option<u32> = None;
    let mut iterations: Option<u32> = None;
    let mut parallelism: Option<u32> = None;
    let mut salt: Option<[u8; SALT_LEN]> = None;

    for (k, val) in entries {
        let key = take_text_key(k)?;
        match key.as_str() {
            KEY_MEMORY_KIB => memory_kib = Some(take_u32(val, KEY_MEMORY_KIB)?),
            KEY_ITERATIONS => iterations = Some(take_u32(val, KEY_ITERATIONS)?),
            KEY_PARALLELISM => parallelism = Some(take_u32(val, KEY_PARALLELISM)?),
            KEY_SALT => salt = Some(take_fixed_bytes::<SALT_LEN>(val, KEY_SALT)?),
            // kdf_params has a fixed shape in v1; reject unknown keys
            // here for the same reason as vector_clock entries.
            _ => {
                return Err(ManifestError::WrongType {
                    field: KEY_KDF_PARAMS,
                    expected: "map with only memory_kib/iterations/parallelism/salt keys",
                })
            }
        }
    }

    Ok(KdfParamsRef {
        memory_kib: memory_kib.ok_or(ManifestError::MissingField {
            field: KEY_MEMORY_KIB,
        })?,
        iterations: iterations.ok_or(ManifestError::MissingField {
            field: KEY_ITERATIONS,
        })?,
        parallelism: parallelism.ok_or(ManifestError::MissingField {
            field: KEY_PARALLELISM,
        })?,
        salt: salt.ok_or(ManifestError::MissingField { field: KEY_SALT })?,
    })
}

// ---------------------------------------------------------------------------
// Typed-extract helpers (manifest-local; per the brief, do NOT extract
// these into a shared canonical helper module — duplication is the right
// call until a fourth caller materialises).
// ---------------------------------------------------------------------------

fn take_text_key(v: Value) -> Result<String, ManifestError> {
    match v {
        Value::Text(s) => Ok(s),
        _ => Err(ManifestError::NonTextKey),
    }
}

fn take_text(v: Value, field: &'static str) -> Result<String, ManifestError> {
    match v {
        Value::Text(s) => Ok(s),
        _ => Err(ManifestError::WrongType {
            field,
            expected: "text string",
        }),
    }
}

fn take_fixed_bytes<const N: usize>(
    v: Value,
    field: &'static str,
) -> Result<[u8; N], ManifestError> {
    let bytes = match v {
        Value::Bytes(b) => b,
        _ => {
            return Err(ManifestError::WrongType {
                field,
                expected: "byte string",
            })
        }
    };
    let length = bytes.len();
    bytes
        .try_into()
        .map_err(|_: Vec<u8>| ManifestError::InvalidByteLength {
            field,
            expected: N,
            length,
        })
}

fn take_u8(v: Value, field: &'static str) -> Result<u8, ManifestError> {
    let i = take_integer_i128(v, field)?;
    if !(0..=u8::MAX as i128).contains(&i) {
        return Err(ManifestError::IntegerOutOfRange { field, value: i });
    }
    Ok(i as u8)
}

fn take_u16(v: Value, field: &'static str) -> Result<u16, ManifestError> {
    let i = take_integer_i128(v, field)?;
    if !(0..=u16::MAX as i128).contains(&i) {
        return Err(ManifestError::IntegerOutOfRange { field, value: i });
    }
    Ok(i as u16)
}

fn take_u32(v: Value, field: &'static str) -> Result<u32, ManifestError> {
    let i = take_integer_i128(v, field)?;
    if !(0..=u32::MAX as i128).contains(&i) {
        return Err(ManifestError::IntegerOutOfRange { field, value: i });
    }
    Ok(i as u32)
}

fn take_u64(v: Value, field: &'static str) -> Result<u64, ManifestError> {
    let i = take_integer_i128(v, field)?;
    if !(0..=u64::MAX as i128).contains(&i) {
        return Err(ManifestError::IntegerOutOfRange { field, value: i });
    }
    Ok(i as u64)
}

/// Decode a CBOR integer as i128 so all of [u8 .. u64] fit a single
/// accessor. `ciborium::value::Integer` → `i128` is infallible.
fn take_integer_i128(v: Value, field: &'static str) -> Result<i128, ManifestError> {
    match v {
        Value::Integer(i) => Ok(i128::from(i)),
        _ => Err(ManifestError::WrongType {
            field,
            expected: "unsigned integer",
        }),
    }
}

/// Wrap a raw `Value` (from an unknown top-level / per-entry key) into
/// an [`UnknownValue`] for round-trip preservation. We re-encode and
/// re-decode through `UnknownValue::from_canonical_cbor` so any future
/// tightening of the unknown-value invariant fires here too.
fn value_to_unknown(v: Value) -> Result<UnknownValue, ManifestError> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&v, &mut buf)
        .map_err(|e| ManifestError::CborEncode(e.to_string()))?;
    UnknownValue::from_canonical_cbor(&buf)
        .map_err(|e| ManifestError::CborDecode(e.to_string()))
}

// ---------------------------------------------------------------------------
// Binary header (§4.1) + AEAD body wiring
// ---------------------------------------------------------------------------

/// Wire-form byte length of the manifest binary header (`docs/vault-format.md`
/// §4.1): `magic`(4) + `format_version`(2) + `suite_id`(2) + `file_kind`(2)
/// + `vault_uuid`(16) + `created_at_ms`(8) + `last_mod_ms`(8) = 42 bytes.
///
/// These 42 bytes are bound into the AEAD as Additional Authenticated Data
/// — the §4.1 cross-file-kind anti-substitution property — so any bit-flip
/// inside the header invalidates the Poly1305 tag on decrypt.
pub const MANIFEST_HEADER_LEN: usize = 4 + 2 + 2 + 2 + 16 + 8 + 8;

const _: () = {
    // Spec-conformance assertion: §4.1 fixes the manifest header at 42
    // bytes from `magic` through `last_mod_ms` inclusive. Any future
    // re-shuffle of constituent field widths must also update §4.1 of
    // the spec; this compile-time check makes the contract explicit.
    assert!(MANIFEST_HEADER_LEN == 42);
};

/// Manifest binary header (`docs/vault-format.md` §4.1).
///
/// The 42-byte prefix that sits in front of the AEAD nonce + ciphertext.
/// `magic`, `format_version`, `suite_id`, and `file_kind` are constants
/// pinned by the v1 cipher suite — callers don't pass them; [`encode`](Self::encode)
/// emits them and [`decode`](Self::decode) verifies them. Bound into the
/// AEAD as AAD so a tampered header invalidates the tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestHeader {
    pub vault_uuid: [u8; UUID_LEN],
    pub created_at_ms: u64,
    pub last_mod_ms: u64,
}

impl ManifestHeader {
    /// Encode the 42-byte header. Constant fields (magic, format_version,
    /// suite_id, file_kind) are emitted from [`crate::version`] sentinels
    /// — callers don't get to override them.
    ///
    /// Returns a fixed-size array rather than a `Vec` so the AEAD AAD
    /// length is statically obvious at the call site (and so the result
    /// can be passed directly as a `&[u8]` slice).
    pub fn encode(&self) -> [u8; MANIFEST_HEADER_LEN] {
        let mut out = [0u8; MANIFEST_HEADER_LEN];
        let mut pos = 0;
        out[pos..pos + 4].copy_from_slice(&MAGIC.to_be_bytes());
        pos += 4;
        out[pos..pos + 2].copy_from_slice(&FORMAT_VERSION.to_be_bytes());
        pos += 2;
        out[pos..pos + 2].copy_from_slice(&SUITE_ID.to_be_bytes());
        pos += 2;
        out[pos..pos + 2].copy_from_slice(&FILE_KIND_MANIFEST.to_be_bytes());
        pos += 2;
        out[pos..pos + UUID_LEN].copy_from_slice(&self.vault_uuid);
        pos += UUID_LEN;
        out[pos..pos + 8].copy_from_slice(&self.created_at_ms.to_be_bytes());
        pos += 8;
        out[pos..pos + 8].copy_from_slice(&self.last_mod_ms.to_be_bytes());
        pos += 8;
        debug_assert_eq!(pos, MANIFEST_HEADER_LEN);
        out
    }

    /// Decode the 42-byte header. Returns the parsed [`ManifestHeader`]
    /// alongside the trailing byte slice (so a caller mid-parse of the
    /// surrounding §4.1 envelope — which Task 7's `ManifestFile` will be —
    /// can keep parsing the AEAD section).
    ///
    /// Validates:
    ///
    /// 1. Sufficient input length ([`ManifestError::HeaderTruncated`]).
    /// 2. `magic == MAGIC` ([`ManifestError::BadMagic`]).
    /// 3. `format_version == FORMAT_VERSION`
    ///    ([`ManifestError::UnsupportedFormatVersion`]).
    /// 4. `suite_id == SUITE_ID` ([`ManifestError::UnsupportedSuiteId`]).
    /// 5. `file_kind == FILE_KIND_MANIFEST`
    ///    ([`ManifestError::UnsupportedFileKind`]) — the §4.1
    ///    cross-file-kind protection.
    ///
    /// `created_at_ms` and `last_mod_ms` are read verbatim — temporal
    /// invariants (e.g. `created_at_ms <= last_mod_ms`) are not policed
    /// at this layer; the manifest body and orchestrator layers handle
    /// rollback and freshness checks (Task 8 onward).
    pub fn decode(bytes: &[u8]) -> Result<(ManifestHeader, &[u8]), ManifestError> {
        if bytes.len() < MANIFEST_HEADER_LEN {
            return Err(ManifestError::HeaderTruncated {
                need: MANIFEST_HEADER_LEN,
                got: bytes.len(),
            });
        }
        let mut pos = 0;

        let magic = u32::from_be_bytes(slice_array::<4>(bytes, &mut pos));
        if magic != MAGIC {
            return Err(ManifestError::BadMagic {
                expected: MAGIC,
                got: magic,
            });
        }
        let format_version = u16::from_be_bytes(slice_array::<2>(bytes, &mut pos));
        if format_version != FORMAT_VERSION {
            return Err(ManifestError::UnsupportedFormatVersion(format_version));
        }
        let suite_id = u16::from_be_bytes(slice_array::<2>(bytes, &mut pos));
        if suite_id != SUITE_ID {
            return Err(ManifestError::UnsupportedSuiteId(suite_id));
        }
        let file_kind = u16::from_be_bytes(slice_array::<2>(bytes, &mut pos));
        if file_kind != FILE_KIND_MANIFEST {
            return Err(ManifestError::UnsupportedFileKind {
                expected: FILE_KIND_MANIFEST,
                got: file_kind,
            });
        }
        let vault_uuid = slice_array::<UUID_LEN>(bytes, &mut pos);
        let created_at_ms = u64::from_be_bytes(slice_array::<8>(bytes, &mut pos));
        let last_mod_ms = u64::from_be_bytes(slice_array::<8>(bytes, &mut pos));
        debug_assert_eq!(pos, MANIFEST_HEADER_LEN);

        Ok((
            ManifestHeader {
                vault_uuid,
                created_at_ms,
                last_mod_ms,
            },
            &bytes[MANIFEST_HEADER_LEN..],
        ))
    }
}

/// Read a fixed-size byte chunk out of `bytes`, advancing `pos`. The
/// caller has already length-checked the input, so this helper takes
/// ownership of that invariant — a panic here is a bug in the caller.
/// Mirrors block.rs's `read_array` style minus the truncation check
/// (we hoist it once at the top of [`ManifestHeader::decode`] since the
/// header is a fixed 42 bytes, not variable-length like a block header).
fn slice_array<const N: usize>(bytes: &[u8], pos: &mut usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[*pos..*pos + N]);
    *pos += N;
    out
}

/// AEAD-encrypt a canonical-CBOR-encoded manifest body under `ibk` with
/// `nonce`, binding `header.encode()` into the AAD per §4.1.
///
/// Returns `aead_ct || aead_tag` — the concatenation that the §4.1
/// envelope places between `aead_nonce` and the (Task 7) signature
/// suffix. The tag length is [`crate::crypto::aead::AEAD_TAG_LEN`] (16
/// bytes); the ciphertext length matches `manifest_bytes.len()`.
///
/// `manifest_bytes` is the output of [`encode_manifest`]; callers that
/// haven't encoded yet should pipe through that function first. We don't
/// take a `&Manifest` directly because callers occasionally already have
/// the canonical bytes in hand (e.g. cached on a previous read).
pub fn encrypt_manifest_body(
    header: &ManifestHeader,
    manifest_bytes: &[u8],
    ibk: &AeadKey,
    nonce: &AeadNonce,
) -> Result<Vec<u8>, ManifestError> {
    let aad = header.encode();
    aead::encrypt(ibk, nonce, &aad, manifest_bytes).map_err(|_| ManifestError::AeadFailure)
}

/// AEAD-decrypt a manifest body. `ct_with_tag` is the concatenation of
/// `aead_ct` (length declared upstream by the §4.1 envelope's
/// `aead_ct_len` field — Task 7 territory) and `aead_tag`. AAD is
/// `header.encode()`.
///
/// On AEAD success, parses the recovered plaintext via [`decode_manifest`]
/// and returns the [`Manifest`]. AEAD failure (wrong key, wrong nonce,
/// tampered header, tampered ciphertext) collapses to a single
/// [`ManifestError::AeadFailure`] per the AEAD security model
/// — distinguishing causes would leak information to a probing attacker.
pub fn decrypt_manifest_body(
    header: &ManifestHeader,
    ct_with_tag: &[u8],
    ibk: &AeadKey,
    nonce: &AeadNonce,
) -> Result<Manifest, ManifestError> {
    let aad = header.encode();
    let plaintext = aead::decrypt(ibk, nonce, &aad, ct_with_tag)
        .map_err(|_| ManifestError::AeadFailure)?;
    decode_manifest(plaintext.expose())
}

// ---------------------------------------------------------------------------
// ManifestFile — full §4.1 envelope (header + AEAD section + sig suffix)
// ---------------------------------------------------------------------------

const _: () = {
    // Spec-conformance assertion: §4.1 / §14 pin the Ed25519 signature
    // length at 64 bytes; the wire `sig_ed_len` field declares the same
    // value. Mirrors block.rs's compile-time guard.
    assert!(ED25519_SIG_LEN == 64);
};

const _: () = {
    // Spec-conformance assertion: §4.1 / §14 pin the ML-DSA-65 signature
    // length at 3309 bytes under suite v1 (`secretary-v1-pq-hybrid`).
    assert!(ML_DSA_65_SIG_LEN == 3309);
};

/// 16-byte fingerprint length: matches [`Fingerprint`]'s underlying
/// type alias. Pinned here so the §4.1 envelope size arithmetic is
/// self-evident at the call site.
const FINGERPRINT_LEN_BYTES: usize = 16;

/// The complete manifest file as it sits on disk: header (§4.1, 42
/// bytes) + AEAD section (24-byte nonce + 4-byte ct-len + variable ct
/// + 16-byte tag) + signature suffix (16-byte author fingerprint +
///   length-prefixed Ed25519 sig + length-prefixed ML-DSA-65 sig).
///
/// [`Manifest`] is the *opened* (decrypted) body that lives inside
/// `aead_ct`; `ManifestFile` is the on-disk envelope. They are
/// intentionally distinct types: a [`ManifestFile`] never holds
/// plaintext, and [`sign_manifest`] / [`verify_manifest`] +
/// [`decrypt_manifest_body`] are the only conversion paths between the
/// two. Same discipline as [`super::block::BlockFile`] vs
/// [`super::block::BlockPlaintext`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestFile {
    /// Binary header (§4.1, 42 bytes from `magic` through `last_mod_ms`).
    pub header: ManifestHeader,
    /// 24-byte XChaCha20 nonce for the body AEAD.
    pub aead_nonce: [u8; 24],
    /// AEAD ciphertext of the canonical-CBOR manifest body (§4.2),
    /// *without* the trailing 16-byte Poly1305 tag. The tag is held
    /// separately because §4.1 splits them on the wire (`aead_ct` is
    /// variable-length, `aead_tag` is a fixed 16-byte field).
    pub aead_ct: Vec<u8>,
    /// 16-byte Poly1305 authentication tag for the body AEAD.
    pub aead_tag: [u8; AEAD_TAG_LEN],
    /// 16-byte fingerprint of the manifest author's contact card
    /// (§4.1). For the single-user vault case this is the owner's
    /// fingerprint.
    pub author_fingerprint: Fingerprint,
    /// Ed25519 half of the §8 hybrid signature, 64 bytes.
    pub sig_ed: Ed25519Sig,
    /// ML-DSA-65 half of the §8 hybrid signature, 3309 bytes (suite v1).
    pub sig_pq: MlDsa65Sig,
}

/// Build the bytes the §4.1 hybrid signature commits to: header(42) ||
/// aead_nonce(24) || aead_ct_len(4 BE) || aead_ct(var) || aead_tag(16).
///
/// This is the bytes-from-`magic`-through-`aead_tag`-inclusive range.
/// The role-tag prefix `"secretary-v1-manifest-sig"` is added by
/// [`crate::crypto::sig::sign`] / [`crate::crypto::sig::verify`] via
/// [`SigRole::Manifest`] — DO NOT prepend it here, or both halves of
/// the hybrid signature would double-tag and round-trip verify would
/// break. Same discipline as [`super::block::signed_message_bytes`].
///
/// Takes the four signed-range fields directly (rather than a
/// `&ManifestFile`) so `sign_manifest` doesn't need to fabricate a
/// zero-filled placeholder `ManifestFile` to compute the pre-image. A
/// future refactor adding new fields to `ManifestFile` cannot
/// accidentally extend the signed range without updating this
/// function's signature — the compiler enforces the invariant.
fn signed_message_bytes(
    header: &ManifestHeader,
    aead_nonce: &[u8; 24],
    aead_ct: &[u8],
    aead_tag: &[u8; AEAD_TAG_LEN],
) -> Result<Vec<u8>, ManifestError> {
    let header_bytes = header.encode();
    let ct_len_u32 = u32::try_from(aead_ct.len()).map_err(|_| {
        // u32 overflow on aead_ct.len() is a degenerate case: a single
        // manifest body would have to exceed 4 GiB. Surface it as the
        // declared/remaining mismatch rather than inventing a fresh
        // variant — the resulting envelope would be unparseable anyway.
        ManifestError::AeadCtLenMismatch {
            declared: u32::MAX,
            remaining: aead_ct.len(),
        }
    })?;
    let mut out =
        Vec::with_capacity(MANIFEST_HEADER_LEN + 24 + 4 + aead_ct.len() + AEAD_TAG_LEN);
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(aead_nonce);
    out.extend_from_slice(&ct_len_u32.to_be_bytes());
    out.extend_from_slice(aead_ct);
    out.extend_from_slice(aead_tag);
    Ok(out)
}

/// Encode a complete [`ManifestFile`] to its §4.1 wire form: header
/// (42) || aead_nonce (24) || aead_ct_len (u32 BE = 4) || aead_ct
/// (var) || aead_tag (16) || author_fingerprint (16) || sig_ed_len
/// (u16 BE = 2) || sig_ed (64) || sig_pq_len (u16 BE = 2) || sig_pq
/// (3309 in suite v1).
///
/// Length-prefix fields (`aead_ct_len`, `sig_ed_len`, `sig_pq_len`)
/// are written from the corresponding field's actual length; encode-
/// time validation ensures the lengths fit their declared widths and
/// match the suite-v1 fixed sizes. A `sig_ed` whose alias has shifted
/// shape (defensive — the type is pinned `[u8; 64]`), or a `sig_pq`
/// whose suite version mismatches the wire format, surfaces as a
/// typed [`ManifestError::SigEdWrongLength`] /
/// [`ManifestError::SigPqWrongLength`] before any bytes are written.
pub fn encode_manifest_file(file: &ManifestFile) -> Result<Vec<u8>, ManifestError> {
    // Defensive length checks. `sig_ed: Ed25519Sig` is a `[u8; 64]`
    // alias so the first check cannot fire today, but pinning it here
    // matches the §4.1 wire contract and protects against a future
    // alias change. `sig_pq: MlDsa65Sig` is constructed via
    // `MlDsa65Sig::from_bytes` which already pins the length, so the
    // second check is also defensive. Both stay for symmetry with the
    // decode path's strict validation.
    if file.sig_ed.len() != ED25519_SIG_LEN {
        return Err(ManifestError::SigEdWrongLength {
            expected: ED25519_SIG_LEN as u16,
            got: file.sig_ed.len() as u16,
        });
    }
    if file.sig_pq.as_bytes().len() != ML_DSA_65_SIG_LEN {
        return Err(ManifestError::SigPqWrongLength {
            expected: ML_DSA_65_SIG_LEN as u16,
            got: file.sig_pq.as_bytes().len() as u16,
        });
    }
    let ct_len_u32 = u32::try_from(file.aead_ct.len()).map_err(|_| {
        ManifestError::AeadCtLenMismatch {
            declared: u32::MAX,
            remaining: file.aead_ct.len(),
        }
    })?;

    let header_bytes = file.header.encode();
    let sig_pq_bytes = file.sig_pq.as_bytes();
    let total = MANIFEST_HEADER_LEN
        + 24
        + 4
        + file.aead_ct.len()
        + AEAD_TAG_LEN
        + FINGERPRINT_LEN_BYTES
        + 2
        + ED25519_SIG_LEN
        + 2
        + sig_pq_bytes.len();
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&file.aead_nonce);
    out.extend_from_slice(&ct_len_u32.to_be_bytes());
    out.extend_from_slice(&file.aead_ct);
    out.extend_from_slice(&file.aead_tag);
    out.extend_from_slice(&file.author_fingerprint);
    out.extend_from_slice(&(ED25519_SIG_LEN as u16).to_be_bytes());
    out.extend_from_slice(&file.sig_ed);
    out.extend_from_slice(&(sig_pq_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(sig_pq_bytes);
    debug_assert_eq!(out.len(), total);
    Ok(out)
}

/// Decode a complete [`ManifestFile`] from `bytes`. Strict on lengths:
/// every section has a typed truncation diagnostic that pinpoints
/// which §4.1 field is short. Trailing bytes after `sig_pq` are
/// rejected with [`ManifestError::TrailingBytes`].
///
/// Validates:
///
/// 1. Header (42 bytes) via [`ManifestHeader::decode`] — magic,
///    format_version, suite_id, file_kind.
/// 2. Sufficient input for `aead_nonce` (24), `aead_ct_len` (4),
///    `aead_ct` (declared), `aead_tag` (16), `author_fingerprint` (16),
///    `sig_ed_len` (2), `sig_ed` (64), `sig_pq_len` (2), and `sig_pq`
///    (3309 in suite v1) — each surfaces as
///    [`ManifestError::SectionTruncated`] with a section-specific name.
/// 3. `aead_ct_len` matches the bytes available between the length
///    prefix and the trailing signature suffix (after subtracting the
///    fixed 16-byte AEAD tag and the trailing fixed-size suffix);
///    surfaces as [`ManifestError::AeadCtLenMismatch`] when the wire
///    declares a length the envelope cannot satisfy.
/// 4. `sig_ed_len == 64` and `sig_pq_len == 3309` —
///    [`ManifestError::SigEdWrongLength`] / [`ManifestError::SigPqWrongLength`].
/// 5. No bytes remain after `sig_pq` —
///    [`ManifestError::TrailingBytes`].
///
/// Does NOT decrypt the AEAD body and does NOT verify the hybrid
/// signature. Those are separate concerns: an orchestrator sequences
/// `decode_manifest_file` → `verify_manifest` → `decrypt_manifest_body`.
pub fn decode_manifest_file(bytes: &[u8]) -> Result<ManifestFile, ManifestError> {
    // Step 1: header (42 bytes). Returns the trailing slice for the
    // AEAD section to pick up from.
    let (header, rest) = ManifestHeader::decode(bytes)?;

    let mut pos = 0usize;

    // Step 2: aead_nonce (24).
    if rest.len().saturating_sub(pos) < 24 {
        return Err(ManifestError::SectionTruncated {
            section: "aead_nonce",
            need: 24,
            got: rest.len().saturating_sub(pos),
        });
    }
    let mut aead_nonce = [0u8; 24];
    aead_nonce.copy_from_slice(&rest[pos..pos + 24]);
    pos += 24;

    // Step 3: aead_ct_len (u32 BE).
    if rest.len().saturating_sub(pos) < 4 {
        return Err(ManifestError::SectionTruncated {
            section: "aead_ct_len",
            need: 4,
            got: rest.len().saturating_sub(pos),
        });
    }
    let mut len_buf = [0u8; 4];
    len_buf.copy_from_slice(&rest[pos..pos + 4]);
    pos += 4;
    let declared_ct_len = u32::from_be_bytes(len_buf);
    let declared_ct_len_usize = declared_ct_len as usize;

    // Step 4: We must reserve room for aead_tag(16), author_fingerprint(16),
    // sig_ed_len(2), sig_ed(64), sig_pq_len(2), sig_pq(ML_DSA_65_SIG_LEN=3309).
    // The "remaining" expected after the ct_len prefix is:
    //   declared_ct_len + 16 (tag) + 16 (fp) + 2 (sig_ed_len) + 64 (sig_ed)
    //                  + 2 (sig_pq_len) + 3309 (sig_pq)
    // If the declared aead_ct_len asks for more bytes than are present
    // (after subtracting the fixed-size suffix), surface the typed
    // mismatch rather than waiting for a downstream truncation.
    let fixed_suffix_after_ct = AEAD_TAG_LEN
        + FINGERPRINT_LEN_BYTES
        + 2
        + ED25519_SIG_LEN
        + 2
        + ML_DSA_65_SIG_LEN;
    let remaining_after_len_prefix = rest.len().saturating_sub(pos);
    if remaining_after_len_prefix < fixed_suffix_after_ct {
        // We don't even have enough bytes for the fixed-size tail; report
        // truncation at the aead_ct boundary because that's the first
        // section to overflow available bytes.
        return Err(ManifestError::SectionTruncated {
            section: "aead_ct",
            need: declared_ct_len_usize + fixed_suffix_after_ct,
            got: remaining_after_len_prefix,
        });
    }
    let max_possible_ct_len = remaining_after_len_prefix - fixed_suffix_after_ct;
    if declared_ct_len_usize > max_possible_ct_len {
        return Err(ManifestError::AeadCtLenMismatch {
            declared: declared_ct_len,
            remaining: max_possible_ct_len,
        });
    }

    // Step 5: aead_ct (declared length).
    let aead_ct = rest[pos..pos + declared_ct_len_usize].to_vec();
    pos += declared_ct_len_usize;

    // Step 6: aead_tag (16). Length already reserved above.
    let mut aead_tag = [0u8; AEAD_TAG_LEN];
    aead_tag.copy_from_slice(&rest[pos..pos + AEAD_TAG_LEN]);
    pos += AEAD_TAG_LEN;

    // Step 7: author_fingerprint (16).
    let mut author_fingerprint = [0u8; FINGERPRINT_LEN_BYTES];
    author_fingerprint.copy_from_slice(&rest[pos..pos + FINGERPRINT_LEN_BYTES]);
    pos += FINGERPRINT_LEN_BYTES;

    // Step 8: sig_ed_len (u16 BE).
    let mut sig_ed_len_buf = [0u8; 2];
    sig_ed_len_buf.copy_from_slice(&rest[pos..pos + 2]);
    pos += 2;
    let sig_ed_len = u16::from_be_bytes(sig_ed_len_buf);
    if sig_ed_len as usize != ED25519_SIG_LEN {
        return Err(ManifestError::SigEdWrongLength {
            expected: ED25519_SIG_LEN as u16,
            got: sig_ed_len,
        });
    }

    // Step 9: sig_ed (64). Length already reserved above.
    let mut sig_ed: Ed25519Sig = [0u8; ED25519_SIG_LEN];
    sig_ed.copy_from_slice(&rest[pos..pos + ED25519_SIG_LEN]);
    pos += ED25519_SIG_LEN;

    // Step 10: sig_pq_len (u16 BE).
    let mut sig_pq_len_buf = [0u8; 2];
    sig_pq_len_buf.copy_from_slice(&rest[pos..pos + 2]);
    pos += 2;
    let sig_pq_len = u16::from_be_bytes(sig_pq_len_buf);
    if sig_pq_len as usize != ML_DSA_65_SIG_LEN {
        return Err(ManifestError::SigPqWrongLength {
            expected: ML_DSA_65_SIG_LEN as u16,
            got: sig_pq_len,
        });
    }

    // Step 11: sig_pq. Length already reserved.
    let sig_pq_bytes = rest[pos..pos + ML_DSA_65_SIG_LEN].to_vec();
    pos += ML_DSA_65_SIG_LEN;

    // MlDsa65Sig::from_bytes hard-pins length at ML_DSA_65_SIG_LEN; the
    // wire-format check above makes this defensive (cannot fire today)
    // but it stays as the construction path for the typed wrapper.
    let sig_pq = MlDsa65Sig::from_bytes(&sig_pq_bytes).map_err(|e| match e {
        SigError::InvalidSignatureLength => ManifestError::SigPqWrongLength {
            expected: ML_DSA_65_SIG_LEN as u16,
            got: sig_pq_bytes.len() as u16,
        },
        // Other SigError variants do not fire on this path; lift
        // defensively into the closest equivalent.
        other => ManifestError::SignInternal(other),
    })?;

    // Step 12: trailing-bytes check.
    if pos != rest.len() {
        return Err(ManifestError::TrailingBytes(rest.len() - pos));
    }

    Ok(ManifestFile {
        header,
        aead_nonce,
        aead_ct,
        aead_tag,
        author_fingerprint,
        sig_ed,
        sig_pq,
    })
}

/// Build a complete on-disk [`ManifestFile`] from `header`, plaintext
/// `body`, and signing keys. Steps mirror §4.1 / §8 step 6:
///
/// 1. Canonical-CBOR-encode `body` (§4.2).
/// 2. AEAD-encrypt under `ibk` with `nonce` and `header.encode()` AAD,
///    yielding `ct || tag`. Split into `aead_ct` (variable) and
///    `aead_tag` (16 bytes).
/// 3. Hybrid-sign the bytes from `magic` through `aead_tag` inclusive
///    via [`crate::crypto::sig::sign`] with [`SigRole::Manifest`]. The
///    role tag `"secretary-v1-manifest-sig"` is prepended *internally*
///    by [`crate::crypto::sig::sign`] — DO NOT prepend it here.
///
/// Returns the populated [`ManifestFile`]. Encoding it to the wire
/// form is the caller's job ([`encode_manifest_file`]).
pub fn sign_manifest(
    header: ManifestHeader,
    body: &Manifest,
    ibk: &AeadKey,
    nonce: &AeadNonce,
    author: Fingerprint,
    sk_ed: &Ed25519Secret,
    sk_pq: &MlDsa65Secret,
) -> Result<ManifestFile, ManifestError> {
    // Step 1: encode the manifest body to canonical CBOR.
    let body_bytes = encode_manifest(body)?;

    // Step 2: AEAD-encrypt with header AAD.
    let ct_with_tag = encrypt_manifest_body(&header, &body_bytes, ibk, nonce)?;
    debug_assert_eq!(ct_with_tag.len(), body_bytes.len() + AEAD_TAG_LEN);

    // Split (ct || tag) into aead_ct (variable) and aead_tag (16).
    let split_at = ct_with_tag.len() - AEAD_TAG_LEN;
    let aead_ct = ct_with_tag[..split_at].to_vec();
    let mut aead_tag = [0u8; AEAD_TAG_LEN];
    aead_tag.copy_from_slice(&ct_with_tag[split_at..]);

    // Step 3: compute the signed-range bytes from raw parts (no
    // placeholder ManifestFile dance), sign, and assemble the final
    // ManifestFile in one shot.
    let m = signed_message_bytes(&header, nonce, &aead_ct, &aead_tag)?;
    let hybrid =
        sig::sign(SigRole::Manifest, &m, sk_ed, sk_pq).map_err(ManifestError::SignInternal)?;
    Ok(ManifestFile {
        header,
        aead_nonce: *nonce,
        aead_ct,
        aead_tag,
        author_fingerprint: author,
        sig_ed: hybrid.sig_ed,
        sig_pq: hybrid.sig_pq,
    })
}

/// Verify the §8 hybrid signature on a complete [`ManifestFile`].
/// Does NOT decrypt the AEAD body — that's a separate concern via
/// [`decrypt_manifest_body`]. Position-specific error variants
/// distinguish "Ed25519 half rejected" from "ML-DSA-65 half rejected"
/// (see [`ManifestError::Ed25519SignatureInvalid`] /
/// [`ManifestError::MlDsa65SignatureInvalid`]); other failures (wrong
/// key length, etc.) surface as [`ManifestError::SignInternal`].
///
/// The role tag `"secretary-v1-manifest-sig"` is prepended internally
/// by [`crate::crypto::sig::verify`] — DO NOT prepend it here.
pub fn verify_manifest(
    file: &ManifestFile,
    pk_ed: &Ed25519Public,
    pk_pq: &MlDsa65Public,
) -> Result<(), ManifestError> {
    let m = signed_message_bytes(&file.header, &file.aead_nonce, &file.aead_ct, &file.aead_tag)?;
    let hybrid = HybridSig {
        sig_ed: file.sig_ed,
        sig_pq: file.sig_pq.clone(),
    };
    sig::verify(SigRole::Manifest, &m, &hybrid, pk_ed, pk_pq).map_err(|e| match e {
        SigError::Ed25519VerifyFailed => ManifestError::Ed25519SignatureInvalid,
        SigError::MlDsa65VerifyFailed => ManifestError::MlDsa65SignatureInvalid,
        other => ManifestError::SignInternal(other),
    })
}

// ---------------------------------------------------------------------------
// §10 — Rollback resistance
// ---------------------------------------------------------------------------

/// Returns `true` iff `incoming` is *strictly dominated by* `local`,
/// per `docs/crypto-design.md` §10 ("Vector-clock rollback resistance").
///
/// Both inputs are interpreted as logical maps from `device_uuid` to
/// `counter`, regardless of slice order. Devices missing from a slice
/// are treated as having counter 0 — a device that has never bumped its
/// clock is indistinguishable from a device that is absent.
///
/// Decision rules (caller is the OS-keystore-backed orchestrator that
/// holds the per-vault "highest-seen" clock):
///
/// - **Equal** clocks → NOT a rollback. Returns `false`.
/// - **`incoming` dominates** (every counter ≥ local, at least one
///   strictly more — or `incoming` introduces a device with counter > 0
///   that `local` does not have) → NOT a rollback. Caller accepts and
///   updates highest-seen. Returns `false`.
/// - **`incoming` strictly dominated** (every counter ≤ local, at least
///   one strictly less — or `local` carries a device at counter > 0 that
///   `incoming` lacks) → rollback. Returns `true`.
/// - **Concurrent** (some incoming counters strictly higher, some
///   strictly lower) → NOT a rollback per se. Returns `false`. Caller
///   triggers merge (PR-C territory; not implemented here).
///
/// Duplicate device UUIDs in either input are NOT detected here —
/// callers must reject them earlier. [`decode_manifest`] (§4.2's
/// `vector_clock` array sort discipline) already does this on the
/// incoming side.
///
/// PR-C will replace this boolean with a richer `ClockRelation` enum
/// (Equal / IncomingDominates / IncomingDominated / Concurrent); for
/// PR-B the reject-on-rollback predicate is the only consumer.
pub fn is_rollback(local: &[VectorClockEntry], incoming: &[VectorClockEntry]) -> bool {
    // Build maps so we can compare component-wise regardless of slice
    // order. Use BTreeMap for deterministic union iteration (test
    // diagnostics stay reproducible) and to side-step any hash-DoS
    // concerns at zero perf cost on these tiny inputs.
    let local_map: BTreeMap<[u8; 16], u64> = local
        .iter()
        .map(|e| (e.device_uuid, e.counter))
        .collect();
    let incoming_map: BTreeMap<[u8; 16], u64> = incoming
        .iter()
        .map(|e| (e.device_uuid, e.counter))
        .collect();

    let mut any_strictly_less = false;
    let mut any_strictly_more = false;

    // Iterate the union of device UUIDs, treating "absent" as counter 0.
    for uuid in local_map.keys().chain(incoming_map.keys()) {
        let l = local_map.get(uuid).copied().unwrap_or(0);
        let i = incoming_map.get(uuid).copied().unwrap_or(0);
        match i.cmp(&l) {
            std::cmp::Ordering::Less => any_strictly_less = true,
            std::cmp::Ordering::Greater => any_strictly_more = true,
            std::cmp::Ordering::Equal => {}
        }
    }

    any_strictly_less && !any_strictly_more
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use crate::crypto::secret::Sensitive;

    fn dummy_kdf_params() -> KdfParamsRef {
        KdfParamsRef {
            memory_kib: 262_144,
            iterations: 3,
            parallelism: 1,
            salt: [0x11; SALT_LEN],
        }
    }

    fn minimal_manifest() -> Manifest {
        Manifest {
            manifest_version: MANIFEST_VERSION_V1,
            vault_uuid: [0x01; UUID_LEN],
            format_version: FORMAT_VERSION_V1,
            suite_id: SUITE_ID_V1,
            owner_user_uuid: [0x02; UUID_LEN],
            vector_clock: Vec::new(),
            blocks: Vec::new(),
            trash: Vec::new(),
            kdf_params: dummy_kdf_params(),
            unknown: BTreeMap::new(),
        }
    }

    fn populated_manifest() -> Manifest {
        let vc = vec![
            VectorClockEntry {
                device_uuid: [0xaa; UUID_LEN],
                counter: 7,
            },
            VectorClockEntry {
                device_uuid: [0x55; UUID_LEN],
                counter: 3,
            },
        ];
        let block_a = BlockEntry {
            block_uuid: [0xb1; UUID_LEN],
            block_name: "logins".to_string(),
            fingerprint: [0xff; FINGERPRINT_LEN],
            recipients: vec![[0xc1; UUID_LEN], [0xc2; UUID_LEN]],
            vector_clock_summary: vec![
                VectorClockEntry {
                    device_uuid: [0xaa; UUID_LEN],
                    counter: 4,
                },
                VectorClockEntry {
                    device_uuid: [0x55; UUID_LEN],
                    counter: 2,
                },
            ],
            suite_id: SUITE_ID_V1,
            created_at_ms: 1_714_060_800_000,
            last_mod_ms: 1_714_060_800_010,
            unknown: BTreeMap::new(),
        };
        let block_b = BlockEntry {
            block_uuid: [0xa2; UUID_LEN],
            block_name: "notes".to_string(),
            fingerprint: [0xee; FINGERPRINT_LEN],
            recipients: vec![[0xc1; UUID_LEN], [0xc3; UUID_LEN]],
            vector_clock_summary: vec![
                VectorClockEntry {
                    device_uuid: [0x55; UUID_LEN],
                    counter: 1,
                },
                VectorClockEntry {
                    device_uuid: [0xaa; UUID_LEN],
                    counter: 5,
                },
            ],
            suite_id: SUITE_ID_V1,
            created_at_ms: 1_714_060_800_001,
            last_mod_ms: 1_714_060_800_011,
            unknown: BTreeMap::new(),
        };
        let trash = vec![TrashEntry {
            block_uuid: [0xde; UUID_LEN],
            tombstoned_at_ms: 1_714_060_900_000,
            tombstoned_by: [0xaa; UUID_LEN],
            unknown: BTreeMap::new(),
        }];
        Manifest {
            manifest_version: MANIFEST_VERSION_V1,
            vault_uuid: [0x42; UUID_LEN],
            format_version: FORMAT_VERSION_V1,
            suite_id: SUITE_ID_V1,
            owner_user_uuid: [0x99; UUID_LEN],
            vector_clock: vc,
            blocks: vec![block_a, block_b],
            trash,
            kdf_params: KdfParamsRef {
                memory_kib: 524_288,
                iterations: 4,
                parallelism: 2,
                salt: [0x22; SALT_LEN],
            },
            unknown: BTreeMap::new(),
        }
    }

    // ---- Round-trip ------------------------------------------------------

    #[test]
    fn roundtrip_minimal_manifest() {
        let m = minimal_manifest();
        let bytes = encode_manifest(&m).expect("encode minimal");
        let parsed = decode_manifest(&bytes).expect("decode minimal");
        assert_eq!(parsed, m);
        let bytes_again = encode_manifest(&parsed).expect("re-encode minimal");
        assert_eq!(bytes, bytes_again, "encode is deterministic");
    }

    #[test]
    fn roundtrip_populated_manifest() {
        let m = populated_manifest();
        let bytes = encode_manifest(&m).expect("encode populated");
        let parsed = decode_manifest(&bytes).expect("decode populated");
        // We can't compare `parsed == m` directly because the input
        // vector_clock and recipients arrays were built in non-canonical
        // order. After encode-then-decode they come back sorted. So we
        // sort `m`'s arrays the same way before comparing.
        let mut m_sorted = m.clone();
        m_sorted
            .vector_clock
            .sort_by(|a, b| a.device_uuid.cmp(&b.device_uuid));
        m_sorted.blocks.sort_by(|a, b| a.block_uuid.cmp(&b.block_uuid));
        for blk in &mut m_sorted.blocks {
            blk.recipients.sort();
            blk.vector_clock_summary
                .sort_by(|a, b| a.device_uuid.cmp(&b.device_uuid));
        }
        m_sorted.trash.sort_by(|a, b| a.block_uuid.cmp(&b.block_uuid));
        assert_eq!(parsed, m_sorted);

        let bytes_again = encode_manifest(&parsed).expect("re-encode populated");
        assert_eq!(bytes, bytes_again, "round-trip is bit-identical");
    }

    // ---- Encoding sorts arrays on output ---------------------------------

    /// Re-parse encoded bytes to a `ciborium::Value` map for raw
    /// inspection of array order.
    fn parse_to_value_map(bytes: &[u8]) -> Vec<(Value, Value)> {
        match ciborium::de::from_reader(bytes).expect("ciborium parse") {
            Value::Map(m) => m,
            _ => panic!("manifest is not a map"),
        }
    }

    fn find_array<'a>(map: &'a [(Value, Value)], key: &str) -> &'a [Value] {
        for (k, v) in map {
            if let Value::Text(s) = k {
                if s == key {
                    return match v {
                        Value::Array(a) => a.as_slice(),
                        _ => panic!("{key} is not an array"),
                    };
                }
            }
        }
        panic!("key {key} not present in manifest map");
    }

    fn entry_bytes_field(entry: &Value, key: &str) -> Vec<u8> {
        match entry {
            Value::Map(m) => {
                for (k, v) in m {
                    if let Value::Text(s) = k {
                        if s == key {
                            return match v {
                                Value::Bytes(b) => b.clone(),
                                _ => panic!("{key} is not bytes"),
                            };
                        }
                    }
                }
                panic!("entry missing key {key}");
            }
            _ => panic!("entry is not a map"),
        }
    }

    #[test]
    fn encoding_sorts_arrays_on_output() {
        let m = populated_manifest();
        let bytes = encode_manifest(&m).expect("encode");
        let map = parse_to_value_map(&bytes);

        // vector_clock sorted ascending by device_uuid.
        let vc = find_array(&map, KEY_VECTOR_CLOCK);
        let device_ids: Vec<Vec<u8>> = vc
            .iter()
            .map(|e| entry_bytes_field(e, KEY_DEVICE_UUID))
            .collect();
        assert_eq!(
            device_ids,
            vec![vec![0x55; UUID_LEN], vec![0xaa; UUID_LEN]],
            "vector_clock sorted by device_uuid lex"
        );

        // blocks sorted ascending by block_uuid.
        let blocks = find_array(&map, KEY_BLOCKS);
        let block_ids: Vec<Vec<u8>> = blocks
            .iter()
            .map(|b| entry_bytes_field(b, KEY_BLOCK_UUID))
            .collect();
        assert_eq!(
            block_ids,
            vec![vec![0xa2; UUID_LEN], vec![0xb1; UUID_LEN]],
            "blocks sorted by block_uuid lex"
        );

        // Inner vector_clock_summary on each block is also sorted.
        for blk in blocks {
            let inner_vc = match blk {
                Value::Map(entries) => entries
                    .iter()
                    .find_map(|(k, v)| match k {
                        Value::Text(s) if s == KEY_VECTOR_CLOCK_SUMMARY => match v {
                            Value::Array(a) => Some(a.as_slice()),
                            _ => None,
                        },
                        _ => None,
                    })
                    .expect("vector_clock_summary present"),
                _ => panic!("block entry not a map"),
            };
            let ids: Vec<Vec<u8>> = inner_vc
                .iter()
                .map(|e| entry_bytes_field(e, KEY_DEVICE_UUID))
                .collect();
            let mut sorted = ids.clone();
            sorted.sort();
            assert_eq!(ids, sorted, "vector_clock_summary sorted on output");
        }

        // trash array — only one entry, but check the key is present.
        let trash = find_array(&map, KEY_TRASH);
        assert_eq!(trash.len(), 1, "trash has one entry");
    }

    // ---- Forward-compat round-trip ---------------------------------------

    #[test]
    fn forward_compat_unknown_top_level_key_round_trips() {
        let mut m = minimal_manifest();
        // CBOR for a tiny array `[1, 2]`: 0x82 0x01 0x02.
        m.unknown.insert(
            "future_field".into(),
            UnknownValue::from_canonical_cbor(&[0x82, 0x01, 0x02])
                .expect("UnknownValue from canonical bytes"),
        );
        let bytes = encode_manifest(&m).expect("encode with unknown");
        let parsed = decode_manifest(&bytes).expect("decode with unknown");
        assert!(
            parsed.unknown.contains_key("future_field"),
            "unknown top-level key preserved on decode"
        );
        let bytes_again = encode_manifest(&parsed).expect("re-encode");
        assert_eq!(
            bytes, bytes_again,
            "unknown top-level key round-trips bit-identically"
        );
    }

    // ---- Negative paths --------------------------------------------------

    /// Build a top-level manifest CBOR map by hand. Useful for negative
    /// tests where we want to mutate one key away from canonical.
    fn build_manifest_map_with_overrides(
        manifest_version: Option<u8>,
        vault_uuid_present: bool,
    ) -> Vec<u8> {
        let mut entries: Vec<(Value, Value)> = Vec::new();
        if let Some(mv) = manifest_version {
            entries.push((
                Value::Text(KEY_MANIFEST_VERSION.into()),
                Value::Integer(u64::from(mv).into()),
            ));
        }
        if vault_uuid_present {
            entries.push((
                Value::Text(KEY_VAULT_UUID.into()),
                Value::Bytes([0x01; UUID_LEN].to_vec()),
            ));
        }
        entries.push((
            Value::Text(KEY_FORMAT_VERSION.into()),
            Value::Integer(u64::from(FORMAT_VERSION_V1).into()),
        ));
        entries.push((
            Value::Text(KEY_SUITE_ID.into()),
            Value::Integer(u64::from(SUITE_ID_V1).into()),
        ));
        entries.push((
            Value::Text(KEY_OWNER_USER_UUID.into()),
            Value::Bytes([0x02; UUID_LEN].to_vec()),
        ));
        entries.push((
            Value::Text(KEY_VECTOR_CLOCK.into()),
            Value::Array(Vec::new()),
        ));
        entries.push((Value::Text(KEY_BLOCKS.into()), Value::Array(Vec::new())));
        entries.push((Value::Text(KEY_TRASH.into()), Value::Array(Vec::new())));
        entries.push((
            Value::Text(KEY_KDF_PARAMS.into()),
            kdf_params_to_value(&dummy_kdf_params()).expect("kdf_params"),
        ));
        encode_canonical_map(&entries).expect("encode_canonical_map")
    }

    #[test]
    fn rejects_unsupported_manifest_version() {
        let bytes = build_manifest_map_with_overrides(Some(2), true);
        let err = decode_manifest(&bytes).expect_err("manifest_version=2 must reject");
        assert!(
            matches!(err, ManifestError::UnsupportedManifestVersion(2)),
            "expected UnsupportedManifestVersion(2), got {err:?}"
        );
    }

    #[test]
    fn rejects_duplicate_device_uuid_in_vector_clock() {
        // Hand-build a manifest with two vector_clock entries sharing the
        // same device_uuid. We can NOT rely on encode_manifest to produce
        // duplicates (the input already needs to have them and the encode
        // path doesn't dedupe — but the canonical sort doesn't either).
        // The simplest path: just build the duplicate input, then invoke
        // encode_manifest and decode it.
        let dupe_dev = [0x33; UUID_LEN];
        let m = Manifest {
            manifest_version: MANIFEST_VERSION_V1,
            vault_uuid: [0x01; UUID_LEN],
            format_version: FORMAT_VERSION_V1,
            suite_id: SUITE_ID_V1,
            owner_user_uuid: [0x02; UUID_LEN],
            vector_clock: vec![
                VectorClockEntry {
                    device_uuid: dupe_dev,
                    counter: 1,
                },
                VectorClockEntry {
                    device_uuid: dupe_dev,
                    counter: 2,
                },
            ],
            blocks: Vec::new(),
            trash: Vec::new(),
            kdf_params: dummy_kdf_params(),
            unknown: BTreeMap::new(),
        };
        let bytes = encode_manifest(&m).expect("encode duplicates");
        let err = decode_manifest(&bytes)
            .expect_err("duplicate device_uuid must be rejected on decode");
        assert!(
            matches!(err, ManifestError::VectorClockDuplicateDevice),
            "expected VectorClockDuplicateDevice, got {err:?}"
        );
    }

    #[test]
    fn rejects_duplicate_block_uuid() {
        let dupe = [0x77; UUID_LEN];
        let make_block = |suffix: u8| BlockEntry {
            block_uuid: dupe,
            block_name: format!("blk-{suffix}"),
            fingerprint: [suffix; FINGERPRINT_LEN],
            recipients: vec![[0xc1; UUID_LEN]],
            vector_clock_summary: Vec::new(),
            suite_id: SUITE_ID_V1,
            created_at_ms: 1,
            last_mod_ms: 2,
            unknown: BTreeMap::new(),
        };
        let m = Manifest {
            manifest_version: MANIFEST_VERSION_V1,
            vault_uuid: [0x01; UUID_LEN],
            format_version: FORMAT_VERSION_V1,
            suite_id: SUITE_ID_V1,
            owner_user_uuid: [0x02; UUID_LEN],
            vector_clock: Vec::new(),
            blocks: vec![make_block(1), make_block(2)],
            trash: Vec::new(),
            kdf_params: dummy_kdf_params(),
            unknown: BTreeMap::new(),
        };
        let bytes = encode_manifest(&m).expect("encode duplicates");
        let err = decode_manifest(&bytes)
            .expect_err("duplicate block_uuid must be rejected on decode");
        assert!(
            matches!(err, ManifestError::DuplicateBlockUuid),
            "expected DuplicateBlockUuid, got {err:?}"
        );
    }

    #[test]
    fn rejects_non_map_top_level() {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&Value::Array(Vec::new()), &mut buf)
            .expect("encode array");
        let err = decode_manifest(&buf).expect_err("array top-level must reject");
        assert!(
            matches!(err, ManifestError::NotAMap),
            "expected NotAMap, got {err:?}"
        );
    }

    #[test]
    fn rejects_float_in_unknown_value() {
        // Build a manifest map with an unknown top-level key whose value
        // is a CBOR float. The float-rejection walker fires up front in
        // decode_manifest before the unknown bag is even populated.
        let entries: Vec<(Value, Value)> = vec![
            (
                Value::Text(KEY_MANIFEST_VERSION.into()),
                Value::Integer(u64::from(MANIFEST_VERSION_V1).into()),
            ),
            (
                Value::Text(KEY_VAULT_UUID.into()),
                Value::Bytes([0x01; UUID_LEN].to_vec()),
            ),
            (
                Value::Text(KEY_FORMAT_VERSION.into()),
                Value::Integer(u64::from(FORMAT_VERSION_V1).into()),
            ),
            (
                Value::Text(KEY_SUITE_ID.into()),
                Value::Integer(u64::from(SUITE_ID_V1).into()),
            ),
            (
                Value::Text(KEY_OWNER_USER_UUID.into()),
                Value::Bytes([0x02; UUID_LEN].to_vec()),
            ),
            (
                Value::Text(KEY_VECTOR_CLOCK.into()),
                Value::Array(Vec::new()),
            ),
            (Value::Text(KEY_BLOCKS.into()), Value::Array(Vec::new())),
            (Value::Text(KEY_TRASH.into()), Value::Array(Vec::new())),
            (
                Value::Text(KEY_KDF_PARAMS.into()),
                kdf_params_to_value(&dummy_kdf_params()).expect("kdf_params"),
            ),
            // Float lives inside an unknown forward-compat key.
            (Value::Text("future_floaty".into()), Value::Float(1.5)),
        ];
        let bytes = encode_canonical_map(&entries).expect("encode_canonical_map");

        let err = decode_manifest(&bytes).expect_err("float must be rejected");
        assert!(
            matches!(
                err,
                ManifestError::Canonical(CanonicalError::FloatRejected { .. })
            ),
            "expected Canonical(FloatRejected), got {err:?}"
        );
    }

    #[test]
    fn rejects_missing_required_field_vault_uuid() {
        let bytes = build_manifest_map_with_overrides(Some(MANIFEST_VERSION_V1), false);
        let err = decode_manifest(&bytes).expect_err("missing vault_uuid must reject");
        assert!(
            matches!(
                err,
                ManifestError::MissingField {
                    field: KEY_VAULT_UUID
                }
            ),
            "expected MissingField {{ field: \"vault_uuid\" }}, got {err:?}"
        );
    }

    // ---- Binary header encode/decode (§4.1) ------------------------------
    //
    // The header is the 42-byte AAD prefix that wraps the AEAD body. Every
    // negative test below pins one §4.1 invariant; the round-trip and
    // tamper tests pin the AAD-binding property (a tampered header
    // invalidates the Poly1305 tag).

    /// Pinned 32-byte test IBK. The `Sensitive` wrapper zeroizes on drop,
    /// so each test gets a fresh instance — we don't share one across
    /// tests. Same fixture style as PR-A's block.rs tests.
    fn test_ibk(byte: u8) -> AeadKey {
        Sensitive::new([byte; 32])
    }

    fn test_nonce() -> AeadNonce {
        // Deterministic 24-byte nonce for fixture stability. NOT
        // representative of production: real callers must source nonces
        // from `crypto::rand` (or pinned KAT inputs in tests).
        let mut n = [0u8; 24];
        for (i, b) in n.iter_mut().enumerate() {
            *b = i as u8;
        }
        n
    }

    fn fixed_manifest_header() -> ManifestHeader {
        ManifestHeader {
            vault_uuid: [0x42; UUID_LEN],
            created_at_ms: 1_714_060_800_000,
            last_mod_ms: 1_714_060_900_000,
        }
    }

    #[test]
    fn header_encode_round_trips() {
        let h = fixed_manifest_header();
        let bytes = h.encode();
        assert_eq!(bytes.len(), MANIFEST_HEADER_LEN, "encoded header is 42 bytes");
        assert_eq!(bytes.len(), 42, "MANIFEST_HEADER_LEN spec value");

        // Pin the constant prefix. magic = "SECR" big-endian.
        assert_eq!(&bytes[0..4], b"SECR");
        // format_version 0x0001
        assert_eq!(&bytes[4..6], &[0x00, 0x01]);
        // suite_id 0x0001
        assert_eq!(&bytes[6..8], &[0x00, 0x01]);
        // file_kind 0x0002 (manifest)
        assert_eq!(&bytes[8..10], &[0x00, 0x02]);

        let (decoded, tail) = ManifestHeader::decode(&bytes).expect("decode round-trip");
        assert!(tail.is_empty(), "exact-length input leaves no tail");
        assert_eq!(decoded, h, "header round-trips");
    }

    #[test]
    fn header_decode_returns_tail() {
        // Decoder leaves any post-header bytes as the returned tail so a
        // future ManifestFile decoder (Task 7) can keep parsing.
        let h = fixed_manifest_header();
        let mut buf = h.encode().to_vec();
        buf.extend_from_slice(&[0xab, 0xcd, 0xef]);
        let (decoded, tail) = ManifestHeader::decode(&buf).expect("decode with trailer");
        assert_eq!(decoded, h);
        assert_eq!(tail, &[0xab, 0xcd, 0xef]);
    }

    #[test]
    fn header_decode_rejects_bad_magic() {
        let mut bytes = [0u8; MANIFEST_HEADER_LEN];
        // First 4 bytes deliberately wrong; rest doesn't matter — magic
        // is checked first.
        let err = ManifestHeader::decode(&bytes).expect_err("bad magic must reject");
        assert!(
            matches!(err, ManifestError::BadMagic { expected, got }
                if expected == MAGIC && got == 0),
            "expected BadMagic with expected=MAGIC and got=0, got {err:?}"
        );
        // Also try a non-zero wrong magic to make sure the comparison is
        // structural, not just zero-vs-nonzero.
        bytes[0..4].copy_from_slice(&0xdead_beef_u32.to_be_bytes());
        let err = ManifestHeader::decode(&bytes).expect_err("bad magic must reject");
        assert!(
            matches!(err, ManifestError::BadMagic { expected, got }
                if expected == MAGIC && got == 0xdead_beef),
            "expected BadMagic with got=0xdeadbeef, got {err:?}"
        );
    }

    #[test]
    fn header_decode_rejects_wrong_format_version() {
        let mut bytes = fixed_manifest_header().encode();
        // format_version lives at offset 4..6 (after magic).
        bytes[4..6].copy_from_slice(&0x0002_u16.to_be_bytes());
        let err = ManifestHeader::decode(&bytes)
            .expect_err("non-v1 format_version must reject");
        assert!(
            matches!(err, ManifestError::UnsupportedFormatVersion(2)),
            "expected UnsupportedFormatVersion(2), got {err:?}"
        );
    }

    #[test]
    fn header_decode_rejects_wrong_suite_id() {
        let mut bytes = fixed_manifest_header().encode();
        // suite_id lives at offset 6..8.
        bytes[6..8].copy_from_slice(&0x0099_u16.to_be_bytes());
        let err = ManifestHeader::decode(&bytes).expect_err("non-v1 suite_id must reject");
        assert!(
            matches!(err, ManifestError::UnsupportedSuiteId(0x99)),
            "expected UnsupportedSuiteId(0x99), got {err:?}"
        );
    }

    #[test]
    fn header_decode_rejects_wrong_file_kind() {
        let mut bytes = fixed_manifest_header().encode();
        // file_kind lives at offset 8..10. 0x0001 is the identity-bundle
        // file kind; rejecting it here pins the §4.1 cross-file-kind
        // anti-substitution check at the binary layer (the AEAD AAD also
        // catches it later, but we'd rather fail with a typed error than
        // a generic AEAD failure when the file-kind alone is enough to
        // disambiguate).
        bytes[8..10].copy_from_slice(&0x0001_u16.to_be_bytes());
        let err = ManifestHeader::decode(&bytes).expect_err("non-manifest file_kind must reject");
        assert!(
            matches!(
                err,
                ManifestError::UnsupportedFileKind {
                    expected: FILE_KIND_MANIFEST,
                    got: 0x0001
                }
            ),
            "expected UnsupportedFileKind {{ expected: 0x0002, got: 0x0001 }}, got {err:?}"
        );
    }

    #[test]
    fn header_decode_rejects_truncation() {
        // 41 bytes — one short of the §4.1 header length.
        let bytes = [0u8; MANIFEST_HEADER_LEN - 1];
        let err = ManifestHeader::decode(&bytes).expect_err("41 bytes must reject as truncated");
        assert!(
            matches!(
                err,
                ManifestError::HeaderTruncated {
                    need: MANIFEST_HEADER_LEN,
                    got: 41
                }
            ),
            "expected HeaderTruncated {{ need: 42, got: 41 }}, got {err:?}"
        );

        // Also: empty input.
        let err = ManifestHeader::decode(&[])
            .expect_err("empty input must reject as truncated");
        assert!(
            matches!(
                err,
                ManifestError::HeaderTruncated {
                    need: MANIFEST_HEADER_LEN,
                    got: 0
                }
            ),
            "expected HeaderTruncated with got=0, got {err:?}"
        );
    }

    // ---- AEAD body encrypt/decrypt round-trip ---------------------------

    #[test]
    fn encrypt_decrypt_body_round_trip() {
        let m = populated_manifest();
        let manifest_bytes = encode_manifest(&m).expect("encode manifest body");
        let header = fixed_manifest_header();
        let ibk = test_ibk(0x00);
        let nonce = test_nonce();

        let ct_with_tag = encrypt_manifest_body(&header, &manifest_bytes, &ibk, &nonce)
            .expect("encrypt body");
        // The tag is appended to the ciphertext per crypto::aead's contract.
        assert_eq!(
            ct_with_tag.len(),
            manifest_bytes.len() + AEAD_TAG_LEN,
            "ct||tag length is plaintext+16"
        );

        let ibk2 = test_ibk(0x00);
        let recovered = decrypt_manifest_body(&header, &ct_with_tag, &ibk2, &nonce)
            .expect("decrypt body");

        // populated_manifest's input arrays are non-canonical-order; the
        // decoded copy is in canonical order. Use the same sort-then-compare
        // discipline as the existing `roundtrip_populated_manifest` test.
        let mut m_sorted = m.clone();
        m_sorted
            .vector_clock
            .sort_by(|a, b| a.device_uuid.cmp(&b.device_uuid));
        m_sorted.blocks.sort_by(|a, b| a.block_uuid.cmp(&b.block_uuid));
        for blk in &mut m_sorted.blocks {
            blk.recipients.sort();
            blk.vector_clock_summary
                .sort_by(|a, b| a.device_uuid.cmp(&b.device_uuid));
        }
        m_sorted.trash.sort_by(|a, b| a.block_uuid.cmp(&b.block_uuid));
        assert_eq!(recovered, m_sorted, "decrypted manifest matches original");
    }

    #[test]
    fn tamper_header_breaks_aead() {
        // Central §4.1 spec property: the header is bound into the AEAD
        // tag via AAD, so a single-byte flip in the header invalidates
        // the tag on decrypt.
        let m = minimal_manifest();
        let manifest_bytes = encode_manifest(&m).expect("encode");
        let header = fixed_manifest_header();
        let ibk = test_ibk(0x00);
        let nonce = test_nonce();
        let ct_with_tag =
            encrypt_manifest_body(&header, &manifest_bytes, &ibk, &nonce).expect("encrypt");

        // Tamper #1: flip a byte in vault_uuid.
        let mut tampered = header;
        tampered.vault_uuid[0] ^= 0xff;
        let err = decrypt_manifest_body(&tampered, &ct_with_tag, &ibk, &nonce)
            .expect_err("tampered header must fail AEAD");
        assert!(
            matches!(err, ManifestError::AeadFailure),
            "expected AeadFailure (tampered vault_uuid), got {err:?}"
        );

        // Tamper #2: change last_mod_ms.
        let tampered = ManifestHeader {
            last_mod_ms: header.last_mod_ms.wrapping_add(1),
            ..header
        };
        let err = decrypt_manifest_body(&tampered, &ct_with_tag, &ibk, &nonce)
            .expect_err("tampered last_mod_ms must fail AEAD");
        assert!(
            matches!(err, ManifestError::AeadFailure),
            "expected AeadFailure (tampered last_mod_ms), got {err:?}"
        );
    }

    #[test]
    fn tamper_ct_breaks_aead() {
        let m = minimal_manifest();
        let manifest_bytes = encode_manifest(&m).expect("encode");
        let header = fixed_manifest_header();
        let ibk = test_ibk(0x00);
        let nonce = test_nonce();
        let mut ct_with_tag =
            encrypt_manifest_body(&header, &manifest_bytes, &ibk, &nonce).expect("encrypt");

        // Flip a byte deep inside the ciphertext (not the tag region).
        // `manifest_bytes.len()` would be the start of the tag; pick
        // somewhere safely before that.
        ct_with_tag[2] ^= 0xff;
        let err = decrypt_manifest_body(&header, &ct_with_tag, &ibk, &nonce)
            .expect_err("tampered ct must fail AEAD");
        assert!(
            matches!(err, ManifestError::AeadFailure),
            "expected AeadFailure on flipped ciphertext byte, got {err:?}"
        );
    }

    #[test]
    fn wrong_ibk_breaks_aead() {
        let m = minimal_manifest();
        let manifest_bytes = encode_manifest(&m).expect("encode");
        let header = fixed_manifest_header();
        let ibk = test_ibk(0x00);
        let nonce = test_nonce();
        let ct_with_tag =
            encrypt_manifest_body(&header, &manifest_bytes, &ibk, &nonce).expect("encrypt");

        let wrong_ibk = test_ibk(0xff);
        let err = decrypt_manifest_body(&header, &ct_with_tag, &wrong_ibk, &nonce)
            .expect_err("wrong IBK must fail AEAD");
        assert!(
            matches!(err, ManifestError::AeadFailure),
            "expected AeadFailure under wrong IBK, got {err:?}"
        );
    }

    // ---- ManifestFile envelope encode/decode (§4.1) ----------------------

    /// Build a deterministic, fully-populated `ManifestFile` for the
    /// envelope-level tests: pinned header, pinned AEAD ciphertext and
    /// tag, pinned author fingerprint, and a length-correct (but
    /// fake-content) ML-DSA-65 signature. The "fake content" makes the
    /// envelope tests truly orthogonal to signature verification — the
    /// signature is just bytes here. The sign/verify tests below use
    /// real `sign_manifest` output.
    fn fixture_manifest_file() -> ManifestFile {
        ManifestFile {
            header: fixed_manifest_header(),
            aead_nonce: test_nonce(),
            aead_ct: vec![0x77; 32],
            aead_tag: [0x88; AEAD_TAG_LEN],
            author_fingerprint: [0xa5; 16],
            sig_ed: [0x44; ED25519_SIG_LEN],
            sig_pq: MlDsa65Sig::from_bytes(&vec![0x55; ML_DSA_65_SIG_LEN])
                .expect("ML-DSA-65 sig bytes"),
        }
    }

    #[test]
    fn manifest_file_encode_decode_round_trip() {
        let file = fixture_manifest_file();
        let bytes = encode_manifest_file(&file).expect("encode_manifest_file");
        let decoded = decode_manifest_file(&bytes).expect("decode_manifest_file");
        assert_eq!(decoded, file, "ManifestFile round-trips bit-identically");
        let bytes_again =
            encode_manifest_file(&decoded).expect("re-encode_manifest_file");
        assert_eq!(bytes, bytes_again, "encode is deterministic");
    }

    #[test]
    fn encode_decode_pinned_byte_layout() {
        // Spec arithmetic for §4.1:
        //   header(42) + aead_nonce(24) + aead_ct_len(4) + aead_ct(N)
        //   + aead_tag(16) + author_fingerprint(16) + sig_ed_len(2)
        //   + sig_ed(64) + sig_pq_len(2) + sig_pq(3309)
        let file = fixture_manifest_file();
        let bytes = encode_manifest_file(&file).expect("encode");
        let ct_len = file.aead_ct.len();
        let expected = 42 + 24 + 4 + ct_len + 16 + 16 + 2 + 64 + 2 + 3309;
        assert_eq!(
            bytes.len(),
            expected,
            "encoded length matches §4.1 spec arithmetic"
        );

        // Spot-check: sig_ed_len at offset (42+24+4+ct_len+16+16) = 64.
        let sig_ed_len_offset = 42 + 24 + 4 + ct_len + 16 + 16;
        let sig_ed_len_bytes = [
            bytes[sig_ed_len_offset],
            bytes[sig_ed_len_offset + 1],
        ];
        assert_eq!(
            u16::from_be_bytes(sig_ed_len_bytes),
            64,
            "sig_ed_len encodes 64 at the spec offset"
        );

        // Spot-check: aead_ct_len is u32 BE at offset 42+24=66.
        let ct_len_offset = 42 + 24;
        let ct_len_bytes = [
            bytes[ct_len_offset],
            bytes[ct_len_offset + 1],
            bytes[ct_len_offset + 2],
            bytes[ct_len_offset + 3],
        ];
        assert_eq!(
            u32::from_be_bytes(ct_len_bytes) as usize,
            ct_len,
            "aead_ct_len encodes the actual aead_ct length"
        );

        // Spot-check: sig_pq_len at offset (sig_ed_len_offset+2+64) = 3309.
        let sig_pq_len_offset = sig_ed_len_offset + 2 + 64;
        let sig_pq_len_bytes = [
            bytes[sig_pq_len_offset],
            bytes[sig_pq_len_offset + 1],
        ];
        assert_eq!(
            u16::from_be_bytes(sig_pq_len_bytes),
            3309,
            "sig_pq_len encodes 3309 at the spec offset"
        );
    }

    #[test]
    fn decode_rejects_sig_ed_wrong_length() {
        let file = fixture_manifest_file();
        let mut bytes = encode_manifest_file(&file).expect("encode");
        let ct_len = file.aead_ct.len();
        // sig_ed_len lives at offset (42+24+4+ct_len+16+16); flip it from
        // 64 to 63.
        let off = 42 + 24 + 4 + ct_len + 16 + 16;
        bytes[off..off + 2].copy_from_slice(&63u16.to_be_bytes());
        let err = decode_manifest_file(&bytes).expect_err("sig_ed_len=63 must reject");
        assert!(
            matches!(
                err,
                ManifestError::SigEdWrongLength {
                    expected: 64,
                    got: 63
                }
            ),
            "expected SigEdWrongLength {{ expected: 64, got: 63 }}, got {err:?}"
        );
    }

    #[test]
    fn decode_rejects_sig_pq_wrong_length() {
        let file = fixture_manifest_file();
        let mut bytes = encode_manifest_file(&file).expect("encode");
        let ct_len = file.aead_ct.len();
        // sig_pq_len lives at offset (42+24+4+ct_len+16+16+2+64).
        let off = 42 + 24 + 4 + ct_len + 16 + 16 + 2 + 64;
        bytes[off..off + 2].copy_from_slice(&3308u16.to_be_bytes());
        let err = decode_manifest_file(&bytes).expect_err("sig_pq_len=3308 must reject");
        assert!(
            matches!(
                err,
                ManifestError::SigPqWrongLength {
                    expected: 3309,
                    got: 3308
                }
            ),
            "expected SigPqWrongLength {{ expected: 3309, got: 3308 }}, got {err:?}"
        );
    }

    #[test]
    fn decode_rejects_aead_ct_len_overflow() {
        // Encode a valid file, then bump aead_ct_len past the available
        // remaining body. Decoder must surface AeadCtLenMismatch (or, if
        // the declared length pushes the suffix-reservation impossible,
        // SectionTruncated at "aead_ct"). We pin the AeadCtLenMismatch
        // case here: declared = ct_len + 100, plenty of fixed-suffix
        // bytes still present.
        let file = fixture_manifest_file();
        let mut bytes = encode_manifest_file(&file).expect("encode");
        let original_ct_len = file.aead_ct.len() as u32;
        // aead_ct_len lives at offset 42+24=66.
        let off = 42 + 24;
        let bumped = original_ct_len + 100;
        bytes[off..off + 4].copy_from_slice(&bumped.to_be_bytes());
        let err = decode_manifest_file(&bytes).expect_err("oversized aead_ct_len must reject");
        assert!(
            matches!(
                err,
                ManifestError::AeadCtLenMismatch {
                    declared,
                    remaining,
                } if declared == bumped && remaining == original_ct_len as usize
            ),
            "expected AeadCtLenMismatch, got {err:?}"
        );
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let file = fixture_manifest_file();
        let mut bytes = encode_manifest_file(&file).expect("encode");
        bytes.push(0x99);
        let err = decode_manifest_file(&bytes).expect_err("trailing junk byte must reject");
        assert!(
            matches!(err, ManifestError::TrailingBytes(1)),
            "expected TrailingBytes(1), got {err:?}"
        );
    }

    #[test]
    fn decode_rejects_truncation_at_header() {
        // 41 bytes — one short of the §4.1 header.
        let bytes = [0u8; MANIFEST_HEADER_LEN - 1];
        let err = decode_manifest_file(&bytes).expect_err("41 bytes must reject as truncated");
        assert!(
            matches!(
                err,
                ManifestError::HeaderTruncated {
                    need: MANIFEST_HEADER_LEN,
                    got: 41
                }
            ),
            "expected HeaderTruncated, got {err:?}"
        );
    }

    #[test]
    fn decode_rejects_truncation_at_aead_section() {
        // Header (42) plus 23 of the 24 nonce bytes.
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&fixed_manifest_header().encode());
        bytes.extend_from_slice(&[0u8; 23]);
        let err = decode_manifest_file(&bytes)
            .expect_err("header + 23 bytes must reject as nonce-truncated");
        assert!(
            matches!(
                err,
                ManifestError::SectionTruncated {
                    section: "aead_nonce",
                    need: 24,
                    got: 23
                }
            ),
            "expected SectionTruncated at aead_nonce, got {err:?}"
        );
    }

    #[test]
    fn decode_rejects_truncation_at_signature_suffix() {
        // Header (42) + nonce (24) + aead_ct_len (4) + nothing else —
        // the fixed-size suffix needs 16 (tag) + 16 (fp) + 2 + 64 + 2 +
        // 3309 = 3409 bytes; we provide 0 so the decoder should reject
        // truncated at the aead_ct boundary.
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&fixed_manifest_header().encode());
        bytes.extend_from_slice(&[0u8; 24]); // nonce
        bytes.extend_from_slice(&0u32.to_be_bytes()); // aead_ct_len = 0
        // No more bytes — the fixed suffix-after-ct (3409) is missing.
        let err = decode_manifest_file(&bytes)
            .expect_err("missing signature suffix must reject");
        assert!(
            matches!(
                err,
                ManifestError::SectionTruncated {
                    section: "aead_ct",
                    need,
                    got: 0,
                } if need == AEAD_TAG_LEN + 16 + 2 + 64 + 2 + ML_DSA_65_SIG_LEN
            ),
            "expected SectionTruncated at aead_ct (need=fixed-suffix, got=0), got {err:?}"
        );
    }

    // ---- Sign / verify (§4.1 / §8) ---------------------------------------

    /// Build a fresh hybrid keypair from a pinned ChaCha20Rng seed.
    /// Same pattern as block.rs's signing-key fixtures.
    fn fixture_hybrid_keypair(
        seed: u8,
    ) -> (
        Ed25519Secret,
        Ed25519Public,
        MlDsa65Secret,
        MlDsa65Public,
    ) {
        use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
        let mut ed_rng = ChaCha20Rng::from_seed([seed; 32]);
        let mut pq_rng = ChaCha20Rng::from_seed([seed.wrapping_add(1); 32]);
        let (sk_ed, pk_ed) = sig::generate_ed25519(&mut ed_rng);
        let (sk_pq, pk_pq) = sig::generate_ml_dsa_65(&mut pq_rng);
        (sk_ed, pk_ed, sk_pq, pk_pq)
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let body = populated_manifest();
        let header = fixed_manifest_header();
        let ibk = test_ibk(0x00);
        let nonce = test_nonce();
        let author: Fingerprint = [0xa5; 16];
        let (sk_ed, pk_ed, sk_pq, pk_pq) = fixture_hybrid_keypair(0x10);

        let file = sign_manifest(header, &body, &ibk, &nonce, author, &sk_ed, &sk_pq)
            .expect("sign_manifest");
        verify_manifest(&file, &pk_ed, &pk_pq).expect("verify_manifest");
    }

    #[test]
    fn verify_rejects_tampered_aead_ct() {
        let body = minimal_manifest();
        let header = fixed_manifest_header();
        let ibk = test_ibk(0x00);
        let nonce = test_nonce();
        let author: Fingerprint = [0xa5; 16];
        let (sk_ed, pk_ed, sk_pq, pk_pq) = fixture_hybrid_keypair(0x20);

        let mut file = sign_manifest(header, &body, &ibk, &nonce, author, &sk_ed, &sk_pq)
            .expect("sign_manifest");
        // Flip a byte deep inside the ciphertext.
        if file.aead_ct.is_empty() {
            // minimal_manifest's CBOR is non-empty in practice, but guard
            // against a future trim.
            file.aead_ct.push(0x00);
        }
        file.aead_ct[0] ^= 0xff;
        let err = verify_manifest(&file, &pk_ed, &pk_pq)
            .expect_err("tampered aead_ct must fail verify");
        assert!(
            matches!(
                err,
                ManifestError::Ed25519SignatureInvalid
                    | ManifestError::MlDsa65SignatureInvalid
            ),
            "expected hybrid verify failure, got {err:?}"
        );
    }

    #[test]
    fn verify_rejects_tampered_header() {
        let body = minimal_manifest();
        let header = fixed_manifest_header();
        let ibk = test_ibk(0x00);
        let nonce = test_nonce();
        let author: Fingerprint = [0xa5; 16];
        let (sk_ed, pk_ed, sk_pq, pk_pq) = fixture_hybrid_keypair(0x30);

        let mut file = sign_manifest(header, &body, &ibk, &nonce, author, &sk_ed, &sk_pq)
            .expect("sign_manifest");
        // Mutate last_mod_ms — the header is part of the signed bytes.
        file.header.last_mod_ms = file.header.last_mod_ms.wrapping_add(1);
        let err = verify_manifest(&file, &pk_ed, &pk_pq)
            .expect_err("tampered header must fail verify");
        assert!(
            matches!(
                err,
                ManifestError::Ed25519SignatureInvalid
                    | ManifestError::MlDsa65SignatureInvalid
            ),
            "expected hybrid verify failure on header tamper, got {err:?}"
        );
    }

    #[test]
    fn verify_rejects_wrong_pk() {
        let body = minimal_manifest();
        let header = fixed_manifest_header();
        let ibk = test_ibk(0x00);
        let nonce = test_nonce();
        let author: Fingerprint = [0xa5; 16];
        let (sk_ed, _pk_ed, sk_pq, _pk_pq) = fixture_hybrid_keypair(0x40);
        let (_sk_ed2, pk_ed2, _sk_pq2, pk_pq2) = fixture_hybrid_keypair(0x50);

        let file = sign_manifest(header, &body, &ibk, &nonce, author, &sk_ed, &sk_pq)
            .expect("sign_manifest");
        // Verify with a *different* keypair's public keys.
        let err = verify_manifest(&file, &pk_ed2, &pk_pq2)
            .expect_err("wrong pk must fail verify");
        assert!(
            matches!(
                err,
                ManifestError::Ed25519SignatureInvalid
                    | ManifestError::MlDsa65SignatureInvalid
            ),
            "expected hybrid verify failure under wrong pk, got {err:?}"
        );
    }

    #[test]
    fn sign_then_decrypt_round_trips() {
        // Full pipeline: sign → verify → decrypt → compare body.
        let body = populated_manifest();
        let header = fixed_manifest_header();
        let ibk = test_ibk(0x00);
        let nonce = test_nonce();
        let author: Fingerprint = [0xa5; 16];
        let (sk_ed, pk_ed, sk_pq, pk_pq) = fixture_hybrid_keypair(0x60);

        let file = sign_manifest(header, &body, &ibk, &nonce, author, &sk_ed, &sk_pq)
            .expect("sign_manifest");

        // Verify before decrypt — orchestrator-style sequencing.
        verify_manifest(&file, &pk_ed, &pk_pq).expect("verify_manifest");

        // Reconstruct ct_with_tag = aead_ct ++ aead_tag for the AEAD API.
        let mut ct_with_tag =
            Vec::with_capacity(file.aead_ct.len() + AEAD_TAG_LEN);
        ct_with_tag.extend_from_slice(&file.aead_ct);
        ct_with_tag.extend_from_slice(&file.aead_tag);
        let recovered = decrypt_manifest_body(&file.header, &ct_with_tag, &ibk, &nonce)
            .expect("decrypt_manifest_body");

        // populated_manifest's input arrays are non-canonical-order; the
        // decoded copy is in canonical order. Use the same sort-then-compare
        // discipline as the existing `roundtrip_populated_manifest` test.
        let mut body_sorted = body.clone();
        body_sorted
            .vector_clock
            .sort_by(|a, b| a.device_uuid.cmp(&b.device_uuid));
        body_sorted
            .blocks
            .sort_by(|a, b| a.block_uuid.cmp(&b.block_uuid));
        for blk in &mut body_sorted.blocks {
            blk.recipients.sort();
            blk.vector_clock_summary
                .sort_by(|a, b| a.device_uuid.cmp(&b.device_uuid));
        }
        body_sorted
            .trash
            .sort_by(|a, b| a.block_uuid.cmp(&b.block_uuid));
        assert_eq!(recovered, body_sorted, "decrypted manifest matches original");
    }

    // ---- §10 rollback resistance --------------------------------------

    /// Tiny construction shorthand for the rollback test matrix.
    fn vc(uuid_byte: u8, counter: u64) -> VectorClockEntry {
        VectorClockEntry {
            device_uuid: [uuid_byte; 16],
            counter,
        }
    }

    // (9) Spec-discipline lodestone: `is_rollback` must be defined on
    //     the *logical* clock (a map from device_uuid → counter), not on
    //     the slice. A consumer that confuses ordering with semantics
    //     will silently mis-classify reorderings of the very same clock.
    //     Pin two pairs that differ only in slice order.
    #[test]
    fn order_independence() {
        let local_a = vec![vc(0x01, 5), vc(0x02, 3), vc(0x03, 7)];
        let local_b = vec![vc(0x03, 7), vc(0x01, 5), vc(0x02, 3)];

        let incoming_a = vec![vc(0x01, 4), vc(0x02, 3), vc(0x03, 7)];
        let incoming_b = vec![vc(0x02, 3), vc(0x03, 7), vc(0x01, 4)];

        // Same logical clocks; differing slice orders. The boolean
        // verdict must not move with the order.
        assert_eq!(
            is_rollback(&local_a, &incoming_a),
            is_rollback(&local_b, &incoming_b),
            "is_rollback must be order-independent in both arguments"
        );

        // And likewise for the equal-clocks case in both directions.
        let eq_a = vec![vc(0x01, 5), vc(0x02, 3)];
        let eq_b = vec![vc(0x02, 3), vc(0x01, 5)];
        assert_eq!(
            is_rollback(&eq_a, &eq_b),
            is_rollback(&eq_b, &eq_a),
            "equal logical clocks reordered must compare identically"
        );
    }

    #[test]
    fn equal_clocks_not_rollback() {
        let clock = vec![vc(0x01, 5), vc(0x02, 3)];
        assert!(
            !is_rollback(&clock, &clock),
            "identical clocks are not a rollback"
        );
    }

    #[test]
    fn incoming_dominates_not_rollback() {
        let local = vec![vc(0x01, 5), vc(0x02, 3)];
        let incoming = vec![vc(0x01, 6), vc(0x02, 3)]; // ≥ everywhere, > on D1
        assert!(
            !is_rollback(&local, &incoming),
            "incoming strictly dominates local — accept, not rollback"
        );
    }

    #[test]
    fn incoming_strictly_dominated_is_rollback() {
        let local = vec![vc(0x01, 5), vc(0x02, 3)];
        let incoming = vec![vc(0x01, 4), vc(0x02, 3)]; // ≤ everywhere, < on D1
        assert!(
            is_rollback(&local, &incoming),
            "incoming strictly dominated by local — rollback"
        );
    }

    #[test]
    fn incoming_introduces_new_device_not_rollback() {
        let local = vec![vc(0x01, 5)];
        // incoming carries D1 unchanged AND introduces D2 with counter > 0.
        // That's "incoming dominates" (D2's counter is implicitly 0 in local).
        let incoming = vec![vc(0x01, 5), vc(0x02, 1)];
        assert!(
            !is_rollback(&local, &incoming),
            "incoming introducing a new device dominates — not a rollback"
        );
    }

    #[test]
    fn local_introduces_device_incoming_lacks_is_rollback() {
        // local has D1 and D2; incoming has only D1 at the same counter.
        // D2 in incoming is implicitly 0, so any_strictly_less fires.
        // No counter in incoming is strictly more → rollback.
        let local = vec![vc(0x01, 5), vc(0x02, 2)];
        let incoming = vec![vc(0x01, 5)];
        assert!(
            is_rollback(&local, &incoming),
            "incoming missing a device that local has at counter > 0 — rollback"
        );
    }

    #[test]
    fn concurrent_not_rollback() {
        // D1 higher in incoming, D2 higher in local → concurrent.
        let local = vec![vc(0x01, 5), vc(0x02, 4)];
        let incoming = vec![vc(0x01, 6), vc(0x02, 3)];
        assert!(
            !is_rollback(&local, &incoming),
            "concurrent clocks are not a rollback per se — caller will merge"
        );
    }

    #[test]
    fn empty_incoming_against_nonempty_local_is_rollback() {
        let local = vec![vc(0x01, 1)];
        let incoming: Vec<VectorClockEntry> = Vec::new();
        assert!(
            is_rollback(&local, &incoming),
            "empty incoming against local with counter > 0 — rollback"
        );
    }

    #[test]
    fn empty_local_against_any_incoming_not_rollback() {
        let local: Vec<VectorClockEntry> = Vec::new();
        let incoming = vec![vc(0x01, 5), vc(0x02, 3)];
        assert!(
            !is_rollback(&local, &incoming),
            "empty local — any incoming dominates (or is also empty)"
        );

        // And the both-empty edge: equal, not a rollback.
        let empty: Vec<VectorClockEntry> = Vec::new();
        assert!(
            !is_rollback(&empty, &empty),
            "both empty — equal, not a rollback"
        );
    }
}
