//! Block file format: binary header (`docs/vault-format.md` §6.1) and
//! plaintext CBOR body (`docs/vault-format.md` §6.3).
//!
//! This module ships two halves of a block file:
//!
//! 1. [`BlockHeader`] / [`encode_header`] / [`decode_header`] — the
//!    fixed-format big-endian byte layout at the start of a block file.
//!    This module covers the bytes from `magic` through the end of
//!    `vector_clock_entries`. The recipient table (§6.2) and everything
//!    after it (`aead_nonce`, `aead_ct`, signatures) ship in subsequent
//!    build-sequence steps; [`decode_header`] returns the unconsumed
//!    bytes after the vector clock so those steps can pick up where this
//!    one leaves off.
//!
//! 2. [`BlockPlaintext`] / [`encode_plaintext`] / [`decode_plaintext`] —
//!    the canonical-CBOR document that lives inside `aead_ct` (§6.3).
//!    Records are delegated to [`super::record::encode`] /
//!    [`super::record::decode`]; this module only owns the block-level
//!    framing (`block_version`, `block_uuid`, `block_name`,
//!    `schema_version`, the records array, and forward-compat unknowns).
//!
//! The two halves cross-check each other: §6.4 step 9 requires a reader
//! to verify `plaintext.block_uuid == header.block_uuid` after decryption
//! and parse. That cross-check is the *caller's* responsibility (it
//! straddles the encrypt/decrypt layer that lands in a later task);
//! [`BlockError::BlockUuidMismatch`] is defined here so the caller can
//! emit a typed error.
//!
//! ## Canonical CBOR (plaintext only)
//!
//! [`encode_plaintext`] and [`decode_plaintext`] follow the same
//! deterministic encoding profile as [`super::record`]: RFC 8949 §4.2.1
//! with no floats, no tags, no indefinite-length items, no duplicate map
//! keys, and a strict re-encode-and-compare canonical-input gate. See
//! `docs/crypto-design.md` §6.2 for the rule set and [`super::record`]'s
//! module documentation for the rationale of each rule.
//!
//! Forward compatibility (§6.3.2) preserves unknown top-level keys
//! verbatim into [`BlockPlaintext::unknown`]. Unknown keys *inside* a
//! record are handled by [`super::record`].
//!
//! ## Binary header (no forward-compat mechanism)
//!
//! [`BlockHeader`]'s byte layout is rigid per §6.1; it has no
//! forward-compat extension bytes. Length-prefixed fields are limited to
//! what §6.1 spells out (currently just the vector clock). Any change to
//! the header shape requires a `format_version` bump, which v1 readers
//! reject (see [`BlockError::UnsupportedFormatVersion`]).

use std::collections::BTreeMap;

use ciborium::Value;

use crate::version::{FORMAT_VERSION, MAGIC, SUITE_ID};

use super::record::{
    self, Record, RecordError, UnknownValue, RECORD_UUID_LEN,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// File-kind identifier for block files (`docs/vault-format.md` §6.1 line
/// 264; `docs/crypto-design.md` §14 lists the per-file-type kind table).
pub const FILE_KIND_BLOCK: u16 = 0x0003;

/// Vector clock entry on-the-wire size: 16-byte device UUID + u64 counter.
const VECTOR_CLOCK_ENTRY_LEN: usize = 16 + 8;

/// Fixed prefix size of [`BlockHeader`] up to and including `last_mod_ms`.
/// `magic` (4) + `format_version` (2) + `suite_id` (2) + `file_kind` (2) +
/// `vault_uuid` (16) + `block_uuid` (16) + `created_at_ms` (8) +
/// `last_mod_ms` (8) = 58 bytes.
const HEADER_PREFIX_LEN: usize = 4 + 2 + 2 + 2 + 16 + 16 + 8 + 8;

// ---------------------------------------------------------------------------
// CBOR keys (plaintext §6.3)
// ---------------------------------------------------------------------------

const KEY_BLOCK_VERSION: &str = "block_version";
const KEY_BLOCK_UUID: &str = "block_uuid";
const KEY_BLOCK_NAME: &str = "block_name";
const KEY_SCHEMA_VERSION: &str = "schema_version";
const KEY_RECORDS: &str = "records";

/// UUID byte length. Same value as [`record::RECORD_UUID_LEN`]; re-exported
/// here so callers don't have to reach into `record` for the block UUID.
pub const BLOCK_UUID_LEN: usize = RECORD_UUID_LEN;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from block header and plaintext encode / decode.
///
/// Contains both binary-header errors (e.g. [`Self::BadMagic`],
/// [`Self::Truncated`]) and CBOR-plaintext errors (e.g. [`Self::FloatRejected`],
/// [`Self::NonCanonicalEncoding`]). The two share an enum because they
/// share a typical caller (block encode / decode flows touch both halves
/// in sequence) and because keeping them split would force callers to
/// match on two enums for one logical operation.
#[derive(Debug, thiserror::Error)]
pub enum BlockError {
    /// Record-level CBOR error bubbled up from [`super::record::encode`]
    /// or [`super::record::decode`]. Block plaintext delegates record
    /// serialisation to that module rather than reimplementing it; any
    /// error from that layer surfaces here unchanged.
    #[error("record CBOR error: {0}")]
    Record(#[from] RecordError),

    /// `ciborium` returned an I/O or serialisation error during plaintext
    /// encode. Carries the formatted error message because the underlying
    /// `ciborium::ser::Error<E>` is generic over the writer's I/O error
    /// (`std::io::Error` / `core::convert::Infallible`) and so cannot be
    /// uniformly captured as a `#[from]` source. Same justification as
    /// [`RecordError::CborEncode`].
    #[error("CBOR encode error: {0}")]
    CborEncode(String),

    /// `ciborium` returned a parse error during plaintext decode. Same
    /// generic-source justification as [`Self::CborEncode`].
    #[error("CBOR decode error: {0}")]
    CborDecode(String),

    /// File magic did not match `MAGIC` (`"SECR"` big-endian, see
    /// [`crate::version::MAGIC`]).
    #[error("bad magic: expected SECR, got {found:#010x}")]
    BadMagic { found: u32 },

    /// `format_version` did not match [`crate::version::FORMAT_VERSION`].
    /// v1 readers reject foreign versions outright (no forward-compat at
    /// the binary-header layer).
    #[error("unsupported format version: {found}")]
    UnsupportedFormatVersion { found: u16 },

    /// `suite_id` did not match [`crate::version::SUITE_ID`]. Distinct
    /// from format-version mismatch because `suite_id` is per-block and a
    /// future suite (§13) might appear in a v1 vault.
    #[error("unsupported suite id: {found}")]
    UnsupportedSuiteId { found: u16 },

    /// `file_kind` did not match [`FILE_KIND_BLOCK`]. Catches mistaken
    /// attempts to parse a manifest or identity bundle as a block.
    #[error("wrong file kind: expected {expected:#06x}, got {found:#06x}")]
    WrongFileKind { found: u16, expected: u16 },

    /// Decoder ran out of input bytes mid-field. `needed` is the next
    /// chunk's expected size; `got` is the bytes remaining when the read
    /// was attempted.
    #[error("truncated input: needed {needed} bytes, got {got}")]
    Truncated { needed: usize, got: usize },

    /// Vector clock entries were not in ascending lex order by
    /// `device_uuid`. §6.1 requires sorted order on disk so the file
    /// hashes deterministically; the encoder sorts before writing and
    /// the decoder rejects unsorted input rather than silently
    /// re-sorting it.
    #[error("vector clock entries not sorted ascending by device_uuid")]
    VectorClockNotSorted,

    /// Two vector clock entries shared the same `device_uuid`. The vector
    /// clock is a per-device counter map and duplicate keys are
    /// structurally invalid (which device's counter wins?).
    #[error("vector clock contains duplicate device_uuid")]
    VectorClockDuplicateDevice,

    /// `vector_clock_count` (the u16 length prefix) did not match the
    /// number of entries that followed. A truncated input typically
    /// surfaces as [`Self::Truncated`] first; this variant catches
    /// declared lengths that the rest of the file disagrees with — a
    /// signal of intentional tampering or a buggy producer.
    #[error("vector clock count mismatch: declared {declared}, actual {actual}")]
    VectorClockCountMismatch { declared: u16, actual: usize },

    /// Cross-check between the binary header's `block_uuid` and the
    /// plaintext's `block_uuid` (§6.4 step 9) failed. Defined here for
    /// callers that combine [`decode_header`] and [`decode_plaintext`];
    /// neither function emits this on its own.
    #[error("block UUID mismatch between header and plaintext")]
    BlockUuidMismatch {
        header: [u8; BLOCK_UUID_LEN],
        plaintext: [u8; BLOCK_UUID_LEN],
    },

    /// Top-level plaintext CBOR item was not a map. §6.3 mandates a map
    /// at the root.
    #[error("expected top-level CBOR map for block plaintext")]
    NotAMap,

    /// A plaintext map key was not a text string. §6.3 maps use `tstr`
    /// keys throughout.
    #[error("non-string CBOR map key in block plaintext")]
    NonTextKey,

    /// A required plaintext field was absent. The payload is the §6.3
    /// CBOR key name.
    #[error("missing required field in block plaintext: {field}")]
    MissingField { field: &'static str },

    /// A plaintext field had the wrong CBOR type. `expected` describes
    /// the spec shape (e.g. `"text string"`, `"array"`).
    #[error("wrong type for block plaintext field {field}: expected {expected}")]
    WrongType {
        field: &'static str,
        expected: &'static str,
    },

    /// A 16-byte UUID field arrived with the wrong length. Currently
    /// only `block_uuid` triggers this in plaintext.
    #[error("invalid UUID for block plaintext field {field}: expected {BLOCK_UUID_LEN} bytes, got {length}")]
    InvalidUuid {
        field: &'static str,
        length: usize,
    },

    /// An integer plaintext field's value did not fit a `u64` (or `u32`
    /// for `block_version` / `schema_version`). All numeric §6.3 block
    /// fields are unsigned.
    #[error("integer for block plaintext field {field} does not fit its declared width")]
    IntegerOverflow { field: &'static str },

    /// A plaintext map had a duplicate key. RFC 8949 §5.4 forbids
    /// duplicates; the decoder rejects them.
    #[error("duplicate map key in block plaintext: {key}")]
    DuplicateKey { key: String },

    /// Floats are forbidden in v1 block plaintext (canonical CBOR rule,
    /// `docs/crypto-design.md` §6.2 #4). `field` carries the entry-point
    /// hint analogous to [`RecordError::FloatRejected`]: `"<root>"` for
    /// floats found by the top-level walker, finer-grained where the
    /// caller knows more.
    #[error("float values are not permitted in v1 block plaintext (in field {field})")]
    FloatRejected { field: &'static str },

    /// CBOR tags are forbidden in v1 block plaintext (canonical CBOR
    /// rule, `docs/crypto-design.md` §6.2 #4).
    #[error("CBOR tags are not permitted in v1 block plaintext")]
    TagRejected,

    /// The decoded plaintext byte stream was not in canonical form:
    /// re-encoding the parsed representation produced different bytes.
    /// Same set of root causes as [`RecordError::NonCanonicalEncoding`]
    /// (indefinite-length items, key disorder, non-shortest length
    /// prefixes).
    #[error("non-canonical CBOR encoding in block plaintext (e.g. indefinite-length item, key disorder, or non-shortest length)")]
    NonCanonicalEncoding,
}

// ---------------------------------------------------------------------------
// In-memory types
// ---------------------------------------------------------------------------

/// One vector clock entry: a per-device monotonic counter (`docs/vault-format.md`
/// §6.1, `docs/crypto-design.md` §10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VectorClockEntry {
    /// 16-byte device UUID. Stable per device across vault lifetime.
    pub device_uuid: [u8; 16],
    /// Monotonically increasing per-device write counter.
    pub counter: u64,
}

/// Block file binary header (`docs/vault-format.md` §6.1, partial — bytes
/// from `magic` through the end of `vector_clock_entries`).
///
/// Fields after the vector clock (`recipient_count`, `recipient_entries`,
/// `aead_nonce`, `aead_ct_len`, `aead_ct`, `aead_tag`, `author_fingerprint`,
/// signature suffix) live in subsequent build-sequence steps and will be
/// modelled in a wider type that wraps this one.
///
/// All multi-byte integers are big-endian on disk per §6.1 / §14.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    /// File magic — must equal [`crate::version::MAGIC`].
    pub magic: u32,
    /// Format version — must equal [`crate::version::FORMAT_VERSION`].
    pub format_version: u16,
    /// Cipher-suite id — must equal [`crate::version::SUITE_ID`] for
    /// `secretary-v1-pq-hybrid`.
    pub suite_id: u16,
    /// File kind — must equal [`FILE_KIND_BLOCK`].
    pub file_kind: u16,
    /// 16-byte vault UUID; identifies the source vault for sharing
    /// exports (§6.1 line 265).
    pub vault_uuid: [u8; 16],
    /// 16-byte block UUID; cross-checked against
    /// [`BlockPlaintext::block_uuid`] on read (§6.4 step 9).
    pub block_uuid: [u8; 16],
    /// Block creation timestamp, Unix milliseconds.
    pub created_at_ms: u64,
    /// Last-modification timestamp at the block level, Unix milliseconds.
    pub last_mod_ms: u64,
    /// Per-device vector clock for this block. Encoded sorted ascending
    /// by `device_uuid`; the encoder sorts before writing, the decoder
    /// rejects unsorted input.
    pub vector_clock: Vec<VectorClockEntry>,
}

/// Block plaintext — the canonical CBOR document inside `aead_ct`
/// (`docs/vault-format.md` §6.3).
///
/// Numeric widths chosen per §14 / §6.3:
///
/// - `block_version`: u32. §6.3 specifies the value `1`; v1 fits in any
///   width and §14 does not pin a wider type. u32 mirrors `schema_version`
///   for symmetry.
/// - `schema_version`: u32, same rationale.
///
/// Records are not stored as raw CBOR `Value`s here; they are typed
/// [`Record`]s built by [`super::record::decode`]. On encode, each
/// record is canonical-CBOR-encoded by [`super::record::encode`] and the
/// resulting byte string is parsed back into `ciborium::Value` for
/// inclusion in this map. (We can't hand `Record` directly to ciborium
/// because `Record` has its own canonical-encoding rules that ciborium's
/// generic serde path would not respect.)
#[derive(Debug, Clone, PartialEq)]
pub struct BlockPlaintext {
    /// Reserved for future incompatible block-body changes (§6.3 line
    /// 319). v1 emits `1`.
    pub block_version: u32,
    /// 16-byte block UUID; cross-checked against
    /// [`BlockHeader::block_uuid`] (§6.4 step 9).
    pub block_uuid: [u8; BLOCK_UUID_LEN],
    /// User-visible block label (§6.3 line 321). Empty string is
    /// permitted; the spec sets no length cap for v1.
    pub block_name: String,
    /// Record schema version (§6.3 line 322). v1 emits `1`.
    pub schema_version: u32,
    /// Records contained in this block. Encoded order matches in-memory
    /// order (the §6.3 schema models `records` as an ordered array).
    pub records: Vec<Record>,
    /// Forward-compat: top-level CBOR keys not recognised by this version
    /// are preserved verbatim and re-emitted unchanged (§6.3.2). Stored
    /// in a [`BTreeMap`] for deterministic iteration; the canonical-CBOR
    /// sort decides the wire order.
    pub unknown: BTreeMap<String, UnknownValue>,
}

/// Block umbrella combining the binary header and the plaintext body.
///
/// Intentionally incomplete in this build-sequence step: the recipient
/// table, AEAD body, author fingerprint, and dual signatures join in
/// later steps. v1 readers will eventually use a wider type (or extra
/// fields on this one) that owns the full §6.1 byte layout end-to-end.
#[derive(Debug, Clone, PartialEq)]
pub struct Block {
    /// Binary header (§6.1, partial — bytes through `vector_clock_entries`).
    pub header: BlockHeader,
    /// Plaintext CBOR body that lives inside `aead_ct` (§6.3).
    pub plaintext: BlockPlaintext,
}

// ---------------------------------------------------------------------------
// Header encode
// ---------------------------------------------------------------------------

/// Encode a [`BlockHeader`] to its `vault-format.md` §6.1 binary form
/// (bytes from `magic` through the end of `vector_clock_entries`).
///
/// Vector clock entries are sorted ascending by `device_uuid` before
/// emission (§6.1). Duplicate `device_uuid`s are rejected here rather
/// than silently coalesced — a duplicate is structurally invalid and
/// likely indicates a caller bug.
pub fn encode_header(header: &BlockHeader) -> Result<Vec<u8>, BlockError> {
    let mut sorted: Vec<VectorClockEntry> = header.vector_clock.clone();
    sorted.sort_by(|a, b| a.device_uuid.cmp(&b.device_uuid));
    // Detect duplicates after sorting — adjacent equal device_uuids.
    for w in sorted.windows(2) {
        if w[0].device_uuid == w[1].device_uuid {
            return Err(BlockError::VectorClockDuplicateDevice);
        }
    }
    let count = u16::try_from(sorted.len())
        .map_err(|_| BlockError::IntegerOverflow {
            field: "vector_clock_count",
        })?;

    let mut out = Vec::with_capacity(
        HEADER_PREFIX_LEN + 2 + sorted.len() * VECTOR_CLOCK_ENTRY_LEN,
    );
    out.extend_from_slice(&header.magic.to_be_bytes());
    out.extend_from_slice(&header.format_version.to_be_bytes());
    out.extend_from_slice(&header.suite_id.to_be_bytes());
    out.extend_from_slice(&header.file_kind.to_be_bytes());
    out.extend_from_slice(&header.vault_uuid);
    out.extend_from_slice(&header.block_uuid);
    out.extend_from_slice(&header.created_at_ms.to_be_bytes());
    out.extend_from_slice(&header.last_mod_ms.to_be_bytes());

    out.extend_from_slice(&count.to_be_bytes());
    for entry in &sorted {
        out.extend_from_slice(&entry.device_uuid);
        out.extend_from_slice(&entry.counter.to_be_bytes());
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Header decode
// ---------------------------------------------------------------------------

/// Decode a [`BlockHeader`] from `bytes`, returning the parsed header
/// alongside the trailing byte slice (which Task 4 consumes for the
/// recipient table and beyond).
///
/// Validates:
///
/// 1. `magic == MAGIC`, `format_version == FORMAT_VERSION`,
///    `suite_id == SUITE_ID`, `file_kind == FILE_KIND_BLOCK`.
/// 2. Sufficient input length at every field boundary
///    ([`BlockError::Truncated`]).
/// 3. Vector clock entries sorted ascending by `device_uuid`
///    ([`BlockError::VectorClockNotSorted`]).
/// 4. No duplicate `device_uuid`s ([`BlockError::VectorClockDuplicateDevice`]).
/// 5. The declared `vector_clock_count` matches the actual entry count
///    consumed ([`BlockError::VectorClockCountMismatch`] — a structural
///    invariant that pairs with the truncation check).
///
/// Does not validate cross-references to plaintext (e.g. the §6.4 step 9
/// `block_uuid` check), which require decryption.
pub fn decode_header(bytes: &[u8]) -> Result<(BlockHeader, &[u8]), BlockError> {
    let mut pos = 0;

    let magic = read_u32_be(bytes, &mut pos)?;
    if magic != MAGIC {
        return Err(BlockError::BadMagic { found: magic });
    }
    let format_version = read_u16_be(bytes, &mut pos)?;
    if format_version != FORMAT_VERSION {
        return Err(BlockError::UnsupportedFormatVersion {
            found: format_version,
        });
    }
    let suite_id = read_u16_be(bytes, &mut pos)?;
    if suite_id != SUITE_ID {
        return Err(BlockError::UnsupportedSuiteId { found: suite_id });
    }
    let file_kind = read_u16_be(bytes, &mut pos)?;
    if file_kind != FILE_KIND_BLOCK {
        return Err(BlockError::WrongFileKind {
            found: file_kind,
            expected: FILE_KIND_BLOCK,
        });
    }
    let vault_uuid = read_array::<16>(bytes, &mut pos)?;
    let block_uuid = read_array::<16>(bytes, &mut pos)?;
    let created_at_ms = read_u64_be(bytes, &mut pos)?;
    let last_mod_ms = read_u64_be(bytes, &mut pos)?;

    let vector_clock_count = read_u16_be(bytes, &mut pos)?;
    let count_usize = vector_clock_count as usize;
    let needed = count_usize
        .checked_mul(VECTOR_CLOCK_ENTRY_LEN)
        .ok_or(BlockError::IntegerOverflow {
            field: "vector_clock_entries",
        })?;
    let available = bytes.len().saturating_sub(pos);
    if available < needed {
        return Err(BlockError::Truncated {
            needed,
            got: available,
        });
    }

    let mut vector_clock: Vec<VectorClockEntry> = Vec::with_capacity(count_usize);
    for _ in 0..count_usize {
        let device_uuid = read_array::<16>(bytes, &mut pos)?;
        let counter = read_u64_be(bytes, &mut pos)?;
        vector_clock.push(VectorClockEntry {
            device_uuid,
            counter,
        });
    }

    // Defence-in-depth: the loop bound was the declared count, so this
    // can only mismatch if a future edit drifts the loop body. Cheap
    // check, kept for spec-conformance assertions.
    if vector_clock.len() != count_usize {
        return Err(BlockError::VectorClockCountMismatch {
            declared: vector_clock_count,
            actual: vector_clock.len(),
        });
    }

    // Spec requires sorted ascending; reject unsorted rather than
    // silently re-sorting (matches `bundle_file::decode`'s strict-mode
    // posture).
    for w in vector_clock.windows(2) {
        match w[0].device_uuid.cmp(&w[1].device_uuid) {
            std::cmp::Ordering::Less => {}
            std::cmp::Ordering::Equal => {
                return Err(BlockError::VectorClockDuplicateDevice);
            }
            std::cmp::Ordering::Greater => {
                return Err(BlockError::VectorClockNotSorted);
            }
        }
    }

    let header = BlockHeader {
        magic,
        format_version,
        suite_id,
        file_kind,
        vault_uuid,
        block_uuid,
        created_at_ms,
        last_mod_ms,
        vector_clock,
    };
    Ok((header, &bytes[pos..]))
}

// ---------------------------------------------------------------------------
// Header byte-reader helpers
// ---------------------------------------------------------------------------

fn read_u16_be(bytes: &[u8], pos: &mut usize) -> Result<u16, BlockError> {
    let arr = read_array::<2>(bytes, pos)?;
    Ok(u16::from_be_bytes(arr))
}

fn read_u32_be(bytes: &[u8], pos: &mut usize) -> Result<u32, BlockError> {
    let arr = read_array::<4>(bytes, pos)?;
    Ok(u32::from_be_bytes(arr))
}

fn read_u64_be(bytes: &[u8], pos: &mut usize) -> Result<u64, BlockError> {
    let arr = read_array::<8>(bytes, pos)?;
    Ok(u64::from_be_bytes(arr))
}

fn read_array<const N: usize>(bytes: &[u8], pos: &mut usize) -> Result<[u8; N], BlockError> {
    let available = bytes.len().saturating_sub(*pos);
    if available < N {
        return Err(BlockError::Truncated {
            needed: N,
            got: available,
        });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[*pos..*pos + N]);
    *pos += N;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Plaintext encode
// ---------------------------------------------------------------------------

/// Canonical CBOR encoding of a [`BlockPlaintext`] (§6.3 + canonical-CBOR
/// rules from §6.2). Output is deterministic: `encode_plaintext(p)`
/// produces the same bytes on every call.
///
/// Records are serialised one-at-a-time via [`super::record::encode`]
/// then parsed into `ciborium::Value` for inclusion in this map. The
/// extra parse step is intentional: we must not bypass `record::encode`'s
/// canonical-encoding discipline, but ciborium's writer takes a `Value`
/// tree, so we materialise each record's canonical bytes and re-read them.
pub fn encode_plaintext(plaintext: &BlockPlaintext) -> Result<Vec<u8>, BlockError> {
    let entries = plaintext_to_entries(plaintext)?;
    encode_canonical_map(&entries)
}

fn plaintext_to_entries(
    plaintext: &BlockPlaintext,
) -> Result<Vec<(Value, Value)>, BlockError> {
    // Initial known-fields list. A `vec![]` literal here (rather than
    // `Vec::new()` + sequential pushes) satisfies clippy's
    // `vec_init_then_push` lint, which fires when more than three items
    // are pushed in a row immediately after construction. `record.rs`
    // interleaves a conditional push so the lint doesn't trigger there;
    // here every known field is unconditional, so the literal is the
    // idiomatic choice.
    let mut entries: Vec<(Value, Value)> = vec![
        (
            Value::Text(KEY_BLOCK_VERSION.into()),
            Value::Integer(u64::from(plaintext.block_version).into()),
        ),
        (
            Value::Text(KEY_BLOCK_UUID.into()),
            Value::Bytes(plaintext.block_uuid.to_vec()),
        ),
        (
            Value::Text(KEY_BLOCK_NAME.into()),
            Value::Text(plaintext.block_name.clone()),
        ),
        (
            Value::Text(KEY_SCHEMA_VERSION.into()),
            Value::Integer(u64::from(plaintext.schema_version).into()),
        ),
        (
            Value::Text(KEY_RECORDS.into()),
            records_to_value(&plaintext.records)?,
        ),
    ];

    // Forward-compat: splice unknowns alongside known keys. The canonical
    // sort step in encode_canonical_map decides the final byte order, so
    // it does not matter whether unknowns are pushed before or after the
    // known entries. Mirrors `record::record_to_entries`.
    for (k, v) in &plaintext.unknown {
        entries.push((Value::Text(k.clone()), unknown_to_value(v)?));
    }

    Ok(entries)
}

/// Encode each record via [`super::record::encode`] and re-parse the
/// resulting bytes as a `Value` so they can join the outer map. The
/// extra serialise/parse round-trip is the price of keeping
/// `record::encode` as the sole authority on record CBOR shape.
///
/// Performance hook: if profiling shows this on a hot path (Task 4
/// onwards will bench AEAD-encrypted block writes), introduce a
/// `pub(crate) fn record::record_to_value` and `value_to_record` that
/// skip the byte round-trip. Defer until measurements warrant it.
fn records_to_value(records: &[Record]) -> Result<Value, BlockError> {
    let mut items: Vec<Value> = Vec::with_capacity(records.len());
    for r in records {
        let bytes = record::encode(r)?;
        let val: Value = ciborium::de::from_reader(bytes.as_slice())
            .map_err(|e| BlockError::CborDecode(e.to_string()))?;
        items.push(val);
    }
    Ok(Value::Array(items))
}

/// Convert an [`UnknownValue`] back to a `ciborium::Value` for splicing
/// into the outer map. Goes through the public canonical-CBOR
/// serialisation so we don't depend on `UnknownValue`'s private wrapped
/// field — keeps that abstraction intact across crate boundaries.
fn unknown_to_value(u: &UnknownValue) -> Result<Value, BlockError> {
    let bytes = u.to_canonical_cbor()?;
    let val: Value = ciborium::de::from_reader(bytes.as_slice())
        .map_err(|e| BlockError::CborDecode(e.to_string()))?;
    Ok(val)
}

/// Encode an entry list as a top-level canonical-CBOR map. Mirror of
/// [`super::record`]'s `encode_canonical_map`; the duplication is a
/// deliberate trade-off — sharing the helper would require parameterising
/// over the error type or moving the helper to a third module, both of
/// which add more code than two ~10-line copies. The two implementations
/// must stay in lockstep on the canonical-sort algorithm; if one is
/// updated, update the other.
fn encode_canonical_map(entries: &[(Value, Value)]) -> Result<Vec<u8>, BlockError> {
    // We sort first because `ciborium` emits a `Value::Map`'s `Vec<(Value, Value)>`
    // in iteration order, NOT in CBOR canonical order. `canonical_sort_entries`
    // re-orders against materialised CBOR-encoded key bytes (length-then-bytewise
    // per RFC 8949 §4.2.1) so the wire output is canonical.
    let sorted = canonical_sort_entries(entries)?;
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&Value::Map(sorted), &mut buf)
        .map_err(|e| BlockError::CborEncode(e.to_string()))?;
    Ok(buf)
}

/// Sort entries by canonical CBOR encoding of their keys. Mirror of
/// [`super::record`]'s `canonical_sort_entries`; see notes there for the
/// algorithmic detail.
fn canonical_sort_entries(
    entries: &[(Value, Value)],
) -> Result<Vec<(Value, Value)>, BlockError> {
    let mut materialised: Vec<(Vec<u8>, (Value, Value))> = entries
        .iter()
        .map(|pair| {
            let mut key_bytes = Vec::new();
            ciborium::ser::into_writer(&pair.0, &mut key_bytes)
                .map_err(|e| BlockError::CborEncode(e.to_string()))?;
            Ok((key_bytes, pair.clone()))
        })
        .collect::<Result<_, BlockError>>()?;
    materialised.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(materialised.into_iter().map(|(_, pair)| pair).collect())
}

// ---------------------------------------------------------------------------
// Plaintext decode
// ---------------------------------------------------------------------------

/// Strict canonical-CBOR decoder for a block plaintext (§6.3).
///
/// Validates the same rules as [`super::record::decode`]:
///
/// 1. Top-level item is a map.
/// 2. All map keys are text strings.
/// 3. No floats anywhere in the tree.
/// 4. No CBOR tags anywhere in the tree.
/// 5. No duplicate map keys at any level.
/// 6. All required §6.3 block fields are present with their spec types.
/// 7. Each entry of `records` is itself a canonical record (delegates to
///    [`super::record::decode`]).
/// 8. The bytes are themselves canonical (re-encode-and-compare).
///
/// Forward-compat unknown keys are preserved into [`BlockPlaintext::unknown`].
/// Cross-checking the plaintext's `block_uuid` against a sibling header
/// (§6.4 step 9) is the *caller's* responsibility — see
/// [`BlockError::BlockUuidMismatch`].
pub fn decode_plaintext(bytes: &[u8]) -> Result<BlockPlaintext, BlockError> {
    let parsed: Value = ciborium::de::from_reader(bytes)
        .map_err(|e| BlockError::CborDecode(e.to_string()))?;

    // Walk the tree to enforce no-float / no-tag everywhere (including
    // forward-compat unknowns and inside record maps). Doing this once
    // up front means the per-field decoders don't re-check.
    reject_floats_and_tags(&parsed, "<root>")?;

    let map = match parsed {
        Value::Map(m) => m,
        _ => return Err(BlockError::NotAMap),
    };

    let plaintext = parse_plaintext_map(map)?;

    // Strict canonical-input check: re-encode and compare. Mirrors
    // `record::decode`. Catches indefinite-length items, non-canonical
    // map key order, and non-shortest length / integer prefixes.
    let re_encoded = encode_plaintext(&plaintext)?;
    if re_encoded.as_slice() != bytes {
        return Err(BlockError::NonCanonicalEncoding);
    }

    Ok(plaintext)
}

/// Walk a `Value` tree and reject floats and tags. Mirror of
/// [`super::record`]'s walker; kept separate so the error type is
/// `BlockError` without plumbing a generic. The walkers must stay in
/// lockstep — if one gains a new permitted variant, the other must too.
///
/// Termination relies on `ciborium`'s default `from_reader` recursion
/// limit (256), same as record's walker. See record.rs's walker doc for
/// the dependency note.
fn reject_floats_and_tags(v: &Value, field_hint: &'static str) -> Result<(), BlockError> {
    match v {
        Value::Float(_) => Err(BlockError::FloatRejected { field: field_hint }),
        Value::Tag(_, _) => Err(BlockError::TagRejected),
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

fn parse_plaintext_map(map: Vec<(Value, Value)>) -> Result<BlockPlaintext, BlockError> {
    let mut block_version: Option<u32> = None;
    let mut block_uuid: Option<[u8; BLOCK_UUID_LEN]> = None;
    let mut block_name: Option<String> = None;
    let mut schema_version: Option<u32> = None;
    let mut records: Option<Vec<Record>> = None;
    let mut unknown: BTreeMap<String, UnknownValue> = BTreeMap::new();
    let mut seen_keys: BTreeMap<String, ()> = BTreeMap::new();

    for (k, v) in map {
        let key = match k {
            Value::Text(s) => s,
            _ => return Err(BlockError::NonTextKey),
        };
        if seen_keys.insert(key.clone(), ()).is_some() {
            return Err(BlockError::DuplicateKey { key });
        }
        match key.as_str() {
            KEY_BLOCK_VERSION => {
                block_version = Some(take_u32(v, KEY_BLOCK_VERSION)?);
            }
            KEY_BLOCK_UUID => {
                block_uuid = Some(take_uuid(v, KEY_BLOCK_UUID)?);
            }
            KEY_BLOCK_NAME => {
                block_name = Some(take_text(v, KEY_BLOCK_NAME)?);
            }
            KEY_SCHEMA_VERSION => {
                schema_version = Some(take_u32(v, KEY_SCHEMA_VERSION)?);
            }
            KEY_RECORDS => {
                records = Some(take_records(v)?);
            }
            _ => {
                // Forward-compat: any other key is preserved verbatim.
                // The float/tag walker at the top of decode_plaintext()
                // has already vetted v's subtree.
                unknown.insert(key, value_to_unknown(v)?);
            }
        }
    }

    Ok(BlockPlaintext {
        block_version: block_version.ok_or(BlockError::MissingField {
            field: KEY_BLOCK_VERSION,
        })?,
        block_uuid: block_uuid.ok_or(BlockError::MissingField {
            field: KEY_BLOCK_UUID,
        })?,
        block_name: block_name.ok_or(BlockError::MissingField {
            field: KEY_BLOCK_NAME,
        })?,
        schema_version: schema_version.ok_or(BlockError::MissingField {
            field: KEY_SCHEMA_VERSION,
        })?,
        records: records.ok_or(BlockError::MissingField {
            field: KEY_RECORDS,
        })?,
        unknown,
    })
}

/// Decode each `records` array entry by re-serialising it and feeding the
/// bytes to [`super::record::decode`]. Same justification as
/// [`records_to_value`]: keep `record::decode` the sole authority on
/// record CBOR shape, even at the cost of a serialise/parse round-trip
/// per record. Same performance-hook note applies — see [`records_to_value`].
fn take_records(v: Value) -> Result<Vec<Record>, BlockError> {
    let items = match v {
        Value::Array(a) => a,
        _ => {
            return Err(BlockError::WrongType {
                field: KEY_RECORDS,
                expected: "array",
            })
        }
    };
    let mut out: Vec<Record> = Vec::with_capacity(items.len());
    for item in items {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&item, &mut buf)
            .map_err(|e| BlockError::CborEncode(e.to_string()))?;
        let r = record::decode(&buf)?;
        out.push(r);
    }
    Ok(out)
}

/// Convert an unknown `Value` subtree back into an [`UnknownValue`]. We
/// don't have a public `UnknownValue::from_value(Value)` constructor by
/// design (UnknownValue's wrapped field is private), so we round-trip
/// through canonical CBOR — which also re-validates no-float / no-tag.
fn value_to_unknown(v: Value) -> Result<UnknownValue, BlockError> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&v, &mut buf)
        .map_err(|e| BlockError::CborEncode(e.to_string()))?;
    let u = UnknownValue::from_canonical_cbor(&buf)?;
    Ok(u)
}

fn take_text(v: Value, field: &'static str) -> Result<String, BlockError> {
    match v {
        Value::Text(s) => Ok(s),
        _ => Err(BlockError::WrongType {
            field,
            expected: "text string",
        }),
    }
}

fn take_u32(v: Value, field: &'static str) -> Result<u32, BlockError> {
    let i = match v {
        Value::Integer(i) => i,
        _ => {
            return Err(BlockError::WrongType {
                field,
                expected: "unsigned integer",
            })
        }
    };
    let as_u64: u64 = i
        .try_into()
        .map_err(|_| BlockError::IntegerOverflow { field })?;
    u32::try_from(as_u64).map_err(|_| BlockError::IntegerOverflow { field })
}

fn take_uuid(v: Value, field: &'static str) -> Result<[u8; BLOCK_UUID_LEN], BlockError> {
    let bytes = match v {
        Value::Bytes(b) => b,
        _ => {
            return Err(BlockError::WrongType {
                field,
                expected: "byte string",
            })
        }
    };
    let length = bytes.len();
    bytes
        .try_into()
        .map_err(|_: Vec<u8>| BlockError::InvalidUuid { field, length })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::record::{RecordField, RecordFieldValue};

    /// Smoke test: build a minimal [`BlockHeader`] and a minimal
    /// [`BlockPlaintext`] (one record), encode and decode each, assert
    /// equality, and manually cross-check `header.block_uuid ==
    /// plaintext.block_uuid` (the §6.4 step 9 invariant that is the
    /// caller's responsibility, not the encoder/decoder's).
    ///
    /// Comprehensive tests for negative paths (bad magic, truncation,
    /// unsorted vector clock, non-canonical CBOR, forward-compat unknown
    /// preservation, etc.) ship in the build-sequence step that adds the
    /// full test corpus.
    #[test]
    fn smoke_block_header_and_plaintext_roundtrip() {
        let block_uuid: [u8; BLOCK_UUID_LEN] = [0x42; BLOCK_UUID_LEN];

        // ---- Header --------------------------------------------------
        let header = BlockHeader {
            magic: MAGIC,
            format_version: FORMAT_VERSION,
            suite_id: SUITE_ID,
            file_kind: FILE_KIND_BLOCK,
            vault_uuid: [0x11; 16],
            block_uuid,
            created_at_ms: 1_714_060_800_000,
            last_mod_ms: 1_714_060_800_500,
            vector_clock: vec![
                VectorClockEntry {
                    device_uuid: [0xaa; 16],
                    counter: 7,
                },
                VectorClockEntry {
                    device_uuid: [0x33; 16],
                    counter: 1,
                },
            ],
        };
        let header_bytes = encode_header(&header).expect("encode_header");
        let (decoded_header, rest) =
            decode_header(&header_bytes).expect("decode_header");
        assert!(rest.is_empty(), "decode_header must consume all bytes");

        // The encoder sorts vector_clock, so the decoded form has the
        // sorted order. Build the expected post-sort header for the
        // equality check.
        let mut expected_header = header.clone();
        expected_header
            .vector_clock
            .sort_by(|a, b| a.device_uuid.cmp(&b.device_uuid));
        assert_eq!(decoded_header, expected_header);

        // ---- Plaintext ----------------------------------------------
        let mut fields = BTreeMap::new();
        fields.insert(
            "username".to_string(),
            RecordField {
                value: RecordFieldValue::Text("alice".to_string()),
                last_mod: 1_714_060_800_000,
                device_uuid: [0xaa; RECORD_UUID_LEN],
                unknown: BTreeMap::new(),
            },
        );
        let one_record = Record {
            record_uuid: [0xcd; RECORD_UUID_LEN],
            record_type: "login".to_string(),
            fields,
            tags: Vec::new(),
            created_at_ms: 1_714_060_800_000,
            last_mod_ms: 1_714_060_800_001,
            tombstone: false,
            unknown: BTreeMap::new(),
        };

        let plaintext = BlockPlaintext {
            block_version: 1,
            block_uuid,
            block_name: "personal".to_string(),
            schema_version: 1,
            records: vec![one_record],
            unknown: BTreeMap::new(),
        };
        let plaintext_bytes =
            encode_plaintext(&plaintext).expect("encode_plaintext");
        let decoded_plaintext =
            decode_plaintext(&plaintext_bytes).expect("decode_plaintext");
        assert_eq!(decoded_plaintext, plaintext);

        // ---- Cross-check --------------------------------------------
        // §6.4 step 9: the caller must verify these match. Encoder and
        // decoder do not do it on their own (the check straddles the
        // header/AEAD boundary). Mirror the caller's responsibility here.
        assert_eq!(decoded_header.block_uuid, decoded_plaintext.block_uuid);
    }
}
