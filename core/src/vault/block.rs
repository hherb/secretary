//! Block file format: binary header (`docs/vault-format.md` §6.1),
//! recipient table (§6.2), AEAD body (§6.1 + §6.3), trailing hybrid
//! signature suffix (§6.1 / §8), and the on-disk [`BlockFile`] composite.
//!
//! This module ships these pieces:
//!
//! 1. [`BlockHeader`] / [`encode_header`] / [`decode_header`] — the
//!    fixed-format big-endian byte layout at the start of a block file
//!    (bytes from `magic` through the end of `vector_clock_entries`).
//!    [`decode_header`] returns the unconsumed bytes after the vector
//!    clock so the recipient-table decoder can pick up from there.
//!
//! 2. [`RecipientWrap`] / [`encode_recipient_table`] /
//!    [`decode_recipient_table`] — the §6.2 recipient table (1208 bytes
//!    per entry) wrapping a per-recipient hybrid-KEM ciphertext over the
//!    Block Content Key. Recipients are sorted ascending by fingerprint
//!    on encode and rejected if unsorted on decode (mirroring the vector
//!    clock invariant).
//!
//! 3. [`BlockPlaintext`] / [`encode_plaintext`] / [`decode_plaintext`] —
//!    the canonical-CBOR document that lives inside `aead_ct` (§6.3).
//!    Records are delegated to [`super::record::encode`] /
//!    [`super::record::decode`]; this module only owns the block-level
//!    framing (`block_version`, `block_uuid`, `block_name`,
//!    `schema_version`, the records array, and forward-compat unknowns).
//!
//! 4. [`BlockFile`] / [`encode_block_file`] / [`decode_block_file`] /
//!    [`encrypt_block`] / [`decrypt_block`] — the on-disk composite
//!    type (header + recipients + AEAD body + trailing hybrid signature
//!    suffix) and the high-level encrypt and decrypt orchestrators.
//!    The signature suffix is `author_fingerprint (16) || sig_ed_len (u16
//!    BE) || sig_ed (64) || sig_pq_len (u16 BE) || sig_pq` per §6.1.
//!    The signed message is the bytes from `magic` through `aead_tag`
//!    inclusive, with the role-tag prefix [`crate::crypto::kdf::TAG_BLOCK_SIG`]
//!    added by [`crate::crypto::sig::sign`] (and stripped by
//!    [`crate::crypto::sig::verify`]).
//!
//! The §6.4 step 9 cross-check (`plaintext.block_uuid == header.block_uuid`)
//! is enforced by [`decrypt_block`]. [`BlockError::BlockUuidMismatch`]
//! surfaces a header-vs-plaintext mismatch as a typed error distinct from
//! corruption. Likewise [`BlockError::AuthorFingerprintMismatch`]
//! surfaces a §6.4 step 6 cross-check between the on-disk
//! `author_fingerprint` and the expected sender's fingerprint.
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

use std::collections::{BTreeMap, BTreeSet};

use ciborium::Value;
use rand_core::{CryptoRng, RngCore};

use crate::crypto::aead::{self, AeadError, AeadKey, AeadNonce, AEAD_TAG_LEN};
use crate::crypto::kem::{self, HybridWrap, KemError, ML_KEM_768_CT_LEN, X25519_PK_LEN};
use crate::crypto::secret::Sensitive;
use zeroize::Zeroize as _;
use crate::crypto::sig::{
    self, Ed25519Public, Ed25519Secret, HybridSig, MlDsa65Public, MlDsa65Secret, MlDsa65Sig,
    SigError, SigRole, ED25519_SIG_LEN,
};
use crate::identity::fingerprint::Fingerprint;
use crate::version::{FORMAT_VERSION, MAGIC, SUITE_ID};

use super::canonical::{encode_canonical_map, reject_floats_and_tags, CanonicalError};
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
    /// plaintext's `block_uuid` (§6.4 step 9) failed. Emitted by
    /// [`decrypt_block`] after a successful AEAD-decrypt and CBOR parse.
    #[error("block UUID mismatch between header and plaintext")]
    BlockUuidMismatch {
        header: [u8; BLOCK_UUID_LEN],
        plaintext: [u8; BLOCK_UUID_LEN],
    },

    /// Recipient table contained two entries with the same
    /// `recipient_fingerprint`. Per §6.2 every recipient appears exactly
    /// once. Strict reject on both encode (defensive — caller bug) and
    /// decode (tampering or buggy producer).
    #[error("duplicate recipient fingerprint in recipient table")]
    DuplicateRecipient { fingerprint: Fingerprint },

    /// Recipient table was empty. §6.2 requires the owner to always be a
    /// recipient, so a zero-recipient block is structurally invalid.
    #[error("empty recipient list (every block must have at least one recipient)")]
    EmptyRecipientList,

    /// Recipient count exceeded the u16 length-prefix limit imposed by
    /// the §6.1 wire format. `count` is the caller-supplied recipient
    /// list length.
    #[error("too many recipients: {count} (max u16::MAX)")]
    TooManyRecipients { count: usize },

    /// Recipient table arrived with entries not sorted ascending by
    /// `recipient_fingerprint`. §6.2 fixes the on-disk order; the encoder
    /// sorts before writing and the decoder rejects unsorted input rather
    /// than silently re-sorting it (mirrors the vector-clock posture).
    #[error("recipient entries not sorted ascending by recipient_fingerprint")]
    RecipientsNotSorted,

    /// A recipient entry's `hybrid_kem_ct_pq` field was not exactly
    /// [`crate::crypto::kem::ML_KEM_768_CT_LEN`] (1088) bytes. The on-disk wire
    /// form pins this length per §6.2; the in-memory [`HybridWrap`] uses
    /// `Vec<u8>` so producers can in principle build a wrong-length one
    /// in memory. Encode rejects so the wire stays well-formed.
    #[error("ML-KEM-768 ciphertext wrong length: expected {ML_KEM_768_CT_LEN}, got {found}")]
    RecipientCtPqWrongLength { found: usize },

    /// A recipient entry's `wrap_ct` (the AEAD-wrapped Block Content Key,
    /// 32-byte ciphertext + 16-byte Poly1305 tag = 48 bytes) was not
    /// exactly 48 bytes. Same shape as [`Self::RecipientCtPqWrongLength`]:
    /// the wire pins the length per §6.2 but the in-memory
    /// [`HybridWrap::ct_w`] is `Vec<u8>` so a hand-built recipient could
    /// in principle be wrong-shaped. Encode rejects so the wire stays
    /// well-formed and the §6.2 split between `wrap_ct` and `wrap_tag`
    /// is unambiguous.
    #[error("recipient wrap_ct wrong length: expected 48, got {found}")]
    RecipientCtWrongLength { found: usize },

    /// The reading user's fingerprint was not present in the block's
    /// recipient table. Per §6.4 this is a distinct UI condition ("this
    /// block is not shared with you") from corruption.
    #[error("not a recipient of this block")]
    NotARecipient { fingerprint: Fingerprint },

    /// AEAD-decrypt of the block body failed (§6.1 / §6.4 step 4–5).
    /// Position-specific: this variant is reserved for the *block body*
    /// AEAD operation. Other AEAD positions (e.g. recipient-wrap unwrap
    /// inside [`crate::crypto::kem::decap`], future manifest decrypts) get their
    /// own variants per the PR #1 review discipline — there is no
    /// blanket `From<AeadError>` impl beyond this one.
    #[error("block body AEAD failure: {0}")]
    Aead(#[from] AeadError),

    /// Hybrid-KEM encap or decap (§7) failed during [`encrypt_block`] or
    /// [`decrypt_block`]. Surfaces every §7.1 failure mode (wrong key,
    /// tampered wrap, tampered pk-bundle, wrong block UUID) as the same
    /// generic error — same discipline as [`crate::crypto::kem::KemError`].
    #[error("hybrid-KEM error: {0}")]
    Kem(#[from] KemError),

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

    /// Hybrid signature sign or verify failed — for the *block-hybrid-sig
    /// position only*. §6.1 places exactly one hybrid signature on a
    /// block file (`sig_ed` + `sig_pq` immediately after `aead_tag`); this
    /// variant represents that one position. Other future signature
    /// positions (manifest sig per §10, contact-card self-sig per §6)
    /// will get their own variants per the PR #1 review-fix `97af857`
    /// discipline — there is no blanket `From<SigError>` impl beyond the
    /// `#[from]` here, which only fires inside this module.
    #[error("block signature error: {0}")]
    Sig(#[from] SigError),

    /// On-disk `sig_ed_len` (the u16 BE length prefix immediately before
    /// the Ed25519 signature bytes) was not [`ED25519_SIG_LEN`] (64).
    /// §6.1 / §14 fix the Ed25519 signature length; this variant catches
    /// both decode-side wire-format violations and (defensively) any
    /// encode-side mismatch should the upstream type alias ever change.
    #[error("sig_ed wrong length: expected {ED25519_SIG_LEN}, got {found}")]
    SigEdWrongLength { found: usize },
    /// `sig_pq_len` would not fit a u16 on encode. The §6.1 wire-format
    /// `sig_pq_len` field is u16 BE, capping the on-disk PQ signature at
    /// `u16::MAX`. ML-DSA-65 signatures are 3309 bytes so this is a
    /// defensive bound; a future suite migration to a PQ scheme with a
    /// larger signature would need a wider length field and a suite bump.
    #[error("sig_pq too long for u16 length prefix: {found}")]
    SigPqTooLong { found: usize },

    /// On-disk `sig_pq_len` was not [`crate::crypto::sig::ML_DSA_65_SIG_LEN`]
    /// (3309). §6.1 / §14 fix the ML-DSA-65 signature length under suite
    /// `secretary-v1-pq-hybrid`. Mirrors [`Self::SigEdWrongLength`]: a
    /// wire-format length violation is a parse error, not a sign / verify
    /// failure, and gets its own variant rather than being collapsed into
    /// [`Self::Sig`] (same discipline as the Task 4 fix `7fa9a7b` that
    /// introduced [`Self::RecipientCtWrongLength`] rather than reusing
    /// [`Self::Aead`]).
    #[error(
        "sig_pq wrong length: expected {}, got {found}",
        crate::crypto::sig::ML_DSA_65_SIG_LEN
    )]
    SigPqWrongLength { found: usize },

    /// On-disk `author_fingerprint` did not match the expected sender's
    /// fingerprint passed to [`decrypt_block`] (§6.4 step 6). Distinct
    /// from corruption and from signature-verify failure: this means the
    /// block claims a different author than the caller is expecting,
    /// which the UI should surface as "wrong sender" rather than as
    /// "tampered file".
    #[error(
        "author fingerprint mismatch: expected {expected:02x?}, found {found:02x?}"
    )]
    AuthorFingerprintMismatch {
        expected: Fingerprint,
        found: Fingerprint,
    },

    /// [`decode_block_file`] found bytes after the trailing signature
    /// suffix. The §6.1 file format has a fixed-length suffix; any bytes
    /// after `sig_pq` are corruption (or wire-format extension by a
    /// future suite that the v1 reader does not understand). Strict
    /// reject — the v1 spec defines no forward-compat trailing fields.
    #[error("trailing bytes after signature suffix: {count}")]
    TrailingBytes { count: usize },
}

/// Lift a [`CanonicalError`] from the shared
/// [`crate::vault::canonical`] helpers into the block-layer error
/// surface, preserving the pre-extraction variant shape verbatim. The
/// public [`BlockError`] surface stays bit-identical to its
/// pre-refactor shape so existing pattern-matches on
/// [`BlockError::FloatRejected`] / [`BlockError::TagRejected`] /
/// [`BlockError::CborEncode`] keep matching after the helpers were
/// pulled out into the shared module. The `field` hint on
/// `CanonicalError::TagRejected` is intentionally discarded here because
/// the original `BlockError::TagRejected` did not carry one — the
/// `From` is a behaviour-preserving bridge, not a surface enrichment.
impl From<CanonicalError> for BlockError {
    fn from(e: CanonicalError) -> Self {
        match e {
            CanonicalError::CborEncode(s) => BlockError::CborEncode(s),
            CanonicalError::FloatRejected { field } => BlockError::FloatRejected { field },
            CanonicalError::TagRejected { .. } => BlockError::TagRejected,
        }
    }
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
/// signature suffix) are modelled by [`BlockFile`] which wraps this header
/// alongside the recipient table, AEAD body, and the trailing hybrid
/// signature suffix.
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

/// Per-recipient hybrid-KEM wrap as it appears in the §6.2 recipient
/// table.
///
/// Pairs the 16-byte [`Fingerprint`] (the recipient's contact-card short
/// id, used to look up the right entry on read) with the four-field
/// [`HybridWrap`] produced by [`crate::crypto::kem::encap`].
///
/// Wire form is [`RECIPIENT_ENTRY_LEN`] (1208) bytes per §6.2:
///
/// ```text
/// recipient_fingerprint (16)
/// hybrid_kem_ct_x       (32)         ; wrap.ct_x
/// hybrid_kem_ct_pq      (1088)       ; wrap.ct_pq (must be exactly 1088)
/// wrap_nonce            (24)         ; wrap.nonce_w
/// wrap_ct               (32)         ; first 32 bytes of wrap.ct_w
/// wrap_tag              (16)         ; trailing 16 bytes of wrap.ct_w
/// ```
///
/// In memory we keep `wrap.ct_w` as one 48-byte buffer (matching
/// [`HybridWrap`]); the wire layout is only assembled at encode time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientWrap {
    /// 16-byte recipient contact-card fingerprint (§6.1).
    pub recipient_fingerprint: Fingerprint,
    /// The four-field hybrid-KEM wrap (§7) produced by
    /// [`crate::crypto::kem::encap`].
    pub wrap: HybridWrap,
}

/// Recipient public-key handle for [`encrypt_block`].
///
/// Borrows from the caller (no copies of the 1184-byte ML-KEM-768 public
/// key) and mirrors the parameter shape of [`crate::crypto::kem::encap`]: the
/// canonical `pk_bundle` bytes plus the parsed X25519 / ML-KEM-768 public
/// keys. The [`Fingerprint`] is the recipient's contact-card short id —
/// the same value that lands in [`RecipientWrap::recipient_fingerprint`]
/// on the wire.
#[derive(Debug)]
pub struct RecipientPublicKeys<'a> {
    /// 16-byte recipient contact-card fingerprint (§6.1).
    pub fingerprint: Fingerprint,
    /// Canonical CBOR pk-bundle bytes for the recipient's contact card,
    /// fed into the §7 HKDF combiner.
    pub pk_bundle: &'a [u8],
    /// Recipient's X25519 public key.
    pub x25519_pk: &'a kem::X25519Public,
    /// Recipient's ML-KEM-768 public (encapsulation) key.
    pub ml_kem_768_pk: &'a kem::MlKem768Public,
}

/// On-disk block file representation (`docs/vault-format.md` §6.1).
///
/// Wraps the header (§6.1), recipient table (§6.2), AEAD body section
/// (§6.1, `aead_nonce` / `aead_ct` / `aead_tag`), and the trailing hybrid
/// signature suffix (§6.1, `author_fingerprint` plus the
/// length-prefixed `sig_ed` / `sig_pq` pair).
///
/// [`BlockPlaintext`] is the *opened* (decrypted) form of the body;
/// [`BlockFile`] is the on-disk form. They are intentionally distinct
/// types: a [`BlockFile`] never holds plaintext, and [`encrypt_block`] /
/// [`decrypt_block`] are the only conversion paths between the two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockFile {
    /// Binary header (§6.1, bytes from `magic` through end of
    /// `vector_clock_entries`).
    pub header: BlockHeader,
    /// Recipient table (§6.2). Stored sorted ascending by
    /// `recipient_fingerprint` (the encode/decode roundtrip enforces this).
    pub recipients: Vec<RecipientWrap>,
    /// 24-byte XChaCha20 nonce for the body AEAD.
    pub aead_nonce: [u8; 24],
    /// AEAD ciphertext of the canonical-CBOR plaintext (§6.3), *without*
    /// the trailing 16-byte Poly1305 tag. The tag is held separately
    /// because §6.1 splits them on the wire (`aead_ct` is variable-length,
    /// `aead_tag` is a fixed 16-byte field). Length equals the plaintext
    /// length.
    pub aead_ct: Vec<u8>,
    /// 16-byte Poly1305 authentication tag for the body AEAD.
    pub aead_tag: [u8; AEAD_TAG_LEN],
    /// 16-byte fingerprint of the block author's contact card (§6.1).
    /// Cross-checked against the expected sender on read
    /// ([`BlockError::AuthorFingerprintMismatch`]).
    pub author_fingerprint: Fingerprint,
    /// Hybrid (Ed25519 + ML-DSA-65) signature over the bytes from `magic`
    /// through `aead_tag` inclusive, with the [`SigRole::Block`] role tag
    /// prepended internally by [`crate::crypto::sig::sign`] (§8 / §6.5
    /// step 7). Verified before hybrid-decap on read (§6.4 step 6–7).
    pub sig: HybridSig,
}

/// Wire-form byte length of one recipient table entry (§6.2): exactly
/// 16 + 32 + 1088 + 24 + 32 + 16 = 1208.
pub const RECIPIENT_ENTRY_LEN: usize =
    16 + X25519_PK_LEN + ML_KEM_768_CT_LEN + 24 + 32 + AEAD_TAG_LEN;

const _: () = {
    // Spec-conformance assertion: §6.2 fixes 1208 bytes per entry. Any
    // change to one of the size constants this expression sums must be
    // matched by a §6.2 spec amendment.
    assert!(RECIPIENT_ENTRY_LEN == 1208);
};

const _: () = {
    // Spec-conformance assertion: §6.1 / §14 pin the Ed25519 signature
    // length at 64 bytes; the wire `sig_ed_len` field declares the same
    // value. Any future widening of [`ED25519_SIG_LEN`] in
    // `crypto::sig` would invalidate the §6.1 wire format and must
    // surface as a loud compile failure here, mirroring the
    // `RECIPIENT_ENTRY_LEN` assertion.
    assert!(ED25519_SIG_LEN == 64);
};

const _: () = {
    // Spec-conformance assertion: §6.1 / §14 pin the ML-DSA-65 signature
    // length at 3309 bytes under suite v1 (`secretary-v1-pq-hybrid`,
    // §1.3 / FIPS 204). decode_signature_suffix length-checks the wire
    // sig_pq_len against this constant; if the upstream value ever
    // shifts, this assertion catches it before runtime.
    assert!(crate::crypto::sig::ML_DSA_65_SIG_LEN == 3309);
};

const _: () = {
    // Spec-conformance assertion: §6.1 vector_clock entry layout is
    // (device_uuid: 16) || (counter: u64 = 8) = 24 bytes. The encoder
    // writes per-entry length unconditionally; pinning it here guards
    // against an inadvertent shape change.
    assert!(VECTOR_CLOCK_ENTRY_LEN == 24);
};

const _: () = {
    // Spec-conformance assertion: §6.1 fixed-size header prefix is
    // magic(4) + format_version(2) + suite_id(2) + file_kind(2) +
    // vault_uuid(16) + block_uuid(16) + created_at_ms(8) +
    // last_mod_ms(8) = 58 bytes, before the variable vector_clock
    // section begins. Encoder pre-allocates against this; pinning here
    // guards against silent header growth.
    assert!(HEADER_PREFIX_LEN == 58);
};

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
    Ok(encode_canonical_map(&entries)?)
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

// `encode_canonical_map` and `canonical_sort_entries` live in
// [`crate::vault::canonical`] so block / record / manifest share one
// implementation. The shared helpers return a [`CanonicalError`]; the
// `From<CanonicalError> for BlockError` impl above lifts those errors
// to the existing block-layer variants so the public surface stays
// unchanged.

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

// `reject_floats_and_tags` lives in [`crate::vault::canonical`]; see the
// `From<CanonicalError> for BlockError` impl above for how its
// `FloatRejected` / `TagRejected` errors map back to the block-layer
// variants without changing the public surface.

fn parse_plaintext_map(map: Vec<(Value, Value)>) -> Result<BlockPlaintext, BlockError> {
    let mut block_version: Option<u32> = None;
    let mut block_uuid: Option<[u8; BLOCK_UUID_LEN]> = None;
    let mut block_name: Option<String> = None;
    let mut schema_version: Option<u32> = None;
    let mut records: Option<Vec<Record>> = None;
    let mut unknown: BTreeMap<String, UnknownValue> = BTreeMap::new();
    let mut seen_keys: BTreeSet<String> = BTreeSet::new();

    for (k, v) in map {
        let key = match k {
            Value::Text(s) => s,
            _ => return Err(BlockError::NonTextKey),
        };
        if !seen_keys.insert(key.clone()) {
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
// Recipient table encode / decode (§6.2)
// ---------------------------------------------------------------------------

/// Serialize one [`RecipientWrap`] to its [`RECIPIENT_ENTRY_LEN`] (1208)
/// byte wire form per §6.2. Rejects a wrap whose `ct_pq` is not exactly
/// [`ML_KEM_768_CT_LEN`] (1088) bytes or whose `ct_w` is not exactly
/// `BCK length + AEAD_TAG_LEN` (32 + 16 = 48) bytes — both of those are
/// invariants of [`HybridWrap`] from a well-formed [`crate::crypto::kem::encap`]
/// call, but a hand-constructed wrap could violate them, so we check.
fn encode_recipient(r: &RecipientWrap) -> Result<Vec<u8>, BlockError> {
    if r.wrap.ct_pq.len() != ML_KEM_768_CT_LEN {
        return Err(BlockError::RecipientCtPqWrongLength {
            found: r.wrap.ct_pq.len(),
        });
    }
    // ct_w = wrap_ct (32 bytes BCK ciphertext) || wrap_tag (16 bytes
    // Poly1305). Reject any other length so the on-disk split is
    // unambiguous. Position-specific error: this is a recipient-table
    // wire-format violation, not a body-AEAD failure, so it gets its
    // own variant rather than abusing BlockError::Aead.
    if r.wrap.ct_w.len() != kem::BLOCK_CONTENT_KEY_LEN + AEAD_TAG_LEN {
        return Err(BlockError::RecipientCtWrongLength {
            found: r.wrap.ct_w.len(),
        });
    }

    let mut out = Vec::with_capacity(RECIPIENT_ENTRY_LEN);
    out.extend_from_slice(&r.recipient_fingerprint);
    out.extend_from_slice(&r.wrap.ct_x);
    out.extend_from_slice(&r.wrap.ct_pq);
    out.extend_from_slice(&r.wrap.nonce_w);
    // ct_w is already (wrap_ct || wrap_tag); the on-disk split is purely
    // a wire-format presentation, the two are concatenated again on
    // read for AEAD-decrypt. Here we just emit the same bytes.
    out.extend_from_slice(&r.wrap.ct_w);
    debug_assert_eq!(out.len(), RECIPIENT_ENTRY_LEN);
    Ok(out)
}

/// Parse one §6.2 recipient entry from a [`RECIPIENT_ENTRY_LEN`]-byte
/// slice. Strict length check; the caller (`decode_recipient_table`) is
/// responsible for slicing the table into the correct chunks first.
fn decode_recipient(bytes: &[u8]) -> Result<RecipientWrap, BlockError> {
    if bytes.len() != RECIPIENT_ENTRY_LEN {
        return Err(BlockError::Truncated {
            needed: RECIPIENT_ENTRY_LEN,
            got: bytes.len(),
        });
    }
    let mut pos = 0;
    let recipient_fingerprint = read_array::<16>(bytes, &mut pos)?;
    let ct_x = read_array::<X25519_PK_LEN>(bytes, &mut pos)?;
    let ct_pq = bytes[pos..pos + ML_KEM_768_CT_LEN].to_vec();
    pos += ML_KEM_768_CT_LEN;
    let nonce_w = read_array::<24>(bytes, &mut pos)?;
    // wrap_ct (32) || wrap_tag (16) = 48 bytes ct_w as kem.rs holds it.
    let ct_w = bytes[pos..pos + kem::BLOCK_CONTENT_KEY_LEN + AEAD_TAG_LEN].to_vec();
    pos += kem::BLOCK_CONTENT_KEY_LEN + AEAD_TAG_LEN;
    debug_assert_eq!(pos, RECIPIENT_ENTRY_LEN);

    Ok(RecipientWrap {
        recipient_fingerprint,
        wrap: HybridWrap {
            ct_x,
            ct_pq,
            nonce_w,
            ct_w,
        },
    })
}

/// Serialize the recipient table to its §6.1 / §6.2 wire form:
/// `recipient_count` (u16 BE) followed by `recipient_count × 1208` bytes
/// of entries.
///
/// Sorts entries ascending by `recipient_fingerprint` before emission
/// (defensive — don't trust caller order). Rejects the empty list
/// ([`BlockError::EmptyRecipientList`]: §6.2 requires the owner is
/// always a recipient), duplicate fingerprints
/// ([`BlockError::DuplicateRecipient`]), and counts beyond
/// [`u16::MAX`] ([`BlockError::TooManyRecipients`]: the wire-format
/// length prefix is u16).
pub fn encode_recipient_table(
    recipients: &[RecipientWrap],
) -> Result<Vec<u8>, BlockError> {
    if recipients.is_empty() {
        return Err(BlockError::EmptyRecipientList);
    }
    if recipients.len() > u16::MAX as usize {
        return Err(BlockError::TooManyRecipients {
            count: recipients.len(),
        });
    }

    let mut sorted: Vec<RecipientWrap> = recipients.to_vec();
    sorted.sort_by(|a, b| a.recipient_fingerprint.cmp(&b.recipient_fingerprint));
    for w in sorted.windows(2) {
        if w[0].recipient_fingerprint == w[1].recipient_fingerprint {
            return Err(BlockError::DuplicateRecipient {
                fingerprint: w[0].recipient_fingerprint,
            });
        }
    }

    // Length narrowing safe: bounds-checked above.
    let count = sorted.len() as u16;
    let mut out = Vec::with_capacity(2 + sorted.len() * RECIPIENT_ENTRY_LEN);
    out.extend_from_slice(&count.to_be_bytes());
    for r in &sorted {
        out.extend_from_slice(&encode_recipient(r)?);
    }
    Ok(out)
}

/// Parse the §6.2 recipient table from `bytes`, returning the parsed
/// [`Vec<RecipientWrap>`] alongside the trailing byte slice (which the
/// AEAD-body decoder then consumes).
///
/// Validates:
///
/// 1. Sufficient input length at the count prefix and the entry array
///    ([`BlockError::Truncated`]).
/// 2. Each entry parses as a well-formed [`RecipientWrap`].
/// 3. Entries arrive sorted ascending by `recipient_fingerprint`
///    ([`BlockError::RecipientsNotSorted`] — strict, mirrors the vector
///    clock posture).
/// 4. No duplicate fingerprints
///    ([`BlockError::DuplicateRecipient`]).
/// 5. Non-empty table ([`BlockError::EmptyRecipientList`]).
pub fn decode_recipient_table(
    bytes: &[u8],
) -> Result<(Vec<RecipientWrap>, &[u8]), BlockError> {
    let mut pos = 0;
    let count = read_u16_be(bytes, &mut pos)?;
    let count_usize = count as usize;
    if count_usize == 0 {
        return Err(BlockError::EmptyRecipientList);
    }
    let needed = count_usize
        .checked_mul(RECIPIENT_ENTRY_LEN)
        .ok_or(BlockError::TooManyRecipients { count: count_usize })?;
    let available = bytes.len().saturating_sub(pos);
    if available < needed {
        return Err(BlockError::Truncated {
            needed,
            got: available,
        });
    }

    let mut recipients: Vec<RecipientWrap> = Vec::with_capacity(count_usize);
    for _ in 0..count_usize {
        let entry_bytes = &bytes[pos..pos + RECIPIENT_ENTRY_LEN];
        recipients.push(decode_recipient(entry_bytes)?);
        pos += RECIPIENT_ENTRY_LEN;
    }

    // Strict-mode: must be sorted ascending and unique.
    for w in recipients.windows(2) {
        match w[0].recipient_fingerprint.cmp(&w[1].recipient_fingerprint) {
            std::cmp::Ordering::Less => {}
            std::cmp::Ordering::Equal => {
                return Err(BlockError::DuplicateRecipient {
                    fingerprint: w[0].recipient_fingerprint,
                });
            }
            std::cmp::Ordering::Greater => {
                return Err(BlockError::RecipientsNotSorted);
            }
        }
    }

    Ok((recipients, &bytes[pos..]))
}

// ---------------------------------------------------------------------------
// AEAD body encode / decode (§6.1)
// ---------------------------------------------------------------------------

/// Serialize the AEAD body section (§6.1, bytes from `aead_nonce`
/// through `aead_tag` inclusive). The `plaintext_len` length prefix is
/// the *plaintext* length — the AEAD ciphertext (without the tag) — not
/// `aead_ct.len() + AEAD_TAG_LEN`. See [`BlockFile::aead_ct`] for the
/// split rationale.
fn encode_aead_section(block: &BlockFile) -> Result<Vec<u8>, BlockError> {
    let ct_len_u32 = u32::try_from(block.aead_ct.len()).map_err(|_| {
        BlockError::IntegerOverflow {
            field: "aead_ct_len",
        }
    })?;
    let mut out = Vec::with_capacity(24 + 4 + block.aead_ct.len() + AEAD_TAG_LEN);
    out.extend_from_slice(&block.aead_nonce);
    out.extend_from_slice(&ct_len_u32.to_be_bytes());
    out.extend_from_slice(&block.aead_ct);
    out.extend_from_slice(&block.aead_tag);
    Ok(out)
}

/// Parsed §6.1 AEAD section: nonce, ciphertext, and tag, plus the
/// trailing byte slice. Internal-use struct for [`decode_aead_section`];
/// the public surface returns these fields as part of [`BlockFile`].
struct AeadSection<'a> {
    aead_nonce: [u8; 24],
    aead_ct: Vec<u8>,
    aead_tag: [u8; AEAD_TAG_LEN],
    rest: &'a [u8],
}

/// Parse the AEAD body section from `bytes`, returning the parsed
/// fields plus the trailing slice.
///
/// Strict on lengths: a declared `aead_ct_len` larger than the
/// remaining input surfaces as [`BlockError::Truncated`], not as a
/// later AEAD-decrypt failure (so the diagnostic points at the actual
/// problem).
fn decode_aead_section(bytes: &[u8]) -> Result<AeadSection<'_>, BlockError> {
    let mut pos = 0;
    let aead_nonce = read_array::<24>(bytes, &mut pos)?;
    let aead_ct_len = read_u32_be(bytes, &mut pos)? as usize;

    let available = bytes.len().saturating_sub(pos);
    let needed = aead_ct_len
        .checked_add(AEAD_TAG_LEN)
        .ok_or(BlockError::IntegerOverflow {
            field: "aead_ct_len",
        })?;
    if available < needed {
        return Err(BlockError::Truncated {
            needed,
            got: available,
        });
    }

    let aead_ct = bytes[pos..pos + aead_ct_len].to_vec();
    pos += aead_ct_len;
    let aead_tag = read_array::<AEAD_TAG_LEN>(bytes, &mut pos)?;
    Ok(AeadSection {
        aead_nonce,
        aead_ct,
        aead_tag,
        rest: &bytes[pos..],
    })
}

// ---------------------------------------------------------------------------
// Signature suffix encode / decode (§6.1)
// ---------------------------------------------------------------------------

/// Serialize the §6.1 trailing hybrid-signature suffix:
/// `author_fingerprint (16) || sig_ed_len (u16 BE) || sig_ed (64) ||
/// sig_pq_len (u16 BE) || sig_pq`.
///
/// `sig_ed_len` is hard-validated against [`ED25519_SIG_LEN`] (64). The
/// type alias [`Ed25519Sig`](crate::crypto::sig::Ed25519Sig) is
/// `[u8; 64]` so a [`HybridSig`] always carries a 64-byte `sig_ed`, but
/// the check belongs here for future-proofing if the alias ever changes
/// shape. `sig_pq_len` is bounded by `u16::MAX`; the spec does not pin
/// the PQ signature length on the wire (only [`ED25519_SIG_LEN`] is
/// fixed), so we only enforce the length-prefix's u16 ceiling rather
/// than [`crate::crypto::sig::ML_DSA_65_SIG_LEN`].
fn encode_signature_suffix(
    author: &Fingerprint,
    sig: &HybridSig,
) -> Result<Vec<u8>, BlockError> {
    if sig.sig_ed.len() != ED25519_SIG_LEN {
        return Err(BlockError::SigEdWrongLength {
            found: sig.sig_ed.len(),
        });
    }
    let sig_pq_bytes = sig.sig_pq.as_bytes();
    if sig_pq_bytes.len() > u16::MAX as usize {
        return Err(BlockError::SigPqTooLong {
            found: sig_pq_bytes.len(),
        });
    }
    // Length narrowings safe — both bounds-checked above.
    let sig_ed_len_u16 = sig.sig_ed.len() as u16;
    let sig_pq_len_u16 = sig_pq_bytes.len() as u16;

    let mut out = Vec::with_capacity(
        16 + 2 + sig.sig_ed.len() + 2 + sig_pq_bytes.len(),
    );
    out.extend_from_slice(author);
    out.extend_from_slice(&sig_ed_len_u16.to_be_bytes());
    out.extend_from_slice(&sig.sig_ed);
    out.extend_from_slice(&sig_pq_len_u16.to_be_bytes());
    out.extend_from_slice(sig_pq_bytes);
    Ok(out)
}

/// Parse the §6.1 trailing hybrid-signature suffix from `bytes`,
/// returning `(author_fingerprint, sig, &remaining)` where `&remaining`
/// is the slice after the suffix. End-of-file in v1 leaves `remaining`
/// empty; [`decode_block_file`] enforces that with
/// [`BlockError::TrailingBytes`].
///
/// Validates `sig_ed_len == ED25519_SIG_LEN` strictly and rejects
/// truncated input at every field boundary.
fn decode_signature_suffix(
    bytes: &[u8],
) -> Result<(Fingerprint, HybridSig, &[u8]), BlockError> {
    let mut pos = 0;
    let author = read_array::<16>(bytes, &mut pos)?;
    let sig_ed_len = read_u16_be(bytes, &mut pos)? as usize;
    if sig_ed_len != ED25519_SIG_LEN {
        return Err(BlockError::SigEdWrongLength { found: sig_ed_len });
    }
    let sig_ed = read_array::<ED25519_SIG_LEN>(bytes, &mut pos)?;

    let sig_pq_len = read_u16_be(bytes, &mut pos)? as usize;
    // §6.1 / §14 pin sig_pq at ML_DSA_65_SIG_LEN (3309) under suite
    // secretary-v1-pq-hybrid. Reject a wire-format length mismatch
    // before reading the bytes, as a parse error — same shape as the
    // SigEdWrongLength check above. Letting MlDsa65Sig::from_bytes
    // surface this as SigError::InvalidSignatureLength via the Sig
    // variant would conflate parse errors with sign / verify failures
    // and break symmetry with SigEdWrongLength (PR #1 review-fix
    // 97af857 / Task 4 fix 7fa9a7b discipline).
    if sig_pq_len != crate::crypto::sig::ML_DSA_65_SIG_LEN {
        return Err(BlockError::SigPqWrongLength { found: sig_pq_len });
    }
    let available = bytes.len().saturating_sub(pos);
    if available < sig_pq_len {
        return Err(BlockError::Truncated {
            needed: sig_pq_len,
            got: available,
        });
    }
    let sig_pq_bytes = bytes[pos..pos + sig_pq_len].to_vec();
    pos += sig_pq_len;

    // MlDsa65Sig::from_bytes hard-pins length at ML_DSA_65_SIG_LEN; the
    // earlier wire-format check makes this defensive (cannot fire today)
    // but it stays as the construction path for the typed wrapper.
    let sig_pq = MlDsa65Sig::from_bytes(&sig_pq_bytes)?;

    Ok((author, HybridSig { sig_ed, sig_pq }, &bytes[pos..]))
}

// ---------------------------------------------------------------------------
// Full BlockFile encode / decode
// ---------------------------------------------------------------------------

/// Serialize a [`BlockFile`] to its complete §6.1 wire form (bytes from
/// `magic` through `sig_pq` inclusive — header, recipient table, AEAD
/// body, and the trailing hybrid-signature suffix).
pub fn encode_block_file(block: &BlockFile) -> Result<Vec<u8>, BlockError> {
    let header_bytes = encode_header(&block.header)?;
    let recipient_bytes = encode_recipient_table(&block.recipients)?;
    let aead_bytes = encode_aead_section(block)?;
    let sig_bytes = encode_signature_suffix(&block.author_fingerprint, &block.sig)?;

    let mut out = Vec::with_capacity(
        header_bytes.len() + recipient_bytes.len() + aead_bytes.len() + sig_bytes.len(),
    );
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&recipient_bytes);
    out.extend_from_slice(&aead_bytes);
    out.extend_from_slice(&sig_bytes);
    Ok(out)
}

/// Parse a complete [`BlockFile`] from `bytes` (header, recipient table,
/// AEAD body, signature suffix). Rejects any trailing bytes after the
/// signature suffix with [`BlockError::TrailingBytes`] — the §6.1 file
/// format is fixed-length-suffix and v1 defines no forward-compat
/// trailing fields.
pub fn decode_block_file(bytes: &[u8]) -> Result<BlockFile, BlockError> {
    let (header, rest) = decode_header(bytes)?;
    let (recipients, rest) = decode_recipient_table(rest)?;
    let aead = decode_aead_section(rest)?;
    let (author_fingerprint, sig, rest) = decode_signature_suffix(aead.rest)?;
    if !rest.is_empty() {
        return Err(BlockError::TrailingBytes { count: rest.len() });
    }
    Ok(BlockFile {
        header,
        recipients,
        aead_nonce: aead.aead_nonce,
        aead_ct: aead.aead_ct,
        aead_tag: aead.aead_tag,
        author_fingerprint,
        sig,
    })
}

// ---------------------------------------------------------------------------
// Orchestrators: encrypt_block / decrypt_block (§6.4 / §6.5)
// ---------------------------------------------------------------------------

/// Build the AEAD AAD for the block body: the on-disk bytes from `magic`
/// through end of `recipient_entries` (§6.1). Computed by re-encoding the
/// header and recipient table — the same bytes the writer just emitted,
/// or that the reader just parsed. Wraps both in one buffer so both
/// encrypt and decrypt sides feed the AEAD identical AAD.
fn build_body_aad(
    header: &BlockHeader,
    recipients: &[RecipientWrap],
) -> Result<Vec<u8>, BlockError> {
    let header_bytes = encode_header(header)?;
    let recipient_bytes = encode_recipient_table(recipients)?;
    let mut aad = Vec::with_capacity(header_bytes.len() + recipient_bytes.len());
    aad.extend_from_slice(&header_bytes);
    aad.extend_from_slice(&recipient_bytes);
    Ok(aad)
}

/// Build the signed-message bytes for the §6.1 / §8 block hybrid
/// signature: the on-disk bytes from `magic` through `aead_tag`
/// inclusive — i.e. everything before the signature suffix starts.
/// Mirrors [`build_body_aad`] in shape: re-encode the header and
/// recipient table, then concatenate the AEAD section.
///
/// Critical: do NOT prepend [`crate::crypto::kdf::TAG_BLOCK_SIG`] here.
/// [`crate::crypto::sig::sign`] / [`crate::crypto::sig::verify`] add the
/// role-tag prefix internally (see [`SigRole::tag`]). Doing it again
/// here would double-tag and break round-trip verification.
fn signed_message_bytes(
    header: &BlockHeader,
    recipients: &[RecipientWrap],
    aead_nonce: &[u8; 24],
    aead_ct: &[u8],
    aead_tag: &[u8; AEAD_TAG_LEN],
) -> Result<Vec<u8>, BlockError> {
    let header_bytes = encode_header(header)?;
    let recipient_bytes = encode_recipient_table(recipients)?;
    let ct_len_u32 =
        u32::try_from(aead_ct.len()).map_err(|_| BlockError::IntegerOverflow {
            field: "aead_ct_len",
        })?;
    let mut out = Vec::with_capacity(
        header_bytes.len()
            + recipient_bytes.len()
            + 24
            + 4
            + aead_ct.len()
            + AEAD_TAG_LEN,
    );
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&recipient_bytes);
    out.extend_from_slice(aead_nonce);
    out.extend_from_slice(&ct_len_u32.to_be_bytes());
    out.extend_from_slice(aead_ct);
    out.extend_from_slice(aead_tag);
    Ok(out)
}

/// Build a complete on-disk [`BlockFile`] from a header, a plaintext, and
/// the recipient list (§6.5).
///
/// Steps (mirroring §6.5 1–7):
///
/// 1. Generate a fresh 32-byte Block Content Key from `rng`.
/// 2. For each recipient, [`crate::crypto::kem::encap`] wraps the BCK against
///    the recipient's public-key bundle, producing one [`RecipientWrap`].
/// 3. Sort the recipient table ascending by fingerprint (handled inside
///    [`encode_recipient_table`], which re-runs at AAD-build time).
/// 4. Generate a fresh 24-byte AEAD nonce from `rng`.
/// 5. Canonical-CBOR-encode the plaintext (§6.3).
/// 6. AEAD-encrypt the plaintext under the BCK, with AAD = bytes
///    `magic..end_of_recipient_entries`. The returned `ct || tag` is
///    split into the wire-form `aead_ct` (variable-length) and `aead_tag`
///    (fixed 16 bytes).
/// 7. Compute the §8 hybrid signature over the bytes from `magic`
///    through `aead_tag` inclusive (the role-tag prefix is added by
///    [`crate::crypto::sig::sign`]). The author of the block is the
///    sender, so [`BlockFile::author_fingerprint`] = `sender_card_fingerprint`.
///
/// `rng` is consumed for the BCK, every per-recipient encap, and the
/// body AEAD nonce — in production pass `rand_core::OsRng`. Hybrid
/// signing is deterministic (RFC 8032 Ed25519 + ML-DSA hedged-deterministic),
/// so no extra RNG draws happen at the sign step.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_block<R: RngCore + CryptoRng>(
    rng: &mut R,
    header: &BlockHeader,
    plaintext: &BlockPlaintext,
    sender_card_fingerprint: &Fingerprint,
    sender_pk_bundle: &[u8],
    sender_ed_sk: &Ed25519Secret,
    sender_pq_sk: &MlDsa65Secret,
    recipients: &[RecipientPublicKeys<'_>],
) -> Result<BlockFile, BlockError> {
    if recipients.is_empty() {
        // Catch the empty case here too — `encode_recipient_table` would
        // also catch it, but reporting before doing per-recipient work
        // makes the diagnostic match the §6.2 invariant directly.
        return Err(BlockError::EmptyRecipientList);
    }

    // Step 1: fresh BCK.
    let mut bck_bytes = [0u8; kem::BLOCK_CONTENT_KEY_LEN];
    rng.fill_bytes(&mut bck_bytes);
    let bck = Sensitive::new(bck_bytes);
    // The original stack copy still holds the BCK; zero it before frame
    // reuse so the secret only lives inside `bck`. Same pattern as
    // `crypto::kem::derive_wrap_key`.
    bck_bytes.zeroize();

    // Step 2: per-recipient encap.
    let mut wraps: Vec<RecipientWrap> = Vec::with_capacity(recipients.len());
    for r in recipients {
        let wrap = kem::encap(
            rng,
            sender_card_fingerprint,
            &r.fingerprint,
            sender_pk_bundle,
            r.pk_bundle,
            r.x25519_pk,
            r.ml_kem_768_pk,
            &header.block_uuid,
            &bck,
        )?;
        wraps.push(RecipientWrap {
            recipient_fingerprint: r.fingerprint,
            wrap,
        });
    }

    // Step 3: sort + dedup are handled inside encode_recipient_table.
    // We sort `wraps` here too so that the recipient list inside the
    // returned BlockFile matches what would be emitted on disk byte-
    // for-byte, and so the AAD computed below matches.
    wraps.sort_by(|a, b| a.recipient_fingerprint.cmp(&b.recipient_fingerprint));
    for w in wraps.windows(2) {
        if w[0].recipient_fingerprint == w[1].recipient_fingerprint {
            return Err(BlockError::DuplicateRecipient {
                fingerprint: w[0].recipient_fingerprint,
            });
        }
    }

    // Step 4: fresh AEAD nonce.
    let mut aead_nonce: AeadNonce = [0u8; 24];
    rng.fill_bytes(&mut aead_nonce);

    // Step 5: canonical-CBOR plaintext.
    let pt_bytes = encode_plaintext(plaintext)?;

    // Step 6: AAD = bytes magic..end_of_recipient_entries; AEAD-encrypt.
    let aad = build_body_aad(header, &wraps)?;
    let mut bck_key_bytes = *bck.expose();
    let bck_key: AeadKey = Sensitive::new(bck_key_bytes);
    bck_key_bytes.zeroize();
    let ct_with_tag = aead::encrypt(&bck_key, &aead_nonce, &aad, &pt_bytes)?;
    debug_assert_eq!(ct_with_tag.len(), pt_bytes.len() + AEAD_TAG_LEN);

    // Split (ct || tag) into aead_ct (variable) and aead_tag (16).
    let split_at = ct_with_tag.len() - AEAD_TAG_LEN;
    let aead_ct = ct_with_tag[..split_at].to_vec();
    let mut aead_tag = [0u8; AEAD_TAG_LEN];
    aead_tag.copy_from_slice(&ct_with_tag[split_at..]);

    // Step 7 (§6.5 step 7): hybrid-sign the bytes from `magic` through
    // `aead_tag` inclusive. crypto::sig::sign prepends TAG_BLOCK_SIG
    // internally — passing it here would double-tag.
    let m = signed_message_bytes(header, &wraps, &aead_nonce, &aead_ct, &aead_tag)?;
    let sig = sig::sign(SigRole::Block, &m, sender_ed_sk, sender_pq_sk)?;

    Ok(BlockFile {
        header: header.clone(),
        recipients: wraps,
        aead_nonce,
        aead_ct,
        aead_tag,
        author_fingerprint: *sender_card_fingerprint,
        sig,
    })
}

/// Open a [`BlockFile`] and return the decrypted [`BlockPlaintext`]
/// (§6.4).
///
/// Steps (§6.4 1–9):
///
/// 1. Cross-check `block.author_fingerprint == sender_card_fingerprint`
///    (§6.4 step 6 — "look up author_fingerprint to obtain verification
///    keys"). Mismatch → [`BlockError::AuthorFingerprintMismatch`].
/// 2. Hybrid-verify the §8 signature over the bytes from `magic`
///    through `aead_tag` inclusive (§6.4 step 7). Failure →
///    [`BlockError::Sig`]. Verify happens BEFORE hybrid-decap so a
///    forged file is rejected before any secret-key operation runs.
/// 3. Locate the reader's entry by `reader_card_fingerprint` lookup
///    against the recipient table. Missing → [`BlockError::NotARecipient`].
/// 4. Hybrid-decap that entry to recover the BCK
///    ([`crate::crypto::kem::decap`]).
/// 5. Compute AAD = bytes from `magic` through end of `recipient_entries`.
/// 6. AEAD-decrypt `aead_ct || aead_tag` under the BCK with that AAD.
///    Failure surfaces as [`BlockError::Aead`] (position-specific to
///    the block body).
/// 7. Parse the plaintext as canonical CBOR ([`decode_plaintext`]).
/// 8. Cross-check `plaintext.block_uuid == header.block_uuid`
///    ([`BlockError::BlockUuidMismatch`]).
#[allow(clippy::too_many_arguments)]
pub fn decrypt_block(
    block: &BlockFile,
    sender_card_fingerprint: &Fingerprint,
    sender_pk_bundle: &[u8],
    sender_ed_pk: &Ed25519Public,
    sender_pq_pk: &MlDsa65Public,
    reader_card_fingerprint: &Fingerprint,
    reader_pk_bundle: &[u8],
    reader_x_sk: &kem::X25519Secret,
    reader_pq_sk: &kem::MlKem768Secret,
) -> Result<BlockPlaintext, BlockError> {
    // Step 1: author fingerprint cross-check (§6.4 step 6). Reject
    // before any signature- or KEM-related work to make the diagnostic
    // point at the actual problem (wrong sender, not bad signature).
    if &block.author_fingerprint != sender_card_fingerprint {
        return Err(BlockError::AuthorFingerprintMismatch {
            expected: *sender_card_fingerprint,
            found: block.author_fingerprint,
        });
    }

    // Step 2: hybrid-verify the §8 block signature. Done BEFORE
    // hybrid-decap so a tampered/forged file never causes a private-key
    // operation to run. crypto::sig::verify prepends TAG_BLOCK_SIG
    // internally — passing it here would double-tag and break verify.
    let m = signed_message_bytes(
        &block.header,
        &block.recipients,
        &block.aead_nonce,
        &block.aead_ct,
        &block.aead_tag,
    )?;
    sig::verify(SigRole::Block, &m, &block.sig, sender_ed_pk, sender_pq_pk)?;

    // Step 3: locate the reader's entry. Linear scan is fine — the
    // recipient list is small (typical: handful, hard cap u16::MAX) and
    // this avoids materialising a HashMap for one lookup.
    let entry = block
        .recipients
        .iter()
        .find(|r| &r.recipient_fingerprint == reader_card_fingerprint)
        .ok_or(BlockError::NotARecipient {
            fingerprint: *reader_card_fingerprint,
        })?;

    // Step 4: hybrid-decap to recover the BCK.
    let bck = kem::decap(
        &entry.wrap,
        sender_card_fingerprint,
        reader_card_fingerprint,
        sender_pk_bundle,
        reader_pk_bundle,
        reader_x_sk,
        reader_pq_sk,
        &block.header.block_uuid,
    )?;

    // Step 5: AAD from the on-disk bytes magic..end_of_recipient_entries.
    let aad = build_body_aad(&block.header, &block.recipients)?;

    // Step 6: re-concatenate (aead_ct || aead_tag) for the AEAD API.
    let mut ct_with_tag = Vec::with_capacity(block.aead_ct.len() + AEAD_TAG_LEN);
    ct_with_tag.extend_from_slice(&block.aead_ct);
    ct_with_tag.extend_from_slice(&block.aead_tag);
    let mut bck_key_bytes = *bck.expose();
    let bck_key: AeadKey = Sensitive::new(bck_key_bytes);
    bck_key_bytes.zeroize();
    let pt_secret = aead::decrypt(&bck_key, &block.aead_nonce, &aad, &ct_with_tag)?;

    // Step 7: parse the canonical-CBOR plaintext. SecretBytes derefs to
    // a byte slice via `expose`; the resulting `BlockPlaintext` itself
    // contains record fields whose `value` may carry secret material —
    // the surrounding caller is responsible for handling it accordingly.
    let plaintext = decode_plaintext(pt_secret.expose())?;

    // Step 8: §6.4 step 9 cross-check.
    if plaintext.block_uuid != block.header.block_uuid {
        return Err(BlockError::BlockUuidMismatch {
            header: block.header.block_uuid,
            plaintext: plaintext.block_uuid,
        });
    }

    Ok(plaintext)
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
                value: RecordFieldValue::Text("alice".into()),
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
            tombstoned_at_ms: 0,
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

    /// Smoke test: full [`BlockFile`] round-trip with the sender as the
    /// sole recipient (the §6.2 "owner is always a recipient" base case).
    ///
    /// Exercises the encode → decode → encrypt → decrypt path end-to-end:
    ///
    /// - [`encrypt_block`] generates a fresh BCK, encaps for the one
    ///   recipient, AEAD-encrypts the body.
    /// - [`encode_block_file`] serialises and [`decode_block_file`] parses
    ///   back; the two halves must produce bit-identical bytes
    ///   ([`BlockFile`] derives `Eq`).
    /// - [`decrypt_block`] recovers the BCK via hybrid-decap, AEAD-decrypts,
    ///   and cross-checks the §6.4 step 9 `block_uuid` invariant.
    ///
    /// Identity is generated via [`crate::unlock::bundle::generate`] from
    /// a seeded `ChaCha20Rng` for determinism. The pk-bundle bytes are
    /// the canonical-CBOR concatenation of the four public keys (any
    /// stable byte string works because [`crate::crypto::kem::encap`]
    /// treats the bundle opaquely; both sides just need to agree).
    /// Comprehensive multi-recipient and corruption coverage lands in
    /// the next build-sequence step.
    #[test]
    fn smoke_block_file_roundtrip_self_recipient() {
        use crate::unlock::bundle;
        use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

        // ---- Identity (sender == sole recipient == self) -------------
        let mut id_rng = ChaCha20Rng::from_seed([0x11; 32]);
        let id = bundle::generate("Owner", 1_714_060_800_000, &mut id_rng);

        // pk-bundle bytes: any deterministic byte string works because
        // kem::encap / kem::decap treat it opaquely. Concatenating the
        // four public keys is a clear deterministic choice for this
        // smoke test; the real pk_bundle_bytes() helper on ContactCard
        // will land alongside the contact-card encryption work.
        let mut pk_bundle: Vec<u8> = Vec::with_capacity(
            id.x25519_pk.len() + id.ml_kem_768_pk.len() + id.ed25519_pk.len() + id.ml_dsa_65_pk.len(),
        );
        pk_bundle.extend_from_slice(&id.x25519_pk);
        pk_bundle.extend_from_slice(&id.ml_kem_768_pk);
        pk_bundle.extend_from_slice(&id.ed25519_pk);
        pk_bundle.extend_from_slice(&id.ml_dsa_65_pk);

        // Fingerprint: the §6.1 fingerprint is over the canonical-CBOR
        // *signed* contact card, which doesn't exist in this build step.
        // For this smoke test any deterministic 16-byte handle suffices —
        // the key invariant we exercise is "encrypt_block writes
        // fingerprint X and decrypt_block looks up fingerprint X".
        let card_fp: Fingerprint = [0xab; 16];

        // ---- Reconstitute the kem secret keys for decap --------------
        // bundle.x25519_sk is already a Sensitive<[u8; 32]> typed as
        // X25519Secret; bundle.ml_kem_768_sk is a Sensitive<Vec<u8>>
        // which we wrap into the kem::MlKem768Secret newtype.
        let x_sk: kem::X25519Secret = Sensitive::new(*id.x25519_sk.expose());
        let pq_sk = kem::MlKem768Secret::from_bytes(id.ml_kem_768_sk.expose())
            .expect("ml-kem-768 sk length");
        let pq_pk =
            kem::MlKem768Public::from_bytes(&id.ml_kem_768_pk).expect("ml-kem-768 pk length");

        // ---- Reconstitute the sig keys for sign / verify -------------
        // bundle.ed25519_sk is already typed Sensitive<[u8;32]> = Ed25519Secret.
        // bundle.ml_dsa_65_sk is Sensitive<Vec<u8>>; rewrap into the
        // MlDsa65Secret newtype for sig::sign. Public side: ed25519_pk
        // is a [u8;32] = Ed25519Public; ml_dsa_65_pk is Vec<u8> that we
        // wrap into MlDsa65Public.
        let ed_sk: Ed25519Secret = Sensitive::new(*id.ed25519_sk.expose());
        let dsa_sk = MlDsa65Secret::from_bytes(id.ml_dsa_65_sk.expose())
            .expect("ml-dsa-65 sk length");
        let dsa_pk =
            MlDsa65Public::from_bytes(&id.ml_dsa_65_pk).expect("ml-dsa-65 pk length");

        // ---- Header / plaintext --------------------------------------
        let block_uuid: [u8; BLOCK_UUID_LEN] = [0x42; BLOCK_UUID_LEN];
        let header = BlockHeader {
            magic: MAGIC,
            format_version: FORMAT_VERSION,
            suite_id: SUITE_ID,
            file_kind: FILE_KIND_BLOCK,
            vault_uuid: [0x11; 16],
            block_uuid,
            created_at_ms: 1_714_060_800_000,
            last_mod_ms: 1_714_060_800_500,
            vector_clock: vec![VectorClockEntry {
                device_uuid: [0x33; 16],
                counter: 1,
            }],
        };

        let mut fields = BTreeMap::new();
        fields.insert(
            "username".to_string(),
            RecordField {
                value: RecordFieldValue::Text("alice".into()),
                last_mod: 1_714_060_800_000,
                device_uuid: [0xaa; RECORD_UUID_LEN],
                unknown: BTreeMap::new(),
            },
        );
        let plaintext = BlockPlaintext {
            block_version: 1,
            block_uuid,
            block_name: "personal".to_string(),
            schema_version: 1,
            records: vec![Record {
                record_uuid: [0xcd; RECORD_UUID_LEN],
                record_type: "login".to_string(),
                fields,
                tags: Vec::new(),
                created_at_ms: 1_714_060_800_000,
                last_mod_ms: 1_714_060_800_001,
                tombstone: false,
                tombstoned_at_ms: 0,
                unknown: BTreeMap::new(),
            }],
            unknown: BTreeMap::new(),
        };

        // ---- Encrypt -------------------------------------------------
        let mut enc_rng = ChaCha20Rng::from_seed([0x22; 32]);
        let recipients = [RecipientPublicKeys {
            fingerprint: card_fp,
            pk_bundle: &pk_bundle,
            x25519_pk: &id.x25519_pk,
            ml_kem_768_pk: &pq_pk,
        }];
        let block = encrypt_block(
            &mut enc_rng,
            &header,
            &plaintext,
            &card_fp,
            &pk_bundle,
            &ed_sk,
            &dsa_sk,
            &recipients,
        )
        .expect("encrypt_block");

        // Signature is well-formed: 64-byte Ed25519 + 3309-byte ML-DSA-65.
        assert_eq!(block.sig.sig_ed.len(), ED25519_SIG_LEN);
        assert_eq!(
            block.sig.sig_pq.as_bytes().len(),
            crate::crypto::sig::ML_DSA_65_SIG_LEN
        );
        assert_eq!(block.author_fingerprint, card_fp);

        // ---- encode → decode round-trip -----------------------------
        let bytes = encode_block_file(&block).expect("encode_block_file");
        let decoded = decode_block_file(&bytes).expect("decode_block_file");
        // BlockFile derives Eq — bit-identical bytes ⇒ bit-identical
        // structure. (The encoder sorts the vector clock, so the decoded
        // header's vector_clock is in sorted order; we built `header`
        // already in sorted order so equality holds without re-sort.)
        assert_eq!(decoded, block);

        // ---- Decrypt -------------------------------------------------
        let recovered = decrypt_block(
            &decoded,
            &card_fp,
            &pk_bundle,
            &id.ed25519_pk,
            &dsa_pk,
            &card_fp,
            &pk_bundle,
            &x_sk,
            &pq_sk,
        )
        .expect("decrypt_block");
        assert_eq!(recovered, plaintext);
    }

    /// Smoke test: a non-recipient's [`decrypt_block`] call surfaces
    /// [`BlockError::NotARecipient`] rather than corruption or AEAD
    /// failure. Per §6.4 the UI distinguishes "not shared with you" from
    /// "block is corrupt"; the typed-error split exists so that
    /// distinction can land at the call site.
    #[test]
    fn smoke_decrypt_block_rejects_non_recipient() {
        use crate::unlock::bundle;
        use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

        // ---- Two distinct identities --------------------------------
        let mut owner_rng = ChaCha20Rng::from_seed([0x33; 32]);
        let owner = bundle::generate("Owner", 1_714_060_800_000, &mut owner_rng);
        let mut other_rng = ChaCha20Rng::from_seed([0x44; 32]);
        let other = bundle::generate("Other", 1_714_060_800_000, &mut other_rng);

        let make_pk_bundle = |b: &bundle::IdentityBundle| -> Vec<u8> {
            let mut v = Vec::new();
            v.extend_from_slice(&b.x25519_pk);
            v.extend_from_slice(&b.ml_kem_768_pk);
            v.extend_from_slice(&b.ed25519_pk);
            v.extend_from_slice(&b.ml_dsa_65_pk);
            v
        };
        let owner_bundle = make_pk_bundle(&owner);
        let other_bundle = make_pk_bundle(&other);

        let owner_fp: Fingerprint = [0xaa; 16];
        let other_fp: Fingerprint = [0xbb; 16];

        let owner_pq_pk = kem::MlKem768Public::from_bytes(&owner.ml_kem_768_pk)
            .expect("ml-kem-768 pk length");

        // Owner sign / verify keys for encrypt_block / decrypt_block.
        let owner_ed_sk: Ed25519Secret = Sensitive::new(*owner.ed25519_sk.expose());
        let owner_dsa_sk = MlDsa65Secret::from_bytes(owner.ml_dsa_65_sk.expose())
            .expect("ml-dsa-65 sk length");
        let owner_dsa_pk = MlDsa65Public::from_bytes(&owner.ml_dsa_65_pk)
            .expect("ml-dsa-65 pk length");

        // ---- Block addressed only to the owner ----------------------
        let block_uuid = [0x42; BLOCK_UUID_LEN];
        let header = BlockHeader {
            magic: MAGIC,
            format_version: FORMAT_VERSION,
            suite_id: SUITE_ID,
            file_kind: FILE_KIND_BLOCK,
            vault_uuid: [0x11; 16],
            block_uuid,
            created_at_ms: 1_714_060_800_000,
            last_mod_ms: 1_714_060_800_500,
            vector_clock: Vec::new(),
        };
        let plaintext = BlockPlaintext {
            block_version: 1,
            block_uuid,
            block_name: "owner-only".to_string(),
            schema_version: 1,
            records: Vec::new(),
            unknown: BTreeMap::new(),
        };
        let mut enc_rng = ChaCha20Rng::from_seed([0x55; 32]);
        let recipients = [RecipientPublicKeys {
            fingerprint: owner_fp,
            pk_bundle: &owner_bundle,
            x25519_pk: &owner.x25519_pk,
            ml_kem_768_pk: &owner_pq_pk,
        }];
        let block = encrypt_block(
            &mut enc_rng,
            &header,
            &plaintext,
            &owner_fp,
            &owner_bundle,
            &owner_ed_sk,
            &owner_dsa_sk,
            &recipients,
        )
        .expect("encrypt_block");

        // ---- The other party tries to read it -----------------------
        let other_x_sk: kem::X25519Secret = Sensitive::new(*other.x25519_sk.expose());
        let other_pq_sk = kem::MlKem768Secret::from_bytes(other.ml_kem_768_sk.expose())
            .expect("ml-kem-768 sk length");
        let err = decrypt_block(
            &block,
            &owner_fp,
            &owner_bundle,
            &owner.ed25519_pk,
            &owner_dsa_pk,
            &other_fp,
            &other_bundle,
            &other_x_sk,
            &other_pq_sk,
        )
        .expect_err("non-recipient must be rejected");
        match err {
            BlockError::NotARecipient { fingerprint } => {
                assert_eq!(fingerprint, other_fp);
            }
            other => panic!("expected NotARecipient, got {other:?}"),
        }
    }

    /// Smoke test: tamper with the Ed25519 half of the trailing block
    /// signature and assert [`decrypt_block`] returns
    /// [`BlockError::Sig`] wrapping [`SigError::Ed25519VerifyFailed`].
    /// Comprehensive corruption coverage (every byte field flipped)
    /// lands in Task 6 — this test fixes the verify happy + sad path
    /// contract before then.
    #[test]
    fn smoke_decrypt_block_rejects_tampered_signature() {
        use crate::unlock::bundle;
        use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

        // ---- Identity (sender == sole recipient == self) -------------
        let mut id_rng = ChaCha20Rng::from_seed([0x66; 32]);
        let id = bundle::generate("Owner", 1_714_060_800_000, &mut id_rng);

        let mut pk_bundle: Vec<u8> = Vec::new();
        pk_bundle.extend_from_slice(&id.x25519_pk);
        pk_bundle.extend_from_slice(&id.ml_kem_768_pk);
        pk_bundle.extend_from_slice(&id.ed25519_pk);
        pk_bundle.extend_from_slice(&id.ml_dsa_65_pk);

        let card_fp: Fingerprint = [0xab; 16];

        let pq_pk =
            kem::MlKem768Public::from_bytes(&id.ml_kem_768_pk).expect("ml-kem-768 pk length");
        let x_sk: kem::X25519Secret = Sensitive::new(*id.x25519_sk.expose());
        let pq_sk = kem::MlKem768Secret::from_bytes(id.ml_kem_768_sk.expose())
            .expect("ml-kem-768 sk length");
        let ed_sk: Ed25519Secret = Sensitive::new(*id.ed25519_sk.expose());
        let dsa_sk = MlDsa65Secret::from_bytes(id.ml_dsa_65_sk.expose())
            .expect("ml-dsa-65 sk length");
        let dsa_pk =
            MlDsa65Public::from_bytes(&id.ml_dsa_65_pk).expect("ml-dsa-65 pk length");

        // ---- Build a valid block ------------------------------------
        let block_uuid = [0x42; BLOCK_UUID_LEN];
        let header = BlockHeader {
            magic: MAGIC,
            format_version: FORMAT_VERSION,
            suite_id: SUITE_ID,
            file_kind: FILE_KIND_BLOCK,
            vault_uuid: [0x11; 16],
            block_uuid,
            created_at_ms: 1_714_060_800_000,
            last_mod_ms: 1_714_060_800_500,
            vector_clock: Vec::new(),
        };
        let plaintext = BlockPlaintext {
            block_version: 1,
            block_uuid,
            block_name: "personal".to_string(),
            schema_version: 1,
            records: Vec::new(),
            unknown: BTreeMap::new(),
        };
        let mut enc_rng = ChaCha20Rng::from_seed([0x77; 32]);
        let recipients = [RecipientPublicKeys {
            fingerprint: card_fp,
            pk_bundle: &pk_bundle,
            x25519_pk: &id.x25519_pk,
            ml_kem_768_pk: &pq_pk,
        }];
        let mut block = encrypt_block(
            &mut enc_rng,
            &header,
            &plaintext,
            &card_fp,
            &pk_bundle,
            &ed_sk,
            &dsa_sk,
            &recipients,
        )
        .expect("encrypt_block");

        // ---- Tamper: flip one bit in the Ed25519 signature ---------
        // sig_ed[0] ^= 0x01 is the simplest single-bit flip; verify
        // must reject it as Ed25519VerifyFailed (the deterministic-
        // signature property guarantees the unmodified half would
        // still pass — only Ed25519 was disturbed).
        block.sig.sig_ed[0] ^= 0x01;

        let err = decrypt_block(
            &block,
            &card_fp,
            &pk_bundle,
            &id.ed25519_pk,
            &dsa_pk,
            &card_fp,
            &pk_bundle,
            &x_sk,
            &pq_sk,
        )
        .expect_err("tampered signature must be rejected");
        match err {
            BlockError::Sig(SigError::Ed25519VerifyFailed) => {}
            other => panic!(
                "expected BlockError::Sig(Ed25519VerifyFailed), got {other:?}"
            ),
        }
    }
}
