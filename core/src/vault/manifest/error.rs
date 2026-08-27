//! Manifest layer-local error enum (`docs/vault-format.md` §4).

use crate::cbor::CborFault;
use crate::crypto::sig::SigError;
use crate::vault::canonical::CanonicalError;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors emitted by the manifest CBOR encode and decode paths.
///
/// **Not `#[non_exhaustive]`, deliberately** — the same stance `BlockError`
/// and `RecordError` take, recorded here in the #575 review because that
/// PR added a variant ([`ManifestError::DuplicateKey`]) and the decision
/// had never been written down for this enum. Adding a variant is
/// therefore a real, compiler-checked surface change rather than a silent
/// one. Nothing outside this file matches `ManifestError` exhaustively
/// today — every bridge fold binds `VaultError::Manifest(_)` with a
/// wildcard — but that is a property of the current fold shape, not a
/// guarantee, so a `cargo build --release --workspace` is what confirms a
/// new variant costs nothing downstream.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    /// `ciborium` returned an I/O or serialisation error during encode.
    ///
    /// Carries a classified [`CborFault`] rather than the upstream message:
    /// `ciborium`'s `Display` is its `Debug` form, so stringifying it copies
    /// `ser::Error::Value(String)` verbatim — a `serde` custom message that can
    /// embed the offending value (#474). The generic-source problem that
    /// originally forced a `String` (`ciborium::ser::Error<E>` is generic over
    /// the writer's I/O error, so `#[from]` does not apply) is solved by
    /// [`crate::cbor::classify_ser`] projecting to a non-generic type. Same
    /// justification as `RecordError::CborEncode`.
    #[error("CBOR encode error: {0}")]
    CborEncode(CborFault),

    /// `ciborium` returned a parse error during decode. Carries a classified
    /// [`CborFault`] for the same reason as [`Self::CborEncode`].
    #[error("CBOR decode error: {0}")]
    CborDecode(CborFault),

    /// Top-level CBOR item was not a map.
    #[error("manifest body must be a CBOR map")]
    NotAMap,

    /// A map key was not a text string. §4.2 keys are all `tstr`.
    #[error("manifest map keys must be text strings")]
    NonTextKey,

    /// A CBOR map key appeared more than once in the top-level manifest
    /// map. RFC 8949 §5.4 leaves this to the application, and silent
    /// last-wins was the wrong direction here.
    ///
    /// **What the neighbouring decoders actually do**, corrected in the
    /// #575 review — this said `record.rs` and `block.rs` "reject a
    /// duplicate key at *every* nesting level", which is false in two
    /// ways, and it was the stated justification for scoping this fix to
    /// one level:
    ///
    /// - They check only the levels they parse STRUCTURALLY. `record.rs`
    ///   has three such levels (`<record>`, `fields`, `<field>`);
    ///   `block.rs` has exactly one (`<block>`).
    /// - NEITHER checks inside a forward-compat `unknown` subtree, which
    ///   is an arbitrary-depth CBOR map stored verbatim. `UnknownValue`'s
    ///   only validation is `reject_floats_and_tags`. The record-level
    ///   re-encode-and-compare does not catch it either: duplicate keys
    ///   sort adjacently and re-encode byte-identically.
    ///
    /// So the correct comparison makes **#573 larger, not smaller**. This
    /// variant closes the top level only; `parse_vector_clock_entry`,
    /// `parse_block_entry`, `parse_trash_entry` and `parse_kdf_params`
    /// still silently last-win on their own nested maps, and no decoder
    /// in the crate looks inside an `unknown` subtree.
    ///
    /// Payload is data-free by construction (#474). `field` is a
    /// compile-time constant: the §4.2 `KEY_*` name for a known key, or
    /// the literal `"<unknown>"` for a forward-compat one. `index` is the
    /// entry's ordinal. The repeated key itself is never carried — a
    /// forward-compat unknown key is attacker-influenced text, and
    /// `RecordError::DuplicateKey` once leaked exactly that class.
    #[error("duplicate CBOR map key in {field} at entry {index}")]
    DuplicateKey { field: &'static str, index: usize },

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

    /// Two or more `trash` entries shared the same `block_uuid`. The
    /// manifest tracks only the most-recent tombstone per block (§7), so a
    /// repeated `block_uuid` is nonsensical — a sign of corruption or attack.
    #[error("trash array contains duplicate block_uuid")]
    DuplicateTrashUuid,

    /// A canonical-CBOR rule was violated (float, tag, …). Lifted from
    /// the shared `crate::vault::canonical` helpers.
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
    ///
    /// [`MANIFEST_HEADER_LEN`]: crate::vault::manifest::MANIFEST_HEADER_LEN
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
    ///
    /// [`decode_manifest_file`]: crate::vault::manifest::decode_manifest_file
    #[error("trailing bytes after manifest file: {0} extra")]
    TrailingBytes(usize),

    /// On-disk `sig_ed_len` (the u16 BE length prefix immediately
    /// before the Ed25519 signature bytes) was not [`ED25519_SIG_LEN`]
    /// (64). §4.1 / §14 fix the Ed25519 signature length; this variant
    /// catches wire-format violations. Mirrors
    /// `BlockError::SigEdWrongLength`.
    ///
    /// [`ED25519_SIG_LEN`]: crate::crypto::sig::ED25519_SIG_LEN
    #[error("sig_ed_len wrong: expected {expected}, got {got}")]
    SigEdWrongLength { expected: u16, got: u16 },

    /// On-disk `sig_pq_len` was not [`ML_DSA_65_SIG_LEN`] (3309). §4.1
    /// / §14 fix the ML-DSA-65 signature length under suite
    /// `secretary-v1-pq-hybrid`. Mirrors `BlockError::SigPqWrongLength`:
    /// a wire-format length violation is a parse error, not a sign /
    /// verify failure, and gets its own variant rather than being
    /// collapsed.
    ///
    /// [`ML_DSA_65_SIG_LEN`]: crate::crypto::sig::ML_DSA_65_SIG_LEN
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
