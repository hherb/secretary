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
    /// map, or inside one of the four nested per-entry maps
    /// (`parse_vector_clock_entry`, `parse_block_entry`,
    /// `parse_trash_entry`, `parse_kdf_params`). RFC 8949 §5.4 leaves
    /// this to the application, and silent last-wins was the wrong
    /// direction here.
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
    /// - NEITHER checks for a duplicate key inside a forward-compat
    ///   `unknown` subtree, which is an arbitrary-depth CBOR map whose
    ///   only validation is `reject_floats_and_tags`. The record-level
    ///   re-encode-and-compare does not catch it either: duplicate keys
    ///   sort adjacently and re-encode byte-identically.
    ///
    /// So the correct comparison made **#573 larger, not smaller** — the
    /// top-level check (#568) covered one level; #573 closed the
    /// remaining four nested parsers the same way. **What is still true
    /// after all three** — #568, #573, and the manifest layer's own
    /// re-encode-and-compare, which #572 added afterwards
    /// ([`Self::NonCanonicalEncoding`]): none of them rejects a
    /// DUPLICATE KEY inside a forward-compat `unknown` subtree. A
    /// duplicate key is one of exactly two things that survive
    /// `ciborium`'s parse of the body (the other is map key ORDER),
    /// because `ciborium::Value::Map` is an ordered `Vec` of pairs — so
    /// it re-encodes byte-identically and the comparison passes. Do not
    /// generalise that to "unknown subtrees round-trip verbatim": they
    /// do not, and
    /// [`Self::NonCanonicalEncoding`]'s doc gives the measured list of
    /// what inside one IS rejected. Do not read any of these fixes as
    /// "manifest duplicate keys are handled" without this residual
    /// attached.
    ///
    /// Payload is data-free by construction (#474). `field` is a
    /// compile-time constant: the §4.2 `KEY_*` name for a known key
    /// (naming the specific nested key that was repeated, not its
    /// container — a repeated `device_uuid` inside a `vector_clock`
    /// entry reports `field: KEY_DEVICE_UUID`, not `KEY_VECTOR_CLOCK`),
    /// or the literal `"<unknown>"` for a forward-compat one. `index` is
    /// the entry's ordinal within whichever map the duplicate was found
    /// in. The repeated key itself is never carried — a forward-compat
    /// unknown key is attacker-influenced text, and
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

    /// The decoded manifest body was not in canonical form: re-encoding
    /// the parsed [`Manifest`] did not reproduce the input bytes. The
    /// same check `record::decode` and `block::decode_plaintext` have
    /// applied since the format was frozen, and which this decoder simply
    /// did not have (#572).
    ///
    /// Same set of root causes as [`RecordError::NonCanonicalEncoding`]
    /// and [`BlockError::NonCanonicalEncoding`] — indefinite-length
    /// items (which `ciborium`'s `Value` reader normalises on parse, so
    /// the re-encode diverging is the only signal), map keys out of RFC
    /// 8949 §4.2.1 order, non-shortest-form integer or length prefixes —
    /// **plus one this layer adds**: §4.2's array sort disciplines.
    /// `encode_manifest` sorts `vector_clock`, every
    /// `vector_clock_summary`, `blocks`, `trash` and every block's
    /// `recipients` on output, so an input whose arrays arrive in any
    /// other order re-encodes differently and lands here. That is a
    /// stronger rejection than "not canonical CBOR" in the RFC 8949
    /// sense, and it is deliberate: vault-format §4.2 ("Array element
    /// order is normative") fixes those five orders, and the manifest
    /// body sits inside vault-format §4.1's hybrid-signature envelope,
    /// where crypto-design §6.2's deterministic encoding profile
    /// applies.
    /// (That §4.2 paragraph was added by #572's review — the sort
    /// disciplines had been in the encoder since the first manifest
    /// commit `6e53b49d` and stated in its module doc, but were never
    /// written into `docs/`, so a clean-room implementer reading the
    /// spec alone would have emitted unsorted arrays and been rejected
    /// here.)
    ///
    /// **What it does NOT catch, stated exactly** — the wider claim is
    /// false and stood in this doc for one commit: **a duplicate key,
    /// and map key ORDER, inside a forward-compat `unknown` subtree.**
    /// Nothing else — of what still REACHES this check. A tag or a float
    /// inside such a subtree escapes the re-encode comparison too (a
    /// normalising parse preserves both and re-encodes them identically),
    /// but neither reaches it: `decode_manifest` runs
    /// `reject_floats_and_tags` over the whole body, subtrees included,
    /// first. So the residual is the DECODER's, which is the claim that
    /// matters — but do not read "nothing else" as a property of this
    /// byte comparison in isolation. The cause is `ciborium`'s `Value`
    /// reader, which
    /// collapses indefinite lengths and non-shortest-form heads **on
    /// parse** — the same mechanism
    /// [`RecordError::NonCanonicalEncoding`]'s doc names. Every subtree
    /// is therefore already normalised before anything examines it, so
    /// the re-encode diverges; only what `ciborium::Value` can still
    /// represent survives, and `Value::Map` is an ordered `Vec` of
    /// pairs. An indefinite-length map, array, text string or byte
    /// string, or a non-shortest-form integer or length prefix, ANYWHERE
    /// inside an unknown subtree therefore **is** caught (verified by
    /// execution, #572 review rounds 1-2) — a real constraint on future
    /// format extensions: such a subtree makes the vault unopenable by a
    /// v1 client. See [`Self::DuplicateKey`]'s doc for the residual that
    /// genuinely remains.
    ///
    /// **Not** attributable to `extract::value_to_unknown`'s
    /// re-serialise/re-parse hop, which an earlier version of this doc
    /// blamed: that hop is an identity on an already-parsed `Value`, and
    /// `record::decode` — which has no such hop, storing
    /// `UnknownValue(v.clone())` directly — behaves identically on every
    /// one of these shapes.
    ///
    /// [`RecordError::NonCanonicalEncoding`]: crate::vault::record::RecordError::NonCanonicalEncoding
    /// [`BlockError::NonCanonicalEncoding`]: crate::vault::block::BlockError::NonCanonicalEncoding
    /// [`Manifest`]: crate::vault::manifest::Manifest
    #[error(
        "non-canonical CBOR encoding in manifest body (e.g. indefinite-length \
         item, key disorder, non-shortest length, or an array not in its \
         §4.2 sort order)"
    )]
    NonCanonicalEncoding,

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
