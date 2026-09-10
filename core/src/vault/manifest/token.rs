//! A language-neutral name for the rule a rejecting manifest decoder is
//! reporting, so two independent implementations can be compared on WHICH
//! rule they named and not merely on whether they rejected (#634).
//!
//! **Deliberately coarser than [`ManifestError`].** Every distinction this
//! vocabulary draws is one both implementations must then maintain forever,
//! so it draws only the ones that carry evidence: enough to separate the
//! divergences #618 and #621 found, and no finer. `ContainerMalformed`
//! merges eight file-level variants for that reason.
//!
//! **A token may only draw a distinction BOTH implementations can make.**
//! Where one is structurally blind, the token coarsens to what they share.
//! The worked example is trailing bytes after the manifest map:
//! `ciborium`'s reader performs no EOF check, so Rust's parse discards them
//! before the §4.3 step-4 comparison and `classify_non_canonical` has
//! nothing in the body to point at — it can only ever say
//! [`Self::NonCanonicalUnclassified`]. `conformance.py` names them exactly.
//! There is therefore no `trailing_bytes` token, and Python's raise carries
//! the coarse one; its own message stays specific, so no human loses a
//! diagnostic.
//!
//! [`ManifestError`]: super::ManifestError

use super::cause::NonCanonicalCause;
use super::error::ManifestError;
use crate::vault::canonical::CanonicalError;

/// Which rule a rejecting manifest decoder is reporting.
///
/// Fieldless by construction (#474): every variant is a compile-time
/// constant, so no decrypted manifest content can ride along.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuleToken {
    /// crypto-design §6.2 rule 2 — an indefinite-length item.
    Rule2IndefiniteLength,
    /// crypto-design §6.2 rule 3 — a non-shortest-form integer or length head.
    Rule3NonShortestForm,
    /// crypto-design §6.2 rule 4 — a tag or a float, anywhere in the body.
    Rule4TagOrFloat,
    /// The body is not the canonical encoding of the value this reader
    /// parsed, with no finer classification the two implementations agree on.
    ///
    /// Covers map-key disorder (§6.2 rule 1), which leaves nothing in the
    /// body to point at, and trailing bytes — see this module's own doc for
    /// why the latter has no token of its own.
    NonCanonicalUnclassified,
    /// One of `docs/vault-format.md` §4.2's five array sort disciplines.
    ArraySortOrder,
    /// §4.2's repeated-array-value prohibition, in one of the four arrays it
    /// binds. `recipients` is the explicit exception and never produces this.
    RepeatedArrayValue,
    /// A map this reader interprets carries the same key twice.
    DuplicateMapKey,
    /// A §4.2 required key is absent.
    MissingField,
    /// A field's CBOR major type, or a byte string's length, is not what §4.2
    /// requires — including a body that is not a map, and a non-text map key.
    WrongType,
    /// An integer field is outside the width §4.2 gives it.
    IntegerOutOfRange,
    /// A v1 sentinel — `manifest_version`, `format_version`, `suite_id` — is
    /// not the v1 value, at either the body or the file-header layer.
    UnsupportedVersion,
    /// The bytes are not well-formed CBOR at all.
    MalformedCbor,
    /// The §4.1 file envelope is malformed: magic, file kind, header or
    /// section truncation, a declared length that does not match, trailing
    /// bytes after the file, or a wrong signature length.
    ContainerMalformed,
    /// §4.1 AEAD verification failed.
    AeadFailure,
    /// An §8 hybrid signature half did not verify.
    SignatureInvalid,
    /// The ENCODER refused to emit a body its own decoder would reject. Not a
    /// property of any input — a caller built a malformed `Manifest` in
    /// memory (#600, #587).
    EncoderRefusal,
    /// A fault in this implementation rather than in the input: an encode
    /// failure, a capacity bound, a signing error.
    InternalError,
}

impl RuleToken {
    /// Every variant, in declaration order.
    ///
    /// **Fail-closed in practice, not a compile-time guarantee — say the
    /// weaker thing.** `token/tests.rs`'s `all_lists_every_variant` matches
    /// exhaustively over the variants it iterates out of this slice, so
    /// adding an 18th variant *and nothing else* fails to COMPILE there. It
    /// does not follow that the list cannot fall behind: an author who adds
    /// the new arm to that match and forgets this slice compiles clean and
    /// passes, because the match then still iterates 17 elements and the
    /// length assertion still reads 17. What would actually catch that pair
    /// of edits is `vocabulary_fixture_matches_the_enum`, which compares this
    /// slice's length against `rule_token_vocabulary.json`'s row count — and
    /// only once the fixture gains the 18th row.
    pub const ALL: &'static [RuleToken] = &[
        RuleToken::Rule2IndefiniteLength,
        RuleToken::Rule3NonShortestForm,
        RuleToken::Rule4TagOrFloat,
        RuleToken::NonCanonicalUnclassified,
        RuleToken::ArraySortOrder,
        RuleToken::RepeatedArrayValue,
        RuleToken::DuplicateMapKey,
        RuleToken::MissingField,
        RuleToken::WrongType,
        RuleToken::IntegerOutOfRange,
        RuleToken::UnsupportedVersion,
        RuleToken::MalformedCbor,
        RuleToken::ContainerMalformed,
        RuleToken::AeadFailure,
        RuleToken::SignatureInvalid,
        RuleToken::EncoderRefusal,
        RuleToken::InternalError,
    ];

    /// The wire spelling, shared with `conformance.py` through
    /// `core/tests/data/rule_token_vocabulary.json`.
    pub fn as_str(&self) -> &'static str {
        match self {
            RuleToken::Rule2IndefiniteLength => "rule2_indefinite_length",
            RuleToken::Rule3NonShortestForm => "rule3_non_shortest_form",
            RuleToken::Rule4TagOrFloat => "rule4_tag_or_float",
            RuleToken::NonCanonicalUnclassified => "non_canonical_unclassified",
            RuleToken::ArraySortOrder => "array_sort_order",
            RuleToken::RepeatedArrayValue => "repeated_array_value",
            RuleToken::DuplicateMapKey => "duplicate_map_key",
            RuleToken::MissingField => "missing_field",
            RuleToken::WrongType => "wrong_type",
            RuleToken::IntegerOutOfRange => "integer_out_of_range",
            RuleToken::UnsupportedVersion => "unsupported_version",
            RuleToken::MalformedCbor => "malformed_cbor",
            RuleToken::ContainerMalformed => "container_malformed",
            RuleToken::AeadFailure => "aead_failure",
            RuleToken::SignatureInvalid => "signature_invalid",
            RuleToken::EncoderRefusal => "encoder_refusal",
            RuleToken::InternalError => "internal_error",
        }
    }

    /// True when the two reader designs `docs/vault-format.md` §4.2 admits
    /// detect this rule at DIFFERENT points, so §4.2 declares its order
    /// against the section's fixed orderings unspecified.
    ///
    /// **DERIVED from §4.2's "deliberately unspecified" paragraphs, and
    /// strictly BROADER than them.** It is not that sentence, and the
    /// difference is not cosmetic — see LIMITS below for the two families it
    /// tolerates that §4.2 does not free. It is still a predicate rather than
    /// a hand-maintained list of tolerated pairs, because a pair list would
    /// have to be re-derived every time a token is added and would drift from
    /// §4.2 silently; a predicate that is knowably wider is easier to state
    /// the residual of than a list that is silently stale.
    ///
    /// A normalising-parse reader sees these only at the §4.3 step-4
    /// re-encode — after interpretation. A byte-retaining reader must see
    /// them during its scan — before it. Rule 4 is deliberately absent:
    /// NEITHER design obtains it from the re-encode, so §4.2 can and does
    /// require both to run the whole-body walk first (#618).
    ///
    /// The repeated-array-value rule is absent for the mirror reason: both
    /// designs check it during interpretation, because `[x, x]` is sorted
    /// and re-encodes to itself, so no reader gets it from the re-encode
    /// either.
    ///
    /// # LIMITS
    ///
    /// Marking a TOKEN phase-dependent tolerates every pair that token
    /// appears in. THREE families are tolerated that §4.2 orders or leaves
    /// unmentioned. Both are recorded rather than fixed: narrowing the
    /// predicate would manufacture false disagreements on the pairs §4.2
    /// genuinely does leave free, and the mechanism behind each is a
    /// coarsening this vocabulary took deliberately.
    ///
    /// 1. **[`Self::NonCanonicalUnclassified`] is a UNION of two causes and
    ///    only one of them is phase-dependent.** It covers §6.2 rule-1
    ///    map-key disorder, which genuinely is, and trailing bytes after the
    ///    manifest map, which is not — §4.2 gives trailing bytes no ordering
    ///    at all. The two readers place that check at opposite ends of their
    ///    pipelines: `conformance.py` tests it immediately after the rule-4
    ///    walk, before every schema check, while this crate cannot see it
    ///    until the §4.3 step-4 re-encode, the last step, because `ciborium`
    ///    performs no EOF check. So a body carrying trailing bytes *and* any
    ///    schema fault makes the two name genuinely different rules and the
    ///    harness still scores agreement. Measured on
    ///    `uniq__blocks__duplicate_block_uuid.bin`: Python says
    ///    `repeated_array_value`, and with one `0x00` appended it says
    ///    `non_canonical_unclassified` while this crate's answer cannot move.
    ///    The same holds for trailing bytes beside a missing field, a wrong
    ///    type, an out-of-range integer, a duplicate map key or a bad
    ///    sentinel — a systematic family, not one input. Splitting the union
    ///    would need a `trailing_bytes` token, which is precisely the
    ///    distinction only ONE implementation can make (see this module's own
    ///    doc), so the residual is the price of that coarsening rule.
    /// 2. **[`Self::ArraySortOrder`] against [`Self::Rule4TagOrFloat`] is
    ///    ORDERED by §4.2 and tolerated here.** §4.2's ordering 1 puts rule 4
    ///    ahead of "this section's schema checks", and the five array sort
    ///    disciplines are among them — §4.2 says so in as many words. The
    ///    predicate cannot express that, because it reads one token at a time
    ///    and `ArraySortOrder` is phase-dependent against §6.2 rules 1-3.
    /// 3. **[`Self::ArraySortOrder`] against [`Self::RepeatedArrayValue`] is
    ///    tolerated, and §4.2 pointedly does NOT free it.** That section's
    ///    closing paragraph says the repeated-array-value rules stay ordered,
    ///    because both designs check them during interpretation. The two
    ///    nonetheless disagree, for the same one-token-at-a-time reason as
    ///    family 2. Measured on both sides, from one body whose `blocks`
    ///    array is both out of order and carries a repeat: this crate says
    ///    `repeated_array_value` (`DuplicateBlockUuid`, raised by
    ///    `decode/entries.rs` during the parse), `conformance.py` says
    ///    `array_sort_order` (its sort check precedes its repeat check), and
    ///    the harness scores agreement.
    pub fn is_phase_dependent(&self) -> bool {
        match self {
            RuleToken::Rule2IndefiniteLength
            | RuleToken::Rule3NonShortestForm
            | RuleToken::NonCanonicalUnclassified
            | RuleToken::ArraySortOrder => true,
            RuleToken::Rule4TagOrFloat
            | RuleToken::RepeatedArrayValue
            | RuleToken::DuplicateMapKey
            | RuleToken::MissingField
            | RuleToken::WrongType
            | RuleToken::IntegerOutOfRange
            | RuleToken::UnsupportedVersion
            | RuleToken::MalformedCbor
            | RuleToken::ContainerMalformed
            | RuleToken::AeadFailure
            | RuleToken::SignatureInvalid
            | RuleToken::EncoderRefusal
            | RuleToken::InternalError => false,
        }
    }
}

impl ManifestError {
    /// Which rule this rejection is reporting, as a language-neutral token.
    ///
    /// **Exhaustive by construction.** Adding a `ManifestError` variant
    /// without classifying it is a compile error, which is the whole point:
    /// a wildcard arm would let a new variant fall silently into some
    /// neighbour's token and present a divergence as agreement. Same ruling
    /// as #589's `Once` and #608's `Verdict` — make the obligation a type
    /// obligation, not a convention.
    ///
    /// **Advisory, never a verdict.** Nothing in the crate consults this to
    /// decide acceptance; it exists so two implementations can be compared
    /// on what they said. Same family as [`NonCanonicalCause`] (#590).
    pub fn rule_token(&self) -> RuleToken {
        match self {
            // --- §4.2 body: canonical form -------------------------------
            ManifestError::NonCanonicalEncoding { cause, .. } => match cause {
                NonCanonicalCause::ArraySortOrder => RuleToken::ArraySortOrder,
                NonCanonicalCause::IndefiniteLength => RuleToken::Rule2IndefiniteLength,
                NonCanonicalCause::NonShortestForm => RuleToken::Rule3NonShortestForm,
                NonCanonicalCause::Unclassified => RuleToken::NonCanonicalUnclassified,
            },
            // `reject_floats_and_tags` runs before `parse_manifest_map`, so
            // this is §6.2 rule 4. The DuplicateKey arm is the canonical
            // encoder's own, reached through the §4.3 step-4 re-encode.
            ManifestError::Canonical(e) => match e {
                CanonicalError::FloatRejected { .. } | CanonicalError::TagRejected { .. } => {
                    RuleToken::Rule4TagOrFloat
                }
                CanonicalError::DuplicateKey { .. } => RuleToken::DuplicateMapKey,
                CanonicalError::CborEncode(_) | CanonicalError::CapacityBoundExceeded { .. } => {
                    RuleToken::InternalError
                }
            },

            // --- §4.2 body: schema ---------------------------------------
            ManifestError::DuplicateKey { .. } => RuleToken::DuplicateMapKey,
            ManifestError::MissingField { .. } => RuleToken::MissingField,
            ManifestError::NotAMap
            | ManifestError::NonTextKey
            | ManifestError::WrongType { .. }
            | ManifestError::InvalidByteLength { .. } => RuleToken::WrongType,
            ManifestError::IntegerOutOfRange { .. } => RuleToken::IntegerOutOfRange,

            // --- v1 sentinels, at BOTH layers ----------------------------
            // `header.rs` raises the format/suite pair for the §4.1 file
            // header and `decode/mod.rs` raises all three for the §4.2 body.
            // (`sentinel.rs` is the WRITER-side check and raises the THREE
            // `EncodeUnsupported*` variants instead; `uniqueness.rs` raises
            // the other three `Encode*` — #587 kept writer and reader apart,
            // and the #640 argument turns on which sites share a variant, so
            // the file matters.) One token cannot tell the two decode layers
            // apart, which is precisely why `manifest_file` is not
            // token-compared (#640).
            ManifestError::UnsupportedManifestVersion(_)
            | ManifestError::UnsupportedFormatVersion(_)
            | ManifestError::UnsupportedSuiteId(_) => RuleToken::UnsupportedVersion,

            // --- §4.2 arrays ---------------------------------------------
            ManifestError::VectorClockDuplicateDevice
            | ManifestError::DuplicateBlockUuid
            | ManifestError::DuplicateTrashUuid => RuleToken::RepeatedArrayValue,

            // --- the encoder refusing to emit a body ---------------------
            // Not a property of any input: a caller built a malformed
            // `Manifest` in memory. Kept apart from the decoder's tokens for
            // the reason #600 kept the variants apart.
            ManifestError::EncodeDuplicateBlockUuid
            | ManifestError::EncodeDuplicateTrashUuid
            | ManifestError::EncodeVectorClockDuplicateDevice
            | ManifestError::EncodeUnsupportedManifestVersion(_)
            | ManifestError::EncodeUnsupportedFormatVersion(_)
            | ManifestError::EncodeUnsupportedSuiteId(_) => RuleToken::EncoderRefusal,

            // --- CBOR well-formedness ------------------------------------
            ManifestError::CborDecode(_) => RuleToken::MalformedCbor,

            // --- §4.1 file envelope --------------------------------------
            ManifestError::BadMagic { .. }
            | ManifestError::UnsupportedFileKind { .. }
            | ManifestError::HeaderTruncated { .. }
            | ManifestError::SectionTruncated { .. }
            | ManifestError::AeadCtLenMismatch { .. }
            | ManifestError::TrailingBytes(_)
            | ManifestError::SigEdWrongLength { .. }
            | ManifestError::SigPqWrongLength { .. } => RuleToken::ContainerMalformed,
            ManifestError::AeadFailure => RuleToken::AeadFailure,
            ManifestError::Ed25519SignatureInvalid | ManifestError::MlDsa65SignatureInvalid => {
                RuleToken::SignatureInvalid
            }

            // --- this implementation's own faults ------------------------
            ManifestError::CborEncode(_) | ManifestError::SignInternal(_) => {
                RuleToken::InternalError
            }
        }
    }
}

#[cfg(test)]
mod tests;
