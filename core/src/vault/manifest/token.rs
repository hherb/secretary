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
    /// `token/tests.rs` pins that this really is every variant, by an
    /// exhaustive match that fails to COMPILE when a variant is added
    /// without being listed here.
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
    /// against the section's two fixed orderings unspecified.
    ///
    /// This predicate IS that sentence, which is why the cross-language
    /// harness derives its tolerance from it rather than from a
    /// hand-maintained list of tolerated pairs: a pair list would have to be
    /// re-derived every time a token is added and would drift from §4.2
    /// silently.
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

#[cfg(test)]
mod tests;
