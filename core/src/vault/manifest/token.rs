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

/// Which rule a rejecting decoder is reporting: the manifest body (#634), and
/// the record and block-file envelope replay targets (#641).
///
/// Fieldless by construction (#474): every variant is a compile-time
/// constant, so no decrypted manifest content can ride along. Note the
/// difference from [`NonCanonicalCause`], which the payload guard credits as
/// data-free by recursion because it carries `#[error(...)]` and sits in a
/// payload position: this type carries neither, so no guard has jurisdiction
/// over it and the fieldlessness is a review property, not a checked one.
///
/// **Public API with no in-crate consumer, deliberately and not yet settled.**
/// It is `pub` only because `core/tests/differential_replay.rs` is an
/// integration test; nothing in the crate reads it. The vocabulary is designed
/// to grow as #640/#641 make more targets comparable, and for a `pub` enum
/// without `#[non_exhaustive]` that growth is a breaking change downstream —
/// "additive" is true of the vocabulary and false of the semver surface.
/// **#648** tracks choosing between `#[non_exhaustive]` and a
/// `#[doc(hidden)] pub` re-export; do not read the current shape as a decision
/// already taken.
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
    /// One of `docs/vault-format.md` §4.2's five array sort disciplines, or a
    /// §6.1 block file's vector clock or recipient table out of ascending
    /// order (#641).
    ArraySortOrder,
    /// A repeated value in a table that forbids one: §4.2's
    /// repeated-array-value prohibition, in one of the four arrays it binds
    /// (`recipients` is the explicit exception and never produces this), or
    /// a repeat in a §6.1 block file's vector clock or recipient table (#641).
    RepeatedArrayValue,
    /// A map this reader interprets carries the same key twice.
    DuplicateMapKey,
    /// A required key is absent (§4.2 manifest body; §6.3 record or block
    /// plaintext).
    MissingField,
    /// A map key the schema does not define, on a decoder that has no
    /// forward-compat `unknown` bag to put it in (#641).
    ///
    /// Today's sole producer is `CardError::UnknownField`: the §6 contact
    /// card rejects every unrecognised key outright, where the manifest body,
    /// the record and a block's plaintext all retain one. Distinct from
    /// [`Self::WrongType`] because both implementations name the two apart —
    /// a non-text key is a wrong type, a well-typed key that is not in the
    /// schema is this.
    UnknownField,
    /// A field's CBOR major type, or a byte string's or text string's length,
    /// is not what §4.2 (the manifest body), §6 (a contact card) or §6.3 (a
    /// block's plaintext, or a record alone or inside it) requires —
    /// including a body that is not a map, and a non-text map key.
    WrongType,
    /// An integer field is outside the width §4.2 or §6.3 gives it.
    IntegerOutOfRange,
    /// A v1 sentinel — `manifest_version`, `format_version`, `suite_id` — is
    /// not the v1 value, at either the body or the file-header layer,
    /// including a §6.1 block file's header (#641).
    UnsupportedVersion,
    /// The bytes are not well-formed CBOR at all.
    MalformedCbor,
    /// A §4.1 manifest or §6.1 block file envelope is malformed: magic, file
    /// kind, header or section truncation, a declared length that does not
    /// match, trailing bytes after the file, a wrong signature length, or
    /// (for a block file) an empty recipient table.
    ContainerMalformed,
    /// AEAD verification failed: §4.1's, for a manifest. `BlockError`'s AEAD,
    /// KEM and not-a-recipient arms map here too (#641), as diagnostics only
    /// — the `block_file` replay target never decrypts, so it cannot reach
    /// them.
    AeadFailure,
    /// An §8 hybrid signature half did not verify. `BlockError`'s signature
    /// and author-fingerprint arms map here too (#641), as diagnostics only
    /// — the envelope-only `block_file` replay target never verifies.
    SignatureInvalid,
    /// The ENCODER refused to emit a body its own decoder would reject. Not a
    /// property of any input — a caller built a malformed `Manifest` in
    /// memory (#600, #587), or a `BlockFile` whose recipient count or
    /// ciphertext and signature lengths the block encoder refuses (#641).
    EncoderRefusal,
    /// A fault in this implementation rather than in the input: an encode
    /// failure, a capacity bound, a signing error.
    InternalError,
}

impl RuleToken {
    /// Every variant, in declaration order.
    ///
    /// **Fail-closed in practice, not a compile-time guarantee — say the
    /// weaker thing.** `token/tests/vocabulary.rs`'s `all_lists_every_variant` matches
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
        RuleToken::UnknownField,
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
            RuleToken::UnknownField => "unknown_field",
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
    /// difference is not cosmetic — see LIMITS below for the FOUR groups of
    /// pairs it tolerates without a §4.2 licence, and for how much of the
    /// committed corpus that costs. It is still a predicate rather than
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
    /// **On `manifest_body` only.** Since #641 the replay harness applies
    /// this predicate solely on the targets its
    /// `PHASE_DEPENDENT_TOLERANCE_TARGETS` lists, today `manifest_body`: the
    /// licence is §4.2's two manifest reader designs, and §6.1 and §6.3 give
    /// none, so `record` and `block_file` compare strictly and tolerate no
    /// unequal pair. Every count below is about `manifest_body`.
    ///
    /// On that target, marking a TOKEN phase-dependent tolerates EVERY pair
    /// that token appears in, so the tolerated set is far wider than the set
    /// §4.2 frees, and the honest way to state it is a count rather than a
    /// short list of exceptions. Four of the eighteen tokens are
    /// phase-dependent, so 62 of the 153 unequal token pairs have at least
    /// one phase-dependent member, and **58 are tolerated**: the harness
    /// withholds the four that pair one with [`Self::MalformedCbor`], because
    /// §4.2 makes well-formedness the precondition for both of its orderings
    /// rather than a rule inside them (PR #673 review). §4.2 licenses a
    /// strict subset of those 58. (#641's [`Self::UnknownField`] joined the
    /// non-phase-dependent majority and moved these two counts up from 58/54
    /// — a new non-phase-dependent token always adds four tolerated pairs,
    /// one per phase-dependent token it now pairs against.)
    ///
    /// **What that costs on the committed corpus, measured rather than
    /// argued.** All four [`NonCanonicalCause`] outcomes map to
    /// phase-dependent tokens, so every `NonCanonicalEncoding` rejection
    /// this crate makes is scored as agreement whatever `conformance.py`
    /// said. `core/fuzz/seeds/manifest_body/` holds 47 bodies of which 32
    /// are rejected by both implementations, and **17 of those 32** make
    /// this crate answer with a phase-dependent token: 7 `arraysort__*`,
    /// 4 `keyorder__*`, 3 `*__rule2_indefinite_map`, 3
    /// `*__rule3_non_shortest_int`. 15 reach a real comparison — the 3
    /// `*__rule4_float` rows, the 4 `uniq__*` rows, the 6
    /// `valuetype__trash_*` rows #669 added, which answer `wrong_type` or
    /// `integer_out_of_range`, and the 2 rejecting `nesting__*` rows #667
    /// added, which answer `malformed_cbor` (measured per seed, both
    /// decoders; neither addition moved the tolerated 17, while the strict
    /// count went 7 -> 13 -> 15). Re-measure rather than quoting: these
    /// figures were stale by a whole slice twice already. Do not read the
    /// committed witness under `tests/data/diff_regressions/manifest_body/`
    /// as evidence against this: it is itself one of the tolerated pairs, so
    /// it proves the tolerance FIRES, not that it is tight.
    ///
    /// The four GROUPS below are tolerated with no §4.2 licence. They are
    /// recorded rather than closed, because a per-token predicate cannot
    /// express a pairwise ordering at all and narrowing it by hand would
    /// manufacture false disagreements on the pairs §4.2 genuinely does
    /// leave free. Closing them needs §4.2 to settle groups C and D and a
    /// two-argument tolerance derived from that text, which is **#646**.
    ///
    /// A. **[`Self::NonCanonicalUnclassified`] is a UNION of two causes and
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
    /// B. **[`Self::ArraySortOrder`] against [`Self::Rule4TagOrFloat`] is
    ///    ORDERED by §4.2 and tolerated here.** §4.2's ordering 1 puts rule 4
    ///    ahead of "this section's schema checks", and the five array sort
    ///    disciplines are among them — §4.2 says so in as many words. The
    ///    predicate cannot express that, because it reads one token at a time
    ///    and `ArraySortOrder` is phase-dependent against §6.2 rules 1-3.
    /// C. **[`Self::Rule2IndefiniteLength`], [`Self::Rule3NonShortestForm`]
    ///    and [`Self::NonCanonicalUnclassified`] against
    ///    [`Self::Rule4TagOrFloat`], where §4.2 does not read consistently.**
    ///    Ordering 1 says rule 4 outranks "every check below it", scoped to
    ///    "§6.2 rules 1–5", which includes rules 1, 2 and 3; the
    ///    paragraph immediately after declares the order of rules 1, 2 and 3
    ///    against BOTH fixed orderings unspecified. The two sentences cannot
    ///    both govern this pair. There is no live divergence today, because
    ///    both implementations run the whole-body rule-4 walk first — which
    ///    is exactly what #618 established, and exactly what this harness is
    ///    the negative control for. The control is switched off precisely
    ///    when the other rule is 1, 2 or 3.
    /// D. **[`Self::ArraySortOrder`], [`Self::Rule2IndefiniteLength`],
    ///    [`Self::Rule3NonShortestForm`] and
    ///    [`Self::NonCanonicalUnclassified`] against
    ///    [`Self::RepeatedArrayValue`], where §4.2 is SILENT.** Its closing
    ///    paragraph withholds the freedom from the repeated-array-value
    ///    rules only "relative to the two fixed orderings above", and none
    ///    of these four is one of those two — so the section neither frees
    ///    nor orders these pairs. **An earlier version of this block said
    ///    §4.2 "pointedly does NOT free it" and that the repeated-array-value
    ///    rules "stay ordered"; §4.2 says neither of those things about this
    ///    pair, and a comment asserting a spec sentence that does not exist
    ///    is worse than one admitting silence.** The `ArraySortOrder` member
    ///    is a MEASURED live divergence: from one body whose `blocks` array
    ///    is both out of order and carries a repeat, this crate says
    ///    `repeated_array_value` (`DuplicateBlockUuid`, raised by
    ///    `decode/entries.rs` during the parse) and `conformance.py` says
    ///    `array_sort_order` (its sort check precedes its repeat check), and
    ///    the harness scores agreement. It has no committed witness; #646
    ///    owns both halves.
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
            | RuleToken::UnknownField
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
            // ENCODER's own (#586), and it is NOT reachable from a decoded
            // body: `parse_manifest_map` routes each key either to a `Once`
            // slot or to `UnknownBag`, never both, and `UnknownBag` is a
            // `BTreeMap` — so a parsed `Manifest` cannot re-encode into a
            // `CanonicalMap` carrying a repeat, and the §4.3 step-4 re-encode
            // never raises it. Its producer is `encode_manifest` on a
            // caller-built `Manifest` whose `unknown` bag collides with a
            // known key. An earlier comment here said "reached through the
            // §4.3 step-4 re-encode", which is the opposite. It keeps
            // `DuplicateMapKey` rather than `EncoderRefusal` because the
            // rule it names is the repeated-map-key rule either way, and no
            // corpus input reaches it on the compared path.
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
