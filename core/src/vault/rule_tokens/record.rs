//! [`RecordError::rule_token`] (#641). The mapping is §3.1 of the design doc
//! `docs/superpowers/specs/2026-09-15-token-compare-record-block-design.md`.

use crate::vault::manifest::RuleToken;
use crate::vault::record::RecordError;

impl RecordError {
    /// Which rule this rejection is reporting, as a language-neutral token
    /// shared with `conformance.py` (#634, #641).
    ///
    /// **Exhaustive by construction.** Adding a `RecordError` variant without
    /// classifying it is a compile error: a wildcard arm would let a new
    /// variant fall silently into some neighbour's token and present a
    /// divergence as agreement.
    ///
    /// **Coarse on purpose.** A token may only draw a distinction both
    /// implementations can make. [`RecordError::NonCanonicalEncoding`] is
    /// fieldless, so this crate cannot tell §6.2 rule 1, 2, 3 or trailing
    /// bytes apart, and `conformance.py` reports all four under the same
    /// token on the record path.
    ///
    /// **Advisory, never a verdict.** Nothing in the crate consults it to
    /// decide acceptance.
    pub fn rule_token(&self) -> RuleToken {
        match self {
            // Every kind, including `RecursionLimit`: ciborium's depth cap is
            // Rust-only, a residual #667 tracks rather than one fixed here.
            RecordError::CborDecode(_) => RuleToken::MalformedCbor,
            RecordError::NotAMap
            | RecordError::NonTextKey
            | RecordError::WrongType { .. }
            | RecordError::InvalidUuid { .. } => RuleToken::WrongType,
            RecordError::IntegerOverflow { .. } => RuleToken::IntegerOutOfRange,
            RecordError::MissingField { .. } => RuleToken::MissingField,
            // `CanonicalDuplicateKey` is the canonical encoder's twin; it
            // takes the rule it names, as `ManifestError::Canonical`'s
            // `DuplicateKey` arm does.
            RecordError::DuplicateKey { .. } | RecordError::CanonicalDuplicateKey { .. } => {
                RuleToken::DuplicateMapKey
            }
            RecordError::FloatRejected { .. } | RecordError::TagRejected => {
                RuleToken::Rule4TagOrFloat
            }
            RecordError::NonCanonicalEncoding => RuleToken::NonCanonicalUnclassified,
            RecordError::CborEncode(_) | RecordError::CanonicalSizeBoundExceeded { .. } => {
                RuleToken::InternalError
            }
        }
    }
}
