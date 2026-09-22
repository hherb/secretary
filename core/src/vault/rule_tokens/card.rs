//! [`CardError::rule_token`] (#641). The mapping is §3 of the design doc
//! `docs/superpowers/specs/2026-09-22-token-compare-contact-card-design.md`.

use crate::identity::card::CardError;
use crate::vault::manifest::RuleToken;

impl CardError {
    /// Which rule this rejection is reporting, as a language-neutral token
    /// shared with `conformance.py` (#634, #641).
    ///
    /// **Exhaustive by construction.** Adding a `CardError` variant without
    /// classifying it is a compile error; a wildcard arm would let a new
    /// variant fall silently into a neighbour's token and present a
    /// divergence as agreement.
    ///
    /// **Coarse on purpose.** [`CardError::DisplayNameTooLong`] and
    /// [`CardError::InvalidFieldLength`] share [`RuleToken::WrongType`]:
    /// both are length bounds, and a token may only draw distinctions that
    /// carry evidence. [`CardError::Malformed`] carries a closed set of
    /// `&'static str` literals covering a non-map body and a non-text key,
    /// which `RuleToken::WrongType`'s own doc names.
    ///
    /// **`SigVerifyFailed` is a diagnostic, not coverage.** The
    /// `contact_card` replay target calls `from_canonical_cbor`, which does
    /// not verify — nothing in it reaches [`crate::identity::card::ContactCard::verify_self`]
    /// or [`crate::crypto::sig::verify`] — so this arm is classified for
    /// completeness, as `BlockError`'s AEAD and signature arms are.
    ///
    /// **`CborEncode` is reachable, but not corpus-triggerable.**
    /// `from_canonical_cbor` ends with its own re-encode-and-compare
    /// canonicality check (`card.to_canonical_cbor()?`), and
    /// `to_canonical_cbor` is exactly the path that can yield this variant,
    /// via `canonical_error_to_card_error`'s `CanonicalError::CborEncode`
    /// arm — unlike `SigVerifyFailed`, it genuinely can propagate out of the
    /// function the replay calls. What makes it a diagnostic in practice is
    /// narrower: reaching it needs a `ciborium::ser::into_writer` failure
    /// serialising a shallow, well-typed `Value` tree into an in-memory
    /// `Vec<u8>`, which no corpus input can provoke. `BlockError`'s own
    /// `CborEncode` arm is the opposite case — `block_file`'s replay target
    /// round-trips `decode_block_file` → `encode_block_file`, so there it
    /// sits in the COMPARED bucket, not the diagnostics-only one.
    ///
    /// **Advisory, never a verdict.** Nothing in the crate consults it to
    /// decide acceptance.
    pub fn rule_token(&self) -> RuleToken {
        match self {
            CardError::CborDecode(_) => RuleToken::MalformedCbor,
            CardError::Malformed(_)
            | CardError::InvalidFieldLength
            | CardError::DisplayNameTooLong => RuleToken::WrongType,
            CardError::MissingField { .. } => RuleToken::MissingField,
            CardError::DuplicateField { .. } => RuleToken::DuplicateMapKey,
            CardError::UnknownField { .. } => RuleToken::UnknownField,
            CardError::NonCanonicalCbor => RuleToken::NonCanonicalUnclassified,
            CardError::InvalidVersion => RuleToken::UnsupportedVersion,
            CardError::FloatRejected { .. } | CardError::TagRejected => RuleToken::Rule4TagOrFloat,
            CardError::SigVerifyFailed(_) => RuleToken::SignatureInvalid,
            CardError::CborEncode(_) => RuleToken::InternalError,
        }
    }
}
