//! [`BlockError::rule_token`] (#641). Spec §3.2.

use crate::vault::block::BlockError;
use crate::vault::manifest::RuleToken;

impl BlockError {
    /// Which rule this rejection is reporting, as a language-neutral token
    /// shared with `conformance.py` (#641).
    ///
    /// **Exhaustive by construction**, for the reason
    /// [`RecordError::rule_token`](crate::vault::record::RecordError::rule_token)
    /// gives.
    ///
    /// **What the `block_file` replay target can reach.** That target
    /// round-trips `decode_block_file` → `encode_block_file` and never
    /// decrypts, so only the envelope arms below are compared. The plaintext
    /// arms match `RecordError`'s. The AEAD, KEM, signature and binding arms
    /// are unreachable from that target; each takes the nearest existing
    /// token and is a diagnostic only.
    pub fn rule_token(&self) -> RuleToken {
        match self {
            BlockError::Record(e) => e.rule_token(),

            // --- §6.1 / §6.2 envelope ------------------------------------
            BlockError::Truncated { .. }
            | BlockError::BadMagic { .. }
            | BlockError::WrongFileKind { .. }
            | BlockError::EmptyRecipientList
            | BlockError::SigEdWrongLength { .. }
            | BlockError::SigPqWrongLength { .. }
            | BlockError::TrailingBytes { .. }
            | BlockError::VectorClockCountMismatch { .. } => RuleToken::ContainerMalformed,
            BlockError::UnsupportedFormatVersion { .. } | BlockError::UnsupportedSuiteId { .. } => {
                RuleToken::UnsupportedVersion
            }
            BlockError::VectorClockNotSorted | BlockError::RecipientsNotSorted => {
                RuleToken::ArraySortOrder
            }
            BlockError::VectorClockDuplicateDevice | BlockError::DuplicateRecipient { .. } => {
                RuleToken::RepeatedArrayValue
            }
            // Caller-built values the ENCODER refuses. `TooManyRecipients`
            // also has a decode-side producer (`count * 1208` overflowing
            // `usize`), unreachable on any 64-bit target.
            BlockError::TooManyRecipients { .. }
            | BlockError::RecipientCtPqWrongLength { .. }
            | BlockError::RecipientCtWrongLength { .. }
            | BlockError::SigPqTooLong { .. } => RuleToken::EncoderRefusal,

            // --- §6.3 plaintext, as `RecordError` ------------------------
            BlockError::CborDecode(_) => RuleToken::MalformedCbor,
            BlockError::NotAMap
            | BlockError::NonTextKey
            | BlockError::WrongType { .. }
            | BlockError::InvalidUuid { .. } => RuleToken::WrongType,
            BlockError::IntegerOverflow { .. } => RuleToken::IntegerOutOfRange,
            BlockError::MissingField { .. } => RuleToken::MissingField,
            BlockError::DuplicateKey { .. } | BlockError::CanonicalDuplicateKey { .. } => {
                RuleToken::DuplicateMapKey
            }
            BlockError::FloatRejected { .. } | BlockError::TagRejected => {
                RuleToken::Rule4TagOrFloat
            }
            BlockError::NonCanonicalEncoding => RuleToken::NonCanonicalUnclassified,
            BlockError::CborEncode(_) | BlockError::CanonicalSizeBoundExceeded { .. } => {
                RuleToken::InternalError
            }

            // --- diagnostics only: unreachable from `block_file` ---------
            BlockError::Aead(_) | BlockError::Kem(_) | BlockError::NotARecipient { .. } => {
                RuleToken::AeadFailure
            }
            BlockError::Sig(_) | BlockError::AuthorFingerprintMismatch { .. } => {
                RuleToken::SignatureInvalid
            }
            BlockError::BlockUuidMismatch { .. } => RuleToken::ContainerMalformed,
        }
    }
}
