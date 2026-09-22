//! Which token each `CardError` variant carries.

use crate::cbor::{CborErrorKind, CborFault};
use crate::crypto::sig::SigError;
use crate::identity::card::CardError;
use crate::vault::manifest::RuleToken;

/// `CardError`'s variant count. A new variant is a compile error in the
/// exhaustive match below first, and a failure of this count second.
const CARD_ERROR_VARIANTS: usize = 13;

fn fault(kind: CborErrorKind) -> CborFault {
    CborFault { kind, offset: None }
}

fn every_variant_and_its_token() -> Vec<(CardError, RuleToken)> {
    vec![
        (
            CardError::CborEncode(fault(CborErrorKind::Serialization)),
            RuleToken::InternalError,
        ),
        // Every decode kind is `malformed_cbor`, `RecursionLimit` included:
        // §6.2 rule 6, which the walk reports and `conformance_lib` reports
        // under the same token.
        (
            CardError::CborDecode(fault(CborErrorKind::Io)),
            RuleToken::MalformedCbor,
        ),
        (
            CardError::CborDecode(fault(CborErrorKind::Syntax)),
            RuleToken::MalformedCbor,
        ),
        (
            CardError::CborDecode(fault(CborErrorKind::Semantic)),
            RuleToken::MalformedCbor,
        ),
        (
            CardError::CborDecode(fault(CborErrorKind::RecursionLimit)),
            RuleToken::MalformedCbor,
        ),
        (
            CardError::Malformed("expected top-level CBOR map"),
            RuleToken::WrongType,
        ),
        (
            CardError::MissingField {
                field: "card_version",
            },
            RuleToken::MissingField,
        ),
        (
            CardError::DuplicateField {
                field: "created_at",
            },
            RuleToken::DuplicateMapKey,
        ),
        (
            CardError::UnknownField { index: 0 },
            RuleToken::UnknownField,
        ),
        (
            CardError::NonCanonicalCbor,
            RuleToken::NonCanonicalUnclassified,
        ),
        (CardError::InvalidVersion, RuleToken::UnsupportedVersion),
        (CardError::InvalidFieldLength, RuleToken::WrongType),
        // A length bound, so `wrong_type` — the same token a fixed-size field
        // at the wrong length takes. Deliberately NOT a 19th vocabulary
        // variant: one length bound draws no distinction that carries
        // evidence (design §3.5).
        (CardError::DisplayNameTooLong, RuleToken::WrongType),
        (
            CardError::FloatRejected { field: "<root>" },
            RuleToken::Rule4TagOrFloat,
        ),
        (CardError::TagRejected, RuleToken::Rule4TagOrFloat),
        // Unreachable from the `contact_card` replay target — it calls
        // `from_canonical_cbor`, which does not verify — so this is a
        // diagnostic mapping, exactly as `BlockError`'s AEAD and signature
        // arms are.
        (
            CardError::SigVerifyFailed(SigError::Ed25519VerifyFailed),
            RuleToken::SignatureInvalid,
        ),
    ]
}

#[test]
fn every_card_error_variant_carries_its_declared_token() {
    let rows = every_variant_and_its_token();
    for (err, want) in &rows {
        assert_eq!(err.rule_token(), *want, "variant {err:?}");
    }

    // Exhaustive: a fourteenth variant is a COMPILE error here.
    for (err, _) in &rows {
        match err {
            CardError::CborEncode(_)
            | CardError::CborDecode(_)
            | CardError::Malformed(_)
            | CardError::MissingField { .. }
            | CardError::DuplicateField { .. }
            | CardError::UnknownField { .. }
            | CardError::NonCanonicalCbor
            | CardError::InvalidVersion
            | CardError::InvalidFieldLength
            | CardError::DisplayNameTooLong
            | CardError::FloatRejected { .. }
            | CardError::TagRejected
            | CardError::SigVerifyFailed(_) => (),
        }
    }

    let distinct: std::collections::HashSet<_> = rows
        .iter()
        .map(|(e, _)| std::mem::discriminant(e))
        .collect();
    assert_eq!(
        distinct.len(),
        CARD_ERROR_VARIANTS,
        "the table covers {} of the {CARD_ERROR_VARIANTS} CardError variants",
        distinct.len()
    );
}
