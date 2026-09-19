//! Which token each `RecordError` variant carries.

use crate::cbor::{CborErrorKind, CborFault};
use crate::vault::manifest::RuleToken;
use crate::vault::record::RecordError;

/// `RecordError`'s variant count. A new variant is a compile error in the
/// exhaustive match below first, and a failure of this count second.
const RECORD_ERROR_VARIANTS: usize = 14;

fn fault(kind: CborErrorKind) -> CborFault {
    CborFault { kind, offset: None }
}

fn every_variant_and_its_token() -> Vec<(RecordError, RuleToken)> {
    vec![
        (
            RecordError::CborEncode(fault(CborErrorKind::Serialization)),
            RuleToken::InternalError,
        ),
        // Every kind a decode can report is `malformed_cbor`, including
        // `RecursionLimit`: crypto-design §6.2 rule 6 (#667), which
        // `conformance_lib` reports under the same token.
        (
            RecordError::CborDecode(fault(CborErrorKind::Io)),
            RuleToken::MalformedCbor,
        ),
        (
            RecordError::CborDecode(fault(CborErrorKind::Syntax)),
            RuleToken::MalformedCbor,
        ),
        (
            RecordError::CborDecode(fault(CborErrorKind::Semantic)),
            RuleToken::MalformedCbor,
        ),
        (
            RecordError::CborDecode(fault(CborErrorKind::RecursionLimit)),
            RuleToken::MalformedCbor,
        ),
        (RecordError::NotAMap, RuleToken::WrongType),
        (RecordError::NonTextKey, RuleToken::WrongType),
        (
            RecordError::MissingField {
                field: "record_uuid",
            },
            RuleToken::MissingField,
        ),
        (
            RecordError::WrongType {
                field: "tags",
                expected: "array",
            },
            RuleToken::WrongType,
        ),
        (
            RecordError::InvalidUuid {
                field: "record_uuid",
                length: 3,
            },
            RuleToken::WrongType,
        ),
        (
            RecordError::IntegerOverflow {
                field: "created_at_ms",
            },
            RuleToken::IntegerOutOfRange,
        ),
        (
            RecordError::DuplicateKey {
                field: "<record>",
                index: 1,
            },
            RuleToken::DuplicateMapKey,
        ),
        (
            RecordError::FloatRejected { field: "<root>" },
            RuleToken::Rule4TagOrFloat,
        ),
        (RecordError::TagRejected, RuleToken::Rule4TagOrFloat),
        (
            RecordError::NonCanonicalEncoding,
            RuleToken::NonCanonicalUnclassified,
        ),
        (
            RecordError::CanonicalSizeBoundExceeded {
                actual: 2,
                bound: 1,
            },
            RuleToken::InternalError,
        ),
        (
            RecordError::CanonicalDuplicateKey { index: 1 },
            RuleToken::DuplicateMapKey,
        ),
    ]
}

#[test]
fn every_record_error_variant_carries_its_declared_token() {
    let rows = every_variant_and_its_token();
    for (err, want) in &rows {
        assert_eq!(err.rule_token(), *want, "variant {err:?}");
    }

    // Exhaustive: a fifteenth variant is a COMPILE error here.
    for (err, _) in &rows {
        match err {
            RecordError::CborEncode(_)
            | RecordError::CborDecode(_)
            | RecordError::NotAMap
            | RecordError::NonTextKey
            | RecordError::MissingField { .. }
            | RecordError::WrongType { .. }
            | RecordError::InvalidUuid { .. }
            | RecordError::IntegerOverflow { .. }
            | RecordError::DuplicateKey { .. }
            | RecordError::FloatRejected { .. }
            | RecordError::TagRejected
            | RecordError::NonCanonicalEncoding
            | RecordError::CanonicalSizeBoundExceeded { .. }
            | RecordError::CanonicalDuplicateKey { .. } => (),
        }
    }

    let distinct: std::collections::HashSet<_> = rows
        .iter()
        .map(|(e, _)| std::mem::discriminant(e))
        .collect();
    assert_eq!(
        distinct.len(),
        RECORD_ERROR_VARIANTS,
        "the table covers {} of the {RECORD_ERROR_VARIANTS} RecordError variants",
        distinct.len()
    );
}
