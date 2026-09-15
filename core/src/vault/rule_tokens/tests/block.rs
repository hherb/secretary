//! Which token each `BlockError` variant carries.

use rand_core::{OsRng, RngCore};

use crate::cbor::{CborErrorKind, CborFault};
use crate::crypto::aead::AeadError;
use crate::crypto::kem::KemError;
use crate::crypto::sig::SigError;
use crate::identity::fingerprint::Fingerprint;
use crate::vault::block::{BlockError, BLOCK_UUID_LEN};
use crate::vault::manifest::RuleToken;
use crate::vault::record::RecordError;

/// `BlockError`'s variant count. A new variant is a compile error in the
/// exhaustive match below first, and a failure of this count second.
const BLOCK_ERROR_VARIANTS: usize = 39;

/// A random 16-byte id. Error payloads never reach the token, but literal
/// byte arrays read as hard-coded key material to CodeQL.
fn random_id() -> [u8; BLOCK_UUID_LEN] {
    let mut id = [0u8; BLOCK_UUID_LEN];
    OsRng.fill_bytes(&mut id);
    id
}

fn random_fingerprint() -> Fingerprint {
    random_id()
}

fn fault() -> CborFault {
    CborFault {
        kind: CborErrorKind::Syntax,
        offset: None,
    }
}

fn every_variant_and_its_token() -> Vec<(BlockError, RuleToken)> {
    use RuleToken as T;
    vec![
        // Delegation: two inner variants with two different tokens.
        (BlockError::Record(RecordError::NonTextKey), T::WrongType),
        (
            BlockError::Record(RecordError::TagRejected),
            T::Rule4TagOrFloat,
        ),
        (BlockError::CborEncode(fault()), T::InternalError),
        (BlockError::CborDecode(fault()), T::MalformedCbor),
        (BlockError::BadMagic { found: 0 }, T::ContainerMalformed),
        (
            BlockError::UnsupportedFormatVersion { found: 2 },
            T::UnsupportedVersion,
        ),
        (
            BlockError::UnsupportedSuiteId { found: 2 },
            T::UnsupportedVersion,
        ),
        (
            BlockError::WrongFileKind {
                found: 2,
                expected: 3,
            },
            T::ContainerMalformed,
        ),
        (
            BlockError::Truncated { needed: 2, got: 1 },
            T::ContainerMalformed,
        ),
        (BlockError::VectorClockNotSorted, T::ArraySortOrder),
        (
            BlockError::VectorClockDuplicateDevice,
            T::RepeatedArrayValue,
        ),
        (
            BlockError::VectorClockCountMismatch {
                declared: 2,
                actual: 1,
            },
            T::ContainerMalformed,
        ),
        (
            BlockError::BlockUuidMismatch {
                header: random_id(),
                plaintext: random_id(),
            },
            T::ContainerMalformed,
        ),
        (
            BlockError::DuplicateRecipient {
                fingerprint: random_fingerprint(),
            },
            T::RepeatedArrayValue,
        ),
        (BlockError::EmptyRecipientList, T::ContainerMalformed),
        (
            BlockError::TooManyRecipients { count: 2 },
            T::EncoderRefusal,
        ),
        (BlockError::RecipientsNotSorted, T::ArraySortOrder),
        (
            BlockError::RecipientCtPqWrongLength { found: 1 },
            T::EncoderRefusal,
        ),
        (
            BlockError::RecipientCtWrongLength { found: 1 },
            T::EncoderRefusal,
        ),
        (
            BlockError::NotARecipient {
                fingerprint: random_fingerprint(),
            },
            T::AeadFailure,
        ),
        (BlockError::Aead(AeadError::Decryption), T::AeadFailure),
        (BlockError::Kem(KemError::MlKemDecapsFailed), T::AeadFailure),
        (BlockError::NotAMap, T::WrongType),
        (BlockError::NonTextKey, T::WrongType),
        (
            BlockError::MissingField {
                field: "block_uuid",
            },
            T::MissingField,
        ),
        (
            BlockError::WrongType {
                field: "records",
                expected: "array",
            },
            T::WrongType,
        ),
        (
            BlockError::InvalidUuid {
                field: "block_uuid",
                length: 3,
            },
            T::WrongType,
        ),
        (
            BlockError::IntegerOverflow {
                field: "block_version",
            },
            T::IntegerOutOfRange,
        ),
        (
            BlockError::DuplicateKey {
                field: "<block>",
                index: 1,
            },
            T::DuplicateMapKey,
        ),
        (
            BlockError::FloatRejected { field: "<root>" },
            T::Rule4TagOrFloat,
        ),
        (BlockError::TagRejected, T::Rule4TagOrFloat),
        (
            BlockError::NonCanonicalEncoding,
            T::NonCanonicalUnclassified,
        ),
        (
            BlockError::Sig(SigError::Ed25519VerifyFailed),
            T::SignatureInvalid,
        ),
        (
            BlockError::SigEdWrongLength { found: 1 },
            T::ContainerMalformed,
        ),
        (BlockError::SigPqTooLong { found: 1 }, T::EncoderRefusal),
        (
            BlockError::SigPqWrongLength { found: 1 },
            T::ContainerMalformed,
        ),
        (
            BlockError::AuthorFingerprintMismatch {
                expected: random_fingerprint(),
                found: random_fingerprint(),
            },
            T::SignatureInvalid,
        ),
        (
            BlockError::TrailingBytes { count: 1 },
            T::ContainerMalformed,
        ),
        (
            BlockError::CanonicalSizeBoundExceeded {
                actual: 2,
                bound: 1,
            },
            T::InternalError,
        ),
        (
            BlockError::CanonicalDuplicateKey { index: 1 },
            T::DuplicateMapKey,
        ),
    ]
}

#[test]
fn every_block_error_variant_carries_its_declared_token() {
    let rows = every_variant_and_its_token();
    for (err, want) in &rows {
        assert_eq!(err.rule_token(), *want, "variant {err:?}");
    }

    // Exhaustive: a fortieth variant is a COMPILE error here.
    for (err, _) in &rows {
        match err {
            BlockError::Record(_)
            | BlockError::CborEncode(_)
            | BlockError::CborDecode(_)
            | BlockError::BadMagic { .. }
            | BlockError::UnsupportedFormatVersion { .. }
            | BlockError::UnsupportedSuiteId { .. }
            | BlockError::WrongFileKind { .. }
            | BlockError::Truncated { .. }
            | BlockError::VectorClockNotSorted
            | BlockError::VectorClockDuplicateDevice
            | BlockError::VectorClockCountMismatch { .. }
            | BlockError::BlockUuidMismatch { .. }
            | BlockError::DuplicateRecipient { .. }
            | BlockError::EmptyRecipientList
            | BlockError::TooManyRecipients { .. }
            | BlockError::RecipientsNotSorted
            | BlockError::RecipientCtPqWrongLength { .. }
            | BlockError::RecipientCtWrongLength { .. }
            | BlockError::NotARecipient { .. }
            | BlockError::Aead(_)
            | BlockError::Kem(_)
            | BlockError::NotAMap
            | BlockError::NonTextKey
            | BlockError::MissingField { .. }
            | BlockError::WrongType { .. }
            | BlockError::InvalidUuid { .. }
            | BlockError::IntegerOverflow { .. }
            | BlockError::DuplicateKey { .. }
            | BlockError::FloatRejected { .. }
            | BlockError::TagRejected
            | BlockError::NonCanonicalEncoding
            | BlockError::Sig(_)
            | BlockError::SigEdWrongLength { .. }
            | BlockError::SigPqTooLong { .. }
            | BlockError::SigPqWrongLength { .. }
            | BlockError::AuthorFingerprintMismatch { .. }
            | BlockError::TrailingBytes { .. }
            | BlockError::CanonicalSizeBoundExceeded { .. }
            | BlockError::CanonicalDuplicateKey { .. } => (),
        }
    }

    // The two `Record(_)` rows collapse to one discriminant.
    let distinct: std::collections::HashSet<_> = rows
        .iter()
        .map(|(e, _)| std::mem::discriminant(e))
        .collect();
    assert_eq!(
        distinct.len(),
        BLOCK_ERROR_VARIANTS,
        "the table covers {} of the {BLOCK_ERROR_VARIANTS} BlockError variants",
        distinct.len()
    );
}
