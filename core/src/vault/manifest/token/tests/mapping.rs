//! Which token each `ManifestError` variant carries.

use super::super::*;
use crate::vault::manifest::ManifestError;

/// The four causes must each keep their own token. Collapsing any two would
/// make #621's divergence — array sort order vs §6.2 rule 2 — invisible again.
#[test]
fn each_non_canonical_cause_has_its_own_token() {
    use crate::vault::manifest::NonCanonicalCause as C;
    let pairs = [
        (C::ArraySortOrder, RuleToken::ArraySortOrder),
        (C::IndefiniteLength, RuleToken::Rule2IndefiniteLength),
        (C::NonShortestForm, RuleToken::Rule3NonShortestForm),
        (C::Unclassified, RuleToken::NonCanonicalUnclassified),
    ];
    for (cause, want) in pairs {
        let err = ManifestError::NonCanonicalEncoding { cause, at: None };
        assert_eq!(err.rule_token(), want, "cause {:?}", cause);
    }
}

/// A repeated map key and a repeated ARRAY value are different rules and must
/// not share a token: §4.2 orders the first against the type checks and leaves
/// the second alone.
#[test]
fn map_key_repeats_and_array_value_repeats_are_different_tokens() {
    let map_key = ManifestError::DuplicateKey {
        field: "manifest",
        index: 1,
    };
    assert_eq!(map_key.rule_token(), RuleToken::DuplicateMapKey);
    for err in [
        ManifestError::DuplicateBlockUuid,
        ManifestError::DuplicateTrashUuid,
        ManifestError::VectorClockDuplicateDevice,
    ] {
        assert_eq!(err.rule_token(), RuleToken::RepeatedArrayValue);
    }
}

/// A decoder rejection and an ENCODER refusal are different events (#600,
/// #587) and must stay different tokens — otherwise a body a caller built
/// wrong in memory would be compared against a peer's reading of real bytes.
#[test]
fn encoder_refusals_are_not_decoder_rejections() {
    for err in [
        ManifestError::EncodeDuplicateBlockUuid,
        ManifestError::EncodeDuplicateTrashUuid,
        ManifestError::EncodeVectorClockDuplicateDevice,
        ManifestError::EncodeUnsupportedManifestVersion(7),
        ManifestError::EncodeUnsupportedFormatVersion(9),
        ManifestError::EncodeUnsupportedSuiteId(9),
    ] {
        assert_eq!(err.rule_token(), RuleToken::EncoderRefusal);
    }
    assert_eq!(
        ManifestError::UnsupportedManifestVersion(7).rule_token(),
        RuleToken::UnsupportedVersion
    );
}

/// The three v1 sentinels share one token at BOTH layers. `header.rs` raises
/// the same two variants the body sentinel check does, which is exactly why
/// `manifest_file` cannot be token-compared (#640) — recorded here so the
/// reason survives beside the mapping that causes it.
#[test]
fn every_v1_sentinel_maps_to_unsupported_version() {
    for err in [
        ManifestError::UnsupportedManifestVersion(7),
        ManifestError::UnsupportedFormatVersion(9),
        ManifestError::UnsupportedSuiteId(9),
    ] {
        assert_eq!(err.rule_token(), RuleToken::UnsupportedVersion);
    }
}

/// A real decode of a real corrupt body must produce the token the corpus
/// says. Reading the match arms proves nothing about which arm the decoder
/// reaches; this drives `decode_manifest` end to end.
#[test]
fn a_real_rejection_carries_the_expected_token() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds/manifest_body");
    let cases = [
        ("top__rule4_float.bin", RuleToken::Rule4TagOrFloat),
        (
            "top__rule2_indefinite_map.bin",
            RuleToken::Rule2IndefiniteLength,
        ),
        (
            "top__rule3_non_shortest_int.bin",
            RuleToken::Rule3NonShortestForm,
        ),
        ("keyorder__top.bin", RuleToken::NonCanonicalUnclassified),
        ("arraysort__blocks.bin", RuleToken::ArraySortOrder),
        (
            "uniq__blocks__duplicate_block_uuid.bin",
            RuleToken::RepeatedArrayValue,
        ),
    ];
    for (name, want) in cases {
        let bytes =
            std::fs::read(dir.join(name)).unwrap_or_else(|e| panic!("read {}: {}", name, e));
        let err = crate::vault::manifest::decode_manifest(&bytes)
            .expect_err(&format!("{} must be rejected", name));
        assert_eq!(err.rule_token(), want, "seed {}", name);
    }
}

/// Every `ManifestError` variant, constructed, beside the token it must carry.
///
/// **Why a second table rather than more one-off tests.** Before this, fifteen
/// of the thirty-five arms were pinned and twenty were not, and seven of those
/// twenty are live on the ONE token-compared target: `MissingField`,
/// `NotAMap`, `NonTextKey`, `WrongType`, `InvalidByteLength`,
/// `IntegerOutOfRange` and the `Canonical(_)` family. A wrong-but-valid token
/// on any of them compiled clean, passed the whole tree, and — because
/// `differential_replay.rs` runs in no CI workflow (#647) and Section RTV
/// checks token MEMBERSHIP rather than identity — would have reached a peer as
/// a silently wrong rule name.
///
/// This is deliberately a SECOND, independent declaration of the mapping, in
/// the same spirit as the phase-dependent set being declared on both sides of
/// the language boundary. Copying a production edit into this table is a
/// visible act; inheriting it silently is not.
///
/// # LIMITS
///
/// The exhaustive `match` in [`every_variant_carries_its_token`] means a
/// thirty-sixth variant fails to COMPILE here, so it cannot be added without a
/// decision. It does NOT force that variant into this table: an author who
/// adds the arm and leaves the row out compiles clean, and only the row-count
/// assertion — a literal, which they would then have to change — catches it.
/// Say the weaker thing, as [`RuleToken::ALL`]'s own doc does about the same
/// residual.
fn every_variant_and_its_token() -> Vec<(ManifestError, RuleToken)> {
    use crate::cbor::{CborErrorKind, CborFault};
    use crate::crypto::sig::SigError;
    use crate::vault::canonical::CanonicalError;
    use crate::vault::manifest::NonCanonicalCause as C;

    let fault = CborFault {
        kind: CborErrorKind::Syntax,
        offset: None,
    };
    vec![
        // --- §4.2 body: canonical form -------------------------------
        (
            ManifestError::NonCanonicalEncoding {
                cause: C::ArraySortOrder,
                at: None,
            },
            RuleToken::ArraySortOrder,
        ),
        (
            ManifestError::NonCanonicalEncoding {
                cause: C::IndefiniteLength,
                at: None,
            },
            RuleToken::Rule2IndefiniteLength,
        ),
        (
            ManifestError::NonCanonicalEncoding {
                cause: C::NonShortestForm,
                at: None,
            },
            RuleToken::Rule3NonShortestForm,
        ),
        (
            ManifestError::NonCanonicalEncoding {
                cause: C::Unclassified,
                at: None,
            },
            RuleToken::NonCanonicalUnclassified,
        ),
        (
            ManifestError::Canonical(CanonicalError::FloatRejected { field: "blocks" }),
            RuleToken::Rule4TagOrFloat,
        ),
        (
            ManifestError::Canonical(CanonicalError::TagRejected { field: "blocks" }),
            RuleToken::Rule4TagOrFloat,
        ),
        (
            ManifestError::Canonical(CanonicalError::DuplicateKey { index: 1 }),
            RuleToken::DuplicateMapKey,
        ),
        (
            ManifestError::Canonical(CanonicalError::CborEncode(fault)),
            RuleToken::InternalError,
        ),
        (
            ManifestError::Canonical(CanonicalError::CapacityBoundExceeded {
                actual: 2,
                bound: 1,
            }),
            RuleToken::InternalError,
        ),
        // --- §4.2 body: schema ---------------------------------------
        (
            ManifestError::DuplicateKey {
                field: "manifest",
                index: 1,
            },
            RuleToken::DuplicateMapKey,
        ),
        (
            ManifestError::MissingField { field: "blocks" },
            RuleToken::MissingField,
        ),
        (ManifestError::NotAMap, RuleToken::WrongType),
        (ManifestError::NonTextKey, RuleToken::WrongType),
        (
            ManifestError::WrongType {
                field: "blocks",
                expected: "array",
            },
            RuleToken::WrongType,
        ),
        (
            ManifestError::InvalidByteLength {
                field: "vault_uuid",
                expected: 16,
                length: 15,
            },
            RuleToken::WrongType,
        ),
        (
            ManifestError::IntegerOutOfRange {
                field: "memory_kib",
                value: 1 << 40,
            },
            RuleToken::IntegerOutOfRange,
        ),
        // --- v1 sentinels, at BOTH layers ----------------------------
        (
            ManifestError::UnsupportedManifestVersion(7),
            RuleToken::UnsupportedVersion,
        ),
        (
            ManifestError::UnsupportedFormatVersion(9),
            RuleToken::UnsupportedVersion,
        ),
        (
            ManifestError::UnsupportedSuiteId(9),
            RuleToken::UnsupportedVersion,
        ),
        // --- §4.2 arrays ---------------------------------------------
        (
            ManifestError::VectorClockDuplicateDevice,
            RuleToken::RepeatedArrayValue,
        ),
        (
            ManifestError::DuplicateBlockUuid,
            RuleToken::RepeatedArrayValue,
        ),
        (
            ManifestError::DuplicateTrashUuid,
            RuleToken::RepeatedArrayValue,
        ),
        // --- the encoder refusing to emit a body ---------------------
        (
            ManifestError::EncodeDuplicateBlockUuid,
            RuleToken::EncoderRefusal,
        ),
        (
            ManifestError::EncodeDuplicateTrashUuid,
            RuleToken::EncoderRefusal,
        ),
        (
            ManifestError::EncodeVectorClockDuplicateDevice,
            RuleToken::EncoderRefusal,
        ),
        (
            ManifestError::EncodeUnsupportedManifestVersion(7),
            RuleToken::EncoderRefusal,
        ),
        (
            ManifestError::EncodeUnsupportedFormatVersion(9),
            RuleToken::EncoderRefusal,
        ),
        (
            ManifestError::EncodeUnsupportedSuiteId(9),
            RuleToken::EncoderRefusal,
        ),
        // --- CBOR well-formedness ------------------------------------
        (ManifestError::CborDecode(fault), RuleToken::MalformedCbor),
        // --- §4.1 file envelope --------------------------------------
        (
            ManifestError::BadMagic {
                expected: 1,
                got: 2,
            },
            RuleToken::ContainerMalformed,
        ),
        (
            ManifestError::UnsupportedFileKind {
                expected: 1,
                got: 2,
            },
            RuleToken::ContainerMalformed,
        ),
        (
            ManifestError::HeaderTruncated { need: 2, got: 1 },
            RuleToken::ContainerMalformed,
        ),
        (
            ManifestError::SectionTruncated {
                section: "body",
                need: 2,
                got: 1,
            },
            RuleToken::ContainerMalformed,
        ),
        (
            ManifestError::AeadCtLenMismatch {
                declared: 2,
                remaining: 1,
            },
            RuleToken::ContainerMalformed,
        ),
        (
            ManifestError::TrailingBytes(1),
            RuleToken::ContainerMalformed,
        ),
        (
            ManifestError::SigEdWrongLength {
                expected: 64,
                got: 63,
            },
            RuleToken::ContainerMalformed,
        ),
        (
            ManifestError::SigPqWrongLength {
                expected: 3309,
                got: 3308,
            },
            RuleToken::ContainerMalformed,
        ),
        (ManifestError::AeadFailure, RuleToken::AeadFailure),
        (
            ManifestError::Ed25519SignatureInvalid,
            RuleToken::SignatureInvalid,
        ),
        (
            ManifestError::MlDsa65SignatureInvalid,
            RuleToken::SignatureInvalid,
        ),
        // --- this implementation's own faults ------------------------
        (ManifestError::CborEncode(fault), RuleToken::InternalError),
        (
            ManifestError::SignInternal(SigError::Ed25519VerifyFailed),
            RuleToken::InternalError,
        ),
    ]
}

/// Drive [`every_variant_and_its_token`] and require the production match to
/// agree with it, then require the table to have covered every variant.
#[test]
fn every_variant_carries_its_token() {
    let rows = every_variant_and_its_token();

    for (err, want) in &rows {
        assert_eq!(err.rule_token(), *want, "variant {err:?}");
    }

    // Exhaustive over `ManifestError`: a thirty-sixth variant is a COMPILE
    // error here, so it cannot be introduced without someone looking at this
    // table. See this module's LIMITS note for what that does NOT force.
    for (err, _) in &rows {
        match err {
            ManifestError::CborEncode(_)
            | ManifestError::CborDecode(_)
            | ManifestError::NotAMap
            | ManifestError::NonTextKey
            | ManifestError::DuplicateKey { .. }
            | ManifestError::MissingField { .. }
            | ManifestError::WrongType { .. }
            | ManifestError::InvalidByteLength { .. }
            | ManifestError::IntegerOutOfRange { .. }
            | ManifestError::UnsupportedManifestVersion(_)
            | ManifestError::UnsupportedFormatVersion(_)
            | ManifestError::UnsupportedSuiteId(_)
            | ManifestError::VectorClockDuplicateDevice
            | ManifestError::DuplicateBlockUuid
            | ManifestError::DuplicateTrashUuid
            | ManifestError::EncodeDuplicateBlockUuid
            | ManifestError::EncodeDuplicateTrashUuid
            | ManifestError::EncodeVectorClockDuplicateDevice
            | ManifestError::EncodeUnsupportedManifestVersion(_)
            | ManifestError::EncodeUnsupportedFormatVersion(_)
            | ManifestError::EncodeUnsupportedSuiteId(_)
            | ManifestError::Canonical(_)
            | ManifestError::NonCanonicalEncoding { .. }
            | ManifestError::BadMagic { .. }
            | ManifestError::UnsupportedFileKind { .. }
            | ManifestError::HeaderTruncated { .. }
            | ManifestError::AeadFailure
            | ManifestError::SectionTruncated { .. }
            | ManifestError::AeadCtLenMismatch { .. }
            | ManifestError::TrailingBytes(_)
            | ManifestError::SigEdWrongLength { .. }
            | ManifestError::SigPqWrongLength { .. }
            | ManifestError::Ed25519SignatureInvalid
            | ManifestError::MlDsa65SignatureInvalid
            | ManifestError::SignInternal(_) => (),
        }
    }

    // Every variant appears, counted by discriminant so the five `Canonical`
    // rows and the four `NonCanonicalEncoding` rows collapse to one each.
    let distinct: std::collections::HashSet<_> = rows
        .iter()
        .map(|(e, _)| std::mem::discriminant(e))
        .collect();
    assert_eq!(
        distinct.len(),
        35,
        "every_variant_and_its_token covers {} of the 35 ManifestError variants",
        distinct.len()
    );

    // Every token the vocabulary declares is either produced by some variant
    // or is one this crate cannot raise. Nothing is produced today that the
    // vocabulary does not declare.
    for (_, want) in &rows {
        assert!(
            RuleToken::ALL.contains(want),
            "{want:?} is not in RuleToken::ALL"
        );
    }
}
