use super::*;

/// Every token spells itself distinctly. Two tokens sharing a string would
/// make the Python side unable to tell them apart, and the divergence would
/// present as agreement — the exact failure this vocabulary exists to end.
#[test]
fn token_strings_are_distinct() {
    let mut seen = std::collections::BTreeSet::new();
    for t in RuleToken::ALL {
        assert!(
            seen.insert(t.as_str()),
            "two RuleToken variants share the spelling {:?}",
            t.as_str()
        );
    }
    assert_eq!(seen.len(), RuleToken::ALL.len());
}

/// `ALL` must really be all of them. A variant missing from the slice is
/// invisible to the fixture cross-check below and to Python.
///
/// Note what this does and does not force, because the obvious reading is
/// too strong: adding a variant *and nothing else* is a COMPILE error here,
/// since the match below stops being exhaustive. Adding the variant AND its
/// arm while forgetting `ALL` compiles and passes — the match then iterates
/// 17 elements and the assertion still reads 17. See `RuleToken::ALL`'s own
/// doc for what would catch that pair of edits.
#[test]
fn all_lists_every_variant() {
    // Exhaustive match over the variants iterated out of `ALL`: adding a
    // variant without adding an arm here is a COMPILE error.
    for t in RuleToken::ALL {
        match t {
            RuleToken::Rule2IndefiniteLength
            | RuleToken::Rule3NonShortestForm
            | RuleToken::Rule4TagOrFloat
            | RuleToken::NonCanonicalUnclassified
            | RuleToken::ArraySortOrder
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
            | RuleToken::InternalError => (),
        };
    }
    assert_eq!(RuleToken::ALL.len(), 17);
}

/// Exactly the four rules vault-format §4.2 declares unordered are
/// phase-dependent. Pinned as a SET, not per-variant, so widening the
/// predicate without widening the spec reds here.
#[test]
fn phase_dependent_set_matches_the_spec() {
    let got: std::collections::BTreeSet<&str> = RuleToken::ALL
        .iter()
        .filter(|t| t.is_phase_dependent())
        .map(|t| t.as_str())
        .collect();
    let want: std::collections::BTreeSet<&str> = [
        "array_sort_order",
        "non_canonical_unclassified",
        "rule2_indefinite_length",
        "rule3_non_shortest_form",
    ]
    .into_iter()
    .collect();
    assert_eq!(got, want);
}

/// Rule 4 is deliberately NOT phase-dependent: neither reader design obtains
/// it from the re-encode, so §4.2 requires both to run the walk first. If this
/// ever flips, #618's whole precedence paragraph has been undone.
#[test]
fn rule4_is_ordered_not_phase_dependent() {
    assert!(!RuleToken::Rule4TagOrFloat.is_phase_dependent());
}

/// The committed fixture both languages read must agree with this enum, in
/// BOTH directions. Without it the two could drift onto different spellings
/// and every cross-language comparison would silently become a mismatch.
#[test]
fn vocabulary_fixture_matches_the_enum() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/rule_token_vocabulary.json");
    let raw = std::fs::read_to_string(&path).expect("read rule_token_vocabulary.json");
    let doc: serde_json::Value = serde_json::from_str(&raw).expect("parse vocabulary JSON");
    let rows = doc["tokens"]
        .as_object()
        .expect("`tokens` must be an object");

    assert_eq!(
        rows.len(),
        RuleToken::ALL.len(),
        "fixture has {} tokens, enum has {}",
        rows.len(),
        RuleToken::ALL.len()
    );
    for t in RuleToken::ALL {
        let row = rows
            .get(t.as_str())
            .unwrap_or_else(|| panic!("fixture is missing token {:?}", t.as_str()));
        let want = row["phase_dependent"]
            .as_bool()
            .unwrap_or_else(|| panic!("token {:?} has no boolean phase_dependent", t.as_str()));
        assert_eq!(
            want,
            t.is_phase_dependent(),
            "token {:?}: fixture says phase_dependent={}, enum says {}",
            t.as_str(),
            want,
            t.is_phase_dependent()
        );
    }
}

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
