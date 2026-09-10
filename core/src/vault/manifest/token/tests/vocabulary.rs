//! The token set: spellings, completeness, phase-dependence, and the shared
//! JSON fixture.

use super::super::*;

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

/// A variant's SPELLING, not just its variant identity.
///
/// `token_strings_are_distinct` proves no two tokens share a string and
/// `vocabulary_fixture_matches_the_enum` looks each row up BY `as_str()`, so
/// swapping two spellings of the same phase-dependence class — `missing_field`
/// with `wrong_type`, say, or `aead_failure` with `signature_invalid` — passes
/// both, and passes every mapping test above, which compare variants rather
/// than strings. The Python side reads only the string, so a permutation is a
/// silent cross-language rename.
#[test]
fn each_variant_spells_itself_the_same_way_forever() {
    let want = [
        (RuleToken::Rule2IndefiniteLength, "rule2_indefinite_length"),
        (RuleToken::Rule3NonShortestForm, "rule3_non_shortest_form"),
        (RuleToken::Rule4TagOrFloat, "rule4_tag_or_float"),
        (
            RuleToken::NonCanonicalUnclassified,
            "non_canonical_unclassified",
        ),
        (RuleToken::ArraySortOrder, "array_sort_order"),
        (RuleToken::RepeatedArrayValue, "repeated_array_value"),
        (RuleToken::DuplicateMapKey, "duplicate_map_key"),
        (RuleToken::MissingField, "missing_field"),
        (RuleToken::WrongType, "wrong_type"),
        (RuleToken::IntegerOutOfRange, "integer_out_of_range"),
        (RuleToken::UnsupportedVersion, "unsupported_version"),
        (RuleToken::MalformedCbor, "malformed_cbor"),
        (RuleToken::ContainerMalformed, "container_malformed"),
        (RuleToken::AeadFailure, "aead_failure"),
        (RuleToken::SignatureInvalid, "signature_invalid"),
        (RuleToken::EncoderRefusal, "encoder_refusal"),
        (RuleToken::InternalError, "internal_error"),
    ];
    assert_eq!(want.len(), RuleToken::ALL.len());
    for (token, spelling) in want {
        assert_eq!(token.as_str(), spelling, "{token:?} changed its spelling");
    }
}
