//! Unit tests for the manifest-body surgery helper (#600).
//!
//! The helper builds fixtures for OTHER tests, so a bug in it makes those
//! tests silently test the wrong bytes — the class this repo has hit
//! repeatedly (a mutation that fails to apply looks exactly like a
//! mutation nothing catches). Its two load-bearing claims are asserted
//! here directly rather than inferred from its consumers passing.

use super::*;
use crate::vault::manifest::test_support::populated_manifest;
use crate::vault::manifest::{decode_manifest, encode_manifest};

/// CLAIM 1: parse-then-re-encode is the identity on a canonical body.
///
/// Everything the helper does rests on this — it returns a re-encoded
/// `Value`, so if the round-trip perturbed anything, every fixture it
/// builds would differ from the encoder's output in ways nobody chose.
/// The manifest uniqueness corpus depends on it byte-for-byte against a
/// frozen fixture; this states it in one line, where a failure names the
/// cause instead of surfacing as "the fixture has been hand-edited".
#[test]
fn parse_and_reencode_is_byte_preserving_for_a_canonical_body() {
    let body = encode_manifest(&populated_manifest())
        .expect("encode")
        .expose()
        .to_vec();

    let v: ciborium::value::Value = ciborium::de::from_reader(&body[..]).expect("parse");
    let mut round_tripped = Vec::new();
    ciborium::ser::into_writer(&v, &mut round_tripped).expect("re-encode");

    assert_eq!(
        round_tripped, body,
        "ciborium's Value round-trip must be byte-preserving for a canonical \
         manifest body -- every surgery fixture inherits any drift here"
    );
}

/// CLAIM 2: the planted field is the ONLY thing that changes.
///
/// A helper that also perturbed a neighbouring field would still produce
/// a body the decoder rejects, so a consumer asserting only `is_err()`
/// could not tell the two apart — and would be pinning the wrong rule.
#[test]
fn copy_entry_field_changes_the_named_field_and_nothing_else() {
    let m = populated_manifest();
    let body = encode_manifest(&m).expect("encode").expose().to_vec();
    let before = decode_manifest(&body).expect("baseline decodes");

    let planted = copy_entry_field(&body, BodyArray::Top("blocks"), 0, 1, "block_uuid");

    // The result no longer decodes (that is the point), so compare through
    // `Value` rather than through the typed decoder.
    let after: ciborium::value::Value =
        ciborium::de::from_reader(&planted[..]).expect("planted body still parses");
    let blocks = match &after {
        ciborium::value::Value::Map(entries) => entries
            .iter()
            .find(|(k, _)| k.as_text() == Some("blocks"))
            .map(|(_, v)| v)
            .expect("blocks key"),
        other => panic!("not a map: {other:?}"),
    };
    let items = match blocks {
        ciborium::value::Value::Array(a) => a,
        other => panic!("blocks is not an array: {other:?}"),
    };

    assert_eq!(
        field_of(&items[1], "block_uuid"),
        field_of(&items[0], "block_uuid"),
        "the repeat must have been planted"
    );
    assert_eq!(
        field_of(&items[1], "block_name").as_text(),
        Some(before.blocks[1].block_name.as_str()),
        "no neighbouring field may move"
    );
    assert_eq!(
        field_of(&items[0], "block_name").as_text(),
        Some(before.blocks[0].block_name.as_str()),
        "the SOURCE element must be untouched"
    );
}

/// The nested arm, indexing a block other than the first.
///
/// §4.2 constrains "**each** block's" `vector_clock_summary`, so the
/// fixtures that matter plant into a non-first block — a helper that
/// silently ignored the index would make those fixtures test `blocks[0]`
/// and the "each block" claim would go unpinned.
#[test]
fn copy_entry_field_reaches_into_a_non_first_block() {
    let m = populated_manifest();
    let body = encode_manifest(&m).expect("encode").expose().to_vec();

    let planted = copy_entry_field(
        &body,
        BodyArray::InBlock(1, "vector_clock_summary"),
        0,
        1,
        "device_uuid",
    );

    assert_ne!(planted, body, "the surgery must change the body");
    assert!(
        matches!(
            decode_manifest(&planted),
            Err(crate::vault::manifest::ManifestError::VectorClockDuplicateDevice)
        ),
        "a repeat in blocks[1]'s summary must be rejected by the decoder"
    );
}

/// The vacuity guards fire rather than silently producing a no-op
/// fixture. Both are the "a mutation that did not apply looks like a
/// mutation nothing caught" trap, caught at the helper instead of at
/// every consumer.
#[test]
#[should_panic(expected = "already share")]
fn copy_entry_field_refuses_a_source_and_target_that_already_agree() {
    let mut m = populated_manifest();
    m.blocks[0].recipients = vec![[0xc1; 16]];
    m.blocks[1].recipients = vec![[0xc1; 16]];
    // Both blocks' single recipient is the same value, so copying
    // `blocks`-level `suite_id` (identical across entries by construction)
    // plants nothing.
    let body = encode_manifest(&m).expect("encode").expose().to_vec();
    let _ = copy_entry_field(&body, BodyArray::Top("blocks"), 0, 1, "suite_id");
}

#[test]
#[should_panic(expected = "plants nothing")]
fn copy_entry_field_refuses_to_copy_an_element_onto_itself() {
    let body = encode_manifest(&populated_manifest())
        .expect("encode")
        .expose()
        .to_vec();
    let _ = copy_entry_field(&body, BodyArray::Top("blocks"), 0, 0, "block_uuid");
}
