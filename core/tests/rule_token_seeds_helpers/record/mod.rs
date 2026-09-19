//! Single-fault `record` seeds, planted into
//! `core/fuzz/seeds/record/login.cbor` (keys `fields`, `last_mod_ms`,
//! `record_type`, `record_uuid`, `created_at_ms`; fields `username`,
//! `totp_seed`).
//!
//! [`surgery`] splits the base into entries and reassembles it; [`plants`]
//! holds one function per shape; [`cases`] is the table both the generator
//! and the label-binding check read. Split out of one 555-line file in the
//! PR #673 review.

mod plants;
mod surgery;

use secretary_core::vault::manifest::RuleToken;

use super::SeedCase;
// Every plant is named in the table below, so the glob keeps each row short.
use plants::*;

pub fn cases() -> Vec<SeedCase> {
    let case = |token: RuleToken,
                shape: &'static str,
                variant: &'static str,
                plant: fn(&[u8]) -> Vec<u8>| SeedCase {
        target: "record",
        token,
        shape,
        variant,
        plant,
    };
    use RuleToken::{
        DuplicateMapKey, IntegerOutOfRange, MalformedCbor, MissingField, NonCanonicalUnclassified,
        Rule4TagOrFloat, WrongType,
    };
    vec![
        case(MalformedCbor, "truncated", "CborDecode", truncated),
        case(
            MalformedCbor,
            "undefined_value",
            "CborDecode",
            undefined_value,
        ),
        case(
            MalformedCbor,
            "nested_indefinite_chunk",
            "CborDecode",
            nested_indefinite_chunk,
        ),
        case(
            MalformedCbor,
            "invalid_utf8_text",
            "CborDecode",
            invalid_utf8_text,
        ),
        case(Rule4TagOrFloat, "float_value", "FloatRejected", float_value),
        case(Rule4TagOrFloat, "tag_value", "TagRejected", tag_value),
        case(Rule4TagOrFloat, "bignum_tag", "TagRejected", bignum_tag),
        case(WrongType, "top_level_array", "NotAMap", top_level_array),
        case(WrongType, "non_text_key", "NonTextKey", non_text_key),
        case(WrongType, "record_uuid_text", "WrongType", record_uuid_text),
        case(
            WrongType,
            "record_uuid_short",
            "InvalidUuid",
            record_uuid_short,
        ),
        case(WrongType, "fields_not_a_map", "WrongType", fields_not_a_map),
        case(
            WrongType,
            "created_at_ms_bool",
            "WrongType",
            created_at_ms_bool,
        ),
        case(
            WrongType,
            "field_last_mod_bool",
            "WrongType",
            field_last_mod_bool,
        ),
        case(
            WrongType,
            "tags_not_an_array",
            "WrongType",
            tags_not_an_array,
        ),
        case(WrongType, "tag_not_text", "WrongType", tag_not_text),
        case(
            WrongType,
            "tombstone_not_a_bool",
            "WrongType",
            tombstone_not_a_bool,
        ),
        case(
            WrongType,
            "field_value_uint",
            "WrongType",
            field_value_wrong_type,
        ),
        case(
            WrongType,
            "field_device_uuid_short",
            "InvalidUuid",
            field_device_uuid_short,
        ),
        case(
            WrongType,
            "fields_non_text_key",
            "NonTextKey",
            fields_non_text_key,
        ),
        case(
            WrongType,
            "field_non_text_key",
            "NonTextKey",
            field_non_text_key,
        ),
        case(WrongType, "field_not_a_map", "WrongType", field_not_a_map),
        case(
            IntegerOutOfRange,
            "negative_created_at_ms",
            "IntegerOverflow",
            negative_created_at_ms,
        ),
        case(
            IntegerOutOfRange,
            "negative_tombstoned_at_ms",
            "IntegerOverflow",
            negative_tombstoned_at_ms,
        ),
        case(
            IntegerOutOfRange,
            "negative_field_last_mod",
            "IntegerOverflow",
            negative_field_last_mod,
        ),
        case(
            MissingField,
            "record_uuid",
            "MissingField",
            missing_record_uuid,
        ),
        case(
            MissingField,
            "field_value",
            "MissingField",
            missing_field_value,
        ),
        case(
            DuplicateMapKey,
            "record_level",
            "DuplicateKey",
            duplicate_record_key,
        ),
        case(
            DuplicateMapKey,
            "fields_level",
            "DuplicateKey",
            duplicate_field_name,
        ),
        case(
            DuplicateMapKey,
            "field_level",
            "DuplicateKey",
            duplicate_field_level_key,
        ),
        case(
            NonCanonicalUnclassified,
            "key_order",
            "NonCanonicalEncoding",
            key_order,
        ),
        case(
            NonCanonicalUnclassified,
            "indefinite_map",
            "NonCanonicalEncoding",
            indefinite_map,
        ),
        case(
            NonCanonicalUnclassified,
            "non_shortest_map_head",
            "NonCanonicalEncoding",
            non_shortest_map_head,
        ),
        case(
            NonCanonicalUnclassified,
            "trailing_bytes",
            "NonCanonicalEncoding",
            trailing_bytes,
        ),
        case(
            NonCanonicalUnclassified,
            "present_default_tags",
            "NonCanonicalEncoding",
            present_default_tags,
        ),
        case(
            NonCanonicalUnclassified,
            "present_default_tombstone",
            "NonCanonicalEncoding",
            present_default_tombstone,
        ),
        case(
            NonCanonicalUnclassified,
            "present_default_tombstoned_at_ms",
            "NonCanonicalEncoding",
            present_default_tombstoned_at_ms,
        ),
    ]
}

#[test]
fn reassembling_the_base_is_byte_identical() {
    let base = super::base("record");
    assert_eq!(
        surgery::map(&surgery::entries(&base)),
        base,
        "the entry split must round-trip the base"
    );
}
