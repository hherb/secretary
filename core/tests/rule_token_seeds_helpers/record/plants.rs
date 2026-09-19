//! One plant per `record` seed shape: each takes the committed base and
//! returns it with exactly one fault planted.

use secretary_core::vault::record::RECORD_UUID_LEN;

use super::surgery::{
    entries, entry_bytes, inserted, map, repeated, shortened_uuid, small_count, text, value_of,
    with_edited_field, with_future_value, with_value, without, EDITED_FIELD,
};

// RFC 8949 bytes planted below.
const MAP_ONE_BYTE_COUNT: u8 = 0xb8;
const MAP_INDEFINITE: u8 = 0xbf;
const ARRAY_EMPTY: u8 = 0x80;
const ARRAY_1: u8 = 0x81;
const BYTES_SMALL_BASE: u8 = 0x40;
const TEXT_SMALL_BASE: u8 = 0x60;
const TEXT_INDEFINITE: u8 = 0x7f;
const UINT_ZERO: u8 = 0x00;
const UINT_ONE: u8 = 0x01;
const NINT_ONE: u8 = 0x20;
const TAG_EPOCH: u8 = 0xc1;
const TAG_BIGNUM_POSITIVE: u8 = 0xc2;
const FLOAT16: u8 = 0xf9;
/// A CBOR boolean, where an integer or another type belongs.
const TRUE: u8 = 0xf5;
/// A CBOR `false`: `tombstone`'s default.
const FALSE: u8 = 0xf4;
const UNDEFINED: u8 = 0xf7;
const BREAK: u8 = 0xff;
const INVALID_UTF8: u8 = 0xff;
const ASCII_A: u8 = b'a';

pub(super) fn truncated(base: &[u8]) -> Vec<u8> {
    base[..base.len() - 1].to_vec()
}

pub(super) fn undefined_value(base: &[u8]) -> Vec<u8> {
    with_future_value(base, vec![UNDEFINED])
}

pub(super) fn nested_indefinite_chunk(base: &[u8]) -> Vec<u8> {
    let chunk = vec![
        TEXT_INDEFINITE,
        TEXT_INDEFINITE,
        TEXT_SMALL_BASE | 1,
        ASCII_A,
        BREAK,
        BREAK,
    ];
    with_future_value(base, chunk)
}

pub(super) fn invalid_utf8_text(base: &[u8]) -> Vec<u8> {
    map(&with_value(
        &entries(base),
        "record_type",
        vec![TEXT_SMALL_BASE | 1, INVALID_UTF8],
    ))
}

pub(super) fn float_value(base: &[u8]) -> Vec<u8> {
    with_future_value(base, vec![FLOAT16, UINT_ZERO, UINT_ZERO])
}

pub(super) fn tag_value(base: &[u8]) -> Vec<u8> {
    with_future_value(base, vec![TAG_EPOCH, UINT_ZERO])
}

pub(super) fn bignum_tag(base: &[u8]) -> Vec<u8> {
    let bignum = vec![TAG_BIGNUM_POSITIVE, BYTES_SMALL_BASE | 1, UINT_ONE];
    map(&with_value(&entries(base), "created_at_ms", bignum))
}

pub(super) fn top_level_array(base: &[u8]) -> Vec<u8> {
    let mut out = vec![ARRAY_1];
    out.extend_from_slice(base);
    out
}

pub(super) fn non_text_key(base: &[u8]) -> Vec<u8> {
    map(&inserted(&entries(base), vec![UINT_ONE], vec![UINT_ZERO]))
}

pub(super) fn record_uuid_text(base: &[u8]) -> Vec<u8> {
    let as_text = text(&"u".repeat(RECORD_UUID_LEN));
    map(&with_value(&entries(base), "record_uuid", as_text))
}

pub(super) fn record_uuid_short(base: &[u8]) -> Vec<u8> {
    let top = entries(base);
    let short = shortened_uuid(&value_of(&top, "record_uuid"));
    map(&with_value(&top, "record_uuid", short))
}

pub(super) fn fields_not_a_map(base: &[u8]) -> Vec<u8> {
    map(&with_value(&entries(base), "fields", vec![ARRAY_EMPTY]))
}

pub(super) fn negative_created_at_ms(base: &[u8]) -> Vec<u8> {
    map(&with_value(&entries(base), "created_at_ms", vec![NINT_ONE]))
}

pub(super) fn missing_record_uuid(base: &[u8]) -> Vec<u8> {
    map(&without(&entries(base), "record_uuid"))
}

pub(super) fn missing_field_value(base: &[u8]) -> Vec<u8> {
    with_edited_field(base, |field| map(&without(field, "value")))
}

pub(super) fn duplicate_record_key(base: &[u8]) -> Vec<u8> {
    map(&repeated(&entries(base), "record_type"))
}

pub(super) fn duplicate_field_name(base: &[u8]) -> Vec<u8> {
    let top = entries(base);
    let fields = repeated(&entries(&value_of(&top, "fields")), EDITED_FIELD);
    map(&with_value(&top, "fields", map(&fields)))
}

pub(super) fn duplicate_field_level_key(base: &[u8]) -> Vec<u8> {
    with_edited_field(base, |field| map(&repeated(field, "last_mod")))
}

pub(super) fn key_order(base: &[u8]) -> Vec<u8> {
    let mut top = entries(base);
    top.swap(0, 1);
    map(&top)
}

pub(super) fn indefinite_map(base: &[u8]) -> Vec<u8> {
    let top = entries(base);
    let mut fields = vec![MAP_INDEFINITE];
    fields.extend(entry_bytes(&entries(&value_of(&top, "fields"))));
    fields.push(BREAK);
    map(&with_value(&top, "fields", fields))
}

pub(super) fn non_shortest_map_head(base: &[u8]) -> Vec<u8> {
    let top = entries(base);
    let field_entries = entries(&value_of(&top, "fields"));
    let mut fields = vec![MAP_ONE_BYTE_COUNT, small_count(field_entries.len())];
    fields.extend(entry_bytes(&field_entries));
    map(&with_value(&top, "fields", fields))
}

pub(super) fn trailing_bytes(base: &[u8]) -> Vec<u8> {
    let mut out = base.to_vec();
    out.push(UINT_ZERO);
    out
}

// The rejection paths the first cut left unseeded (PR #673 review). The
// first two are the bool-as-integer acceptance divergence this slice closed
// in Python: `bool` subclasses `int`, and nothing else in CI would red a
// revert of that fix.

pub(super) fn created_at_ms_bool(base: &[u8]) -> Vec<u8> {
    map(&with_value(&entries(base), "created_at_ms", vec![TRUE]))
}

pub(super) fn field_last_mod_bool(base: &[u8]) -> Vec<u8> {
    with_edited_field(base, |field| {
        map(&with_value(field, "last_mod", vec![TRUE]))
    })
}

pub(super) fn tags_not_an_array(base: &[u8]) -> Vec<u8> {
    map(&inserted(&entries(base), text("tags"), vec![UINT_ZERO]))
}

pub(super) fn tag_not_text(base: &[u8]) -> Vec<u8> {
    map(&inserted(
        &entries(base),
        text("tags"),
        vec![ARRAY_1, UINT_ONE],
    ))
}

pub(super) fn tombstone_not_a_bool(base: &[u8]) -> Vec<u8> {
    map(&inserted(&entries(base), text("tombstone"), vec![UINT_ONE]))
}

pub(super) fn negative_tombstoned_at_ms(base: &[u8]) -> Vec<u8> {
    map(&inserted(
        &entries(base),
        text("tombstoned_at_ms"),
        vec![NINT_ONE],
    ))
}

pub(super) fn field_value_wrong_type(base: &[u8]) -> Vec<u8> {
    with_edited_field(base, |field| {
        map(&with_value(field, "value", vec![UINT_ZERO]))
    })
}

pub(super) fn negative_field_last_mod(base: &[u8]) -> Vec<u8> {
    with_edited_field(base, |field| {
        map(&with_value(field, "last_mod", vec![NINT_ONE]))
    })
}

pub(super) fn field_device_uuid_short(base: &[u8]) -> Vec<u8> {
    with_edited_field(base, |field| {
        let short = shortened_uuid(&value_of(field, "device_uuid"));
        map(&with_value(field, "device_uuid", short))
    })
}

pub(super) fn fields_non_text_key(base: &[u8]) -> Vec<u8> {
    let top = entries(base);
    let fields = inserted(
        &entries(&value_of(&top, "fields")),
        vec![UINT_ONE],
        vec![UINT_ZERO],
    );
    map(&with_value(&top, "fields", map(&fields)))
}

pub(super) fn field_non_text_key(base: &[u8]) -> Vec<u8> {
    with_edited_field(base, |field| {
        map(&inserted(field, vec![UINT_ONE], vec![UINT_ZERO]))
    })
}

pub(super) fn field_not_a_map(base: &[u8]) -> Vec<u8> {
    let top = entries(base);
    let fields = with_value(
        &entries(&value_of(&top, "fields")),
        EDITED_FIELD,
        vec![UINT_ZERO],
    );
    map(&with_value(&top, "fields", map(&fields)))
}

// vault-format §6.3 (#670): a default value is written by omission, so each of
// these is the base plus one optional key PRESENT at its default. Rust's
// encoder omits all three, so the re-encode comparison rejects the body.

pub(super) fn present_default_tags(base: &[u8]) -> Vec<u8> {
    map(&inserted(&entries(base), text("tags"), vec![ARRAY_EMPTY]))
}

pub(super) fn present_default_tombstone(base: &[u8]) -> Vec<u8> {
    map(&inserted(&entries(base), text("tombstone"), vec![FALSE]))
}

pub(super) fn present_default_tombstoned_at_ms(base: &[u8]) -> Vec<u8> {
    map(&inserted(
        &entries(base),
        text("tombstoned_at_ms"),
        vec![UINT_ZERO],
    ))
}
