//! Unit tests for the manifest canonical-CBOR encode path (§4.2).
//!
//! Moved verbatim out of the pre-split `manifest/tests.rs` (#564); shared
//! fixtures live in [`crate::vault::manifest::test_support`].

use crate::vault::manifest::test_support::{
    entry_bytes_field, find_array, minimal_manifest, parse_to_value_map, populated_manifest,
};
use crate::vault::manifest::{decode_manifest, BLOCK_FINGERPRINT_LEN};

use super::*;

// ---- TrashEntry content-commitment round-trip (#293) -----------------
//
// Primary subject: `trash_entry_to_value`'s optional-key discipline (a
// `None` must emit no key at all). Also covers `decode::entries::
// parse_trash_entry` on the read-back leg.

#[test]
fn trash_entry_fingerprint_some_round_trips() {
    // A TrashEntry carrying a content commitment must survive a full
    // encode → decode cycle with the fingerprint intact (#293).
    let mut m = populated_manifest();
    m.trash[0].fingerprint = Some([0x7a; BLOCK_FINGERPRINT_LEN]);
    let bytes = encode_manifest(&m).unwrap();
    let decoded = decode_manifest(bytes.expose()).unwrap();
    assert_eq!(
        decoded.trash[0].fingerprint,
        Some([0x7a; BLOCK_FINGERPRINT_LEN]),
        "Some(fingerprint) must round-trip"
    );
    // The typed key must NOT leak into the forward-compat `unknown` map.
    assert!(
        decoded.trash[0].unknown.is_empty(),
        "fingerprint must decode as a typed field, not into unknown"
    );
}

#[test]
fn trash_entry_fingerprint_none_omits_key() {
    // A legacy-shaped entry (no commitment) must encode WITHOUT the
    // "fingerprint" key and decode back to None — byte-compatible with
    // pre-#293 manifests.
    let mut m = populated_manifest();
    m.trash[0].fingerprint = None;
    let bytes = encode_manifest(&m).unwrap();
    // The "fingerprint" key must be byte-absent from the TrashEntry
    // encoding (legacy-byte-identical — the frozen-v1 no-format-bump
    // guarantee). We encode the trash entry in isolation so the check is
    // scoped to TrashEntry bytes only (BlockEntry.fingerprint is always
    // present and would otherwise be a false positive).
    let entry_value = trash_entry_to_value(&m.trash[0]).unwrap();
    let mut entry_bytes = Vec::new();
    ciborium::ser::into_writer(&entry_value, &mut entry_bytes).unwrap();
    assert!(
        !String::from_utf8_lossy(&entry_bytes).contains("fingerprint"),
        "None must not emit the fingerprint key"
    );
    let decoded = decode_manifest(bytes.expose()).unwrap();
    assert_eq!(decoded.trash[0].fingerprint, None, "None must round-trip");
}

// ---- TrashEntry.purged_at_ms round-trip (#399) ------------------------
//
// Same primary subject and same cross-module coverage as the #293 pair
// above.

#[test]
fn trash_entry_purged_at_ms_some_round_trips() {
    // A TrashEntry marked as purged must survive a full encode → decode
    // cycle with purged_at_ms intact (#399).
    let mut m = populated_manifest();
    m.trash[0].purged_at_ms = Some(1_724_000_000_123);
    let bytes = encode_manifest(&m).unwrap();
    let decoded = decode_manifest(bytes.expose()).unwrap();
    assert_eq!(
        decoded.trash[0].purged_at_ms,
        Some(1_724_000_000_123),
        "Some(purged_at_ms) must round-trip"
    );
    // The typed key must NOT leak into the forward-compat `unknown` map.
    assert!(
        decoded.trash[0].unknown.is_empty(),
        "purged_at_ms must decode as a typed field, not into unknown"
    );
}

#[test]
fn trash_entry_purged_at_ms_none_roundtrips_byte_identical() {
    // A still-restorable trash entry (not purged) must encode WITHOUT
    // the "purged_at_ms" key and decode back to None — byte-compatible
    // with pre-#399 manifests (frozen-v1 no-format-bump guarantee).
    let mut m = populated_manifest();
    m.trash[0].purged_at_ms = None;
    let entry_value = trash_entry_to_value(&m.trash[0]).unwrap();
    let mut entry_bytes = Vec::new();
    ciborium::ser::into_writer(&entry_value, &mut entry_bytes).unwrap();
    assert!(
        !String::from_utf8_lossy(&entry_bytes).contains("purged_at_ms"),
        "None must not emit the purged_at_ms key"
    );

    let bytes = encode_manifest(&m).unwrap();
    let decoded = decode_manifest(bytes.expose()).unwrap();
    assert_eq!(decoded.trash[0].purged_at_ms, None, "None must round-trip");

    // Absent key, not explicit null: re-encoding the decoded entry
    // reproduces byte-identical bytes to the pre-purge entry.
    let re_entry_value = trash_entry_to_value(&decoded.trash[0]).unwrap();
    let mut re_entry_bytes = Vec::new();
    ciborium::ser::into_writer(&re_entry_value, &mut re_entry_bytes).unwrap();
    assert_eq!(
        entry_bytes, re_entry_bytes,
        "None must re-encode byte-identically (no explicit null)"
    );
}

// ---- Round-trip ------------------------------------------------------
//
// Primary subject: `encode_manifest`'s determinism and canonical output
// order. Also covers `decode::decode_manifest`, which supplies the return
// leg of each round trip.

#[test]
fn roundtrip_minimal_manifest() {
    let m = minimal_manifest();
    let bytes = encode_manifest(&m).expect("encode minimal");
    let parsed = decode_manifest(bytes.expose()).expect("decode minimal");
    assert_eq!(parsed, m);
    let bytes_again = encode_manifest(&parsed).expect("re-encode minimal");
    assert_eq!(bytes, bytes_again, "encode is deterministic");
}

#[test]
fn roundtrip_populated_manifest() {
    let m = populated_manifest();
    let bytes = encode_manifest(&m).expect("encode populated");
    let parsed = decode_manifest(bytes.expose()).expect("decode populated");
    // We can't compare `parsed == m` directly because the input
    // vector_clock and recipients arrays were built in non-canonical
    // order. After encode-then-decode they come back sorted. So we
    // sort `m`'s arrays the same way before comparing.
    let mut m_sorted = m.clone();
    m_sorted.vector_clock.sort_by_key(|a| a.device_uuid);
    m_sorted.blocks.sort_by_key(|a| a.block_uuid);
    for blk in &mut m_sorted.blocks {
        blk.recipients.sort();
        blk.vector_clock_summary.sort_by_key(|a| a.device_uuid);
    }
    m_sorted.trash.sort_by_key(|a| a.block_uuid);
    assert_eq!(parsed, m_sorted);

    let bytes_again = encode_manifest(&parsed).expect("re-encode populated");
    assert_eq!(bytes, bytes_again, "round-trip is bit-identical");
}

// ---- Encoding sorts arrays on output ---------------------------------

#[test]
fn encoding_sorts_arrays_on_output() {
    let m = populated_manifest();
    let bytes = encode_manifest(&m).expect("encode");
    let map = parse_to_value_map(bytes.expose());

    // vector_clock sorted ascending by device_uuid.
    let vc = find_array(&map, KEY_VECTOR_CLOCK);
    let device_ids: Vec<Vec<u8>> = vc
        .iter()
        .map(|e| entry_bytes_field(e, KEY_DEVICE_UUID))
        .collect();
    assert_eq!(
        device_ids,
        vec![vec![0x55; UUID_LEN], vec![0xaa; UUID_LEN]],
        "vector_clock sorted by device_uuid lex"
    );

    // blocks sorted ascending by block_uuid.
    let blocks = find_array(&map, KEY_BLOCKS);
    let block_ids: Vec<Vec<u8>> = blocks
        .iter()
        .map(|b| entry_bytes_field(b, KEY_BLOCK_UUID))
        .collect();
    assert_eq!(
        block_ids,
        vec![vec![0xa2; UUID_LEN], vec![0xb1; UUID_LEN]],
        "blocks sorted by block_uuid lex"
    );

    // Inner vector_clock_summary on each block is also sorted.
    for blk in blocks {
        let inner_vc = match blk {
            Value::Map(entries) => entries
                .iter()
                .find_map(|(k, v)| match k {
                    Value::Text(s) if s == KEY_VECTOR_CLOCK_SUMMARY => match v {
                        Value::Array(a) => Some(a.as_slice()),
                        _ => None,
                    },
                    _ => None,
                })
                .expect("vector_clock_summary present"),
            _ => panic!("block entry not a map"),
        };
        let ids: Vec<Vec<u8>> = inner_vc
            .iter()
            .map(|e| entry_bytes_field(e, KEY_DEVICE_UUID))
            .collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted, "vector_clock_summary sorted on output");
    }

    // trash array — only one entry, but check the key is present.
    let trash = find_array(&map, KEY_TRASH);
    assert_eq!(trash.len(), 1, "trash has one entry");
}

// ---- Forward-compat round-trip ---------------------------------------
//
// Also covers `decode`'s unknown-key capture: the encoder splices the
// unknown bag back in, the decoder is what put it there.

#[test]
fn forward_compat_unknown_top_level_key_round_trips() {
    let mut m = minimal_manifest();
    // CBOR for a tiny array `[1, 2]`: 0x82 0x01 0x02.
    m.unknown.insert(
        "future_field".into(),
        UnknownValue::from_canonical_cbor(&[0x82, 0x01, 0x02])
            .expect("UnknownValue from canonical bytes"),
    );
    let bytes = encode_manifest(&m).expect("encode with unknown");
    let parsed = decode_manifest(bytes.expose()).expect("decode with unknown");
    assert!(
        parsed.unknown.contains_key("future_field"),
        "unknown top-level key preserved on decode"
    );
    let bytes_again = encode_manifest(&parsed).expect("re-encode");
    assert_eq!(
        bytes, bytes_again,
        "unknown top-level key round-trips bit-identically"
    );
}

// ---- unknown_value_inner wipes the parser scratch buffer (#561) -------

// `encode_manifest_wipes_unknown_value_inners_intermediate_parse` stood
// here until the #560 review. It pinned `unknown_value_inner`'s
// `SecretValueTree` wrap — and that wrap is gone, because it covered no
// early-return window and forced a deep clone of decrypted forward-compat
// content to get the value back out of a type with no consuming accessor.
// See that function's doc for the full reasoning and for what replaced it
// (a `SecretBytes` wrap on `bytes`, which DOES have a window). The test is
// retired with the wrap it pinned rather than repointed: the replacement
// is not counter-observable, which is the #558 class, and writing a test
// that asserts nothing about it would be worse than admitting the gap.

/// `unknown_value_inner` must parse through `cbor::from_secret_reader`
/// (#561): its input is a re-encode of a forward-compat unknown
/// subtree, plaintext this version cannot interpret but must still not
/// leave staged in `ciborium`'s own frame. Called directly rather than
/// through `encode_manifest`, matching the file's existing convention
/// of testing this private helper in isolation (see the retired-test
/// comment above this section) — an end-to-end `encode_manifest` call
/// would also exercise `value_to_unknown` on the decode side, which
/// wipes independently and would muddy this function's own count.
#[test]
fn unknown_value_inner_wipes_the_parser_scratch_buffer() {
    // CBOR for a tiny array `[1, 2]`: 0x82 0x01 0x02.
    let uv = UnknownValue::from_canonical_cbor(&[0x82, 0x01, 0x02])
        .expect("UnknownValue from canonical bytes");

    let before = crate::cbor::wipe_calls();
    let v = unknown_value_inner(&uv).expect("unknown_value_inner");
    let after = crate::cbor::wipe_calls();

    assert_eq!(
        v,
        Value::Array(vec![Value::Integer(1.into()), Value::Integer(2.into())])
    );
    // One wipe: `unknown_value_inner` calls `from_secret_reader` exactly
    // once and returns the raw parsed `Value` with no further wrap
    // (see the function's own doc for why the `SecretValueTree` wrap
    // that used to sit here was removed — it covered no early-return
    // window since `Ok(v)` is the very next line).
    assert_eq!(
        after - before,
        1,
        "expected exactly 1 wipe on the unknown_value_inner path"
    );
}
