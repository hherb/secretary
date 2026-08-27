//! Unit tests for the manifest canonical-CBOR encode path (§4.2).
//!
//! Moved verbatim out of the pre-split `manifest/tests.rs` (#564); shared
//! fixtures live in [`crate::vault::manifest::test_support`].

use ciborium::Value;

use crate::vault::manifest::test_support::{
    entry_bytes_field, find_array, minimal_manifest, parse_to_value_map, populated_manifest,
};
use crate::vault::manifest::{decode_manifest, BLOCK_FINGERPRINT_LEN};
use crate::vault::record::UnknownValue;

// `Value` and `UnknownValue` are imported directly rather than reached
// through `super::*`: as of #569 path 2 the encode path names neither type
// (it borrows through `CanonicalValue` and `UnknownValue::as_value`), so
// `encode.rs` no longer has the `use` lines this module used to inherit.
use super::*;

// ---- TrashEntry content-commitment round-trip (#293) -----------------
//
// Primary subject: `trash_entry_to_canonical`'s optional-key discipline (a
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
    let entry_bytes = to_canonical_vec(&trash_entry_to_canonical(&m.trash[0])).unwrap();
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
    let entry_bytes = to_canonical_vec(&trash_entry_to_canonical(&m.trash[0])).unwrap();
    assert!(
        !String::from_utf8_lossy(&entry_bytes).contains("purged_at_ms"),
        "None must not emit the purged_at_ms key"
    );

    let bytes = encode_manifest(&m).unwrap();
    let decoded = decode_manifest(bytes.expose()).unwrap();
    assert_eq!(decoded.trash[0].purged_at_ms, None, "None must round-trip");

    // Absent key, not explicit null: re-encoding the decoded entry
    // reproduces byte-identical bytes to the pre-purge entry.
    let re_entry_bytes = to_canonical_vec(&trash_entry_to_canonical(&decoded.trash[0])).unwrap();
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

/// A forward-compat unknown subtree that can DETECT a re-ordering: a
/// 2-key CBOR map whose keys are in NON-canonical order.
///
/// ```text
/// A2                 map(2)
///   62 7A 7A  01     "zz" => 1     <- 2-byte key FIRST
///   61 61     02     "a"  => 2     <- 1-byte key SECOND
/// ```
///
/// RFC 8949 §4.2.1 orders text keys by `(byte length, bytes)`, so the
/// canonical order is `"a"` then `"zz"` and these bytes are deliberately
/// the other way round. That asymmetry is the whole point: until #569
/// path 2 the only forward-compat fixture in this file was the 3-byte
/// array `[1, 2]` (`0x82 0x01 0x02`), which has no key order to preserve
/// and therefore could not tell "emitted verbatim" apart from "re-sorted
/// on the way out".
///
/// `UnknownValue::from_canonical_cbor` accepts this despite its name: it
/// validates only the no-float / no-tag rules, never key order (see its
/// own doc comment, which says so outright).
const UNKNOWN_MAP_NONCANONICAL: &[u8] = &[0xA2, 0x62, b'z', b'z', 0x01, 0x61, b'a', 0x02];

/// A v1 client re-encoding a v2 manifest must emit each unknown subtree
/// BYTE-VERBATIM, including a key order this version would not itself
/// have chosen.
///
/// The substitution #569 path 2 makes here is `ser(de(ser(v)))` (the
/// deleted `unknown_value_inner`) -> `ser(v)` (`CanonicalValue::Borrowed`).
/// It is byte-identical by construction, `de` being a left inverse of
/// `ser` over the tag/float-free `Value` domain the decoder guarantees —
/// but that is an argument, and this test is what makes it a fixture. A
/// mutation that emitted the subtree through `CanonicalMap` instead of
/// `Borrowed` would sort those two keys and reds the verbatim assertion
/// below, while leaving the round-trip assertion (which compares two
/// passes of the SAME encoder to each other) perfectly green.
///
/// **Mutation-verified, and the fixture is what buys it.** All three
/// `CanonicalValue::Borrowed(v.as_value())` splice sites in `encode.rs`
/// were rerouted through a probe that rebuilds a `Value::Map` subtree as
/// a `CanonicalMap` (identity for every non-map subtree). With
/// `UNKNOWN_MAP_NONCANONICAL` as written, this test and its block-entry
/// sibling both **FAIL** on the verbatim assertion. With the const
/// reverted to the pre-#569 array fixture `[0x82, 0x01, 0x02]` and the
/// same probe still in place, both **PASS** — as does
/// `golden_vault_001_pinned`. So the re-ordering was invisible to the
/// whole suite before this fixture changed; the added assertion alone
/// would not have been enough.
#[test]
fn forward_compat_unknown_top_level_key_round_trips() {
    let mut m = minimal_manifest();
    m.unknown.insert(
        "future_field".into(),
        UnknownValue::from_canonical_cbor(UNKNOWN_MAP_NONCANONICAL)
            .expect("UnknownValue from canonical bytes"),
    );
    let bytes = encode_manifest(&m).expect("encode with unknown");

    // The subtree reaches the wire byte-for-byte, non-canonical key order
    // and all. This is the assertion the pre-#569 array fixture could not
    // make.
    assert!(
        bytes
            .expose()
            .windows(UNKNOWN_MAP_NONCANONICAL.len())
            .any(|w| w == UNKNOWN_MAP_NONCANONICAL),
        "top-level unknown subtree must be emitted verbatim, in its own \
         non-canonical key order"
    );

    let parsed = decode_manifest(bytes.expose()).expect("decode with unknown");
    assert!(
        parsed.unknown.contains_key("future_field"),
        "unknown top-level key preserved on decode"
    );
    assert_eq!(
        parsed.unknown["future_field"], m.unknown["future_field"],
        "the unknown value itself must survive decode unchanged"
    );
    let bytes_again = encode_manifest(&parsed).expect("re-encode");
    assert_eq!(
        bytes, bytes_again,
        "unknown top-level key round-trips bit-identically"
    );
}

/// The same property one level down, where nothing covered it at all.
///
/// Before #569 path 2 the only forward-compat manifest fixture was at TOP
/// level. `block_entry_to_canonical` and `trash_entry_to_canonical` splice
/// unknowns too — through the same `CanonicalValue::Borrowed(v.as_value())`
/// call — and a nested `CanonicalMap` is where a re-ordering mutation is
/// most plausible, because the surrounding block-entry map genuinely IS
/// sorted at serialise time. This pins that the SUBTREE is not.
#[test]
fn forward_compat_unknown_block_entry_key_round_trips() {
    let mut m = populated_manifest();
    m.blocks[0].unknown.insert(
        "future_block_field".into(),
        UnknownValue::from_canonical_cbor(UNKNOWN_MAP_NONCANONICAL)
            .expect("UnknownValue from canonical bytes"),
    );
    let bytes = encode_manifest(&m).expect("encode with block-entry unknown");

    assert!(
        bytes
            .expose()
            .windows(UNKNOWN_MAP_NONCANONICAL.len())
            .any(|w| w == UNKNOWN_MAP_NONCANONICAL),
        "block-entry unknown subtree must be emitted verbatim, in its own \
         non-canonical key order"
    );

    let parsed = decode_manifest(bytes.expose()).expect("decode with block-entry unknown");
    // `blocks` is sorted by `block_uuid` on output, so find the block by
    // uuid rather than assuming index 0 survives the sort.
    let target = m.blocks[0].block_uuid;
    let decoded_block = parsed
        .blocks
        .iter()
        .find(|b| b.block_uuid == target)
        .expect("block present after round-trip");
    assert_eq!(
        decoded_block.unknown["future_block_field"], m.blocks[0].unknown["future_block_field"],
        "block-entry unknown must survive decode unchanged"
    );

    let bytes_again = encode_manifest(&parsed).expect("re-encode");
    assert_eq!(
        bytes, bytes_again,
        "block-entry unknown round-trips bit-identically"
    );
}

// ---- Retired: the encode path's own scratch-buffer wipe (#561) -------
//
// `encode_manifest_wipes_unknown_value_inners_intermediate_parse` stood
// here until the #560 review; `unknown_value_inner_wipes_the_parser_
// scratch_buffer` replaced it and stood here until #569 path 2. Both
// pinned properties of `unknown_value_inner`, and that function is now
// DELETED, not merely reworked: the encode path emits a forward-compat
// unknown subtree as a borrow (`CanonicalValue::Borrowed(v.as_value())`)
// instead of re-encoding it to CBOR and re-parsing it. There is no
// intermediate `SecretBytes`, no `from_secret_reader` call and no parser
// scratch buffer left on the encode side to assert about, so the test is
// retired with the code it pinned rather than repointed at something
// else. Keeping the function alive to keep the test green would have
// preserved exactly the cost this change removes.
//
// Consequence for the neighbouring counts, stated so nobody re-derives
// it from scratch: `decode::tests`'s two `wipe_calls()` assertions are
// unaffected. Both call `encode_manifest` to build their input BEFORE
// taking their `before` baseline, so the encode side never entered
// their deltas even when it did call `from_secret_reader`.

// ---- #569 path 2: the encode path BORROWS ----------------------------

/// #569 path 2: the manifest encode path must BORROW every plaintext
/// value, not copy it. `block_name` is user-authored plaintext inside the
/// encrypted manifest; the pre-#569 path cloned it into an owned
/// `Value::Text` and again inside `canonical_sort_entries`, two unwiped
/// copies per manifest save.
///
/// This pins the borrow structurally: the returned `CanonicalMap` holds a
/// `&str` INTO the `Manifest`, so it cannot outlive it. A body that built
/// owned `Value`s could not satisfy this signature — reverting to one
/// fails to COMPILE.
///
/// **It catches that revert, not every possible copy**, and an earlier
/// draft of this comment called it "the strongest form this property can
/// take", which is a shade too strong. `CanonicalValue::Text` holds a
/// `&'a str` and `'a` unifies with `'static`, so
/// `Box::leak(entry.block_name.clone().into_boxed_str())` would satisfy
/// the signature, clone the plaintext, leak it permanently, and leave
/// this test green — the same `Box::leak` escape CLAUDE.md records
/// against `&'static str` in the error-payload guard. What the signature
/// rules out is the *shape the code actually had* (an owned `Value` tree)
/// and every ordinary borrow-vs-clone slip; a deliberate leak is outside
/// what any type-level pin here can reach.
///
/// **Where the strength actually is, stated so the assertions are not
/// read as more than they are.** The load-bearing proof is the SIGNATURE,
/// checked by the compiler at the `to_canonical_vec(&canonical)` line;
/// the two runtime assertions only confirm that the borrowed bytes reach
/// the wire. The closing `assert_eq!` re-reads `block_name` through `m`
/// alongside the borrow `canonical` holds — both are shared borrows, so
/// it is a *consistency* check, not an independent runtime demonstration
/// that no copy was made. Rust gives no runtime signal for "this was a
/// borrow"; a copy is not observable from safe code.
///
/// **Mutation-verified, by execution.** `manifest_to_canonical` was
/// reverted to an owned `Vec<(Value, Value)>` body, with `encode_manifest`
/// routed back through `encode_canonical_map` so the LIB still compiled —
/// that isolation is the point, since a naive signature-only revert reds
/// the lib itself and so proves nothing about what THIS test adds.
/// Measured on the current tree, with this test commented out so the
/// lib-test target could link:
///
/// - `cargo build --release -p secretary-core` — clean
/// - `cargo test --release -p secretary-core --test golden_vault_001` —
///   `golden_vault_001_pinned` **PASS**
/// - `cargo test --release -p secretary-core --lib vault::manifest::` —
///   **62 passed, 0 failed**
/// - `cargo test --release --workspace` — **1985 passed, 0 failed**
///
/// Re-enabled, the same tree produces exactly **one** `error[E0308]`
/// (`expected &CanonicalMap<'_>, found &Vec<(Value, Value)>`), in the
/// lib-test target only. That is the gap this test exists to close: every
/// other test in the repository stays green against the revert.
///
/// The filter is spelled `vault::manifest::`, not `manifest`: the latter
/// also matches `sync::ingest::*manifest*` and
/// `version::tests::file_kind_manifest_*`, so it reports a larger,
/// moving number that does not mean "manifest-module tests".
#[test]
fn manifest_encode_borrows_block_name_rather_than_cloning_it() {
    let m = populated_manifest();
    let canonical = manifest_to_canonical(&m);
    let encoded = to_canonical_vec(&canonical).expect("encode");
    // The block name's bytes must appear in the output...
    let name_bytes = m.blocks[0].block_name.as_bytes();
    assert!(
        encoded.windows(name_bytes.len()).any(|w| w == name_bytes),
        "block_name must reach the wire"
    );
    // ...and the map must borrow from `m`, which this line proves by
    // construction: `canonical` is still alive and `m` is still borrowed.
    assert_eq!(m.blocks[0].block_name.as_bytes(), name_bytes);
}
