//! Unit tests for the manifest canonical-CBOR decode path (§4.2).
//!
//! Moved verbatim out of the pre-split `manifest/tests.rs` (#564); shared
//! fixtures live in [`crate::vault::manifest::test_support`].
//!
//! Negatives that fire inside a per-array parser live in
//! [`entries`](super::entries)'s own `tests`; ones that fire inside a
//! typed-extract helper live in [`extract`](super::extract)'s.

use crate::vault::canonical::{encode_canonical_map, CanonicalError};
use crate::vault::manifest::encode::encode_manifest;
// `KEY_DEVICE_UUID` / `KEY_COUNTER` are NOT re-exported by
// `decode::mod`'s own `use super::{..}` list (the top-level parser never
// names them — `entries.rs` does), so `use super::*` below does not reach
// them and they are imported explicitly here.
use crate::vault::manifest::test_support::{
    build_manifest_map_with_overrides, dummy_kdf_params_value, minimal_manifest,
    parse_to_value_map, populated_manifest, unexpected, UNKNOWN_MAP_NONCANONICAL,
    UNKNOWN_MAP_NONCANONICAL_BLOCK, UNKNOWN_MAP_NONCANONICAL_TRASH,
};
use crate::vault::manifest::{
    KEY_COUNTER, KEY_DEVICE_UUID, KEY_RECIPIENTS, KEY_VECTOR_CLOCK_SUMMARY,
};

use super::*;

// ---- Decode wipes its parsed tree (#547 Task 7b) ----------------------
//
// Both also drive `encode_manifest` to build their input; the wipe
// counts they assert are `decode_manifest`'s. `encode_manifest` runs
// BEFORE each test's `wipe_calls()` baseline is taken, so it does not
// enter either delta — which is why deleting `unknown_value_inner` (a
// `from_secret_reader` call on the encode side, #569 path 2) left both
// counts at 2. Re-derived, not assumed: see each assertion's comment.

/// THE test #547 Task 7b's brief asks for: drive an early-return path
/// through `decode_manifest` and prove `SecretValueTree::drop` actually
/// fires, mirroring `record::decode`'s
/// `decode_wipes_its_parsed_tree_on_an_early_return` and
/// `block::decode_plaintext`'s
/// `decode_plaintext_wipes_its_parsed_tree_on_an_early_return`.
///
/// That second citation was FALSE when first written and is corrected
/// rather than dropped: no such block test existed, `block.rs` had zero
/// `wipe_calls()` assertions of any kind, and open issue #557 said so
/// outright — so this comment told a reader the opposite of the tracker.
/// The block test was written during the #560 review; the claim is true
/// now because the code changed, not because the wording softened.
///
/// `manifest_version` is corrupted to the wrong CBOR type and placed
/// FIRST in the map, so `parse_manifest_map`'s very first
/// `take_u8(KEY_MANIFEST_VERSION)` call fails and the `?` propagates
/// all the way back to `decode_manifest` before the `blocks` array
/// entry — carrying a structurally valid `block_name` ("logins"), the
/// user-visible plaintext this whole task exists to cover — is ever
/// examined. `parse_manifest_map` dispatches in map ORDER, so the
/// position is what makes that claim true; wiping here proves
/// not-yet-examined content is covered too, not just already-consumed
/// content.
///
/// **The reorder is explicit as of #569 path 2**, and the change is
/// worth naming rather than absorbing. This test used to serialise the
/// raw, UNSORTED `Vec<(Value, Value)>` that the deleted
/// `manifest_to_entries` returned, where `manifest_version` happened to
/// be the entry pushed first. Its replacement `manifest_to_canonical`
/// returns a borrowing `CanonicalMap` with no mutable entry list to
/// corrupt, so the input is now built by re-parsing `encode_manifest`'s
/// canonical output — and under RFC 8949 §4.2.1 key order
/// ("(length, bytes)") `manifest_version` (16 bytes) sorts LAST and
/// `blocks` (6) second. Leaving it there would have silently inverted
/// the property above: `blocks` would be parsed BEFORE the early
/// return, and the test would no longer pin what its name and doc say
/// it pins. Rotating the corrupted entry to the front restores it.
/// The resulting map is deliberately NON-canonical in key order. As of
/// #572 `decode_manifest` DOES check that — but only after
/// `parse_manifest_map` returns, and this input never gets that far: the
/// wrong-typed `manifest_version` is entry 0, so the `WrongType` `?`
/// fires first and the canonicality check is never reached. The
/// assertion below still pins `WrongType`, unchanged. (This paragraph
/// read "which `decode_manifest` does not check" until #572 added it.)
///
/// **Updated to `before + 2` by Task 2 (#561), and re-tightened to an
/// exact count in review.** `decode_manifest` now parses through
/// `crate::cbor::from_secret_reader` instead of plain
/// `ciborium::de::from_reader`; that call's own `CborScratch` wipes
/// unconditionally when it drops at the end of `from_secret_reader`,
/// before `parse_manifest_map` even runs — so a first pass at this
/// update left the assertion as `> before`, which the added scratch
/// wipe alone satisfies regardless of whether the early-return path
/// wipes anything. Proven by mutation: wrapping
/// `SecretValueTree::new(parsed)` in `ManuallyDrop` inside
/// `decode_manifest` (killing that `Drop`) left the `> before` form of
/// this test PASSING — only the happy-path exact-count test below
/// failed. `before + 2` is exact: 1 scratch wipe (`from_secret_reader`,
/// unconditional) + 1 `SecretValueTree::drop` on the early return this
/// test exists to pin — the second of the two is what the mutation
/// above proved this assertion was no longer covering.
#[test]
fn decode_manifest_wipes_its_parsed_tree_on_an_early_return() {
    let m = populated_manifest();
    let encoded = encode_manifest(&m).expect("encode");
    let mut entries = parse_to_value_map(encoded.expose());
    let version_idx = entries
        .iter()
        .position(|(k, _)| matches!(k, Value::Text(s) if s == KEY_MANIFEST_VERSION))
        .expect("manifest_version entry present");
    entries[version_idx].1 = Value::Text("not-a-u8".to_string());
    // Front-load it — see this test's doc comment for why the position
    // is load-bearing and why it is now set explicitly.
    let corrupted = entries.remove(version_idx);
    entries.insert(0, corrupted);

    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&Value::Map(entries), &mut bytes).expect("serialize");

    let before = crate::cbor::wipe_calls();
    let err = decode_manifest(&bytes).expect_err("wrong-typed manifest_version must be rejected");
    assert!(
        matches!(
            err,
            ManifestError::WrongType {
                field: KEY_MANIFEST_VERSION,
                expected: "unsigned integer",
            }
        ),
        "expected WrongType {{ field: manifest_version, expected: unsigned integer }}, got {err:?}"
    );
    assert_eq!(
        crate::cbor::wipe_calls(),
        before + 2,
        "expected exactly 2 wipes (from_secret_reader's scratch wipe, \
         plus SecretValueTree::drop on the early return out of \
         parse_manifest_map) — decode_manifest's wrap is gone, or no \
         longer covers this path (#561)"
    );
}

/// `decode_manifest` must parse through `cbor::from_secret_reader`,
/// whose scratch buffer holds a copy of every decrypted plaintext value
/// in the input — including every `block_name` (#561). Pinning the
/// COMPOSITION on the HAPPY path, complementing the early-return test
/// above: `scratch.rs`'s own tests prove the wipe fires, this one
/// proves this path uses it.
#[test]
fn decode_manifest_wipes_the_parser_scratch_buffer() {
    let m = populated_manifest();
    let bytes = encode_manifest(&m).expect("encode");

    let before = crate::cbor::wipe_calls();
    let decoded = decode_manifest(bytes.expose()).expect("decode");
    let after = crate::cbor::wipe_calls();

    assert_eq!(decoded.vault_uuid, m.vault_uuid);
    // Two wipes: one scratch wipe from `from_secret_reader`'s own
    // `CborScratch::drop` (fires unconditionally at the end of that
    // call), and one tree wipe from `SecretValueTree::drop` at the end
    // of `decode_manifest`. `populated_manifest()` deliberately carries
    // NO forward-compat `unknown` entries at any level (manifest,
    // block-entry, or trash-entry — all three are `BTreeMap::new()`),
    // so `parse_manifest_map`'s `value_to_unknown` — which, like
    // `block.rs`'s function of the same name, re-encodes and re-parses
    // through `UnknownValue::from_canonical_cbor`, itself now routed
    // through `from_secret_reader` — is never called on this fixture.
    // `block::decode_plaintext_wipes_the_parser_scratch_buffer`'s own
    // comment documents what happens when it IS: one extra wipe per
    // unknown value. Do not copy this fixture's "2" onto a manifest
    // that carries any `unknown` entry without re-deriving the count.
    //
    // DERIVED from the fixture rather than hardcoded (#575 review) —
    // same reasoning as `block::decode_plaintext_wipes_the_parser_
    // scratch_buffer`. `populated_manifest()` carries no `unknown`
    // entries at any of the three levels today; if one is ever added,
    // `value_to_unknown` re-parses it and this count follows
    // automatically instead of redding a security test for an
    // unrelated fixture change.
    let expected = 2 + m.unknown.len();
    assert_eq!(
        m.unknown.len(),
        0,
        "fixture guard: populated_manifest() is expected to carry no \
         top-level unknowns; `expected` tracks it if that changes"
    );
    assert_eq!(
        after - before,
        expected,
        "expected exactly {expected} wipes on the decode_manifest path"
    );
}

// ---- Negative paths --------------------------------------------------
//
// Every test below drives `decode_manifest`; several build their input
// through `encode` or `crate::vault::canonical::encode_canonical_map`.

#[test]
fn rejects_unsupported_manifest_version() {
    let bytes = build_manifest_map_with_overrides(Some(2), true);
    let err = decode_manifest(&bytes).expect_err("manifest_version=2 must reject");
    assert!(
        matches!(err, ManifestError::UnsupportedManifestVersion(2)),
        "expected UnsupportedManifestVersion(2), got {err:?}"
    );
}

#[test]
fn rejects_non_map_top_level() {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&Value::Array(Vec::new()), &mut buf).expect("encode array");
    let err = decode_manifest(&buf).expect_err("array top-level must reject");
    assert!(
        matches!(err, ManifestError::NotAMap),
        "expected NotAMap, got {err:?}"
    );
}

#[test]
fn rejects_float_in_unknown_value() {
    // Build a manifest map with an unknown top-level key whose value
    // is a CBOR float. The float-rejection walker fires up front in
    // decode_manifest before the unknown bag is even populated.
    let entries: Vec<(Value, Value)> = vec![
        (
            Value::Text(KEY_MANIFEST_VERSION.into()),
            Value::Integer(u64::from(MANIFEST_VERSION_V1).into()),
        ),
        (
            Value::Text(KEY_VAULT_UUID.into()),
            Value::Bytes([0x01; UUID_LEN].to_vec()),
        ),
        (
            Value::Text(KEY_FORMAT_VERSION.into()),
            Value::Integer(u64::from(FORMAT_VERSION_V1).into()),
        ),
        (
            Value::Text(KEY_SUITE_ID.into()),
            Value::Integer(u64::from(SUITE_ID_V1).into()),
        ),
        (
            Value::Text(KEY_OWNER_USER_UUID.into()),
            Value::Bytes([0x02; UUID_LEN].to_vec()),
        ),
        (
            Value::Text(KEY_VECTOR_CLOCK.into()),
            Value::Array(Vec::new()),
        ),
        (Value::Text(KEY_BLOCKS.into()), Value::Array(Vec::new())),
        (Value::Text(KEY_TRASH.into()), Value::Array(Vec::new())),
        (Value::Text(KEY_KDF_PARAMS.into()), dummy_kdf_params_value()),
        // Float lives inside an unknown forward-compat key.
        (Value::Text("future_floaty".into()), Value::Float(1.5)),
    ];
    let bytes = encode_canonical_map(&entries).expect("encode_canonical_map");

    let err = decode_manifest(&bytes).expect_err("float must be rejected");
    assert!(
        matches!(
            err,
            ManifestError::Canonical(CanonicalError::FloatRejected { .. })
        ),
        "expected Canonical(FloatRejected), got {err:?}"
    );
}

#[test]
fn rejects_missing_required_field_vault_uuid() {
    let bytes = build_manifest_map_with_overrides(Some(MANIFEST_VERSION_V1), false);
    let err = decode_manifest(&bytes).expect_err("missing vault_uuid must reject");
    assert!(
        matches!(
            err,
            ManifestError::MissingField {
                field: KEY_VAULT_UUID
            }
        ),
        "expected MissingField {{ field: \"vault_uuid\" }}, got {err:?}"
    );
}

/// `parse_manifest_map` is the last of four decoders without a
/// duplicate-key check; the other three reject and this one silently
/// last-wins (#568). Defence in depth, not a live hole: the manifest
/// body is covered by the hybrid signature (Ed25519 AND ML-DSA-65),
/// computed over the on-disk AEAD ciphertext — an attacker without the
/// owner's signing keys cannot forge a duplicate-key manifest that
/// still verifies. When #568 landed, `decode_manifest` — unlike
/// `block::decode_plaintext` / `record::decode` — had no independent
/// re-encode-and-compare canonicality backstop of its own, so the
/// signature was the *only* defence a duplicate key ran into, not a
/// second layer over an existing one. #572 has since added that
/// backstop; #568's justification is unaffected, because a duplicate
/// top-level key must still produce the precise `DuplicateKey` rather
/// than the generic `NonCanonicalEncoding` — which the sweep below now
/// also pins, for all nine keys.
#[test]
fn a_manifest_with_a_repeated_key_is_rejected() {
    let m = populated_manifest();
    let bytes = encode_manifest(&m).expect("encode");

    let entries = match ciborium::de::from_reader::<Value, _>(bytes.expose()).expect("parse") {
        Value::Map(m) => m,
        other => panic!("expected a map, got {other:?}"),
    };

    // EVERY known key, not just whichever sorts first. The check is now
    // per-`Option`-slot — nine independent `if slot.is_some()` arms
    // rather than the single shared `BTreeSet` lookup the first version
    // used — so a test that duplicates only `entries[0]` pins exactly
    // one of the nine and leaves eight deletable with the suite green.
    // That is the "nothing would notice if it were removed" failure this
    // whole slice exists to close, so the sweep is the point (#575
    // review). Mutation-verified: neutering any single arm reds this
    // test.
    assert_eq!(
        entries.len(),
        9,
        "populated_manifest() is expected to emit all nine known keys and \
         no unknowns; the sweep below covers whatever it emits, but a \
         change here means the arm census moved"
    );

    for i in 0..entries.len() {
        let repeated = match &entries[i].0 {
            Value::Text(s) => s.clone(),
            other => panic!("non-text manifest key: {other:?}"),
        };

        // Re-parse, duplicate entry `i`, re-encode. Non-canonical by
        // construction, and since #572 `decode_manifest` DOES have a
        // re-encode-and-compare check that would reject it — so this
        // loop is now also an ordering assertion at the TOP level, the
        // sibling of `duplicate_key_wins_over_non_canonical_encoding`'s
        // nested one: the precise `DuplicateKey` must be the thing that
        // fires, not the generic `NonCanonicalEncoding` and not some
        // other decode failure downstream.
        let mut doubled_entries = entries.clone();
        doubled_entries.push(entries[i].clone());
        let mut doubled = Vec::new();
        ciborium::ser::into_writer(&Value::Map(doubled_entries), &mut doubled).expect("re-encode");

        let err = decode_manifest(&doubled).expect_err("a repeated key must be rejected");
        match err {
            ManifestError::DuplicateKey { field, .. } => assert_eq!(
                field, repeated,
                "DuplicateKey must name the key that was actually repeated"
            ),
            other => panic!("expected DuplicateKey for {repeated}, got {other:?}"),
        }
    }
}

/// The unknown-key arm has its own duplicate check — `BTreeMap::insert`'s
/// previous-value return, not an `Option` slot — so it needs its own
/// test (#575 review). `field` is the literal `"<unknown>"`: the
/// repeated key here is attacker-influenced forward-compat text from
/// inside the encrypted manifest, and carrying it would be exactly the
/// #474 leak class.
#[test]
fn a_manifest_with_a_repeated_unknown_key_is_rejected() {
    let mut m = populated_manifest();
    m.unknown.insert(
        "future_field".to_string(),
        UnknownValue::from_canonical_cbor(&[0x01]).expect("UnknownValue"),
    );
    let bytes = encode_manifest(&m).expect("encode");

    let mut entries = match ciborium::de::from_reader::<Value, _>(bytes.expose()).expect("parse") {
        Value::Map(m) => m,
        other => panic!("expected a map, got {other:?}"),
    };
    let unknown_entry = entries
        .iter()
        .find(|(k, _)| matches!(k, Value::Text(s) if s == "future_field"))
        .expect("the unknown key must be on the wire")
        .clone();
    entries.push(unknown_entry);
    let mut doubled = Vec::new();
    ciborium::ser::into_writer(&Value::Map(entries), &mut doubled).expect("re-encode");

    let err = decode_manifest(&doubled).expect_err("a repeated unknown key must be rejected");
    assert!(
        matches!(
            err,
            ManifestError::DuplicateKey {
                field: "<unknown>",
                index: _
            }
        ),
        "expected DuplicateKey {{ field: \"<unknown>\" }}, got {err:?}"
    );
}

/// Regression: ensures `decode_manifest` surfaces a typed `CborDecode`
/// error (with a classified [`CborFault`] payload, #474) when `ciborium`
/// itself can't parse the input bytes. Pins that the
/// `ciborium::de::Error → ManifestError` adaptation at the top of
/// `decode_manifest` is wired correctly — without this, a parse error
/// inside the manifest layer could collapse into a panic or a different
/// error variant on a future refactor.
#[test]
fn rejects_cbor_garbage() {
    // 16 bytes of 0xff — not a valid CBOR head byte for any major
    // type that decodes to a complete value (0xff is the indefinite-
    // length break, illegal at the top level).
    let bytes = [0xffu8; 16];
    let err = decode_manifest(&bytes).expect_err("garbage bytes must fail to parse");
    // CborDecode carries a data-free CborFault (not the upstream ciborium
    // message, #474), so a wildcard match is still the right granularity
    // here — this test pins the variant, not the classification.
    assert!(
        matches!(err, ManifestError::CborDecode(_)),
        "expected CborDecode(_), got {err:?}"
    );
}

// ---- #572: re-encode-and-compare canonicality check -------------------
//
// `decode_manifest` re-encodes the parsed `Manifest` and requires the
// bytes back. The three tests below pin, in order: that a non-canonical
// body is rejected at all; that #573's precise nested `DuplicateKey`
// still wins the race against this generic check; and that the check
// rejects nothing a forward-compat v2 manifest legitimately carries.

/// Re-serialise a manifest body's top-level map with its entries in
/// REVERSE order.
///
/// Every key is still present exactly once and still well-typed, so
/// `parse_manifest_map` — which dispatches on key TEXT, not position —
/// accepts it unchanged and no earlier check can fire. Key order is the
/// only thing that differs from the input, which makes the canonicality
/// re-check the sole possible source of a rejection.
fn reorder_top_level_keys(canonical: &[u8]) -> Vec<u8> {
    let mut entries = parse_to_value_map(canonical);
    entries.reverse();
    let mut out = Vec::new();
    ciborium::ser::into_writer(&Value::Map(entries), &mut out).expect("serialize reordered map");
    out
}

/// #572: `decode_manifest` must re-encode the parsed struct and compare,
/// exactly as `record::decode` and `block::decode_plaintext` do. Without
/// it the hybrid signature (Ed25519 AND ML-DSA-65) was the ONLY
/// decoder-level defence against a non-canonical manifest body — there
/// was no second check, which is what #568's implementation established
/// by execution and what #575's design spec had asserted the opposite of.
#[test]
fn decode_manifest_rejects_a_non_canonical_body() {
    let m = populated_manifest();
    let canonical = encode_manifest(&m).expect("encode");
    let scrambled = reorder_top_level_keys(canonical.expose());
    assert_ne!(
        scrambled,
        canonical.expose(),
        "the fixture must actually differ, or this test is vacuous"
    );
    // The scrambled bytes must still be ACCEPTED by everything else, or
    // the test would pass for the wrong reason. Proven positively rather
    // than assumed: the only difference is key order, and the canonical
    // form decodes fine (`decode_manifest_wipes_the_parser_scratch_buffer`
    // above drives exactly that).
    match decode_manifest(&scrambled) {
        Err(ManifestError::NonCanonicalEncoding) => {}
        other => panic!("expected NonCanonicalEncoding, got {}", unexpected(&other)),
    }
}

/// A manifest whose `vector_clock` holds ONE entry map with `device_uuid`
/// written twice.
///
/// Hand-built rather than routed through `build_manifest_map_with_
/// overrides`, which always emits an EMPTY `vector_clock` and so has no
/// entry map to inject a duplicate key into (its own signature is
/// `(Option<u8>, bool)`). Modelled on `decode::entries::tests`'s
/// `vector_clock_entry_value_with_duplicate`, which builds the same
/// entry map — but that test hands it straight to
/// `parse_vector_clock_entry`, so it never reaches `decode_manifest` and
/// cannot pin anything about ordering against a whole-body check.
fn manifest_bytes_with_duplicate_nested_key() -> Vec<u8> {
    let dup_entry = Value::Map(vec![
        (
            Value::Text(KEY_DEVICE_UUID.into()),
            Value::Bytes([0x33; UUID_LEN].to_vec()),
        ),
        (Value::Text(KEY_COUNTER.into()), Value::Integer(7u64.into())),
        // The repeat. RFC 8949 §5.4 leaves this to the application;
        // #573 made every nested manifest parser reject it.
        (
            Value::Text(KEY_DEVICE_UUID.into()),
            Value::Bytes([0x33; UUID_LEN].to_vec()),
        ),
    ]);
    let entries: Vec<(Value, Value)> = vec![
        (
            Value::Text(KEY_MANIFEST_VERSION.into()),
            Value::Integer(u64::from(MANIFEST_VERSION_V1).into()),
        ),
        (
            Value::Text(KEY_VAULT_UUID.into()),
            Value::Bytes([0x01; UUID_LEN].to_vec()),
        ),
        (
            Value::Text(KEY_FORMAT_VERSION.into()),
            Value::Integer(u64::from(FORMAT_VERSION_V1).into()),
        ),
        (
            Value::Text(KEY_SUITE_ID.into()),
            Value::Integer(u64::from(SUITE_ID_V1).into()),
        ),
        (
            Value::Text(KEY_OWNER_USER_UUID.into()),
            Value::Bytes([0x02; UUID_LEN].to_vec()),
        ),
        (
            Value::Text(KEY_VECTOR_CLOCK.into()),
            Value::Array(vec![dup_entry]),
        ),
        (Value::Text(KEY_BLOCKS.into()), Value::Array(Vec::new())),
        (Value::Text(KEY_TRASH.into()), Value::Array(Vec::new())),
        (Value::Text(KEY_KDF_PARAMS.into()), dummy_kdf_params_value()),
    ];
    encode_canonical_map(&entries).expect("encode_canonical_map")
}

/// #573's precise duplicate-key errors must fire BEFORE #572's generic
/// check, or every nested duplicate diagnostic silently coarsens to
/// `NonCanonicalEncoding`.
///
/// These bytes trip BOTH: the repeated `device_uuid` is a `DuplicateKey`
/// for `parse_vector_clock_entry`, and — because a manifest re-encoded
/// from the parsed struct emits that key ONCE — they are also
/// non-canonical, so whichever check runs first decides the diagnostic.
/// The race is real, not hypothetical, and it is why this test exists.
///
/// **Mutation-verified in the direction that matters.** Deleting
/// `parse_vector_clock_entry`'s `KEY_DEVICE_UUID` duplicate arm (i.e.
/// letting the parse silently last-win, as it did before #573) makes
/// this exact input return `NonCanonicalEncoding` instead — the
/// coarsening this test exists to detect, observed rather than argued.
/// Note what could NOT be mutated: the check cannot literally be "moved
/// before `parse_manifest_map`", because it re-encodes that function's
/// own return value. Removing the precise check is the expressible form
/// of the same race, and it is the one that was run.
#[test]
fn duplicate_key_wins_over_non_canonical_encoding() {
    let bytes = manifest_bytes_with_duplicate_nested_key();
    match decode_manifest(&bytes) {
        Err(ManifestError::DuplicateKey {
            field: KEY_DEVICE_UUID,
            ..
        }) => {}
        other => panic!(
            "DuplicateKey must precede NonCanonicalEncoding, got {}",
            unexpected(&other)
        ),
    }
}

/// A manifest carrying a forward-compat unknown key at all three levels
/// that have an `unknown` bag: top level, one `blocks` entry, and the
/// `trash` entry.
///
/// Each unknown value is [`UNKNOWN_MAP_NONCANONICAL`] — a sub-map whose
/// own key order is NOT RFC 8949 §4.2.1 canonical. That is the load-
/// bearing part: a v2 client's key ORDER survives a v1 client's
/// re-encode, so the check tolerates it. A fixture with a
/// canonically-ordered subtree could not tell that apart from
/// "re-sorted on the way out".
///
/// Note the exact scope, because the neighbouring overclaim is what
/// #572's review had to correct: key order survives, and so does a
/// duplicate key — but NOT an indefinite-length or non-shortest-form
/// encoding anywhere inside the subtree, which is rejected.
/// `unknown_subtree_tolerates_key_order_and_duplicates_but_not_encoding`
/// below pins both halves; this test pins only the tolerated half, at
/// all three levels that have an `unknown` bag.
///
/// The bytes come from this crate's own `encode_manifest` — there is no
/// foreign v2 encoder in-tree — so what this fixture pins is that the
/// check accepts everything the encoder emits for a manifest carrying
/// unknowns, INCLUDING a subtree key order this version would never
/// choose. It does not simulate an arbitrary third-party encoder.
fn manifest_bytes_with_unknowns_at_top_level_block_and_trash() -> Vec<u8> {
    let mut m = populated_manifest();
    assert!(
        !m.blocks.is_empty() && !m.trash.is_empty(),
        "fixture guard: populated_manifest() must carry at least one block \
         and one trash entry for this fixture to reach all three levels"
    );
    // A DISTINCT subtree per level — see `UNKNOWN_MAP_NONCANONICAL_BLOCK`'s
    // doc for why one shared constant made the byte scan below unable to
    // distinguish the three levels.
    let unknown = |bytes: &[u8]| UnknownValue::from_canonical_cbor(bytes).expect("UnknownValue");
    m.unknown
        .insert("future_field".into(), unknown(UNKNOWN_MAP_NONCANONICAL));
    m.blocks[0].unknown.insert(
        "future_block_field".into(),
        unknown(UNKNOWN_MAP_NONCANONICAL_BLOCK),
    );
    m.trash[0].unknown.insert(
        "future_trash_field".into(),
        unknown(UNKNOWN_MAP_NONCANONICAL_TRASH),
    );
    encode_manifest(&m)
        .expect("encode with unknowns")
        .expose()
        .to_vec()
}

/// #572's check must reject nothing that is valid today. A v2 manifest
/// carrying unknown keys at all three levels that have an `unknown` bag
/// must still decode — this is the forward-compatibility hazard the
/// design checked against all four nested parsers before the check was
/// written:
///
/// - `parse_vector_clock_entry` and `parse_kdf_params` REJECT an unknown
///   key outright (`WrongType`), so nothing is silently dropped there and
///   there is no shape they accept but cannot reproduce.
/// - `Manifest`, `BlockEntry` and `TrashEntry` each carry an
///   `unknown: BTreeMap<String, UnknownValue>` that round-trips verbatim.
///
/// So every manifest the decoder ACCEPTS is fully representable, and the
/// re-encode is byte-identical. A counterexample would be a decoder bug
/// to surface, not a reason to weaken the check.
#[test]
fn forward_compat_unknown_keys_survive_the_canonicality_check() {
    let bytes = manifest_bytes_with_unknowns_at_top_level_block_and_trash();
    let m = decode_manifest(&bytes).expect("a forward-compat manifest must still decode");
    assert!(!m.unknown.is_empty(), "top-level unknown preserved");
    assert!(
        m.blocks.iter().any(|b| !b.unknown.is_empty()),
        "block-entry unknown preserved"
    );
    assert!(
        m.trash.iter().any(|t| !t.unknown.is_empty()),
        "trash-entry unknown preserved"
    );
    // Each subtree reached the wire in its own non-canonical key order and
    // came back unchanged — the property the check had to tolerate. Scanned
    // PER LEVEL: a single shared needle would be satisfied by any one of the
    // three, so a block- or trash-level splice that re-sorted its subtree
    // would pass. The `decode_manifest` call above cannot catch that either
    // — `bytes` is the encoder's own output, so #572's re-encode compares
    // like with like whatever the encoder did (#584 review).
    for (label, needle) in [
        ("top-level", UNKNOWN_MAP_NONCANONICAL),
        ("block-entry", UNKNOWN_MAP_NONCANONICAL_BLOCK),
        ("trash-entry", UNKNOWN_MAP_NONCANONICAL_TRASH),
    ] {
        assert!(
            bytes.windows(needle.len()).any(|w| w == needle),
            "{label} subtree must reach the wire in its own non-canonical key \
             order, or this test does not exercise the tolerance it claims to"
        );
    }
}

/// Three of the FOUR shapes [`ManifestError::NonCanonicalEncoding`]'s doc
/// claims to catch, pinned by execution rather than by argument. The
/// fourth — map keys out of RFC 8949 §4.2.1 order — is
/// [`decode_manifest_rejects_a_non_canonical_body`] above, and is not
/// repeated here.
///
/// Two of the three below (non-shortest-form integer, indefinite-length
/// item) are shapes `record::decode` and `block::decode_plaintext` catch
/// too. The THIRD — an array not in its §4.2 sort order — is specific to
/// this layer, because `encode_manifest` sorts `vector_clock`, every
/// `vector_clock_summary`, `blocks`, `trash` and every block's
/// `recipients` on output. That makes this check strictly stronger here
/// than "canonical CBOR" in the bare RFC 8949 sense, which is a claim
/// worth a test rather than a comment.
///
/// Every case starts from `encode_manifest`'s own canonical output and
/// perturbs exactly one thing, so nothing else can be what fires.
#[test]
fn non_canonical_shapes_are_each_rejected() {
    let m = populated_manifest();
    let canonical = encode_manifest(&m).expect("encode");
    // Re-serialise once through `ciborium` so the byte offsets below are
    // over a buffer this test built, not over `encode_manifest`'s
    // internals.
    let body = {
        let mut b = Vec::new();
        ciborium::ser::into_writer(&Value::Map(parse_to_value_map(canonical.expose())), &mut b)
            .expect("serialize");
        b
    };
    assert_eq!(
        body,
        canonical.expose(),
        "the ciborium round-trip must be a no-op on canonical input, or \
         every offset below is measured against the wrong buffer"
    );

    // (1) Non-shortest-form integer: `manifest_version`'s value `1`,
    //     written as `0x18 0x01` (uint8 head) instead of the shortest
    //     `0x01`. `ciborium` PARSES this — it does not reject it — so
    //     the re-encode is the only signal.
    const MANIFEST_VERSION_KEY_ON_THE_WIRE: &[u8] = b"\x70manifest_version";
    let key_at = body
        .windows(MANIFEST_VERSION_KEY_ON_THE_WIRE.len())
        .position(|w| w == MANIFEST_VERSION_KEY_ON_THE_WIRE)
        .expect("manifest_version key present on the wire");
    let value_at = key_at + MANIFEST_VERSION_KEY_ON_THE_WIRE.len();
    assert_eq!(
        body[value_at], MANIFEST_VERSION_V1,
        "the byte after the key must be the shortest-form value 1"
    );
    let mut non_shortest = body.clone();
    non_shortest.splice(value_at..value_at + 1, [0x18u8, MANIFEST_VERSION_V1]);
    match decode_manifest(&non_shortest) {
        Err(ManifestError::NonCanonicalEncoding) => {}
        other => panic!(
            "non-shortest-form integer: expected NonCanonicalEncoding, got {}",
            unexpected(&other)
        ),
    }

    // (2) Indefinite-length top-level map: `0xBF … 0xFF` in place of the
    //     definite `0xA9` head.
    let mut indefinite = vec![0xBFu8];
    indefinite.extend_from_slice(&body[1..]);
    indefinite.push(0xFF);
    match decode_manifest(&indefinite) {
        Err(ManifestError::NonCanonicalEncoding) => {}
        other => panic!(
            "indefinite-length map: expected NonCanonicalEncoding, got {}",
            unexpected(&other)
        ),
    }

    // (3) An array out of its §4.2 sort order. `populated_manifest()`'s
    //     two `vector_clock` entries have distinct `device_uuid`s, so
    //     reversing them changes nothing except the order — no duplicate
    //     for `parse_vector_clock`'s own sweep to catch first.
    let mut entries = parse_to_value_map(&body);
    let vc = entries
        .iter_mut()
        .find(|(k, _)| matches!(k, Value::Text(s) if s == KEY_VECTOR_CLOCK))
        .expect("vector_clock present");
    match &mut vc.1 {
        Value::Array(items) => {
            assert_eq!(
                items.len(),
                2,
                "fixture guard: populated_manifest() is expected to emit two \
                 vector_clock entries, or reversing them is a no-op"
            );
            items.reverse();
        }
        other => panic!("vector_clock is not an array: {other:?}"),
    }
    let mut unsorted = Vec::new();
    ciborium::ser::into_writer(&Value::Map(entries), &mut unsorted).expect("serialize");
    assert_ne!(
        unsorted, body,
        "the reversal must actually change the bytes"
    );
    match decode_manifest(&unsorted) {
        Err(ManifestError::NonCanonicalEncoding) => {}
        other => panic!(
            "unsorted vector_clock: expected NonCanonicalEncoding, got {}",
            unexpected(&other)
        ),
    }
}

/// vault-format §4.2 makes all FIVE array sort disciplines a reader MUST,
/// and #572's re-encode-and-compare is the entire mechanism: `encode_manifest`
/// sorts all five on output, so an array that arrived in any other order
/// re-encodes to different bytes and is rejected.
///
/// [`non_canonical_shapes_are_each_rejected`] above drives that for
/// `vector_clock`. The other four had **no decode-side test at all** until
/// the #584 review. Be precise about what was already covered, because the
/// two claims are easy to conflate: the ENCODER's five sorts are pinned by
/// `manifest_props::manifest_roundtrip` in `core/tests/proptest.rs`, whose
/// strategies generate genuinely unsorted arrays — deleting the `recipients`
/// sort or the `trash` sort fails it, verified by mutation. "The reader
/// REJECTS an unsorted input" is a different claim, it is the one the spec
/// now states normatively, and it is what this test pins.
///
/// `trash` needs a second entry to have an order at all, so it perturbs a
/// locally-extended manifest rather than `populated_manifest()` itself —
/// changing the shared fixture would re-derive the `entries.len() == 9` and
/// `items.len() == 2` guards several tests above depend on.
#[test]
fn every_array_sort_discipline_is_rejected_out_of_order_on_decode() {
    fn reserialize(entries: Vec<(Value, Value)>) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(&Value::Map(entries), &mut out).expect("serialize");
        out
    }

    fn array_at<'a>(map: &'a mut [(Value, Value)], key: &str) -> &'a mut Vec<Value> {
        let slot = map
            .iter_mut()
            .find(|(k, _)| matches!(k, Value::Text(s) if s == key))
            .unwrap_or_else(|| panic!("{key} must be present"));
        match &mut slot.1 {
            Value::Array(items) => items,
            other => panic!("{key} is not an array: {other:?}"),
        }
    }

    fn expect_rejected(label: &str, canonical: &[u8], perturbed: &[u8]) {
        assert_ne!(
            perturbed, canonical,
            "{label}: reversing must actually change the bytes, or the case is vacuous"
        );
        match decode_manifest(perturbed) {
            Err(ManifestError::NonCanonicalEncoding) => {}
            other => panic!(
                "{label}: expected NonCanonicalEncoding, got {}",
                unexpected(&other)
            ),
        }
    }

    let canonical = encode_manifest(&populated_manifest()).expect("encode");
    let canonical = canonical.expose().to_vec();

    // (1) `blocks`, ascending by block_uuid.
    let mut entries = parse_to_value_map(&canonical);
    let blocks = array_at(&mut entries, KEY_BLOCKS);
    assert_eq!(
        blocks.len(),
        2,
        "fixture guard: two blocks, or reversing is a no-op"
    );
    blocks.reverse();
    expect_rejected("blocks", &canonical, &reserialize(entries));

    // (2) each block's `recipients`, and (3) each block's
    //     `vector_clock_summary` — both reversed inside block 0 only, so
    //     each case perturbs exactly one array.
    for (label, key) in [
        ("recipients", KEY_RECIPIENTS),
        ("vector_clock_summary", KEY_VECTOR_CLOCK_SUMMARY),
    ] {
        let mut entries = parse_to_value_map(&canonical);
        let blocks = array_at(&mut entries, KEY_BLOCKS);
        let Value::Map(block) = &mut blocks[0] else {
            panic!("block entry is not a map");
        };
        let inner = array_at(block, key);
        assert_eq!(
            inner.len(),
            2,
            "fixture guard: block 0 must carry two {label}, or reversing is a no-op"
        );
        inner.reverse();
        expect_rejected(label, &canonical, &reserialize(entries));
    }

    // (4) `trash`, ascending by block_uuid. `populated_manifest()` has one
    //     entry, so extend a local copy rather than the shared fixture.
    let mut m = populated_manifest();
    let mut second = m.trash[0].clone();
    second.block_uuid = [0x11; UUID_LEN];
    second.fingerprint = None;
    m.trash.push(second);
    let two_trash = encode_manifest(&m).expect("encode two-trash manifest");
    let two_trash = two_trash.expose().to_vec();
    decode_manifest(&two_trash).expect("the two-trash fixture must itself be valid");
    let mut entries = parse_to_value_map(&two_trash);
    let trash = array_at(&mut entries, KEY_TRASH);
    assert_eq!(trash.len(), 2, "fixture guard: two trash entries");
    trash.reverse();
    expect_rejected("trash", &two_trash, &reserialize(entries));
}

/// What is and is NOT tolerated inside a forward-compat `unknown`
/// subtree, measured rather than asserted.
///
/// This test exists because the claim it pins shipped WRONG for one
/// commit. `decode/mod.rs` and `ManifestError::NonCanonicalEncoding`
/// both said the check misses "a duplicate key — or any other
/// non-canonical shape" inside such a subtree, "no matter what is
/// inside them". Only the first half is true, and nothing pinned
/// either half, so the overclaim was invisible to the suite.
///
/// The mechanism is `ciborium`'s `Value` reader, which collapses
/// indefinite lengths and non-shortest-form heads **on parse** — so by
/// the time any subtree is examined it is already the normalisation of
/// the wire bytes, and re-encoding emits that. Only properties
/// `ciborium::Value` can still represent survive — and `Value::Map` is
/// an ordered `Vec` of pairs, so entry order and repeats do, while
/// encoding-level choices do not.
///
/// It is NOT `extract::value_to_unknown`'s re-serialise/re-parse hop,
/// which the first fix for this blamed: that hop is an identity on an
/// already-parsed `Value`, and `record::decode` — which has no such hop
/// — behaves identically on every row below.
///
/// **Forward-compat consequence, and the reason this is worth a test
/// rather than a comment**: any indefinite-length or non-shortest-form
/// item inside an unknown subtree makes the vault unopenable by a v1
/// client. Unknown subtrees must stay inside the deterministic profile
/// (crypto-design §6.2) like the rest of the body. vault-format §4.2's
/// forward-compat exemption is for array ORDER, not for encoding.
#[test]
fn unknown_subtree_tolerates_key_order_and_duplicates_but_not_encoding() {
    // `{"a": 1}` — the subtree spliced over, and short enough to be
    // unambiguous in the encoded manifest.
    const BASE: &[u8] = &[0xA1, 0x61, b'a', 0x01];

    let mut m = minimal_manifest();
    // A 10-byte key sorts after all nine known keys (RFC 8949 §4.2.1 is
    // length-first), so the subtree lands near the end of the body.
    m.unknown.insert(
        "zzz_future".into(),
        UnknownValue::from_canonical_cbor(BASE).expect("UnknownValue"),
    );
    let encoded = encode_manifest(&m).expect("encode");
    let bytes = encoded.expose().to_vec();
    decode_manifest(&bytes).expect("baseline: the unspliced fixture must decode");

    let at = {
        let hits: Vec<usize> = bytes
            .windows(BASE.len())
            .enumerate()
            .filter(|(_, w)| *w == BASE)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(
            hits.len(),
            1,
            "the subtree must occur exactly once, or the splice below is \
             overwriting something else"
        );
        hits[0]
    };
    let splice = |repl: &[u8]| -> Vec<u8> {
        let mut v = bytes.clone();
        v.splice(at..at + BASE.len(), repl.iter().copied());
        v
    };

    // REJECTED: every encoding-level departure from the deterministic
    // profile, at any CBOR major type the subtree can hold.
    for (what, repl) in [
        (
            "indefinite-length map",
            &[0xBFu8, 0x61, b'a', 0x01, 0xFF][..],
        ),
        (
            "non-shortest-form integer",
            &[0xA1u8, 0x61, b'a', 0x18, 0x01][..],
        ),
        (
            "indefinite-length text string",
            &[0xA1u8, 0x61, b'a', 0x7F, 0x61, b'x', 0xFF][..],
        ),
        (
            "indefinite-length byte string",
            &[0xA1u8, 0x61, b'a', 0x5F, 0x41, 0xAA, 0xFF][..],
        ),
        (
            "indefinite-length array",
            &[0xA1u8, 0x61, b'a', 0x9F, 0x01, 0xFF][..],
        ),
        // A non-shortest LENGTH prefix, as distinct from a non-shortest
        // integer VALUE above: `B8 01` is a 1-entry map written with a
        // uint8 count header where `A1` suffices.
        (
            "non-shortest-form map length",
            &[0xB8u8, 0x01, 0x61, b'a', 0x01][..],
        ),
    ] {
        match decode_manifest(&splice(repl)) {
            Err(ManifestError::NonCanonicalEncoding) => {}
            other => panic!(
                "{what} inside an unknown subtree: expected NonCanonicalEncoding, got {}",
                unexpected(&other)
            ),
        }
    }

    // ACCEPTED: the two order-carrying shapes, which are exactly the
    // residual #573 documents. `Value::Map` is an ordered `Vec` of
    // pairs, so both survive the PARSE that normalises everything above
    // — see this test's doc for why the filter is `ciborium`'s reader
    // and not `value_to_unknown`'s hop — and re-encode byte-identically.
    for (what, repl) in [
        (
            "duplicate key",
            &[0xA2u8, 0x61, b'a', 0x01, 0x61, b'a', 0x02][..],
        ),
        (
            "keys out of canonical order",
            &[0xA2u8, 0x62, b'z', b'z', 0x01, 0x61, b'a', 0x02][..],
        ),
    ] {
        decode_manifest(&splice(repl)).unwrap_or_else(|e| {
            panic!("{what} inside an unknown subtree must still decode, got {e:?}")
        });
    }
}
