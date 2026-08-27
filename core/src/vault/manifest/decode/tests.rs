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
use crate::vault::manifest::test_support::{
    build_manifest_map_with_overrides, dummy_kdf_params_value, parse_to_value_map,
    populated_manifest,
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
/// The resulting map is deliberately NON-canonical in key order, which
/// `decode_manifest` does not check (#572).
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
/// still verifies. Unlike `block::decode_plaintext` / `record::decode`,
/// `decode_manifest` has no independent re-encode-and-compare
/// canonicality backstop of its own (#572) — before this fix the
/// signature was the *only* defence a duplicate key ran into, not a
/// second layer over an existing one.
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
        "populated_manifest() is expected to emit all nine known keys              and no unknowns; the sweep below covers whatever it emits, but              a change here means the arm census moved"
    );

    for i in 0..entries.len() {
        let repeated = match &entries[i].0 {
            Value::Text(s) => s.clone(),
            other => panic!("non-text manifest key: {other:?}"),
        };

        // Re-parse, duplicate entry `i`, re-encode. Non-canonical by
        // construction (irrelevant here — `decode_manifest` has no
        // re-encode-and-compare canonicality check of its own, #572 —
        // but the duplicate-key check must still be the thing that
        // fires, not some other decode failure downstream).
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
