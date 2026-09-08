//! Unit tests for §4.2's v1 sentinel rule on the write side (#587).
//!
//! Three layers, and each answers a question the others cannot:
//!
//! 1. [`check_v1_sentinels`] directly — one test per sentinel, plus the
//!    field-order precedence a body violating two of them resolves by.
//! 2. `encode_manifest` and `sign_manifest` — that the rule is actually
//!    *wired* to the writer, which is the whole of #587. A correct
//!    checker nobody calls closes nothing.
//! 3. Both directions together — that the reader and the writer agree on
//!    WHICH fields are sentinels, and that the writer's check does not
//!    stand in for the reader's.
//!
//! Layer 3 is the one that would otherwise be missing. §4.3 step 4
//! re-encodes every parsed manifest through `encode_manifest`, so this
//! module's function runs on the decode path too, and a shared error
//! variant would have let it silently satisfy the decoder's own
//! regressions. See [`check_v1_sentinels`]'s doc for the full statement.

use super::*;
use crate::vault::manifest::encode::encode_manifest;
use crate::vault::manifest::test_support::{
    build_manifest_map_with_sentinels, expect_rejected, minimal_manifest, populated_manifest,
};

/// A sentinel value that is not v1 and not a plausible off-by-one, so a
/// test asserting on it cannot pass by accident against a `+ 1` mutation.
const NOT_V1: u16 = 7;

/// One sweep case: the §4.2 field name, and the edit that makes it non-v1.
///
/// A named type rather than an inline tuple because `-D clippy::type_complexity`
/// rejects the latter — and because the sweep only means anything if every
/// row is the same shape, which a name states and a repeated tuple does not.
type BreakCase = (&'static str, fn(&mut Manifest));

/// One parity case: the field under test, then the three sentinel values to
/// give both directions. Spelled out per direction rather than derived, so
/// the reader and writer are handed *the same* triple by construction.
type ParityCase = (&'static str, u8, u16, u16);

// ---- check_v1_sentinels, directly ------------------------------------

#[test]
fn a_v1_manifest_passes_the_sentinel_check() {
    // The positive control. Without it, a checker that rejected
    // unconditionally would pass every other test in this file.
    assert!(check_v1_sentinels(&populated_manifest()).is_ok());
    assert!(check_v1_sentinels(&minimal_manifest()).is_ok());
}

#[test]
fn a_non_v1_manifest_version_is_rejected() {
    let mut m = minimal_manifest();
    m.manifest_version = NOT_V1 as u8;
    let err = expect_rejected(check_v1_sentinels(&m), "non-v1 manifest_version");
    assert!(
        matches!(err, ManifestError::EncodeUnsupportedManifestVersion(v) if v == NOT_V1 as u8),
        "expected EncodeUnsupportedManifestVersion({NOT_V1}), got {err:?}"
    );
}

#[test]
fn a_non_v1_format_version_is_rejected() {
    let mut m = minimal_manifest();
    m.format_version = NOT_V1;
    let err = expect_rejected(check_v1_sentinels(&m), "non-v1 format_version");
    assert!(
        matches!(err, ManifestError::EncodeUnsupportedFormatVersion(v) if v == NOT_V1),
        "expected EncodeUnsupportedFormatVersion({NOT_V1}), got {err:?}"
    );
}

#[test]
fn a_non_v1_suite_id_is_rejected() {
    let mut m = minimal_manifest();
    m.suite_id = NOT_V1;
    let err = expect_rejected(check_v1_sentinels(&m), "non-v1 suite_id");
    assert!(
        matches!(err, ManifestError::EncodeUnsupportedSuiteId(v) if v == NOT_V1),
        "expected EncodeUnsupportedSuiteId({NOT_V1}), got {err:?}"
    );
}

#[test]
fn the_reported_value_is_the_offending_one_not_a_constant() {
    // Each variant carries the value it rejected. A body declaring 9 must
    // say 9 — an implementation hard-coding the payload, or reporting the
    // *expected* v1 value instead of the observed one, passes every
    // `matches!(err, Encode…(_))` assertion in the tree.
    let mut m = minimal_manifest();
    m.manifest_version = 9;
    let err = expect_rejected(check_v1_sentinels(&m), "manifest_version 9");
    assert!(
        matches!(err, ManifestError::EncodeUnsupportedManifestVersion(9)),
        "expected the observed value 9, got {err:?}"
    );
}

#[test]
fn a_body_violating_two_sentinels_names_the_first_in_field_order() {
    // §4.2 field order is manifest_version, format_version, suite_id, and
    // `parse_manifest_map` reports in that order too. Pinning it here
    // means a body violating several sentinels names the same field
    // whichever direction rejects it — asserted rather than left to
    // coincidence, because the two implementations are independent.
    let mut m = minimal_manifest();
    m.manifest_version = NOT_V1 as u8;
    m.format_version = NOT_V1;
    m.suite_id = NOT_V1;
    let err = expect_rejected(check_v1_sentinels(&m), "all three sentinels wrong");
    assert!(
        matches!(err, ManifestError::EncodeUnsupportedManifestVersion(_)),
        "expected the FIRST field in §4.2 order, got {err:?}"
    );

    // ...and with the first one restored, the next in order.
    m.manifest_version = MANIFEST_VERSION_V1;
    let err = expect_rejected(check_v1_sentinels(&m), "two sentinels wrong");
    assert!(
        matches!(err, ManifestError::EncodeUnsupportedFormatVersion(_)),
        "expected format_version once manifest_version is v1, got {err:?}"
    );
}

// ---- the rule is wired to the writer ---------------------------------

#[test]
fn encode_manifest_rejects_every_non_v1_sentinel() {
    // The sweep, not three hand-copies: #589's lesson is that a rule
    // shared by several arms needs one test that walks every arm, or the
    // arm nobody wrote a case for is the one that breaks.
    let cases: [BreakCase; 3] = [
        ("manifest_version", |m| m.manifest_version = NOT_V1 as u8),
        ("format_version", |m| m.format_version = NOT_V1),
        ("suite_id", |m| m.suite_id = NOT_V1),
    ];
    for (field, break_it) in cases {
        let mut m = populated_manifest();
        break_it(&mut m);
        let outcome = encode_manifest(&m);
        assert!(
            outcome.is_err(),
            "encode_manifest accepted a manifest whose {field} is not v1"
        );
    }
}

#[test]
fn encode_manifest_still_accepts_a_v1_manifest() {
    // The other half of the sweep above. A check wired as
    // `return Err(..)` unconditionally would pass it alone.
    assert!(encode_manifest(&populated_manifest()).is_ok());
}

// `sign_manifest`'s own refusal — #587's user-visible property — is
// pinned in `file/sign/tests.rs`, beside the hybrid-keypair fixture it
// needs, rather than duplicating that fixture here.

#[test]
fn the_sentinel_check_outranks_the_repeated_value_check() {
    // Both #587's and #600's rules are `encode_manifest` preconditions,
    // so a manifest violating both has a reportable precedence. It is
    // fixed deliberately — a body whose *version* this client cannot
    // speak should say so before complaining about the contents of arrays
    // whose meaning is version-dependent — and pinned here so a future
    // reordering of `encode_manifest`'s opening statements is a test
    // failure rather than a silent change.
    let mut m = populated_manifest();
    m.manifest_version = NOT_V1 as u8;
    let dup = m.blocks[0].clone();
    m.blocks.push(dup);

    let err = expect_rejected(encode_manifest(&m), "both rules violated");
    assert!(
        matches!(err, ManifestError::EncodeUnsupportedManifestVersion(_)),
        "expected the sentinel rule to outrank the repeated-value rule, got {err:?}"
    );
}

// ---- the two directions, together ------------------------------------

#[test]
fn each_v1_sentinel_is_rejected_in_both_directions() {
    // The parity floor. The two implementations of §4.2's sentinel rule
    // are independent by design (see the module doc), so nothing but this
    // test stops one direction gaining a sentinel the other does not
    // check. It asserts the WEAK property — both directions reject —
    // deliberately: the STRONG property (which variant) is what
    // `the_decode_side_check_is_not_backstopped_by_this_one` covers, and
    // conflating them would let a backstop satisfy this one.
    use crate::vault::manifest::decode::decode_manifest;

    let cases: [ParityCase; 3] = [
        (
            "manifest_version",
            NOT_V1 as u8,
            FORMAT_VERSION_V1,
            SUITE_ID_V1,
        ),
        ("format_version", MANIFEST_VERSION_V1, NOT_V1, SUITE_ID_V1),
        ("suite_id", MANIFEST_VERSION_V1, FORMAT_VERSION_V1, NOT_V1),
    ];

    for (field, mv, fv, sid) in cases {
        // Write side.
        let mut m = minimal_manifest();
        m.manifest_version = mv;
        m.format_version = fv;
        m.suite_id = sid;
        assert!(
            encode_manifest(&m).is_err(),
            "the WRITER accepted a manifest whose {field} is not v1"
        );

        // Read side, over bytes built without going through the encoder
        // — which now refuses to produce them, exactly as #602 found for
        // the card: a checked encoder cannot build its own hostile
        // fixture.
        let bytes = build_manifest_map_with_sentinels(Some(mv), true, fv, sid);
        assert!(
            decode_manifest(&bytes).is_err(),
            "the READER accepted a body whose {field} is not v1"
        );
    }
}

#[test]
fn the_decode_side_check_is_not_backstopped_by_this_one() {
    // The property the separate `Encode*` variants exist for.
    //
    // §4.3 step 4 re-encodes the parsed manifest through
    // `encode_manifest`, so `check_v1_sentinels` runs on the decode path.
    // Had the write side reused the decoder's three variants, deleting
    // `parse_manifest_map`'s sentinel rejection would leave a bad body
    // still rejected — here, at the re-encode, with a byte-identical
    // error — and the decoder's own regression could no longer fail.
    //
    // Asserting the DECODE-side variant specifically is what makes that
    // mutation visible: with the decoder's check deleted, this test sees
    // `EncodeUnsupportedManifestVersion` and reds.
    use crate::vault::manifest::decode::decode_manifest;

    let bytes =
        build_manifest_map_with_sentinels(Some(NOT_V1 as u8), true, FORMAT_VERSION_V1, SUITE_ID_V1);
    let err = expect_rejected(decode_manifest(&bytes), "non-v1 manifest_version on read");
    assert!(
        matches!(err, ManifestError::UnsupportedManifestVersion(v) if v == NOT_V1 as u8),
        "a READ of a non-v1 body must report the DECODE-side variant, not the \
         writer's; got {err:?}"
    );
}

#[test]
fn a_valid_manifest_still_round_trips_through_decode() {
    // `check_v1_sentinels` is a new early return inside `encode_manifest`,
    // which every vault open reaches through §4.3 step 4's re-encode. This
    // is the regression that says the new statement changed nothing on
    // that path.
    use crate::vault::manifest::decode::decode_manifest;

    let m = populated_manifest();
    let bytes = encode_manifest(&m).expect("encode a v1 manifest");
    let round_tripped = decode_manifest(bytes.expose()).expect("decode it back");
    assert_eq!(
        encode_manifest(&round_tripped).expect("re-encode").expose(),
        bytes.expose(),
        "the round trip must be byte-identical"
    );
}
