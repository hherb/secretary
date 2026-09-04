//! Unit tests for manifest hybrid signing / verification (§8) and §10
//! rollback resistance.
//!
//! Moved verbatim out of the pre-split `manifest/tests.rs` (#564); shared
//! fixtures live in [`crate::vault::manifest::test_support`].

use crate::vault::manifest::decrypt_manifest_body;
use crate::vault::manifest::test_support::{
    fixed_manifest_header, minimal_manifest, populated_manifest, test_ibk, test_nonce,
};

use super::*;

// ---- Sign / verify (§4.1 / §8) ---------------------------------------
//
// `sign_manifest` also drives `encode::encode_manifest` and
// `header::encrypt_manifest_body`; the property each test pins is the
// hybrid signature over `file::signed_message_bytes`' range.

/// Build a fresh hybrid keypair from a pinned ChaCha20Rng seed.
/// Same pattern as block.rs's signing-key fixtures.
fn fixture_hybrid_keypair(
    seed: u8,
) -> (Ed25519Secret, Ed25519Public, MlDsa65Secret, MlDsa65Public) {
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    let mut ed_rng = ChaCha20Rng::from_seed([seed; 32]);
    let mut pq_rng = ChaCha20Rng::from_seed([seed.wrapping_add(1); 32]);
    let (sk_ed, pk_ed) = sig::generate_ed25519(&mut ed_rng);
    let (sk_pq, pk_pq) = sig::generate_ml_dsa_65(&mut pq_rng);
    (sk_ed, pk_ed, sk_pq, pk_pq)
}

#[test]
fn sign_then_verify_round_trips() {
    let body = populated_manifest();
    let header = fixed_manifest_header();
    let ibk = test_ibk(0x00);
    let nonce = test_nonce();
    let author: Fingerprint = [0xa5; 16];
    let (sk_ed, pk_ed, sk_pq, pk_pq) = fixture_hybrid_keypair(0x10);

    let file =
        sign_manifest(header, &body, &ibk, &nonce, author, &sk_ed, &sk_pq).expect("sign_manifest");
    verify_manifest(&file, &pk_ed, &pk_pq).expect("verify_manifest");
}

#[test]
fn sign_manifest_refuses_a_body_with_a_repeated_block_uuid() {
    // §4.2's writer half at the SIGNING boundary, which is the harm #600
    // is actually about: before it, `encode_manifest` would emit — and
    // this function would hybrid-sign — a body `decode_manifest` refuses
    // to open, producing an owner-signed manifest no client can read.
    //
    // Every other test of the new check calls `encode_manifest`
    // directly, so the stated harm was argued rather than executable
    // (#608 review). It propagates through a plain `?`, so this pins the
    // wiring, not the rule.
    let mut body = populated_manifest();
    body.blocks[1].block_uuid = body.blocks[0].block_uuid;
    let header = fixed_manifest_header();
    let ibk = test_ibk(0x00);
    let nonce = test_nonce();
    let (sk_ed, _pk_ed, sk_pq, _pk_pq) = fixture_hybrid_keypair(0x10);

    assert!(matches!(
        sign_manifest(header, &body, &ibk, &nonce, [0xa5; 16], &sk_ed, &sk_pq),
        Err(ManifestError::EncodeDuplicateBlockUuid)
    ));
}

#[test]
fn verify_rejects_tampered_aead_ct() {
    let body = minimal_manifest();
    let header = fixed_manifest_header();
    let ibk = test_ibk(0x00);
    let nonce = test_nonce();
    let author: Fingerprint = [0xa5; 16];
    let (sk_ed, pk_ed, sk_pq, pk_pq) = fixture_hybrid_keypair(0x20);

    let mut file =
        sign_manifest(header, &body, &ibk, &nonce, author, &sk_ed, &sk_pq).expect("sign_manifest");
    // Flip a byte deep inside the ciphertext.
    if file.aead_ct.is_empty() {
        // minimal_manifest's CBOR is non-empty in practice, but guard
        // against a future trim.
        file.aead_ct.push(0x00);
    }
    file.aead_ct[0] ^= 0xff;
    let err =
        verify_manifest(&file, &pk_ed, &pk_pq).expect_err("tampered aead_ct must fail verify");
    assert!(
        matches!(
            err,
            ManifestError::Ed25519SignatureInvalid | ManifestError::MlDsa65SignatureInvalid
        ),
        "expected hybrid verify failure, got {err:?}"
    );
}

#[test]
fn verify_rejects_tampered_header() {
    let body = minimal_manifest();
    let header = fixed_manifest_header();
    let ibk = test_ibk(0x00);
    let nonce = test_nonce();
    let author: Fingerprint = [0xa5; 16];
    let (sk_ed, pk_ed, sk_pq, pk_pq) = fixture_hybrid_keypair(0x30);

    let mut file =
        sign_manifest(header, &body, &ibk, &nonce, author, &sk_ed, &sk_pq).expect("sign_manifest");
    // Mutate last_mod_ms — the header is part of the signed bytes.
    file.header.last_mod_ms = file.header.last_mod_ms.wrapping_add(1);
    let err = verify_manifest(&file, &pk_ed, &pk_pq).expect_err("tampered header must fail verify");
    assert!(
        matches!(
            err,
            ManifestError::Ed25519SignatureInvalid | ManifestError::MlDsa65SignatureInvalid
        ),
        "expected hybrid verify failure on header tamper, got {err:?}"
    );
}

#[test]
fn verify_rejects_wrong_pk() {
    let body = minimal_manifest();
    let header = fixed_manifest_header();
    let ibk = test_ibk(0x00);
    let nonce = test_nonce();
    let author: Fingerprint = [0xa5; 16];
    let (sk_ed, _pk_ed, sk_pq, _pk_pq) = fixture_hybrid_keypair(0x40);
    let (_sk_ed2, pk_ed2, _sk_pq2, pk_pq2) = fixture_hybrid_keypair(0x50);

    let file =
        sign_manifest(header, &body, &ibk, &nonce, author, &sk_ed, &sk_pq).expect("sign_manifest");
    // Verify with a *different* keypair's public keys.
    let err = verify_manifest(&file, &pk_ed2, &pk_pq2).expect_err("wrong pk must fail verify");
    assert!(
        matches!(
            err,
            ManifestError::Ed25519SignatureInvalid | ManifestError::MlDsa65SignatureInvalid
        ),
        "expected hybrid verify failure under wrong pk, got {err:?}"
    );
}

// (Group C) Pin the §8 signed-range invariants for the two regions
// exercised only stochastically by proptest property G:
// `aead_nonce` (24 bytes) and `aead_tag` (16 bytes). Both are inside
// the §8 signed-message range (magic..aead_tag inclusive — see
// `signed_message_bytes`), so a deterministic single-byte flip MUST
// fail signature verification. Companion to the existing
// `verify_rejects_tampered_aead_ct` / `verify_rejects_tampered_header`
// tests; this closes the §8 coverage to all four mutable regions.

/// Regression: ensures `aead_nonce` is inside the §8 signed range.
/// If a future signed_message_bytes refactor accidentally drops the
/// nonce from the signed prefix, this test catches it (verify would
/// suddenly accept a flipped-nonce file).
#[test]
fn tamper_aead_nonce_breaks_signature() {
    let body = minimal_manifest();
    let header = fixed_manifest_header();
    let ibk = test_ibk(0x00);
    let nonce = test_nonce();
    let author: Fingerprint = [0xa5; 16];
    let (sk_ed, pk_ed, sk_pq, pk_pq) = fixture_hybrid_keypair(0x70);

    let mut file =
        sign_manifest(header, &body, &ibk, &nonce, author, &sk_ed, &sk_pq).expect("sign_manifest");
    // Flip a byte in the nonce. Pick the middle to avoid any
    // boundary-mistake regressions where the signed slice off-by-ones
    // either edge.
    file.aead_nonce[12] ^= 0x01;
    let err =
        verify_manifest(&file, &pk_ed, &pk_pq).expect_err("tampered aead_nonce must fail verify");
    assert!(
        matches!(
            err,
            ManifestError::Ed25519SignatureInvalid | ManifestError::MlDsa65SignatureInvalid
        ),
        "expected hybrid verify failure on aead_nonce tamper, got {err:?}"
    );
}

/// Regression: ensures `aead_tag` is inside the §8 signed range.
/// If a future signed_message_bytes refactor accidentally truncates
/// the signed prefix at aead_ct (excluding the tag), this test
/// catches it. The §8 spec range is "magic..aead_tag inclusive" —
/// a flipped tag byte must still fail the signature even though
/// AEAD verification (which would also catch it) is sequenced AFTER
/// the verify per the verify-before-decrypt discipline.
#[test]
fn tamper_aead_tag_breaks_signature() {
    let body = minimal_manifest();
    let header = fixed_manifest_header();
    let ibk = test_ibk(0x00);
    let nonce = test_nonce();
    let author: Fingerprint = [0xa5; 16];
    let (sk_ed, pk_ed, sk_pq, pk_pq) = fixture_hybrid_keypair(0x80);

    let mut file =
        sign_manifest(header, &body, &ibk, &nonce, author, &sk_ed, &sk_pq).expect("sign_manifest");
    // Flip a byte in the AEAD tag. Tag is fixed-size (16 bytes), so
    // any index 0..AEAD_TAG_LEN works; pick the first.
    file.aead_tag[0] ^= 0x01;
    let err =
        verify_manifest(&file, &pk_ed, &pk_pq).expect_err("tampered aead_tag must fail verify");
    assert!(
        matches!(
            err,
            ManifestError::Ed25519SignatureInvalid | ManifestError::MlDsa65SignatureInvalid
        ),
        "expected hybrid verify failure on aead_tag tamper, got {err:?}"
    );
}

// Full pipeline test: also covers `header::decrypt_manifest_body` and
// `encode::encode_manifest`; `sign_manifest` / `verify_manifest` are the
// primary subject.

#[test]
fn sign_then_decrypt_round_trips() {
    // Full pipeline: sign → verify → decrypt → compare body.
    let body = populated_manifest();
    let header = fixed_manifest_header();
    let ibk = test_ibk(0x00);
    let nonce = test_nonce();
    let author: Fingerprint = [0xa5; 16];
    let (sk_ed, pk_ed, sk_pq, pk_pq) = fixture_hybrid_keypair(0x60);

    let file =
        sign_manifest(header, &body, &ibk, &nonce, author, &sk_ed, &sk_pq).expect("sign_manifest");

    // Verify before decrypt — orchestrator-style sequencing.
    verify_manifest(&file, &pk_ed, &pk_pq).expect("verify_manifest");

    // Reconstruct ct_with_tag = aead_ct ++ aead_tag for the AEAD API.
    let mut ct_with_tag = Vec::with_capacity(file.aead_ct.len() + AEAD_TAG_LEN);
    ct_with_tag.extend_from_slice(&file.aead_ct);
    ct_with_tag.extend_from_slice(&file.aead_tag);
    let recovered = decrypt_manifest_body(&file.header, &ct_with_tag, &ibk, &nonce)
        .expect("decrypt_manifest_body");

    // populated_manifest's input arrays are non-canonical-order; the
    // decoded copy is in canonical order. Use the same sort-then-compare
    // discipline as the existing `roundtrip_populated_manifest` test.
    let mut body_sorted = body.clone();
    body_sorted.vector_clock.sort_by_key(|a| a.device_uuid);
    body_sorted.blocks.sort_by_key(|a| a.block_uuid);
    for blk in &mut body_sorted.blocks {
        blk.recipients.sort();
        blk.vector_clock_summary.sort_by_key(|a| a.device_uuid);
    }
    body_sorted.trash.sort_by_key(|a| a.block_uuid);
    assert_eq!(
        recovered, body_sorted,
        "decrypted manifest matches original"
    );
}

// ---- §10 rollback resistance --------------------------------------

/// Tiny construction shorthand for the rollback test matrix.
fn vc(uuid_byte: u8, counter: u64) -> VectorClockEntry {
    VectorClockEntry {
        device_uuid: [uuid_byte; 16],
        counter,
    }
}

// (9) Spec-discipline lodestone: `is_rollback` must be defined on
//     the *logical* clock (a map from device_uuid → counter), not on
//     the slice. A consumer that confuses ordering with semantics
//     will silently mis-classify reorderings of the very same clock.
//     Pin two pairs that differ only in slice order.
#[test]
fn order_independence() {
    let local_a = vec![vc(0x01, 5), vc(0x02, 3), vc(0x03, 7)];
    let local_b = vec![vc(0x03, 7), vc(0x01, 5), vc(0x02, 3)];

    let incoming_a = vec![vc(0x01, 4), vc(0x02, 3), vc(0x03, 7)];
    let incoming_b = vec![vc(0x02, 3), vc(0x03, 7), vc(0x01, 4)];

    // Same logical clocks; differing slice orders. The boolean
    // verdict must not move with the order.
    assert_eq!(
        is_rollback(&local_a, &incoming_a),
        is_rollback(&local_b, &incoming_b),
        "is_rollback must be order-independent in both arguments"
    );

    // And likewise for the equal-clocks case in both directions.
    let eq_a = vec![vc(0x01, 5), vc(0x02, 3)];
    let eq_b = vec![vc(0x02, 3), vc(0x01, 5)];
    assert_eq!(
        is_rollback(&eq_a, &eq_b),
        is_rollback(&eq_b, &eq_a),
        "equal logical clocks reordered must compare identically"
    );
}

#[test]
fn equal_clocks_not_rollback() {
    let clock = vec![vc(0x01, 5), vc(0x02, 3)];
    assert!(
        !is_rollback(&clock, &clock),
        "identical clocks are not a rollback"
    );
}

#[test]
fn incoming_dominates_not_rollback() {
    let local = vec![vc(0x01, 5), vc(0x02, 3)];
    let incoming = vec![vc(0x01, 6), vc(0x02, 3)]; // ≥ everywhere, > on D1
    assert!(
        !is_rollback(&local, &incoming),
        "incoming strictly dominates local — accept, not rollback"
    );
}

#[test]
fn incoming_strictly_dominated_is_rollback() {
    let local = vec![vc(0x01, 5), vc(0x02, 3)];
    let incoming = vec![vc(0x01, 4), vc(0x02, 3)]; // ≤ everywhere, < on D1
    assert!(
        is_rollback(&local, &incoming),
        "incoming strictly dominated by local — rollback"
    );
}

#[test]
fn incoming_introduces_new_device_not_rollback() {
    let local = vec![vc(0x01, 5)];
    // incoming carries D1 unchanged AND introduces D2 with counter > 0.
    // That's "incoming dominates" (D2's counter is implicitly 0 in local).
    let incoming = vec![vc(0x01, 5), vc(0x02, 1)];
    assert!(
        !is_rollback(&local, &incoming),
        "incoming introducing a new device dominates — not a rollback"
    );
}

#[test]
fn local_introduces_device_incoming_lacks_is_rollback() {
    // local has D1 and D2; incoming has only D1 at the same counter.
    // D2 in incoming is implicitly 0, so any_strictly_less fires.
    // No counter in incoming is strictly more → rollback.
    let local = vec![vc(0x01, 5), vc(0x02, 2)];
    let incoming = vec![vc(0x01, 5)];
    assert!(
        is_rollback(&local, &incoming),
        "incoming missing a device that local has at counter > 0 — rollback"
    );
}

#[test]
fn concurrent_not_rollback() {
    // D1 higher in incoming, D2 higher in local → concurrent.
    let local = vec![vc(0x01, 5), vc(0x02, 4)];
    let incoming = vec![vc(0x01, 6), vc(0x02, 3)];
    assert!(
        !is_rollback(&local, &incoming),
        "concurrent clocks are not a rollback per se — caller will merge"
    );
}

#[test]
fn empty_incoming_against_nonempty_local_is_rollback() {
    let local = vec![vc(0x01, 1)];
    let incoming: Vec<VectorClockEntry> = Vec::new();
    assert!(
        is_rollback(&local, &incoming),
        "empty incoming against local with counter > 0 — rollback"
    );
}

#[test]
fn empty_local_against_any_incoming_not_rollback() {
    let local: Vec<VectorClockEntry> = Vec::new();
    let incoming = vec![vc(0x01, 5), vc(0x02, 3)];
    assert!(
        !is_rollback(&local, &incoming),
        "empty local — any incoming dominates (or is also empty)"
    );

    // And the both-empty edge: equal, not a rollback.
    let empty: Vec<VectorClockEntry> = Vec::new();
    assert!(
        !is_rollback(&empty, &empty),
        "both empty — equal, not a rollback"
    );
}
