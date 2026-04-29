//! Integration negatives for `secretary_core::vault::open_vault` —
//! Group A of the post-PR-B coverage closure. Each test forges one
//! specific on-disk inconsistency (mis-matched contact card,
//! tampered manifest header field, swapped vault.toml KDF block)
//! and asserts that `open_vault` surfaces the matching typed
//! [`VaultError`] variant.
//!
//! These tests sit alongside the happy-path `tests/open_vault.rs`
//! file. They share no helpers across files (per the project
//! convention against extracting shared test crates) — the
//! `make_fast_vault` fixture is duplicated locally.
//!
//! Each test (a) triggers ONLY the target `VaultError` variant,
//! (b) uses `matches!` for the assertion, and (c) carries a
//! one-line comment explaining the regression it catches.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;

use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use rand_core::RngCore;

use secretary_core::crypto::kdf::Argon2idParams;
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::crypto::sig::{MlDsa65Secret, ED25519_SIG_LEN, ML_DSA_65_SIG_LEN};
use secretary_core::identity::card::{ContactCard, CARD_VERSION_V1};
use secretary_core::identity::fingerprint;
use secretary_core::unlock::{
    self, bundle, create_vault_unchecked, mnemonic::Mnemonic, vault_toml,
};
use secretary_core::vault::{
    decode_manifest_file, decrypt_manifest_body, encode_manifest_file, open_vault,
    sign_manifest, KdfParamsRef, Manifest, ManifestHeader, Unlocker, VaultError,
};

// ---------------------------------------------------------------------------
// Fixture helpers (mirror `tests/open_vault.rs::make_fast_vault`)
// ---------------------------------------------------------------------------

fn fast_kdf() -> Argon2idParams {
    Argon2idParams::new(8, 1, 1)
}

/// Create a complete on-disk vault with sub-floor KDF for fast tests.
/// Mirrors `tests/open_vault.rs::make_fast_vault` byte-for-byte; we
/// duplicate rather than share so each integration-test file stays
/// self-contained per the project's testing conventions.
fn make_fast_vault(
    seed: u8,
    password: &[u8],
    display_name: &str,
) -> (tempfile::TempDir, Mnemonic, SecretBytes) {
    let dir = tempfile::tempdir().unwrap();
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let pw = SecretBytes::new(password.to_vec());
    let created_at_ms = 1_714_060_800_000u64;
    let created =
        create_vault_unchecked(&pw, display_name, created_at_ms, fast_kdf(), &mut rng).unwrap();

    let vt = vault_toml::decode(std::str::from_utf8(&created.vault_toml_bytes).unwrap()).unwrap();

    let pq_sk = MlDsa65Secret::from_bytes(created.identity.ml_dsa_65_sk.expose()).unwrap();
    let mut card = ContactCard {
        card_version: CARD_VERSION_V1,
        contact_uuid: created.identity.user_uuid,
        display_name: created.identity.display_name.clone(),
        x25519_pk: created.identity.x25519_pk,
        ml_kem_768_pk: created.identity.ml_kem_768_pk.clone(),
        ed25519_pk: created.identity.ed25519_pk,
        ml_dsa_65_pk: created.identity.ml_dsa_65_pk.clone(),
        created_at_ms: created.identity.created_at_ms,
        self_sig_ed: [0u8; ED25519_SIG_LEN],
        self_sig_pq: vec![0u8; ML_DSA_65_SIG_LEN],
    };
    card.sign(&created.identity.ed25519_sk, &pq_sk).unwrap();
    let owner_card_bytes = card.to_canonical_cbor().unwrap();
    let author_fp = fingerprint::fingerprint(&owner_card_bytes);

    let manifest = Manifest {
        manifest_version: 1,
        vault_uuid: vt.vault_uuid,
        format_version: secretary_core::version::FORMAT_VERSION,
        suite_id: secretary_core::version::SUITE_ID,
        owner_user_uuid: created.identity.user_uuid,
        vector_clock: Vec::new(),
        blocks: Vec::new(),
        trash: Vec::new(),
        kdf_params: KdfParamsRef {
            memory_kib: vt.kdf.memory_kib,
            iterations: vt.kdf.iterations,
            parallelism: vt.kdf.parallelism,
            salt: vt.kdf.salt,
        },
        unknown: BTreeMap::new(),
    };
    let header = ManifestHeader {
        vault_uuid: vt.vault_uuid,
        created_at_ms,
        last_mod_ms: created_at_ms,
    };
    let mut nonce = [0u8; 24];
    rng.fill_bytes(&mut nonce);

    let mf = sign_manifest(
        header,
        &manifest,
        &created.identity_block_key,
        &nonce,
        author_fp,
        &created.identity.ed25519_sk,
        &pq_sk,
    )
    .unwrap();
    let mf_bytes = encode_manifest_file(&mf).unwrap();

    let owner_uuid_hex = format_uuid_hyphenated(&created.identity.user_uuid);
    let contacts_dir = dir.path().join("contacts");
    fs::create_dir_all(&contacts_dir).unwrap();
    fs::write(dir.path().join("vault.toml"), &created.vault_toml_bytes).unwrap();
    fs::write(
        dir.path().join("identity.bundle.enc"),
        &created.identity_bundle_bytes,
    )
    .unwrap();
    fs::write(
        contacts_dir.join(format!("{owner_uuid_hex}.card")),
        &owner_card_bytes,
    )
    .unwrap();
    fs::write(dir.path().join("manifest.cbor.enc"), &mf_bytes).unwrap();

    (dir, created.recovery_mnemonic, pw)
}

fn format_uuid_hyphenated(uuid: &[u8; 16]) -> String {
    let mut s = String::with_capacity(36);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, b) in uuid.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            s.push('-');
        }
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

// ---------------------------------------------------------------------------
// 1. OwnerUuidMismatch: replace the on-disk owner card with another
//    identity's signed card kept under the orchestrator's expected
//    filename. Catches a regression where the §4.3 step-3 owner-UUID
//    cross-check between the loaded card and the unlocked identity is
//    skipped (e.g. on a refactor of `open_vault` that drops the
//    contact_uuid comparison).
// ---------------------------------------------------------------------------

#[test]
fn open_vault_owner_uuid_mismatch_rejected() {
    let (dir, _mnemonic, pw) = make_fast_vault(1, b"hunter2", "Owner");

    // Build a different identity with its own self-signed card. The
    // orchestrator finds the card by `<owner_uuid>.card` filename
    // (computed from the unlocked IdentityBundle); we substitute the
    // file's BYTES with this other card's CBOR so the filename still
    // matches but the card's `contact_uuid` does not match the bundle.
    let mut other_rng = ChaCha20Rng::from_seed([0xee; 32]);
    let other_id = bundle::generate("Eve", 1_714_060_800_000, &mut other_rng);
    let other_pq_sk = MlDsa65Secret::from_bytes(other_id.ml_dsa_65_sk.expose()).unwrap();
    let mut other_card = ContactCard {
        card_version: CARD_VERSION_V1,
        contact_uuid: other_id.user_uuid,
        display_name: other_id.display_name.clone(),
        x25519_pk: other_id.x25519_pk,
        ml_kem_768_pk: other_id.ml_kem_768_pk.clone(),
        ed25519_pk: other_id.ed25519_pk,
        ml_dsa_65_pk: other_id.ml_dsa_65_pk.clone(),
        created_at_ms: other_id.created_at_ms,
        self_sig_ed: [0u8; ED25519_SIG_LEN],
        self_sig_pq: vec![0u8; ML_DSA_65_SIG_LEN],
    };
    other_card.sign(&other_id.ed25519_sk, &other_pq_sk).unwrap();
    let other_card_bytes = other_card.to_canonical_cbor().unwrap();

    // Find the on-disk owner card path (the orchestrator computes the
    // same name from the unlocked IdentityBundle's user_uuid; we
    // discover it by listing the contacts/ dir, since make_fast_vault
    // wrote exactly one card).
    let contacts_dir = dir.path().join("contacts");
    let entries: Vec<_> = fs::read_dir(&contacts_dir).unwrap().collect();
    assert_eq!(entries.len(), 1, "fixture has exactly one card on disk");
    let owner_card_path = entries.into_iter().next().unwrap().unwrap().path();

    // Overwrite the owner card with the other identity's card bytes —
    // same filename, different contact_uuid embedded in the card.
    fs::write(&owner_card_path, &other_card_bytes).unwrap();

    let err = open_vault(dir.path(), Unlocker::Password(&pw), None)
        .expect_err("mismatched on-disk card must reject");

    match err {
        VaultError::OwnerUuidMismatch { vault, found } => {
            assert_ne!(vault, found, "the two UUIDs must disagree");
            assert_eq!(
                found, other_id.user_uuid,
                "found is the substituted card's contact_uuid"
            );
        }
        other => panic!("expected OwnerUuidMismatch, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 2. ManifestAuthorMismatch: rewrite the manifest envelope with a
//    different `author_fingerprint`, re-sign with the OWNER's keys so
//    the §8 hybrid signature still verifies. The author_fingerprint
//    field is INSIDE the §8 signed range, so we must re-sign — the
//    signature is the gate the orchestrator runs before the
//    fingerprint cross-check fires. Catches a regression where the
//    §4.3 step-3 author_fingerprint vs computed-owner-card-fingerprint
//    check is skipped.
// ---------------------------------------------------------------------------

#[test]
fn open_vault_manifest_author_mismatch_rejected() {
    let (dir, _mnemonic, pw) = make_fast_vault(2, b"hunter2", "Owner");

    // Recover the owner identity material exactly as `open_vault`
    // would: read vault.toml + identity.bundle.enc and unlock with the
    // password.
    let vt_bytes = fs::read(dir.path().join("vault.toml")).unwrap();
    let bundle_bytes = fs::read(dir.path().join("identity.bundle.enc")).unwrap();
    let unlocked = unlock::open_with_password(&vt_bytes, &bundle_bytes, &pw).unwrap();
    let pq_sk = MlDsa65Secret::from_bytes(unlocked.identity.ml_dsa_65_sk.expose()).unwrap();

    // Re-decrypt the on-disk manifest body so we can hold the in-memory
    // Manifest, then re-sign with a TAMPERED author_fingerprint. The
    // body itself is unchanged, so all post-decrypt cross-checks
    // (owner_user_uuid, vault_uuid, kdf_params) succeed — the test
    // isolates ManifestAuthorMismatch.
    let manifest_path = dir.path().join("manifest.cbor.enc");
    let mf_bytes = fs::read(&manifest_path).unwrap();
    let original = decode_manifest_file(&mf_bytes).unwrap();

    // Decrypt body to recover the in-memory Manifest for re-encrypt.
    let mut ct_with_tag = Vec::with_capacity(original.aead_ct.len() + 16);
    ct_with_tag.extend_from_slice(&original.aead_ct);
    ct_with_tag.extend_from_slice(&original.aead_tag);
    let body = decrypt_manifest_body(
        &original.header,
        &ct_with_tag,
        &unlocked.identity_block_key,
        &original.aead_nonce,
    )
    .unwrap();

    // Tamper: a known-different 16-byte fingerprint (definitely not the
    // computed owner card fingerprint).
    let bogus_author = [0xa5u8; 16];

    let resigned = sign_manifest(
        original.header,
        &body,
        &unlocked.identity_block_key,
        &original.aead_nonce,
        bogus_author,
        &unlocked.identity.ed25519_sk,
        &pq_sk,
    )
    .expect("re-sign with bogus author");
    fs::write(&manifest_path, encode_manifest_file(&resigned).unwrap()).unwrap();

    let err = open_vault(dir.path(), Unlocker::Password(&pw), None)
        .expect_err("manifest author_fingerprint mismatch must reject");
    assert!(
        matches!(err, VaultError::ManifestAuthorMismatch),
        "expected ManifestAuthorMismatch, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 3. ManifestVaultUuidMismatch: rewrite the manifest envelope with a
//    body whose `vault_uuid` differs from the (AAD-bound) header's
//    `vault_uuid`. The header on disk stays intact, but the encryptor
//    feeds a body with a different `vault_uuid` field. AEAD decrypt
//    succeeds (the AAD-bound header is unchanged), so the §4.3 step-5
//    explicit equality check is the one that fires. Catches a
//    regression where that cross-check is skipped on a multi-suite v2
//    where AAD could decouple from header layout.
// ---------------------------------------------------------------------------

#[test]
fn open_vault_manifest_vault_uuid_mismatch_rejected() {
    let (dir, _mnemonic, pw) = make_fast_vault(3, b"hunter2", "Owner");

    let vt_bytes = fs::read(dir.path().join("vault.toml")).unwrap();
    let bundle_bytes = fs::read(dir.path().join("identity.bundle.enc")).unwrap();
    let unlocked = unlock::open_with_password(&vt_bytes, &bundle_bytes, &pw).unwrap();
    let pq_sk = MlDsa65Secret::from_bytes(unlocked.identity.ml_dsa_65_sk.expose()).unwrap();

    let manifest_path = dir.path().join("manifest.cbor.enc");
    let mf_bytes = fs::read(&manifest_path).unwrap();
    let original = decode_manifest_file(&mf_bytes).unwrap();

    let mut ct_with_tag = Vec::with_capacity(original.aead_ct.len() + 16);
    ct_with_tag.extend_from_slice(&original.aead_ct);
    ct_with_tag.extend_from_slice(&original.aead_tag);
    let mut body = decrypt_manifest_body(
        &original.header,
        &ct_with_tag,
        &unlocked.identity_block_key,
        &original.aead_nonce,
    )
    .unwrap();

    // Mutate ONLY the body's vault_uuid; keep the header's vault_uuid
    // untouched in `original.header`. After re-AEAD with the original
    // header (as AAD), the body and header disagree on vault_uuid,
    // which is exactly the §4.3 step-5 invariant.
    let original_header_vault_uuid = original.header.vault_uuid;
    body.vault_uuid = [0xc7u8; 16];
    assert_ne!(body.vault_uuid, original_header_vault_uuid);

    // Recompute the owner card fingerprint to keep `author_fingerprint`
    // valid (otherwise ManifestAuthorMismatch would fire first).
    // We do that by reading the on-disk card, since make_fast_vault
    // already wrote it.
    let contacts_dir = dir.path().join("contacts");
    let entries: Vec<_> = fs::read_dir(&contacts_dir).unwrap().collect();
    let owner_card_path = entries.into_iter().next().unwrap().unwrap().path();
    let owner_card_bytes = fs::read(&owner_card_path).unwrap();
    let author_fp = fingerprint::fingerprint(&owner_card_bytes);

    let resigned = sign_manifest(
        original.header, // keep the header's vault_uuid
        &body,           // body has the different vault_uuid
        &unlocked.identity_block_key,
        &original.aead_nonce,
        author_fp,
        &unlocked.identity.ed25519_sk,
        &pq_sk,
    )
    .expect("re-sign with body.vault_uuid != header.vault_uuid");
    fs::write(&manifest_path, encode_manifest_file(&resigned).unwrap()).unwrap();

    let err = open_vault(dir.path(), Unlocker::Password(&pw), None)
        .expect_err("body.vault_uuid != header.vault_uuid must reject");
    match err {
        VaultError::ManifestVaultUuidMismatch { header, body: body_uuid } => {
            assert_eq!(header, original_header_vault_uuid);
            assert_eq!(body_uuid, [0xc7u8; 16]);
        }
        other => panic!("expected ManifestVaultUuidMismatch, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 4. KdfParamsMismatch: rewrite the manifest body with a different
//    `kdf_params` (e.g. larger memory_kib) and re-AEAD+re-sign. We do
//    NOT touch vault.toml — the unlock path keeps deriving the
//    correct IBK from the on-disk vault.toml, manifest decrypt
//    succeeds, but the §4.3 step-6 cross-check between manifest
//    body's kdf_params and vault.toml's [kdf] fires. Catches a
//    regression where that cross-check is skipped, allowing a
//    malicious cloud host to swap memory_kib in vault.toml without
//    detection (`KdfParamsMismatch` rejects loudly here).
//
// Note: the brief originally suggested mutating vault.toml instead.
// We mutate the manifest body for two reasons: (a) changing
// vault.toml mutates the master_kek derivation, which fails the
// unlock AEAD (`UnlockError::WrongPasswordOrCorrupt`) before the
// kdf_params check can fire; and (b) the inequality is symmetric —
// either side of the comparison reaching a mismatch state surfaces
// the same `KdfParamsMismatch` variant, so this still exercises the
// exact code path the brief targets.
// ---------------------------------------------------------------------------

#[test]
fn open_vault_kdf_params_mismatch_rejected() {
    let (dir, _mnemonic, pw) = make_fast_vault(4, b"hunter2", "Owner");

    let vt_bytes = fs::read(dir.path().join("vault.toml")).unwrap();
    let bundle_bytes = fs::read(dir.path().join("identity.bundle.enc")).unwrap();
    let unlocked = unlock::open_with_password(&vt_bytes, &bundle_bytes, &pw).unwrap();
    let pq_sk = MlDsa65Secret::from_bytes(unlocked.identity.ml_dsa_65_sk.expose()).unwrap();

    let manifest_path = dir.path().join("manifest.cbor.enc");
    let mf_bytes = fs::read(&manifest_path).unwrap();
    let original = decode_manifest_file(&mf_bytes).unwrap();

    let mut ct_with_tag = Vec::with_capacity(original.aead_ct.len() + 16);
    ct_with_tag.extend_from_slice(&original.aead_ct);
    ct_with_tag.extend_from_slice(&original.aead_tag);
    let mut body = decrypt_manifest_body(
        &original.header,
        &ct_with_tag,
        &unlocked.identity_block_key,
        &original.aead_nonce,
    )
    .unwrap();

    // Bump memory_kib to a value definitely different from
    // vault.toml's (which the fast-KDF helper sets to 8). vault.toml
    // is unchanged on disk, so the orchestrator's decoded vt.kdf
    // still has the original memory_kib. After re-AEAD+re-sign, the
    // manifest body's kdf_params != vault_toml.kdf.
    let original_memory_kib = body.kdf_params.memory_kib;
    body.kdf_params.memory_kib = original_memory_kib.wrapping_add(1);
    assert_ne!(body.kdf_params.memory_kib, original_memory_kib);

    let contacts_dir = dir.path().join("contacts");
    let entries: Vec<_> = fs::read_dir(&contacts_dir).unwrap().collect();
    let owner_card_path = entries.into_iter().next().unwrap().unwrap().path();
    let owner_card_bytes = fs::read(&owner_card_path).unwrap();
    let author_fp = fingerprint::fingerprint(&owner_card_bytes);

    let resigned = sign_manifest(
        original.header,
        &body,
        &unlocked.identity_block_key,
        &original.aead_nonce,
        author_fp,
        &unlocked.identity.ed25519_sk,
        &pq_sk,
    )
    .expect("re-sign with mutated kdf_params");
    fs::write(&manifest_path, encode_manifest_file(&resigned).unwrap()).unwrap();

    let err = open_vault(dir.path(), Unlocker::Password(&pw), None)
        .expect_err("manifest body kdf_params != vault.toml [kdf] must reject");
    assert!(
        matches!(err, VaultError::KdfParamsMismatch),
        "expected KdfParamsMismatch, got {err:?}"
    );
}
