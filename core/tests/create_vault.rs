//! Integration tests for `secretary_core::vault::create_vault` —
//! Task 10 of PR-B. Exercises the full four-file initial layout:
//! `vault.toml`, `identity.bundle.enc`, `manifest.cbor.enc`, and the
//! owner's signed contact card under `contacts/`.
//!
//! Tests are deterministic by construction: a seeded
//! [`ChaCha20Rng`] drives [`unlock::create_vault_unchecked`] inside
//! the orchestrator, the password is fixed, and the KDF parameters
//! are the test-only sub-floor (8 KiB / 1 iteration / 1 lane) so
//! Argon2id runs in milliseconds rather than the v1-floor seconds.
//!
//! `create_vault` itself enforces the v1 floor; tests that want fast
//! KDF run against the public function with a tiny ad-hoc helper that
//! goes through `unlock::create_vault_unchecked` instead. See
//! `make_fast_vault` below.

#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;

use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

use secretary_core::crypto::aead::AEAD_TAG_LEN;
use secretary_core::crypto::kdf::Argon2idParams;
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::crypto::sig::MlDsa65Public;
use secretary_core::identity::card::ContactCard;
use secretary_core::identity::fingerprint;
use secretary_core::unlock::{
    self, bundle_file, create_vault_unchecked, mnemonic::Mnemonic, open_with_password, vault_toml,
};
use secretary_core::vault::{
    create_vault, decode_manifest_file, decrypt_manifest_body, verify_manifest, VaultError,
};

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

/// v1-floor-bypassing Argon2id parameters. The orchestrator under
/// test (`create_vault`) routes through `unlock::create_vault` which
/// rejects sub-floor params — see `unlock::UnlockError::WeakKdfParams`.
/// We confirm that contract in `create_vault_rejects_sub_floor_kdf`,
/// and use the unchecked path for the round-trip tests via
/// `make_fast_vault`.
fn fast_kdf() -> Argon2idParams {
    Argon2idParams::new(8, 1, 1)
}

/// Run the orchestrator against an empty tempdir, returning the dir
/// handle (kept alive so the directory is not dropped) plus the
/// returned recovery mnemonic. Uses the test-only fast KDF route via
/// the orchestrator's internal `unlock::create_vault_unchecked`
/// substitute; we replicate the orchestrator's logic against the
/// unchecked entry point so that integration tests run in
/// milliseconds. The bytes-on-disk shape is identical.
///
/// Mirrors the four-file write layout of the public `create_vault`
/// — adapted only on the KDF side.
fn make_fast_vault(seed: u8, password: &[u8], display_name: &str) -> (tempfile::TempDir, Mnemonic) {
    use secretary_core::identity::card::CARD_VERSION_V1;
    use secretary_core::crypto::sig::{MlDsa65Secret, ED25519_SIG_LEN, ML_DSA_65_SIG_LEN};
    use secretary_core::vault::{
        encode_manifest_file, sign_manifest, KdfParamsRef, Manifest, ManifestHeader,
    };

    let dir = tempfile::tempdir().unwrap();
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let pw = SecretBytes::new(password.to_vec());
    let created_at_ms = 1_714_060_800_000u64;
    let created = create_vault_unchecked(&pw, display_name, created_at_ms, fast_kdf(), &mut rng)
        .expect("unlock::create_vault_unchecked");

    // Re-parse vault.toml to recover vault_uuid + salt — mirrors
    // create_vault.
    let vt =
        vault_toml::decode(std::str::from_utf8(&created.vault_toml_bytes).unwrap()).unwrap();

    // Owner card.
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
        unknown: std::collections::BTreeMap::new(),
    };
    let header = ManifestHeader {
        vault_uuid: vt.vault_uuid,
        created_at_ms,
        last_mod_ms: created_at_ms,
    };
    let mut nonce = [0u8; 24];
    rand_core::RngCore::fill_bytes(&mut rng, &mut nonce);

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

    // Disk writes.
    let owner_uuid_hex = format_uuid_hyphenated(&created.identity.user_uuid);
    let contacts_dir = dir.path().join("contacts");
    fs::create_dir_all(&contacts_dir).unwrap();
    fs::write(dir.path().join("vault.toml"), &created.vault_toml_bytes).unwrap();
    fs::write(
        dir.path().join("identity.bundle.enc"),
        &created.identity_bundle_bytes,
    )
    .unwrap();
    fs::write(contacts_dir.join(format!("{owner_uuid_hex}.card")), &owner_card_bytes).unwrap();
    fs::write(dir.path().join("manifest.cbor.enc"), &mf_bytes).unwrap();
    (dir, created.recovery_mnemonic)
}

/// Hyphenated 8-4-4-4-12 lowercase hex of a 16-byte UUID. Mirrors the
/// orchestrator's internal helper so test paths are computed without
/// re-importing crate-private code.
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

/// Locate `contacts/<owner-uuid>.card` inside a vault folder by
/// scanning the directory; the test does not need to know the UUID
/// up-front. Returns the file path of the (sole) `.card` file.
fn find_owner_card(folder: &Path) -> std::path::PathBuf {
    let mut hits: Vec<_> = fs::read_dir(folder.join("contacts"))
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("card"))
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "expected exactly one .card file in contacts/, got {hits:?}"
    );
    hits.remove(0)
}

// ---------------------------------------------------------------------------
// 1. Files exist and are non-empty
// ---------------------------------------------------------------------------

#[test]
fn create_vault_writes_four_canonical_files() {
    let (dir, _mnemonic) = make_fast_vault(7, b"hunter2", "Alice");

    let vault_toml_path = dir.path().join("vault.toml");
    let bundle_path = dir.path().join("identity.bundle.enc");
    let manifest_path = dir.path().join("manifest.cbor.enc");
    let contacts_dir = dir.path().join("contacts");

    for p in [&vault_toml_path, &bundle_path, &manifest_path] {
        assert!(p.is_file(), "expected file at {p:?}");
        let n = fs::metadata(p).unwrap().len();
        assert!(n > 0, "{p:?} must be non-empty (got {n} bytes)");
    }
    assert!(contacts_dir.is_dir(), "contacts/ subdir missing");
    let card_path = find_owner_card(dir.path());
    assert!(card_path.is_file(), "owner card missing");
    assert!(fs::metadata(&card_path).unwrap().len() > 0);
}

// ---------------------------------------------------------------------------
// 2. All four files round-trip through the existing decoders
// ---------------------------------------------------------------------------

#[test]
fn create_vault_files_parse() {
    let (dir, _) = make_fast_vault(8, b"hunter2", "Alice");

    let vt_bytes = fs::read(dir.path().join("vault.toml")).unwrap();
    let bundle_bytes = fs::read(dir.path().join("identity.bundle.enc")).unwrap();
    let manifest_bytes = fs::read(dir.path().join("manifest.cbor.enc")).unwrap();
    let card_bytes = fs::read(find_owner_card(dir.path())).unwrap();

    let vt = vault_toml::decode(std::str::from_utf8(&vt_bytes).unwrap())
        .expect("vault.toml decodes");
    let bf = bundle_file::decode(&bundle_bytes).expect("identity.bundle.enc decodes");
    let mf = decode_manifest_file(&manifest_bytes).expect("manifest.cbor.enc decodes");
    let card = ContactCard::from_canonical_cbor(&card_bytes).expect("contact card decodes");

    // Cross-checks that tie the four files into one coherent vault.
    assert_eq!(bf.vault_uuid, vt.vault_uuid);
    assert_eq!(bf.created_at_ms, vt.created_at_ms);
    assert_eq!(mf.header.vault_uuid, vt.vault_uuid);
    assert_eq!(card.contact_uuid.len(), 16);
    assert_eq!(card.display_name, "Alice");
    // The card must self-verify (signature was minted on the way out).
    card.verify_self().expect("card self-signature verifies");
}

// ---------------------------------------------------------------------------
// 3. Manifest signature verifies under the owner card's keys
// ---------------------------------------------------------------------------

#[test]
fn create_vault_manifest_signature_verifies() {
    let (dir, _) = make_fast_vault(9, b"hunter2", "Alice");

    let manifest_bytes = fs::read(dir.path().join("manifest.cbor.enc")).unwrap();
    let mf = decode_manifest_file(&manifest_bytes).expect("decode");

    let card_bytes = fs::read(find_owner_card(dir.path())).unwrap();
    let card = ContactCard::from_canonical_cbor(&card_bytes).expect("decode card");

    let pq_pk = MlDsa65Public::from_bytes(&card.ml_dsa_65_pk).expect("pq pk");
    verify_manifest(&mf, &card.ed25519_pk, &pq_pk)
        .expect("manifest hybrid signature verifies under owner card keys");

    // Sanity: the manifest's author_fingerprint matches the card's
    // computed fingerprint. Without this check the verify above could
    // technically pass against an unrelated card whose keys happened
    // to match.
    let expected_fp = fingerprint::fingerprint(&card_bytes);
    assert_eq!(mf.author_fingerprint, expected_fp);
}

// ---------------------------------------------------------------------------
// 4. Manifest body decrypts under the password-derived IBK and yields
//    an empty Manifest with the right invariants.
// ---------------------------------------------------------------------------

#[test]
fn create_vault_manifest_decrypts() {
    let pw = b"hunter2";
    let (dir, _) = make_fast_vault(10, pw, "Alice");

    let vt_bytes = fs::read(dir.path().join("vault.toml")).unwrap();
    let bundle_bytes = fs::read(dir.path().join("identity.bundle.enc")).unwrap();
    let manifest_bytes = fs::read(dir.path().join("manifest.cbor.enc")).unwrap();

    // Re-derive the IBK via the password unlock path. open_with_password
    // is the "task 10 substitute" for the not-yet-existing open_vault
    // orchestrator (Task 11) — see the task brief.
    let opened = open_with_password(&vt_bytes, &bundle_bytes, &SecretBytes::new(pw.to_vec()))
        .expect("password unlock");
    let mf = decode_manifest_file(&manifest_bytes).expect("decode");

    // Reassemble ct_with_tag from the split aead_ct + aead_tag fields
    // — that's the wire shape decrypt_manifest_body expects.
    let mut ct_with_tag = Vec::with_capacity(mf.aead_ct.len() + AEAD_TAG_LEN);
    ct_with_tag.extend_from_slice(&mf.aead_ct);
    ct_with_tag.extend_from_slice(&mf.aead_tag);

    let m = decrypt_manifest_body(
        &mf.header,
        &ct_with_tag,
        &opened.identity_block_key,
        &mf.aead_nonce,
    )
    .expect("manifest body decrypts");

    assert_eq!(m.manifest_version, 1);
    assert_eq!(m.owner_user_uuid, opened.identity.user_uuid);
    assert!(m.vector_clock.is_empty(), "fresh vault has empty vector_clock");
    assert!(m.blocks.is_empty(), "fresh vault has no blocks");
    assert!(m.trash.is_empty(), "fresh vault has empty trash");
    assert!(m.unknown.is_empty(), "no forward-compat unknowns yet");
}

// ---------------------------------------------------------------------------
// 5. Reject non-empty target directory
// ---------------------------------------------------------------------------

#[test]
fn create_vault_rejects_nonempty_directory() {
    // The public create_vault path is exercised here (instead of the
    // fast helper) because folder validation runs before any KDF
    // work and is not affected by Argon2id parameters. We use the v1
    // floor to avoid the `WeakKdfParams` precondition kicking in
    // ahead of the folder check.
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("clutter.txt"), b"hi").unwrap();

    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
    let err = create_vault(
        dir.path(),
        &SecretBytes::new(b"pw".to_vec()),
        "Alice",
        // Sub-floor params would error before the folder check runs;
        // the v1 default is the path under test here.
        Argon2idParams::V1_DEFAULT,
        1_714_060_800_000,
        &mut rng,
    )
    .expect_err("non-empty folder must be rejected");

    assert!(
        matches!(err, VaultError::Io { context, .. } if context.contains("not empty")),
        "expected VaultError::Io 'not empty', got {err:?}"
    );

    // Confirm the orchestrator did not create any of its own files
    // alongside the clutter (atomic-failure guarantee — fail before
    // touching disk).
    let leftovers: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(leftovers, vec!["clutter.txt".to_string()]);
}

// ---------------------------------------------------------------------------
// 6. Reject missing target directory
// ---------------------------------------------------------------------------

#[test]
fn create_vault_rejects_missing_directory() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("does-not-exist");

    let mut rng = ChaCha20Rng::from_seed([2u8; 32]);
    let err = create_vault(
        &missing,
        &SecretBytes::new(b"pw".to_vec()),
        "Alice",
        Argon2idParams::V1_DEFAULT,
        1_714_060_800_000,
        &mut rng,
    )
    .expect_err("missing folder must be rejected");

    assert!(
        matches!(err, VaultError::Io { .. }),
        "expected VaultError::Io, got {err:?}"
    );
    // Belt-and-braces: the missing path was not silently created.
    assert!(!missing.exists());
}

// ---------------------------------------------------------------------------
// 7. (Bonus) The public `create_vault` rejects sub-floor KDF params.
// ---------------------------------------------------------------------------
//
// This is not in the task list as a numbered case, but it is the
// only way to confirm the orchestrator routes weak params through
// `unlock::create_vault` (the v1-floor entry) rather than the
// unchecked variant. Cheap and high-signal.

#[test]
fn create_vault_rejects_sub_floor_kdf() {
    let dir = tempfile::tempdir().unwrap();
    let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
    let err = create_vault(
        dir.path(),
        &SecretBytes::new(b"pw".to_vec()),
        "Alice",
        fast_kdf(), // 8 KiB — well below the 64 MiB v1 floor
        1_714_060_800_000,
        &mut rng,
    )
    .expect_err("sub-floor params must be rejected");

    assert!(
        matches!(
            err,
            VaultError::Unlock(unlock::UnlockError::WeakKdfParams { .. })
        ),
        "expected Unlock(WeakKdfParams), got {err:?}"
    );
    // The folder should still be empty — KDF rejection happens before
    // any I/O.
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}
