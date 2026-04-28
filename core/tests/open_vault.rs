//! Integration tests for `secretary_core::vault::open_vault` —
//! Task 11 of PR-B. Each test creates a vault first via the
//! Task 10 fast-KDF helper (replicated locally to keep the
//! integration tests self-contained), then exercises the full
//! `open_vault` orchestrator: read on-disk metadata → unlock →
//! verify-then-decrypt manifest → optional §10 rollback check.
//!
//! The fast-KDF helper bypasses the v1 Argon2id floor enforced by
//! the public `create_vault` entry point, so the round-trip cost
//! is dominated by ML-DSA-65 sign/verify (a few ms) rather than
//! Argon2id (seconds at the v1 floor). All tests are deterministic
//! by construction: a seeded `ChaCha20Rng` drives the orchestrator,
//! the password / mnemonic are fixed, and the on-disk byte shape
//! matches the production `create_vault`.

#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;

use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

use secretary_core::crypto::kdf::Argon2idParams;
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::crypto::sig::{MlDsa65Secret, ED25519_SIG_LEN, ML_DSA_65_SIG_LEN};
use secretary_core::identity::card::{ContactCard, CARD_VERSION_V1};
use secretary_core::identity::fingerprint;
use secretary_core::unlock::{
    self, create_vault_unchecked, mnemonic::Mnemonic, vault_toml,
};
use secretary_core::vault::{
    encode_manifest_file, open_vault, sign_manifest, KdfParamsRef, Manifest, ManifestError,
    ManifestHeader, OpenVault, Unlocker, VaultError, VectorClockEntry,
};

// ---------------------------------------------------------------------------
// Fixture helpers (mirror `create_vault.rs::make_fast_vault`)
// ---------------------------------------------------------------------------

/// v1-floor-bypassing Argon2id parameters. The orchestrators in the
/// production path enforce the v1 floor; tests use the unchecked
/// `unlock::create_vault_unchecked` substitute through `make_fast_vault`
/// so the round-trip stays in milliseconds.
fn fast_kdf() -> Argon2idParams {
    Argon2idParams::new(8, 1, 1)
}

/// Lay out a complete four-file vault on disk in a fresh tempdir,
/// using the fast-KDF unchecked unlock path. Replicates `create_vault`
/// exactly except for the KDF strength check — the on-disk byte shape
/// matches the production output.
///
/// Returns the dir handle (kept alive so the directory is not dropped
/// while the test runs), the recovery mnemonic (the only path back to
/// the IBK if the password is lost), and the password used. Tests
/// derive everything else they need from the on-disk files plus the
/// returned credentials.
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
        create_vault_unchecked(&pw, display_name, created_at_ms, fast_kdf(), &mut rng)
            .expect("unlock::create_vault_unchecked");

    // Re-parse vault.toml to recover vault_uuid + salt.
    let vt = vault_toml::decode(std::str::from_utf8(&created.vault_toml_bytes).unwrap()).unwrap();

    // Owner card (self-signed).
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

    // Empty manifest body.
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
    fs::write(
        contacts_dir.join(format!("{owner_uuid_hex}.card")),
        &owner_card_bytes,
    )
    .unwrap();
    fs::write(dir.path().join("manifest.cbor.enc"), &mf_bytes).unwrap();

    (dir, created.recovery_mnemonic, pw)
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

/// Read the user_uuid out of the unlocked identity bundle without
/// replaying an open. Tests that assert "the round-trip preserved the
/// owner UUID" use this against a fresh password unlock done outside
/// `open_vault` so the assertion is independent of the orchestrator
/// under test.
fn read_owner_uuid_via_password(folder: &Path, password: &SecretBytes) -> [u8; 16] {
    let vt_bytes = fs::read(folder.join("vault.toml")).unwrap();
    let bundle_bytes = fs::read(folder.join("identity.bundle.enc")).unwrap();
    let opened = unlock::open_with_password(&vt_bytes, &bundle_bytes, password).unwrap();
    opened.identity.user_uuid
}

// ---------------------------------------------------------------------------
// 1. Round-trip via password unlocker
// ---------------------------------------------------------------------------

#[test]
fn open_vault_password_round_trip() {
    let (dir, _mnemonic, pw) = make_fast_vault(1, b"hunter2", "Alice");

    let expected_owner_uuid = read_owner_uuid_via_password(dir.path(), &pw);

    let opened: OpenVault =
        open_vault(dir.path(), Unlocker::Password(&pw), None).expect("open_vault");

    assert_eq!(opened.identity.user_uuid, expected_owner_uuid);
    assert_eq!(opened.owner_card.contact_uuid, expected_owner_uuid);
    assert_eq!(opened.manifest.owner_user_uuid, expected_owner_uuid);
    assert_eq!(opened.manifest.manifest_version, 1);
    assert!(
        opened.manifest.blocks.is_empty(),
        "fresh vault has no blocks"
    );
    assert!(
        opened.manifest.trash.is_empty(),
        "fresh vault has empty trash"
    );
    assert!(
        opened.manifest.vector_clock.is_empty(),
        "fresh vault has empty vector_clock"
    );
    assert!(
        opened.manifest.unknown.is_empty(),
        "no forward-compat unknowns yet"
    );

    // The IBK returned by open_vault must equal the one a separate
    // unlock pass produces — invariant of the orchestrator.
    let vt_bytes = fs::read(dir.path().join("vault.toml")).unwrap();
    let bundle_bytes = fs::read(dir.path().join("identity.bundle.enc")).unwrap();
    let direct = unlock::open_with_password(&vt_bytes, &bundle_bytes, &pw).unwrap();
    assert_eq!(
        opened.identity_block_key.expose(),
        direct.identity_block_key.expose(),
        "IBK from open_vault must match the IBK from a direct unlock"
    );
}

// ---------------------------------------------------------------------------
// 2. Round-trip via recovery-mnemonic unlocker
// ---------------------------------------------------------------------------

#[test]
fn open_vault_recovery_round_trip() {
    let (dir, mnemonic, pw) = make_fast_vault(2, b"hunter2", "Alice");

    let expected_owner_uuid = read_owner_uuid_via_password(dir.path(), &pw);
    let phrase = mnemonic.phrase().to_string();

    let opened = open_vault(dir.path(), Unlocker::Recovery(&phrase), None).expect("open_vault");

    assert_eq!(opened.identity.user_uuid, expected_owner_uuid);
    assert_eq!(opened.owner_card.contact_uuid, expected_owner_uuid);
    assert_eq!(opened.manifest.owner_user_uuid, expected_owner_uuid);
    assert!(opened.manifest.blocks.is_empty());
    assert!(opened.manifest.trash.is_empty());

    // The IBK derived via the recovery path must equal the IBK derived
    // via the password path — both unlock paths recover the same key.
    let vt_bytes = fs::read(dir.path().join("vault.toml")).unwrap();
    let bundle_bytes = fs::read(dir.path().join("identity.bundle.enc")).unwrap();
    let direct = unlock::open_with_password(&vt_bytes, &bundle_bytes, &pw).unwrap();
    assert_eq!(
        opened.identity_block_key.expose(),
        direct.identity_block_key.expose(),
    );
}

// ---------------------------------------------------------------------------
// 3. Wrong password is rejected with the wrapped unlock error
// ---------------------------------------------------------------------------

#[test]
fn open_vault_wrong_password_rejected() {
    let (dir, _mnemonic, _pw) = make_fast_vault(3, b"hunter2", "Alice");

    let bad = SecretBytes::new(b"definitely-not-the-password".to_vec());
    let err = open_vault(dir.path(), Unlocker::Password(&bad), None)
        .expect_err("wrong password must reject");

    assert!(
        matches!(
            err,
            VaultError::Unlock(unlock::UnlockError::WrongPasswordOrCorrupt)
        ),
        "expected Unlock(WrongPasswordOrCorrupt), got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 4. Wrong recovery mnemonic is rejected with the wrapped unlock error
// ---------------------------------------------------------------------------

#[test]
fn open_vault_wrong_recovery_words_rejected() {
    let (dir, _mnemonic, _pw) = make_fast_vault(4, b"hunter2", "Alice");

    // A valid-checksum mnemonic that does not belong to this vault.
    let mut other_rng = ChaCha20Rng::from_seed([99u8; 32]);
    let other = unlock::mnemonic::generate(&mut other_rng);
    let phrase = other.phrase().to_string();

    let err = open_vault(dir.path(), Unlocker::Recovery(&phrase), None)
        .expect_err("wrong mnemonic must reject");

    assert!(
        matches!(
            err,
            VaultError::Unlock(unlock::UnlockError::WrongMnemonicOrCorrupt)
        ),
        "expected Unlock(WrongMnemonicOrCorrupt), got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 5. Tampered manifest signature suffix → manifest signature failure
// ---------------------------------------------------------------------------

#[test]
fn open_vault_tampered_manifest_signature_rejected() {
    let (dir, _mnemonic, pw) = make_fast_vault(5, b"hunter2", "Alice");

    let manifest_path = dir.path().join("manifest.cbor.enc");
    let mut bytes = fs::read(&manifest_path).unwrap();
    // Flip the last byte — that lives inside the §4.1 sig_pq tail.
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    fs::write(&manifest_path, &bytes).unwrap();

    let err = open_vault(dir.path(), Unlocker::Password(&pw), None)
        .expect_err("tampered signature must reject");

    // Either Ed25519 or ML-DSA-65 half can surface depending on which
    // byte was flipped; both are valid outcomes for "verify-before-
    // decrypt rejected the envelope".
    assert!(
        matches!(
            err,
            VaultError::Manifest(ManifestError::Ed25519SignatureInvalid)
                | VaultError::Manifest(ManifestError::MlDsa65SignatureInvalid)
        ),
        "expected manifest signature failure, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 6. Tampered AEAD ciphertext → manifest signature failure
//    (the signature covers magic..aead_tag, so a flipped ct byte
//    breaks the signature first — verify-before-decrypt discipline.)
// ---------------------------------------------------------------------------

#[test]
fn open_vault_tampered_aead_rejected() {
    let (dir, _mnemonic, pw) = make_fast_vault(6, b"hunter2", "Alice");

    // Decode the on-disk envelope to find the absolute byte offset of
    // the first ciphertext byte. §4.1 layout up to and including
    // aead_ct_len: header(42) + aead_nonce(24) + aead_ct_len(4) = 70.
    // Flip the byte at offset 70 — that is the first byte of aead_ct.
    let manifest_path = dir.path().join("manifest.cbor.enc");
    let mut bytes = fs::read(&manifest_path).unwrap();
    bytes[70] ^= 0x01;
    fs::write(&manifest_path, &bytes).unwrap();

    let err = open_vault(dir.path(), Unlocker::Password(&pw), None)
        .expect_err("tampered ciphertext must reject");

    // The signature covers magic..aead_tag inclusive, so a tampered
    // aead_ct byte breaks the signature *before* AEAD ever sees the
    // body — that's the verify-before-decrypt invariant. Either half
    // can fire depending on which signature subsystem hits its
    // mismatch first; both are correct outcomes.
    assert!(
        matches!(
            err,
            VaultError::Manifest(ManifestError::Ed25519SignatureInvalid)
                | VaultError::Manifest(ManifestError::MlDsa65SignatureInvalid)
        ),
        "expected manifest signature failure, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 7. Missing manifest.cbor.enc → VaultError::Io
// ---------------------------------------------------------------------------

#[test]
fn open_vault_missing_manifest_file_rejected() {
    let (dir, _mnemonic, pw) = make_fast_vault(7, b"hunter2", "Alice");

    fs::remove_file(dir.path().join("manifest.cbor.enc")).unwrap();

    let err = open_vault(dir.path(), Unlocker::Password(&pw), None)
        .expect_err("missing manifest must reject");

    assert!(
        matches!(err, VaultError::Io { context, .. } if context.contains("manifest.cbor.enc")),
        "expected Io for missing manifest, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 8. Rollback rejection — local clock dominates the (empty) incoming clock.
// ---------------------------------------------------------------------------

#[test]
fn open_vault_rollback_rejected() {
    let (dir, _mnemonic, pw) = make_fast_vault(8, b"hunter2", "Alice");

    // The fresh manifest has an empty vector_clock. Any local clock
    // with a positive counter strictly dominates the empty incoming
    // clock per §10's `is_rollback`.
    let local: Vec<VectorClockEntry> = vec![VectorClockEntry {
        device_uuid: [0xab; 16],
        counter: 1,
    }];

    let err = open_vault(dir.path(), Unlocker::Password(&pw), Some(&local))
        .expect_err("local-dominates-incoming must trigger rollback");

    match err {
        VaultError::Rollback {
            local_clock,
            incoming_clock,
        } => {
            assert_eq!(local_clock, local);
            assert!(
                incoming_clock.is_empty(),
                "fresh vault's incoming_clock must be empty, got {incoming_clock:?}"
            );
        }
        other => panic!("expected VaultError::Rollback, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 9. Rollback skipped when local_highest_clock is None.
// ---------------------------------------------------------------------------

#[test]
fn open_vault_rollback_skipped_when_local_clock_none() {
    let (dir, _mnemonic, pw) = make_fast_vault(9, b"hunter2", "Alice");

    // Same fresh vault as the rollback test, but with `None` for the
    // local highest-seen clock. The orchestrator must not run the
    // rollback check, so the open succeeds.
    let opened = open_vault(dir.path(), Unlocker::Password(&pw), None)
        .expect("open succeeds when local_highest_clock is None");
    assert!(opened.manifest.vector_clock.is_empty());
}
