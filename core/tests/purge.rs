//! Integration tests for the #399 purge/empty-trash slice — Task 2:
//! `VaultError::BlockPurged` and the `restore_block` fail-fast guard.
//!
//! A `TrashEntry.purged_at_ms.is_some()` means the block's ciphertext was
//! permanently removed (purge_block, Task 3 — not implemented yet). This
//! test isolates JUST the `restore_block` guard by hand-setting the
//! manifest marker on a normally-trashed block, without needing
//! `purge_block` to exist.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;

use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use rand_core::RngCore;

use secretary_core::crypto::kdf::Argon2idParams;
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::crypto::sig::{MlDsa65Secret, ED25519_SIG_LEN, ML_DSA_65_SIG_LEN};
use secretary_core::identity::card::{ContactCard, CARD_VERSION_V1};
use secretary_core::identity::fingerprint::fingerprint;
use secretary_core::unlock::{create_vault_unchecked, mnemonic::Mnemonic, vault_toml};
use secretary_core::vault::{
    encode_manifest_file, open_vault, restore_block, save_block, sign_manifest, trash_block,
    BlockPlaintext, KdfParamsRef, Manifest, ManifestHeader, OpenVault, Unlocker, VaultError,
};
use secretary_core::version::{FORMAT_VERSION, SUITE_ID};

// ---------------------------------------------------------------------------
// Fixture helpers — mirrors core/tests/trash_restore.rs::make_fast_vault
// (that file notes it duplicates from save_block.rs; no shared
// test-helper crate exists yet, so we duplicate again here).
// ---------------------------------------------------------------------------

fn fast_kdf() -> Argon2idParams {
    Argon2idParams::new(8, 1, 1)
}

fn make_fast_vault(seed: u8, display_name: &str) -> (tempfile::TempDir, Mnemonic, SecretBytes) {
    let dir = tempfile::tempdir().unwrap();
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    // Derive the vault password from the seeded RNG rather than a
    // hard-coded literal: keeps the fixture deterministic per `seed`
    // while avoiding CodeQL's "hard-coded value used as a password"
    // (rust/hard-coded-cryptographic-value) — see
    // feedback_test_crypto_random_not_hardcoded.
    let mut pw_bytes = [0u8; 16];
    rng.fill_bytes(&mut pw_bytes);
    let pw = SecretBytes::new(pw_bytes.to_vec());
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
    let author_fp = fingerprint(&owner_card_bytes);

    let manifest_body = Manifest {
        manifest_version: 1,
        vault_uuid: vt.vault_uuid,
        format_version: FORMAT_VERSION,
        suite_id: SUITE_ID,
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
        &manifest_body,
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

fn make_simple_plaintext(block_uuid: [u8; 16], block_name: &str) -> BlockPlaintext {
    BlockPlaintext {
        block_version: 1,
        block_uuid,
        block_name: block_name.to_string(),
        schema_version: 1,
        records: Vec::new(),
        unknown: BTreeMap::new(),
    }
}

/// Build a fresh fast vault, unlock it, save one block, and trash it.
/// Returns everything the caller needs to isolate the `restore_block`
/// purge-guard: the vault's temp dir (kept alive), the open vault, the
/// device uuid used to trash it, an RNG positioned to continue the
/// scenario, and the trashed block's own uuid (returned explicitly so
/// callers never need a placeholder).
fn setup_vault_with_trashed_block() -> (
    tempfile::TempDir,
    OpenVault,
    [u8; 16],
    ChaCha20Rng,
    [u8; 16],
) {
    let (dir, _mnemonic, pw) = make_fast_vault(50, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0xf1; 32]);

    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let device_uuid = [0xf2; 16];
    let block_uuid = [0xf3; 16];
    let plaintext = make_simple_plaintext(block_uuid, "to-be-purged");
    let recipients = vec![open.owner_card.clone()];
    save_block(
        folder,
        &mut open,
        plaintext,
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();
    trash_block(folder, &mut open, block_uuid, device_uuid, 2_000, &mut rng).unwrap();

    (dir, open, device_uuid, rng, block_uuid)
}

// ---------------------------------------------------------------------------
// restore_block — rejection: BlockPurged
// ---------------------------------------------------------------------------

/// `restore_block` must fail fast with `VaultError::BlockPurged` when the
/// matched `TrashEntry.purged_at_ms` is `Some(_)` — the ciphertext was
/// permanently removed and cannot be restored. The guard must fire before
/// any trash-file scan result is used to select a restore source.
#[test]
fn restore_of_purged_block_returns_block_purged() {
    let (dir, mut open, device, mut rng, uuid) = setup_vault_with_trashed_block();
    let folder = dir.path();

    let idx = open
        .manifest
        .trash
        .iter()
        .position(|t| t.block_uuid == uuid)
        .unwrap();
    open.manifest.trash[idx].purged_at_ms = Some(42);

    let err = restore_block(folder, &mut open, uuid, device, 1000, &mut rng).unwrap_err();
    assert!(
        matches!(err, VaultError::BlockPurged { block_uuid } if block_uuid == uuid),
        "expected BlockPurged for the purged block, got {err:?}"
    );

    // Manifest must be untouched by the rejected restore: the TrashEntry
    // (still marked purged) survives, and no BlockEntry was added.
    assert!(
        open.manifest
            .trash
            .iter()
            .any(|t| t.block_uuid == uuid && t.purged_at_ms == Some(42)),
        "TrashEntry must persist unmodified after a rejected restore"
    );
    assert!(
        !open.manifest.blocks.iter().any(|b| b.block_uuid == uuid),
        "BlockEntry must not be added after a rejected restore"
    );
}
