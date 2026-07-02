//! Integration tests for `secretary_core::vault::repair` — #350
//! crash-recovery coverage. `open_vault`'s best-effort trash-completion
//! sweep (`complete_pending_trash_renames`) resumes a `trash_block` call
//! that crashed between its manifest commit (signed `TrashEntry`
//! appended) and its physical file rename: the block file is still
//! sitting in `blocks/<uuid>.cbor.enc` even though the manifest already
//! says it is trashed. The sweep is gated on the signed
//! `TrashEntry.fingerprint` content commitment (#293) so an attacker
//! with write access to `blocks/` cannot steer it, and it never touches
//! a UUID that is live again in `manifest.blocks`.
//!
//! Fixture helpers below are copied verbatim from `trash_restore.rs`
//! per this repo's no-shared-test-crate convention.

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
    BlockPlaintext, KdfParamsRef, Manifest, ManifestHeader, Unlocker,
};
use secretary_core::version::{FORMAT_VERSION, SUITE_ID};

// ---------------------------------------------------------------------------
// Fixture helpers (mirror save_block.rs / share_block.rs / trash_restore.rs)
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

// ---------------------------------------------------------------------------
// #350 crash-recovery residue builder
// ---------------------------------------------------------------------------

/// Build the manifest-first #350 trash-crash residue: a normally
/// trashed block whose physical file is moved back into `blocks/`
/// (equivalent to a crash before trash_block's best-effort rename).
/// Returns the trash-path the sweep is expected to produce.
fn make_trash_residue(
    folder: &std::path::Path,
    open: &mut secretary_core::vault::OpenVault,
    block_uuid: [u8; 16],
    device_uuid: [u8; 16],
    trash_ms: u64,
    rng: &mut ChaCha20Rng,
) -> (std::path::PathBuf, std::path::PathBuf) {
    trash_block(folder, open, block_uuid, device_uuid, trash_ms, rng).unwrap();
    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    let trash_path = folder
        .join("trash")
        .join(format!("{uuid_hex}.cbor.enc.{trash_ms}"));
    let blocks_path = folder.join("blocks").join(format!("{uuid_hex}.cbor.enc"));
    fs::rename(&trash_path, &blocks_path).expect("simulate crash: undo the rename");
    (blocks_path, trash_path)
}

/// #350: open_vault's best-effort sweep completes an interrupted trash
/// rename — gated on the signed TrashEntry.fingerprint.
#[test]
fn open_vault_sweep_relocates_interrupted_trash() {
    let (dir, _mnemonic, pw) = make_fast_vault(51, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x51; 32]);
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let (device_uuid, block_uuid) = ([0xd6; 16], [0xb6; 16]);
    let plaintext = make_simple_plaintext(block_uuid, "sweep-me");
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
    let (blocks_path, trash_path) =
        make_trash_residue(folder, &mut open, block_uuid, device_uuid, 2_000, &mut rng);
    drop(open);

    let reopened = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    assert!(
        trash_path.is_file(),
        "sweep must relocate the orphan to its §7 trash path"
    );
    assert!(!blocks_path.exists(), "orphan must be gone from blocks/");
    // Restore still works after the sweep (normal trash-file path now).
    drop(reopened);
    let mut open2 = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    restore_block(folder, &mut open2, block_uuid, device_uuid, 3_000, &mut rng).unwrap();
}

/// #350 sweep negative gate: orphan bytes not matching the signed
/// TrashEntry.fingerprint are NOT moved (attacker-planted file).
#[test]
fn sweep_skips_orphan_with_wrong_fingerprint() {
    let (dir, _mnemonic, pw) = make_fast_vault(52, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x52; 32]);
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let (device_uuid, block_uuid) = ([0xd7; 16], [0xb7; 16]);
    let plaintext = make_simple_plaintext(block_uuid, "tamper");
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
    let (blocks_path, trash_path) =
        make_trash_residue(folder, &mut open, block_uuid, device_uuid, 2_000, &mut rng);
    // Overwrite the orphan with junk of a different hash.
    fs::write(&blocks_path, b"not the committed bytes").unwrap();
    drop(open);

    let _reopened = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    assert!(blocks_path.is_file(), "junk orphan must not be moved");
    assert!(
        !trash_path.exists(),
        "no trash file may be minted from junk"
    );
}

/// #350 sweep negative gate: a TrashEntry whose UUID is live again
/// (trash → re-save same uuid) must not steal the live file, even if
/// an attacker crafts fingerprint agreement. We simulate by re-saving
/// the same uuid after a residue: live entry exists, so the sweep must
/// skip regardless of the orphan/live file's hash.
#[test]
fn sweep_skips_live_uuid() {
    let (dir, _mnemonic, pw) = make_fast_vault(53, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x53; 32]);
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let (device_uuid, block_uuid) = ([0xd8; 16], [0xb8; 16]);
    let plaintext = make_simple_plaintext(block_uuid, "gen-1");
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
    let (blocks_path, trash_path) =
        make_trash_residue(folder, &mut open, block_uuid, device_uuid, 2_000, &mut rng);
    // Re-save the same uuid: clobbers the orphan with new live content;
    // manifest now has BOTH a live entry and the TrashEntry.
    let plaintext2 = make_simple_plaintext(block_uuid, "gen-2");
    save_block(
        folder,
        &mut open,
        plaintext2,
        &recipients,
        device_uuid,
        3_000,
        &mut rng,
    )
    .unwrap();
    drop(open);

    let reopened = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    assert!(blocks_path.is_file(), "live file must stay in blocks/");
    assert!(!trash_path.exists(), "sweep must not touch a live uuid");
    assert!(reopened
        .manifest
        .blocks
        .iter()
        .any(|b| b.block_uuid == block_uuid));
}

/// #350 sweep negative gate: legacy TrashEntry { fingerprint: None }
/// (pre-#293) gives the sweep no content commitment — skip.
#[test]
fn sweep_skips_legacy_entry_without_fingerprint() {
    let (dir, _mnemonic, pw) = make_fast_vault(54, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x54; 32]);
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let (device_uuid, block_uuid) = ([0xd9; 16], [0xb9; 16]);
    let plaintext = make_simple_plaintext(block_uuid, "legacy");
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
    let (blocks_path, trash_path) =
        make_trash_residue(folder, &mut open, block_uuid, device_uuid, 2_000, &mut rng);

    // Strip the fingerprint from the TrashEntry and re-sign the manifest
    // (tests hold the owner identity, so this is a legitimate re-sign).
    let mut manifest = open.manifest.clone();
    for t in &mut manifest.trash {
        t.fingerprint = None;
    }
    let header = ManifestHeader {
        vault_uuid: open.manifest_file.header.vault_uuid,
        created_at_ms: open.manifest_file.header.created_at_ms,
        last_mod_ms: 2_500,
    };
    let pq_sk = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).unwrap();
    let mut nonce = [0u8; 24];
    rng.fill_bytes(&mut nonce);
    let mf = sign_manifest(
        header,
        &manifest,
        &open.identity_block_key,
        &nonce,
        open.manifest_file.author_fingerprint,
        &open.identity.ed25519_sk,
        &pq_sk,
    )
    .unwrap();
    fs::write(
        folder.join("manifest.cbor.enc"),
        encode_manifest_file(&mf).unwrap(),
    )
    .unwrap();
    drop(open);

    let _reopened = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    assert!(
        blocks_path.is_file(),
        "legacy entry: orphan must not be moved"
    );
    assert!(!trash_path.exists());
}
