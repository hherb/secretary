//! Integration tests for the #399 purge/empty-trash slice.
//!
//! Task 2 landed `VaultError::BlockPurged` + the `restore_block` fail-fast
//! guard, tested below by hand-setting the manifest marker on a normally-
//! trashed block (isolates the guard without needing `purge_block`).
//!
//! Task 3 (this file's remaining tests) exercises `purge_block` itself:
//! the owner-only happy path, the shared-block classification, the
//! `BlockNotInTrash` rejection for an unknown uuid, and idempotent
//! re-purge (no second manifest re-sign).

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
    empty_trash, encode_manifest_file, open_vault, purge_block, restore_block, save_block,
    sign_manifest, trash_block, BlockPlaintext, KdfParamsRef, Manifest, ManifestHeader, OpenVault,
    Unlocker, VaultError,
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

// ---------------------------------------------------------------------------
// purge_block — Task 3
// ---------------------------------------------------------------------------

/// Mint a fully independent, self-signed `ContactCard` for use as an
/// *additional* `save_block` recipient (never opens or writes a vault of
/// its own — only the card is needed). Uses a distinct RNG seed from the
/// owner's (see `feedback_test_crypto_random_not_hardcoded`: derive, don't
/// hard-code) so the two identities' keys are independent.
fn mint_external_card(seed: u8, display_name: &str) -> ContactCard {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let mut pw_bytes = [0u8; 16];
    rng.fill_bytes(&mut pw_bytes);
    let pw = SecretBytes::new(pw_bytes.to_vec());
    let created_at_ms = 1_714_060_800_000u64;
    let created =
        create_vault_unchecked(&pw, display_name, created_at_ms, fast_kdf(), &mut rng).unwrap();
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
    card
}

/// Same shape as `setup_vault_with_trashed_block`, but the trashed block
/// was saved with a second (external) recipient, so `purge_block`'s
/// classification is exercised on a genuinely shared block.
fn setup_vault_with_trashed_shared_block() -> (
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
    let plaintext = make_simple_plaintext(block_uuid, "to-be-purged-shared");
    let other_card = mint_external_card(77, "Other");
    let recipients = vec![open.owner_card.clone(), other_card];
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

/// List every `trash/<uuid_hex>.cbor.enc.*` file currently on disk for
/// `block_uuid`.
fn trash_files_for(folder: &std::path::Path, block_uuid: &[u8; 16]) -> Vec<std::path::PathBuf> {
    let trash_dir = folder.join("trash");
    let uuid_hex = format_uuid_hyphenated(block_uuid);
    let prefix = format!("{uuid_hex}.cbor.enc.");
    let Ok(rd) = fs::read_dir(&trash_dir) else {
        return Vec::new();
    };
    rd.flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|s| s.to_str())
                .map(|n| n.starts_with(&prefix))
                .unwrap_or(false)
        })
        .collect()
}

/// Owner-only happy path: `purge_block` marks the `TrashEntry` purged,
/// reports `was_shared == Some(false)` / `recipient_count == Some(1)`,
/// and removes the on-disk trash file. The block must stay absent from
/// `manifest.blocks` (it was never resurrected).
#[test]
fn purge_owner_only_block_reports_not_shared_and_removes_file() {
    let (dir, mut open, device, mut rng, uuid) = setup_vault_with_trashed_block();
    let folder = dir.path();

    assert!(
        !trash_files_for(folder, &uuid).is_empty(),
        "fixture sanity: a trash file must exist before purge"
    );

    let report = purge_block(folder, &mut open, uuid, device, 5_000, &mut rng).unwrap();

    assert_eq!(report.block_uuid, uuid);
    assert_eq!(report.was_shared, Some(false));
    assert_eq!(report.recipient_count, Some(1));
    assert!(report.files_removed >= 1);

    let idx = open
        .manifest
        .trash
        .iter()
        .position(|t| t.block_uuid == uuid)
        .unwrap();
    assert!(open.manifest.trash[idx].purged_at_ms.is_some());
    assert!(!open.manifest.blocks.iter().any(|b| b.block_uuid == uuid));
    assert!(
        trash_files_for(folder, &uuid).is_empty(),
        "purge must remove every trash/ file for the purged uuid"
    );
}

/// Shared-block variant: two recipients on the block at trash time ⇒
/// `was_shared == Some(true)` and `recipient_count == Some(2)`.
#[test]
fn purge_shared_block_reports_shared_and_count() {
    let (dir, mut open, device, mut rng, uuid) = setup_vault_with_trashed_shared_block();
    let folder = dir.path();

    let report = purge_block(folder, &mut open, uuid, device, 5_000, &mut rng).unwrap();

    assert_eq!(report.was_shared, Some(true));
    assert_eq!(report.recipient_count, Some(2));
    assert!(report.files_removed >= 1);
    assert!(trash_files_for(folder, &uuid).is_empty());
}

/// An unknown `block_uuid` (never trashed) must surface `BlockNotInTrash`
/// without mutating the manifest.
#[test]
fn purge_unknown_uuid_is_block_not_in_trash() {
    let (dir, mut open, device, mut rng, _uuid) = setup_vault_with_trashed_block();
    let folder = dir.path();
    let trash_len_before = open.manifest.trash.len();

    let err = purge_block(folder, &mut open, [0x99; 16], device, 5_000, &mut rng).unwrap_err();

    assert!(
        matches!(err, VaultError::BlockNotInTrash { block_uuid } if block_uuid == [0x99; 16]),
        "expected BlockNotInTrash, got {err:?}"
    );
    assert_eq!(open.manifest.trash.len(), trash_len_before);
}

/// Re-purging an already-purged block must be a no-op with respect to the
/// signed manifest: the second call must NOT re-sign / re-write
/// `manifest.cbor.enc`. Proven by cloning `open.manifest_file` (the
/// signed on-disk envelope — header, AEAD ct/tag, hybrid signature) after
/// the first purge and asserting it is byte-for-byte (field-for-field,
/// via `PartialEq`) identical after the second call.
#[test]
fn re_purge_is_idempotent_no_second_resign() {
    let (dir, mut open, device, mut rng, uuid) = setup_vault_with_trashed_block();
    let folder = dir.path();

    let first = purge_block(folder, &mut open, uuid, device, 5_000, &mut rng).unwrap();
    assert_eq!(first.was_shared, Some(false));

    let manifest_file_before = open.manifest_file.clone();
    let manifest_before = open.manifest.clone();

    let second = purge_block(folder, &mut open, uuid, device, 6_000, &mut rng).unwrap();

    assert_eq!(
        second.was_shared, None,
        "already-purged re-purge must report unknown classification, not a fabricated one"
    );
    assert_eq!(
        second.recipient_count, None,
        "already-purged re-purge must report unknown recipient_count"
    );
    assert_eq!(
        open.manifest_file, manifest_file_before,
        "re-purge on an already-purged block must NOT re-sign the manifest"
    );
    assert_eq!(
        open.manifest, manifest_before,
        "re-purge on an already-purged block must not otherwise mutate the manifest body"
    );
}

// ---------------------------------------------------------------------------
// sweep_purged_trash_files — Task 4 (open-time purge-cleanup sweep)
// ---------------------------------------------------------------------------

/// Re-sign `manifest` with the still-open identity and atomically write it,
/// mirroring `crash_recovery.rs`'s hand-mutation-then-resign pattern (the
/// test holds the owner identity, so this is a legitimate re-sign — it
/// simulates a manifest that arrived via file sync, e.g. from a peer device
/// that purged or restored the same block).
fn resign_and_write(
    folder: &std::path::Path,
    open: &OpenVault,
    manifest: &Manifest,
    now_ms: u64,
    rng: &mut ChaCha20Rng,
) {
    let header = ManifestHeader {
        vault_uuid: open.manifest_file.header.vault_uuid,
        created_at_ms: open.manifest_file.header.created_at_ms,
        last_mod_ms: now_ms,
    };
    let pq_sk = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).unwrap();
    let mut nonce = [0u8; 24];
    rng.fill_bytes(&mut nonce);
    let mf = sign_manifest(
        header,
        manifest,
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
}

/// Case 1: a purged, NOT-live entry whose `trash/` file has lingered (e.g.
/// a peer device received the already-purged manifest via file sync before
/// running its own delete) must be removed by the open-time sweep. This is
/// what propagates a purge across the owner's devices.
#[test]
fn open_vault_sweep_removes_purged_file_when_not_live() {
    let (dir, _mnemonic, pw) = make_fast_vault(70, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x70; 32]);
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let (device_uuid, block_uuid) = ([0xe0; 16], [0xc0; 16]);
    let recipients = vec![open.owner_card.clone()];
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "to-purge"),
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();
    trash_block(folder, &mut open, block_uuid, device_uuid, 2_000, &mut rng).unwrap();

    let report = purge_block(folder, &mut open, block_uuid, device_uuid, 3_000, &mut rng).unwrap();
    assert!(report.files_removed >= 1);
    assert!(
        trash_files_for(folder, &block_uuid).is_empty(),
        "purge_block's own best-effort delete already removed the file"
    );

    // Recreate the file to simulate a peer device that has not yet run its
    // own delete — the sweep's job is to converge that peer to the purged
    // state at its next open.
    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    let linger_path = folder
        .join("trash")
        .join(format!("{uuid_hex}.cbor.enc.2000"));
    fs::write(&linger_path, b"stale ciphertext lingering on a peer device").unwrap();
    assert!(linger_path.is_file(), "fixture sanity: file must linger");

    drop(open);
    let _reopened = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    assert!(
        !linger_path.exists(),
        "open-time sweep must remove a purged, non-live trash file"
    );
}

/// Case 2: a purged entry whose `block_uuid` IS live again in
/// `manifest.blocks` (a concurrent restore won the merge) must be left
/// completely untouched — the "not live" gate is what makes the restore
/// win safely.
#[test]
fn open_vault_sweep_keeps_purged_file_when_uuid_is_live() {
    let (dir, _mnemonic, pw) = make_fast_vault(71, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x71; 32]);
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let (device_uuid, block_uuid) = ([0xe1; 16], [0xc1; 16]);
    let recipients = vec![open.owner_card.clone()];
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "gen-1"),
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();
    trash_block(folder, &mut open, block_uuid, device_uuid, 2_000, &mut rng).unwrap();

    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    let trash_path = folder
        .join("trash")
        .join(format!("{uuid_hex}.cbor.enc.2000"));
    assert!(trash_path.is_file(), "fixture sanity");

    // Same uuid re-saved (restore-equivalent): manifest now has both a live
    // BlockEntry and the (stale) TrashEntry, mirroring
    // `crash_recovery.rs::sweep_skips_live_uuid`.
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "gen-2"),
        &recipients,
        device_uuid,
        3_000,
        &mut rng,
    )
    .unwrap();
    assert!(open
        .manifest
        .blocks
        .iter()
        .any(|b| b.block_uuid == block_uuid));

    // Hand-mark the stale TrashEntry purged: models a manifest merge where
    // a peer's purge and this device's restore both landed. The gate must
    // never delete a live block's trash residue, regardless of the purge
    // flag.
    let mut manifest = open.manifest.clone();
    let idx = manifest
        .trash
        .iter()
        .position(|t| t.block_uuid == block_uuid)
        .unwrap();
    manifest.trash[idx].purged_at_ms = Some(9_999);
    resign_and_write(folder, &open, &manifest, 4_000, &mut rng);
    drop(open);

    let reopened = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    assert!(
        trash_path.is_file(),
        "sweep must never delete a live block's trash file, purged or not"
    );
    assert!(reopened
        .manifest
        .blocks
        .iter()
        .any(|b| b.block_uuid == block_uuid));
    assert!(reopened
        .manifest
        .trash
        .iter()
        .any(|t| t.block_uuid == block_uuid && t.purged_at_ms == Some(9_999)));
}

/// Case 3: a NOT-purged trash entry's file must be left untouched by the
/// sweep (baseline regression — the sweep only acts on purged entries).
#[test]
fn open_vault_sweep_keeps_non_purged_trash_file() {
    let (dir, _mnemonic, pw) = make_fast_vault(72, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x72; 32]);
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let (device_uuid, block_uuid) = ([0xe2; 16], [0xc2; 16]);
    let recipients = vec![open.owner_card.clone()];
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "keep-me"),
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();
    trash_block(folder, &mut open, block_uuid, device_uuid, 2_000, &mut rng).unwrap();

    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    let trash_path = folder
        .join("trash")
        .join(format!("{uuid_hex}.cbor.enc.2000"));
    assert!(trash_path.is_file(), "fixture sanity");
    assert!(open
        .manifest
        .trash
        .iter()
        .any(|t| t.block_uuid == block_uuid && t.purged_at_ms.is_none()));
    drop(open);

    let _reopened = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    assert!(
        trash_path.is_file(),
        "sweep must not touch a not-purged trash entry's file"
    );
}

/// #401: a purged, NOT-live entry may also leave a leftover
/// `blocks/<uuid>.cbor.enc` — the residue of a conflict-copy merge in which
/// this device had concurrently restored the block before a peer's purge
/// won at the manifest level. The open-time sweep must unlink that file
/// too, completing the purge on this device.
///
/// Built directly from `make_fast_vault` (rather than
/// `setup_vault_with_trashed_block`, which does not return the vault
/// password) since the reopen below needs the password in scope, mirroring
/// the `open_vault_sweep_*` fixtures above.
#[test]
fn sweep_removes_purged_blocks_residue() {
    let (dir, _mnemonic, pw) = make_fast_vault(73, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x73; 32]);
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let (device_uuid, block_uuid) = ([0xe3; 16], [0xc3; 16]);
    let recipients = vec![open.owner_card.clone()];
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "to-purge-residue"),
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();
    trash_block(folder, &mut open, block_uuid, device_uuid, 2_000, &mut rng).unwrap();
    purge_block(folder, &mut open, block_uuid, device_uuid, 3_000, &mut rng).unwrap();
    assert!(
        !open
            .manifest
            .blocks
            .iter()
            .any(|b| b.block_uuid == block_uuid),
        "fixture sanity: purged block must not be live"
    );

    // Plant the conflict-copy-restore residue: a leftover blocks/ file for
    // the now-purged, not-live uuid. The sweep removes by exact filename —
    // content is irrelevant.
    let blocks_path = folder
        .join("blocks")
        .join(format!("{}.cbor.enc", format_uuid_hyphenated(&block_uuid)));
    fs::write(
        &blocks_path,
        b"leftover ciphertext from a conflict-copy restore",
    )
    .unwrap();
    assert!(blocks_path.is_file(), "fixture sanity: residue must exist");

    drop(open);
    let _reopened = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    assert!(
        !blocks_path.exists(),
        "open-time sweep must remove a purged, non-live blocks/ residue file"
    );
}

// ---------------------------------------------------------------------------
// empty_trash — Task 5 (single-resign batch purge)
// ---------------------------------------------------------------------------

/// Build a fresh vault with three trashed blocks: one owner-only trashed
/// (not yet purged), one shared-with-a-second-recipient trashed (not yet
/// purged), and one owner-only trashed AND already purged (via
/// `purge_block`, so its `TrashEntry.purged_at_ms` is already `Some(1_600)`
/// before `empty_trash` ever runs). All three share the same device, so
/// `empty_trash`'s single vector-clock tick / single re-sign is provable
/// against a genuinely mixed target set. The RNG is returned positioned so
/// callers can pass it straight into `empty_trash`.
fn setup_vault_with_mixed_trash() -> (tempfile::TempDir, OpenVault, [u8; 16], ChaCha20Rng) {
    let (dir, _mnemonic, pw) = make_fast_vault(90, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x90; 32]);

    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let device_uuid = [0x91; 16];

    // 1. owner-only, trashed, not purged.
    let owner_only_uuid = [0xa1; 16];
    let owner_only_recipients = vec![open.owner_card.clone()];
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(owner_only_uuid, "owner-only"),
        &owner_only_recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();
    trash_block(
        folder,
        &mut open,
        owner_only_uuid,
        device_uuid,
        1_100,
        &mut rng,
    )
    .unwrap();

    // 2. shared with a second recipient, trashed, not purged.
    let shared_uuid = [0xa2; 16];
    let other_card = mint_external_card(91, "Other");
    let shared_recipients = vec![open.owner_card.clone(), other_card];
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(shared_uuid, "shared"),
        &shared_recipients,
        device_uuid,
        1_200,
        &mut rng,
    )
    .unwrap();
    trash_block(folder, &mut open, shared_uuid, device_uuid, 1_300, &mut rng).unwrap();

    // 3. owner-only, trashed, AND already purged — must be skipped by
    // `empty_trash` (not re-counted, `purged_at_ms` left untouched).
    let purged_uuid = [0xa3; 16];
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(purged_uuid, "already-purged"),
        &owner_only_recipients,
        device_uuid,
        1_400,
        &mut rng,
    )
    .unwrap();
    trash_block(folder, &mut open, purged_uuid, device_uuid, 1_500, &mut rng).unwrap();
    purge_block(folder, &mut open, purged_uuid, device_uuid, 1_600, &mut rng).unwrap();

    (dir, open, device_uuid, rng)
}

/// The single-resign requirement, proven directly: seed a mixed trash (one
/// owner-only unpurged, one shared unpurged, one already-purged), call
/// `empty_trash` once, and assert both the aggregate classification counts
/// AND that the two freshly-purged entries share the exact same
/// `purged_at_ms == now_ms` — which could only happen if both were staged
/// into the same manifest clone before a single `resign_and_write_manifest`
/// call. The already-purged entry must be left at its original stamp,
/// proving it was skipped rather than re-counted.
#[test]
fn empty_trash_purges_all_unpurged_in_single_resign() {
    let (dir, mut open, device, mut rng) = setup_vault_with_mixed_trash();
    let folder = dir.path();

    let report = empty_trash(folder, &mut open, device, 7_000, &mut rng).unwrap();

    assert_eq!(report.purged_count, 2, "already-purged is skipped");
    assert_eq!(report.owner_only_count, 1);
    assert_eq!(report.shared_count, 1);
    assert_eq!(report.unknown_count, 0);
    assert!(report.files_removed >= 2);
    assert_eq!(
        report.files_failed, 0,
        "no removal failures expected in this fixture"
    );

    // Every trash entry is now purged (the pre-existing one always was).
    assert!(open.manifest.trash.iter().all(|t| t.purged_at_ms.is_some()));

    // Single new signed manifest: both freshly-purged entries share the
    // exact same now_ms stamp.
    let purged_stamps: std::collections::HashSet<_> = open
        .manifest
        .trash
        .iter()
        .filter_map(|t| t.purged_at_ms)
        .collect();
    assert!(
        purged_stamps.contains(&7_000),
        "both freshly-purged entries must share now_ms=7000"
    );

    // The pre-existing purge keeps its own original stamp — untouched, not
    // re-stamped with the new now_ms.
    let pre_purged_uuid = [0xa3; 16];
    let pre_purged_stamp = open
        .manifest
        .trash
        .iter()
        .find(|t| t.block_uuid == pre_purged_uuid)
        .unwrap()
        .purged_at_ms;
    assert_eq!(
        pre_purged_stamp,
        Some(1_600),
        "already-purged entry must not be touched by empty_trash"
    );
}

/// Calling `empty_trash` when there is nothing to purge (no trash at all)
/// must return a zeroed default report WITHOUT re-signing the manifest.
#[test]
fn empty_trash_on_empty_target_set_is_noop_no_resign() {
    let (dir, _mnemonic, pw) = make_fast_vault(92, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x92; 32]);
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let device_uuid = [0x93; 16];

    let manifest_file_before = open.manifest_file.clone();
    let manifest_before = open.manifest.clone();

    let report = empty_trash(folder, &mut open, device_uuid, 5_000, &mut rng).unwrap();

    assert_eq!(report.purged_count, 0);
    assert_eq!(report.shared_count, 0);
    assert_eq!(report.owner_only_count, 0);
    assert_eq!(report.unknown_count, 0);
    assert_eq!(report.files_removed, 0);
    assert_eq!(report.files_failed, 0);
    assert_eq!(
        open.manifest_file, manifest_file_before,
        "empty target set must not re-sign the manifest"
    );
    assert_eq!(open.manifest, manifest_before);
}
