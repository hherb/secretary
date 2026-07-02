//! Integration tests for `secretary_core::vault::trash_block` and
//! `secretary_core::vault::restore_block` — Task B.5 of PR-B. The trash
//! side moves a live block file into `trash/` with a tombstone timestamp
//! in the filename, removes the matching `BlockEntry` from
//! `manifest.blocks`, appends a `TrashEntry` to `manifest.trash`, and
//! re-signs the manifest. The restore side reverses the move: scans
//! `trash/<uuid>.cbor.enc.*`, picks the file whose suffix matches the
//! signed `TrashEntry.tombstoned_at_ms` (#205),
//! decrypts + hybrid-verifies, renames into `blocks/`, purges older
//! copies, and re-signs the manifest. The §7 / §7.1 file-renaming
//! semantics are atomic per POSIX `rename(2)`.
//!
//! NOTE: deviation from plan §2.1/2.5/2.6 — the plan called for inline
//! `#[cfg(test)] mod tests` unit tests in `orchestrators.rs`. We pivot
//! to integration tests here because the unit-test approach would need
//! ~150 LOC of `make_fast_vault` machinery duplicated into the inline
//! module, and `core/src/vault/orchestrators.rs` is already well past
//! the project's 500-LOC threshold. The behavioural coverage is the
//! same; the difference is which crate boundary the tests live behind.

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
use secretary_core::unlock::{
    self, bundle::IdentityBundle, create_vault_unchecked, mnemonic::Mnemonic, vault_toml,
};
use secretary_core::vault::{
    encode_manifest_file, open_vault, restore_block, save_block, sign_manifest, trash_block,
    BlockPlaintext, KdfParamsRef, Manifest, ManifestHeader, Unlocker, VaultError,
};
use secretary_core::version::{FORMAT_VERSION, SUITE_ID};

// ---------------------------------------------------------------------------
// Fixture helpers (mirror save_block.rs / share_block.rs)
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

/// Build a co-recipient contact card from a freshly-generated identity
/// bundle. Mirrors `core/tests/save_block.rs::make_signed_card` — kept
/// local to avoid a shared test-helper crate for the only test that
/// needs it.
fn make_signed_card(id: &IdentityBundle) -> ContactCard {
    let pq_sk = MlDsa65Secret::from_bytes(id.ml_dsa_65_sk.expose()).unwrap();
    let mut card = ContactCard {
        card_version: CARD_VERSION_V1,
        contact_uuid: id.user_uuid,
        display_name: id.display_name.clone(),
        x25519_pk: id.x25519_pk,
        ml_kem_768_pk: id.ml_kem_768_pk.clone(),
        ed25519_pk: id.ed25519_pk,
        ml_dsa_65_pk: id.ml_dsa_65_pk.clone(),
        created_at_ms: id.created_at_ms,
        self_sig_ed: [0u8; ED25519_SIG_LEN],
        self_sig_pq: vec![0u8; ML_DSA_65_SIG_LEN],
    };
    card.sign(&id.ed25519_sk, &pq_sk).unwrap();
    card
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
// trash_block — happy path
// ---------------------------------------------------------------------------

/// `trash_block` moves the block file into `trash/<uuid>.cbor.enc.<now_ms>`,
/// drops the matching `BlockEntry`, and appends a `TrashEntry`.
#[test]
fn trash_block_moves_file_and_updates_manifest() {
    let (dir, _mnemonic, pw) = make_fast_vault(1, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0xc1; 32]);

    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let device_uuid = [0xd1; 16];
    let block_uuid = [0xb1; 16];
    let plaintext = make_simple_plaintext(block_uuid, "to-trash");
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

    let blocks_count_before = open.manifest.blocks.len();
    let trash_count_before = open.manifest.trash.len();

    let trash_now_ms = 2_000u64;
    trash_block(
        folder,
        &mut open,
        block_uuid,
        device_uuid,
        trash_now_ms,
        &mut rng,
    )
    .unwrap();

    // File moved: blocks/<uuid>.cbor.enc absent, trash/<uuid>.cbor.enc.<ms> present.
    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    assert!(
        !folder
            .join("blocks")
            .join(format!("{uuid_hex}.cbor.enc"))
            .exists(),
        "block file should have been moved out of blocks/"
    );
    let trash_filename = format!("{uuid_hex}.cbor.enc.{trash_now_ms}");
    assert!(
        folder.join("trash").join(&trash_filename).exists(),
        "block file should now exist at trash/{trash_filename}"
    );

    // Manifest: block entry removed, trash entry added with matching metadata.
    assert_eq!(open.manifest.blocks.len(), blocks_count_before - 1);
    assert_eq!(open.manifest.trash.len(), trash_count_before + 1);
    let trash_entry = open
        .manifest
        .trash
        .iter()
        .find(|t| t.block_uuid == block_uuid)
        .expect("TrashEntry for the trashed block");
    assert_eq!(trash_entry.tombstoned_at_ms, trash_now_ms);
    assert_eq!(trash_entry.tombstoned_by, device_uuid);
}

// ---------------------------------------------------------------------------
// trash_block — rejection: unknown UUID
// ---------------------------------------------------------------------------

/// `trash_block` surfaces `VaultError::BlockNotFound` when the UUID is
/// not in `manifest.blocks`; the manifest is left untouched.
#[test]
fn trash_block_rejects_unknown_uuid() {
    let (dir, _mnemonic, pw) = make_fast_vault(2, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0xc2; 32]);

    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let device_uuid = [0xd2; 16];
    let unknown_uuid = [0xff; 16];
    let blocks_count_before = open.manifest.blocks.len();
    let trash_count_before = open.manifest.trash.len();

    let result = trash_block(
        folder,
        &mut open,
        unknown_uuid,
        device_uuid,
        1_000,
        &mut rng,
    );
    match result {
        Err(VaultError::BlockNotFound { block_uuid }) => {
            assert_eq!(block_uuid, unknown_uuid);
        }
        other => panic!("expected BlockNotFound, got {other:?}"),
    }
    // Manifest unmodified — no half-applied state.
    assert_eq!(open.manifest.blocks.len(), blocks_count_before);
    assert_eq!(open.manifest.trash.len(), trash_count_before);
}

// ---------------------------------------------------------------------------
// trash_block — clock invariant: manifest clock ticks, block clock untouched
// ---------------------------------------------------------------------------

/// `trash_block` ticks the manifest-level vector clock for the calling
/// device but does NOT mutate the trashed block file's content — the
/// move is `rename(2)`, not a rewrite. The block's per-block clock
/// (frozen into the on-disk bytes) is therefore unchanged.
#[test]
fn trash_block_ticks_manifest_clock() {
    let (dir, _mnemonic, pw) = make_fast_vault(3, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0xc3; 32]);

    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let device_uuid = [0xd3; 16];
    let block_uuid = [0xb3; 16];
    let plaintext = make_simple_plaintext(block_uuid, "clock-test");
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
    let device_counter_before = open
        .manifest
        .vector_clock
        .iter()
        .find(|e| e.device_uuid == device_uuid)
        .map(|e| e.counter)
        .unwrap_or(0);

    trash_block(folder, &mut open, block_uuid, device_uuid, 2_000, &mut rng).unwrap();

    let device_counter_after = open
        .manifest
        .vector_clock
        .iter()
        .find(|e| e.device_uuid == device_uuid)
        .expect("device clock entry must exist after trash_block")
        .counter;
    assert_eq!(device_counter_after, device_counter_before + 1);
}

// ---------------------------------------------------------------------------
// trash_block — round-trip: re-open sees the trashed state
// ---------------------------------------------------------------------------

/// After `trash_block` re-signs the manifest and atomic-writes it,
/// `open_vault` on the same folder sees the block in `manifest.trash`
/// and gone from `manifest.blocks`. Verifies the on-disk manifest is
/// authoritative, not just the in-memory `OpenVault`.
#[test]
fn trash_block_then_reopen_round_trip() {
    let (dir, _mnemonic, pw) = make_fast_vault(4, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0xc4; 32]);

    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let device_uuid = [0xd4; 16];
    let block_uuid = [0xb4; 16];
    let plaintext = make_simple_plaintext(block_uuid, "round-trip");
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

    // Drop the in-memory open vault and re-open from disk.
    drop(open);
    let reopened = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    assert!(
        !reopened
            .manifest
            .blocks
            .iter()
            .any(|b| b.block_uuid == block_uuid),
        "block_uuid must no longer appear in manifest.blocks after reopen"
    );
    assert!(
        reopened
            .manifest
            .trash
            .iter()
            .any(|t| t.block_uuid == block_uuid && t.tombstoned_at_ms == 2_000),
        "TrashEntry must persist on disk through manifest re-sign"
    );
}

// ---------------------------------------------------------------------------
// trash_block — content commitment (#293)
// ---------------------------------------------------------------------------

/// `trash_block` captures the live `BlockEntry.fingerprint` into the new
/// `TrashEntry.fingerprint` (the content commitment that `restore_block`
/// later verifies, #293).
#[test]
fn trash_block_captures_content_commitment() {
    let (dir, _mnemonic, pw) = make_fast_vault(20, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x20; 32]);

    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let device_uuid = [0xd2; 16];
    let block_uuid = [0xb2; 16];
    let recipients = vec![open.owner_card.clone()];
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "secret"),
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();

    // Capture the live block's fingerprint BEFORE trashing.
    let live_fp = open
        .manifest
        .blocks
        .iter()
        .find(|b| b.block_uuid == block_uuid)
        .expect("block must be live before trash")
        .fingerprint;

    trash_block(folder, &mut open, block_uuid, device_uuid, 2_000, &mut rng).unwrap();

    let entry = open
        .manifest
        .trash
        .iter()
        .find(|t| t.block_uuid == block_uuid)
        .expect("TrashEntry for the trashed block");
    assert_eq!(
        entry.fingerprint,
        Some(live_fp),
        "trash_block must commit the live BlockEntry.fingerprint into the TrashEntry",
    );
}

// ---------------------------------------------------------------------------
// restore_block — happy path: trash → restore round-trip
// ---------------------------------------------------------------------------

/// `restore_block` is the inverse of `trash_block` over a single
/// trashed copy: after restore, the block file is back in `blocks/`,
/// the `BlockEntry` is back in `manifest.blocks`, and the matching
/// `TrashEntry` is gone.
#[test]
fn restore_block_round_trip_after_single_trash() {
    let (dir, _mnemonic, pw) = make_fast_vault(5, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0xc5; 32]);

    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let device_uuid = [0xd5; 16];
    let block_uuid = [0xb5; 16];
    let plaintext = make_simple_plaintext(block_uuid, "restore-round-trip");
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

    restore_block(folder, &mut open, block_uuid, device_uuid, 3_000, &mut rng).unwrap();

    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    assert!(
        folder
            .join("blocks")
            .join(format!("{uuid_hex}.cbor.enc"))
            .exists(),
        "block file should be back in blocks/ after restore"
    );
    assert!(
        open.manifest
            .blocks
            .iter()
            .any(|b| b.block_uuid == block_uuid),
        "BlockEntry should be back in manifest.blocks"
    );
    assert!(
        !open
            .manifest
            .trash
            .iter()
            .any(|t| t.block_uuid == block_uuid),
        "TrashEntry should be gone from manifest.trash"
    );
}

// ---------------------------------------------------------------------------
// restore_block — crash resume: file already in blocks/, manifest not updated
// ---------------------------------------------------------------------------

/// #351: a prior `restore_block` renamed the trash file into `blocks/` (step 6)
/// then crashed before the manifest write (step 11), leaving the manifest still
/// listing the signed `TrashEntry` while `trash/` has no matching file. Retrying
/// must RESUME from the live `blocks/` file (whose bytes hash to the signed
/// `TrashEntry.fingerprint`) and complete the manifest update — not fail
/// `BlockNotInTrash` — and the vault must reopen cleanly afterwards.
#[test]
fn restore_block_resumes_when_file_already_in_blocks_after_crash() {
    let (dir, _mnemonic, pw) = make_fast_vault(9, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0xc9; 32]);

    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let device_uuid = [0xd9; 16];
    let block_uuid = [0xb9; 16];
    let plaintext = make_simple_plaintext(block_uuid, "resume-after-crash");
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

    // Simulate the crash: move trash/<uuid>.cbor.enc.2000 → blocks/<uuid>.cbor.enc,
    // leaving `open.manifest` still holding the TrashEntry (manifest not written).
    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    let trash_file = folder
        .join("trash")
        .join(format!("{uuid_hex}.cbor.enc.2000"));
    let live = folder.join("blocks").join(format!("{uuid_hex}.cbor.enc"));
    std::fs::rename(&trash_file, &live).unwrap();
    assert!(!trash_file.exists() && live.exists(), "crash state staged");
    assert!(
        open.manifest
            .trash
            .iter()
            .any(|t| t.block_uuid == block_uuid),
        "manifest still lists the TrashEntry (crash before step 11)",
    );

    // Retry restore — must resume rather than fail BlockNotInTrash.
    restore_block(folder, &mut open, block_uuid, device_uuid, 3_000, &mut rng)
        .expect("restore must resume from the already-restored blocks/ file");

    assert!(
        open.manifest
            .blocks
            .iter()
            .any(|b| b.block_uuid == block_uuid),
        "BlockEntry restored to manifest",
    );
    assert!(
        !open
            .manifest
            .trash
            .iter()
            .any(|t| t.block_uuid == block_uuid),
        "TrashEntry cleared from manifest",
    );
    assert!(live.exists(), "block remains live in blocks/");

    // The vault must reopen cleanly (block fingerprint matches the manifest).
    drop(open);
    let reopened = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    assert!(reopened
        .manifest
        .blocks
        .iter()
        .any(|b| b.block_uuid == block_uuid));
}

// ---------------------------------------------------------------------------
// restore_block — multi-copy purge: newest restored, older copies removed
// ---------------------------------------------------------------------------

/// When multiple files match `<uuid>.cbor.enc.*` (the same block was
/// trashed → restored → re-trashed, or an older copy was manually
/// preserved), `restore_block` picks the file matching the signed
/// `tombstoned_at_ms` (here the newest, suffix 4000) and physically
/// removes the older copies.
#[test]
fn restore_block_purges_older_copies() {
    let (dir, _mnemonic, pw) = make_fast_vault(6, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0xc6; 32]);

    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let device_uuid = [0xd6; 16];
    let block_uuid = [0xb6; 16];
    let plaintext = make_simple_plaintext(block_uuid, "multi-trash");
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
    trash_block(folder, &mut open, block_uuid, device_uuid, 4_000, &mut rng).unwrap();

    // Plant an older trashed copy by hand-copying the newest. Simulates
    // a leftover from a prior trash-restore-trash cycle inside the
    // retention window.
    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    let trash_dir = folder.join("trash");
    let newest = trash_dir.join(format!("{uuid_hex}.cbor.enc.4000"));
    let older = trash_dir.join(format!("{uuid_hex}.cbor.enc.3500"));
    fs::copy(&newest, &older).unwrap();
    assert!(older.exists());

    restore_block(folder, &mut open, block_uuid, device_uuid, 5_000, &mut rng).unwrap();

    // Newest moved to blocks/, older purged.
    assert!(
        folder
            .join("blocks")
            .join(format!("{uuid_hex}.cbor.enc"))
            .exists(),
        "newest trashed copy should be restored to blocks/"
    );
    assert!(!older.exists(), "older trashed copy should be purged");
    assert!(!newest.exists(), "newest moved out of trash/");
}

// ---------------------------------------------------------------------------
// restore_block — preserves block-level vector clock (sync correctness)
// ---------------------------------------------------------------------------

/// `restore_block` rebuilds the `BlockEntry` from the on-disk file's
/// header — the per-block `vector_clock_summary` is preserved verbatim,
/// because the block's *content* did not change between trash and
/// restore (rename is a move, not a rewrite). This is the sync-
/// correctness invariant that makes restore a continuation, not a
/// fork.
#[test]
fn restore_block_preserves_block_vector_clock() {
    let (dir, _mnemonic, pw) = make_fast_vault(7, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0xc7; 32]);

    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let device_uuid = [0xd7; 16];
    let block_uuid = [0xb7; 16];
    let plaintext = make_simple_plaintext(block_uuid, "clock-continuity");
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
    let block_clock_before = open
        .manifest
        .blocks
        .iter()
        .find(|b| b.block_uuid == block_uuid)
        .unwrap()
        .vector_clock_summary
        .clone();

    trash_block(folder, &mut open, block_uuid, device_uuid, 2_000, &mut rng).unwrap();
    restore_block(folder, &mut open, block_uuid, device_uuid, 3_000, &mut rng).unwrap();

    let block_clock_after = open
        .manifest
        .blocks
        .iter()
        .find(|b| b.block_uuid == block_uuid)
        .unwrap()
        .vector_clock_summary
        .clone();
    assert_eq!(
        block_clock_before, block_clock_after,
        "block-level vector clock must be preserved across trash/restore"
    );
}

// ---------------------------------------------------------------------------
// restore_block — rejection: BlockUuidAlreadyLive
// ---------------------------------------------------------------------------

/// `restore_block` must reject when the UUID is currently live (both in
/// `manifest.blocks` and somehow also in `trash/`). The spec requires
/// the caller to trash the live copy first. The manifest must not be
/// mutated.
#[test]
fn restore_block_rejects_live_uuid_collision() {
    let (dir, _mnemonic, pw) = make_fast_vault(8, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0xc8; 32]);

    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let device_uuid = [0xd8; 16];
    let block_uuid = [0xb8; 16];
    let plaintext = make_simple_plaintext(block_uuid, "collision");
    let recipients = vec![open.owner_card.clone()];

    // Save → trash → re-save: now the block is live AND a trash file
    // exists (planted by the trash_block call before re-save). To
    // simulate the collision: trash, re-create the block on disk while
    // keeping the trash file around.
    save_block(
        folder,
        &mut open,
        plaintext.clone(),
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();
    trash_block(folder, &mut open, block_uuid, device_uuid, 2_000, &mut rng).unwrap();
    save_block(
        folder,
        &mut open,
        plaintext,
        &recipients,
        device_uuid,
        3_000,
        &mut rng,
    )
    .unwrap();

    let blocks_count_before = open.manifest.blocks.len();
    let result = restore_block(folder, &mut open, block_uuid, device_uuid, 4_000, &mut rng);
    match result {
        Err(VaultError::BlockUuidAlreadyLive {
            block_uuid: returned,
        }) => assert_eq!(returned, block_uuid),
        other => panic!("expected BlockUuidAlreadyLive, got {other:?}"),
    }
    // Manifest unmodified — no half-applied restore.
    assert_eq!(open.manifest.blocks.len(), blocks_count_before);
}

// ---------------------------------------------------------------------------
// restore_block — rejection: BlockNotInTrash
// ---------------------------------------------------------------------------

/// `restore_block` surfaces `VaultError::BlockNotInTrash` when neither
/// a trash file nor a `TrashEntry` exists for the requested UUID. The
/// manifest is left untouched.
#[test]
fn restore_block_rejects_when_not_in_trash() {
    let (dir, _mnemonic, pw) = make_fast_vault(9, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0xc9; 32]);

    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let device_uuid = [0xd9; 16];
    let unknown_uuid = [0xee; 16];

    let result = restore_block(
        folder,
        &mut open,
        unknown_uuid,
        device_uuid,
        1_000,
        &mut rng,
    );
    match result {
        Err(VaultError::BlockNotInTrash {
            block_uuid: returned,
        }) => assert_eq!(returned, unknown_uuid),
        other => panic!("expected BlockNotInTrash, got {other:?}"),
    }
}

/// `restore_block` surfaces `VaultError::BlockNotInTrash` when a trash
/// *file* exists for the requested UUID but the manifest has no
/// matching `TrashEntry`. The §7.1 contract is strict: file and
/// manifest entry MUST be paired, and a one-sided disagreement is an
/// integrity failure. Without this rejection, an attacker with write
/// access to `trash/` could plant a forged file; defense-in-depth
/// (§6.1 hybrid-verify) would still catch a forgery, but we reject
/// earlier and with a typed error rather than relying on later
/// verification to cover for the missing pre-check.
#[test]
fn restore_block_rejects_orphan_trash_file_without_manifest_entry() {
    let (dir, _mnemonic, pw) = make_fast_vault(28, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0xd1; 32]);

    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let device_uuid = [0xe1; 16];
    let block_uuid = [0xb1; 16];

    // Plant a syntactically well-formed trash file (any bytes — the
    // §6.1 hybrid-verify will never fire because we reject first on
    // the manifest-entry pre-check) without a matching TrashEntry in
    // `manifest.trash`. The `trash/` directory must exist; we use the
    // canonical `<uuid>.cbor.enc.<unix-millis>` filename.
    let trash_dir = folder.join("trash");
    fs::create_dir_all(&trash_dir).unwrap();
    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    let orphan_path = trash_dir.join(format!("{uuid_hex}.cbor.enc.5000"));
    fs::write(&orphan_path, b"orphan-bytes").unwrap();

    // No TrashEntry was appended to `manifest.trash`, so the §7.1
    // pairing contract is violated.
    assert!(
        !open
            .manifest
            .trash
            .iter()
            .any(|t| t.block_uuid == block_uuid),
        "fixture: manifest must NOT have a TrashEntry for this UUID"
    );

    let result = restore_block(folder, &mut open, block_uuid, device_uuid, 6_000, &mut rng);
    match result {
        Err(VaultError::BlockNotInTrash {
            block_uuid: returned,
        }) => assert_eq!(returned, block_uuid),
        other => panic!("expected BlockNotInTrash, got {other:?}"),
    }

    // The orphan trash file is preserved — the caller decides between
    // purge-without-restore and forensic capture (same contract as
    // tampered-file rejection).
    assert!(
        orphan_path.exists(),
        "orphan trash file must persist after a rejected restore"
    );
    // Manifest is untouched on either side.
    assert!(
        !open
            .manifest
            .blocks
            .iter()
            .any(|b| b.block_uuid == block_uuid),
        "BlockEntry must not be added after a rejected restore"
    );
}

/// `restore_block`'s step-4 contacts/ scan MUST verify each card's
/// Ed25519 ∧ ML-DSA-65 self-signature before trusting its
/// `contact_uuid` for the manifest's recipient table. Cards that
/// parse but fail self-verify are skipped — they cannot mint a
/// `contact_uuid` into a signed manifest.
///
/// Setup: a block is saved with both the owner AND a co-recipient
/// "Bob" (whose card is planted in `contacts/`). The block is then
/// trashed. Before restore, we tamper Bob's on-disk card so its
/// self-signature no longer verifies. The wrap for Bob in the trashed
/// block must then fail to resolve — `MissingRecipientCard` is the
/// typed surface, and the manifest stays untouched (the rename step
/// has not yet run when step 5's wrap-resolution loop bails).
#[test]
fn restore_block_skips_contact_cards_failing_self_verify() {
    let (dir, _mnemonic, pw) = make_fast_vault(29, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0xd2; 32]);

    // Build Bob's identity + valid card and plant it in contacts/.
    let mut bob_rng = ChaCha20Rng::from_seed([0xc2; 32]);
    let bob_id = unlock::bundle::generate("Bob", 1_714_060_800_000, &mut bob_rng);
    let bob_card = make_signed_card(&bob_id);
    let bob_card_bytes = bob_card.to_canonical_cbor().unwrap();
    let bob_uuid_hex = format_uuid_hyphenated(&bob_id.user_uuid);
    let contacts_dir = folder.join("contacts");
    let bob_card_path = contacts_dir.join(format!("{bob_uuid_hex}.card"));
    fs::write(&bob_card_path, &bob_card_bytes).unwrap();

    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let device_uuid = [0xe2; 16];
    let block_uuid = [0xb2; 16];

    // Save with two recipients: owner + Bob. The block's §6.2 wrap
    // table will have entries for both fingerprints, so step-4's
    // contacts/ scan WILL be triggered (the owner-only short-circuit
    // does not apply).
    let plaintext = make_simple_plaintext(block_uuid, "shared-with-bob");
    let recipients = vec![open.owner_card.clone(), bob_card.clone()];
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

    // Tamper Bob's card: flip a bit of `self_sig_ed`. `verify_self`
    // checks Ed25519 ∧ ML-DSA-65 — failing either half is enough.
    // `from_canonical_cbor` will still parse the tampered bytes.
    let mut tampered = bob_card_bytes.clone();
    // The Ed25519 sig is 64 bytes inside the card's CBOR; flipping
    // *any* byte inside the structurally valid sig field defeats
    // verify_self without breaking the parse. We locate the sig by
    // searching for its known prefix and flip the next byte.
    let sig_first_byte = bob_card.self_sig_ed[0];
    let idx = tampered
        .iter()
        .position(|&b| b == sig_first_byte)
        .expect("bob's self_sig_ed first byte must appear in canonical-cbor bytes");
    tampered[idx] ^= 0xff;
    fs::write(&bob_card_path, &tampered).unwrap();

    // Restore: the trashed block decrypts + hybrid-verifies fine
    // (the block file is untouched), but Bob's wrap cannot resolve
    // to a `contact_uuid` because the only candidate card on disk
    // now fails `verify_self()` and is skipped. The typed surface
    // is `MissingRecipientCard`.
    let result = restore_block(folder, &mut open, block_uuid, device_uuid, 3_000, &mut rng);
    let bob_card_fp = fingerprint(&bob_card_bytes);
    match result {
        Err(VaultError::MissingRecipientCard { fingerprint: fp }) => {
            assert_eq!(
                fp, bob_card_fp,
                "the missing fingerprint must be Bob's, since the owner is resolved in-memory"
            );
        }
        other => panic!("expected MissingRecipientCard, got {other:?}"),
    }

    // Manifest is untouched on either side.
    assert!(
        !open
            .manifest
            .blocks
            .iter()
            .any(|b| b.block_uuid == block_uuid),
        "BlockEntry must not be added after a rejected restore"
    );
    assert!(
        open.manifest
            .trash
            .iter()
            .any(|t| t.block_uuid == block_uuid),
        "TrashEntry must persist after a rejected restore"
    );
}

/// `restore_block`'s scan in step 2 MUST tolerate non-canonical
/// suffixes by skipping them rather than hard-failing. A buggy peer
/// client (or filesystem cruft on a shared sync folder) that drops
/// `<uuid>.cbor.enc.abc` or `<uuid>.cbor.enc.007` next to a valid
/// `<uuid>.cbor.enc.<canonical>` must not wedge restore — only the
/// canonical-suffix match is the trusted record of when the trashing
/// happened, and the §6.1 hybrid verify still gates correctness on
/// that file's contents.
#[test]
fn restore_block_skips_noncanonical_trash_suffixes() {
    let (dir, _mnemonic, pw) = make_fast_vault(30, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0xd3; 32]);

    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let device_uuid = [0xe3; 16];
    let block_uuid = [0xb3; 16];
    let plaintext = make_simple_plaintext(block_uuid, "needs-cleanup");
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
    let trash_now_ms = 2_000u64;
    trash_block(
        folder,
        &mut open,
        block_uuid,
        device_uuid,
        trash_now_ms,
        &mut rng,
    )
    .unwrap();

    // Plant three noise files alongside the legitimate trash file:
    //   1. Non-numeric suffix (`abc`).
    //   2. Leading-zero suffix (`007` — parses to 7 but is not
    //      canonical decimal).
    //   3. `+`-prefixed suffix (`+5` — `u64::from_str` rejects, but
    //      the strict-fail-on-any-junk variant would still surface
    //      an Io error before we get to a legitimate match).
    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    let trash_dir = folder.join("trash");
    fs::write(trash_dir.join(format!("{uuid_hex}.cbor.enc.abc")), b"junk1").unwrap();
    fs::write(trash_dir.join(format!("{uuid_hex}.cbor.enc.007")), b"junk2").unwrap();
    fs::write(trash_dir.join(format!("{uuid_hex}.cbor.enc.+5")), b"junk3").unwrap();

    // Restore must succeed despite the cruft — the canonical
    // `<uuid>.cbor.enc.2000` match is picked, verified, and renamed
    // into blocks/.
    let restore_now_ms = 3_000u64;
    restore_block(
        folder,
        &mut open,
        block_uuid,
        device_uuid,
        restore_now_ms,
        &mut rng,
    )
    .unwrap();

    assert!(
        open.manifest
            .blocks
            .iter()
            .any(|b| b.block_uuid == block_uuid),
        "BlockEntry must be appended after a successful restore"
    );
    assert!(
        !open
            .manifest
            .trash
            .iter()
            .any(|t| t.block_uuid == block_uuid),
        "TrashEntry must be removed after a successful restore"
    );

    // The cruft files are left in place. They are not the project's
    // problem to clean up — the user-facing "trash purge after
    // retention window" pass deals with leftover files. We assert
    // they survive to document the expected behaviour: skip-and-
    // ignore, not skip-and-delete.
    assert!(
        trash_dir.join(format!("{uuid_hex}.cbor.enc.abc")).exists(),
        "non-numeric cruft file must be left in place"
    );
    assert!(
        trash_dir.join(format!("{uuid_hex}.cbor.enc.007")).exists(),
        "leading-zero cruft file must be left in place"
    );
}

// ---------------------------------------------------------------------------
// restore_block — rejection: RestoreVerificationFailed (tampered file)
// ---------------------------------------------------------------------------

/// If an attacker (or a disk fault) corrupts the bytes of the trashed
/// file, `restore_block` must reject the file before mutating the
/// manifest. The trash file and `TrashEntry` are preserved so the
/// caller can decide between purge-without-restore and forensic
/// capture.
#[test]
fn restore_block_rejects_tampered_file() {
    let (dir, _mnemonic, pw) = make_fast_vault(10, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0xca; 32]);

    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let device_uuid = [0xda; 16];
    let block_uuid = [0xba; 16];
    let plaintext = make_simple_plaintext(block_uuid, "tampered");
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

    // Tamper: flip a byte in the middle of the trash file. The §6.1
    // hybrid signature will reject the file regardless of where the
    // bit lands (header, recipient table, AEAD payload — all are
    // inside the signed range).
    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    let trash_path = folder
        .join("trash")
        .join(format!("{uuid_hex}.cbor.enc.2000"));
    let mut bytes = fs::read(&trash_path).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xff;
    fs::write(&trash_path, &bytes).unwrap();

    let result = restore_block(folder, &mut open, block_uuid, device_uuid, 3_000, &mut rng);
    match result {
        Err(VaultError::RestoreVerificationFailed {
            block_uuid: returned,
            ..
        }) => assert_eq!(returned, block_uuid),
        other => panic!("expected RestoreVerificationFailed, got {other:?}"),
    }
    // Trash file still present (caller decides what to do with it).
    assert!(
        trash_path.exists(),
        "trash file must persist after a rejected restore"
    );
    // TrashEntry still in manifest.
    assert!(
        open.manifest
            .trash
            .iter()
            .any(|t| t.block_uuid == block_uuid),
        "TrashEntry must persist after a rejected restore"
    );
    // Manifest.blocks unchanged.
    assert!(
        !open
            .manifest
            .blocks
            .iter()
            .any(|b| b.block_uuid == block_uuid),
        "BlockEntry must not be added after a rejected restore"
    );
}

// ---------------------------------------------------------------------------
// restore_block — re-open round-trip: on-disk state matches in-memory
// ---------------------------------------------------------------------------

/// After `restore_block` re-signs the manifest and atomic-writes it,
/// `open_vault` on the same folder sees the restored block. Verifies
/// the on-disk manifest is authoritative.
#[test]
fn restore_block_then_reopen_round_trip() {
    let (dir, _mnemonic, pw) = make_fast_vault(11, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0xcb; 32]);

    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let device_uuid = [0xdb; 16];
    let block_uuid = [0xbb; 16];
    let plaintext = make_simple_plaintext(block_uuid, "reopen");
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
    restore_block(folder, &mut open, block_uuid, device_uuid, 3_000, &mut rng).unwrap();
    drop(open);

    let reopened = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    assert!(
        reopened
            .manifest
            .blocks
            .iter()
            .any(|b| b.block_uuid == block_uuid),
        "BlockEntry must persist on disk after restore_block manifest re-sign"
    );
    assert!(
        !reopened
            .manifest
            .trash
            .iter()
            .any(|t| t.block_uuid == block_uuid),
        "TrashEntry must be gone on disk after restore_block manifest re-sign"
    );
}

// ---------------------------------------------------------------------------
// restore_block — #205: selection binds to the signed tombstoned_at_ms
// ---------------------------------------------------------------------------

/// #205 regression: `restore_block` MUST select the trashed file whose
/// suffix equals the signed `TrashEntry.tombstoned_at_ms`, NOT the file
/// with the largest suffix. An attacker with write access to `trash/`
/// plants a forged copy with a LARGER suffix; the pre-#205 largest-suffix
/// selection would pick it (and, on a corrupt plant, fail to verify).
/// Equality selection picks the authentic file and purges the plant.
#[test]
fn restore_block_ignores_larger_suffix_forgery() {
    let (dir, _mnemonic, pw) = make_fast_vault(9, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0xc9; 32]);

    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let device_uuid = [0xd9; 16];
    let block_uuid = [0xb9; 16];
    let plaintext = make_simple_plaintext(block_uuid, "authentic-current");
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

    let trash_ts = 5_000u64;
    trash_block(
        folder,
        &mut open,
        block_uuid,
        device_uuid,
        trash_ts,
        &mut rng,
    )
    .unwrap();

    // Capture the authentic trashed bytes (suffix == signed tombstoned_at_ms).
    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    let trash_dir = folder.join("trash");
    let authentic = trash_dir.join(format!("{uuid_hex}.cbor.enc.{trash_ts}"));
    let authentic_bytes = fs::read(&authentic).unwrap();

    // Plant a corrupt forgery with a LARGER suffix. The largest-suffix
    // selection (pre-#205) would pick this and fail verification.
    let forgery_ts = 9_000u64;
    let forgery = trash_dir.join(format!("{uuid_hex}.cbor.enc.{forgery_ts}"));
    let mut corrupt = authentic_bytes.clone();
    let mid = corrupt.len() / 2;
    corrupt[mid] ^= 0xff; // flip a byte → fails decode/hybrid-verify if selected
    fs::write(&forgery, &corrupt).unwrap();

    // Restore MUST succeed by selecting the authentic (signed-ts) file.
    restore_block(folder, &mut open, block_uuid, device_uuid, 10_000, &mut rng).unwrap();

    // The restored live file is byte-identical to the authentic trashed
    // file (rename is a move), proving the forgery was NOT selected.
    let restored = folder.join("blocks").join(format!("{uuid_hex}.cbor.enc"));
    assert_eq!(
        fs::read(&restored).unwrap(),
        authentic_bytes,
        "restored file must be the authentic signed-timestamp copy, not the larger-suffix forgery",
    );
    assert!(!forgery.exists(), "larger-suffix forgery must be purged");
    assert!(!authentic.exists(), "authentic copy moved out of trash/");
}

/// #205 regression (the real attack): an attacker plants a **valid,
/// genuinely owner-signed** *older* copy of the same `block_uuid` at a
/// LARGER suffix. Unlike `restore_block_ignores_larger_suffix_forgery`
/// (which plants a *corrupt* file that the §6.1 hybrid-verify would
/// reject regardless of selection), this plant verifies fine — so this
/// test proves the **selection** logic, not verification, is what
/// rejects the rollback. On the pre-#205 largest-suffix logic restore
/// would pick the plant, hybrid-verify would PASS (authenticity ≠
/// currency), and the stale content would go live; the content assertion
/// below catches exactly that.
#[test]
fn restore_block_selects_signed_timestamp_over_valid_larger_suffix_plant() {
    let (dir, _mnemonic, pw) = make_fast_vault(11, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0xcb; 32]);

    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let device_uuid = [0xdb; 16];
    let block_uuid = [0xbb; 16];
    let recipients = vec![open.owner_card.clone()];

    // First save: the STALE content. Capture its valid owner-signed
    // envelope bytes before overwriting it.
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "stale-old-secret"),
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();
    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    let live_path = folder.join("blocks").join(format!("{uuid_hex}.cbor.enc"));
    let stale_bytes = fs::read(&live_path).unwrap();

    // Second save (update — same block_uuid): the AUTHENTIC-CURRENT
    // content. Different plaintext + a second clock tick → different
    // bytes, but still a valid owner-signed envelope.
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "authentic-current-secret"),
        &recipients,
        device_uuid,
        2_000,
        &mut rng,
    )
    .unwrap();

    let trash_ts = 5_000u64;
    trash_block(
        folder,
        &mut open,
        block_uuid,
        device_uuid,
        trash_ts,
        &mut rng,
    )
    .unwrap();

    // The authentic-current envelope now lives at suffix == signed ts.
    let trash_dir = folder.join("trash");
    let authentic = trash_dir.join(format!("{uuid_hex}.cbor.enc.{trash_ts}"));
    let authentic_bytes = fs::read(&authentic).unwrap();
    assert_ne!(
        stale_bytes, authentic_bytes,
        "sanity: the two valid envelopes must differ in content",
    );

    // Plant the VALID stale envelope at a LARGER suffix. Largest-suffix
    // selection (pre-#205) would pick this, verify it successfully, and
    // restore the stale secret.
    let plant_ts = 9_000u64;
    let plant = trash_dir.join(format!("{uuid_hex}.cbor.enc.{plant_ts}"));
    fs::write(&plant, &stale_bytes).unwrap();

    restore_block(folder, &mut open, block_uuid, device_uuid, 10_000, &mut rng).unwrap();

    // The restored live file is the authentic-current envelope, NOT the
    // valid-but-stale larger-suffix plant — selection bound to the signed
    // timestamp, not the largest suffix.
    assert_eq!(
        fs::read(&live_path).unwrap(),
        authentic_bytes,
        "restored file must be the signed-timestamp (current) copy, not the valid larger-suffix stale plant",
    );
    assert!(
        !plant.exists(),
        "valid larger-suffix stale plant must be purged"
    );
    assert!(!authentic.exists(), "authentic copy moved out of trash/");
}

/// #205: when a signed `TrashEntry` exists and trash files are present
/// but NONE has a suffix equal to the signed `tombstoned_at_ms` (the
/// authentic file was renamed to a larger suffix, leaving only a planted
/// — but genuinely owner-signed — copy), `restore_block` rejects with
/// `RestoreTargetMissing` rather than silently restoring the stale copy.
/// On the pre-#205 largest-suffix logic this would succeed (the rollback),
/// so this test also pins the security fix.
#[test]
fn restore_block_missing_signed_target_rejected() {
    let (dir, _mnemonic, pw) = make_fast_vault(10, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0xca; 32]);

    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let device_uuid = [0xda; 16];
    let block_uuid = [0xba; 16];
    let plaintext = make_simple_plaintext(block_uuid, "authentic");
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

    let trash_ts = 5_000u64;
    trash_block(
        folder,
        &mut open,
        block_uuid,
        device_uuid,
        trash_ts,
        &mut rng,
    )
    .unwrap();

    // Attacker renames the authentic file to a LARGER suffix, removing the
    // suffix == signed tombstoned_at_ms file. Only a non-matching (but
    // genuinely owner-signed) copy remains; the manifest's signed
    // TrashEntry still says tombstoned_at_ms = 5000.
    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    let trash_dir = folder.join("trash");
    let authentic = trash_dir.join(format!("{uuid_hex}.cbor.enc.{trash_ts}"));
    let planted = trash_dir.join(format!("{uuid_hex}.cbor.enc.9000"));
    fs::rename(&authentic, &planted).unwrap();

    let err = restore_block(folder, &mut open, block_uuid, device_uuid, 10_000, &mut rng)
        .expect_err("restore must reject when no file matches the signed timestamp");
    assert!(
        matches!(
            err,
            VaultError::RestoreTargetMissing { block_uuid: b, expected_tombstoned_at_ms }
                if b == block_uuid && expected_tombstoned_at_ms == trash_ts
        ),
        "expected RestoreTargetMissing {{ expected_tombstoned_at_ms: {trash_ts} }}, got {err:?}",
    );
    // Manifest untouched: the TrashEntry is still present, no live BlockEntry.
    assert!(
        open.manifest
            .trash
            .iter()
            .any(|t| t.block_uuid == block_uuid),
        "TrashEntry must remain after a rejected restore",
    );
    assert!(
        !open
            .manifest
            .blocks
            .iter()
            .any(|b| b.block_uuid == block_uuid),
        "no BlockEntry must be created on a rejected restore",
    );
}

/// #293: an attacker with write access to the synced trash/ folder overwrites
/// the suffix-matching file IN PLACE with a previously-retained, genuinely
/// owner-signed, OLDER copy of the same block_uuid. The §6.1 hybrid-verify
/// passes (authenticity != currency), and the suffix still equals the signed
/// tombstoned_at_ms — so #205's suffix-equality cannot defend it. The content
/// commitment in the signed TrashEntry rejects it: BLAKE3 of the stale bytes
/// != the committed fingerprint. On `main` (no commitment) this restore would
/// SUCCEED and resurrect the stale secret (the rollback this test pins shut).
#[test]
fn restore_block_rejects_in_place_overwrite_with_stale_signed_copy() {
    let (dir, _mnemonic, pw) = make_fast_vault(21, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x21; 32]);

    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let device_uuid = [0xd3; 16];
    let block_uuid = [0xb3; 16];
    let recipients = vec![open.owner_card.clone()];

    // First save: STALE content. Capture its valid owner-signed bytes.
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "stale-old-secret"),
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();
    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    let live_path = folder.join("blocks").join(format!("{uuid_hex}.cbor.enc"));
    let stale_bytes = fs::read(&live_path).unwrap();

    // Second save (update — same block_uuid): the AUTHENTIC-CURRENT content.
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "authentic-current-secret"),
        &recipients,
        device_uuid,
        2_000,
        &mut rng,
    )
    .unwrap();

    let trash_ts = 5_000u64;
    trash_block(
        folder,
        &mut open,
        block_uuid,
        device_uuid,
        trash_ts,
        &mut rng,
    )
    .unwrap();

    // The authentic-current envelope is at suffix == signed ts; the signed
    // TrashEntry commits to ITS fingerprint.
    let trash_dir = folder.join("trash");
    let authentic = trash_dir.join(format!("{uuid_hex}.cbor.enc.{trash_ts}"));
    let authentic_bytes = fs::read(&authentic).unwrap();
    assert_ne!(
        stale_bytes, authentic_bytes,
        "sanity: the two valid envelopes must differ in content",
    );

    // ATTACK: overwrite the suffix-matching file IN PLACE with the valid stale
    // envelope. Suffix unchanged (== signed ts); bytes are genuinely signed.
    fs::write(&authentic, &stale_bytes).unwrap();

    let err = restore_block(folder, &mut open, block_uuid, device_uuid, 10_000, &mut rng)
        .expect_err("restore must reject an in-place stale-content overwrite");
    assert!(
        matches!(
            &err,
            VaultError::RestoreVerificationFailed { block_uuid: b, detail }
                if *b == block_uuid && detail.contains("content commitment mismatch")
        ),
        "expected RestoreVerificationFailed(content commitment mismatch), got {err:?}",
    );
    // Manifest + trash untouched; no live block; nothing renamed into blocks/.
    assert!(
        open.manifest
            .trash
            .iter()
            .any(|t| t.block_uuid == block_uuid),
        "TrashEntry must remain after a rejected restore",
    );
    assert!(
        !open
            .manifest
            .blocks
            .iter()
            .any(|b| b.block_uuid == block_uuid),
        "no BlockEntry must be created on a rejected restore",
    );
    assert!(
        !live_path.exists(),
        "nothing must be renamed into blocks/ on a rejected restore",
    );
}

/// #293: a legacy TrashEntry (fingerprint None — trashed by a pre-#293 client)
/// must still restore via the #205 suffix-equality + §6.1 hybrid-verify path.
/// We simulate the legacy shape by nulling the in-memory committed fingerprint
/// (restore_block reads the commitment from the open, already-verified
/// manifest). The authentic file is unchanged, so restore succeeds.
#[test]
fn restore_block_legacy_entry_without_fingerprint_falls_back() {
    let (dir, _mnemonic, pw) = make_fast_vault(22, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x22; 32]);

    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let device_uuid = [0xd4; 16];
    let block_uuid = [0xb4; 16];
    let recipients = vec![open.owner_card.clone()];
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "secret"),
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();
    trash_block(folder, &mut open, block_uuid, device_uuid, 2_000, &mut rng).unwrap();

    // Simulate a legacy (pre-#293) signed TrashEntry: no content commitment.
    for t in &mut open.manifest.trash {
        if t.block_uuid == block_uuid {
            t.fingerprint = None;
        }
    }

    restore_block(folder, &mut open, block_uuid, device_uuid, 3_000, &mut rng)
        .expect("legacy (None-commitment) restore must succeed via suffix-equality");
    assert!(
        open.manifest
            .blocks
            .iter()
            .any(|b| b.block_uuid == block_uuid),
        "block must be live after legacy restore",
    );
    assert!(
        !open
            .manifest
            .trash
            .iter()
            .any(|t| t.block_uuid == block_uuid),
        "TrashEntry must be gone after legacy restore",
    );
}
