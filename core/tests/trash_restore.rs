//! Integration tests for `secretary_core::vault::trash_block` and
//! (in a later commit) `secretary_core::vault::restore_block` — Task B.5
//! of PR-B. The trash side moves a live block file into `trash/` with a
//! tombstone timestamp in the filename, removes the matching `BlockEntry`
//! from `manifest.blocks`, appends a `TrashEntry` to `manifest.trash`,
//! and re-signs the manifest. The §7 file-renaming semantics are atomic
//! per POSIX `rename(2)`.
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
use secretary_core::unlock::{create_vault_unchecked, mnemonic::Mnemonic, vault_toml};
use secretary_core::vault::{
    encode_manifest_file, open_vault, save_block, sign_manifest, trash_block, BlockPlaintext,
    KdfParamsRef, Manifest, ManifestHeader, Unlocker, VaultError,
};
use secretary_core::version::{FORMAT_VERSION, SUITE_ID};

// ---------------------------------------------------------------------------
// Fixture helpers (mirror save_block.rs / share_block.rs)
// ---------------------------------------------------------------------------

fn fast_kdf() -> Argon2idParams {
    Argon2idParams::new(8, 1, 1)
}

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
// trash_block — happy path
// ---------------------------------------------------------------------------

/// `trash_block` moves the block file into `trash/<uuid>.cbor.enc.<now_ms>`,
/// drops the matching `BlockEntry`, and appends a `TrashEntry`.
#[test]
fn trash_block_moves_file_and_updates_manifest() {
    let (dir, _mnemonic, pw) = make_fast_vault(1, b"hunter2", "Owner");
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
    let (dir, _mnemonic, pw) = make_fast_vault(2, b"hunter2", "Owner");
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
    let (dir, _mnemonic, pw) = make_fast_vault(3, b"hunter2", "Owner");
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
    let (dir, _mnemonic, pw) = make_fast_vault(4, b"hunter2", "Owner");
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
