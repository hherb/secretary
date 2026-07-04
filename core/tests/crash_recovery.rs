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
use secretary_core::unlock::{
    bundle::IdentityBundle, create_vault_unchecked, mnemonic::Mnemonic, vault_toml,
};
use secretary_core::vault::device_slot::add_device_slot;
use secretary_core::vault::{
    encode_manifest_file, open_vault, restore_block, save_block, share_block, sign_manifest,
    trash_block, BlockPlaintext, KdfParamsRef, Manifest, ManifestHeader, Unlocker, VaultError,
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

/// Build a co-recipient contact card from a freshly-generated identity
/// bundle. Copied verbatim from `trash_restore.rs::make_signed_card` per
/// this repo's no-shared-test-crate convention.
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

// ---------------------------------------------------------------------------
// repair_vault — #350 save_block / re-key crash residue
// ---------------------------------------------------------------------------

/// #350 happy path: a save_block update whose manifest write was lost
/// (crash simulated by restoring the pre-save manifest bytes) makes
/// open_vault fail BlockFingerprintMismatch; repair_vault adopts the
/// newer owner-signed block, rebuilds the entry, and returns a live
/// OpenVault; a subsequent open_vault is green.
#[test]
fn repair_vault_adopts_interrupted_save() {
    let (dir, _mnemonic, pw) = make_fast_vault(61, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x61; 32]);
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let (device_uuid, block_uuid) = ([0xda; 16], [0xba; 16]);
    let recipients = vec![open.owner_card.clone()];
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "v1"),
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();
    let manifest_v1 = fs::read(folder.join("manifest.cbor.enc")).unwrap();
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "v2"),
        &recipients,
        device_uuid,
        2_000,
        &mut rng,
    )
    .unwrap();
    drop(open);
    // Crash simulation: the v2 block hit disk, the v2 manifest didn't.
    fs::write(folder.join("manifest.cbor.enc"), &manifest_v1).unwrap();

    let err =
        open_vault(folder, Unlocker::Password(&pw), None).expect_err("residue must fail open");
    assert!(
        matches!(err, VaultError::BlockFingerprintMismatch { block_uuid: b, .. } if b == block_uuid),
        "got {err:?}"
    );

    let repaired = secretary_core::vault::repair_vault(
        folder,
        Unlocker::Password(&pw),
        |_| Ok(None),
        device_uuid,
        3_000,
        &mut rng,
    )
    .expect("gated adoption must succeed on genuine crash residue");

    let entry = repaired
        .manifest
        .blocks
        .iter()
        .find(|b| b.block_uuid == block_uuid)
        .expect("entry present");
    assert_eq!(
        entry.block_name, "v2",
        "adopted entry carries the on-disk content"
    );
    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    let disk = fs::read(folder.join("blocks").join(format!("{uuid_hex}.cbor.enc"))).unwrap();
    assert_eq!(
        entry.fingerprint,
        *secretary_core::crypto::hash::hash(&disk).as_bytes()
    );
    // Block clock adopted verbatim: device ticked twice (v1 + v2).
    assert_eq!(entry.vector_clock_summary.len(), 1);
    assert_eq!(entry.vector_clock_summary[0].counter, 2);
    drop(repaired);

    open_vault(folder, Unlocker::Password(&pw), None).expect("vault must be healthy after repair");
}

/// #374 part 4: the crash-recovery adopt path must go through the SAME gated
/// adoption when the vault is unlocked via `Unlocker::DeviceSecret` (ADR 0009),
/// not only via password. Previously the device arm was covered only
/// transitively through the shared `unlock_vault_identity`; this pins it
/// end-to-end (device unlock is not a weaker open, per B.2 orchestrators).
#[test]
fn repair_vault_adopts_interrupted_save_via_device_secret() {
    let (dir, _mnemonic, pw) = make_fast_vault(0x37, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x37; 32]);

    // Enroll a device slot so the vault can be opened without the password.
    let enrolled = add_device_slot(folder, &pw, &mut rng).expect("enroll device slot");
    let dev_unlocker = || Unlocker::DeviceSecret {
        device_uuid: &enrolled.device_uuid,
        secret: &enrolled.device_secret,
    };

    // Stage a crashed save: v2 block on disk, v1 manifest committed.
    let mut open = open_vault(folder, dev_unlocker(), None).unwrap();
    let (writer_device_uuid, block_uuid) = ([0xda; 16], [0xba; 16]);
    let recipients = vec![open.owner_card.clone()];
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "v1"),
        &recipients,
        writer_device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();
    let manifest_v1 = fs::read(folder.join("manifest.cbor.enc")).unwrap();
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "v2"),
        &recipients,
        writer_device_uuid,
        2_000,
        &mut rng,
    )
    .unwrap();
    drop(open);
    fs::write(folder.join("manifest.cbor.enc"), &manifest_v1).unwrap();

    // Open via the device secret must fail typed on the residue.
    let err = open_vault(folder, dev_unlocker(), None).expect_err("residue must fail open");
    assert!(
        matches!(err, VaultError::BlockFingerprintMismatch { block_uuid: b, .. } if b == block_uuid),
        "got {err:?}"
    );

    // Repair via the device secret must adopt the on-disk v2 (same gate).
    let repaired = secretary_core::vault::repair_vault(
        folder,
        dev_unlocker(),
        |_| Ok(None),
        enrolled.device_uuid,
        3_000,
        &mut rng,
    )
    .expect("gated adoption must succeed via device secret");

    let entry = repaired
        .manifest
        .blocks
        .iter()
        .find(|b| b.block_uuid == block_uuid)
        .expect("entry present");
    assert_eq!(
        entry.block_name, "v2",
        "adopted entry carries on-disk content"
    );
    assert_eq!(entry.vector_clock_summary[0].counter, 2);
    drop(repaired);

    open_vault(folder, dev_unlocker(), None).expect("healthy after device-secret repair");
}

/// #350: a crashed revocation re-key repairs to the REDUCED recipient
/// set (the on-disk §6.2 table), not the stale manifest one.
#[test]
fn repair_vault_adopts_interrupted_revocation() {
    let (dir, _mnemonic, pw) = make_fast_vault(62, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x62; 32]);
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let (device_uuid, block_uuid) = ([0xdb; 16], [0xbb; 16]);

    // Co-recipient B: mint an identity bundle, write its card to
    // contacts/ (pattern from core/tests/revoke_block.rs).
    let mut rng_b = ChaCha20Rng::from_seed([0x63; 32]);
    let id_b = secretary_core::unlock::bundle::generate("Bee", 1_714_060_800_000, &mut rng_b);
    let card_b = make_signed_card(&id_b);
    let card_b_bytes = card_b.to_canonical_cbor().unwrap();
    fs::write(
        folder.join("contacts").join(format!(
            "{}.card",
            format_uuid_hyphenated(&card_b.contact_uuid)
        )),
        &card_b_bytes,
    )
    .unwrap();

    let recipients = vec![open.owner_card.clone(), card_b.clone()];
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "shared"),
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();
    let manifest_pre = fs::read(folder.join("manifest.cbor.enc")).unwrap();

    let author_card = open.owner_card.clone();
    let author_sk_ed: secretary_core::crypto::sig::Ed25519Secret =
        secretary_core::crypto::secret::Sensitive::new(*open.identity.ed25519_sk.expose());
    let author_sk_pq = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).unwrap();
    secretary_core::vault::revoke_block_recipient(
        folder,
        &mut open,
        secretary_core::vault::BlockUuid::new(block_uuid),
        &author_card,
        &author_sk_ed,
        &author_sk_pq,
        &recipients,
        secretary_core::vault::RecipientUuid::new(card_b.contact_uuid),
        secretary_core::vault::DeviceUuid::new(device_uuid),
        2_000,
        &mut rng,
    )
    .unwrap();
    drop(open);
    fs::write(folder.join("manifest.cbor.enc"), &manifest_pre).unwrap();

    let repaired = secretary_core::vault::repair_vault(
        folder,
        Unlocker::Password(&pw),
        |_| Ok(None),
        device_uuid,
        3_000,
        &mut rng,
    )
    .unwrap();
    let entry = repaired
        .manifest
        .blocks
        .iter()
        .find(|b| b.block_uuid == block_uuid)
        .unwrap();
    assert_eq!(entry.recipients.len(), 1, "revoked recipient must be gone");
    assert_eq!(entry.recipients[0], repaired.owner_card.contact_uuid);
}

/// #350 security: Gate 3's `ClockRelation::Equal` branch (needed because
/// `rewrite_block_with_recipients` deliberately preserves the block-level
/// vector clock across a content-preserving re-key) must NOT let an
/// attacker with `blocks/` write access (but no keys) resurrect a
/// revoked recipient's access by replaying the pre-revocation,
/// genuinely-owner-signed block bytes over the post-revocation live
/// file. Same vector clock either way (revoke never ticks it) — under
/// the subset-only rule the replayed set {owner, B} would ADD B relative
/// to the committed {owner}, so adoption is refused (re-granting access
/// is never automatic). `repair_vault` must reject, and — all-or-nothing
/// — leave the attacker-planted disk state and the manifest untouched.
#[test]
fn repair_rejects_stale_equal_clock_replay() {
    let (dir, _mnemonic, pw) = make_fast_vault(64, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x64; 32]);
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let (device_uuid, block_uuid) = ([0xdc; 16], [0xbc; 16]);

    let mut rng_b = ChaCha20Rng::from_seed([0x65; 32]);
    let id_b = secretary_core::unlock::bundle::generate("Bee", 1_714_060_800_000, &mut rng_b);
    let card_b = make_signed_card(&id_b);
    let card_b_bytes = card_b.to_canonical_cbor().unwrap();
    fs::write(
        folder.join("contacts").join(format!(
            "{}.card",
            format_uuid_hyphenated(&card_b.contact_uuid)
        )),
        &card_b_bytes,
    )
    .unwrap();

    let recipients = vec![open.owner_card.clone(), card_b.clone()];
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "shared"),
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();
    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    let block_path = folder.join("blocks").join(format!("{uuid_hex}.cbor.enc"));
    // Genuinely owner-signed pre-revocation bytes (recipients = [owner, B]).
    let pre_revoke_block_bytes = fs::read(&block_path).unwrap();

    let author_card = open.owner_card.clone();
    let author_sk_ed: secretary_core::crypto::sig::Ed25519Secret =
        secretary_core::crypto::secret::Sensitive::new(*open.identity.ed25519_sk.expose());
    let author_sk_pq = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).unwrap();
    secretary_core::vault::revoke_block_recipient(
        folder,
        &mut open,
        secretary_core::vault::BlockUuid::new(block_uuid),
        &author_card,
        &author_sk_ed,
        &author_sk_pq,
        &recipients,
        secretary_core::vault::RecipientUuid::new(card_b.contact_uuid),
        secretary_core::vault::DeviceUuid::new(device_uuid),
        2_000,
        &mut rng,
    )
    .unwrap();
    drop(open);

    // Attack: revoke_block_recipient completed cleanly (manifest + block
    // file both reflect the post-revocation state). Now replay the
    // pre-revocation block bytes over the live file — same block-level
    // vector clock (revoke never ticks it), older last_mod_ms.
    let manifest_post = fs::read(folder.join("manifest.cbor.enc")).unwrap();
    fs::write(&block_path, &pre_revoke_block_bytes).unwrap();

    let err = open_vault(folder, Unlocker::Password(&pw), None)
        .expect_err("planted stale block must fail open");
    assert!(
        matches!(err, VaultError::BlockFingerprintMismatch { block_uuid: b, .. } if b == block_uuid),
        "got {err:?}"
    );

    let err = secretary_core::vault::repair_vault(
        folder,
        Unlocker::Password(&pw),
        |_| Ok(None),
        device_uuid,
        3_000,
        &mut rng,
    )
    .expect_err("stale equal-clock replay must NOT be adopted");
    assert!(
        matches!(&err, VaultError::RepairRejected { block_uuid: b, .. } if *b == block_uuid),
        "got {err:?}"
    );
    // The reject must ride the subset-only rule's ADD branch: the replay
    // would re-grant B relative to the committed post-revocation set.
    let msg = err.to_string();
    assert!(msg.contains("would ADD recipients"), "got: {msg}");
    assert!(
        msg.contains(&format_uuid_hyphenated(&card_b.contact_uuid)),
        "added-recipient uuid must be named: {msg}"
    );

    // All-or-nothing: the manifest must be byte-identical to the
    // post-revocation state (repair wrote nothing), and the
    // attacker-planted block bytes must still be on disk (repair adopts
    // nothing, purges nothing).
    assert_eq!(
        fs::read(folder.join("manifest.cbor.enc")).unwrap(),
        manifest_post,
        "rejected repair must not touch the manifest"
    );
    assert_eq!(
        fs::read(&block_path).unwrap(),
        pre_revoke_block_bytes,
        "rejected repair must not touch blocks/"
    );
}

/// #350 security — the 2026-07 review exploit against the retired
/// `last_mod_ms` discriminator. `last_mod_ms` is caller wall-clock with
/// no monotonicity guard, so a later legitimate operation can commit
/// with an EARLIER stamp (backward clock step): save {owner, B} → share
/// C at now=3000 (attacker retains the owner-signed bytes) → revoke B
/// at now=2000. The retained share-C bytes then carry the same block
/// clock as the committed entry (re-keys never tick it) AND a larger
/// `last_mod_ms` (3000 > 2000) — a timestamp gate would adopt them and
/// re-grant the revoked B. The subset-only rule must reject instead:
/// {owner, B, C} is not a subset of the committed {owner, C}.
#[test]
fn repair_rejects_backward_clock_share_replay() {
    let (dir, _mnemonic, pw) = make_fast_vault(65, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x71; 32]);
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let (device_uuid, block_uuid) = ([0xdd; 16], [0xbd; 16]);

    let mut rng_b = ChaCha20Rng::from_seed([0x72; 32]);
    let id_b = secretary_core::unlock::bundle::generate("Bee", 1_714_060_800_000, &mut rng_b);
    let card_b = make_signed_card(&id_b);
    fs::write(
        folder.join("contacts").join(format!(
            "{}.card",
            format_uuid_hyphenated(&card_b.contact_uuid)
        )),
        card_b.to_canonical_cbor().unwrap(),
    )
    .unwrap();
    let mut rng_c = ChaCha20Rng::from_seed([0x73; 32]);
    let id_c = secretary_core::unlock::bundle::generate("Cee", 1_714_060_800_000, &mut rng_c);
    let card_c = make_signed_card(&id_c);

    let recipients = vec![open.owner_card.clone(), card_b.clone()];
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "shared"),
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();

    let author_card = open.owner_card.clone();
    let author_sk_ed: secretary_core::crypto::sig::Ed25519Secret =
        secretary_core::crypto::secret::Sensitive::new(*open.identity.ed25519_sk.expose());
    let author_sk_pq = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).unwrap();

    // Share C at now=3000 (share_block persists C's card to contacts/).
    share_block(
        folder,
        &mut open,
        secretary_core::vault::BlockUuid::new(block_uuid),
        &author_card,
        &author_sk_ed,
        &author_sk_pq,
        &recipients,
        &card_c,
        secretary_core::vault::DeviceUuid::new(device_uuid),
        3_000,
        &mut rng,
    )
    .unwrap();
    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    let block_path = folder.join("blocks").join(format!("{uuid_hex}.cbor.enc"));
    // Attacker retains the owner-signed share-C generation ({owner,B,C},
    // last_mod_ms = 3000).
    let share_c_bytes = fs::read(&block_path).unwrap();

    // Revoke B at now=2000 — a backward wall-clock step relative to the
    // share. Committed set becomes {owner, C}.
    let all_cards = vec![open.owner_card.clone(), card_b.clone(), card_c.clone()];
    secretary_core::vault::revoke_block_recipient(
        folder,
        &mut open,
        secretary_core::vault::BlockUuid::new(block_uuid),
        &author_card,
        &author_sk_ed,
        &author_sk_pq,
        &all_cards,
        secretary_core::vault::RecipientUuid::new(card_b.contact_uuid),
        secretary_core::vault::DeviceUuid::new(device_uuid),
        2_000,
        &mut rng,
    )
    .unwrap();
    drop(open);

    let manifest_post = fs::read(folder.join("manifest.cbor.enc")).unwrap();
    fs::write(&block_path, &share_c_bytes).unwrap();

    let err = open_vault(folder, Unlocker::Password(&pw), None)
        .expect_err("planted share-generation bytes must fail open");
    assert!(
        matches!(err, VaultError::BlockFingerprintMismatch { block_uuid: b, .. } if b == block_uuid),
        "got {err:?}"
    );

    let err = secretary_core::vault::repair_vault(
        folder,
        Unlocker::Password(&pw),
        |_| Ok(None),
        device_uuid,
        4_000,
        &mut rng,
    )
    .expect_err("equal-clock superset replay must NOT be adopted, whatever its last_mod_ms");
    assert!(
        matches!(&err, VaultError::RepairRejected { block_uuid: b, .. } if *b == block_uuid),
        "got {err:?}"
    );
    let msg = err.to_string();
    assert!(msg.contains("would ADD recipients"), "got: {msg}");
    assert!(
        msg.contains(&format_uuid_hyphenated(&card_b.contact_uuid)),
        "the re-granted recipient must be named: {msg}"
    );

    assert_eq!(
        fs::read(folder.join("manifest.cbor.enc")).unwrap(),
        manifest_post,
        "rejected repair must not touch the manifest"
    );
    assert_eq!(
        fs::read(&block_path).unwrap(),
        share_c_bytes,
        "rejected repair must not touch blocks/"
    );
}

/// #350 documented limitation: the residue of a genuinely crashed
/// `share_block` (block written with the superset, manifest write lost)
/// is NOT auto-adopted — access widening requires the informed-consent
/// path that ships with the FFI projection. The rejection `detail` must
/// name the recipients the adoption would add.
#[test]
fn repair_rejects_crashed_share_superset() {
    let (dir, _mnemonic, pw) = make_fast_vault(66, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x74; 32]);
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let (device_uuid, block_uuid) = ([0xde; 16], [0xbe; 16]);

    let mut rng_c = ChaCha20Rng::from_seed([0x75; 32]);
    let id_c = secretary_core::unlock::bundle::generate("Cee", 1_714_060_800_000, &mut rng_c);
    let card_c = make_signed_card(&id_c);

    let recipients = vec![open.owner_card.clone()];
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "mine"),
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();
    let manifest_pre_share = fs::read(folder.join("manifest.cbor.enc")).unwrap();

    let author_card = open.owner_card.clone();
    let author_sk_ed: secretary_core::crypto::sig::Ed25519Secret =
        secretary_core::crypto::secret::Sensitive::new(*open.identity.ed25519_sk.expose());
    let author_sk_pq = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).unwrap();
    share_block(
        folder,
        &mut open,
        secretary_core::vault::BlockUuid::new(block_uuid),
        &author_card,
        &author_sk_ed,
        &author_sk_pq,
        &recipients,
        &card_c,
        secretary_core::vault::DeviceUuid::new(device_uuid),
        2_000,
        &mut rng,
    )
    .unwrap();
    drop(open);
    // Crash simulation: the {owner, C} block hit disk, the manifest
    // write was lost.
    fs::write(folder.join("manifest.cbor.enc"), &manifest_pre_share).unwrap();

    let err = secretary_core::vault::repair_vault(
        folder,
        Unlocker::Password(&pw),
        |_| Ok(None),
        device_uuid,
        3_000,
        &mut rng,
    )
    .expect_err("crashed-share superset must be refused (documented limitation)");
    assert!(
        matches!(&err, VaultError::RepairRejected { block_uuid: b, .. } if *b == block_uuid),
        "got {err:?}"
    );
    let msg = err.to_string();
    assert!(msg.contains("would ADD recipients"), "got: {msg}");
    assert!(
        msg.contains(&format_uuid_hyphenated(&card_c.contact_uuid)),
        "the would-be-added recipient must be named: {msg}"
    );
    assert_eq!(
        fs::read(folder.join("manifest.cbor.enc")).unwrap(),
        manifest_pre_share,
        "rejected repair must not touch the manifest"
    );
}

/// #350 security: an equal-clock plant whose recipient set EQUALS the
/// committed one (but with different bytes) matches no legitimate
/// crashed operation — a real crashed re-key always changes the set.
/// Strict subset means subset AND not equal, so this forgery/stale-
/// replay shape is refused. Construction: save {owner, B} (retain the
/// bytes) → share C → revoke C. Both the retained generation and the
/// committed one carry {owner, B} at the same block clock, but the
/// bytes differ (each re-key rotates the BCK, nonce, and signature).
#[test]
fn repair_rejects_equal_set_different_bytes() {
    let (dir, _mnemonic, pw) = make_fast_vault(67, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x76; 32]);
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let (device_uuid, block_uuid) = ([0xdf; 16], [0xbf; 16]);

    let mut rng_b = ChaCha20Rng::from_seed([0x77; 32]);
    let id_b = secretary_core::unlock::bundle::generate("Bee", 1_714_060_800_000, &mut rng_b);
    let card_b = make_signed_card(&id_b);
    fs::write(
        folder.join("contacts").join(format!(
            "{}.card",
            format_uuid_hyphenated(&card_b.contact_uuid)
        )),
        card_b.to_canonical_cbor().unwrap(),
    )
    .unwrap();
    let mut rng_c = ChaCha20Rng::from_seed([0x78; 32]);
    let id_c = secretary_core::unlock::bundle::generate("Cee", 1_714_060_800_000, &mut rng_c);
    let card_c = make_signed_card(&id_c);

    let recipients = vec![open.owner_card.clone(), card_b.clone()];
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "shared"),
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();
    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    let block_path = folder.join("blocks").join(format!("{uuid_hex}.cbor.enc"));
    // Retained generation: {owner, B} — same set the manifest will end
    // up committing again after share C → revoke C.
    let save_gen_bytes = fs::read(&block_path).unwrap();

    let author_card = open.owner_card.clone();
    let author_sk_ed: secretary_core::crypto::sig::Ed25519Secret =
        secretary_core::crypto::secret::Sensitive::new(*open.identity.ed25519_sk.expose());
    let author_sk_pq = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).unwrap();
    share_block(
        folder,
        &mut open,
        secretary_core::vault::BlockUuid::new(block_uuid),
        &author_card,
        &author_sk_ed,
        &author_sk_pq,
        &recipients,
        &card_c,
        secretary_core::vault::DeviceUuid::new(device_uuid),
        2_000,
        &mut rng,
    )
    .unwrap();
    let all_cards = vec![open.owner_card.clone(), card_b.clone(), card_c.clone()];
    secretary_core::vault::revoke_block_recipient(
        folder,
        &mut open,
        secretary_core::vault::BlockUuid::new(block_uuid),
        &author_card,
        &author_sk_ed,
        &author_sk_pq,
        &all_cards,
        secretary_core::vault::RecipientUuid::new(card_c.contact_uuid),
        secretary_core::vault::DeviceUuid::new(device_uuid),
        3_000,
        &mut rng,
    )
    .unwrap();
    drop(open);

    let manifest_post = fs::read(folder.join("manifest.cbor.enc")).unwrap();
    let committed_bytes = fs::read(&block_path).unwrap();
    assert_ne!(
        save_gen_bytes, committed_bytes,
        "re-keys must have rotated the bytes for this test to be meaningful"
    );
    fs::write(&block_path, &save_gen_bytes).unwrap();

    let err = secretary_core::vault::repair_vault(
        folder,
        Unlocker::Password(&pw),
        |_| Ok(None),
        device_uuid,
        4_000,
        &mut rng,
    )
    .expect_err("equal-set different-bytes plant must NOT be adopted");
    assert!(
        matches!(&err, VaultError::RepairRejected { block_uuid: b, .. } if *b == block_uuid),
        "got {err:?}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("recipient set unchanged"),
        "must ride the equal-set reject branch: {msg}"
    );
    assert_eq!(
        fs::read(folder.join("manifest.cbor.enc")).unwrap(),
        manifest_post,
        "rejected repair must not touch the manifest"
    );
}

/// #350 security (regression for the review finding on PR #375): the
/// recipient-widening refusal is CROSS-CUTTING — it must fire even when
/// the on-disk block's clock strictly DOMINATES the committed entry, not
/// only in the equal-clock tier. A revoke is invisible to the block
/// clock (re-keys preserve it), so a planted owner-signed content-save
/// carrying a pre-revocation recipient set can dominate a committed
/// post-revoke entry. If the widening guard were Equal-only, that plant
/// would re-grant the revoked recipient. Construction (single replica,
/// two device ids): save {owner, B} on D1 (clock {D1:1}); revoke B on D1
/// (committed → {owner}, clock preserved {D1:1}); then a fresh content
/// save on D2 re-encrypts to {owner, B} and ticks the block clock to
/// {D1:1, D2:1} — this owner-signed generation both DOMINATES the
/// committed {D1:1} AND widens {owner} back to {owner, B}. Planting it
/// must be refused with "would ADD recipients".
#[test]
fn repair_rejects_dominating_clock_recipient_widening() {
    let (dir, _mnemonic, pw) = make_fast_vault(68, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x79; 32]);
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let (device_1, device_2, block_uuid) = ([0xd1; 16], [0xd2; 16], [0xba; 16]);

    let mut rng_b = ChaCha20Rng::from_seed([0x7a; 32]);
    let id_b = secretary_core::unlock::bundle::generate("Bee", 1_714_060_800_000, &mut rng_b);
    let card_b = make_signed_card(&id_b);
    fs::write(
        folder.join("contacts").join(format!(
            "{}.card",
            format_uuid_hyphenated(&card_b.contact_uuid)
        )),
        card_b.to_canonical_cbor().unwrap(),
    )
    .unwrap();

    // save {owner, B} on device D1 → block clock {D1:1}.
    let recipients = vec![open.owner_card.clone(), card_b.clone()];
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "shared"),
        &recipients,
        device_1,
        1_000,
        &mut rng,
    )
    .unwrap();

    let author_card = open.owner_card.clone();
    let author_sk_ed: secretary_core::crypto::sig::Ed25519Secret =
        secretary_core::crypto::secret::Sensitive::new(*open.identity.ed25519_sk.expose());
    let author_sk_pq = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).unwrap();

    // Revoke B on D1 → committed {owner}, block clock preserved {D1:1}.
    let all_cards = vec![open.owner_card.clone(), card_b.clone()];
    secretary_core::vault::revoke_block_recipient(
        folder,
        &mut open,
        secretary_core::vault::BlockUuid::new(block_uuid),
        &author_card,
        &author_sk_ed,
        &author_sk_pq,
        &all_cards,
        secretary_core::vault::RecipientUuid::new(card_b.contact_uuid),
        secretary_core::vault::DeviceUuid::new(device_1),
        2_000,
        &mut rng,
    )
    .unwrap();
    // Snapshot the committed post-revoke state: {owner} at block clock
    // {D1:1}. This is what the plant must be judged against.
    let manifest_committed = fs::read(folder.join("manifest.cbor.enc")).unwrap();

    // Mint the DOMINATING wide generation: a content save on a second
    // device D2 re-encrypting to {owner, B} ticks the block clock to
    // {D1:1, D2:1} (dominates the committed {D1:1}).
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "edited-elsewhere"),
        &recipients,
        device_2,
        3_000,
        &mut rng,
    )
    .unwrap();
    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    let block_path = folder.join("blocks").join(format!("{uuid_hex}.cbor.enc"));
    let dominating_wide_bytes = fs::read(&block_path).unwrap();
    drop(open);

    // Roll the manifest back to the committed post-revoke state and plant
    // the dominating {owner, B} generation over the block file.
    fs::write(folder.join("manifest.cbor.enc"), &manifest_committed).unwrap();
    fs::write(&block_path, &dominating_wide_bytes).unwrap();

    // open_vault refuses (fingerprint mismatch), as for any residue.
    let err = open_vault(folder, Unlocker::Password(&pw), None)
        .expect_err("planted dominating widening bytes must fail open");
    assert!(
        matches!(err, VaultError::BlockFingerprintMismatch { block_uuid: b, .. } if b == block_uuid),
        "got {err:?}"
    );

    // repair_vault must REFUSE — dominance does not license widening.
    let err = secretary_core::vault::repair_vault(
        folder,
        Unlocker::Password(&pw),
        |_| Ok(None),
        device_1,
        4_000,
        &mut rng,
    )
    .expect_err("a dominating clock must NOT license a recipient widening");
    assert!(
        matches!(&err, VaultError::RepairRejected { block_uuid: b, .. } if *b == block_uuid),
        "got {err:?}"
    );
    let msg = err.to_string();
    assert!(msg.contains("would ADD recipients"), "got: {msg}");
    assert!(
        msg.contains(&format_uuid_hyphenated(&card_b.contact_uuid)),
        "the re-granted recipient must be named: {msg}"
    );
    assert_eq!(
        fs::read(folder.join("manifest.cbor.enc")).unwrap(),
        manifest_committed,
        "rejected repair must not touch the manifest"
    );
    assert_eq!(
        fs::read(&block_path).unwrap(),
        dominating_wide_bytes,
        "rejected repair must not touch blocks/"
    );
}

// ---------------------------------------------------------------------------
// repair_vault — #350 review-followup gates: rollback, concurrent, missing,
// idempotence
// ---------------------------------------------------------------------------

/// Minimal recursive dir copy for vault-state forking (see #186 for the
/// planned shared helper; kept local per test-crate convention).
fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let target = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir_recursive(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// #350 gate: a genuinely owner-signed but OLDER block copy planted
/// over the live file is a rollback, not crash residue — clock
/// dominated → RepairRejected, and the manifest is untouched.
#[test]
fn repair_vault_rejects_rollback_plant() {
    let (dir, _mnemonic, pw) = make_fast_vault(71, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x71; 32]);
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let (device_uuid, block_uuid) = ([0xdc; 16], [0xbc; 16]);
    let recipients = vec![open.owner_card.clone()];
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "v1"),
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();
    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    let block_path = folder.join("blocks").join(format!("{uuid_hex}.cbor.enc"));
    let v1_bytes = fs::read(&block_path).unwrap();
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "v2"),
        &recipients,
        device_uuid,
        2_000,
        &mut rng,
    )
    .unwrap();
    drop(open);
    fs::write(&block_path, &v1_bytes).unwrap(); // the rollback plant
    let manifest_before = fs::read(folder.join("manifest.cbor.enc")).unwrap();

    let err = secretary_core::vault::repair_vault(
        folder,
        Unlocker::Password(&pw),
        |_| Ok(None),
        device_uuid,
        3_000,
        &mut rng,
    )
    .expect_err("rollback must be refused");
    assert!(
        matches!(err, VaultError::RepairRejected { block_uuid: b, ref detail }
                 if b == block_uuid && detail.contains("clock relation")),
        "got {err:?}"
    );
    assert_eq!(
        fs::read(folder.join("manifest.cbor.enc")).unwrap(),
        manifest_before,
        "all-or-nothing: rejected repair must not write the manifest"
    );
}

/// #350 gate: fork the vault pre-save, save independently in the fork
/// under a DIFFERENT device, transplant the fork's block file — the
/// concurrent clock ({A:1} committed vs {B:1} on disk) must be refused.
/// (The same-device fork — Equal clock, same recipient set, different
/// bytes — is already pinned by `repair_rejects_equal_set_different_bytes`
/// from the Task 6 review fix; do not duplicate it.)
#[test]
fn repair_vault_rejects_concurrent_clock_transplant() {
    let (dir, _mnemonic, pw) = make_fast_vault(72, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x72; 32]);
    let (device_a, device_b, block_uuid) = ([0xaa; 16], [0xbb; 16], [0xbd; 16]);
    let uuid_hex = format_uuid_hyphenated(&block_uuid);

    // Fork BEFORE the block exists.
    let fork = tempfile::tempdir().unwrap();
    copy_dir_recursive(folder, fork.path());

    // Main: save under device A → manifest summary {A:1}.
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let recipients = vec![open.owner_card.clone()];
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "main"),
        &recipients,
        device_a,
        1_000,
        &mut rng,
    )
    .unwrap();
    drop(open);
    let block_path = folder.join("blocks").join(format!("{uuid_hex}.cbor.enc"));

    // Fork: save the same uuid under device B → block clock {B:1}.
    let mut rng_f = ChaCha20Rng::from_seed([0x73; 32]);
    let mut open_f = open_vault(fork.path(), Unlocker::Password(&pw), None).unwrap();
    let recip_f = vec![open_f.owner_card.clone()];
    save_block(
        fork.path(),
        &mut open_f,
        make_simple_plaintext(block_uuid, "fork"),
        &recip_f,
        device_b,
        1_500,
        &mut rng_f,
    )
    .unwrap();
    drop(open_f);
    // Transplant: same owner, same vault_uuid, different bytes.
    fs::copy(
        fork.path()
            .join("blocks")
            .join(format!("{uuid_hex}.cbor.enc")),
        &block_path,
    )
    .unwrap();

    let err = secretary_core::vault::repair_vault(
        folder,
        Unlocker::Password(&pw),
        |_| Ok(None),
        device_a,
        3_000,
        &mut rng,
    )
    .expect_err("concurrent clock must be refused");
    assert!(
        matches!(err, VaultError::RepairRejected { ref detail, .. } if detail.contains("Concurrent")),
        "expected Concurrent rejection, got {err:?}"
    );
}

/// #350: a listed block whose file is simply GONE is not repairable —
/// typed BlockFileMissing from open_vault AND repair_vault.
#[test]
fn missing_block_file_is_typed_and_unrepairable() {
    let (dir, _mnemonic, pw) = make_fast_vault(73, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x74; 32]);
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let (device_uuid, block_uuid) = ([0xde; 16], [0xbe; 16]);
    let recipients = vec![open.owner_card.clone()];
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "gone"),
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();
    drop(open);
    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    fs::remove_file(folder.join("blocks").join(format!("{uuid_hex}.cbor.enc"))).unwrap();

    let e1 = open_vault(folder, Unlocker::Password(&pw), None).expect_err("open");
    assert!(
        matches!(e1, VaultError::BlockFileMissing { block_uuid: b } if b == block_uuid),
        "got {e1:?}"
    );
    let e2 = secretary_core::vault::repair_vault(
        folder,
        Unlocker::Password(&pw),
        |_| Ok(None),
        device_uuid,
        2_000,
        &mut rng,
    )
    .expect_err("repair cannot invent bytes");
    assert!(
        matches!(e2, VaultError::BlockFileMissing { block_uuid: b } if b == block_uuid),
        "got {e2:?}"
    );
}

/// #350: repair_vault on a healthy vault is a plain open — nothing
/// written (manifest bytes byte-identical).
#[test]
fn repair_vault_is_idempotent_on_healthy_vault() {
    let (dir, _mnemonic, pw) = make_fast_vault(74, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x75; 32]);
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let (device_uuid, block_uuid) = ([0xdf; 16], [0xbf; 16]);
    let recipients = vec![open.owner_card.clone()];
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "healthy"),
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();
    drop(open);
    let before = fs::read(folder.join("manifest.cbor.enc")).unwrap();

    let repaired = secretary_core::vault::repair_vault(
        folder,
        Unlocker::Password(&pw),
        |_| Ok(None),
        device_uuid,
        2_000,
        &mut rng,
    )
    .expect("healthy vault must open through repair");
    assert!(repaired
        .manifest
        .blocks
        .iter()
        .any(|b| b.block_uuid == block_uuid));
    drop(repaired);
    assert_eq!(
        fs::read(folder.join("manifest.cbor.enc")).unwrap(),
        before,
        "healthy repair must not rewrite the manifest"
    );
}

/// #384: the §10 baseline provider must be invoked with the VERIFIED
/// manifest `vault_uuid` (available only after hybrid-verify + AEAD
/// decrypt) — never a plaintext-derived value. Pins the keying half of
/// the #384 hardening at the core seam.
#[test]
fn repair_passes_verified_manifest_uuid_to_baseline_provider() {
    let (dir, _mnemonic, pw) = make_fast_vault(71, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x71; 32]);
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let expected_uuid = open.manifest.vault_uuid;
    let (device_uuid, block_uuid) = ([0xd1; 16], [0xb1; 16]);
    let recipients = vec![open.owner_card.clone()];
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "v1"),
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();
    let manifest_v1 = fs::read(folder.join("manifest.cbor.enc")).unwrap();
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "v2"),
        &recipients,
        device_uuid,
        2_000,
        &mut rng,
    )
    .unwrap();
    drop(open);
    // Crash simulation: the v2 block hit disk, the v2 manifest didn't.
    fs::write(folder.join("manifest.cbor.enc"), &manifest_v1).unwrap();

    let mut seen: Option<[u8; 16]> = None;
    let repaired = secretary_core::vault::repair_vault(
        folder,
        Unlocker::Password(&pw),
        |uuid: &[u8; 16]| {
            seen = Some(*uuid);
            Ok(None)
        },
        device_uuid,
        3_000,
        &mut rng,
    )
    .expect("adoptable residue with an empty baseline must repair");
    drop(repaired);
    assert_eq!(
        seen,
        Some(expected_uuid),
        "provider must be keyed by the verified manifest vault_uuid"
    );
}

/// #384: a baseline-provider error must abort the repair FAIL-CLOSED —
/// propagated before anything is staged or written. Pins the posture
/// half of the #384 hardening at the core seam (the bridge maps its
/// state-store failures onto exactly this contract).
#[test]
fn repair_aborts_when_baseline_provider_errors() {
    let (dir, _mnemonic, pw) = make_fast_vault(72, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x72; 32]);
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let (device_uuid, block_uuid) = ([0xd2; 16], [0xb2; 16]);
    let recipients = vec![open.owner_card.clone()];
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "v1"),
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();
    let manifest_v1 = fs::read(folder.join("manifest.cbor.enc")).unwrap();
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "v2"),
        &recipients,
        device_uuid,
        2_000,
        &mut rng,
    )
    .unwrap();
    drop(open);
    fs::write(folder.join("manifest.cbor.enc"), &manifest_v1).unwrap();

    let before = fs::read(folder.join("manifest.cbor.enc")).unwrap();
    let err = secretary_core::vault::repair_vault(
        folder,
        Unlocker::Password(&pw),
        |_: &[u8; 16]| {
            Err(VaultError::Io {
                context: "test: baseline store unreadable",
                source: std::io::Error::new(std::io::ErrorKind::InvalidData, "seeded failure"),
            })
        },
        device_uuid,
        3_000,
        &mut rng,
    )
    .expect_err("a provider error must refuse the repair");
    assert!(
        matches!(err, VaultError::Io { context, .. } if context == "test: baseline store unreadable"),
        "the provider's own error must propagate, got {err:?}"
    );
    assert_eq!(
        fs::read(folder.join("manifest.cbor.enc")).unwrap(),
        before,
        "refused repair must not mutate the manifest"
    );
}
