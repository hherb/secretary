//! Integration tests for the `repair_vault` FFI projection (#374). Fixtures
//! are a fresh temp copy of `golden_vault_001` (mirrors
//! `device.rs::tmp_golden_vault`); crash residue is staged by calling
//! `secretary_core::vault::{open_vault, save_block, share_block}` directly —
//! same staging sequence as `core/tests/crash_recovery.rs` — then asserted
//! through the bridge `repair_vault_with_*` / `open_vault_with_*` /
//! `add_device_slot` fns, not the core orchestrator.

use std::collections::BTreeMap;
use std::path::Path;

use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

use secretary_core::crypto::secret::{SecretBytes, Sensitive};
use secretary_core::crypto::sig::{
    Ed25519Secret, MlDsa65Secret, ED25519_SIG_LEN, ML_DSA_65_SIG_LEN,
};
use secretary_core::identity::card::{ContactCard, CARD_VERSION_V1};
use secretary_core::vault::{
    format_uuid_hyphenated, open_vault, save_block, share_block, BlockPlaintext, BlockUuid,
    DeviceUuid, Unlocker, VectorClockEntry,
};

use crate::device::add_device_slot;
use crate::error::FfiVaultError;
use crate::vault::orchestration::open_vault_with_password;

use super::orchestration::repair_vault_with_password_in;
use super::{repair_vault_with_device_secret, repair_vault_with_password};

// ── fixture helpers (mirrors `device.rs`'s `tmp_golden_vault`) ─────────────

fn golden_vault_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../core/tests/data/golden_vault_001")
}

fn golden_inputs_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../core/tests/data/golden_vault_001_inputs.json")
}

fn golden_password() -> Vec<u8> {
    let raw = std::fs::read_to_string(golden_inputs_path())
        .expect("golden_vault_001_inputs.json must be readable");
    let v: serde_json::Value =
        serde_json::from_str(&raw).expect("golden_vault_001_inputs.json must parse");
    v["password"]
        .as_str()
        .expect("password field must be a string")
        .as_bytes()
        .to_vec()
}

fn copy_dir_all(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        let dst_path = dst.join(entry.file_name());
        if ft.is_dir() {
            copy_dir_all(&entry.path(), &dst_path)?;
        } else {
            std::fs::copy(entry.path(), dst_path)?;
        }
    }
    Ok(())
}

fn tmp_golden_vault() -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().expect("tempdir must be creatable");
    let vault_dir = tmp.path().join("golden_vault_001");
    copy_dir_all(&golden_vault_dir(), &vault_dir).expect("golden vault must be copyable");
    (tmp, vault_dir)
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

/// Mint a fresh, self-signed co-recipient contact card from a brand-new
/// identity bundle generated with a distinct RNG seed. Mirrors
/// `crash_recovery.rs::make_signed_card`. Uses a seed disjoint from the
/// golden-vault mint seeds ([0xA0]/[0xA1]/[0xA2]) per
/// `project_secretary_golden_vault_mint_seed_collision` — a colliding seed
/// would TOFU-collide with an existing golden-vault contact and trip
/// `ContactAlreadyExists`.
fn mint_external_card(seed: u8, display_name: &str) -> ContactCard {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let id = secretary_core::unlock::bundle::generate(display_name, 1_714_060_800_000, &mut rng);
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

// ── tests ────────────────────────────────────────────────────────────────

/// Case 1: happy-adopt via the password arm. Stage a crashed `save_block`
/// (v2 block on disk, v1 manifest committed) via the CORE `save_block`
/// directly (same sequence as
/// `crash_recovery.rs::repair_vault_adopts_interrupted_save`), then drive
/// the assertions entirely through the bridge surface: the plain open must
/// surface the typed `VaultNeedsRepair` signal, `repair_vault_with_password`
/// must adopt, and a subsequent bridge open must be green.
#[test]
fn repair_vault_with_password_adopts_interrupted_save_then_reopens() {
    let (_tmp, folder) = tmp_golden_vault();
    let pw = golden_password();
    let pw_secret = SecretBytes::new(pw.clone());
    let mut rng = ChaCha20Rng::from_seed([0x91; 32]);
    let mut open = open_vault(&folder, Unlocker::Password(&pw_secret), None).unwrap();
    let (device_uuid, block_uuid) = ([0xe0; 16], [0xf0; 16]);
    let recipients = vec![open.owner_card.clone()];
    save_block(
        &folder,
        &mut open,
        make_simple_plaintext(block_uuid, "v1"),
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();
    let manifest_v1 = std::fs::read(folder.join("manifest.cbor.enc")).unwrap();
    save_block(
        &folder,
        &mut open,
        make_simple_plaintext(block_uuid, "v2"),
        &recipients,
        device_uuid,
        2_000,
        &mut rng,
    )
    .unwrap();
    drop(open);
    // Crash simulation: v2 block hit disk, v2 manifest write was lost.
    std::fs::write(folder.join("manifest.cbor.enc"), &manifest_v1).unwrap();

    // The plain bridge open must surface the actionable typed signal.
    let err =
        open_vault_with_password(&folder, &pw).expect_err("crash residue must fail the plain open");
    match err {
        FfiVaultError::VaultNeedsRepair { block_uuid_hex } => {
            assert_eq!(block_uuid_hex, format_uuid_hyphenated(&block_uuid));
        }
        other => panic!("expected VaultNeedsRepair, got {other:?}"),
    }

    // repair_vault_with_password adopts the on-disk v2 generation.
    let repaired = repair_vault_with_password(&folder, &pw, &device_uuid, 3_000)
        .expect("gated adoption must succeed on genuine crash residue");
    drop(repaired);

    // A subsequent plain bridge open is green.
    open_vault_with_password(&folder, &pw).expect("vault must be healthy after repair");
}

/// Case 2: happy-adopt via the device-secret arm. Enroll a fresh device
/// slot through the bridge's own `add_device_slot` projection, stage the
/// same crashed-save residue, then adopt through
/// `repair_vault_with_device_secret`.
#[test]
fn repair_vault_with_device_secret_adopts_interrupted_save() {
    let (_tmp, folder) = tmp_golden_vault();
    let pw = golden_password();
    let mut rng = ChaCha20Rng::from_seed([0x92; 32]);

    // Enroll a fresh device slot via the bridge projection.
    let enrolled = add_device_slot(&folder, &pw).expect("add_device_slot must succeed");
    let device_uuid: [u8; 16] = enrolled
        .device_uuid
        .as_slice()
        .try_into()
        .expect("device_uuid must be 16 bytes");
    let device_secret_bytes = enrolled
        .device_secret
        .take_secret()
        .expect("first take_secret must return Some");
    let device_secret: [u8; 32] = device_secret_bytes
        .as_slice()
        .try_into()
        .expect("device secret must be 32 bytes");

    // Stage a crashed save under this device's own unlock path.
    let device_secret_sb = SecretBytes::new(device_secret.to_vec());
    let dev_unlocker = || Unlocker::DeviceSecret {
        device_uuid: &device_uuid,
        secret: &device_secret_sb,
    };
    let mut open = open_vault(&folder, dev_unlocker(), None).unwrap();
    let block_uuid = [0xf1; 16];
    let recipients = vec![open.owner_card.clone()];
    save_block(
        &folder,
        &mut open,
        make_simple_plaintext(block_uuid, "v1"),
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();
    let manifest_v1 = std::fs::read(folder.join("manifest.cbor.enc")).unwrap();
    save_block(
        &folder,
        &mut open,
        make_simple_plaintext(block_uuid, "v2"),
        &recipients,
        device_uuid,
        2_000,
        &mut rng,
    )
    .unwrap();
    drop(open);
    std::fs::write(folder.join("manifest.cbor.enc"), &manifest_v1).unwrap();

    let repaired = repair_vault_with_device_secret(&folder, &device_uuid, &device_secret, 3_000)
        .expect("gated adoption via device secret must succeed");
    let entry = repaired
        .manifest
        .block_summaries()
        .into_iter()
        .find(|b| b.block_uuid == block_uuid)
        .expect("adopted entry present");
    assert_eq!(
        entry.block_name, "v2",
        "adopted entry carries on-disk content"
    );
}

/// Case 3: rejected — a crashed `share_block` (recipient-widening residue)
/// must NOT be auto-adopted. `repair_vault_with_password` must surface
/// `FfiVaultError::RepairRejected` whose `detail` names the would-be-added
/// recipient (mirrors `crash_recovery.rs::repair_rejects_crashed_share_superset`).
#[test]
fn repair_vault_with_password_rejects_recipient_widening_residue() {
    let (_tmp, folder) = tmp_golden_vault();
    let pw = golden_password();
    let pw_secret = SecretBytes::new(pw.clone());
    let mut rng = ChaCha20Rng::from_seed([0x93; 32]);
    let mut open = open_vault(&folder, Unlocker::Password(&pw_secret), None).unwrap();
    let (device_uuid, block_uuid) = ([0xe2; 16], [0xf2; 16]);

    // Fresh external recipient — disjoint seed from the golden-vault mint
    // seeds so TOFU never collides.
    let card_c = mint_external_card(0x94, "Cee");

    let recipients = vec![open.owner_card.clone()];
    save_block(
        &folder,
        &mut open,
        make_simple_plaintext(block_uuid, "mine"),
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();
    let manifest_pre_share = std::fs::read(folder.join("manifest.cbor.enc")).unwrap();

    let author_card = open.owner_card.clone();
    let author_sk_ed: Ed25519Secret = Sensitive::new(*open.identity.ed25519_sk.expose());
    let author_sk_pq = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).unwrap();
    share_block(
        &folder,
        &mut open,
        BlockUuid::new(block_uuid),
        &author_card,
        &author_sk_ed,
        &author_sk_pq,
        &recipients,
        &card_c,
        DeviceUuid::new(device_uuid),
        2_000,
        &mut rng,
    )
    .unwrap();
    drop(open);
    // Crash simulation: the {owner, C} block hit disk, the manifest write
    // that would have committed the widened recipient set was lost.
    std::fs::write(folder.join("manifest.cbor.enc"), &manifest_pre_share).unwrap();

    let err = repair_vault_with_password(&folder, &pw, &device_uuid, 3_000)
        .expect_err("crashed-share superset must be refused (documented limitation)");
    match err {
        FfiVaultError::RepairRejected {
            block_uuid_hex,
            detail,
        } => {
            assert_eq!(block_uuid_hex, format_uuid_hyphenated(&block_uuid));
            assert!(
                detail.contains("would ADD recipients"),
                "detail must name the widening reason: {detail}"
            );
            assert!(
                detail.contains(&format_uuid_hyphenated(&card_c.contact_uuid)),
                "detail must name the would-be-added recipient: {detail}"
            );
        }
        other => panic!("expected RepairRejected, got {other:?}"),
    }
    // All-or-nothing: the manifest must be untouched by the rejected repair.
    assert_eq!(
        std::fs::read(folder.join("manifest.cbor.enc")).unwrap(),
        manifest_pre_share,
        "rejected repair must not touch the manifest"
    );
}

/// Case 5 (#374 regression): the §10 rollback-resistance gate must run
/// BEFORE the repair write, on the COMMITTED manifest clock — not after the
/// adopt-and-tick, where the local tick would flip a strictly-dominated
/// (rollback) clock into an unflagged "concurrent" one and mask it
/// permanently. Stage genuine adoptable crash residue (a crashed save), seed a
/// §10 baseline (via a temp state dir injected through the `_in` seam) that
/// strictly dominates the committed clock — ahead on a FOREIGN device the
/// repair tick never touches — then assert repair REFUSES with `CorruptVault`
/// (core `VaultError::Rollback` folds to `CorruptVault`) and leaves the
/// on-disk manifest byte-for-byte unchanged (refuse-without-mutation — the
/// crux). Before the fix (baseline passed as `None`, §10 checked only on the
/// post-tick clock) this residue was silently adopted and the manifest
/// rewritten.
#[test]
fn repair_gates_rollback_before_write_and_leaves_manifest_untouched() {
    let (_tmp, folder) = tmp_golden_vault();
    let state_dir = tempfile::tempdir().unwrap();
    let pw = golden_password();
    let pw_secret = SecretBytes::new(pw.clone());
    let mut rng = ChaCha20Rng::from_seed([0x96; 32]);
    let mut open = open_vault(&folder, Unlocker::Password(&pw_secret), None).unwrap();
    let (device_uuid, block_uuid) = ([0xe5; 16], [0xf5; 16]);
    let recipients = vec![open.owner_card.clone()];

    // v1: committed. Snapshot the committed manifest's clock + vault_uuid.
    save_block(
        &folder,
        &mut open,
        make_simple_plaintext(block_uuid, "v1"),
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();
    let manifest_v1 = std::fs::read(folder.join("manifest.cbor.enc")).unwrap();
    let committed_clock = open.manifest.vector_clock.clone();
    let vault_uuid = open.manifest.vault_uuid;

    // v2: block hits disk; the manifest write is "lost" (restored below).
    save_block(
        &folder,
        &mut open,
        make_simple_plaintext(block_uuid, "v2"),
        &recipients,
        device_uuid,
        2_000,
        &mut rng,
    )
    .unwrap();
    drop(open);
    std::fs::write(folder.join("manifest.cbor.enc"), &manifest_v1).unwrap();

    // Sanity: this residue is GENUINELY adoptable — without a rollback
    // baseline the plain open flags the actionable VaultNeedsRepair (i.e. the
    // refusal below is caused by the §10 gate, not by unrelated corruption).
    assert!(
        matches!(
            open_vault_with_password(&folder, &pw),
            Err(FfiVaultError::VaultNeedsRepair { .. })
        ),
        "residue must be adoptable crash residue, not pre-existing corruption",
    );

    // Seed a §10 baseline that strictly DOMINATES the committed clock: every
    // committed entry verbatim (so the committed clock is never strictly
    // greater anywhere) plus a FOREIGN device ahead (so it is strictly less
    // there) → is_rollback(committed) == true. The foreign device is NOT the
    // one repair ticks — proving the gate fires on the pre-tick committed
    // clock, independent of the adopt-and-tick that would otherwise mask it.
    let foreign = [0x0f; 16];
    assert!(
        !committed_clock.iter().any(|e| e.device_uuid == foreign),
        "foreign device_uuid must be disjoint from the committed clock",
    );
    let mut baseline = committed_clock.clone();
    baseline.push(VectorClockEntry {
        device_uuid: foreign,
        counter: 1,
    });
    baseline.sort_by_key(|e| e.device_uuid);
    let synced = secretary_core::sync::SyncState::new(vault_uuid, baseline).unwrap();
    secretary_cli::state::save(state_dir.path(), &synced).unwrap();

    // Snapshot the on-disk manifest immediately before the repair attempt.
    let before = std::fs::read(folder.join("manifest.cbor.enc")).unwrap();
    let err =
        repair_vault_with_password_in(Some(state_dir.path()), &folder, &pw, &device_uuid, 3_000)
            .expect_err("a strictly-dominated committed clock must refuse repair PRE-write");
    assert!(
        matches!(err, FfiVaultError::CorruptVault { .. }),
        "core VaultError::Rollback must fold to CorruptVault, got {err:?}",
    );
    assert_eq!(
        std::fs::read(folder.join("manifest.cbor.enc")).unwrap(),
        before,
        "refused repair must not mutate the manifest (pre-write gate — the crux)",
    );
}

/// Case 4: idempotent — `repair_vault_with_password` on a healthy vault
/// (no crash residue) succeeds and writes no new manifest bytes.
#[test]
fn repair_vault_with_password_is_idempotent_on_healthy_vault() {
    let (_tmp, folder) = tmp_golden_vault();
    let pw = golden_password();
    let pw_secret = SecretBytes::new(pw.clone());
    let mut rng = ChaCha20Rng::from_seed([0x95; 32]);
    let mut open = open_vault(&folder, Unlocker::Password(&pw_secret), None).unwrap();
    let (device_uuid, block_uuid) = ([0xe3; 16], [0xf3; 16]);
    let recipients = vec![open.owner_card.clone()];
    save_block(
        &folder,
        &mut open,
        make_simple_plaintext(block_uuid, "healthy"),
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();
    drop(open);
    let before = std::fs::read(folder.join("manifest.cbor.enc")).unwrap();

    let repaired = repair_vault_with_password(&folder, &pw, &device_uuid, 2_000)
        .expect("healthy vault must open through repair");
    let has_block = repaired
        .manifest
        .block_summaries()
        .into_iter()
        .any(|b| b.block_uuid == block_uuid);
    assert!(has_block, "healthy repair must still see the live block");
    drop(repaired);

    assert_eq!(
        std::fs::read(folder.join("manifest.cbor.enc")).unwrap(),
        before,
        "healthy repair must not rewrite the manifest"
    );
}
