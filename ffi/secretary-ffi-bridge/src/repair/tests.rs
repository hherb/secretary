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
    DeviceUuid, OpenVault, Unlocker, VectorClockEntry,
};

use crate::device::{add_device_slot, open_with_device_secret};
use crate::error::FfiVaultError;
use crate::repair::types::FfiApprovedWidening;
use crate::vault::orchestration::open_vault_with_password;

use super::orchestration::{
    repair_vault_with_device_secret_in, repair_vault_with_password_in,
    repair_vault_with_recovery_in,
};
use super::preview::preview_repair_with_password_in;
use super::{
    preview_repair_with_password, repair_vault_with_device_secret, repair_vault_with_password,
    repair_vault_with_recovery,
};

// ── fixture helpers (mirrors `device.rs`'s `tmp_golden_vault`) ─────────────

/// The golden vault's recovery mnemonic (same pin as `vault/tests.rs`;
/// sourced from `golden_vault_001_inputs.json`'s `recovery_mnemonic_phrase`).
const VAULT_001_PHRASE: &[u8] = b"wall annual clay zebra cost cricket choose light small neck mimic season fix situate love asset dismiss online island disease turkey grab dish that";

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

/// What later assertions need from the canonical crashed-save staging:
/// the rolled-back v1 manifest bytes (for byte-untouched refusal
/// asserts) plus the committed clock / vault uuid snapshotted after the
/// v1 commit (for §10 baseline seeding).
struct StagedCrashedSave {
    manifest_v1: Vec<u8>,
    committed_clock: Vec<VectorClockEntry>,
    vault_uuid: [u8; 16],
}

/// Stage the canonical crashed-`save_block` residue shared by the adopt
/// and §10-gate tests: commit "v1" (ts 1_000), snapshot the committed
/// manifest, write "v2" (ts 2_000 — the block file hits disk), then roll
/// the manifest back to the v1 snapshot, as if the crash hit between
/// `save_block`'s block write and its manifest write. Consumes `open` —
/// the "crashed" session must not keep writing after the rollback.
fn stage_crashed_save(
    folder: &Path,
    mut open: OpenVault,
    block_uuid: [u8; 16],
    device_uuid: [u8; 16],
    rng: &mut ChaCha20Rng,
) -> StagedCrashedSave {
    let recipients = vec![open.owner_card.clone()];
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "v1"),
        &recipients,
        device_uuid,
        1_000,
        rng,
    )
    .unwrap();
    let manifest_v1 = std::fs::read(folder.join("manifest.cbor.enc")).unwrap();
    let committed_clock = open.manifest.vector_clock.clone();
    let vault_uuid = open.manifest.vault_uuid;
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "v2"),
        &recipients,
        device_uuid,
        2_000,
        rng,
    )
    .unwrap();
    drop(open);
    std::fs::write(folder.join("manifest.cbor.enc"), &manifest_v1).unwrap();
    StagedCrashedSave {
        manifest_v1,
        committed_clock,
        vault_uuid,
    }
}

/// What the approval-adoption tests need from the canonical crashed-
/// `share_block` staging: the rolled-back pre-share manifest bytes (for
/// byte-untouched refusal asserts and the §10 valid-approval regression),
/// the BLAKE3-256 fingerprint of the on-disk (post-share) block file (to
/// bind an exact [`FfiApprovedWidening`]), the added recipient's contact
/// UUID, and the vault UUID (for seeding a §10 baseline at the right
/// state-file path).
struct StagedCrashedShare {
    manifest_pre_share: Vec<u8>,
    file_fingerprint: [u8; 32],
    added_contact_uuid: [u8; 16],
    vault_uuid: [u8; 16],
}

/// Stage the canonical crashed-`share_block` residue (recipient-widening
/// shape): commit a block visible only to the owner, share it to add
/// `card_c` (bumping the on-disk block file to `{owner, C}`), then roll
/// the manifest back to the pre-share snapshot — as if the crash hit
/// between `share_block`'s block write and its manifest write. Mirrors
/// `repair_vault_with_password_rejects_recipient_widening_residue`'s
/// inline staging above and core's
/// `crash_recovery.rs::stage_crashed_share`. Consumes `open` — the
/// "crashed" session must not keep writing after the rollback.
fn stage_crashed_share(
    folder: &Path,
    mut open: OpenVault,
    block_uuid: [u8; 16],
    device_uuid: [u8; 16],
    card_c: &ContactCard,
    rng: &mut ChaCha20Rng,
) -> StagedCrashedShare {
    let vault_uuid = open.manifest.vault_uuid;
    let recipients = vec![open.owner_card.clone()];
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "mine"),
        &recipients,
        device_uuid,
        1_000,
        rng,
    )
    .unwrap();
    let manifest_pre_share = std::fs::read(folder.join("manifest.cbor.enc")).unwrap();

    let author_card = open.owner_card.clone();
    let author_sk_ed: Ed25519Secret = Sensitive::new(*open.identity.ed25519_sk.expose());
    let author_sk_pq = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).unwrap();
    share_block(
        folder,
        &mut open,
        BlockUuid::new(block_uuid),
        &author_card,
        &author_sk_ed,
        &author_sk_pq,
        &recipients,
        card_c,
        DeviceUuid::new(device_uuid),
        2_000,
        rng,
    )
    .unwrap();
    drop(open);
    // Crash simulation: the {owner, C} block hit disk, the manifest write
    // that would have committed the widened recipient set was lost.
    std::fs::write(folder.join("manifest.cbor.enc"), &manifest_pre_share).unwrap();

    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    let block_bytes =
        std::fs::read(folder.join("blocks").join(format!("{uuid_hex}.cbor.enc"))).unwrap();
    let file_fingerprint = *secretary_core::crypto::hash::hash(&block_bytes).as_bytes();

    StagedCrashedShare {
        manifest_pre_share,
        file_fingerprint,
        added_contact_uuid: card_c.contact_uuid,
        vault_uuid,
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
    let open = open_vault(&folder, Unlocker::Password(&pw_secret), None).unwrap();
    let (device_uuid, block_uuid) = ([0xe0; 16], [0xf0; 16]);
    // Crash simulation: v2 block hit disk, v2 manifest write was lost.
    stage_crashed_save(&folder, open, block_uuid, device_uuid, &mut rng);

    // The plain bridge open must surface the actionable typed signal.
    let err =
        open_vault_with_password(&folder, &pw).expect_err("crash residue must fail the plain open");
    match err {
        FfiVaultError::VaultNeedsRepair { block_uuid_hex } => {
            assert_eq!(block_uuid_hex, format_uuid_hyphenated(&block_uuid));
        }
        other => panic!("expected VaultNeedsRepair, got {other:?}"),
    }

    // repair_vault_with_password adopts the on-disk v2 generation. Empty
    // approvals is the documented safe zero-value (maps to FailClosed);
    // this residue shape (a crashed content save, not a widening) adopts
    // regardless.
    let repaired = repair_vault_with_password(&folder, &pw, &device_uuid, 3_000, &[])
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
    let open = open_vault(&folder, dev_unlocker(), None).unwrap();
    let block_uuid = [0xf1; 16];
    stage_crashed_save(&folder, open, block_uuid, device_uuid, &mut rng);

    let repaired =
        repair_vault_with_device_secret(&folder, &device_uuid, &device_secret, 3_000, &[])
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

    // No approvals: this is the FailClosed baseline test — the widening
    // must be refused with no consent offered at all.
    let err = repair_vault_with_password(&folder, &pw, &device_uuid, 3_000, &[])
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
    let open = open_vault(&folder, Unlocker::Password(&pw_secret), None).unwrap();
    let (device_uuid, block_uuid) = ([0xe5; 16], [0xf5; 16]);

    // v1 committed, v2 block on disk, manifest rolled back to v1; the
    // staging snapshots the committed clock + vault_uuid for the §10
    // baseline seed below.
    let staged = stage_crashed_save(&folder, open, block_uuid, device_uuid, &mut rng);
    let committed_clock = staged.committed_clock;
    let vault_uuid = staged.vault_uuid;

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
    let err = repair_vault_with_password_in(
        Some(state_dir.path()),
        &folder,
        &pw,
        &device_uuid,
        3_000,
        &[],
    )
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

/// Case 6 (#374 follow-up): the same pre-write §10 rollback gate, proven
/// end-to-end for the DEVICE-SECRET arm. Mirrors
/// `repair_gates_rollback_before_write_and_leaves_manifest_untouched` (Case
/// 5, password arm) exactly, but enrolls a device slot and stages/repairs
/// through the device-secret unlock path — closing the coverage gap where
/// the pre-write gate was previously proven end-to-end only for password.
#[test]
fn repair_device_secret_gates_rollback_before_write_and_leaves_manifest_untouched() {
    let (_tmp, folder) = tmp_golden_vault();
    let state_dir = tempfile::tempdir().unwrap();
    let pw = golden_password();
    let mut rng = ChaCha20Rng::from_seed([0x97; 32]);

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

    // Stage crash residue under this device's own unlock path.
    let device_secret_sb = SecretBytes::new(device_secret.to_vec());
    let dev_unlocker = || Unlocker::DeviceSecret {
        device_uuid: &device_uuid,
        secret: &device_secret_sb,
    };
    let open = open_vault(&folder, dev_unlocker(), None).unwrap();
    let block_uuid = [0xf6; 16];

    // v1 committed, v2 block on disk, manifest rolled back to v1; the
    // staging snapshots the committed clock + vault_uuid for the §10
    // baseline seed below.
    let staged = stage_crashed_save(&folder, open, block_uuid, device_uuid, &mut rng);
    let committed_clock = staged.committed_clock;
    let vault_uuid = staged.vault_uuid;

    // Sanity: this residue is GENUINELY adoptable — without a rollback
    // baseline the plain device-secret open flags the actionable
    // VaultNeedsRepair (i.e. the refusal below is caused by the §10 gate,
    // not by unrelated corruption).
    assert!(
        matches!(
            open_with_device_secret(&folder, &device_uuid, &device_secret),
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
    let foreign = [0x1f; 16];
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
    let err = repair_vault_with_device_secret_in(
        Some(state_dir.path()),
        &folder,
        &device_uuid,
        &device_secret,
        3_000,
        &[],
    )
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

    let repaired = repair_vault_with_password(&folder, &pw, &device_uuid, 2_000, &[])
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

/// #384 posture (password arm): an EXISTING but unreadable/undecodable
/// §10 baseline state file must refuse the MUTATING repair fail-closed —
/// a skipped check here would let adoption tick + re-sign the manifest,
/// permanently laundering a rolled-back clock. The refusal surfaces as
/// `CorruptVault` whose detail names the state file and the documented
/// remedy (delete it = the crypto-design §10 reset); the manifest must be
/// byte-for-byte untouched. Missing-file/never-synced keeps adopting
/// (Cases 1/2 pin that branch).
#[test]
fn repair_refuses_unreadable_rollback_baseline_and_leaves_manifest_untouched() {
    let (_tmp, folder) = tmp_golden_vault();
    let state_dir = tempfile::tempdir().unwrap();
    let pw = golden_password();
    let pw_secret = SecretBytes::new(pw.clone());
    let mut rng = ChaCha20Rng::from_seed([0x98; 32]);
    let open = open_vault(&folder, Unlocker::Password(&pw_secret), None).unwrap();
    let (device_uuid, block_uuid) = ([0xe7; 16], [0xf7; 16]);

    // Stage genuine adoptable crash residue (crashed save, v2 on disk).
    let staged = stage_crashed_save(&folder, open, block_uuid, device_uuid, &mut rng);

    // Sanity: adoptable residue, not pre-existing corruption.
    assert!(
        matches!(
            open_vault_with_password(&folder, &pw),
            Err(FfiVaultError::VaultNeedsRepair { .. })
        ),
        "residue must be adoptable crash residue",
    );

    // A PRESENT but garbage state file at the exact path load() reads.
    std::fs::write(
        secretary_cli::state::state_file_path(state_dir.path(), staged.vault_uuid),
        b"not a canonical SyncState",
    )
    .unwrap();

    let err = repair_vault_with_password_in(
        Some(state_dir.path()),
        &folder,
        &pw,
        &device_uuid,
        3_000,
        &[],
    )
    .expect_err("existing-but-unreadable baseline must refuse the mutating repair");
    match err {
        FfiVaultError::CorruptVault { detail } => {
            assert!(
                detail.contains("rollback baseline"),
                "detail must name the failing store: {detail}"
            );
            assert!(
                detail.contains("resets this device's rollback history"),
                "detail must carry the documented remedy: {detail}"
            );
        }
        other => panic!("expected CorruptVault, got {other:?}"),
    }
    assert_eq!(
        std::fs::read(folder.join("manifest.cbor.enc")).unwrap(),
        staged.manifest_v1,
        "refused repair must not mutate the manifest (fail-closed pre-write)",
    );
}

/// #384 posture (device-secret arm): same contract as the password-arm
/// test above, proven end-to-end through the device-secret unlock path
/// (arm parity — mirrors how Case 5/6 pin the rollback gate on both arms).
#[test]
fn repair_device_secret_refuses_unreadable_rollback_baseline() {
    let (_tmp, folder) = tmp_golden_vault();
    let state_dir = tempfile::tempdir().unwrap();
    let pw = golden_password();
    let mut rng = ChaCha20Rng::from_seed([0x99; 32]);

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

    let device_secret_sb = SecretBytes::new(device_secret.to_vec());
    let dev_unlocker = || Unlocker::DeviceSecret {
        device_uuid: &device_uuid,
        secret: &device_secret_sb,
    };
    let open = open_vault(&folder, dev_unlocker(), None).unwrap();
    let block_uuid = [0xf8; 16];
    let staged = stage_crashed_save(&folder, open, block_uuid, device_uuid, &mut rng);

    std::fs::write(
        secretary_cli::state::state_file_path(state_dir.path(), staged.vault_uuid),
        b"not a canonical SyncState",
    )
    .unwrap();

    let err = repair_vault_with_device_secret_in(
        Some(state_dir.path()),
        &folder,
        &device_uuid,
        &device_secret,
        3_000,
        &[],
    )
    .expect_err("existing-but-unreadable baseline must refuse the mutating repair");
    assert!(
        matches!(err, FfiVaultError::CorruptVault { .. }),
        "expected CorruptVault, got {err:?}",
    );
    assert_eq!(
        std::fs::read(folder.join("manifest.cbor.enc")).unwrap(),
        staged.manifest_v1,
        "refused repair must not mutate the manifest (fail-closed pre-write)",
    );
}

/// #384 posture (recovery arm): same fail-closed contract as the
/// password-arm test above, proven end-to-end through the mnemonic
/// unlock path — completing arm parity across all three repair arms so
/// a future edit cannot swap this arm's provider for a fail-open one
/// and ship green (the other two arms' tests would stay green).
#[test]
fn repair_recovery_refuses_unreadable_rollback_baseline() {
    let (_tmp, folder) = tmp_golden_vault();
    let state_dir = tempfile::tempdir().unwrap();
    let pw = golden_password();
    let pw_secret = SecretBytes::new(pw.clone());
    let mut rng = ChaCha20Rng::from_seed([0x9b; 32]);
    let open = open_vault(&folder, Unlocker::Password(&pw_secret), None).unwrap();
    let (device_uuid, block_uuid) = ([0xea; 16], [0xfa; 16]);
    let staged = stage_crashed_save(&folder, open, block_uuid, device_uuid, &mut rng);

    // A PRESENT but garbage state file at the exact path load() reads.
    std::fs::write(
        secretary_cli::state::state_file_path(state_dir.path(), staged.vault_uuid),
        b"not a canonical SyncState",
    )
    .unwrap();

    let err = repair_vault_with_recovery_in(
        Some(state_dir.path()),
        &folder,
        VAULT_001_PHRASE,
        &device_uuid,
        3_000,
        &[],
    )
    .expect_err("existing-but-unreadable baseline must refuse the mutating repair");
    assert!(
        matches!(err, FfiVaultError::CorruptVault { .. }),
        "expected CorruptVault, got {err:?}",
    );
    assert_eq!(
        std::fs::read(folder.join("manifest.cbor.enc")).unwrap(),
        staged.manifest_v1,
        "refused repair must not mutate the manifest (fail-closed pre-write)",
    );
}

/// #384 posture: a validly-encoded SyncState whose INTERNAL vault_uuid
/// differs from the file's path key (`StateError::VaultUuidMismatch`) is
/// "present but not usable" — same fail-closed refusal as garbage bytes,
/// NOT a silent skip (a skip would let a planted/mislabelled state file
/// neutralize §10 on the mutating path).
#[test]
fn repair_refuses_uuid_mismatched_rollback_baseline() {
    let (_tmp, folder) = tmp_golden_vault();
    let state_dir = tempfile::tempdir().unwrap();
    let pw = golden_password();
    let pw_secret = SecretBytes::new(pw.clone());
    let mut rng = ChaCha20Rng::from_seed([0x9a; 32]);
    let open = open_vault(&folder, Unlocker::Password(&pw_secret), None).unwrap();
    let (device_uuid, block_uuid) = ([0xe9; 16], [0xf9; 16]);
    let staged = stage_crashed_save(&folder, open, block_uuid, device_uuid, &mut rng);

    // A validly-encoded SyncState under a DIFFERENT internal uuid, planted
    // at the path keyed by the real vault uuid.
    let other_uuid = [0x5a; 16];
    assert_ne!(other_uuid, staged.vault_uuid);
    let clock = vec![VectorClockEntry {
        device_uuid: [0x0e; 16],
        counter: 1,
    }];
    let mismatched = secretary_core::sync::SyncState::new(other_uuid, clock).unwrap();
    secretary_cli::state::save(state_dir.path(), &mismatched).unwrap();
    std::fs::rename(
        secretary_cli::state::state_file_path(state_dir.path(), other_uuid),
        secretary_cli::state::state_file_path(state_dir.path(), staged.vault_uuid),
    )
    .unwrap();

    let err = repair_vault_with_password_in(
        Some(state_dir.path()),
        &folder,
        &pw,
        &device_uuid,
        3_000,
        &[],
    )
    .expect_err("uuid-mismatched baseline must refuse the mutating repair");
    assert!(
        matches!(err, FfiVaultError::CorruptVault { .. }),
        "expected CorruptVault, got {err:?}",
    );
    assert_eq!(
        std::fs::read(folder.join("manifest.cbor.enc")).unwrap(),
        staged.manifest_v1,
        "refused repair must not mutate the manifest (fail-closed pre-write)",
    );
}

// ── #374 part 3: approvals on the three repair arms ────────────────────────

/// Happy-adopt (password arm): an exact approval — bound to the on-disk
/// block file's own BLAKE3 fingerprint and the exact added-recipient set —
/// must adopt the crashed-`share_block` widening residue, and the vault
/// must reopen clean afterwards. Mirrors core's
/// `crash_recovery.rs::repair_adopts_crashed_share_with_matching_approval`.
#[test]
fn repair_with_password_adopts_with_exact_approval() {
    let (_tmp, folder) = tmp_golden_vault();
    let pw = golden_password();
    let pw_secret = SecretBytes::new(pw.clone());
    let mut rng = ChaCha20Rng::from_seed([0x9c; 32]);
    let open = open_vault(&folder, Unlocker::Password(&pw_secret), None).unwrap();
    let (device_uuid, block_uuid) = ([0xeb; 16], [0xfb; 16]);
    let card_c = mint_external_card(0x9d, "Cee");
    let staged = stage_crashed_share(&folder, open, block_uuid, device_uuid, &card_c, &mut rng);

    let approval = FfiApprovedWidening {
        block_uuid,
        file_fingerprint: staged.file_fingerprint,
        added_recipients: vec![staged.added_contact_uuid],
    };
    let repaired = repair_vault_with_password(&folder, &pw, &device_uuid, 3_000, &[approval])
        .expect("exact approval must adopt the crashed-share superset");
    let entry = repaired
        .manifest
        .block_summaries()
        .into_iter()
        .find(|b| b.block_uuid == block_uuid)
        .expect("adopted entry present");
    assert_eq!(entry.recipient_uuids.len(), 2, "widened set committed");
    assert!(entry.recipient_uuids.contains(&staged.added_contact_uuid));
    drop(repaired);

    // Vault opens clean afterwards (residue fully adopted).
    open_vault_with_password(&folder, &pw).expect("post-repair open must succeed");
}

/// Happy-adopt (recovery arm): same contract as the password-arm test
/// above, proven end-to-end through the 24-word mnemonic unlock path —
/// arm parity for the consent-adoption path.
#[test]
fn repair_with_recovery_adopts_with_exact_approval() {
    let (_tmp, folder) = tmp_golden_vault();
    let pw = golden_password();
    let pw_secret = SecretBytes::new(pw.clone());
    let mut rng = ChaCha20Rng::from_seed([0x9e; 32]);
    let open = open_vault(&folder, Unlocker::Password(&pw_secret), None).unwrap();
    let (device_uuid, block_uuid) = ([0xec; 16], [0xfc; 16]);
    let card_c = mint_external_card(0x9f, "Cee");
    let staged = stage_crashed_share(&folder, open, block_uuid, device_uuid, &card_c, &mut rng);

    let approval = FfiApprovedWidening {
        block_uuid,
        file_fingerprint: staged.file_fingerprint,
        added_recipients: vec![staged.added_contact_uuid],
    };
    let repaired =
        repair_vault_with_recovery(&folder, VAULT_001_PHRASE, &device_uuid, 3_000, &[approval])
            .expect("exact approval must adopt the crashed-share superset via the recovery arm");
    let entry = repaired
        .manifest
        .block_summaries()
        .into_iter()
        .find(|b| b.block_uuid == block_uuid)
        .expect("adopted entry present");
    assert_eq!(entry.recipient_uuids.len(), 2, "widened set committed");
    assert!(entry.recipient_uuids.contains(&staged.added_contact_uuid));
    drop(repaired);

    open_vault_with_password(&folder, &pw).expect("post-repair open must succeed");
}

/// Happy-adopt (device-secret arm): same contract, proven end-to-end
/// through a freshly-enrolled device slot — arm parity across all three
/// repair entry points.
#[test]
fn repair_with_device_secret_adopts_with_exact_approval() {
    let (_tmp, folder) = tmp_golden_vault();
    let pw = golden_password();
    let mut rng = ChaCha20Rng::from_seed([0xa0; 32]);

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

    let device_secret_sb = SecretBytes::new(device_secret.to_vec());
    let dev_unlocker = || Unlocker::DeviceSecret {
        device_uuid: &device_uuid,
        secret: &device_secret_sb,
    };
    let open = open_vault(&folder, dev_unlocker(), None).unwrap();
    let block_uuid = [0xfd; 16];
    let card_c = mint_external_card(0xa1, "Cee");
    let staged = stage_crashed_share(&folder, open, block_uuid, device_uuid, &card_c, &mut rng);

    let approval = FfiApprovedWidening {
        block_uuid,
        file_fingerprint: staged.file_fingerprint,
        added_recipients: vec![staged.added_contact_uuid],
    };
    let repaired =
        repair_vault_with_device_secret(&folder, &device_uuid, &device_secret, 3_000, &[approval])
            .expect(
                "exact approval must adopt the crashed-share superset via the device-secret arm",
            );
    let entry = repaired
        .manifest
        .block_summaries()
        .into_iter()
        .find(|b| b.block_uuid == block_uuid)
        .expect("adopted entry present");
    assert_eq!(entry.recipient_uuids.len(), 2, "widened set committed");
    assert!(entry.recipient_uuids.contains(&staged.added_contact_uuid));
    drop(repaired);

    // Vault opens clean afterwards (residue fully adopted). Password reopen
    // is fine here — the assertion is about the on-disk state, not the arm
    // used to unlock it (mirrors the password/recovery siblings above).
    open_vault_with_password(&folder, &pw).expect("post-repair open must succeed");
}

/// Stale consent: an approval whose `file_fingerprint` no longer matches
/// the on-disk block bytes (the residue changed, or the approval was built
/// against a different preview) must be refused as
/// `FfiVaultError::RepairRejected`, and the manifest must be untouched.
/// Mirrors core's
/// `crash_recovery.rs::repair_rejects_approval_with_stale_fingerprint`.
#[test]
fn repair_refuses_stale_approval_as_repair_rejected() {
    let (_tmp, folder) = tmp_golden_vault();
    let pw = golden_password();
    let pw_secret = SecretBytes::new(pw.clone());
    let mut rng = ChaCha20Rng::from_seed([0xa4; 32]);
    let open = open_vault(&folder, Unlocker::Password(&pw_secret), None).unwrap();
    let (device_uuid, block_uuid) = ([0xee; 16], [0xfe; 16]);
    let card_c = mint_external_card(0xa5, "Cee");
    let staged = stage_crashed_share(&folder, open, block_uuid, device_uuid, &card_c, &mut rng);

    let mut stale_fingerprint = staged.file_fingerprint;
    stale_fingerprint[0] ^= 0x01; // consent bound to different bytes than on disk
    let approval = FfiApprovedWidening {
        block_uuid,
        file_fingerprint: stale_fingerprint,
        added_recipients: vec![staged.added_contact_uuid],
    };
    let err = repair_vault_with_password(&folder, &pw, &device_uuid, 3_000, &[approval])
        .expect_err("stale consent must refuse");
    match err {
        FfiVaultError::RepairRejected {
            block_uuid_hex,
            detail,
        } => {
            assert_eq!(block_uuid_hex, format_uuid_hyphenated(&block_uuid));
            assert!(
                detail.contains("does not match the on-disk residue"),
                "must be the stale-consent rejection arm specifically: {detail}"
            );
        }
        other => panic!("expected RepairRejected, got {other:?}"),
    }
    // All-or-nothing: the manifest must be untouched by the rejected repair.
    assert_eq!(
        std::fs::read(folder.join("manifest.cbor.enc")).unwrap(),
        staged.manifest_pre_share,
        "rejected repair must not touch the manifest"
    );
}

/// #374 part 3 / §10 regression: even with a VALID (exact-matching)
/// approval present, an existing-but-unreadable §10 rollback baseline
/// state file must still refuse the repair as `CorruptVault` — the
/// rollback gate runs strictly BEFORE any per-block classification/consent
/// decision (module docs: "§10 rollback resistance is gated PRE-write"),
/// so a valid approval must never let a laundered rollback baseline slip
/// through. Mirrors
/// `repair_refuses_unreadable_rollback_baseline_and_leaves_manifest_untouched`
/// but adds a matching approval to prove fail-closed §10 still wins.
#[test]
fn repair_refuses_unreadable_rollback_baseline_even_with_valid_approval() {
    let (_tmp, folder) = tmp_golden_vault();
    let state_dir = tempfile::tempdir().unwrap();
    let pw = golden_password();
    let pw_secret = SecretBytes::new(pw.clone());
    let mut rng = ChaCha20Rng::from_seed([0xa2; 32]);
    let open = open_vault(&folder, Unlocker::Password(&pw_secret), None).unwrap();
    let (device_uuid, block_uuid) = ([0xef; 16], [0xff; 16]);
    let card_c = mint_external_card(0xa3, "Cee");
    let staged = stage_crashed_share(&folder, open, block_uuid, device_uuid, &card_c, &mut rng);

    let approval = FfiApprovedWidening {
        block_uuid,
        file_fingerprint: staged.file_fingerprint,
        added_recipients: vec![staged.added_contact_uuid],
    };

    // A PRESENT but garbage state file at the exact path load() reads.
    std::fs::write(
        secretary_cli::state::state_file_path(state_dir.path(), staged.vault_uuid),
        b"not a canonical SyncState",
    )
    .unwrap();

    let err = repair_vault_with_password_in(
        Some(state_dir.path()),
        &folder,
        &pw,
        &device_uuid,
        3_000,
        &[approval],
    )
    .expect_err("§10 fail-closed must win even with a valid approval present");
    assert!(
        matches!(err, FfiVaultError::CorruptVault { .. }),
        "expected CorruptVault, got {err:?}",
    );
    assert_eq!(
        std::fs::read(folder.join("manifest.cbor.enc")).unwrap(),
        staged.manifest_pre_share,
        "refused repair must not mutate the manifest (fail-closed pre-write wins over consent)",
    );
}

// ── preview_repair arms (#374 Task 6) ───────────────────────────────────

/// `preview_repair_with_password` on a crashed-`share_block` (recipient-
/// widening) residue must report exactly one `FfiWideningReport`: the
/// affected block's name and hyphenated UUID, a `file_fingerprint_hex`
/// that round-trips the on-disk BLAKE3-256 fingerprint (and is 64
/// lowercase hex chars), and the one added recipient's hyphenated UUID +
/// verified display name + a 32-hex-char card fingerprint. Being
/// read-only, it must not touch the manifest at all.
#[test]
fn preview_with_password_reports_widening() {
    let (_tmp, folder) = tmp_golden_vault();
    let pw = golden_password();
    let pw_secret = SecretBytes::new(pw.clone());
    let mut rng = ChaCha20Rng::from_seed([0xb0; 32]);
    let open = open_vault(&folder, Unlocker::Password(&pw_secret), None).unwrap();
    let (device_uuid, block_uuid) = ([0xb1; 16], [0xb2; 16]);
    let card_c = mint_external_card(0xb3, "Cee");
    let staged = stage_crashed_share(&folder, open, block_uuid, device_uuid, &card_c, &mut rng);

    let manifest_before_preview = std::fs::read(folder.join("manifest.cbor.enc")).unwrap();

    let preview = preview_repair_with_password(&folder, &pw)
        .expect("preview must succeed on consent-eligible widening residue");

    assert_eq!(preview.widenings.len(), 1, "exactly one widened block");
    let report = &preview.widenings[0];
    assert_eq!(report.block_uuid_hex, format_uuid_hyphenated(&block_uuid));
    assert_eq!(report.block_name, "mine");
    assert_eq!(
        report.file_fingerprint_hex.len(),
        64,
        "file_fingerprint_hex must be 64 lowercase hex chars (BLAKE3-256)"
    );
    assert_eq!(
        report.file_fingerprint_hex,
        hex::encode(staged.file_fingerprint),
        "file_fingerprint_hex must round-trip the on-disk BLAKE3 fingerprint"
    );
    assert_eq!(report.added.len(), 1, "exactly one added recipient");
    let added = &report.added[0];
    assert_eq!(
        added.uuid_hex,
        format_uuid_hyphenated(&staged.added_contact_uuid)
    );
    assert_eq!(added.display_name, "Cee");
    assert_eq!(
        added.card_fingerprint_hex.len(),
        32,
        "card_fingerprint_hex must be 32 lowercase hex chars (16-byte identity fingerprint)"
    );

    // Read-only: preview must not write anything, including the manifest.
    assert_eq!(
        std::fs::read(folder.join("manifest.cbor.enc")).unwrap(),
        manifest_before_preview,
        "preview_repair must not mutate the manifest"
    );
}

/// A crashed `save_block` (interrupted content save, not a widening) is
/// exactly what `repair_vault` adopts unconditionally — there is nothing
/// to consent to. `preview_repair_with_password` must report zero
/// widenings for it.
#[test]
fn preview_with_password_empty_for_crashed_save() {
    let (_tmp, folder) = tmp_golden_vault();
    let pw = golden_password();
    let pw_secret = SecretBytes::new(pw.clone());
    let mut rng = ChaCha20Rng::from_seed([0xb4; 32]);
    let open = open_vault(&folder, Unlocker::Password(&pw_secret), None).unwrap();
    let (device_uuid, block_uuid) = ([0xb5; 16], [0xb6; 16]);
    stage_crashed_save(&folder, open, block_uuid, device_uuid, &mut rng);

    let preview = preview_repair_with_password(&folder, &pw)
        .expect("preview must succeed on adoptable (non-widening) residue");
    assert!(
        preview.widenings.is_empty(),
        "a crashed content save is not a widening; preview must report zero widenings, got {:?}",
        preview.widenings
    );
}

/// §10 fail-closed posture (#384) applies identically at preview time
/// (module docs on `super::preview`): an existing-but-unreadable
/// rollback-baseline state file must refuse `preview_repair_with_password`
/// as `CorruptVault` whose detail names the failing state file — before
/// any consent dialog would even be drawn. Mirrors
/// `repair_refuses_unreadable_rollback_baseline_and_leaves_manifest_untouched`
/// but through the read-only preview arm.
#[test]
fn preview_fails_closed_on_garbage_baseline_state() {
    let (_tmp, folder) = tmp_golden_vault();
    let state_dir = tempfile::tempdir().unwrap();
    let pw = golden_password();
    let pw_secret = SecretBytes::new(pw.clone());
    let mut rng = ChaCha20Rng::from_seed([0xb7; 32]);
    let open = open_vault(&folder, Unlocker::Password(&pw_secret), None).unwrap();
    let (device_uuid, block_uuid) = ([0xb8; 16], [0xb9; 16]);
    let staged = stage_crashed_save(&folder, open, block_uuid, device_uuid, &mut rng);

    // A PRESENT but garbage state file at the exact path load() reads.
    let state_path = secretary_cli::state::state_file_path(state_dir.path(), staged.vault_uuid);
    std::fs::write(&state_path, b"not a canonical SyncState").unwrap();

    let err = preview_repair_with_password_in(Some(state_dir.path()), &folder, &pw)
        .expect_err("existing-but-unreadable baseline must refuse the preview fail-closed");
    match err {
        FfiVaultError::CorruptVault { detail } => {
            assert!(
                detail.contains(&state_path.display().to_string()),
                "detail must name the failing state file: {detail}"
            );
            assert!(
                detail.contains("resets this device's rollback history"),
                "detail must carry the documented remedy: {detail}"
            );
        }
        other => panic!("expected CorruptVault, got {other:?}"),
    }
}
