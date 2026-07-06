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
    preview_repair_with_device_secret, preview_repair_with_password, preview_repair_with_recovery,
    repair_vault_with_device_secret, repair_vault_with_password, repair_vault_with_recovery,
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

mod adopt;
mod consent;
mod preview;
mod rollback_gate;
