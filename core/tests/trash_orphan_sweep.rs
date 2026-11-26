//! The open-time sweep of trash files no `TrashEntry` names (#790,
//! vault-format §7, "Open-time unreferenced-file sweep").
//!
//! A restore keeps its `trash/<uuid>.cbor.enc.<ts>` file (§7.1 step 5) and
//! drops the entry. Open removes such a file once the block has been edited
//! since (its live clock strictly dominates the file's) and `<ts>` is more
//! than 90 days before the manifest's signed `last_mod_ms`. A peer's trash file
//! that arrives before the manifest naming it is kept.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use rand_core::{OsRng, RngCore};
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::vault::{
    open_vault, restore_block, save_block, trash_block, BlockPlaintext, OpenVault, Unlocker,
};
use secretary_test_utils::{copy_dir_to_tempdir, core_test_data_dir, golden_vault_001_password};

/// A timestamp after golden_vault_001's `created_at_ms`.
const T0: u64 = 2_000_000_100_000;
/// When the block is trashed: the kept file's suffix.
const TRASHED_AT: u64 = T0 + 1_000;
/// When it is restored.
const RESTORED_AT: u64 = T0 + 2_000;
/// The sweep's fixed window, 90 days (not the retention setting's default).
const WINDOW_MS: u64 = 90 * 24 * 60 * 60 * 1000;
/// The last write at which the sweep still keeps an unreferenced file.
const LAST_KEPT: u64 = TRASHED_AT + WINDOW_MS;

fn random_uuid() -> [u8; 16] {
    let mut u = [0u8; 16];
    OsRng.fill_bytes(&mut u);
    u
}

fn hyphenated(uuid: &[u8; 16]) -> String {
    let hex: String = uuid.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn block_path(folder: &Path, uuid: &[u8; 16]) -> PathBuf {
    folder
        .join("blocks")
        .join(format!("{}.cbor.enc", hyphenated(uuid)))
}

fn trash_path(folder: &Path, uuid: &[u8; 16], ts: u64) -> PathBuf {
    folder
        .join("trash")
        .join(format!("{}.cbor.enc.{ts}", hyphenated(uuid)))
}

struct Vault {
    tmp: tempfile::TempDir,
    pw: SecretBytes,
    device: [u8; 16],
}

impl Vault {
    fn new() -> Self {
        Self {
            tmp: copy_dir_to_tempdir(&core_test_data_dir().join("golden_vault_001")),
            pw: SecretBytes::new(golden_vault_001_password()),
            device: random_uuid(),
        }
    }

    fn folder(&self) -> &Path {
        self.tmp.path()
    }

    fn open(&self) -> OpenVault {
        open_vault(self.folder(), Unlocker::Password(&self.pw), None).expect("open")
    }

    fn save(&self, open: &mut OpenVault, uuid: [u8; 16], name: &str, at: u64) {
        let owner = open.owner_card.clone();
        let plaintext = BlockPlaintext {
            block_version: 1,
            block_uuid: uuid,
            block_name: name.to_string(),
            schema_version: 1,
            records: Vec::new(),
            unknown: BTreeMap::new(),
        };
        save_block(
            self.folder(),
            open,
            plaintext,
            &[owner],
            self.device,
            at,
            &mut OsRng,
        )
        .expect("save_block");
    }

    fn trash(&self, open: &mut OpenVault, uuid: [u8; 16], at: u64) {
        trash_block(self.folder(), open, uuid, self.device, at, &mut OsRng).expect("trash");
    }
}

/// Block `uuid` saved, trashed at [`TRASHED_AT`], restored, then edited at
/// `edited_at`, the vault's last write. Returns the vault and the uuid.
fn restored_then_edited(edited_at: u64) -> (Vault, [u8; 16]) {
    let vault = Vault::new();
    let uuid = random_uuid();
    let mut open = vault.open();
    vault.save(&mut open, uuid, "before", T0);
    vault.trash(&mut open, uuid, TRASHED_AT);
    restore_block(
        vault.folder(),
        &mut open,
        uuid,
        vault.device,
        RESTORED_AT,
        &mut OsRng,
    )
    .expect("restore");
    vault.save(&mut open, uuid, "after", edited_at);
    assert!(
        trash_path(vault.folder(), &uuid, TRASHED_AT).exists(),
        "restore keeps its trash file"
    );
    (vault, uuid)
}

#[test]
fn open_removes_an_unreferenced_trash_file_past_the_window() {
    let (vault, uuid) = restored_then_edited(LAST_KEPT + 1);

    let reopened = vault.open();

    assert!(!trash_path(vault.folder(), &uuid, TRASHED_AT).exists());
    assert!(reopened
        .manifest
        .blocks
        .iter()
        .any(|b| b.block_uuid == uuid));
    assert!(block_path(vault.folder(), &uuid).exists());
    vault.open();
}

#[test]
fn open_keeps_an_unreferenced_trash_file_exactly_window_old() {
    let (vault, uuid) = restored_then_edited(LAST_KEPT);

    vault.open();

    assert!(trash_path(vault.folder(), &uuid, TRASHED_AT).exists());
}

#[test]
fn open_keeps_a_peers_unmerged_trash_file_of_a_live_block() {
    // A peer trashed the block at TRASHED_AT; its file arrived before the
    // manifest naming it. The file's clock equals the live one, so it may be
    // the only copy a later trash-wins merge leaves restorable.
    let vault = Vault::new();
    let uuid = random_uuid();
    let mut open = vault.open();
    vault.save(&mut open, uuid, "trashed by a peer", T0);
    let peer_trash = trash_path(vault.folder(), &uuid, TRASHED_AT);
    fs::create_dir_all(peer_trash.parent().unwrap()).unwrap();
    fs::copy(block_path(vault.folder(), &uuid), &peer_trash).unwrap();
    vault.save(&mut open, random_uuid(), "a later write", LAST_KEPT + 1);

    vault.open();

    assert!(peer_trash.exists());
}

#[test]
fn open_keeps_named_and_out_of_grammar_trash_files() {
    let vault = Vault::new();
    let trashed = random_uuid();
    let mut open = vault.open();
    vault.save(&mut open, trashed, "still trashed", T0);
    vault.trash(&mut open, trashed, TRASHED_AT);
    let trash = vault.folder().join("trash");
    let planted = [
        trash.join("notes.txt"),
        trash.join(format!("{}.cbor.enc.007", hyphenated(&random_uuid()))),
        trash.join(format!(
            "{}.cbor.enc.5",
            hyphenated(&random_uuid()).to_uppercase()
        )),
    ];
    for p in &planted {
        fs::write(p, b"x").unwrap();
    }
    // A real block file under a uuid this manifest does not list: a peer's
    // trash of a block this device has not merged yet.
    let unknown = trash_path(vault.folder(), &random_uuid(), TRASHED_AT);
    fs::copy(trash_path(vault.folder(), &trashed, TRASHED_AT), &unknown).unwrap();
    vault.save(&mut open, random_uuid(), "a later write", LAST_KEPT + 1);

    vault.open();

    assert!(
        trash_path(vault.folder(), &trashed, TRASHED_AT).exists(),
        "a file its (unpurged) entry names stays, however old"
    );
    for p in &planted {
        assert!(p.exists(), "{p:?} is outside the trash grammar");
    }
    assert!(unknown.exists(), "a block not live here is kept");
}
