//! Fixtures for `stale_session_guard.rs` (#101): a golden-vault copy, two
//! handles over it, and a byte-level snapshot of the whole vault folder so a
//! refused write can be shown to have touched no file at all.
//!
//! Fixture bodies are adapted from `share_block.rs` / `trash_restore.rs` /
//! `purge.rs` (integration-test bins share nothing unless pulled in via a
//! `mod`); the fixture copy itself comes from `secretary-test-utils`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::fs;
use std::path::{Path, PathBuf};

use rand_core::{OsRng, RngCore};
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::crypto::sig::{MlDsa65Secret, ED25519_SIG_LEN, ML_DSA_65_SIG_LEN};
use secretary_core::identity::card::{ContactCard, CARD_VERSION_V1};
use secretary_core::unlock::bundle::{self, IdentityBundle};
use secretary_core::vault::{
    open_vault, save_block, BlockPlaintext, OpenVault, Unlocker, VaultError,
};
use secretary_test_utils::{copy_dir_to_tempdir, core_test_data_dir, golden_vault_001_password};

/// A timestamp after golden_vault_001's `created_at_ms`. Tests add offsets.
pub const T0: u64 = 2_000_000_100_000;

/// A per-test copy of golden_vault_001 plus its password.
pub struct Fixture {
    pub tmp: tempfile::TempDir,
    pub pw: SecretBytes,
}

impl Fixture {
    pub fn new() -> Self {
        Self {
            tmp: copy_dir_to_tempdir(&core_test_data_dir().join("golden_vault_001")),
            pw: SecretBytes::new(golden_vault_001_password()),
        }
    }

    pub fn folder(&self) -> &Path {
        self.tmp.path()
    }

    pub fn open(&self) -> OpenVault {
        open_vault(self.folder(), Unlocker::Password(&self.pw), None).expect("open_vault")
    }

    /// Two handles over the same vault, then a write through `fresh` so the
    /// on-disk manifest moves past what `stale` loaded.
    pub fn stale_and_fresh(&self) -> (OpenVault, OpenVault) {
        let stale = self.open();
        let mut fresh = self.open();
        let owner = fresh.owner_card.clone();
        save(self.folder(), &mut fresh, uuid(), &[owner], T0 + 5_000).expect("fresh write");
        (stale, fresh)
    }

    /// The refusal contract: the stale writer returned `ManifestChangedOnDisk`,
    /// every file under the vault folder is byte-identical to `before`, and the
    /// vault still opens.
    pub fn assert_refused_untouched<T: Debug>(
        &self,
        before: &BTreeMap<PathBuf, Vec<u8>>,
        result: Result<T, VaultError>,
    ) {
        match result {
            Err(VaultError::ManifestChangedOnDisk) => {}
            other => panic!("expected Err(ManifestChangedOnDisk), got {other:?}"),
        }
        let after = snapshot_tree(self.folder());
        let changed: BTreeSet<&PathBuf> = before
            .keys()
            .chain(after.keys())
            .filter(|k| before.get(*k) != after.get(*k))
            .collect();
        assert!(
            changed.is_empty(),
            "a refused write must leave every vault file untouched; changed: {changed:?}"
        );
        self.open();
    }
}

/// A runtime-random 16-byte id (block or device uuid).
pub fn uuid() -> [u8; 16] {
    let mut u = [0u8; 16];
    OsRng.fill_bytes(&mut u);
    u
}

/// Every file under `folder`, keyed by its path relative to `folder`.
/// Directories are recorded too (with an empty value) so a refused write
/// that only created `trash/` or `blocks/` is still caught.
pub fn snapshot_tree(folder: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(dir).expect("read_dir") {
            let path = entry.expect("dir entry").path();
            let rel = path.strip_prefix(root).expect("under root").to_path_buf();
            if path.is_dir() {
                out.insert(rel, Vec::new());
                walk(root, &path, out);
            } else {
                out.insert(rel, fs::read(&path).expect("read file"));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(folder, folder, &mut out);
    out
}

/// Save an empty-records block under a fresh random device uuid.
pub fn save(
    folder: &Path,
    open: &mut OpenVault,
    block_uuid: [u8; 16],
    recipients: &[ContactCard],
    now_ms: u64,
) -> Result<(), VaultError> {
    let plaintext = BlockPlaintext {
        block_version: 1,
        block_uuid,
        block_name: "stale-guard".to_string(),
        schema_version: 1,
        records: Vec::new(),
        unknown: BTreeMap::new(),
    };
    save_block(
        folder,
        open,
        plaintext,
        recipients,
        uuid(),
        now_ms,
        &mut OsRng,
    )
}

/// A fresh external identity and its self-signed contact card.
pub fn external_card(name: &str) -> ContactCard {
    let id: IdentityBundle = bundle::generate(name, T0, &mut OsRng);
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
