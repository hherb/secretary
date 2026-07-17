//! Per-device working-copy handle for C.4 convergence tests.
//!
//! Each `Device` owns a deep copy of the baseline vault folder and
//! performs real `save_block` writes — no mocking, no byte surgery.
//! The ChaCha20 RNG is seeded per device so two devices never share
//! nonces (AEAD-uniqueness invariant; see CLAUDE.md atomic-write section).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use secretary_core::crypto::secret::{SecretBytes, SecretString};
use secretary_core::vault::block::VectorClockEntry;
use secretary_core::vault::{
    open_vault, purge_block, restore_block, save_block, trash_block, BlockPlaintext, Record,
    RecordField, RecordFieldValue, Unlocker,
};

use crate::convergence_helpers::Baseline;

/// One device's private replica of the shared vault. Owns a deep copy
/// of the baseline folder + a distinct device_uuid + a deterministic
/// RNG seed (the AEAD/signature randomness source for this device's
/// writes — distinct per device so two devices never share nonces).
pub struct Device {
    _tmp: tempfile::TempDir,
    folder: PathBuf,
    device_uuid: [u8; 16],
    password: SecretBytes,
    rng: ChaCha20Rng,
}

impl Device {
    /// Fork a private working copy of the baseline for this device.
    pub fn fork(baseline: &Baseline, device_uuid: [u8; 16], rng_seed: u8) -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let folder = tmp.path().to_path_buf();
        secretary_test_utils::copy_dir_recursive(baseline.folder(), &folder);
        Self {
            _tmp: tmp,
            folder,
            device_uuid,
            password: SecretBytes::new(crate::convergence_helpers::baseline_password_bytes()),
            rng: ChaCha20Rng::from_seed([rng_seed; 32]),
        }
    }

    pub fn folder(&self) -> &Path {
        &self.folder
    }

    pub fn device_uuid(&self) -> [u8; 16] {
        self.device_uuid
    }

    /// Insert-or-update record `record_uuid` in block `block_uuid` with a
    /// single text field `(field_name -> value)`, via a real `save_block`.
    pub fn edit_text_field(
        &mut self,
        block_uuid: [u8; 16],
        record_uuid: [u8; 16],
        field_name: &str,
        value: &str,
        now_ms: u64,
    ) {
        let record = self.build_record_with_field(record_uuid, field_name, value, now_ms, false);
        self.save_records(block_uuid, vec![record], now_ms);
    }

    /// Tombstone record `record_uuid` in block `block_uuid` (delete), via
    /// a real `save_block`. tombstoned_at_ms == last_mod_ms == now_ms.
    pub fn tombstone(&mut self, block_uuid: [u8; 16], record_uuid: [u8; 16], now_ms: u64) {
        let record = self.build_record_with_field(record_uuid, "k", "deleted", now_ms, true);
        self.save_records(block_uuid, vec![record], now_ms);
    }

    fn build_record_with_field(
        &self,
        record_uuid: [u8; 16],
        field_name: &str,
        value: &str,
        now_ms: u64,
        tombstone: bool,
    ) -> Record {
        let mut fields = BTreeMap::new();
        fields.insert(
            field_name.to_string(),
            RecordField {
                value: RecordFieldValue::Text(SecretString::from(value)),
                last_mod: now_ms,
                device_uuid: self.device_uuid,
                unknown: BTreeMap::new(),
            },
        );
        Record {
            record_uuid,
            record_type: "kv".to_string(),
            fields,
            tags: Vec::new(),
            created_at_ms: now_ms,
            last_mod_ms: now_ms,
            tombstone,
            tombstoned_at_ms: if tombstone { now_ms } else { 0 },
            unknown: BTreeMap::new(),
        }
    }

    fn save_records(&mut self, block_uuid: [u8; 16], records: Vec<Record>, now_ms: u64) {
        let mut open = open_vault(&self.folder, Unlocker::Password(&self.password), None)
            .expect("open working copy");
        let owner_card = open.owner_card.clone();
        let plaintext = BlockPlaintext {
            block_version: 1,
            block_uuid,
            block_name: "c4".to_string(),
            schema_version: 1,
            records,
            unknown: BTreeMap::new(),
        };
        save_block(
            &self.folder,
            &mut open,
            plaintext,
            std::slice::from_ref(&owner_card),
            self.device_uuid,
            now_ms,
            &mut self.rng,
        )
        .expect("save_block");
    }

    /// Trash a whole block (`blocks/` -> `trash/`) at `now_ms`, via a real
    /// `trash_block` call. Mirrors `save_records`'s open+call+expect shape.
    pub fn trash_block(&mut self, block_uuid: [u8; 16], now_ms: u64) {
        let mut open = open_vault(&self.folder, Unlocker::Password(&self.password), None)
            .expect("open working copy");
        trash_block(
            &self.folder,
            &mut open,
            block_uuid,
            self.device_uuid,
            now_ms,
            &mut self.rng,
        )
        .expect("trash_block");
    }

    /// Restore a trashed block (`trash/` -> `blocks/`) at `now_ms`, via a
    /// real `restore_block` call.
    pub fn restore_block(&mut self, block_uuid: [u8; 16], now_ms: u64) {
        let mut open = open_vault(&self.folder, Unlocker::Password(&self.password), None)
            .expect("open working copy");
        restore_block(
            &self.folder,
            &mut open,
            block_uuid,
            self.device_uuid,
            now_ms,
            &mut self.rng,
        )
        .expect("restore_block");
    }

    /// Permanently purge a trashed block at `now_ms`, via a real
    /// `purge_block` call.
    pub fn purge_block(&mut self, block_uuid: [u8; 16], now_ms: u64) {
        let mut open = open_vault(&self.folder, Unlocker::Password(&self.password), None)
            .expect("open working copy");
        purge_block(
            &self.folder,
            &mut open,
            block_uuid,
            self.device_uuid,
            now_ms,
            &mut self.rng,
        )
        .expect("purge_block");
    }

    /// Current manifest vector clock of this device's working copy.
    pub fn manifest_clock(&self) -> Vec<VectorClockEntry> {
        let open = open_vault(&self.folder, Unlocker::Password(&self.password), None)
            .expect("open working copy");
        open.manifest.vector_clock
    }

    /// Decrypt the named block in this device's working copy and return its records.
    pub fn decrypt_block_records(&self, block_uuid: [u8; 16]) -> Vec<Record> {
        crate::convergence_helpers::decrypt_block_records(&self.folder, &self.password, block_uuid)
    }
}
