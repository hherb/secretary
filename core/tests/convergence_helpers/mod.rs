//! Reusable two-device convergence harness. See `convergence.rs`.
#![allow(dead_code)] // helpers land task-by-task; some are unused until later tasks

mod baseline;
mod device;
mod reconcile;
mod sync_drive;

pub use baseline::Baseline;
#[allow(unused_imports)] // copy_dir_all is unused until later convergence tasks
pub use device::{copy_dir_all, Device};
#[allow(unused_imports)] // SharedFolder is used by later convergence tasks
pub use reconcile::{reconcile, SharedFolder};
#[allow(unused_imports)]
// sync_as_pure_adopter is used by later convergence tasks (scenario 1)
pub use sync_drive::sync_as_pure_adopter;
pub use sync_drive::{is_nothing_to_do, sync_as_adopter, sync_as_merger, VetoPolicy};

use secretary_core::crypto::secret::SecretBytes;
use secretary_core::vault::{open_vault, Record, Unlocker};
use std::path::Path;

/// The shared baseline password as raw bytes (every device opens the same vault).
pub fn baseline_password_bytes() -> Vec<u8> {
    baseline::BASELINE_PASSWORD.to_vec()
}

/// Decrypt one block file in `folder` and return its records. Reuses the
/// proven `sync_helpers::decrypt_block_using_open`.
pub fn decrypt_block_records(
    folder: &Path,
    password: &SecretBytes,
    block_uuid: [u8; 16],
) -> Vec<Record> {
    let open = open_vault(folder, Unlocker::Password(password), None).expect("open for decrypt");
    let path = crate::sync_helpers::block_file_path(folder, &block_uuid);
    let bytes = std::fs::read(&path).expect("read block file");
    crate::sync_helpers::decrypt_block_using_open(&open, &bytes)
        .expect("decrypt block")
        .records
}
