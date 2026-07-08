//! Reusable two-device convergence harness. See `convergence.rs` and
//! `sync_trash_merge.rs` — two separate test binaries share this module
//! tree, each exercising a different subset of it.

#![allow(dead_code, unused_imports)] // not every test consumes every helper.

mod assert;
mod baseline;
mod device;
mod reconcile;
mod sync_drive;

pub use assert::{assert_converged, decrypt_state, LogicalRecord};
pub use baseline::Baseline;
pub use device::{copy_dir_all, Device};
pub use reconcile::reconcile;
pub use sync_drive::sync_as_pure_adopter;
pub use sync_drive::{is_nothing_to_do, sync_as_adopter, sync_as_merger, VetoPolicy};

use secretary_core::crypto::secret::SecretBytes;
use secretary_core::vault::{open_vault, Record, Unlocker};
use std::path::Path;

/// The shared baseline password as raw bytes (every device opens the same vault).
pub fn baseline_password_bytes() -> Vec<u8> {
    baseline::BASELINE_PASSWORD.to_vec()
}

/// Promote a seeded device's working copy into a fresh baseline whose
/// common-ancestor state includes the seed record. `prev` is consumed
/// to forward its password; `seed` lives in its own independent tempdir,
/// so copying from `seed.folder()` is independent of `prev`'s lifetime.
pub fn baseline_from_seeded(prev: Baseline, seed: &Device) -> Baseline {
    // Forward the actual baseline password rather than assuming the global
    // constant — avoids cryptic WrongPassword panics if the caller ever
    // creates a baseline with a non-default password.
    let password = prev.password().clone();
    Baseline::from_folder(seed.folder(), password)
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
