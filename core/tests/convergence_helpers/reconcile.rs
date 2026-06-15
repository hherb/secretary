use std::path::{Path, PathBuf};

use crate::convergence_helpers::{copy_dir_all, Device};

/// The reconciled shared folder both devices sync against. Owns its TempDir.
pub struct SharedFolder {
    _tmp: tempfile::TempDir,
    folder: PathBuf,
}

impl SharedFolder {
    pub fn folder(&self) -> &Path {
        &self.folder
    }
}

/// Emulate a cloud-sync reconcile of two concurrent device writes into a
/// single shared folder.
///
/// - `canonical`: the device whose files become the canonical
///   `manifest.cbor.enc` / `blocks/<uuid>.cbor.enc`.
/// - `merger`: `Some(device)` whose `manifest.cbor.enc` and
///   `blocks/<uuid>.cbor.enc` are copied in as conflict-copy siblings;
///   `None` for the one-editor (auto-apply) scenario.
/// - `block_uuid`: the block the canonical device (and optionally the merger) touched.
pub fn reconcile(
    canonical: &Device,
    merger: Option<&Device>,
    block_uuid: [u8; 16],
) -> SharedFolder {
    let tmp = tempfile::tempdir().expect("tempdir");
    let folder = tmp.path().to_path_buf();
    copy_dir_all(canonical.folder(), &folder).expect("copy canonical into shared");

    if let Some(merger_dev) = merger {
        let merger_uuid = merger_dev.device_uuid();
        // first byte only — sufficient while device UUIDs are distinct in byte 0 (e.g. [0x0A;16] / [0x0B;16]); extend to more bytes if the harness gains devices that collide here.
        let suffix = format!(".sync-conflict-from-device-{:02x}", merger_uuid[0]);

        // Manifest conflict-copy.
        let merger_manifest = merger_dev.folder().join("manifest.cbor.enc");
        let manifest_sibling = folder.join(format!("manifest.cbor.enc{suffix}"));
        std::fs::copy(&merger_manifest, &manifest_sibling).expect("copy manifest sibling");

        // Block conflict-copy (only if the merger actually wrote the block).
        let merger_block = crate::sync_helpers::block_file_path(merger_dev.folder(), &block_uuid);
        if merger_block.exists() {
            let canonical_block = crate::sync_helpers::block_file_path(&folder, &block_uuid);
            let block_sibling_name = format!(
                "{}{}",
                canonical_block.file_name().unwrap().to_string_lossy(),
                suffix
            );
            let block_sibling = canonical_block.with_file_name(block_sibling_name);
            std::fs::copy(&merger_block, &block_sibling).expect("copy block sibling");
        }
    }

    SharedFolder { _tmp: tmp, folder }
}
