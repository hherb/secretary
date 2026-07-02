//! #350 crash-recovery: the open-time trash-completion sweep (this
//! task) and the explicit [`repair_vault`] orchestrator (added on top).
//!
//! Split out of `orchestrators.rs` (already ~2.8k lines) — one concept
//! per file: everything here exists to converge a crash-interrupted
//! vault back to the §6.5/§7 on-disk shape without weakening the
//! manifest-as-integrity-commitment.

use std::path::Path;

use crate::crypto::hash::hash as blake3_hash;

use super::manifest::Manifest;
use super::orchestrators::{
    format_uuid_hyphenated, BLOCKS_SUBDIR, BLOCK_FILE_EXTENSION, TRASH_SUBDIR,
};

/// Best-effort completion of trash renames interrupted between
/// `trash_block`'s manifest commit and its physical move (#350).
///
/// For every signed `TrashEntry` whose §7 trash file is absent: if the
/// UUID is not live in `manifest.blocks` and `blocks/<uuid>.cbor.enc`
/// exists with bytes hashing to the entry's signed `fingerprint`, the
/// file is renamed to `trash/<uuid>.cbor.enc.<tombstoned_at_ms>`.
///
/// Rename-only: no manifest mutation, no signing, no trust-state
/// change — the gate is the *signed* content commitment, so an attacker
/// who plants an arbitrary `blocks/` file cannot steer the sweep.
/// Idempotent; every I/O failure is swallowed (a vault that cannot
/// complete the move, e.g. cross-filesystem trash/, stays in the benign
/// orphan state that `restore_block` resumes from).
pub(crate) fn complete_pending_trash_renames(folder: &Path, manifest: &Manifest) {
    let trash_dir = folder.join(TRASH_SUBDIR);
    let blocks_dir = folder.join(BLOCKS_SUBDIR);
    for entry in &manifest.trash {
        // Legacy pre-#293 entry: no signed commitment → no safe gate.
        let Some(committed_fp) = entry.fingerprint else {
            continue;
        };
        // Live-and-trashed (trash → re-save same uuid): never touch the
        // live file, regardless of hashes.
        if manifest
            .blocks
            .iter()
            .any(|b| b.block_uuid == entry.block_uuid)
        {
            continue;
        }
        let uuid_hex = format_uuid_hyphenated(&entry.block_uuid);
        let trash_path = trash_dir.join(format!(
            "{uuid_hex}{BLOCK_FILE_EXTENSION}.{}",
            entry.tombstoned_at_ms
        ));
        if trash_path.exists() {
            continue; // move already completed
        }
        let blocks_path = blocks_dir.join(format!("{uuid_hex}{BLOCK_FILE_EXTENSION}"));
        let Ok(bytes) = std::fs::read(&blocks_path) else {
            continue; // no orphan (or unreadable — best-effort)
        };
        if *blake3_hash(&bytes).as_bytes() != committed_fp {
            continue; // not the committed bytes — planted or clobbered
        }
        let _ = std::fs::create_dir_all(&trash_dir)
            .and_then(|()| std::fs::rename(&blocks_path, &trash_path));
    }
}
