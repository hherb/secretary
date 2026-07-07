use std::path::Path;

use crate::crypto::hash::hash as blake3_hash;
use crate::vault::manifest::Manifest;
use crate::vault::orchestrators::{
    format_uuid_hyphenated, BLOCKS_SUBDIR, BLOCK_FILE_EXTENSION, TRASH_SUBDIR,
};
use crate::vault::trash_relocation::log_relocation;

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
/// Idempotent; every I/O failure is logged at `tracing::warn!` (#376, via
/// `log_relocation`, EXDEV distinguished) and otherwise tolerated — a vault
/// that cannot complete the move, e.g. cross-filesystem trash/, stays in the
/// benign orphan state that `restore_block` resumes from.
pub(crate) fn complete_pending_trash_renames(folder: &Path, manifest: &Manifest) {
    let trash_dir = folder.join(TRASH_SUBDIR);
    let blocks_dir = folder.join(BLOCKS_SUBDIR);
    for entry in &manifest.trash {
        // Legacy pre-#293 entry: no signed content commitment, so there is no
        // safe gate against a planted blocks/ file — the sweep cannot relocate
        // it. Deliberately NOT migrated (#376): no tagged release ever wrote a
        // fingerprint==None entry, so no such vault exists in the wild; and
        // because relocation is organizational-only, a never-swept legacy
        // orphan is harmless — restore_block still recovers it via the §6.1
        // hybrid-verify + suffix-equality fallback the spec documents for
        // legacy entries.
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
        // #376: log a persistent relocation failure (EXDEV / permissions)
        // instead of swallowing it. Best-effort is unchanged — a vault that
        // cannot complete the move stays in the benign orphan state that
        // restore_block resumes from.
        let _ = log_relocation(
            &entry.block_uuid,
            std::fs::create_dir_all(&trash_dir)
                .and_then(|()| std::fs::rename(&blocks_path, &trash_path)),
        );
    }
}
