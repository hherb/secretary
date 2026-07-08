use std::path::Path;

use crate::crypto::hash::hash as blake3_hash;
use crate::vault::manifest::Manifest;
use crate::vault::orchestrators::{
    format_uuid_hyphenated, BLOCKS_SUBDIR, BLOCK_FILE_EXTENSION, TRASH_SUBDIR,
};
use crate::vault::trash_relocation::relocate_and_log;

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
        let _ = relocate_and_log(&entry.block_uuid, &trash_dir, &blocks_path, &trash_path);
    }
}

/// Best-effort removal of local `trash/` **and** `blocks/` files for
/// entries the signed manifest marks purged (#399, extended by #401). For
/// every `TrashEntry` with `purged_at_ms.is_some()` whose `block_uuid` is
/// **not live** in `manifest.blocks`, every `trash/<uuid>.cbor.enc.*` file
/// is deleted, and the exact `blocks/<uuid>.cbor.enc` file (if any) is
/// deleted too. The "not live" gate mirrors
/// [`complete_pending_trash_renames`] exactly and is what makes a
/// concurrent restore win safely: a restored block is live again, so its
/// files are left untouched regardless of the (stale) purge flag on the
/// merged-in `TrashEntry`.
///
/// No manifest mutation, no signing, no trust-state change; idempotent
/// (a purged, non-live entry with no matching file is simply a no-op); every
/// I/O failure is logged at `tracing::warn!` and otherwise tolerated — a
/// leftover file is a benign orphan, never a correctness problem, since
/// `restore_block` already fails fast with `VaultError::BlockPurged` on a
/// purged entry regardless of what is on disk.
///
/// This is what propagates a purge across the owner's devices via manifest
/// file sync: a peer device that already synced the purged manifest but has
/// not yet run its own local delete converges to the purged state at its
/// next `open_vault`. The `blocks/` pass additionally completes a purge on
/// a device that had concurrently restored the block before a peer's purge
/// won at the manifest level in a conflict-copy merge (§11.6): that
/// device's leftover `blocks/<uuid>.cbor.enc` is otherwise never cleaned up
/// since the block is purged-and-not-live, not trashed-and-not-live.
pub(crate) fn sweep_purged_trash_files(folder: &Path, manifest: &Manifest) {
    // Build the target prefix set once. Purged tombstones are terminal and
    // never pruned from `manifest.trash`, so this set grows over a vault's
    // lifetime; reading the trash directory once and matching every entry
    // against the set keeps the per-open cost at a single `read_dir`
    // syscall rather than one per purged entry.
    let live: std::collections::HashSet<[u8; 16]> =
        manifest.blocks.iter().map(|b| b.block_uuid).collect();
    // `(prefix, uuid_hex)` per purged-and-not-live entry; `uuid_hex` is
    // retained for the warn log. A live-and-purged UUID (should not arise
    // from a single well-behaved device, but can appear as a merge outcome —
    // e.g. this device's concurrent restore and a peer's purge both landing)
    // is excluded here so its file is never deleted.
    let targets: Vec<(String, String)> = manifest
        .trash
        .iter()
        .filter(|e| e.purged_at_ms.is_some() && !live.contains(&e.block_uuid))
        .map(|e| {
            let uuid_hex = format_uuid_hyphenated(&e.block_uuid);
            (format!("{uuid_hex}{BLOCK_FILE_EXTENSION}."), uuid_hex)
        })
        .collect();
    if targets.is_empty() {
        return;
    }
    let trash_dir = folder.join(TRASH_SUBDIR);
    let Ok(rd) = std::fs::read_dir(&trash_dir) else {
        return;
    };
    for de in rd.flatten() {
        let path = de.path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let Some((_, uuid_hex)) = targets
            .iter()
            .find(|(prefix, _)| name.starts_with(prefix.as_str()))
        else {
            continue;
        };
        if let Err(e) = std::fs::remove_file(&path) {
            tracing::warn!(
                block_uuid = %uuid_hex,
                error = %e,
                "purge sweep: failed to remove purged trash file; benign orphan remains"
            );
        }
    }

    // #401: a purged, not-live entry may also have a leftover
    // `blocks/<uuid>.cbor.enc` — the residue of a conflict-copy merge in
    // which this device concurrently restored the block before a peer's
    // purge won at the manifest level (§11.6). Remove it to complete the
    // purge on this device. Exact filename (no tombstone suffix), so no
    // read_dir scan is needed.
    let blocks_dir = folder.join(BLOCKS_SUBDIR);
    for (_prefix, uuid_hex) in &targets {
        let blocks_path = blocks_dir.join(format!("{uuid_hex}{BLOCK_FILE_EXTENSION}"));
        match std::fs::remove_file(&blocks_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {} // no residue — normal
            Err(e) => {
                tracing::warn!(
                    block_uuid = %uuid_hex,
                    error = %e,
                    "purge sweep: failed to remove purged blocks/ residue; benign orphan remains"
                );
            }
        }
    }
}
