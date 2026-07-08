//! `list_trashed_blocks` — D.1.5 by-name projection of the manifest
//! trash list for the desktop Trash view.
//!
//! The manifest's [`secretary_core::vault::manifest::TrashEntry`] carries
//! only the block UUID + tombstone metadata; the human-readable block
//! name lives inside the *encrypted* trashed block file. So building the
//! Trash view requires decrypting each trashed file far enough to read
//! its `block_name`. We decrypt the newest file per UUID — selecting the
//! same file `core::vault::restore_block` would (highest canonical-decimal
//! `<ts>` suffix; non-canonical suffixes such as leading-zero forms are
//! skipped to match core's §7 grammar) — using the shared
//! `decrypt_block_file_bytes` tail, then immediately let the decrypted
//! plaintext drop (zeroize) — only the name is projected out. Record
//! plaintext NEVER escapes this function.
//!
//! As of #172 the decrypted name is memoized on the
//! [`OpenVaultManifest`] handle, keyed by
//! `(block_uuid, <ts>)` — the on-disk file version. Repeat calls with an
//! unchanged file hit the memo and skip the decrypt; a re-trash (higher
//! `<ts>`) or restore self-invalidates. Names are non-secret in the
//! bridge (already plaintext in the manifest's block summaries) and the
//! memo is cleared on handle `wipe`.

use std::path::{Path, PathBuf};

use crate::error::FfiVaultError;
use crate::identity::UnlockedIdentity;
use crate::record::orchestration::{decrypt_block_file_bytes, handle_wiped, uuid_hyphenated};
use crate::vault::OpenVaultManifest;

/// One trashed block, projected by name for the Trash view. Carries the
/// tombstone metadata from the manifest [`TrashEntry`] plus the
/// `block_name` recovered by decrypting the trashed file.
///
/// [`TrashEntry`]: secretary_core::vault::manifest::TrashEntry
#[derive(Clone, Debug)]
pub struct TrashedBlock {
    /// The trashed block's UUID (matches the `block_uuid` in the
    /// manifest [`TrashEntry`] and the on-disk `trash/<uuid>.cbor.enc.<ts>`
    /// filename).
    ///
    /// [`TrashEntry`]: secretary_core::vault::manifest::TrashEntry
    pub block_uuid: [u8; 16],
    /// Human-readable block name, recovered by decrypting the newest
    /// trashed file for this UUID.
    pub block_name: String,
    /// Unix-millis timestamp the block was moved to trash (from the
    /// manifest trash entry).
    pub tombstoned_at_ms: u64,
    /// UUID of the device that trashed the block (from the manifest
    /// trash entry).
    pub tombstoned_by: [u8; 16],
}

/// List every trashed block in an open vault, projected by name.
///
/// For each NOT-yet-purged entry in `manifest.trash`, locates the newest
/// `trash/<uuid>.cbor.enc.<ts>` file, decrypts it as the vault owner,
/// and projects `{ block_uuid, block_name, tombstoned_at_ms,
/// tombstoned_by }`. The decrypted block plaintext (including all record
/// material) is dropped — and thereby zeroized — at the end of each
/// iteration; nothing but the block name leaves this function.
///
/// #399: an already-purged entry (`purged_at_ms.is_some()`) is skipped
/// silently — its trash file was intentionally removed by `purge_block`
/// / `empty_trash`, so a missing file there is expected, not an
/// integrity violation.
///
/// # Errors
///
/// - [`FfiVaultError::CorruptVault`] — the manifest handle has been
///   wiped, a NOT-yet-purged trash entry has no matching file on disk
///   (an integrity violation, surfaced as a typed error rather than
///   silently skipped), or any decrypt failure from
///   `decrypt_block_file_bytes` (malformed file, signature/decap/tag
///   failure, closed identity).
/// - [`FfiVaultError::FolderInvalid`] — a trashed file is present but
///   unreadable for non-NotFound IO reasons (permissions, EBUSY, etc).
pub fn list_trashed_blocks(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
) -> Result<Vec<TrashedBlock>, FfiVaultError> {
    let (manifest_body, owner_card, vault_folder) = manifest
        .snapshot_for_read_block()
        .ok_or_else(handle_wiped)?;

    let trash_dir = vault_folder.join("trash");
    let mut out: Vec<TrashedBlock> = Vec::with_capacity(manifest_body.trash.len());
    // Misses decrypted this call, applied to the memo after the loop.
    let mut cache_updates: Vec<([u8; 16], u64, String)> = Vec::new();
    // The current live-trash uuid set; the memo is pruned to this so
    // restored/stale entries do not accumulate.
    let live_uuids: std::collections::HashSet<[u8; 16]> =
        manifest_body.trash.iter().map(|e| e.block_uuid).collect();

    for entry in &manifest_body.trash {
        // #399: a purged entry legitimately has no trash file — its
        // ciphertext was intentionally deleted by `purge_block` /
        // `empty_trash`. Skip it silently rather than falling into the
        // "no file ⇒ integrity error" check below, which is reserved for
        // a NOT-yet-purged entry whose file is unexpectedly missing.
        if entry.purged_at_ms.is_some() {
            continue;
        }

        let (path, ts) = newest_trash_file(&trash_dir, &entry.block_uuid)?.ok_or_else(|| {
            FfiVaultError::CorruptVault {
                detail: format!(
                    "trash entry has no matching file for {}",
                    hex::encode(entry.block_uuid)
                ),
            }
        })?;

        // Memo hit (same uuid + same on-disk ts) → skip the decrypt.
        let block_name = if let Some(name) = manifest.trash_name_cache_get(&entry.block_uuid, ts) {
            name
        } else {
            let bytes = std::fs::read(&path).map_err(|e| FfiVaultError::FolderInvalid {
                detail: format!("failed to read trash file: {e}"),
            })?;
            // Decrypt only to read the name. `plaintext` drops (zeroizes)
            // at the end of this block — record material never escapes.
            let plaintext = decrypt_block_file_bytes(identity, &owner_card, &bytes)?;
            let name = plaintext.block_name.clone();
            cache_updates.push((entry.block_uuid, ts, name.clone()));
            name
        };

        out.push(TrashedBlock {
            block_uuid: entry.block_uuid,
            block_name,
            tombstoned_at_ms: entry.tombstoned_at_ms,
            tombstoned_by: entry.tombstoned_by,
        });
    }

    // Apply this call's freshly-decrypted names and prune to the live set.
    manifest.trash_name_cache_put_and_prune(cache_updates, &live_uuids);

    Ok(out)
}

/// Scan `trash_dir` for files named `<uuid_hyphenated>.cbor.enc.<ts>`
/// and return the path with the highest `<ts>` suffix together with that
/// `<ts>` (newest-wins, matching `core::vault::restore_block`'s
/// selection). The `<ts>` doubles as the #172 name-memo version key.
/// Returns `Ok(None)` when the directory is missing or holds no matching
/// file.
///
/// Suffixes that are not a canonical decimal `u64` — non-`u64`-parseable
/// forms AND non-canonical decimals such as leading-zero forms (e.g.
/// `"00123"`) — are skipped rather than erroring, matching core's §7
/// grammar so a single junk filename alongside a valid one cannot wedge
/// the listing and the bridge picks the SAME file restore would.
fn newest_trash_file(
    trash_dir: &Path,
    block_uuid: &[u8; 16],
) -> Result<Option<(PathBuf, u64)>, FfiVaultError> {
    let prefix = format!("{}.cbor.enc.", uuid_hyphenated(block_uuid));

    let read_dir = match std::fs::read_dir(trash_dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(FfiVaultError::FolderInvalid {
                detail: format!("failed to read trash directory: {e}"),
            })
        }
    };

    let mut best: Option<(u64, PathBuf)> = None;
    for dirent in read_dir {
        let dirent = dirent.map_err(|e| FfiVaultError::FolderInvalid {
            detail: format!("failed to read trash directory entry: {e}"),
        })?;
        let name = dirent.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(suffix) = name.strip_prefix(&prefix) else {
            continue;
        };
        let Ok(ts) = suffix.parse::<u64>() else {
            continue;
        };
        // Spec §7 grammar: `<unix-millis>` is the canonical decimal
        // ASCII form of a u64 (no leading `+`, no leading zeros except
        // `0` itself). `u64::from_str` rejects sign-bearing forms but
        // accepts leading-zero forms (`"00123"` → 123), so pin the
        // canonical form explicitly — matching `core::vault::restore_block`'s
        // identical guard so the list selects the SAME file restore would.
        if ts.to_string() != suffix {
            continue;
        }
        if best.as_ref().is_none_or(|(b, _)| ts > *b) {
            best = Some((ts, dirent.path()));
        }
    }

    Ok(best.map(|(ts, p)| (p, ts)))
}
