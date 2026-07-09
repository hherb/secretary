//! Permanent purge of trashed blocks (#399). Manifest-first: mark the
//! `TrashEntry` purged (commit point = manifest write), then best-effort
//! delete the local `trash/` ciphertext. One erasure mechanism — plain
//! `fs::remove_file`, no overwrite (secure-erase-by-overwrite is
//! unachievable on SSD/CoW filesystems anyway; the bytes are already
//! ciphertext, and unlinking destroys the only local copy of the wrapped
//! Block Content Key, which is what actually renders the plaintext
//! unrecoverable). Owner-only vs shared is classified from the §6.2
//! cleartext recipient table purely for user-facing reporting — it never
//! gates whether the purge proceeds.

use std::path::Path;

use rand_core::{CryptoRng, RngCore};

use crate::identity::card::ContactCard;
use crate::identity::fingerprint::fingerprint;
use crate::vault::block::{self, RecipientWrap};
use crate::vault::orchestrators::{
    format_uuid_hyphenated, resign_and_write_manifest, tick_clock, BLOCK_FILE_EXTENSION,
    TRASH_SUBDIR,
};
use crate::vault::{OpenVault, VaultError};

/// Pure classification over a block file's cleartext §6.2 recipient
/// table: `(was_shared, recipient_count)`.
///
/// `was_shared` is `true` iff at least one recipient's fingerprint
/// differs from `owner_fp` — i.e. the block was ever readable by anyone
/// other than the owner. `recipient_count` is simply the table length.
/// Pure and I/O-free by design ([[feedback_pure_functions]]): the caller
/// is responsible for sourcing `recipients` from an on-disk block file
/// and `owner_fp` from the owner's contact card.
pub(crate) fn classify_recipients(
    recipients: &[RecipientWrap],
    owner_fp: &[u8; 16],
) -> (bool, u16) {
    let count = recipients.len() as u16;
    let was_shared = recipients
        .iter()
        .any(|r| &r.recipient_fingerprint != owner_fp);
    (was_shared, count)
}

/// Report of a completed (or already-completed) `purge_block` call.
///
/// `was_shared` / `recipient_count` are `None` when the trash file could
/// not be read/decoded at classification time (already purged on a prior
/// call, or the file was independently lost) — an honest "unknown",
/// never a fabricated `false`/`0`.
#[derive(Debug, Clone)]
pub struct PurgeReport {
    pub block_uuid: [u8; 16],
    pub was_shared: Option<bool>,
    pub recipient_count: Option<u16>,
    pub files_removed: usize,
}

/// Best-effort removal of every `trash/<uuid>.cbor.enc.*` file for any
/// UUID in `block_uuids` (for a given UUID there is normally exactly one —
/// the current tombstoned copy — but a crash-residue orphan from an
/// earlier trash/restore cycle could also match). Returns
/// `(removed, failed)` — the count actually removed and the count whose
/// `fs::remove_file` call errored, aggregated across every target UUID.
///
/// The trash directory is read a **single time** and each entry matched
/// against every target prefix, so the syscall cost is one `read_dir`
/// regardless of how many UUIDs are being purged — `empty_trash` (a whole
/// batch) would otherwise re-scan the directory once per target.
///
/// Individual failures are logged via `tracing::warn!` and tolerated: a
/// lingering file is a benign orphan (`open_vault`'s fingerprint check
/// only walks `manifest.blocks`, and a purged UUID is never re-added
/// there), not a correctness problem — callers that don't need the
/// failure count (`purge_block`) simply discard it. Caller must have
/// already established each `block_uuid` is a trash entry (true by
/// construction for every call site).
fn remove_trash_files(folder: &Path, block_uuids: &[[u8; 16]]) -> (usize, usize) {
    if block_uuids.is_empty() {
        return (0, 0);
    }
    let trash_dir = folder.join(TRASH_SUBDIR);
    // `(prefix, uuid_hex)` per target; `uuid_hex` retained for the warn log.
    let targets: Vec<(String, String)> = block_uuids
        .iter()
        .map(|u| {
            let uuid_hex = format_uuid_hyphenated(u);
            (format!("{uuid_hex}{BLOCK_FILE_EXTENSION}."), uuid_hex)
        })
        .collect();
    let mut removed = 0usize;
    let mut failed = 0usize;
    let Ok(rd) = std::fs::read_dir(&trash_dir) else {
        return (0, 0);
    };
    for entry in rd.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let Some((_, uuid_hex)) = targets
            .iter()
            .find(|(prefix, _)| name.starts_with(prefix.as_str()))
        else {
            continue;
        };
        match std::fs::remove_file(&path) {
            Ok(()) => removed += 1,
            Err(e) => {
                failed += 1;
                tracing::warn!(
                    block_uuid = %uuid_hex,
                    error = %e,
                    "failed to remove trash file; benign orphan remains"
                );
            }
        }
    }
    (removed, failed)
}

/// Best-effort classification of the current trash target
/// (`trash/<uuid>.cbor.enc.<tombstoned_at_ms>`) for reporting only.
///
/// Reads and decodes the on-disk block file to reach its cleartext §6.2
/// recipient table — no AEAD-decrypt, no plaintext ever touched. Returns
/// `None` when the file is absent or fails to decode (crash residue,
/// prior purge, on-disk corruption): an honest "unknown" rather than a
/// fabricated classification.
pub(crate) fn classify_trash_target(
    folder: &Path,
    block_uuid: &[u8; 16],
    tombstoned_at_ms: u64,
    owner_card: &ContactCard,
) -> Option<(bool, u16)> {
    let uuid_hex = format_uuid_hyphenated(block_uuid);
    let path = folder.join(TRASH_SUBDIR).join(format!(
        "{uuid_hex}{BLOCK_FILE_EXTENSION}.{tombstoned_at_ms}"
    ));
    let bytes = std::fs::read(&path).ok()?;
    let block_file = block::decode_block_file(&bytes).ok()?;
    let owner_fp = fingerprint(&owner_card.to_canonical_cbor().ok()?);
    Some(classify_recipients(&block_file.recipients, &owner_fp))
}

/// Permanently purge a trashed block: mark its `TrashEntry` purged
/// (signed-manifest write = commit point, mirrors `trash_block`'s
/// manifest-first discipline) and best-effort remove the local `trash/`
/// ciphertext. `docs/vault-format.md` §7 (purge extension, #399).
///
/// Sequence:
/// 1. Locate the `TrashEntry` for `block_uuid` → [`VaultError::BlockNotInTrash`]
///    if absent.
/// 2. **Idempotent re-purge**: if already purged (`purged_at_ms.is_some()`),
///    return success without touching the manifest again — only a
///    best-effort residual-file cleanup runs. `was_shared` /
///    `recipient_count` are `None` (no fresh classification is
///    performed; the file may already be gone).
/// 3. Otherwise, classify the current trash target's recipients
///    (reporting-only, best-effort — `None` on any read/decode failure).
/// 4. Stage a manifest clone with `trash[idx].purged_at_ms = Some(now_ms)`,
///    tick the vault-level vector clock, re-sign, atomic-write. **This
///    write is the commit point.**
/// 5. Swap the staged manifest into `open`. From here the purge has
///    happened; nothing below may fail the call.
/// 6. Best-effort `fs::remove_file` every `trash/<uuid>.cbor.enc.*` file.
///    One erasure mechanism, no overwrite (see module docs).
pub fn purge_block(
    folder: &Path,
    open: &mut OpenVault,
    block_uuid: [u8; 16],
    device_uuid: [u8; 16],
    now_ms: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<PurgeReport, VaultError> {
    // Step 1: locate the TrashEntry.
    let idx = open
        .manifest
        .trash
        .iter()
        .position(|t| t.block_uuid == block_uuid)
        .ok_or(VaultError::BlockNotInTrash { block_uuid })?;

    // Step 2: idempotent re-purge — already purged, no second manifest
    // write. Still best-effort clean any residual file (crash residue
    // from a prior partial purge, or a lingering orphan).
    if open.manifest.trash[idx].purged_at_ms.is_some() {
        let (files_removed, _files_failed) = remove_trash_files(folder, &[block_uuid]);
        return Ok(PurgeReport {
            block_uuid,
            was_shared: None,
            recipient_count: None,
            files_removed,
        });
    }

    let tombstoned_at_ms = open.manifest.trash[idx].tombstoned_at_ms;

    // Step 3: classify (reporting only), best-effort.
    let (was_shared, recipient_count) =
        match classify_trash_target(folder, &block_uuid, tombstoned_at_ms, &open.owner_card) {
            Some((shared, count)) => (Some(shared), Some(count)),
            None => (None, None),
        };

    // Step 4: stage the purged marker + tick the vault clock on a
    // clone; nothing observable changes until the manifest write below
    // succeeds. Mirrors `trash_block`'s manifest-first sequence exactly.
    let mut staged = open.manifest.clone();
    staged.trash[idx].purged_at_ms = Some(now_ms);
    tick_clock(&mut staged.vector_clock, &device_uuid)?;
    let new_manifest_file = resign_and_write_manifest(
        folder,
        &staged,
        &open.identity,
        &open.identity_block_key,
        &open.manifest_file.header,
        now_ms,
        open.manifest_file.author_fingerprint,
        rng,
        "purge_block: failed to write manifest.cbor.enc",
    )?;

    // Step 5: swap staged state into `open`. From here the purge has
    // happened; nothing below may fail the call.
    open.manifest = staged;
    open.manifest_file = new_manifest_file;

    // Step 6: best-effort physical removal. The uuid is (by construction,
    // step 1) a trash entry, never a live `manifest.blocks` entry, so
    // deleting its `trash/` files cannot orphan a live block.
    let (files_removed, _files_failed) = remove_trash_files(folder, &[block_uuid]);
    Ok(PurgeReport {
        block_uuid,
        was_shared,
        recipient_count,
        files_removed,
    })
}

/// Report of a completed `empty_trash` call: aggregate counts across every
/// `TrashEntry` that was not-yet-purged and not-live at call time.
///
/// `Default` yields the all-zero report `empty_trash` returns when there is
/// nothing to purge (no manifest write occurs in that case).
#[derive(Debug, Clone, Default)]
pub struct EmptyTrashReport {
    /// Number of `TrashEntry` records newly marked purged by this call.
    pub purged_count: usize,
    /// Of `purged_count`, how many were classified as shared (at least one
    /// non-owner recipient) at classification time.
    pub shared_count: usize,
    /// Of `purged_count`, how many were classified as owner-only.
    pub owner_only_count: usize,
    /// Of `purged_count`, how many could not be classified (trash file
    /// unreadable/undecodable — an honest "unknown", never fabricated).
    pub unknown_count: usize,
    /// Total on-disk `trash/` files removed across every purged entry.
    pub files_removed: usize,
    /// Total on-disk `trash/` file removals that errored (benign orphans;
    /// logged via `tracing::warn!` at removal time, never fatal).
    pub files_failed: usize,
}

/// Batch commit for permanent purge, shared by [`empty_trash`] and
/// `retention::auto_purge_expired`. Stages `purged_at_ms = Some(now_ms)`
/// on every `target_indices` entry of one manifest clone, ticks the vault
/// clock **once**, re-signs **once**, atomic-writes **once**, swaps the
/// staged state into `open`, then best-effort removes every purged UUID's
/// `trash/` files in one directory scan. Returns `(files_removed,
/// files_failed)`.
///
/// **Precondition:** `target_indices` is non-empty and every index is a
/// not-already-purged, not-live `manifest.trash` entry (a live-and-trashed
/// UUID must never be purged — the two lists are mutually exclusive). The
/// caller performs any recipient classification *before* calling, while
/// the trash files are still guaranteed present. The manifest write is the
/// commit point; nothing after it may fail the call.
///
/// `context` is the caller-supplied error-context label passed through to
/// `resign_and_write_manifest` on a manifest-write failure, so the reported
/// error identifies which caller (`empty_trash`, `auto_purge_expired`, ...)
/// triggered the failing write rather than a generic
/// `purge_batch_commit: ...` message.
pub(crate) fn purge_batch_commit(
    folder: &Path,
    open: &mut OpenVault,
    target_indices: &[usize],
    now_ms: u64,
    device_uuid: [u8; 16],
    rng: &mut (impl RngCore + CryptoRng),
    context: &'static str,
) -> Result<(usize, usize), VaultError> {
    let mut staged = open.manifest.clone();
    for &idx in target_indices {
        staged.trash[idx].purged_at_ms = Some(now_ms);
    }
    tick_clock(&mut staged.vector_clock, &device_uuid)?;
    let new_manifest_file = resign_and_write_manifest(
        folder,
        &staged,
        &open.identity,
        &open.identity_block_key,
        &open.manifest_file.header,
        now_ms,
        open.manifest_file.author_fingerprint,
        rng,
        context,
    )?;
    open.manifest = staged;
    open.manifest_file = new_manifest_file;

    let target_uuids: Vec<[u8; 16]> = target_indices
        .iter()
        .map(|&idx| open.manifest.trash[idx].block_uuid)
        .collect();
    Ok(remove_trash_files(folder, &target_uuids))
}

/// Permanently purge every currently-trashed, not-already-purged,
/// not-live block in one batch — the "empty trash" user operation.
/// `docs/vault-format.md` §7 (purge extension, #399).
///
/// Targets are every `TrashEntry` with `purged_at_ms.is_none()` whose
/// `block_uuid` does not also appear in `manifest.blocks` (a live entry
/// there means a concurrent restore won the merge — see
/// `repair.rs`/`crash_recovery.rs`'s "not live" gate — and must never be
/// purged).
///
/// Unlike `purge_block`, which re-signs the manifest once per call, this
/// is a **single batch commit**: every target is classified against the
/// still-on-disk trash file *before* the write, then all of them are
/// marked purged on one manifest clone, ticked once, re-signed once, and
/// atomically written once — one `now_ms`, one signature, one on-disk
/// generation. Only after that single write succeeds does the best-effort
/// file cleanup run (per-file failure never aborts the batch, mirroring
/// `purge_block`'s step 6).
///
/// An empty target set (nothing to purge) returns
/// `EmptyTrashReport::default()` without touching the manifest at all —
/// no clock tick, no re-sign, no write.
pub fn empty_trash(
    folder: &Path,
    open: &mut OpenVault,
    device_uuid: [u8; 16],
    now_ms: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<EmptyTrashReport, VaultError> {
    // Collect indices of not-yet-purged, not-live trash entries.
    let targets: Vec<usize> = open
        .manifest
        .trash
        .iter()
        .enumerate()
        .filter(|(_, t)| {
            t.purged_at_ms.is_none()
                && !open
                    .manifest
                    .blocks
                    .iter()
                    .any(|b| b.block_uuid == t.block_uuid)
        })
        .map(|(i, _)| i)
        .collect();
    if targets.is_empty() {
        return Ok(EmptyTrashReport::default());
    }

    // Classify every target BEFORE the manifest write, while the trash
    // files are still guaranteed present (reporting-only, best-effort —
    // mirrors purge_block's step 3).
    let mut report = EmptyTrashReport::default();
    for &idx in &targets {
        let block_uuid = open.manifest.trash[idx].block_uuid;
        let tombstoned_at_ms = open.manifest.trash[idx].tombstoned_at_ms;
        match classify_trash_target(folder, &block_uuid, tombstoned_at_ms, &open.owner_card) {
            Some((true, _)) => report.shared_count += 1,
            Some((false, _)) => report.owner_only_count += 1,
            None => report.unknown_count += 1,
        }
    }

    // Single batch commit via the shared primitive (Task 3).
    let (removed, failed) = purge_batch_commit(
        folder,
        open,
        &targets,
        now_ms,
        device_uuid,
        rng,
        "empty_trash: failed to write manifest.cbor.enc",
    )?;
    report.purged_count = targets.len();
    report.files_removed += removed;
    report.files_failed += failed;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kem::HybridWrap;

    /// Builds a `RecipientWrap` with the given fingerprint and dummy
    /// (never-decapsulated) wrap bytes — mirrors block.rs's own test
    /// builders. `classify_recipients` only ever reads
    /// `recipient_fingerprint`, so the wrap payload's exact bytes are
    /// irrelevant to these unit tests.
    fn wrap_with_fp(fp: [u8; 16]) -> RecipientWrap {
        RecipientWrap {
            recipient_fingerprint: fp,
            wrap: HybridWrap {
                ct_x: [0u8; 32],
                ct_pq: vec![0u8; 1088],
                nonce_w: [0u8; 24],
                ct_w: vec![0u8; 32 + 16],
            },
        }
    }

    #[test]
    fn classify_owner_only_is_not_shared() {
        let owner = [0xAA; 16];
        let recips = vec![wrap_with_fp(owner)];
        assert_eq!(classify_recipients(&recips, &owner), (false, 1));
    }

    #[test]
    fn classify_owner_plus_other_is_shared() {
        let owner = [0xAA; 16];
        let recips = vec![wrap_with_fp(owner), wrap_with_fp([0xBB; 16])];
        assert_eq!(classify_recipients(&recips, &owner), (true, 2));
    }

    #[test]
    fn classify_empty_recipients_is_not_shared() {
        // Degenerate input (never produced by `encrypt_block`, which
        // always includes the owner) — still must not panic or
        // fabricate `was_shared == true`.
        let owner = [0xAA; 16];
        assert_eq!(classify_recipients(&[], &owner), (false, 0));
    }

    #[test]
    fn classify_multiple_others_no_owner_is_shared_with_full_count() {
        // Owner fingerprint absent entirely — still classified as
        // shared (honest: the caller only knows "not owner-only"),
        // with the full on-wire count.
        let owner = [0xAA; 16];
        let recips = vec![wrap_with_fp([0xBB; 16]), wrap_with_fp([0xCC; 16])];
        assert_eq!(classify_recipients(&recips, &owner), (true, 2));
    }
}
