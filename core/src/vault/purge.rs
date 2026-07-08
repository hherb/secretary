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

/// Best-effort removal of every `trash/<uuid>.cbor.enc.*` file for
/// `block_uuid` (there is normally exactly one — the current tombstoned
/// copy — but a crash-residue orphan from an earlier trash/restore cycle
/// could also match). Returns the count actually removed.
///
/// Individual failures are logged via `tracing::warn!` and tolerated: a
/// lingering file is a benign orphan (`open_vault`'s fingerprint check
/// only walks `manifest.blocks`, and a purged UUID is never re-added
/// there), not a correctness problem. Caller must have already
/// established `block_uuid` is a trash entry (true by construction for
/// every `purge_block` call site).
fn remove_trash_files(folder: &Path, block_uuid: &[u8; 16]) -> usize {
    let trash_dir = folder.join(TRASH_SUBDIR);
    let uuid_hex = format_uuid_hyphenated(block_uuid);
    let prefix = format!("{uuid_hex}{BLOCK_FILE_EXTENSION}.");
    let mut removed = 0usize;
    let Ok(rd) = std::fs::read_dir(&trash_dir) else {
        return 0;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        let is_match = path
            .file_name()
            .and_then(|s| s.to_str())
            .map(|n| n.starts_with(&prefix))
            .unwrap_or(false);
        if !is_match {
            continue;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => removed += 1,
            Err(e) => tracing::warn!(
                block_uuid = %uuid_hex,
                error = %e,
                "purge_block: failed to remove trash file; benign orphan remains"
            ),
        }
    }
    removed
}

/// Best-effort classification of the current trash target
/// (`trash/<uuid>.cbor.enc.<tombstoned_at_ms>`) for reporting only.
///
/// Reads and decodes the on-disk block file to reach its cleartext §6.2
/// recipient table — no AEAD-decrypt, no plaintext ever touched. Returns
/// `None` when the file is absent or fails to decode (crash residue,
/// prior purge, on-disk corruption): an honest "unknown" rather than a
/// fabricated classification.
fn classify_trash_target(
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
        let files_removed = remove_trash_files(folder, &block_uuid);
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
    let files_removed = remove_trash_files(folder, &block_uuid);
    Ok(PurgeReport {
        block_uuid,
        was_shared,
        recipient_count,
        files_removed,
    })
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
