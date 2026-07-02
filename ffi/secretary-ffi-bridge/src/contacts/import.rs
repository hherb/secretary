//! `import_contact_card`: TOFU import of a peer's card. Parse + `verify_self`,
//! dedup-reject (never overwrite a trusted card), atomic write (spec §3, §5).

use std::io::Write;

use secretary_core::vault::format_uuid_hyphenated;

use crate::contacts::{handle_wiped, read_verified_card, ContactSummary};
use crate::error::FfiVaultError;
use crate::vault::OpenVaultManifest;

/// Import one contact card from raw canonical-CBOR bytes. Verifies BOTH
/// self-signature halves, rejects a duplicate `contact_uuid`, and writes
/// `contacts/<hyphenated-uuid>.card` atomically. Returns the imported summary.
///
/// # Atomic write
///
/// `core::vault::io::write_atomic` is `pub(crate)` to its crate and not
/// reachable from this bridge crate, so we replicate its
/// `NamedTempFile::new_in(dir) + write_all + sync_all + persist` rename
/// pattern directly (same `rename(2)` / `MoveFileExW` atomicity guarantee).
/// A plain `std::fs::write` would leave a torn-write window and is avoided.
pub fn import_contact_card(
    manifest: &OpenVaultManifest,
    card_bytes: &[u8],
) -> Result<ContactSummary, FfiVaultError> {
    let card = read_verified_card(card_bytes)?;
    let folder = manifest.vault_folder().ok_or_else(handle_wiped)?;
    let contacts_dir = folder.join("contacts");
    std::fs::create_dir_all(&contacts_dir).map_err(|e| FfiVaultError::FolderInvalid {
        detail: format!("ensure contacts/: {e}"),
    })?;
    let path = contacts_dir.join(format!(
        "{}.card",
        format_uuid_hyphenated(&card.contact_uuid)
    ));
    // Fast-path friendly rejection. This is advisory only: the authoritative
    // no-overwrite guarantee is `persist_noclobber` in `write_card_atomic`,
    // which closes the check-then-write TOCTOU (#361) — two concurrent imports
    // of different cards claiming the same contact_uuid could both pass this
    // `exists()` check, and a plain rename would let the loser silently replace
    // the winner's trusted card.
    if path.exists() {
        return Err(FfiVaultError::ContactAlreadyExists {
            uuid_hex: hex::encode(card.contact_uuid),
        });
    }
    write_card_atomic(&contacts_dir, &path, card_bytes).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            FfiVaultError::ContactAlreadyExists {
                uuid_hex: hex::encode(card.contact_uuid),
            }
        } else {
            FfiVaultError::FolderInvalid {
                detail: format!("write contact card: {e}"),
            }
        }
    })?;
    Ok(ContactSummary {
        contact_uuid: card.contact_uuid,
        display_name: card.display_name,
        // A freshly imported contact has no shared blocks yet.
        shared_block_count: 0,
    })
}

/// Atomic write via temp-file-in-same-dir + fsync + no-clobber rename +
/// dir-fsync. Mirrors `core::vault::io::write_atomic` (which is `pub(crate)`
/// and out of reach here), step for step: the temp file is created in
/// `contacts_dir` so the rename is a same-filesystem `rename(2)`; on failure
/// `tempfile` cleans up the temp file automatically; the final directory fsync
/// makes the rename itself durable across power loss (no-op on non-Unix,
/// matching core).
///
/// Uses `persist_noclobber` rather than `persist` (#361): TOFU import must
/// never replace an existing trusted card, so the rename fails with
/// `ErrorKind::AlreadyExists` (which the caller maps to `ContactAlreadyExists`)
/// if the destination appeared after the caller's advisory `exists()` check.
fn write_card_atomic(
    contacts_dir: &std::path::Path,
    path: &std::path::Path,
    bytes: &[u8],
) -> Result<(), std::io::Error> {
    let mut tmp = tempfile::NamedTempFile::new_in(contacts_dir)?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist_noclobber(path).map_err(|e| e.error)?;
    fsync_dir(contacts_dir)?;
    Ok(())
}

/// fsync the `contacts/` directory so the prior rename into it is durable.
/// Replicates `core::vault::io::fsync_dir` (out of reach: same `pub(crate)`
/// module). On POSIX this `fsync(2)`s the directory inode, flushing the
/// directory-entry update to stable storage; without it the rename can be
/// lost on power loss even though the file's data was already fsynced.
#[cfg(unix)]
fn fsync_dir(dir: &std::path::Path) -> Result<(), std::io::Error> {
    std::fs::File::open(dir)?.sync_all()
}

/// No-op on non-Unix: there is no portable directory-handle fsync, and NTFS
/// journals metadata separately. Matches core's documented best practice.
#[cfg(not(unix))]
fn fsync_dir(_dir: &std::path::Path) -> Result<(), std::io::Error> {
    Ok(())
}
