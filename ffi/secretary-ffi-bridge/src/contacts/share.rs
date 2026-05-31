//! `share_block_to`: share a block by recipient UUID. Reads the block's
//! current recipient set from the manifest, loads every existing card + the
//! new card from `contacts/`, and delegates to the existing `share::share_block`
//! wrapper (which owns the snapshot/zeroize/write-back machinery). Spec §5, §8.

use secretary_core::vault::format_uuid_hyphenated;

use crate::contacts::handle_wiped;
use crate::error::FfiVaultError;
use crate::identity::UnlockedIdentity;
use crate::vault::OpenVaultManifest;

/// Append one new recipient (by `contact_uuid`) to a block the owner authored.
/// `existing_recipient_cards` are assembled from the manifest's
/// `BlockEntry.recipients` (always includes the owner). Card bytes loaded here
/// were self-verified at import time. NotAuthor / RecipientAlreadyPresent /
/// MissingRecipientCard surface unchanged from the underlying `share_block`.
///
/// # Errors
///
/// - [`FfiVaultError::CorruptVault`] — the manifest handle has been wiped.
/// - [`FfiVaultError::BlockNotFound`] — `block_uuid` not in the manifest.
/// - [`FfiVaultError::ContactNotFound`] — an existing recipient's card, or
///   the new recipient's card, has no `.card` file in `contacts/`.
/// - Every error surfaced by [`crate::share::share_block`] (NotAuthor,
///   RecipientAlreadyPresent, MissingRecipientCard, CardDecodeFailure,
///   CorruptVault, FolderInvalid, SaveCryptoFailure).
pub fn share_block_to(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: [u8; 16],
    new_recipient_uuid: [u8; 16],
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<(), FfiVaultError> {
    let body = manifest.manifest_body().ok_or_else(handle_wiped)?;
    let folder = manifest.vault_folder().ok_or_else(handle_wiped)?;
    let contacts_dir = folder.join("contacts");

    let entry = body
        .blocks
        .iter()
        .find(|b| b.block_uuid == block_uuid)
        .ok_or_else(|| FfiVaultError::BlockNotFound {
            uuid_hex: hex::encode(block_uuid),
        })?;

    // Existing recipient cards (file name = hyphenated; error field = hex).
    let mut existing: Vec<Vec<u8>> = Vec::with_capacity(entry.recipients.len());
    for r in &entry.recipients {
        existing.push(load_card_bytes(&contacts_dir, r)?);
    }
    let new_bytes = load_card_bytes(&contacts_dir, &new_recipient_uuid)?;

    crate::share::share_block(
        identity,
        manifest,
        block_uuid,
        &existing,
        &new_bytes,
        device_uuid,
        now_ms,
    )
}

fn load_card_bytes(
    contacts_dir: &std::path::Path,
    uuid: &[u8; 16],
) -> Result<Vec<u8>, FfiVaultError> {
    let path = contacts_dir.join(format!("{}.card", format_uuid_hyphenated(uuid)));
    std::fs::read(&path).map_err(|_| FfiVaultError::ContactNotFound {
        uuid_hex: hex::encode(uuid),
    })
}
