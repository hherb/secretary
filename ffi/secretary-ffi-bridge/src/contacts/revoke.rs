//! `revoke_block_from`: revoke a block recipient by UUID. Reads the block's
//! current recipient set from the manifest, loads every existing card from
//! `contacts/` (INCLUDING the revoke target, needed to resolve the §6.2 wire
//! table), and delegates to the existing `revoke::revoke_block` wrapper
//! (which owns the snapshot/zeroize/write-back machinery). The near-exact
//! inverse of `contacts::share_block_to`. Spec §5, §8.

use crate::contacts::handle_wiped;
use crate::contacts::share::load_card_bytes;
use crate::error::FfiVaultError;
use crate::identity::UnlockedIdentity;
use crate::vault::OpenVaultManifest;

/// Remove one recipient (by `revoked_recipient_uuid`) from a block the owner
/// authored, re-keying for the remaining recipients. `existing_recipient_cards`
/// are assembled from the manifest's `BlockEntry.recipients` (always includes
/// the owner AND, because the revoke target is a current recipient, the target
/// itself). Every card loaded from `contacts/` is re-verified (both
/// Ed25519 ∧ ML-DSA-65 self-signature halves) at load time via
/// `load_card_bytes` before its public keys are trusted — identical to the
/// share path, because the cards are re-read from disk here where a post-import
/// swap would otherwise feed an unverified KEM key to the re-key.
/// CannotRevokeOwner / RecipientNotPresent / NotAuthor / MissingRecipientCard
/// surface unchanged from the underlying `revoke_block`.
///
/// # Errors
///
/// - [`FfiVaultError::CorruptVault`] — the manifest handle has been wiped.
/// - [`FfiVaultError::BlockNotFound`] — `block_uuid` not in the manifest.
/// - [`FfiVaultError::ContactNotFound`] — a current recipient's card has no
///   `.card` file in `contacts/`.
/// - [`FfiVaultError::CardDecodeFailure`] — a `.card` file on disk fails to
///   parse or fails the both-halves self-signature check (tampered/forged).
/// - [`FfiVaultError::FolderInvalid`] — a `.card` file exists but cannot be
///   read (permissions, transient IO) — distinct from "not found".
/// - Every error surfaced by [`crate::revoke::revoke_block`] (NotAuthor,
///   CannotRevokeOwner, RecipientNotPresent, MissingRecipientCard,
///   CardDecodeFailure, CorruptVault, FolderInvalid, SaveCryptoFailure).
pub fn revoke_block_from(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: [u8; 16],
    revoked_recipient_uuid: [u8; 16],
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

    // Current recipient cards (file name = hyphenated; error field = hex).
    // This set already includes the revoke target whenever it is a genuine
    // current recipient — exactly the union core needs to resolve the §6.2
    // wire table before splitting off the revoked one. When the target is
    // NOT a current recipient it simply won't be in this list, and core's
    // require-present check surfaces RecipientNotPresent.
    let mut existing: Vec<Vec<u8>> = Vec::with_capacity(entry.recipients.len());
    for r in &entry.recipients {
        existing.push(load_card_bytes(&contacts_dir, r)?);
    }

    crate::revoke::revoke_block(
        identity,
        manifest,
        block_uuid,
        &existing,
        revoked_recipient_uuid,
        device_uuid,
        now_ms,
    )
}
