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
/// `BlockEntry.recipients` (always includes the owner). Every card loaded from
/// `contacts/` — existing recipients AND the new recipient — is re-verified
/// (both Ed25519 ∧ ML-DSA-65 self-signature halves) at load time via
/// `load_card_bytes` before its public keys are trusted; verification at
/// import time does NOT cover this path because the cards are re-read from disk
/// here, where a post-import swap (an attacker with write access to `contacts/`,
/// the threat `core::vault::restore_block` guards against) would otherwise pass
/// an unverified KEM key to the re-key. NotAuthor / RecipientAlreadyPresent /
/// MissingRecipientCard surface unchanged from the underlying `share_block`.
///
/// # Errors
///
/// - [`FfiVaultError::CorruptVault`] — the manifest handle has been wiped.
/// - [`FfiVaultError::BlockNotFound`] — `block_uuid` not in the manifest.
/// - [`FfiVaultError::ContactNotFound`] — an existing recipient's card, or
///   the new recipient's card, has no `.card` file in `contacts/`.
/// - [`FfiVaultError::CardDecodeFailure`] — a `.card` file on disk fails to
///   parse or fails the both-halves self-signature check (tampered/forged).
/// - [`FfiVaultError::FolderInvalid`] — a `.card` file exists but cannot be
///   read (permissions, transient IO) — distinct from "not found".
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

/// Read a recipient card from `contacts/<hyphenated-uuid>.card` and re-verify
/// both self-signature halves before returning its bytes for re-keying.
///
/// The verification here is the security gate for the share path: the bytes are
/// re-read from disk (not carried over from a prior verified import), so without
/// it a card swapped on disk after import — including a forged NEW recipient
/// card with attacker-controlled KEM keys, which core's `share_block` would use
/// directly with no fingerprint cross-check — would silently redirect the block
/// re-key. Mirrors the `verify_self()` gate in `core::vault::restore_block`.
///
/// `ErrorKind::NotFound` → [`FfiVaultError::ContactNotFound`]; any other IO
/// error (permissions, transient failure) → [`FfiVaultError::FolderInvalid`]
/// so a genuine read failure is not misreported as a missing contact.
pub(crate) fn load_card_bytes(
    contacts_dir: &std::path::Path,
    uuid: &[u8; 16],
) -> Result<Vec<u8>, FfiVaultError> {
    let path = contacts_dir.join(format!("{}.card", format_uuid_hyphenated(uuid)));
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(FfiVaultError::ContactNotFound {
                uuid_hex: hex::encode(uuid),
            })
        }
        Err(e) => {
            return Err(FfiVaultError::FolderInvalid {
                detail: format!("read contact card {}: {e}", hex::encode(uuid)),
            })
        }
    };
    // Both-halves gate before any key in this card is trusted for re-keying.
    crate::contacts::read_verified_card(&bytes)?;
    Ok(bytes)
}
