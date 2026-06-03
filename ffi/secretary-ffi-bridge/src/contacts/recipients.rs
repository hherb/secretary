//! `block_recipients`: project a block's manifest recipient set into
//! name-resolved, classified summaries (spec D.1.8). The inverse of
//! `enumerate_contact_cards`'s per-contact `shared_block_count`. Read-only —
//! no decryption, no write; revoke stays deferred to #177.

use secretary_core::vault::format_uuid_hyphenated;

use crate::contacts::{handle_wiped, read_verified_card};
use crate::error::FfiVaultError;
use crate::vault::OpenVaultManifest;

/// One recipient of a block, classified and (where possible) name-resolved.
///
/// Public, secret-free: the uuid is public material and `display_name` (carried
/// inside [`RecipientKind::Contact`]) is the non-secret card label. Card bytes
/// and public keys never appear here. `Debug` is safe to derive.
#[derive(Debug)]
pub struct RecipientSummary {
    /// 16-byte recipient identity — one uuid from `BlockEntry.recipients`.
    pub recipient_uuid: [u8; 16],
    /// Classification + resolved label.
    pub kind: RecipientKind,
}

/// How a recipient uuid resolved against `contacts/` and the owner card.
#[derive(Debug)]
pub enum RecipientKind {
    /// The vault owner (uuid equals the owner card's `contact_uuid`). Checked
    /// FIRST: the owner self-card also lives in `contacts/`, so without the
    /// owner-first check it would otherwise resolve to `Contact`.
    Owner,
    /// A peer with a present, both-halves-verified card in `contacts/`.
    Contact {
        /// User-facing label from the verified card.
        display_name: String,
    },
    /// The uuid has no usable card: file missing (the D.1.7 delete != revoke
    /// residual keyholder), unreadable, or failing `verify_self()`. An
    /// unverified `display_name` is never surfaced — only the uuid is trusted.
    Unknown,
}

/// Project block `block_uuid`'s `recipients[]` into classified summaries, in
/// manifest recipient order (the client owns presentation ordering). No
/// decryption; the only I/O is reading each referenced `contacts/<uuid>.card`.
///
/// # Errors
/// - [`FfiVaultError::BlockNotFound`] — `block_uuid` absent from the manifest.
/// - [`FfiVaultError::CorruptVault`] — the manifest handle was wiped (locked).
pub fn block_recipients(
    manifest: &OpenVaultManifest,
    block_uuid: [u8; 16],
) -> Result<Vec<RecipientSummary>, FfiVaultError> {
    let folder = manifest.vault_folder().ok_or_else(handle_wiped)?;
    let owner_uuid = manifest.owner_card().ok_or_else(handle_wiped)?.contact_uuid;
    let body = manifest.manifest_body().ok_or_else(handle_wiped)?;
    let contacts_dir = folder.join("contacts");

    let entry = body
        .blocks
        .iter()
        .find(|b| b.block_uuid == block_uuid)
        .ok_or_else(|| FfiVaultError::BlockNotFound {
            uuid_hex: hex::encode(block_uuid),
        })?;

    let summaries = entry
        .recipients
        .iter()
        .map(|uuid| RecipientSummary {
            recipient_uuid: *uuid,
            kind: classify_recipient(&contacts_dir, uuid, &owner_uuid),
        })
        .collect();
    Ok(summaries)
}

/// Classify one recipient uuid: `Owner` (uuid == owner) → `Contact` (a present,
/// both-halves-verified card) → `Unknown` (missing / unreadable / unverifiable).
/// Verification failure folds into `Unknown` so a tampered card's name is never
/// trusted (mirrors the verify gate in `share.rs::load_card_bytes`).
fn classify_recipient(
    contacts_dir: &std::path::Path,
    uuid: &[u8; 16],
    owner_uuid: &[u8; 16],
) -> RecipientKind {
    if uuid == owner_uuid {
        return RecipientKind::Owner;
    }
    let path = contacts_dir.join(format!("{}.card", format_uuid_hyphenated(uuid)));
    match std::fs::read(&path) {
        Ok(bytes) => match read_verified_card(&bytes) {
            Ok(card) => RecipientKind::Contact {
                display_name: card.display_name,
            },
            Err(_) => RecipientKind::Unknown,
        },
        Err(_) => RecipientKind::Unknown,
    }
}
