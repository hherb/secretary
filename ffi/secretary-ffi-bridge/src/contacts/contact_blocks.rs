//! `contact_blocks`: project a contact uuid → the live blocks that list it as
//! a recipient (spec D.1.9). The per-contact inverse of D.1.8's
//! `block_recipients`. Read-only — an in-memory scan of the manifest's live
//! block list. `manifest.blocks` holds only live blocks (trashed blocks live
//! in `manifest.trash`), so they never appear here. No decryption, no I/O, no
//! mutation; revoke stays deferred to #177.

use crate::contacts::handle_wiped;
use crate::error::FfiVaultError;
use crate::vault::manifest::block_entry_to_summary;
use crate::vault::{BlockSummary, OpenVaultManifest};

/// Return the live blocks that list `contact_uuid` as a recipient, in manifest
/// order (ascending `block_uuid`; the client owns presentation ordering).
///
/// This scans the SAME `manifest.blocks` list that `enumerate_contact_cards`
/// counts for `shared_block_count`, so `contact_blocks(uuid).len()` equals that
/// contact's `shared_block_count` by construction. A `contact_uuid` matching no
/// block returns an empty `Vec` (not an error): we scan recipients, not contact
/// cards, so "contact not found" is not a concept here.
///
/// # Errors
/// - [`FfiVaultError::CorruptVault`] — the manifest handle was wiped (locked).
pub fn contact_blocks(
    manifest: &OpenVaultManifest,
    contact_uuid: [u8; 16],
) -> Result<Vec<BlockSummary>, FfiVaultError> {
    let body = manifest.manifest_body().ok_or_else(handle_wiped)?;
    Ok(body
        .blocks
        .iter()
        .filter(|b| b.recipients.contains(&contact_uuid))
        .map(block_entry_to_summary)
        .collect())
}
