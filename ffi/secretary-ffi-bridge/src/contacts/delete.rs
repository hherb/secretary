//! `delete_contact_card`: remove one contact's `.card` from `contacts/`.
//!
//! Warn-but-allow (spec §3): the primitive does NOT check recipient
//! membership — the "this contact still receives N blocks" warning is a UI
//! gate fed by `enumerate`'s `shared_block_count`. Deleting a card does NOT
//! revoke the contact's access to blocks already shared with them (they hold
//! the content key); it only removes the card from the picker and from future
//! re-key assembly. Revoke needs a frozen-core primitive (issue #177).

use secretary_core::vault::format_uuid_hyphenated;

use crate::contacts::handle_wiped;
use crate::error::FfiVaultError;
use crate::vault::OpenVaultManifest;

/// Remove `contacts/<hyphenated-uuid>.card`.
///
/// - `contact_uuid` == owner uuid → [`FfiVaultError::CannotDeleteOwnerContact`]
///   (never removes the vault's own self-card; checked before any I/O).
/// - card file absent → [`FfiVaultError::ContactNotFound`].
/// - any other unlink failure → [`FfiVaultError::FolderInvalid`].
pub fn delete_contact_card(
    manifest: &OpenVaultManifest,
    contact_uuid: [u8; 16],
) -> Result<(), FfiVaultError> {
    let owner_uuid = manifest.owner_card().ok_or_else(handle_wiped)?.contact_uuid;
    if contact_uuid == owner_uuid {
        return Err(FfiVaultError::CannotDeleteOwnerContact);
    }
    let folder = manifest.vault_folder().ok_or_else(handle_wiped)?;
    let path = folder
        .join("contacts")
        .join(format!("{}.card", format_uuid_hyphenated(&contact_uuid)));
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(FfiVaultError::ContactNotFound {
            uuid_hex: hex::encode(contact_uuid),
        }),
        Err(e) => Err(FfiVaultError::FolderInvalid {
            detail: format!("remove contact card: {e}"),
        }),
    }
}
