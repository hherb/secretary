//! D.1.6 contacts namespace fns (#206): verified `import_contact_card` /
//! `share_block_to`.

use crate::errors::VaultError;
use crate::namespace::uuid_from_vec;
use crate::wrappers::contacts::ContactSummary;
use crate::wrappers::identity::UnlockedIdentity;
use crate::wrappers::vault::OpenVaultManifest;

/// TOFU import of one contact card. Verifies both self-signature halves and
/// refuses to overwrite an existing card (`VaultError::ContactAlreadyExists`).
#[allow(clippy::needless_pass_by_value)]
pub fn import_contact_card(
    manifest: std::sync::Arc<OpenVaultManifest>,
    card_bytes: Vec<u8>,
) -> Result<ContactSummary, VaultError> {
    secretary_ffi_bridge::import_contact_card(&manifest.0, &card_bytes)
        .map(ContactSummary::from)
        .map_err(VaultError::from)
}

/// Share a block with a recipient by `new_recipient_uuid`. All cards are
/// loaded from `contacts/` and re-verified before re-keying — no
/// caller-supplied card bytes enter the trust path. Prefer over `share_block`.
///
/// `block_uuid`, `new_recipient_uuid`, and `device_uuid` must each be 16 bytes;
/// passing any other length returns `VaultError::InvalidArgument`.
pub fn share_block_to(
    identity: std::sync::Arc<UnlockedIdentity>,
    manifest: std::sync::Arc<OpenVaultManifest>,
    block_uuid: Vec<u8>,
    new_recipient_uuid: Vec<u8>,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> Result<(), VaultError> {
    let block_uuid = uuid_from_vec(&block_uuid, "block_uuid")?;
    let new_recipient_uuid = uuid_from_vec(&new_recipient_uuid, "new_recipient_uuid")?;
    let device_uuid = uuid_from_vec(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::share_block_to(
        &identity.0,
        &manifest.0,
        block_uuid,
        new_recipient_uuid,
        device_uuid,
        now_ms,
    )
    .map_err(VaultError::from)
}
