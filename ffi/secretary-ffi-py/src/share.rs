//! Block-share entry point (B.4d).

use pyo3::prelude::*;

use crate::errors::{ffi_vault_error_to_pyerr, uuid_array_or_value_error};
use crate::identity::UnlockedIdentity;
use crate::vault::OpenVaultManifest;

/// **Discouraged** — trusts caller-supplied recipient card bytes verbatim.
/// FFI consumers should `import_contact_card` the peer once (TOFU, both
/// self-signature halves verified), then `share_block_to` by UUID (#206).
///
/// Append one new recipient to an existing block. v1 single-author: only
/// the vault owner can share blocks they authored.
///
/// `block_uuid` and `device_uuid` must each be exactly 16 bytes;
/// otherwise raises `ValueError` (mirrors `save_block` and `read_block`).
/// Caller-supplied `existing_recipient_cards` and `new_recipient` are
/// canonical-CBOR-encoded `ContactCard` byte sequences (same shape as
/// `manifest.owner_card_bytes()` returns); decode failures raise
/// `VaultCardDecodeFailure`.
///
/// `existing_recipient_cards` must cover every recipient currently in
/// the block's wire-level recipient table. For a freshly-saved v1 block
/// this is `[manifest.owner_card_bytes()]`. After the first share, the
/// caller is responsible for tracking the growing recipient list (no
/// bridge-side registry).
#[pyfunction]
#[allow(clippy::needless_pass_by_value)] // owned Vec<u8> for bytes ∪ bytearray accept
#[allow(clippy::too_many_arguments)]
pub(crate) fn share_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: Vec<u8>,
    existing_recipient_cards: Vec<Vec<u8>>,
    new_recipient: Vec<u8>,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> PyResult<()> {
    let block_uuid = uuid_array_or_value_error(&block_uuid, "block_uuid")?;
    let device_uuid = uuid_array_or_value_error(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::share_block(
        &identity.0,
        &manifest.0,
        block_uuid,
        &existing_recipient_cards,
        &new_recipient,
        device_uuid,
        now_ms,
    )
    .map_err(ffi_vault_error_to_pyerr)
}
