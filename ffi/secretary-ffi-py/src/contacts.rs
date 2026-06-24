//! D.1.6 contacts surface (#206): the verified `import_contact_card` /
//! `share_block_to` primitives + the `ContactSummary` projection.

use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::errors::{ffi_vault_error_to_pyerr, uuid_array_or_value_error};
use crate::identity::UnlockedIdentity;
use crate::vault::OpenVaultManifest;

/// Secret-free projection of one contact card (uuid + label + share count).
#[pyclass]
pub(crate) struct ContactSummary {
    pub(crate) contact_uuid: [u8; 16],
    pub(crate) display_name: String,
    pub(crate) shared_block_count: u32,
}

#[pymethods]
impl ContactSummary {
    /// 16-byte contact UUID as fresh `bytes`.
    #[getter]
    fn contact_uuid<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.contact_uuid)
    }
    /// User-facing label.
    #[getter]
    fn display_name(&self) -> &str {
        &self.display_name
    }
    /// Number of the owner's blocks listing this contact as a recipient.
    #[getter]
    fn shared_block_count(&self) -> u32 {
        self.shared_block_count
    }
}

impl From<secretary_ffi_bridge::ContactSummary> for ContactSummary {
    fn from(s: secretary_ffi_bridge::ContactSummary) -> Self {
        Self {
            contact_uuid: s.contact_uuid,
            display_name: s.display_name,
            shared_block_count: s.shared_block_count,
        }
    }
}

/// TOFU import of one contact card. Verifies both self-signature halves and
/// refuses to overwrite an existing card (`VaultContactAlreadyExists`).
/// Tampered/unsigned bytes raise `VaultCardDecodeFailure`.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn import_contact_card(
    manifest: &OpenVaultManifest,
    card_bytes: Vec<u8>,
) -> PyResult<ContactSummary> {
    secretary_ffi_bridge::import_contact_card(&manifest.0, &card_bytes)
        .map(ContactSummary::from)
        .map_err(ffi_vault_error_to_pyerr)
}

/// Share a block with a recipient identified by `new_recipient_uuid`. The
/// recipient's card (and every existing recipient's card) is loaded from
/// `contacts/` and re-verified before re-keying — no caller-supplied card
/// bytes enter the trust path. Prefer this over raw `share_block`.
///
/// `block_uuid`, `new_recipient_uuid`, `device_uuid` must each be 16 bytes
/// (`ValueError` otherwise).
#[pyfunction]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn share_block_to(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: Vec<u8>,
    new_recipient_uuid: Vec<u8>,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> PyResult<()> {
    let block_uuid = uuid_array_or_value_error(&block_uuid, "block_uuid")?;
    let new_recipient_uuid = uuid_array_or_value_error(&new_recipient_uuid, "new_recipient_uuid")?;
    let device_uuid = uuid_array_or_value_error(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::share_block_to(
        &identity.0,
        &manifest.0,
        block_uuid,
        new_recipient_uuid,
        device_uuid,
        now_ms,
    )
    .map_err(ffi_vault_error_to_pyerr)
}
