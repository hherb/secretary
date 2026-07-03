//! Python exception classes plus the bridge-error → PyErr translators.
//!
//! Five `FfiUnlockError`-class exceptions and twelve `FfiVaultError`-class
//! exceptions (including the four B.4d `share_block` variants). The
//! translators are free functions rather than `From` impls because the
//! orphan rules forbid `impl From<FfiX> for PyErr` from this downstream
//! crate; the `.map_err(ffi_*_error_to_pyerr)` shape is used at every
//! pyfunction boundary.

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use secretary_ffi_bridge::{FfiUnlockError, FfiVaultError};

create_exception!(secretary_ffi_py, WrongPasswordOrCorrupt, PyException);
create_exception!(secretary_ffi_py, VaultMismatch, PyException);
create_exception!(secretary_ffi_py, CorruptVault, PyException);
create_exception!(secretary_ffi_py, WrongMnemonicOrCorrupt, PyException);
create_exception!(secretary_ffi_py, InvalidMnemonic, PyException);

// FfiVaultError → Python exception classes (B.4a). Five mirror the
// FfiUnlockError exceptions byte-identical on Display string, but they're
// distinct Python classes so foreign callers can `except VaultFolderInvalid:`
// without needing to introspect the exception's source error type.
//
// Naming: prefix with "Vault" to disambiguate from the FfiUnlockError
// classes; the bytes-in callers raise the existing classes, the folder-in
// callers raise these. `VaultMismatchFolder` is renamed from the logical
// `VaultMismatch` to avoid collision with the existing `VaultMismatch`
// class above (which maps to `FfiUnlockError::VaultMismatch`).
create_exception!(secretary_ffi_py, VaultWrongPasswordOrCorrupt, PyException);
create_exception!(secretary_ffi_py, VaultWrongMnemonicOrCorrupt, PyException);
create_exception!(secretary_ffi_py, VaultInvalidMnemonic, PyException);
create_exception!(secretary_ffi_py, VaultMismatchFolder, PyException);
create_exception!(secretary_ffi_py, VaultCorruptVault, PyException);
create_exception!(secretary_ffi_py, VaultFolderInvalid, PyException);
create_exception!(secretary_ffi_py, VaultBlockNotFound, PyException);
create_exception!(secretary_ffi_py, VaultRecordNotFound, PyException);
create_exception!(secretary_ffi_py, VaultSaveCryptoFailure, PyException);
// B.4d share_block error surface — 4 typed exception classes mirroring
// the bridge's FfiVaultError variants.
create_exception!(secretary_ffi_py, VaultNotAuthor, PyException);
create_exception!(secretary_ffi_py, VaultRecipientAlreadyPresent, PyException);
create_exception!(secretary_ffi_py, VaultRecipientNotPresent, PyException);
create_exception!(secretary_ffi_py, VaultCannotRevokeOwner, PyException);
create_exception!(secretary_ffi_py, VaultMissingRecipientCard, PyException);
create_exception!(secretary_ffi_py, VaultCardDecodeFailure, PyException);
// B.5 trash_block / restore_block error surface — 2 typed exception
// classes mirroring the bridge's new FfiVaultError variants.
create_exception!(secretary_ffi_py, VaultBlockUuidAlreadyLive, PyException);
create_exception!(secretary_ffi_py, VaultBlockNotInTrash, PyException);
// D.1.6 share-contacts error surface — 2 typed exception classes mirroring
// the bridge's new FfiVaultError variants.
create_exception!(secretary_ffi_py, VaultContactAlreadyExists, PyException);
create_exception!(secretary_ffi_py, VaultContactNotFound, PyException);
// D.1.7 delete-contact error surface — owner self-card deletion guard.
create_exception!(secretary_ffi_py, VaultCannotDeleteOwnerContact, PyException);
// D.1.13 sync error surface — 5 typed exception classes mirroring the bridge's
// new FfiVaultError sync variants.
create_exception!(secretary_ffi_py, VaultSyncStateVaultMismatch, PyException);
create_exception!(secretary_ffi_py, VaultSyncStateCorrupt, PyException);
create_exception!(secretary_ffi_py, VaultSyncEvidenceStale, PyException);
create_exception!(secretary_ffi_py, VaultSyncInProgress, PyException);
create_exception!(secretary_ffi_py, VaultSyncFailed, PyException);
// Interactive conflict-resolution commit path — decisions did not cover the
// recomputed veto set. Mirrors the bridge's FfiVaultError::SyncDecisionsIncomplete.
create_exception!(secretary_ffi_py, VaultSyncDecisionsIncomplete, PyException);
// ADR 0009 (B.2) device-slot error surface — 3 typed exception classes
// mirroring the bridge's new FfiVaultError device variants.
create_exception!(secretary_ffi_py, VaultDeviceSlotNotFound, PyException);
create_exception!(
    secretary_ffi_py,
    VaultWrongDeviceSecretOrCorrupt,
    PyException
);
create_exception!(secretary_ffi_py, VaultDeviceUuidMismatch, PyException);
// Folder-create precondition — target directory not empty. Mirrors the
// bridge's FfiVaultError::VaultFolderNotEmpty.
create_exception!(secretary_ffi_py, VaultFolderNotEmpty, PyException);
// #374 repair_vault FFI projection — crash-residue "offer Repair" signal
// and the repair-refused outcome. Mirror the bridge's FfiVaultError
// variants; VaultNeedsRepair keeps its bare name (it already reads as
// vault-scoped) while RepairRejected gets the `Vault` prefix like its
// siblings above.
create_exception!(secretary_ffi_py, VaultNeedsRepair, PyException);
create_exception!(secretary_ffi_py, VaultRepairRejected, PyException);

/// Map a bridge-crate `FfiUnlockError` to the matching Python exception
/// class. Used at the `open_with_password` boundary via `.map_err`. A
/// free function (rather than a `From` impl) is preferred because the
/// orphan rules forbid `impl From<FfiUnlockError> for PyErr` from a
/// downstream crate, and `?`-routing isn't needed at the single call
/// site.
pub(crate) fn ffi_unlock_error_to_pyerr(e: FfiUnlockError) -> PyErr {
    match e {
        FfiUnlockError::WrongPasswordOrCorrupt => WrongPasswordOrCorrupt::new_err(e.to_string()),
        FfiUnlockError::WrongMnemonicOrCorrupt => WrongMnemonicOrCorrupt::new_err(e.to_string()),
        FfiUnlockError::InvalidMnemonic { detail } => InvalidMnemonic::new_err(detail),
        FfiUnlockError::VaultMismatch => VaultMismatch::new_err(e.to_string()),
        FfiUnlockError::CorruptVault { detail } => CorruptVault::new_err(detail),
    }
}

/// Map a bridge-crate `FfiVaultError` to the matching Python exception
/// class (B.4a folder-in entry points). Parallels `ffi_unlock_error_to_pyerr`
/// with one-to-one variant translation to the `Vault`-prefixed exception
/// classes. A free function (rather than a `From` impl) mirrors the existing
/// `ffi_unlock_error_to_pyerr` pattern — the orphan rules forbid
/// `impl From<FfiVaultError> for PyErr` here since both types are external.
pub(crate) fn ffi_vault_error_to_pyerr(e: FfiVaultError) -> PyErr {
    match e {
        FfiVaultError::WrongPasswordOrCorrupt => {
            VaultWrongPasswordOrCorrupt::new_err(e.to_string())
        }
        FfiVaultError::WrongMnemonicOrCorrupt => {
            VaultWrongMnemonicOrCorrupt::new_err(e.to_string())
        }
        FfiVaultError::InvalidMnemonic { detail } => VaultInvalidMnemonic::new_err(detail),
        FfiVaultError::VaultMismatch => VaultMismatchFolder::new_err(e.to_string()),
        FfiVaultError::CorruptVault { detail } => VaultCorruptVault::new_err(detail),
        FfiVaultError::FolderInvalid { detail } => VaultFolderInvalid::new_err(detail),
        FfiVaultError::BlockNotFound { uuid_hex } => {
            // Pass uuid_hex as the exception payload so foreign callers
            // can `except VaultBlockNotFound as e: e.args[0]` to get the
            // hex string back.
            VaultBlockNotFound::new_err(uuid_hex)
        }
        FfiVaultError::RecordNotFound { uuid_hex } => {
            // Same args[0] contract as VaultBlockNotFound: the record-UUID
            // hex rides as the exception payload.
            VaultRecordNotFound::new_err(uuid_hex)
        }
        FfiVaultError::SaveCryptoFailure { detail } => VaultSaveCryptoFailure::new_err(detail),
        // B.4d share_block error surface — same args[0] contract as the
        // existing variants: the exception payload carries the most
        // diagnostic-relevant field so foreign callers can pull it via
        // `except VaultX as e: e.args[0]`.
        FfiVaultError::NotAuthor {
            expected_fingerprint_hex,
            got_fingerprint_hex,
        } => VaultNotAuthor::new_err(format!(
            "expected={expected_fingerprint_hex}, got={got_fingerprint_hex}",
        )),
        FfiVaultError::RecipientAlreadyPresent => {
            VaultRecipientAlreadyPresent::new_err(e.to_string())
        }
        FfiVaultError::RecipientNotPresent => VaultRecipientNotPresent::new_err(e.to_string()),
        FfiVaultError::CannotRevokeOwner => VaultCannotRevokeOwner::new_err(e.to_string()),
        FfiVaultError::MissingRecipientCard {
            recipient_fingerprint_hex,
        } => VaultMissingRecipientCard::new_err(recipient_fingerprint_hex),
        FfiVaultError::CardDecodeFailure { detail } => VaultCardDecodeFailure::new_err(detail),
        // B.5 trash_block / restore_block error surface.
        FfiVaultError::BlockUuidAlreadyLive { detail } => {
            VaultBlockUuidAlreadyLive::new_err(detail)
        }
        FfiVaultError::BlockNotInTrash { detail } => VaultBlockNotInTrash::new_err(detail),
        // D.1.6 share-contacts error surface — same args[0] contract: the
        // contact-UUID hex rides as the exception payload.
        FfiVaultError::ContactAlreadyExists { uuid_hex } => {
            VaultContactAlreadyExists::new_err(uuid_hex)
        }
        FfiVaultError::ContactNotFound { uuid_hex } => VaultContactNotFound::new_err(uuid_hex),
        FfiVaultError::CannotDeleteOwnerContact => VaultCannotDeleteOwnerContact::new_err(
            "the vault owner's own contact card cannot be deleted",
        ),
        FfiVaultError::SyncStateVaultMismatch => {
            VaultSyncStateVaultMismatch::new_err(e.to_string())
        }
        FfiVaultError::SyncStateCorrupt { .. } => VaultSyncStateCorrupt::new_err(e.to_string()),
        FfiVaultError::SyncEvidenceStale => VaultSyncEvidenceStale::new_err(e.to_string()),
        FfiVaultError::SyncInProgress => VaultSyncInProgress::new_err(e.to_string()),
        FfiVaultError::SyncFailed { .. } => VaultSyncFailed::new_err(e.to_string()),
        FfiVaultError::SyncDecisionsIncomplete => {
            VaultSyncDecisionsIncomplete::new_err(e.to_string())
        }
        // ADR 0009 (B.2) device-slot error surface.
        FfiVaultError::DeviceSlotNotFound => VaultDeviceSlotNotFound::new_err(e.to_string()),
        FfiVaultError::WrongDeviceSecretOrCorrupt => {
            VaultWrongDeviceSecretOrCorrupt::new_err(e.to_string())
        }
        FfiVaultError::DeviceUuidMismatch { detail } => VaultDeviceUuidMismatch::new_err(detail),
        FfiVaultError::VaultFolderNotEmpty => VaultFolderNotEmpty::new_err(e.to_string()),
        FfiVaultError::VaultNeedsRepair { block_uuid_hex } => {
            VaultNeedsRepair::new_err(block_uuid_hex)
        }
        FfiVaultError::RepairRejected {
            block_uuid_hex,
            detail,
        } => VaultRepairRejected::new_err(format!("{block_uuid_hex}: {detail}")),
    }
}

/// Validate a 16-byte UUID slice; surface wrong length as `ValueError`
/// with the field name embedded in the message.
pub(crate) fn uuid_array_or_value_error(bytes: &[u8], field: &str) -> PyResult<[u8; 16]> {
    bytes.try_into().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "{field} must be 16 bytes, got {}",
            bytes.len()
        ))
    })
}
