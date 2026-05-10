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
create_exception!(secretary_ffi_py, VaultSaveCryptoFailure, PyException);
// B.4d share_block error surface — 4 typed exception classes mirroring
// the bridge's FfiVaultError variants.
create_exception!(secretary_ffi_py, VaultNotAuthor, PyException);
create_exception!(secretary_ffi_py, VaultRecipientAlreadyPresent, PyException);
create_exception!(secretary_ffi_py, VaultMissingRecipientCard, PyException);
create_exception!(secretary_ffi_py, VaultCardDecodeFailure, PyException);

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
        FfiVaultError::MissingRecipientCard {
            recipient_fingerprint_hex,
        } => VaultMissingRecipientCard::new_err(recipient_fingerprint_hex),
        FfiVaultError::CardDecodeFailure { detail } => VaultCardDecodeFailure::new_err(detail),
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
