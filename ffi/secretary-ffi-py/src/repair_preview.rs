//! Read-only `preview_repair` pyo3 projection (#374 Task 8): lets a Python
//! caller build an informed-consent prompt (recipient names + fingerprints)
//! BEFORE choosing an [`crate::repair::ApprovedWidening`] set to hand to
//! one of `crate::repair`'s `repair_with_*` functions.
//!
//! Three arms mirror the three `repair_with_*` arms in [`crate::repair`] —
//! same folder-path UTF-8 validation, same credential-length checks — but
//! call `secretary_ffi_bridge::preview_repair_with_*` instead of
//! `repair_vault_with_*`: nothing is written to disk, so unlike the
//! mutating arms there is no `device_uuid` / `now_ms` to thread through.
//!
//! Output shape mirrors the uniffi binding's dictionary projections
//! (`secretary-ffi-uniffi/src/wrappers/repair.rs`), adapted to
//! `#[pyclass(get_all)]` the same way `sync.rs`'s DTOs are: nested output
//! types (`AddedRecipient` inside `WideningReport.added`, `WideningReport`
//! inside `RepairPreview.widenings`) need `Clone` + `skip_from_py_object`
//! because a `get_all` `Vec` getter clones the field out to Python and
//! these types are output-only (never extracted from Python).

use pyo3::prelude::*;
use zeroize::Zeroize;

use crate::errors::ffi_vault_error_to_pyerr;

/// One recipient a consent-eligible widening would add, projected with
/// display-oriented hex fields. Secret-free — mirrors
/// `secretary_ffi_bridge::FfiAddedRecipient`.
#[pyclass(frozen, get_all, skip_from_py_object)]
#[derive(Clone)]
pub struct AddedRecipient {
    /// Lowercase hyphenated UUID of the contact this widening would add.
    pub uuid_hex: String,
    /// The contact's verified `display_name`.
    pub display_name: String,
    /// 32 lowercase hex chars — the contact's identity fingerprint (NOT
    /// the block content fingerprint; see
    /// [`WideningReport::file_fingerprint_hex`] for that one).
    pub card_fingerprint_hex: String,
}

impl From<secretary_ffi_bridge::FfiAddedRecipient> for AddedRecipient {
    fn from(a: secretary_ffi_bridge::FfiAddedRecipient) -> Self {
        Self {
            uuid_hex: a.uuid_hex,
            display_name: a.display_name,
            card_fingerprint_hex: a.card_fingerprint_hex,
        }
    }
}

/// One block whose crash residue is a consent-eligible recipient
/// widening, projected with display-oriented hex fields for an
/// informed-consent prompt. Mirrors
/// `secretary_ffi_bridge::FfiWideningReport`.
#[pyclass(frozen, get_all, skip_from_py_object)]
#[derive(Clone)]
pub struct WideningReport {
    /// Lowercase hyphenated UUID of the affected block.
    pub block_uuid_hex: String,
    /// The block's plaintext name, for display.
    pub block_name: String,
    /// 64 lowercase hex chars — BLAKE3-256 of the on-disk block file
    /// bytes previewed here. Hex-decode this back to `[u8; 32]` for
    /// `ApprovedWidening.file_fingerprint` to bind a subsequent repair
    /// approval to exactly these bytes; a file swapped between preview
    /// and repair fails that bind as stale consent.
    pub file_fingerprint_hex: String,
    /// The exact recipients this widening would add, in no particular
    /// order.
    pub added: Vec<AddedRecipient>,
}

impl From<secretary_ffi_bridge::FfiWideningReport> for WideningReport {
    fn from(w: secretary_ffi_bridge::FfiWideningReport) -> Self {
        Self {
            block_uuid_hex: w.block_uuid_hex,
            block_name: w.block_name,
            file_fingerprint_hex: w.file_fingerprint_hex,
            added: w.added.into_iter().map(AddedRecipient::from).collect(),
        }
    }
}

/// The read-only result of a `preview_repair_with_*` call: every
/// consent-eligible recipient widening found in the vault's crash
/// residue. Producing this value writes nothing to disk. Top-level
/// return type (not nested inside another `get_all` `Vec`), so no
/// `Clone` / `skip_from_py_object` is needed.
#[pyclass(frozen, get_all)]
pub struct RepairPreview {
    /// One entry per affected block.
    pub widenings: Vec<WideningReport>,
}

impl From<secretary_ffi_bridge::FfiRepairPreview> for RepairPreview {
    fn from(p: secretary_ffi_bridge::FfiRepairPreview) -> Self {
        Self {
            widenings: p.widenings.into_iter().map(WideningReport::from).collect(),
        }
    }
}

/// Preview a crash-residue vault's consent-eligible recipient widenings
/// using its master password, without writing anything.
///
/// # Inputs
///
/// - `folder_path` — UTF-8 path to the vault directory as raw bytes.
/// - `password` — master password as raw bytes (owned; zeroized after the
///   bridge call returns on all paths).
///
/// # Raises
///
/// Same `FfiVaultError`-mapped exceptions as `repair_with_password` — a
/// vault whose residue cannot be repaired at all (e.g. a rollback plant,
/// or a hard-rejected shape) errors identically here, since there is
/// nothing to consent to on a vault that cannot be repaired.
/// - `ValueError` — `folder_path` not valid UTF-8.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)] // owned Vec<u8> required for zeroize discipline
pub(crate) fn preview_repair_with_password(
    folder_path: &[u8],
    mut password: Vec<u8>,
) -> PyResult<RepairPreview> {
    let folder_str = std::str::from_utf8(folder_path).map_err(|_| {
        password.zeroize();
        pyo3::exceptions::PyValueError::new_err("folder_path must be valid UTF-8")
    })?;
    let folder = std::path::Path::new(folder_str);

    let result = secretary_ffi_bridge::preview_repair_with_password(folder, &password)
        .map_err(ffi_vault_error_to_pyerr);
    password.zeroize();

    result.map(RepairPreview::from)
}

/// Preview a crash-residue vault's consent-eligible recipient widenings
/// using its 24-word BIP-39 recovery phrase, without writing anything.
/// See [`preview_repair_with_password`] for the shared semantics.
///
/// `mnemonic` is zeroized after the bridge call returns on all paths.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)] // owned Vec<u8> required for zeroize discipline
pub(crate) fn preview_repair_with_recovery(
    folder_path: &[u8],
    mut mnemonic: Vec<u8>,
) -> PyResult<RepairPreview> {
    let folder_str = std::str::from_utf8(folder_path).map_err(|_| {
        mnemonic.zeroize();
        pyo3::exceptions::PyValueError::new_err("folder_path must be valid UTF-8")
    })?;
    let folder = std::path::Path::new(folder_str);

    let result = secretary_ffi_bridge::preview_repair_with_recovery(folder, &mnemonic)
        .map_err(ffi_vault_error_to_pyerr);
    mnemonic.zeroize();

    result.map(RepairPreview::from)
}

/// Preview a crash-residue vault's consent-eligible recipient widenings
/// using a per-device wrap secret (ADR 0009), without writing anything.
/// See [`preview_repair_with_password`] for the shared semantics.
///
/// `device_uuid` must be exactly 16 bytes; `device_secret` must be
/// exactly 32 bytes (owned; zeroized on all paths, including the
/// `[u8; 32]` stack copy).
///
/// # Raises
///
/// - `ValueError` — `folder_path` not valid UTF-8, or `device_uuid` /
///   `device_secret` wrong length.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)] // owned Vec<u8> required for zeroize discipline
pub(crate) fn preview_repair_with_device_secret(
    folder_path: &[u8],
    device_uuid: &[u8],
    mut device_secret: Vec<u8>,
) -> PyResult<RepairPreview> {
    if device_uuid.len() != 16 {
        device_secret.zeroize();
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "device_uuid must be 16 bytes, got {}",
            device_uuid.len()
        )));
    }
    if device_secret.len() != 32 {
        // Capture the length BEFORE zeroize(): `Vec::zeroize()` calls
        // `self.clear()`, so reading `device_secret.len()` after
        // zeroizing would always report 0 rather than the actual wrong
        // length (mirrors `repair::repair_with_device_secret`).
        let got = device_secret.len();
        device_secret.zeroize();
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "device_secret must be 32 bytes, got {got}"
        )));
    }

    let folder_str = std::str::from_utf8(folder_path).map_err(|_| {
        device_secret.zeroize();
        pyo3::exceptions::PyValueError::new_err("folder_path must be valid UTF-8")
    })?;
    let folder = std::path::Path::new(folder_str);

    // SAFETY: lengths were checked above; unwrap cannot panic here.
    let uuid_arr: [u8; 16] = device_uuid.try_into().expect("length checked above");
    let mut secret_arr: [u8; 32] = device_secret
        .as_slice()
        .try_into()
        .expect("length checked above");

    let result =
        secretary_ffi_bridge::preview_repair_with_device_secret(folder, &uuid_arr, &secret_arr)
            .map_err(ffi_vault_error_to_pyerr);

    // Zeroize the stack copy AND the owned Vec on ALL paths.
    secret_arr.zeroize();
    device_secret.zeroize();

    result.map(RepairPreview::from)
}
