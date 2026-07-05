//! Crash-recovery `repair_vault` entry points (#374): [`repair_with_password`],
//! [`repair_with_recovery`], [`repair_with_device_secret`].
//!
//! Each mirrors its `open_*` / `open_with_device_secret` counterpart in
//! [`crate::vault`] / [`crate::device`] one-for-one — same folder-path UTF-8
//! validation, same credential-length checks, same zeroize discipline, same
//! `OpenVaultOutput` return shape — but calls
//! `secretary_ffi_bridge::repair_vault_with_*` instead of the plain open
//! path. Repair is never a weaker open: the bridge fn runs the same
//! rollback-resistance check as a normal open before returning a handle
//! (`core/src/vault/repair.rs`, vault-format.md §10).
//!
//! `device_uuid` / `now_ms` follow the `save_block` convention (caller-
//! supplied; the manifest-clock tick on adoption keys on `device_uuid`).
//! On the `WrongPasswordOrCorrupt` / crash-residue split: a genuine crash
//! residue surfaces as `VaultNeedsRepair` from the plain `open_*` calls
//! (see `errors.rs`); `repair_with_*` is the follow-up call once the
//! caller has decided to attempt adoption. `VaultRepairRejected` means one
//! of the fail-closed adoption gates (hybrid verify, header binding, clock
//! freshness, or the recipient-widening guard) refused the on-disk residue
//! — no change was written.

use pyo3::prelude::*;
use zeroize::Zeroize;

use crate::errors::ffi_vault_error_to_pyerr;
use crate::identity::UnlockedIdentity;
use crate::vault::{OpenVaultManifest, OpenVaultOutput};

/// Repair a crash-residue vault using its master password.
///
/// # Inputs
///
/// - `folder_path` — UTF-8 path to the vault directory as raw bytes.
/// - `password` — master password as raw bytes (owned; zeroized after the
///   bridge call returns on all paths).
/// - `device_uuid` — 16-byte device UUID; keys the manifest-clock tick on
///   adoption. `ValueError` if not exactly 16 bytes.
/// - `now_ms` — caller-supplied wall-clock milliseconds for the repair's
///   freshness gate.
///
/// # Raises
///
/// - `VaultRepairRejected` — the on-disk residue failed a fail-closed
///   adoption gate; no change was written.
/// - `VaultWrongPasswordOrCorrupt`, `VaultMismatchFolder`,
///   `VaultCorruptVault`, `VaultFolderInvalid` — same semantics as
///   `open_vault_with_password`.
/// - `ValueError` — `folder_path` not valid UTF-8, or `device_uuid` wrong
///   length.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)] // owned Vec<u8> required for zeroize discipline
pub(crate) fn repair_with_password(
    folder_path: &[u8],
    mut password: Vec<u8>,
    device_uuid: &[u8],
    now_ms: u64,
) -> PyResult<OpenVaultOutput> {
    if device_uuid.len() != 16 {
        password.zeroize();
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "device_uuid must be 16 bytes, got {}",
            device_uuid.len()
        )));
    }

    let folder_str = std::str::from_utf8(folder_path).map_err(|_| {
        password.zeroize();
        pyo3::exceptions::PyValueError::new_err("folder_path must be valid UTF-8")
    })?;
    let folder = std::path::Path::new(folder_str);

    // SAFETY: length checked above; unwrap cannot panic here.
    let uuid_arr: [u8; 16] = device_uuid.try_into().expect("length checked above");

    // Approvals project upward in a later task (#374); this entry point
    // always fails closed on any recipient widening for now.
    let result =
        secretary_ffi_bridge::repair_vault_with_password(folder, &password, &uuid_arr, now_ms, &[])
            .map_err(ffi_vault_error_to_pyerr);
    password.zeroize();

    let bridge_out = result?;
    let secretary_ffi_bridge::OpenVaultOutput { identity, manifest } = bridge_out;
    Ok(OpenVaultOutput::from_bridge(
        UnlockedIdentity(identity),
        OpenVaultManifest(manifest),
    ))
}

/// Repair a crash-residue vault using its 24-word BIP-39 recovery phrase.
///
/// # Inputs
///
/// - `folder_path` — UTF-8 path to the vault directory as raw bytes.
/// - `mnemonic` — UTF-8-encoded recovery phrase as raw bytes (owned;
///   zeroized after the bridge call returns on all paths).
/// - `device_uuid` — 16-byte device UUID. `ValueError` if not exactly 16
///   bytes.
/// - `now_ms` — caller-supplied wall-clock milliseconds for the repair's
///   freshness gate.
///
/// # Raises
///
/// - `VaultRepairRejected` — see [`repair_with_password`].
/// - `VaultWrongMnemonicOrCorrupt`, `VaultInvalidMnemonic`,
///   `VaultMismatchFolder`, `VaultCorruptVault`, `VaultFolderInvalid` —
///   same semantics as `open_vault_with_recovery`.
/// - `ValueError` — `folder_path` not valid UTF-8, or `device_uuid` wrong
///   length.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)] // owned Vec<u8> required for zeroize discipline
pub(crate) fn repair_with_recovery(
    folder_path: &[u8],
    mut mnemonic: Vec<u8>,
    device_uuid: &[u8],
    now_ms: u64,
) -> PyResult<OpenVaultOutput> {
    if device_uuid.len() != 16 {
        mnemonic.zeroize();
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "device_uuid must be 16 bytes, got {}",
            device_uuid.len()
        )));
    }

    let folder_str = std::str::from_utf8(folder_path).map_err(|_| {
        mnemonic.zeroize();
        pyo3::exceptions::PyValueError::new_err("folder_path must be valid UTF-8")
    })?;
    let folder = std::path::Path::new(folder_str);

    // SAFETY: length checked above; unwrap cannot panic here.
    let uuid_arr: [u8; 16] = device_uuid.try_into().expect("length checked above");

    // Approvals project upward in a later task (#374); this entry point
    // always fails closed on any recipient widening for now.
    let result =
        secretary_ffi_bridge::repair_vault_with_recovery(folder, &mnemonic, &uuid_arr, now_ms, &[])
            .map_err(ffi_vault_error_to_pyerr);
    mnemonic.zeroize();

    let bridge_out = result?;
    let secretary_ffi_bridge::OpenVaultOutput { identity, manifest } = bridge_out;
    Ok(OpenVaultOutput::from_bridge(
        UnlockedIdentity(identity),
        OpenVaultManifest(manifest),
    ))
}

/// Repair a crash-residue vault using a per-device wrap secret (ADR 0009).
///
/// # Inputs
///
/// - `folder_path` — UTF-8 path to the vault directory as raw bytes.
/// - `device_uuid` — the 16-byte device UUID (also selects the
///   `devices/<uuid>.wrap` slot). `ValueError` if not exactly 16 bytes.
/// - `device_secret` — the 32-byte device secret (owned; zeroized on all
///   paths, including the `[u8; 32]` stack-copy). `ValueError` if not
///   exactly 32 bytes.
/// - `now_ms` — caller-supplied wall-clock milliseconds for the repair's
///   freshness gate.
///
/// # Raises
///
/// - `VaultRepairRejected` — see [`repair_with_password`].
/// - `VaultDeviceSlotNotFound`, `VaultWrongDeviceSecretOrCorrupt`,
///   `VaultDeviceUuidMismatch`, `VaultFolderInvalid` — same semantics as
///   `open_with_device_secret`.
/// - `ValueError` — `folder_path` not valid UTF-8, or `device_uuid` /
///   `device_secret` wrong length.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)] // owned Vec<u8> required for zeroize discipline
pub(crate) fn repair_with_device_secret(
    folder_path: &[u8],
    device_uuid: &[u8],
    mut device_secret: Vec<u8>,
    now_ms: u64,
) -> PyResult<OpenVaultOutput> {
    // Length pre-checks: zeroize device_secret before every early return.
    if device_uuid.len() != 16 {
        device_secret.zeroize();
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "device_uuid must be 16 bytes, got {}",
            device_uuid.len()
        )));
    }
    if device_secret.len() != 32 {
        device_secret.zeroize();
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "device_secret must be 32 bytes, got {}",
            device_secret.len()
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

    // Approvals project upward in a later task (#374); this entry point
    // always fails closed on any recipient widening for now.
    let result = secretary_ffi_bridge::repair_vault_with_device_secret(
        folder,
        &uuid_arr,
        &secret_arr,
        now_ms,
        &[],
    )
    .map_err(ffi_vault_error_to_pyerr);

    // Zeroize the stack copy AND the owned Vec on ALL paths.
    secret_arr.zeroize();
    device_secret.zeroize();

    let bridge_out = result?;
    let secretary_ffi_bridge::OpenVaultOutput { identity, manifest } = bridge_out;
    Ok(OpenVaultOutput::from_bridge(
        UnlockedIdentity(identity),
        OpenVaultManifest(manifest),
    ))
}
