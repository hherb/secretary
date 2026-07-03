//! FFI projection of the `repair_vault` crash-recovery orchestrator (#374).
//!
//! Three arms mirror the three `open_vault_with_*` / `open_with_device_secret`
//! arms. Each runs the same §10 rollback-resistance check as a normal open
//! before returning a handle — repair is never a weaker open. `now_ms` /
//! `device_uuid` follow the `save_block` convention (caller-supplied; the
//! manifest-clock tick keys on `device_uuid`).

use std::path::Path;

use rand_core::OsRng;
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::vault::{repair_vault, Unlocker};

use crate::error::FfiVaultError;
use crate::vault::orchestration::{
    enforce_rollback_resistance, split_core_open_vault, OpenVaultOutput,
};

/// Repair a crash-residue vault opened by master password. See
/// [`crate::open_vault_with_password`] for the open-only counterpart.
///
/// # Errors
///
/// Returns [`FfiVaultError`]. [`FfiVaultError::RepairRejected`] means the
/// on-disk residue failed one of the fail-closed adoption gates (hybrid
/// verify, header binding, clock freshness, or the recipient-widening
/// guard) — no change was written. Other variants mirror
/// [`crate::open_vault_with_password`].
pub fn repair_vault_with_password(
    folder: &Path,
    password: &[u8],
    device_uuid: &[u8; 16],
    now_ms: u64,
) -> Result<OpenVaultOutput, FfiVaultError> {
    let pw = SecretBytes::new(password.to_vec());
    let core_out = repair_vault(
        folder,
        Unlocker::Password(&pw),
        None,
        *device_uuid,
        now_ms,
        &mut OsRng,
    )?;
    enforce_rollback_resistance(&core_out)?;
    Ok(split_core_open_vault(core_out, folder.to_path_buf()))
    // pw drops here → ZeroizeOnDrop wipes the local copy.
}

/// Repair a crash-residue vault opened by 24-word BIP-39 recovery phrase.
/// See [`crate::open_vault_with_recovery`] for the open-only counterpart.
///
/// # Errors
///
/// Returns [`FfiVaultError`]. See [`repair_vault_with_password`] for the
/// repair-specific error semantics.
pub fn repair_vault_with_recovery(
    folder: &Path,
    mnemonic_bytes: &[u8],
    device_uuid: &[u8; 16],
    now_ms: u64,
) -> Result<OpenVaultOutput, FfiVaultError> {
    let phrase =
        std::str::from_utf8(mnemonic_bytes).map_err(|_| FfiVaultError::InvalidMnemonic {
            detail: "phrase contained invalid UTF-8".to_string(),
        })?;
    let core_out = repair_vault(
        folder,
        Unlocker::Recovery(phrase),
        None,
        *device_uuid,
        now_ms,
        &mut OsRng,
    )?;
    enforce_rollback_resistance(&core_out)?;
    Ok(split_core_open_vault(core_out, folder.to_path_buf()))
}

/// Repair a crash-residue vault opened by a per-device wrap secret (ADR 0009).
/// The single `device_uuid` selects the `devices/<uuid>.wrap` slot AND keys the
/// manifest-clock tick — the unlocking device is the slot's device. See
/// [`crate::open_with_device_secret`] for the open-only counterpart.
///
/// # Errors
///
/// Returns [`FfiVaultError`]. See [`repair_vault_with_password`] for the
/// repair-specific error semantics.
pub fn repair_vault_with_device_secret(
    folder: &Path,
    device_uuid: &[u8; 16],
    device_secret: &[u8; 32],
    now_ms: u64,
) -> Result<OpenVaultOutput, FfiVaultError> {
    let secret = SecretBytes::new(device_secret.to_vec());
    let core_out = repair_vault(
        folder,
        Unlocker::DeviceSecret {
            device_uuid,
            secret: &secret,
        },
        None,
        *device_uuid,
        now_ms,
        &mut OsRng,
    )?;
    enforce_rollback_resistance(&core_out)?;
    Ok(split_core_open_vault(core_out, folder.to_path_buf()))
    // secret drops here → SecretBytes ZeroizeOnDrop wipes our local copy.
}
