//! FFI projection of the `repair_vault` crash-recovery orchestrator (#374).
//!
//! Three arms mirror the three `open_vault_with_*` / `open_with_device_secret`
//! arms. `now_ms` / `device_uuid` follow the `save_block` convention
//! (caller-supplied; the manifest-clock tick keys on `device_uuid`).
//!
//! ## §10 rollback resistance is gated PRE-write (the #374 fix)
//!
//! Unlike the read-only open path (where
//! [`enforce_rollback_resistance`](crate::vault::orchestration::enforce_rollback_resistance)
//! runs *after* the decode and is sufficient, because a plain open never mutates the
//! vault), repair is a *mutating* path: core `repair_vault` adopts crash
//! residue, ticks the manifest vector clock, and atomically re-signs +
//! rewrites the signed manifest before it returns. A post-write §10 check would
//! evaluate the *post-tick* clock — the local tick sets `any_strictly_more` in
//! `is_rollback`, flipping a strictly-dominated (rollback) committed clock into
//! a "concurrent" post-tick clock that is no longer flagged, masking the
//! rollback permanently and defeating the #352 invariant on the exact path the
//! design claims preserves it.
//!
//! So we hand core `repair_vault` a baseline *provider* instead of a
//! pre-loaded clock. Core invokes it with the **verified**
//! `manifest.vault_uuid` — available only after hybrid-verify + AEAD
//! decrypt — inside the pre-write window, so the baseline lookup can
//! never be keyed by an attacker-controlled plaintext value. (The
//! previous design keyed it off the plaintext `vault.toml` `vault_uuid`
//! and relied on the unlock-time AEAD AAD binding as an out-of-band
//! guard; #384 removed that reliance.) A provider error propagates
//! fail-closed before anything is staged or written. This replaces the
//! original (buggy) post-write `enforce_rollback_resistance` call.

use std::path::Path;

use rand_core::OsRng;
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::vault::{repair_vault, Unlocker, VaultError, VectorClockEntry};

use crate::error::FfiVaultError;
use crate::vault::orchestration::{split_core_open_vault, OpenVaultOutput};

/// Build the §10 rollback-baseline provider shared by the three repair
/// arms. Core `repair_vault` invokes the returned closure with the
/// **verified** `manifest.vault_uuid` (post hybrid-verify + AEAD
/// decrypt), so the state lookup can never be keyed by an
/// attacker-controlled plaintext value (#384). A `None` state dir (no
/// resolvable OS state dir) and an empty baseline (missing state file /
/// never-synced device) both yield `Ok(None)` — §10 is skipped with no
/// false positive on a fresh device.
fn baseline_provider(
    state_dir: Option<&Path>,
) -> impl FnOnce(&[u8; 16]) -> Result<Option<Vec<VectorClockEntry>>, VaultError> + '_ {
    move |vault_uuid: &[u8; 16]| {
        let Some(state_dir) = state_dir else {
            return Ok(None);
        };
        match secretary_cli::state::load(state_dir, *vault_uuid) {
            Ok(state) => {
                let clock = state.highest_vector_clock_seen;
                // Empty baseline (never-synced) is indistinguishable from
                // no baseline for §10 purposes; skip (no false positive).
                Ok((!clock.is_empty()).then_some(clock))
            }
            // Interim fail-open posture — flipped to fail-closed in the
            // next commit (#384 posture half, RED-proven there).
            Err(_) => Ok(None),
        }
    }
}

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
    repair_vault_with_password_in(
        secretary_cli::state::default_state_dir().as_deref(),
        folder,
        password,
        device_uuid,
        now_ms,
    )
}

/// Explicit-`state_dir` seam for [`repair_vault_with_password`]
/// (host-testable — a test injects a temp state dir carrying a seeded §10
/// baseline). `state_dir == None` (no resolvable OS state dir) or an
/// absent/empty baseline both yield a provider that resolves to `Ok(None)`,
/// i.e. the pre-#374 behavior with no false positive.
pub(crate) fn repair_vault_with_password_in(
    state_dir: Option<&Path>,
    folder: &Path,
    password: &[u8],
    device_uuid: &[u8; 16],
    now_ms: u64,
) -> Result<OpenVaultOutput, FfiVaultError> {
    let pw = SecretBytes::new(password.to_vec());
    // Core invokes the provider with the VERIFIED manifest vault_uuid and
    // runs the §10 check on the COMMITTED clock before it ticks/rewrites
    // the manifest — the pre-write gate for this mutating path (module docs).
    let core_out = repair_vault(
        folder,
        Unlocker::Password(&pw),
        baseline_provider(state_dir),
        *device_uuid,
        now_ms,
        &mut OsRng,
    )?;
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
    repair_vault_with_recovery_in(
        secretary_cli::state::default_state_dir().as_deref(),
        folder,
        mnemonic_bytes,
        device_uuid,
        now_ms,
    )
}

/// Explicit-`state_dir` seam for [`repair_vault_with_recovery`]. See
/// [`repair_vault_with_password_in`] for the §10 pre-write gate rationale.
pub(crate) fn repair_vault_with_recovery_in(
    state_dir: Option<&Path>,
    folder: &Path,
    mnemonic_bytes: &[u8],
    device_uuid: &[u8; 16],
    now_ms: u64,
) -> Result<OpenVaultOutput, FfiVaultError> {
    let phrase =
        std::str::from_utf8(mnemonic_bytes).map_err(|_| FfiVaultError::InvalidMnemonic {
            detail: "phrase contained invalid UTF-8".to_string(),
        })?;
    // Core invokes the provider with the VERIFIED manifest vault_uuid and
    // runs the §10 check on the COMMITTED clock before it ticks/rewrites
    // the manifest — the pre-write gate for this mutating path (module docs).
    let core_out = repair_vault(
        folder,
        Unlocker::Recovery(phrase),
        baseline_provider(state_dir),
        *device_uuid,
        now_ms,
        &mut OsRng,
    )?;
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
    repair_vault_with_device_secret_in(
        secretary_cli::state::default_state_dir().as_deref(),
        folder,
        device_uuid,
        device_secret,
        now_ms,
    )
}

/// Explicit-`state_dir` seam for [`repair_vault_with_device_secret`]. See
/// [`repair_vault_with_password_in`] for the §10 pre-write gate rationale.
pub(crate) fn repair_vault_with_device_secret_in(
    state_dir: Option<&Path>,
    folder: &Path,
    device_uuid: &[u8; 16],
    device_secret: &[u8; 32],
    now_ms: u64,
) -> Result<OpenVaultOutput, FfiVaultError> {
    let secret = SecretBytes::new(device_secret.to_vec());
    // Core invokes the provider with the VERIFIED manifest vault_uuid and
    // runs the §10 check on the COMMITTED clock before it ticks/rewrites
    // the manifest — the pre-write gate for this mutating path (module docs).
    let core_out = repair_vault(
        folder,
        Unlocker::DeviceSecret {
            device_uuid,
            secret: &secret,
        },
        baseline_provider(state_dir),
        *device_uuid,
        now_ms,
        &mut OsRng,
    )?;
    Ok(split_core_open_vault(core_out, folder.to_path_buf()))
    // secret drops here → SecretBytes ZeroizeOnDrop wipes our local copy.
}
