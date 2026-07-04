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
//! So we hand core `repair_vault` the local baseline as `local_highest_clock`
//! (`Some`) instead of `None`. Core runs the §10 `is_rollback` check inside
//! `read_and_verify_manifest`, at the TOP, on the COMMITTED clock, BEFORE the
//! tick/write — a rollback surfaces as `VaultError::Rollback` → fail-closed,
//! nothing is mutated. The baseline is keyed by the `vault_uuid` from the
//! plaintext `vault.toml`; that is sound because that same `vault_uuid` is
//! bound into the unlock-time AEAD as associated data
//! (`compose_aad(TAG_ID_WRAP_PW, &vt.vault_uuid)` in `unlock/mod.rs`, and the
//! bundle-decrypt AAD on the device path), so a tampered `vault.toml`
//! `vault_uuid` makes the unlock's AEAD auth tag fail
//! (`UnlockError::WrongPasswordOrCorrupt` / `VaultMismatch`) *before* repair
//! reaches any manifest read or write — it can never point the baseline at a
//! weaker `vault_uuid` to sneak a rollback through. (Note: this is NOT
//! `ManifestVaultUuidMismatch`, which only cross-checks manifest body vs
//! header — both manifest-internal — and never compares `vault.toml`.) This
//! replaces the previous (buggy) post-write `enforce_rollback_resistance`
//! call, which is no longer made here.

use std::path::Path;

use rand_core::OsRng;
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::vault::{repair_vault, Unlocker, VectorClockEntry};

use crate::error::FfiVaultError;
use crate::vault::orchestration::{split_core_open_vault, OpenVaultOutput};

/// Best-effort load of this device's §10 rollback baseline for `folder`, keyed
/// by the plaintext `vault.toml` `vault_uuid`.
///
/// Mirrors
/// [`enforce_rollback_resistance`](crate::vault::orchestration::enforce_rollback_resistance)'s
/// availability posture: the state
/// directory is OS-local and outside the cloud-replay threat surface, so any
/// failure to obtain a usable baseline — no resolvable state dir, an
/// unreadable / undecodable `vault.toml`, an unreadable / missing state file,
/// or an empty (never-synced) baseline — returns `None` and SKIPs the check
/// rather than bricking a legitimate repair. A never-synced device therefore
/// has no false positive.
///
/// Keying by the *plaintext* `vault.toml` `vault_uuid` is sound: that same
/// `vault_uuid` is bound into the unlock-time AEAD as associated data (the
/// `wrap_pw` AAD on the password/recovery paths, the bundle-decrypt AAD on the
/// device path). A tampered `vault.toml` `vault_uuid` therefore fails the
/// unlock's AEAD auth tag (`WrongPasswordOrCorrupt` / `VaultMismatch`) *before*
/// `repair_vault` reaches any manifest read or write, so it can never point the
/// check at a weaker baseline to sneak a rollback through. This is NOT enforced
/// by `ManifestVaultUuidMismatch` (a manifest body-vs-header check that never
/// looks at `vault.toml`).
fn load_rollback_baseline(
    state_dir: Option<&Path>,
    folder: &Path,
) -> Option<Vec<VectorClockEntry>> {
    let state_dir = state_dir?;
    let vault_toml = std::fs::read_to_string(folder.join("vault.toml")).ok()?;
    let vault_uuid = secretary_core::unlock::vault_toml::decode(&vault_toml)
        .ok()?
        .vault_uuid;
    let clock = secretary_cli::state::load(state_dir, vault_uuid)
        .ok()?
        .highest_vector_clock_seen;
    // Empty baseline (never-synced) is indistinguishable from no baseline for
    // §10 purposes; pass `None` so core skips the check (no false positive).
    (!clock.is_empty()).then_some(clock)
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
/// absent/empty baseline both yield a `None` `local_highest_clock`, i.e.
/// the pre-#374 behavior with no false positive.
pub(crate) fn repair_vault_with_password_in(
    state_dir: Option<&Path>,
    folder: &Path,
    password: &[u8],
    device_uuid: &[u8; 16],
    now_ms: u64,
) -> Result<OpenVaultOutput, FfiVaultError> {
    let baseline = load_rollback_baseline(state_dir, folder);
    let pw = SecretBytes::new(password.to_vec());
    // Pass the baseline as `local_highest_clock`: core runs the §10 check on
    // the COMMITTED clock before it ticks/rewrites the manifest — the
    // pre-write gate is the §10 guard for this mutating path (see module docs).
    let core_out = repair_vault(
        folder,
        Unlocker::Password(&pw),
        baseline.as_deref(),
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
    let baseline = load_rollback_baseline(state_dir, folder);
    let core_out = repair_vault(
        folder,
        Unlocker::Recovery(phrase),
        baseline.as_deref(),
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
    let baseline = load_rollback_baseline(state_dir, folder);
    let secret = SecretBytes::new(device_secret.to_vec());
    let core_out = repair_vault(
        folder,
        Unlocker::DeviceSecret {
            device_uuid,
            secret: &secret,
        },
        baseline.as_deref(),
        *device_uuid,
        now_ms,
        &mut OsRng,
    )?;
    Ok(split_core_open_vault(core_out, folder.to_path_buf()))
    // secret drops here → SecretBytes ZeroizeOnDrop wipes our local copy.
}
