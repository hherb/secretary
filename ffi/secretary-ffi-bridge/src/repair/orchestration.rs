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
//! original post-write `enforce_rollback_resistance` call — that fn
//! remains correct on the read-only open path; the bug was running it
//! post-write on this mutating path.
//!
//! ## Fail-closed on an existing-but-unreadable baseline (#384)
//!
//! The read-only open path skips §10 when the local baseline cannot be
//! read (availability posture: a rolled-back READ leaks once and
//! self-heals on the next open, which re-checks the persisted baseline).
//! Repair is NOT symmetric: it rewrites the manifest, so a skipped check
//! is permanent laundering. Hence: missing/never-synced baseline → skip
//! (no false positive); any OTHER state-load failure → refuse, with the
//! remedy in the error detail. That covers both an existing-but-unusable
//! state file (deleting it is the crypto-design §10 documented reset to a
//! "no history" device) and a path-level failure (PermissionDenied /
//! NotADirectory on the state dir), where the baseline's absence cannot
//! be proven and skipping would risk laundering a real-but-unreadable
//! baseline.

use std::path::Path;

use rand_core::OsRng;
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::vault::{
    repair_vault, ApprovedWidening, RepairPolicy, Unlocker, VaultError, VectorClockEntry,
};

use crate::error::FfiVaultError;
use crate::repair::types::FfiApprovedWidening;
use crate::vault::orchestration::{split_core_open_vault, OpenVaultOutput};

/// Map the FFI-seam approvals slice into the [`RepairPolicy`] the three
/// arms hand to core `repair_vault`. An empty `approvals` slice is the
/// documented safe zero-value: it maps to [`RepairPolicy::FailClosed`],
/// replacing the Task 2 hardcoded stopgap. A non-empty slice licenses
/// ONLY the exact widenings named — every other consent-eligible shape
/// (missing approval, mismatched fingerprint, mismatched added-recipient
/// set) still refuses inside core's classification (see
/// `core/src/vault/repair/policy.rs` / `orchestration.rs`).
fn build_repair_policy(approvals: &[FfiApprovedWidening]) -> RepairPolicy {
    if approvals.is_empty() {
        RepairPolicy::FailClosed
    } else {
        RepairPolicy::AdoptApproved(
            approvals
                .iter()
                .map(|a| ApprovedWidening {
                    block_uuid: a.block_uuid,
                    file_fingerprint: a.file_fingerprint,
                    committed_fingerprint: a.committed_fingerprint,
                    added_recipients: a.added_recipients.iter().copied().collect(),
                })
                .collect(),
        )
    }
}

/// Build the §10 rollback-baseline provider shared by the three repair
/// arms AND the three `preview_repair_with_*` arms in
/// [`super::preview`] (the fail-closed posture applies identically to a
/// read-only preview — see that module's docs). Core `repair_vault` /
/// `preview_repair` invokes the returned closure with the
/// **verified** `manifest.vault_uuid` (post hybrid-verify + AEAD
/// decrypt), so the state lookup can never be keyed by an
/// attacker-controlled plaintext value (#384). A `None` state dir (no
/// resolvable OS state dir) and an empty baseline (missing state file /
/// never-synced device) both yield `Ok(None)` — §10 is skipped with no
/// false positive on a fresh device. Every other state-load failure fails
/// the repair CLOSED: an existing state file that cannot be used
/// (unreadable, undecodable, internal-uuid mismatch), and equally a
/// path-level failure (PermissionDenied / NotADirectory on the state
/// dir), where a baseline may exist but cannot be proven absent — on this
/// mutating path a skipped check would launder a rollback permanently,
/// whereas the read-only open path's skip posture self-heals on the next
/// open (#384; deliberate asymmetry).
pub(super) fn baseline_provider(
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
            // #384 fail-closed: any state-load failure other than a
            // provably-missing file refuses the MUTATING repair — a
            // skipped check here would let adoption tick + re-sign the
            // manifest, permanently laundering a rolled-back clock (unlike
            // the read-only open path, which self-heals on the next open).
            // `state::load` maps only ErrorKind::NotFound to "no
            // baseline"; this arm therefore sees both an existing-but-
            // unusable state file (garbage bytes, internal-uuid mismatch)
            // AND a path-level failure (PermissionDenied / NotADirectory
            // on the state dir) where no file may exist at all — the two
            // are indistinguishable here, so the detail must not assert
            // that the file exists, and must name both remedies.
            // ErrorKind::InvalidData is deliberate: the FfiVaultError
            // conversion routes it to the `CorruptVault { detail }` fold
            // (which carries this full message), never to `FolderInvalid`
            // ("vault path wrong" — a misdiagnosis here), even when the
            // underlying cause was e.g. PermissionDenied on the state file.
            Err(e) => {
                let path = secretary_cli::state::state_file_path(state_dir, *vault_uuid);
                Err(VaultError::Io {
                    context: "§10 rollback baseline state could not be read",
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "{e}; state file path: {}; if that file exists, deleting it resets this device's rollback history (crypto-design §10's documented reset) — then retry the repair; if it does not exist, the state directory itself is inaccessible (permissions, or a path component that is not a directory) and must be fixed instead",
                            path.display()
                        ),
                    ),
                })
            }
        }
    }
}

/// Repair a crash-residue vault opened by master password. See
/// [`crate::open_vault_with_password`] for the open-only counterpart.
///
/// `approvals` licenses consent-eligible recipient-widening residue (the
/// crashed-`share_block` shape); an empty slice is the documented safe
/// zero-value and behaves exactly as pre-#374-part-3 (fail-closed on any
/// widening). See [`FfiApprovedWidening`] for the exact-bind semantics.
///
/// # Errors
///
/// Returns [`FfiVaultError`]. [`FfiVaultError::RepairRejected`] means the
/// on-disk residue failed one of the fail-closed adoption gates (hybrid
/// verify, header binding, clock freshness, or the recipient-widening
/// guard, including a widening with no matching — or a stale — approval)
/// — no change was written. Other variants mirror
/// [`crate::open_vault_with_password`].
pub fn repair_vault_with_password(
    folder: &Path,
    password: &[u8],
    device_uuid: &[u8; 16],
    now_ms: u64,
    approvals: &[FfiApprovedWidening],
) -> Result<OpenVaultOutput, FfiVaultError> {
    repair_vault_with_password_in(
        secretary_cli::state::default_state_dir().as_deref(),
        folder,
        password,
        device_uuid,
        now_ms,
        approvals,
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
    approvals: &[FfiApprovedWidening],
) -> Result<OpenVaultOutput, FfiVaultError> {
    let pw = SecretBytes::new(password.to_vec());
    // Core invokes the provider with the VERIFIED manifest vault_uuid and
    // runs the §10 check on the COMMITTED clock before it ticks/rewrites
    // the manifest — the pre-write gate for this mutating path (module docs).
    // §10 fail-closed is unconditional here: it runs before any per-block
    // classification/consent decision, so a valid `approvals` entry never
    // overrides a refused rollback baseline.
    let core_out = repair_vault(
        folder,
        Unlocker::Password(&pw),
        baseline_provider(state_dir),
        *device_uuid,
        now_ms,
        &mut OsRng,
        build_repair_policy(approvals),
    )?;
    Ok(split_core_open_vault(core_out, folder.to_path_buf()))
    // pw drops here → ZeroizeOnDrop wipes the local copy.
}

/// Repair a crash-residue vault opened by 24-word BIP-39 recovery phrase.
/// See [`crate::open_vault_with_recovery`] for the open-only counterpart.
///
/// `approvals` licenses consent-eligible recipient-widening residue; see
/// [`repair_vault_with_password`] for the exact-bind semantics and the
/// empty-slice safe zero-value.
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
    approvals: &[FfiApprovedWidening],
) -> Result<OpenVaultOutput, FfiVaultError> {
    repair_vault_with_recovery_in(
        secretary_cli::state::default_state_dir().as_deref(),
        folder,
        mnemonic_bytes,
        device_uuid,
        now_ms,
        approvals,
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
    approvals: &[FfiApprovedWidening],
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
        build_repair_policy(approvals),
    )?;
    Ok(split_core_open_vault(core_out, folder.to_path_buf()))
}

/// Repair a crash-residue vault opened by a per-device wrap secret (ADR 0009).
/// The single `device_uuid` selects the `devices/<uuid>.wrap` slot AND keys the
/// manifest-clock tick — the unlocking device is the slot's device. See
/// [`crate::open_with_device_secret`] for the open-only counterpart.
///
/// `approvals` licenses consent-eligible recipient-widening residue; see
/// [`repair_vault_with_password`] for the exact-bind semantics and the
/// empty-slice safe zero-value.
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
    approvals: &[FfiApprovedWidening],
) -> Result<OpenVaultOutput, FfiVaultError> {
    repair_vault_with_device_secret_in(
        secretary_cli::state::default_state_dir().as_deref(),
        folder,
        device_uuid,
        device_secret,
        now_ms,
        approvals,
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
    approvals: &[FfiApprovedWidening],
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
        build_repair_policy(approvals),
    )?;
    Ok(split_core_open_vault(core_out, folder.to_path_buf()))
    // secret drops here → SecretBytes ZeroizeOnDrop wipes our local copy.
}
