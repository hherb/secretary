//! Read-only `preview_repair` FFI projection (#374 Task 6).
//!
//! Three arms mirror the three `repair_vault_with_*` arms in
//! [`super::orchestration`] — same unlock mapping (password →
//! `Unlocker::Password`; recovery → UTF-8 validation then
//! `Unlocker::Recovery`; device-secret → `Unlocker::DeviceSecret`), same
//! `_in(state_dir, ...)` host-testable seam — but they call core's
//! `preview_repair` instead of `repair_vault`: nothing is written to
//! disk. The point is to let a caller show an informed-consent prompt
//! (recipient names + fingerprints) BEFORE choosing a
//! [`super::FfiApprovedWidening`] set to hand to a `repair_vault_with_*`
//! call.
//!
//! Each arm passes the exact same [`baseline_provider`](super::orchestration::baseline_provider)
//! as its `repair_vault_with_*` counterpart — the §10 fail-closed posture
//! documented on that helper applies identically here: a caller must
//! never be shown a "safe to adopt" preview for a vault whose committed
//! clock is itself an unprovable rollback, so a broken baseline store
//! surfaces at preview time, before any consent dialog is even drawn.

use std::path::Path;

use secretary_core::crypto::secret::SecretBytes;
use secretary_core::vault::{format_uuid_hyphenated, preview_repair, Unlocker};

use super::orchestration::baseline_provider;
use crate::error::FfiVaultError;

/// One recipient a consent-eligible widening would add, projected across
/// the FFI seam with display-oriented hex fields.
#[derive(Debug, Clone)]
pub struct FfiAddedRecipient {
    /// Lowercase hyphenated UUID of the contact this widening would add.
    pub uuid_hex: String,
    /// The contact's verified `display_name` read from its
    /// `contacts/*.card`.
    pub display_name: String,
    /// 32 lowercase hex chars — the 16-byte identity fingerprint
    /// (`secretary_core::identity::fingerprint::fingerprint` output; the
    /// same value §6.2 wraps use as `recipient_fingerprint`). This is
    /// NOT the 32-byte block content fingerprint — see
    /// [`FfiWideningReport::file_fingerprint_hex`] for that one.
    pub card_fingerprint_hex: String,
}

/// One block whose crash residue is a consent-eligible recipient
/// widening, projected across the FFI seam with display-oriented hex
/// fields for an informed-consent prompt.
#[derive(Debug, Clone)]
pub struct FfiWideningReport {
    /// Lowercase hyphenated UUID of the affected block.
    pub block_uuid_hex: String,
    /// The block's plaintext name, for display.
    pub block_name: String,
    /// 64 lowercase hex chars — BLAKE3-256 of the on-disk block file
    /// bytes previewed here. Bind a subsequent
    /// [`super::FfiApprovedWidening::file_fingerprint`] approval to
    /// exactly these bytes (decode this string back to `[u8; 32]`); a
    /// file swapped between preview and repair fails that bind as stale
    /// consent.
    pub file_fingerprint_hex: String,
    /// 64 lowercase hex chars — the committed manifest entry fingerprint
    /// this widening was diffed against. Copy it verbatim into
    /// [`super::FfiApprovedWidening::committed_fingerprint`] (decode back
    /// to `[u8; 32]`) — the #391 third bind: any committed write to the
    /// block between preview and repair fails it as stale consent,
    /// making approvals structurally single-use.
    pub committed_fingerprint_hex: String,
    /// The exact recipients this widening would add, in no particular
    /// order.
    pub added: Vec<FfiAddedRecipient>,
}

/// The read-only result of a `preview_repair_with_*` call: every
/// consent-eligible recipient widening found in the vault's crash
/// residue. Producing this value writes nothing to disk — no manifest
/// rewrite, no re-sign, no clock tick.
#[derive(Debug, Clone)]
pub struct FfiRepairPreview {
    /// One entry per affected block.
    pub widenings: Vec<FfiWideningReport>,
}

/// Project core's `RepairPreview` into the FFI-seam, hex-string shape.
fn project_preview(core_preview: secretary_core::vault::RepairPreview) -> FfiRepairPreview {
    FfiRepairPreview {
        widenings: core_preview
            .widenings
            .into_iter()
            .map(|w| FfiWideningReport {
                block_uuid_hex: format_uuid_hyphenated(&w.block_uuid),
                block_name: w.block_name,
                file_fingerprint_hex: hex::encode(w.file_fingerprint),
                committed_fingerprint_hex: hex::encode(w.committed_fingerprint),
                added: w
                    .added
                    .into_iter()
                    .map(|a| FfiAddedRecipient {
                        uuid_hex: format_uuid_hyphenated(&a.uuid),
                        display_name: a.display_name,
                        card_fingerprint_hex: hex::encode(a.card_fingerprint),
                    })
                    .collect(),
            })
            .collect(),
    }
}

/// Preview a crash-residue vault opened by master password, without
/// writing anything. See [`super::repair_vault_with_password`] for the
/// corresponding write path, and [`FfiRepairPreview`] for the returned
/// shape.
///
/// # Errors
///
/// Returns [`FfiVaultError`]. A vault whose residue `repair_vault` could
/// not adopt at all (e.g. a rollback plant, or a hard-rejected shape)
/// errors identically here — there is nothing to consent to on a vault
/// that cannot be repaired (core `preview_repair` docs).
pub fn preview_repair_with_password(
    folder: &Path,
    password: &[u8],
) -> Result<FfiRepairPreview, FfiVaultError> {
    preview_repair_with_password_in(
        secretary_cli::state::default_state_dir().as_deref(),
        folder,
        password,
    )
}

/// Explicit-`state_dir` seam for [`preview_repair_with_password`]
/// (host-testable — a test injects a temp state dir carrying a seeded
/// §10 baseline, exactly as `repair_vault_with_password_in` does).
pub(crate) fn preview_repair_with_password_in(
    state_dir: Option<&Path>,
    folder: &Path,
    password: &[u8],
) -> Result<FfiRepairPreview, FfiVaultError> {
    let pw = SecretBytes::new(password.to_vec());
    let core_preview = preview_repair(
        folder,
        Unlocker::Password(&pw),
        baseline_provider(state_dir),
    )?;
    Ok(project_preview(core_preview))
    // pw drops here → ZeroizeOnDrop wipes the local copy.
}

/// Preview a crash-residue vault opened by 24-word BIP-39 recovery
/// phrase, without writing anything. See [`preview_repair_with_password`]
/// for the shared semantics.
///
/// # Errors
///
/// Returns [`FfiVaultError`]. See [`preview_repair_with_password`].
pub fn preview_repair_with_recovery(
    folder: &Path,
    mnemonic_bytes: &[u8],
) -> Result<FfiRepairPreview, FfiVaultError> {
    preview_repair_with_recovery_in(
        secretary_cli::state::default_state_dir().as_deref(),
        folder,
        mnemonic_bytes,
    )
}

/// Explicit-`state_dir` seam for [`preview_repair_with_recovery`]. See
/// [`preview_repair_with_password_in`] for the rationale.
pub(crate) fn preview_repair_with_recovery_in(
    state_dir: Option<&Path>,
    folder: &Path,
    mnemonic_bytes: &[u8],
) -> Result<FfiRepairPreview, FfiVaultError> {
    let phrase =
        std::str::from_utf8(mnemonic_bytes).map_err(|_| FfiVaultError::InvalidMnemonic {
            detail: "phrase contained invalid UTF-8".to_string(),
        })?;
    let core_preview = preview_repair(
        folder,
        Unlocker::Recovery(phrase),
        baseline_provider(state_dir),
    )?;
    Ok(project_preview(core_preview))
}

/// Preview a crash-residue vault opened by a per-device wrap secret
/// (ADR 0009), without writing anything. See
/// [`preview_repair_with_password`] for the shared semantics.
///
/// # Errors
///
/// Returns [`FfiVaultError`]. See [`preview_repair_with_password`].
pub fn preview_repair_with_device_secret(
    folder: &Path,
    device_uuid: &[u8; 16],
    device_secret: &[u8; 32],
) -> Result<FfiRepairPreview, FfiVaultError> {
    preview_repair_with_device_secret_in(
        secretary_cli::state::default_state_dir().as_deref(),
        folder,
        device_uuid,
        device_secret,
    )
}

/// Explicit-`state_dir` seam for [`preview_repair_with_device_secret`].
/// See [`preview_repair_with_password_in`] for the rationale.
pub(crate) fn preview_repair_with_device_secret_in(
    state_dir: Option<&Path>,
    folder: &Path,
    device_uuid: &[u8; 16],
    device_secret: &[u8; 32],
) -> Result<FfiRepairPreview, FfiVaultError> {
    let secret = SecretBytes::new(device_secret.to_vec());
    let core_preview = preview_repair(
        folder,
        Unlocker::DeviceSecret {
            device_uuid,
            secret: &secret,
        },
        baseline_provider(state_dir),
    )?;
    Ok(project_preview(core_preview))
    // secret drops here → SecretBytes ZeroizeOnDrop wipes our local copy.
}
