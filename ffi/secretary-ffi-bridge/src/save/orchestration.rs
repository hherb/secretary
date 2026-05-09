//! `save_block` — free-function entry point that locks both handles,
//! builds a temporary `core::vault::OpenVault` from clones, calls
//! `core::vault::save_block`, and on Ok writes back the mutated manifest +
//! manifest_file into the bridge handle.
//!
//! Failure invariant: bridge in-memory state is byte-identical to pre-call
//! on Err. On-disk state may have a partial write (block file present,
//! manifest re-sign failed) — harmless because `open_vault` reads only
//! entries listed in the manifest.
//!
//! v1 single-author: recipients = `[owner_card]`. Multi-recipient is B.4d.
//!
//! Rationale: docs/superpowers/specs/2026-05-09-ffi-b4c-save-block-design.md §5.

use crate::error::FfiVaultError;
use crate::identity::UnlockedIdentity;
use crate::save::input::BlockInput;
use crate::vault::OpenVaultManifest;

/// Encrypt and atomically persist one block of records.
///
/// See module-level docs for the failure invariant. v1 single-author:
/// recipients are owner-only; multi-recipient is B.4d.
///
/// # Stub state
///
/// This function is a stub returning [`FfiVaultError::SaveCryptoFailure`]
/// unconditionally. The real data flow lands in the next commit; this
/// stub pins the public surface (signature + module structure) so the
/// integration tests in `tests/save_block.rs` and the PyO3/uniffi
/// wrappers can compile against it incrementally.
pub fn save_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    input: BlockInput,
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<(), FfiVaultError> {
    let _ = (identity, manifest, input, device_uuid, now_ms);
    Err(FfiVaultError::SaveCryptoFailure {
        detail: "save_block not yet implemented".into(),
    })
}
