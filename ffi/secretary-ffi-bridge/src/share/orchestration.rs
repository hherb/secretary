//! `share_block` orchestration: decode caller-supplied ContactCard bytes,
//! snapshot the bridge handles, build a temporary `core::vault::OpenVault`,
//! call `core::vault::share_block`, write back the mutated manifest +
//! manifest_file on Ok, map errors per the spec §6 table.
//!
//! Failure invariant: bridge in-memory state is byte-identical to pre-call
//! on Err. On-disk state may have a partial write (block file rewritten
//! but manifest re-sign failed) — harmless because `open_vault` reads
//! only entries listed in the manifest.
//!
//! Stub implementation: returns `CardDecodeFailure { detail: "share_block
//! not yet implemented" }` unconditionally. Real implementation lands in
//! the next commit (see plan Task 4).

use crate::error::FfiVaultError;
use crate::identity::UnlockedIdentity;
use crate::vault::OpenVaultManifest;

/// Append one new recipient to an existing block. v1 single-author: only
/// the vault's owner can share blocks they authored.
///
/// See spec §4 for the full argument contract; §6 for error mapping; §9
/// for the behavioral invariants this function pins.
#[allow(clippy::too_many_arguments)]
pub fn share_block(
    _identity: &UnlockedIdentity,
    _manifest: &OpenVaultManifest,
    _block_uuid: [u8; 16],
    _existing_recipient_cards: &[Vec<u8>],
    _new_recipient: &[u8],
    _device_uuid: [u8; 16],
    _now_ms: u64,
) -> Result<(), FfiVaultError> {
    Err(FfiVaultError::CardDecodeFailure {
        detail: "share_block stub — not yet implemented (Task 4)".into(),
    })
}
