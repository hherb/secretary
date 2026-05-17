//! `sync_once` — pure-function reconcile of one vault folder against
//! caller-persisted `SyncState`.

use std::path::Path;

use crate::sync::error::SyncError;
use crate::sync::outcome::{RollbackEvidence, SyncOutcome};
use crate::sync::state::SyncState;
use crate::unlock::{vault_toml, UnlockedIdentity};
use crate::vault::block::VectorClockEntry;
use crate::vault::conflict::{clock_relation, ClockRelation};
use crate::vault::read_vault_manifest;

const VAULT_TOML_FILENAME: &str = "vault.toml";

/// Reconcile one local vault folder against caller-persisted state.
///
/// See `docs/superpowers/specs/2026-05-17-c1-sync-detection-design.md`.
///
/// 1. Reads `<folder>/vault.toml` and cross-checks its `vault_uuid`
///    against `state.vault_uuid`. Mismatch → [`SyncError::VaultUuidMismatch`]
///    before any unlock work.
/// 2. Calls [`crate::vault::read_vault_manifest`] with the caller-held
///    `&UnlockedIdentity` to read + verify-and-decrypt the manifest
///    body without re-running Argon2.
/// 3. Computes the [`ClockRelation`] between `state.highest_vector_clock_seen`
///    and the disk manifest's `vector_clock`, then dispatches to the
///    matching [`SyncOutcome`] variant.
///
/// `_now_ms` is unused in C.1 phase 1; the parameter is reserved for
/// C.1.1's merge timestamps so callers can wire the value through
/// without an API break later.
pub fn sync_once(
    vault_folder: &Path,
    identity: &UnlockedIdentity,
    state: &SyncState,
    _now_ms: u64,
) -> Result<SyncOutcome, SyncError> {
    // Step 1: vault.toml UUID cross-check.
    let vault_toml_path = vault_folder.join(VAULT_TOML_FILENAME);
    let vault_toml_string = std::fs::read_to_string(&vault_toml_path).map_err(|e| {
        SyncError::Io {
            context: "failed to read vault.toml",
            source: e,
        }
    })?;
    // Fold path: VaultTomlError → UnlockError::MalformedVaultToml → VaultError::Unlock
    // → SyncError::Vault. The chain preserves the typed error at the umbrella surface
    // (anti-conflation discipline — see core/src/unlock/mod.rs:UnlockError).
    let vt = vault_toml::decode(&vault_toml_string).map_err(|e| {
        SyncError::Vault(crate::vault::VaultError::Unlock(
            crate::unlock::UnlockError::MalformedVaultToml(e),
        ))
    })?;
    if vt.vault_uuid != state.vault_uuid {
        return Err(SyncError::VaultUuidMismatch {
            state_vault_uuid: state.vault_uuid,
            folder_vault_uuid: vt.vault_uuid,
        });
    }

    // Step 2: read manifest body using the caller-held UnlockedIdentity.
    // Skip the §10 rollback check at this layer — sync_once does its own
    // ClockRelation dispatch below.
    let manifest = read_vault_manifest(vault_folder, identity, None)?;

    // Step 3-4: extract disk vector clock and dispatch.
    let disk_clock: Vec<VectorClockEntry> = manifest.vector_clock.clone();
    dispatch(disk_clock, state)
}

fn dispatch(
    disk_clock: Vec<VectorClockEntry>,
    state: &SyncState,
) -> Result<SyncOutcome, SyncError> {
    match clock_relation(&state.highest_vector_clock_seen, &disk_clock) {
        ClockRelation::Equal => Ok(SyncOutcome::NothingToDo),
        ClockRelation::IncomingDominates => Ok(SyncOutcome::AppliedAutomatically {
            new_state: SyncState {
                vault_uuid: state.vault_uuid,
                highest_vector_clock_seen: disk_clock,
            },
        }),
        ClockRelation::IncomingDominated => Ok(SyncOutcome::RollbackRejected(RollbackEvidence {
            disk_vector_clock: disk_clock,
            local_highest_seen: state.highest_vector_clock_seen.clone(),
        })),
        ClockRelation::Concurrent => Ok(SyncOutcome::ForkDetected {
            disk_vector_clock: disk_clock,
            local_highest_seen: state.highest_vector_clock_seen.clone(),
        }),
    }
}

/// Test hook: exercise `dispatch` without going through the disk-IO
/// path. Per the `project_secretary_cfg_test_not_propagated` memory,
/// `#[cfg(test)]` items on the lib crate are invisible to integration
/// tests in `tests/*.rs`. `#[doc(hidden)] pub` makes the helper
/// reachable from both unit tests and integration tests while keeping
/// it out of the rendered API docs.
#[doc(hidden)]
pub fn __test_dispatch(
    disk_clock: Vec<VectorClockEntry>,
    state: &SyncState,
) -> Result<SyncOutcome, SyncError> {
    dispatch(disk_clock, state)
}
