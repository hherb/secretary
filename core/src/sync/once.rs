//! `sync_once` — pure-function reconcile of one vault folder against
//! caller-persisted `SyncState`.

use std::path::Path;

use crate::sync::error::SyncError;
use crate::sync::outcome::{RollbackEvidence, SyncOutcome};
use crate::sync::state::SyncState;
use crate::unlock::UnlockedIdentity;
use crate::vault::block::VectorClockEntry;
use crate::vault::conflict::{clock_relation, ClockRelation};
use crate::vault::read_vault_manifest;

/// Reconcile one local vault folder against caller-persisted state.
///
/// See `docs/superpowers/specs/2026-05-17-c1-sync-detection-design.md`.
///
/// 1. Calls [`crate::vault::read_vault_manifest`] with the caller-held
///    `&UnlockedIdentity` to read + verify-and-decrypt the manifest
///    body without re-running Argon2. The body's `vault_uuid` is bound
///    to the §4 manifest header (AEAD-AAD + §8 hybrid signature) and the
///    body↔`vault.toml` `[kdf]` cross-check inside `read_vault_manifest`
///    transitively authenticates `vault.toml`'s `vault_uuid` against the
///    same signed envelope, so a single authenticated reading is enough.
/// 2. Cross-checks the authenticated `manifest.vault_uuid` against
///    `state.vault_uuid`. Mismatch → [`SyncError::VaultUuidMismatch`].
/// 3. Computes the [`ClockRelation`] between `state.highest_vector_clock_seen`
///    and the disk manifest's `vector_clock`, then dispatches to the
///    matching [`SyncOutcome`] variant.
///
/// `_now_ms` is **currently unused** in C.1 phase 1 — pass any `u64`
/// (callers conventionally pass `0`). The parameter is reserved for
/// C.1.1's merge timestamps so callers can wire the value through
/// without an API break later.
pub fn sync_once(
    vault_folder: &Path,
    identity: &UnlockedIdentity,
    state: &SyncState,
    _now_ms: u64,
) -> Result<SyncOutcome, SyncError> {
    // Step 1: read + verify + AEAD-decrypt the manifest body via the
    // caller-held UnlockedIdentity. `local_highest_clock = None` so
    // read_vault_manifest skips its own §10 check; sync_once does its
    // own ClockRelation dispatch below and surfaces the typed
    // SyncOutcome::RollbackRejected variant instead of VaultError::Rollback.
    let manifest = read_vault_manifest(vault_folder, identity, None)?;

    // Step 2: state ↔ authenticated manifest body vault_uuid check.
    // The body's vault_uuid is bound by the §8 hybrid signature; an
    // attacker swapping vault.toml or the manifest envelope alone cannot
    // forge a body whose vault_uuid matches state.vault_uuid without
    // breaking the signature.
    if manifest.vault_uuid != state.vault_uuid {
        return Err(SyncError::VaultUuidMismatch {
            state_vault_uuid: state.vault_uuid,
            folder_vault_uuid: manifest.vault_uuid,
        });
    }

    // Step 3: extract disk vector clock and dispatch.
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
