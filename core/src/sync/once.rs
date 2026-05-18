//! `sync_once` — pure-function reconcile of one vault folder against
//! caller-persisted `SyncState`. C.1.1a extends the C.1 phase 1
//! dispatch to call into [`crate::sync::ingest`] on the Concurrent
//! arm so the returned `SyncOutcome::ConcurrentDetected` carries an
//! authenticated `VaultBundle` for C.1.1b's merge layer.

use std::path::{Path, PathBuf};

use crate::crypto::sig::MlDsa65Public;
use crate::identity::card::ContactCard;
use crate::identity::fingerprint::fingerprint;
use crate::sync::bundle::{compute_manifest_hash, ManifestHash, VaultBundle};
use crate::sync::error::SyncError;
use crate::sync::ingest::{compute_diff_plan, ingest_conflict_copies};
use crate::sync::outcome::{DiffPlan, RollbackEvidence, SyncOutcome};
use crate::sync::state::SyncState;
use crate::unlock::UnlockedIdentity;
use crate::vault::block::VectorClockEntry;
use crate::vault::conflict::{clock_relation, ClockRelation};
use crate::vault::orchestrators::read_vault_manifest_full;

/// Filename of the canonical manifest on disk. Mirrors
/// [`crate::sync::ingest`]'s constant; kept local because the two
/// modules reach this from different angles and a cross-module
/// re-export would create a needless coupling.
const CANONICAL_MANIFEST_FILENAME: &str = "manifest.cbor.enc";

/// Reconcile one local vault folder against caller-persisted state.
///
/// See `docs/superpowers/specs/2026-05-17-c1-sync-detection-design.md`
/// (phase 1) and
/// `docs/superpowers/specs/2026-05-18-c1-1a-conflict-copy-ingestion-design.md`
/// (this slice's Concurrent-arm extension).
///
/// Steps:
///   1. Calls [`crate::vault::orchestrators::read_vault_manifest_full`]
///      with the caller-held `&UnlockedIdentity` to read + verify-and-
///      decrypt the manifest body without re-running Argon2, AND
///      surface the verified owner contact card + on-disk envelope.
///   2. Cross-checks the authenticated `manifest.vault_uuid` against
///      `state.vault_uuid`. Mismatch → [`SyncError::VaultUuidMismatch`].
///   3. Re-reads the canonical envelope bytes for the BLAKE3
///      [`ManifestHash`] (TOCTOU freshness anchor for C.1.1b's
///      commit path). Cheap re-read of a small file; the alternative
///      (extending the loader to also return bytes) would couple the
///      hash computation to a now-stable byte-format function.
///   4. Computes the [`ClockRelation`] between
///      `state.highest_vector_clock_seen` and the disk manifest's
///      `vector_clock`, then dispatches to the matching
///      [`SyncOutcome`] variant.
///   5. On `Concurrent`, calls
///      [`crate::sync::ingest::ingest_conflict_copies`] with the
///      pre-derived owner public keys + IBK to assemble the
///      [`VaultBundle`], then computes a [`DiffPlan`] from its
///      diverging blocks.
///
/// `_now_ms` is **currently unused** in C.1 phase 1 + 1a — pass any
/// `u64` (callers conventionally pass `0`). Reserved for C.1.1b's
/// merge timestamps so callers can wire the value through without an
/// API break later.
pub fn sync_once(
    vault_folder: &Path,
    identity: &UnlockedIdentity,
    state: &SyncState,
    _now_ms: u64,
) -> Result<SyncOutcome, SyncError> {
    // Step 1: read + verify + AEAD-decrypt the manifest body via the
    // caller-held UnlockedIdentity. `local_highest_clock = None` so
    // read_vault_manifest_full skips its own §10 check; sync_once does
    // its own ClockRelation dispatch below and surfaces the typed
    // SyncOutcome::RollbackRejected variant instead of
    // VaultError::Rollback.
    let (owner_card, manifest, _manifest_file) =
        read_vault_manifest_full(vault_folder, identity, None)?;

    // Step 2: state ↔ authenticated manifest body vault_uuid check.
    if manifest.vault_uuid != state.vault_uuid {
        return Err(SyncError::VaultUuidMismatch {
            state_vault_uuid: state.vault_uuid,
            folder_vault_uuid: manifest.vault_uuid,
        });
    }

    // Step 3: extract disk vector clock + dispatch.
    let disk_clock: Vec<VectorClockEntry> = manifest.vector_clock.clone();
    let relation = clock_relation(&state.highest_vector_clock_seen, &disk_clock);

    match relation {
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
        ClockRelation::Concurrent => assemble_concurrent_outcome(
            vault_folder,
            identity,
            &owner_card,
            &manifest,
            disk_clock,
            state.highest_vector_clock_seen.clone(),
        ),
    }
}

/// Build the `ConcurrentDetected` outcome by reading the canonical
/// envelope bytes, computing the freshness anchor, deriving owner
/// public keys, and invoking
/// [`crate::sync::ingest::ingest_conflict_copies`].
///
/// Factored out for readability — the work isn't independently
/// testable without the same orchestrator-level fixture that
/// integration tests use, so the function stays private to this
/// module.
fn assemble_concurrent_outcome(
    vault_folder: &Path,
    identity: &UnlockedIdentity,
    owner_card: &ContactCard,
    manifest: &crate::vault::Manifest,
    disk_clock: Vec<VectorClockEntry>,
    local_highest_seen: Vec<VectorClockEntry>,
) -> Result<SyncOutcome, SyncError> {
    let canonical_path: PathBuf = vault_folder.join(CANONICAL_MANIFEST_FILENAME);
    let canonical_envelope_bytes = std::fs::read(&canonical_path)
        .map_err(|e| SyncError::ConflictCopyScanIoFailed { source: e })?;
    let manifest_hash: ManifestHash = compute_manifest_hash(&canonical_envelope_bytes);

    let owner_card_bytes = owner_card
        .to_canonical_cbor()
        .map_err(crate::vault::VaultError::from)?;
    let owner_fp = fingerprint(&owner_card_bytes);
    let owner_pq_pk = MlDsa65Public::from_bytes(&owner_card.ml_dsa_65_pk)
        .map_err(|e| SyncError::Vault(crate::vault::VaultError::from(e)))?;

    let bundle: VaultBundle = ingest_conflict_copies(
        vault_folder,
        manifest,
        &canonical_envelope_bytes,
        canonical_path,
        owner_fp,
        &owner_card.ed25519_pk,
        &owner_pq_pk,
        &identity.identity_block_key,
    )
    .map_err(|e| SyncError::ConflictCopyScanIoFailed { source: e })?;

    let plan = DiffPlan {
        diverging_blocks: compute_diff_plan(&bundle),
    };

    Ok(SyncOutcome::ConcurrentDetected {
        bundle,
        plan,
        manifest_hash,
        disk_vector_clock: disk_clock,
        local_highest_seen,
    })
}

/// Pure clock-only dispatch helper. Mirrors the C.1 phase 1
/// `dispatch` shape but cannot construct `ConcurrentDetected`
/// (which carries a folder-derived `VaultBundle`). The Concurrent
/// branch surfaces `None` so callers / tests can distinguish
/// "clocks are concurrent" from the three I/O-free outcomes without
/// needing real vault fixtures.
///
/// Used by [`__test_dispatch`]; do not call from production code
/// (`sync_once` inlines its own dispatch + ingest composition).
fn dispatch(
    disk_clock: Vec<VectorClockEntry>,
    state: &SyncState,
) -> Result<Option<SyncOutcome>, SyncError> {
    Ok(
        match clock_relation(&state.highest_vector_clock_seen, &disk_clock) {
            ClockRelation::Equal => Some(SyncOutcome::NothingToDo),
            ClockRelation::IncomingDominates => Some(SyncOutcome::AppliedAutomatically {
                new_state: SyncState {
                    vault_uuid: state.vault_uuid,
                    highest_vector_clock_seen: disk_clock,
                },
            }),
            ClockRelation::IncomingDominated => {
                Some(SyncOutcome::RollbackRejected(RollbackEvidence {
                    disk_vector_clock: disk_clock,
                    local_highest_seen: state.highest_vector_clock_seen.clone(),
                }))
            }
            // None signals "Concurrent — the integration layer must
            // produce the bundle-carrying outcome via
            // assemble_concurrent_outcome".
            ClockRelation::Concurrent => None,
        },
    )
}

/// Test hook: exercise clock-only `dispatch` without going through the
/// disk-IO path. Returns `Ok(None)` on Concurrent (callers in tests
/// then know to expect ConcurrentDetected via the integration path),
/// or `Ok(Some(outcome))` for the three I/O-free outcomes.
///
/// Per the `project_secretary_cfg_test_not_propagated` memory,
/// `#[cfg(test)]` items on the lib crate are invisible to integration
/// tests in `tests/*.rs`. `#[doc(hidden)] pub` makes the helper
/// reachable from both unit tests and integration tests while keeping
/// it out of the rendered API docs.
#[doc(hidden)]
pub fn __test_dispatch(
    disk_clock: Vec<VectorClockEntry>,
    state: &SyncState,
) -> Result<Option<SyncOutcome>, SyncError> {
    dispatch(disk_clock, state)
}
