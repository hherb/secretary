//! Sync orchestration — phase C.1 (detection only).
//!
//! This module reconciles one local vault folder against caller-persisted
//! "highest vector clock seen" state.
//!
//! The spec-frozen primitive is `docs/crypto-design.md` §10, which
//! enumerates three behaviours on loading a manifest: accept-and-update
//! (new clock ≥ highest seen), reject-as-rollback (new clock strictly
//! dominated), and trigger merge (concurrent). The C.1 surface here is a
//! typed reification of those three behaviours, plus a fourth no-op case
//! (`NothingToDo`) that's the trivial sub-case of accept-on-≥ where
//! nothing actually changes. The §10 reject path is implemented as the
//! pure-function `vault::manifest::is_rollback` predicate (and is also
//! enforced inside `read_vault_manifest`); this module wires that
//! predicate plus `vault::conflict::clock_relation` into a single
//! dispatch over four outcomes:
//!
//! - `NothingToDo` — disk has nothing new since last sync (Equal clocks).
//! - `AppliedAutomatically { new_state }` — disk strictly dominates local
//!   state; caller persists `new_state` and proceeds.
//! - `ConcurrentDetected` — disk and local state are concurrent.
//!   C.1.1a's conflict-copy ingestion runs here: sibling manifest +
//!   block envelopes are authenticated against the canonical owner
//!   identity (§1a-D4) and packaged into a `VaultBundle` for
//!   C.1.1b's merge layer to consume.
//! - `RollbackRejected` — disk is strictly older than local state per §10.
//!
//! The four-outcome enum is orchestration-layer (it widens §10's tri-state
//! into a typed result for caller dispatch); the cryptographic primitives
//! it dispatches on are spec-frozen. Automatic merge of concurrent states
//! and veto-on-tombstone are scoped to C.1.1b.

pub mod bundle;
pub mod commit;
pub mod draft;
pub mod error;
pub mod ingest;
pub mod once;
pub mod outcome;
pub mod prepare;
pub mod state;

pub use bundle::{
    compute_manifest_hash, BlockDivergence, BlockEnvelope, ManifestHash, ManifestSnapshot,
    VaultBundle,
};
pub use commit::commit_with_decisions;
pub use draft::{BlockId, DraftMerge, RecordId, RecordTombstoneVeto, VetoDecision};
pub use error::SyncError;
#[doc(hidden)]
pub use once::__test_dispatch;
pub use once::sync_once;
pub use outcome::{DiffPlan, RollbackEvidence, SyncOutcome};
pub use prepare::prepare_merge;
pub use state::SyncState;
