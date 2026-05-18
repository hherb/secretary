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
//! - `ForkDetected` — disk and local state are concurrent. Per
//!   `docs/threat-model.md` §4 limit 3, detection is sufficient at this
//!   layer; C.1.1 will extend this branch with §10's automatic merge.
//! - `RollbackRejected` — disk is strictly older than local state per §10.
//!
//! The four-outcome enum is orchestration-layer (it widens §10's tri-state
//! into a typed result for caller dispatch); the cryptographic primitives
//! it dispatches on are spec-frozen. Automatic merge of concurrent states,
//! veto-on-tombstone, and conflict-copy file ingestion are scoped to a
//! separate C.1.1 slice with its own design.

pub mod bundle;
pub mod error;
pub mod once;
pub mod outcome;
pub mod state;

pub use bundle::{BlockDivergence, BlockEnvelope, ManifestHash, ManifestSnapshot, VaultBundle};
pub use error::SyncError;
#[doc(hidden)]
pub use once::__test_dispatch;
pub use once::sync_once;
pub use outcome::{RollbackEvidence, SyncOutcome};
pub use state::SyncState;
