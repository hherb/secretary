//! Sync orchestration — phase C.1 (detection only).
//!
//! This module reconciles one local vault folder against caller-persisted
//! "highest vector clock seen" state. It implements the §10 rollback
//! resistance algorithm from `docs/crypto-design.md` as a pure-function
//! dispatch over `clock_relation` outcomes:
//!
//! - `NothingToDo` — disk has nothing new since last sync.
//! - `AppliedAutomatically { new_state }` — disk strictly dominates local
//!   state; caller persists `new_state` and proceeds.
//! - `ForkDetected` — disk and local state are concurrent. Per
//!   `docs/threat-model.md` §4 limit 3, detection is sufficient at this
//!   layer; C.1.1 will extend this branch with automatic merge.
//! - `RollbackRejected` — disk is strictly older than local state per §10.
//!
//! Automatic merge of concurrent states, veto-on-tombstone, and conflict-
//! copy file ingestion are scoped to a separate C.1.1 slice with its own
//! design.

pub mod error;
pub mod once;
pub mod outcome;
pub mod state;

pub use error::SyncError;
#[doc(hidden)]
pub use once::__test_dispatch;
pub use once::sync_once;
pub use outcome::{RollbackEvidence, SyncOutcome};
pub use state::SyncState;
