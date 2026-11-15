//! Bridge-thick sync surface (D.1.13). Read-only `sync_status` in `status`;
//! the password `sync_vault` mutation in `orchestration`; the session sync and
//! `refresh_manifest` (#101) in `session`; the pass body both share in `pass`.
//! Projected onto uniffi/pyo3 since #187.

pub mod dto;
pub mod orchestration;
pub(crate) mod pass;
pub mod session;
pub mod status;

pub use dto::{CollisionDto, SyncOutcomeDto, VetoDecisionDto, VetoDto};
pub use orchestration::{
    sync_commit_decisions, sync_commit_decisions_in, sync_vault, sync_vault_in,
};
pub use session::{
    refresh_manifest, refresh_manifest_in, sync_commit_decisions_with_session,
    sync_commit_decisions_with_session_in, sync_vault_with_session, sync_vault_with_session_in,
};
pub use status::{sync_status, sync_status_in, DeviceClockDto, SyncStatusDto};
