//! Bridge-thick sync surface (D.1.13). Read-only `sync_status` here; the
//! `sync_vault` mutation lands in `orchestration` (D.1.13 Task 5). Functions
//! are bridge-only — the desktop consumes them as a Rust crate; uniffi/pyo3
//! projection is deferred (#167-sibling).

pub mod orchestration;
pub mod status;

pub use orchestration::{sync_vault, SyncOutcomeDto};
pub use status::{sync_status, DeviceClockDto, SyncStatusDto};
