//! Bridge-thick sync surface (D.1.13). Read-only `sync_status` here; the
//! `sync_vault` mutation lives in `orchestration`. Functions are bridge-only —
//! the desktop consumes them as a Rust crate; projecting them onto uniffi/pyo3
//! is deferred to issue #187 (mirrors #167 for the contacts/revoke functions).

pub mod orchestration;
pub mod status;

pub use orchestration::{sync_vault, SyncOutcomeDto};
pub use status::{sync_status, DeviceClockDto, SyncStatusDto};
