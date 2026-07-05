//! #350 crash-recovery: the open-time trash-completion sweep (this
//! task) and the explicit [`repair_vault`] orchestrator (added on top).
//!
//! Split out of `orchestrators.rs` (already ~2.8k lines) — one concept
//! per file: everything here exists to converge a crash-interrupted
//! vault back to the §6.5/§7 on-disk shape without weakening the
//! manifest-as-integrity-commitment.

mod classify;
mod orchestration;
mod policy;
mod sweep;

pub use classify::{AddedRecipient, RepairPreview, WideningReport};
pub use orchestration::{preview_repair, repair_vault};
pub use policy::{ApprovedWidening, RepairPolicy};
pub(crate) use sweep::complete_pending_trash_renames;
