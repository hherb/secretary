//! `trash_block` orchestrator — B.5 lifecycle pair (with `restore_block`).
//!
//! Bridge-side wrapper around [`secretary_core::vault::trash_block`].
//! Mirrors the [`crate::save`] / [`crate::share`] module shape: minimal
//! `orchestration.rs` carrying the free-function entry point + a
//! per-orchestrator core-error mapper.

pub mod list;
pub mod orchestration;

pub use list::{list_trashed_blocks, TrashedBlock};
pub use orchestration::trash_block;
