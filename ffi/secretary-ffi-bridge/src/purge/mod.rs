//! `purge_block` / `empty_trash` orchestrators — #399 permanent-deletion
//! counterpart to [`crate::trash`] / [`crate::restore`].
//!
//! Mirrors the [`crate::trash`] module shape: minimal `orchestration.rs`
//! carrying the free-function entry points, the bridge-side
//! [`PurgeReport`] / [`EmptyTrashReport`] projections, and a
//! per-orchestrator core-error mapper each.

pub mod orchestration;

pub use orchestration::{empty_trash, purge_block, EmptyTrashReport, PurgeReport};
