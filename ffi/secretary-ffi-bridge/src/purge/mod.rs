//! `purge_block` orchestrator — #399 permanent-deletion counterpart to
//! [`crate::trash`] / [`crate::restore`].
//!
//! Mirrors the [`crate::trash`] module shape: minimal `orchestration.rs`
//! carrying the free-function entry point, the bridge-side [`PurgeReport`]
//! projection, and a per-orchestrator core-error mapper.

pub mod orchestration;

pub use orchestration::{purge_block, PurgeReport};
