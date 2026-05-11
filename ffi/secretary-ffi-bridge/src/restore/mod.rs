//! `restore_block` orchestrator — B.5 lifecycle pair (with `trash_block`).
//!
//! Bridge-side wrapper around [`secretary_core::vault::restore_block`].
//! Mirrors the [`crate::save`] / [`crate::share`] / [`crate::trash`]
//! module shape.

pub mod orchestration;

pub use orchestration::restore_block;
