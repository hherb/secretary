//! `save_block` input types and orchestrator. Mirrors `record/`'s structure:
//! [`input`] holds the foreign-facing input shapes; [`orchestration`] holds
//! the free-function entry point.
//!
//! Rationale: docs/superpowers/specs/2026-05-09-ffi-b4c-save-block-design.md

pub mod input;
pub mod orchestration;

pub use input::{BlockInput, FieldInput, FieldInputValue, RecordInput};
pub use orchestration::save_block;
