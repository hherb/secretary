//! `save_block` input types and orchestrator. Mirrors `record/`'s structure:
//! [`input`] holds the foreign-facing input shapes; `orchestration` will
//! hold the free-function entry point (added in Task 2).
//!
//! Rationale: docs/superpowers/specs/2026-05-09-ffi-b4c-save-block-design.md

pub mod input;

pub use input::{BlockInput, FieldInput, FieldInputValue, RecordInput};
