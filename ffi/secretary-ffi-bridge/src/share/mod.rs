//! `share_block` orchestrator. Mirrors `save/`'s structure: this module
//! holds the free-function entry point that appends one new recipient to
//! an existing block. v1 single-author: only the vault owner can share
//! blocks they authored.
//!
//! Rationale: docs/superpowers/specs/2026-05-10-ffi-b4d-share-block-design.md

pub mod orchestration;

pub use orchestration::share_block;
