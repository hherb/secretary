//! Helpers extracted from `conformance_kat.rs` for the B.6 v1 read-only
//! cross-language FFI conformance KAT replay. Split to keep the entry
//! file (the two `#[test]` fns) below the project's 500-LOC guideline.
//!
//! See `docs/superpowers/specs/2026-05-15-ffi-b6-conformance-kat-design.md`
//! for the protocol; see `replay_conformance_kat` in the parent file for
//! the entry test.

pub mod dispatch;
pub mod errors;
pub mod fixtures;
pub mod types;
