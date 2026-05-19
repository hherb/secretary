//! `commit_with_decisions` — atomic disk write of a merged + decided
//! vault state.
//!
//! The module ships two entry points, split across files:
//!
//! - [`apply_decisions`] (C.1.1b Task 10, in [`apply`]): pure helper
//!   that enforces the bijection between [`crate::sync::DraftMerge::vetoes`]
//!   and the caller's [`crate::sync::VetoDecision`] slice and returns
//!   the post-decision merged record set.
//! - [`commit_with_decisions`] (C.1.1b Task 11, in [`write`]): the disk-
//!   mutation orchestrator. Re-opens the vault (signature + block-
//!   fingerprint verification), re-checks the on-disk manifest envelope's
//!   BLAKE3 against `draft.manifest_hash` for TOCTOU freshness, applies
//!   the caller's decisions, re-encrypts any affected blocks, builds +
//!   signs a new manifest, and atomically writes block-first then
//!   manifest-last per design doc §D6 / option (d).
//!
//! Sibling-file split per `feedback_split_files_proactively`: the
//! single-file form crossed the 500-line soft cap once Task 11 landed.
//! `apply.rs` is the pure-helper concept; `write.rs` is the disk-
//! mutation concept. Each is one concept under the cap.
//!
//! See `docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md`
//! §"commit_with_decisions".

#![forbid(unsafe_code)]

mod apply;
mod write;

pub use write::commit_with_decisions;

// `apply_decisions` is `pub(crate)`: consumed by `write::commit_with_decisions`
// in the same crate; no cross-crate consumer in the C.1.1b plan.
pub(crate) use apply::apply_decisions;
