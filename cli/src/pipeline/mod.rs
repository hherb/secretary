//! One sync attempt — composes
//! `sync_once → prepare_merge → veto UX → commit_with_decisions` and
//! updates the caller-held [`secretary_core::sync::SyncState`] in place.
//!
//! Spec: [`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`](../../docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md)
//! §"Module layout" + §"Daemon loop sketch".
//!
//! The [`run_one`] entry point is the single seam consumed by both
//! `once` (one attempt then exit) and `run` (daemon loop) subcommands.
//! It is intentionally pure-orchestration: every disk read/write and
//! every cryptographic step happens inside the `core::sync` primitives
//! it dispatches to. The local side effects are limited to:
//!
//! - Mutating `state` in place when the disk-side clock moves forward
//!   (`AppliedAutomatically`, `SilentMerge`, `MergedAndCommitted`).
//! - Driving the caller-supplied [`crate::veto::VetoUx`] on the
//!   `ConcurrentDetected` arm.
//!
//! `RollbackRejected` deliberately does NOT advance state — `state`
//! survives byte-for-byte so the caller can persist the same value
//! after dispatching the [`RunOutcome::RollbackRejected`] exit code.
//!
//! ## Module layout
//!
//! - `outcomes` — the three outcome enums ([`RunOutcome`],
//!   [`SyncPassOutcome`], [`InspectOutcome`]) plus their pure
//!   variant-level tests.
//! - `passes` — the four sync passes ([`run_one`],
//!   [`sync_pass_pause_on_conflict`], [`sync_pass_inspect`],
//!   [`sync_pass_commit_decisions`]) plus the shared clock-folding
//!   helpers and their LUB-contract tests.

mod outcomes;
mod passes;

pub use outcomes::{InspectOutcome, RunOutcome, SyncPassOutcome};
pub use passes::{
    run_one, sync_pass_commit_decisions, sync_pass_inspect, sync_pass_pause_on_conflict,
};
