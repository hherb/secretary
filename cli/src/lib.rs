//! Library surface of `secretary-cli`.
//!
//! Production consumers run the `secretary-sync` binary entry point
//! (`src/main.rs`); this `lib.rs` re-exports the same orchestration
//! modules so end-to-end integration tests in `cli/tests/*.rs` can
//! drive [`pipeline::run_one`] (and the modules it composes) directly,
//! without spawning the binary.
//!
//! Spec: [`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`](../../docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md).

pub mod args;
pub mod daemon;
pub mod exit;
pub mod logging;
pub mod pipeline;
pub mod signal;
pub mod state;
pub mod unlock;
pub mod veto;
pub mod watcher;
