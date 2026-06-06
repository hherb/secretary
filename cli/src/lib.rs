//! Library surface of `secretary-cli`.
//!
//! Production consumers run the `secretary-sync` binary entry point
//! (`src/main.rs`); this `lib.rs` re-exports the same orchestration
//! modules so end-to-end integration tests in `cli/tests/*.rs` can
//! drive [`pipeline::run_one`] (and the modules it composes) directly,
//! without spawning the binary.
//!
//! Spec: [`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`](../../docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md).

pub mod exit;
pub mod pipeline;
pub mod state;
pub mod veto;

#[cfg(feature = "daemon")]
pub mod args;
#[cfg(feature = "daemon")]
pub mod daemon;
#[cfg(feature = "daemon")]
pub mod logging;
#[cfg(feature = "daemon")]
pub mod signal;
#[cfg(feature = "daemon")]
pub mod unlock;
#[cfg(feature = "daemon")]
pub mod watcher;
