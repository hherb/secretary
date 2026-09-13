//! Helpers for `differential_replay.rs`, split by role so the entry file —
//! which holds the `#[test]` fns and nothing else — stays below the
//! project's 500-LOC guideline.
//!
//! #649 split the entry file along the seams the two open issues against this
//! harness will each edit, so that neither has to rewrite a file the other is
//! also rewriting:
//!
//! - [`targets`] — which targets are replayed, which are token-compared, and
//!   each target's committed input floor. #641 edits this.
//! - [`rust_decoder`] — the Rust decode/re-encode per target, carrying the
//!   rule token on rejection. #641 edits this too.
//! - [`tolerance`] — `tokens_agree`, the §4.2-derived predicate for when two
//!   different tokens still count as agreement. #646 edits this.
//! - [`agreement`] — `judge`, whether one input's two verdicts agree. Pure,
//!   lifted out of the corpus loop by #655. #641 and #646 change what it
//!   compares, so the rules live here rather than in the test body.
//!
//! #655 replaced the per-input Python spawn with one long-lived worker:
//!
//! - [`corpus`] — lists a target's input files, tagged committed or not.
//! - [`python_bridge`] — the `--diff-replay-serve` command and the pure
//!   reading of one verdict into [`python_bridge::PyOutcome`].
//! - [`python_worker`] — the worker process: a bounded wait per input, its
//!   process group killed on timeout, respawned after a transport failure.
//! - [`progress`] — start/progress/finish lines that libtest cannot swallow.

pub mod agreement;
pub mod corpus;
pub mod progress;
pub mod python_bridge;
pub mod python_worker;
pub mod rust_decoder;
pub mod targets;
pub mod tolerance;
