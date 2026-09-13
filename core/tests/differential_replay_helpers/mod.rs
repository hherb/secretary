//! Helpers for `differential_replay.rs`, split by role so the entry file —
//! which holds the `#[test]` fns and nothing else — stays below the
//! project's 500-LOC guideline.
//!
//! #634 moved the first two concerns here; #649 moved the other three, along
//! the seams the two open issues against this harness will each edit, so that
//! neither has to rewrite a file the other is also rewriting:
//!
//! - [`targets`] — which targets are replayed, which are token-compared, and
//!   each target's committed input floor. #641 edits this.
//! - [`rust_decoder`] — the Rust decode/re-encode per target, carrying the
//!   rule token on rejection. #641 edits this too.
//! - [`tolerance`] — `tokens_agree`, the §4.2-derived predicate for when two
//!   different tokens still count as agreement. #646 edits this.
//! - [`corpus`] — discovers the fuzz-corpus input files for a target.
//! - [`python_bridge`] — shells out to `conformance.py --diff-replay` and
//!   parses its verdict into [`python_bridge::PyOutcome`].

pub mod corpus;
pub mod python_bridge;
pub mod rust_decoder;
pub mod targets;
pub mod tolerance;
