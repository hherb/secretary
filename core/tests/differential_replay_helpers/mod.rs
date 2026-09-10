//! Helpers extracted from `differential_replay.rs` (#634) so the entry
//! file -- which holds the target classification tables, the
//! `tokens_agree` tolerance predicate, `rust_decode`, and the `#[test]`
//! fns -- stays below the project's 500-LOC guideline.
//!
//! Split by role: [`corpus`] discovers the fuzz-corpus input files for a
//! target; [`python_bridge`] shells out to `conformance.py --diff-replay`
//! and parses its verdict into [`python_bridge::PyOutcome`].

pub mod corpus;
pub mod python_bridge;
