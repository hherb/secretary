//! Helpers extracted from `manifest_canonicality_kat.rs` (#612) so the
//! entry file -- which holds the `#[test]` fns -- stays below the
//! project's 500-LOC guideline.
//!
//! The split is by role, not by size: [`cases`] is the corpus TABLE (what
//! the spec requires), [`build`] turns a table row into manifest bytes,
//! [`assert`] compares a decoder verdict against the row's declared
//! cause, and [`generate`] is the by-hand regeneration test. See the
//! entry file's module doc for what the corpus means.

use std::path::PathBuf;

pub mod assert;
pub mod build;
pub mod cases;
pub mod generate;

/// Path to the committed fixture, resolved from `CARGO_MANIFEST_DIR` so
/// it does not depend on the process working directory.
pub fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/manifest_canonicality_kat.json")
}
