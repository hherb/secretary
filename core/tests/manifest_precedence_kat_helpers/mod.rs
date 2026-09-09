//! Helpers for the rejection-PRECEDENCE corpus (#618), split by role so
//! the entry file -- which holds the `#[test]` fns -- stays under the
//! project's 500-LOC guideline from the start.
//!
//! [`cases`] is the corpus TABLE (what `docs/vault-format.md` §4.2's
//! precedence paragraph requires), [`build`] turns a row into manifest
//! bytes by surgery on an all-valid baseline, [`assert`] compares a
//! decoder verdict against the row's declared [`Expect`], and
//! [`generate`] is the by-hand regeneration test.
//!
//! See the entry file's module doc for what the corpus means and why the
//! baseline is this corpus's own rather than shared with its two
//! siblings.
//!
//! [`Expect`]: cases::Expect

use std::path::PathBuf;

pub mod assert;
pub mod build;
pub mod cases;
pub mod generate;

/// Path to the committed fixture, resolved from `CARGO_MANIFEST_DIR` so
/// it does not depend on the process working directory.
pub fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/manifest_precedence_kat.json")
}
