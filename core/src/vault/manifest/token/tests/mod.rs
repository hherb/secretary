//! Tests for the [`RuleToken`] vocabulary, split by role (the repo's
//! 500-line guideline; this was one 588-line file).
//!
//! - [`vocabulary`] — the token set itself: distinct spellings, `ALL`'s
//!   completeness, the phase-dependent set, and the committed JSON fixture
//!   both languages read.
//! - [`mapping`] — which token each `ManifestError` variant carries, including
//!   the full 35-variant census.

mod mapping;
mod vocabulary;
