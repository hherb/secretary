//! Crate-wide error type.
//!
//! Variants will be added as the build sequence progresses; keeping a single
//! `Error` enum lets callers match exhaustively across the whole crate.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// Placeholder until concrete variants are introduced by later build-sequence steps.
    #[error("secretary-core: unimplemented ({0})")]
    Unimplemented(&'static str),
}
