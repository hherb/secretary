//! Typed errors surfaced by `sync_once` and `SyncState` codec.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("placeholder")]
    Placeholder,
}
