//! Vault on-disk format: blocks, manifest, recipients, conflict resolution.
//!
//! The on-disk format is normatively specified in `docs/vault-format.md`.
//! This module currently exposes the §6.3 record types ([`record`]) and
//! the §6.1 / §6.3 block layer ([`block`] — binary header bytes through
//! end of `vector_clock_entries`, plus the canonical-CBOR plaintext
//! body). The recipient table (§6.2), AEAD body, signatures, and the
//! manifest (§4) layers land in subsequent build-sequence steps and will
//! plug into the [`VaultError`] umbrella below via additional `#[from]`
//! variants.

pub mod block;
pub mod record;

pub use block::{
    Block, BlockError, BlockHeader, BlockPlaintext, VectorClockEntry, FILE_KIND_BLOCK,
};
pub use record::{Record, RecordError, RecordField, RecordFieldValue, UnknownValue};

/// Umbrella error type for the vault format layer.
///
/// Currently aggregates [`RecordError`] and [`BlockError`]. Future
/// build-sequence steps add `Recipients` and `Manifest` variants — each
/// with `#[from]` so per-layer code paths can use `?` to propagate
/// without hand-mapping. Single-layer surface today, expandable surface
/// tomorrow, with no breaking change at the call sites that already
/// match on this enum.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    /// Record-level CBOR encode / decode failure (§6.3).
    #[error("record CBOR error: {0}")]
    Record(#[from] RecordError),

    /// Block-level encode / decode failure: binary header (§6.1) or
    /// canonical-CBOR plaintext (§6.3).
    #[error("block error: {0}")]
    Block(#[from] BlockError),
}
