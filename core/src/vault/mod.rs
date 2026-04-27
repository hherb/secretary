//! Vault on-disk format: blocks, manifest, recipients, conflict resolution.
//!
//! The on-disk format is normatively specified in `docs/vault-format.md`.
//! This module currently exposes the §6.3 record types ([`record`]); the
//! block file (§6.1, §6.2), manifest (§4), and recipients (§7) layers
//! land in subsequent build-sequence steps and will plug into the
//! [`VaultError`] umbrella below via additional `#[from]` variants.

pub mod record;

pub use record::{Record, RecordError, RecordField, RecordFieldValue, UnknownValue};

/// Umbrella error type for the vault format layer.
///
/// Currently aggregates only [`RecordError`]. Future build-sequence
/// steps add `Block`, `Recipients`, and `Manifest` variants — each with
/// `#[from]` so per-layer code paths can use `?` to propagate without
/// hand-mapping. Single-layer surface today, expandable surface
/// tomorrow, with no breaking change at the call sites that already
/// match on this enum.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    /// Record-level CBOR encode / decode failure (§6.3).
    #[error("record CBOR error: {0}")]
    Record(#[from] RecordError),
}
