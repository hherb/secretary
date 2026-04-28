//! Vault on-disk format: blocks, manifest, recipients, conflict resolution.
//!
//! The on-disk format is normatively specified in `docs/vault-format.md`.
//! This module currently exposes the §6.3 record types ([`record`]) and
//! the §6.1 / §6.2 / §6.3 block layer ([`block`] — binary header,
//! recipient table, AEAD body, the trailing §8 hybrid signature suffix,
//! plus the canonical-CBOR plaintext body and the
//! [`block::encrypt_block`] / [`block::decrypt_block`] orchestrators
//! which sign on encrypt and verify on decrypt). The manifest (§4)
//! layer lands in a subsequent build-sequence step and will plug into
//! the [`VaultError`] umbrella below via an additional `#[from]`
//! variant.

pub mod block;
pub(crate) mod canonical;
pub(crate) mod io;
pub mod manifest;
pub mod record;

pub use block::{
    decode_block_file, decrypt_block, encode_block_file, encrypt_block, BlockError, BlockFile,
    BlockHeader, BlockPlaintext, RecipientPublicKeys, RecipientWrap, VectorClockEntry,
    FILE_KIND_BLOCK, RECIPIENT_ENTRY_LEN,
};
pub use manifest::{
    decode_manifest, decrypt_manifest_body, encode_manifest, encrypt_manifest_body, BlockEntry,
    KdfParamsRef, Manifest, ManifestError, ManifestHeader, TrashEntry, MANIFEST_HEADER_LEN,
};
// NOTE: VectorClockEntry is re-used from block.rs by manifest.rs (re-exported
// there via `pub use super::block::VectorClockEntry`). Do NOT add a second
// re-export here — the type is already re-exported above via block.rs.
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
