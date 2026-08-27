//! In-memory manifest types (`docs/vault-format.md` §4.2).

use std::collections::BTreeMap;

use crate::vault::record::UnknownValue;

use super::{VectorClockEntry, BLOCK_FINGERPRINT_LEN, SALT_LEN, UUID_LEN};

// ---------------------------------------------------------------------------
// In-memory types
// ---------------------------------------------------------------------------

/// KDF parameters mirrored from `vault.toml` so the manifest signature
/// attests to them (§4.2 line 205).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdfParamsRef {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt: [u8; SALT_LEN],
}

/// One block entry within the manifest's `blocks` array (§4.2).
///
/// Only [`PartialEq`] (not [`Eq`]) is implemented — see [`Manifest`] for
/// the full justification.
#[derive(Debug, Clone, PartialEq)]
pub struct BlockEntry {
    /// 16-byte block UUID. Identifies the block file on disk.
    pub block_uuid: [u8; UUID_LEN],
    /// User-visible block name, plaintext within the encrypted manifest.
    pub block_name: String,
    /// BLAKE3-256 of the complete block file bytes.
    pub fingerprint: [u8; BLOCK_FINGERPRINT_LEN],
    /// Contact UUIDs of each recipient (always includes owner). Encoded
    /// in ascending lex order.
    pub recipients: Vec<[u8; UUID_LEN]>,
    /// The block's own vector clock at last manifest update. Encoded in
    /// ascending `device_uuid` order.
    pub vector_clock_summary: Vec<VectorClockEntry>,
    /// Cipher suite the block file is encrypted under.
    pub suite_id: u16,
    pub created_at_ms: u64,
    pub last_mod_ms: u64,
    /// Forward-compat unknown keys preserved verbatim per the §6.3.2
    /// pattern, applied here at the manifest layer.
    pub unknown: BTreeMap<String, UnknownValue>,
}

/// One trash entry (tombstoned block) within `manifest.trash` (§4.2).
///
/// Only [`PartialEq`] (not [`Eq`]) is implemented — see [`Manifest`] for
/// the full justification.
#[derive(Debug, Clone, PartialEq)]
pub struct TrashEntry {
    pub block_uuid: [u8; UUID_LEN],
    pub tombstoned_at_ms: u64,
    /// `device_uuid` that performed the deletion.
    pub tombstoned_by: [u8; UUID_LEN],
    /// BLAKE3-256 of the trashed block file bytes, captured at trash time
    /// (the value the live `BlockEntry.fingerprint` committed to). Binds the
    /// restored content's freshness to the signed manifest (#293). `None`
    /// for entries written before this field existed (legacy vaults); restore
    /// then falls back to suffix-equality + §6.1 hybrid-verify only.
    pub fingerprint: Option<[u8; BLOCK_FINGERPRINT_LEN]>,
    /// `Some(t)` = this block has been purged: its local ciphertext was
    /// permanently removed at unix-millis `t`. Terminal and monotonic — a
    /// purged entry never un-purges. `None` = a still-restorable trash entry.
    /// Additive optional field (§6.3.2 forward-compat), same shape as
    /// `fingerprint`; absent key decodes to `None` and re-encodes to absent.
    pub purged_at_ms: Option<u64>,
    /// Forward-compat unknown keys preserved verbatim per the §6.3.2 pattern.
    pub unknown: BTreeMap<String, UnknownValue>,
}

/// Top-level manifest body (§4.2 — the canonical CBOR plaintext that
/// goes inside `aead_ct`).
///
/// Only [`PartialEq`] (not [`Eq`]) is implemented: the [`UnknownValue`]
/// payload in `unknown` (and in nested `BlockEntry`/`TrashEntry`) wraps
/// a [`ciborium::Value`] which does not implement [`Eq`] (the `Float`
/// variant breaks reflexivity for NaN). The decoder rejects floats, so
/// any [`Manifest`] produced by [`decode_manifest`] is float-free in
/// practice; the type contract is the conservative one. Same reasoning
/// as [`crate::vault::record::Record`].
///
/// [`decode_manifest`]: crate::vault::manifest::decode_manifest
#[derive(Debug, Clone, PartialEq)]
pub struct Manifest {
    /// Manifest schema version. Reserved for future incompatible manifest
    /// changes; v1 is the only value v1 clients accept.
    pub manifest_version: u8,
    pub vault_uuid: [u8; UUID_LEN],
    pub format_version: u16,
    pub suite_id: u16,
    pub owner_user_uuid: [u8; UUID_LEN],
    /// Vault-level vector clock. Encoded in ascending `device_uuid` order.
    pub vector_clock: Vec<VectorClockEntry>,
    /// Block list. Encoded in ascending `block_uuid` order.
    pub blocks: Vec<BlockEntry>,
    /// Tombstoned blocks. Encoded in ascending `block_uuid` order.
    pub trash: Vec<TrashEntry>,
    /// KDF params duplicated from `vault.toml` so the manifest signature
    /// attests to them.
    pub kdf_params: KdfParamsRef,
    /// Forward-compat unknown top-level keys, preserved verbatim.
    pub unknown: BTreeMap<String, UnknownValue>,
}
