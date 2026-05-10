//! Inner state of [`super::OpenVaultManifest`] plus the read-only
//! [`BlockSummary`] projection used by the manifest's accessors.

use secretary_core::crypto::secret::Sensitive;
use secretary_core::identity::card::ContactCard;
use secretary_core::vault::{Manifest, ManifestFile};

/// Read-only metadata projection of one [`secretary_core::vault::BlockEntry`].
/// All five fields are plaintext in the manifest already; no secret material
/// crosses through `BlockSummary`. The struct is `Clone`, `Debug`, and
/// projects directly to a Swift `struct` / Kotlin `data class` /
/// `#[pyclass(frozen)]` at the binding-flavor layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockSummary {
    /// 16-byte block UUID identifying the block file on disk.
    pub block_uuid: [u8; 16],
    /// User-visible block name. Plaintext within the encrypted manifest.
    pub block_name: String,
    /// Wall-clock millisecond timestamp at block creation.
    pub created_at_ms: u64,
    /// Wall-clock millisecond timestamp at last modification.
    pub last_modified_ms: u64,
    /// Contact UUIDs of each recipient (always includes owner). Plaintext
    /// within the encrypted manifest. Encoded in ascending lex order.
    pub recipient_uuids: Vec<[u8; 16]>,
}

/// Internal state of [`super::OpenVaultManifest`]. Held inside
/// `Mutex<Option<...>>` so the wrapper can provide idempotent close +
/// non-throwing post-close accessors + thread-safe access. All four fields
/// are kept for forward-compat with B.4b (read_block needs the IBK), B.4c
/// (save_block needs the manifest envelope + owner card for re-signing),
/// and B.4d (share_block needs the owner card).
///
/// `pub(crate)` so that [`super::OpenVaultManifest::new`] (also
/// `pub(crate)`) can name the type without triggering the
/// `private_interfaces` lint.
pub(crate) struct OpenVaultManifestInner {
    /// 32-byte Identity Block Key. Sensitive; zeroized on drop. Held for
    /// B.4c's `save_block` (which derives a fresh BCK and rewraps under
    /// each recipient using the IBK as the manifest-encryption key).
    /// `read_block` (B.4b) does NOT need the IBK directly — it goes
    /// through `core::block::decrypt_block` with the reader's secret
    /// keys from `UnlockedIdentity`.
    #[allow(dead_code)] // B.4c will use this; intentional now for forward-compat
    pub(super) identity_block_key: Sensitive<[u8; 32]>,
    /// Decrypted manifest body — block list, vault-level vector clock,
    /// kdf_params attestation, owner UUIDs.
    pub(super) manifest: Manifest,
    /// On-disk manifest envelope (header + AEAD nonce + ct/tag + author
    /// fingerprint + §8 hybrid signature). Held for B.4c's `save_block`
    /// to re-sign on update without re-opening.
    #[allow(dead_code)] // B.4c will use this; intentional now for forward-compat
    pub(super) manifest_file: ManifestFile,
    /// Owner's self-signed contact card, already self-verified during
    /// `core::open_vault`. B.4b reads it via the bridge-internal
    /// `owner_card()` accessor in `read_block` (sender + reader for the
    /// v1 single-author flow). B.4c/d will use it for save/share
    /// signature operations. NOT exposed through public B.4a/B.4b
    /// accessors (deferred to B.4d's contact-card surface).
    pub(super) owner_card: ContactCard,
    /// NEW in B.4b: vault folder path the manifest was opened from.
    /// Used by `read_block` to resolve `blocks/<uuid>.cbor.enc`.
    /// B.4c (`save_block`) and B.4d (`share_block`) will reuse this for
    /// atomic-write paths through `tempfile::persist`.
    pub(super) vault_folder: std::path::PathBuf,
}
