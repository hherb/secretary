//! [`OpenVaultManifest`] handle plus its accessors and the typed
//! [`ReplaceManifestError`] for the bridge-internal write-back path.

use std::sync::Mutex;

use secretary_core::crypto::secret::Sensitive;
use secretary_core::identity::card::ContactCard;
use secretary_core::vault::{Manifest, ManifestFile};

use crate::sync_helpers::lock_or_recover;

use super::inner::{BlockSummary, OpenVaultManifestInner};

/// Opaque handle to a successfully-opened vault's manifest.
///
/// # Lifecycle
///
/// [`OpenVaultManifest::wipe`] explicitly drops the wrapped state now —
/// zeroizes the `Sensitive<[u8; 32]>` IBK and source-order-drops the rest.
/// **Idempotent** — multiple calls do not panic. Subsequent accessor calls
/// on a closed handle return empty / zero defaults rather than panicking,
/// keeping the API non-throwing (parallel to
/// [`crate::identity::UnlockedIdentity`]).
///
/// RAII is the safety net: when the foreign-side reference releases, the
/// Rust-side `Drop` cascade still runs.
pub struct OpenVaultManifest {
    inner: Mutex<Option<OpenVaultManifestInner>>,
}

/// Redacted Debug: never leak secret material through fmt.
impl std::fmt::Debug for OpenVaultManifest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let is_closed = lock_or_recover(&self.inner).is_none();
        f.debug_struct("OpenVaultManifest")
            .field("closed", &is_closed)
            .finish()
    }
}

impl OpenVaultManifest {
    /// Wrap a freshly-decoded manifest. Crate-private: only
    /// [`super::open_vault_with_password`] /
    /// [`super::open_vault_with_recovery`] construct this.
    pub(crate) fn new(inner: OpenVaultManifestInner) -> Self {
        Self {
            inner: Mutex::new(Some(inner)),
        }
    }

    /// 16-byte vault UUID from the manifest body. Returns `vec![0u8; 16]`
    /// if the handle has been wiped.
    pub fn vault_uuid(&self) -> Vec<u8> {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.manifest.vault_uuid.to_vec())
            .unwrap_or_else(|| vec![0u8; 16])
    }

    /// 16-byte owner user UUID from the manifest body. Returns
    /// `vec![0u8; 16]` if the handle has been wiped.
    pub fn owner_user_uuid(&self) -> Vec<u8> {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.manifest.owner_user_uuid.to_vec())
            .unwrap_or_else(|| vec![0u8; 16])
    }

    /// Number of blocks in the manifest. Returns `0` if wiped.
    pub fn block_count(&self) -> u64 {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.manifest.blocks.len() as u64)
            .unwrap_or(0)
    }

    /// All block summaries in the manifest's ascending-by-`block_uuid`
    /// order. Returns an empty `Vec` if wiped.
    pub fn block_summaries(&self) -> Vec<BlockSummary> {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| {
                i.manifest
                    .blocks
                    .iter()
                    .map(block_entry_to_summary)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Locate one block by its UUID. Returns `None` if wiped or if no
    /// matching block exists.
    pub fn find_block(&self, block_uuid: &[u8]) -> Option<BlockSummary> {
        if block_uuid.len() != 16 {
            return None;
        }
        let mut needle = [0u8; 16];
        needle.copy_from_slice(block_uuid);
        lock_or_recover(&self.inner).as_ref().and_then(|i| {
            i.manifest
                .blocks
                .iter()
                .find(|b| b.block_uuid == needle)
                .map(block_entry_to_summary)
        })
    }

    /// Drop the wrapped manifest now, zeroizing the IBK at exactly this
    /// moment. **Idempotent** — multiple calls do not panic.
    pub fn wipe(&self) {
        let _drop = lock_or_recover(&self.inner).take();
        // _drop goes out of scope here → OpenVaultManifestInner drops in
        // field-declaration order: identity_block_key (Sensitive<[u8; 32]>
        // — IBK zeroized first via ZeroizeOnDrop), then manifest,
        // manifest_file, owner_card.
    }

    /// Bridge-internal accessor for the vault folder path. NOT exposed
    /// through PyO3 / uniffi. Returns `None` if the handle has been
    /// wiped.
    ///
    /// Originally consumed by `crate::record::read_block`; B.4b's
    /// `snapshot_for_read_block` superseded the per-field call site to
    /// fold 3 lock acquisitions into 1. B.4c (`save_block`) and B.4d
    /// (`share_block`) ultimately landed using `snapshot_for_save_block`
    /// for the same single-lock atomicity, so this per-field accessor
    /// has no live caller today — only the post-wipe contract test in
    /// the sibling `tests` module references it. Retained for
    /// forward-compat with Sub-project C (sync orchestration may need
    /// the folder path without the manifest body); revisit for deletion
    /// when C's surface stabilizes (issue #45).
    #[allow(dead_code)]
    pub(crate) fn vault_folder(&self) -> Option<std::path::PathBuf> {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.vault_folder.clone())
    }

    /// Bridge-internal accessor for the manifest body. NOT exposed
    /// through PyO3 / uniffi. Returns a clone of the manifest (block
    /// list + vector clock + kdf_params attestation). Returns `None`
    /// if the handle has been wiped.
    ///
    /// Originally consumed by `crate::record::read_block`; B.4b's
    /// `snapshot_for_read_block` superseded the per-field call site to
    /// fold 3 lock acquisitions into 1. B.4c (`save_block`) ultimately
    /// landed using `snapshot_for_save_block` instead, so this per-field
    /// accessor has no live caller today — only the post-wipe contract
    /// test in the sibling `tests` module references it. Retained for
    /// forward-compat with Sub-project C (vector-clock comparison may
    /// want the manifest body without the owner card); revisit for
    /// deletion when C's surface stabilizes (issue #45).
    #[allow(dead_code)]
    pub(crate) fn manifest_body(&self) -> Option<Manifest> {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.manifest.clone())
    }

    /// Bridge-internal accessor for the verified owner contact card.
    /// NOT exposed through PyO3 / uniffi. Returns `None` if the
    /// handle has been wiped.
    ///
    /// Originally consumed by `crate::record::read_block`; B.4b's
    /// `snapshot_for_read_block` superseded the per-field call site to
    /// fold 3 lock acquisitions into 1. B.4d (`share_block`) ultimately
    /// landed using `snapshot_for_save_block` instead, so this per-field
    /// accessor has no live caller today — only the post-wipe contract
    /// test in the sibling `tests` module references it. Retained for
    /// forward-compat with Sub-project C; revisit for deletion when C's
    /// surface stabilizes (issue #45).
    #[allow(dead_code)]
    pub(crate) fn owner_card(&self) -> Option<ContactCard> {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.owner_card.clone())
    }

    /// Canonical-CBOR bytes of the vault's `owner_card`. Returns the same
    /// byte sequence as the on-disk `<vault>/contacts/<owner_uuid>.card`
    /// content. Use as the only element of `existing_recipient_cards`
    /// when calling [`crate::share_block`] on a v1 owner-only block, or
    /// as the first element when sharing with multiple recipients.
    ///
    /// Returns `None` iff the manifest handle has been wiped.
    ///
    /// Encodes on demand via `ContactCard::to_canonical_cbor`. The
    /// `.expect()` is justified by the open-vault invariant: the card was
    /// decoded + verified during `open_vault` and lives behind an
    /// immutable handle, so re-encoding a previously-validated card
    /// cannot fail (no IO; deterministic encoder over fixed inputs).
    /// New in B.4d.
    pub fn owner_card_bytes(&self) -> Option<Vec<u8>> {
        lock_or_recover(&self.inner).as_ref().map(|i| {
            i.owner_card
                .to_canonical_cbor()
                .expect("re-encoding a verified card cannot fail")
        })
    }

    /// Bridge-internal atomic snapshot of the three pieces
    /// `crate::record::read_block` needs in one shot: the manifest
    /// body, the verified owner contact card, and the vault folder
    /// path. NOT exposed through PyO3 / uniffi.
    ///
    /// This folds the three sequential `lock_or_recover` calls in
    /// `read_block` into a single critical section, closing the
    /// theoretical atomicity gap where another thread could call
    /// [`OpenVaultManifest::wipe`] between the individual accessor
    /// calls (e.g. observing `Some(manifest)` then `None` on
    /// `owner_card`, leaking through as a misleading
    /// `crate::FfiVaultError::CorruptVault`).
    ///
    /// Returns `None` if the handle has been wiped before the lock
    /// was taken (then `read_block` falls through to a typed
    /// `CorruptVault` with the "wiped" detail). The 3 individual
    /// accessors ([`OpenVaultManifest::manifest_body`],
    /// [`OpenVaultManifest::owner_card`], [`OpenVaultManifest::vault_folder`])
    /// are intentionally retained for forward-compat — B.4c / B.4d
    /// will reuse them piecewise.
    pub(crate) fn snapshot_for_read_block(
        &self,
    ) -> Option<(Manifest, ContactCard, std::path::PathBuf)> {
        lock_or_recover(&self.inner).as_ref().map(|i| {
            (
                i.manifest.clone(),
                i.owner_card.clone(),
                i.vault_folder.clone(),
            )
        })
    }

    /// Bridge-internal write-back used by `crate::save::save_block` after
    /// `core::vault::orchestrators::save_block` returns Ok. Atomically
    /// replaces the inner `manifest` body and `manifest_file` envelope
    /// with the post-mutation values. Returns
    /// [`ReplaceManifestError::HandleWiped`] if the handle has been wiped
    /// (the orchestrator surfaces this as `CorruptVault`).
    ///
    /// The IBK / `owner_card` / `vault_folder` fields are intentionally
    /// NOT mutated — `save_block` only changes the manifest body
    /// (`blocks`, `vector_clock`) and the envelope (re-signed header).
    pub(crate) fn replace_manifest_and_file(
        &self,
        new_manifest: Manifest,
        new_manifest_file: ManifestFile,
    ) -> Result<(), ReplaceManifestError> {
        let mut guard = lock_or_recover(&self.inner);
        let inner = guard.as_mut().ok_or(ReplaceManifestError::HandleWiped)?;
        inner.manifest = new_manifest;
        inner.manifest_file = new_manifest_file;
        Ok(())
    }

    /// Bridge-internal atomic snapshot of the five pieces
    /// `crate::save::save_block` needs in one shot: the manifest body,
    /// the on-disk manifest envelope (for re-sign chaining), the
    /// verified owner contact card, a fresh clone of the IBK
    /// (`Sensitive::new` on a new slot), and the vault folder path.
    /// NOT exposed through PyO3 / uniffi.
    ///
    /// Folds the five sequential `lock_or_recover` calls in `save_block`
    /// into a single critical section, closing the same theoretical
    /// TOCTOU window [`OpenVaultManifest::snapshot_for_read_block`]
    /// closes for the read path.
    ///
    /// Returns `None` if the handle has been wiped before the lock was
    /// taken; the orchestrator falls through to a typed `CorruptVault`
    /// with the `"vault manifest handle has been closed"` detail.
    //
    // The 5-tuple return is local to this internal accessor; defining a
    // typedef just to placate clippy::type_complexity would add ceremony
    // without helping callers. The five fields are documented above.
    #[allow(clippy::type_complexity)]
    #[allow(dead_code)] // consumed by crate::save::save_block in Task 2
    pub(crate) fn snapshot_for_save_block(
        &self,
    ) -> Option<(
        Manifest,
        ManifestFile,
        ContactCard,
        Sensitive<[u8; 32]>,
        std::path::PathBuf,
    )> {
        lock_or_recover(&self.inner).as_ref().map(|i| {
            // Clone the IBK by copying its 32 bytes into a fresh
            // Sensitive slot. The `*expose()` deref produces a temporary
            // [u8; 32] that's immediately moved into Sensitive::new; the
            // source slot's bytes stay live and zeroize on its own drop.
            let ibk = Sensitive::new(*i.identity_block_key.expose());
            (
                i.manifest.clone(),
                i.manifest_file.clone(),
                i.owner_card.clone(),
                ibk,
                i.vault_folder.clone(),
            )
        })
    }
}

/// Bridge-internal failure mode for
/// [`OpenVaultManifest::replace_manifest_and_file`]. Mirrors the
/// `HandleClosed` variant on [`crate::identity::ReaderSecretKeysError`] /
/// [`crate::identity::SignerSecretKeysError`] so the orchestrator can
/// translate the failure to a `CorruptVault` with a non-misleading detail
/// string via `Display`. Single-variant for now; new variants belong here
/// rather than being multiplexed onto `HandleWiped`'s detail string.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReplaceManifestError {
    /// The manifest handle was wiped between snapshot acquisition and
    /// write-back (concurrent-wipe race). The on-disk write may have
    /// already succeeded; the bridge's in-memory state is no longer
    /// authoritative.
    HandleWiped,
}

impl std::fmt::Display for ReplaceManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HandleWiped => f.write_str("vault manifest handle has been closed during save"),
        }
    }
}

/// Internal projection: `core::BlockEntry` → [`BlockSummary`] (drops
/// internal-only fields: `fingerprint`, `vector_clock_summary`, `suite_id`,
/// `unknown`).
pub(super) fn block_entry_to_summary(b: &secretary_core::vault::BlockEntry) -> BlockSummary {
    BlockSummary {
        block_uuid: b.block_uuid,
        block_name: b.block_name.clone(),
        created_at_ms: b.created_at_ms,
        last_modified_ms: b.last_mod_ms,
        recipient_uuids: b.recipients.clone(),
    }
}
