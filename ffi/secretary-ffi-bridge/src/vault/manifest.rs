//! [`OpenVaultManifest`] handle plus its accessors and the typed
//! [`ReplaceManifestError`] for the bridge-internal write-back path.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use secretary_core::crypto::secret::Sensitive;
use secretary_core::identity::card::ContactCard;
use secretary_core::vault::{Manifest, ManifestFile};

use crate::error::FfiVaultError;
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
    /// Test-only hook fired between `core::*` and
    /// `replace_manifest_and_file` in the save / trash / restore
    /// orchestrators. Exposes the documented concurrent-wipe race
    /// window to integration tests.
    ///
    /// Field is always present (a `cfg(test)` gate would not reach
    /// integration tests in `tests/*.rs` — `--cfg test` is not
    /// propagated to dependencies). Default is `None`; production code
    /// never calls [`Self::install_mid_call_hook`], so production
    /// builds pay only one `Mutex` lock + `Option::is_none` check per
    /// `save_block` call. The installer is `pub` with `#[doc(hidden)]`
    /// so integration tests can reach it but it is invisible in
    /// generated docs and does not auto-cross the PyO3 / uniffi FFI
    /// boundary (which require explicit `#[pyo3]` / `#[uniffi::export]`
    /// annotations).
    ///
    /// Bound is `Fn() + Send` (no `+ Sync`): closures installed by
    /// tests typically capture `mpsc::Receiver<()>`, which is `Send`
    /// but not `Sync`. The wrapping `Mutex` already provides outer
    /// `Sync` for the field, so `+ Sync` on the closure itself is
    /// neither needed nor possible without forcing tests to use
    /// awkward `Arc<Condvar>` shapes.
    mid_call_hook: Mutex<Option<Box<dyn Fn() + Send>>>,
    /// Memo: `block_uuid → (ts, block_name)` for the Trash view's
    /// by-name projection. Keyed by the on-disk `<ts>` filename suffix so
    /// it is self-invalidating — a re-trash (higher `<ts>`) is an
    /// automatic miss, a restore is pruned out. Lets repeat
    /// `list_trashed_blocks` calls skip the per-block AEAD decrypt (#172).
    ///
    /// Holds plain `String` names, not `Sensitive`: block names are
    /// non-secret in the bridge (already plaintext in
    /// [`BlockSummary`](super::inner::BlockSummary)). Still cleared on
    /// [`Self::wipe`] to match the handle's secret-lifecycle. In a
    /// separate `Mutex` from `inner` so a cache read never contends with a
    /// manifest mutation.
    name_cache: Mutex<HashMap<[u8; 16], (u64, String)>>,
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
            mid_call_hook: Mutex::new(None),
            name_cache: Mutex::new(HashMap::new()),
        }
    }

    /// Whether this handle has been wiped. Every other accessor returns a
    /// safe default (all-zero UUID, `0`, empty, `false`) on a wiped handle
    /// rather than throwing, so a read-only consumer that keys per-vault
    /// state by `vault_uuid()` / treats `block_count() == 0` as "empty"
    /// after a concurrent wipe would act on a default value (the #252 class
    /// of bug). Call this first to distinguish "wiped" from a genuine value.
    pub fn is_wiped(&self) -> bool {
        lock_or_recover(&self.inner).is_none()
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

    /// Look up a memoized trashed-block name. Returns `Some(name)` iff an
    /// entry exists for `block_uuid` whose stored `ts` equals `ts` (same
    /// on-disk file version). A differing `ts` (file re-trashed) or absent
    /// uuid is a miss. Part of the #172 Trash-view decrypt memo.
    pub(crate) fn trash_name_cache_get(&self, block_uuid: &[u8; 16], ts: u64) -> Option<String> {
        lock_or_recover(&self.name_cache)
            .get(block_uuid)
            .filter(|(cached_ts, _)| *cached_ts == ts)
            .map(|(_, name)| name.clone())
    }

    /// Apply this call's freshly-decrypted `(uuid, ts, name)` results to
    /// the memo, then prune the memo down to `live_uuids` (the current
    /// `manifest.trash` set) so restored/stale entries do not accumulate.
    /// One lock acquisition. Part of the #172 Trash-view decrypt memo.
    pub(crate) fn trash_name_cache_put_and_prune(
        &self,
        updates: Vec<([u8; 16], u64, String)>,
        live_uuids: &HashSet<[u8; 16]>,
    ) {
        let mut cache = lock_or_recover(&self.name_cache);
        for (uuid, ts, name) in updates {
            cache.insert(uuid, (ts, name));
        }
        cache.retain(|uuid, _| live_uuids.contains(uuid));
    }

    /// Drop the wrapped manifest now, zeroizing the IBK at exactly this
    /// moment. **Idempotent** — multiple calls do not panic.
    ///
    /// Does **not** clear `mid_call_hook` — the hook lives in a
    /// separate `Mutex` and is test-only state. Production code never
    /// installs a hook, so this is moot in production; tests that
    /// install-then-wipe-then-call-an-orchestrator-again must reinstall
    /// (or accept the prior closure firing on the next call).
    pub fn wipe(&self) {
        let _drop = lock_or_recover(&self.inner).take();
        // _drop goes out of scope here → OpenVaultManifestInner drops in
        // field-declaration order: identity_block_key (Sensitive<[u8; 32]>
        // — IBK zeroized first via ZeroizeOnDrop), then manifest,
        // manifest_file, owner_card.
        //
        // Drop any memoized trash names too — keeps a wiped handle free of
        // residual (non-secret but handle-scoped) names (#172).
        lock_or_recover(&self.name_cache).clear();
    }

    /// Fire the mid-call test hook if one is installed. Called by
    /// orchestrators between `core::*` and `replace_manifest_and_file`
    /// to expose the concurrent-wipe race window to integration tests.
    ///
    /// Production builds pay one `Mutex` lock + `Option::is_none` check
    /// per call (the hook is `None` unless
    /// [`Self::install_mid_call_hook`] has been called, and production
    /// code never calls that). Orchestrators opt into testability by
    /// adding a single `manifest.run_mid_call_hook();` call between the
    /// core invocation and the write-back. Today only
    /// `save::save_block` opts in; trash and restore can adopt the same
    /// shape in a follow-up.
    ///
    /// The hook closure must not recursively call `run_mid_call_hook`
    /// on the same `OpenVaultManifest` — the `mid_call_hook` mutex is
    /// held across the closure call and would deadlock. Test-only
    /// closures we install today only touch `mpsc` channel ends.
    #[inline]
    pub(crate) fn run_mid_call_hook(&self) {
        if let Some(f) = self
            .mid_call_hook
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
        {
            f();
        }
    }

    /// Install a closure fired by [`Self::run_mid_call_hook`].
    /// **Test-only — do not use in production.** Overwrites any
    /// previously-installed hook.
    ///
    /// `pub` so it is reachable from integration tests in `tests/*.rs`
    /// (where `--cfg test` is not propagated to dependencies, so a
    /// `#[cfg(test)]` gate would hide the method). `#[doc(hidden)]`
    /// keeps it out of generated rustdoc, and the method does not
    /// auto-cross the PyO3 / uniffi FFI boundary (those layers require
    /// explicit `#[pyo3]` / `#[uniffi::export]` annotations).
    ///
    /// The closure bound is `Fn()` (re-callable). The bundled
    /// `MidCallRace` test helper is intentionally *single-shot* — its
    /// `sync_channel(0)` ends drop when the helper is consumed by
    /// `release_worker`, so a second call to an orchestrator that
    /// invokes the hook would panic inside the closure (`send`/`recv`
    /// on a dropped peer). Tests that need multi-shot semantics must
    /// either reinstall between calls or build a helper that doesn't
    /// own one-shot channel ends. A closure panic poisons the
    /// `mid_call_hook` mutex; both call sites recover via
    /// `unwrap_or_else(|p| p.into_inner())`, so the prior closure
    /// remains installed for the next access.
    #[doc(hidden)]
    pub fn install_mid_call_hook<F: Fn() + Send + 'static>(&self, f: F) {
        *self.mid_call_hook.lock().unwrap_or_else(|p| p.into_inner()) = Some(Box::new(f));
    }

    /// Bridge-internal accessor for the vault folder path. NOT exposed
    /// through PyO3 / uniffi. Returns `None` if the handle has been
    /// wiped.
    ///
    /// Originally consumed by `crate::record::read_block`; B.4b's
    /// `snapshot_for_read_block` superseded the per-field call site to
    /// fold 3 lock acquisitions into 1. B.4c (`save_block`) and B.4d
    /// (`share_block`) ultimately landed using `snapshot_for_save_block`
    /// for the same single-lock atomicity. D.1.6's `crate::contacts`
    /// primitives `enumerate_contact_cards`, `import_contact_card`, and
    /// `share_block_to` are now the live callers — they need the vault
    /// folder path to resolve `contacts/` without the manifest body.
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
    /// landed using `snapshot_for_save_block` instead. D.1.6's
    /// `crate::contacts::share_block_to` is now the live caller — it reads
    /// the target block's current `recipients` set (to assemble the
    /// existing-recipient cards) without needing the owner card.
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
    /// landed using `snapshot_for_save_block` instead. D.1.6's
    /// `crate::contacts::enumerate_contact_cards` is now the live caller —
    /// it reads the owner's `contact_uuid` to omit the owner's own card
    /// from the contacts enumeration.
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
    /// Returns `Ok(None)` iff the manifest handle has been wiped — same
    /// `None`-on-wipe contract as the other accessors.
    ///
    /// Encodes on demand via `ContactCard::to_canonical_cbor`. Encode
    /// failure surfaces as [`FfiVaultError::CorruptVault`] rather than
    /// panicking; a panic across the PyO3 / uniffi FFI boundary aborts
    /// the foreign caller without a chance to recover (issue #41).
    ///
    /// On the v1 invariant the encode cannot legitimately fail: the card
    /// was decoded + verified during `open_vault` and lives behind an
    /// immutable handle, so re-encoding a previously-validated card is
    /// deterministic over fixed inputs (no IO). The `Result` return
    /// preserves recoverability if a future encoder version grows a
    /// non-trivial failure mode (e.g. internal allocator failure on a
    /// memory-constrained platform); current callers should treat the
    /// `Err` arm as practically unreachable but propagate it cleanly
    /// rather than `.expect()`-ing.
    ///
    /// New in B.4d; signature widened to `Result` in B.4d-cleanup
    /// (issue #41).
    pub fn owner_card_bytes(&self) -> Result<Option<Vec<u8>>, FfiVaultError> {
        let guard = lock_or_recover(&self.inner);
        let Some(inner) = guard.as_ref() else {
            return Ok(None);
        };
        inner
            .owner_card
            .to_canonical_cbor()
            .map(Some)
            .map_err(|e| FfiVaultError::CorruptVault {
                detail: format!("owner card re-encode failed: {e}"),
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
/// `HandleClosed` variant on [`crate::identity::ReaderSecretKeysError`]
/// so the orchestrator can translate the failure to a `CorruptVault`
/// with a non-misleading detail string via `Display`. Single-variant
/// for now; new variants belong here rather than being multiplexed onto
/// `HandleWiped`'s detail string.
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
pub(crate) fn block_entry_to_summary(b: &secretary_core::vault::BlockEntry) -> BlockSummary {
    BlockSummary {
        block_uuid: b.block_uuid,
        block_name: b.block_name.clone(),
        created_at_ms: b.created_at_ms,
        last_modified_ms: b.last_mod_ms,
        recipient_uuids: b.recipients.clone(),
    }
}

#[cfg(test)]
mod name_cache_tests {
    use std::collections::HashSet;

    fn open_writable_golden_001() -> (tempfile::TempDir, super::OpenVaultManifest) {
        let (tmp, out) = crate::test_support::open_writable_golden_001();
        (tmp, out.manifest)
    }

    #[test]
    fn put_then_get_hits_on_matching_ts_and_misses_otherwise() {
        let (_tmp, manifest) = open_writable_golden_001();
        let uuid = [0xAB; 16];
        let live: HashSet<[u8; 16]> = [uuid].into_iter().collect();

        manifest.trash_name_cache_put_and_prune(vec![(uuid, 42, "Logins".into())], &live);

        assert_eq!(
            manifest.trash_name_cache_get(&uuid, 42),
            Some("Logins".to_string())
        );
        // Wrong ts → miss (file version advanced).
        assert_eq!(manifest.trash_name_cache_get(&uuid, 43), None);
        // Unknown uuid → miss.
        assert_eq!(manifest.trash_name_cache_get(&[0xCD; 16], 42), None);
    }

    #[test]
    fn prune_drops_uuids_absent_from_live_set() {
        let (_tmp, manifest) = open_writable_golden_001();
        let kept = [0x11; 16];
        let dropped = [0x22; 16];

        // First call caches both.
        let both: HashSet<[u8; 16]> = [kept, dropped].into_iter().collect();
        manifest.trash_name_cache_put_and_prune(
            vec![(kept, 1, "Keep".into()), (dropped, 1, "Drop".into())],
            &both,
        );
        assert_eq!(
            manifest.trash_name_cache_get(&dropped, 1),
            Some("Drop".to_string())
        );

        // Second call: `dropped` is no longer live (e.g. restored) → pruned out.
        let only_kept: HashSet<[u8; 16]> = [kept].into_iter().collect();
        manifest.trash_name_cache_put_and_prune(vec![], &only_kept);
        assert_eq!(
            manifest.trash_name_cache_get(&kept, 1),
            Some("Keep".to_string())
        );
        assert_eq!(manifest.trash_name_cache_get(&dropped, 1), None);
    }

    #[test]
    fn wipe_clears_the_cache() {
        let (_tmp, manifest) = open_writable_golden_001();
        let uuid = [0x33; 16];
        let live: HashSet<[u8; 16]> = [uuid].into_iter().collect();
        manifest.trash_name_cache_put_and_prune(vec![(uuid, 7, "Secret".into())], &live);
        assert_eq!(
            manifest.trash_name_cache_get(&uuid, 7),
            Some("Secret".to_string())
        );

        manifest.wipe();
        // After wipe the cache holds no residual names.
        assert_eq!(manifest.trash_name_cache_get(&uuid, 7), None);
    }
}
