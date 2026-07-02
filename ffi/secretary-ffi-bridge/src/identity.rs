//! Opaque foreign-side handle to a successfully-unlocked vault identity.
//!
//! The wrapped `core::unlock::UnlockedIdentity` carries ~2.5 KB of
//! `Sensitive<...>`-wrapped secret material (the 32-byte IBK plus four
//! secret keys: X25519, ML-KEM-768, Ed25519, ML-DSA-65). Foreign callers
//! hold a refcount and read non-secret fields via accessor methods; the
//! secret state stays Rust-side and zeroizes on drop.
//!
//! # Lifecycle
//!
//! [`UnlockedIdentity::wipe`] explicitly drops the wrapped identity now
//! (zeroizing all `Sensitive<...>` fields at exactly this moment instead
//! of waiting for foreign GC). It is **idempotent** — multiple calls do
//! not panic. Subsequent accessor calls on a wiped handle return empty
//! / zero values rather than panicking, keeping the API non-throwing.
//! The non-throwing guarantee extends to a poisoned inner mutex via the
//! private `lock_or_recover` helper: a panic anywhere holding the guard
//! does not turn future accessors into panics.
//!
//! RAII is the safety net: when the foreign-side reference releases, the
//! Rust-side `Drop` cascade still runs.
//!
//! # Naming
//!
//! Every other bridge-side handle (`MnemonicOutput`, `OpenVaultManifest`,
//! `BlockReadOutput`, `Record`, `FieldHandle`) exposes its explicit-zeroize
//! method as `wipe()`. This handle uses the same name for vocabulary
//! uniformity. The PyO3 binding crate still presents `close()` to Python
//! callers because Python's context-manager protocol expects a `close()`
//! method (`__exit__` calls `close`), and PyO3 forwards Python's `close()`
//! to this `wipe()` internally. The uniffi binding crate calls `wipe()`
//! directly because uniffi 0.31's Kotlin codegen auto-generates an
//! `AutoCloseable.close()` that would collide with a UDL-declared `close()`.

use std::fmt;
use std::sync::Mutex;

use crate::sync_helpers::lock_or_recover;

/// Opaque handle to an unlocked vault identity. See [module docs](self).
pub struct UnlockedIdentity {
    /// Wrapped behind a `Mutex<Option<...>>` to provide:
    /// - **idempotent wipe** via `Option::take()`
    /// - **thread-safe accessors** (lock is short — clone a String or copy
    ///   16 bytes — for sub-microsecond read overhead)
    /// - **use-after-wipe non-throwing** semantics (`as_ref()` on `None`
    ///   yields default values via `unwrap_or_default()`)
    inner: Mutex<Option<secretary_core::unlock::UnlockedIdentity>>,
}

/// Redacted Debug: never leak secret material through the fmt path.
impl fmt::Debug for UnlockedIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let is_wiped = lock_or_recover(&self.inner).is_none();
        f.debug_struct("UnlockedIdentity")
            .field("wiped", &is_wiped)
            .finish()
    }
}

impl UnlockedIdentity {
    /// Wrap a freshly-unlocked `core::UnlockedIdentity`. Crate-private:
    /// only [`crate::unlock::open_with_password`] constructs this.
    pub(crate) fn new(inner: secretary_core::unlock::UnlockedIdentity) -> Self {
        Self {
            inner: Mutex::new(Some(inner)),
        }
    }

    /// Whether this handle has been wiped. `display_name()`/`user_uuid()`
    /// return safe defaults (`""` / all-zero UUID) on a wiped handle rather
    /// than throwing, so a read-only consumer keying state by `user_uuid()`
    /// after a concurrent wipe would act on a default (the #252 class of
    /// bug). Call this first to distinguish "wiped" from a genuine value.
    pub fn is_wiped(&self) -> bool {
        lock_or_recover(&self.inner).is_none()
    }

    /// User-facing display name from the IdentityBundle. UTF-8.
    ///
    /// Returns `""` if the handle has been explicitly wiped.
    pub fn display_name(&self) -> String {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|id| id.identity.display_name.clone())
            .unwrap_or_default()
    }

    /// 16-byte stable identifier from the IdentityBundle.
    ///
    /// Returns `vec![0u8; 16]` if the handle has been explicitly wiped.
    pub fn user_uuid(&self) -> Vec<u8> {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|id| id.identity.user_uuid.to_vec())
            .unwrap_or_else(|| vec![0u8; 16])
    }

    /// Drop the wrapped identity now, zeroizing all `Sensitive<...>`
    /// fields at exactly this moment. **Idempotent** — multiple calls do
    /// not panic.
    ///
    /// Renamed from `close()` to `wipe()` for vocabulary uniformity with
    /// every other bridge-side handle. PyO3's binding crate forwards
    /// Python's `close()` (context-manager protocol) to this method
    /// internally; uniffi's binding crate calls this directly.
    pub fn wipe(&self) {
        let _drop = lock_or_recover(&self.inner).take();
        // _drop goes out of scope here → core::UnlockedIdentity drops →
        // Sensitive<...> ZeroizeOnDrop runs for every secret field.
    }

    /// Bridge-internal accessor returning fresh clones of the X25519 +
    /// ML-KEM-768 reader secret keys for `core::block::decrypt_block`.
    /// Public-key material is supplied separately via the manifest's
    /// owner contact card (see `crate::vault::OpenVaultManifest::owner_card`).
    /// NOT exposed through PyO3 / uniffi — used only by
    /// `crate::record::read_block`.
    ///
    /// Returns a typed [`ReaderSecretKeysError`] so the orchestrator can
    /// attach a non-misleading detail string for each failure mode (the
    /// previous `Option<...>` return collapsed both modes into a single
    /// "handle wiped" message even when the actual failure was an
    /// in-memory parse failure on already-validated bytes). The returned
    /// `(X25519Secret, MlKem768Secret)` tuple is `Sensitive`-wrapped on
    /// the `Sensitive::new` path; the caller drops it after the
    /// `decrypt_block` call returns and zeroize-on-drop takes care of
    /// the secret bytes.
    pub(crate) fn reader_secret_keys(
        &self,
    ) -> Result<
        (
            secretary_core::crypto::kem::X25519Secret,
            secretary_core::crypto::kem::MlKem768Secret,
        ),
        ReaderSecretKeysError,
    > {
        use secretary_core::crypto::kem;
        use secretary_core::crypto::secret::Sensitive;
        use zeroize::Zeroize as _;

        let guard = lock_or_recover(&self.inner);
        let id = guard.as_ref().ok_or(ReaderSecretKeysError::HandleClosed)?;

        // X25519: copy the 32 bytes onto the stack, mint a Sensitive,
        // then zeroize the stack copy. Mirrors the same discipline as
        // `crate::vault::split_core_open_vault`.
        let mut x_sk_bytes: [u8; 32] = *id.identity.x25519_sk.expose();
        let x_sk: kem::X25519Secret = Sensitive::new(x_sk_bytes);
        x_sk_bytes.zeroize();

        // ML-KEM-768: from_bytes returns Result<_, KemError>. The bundle
        // was already validated at unlock-time (core::unlock checks the
        // length on decode), so a failure here is structurally impossible
        // unless the in-memory bundle was corrupted post-unlock. We
        // surface this distinctly from the closed-handle case so the
        // orchestrator's CorruptVault detail string isn't misleading.
        let pq_sk = kem::MlKem768Secret::from_bytes(id.identity.ml_kem_768_sk.expose())
            .map_err(|_| ReaderSecretKeysError::MlKem768ParseFailed)?;

        Ok((x_sk, pq_sk))
    }

    /// Bridge-internal: produce an owned [`IdentityBundle`] copy so the
    /// save orchestrator can construct a temporary `core::OpenVault`.
    /// Returns `None` if the handle has been wiped.
    ///
    /// `IdentityBundle` deliberately does NOT derive `Clone` (secret
    /// material should not be silently duplicated). This helper performs
    /// the field-by-field copy explicitly, wrapping each secret in a
    /// fresh `Sensitive` slot so the clone has its own zeroize-on-drop.
    /// Total wall-clock exposure of the duplicated secret material is
    /// the lifetime of one `save_block` call (~5ms) before the temp
    /// `OpenVault` drops.
    ///
    /// NOT exposed through PyO3 / uniffi — used only by
    /// `crate::save::save_block`.
    #[allow(dead_code)] // consumed by crate::save::save_block in Task 2
    pub(crate) fn clone_inner_bundle(
        &self,
    ) -> Option<secretary_core::unlock::bundle::IdentityBundle> {
        use secretary_core::crypto::secret::Sensitive;
        use secretary_core::unlock::bundle::IdentityBundle;

        let guard = lock_or_recover(&self.inner);
        let id = guard.as_ref()?;
        let b = &id.identity;
        Some(IdentityBundle {
            user_uuid: b.user_uuid,
            display_name: b.display_name.clone(),
            x25519_sk: Sensitive::new(*b.x25519_sk.expose()),
            x25519_pk: b.x25519_pk,
            ml_kem_768_sk: Sensitive::new(b.ml_kem_768_sk.expose().to_vec()),
            ml_kem_768_pk: b.ml_kem_768_pk.clone(),
            ed25519_sk: Sensitive::new(*b.ed25519_sk.expose()),
            ed25519_pk: b.ed25519_pk,
            ml_dsa_65_sk: Sensitive::new(b.ml_dsa_65_sk.expose().to_vec()),
            ml_dsa_65_pk: b.ml_dsa_65_pk.clone(),
            created_at_ms: b.created_at_ms,
        })
    }
}

/// Bridge-internal failure mode for [`UnlockedIdentity::reader_secret_keys`].
/// Lets the orchestrator distinguish a wiped handle (legitimate user
/// action) from an in-memory ML-KEM-768 parse failure (structurally
/// impossible — implies post-unlock memory corruption) when surfacing
/// the failure as `FfiVaultError::CorruptVault`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReaderSecretKeysError {
    /// The identity handle has been wiped. Variant name retains
    /// `HandleClosed` for backwards compatibility with the orchestrator's
    /// existing match arms; semantically equivalent to "handle wiped".
    HandleClosed,
    /// ML-KEM-768 secret key parse failed on bytes that were already
    /// validated at unlock-time. Structurally impossible — surfacing
    /// distinctly so the diagnostic string can flag the in-memory
    /// corruption hypothesis to the foreign caller.
    MlKem768ParseFailed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    use secretary_core::crypto::kdf::Argon2idParams;
    use secretary_core::crypto::secret::SecretBytes;
    use secretary_core::unlock::create_vault_unchecked;

    /// Helper: build a fresh UnlockedIdentity by creating + opening a
    /// throwaway vault. Keeps the test isolated from the on-disk fixtures
    /// (which are exercised by the integration tests in unlock.rs).
    fn fresh_unlocked_identity() -> UnlockedIdentity {
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
        let password = SecretBytes::new(b"hunter2".to_vec());
        let params = Argon2idParams::new(8, 1, 1);
        let v = create_vault_unchecked(&password, "TestUser", 0, params, &mut rng).unwrap();
        let opened = secretary_core::unlock::open_with_password(
            &v.vault_toml_bytes,
            &v.identity_bundle_bytes,
            &password,
        )
        .unwrap();
        UnlockedIdentity::new(opened)
    }

    #[test]
    fn display_name_returns_unlocked_identity_display_name() {
        let id = fresh_unlocked_identity();
        assert_eq!(id.display_name(), "TestUser");
    }

    #[test]
    fn user_uuid_returns_16_bytes() {
        let id = fresh_unlocked_identity();
        let uuid = id.user_uuid();
        assert_eq!(uuid.len(), 16);
    }

    #[test]
    fn wipe_then_display_name_returns_empty() {
        let id = fresh_unlocked_identity();
        id.wipe();
        assert_eq!(id.display_name(), "");
    }

    #[test]
    fn wipe_then_user_uuid_returns_zero_bytes() {
        let id = fresh_unlocked_identity();
        id.wipe();
        assert_eq!(id.user_uuid(), vec![0u8; 16]);
    }

    #[test]
    fn is_wiped_transitions_false_to_true_on_wipe() {
        // #362: is_wiped lets a read-only consumer distinguish a wiped handle
        // from a genuine value before acting on user_uuid()'s safe default.
        let id = fresh_unlocked_identity();
        assert!(!id.is_wiped());
        id.wipe();
        assert!(id.is_wiped());
        id.wipe(); // idempotent
        assert!(id.is_wiped());
    }

    #[test]
    fn reader_secret_keys_after_wipe_returns_handle_closed() {
        // Pin the typed-error contract: a wiped handle surfaces as
        // ReaderSecretKeysError::HandleClosed (not collapsed with the
        // structurally-impossible MlKem768ParseFailed case). The
        // orchestrator depends on this distinction to attach a
        // non-misleading CorruptVault.detail.
        let id = fresh_unlocked_identity();
        id.wipe();
        assert_eq!(
            id.reader_secret_keys().err(),
            Some(ReaderSecretKeysError::HandleClosed),
        );
    }

    #[test]
    fn reader_secret_keys_when_live_returns_ok_tuple() {
        // Positive path: live handle returns Ok((X25519, MlKem768)). The
        // bytes-equality check is intentionally NOT performed here — the
        // returned types are Sensitive-wrapped and don't expose Eq; we
        // only need to know the call succeeds.
        let id = fresh_unlocked_identity();
        assert!(id.reader_secret_keys().is_ok());
    }

    #[test]
    fn wipe_is_idempotent() {
        let id = fresh_unlocked_identity();
        id.wipe();
        id.wipe(); // second call must not panic
        id.wipe(); // third call must not panic
        assert_eq!(id.display_name(), "");
    }

    #[test]
    fn accessors_fall_through_mutex_poisoning_without_panicking() {
        // Module docs promise non-throwing accessors. A panic anywhere
        // holding the inner Mutex's guard would otherwise poison it and
        // turn every subsequent accessor into a panic via the original
        // `.expect("UnlockedIdentity mutex poisoned")`. The
        // `lock_or_recover` helper makes the guard recoverable so this
        // test exercises the contract: poison the mutex, then verify
        // accessors still return the expected values.
        use std::sync::Arc;
        use std::thread;

        let id = Arc::new(fresh_unlocked_identity());
        let id_clone = Arc::clone(&id);

        // Force poisoning by panicking inside a thread that holds the
        // guard. We reach into the mutex directly via a helper to lock
        // it in the same shape `lock_or_recover` does, then trigger a
        // panic while the guard is alive.
        let _ = thread::spawn(move || {
            let _guard = id_clone.inner.lock().unwrap();
            panic!("intentional poison for test");
        })
        .join();

        // Mutex is now poisoned. With `lock_or_recover`, accessors must
        // still return live values (the inner Option<...> wasn't mutated
        // by the panicking thread) and must not panic.
        assert_eq!(id.display_name(), "TestUser");
        assert_eq!(id.user_uuid().len(), 16);
        // wipe() must not panic on a poisoned mutex either.
        id.wipe();
        assert_eq!(id.display_name(), "");
        assert_eq!(id.user_uuid(), vec![0u8; 16]);
    }

    #[test]
    fn accessors_thread_safe_with_wipe() {
        // Smoke test: spawn a reader thread; main thread wipes; reader
        // gets a valid (possibly empty) string, never a panic.
        use std::sync::Arc;
        let id = Arc::new(fresh_unlocked_identity());
        let id2 = Arc::clone(&id);
        let handle = std::thread::spawn(move || {
            for _ in 0..1000 {
                let _ = id2.display_name();
            }
        });
        for _ in 0..500 {
            let _ = id.display_name();
        }
        id.wipe();
        handle.join().expect("reader thread panicked");
        // Post-join, all accessors return defaults.
        assert_eq!(id.display_name(), "");
        assert_eq!(id.user_uuid(), vec![0u8; 16]);
    }
}
