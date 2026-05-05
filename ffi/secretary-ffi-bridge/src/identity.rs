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
//! [`UnlockedIdentity::close`] explicitly drops the wrapped identity now
//! (zeroizing all `Sensitive<...>` fields at exactly this moment instead
//! of waiting for foreign GC). It is **idempotent** — multiple calls do
//! not panic. Subsequent accessor calls on a closed handle return empty
//! / zero values rather than panicking, keeping the API non-throwing.
//! The non-throwing guarantee extends to a poisoned inner mutex via the
//! private `lock_or_recover` helper: a panic anywhere holding the guard
//! does not turn future accessors into panics.
//!
//! RAII is the safety net: when the foreign-side reference releases, the
//! Rust-side `Drop` cascade still runs.

use std::fmt;
use std::sync::{Mutex, MutexGuard, PoisonError};

/// Opaque handle to an unlocked vault identity. See [module docs](self).
pub struct UnlockedIdentity {
    /// Wrapped behind a `Mutex<Option<...>>` to provide:
    /// - **idempotent close** via `Option::take()`
    /// - **thread-safe accessors** (lock is short — clone a String or copy
    ///   16 bytes — for sub-microsecond read overhead)
    /// - **use-after-close non-throwing** semantics (`as_ref()` on `None`
    ///   yields default values via `unwrap_or_default()`)
    inner: Mutex<Option<secretary_core::unlock::UnlockedIdentity>>,
}

/// Acquire the inner lock, **falling through poisoning** to preserve the
/// non-throwing API contract. A poisoned mutex would normally cause every
/// accessor to panic, contradicting the module-level promise that "accessor
/// calls on a closed handle return empty / zero values rather than
/// panicking". `into_inner` on the `PoisonError` recovers the guard so the
/// caller gets either the live state (if the panicking thread didn't leave
/// invariants broken) or `None` (if `close()` happened to run mid-panic);
/// in both cases the accessors fall through to defaults rather than
/// re-panicking.
fn lock_or_recover<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Redacted Debug: never leak secret material through the fmt path.
impl fmt::Debug for UnlockedIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let is_closed = lock_or_recover(&self.inner).is_none();
        f.debug_struct("UnlockedIdentity")
            .field("closed", &is_closed)
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

    /// User-facing display name from the IdentityBundle. UTF-8.
    ///
    /// Returns `""` if the handle has been explicitly closed.
    pub fn display_name(&self) -> String {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|id| id.identity.display_name.clone())
            .unwrap_or_default()
    }

    /// 16-byte stable identifier from the IdentityBundle.
    ///
    /// Returns `vec![0u8; 16]` if the handle has been explicitly closed.
    pub fn user_uuid(&self) -> Vec<u8> {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|id| id.identity.user_uuid.to_vec())
            .unwrap_or_else(|| vec![0u8; 16])
    }

    /// Drop the wrapped identity now, zeroizing all `Sensitive<...>`
    /// fields at exactly this moment. **Idempotent** — multiple calls do
    /// not panic.
    pub fn close(&self) {
        let _drop = lock_or_recover(&self.inner).take();
        // _drop goes out of scope here → core::UnlockedIdentity drops →
        // Sensitive<...> ZeroizeOnDrop runs for every secret field.
    }
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
    fn close_then_display_name_returns_empty() {
        let id = fresh_unlocked_identity();
        id.close();
        assert_eq!(id.display_name(), "");
    }

    #[test]
    fn close_then_user_uuid_returns_zero_bytes() {
        let id = fresh_unlocked_identity();
        id.close();
        assert_eq!(id.user_uuid(), vec![0u8; 16]);
    }

    #[test]
    fn close_is_idempotent() {
        let id = fresh_unlocked_identity();
        id.close();
        id.close(); // second call must not panic
        id.close(); // third call must not panic
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
        // close() must not panic on a poisoned mutex either.
        id.close();
        assert_eq!(id.display_name(), "");
        assert_eq!(id.user_uuid(), vec![0u8; 16]);
    }

    #[test]
    fn accessors_thread_safe_with_close() {
        // Smoke test: spawn a reader thread; main thread closes; reader
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
        id.close();
        handle.join().expect("reader thread panicked");
        // Post-join, all accessors return defaults.
        assert_eq!(id.display_name(), "");
        assert_eq!(id.user_uuid(), vec![0u8; 16]);
    }
}
