//! Crate-private synchronization helpers.
//!
//! Centralizes patterns shared by the opaque-handle modules
//! ([`crate::identity`], [`crate::create`]) so the discipline lives in
//! one place. The module is declared `mod sync_helpers` (not `pub mod`)
//! in [`crate::lib`], so nothing here leaks past the bridge crate boundary.

use std::sync::{Mutex, MutexGuard, PoisonError};

/// Acquire the inner lock, **falling through poisoning** to preserve the
/// non-throwing API contract that opaque handles
/// ([`crate::identity::UnlockedIdentity`], [`crate::create::MnemonicOutput`])
/// promise to foreign callers.
///
/// A poisoned mutex would normally cause every accessor to panic,
/// contradicting the module-level promise that "accessor calls on a
/// closed handle return empty / zero values rather than panicking".
/// `into_inner` on the `PoisonError` recovers the guard so the caller
/// gets either the live state (if the panicking thread didn't leave
/// invariants broken) or `None` (if a wipe / close happened to run
/// mid-panic); in both cases the accessors fall through to defaults
/// rather than re-panicking.
pub(crate) fn lock_or_recover<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}
