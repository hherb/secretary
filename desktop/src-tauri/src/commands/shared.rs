//! Helpers shared across command modules.

use std::sync::{Mutex, MutexGuard};

use crate::errors::AppError;
use crate::session::VaultSession;

/// Parse a 32-char hex string into a 16-byte UUID. Bad hex folds to
/// `Internal` — the frontend only ever passes hex it received from a DTO.
pub(crate) fn parse_uuid_16(hex_str: &str) -> Result<[u8; 16], AppError> {
    let bytes = hex::decode(hex_str).map_err(|e| AppError::Internal {
        detail: format!("invalid uuid hex {hex_str:?}: {e}"),
    })?;
    bytes.try_into().map_err(|_| AppError::Internal {
        detail: format!("uuid hex {hex_str:?} is not 16 bytes"),
    })
}

/// Lock the session mutex, folding a poisoned lock to `Internal`. Shared by
/// every command `*_impl`. A poisoned mutex means a prior handler panicked
/// while holding the session lock — unrecoverable, so it surfaces as a typed
/// `Internal` rather than propagating the panic.
pub(crate) fn lock_session(
    state: &Mutex<VaultSession>,
) -> Result<MutexGuard<'_, VaultSession>, AppError> {
    state.lock().map_err(|e| AppError::Internal {
        detail: format!("session mutex poisoned: {e}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::VaultSession;
    use std::sync::{Arc, Mutex};

    #[test]
    fn lock_session_yields_a_guard_on_a_healthy_mutex() {
        // A non-poisoned session mutex locks cleanly; the guard derefs to the
        // session (here: the locked default state — no unlocked identity).
        let state = Mutex::new(VaultSession::new(std::env::temp_dir()));
        let guard = lock_session(&state).expect("healthy mutex must lock");
        // Touching the guard proves we got the real session back, not an error.
        let _ = &*guard;
    }

    #[test]
    fn lock_session_folds_poisoned_mutex_to_internal() {
        // The poison branch is the only observable divergence from a raw
        // `.lock().unwrap()` — and the whole reason the helper exists. Poison
        // the mutex by panicking a thread while it holds the guard, then assert
        // the typed Internal error (not a propagated panic).
        let state = Arc::new(Mutex::new(VaultSession::new(std::env::temp_dir())));
        let state2 = Arc::clone(&state);
        let _ = std::thread::spawn(move || {
            let _guard = state2.lock().unwrap();
            panic!("deliberate poison");
        })
        .join(); // Err(panicked)
        let result = lock_session(&state);
        assert!(result.is_err(), "poisoned mutex must error");
        let err = result.err().unwrap();
        assert!(
            matches!(err, AppError::Internal { ref detail } if detail.contains("session mutex poisoned")),
            "unexpected error: {err:?}"
        );
    }
}
