//! `lock` + `notify_activity` commands.
//!
//! `lock` is a two-step operation: mutate the session under the mutex,
//! then (if and only if the session was previously unlocked) emit a
//! `vault-locked` event for the frontend to render its toast. The mutex
//! is released before `emit` to avoid blocking any concurrent commands
//! on the (potentially slow) event dispatch.
//!
//! `notify_activity` is a no-op when locked (per `VaultSession::notify_activity`
//! itself). Frontend debouncing at `ACTIVITY_NOTIFY_MIN_INTERVAL_MS` (2 s)
//! lands in Task 6; the Rust handler is intentionally cheap so per-call
//! cost is negligible even without it.
//!
//! Tauri event payload schema for `vault-locked`:
//! ```json
//! { "reason": "explicit" | "auto" }
//! ```
//! Task 5's auto-lock timer emits the same event with `reason: "auto"`.

use std::sync::Mutex;

use tauri::{AppHandle, Emitter, State};

use crate::errors::AppError;
use crate::session::VaultSession;

/// Tauri event name emitted whenever the session transitions from
/// unlocked → locked. The payload distinguishes explicit (user-initiated)
/// from auto (timer-driven) so the frontend toast can phrase differently.
pub const VAULT_LOCKED_EVENT: &str = "vault-locked";

/// Reason string for the `vault-locked` event payload when the user
/// invoked `lock` explicitly.
pub const LOCK_REASON_EXPLICIT: &str = "explicit";

#[tauri::command]
pub async fn lock(state: State<'_, Mutex<VaultSession>>, app: AppHandle) -> Result<(), AppError> {
    let was_unlocked = lock_impl(state.inner())?;
    if was_unlocked {
        app.emit(
            VAULT_LOCKED_EVENT,
            serde_json::json!({ "reason": LOCK_REASON_EXPLICIT }),
        )
        .map_err(|e| AppError::Internal {
            detail: format!("event emit failed: {e}"),
        })?;
    }
    Ok(())
}

#[tauri::command]
pub async fn notify_activity(state: State<'_, Mutex<VaultSession>>) -> Result<(), AppError> {
    notify_activity_impl(state.inner())
}

/// Testable core for `lock`. Returns `true` if the session was unlocked
/// before this call (so the wrapper knows whether to emit the event),
/// `false` if it was already locked (idempotent no-op).
pub fn lock_impl(state: &Mutex<VaultSession>) -> Result<bool, AppError> {
    let mut session = state.lock().map_err(|e| AppError::Internal {
        detail: format!("session mutex poisoned: {e}"),
    })?;
    let was_unlocked = session.is_unlocked();
    session.lock();
    Ok(was_unlocked)
}

/// Testable core for `notify_activity`. Forwards into
/// `VaultSession::notify_activity`, whose own contract is: advance the
/// idle tracker while unlocked, silent no-op while locked. The mutex
/// acquisition here is the IPC-state mutex, not a vault-state lock; the
/// session-side locked/unlocked guard happens inside the call.
pub fn notify_activity_impl(state: &Mutex<VaultSession>) -> Result<(), AppError> {
    let mut session = state.lock().map_err(|e| AppError::Internal {
        detail: format!("session mutex poisoned: {e}"),
    })?;
    session.notify_activity();
    Ok(())
}
