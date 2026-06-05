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

use crate::commands::shared::lock_session;
use crate::errors::AppError;
use crate::session::VaultSession;

/// Tauri event name emitted whenever the session transitions from
/// unlocked → locked. The payload distinguishes explicit (user-initiated)
/// from auto (timer-driven) so the frontend toast can phrase differently.
pub const VAULT_LOCKED_EVENT: &str = "vault-locked";

/// Reason string for the `vault-locked` event payload when the user
/// invoked `lock` explicitly.
pub const LOCK_REASON_EXPLICIT: &str = "explicit";

/// Reason string for the `vault-locked` event payload when the auto-lock
/// timer (see [`crate::timer`]) fires after the configured idle threshold.
/// The frontend toast phrases the two reasons differently.
pub const LOCK_REASON_AUTO: &str = "auto";

/// Build the `vault-locked` event payload for a given reason. Single
/// construction site so the wire format can be exercised by the unit
/// tests below and reused by every emit call (`commands::lock` for
/// explicit, `main::auto_lock_timer_loop` for auto). Without this, two
/// independent `serde_json::json!({...})` invocations would have to be
/// kept in lockstep by convention alone.
pub fn vault_locked_payload(reason: &str) -> serde_json::Value {
    serde_json::json!({ "reason": reason })
}

#[tauri::command]
pub async fn lock(state: State<'_, Mutex<VaultSession>>, app: AppHandle) -> Result<(), AppError> {
    let was_unlocked = lock_impl(state.inner())?;
    if was_unlocked {
        app.emit(
            VAULT_LOCKED_EVENT,
            vault_locked_payload(LOCK_REASON_EXPLICIT),
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
    let mut session = lock_session(state)?;
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
    let mut session = lock_session(state)?;
    session.notify_activity();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_locked_event_name_is_kebab_case() {
        // Pin the Tauri event name — Svelte's `listen('vault-locked', ...)`
        // (Task 6) depends on this exact string. A typo here is silent at
        // build time and only surfaces as a missed toast at runtime.
        assert_eq!(VAULT_LOCKED_EVENT, "vault-locked");
    }

    #[test]
    fn lock_reason_constants_match_frontend_discriminator() {
        // The frontend AppError-style discriminated union (Task 6) keys off
        // these literal strings. Pin both so a rename here can't desync
        // the wire format from the TS layer silently.
        assert_eq!(LOCK_REASON_EXPLICIT, "explicit");
        assert_eq!(LOCK_REASON_AUTO, "auto");
    }

    #[test]
    fn explicit_lock_event_payload_serializes_to_expected_json() {
        // Exercises the same `vault_locked_payload` helper the `lock`
        // command calls — so a typo in the production call site (e.g.,
        // renaming the JSON key) is caught here, not only in Task 6's
        // listener at runtime.
        assert_eq!(
            vault_locked_payload(LOCK_REASON_EXPLICIT).to_string(),
            r#"{"reason":"explicit"}"#
        );
    }

    #[test]
    fn auto_lock_event_payload_serializes_to_expected_json() {
        // Mirror of the explicit-reason test for the auto-lock path; the
        // timer thread in `main::auto_lock_timer_loop` (Task 5) calls
        // `vault_locked_payload(LOCK_REASON_AUTO)` so this same assertion
        // covers its emit body.
        assert_eq!(
            vault_locked_payload(LOCK_REASON_AUTO).to_string(),
            r#"{"reason":"auto"}"#
        );
    }
}
