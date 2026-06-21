// Frontend mirror of the desktop app's auto-lock-related constants. The
// canonical source is `desktop/src-tauri/src/constants.rs` (which itself
// mirrors spec §8 "Constants"); this file duplicates the values across
// the wire because the IPC layer doesn't carry constants. When changing
// any value here, change the matching Rust constant in lockstep — a
// drift would silently let the frontend allow values the backend then
// rejects with `AppError::SettingsOutOfRange`, surfacing as a confusing
// "out of range" error on a value the user just saw the UI accept.
//
// Naming intentionally matches the Rust side (`AUTO_LOCK_MIN_MS` etc.)
// so cross-language grep against `git log -S` works.

/** Milliseconds per minute. Used by SettingsDialog to convert between
 *  user-visible minutes (the input unit) and the wire-format ms (what
 *  the IPC sends + what the bounds are expressed in). */
export const MS_PER_MINUTE = 60_000;

/** Lower bound for `auto_lock_timeout_ms`. Mirrors
 *  `desktop/src-tauri/src/constants.rs::AUTO_LOCK_MIN_MS` (1 minute). */
export const AUTO_LOCK_MIN_MS = 60_000;

/** Upper bound for `auto_lock_timeout_ms`. Mirrors
 *  `desktop/src-tauri/src/constants.rs::AUTO_LOCK_MAX_MS` (24 hours).
 *
 *  Anything longer is effectively "never auto-lock", a security
 *  antipattern we don't ship as configurable. */
export const AUTO_LOCK_MAX_MS = 86_400_000;

/** Default used when no Settings record exists (first-unlock case).
 *  Mirrors `desktop/src-tauri/src/constants.rs::AUTO_LOCK_DEFAULT_MS`
 *  (10 minutes). The frontend uses this as the SettingsDialog initial
 *  value when `currentSettings` is null (defence in depth — by the
 *  time the dialog opens, the manifest+settings have been loaded). */
export const AUTO_LOCK_DEFAULT_MS = 600_000;

/** How long a revealed field stays un-masked before auto-re-masking
 *  (shoulder-surfing defence). Frontend-only UX timer — no backend mirror.
 *  20 seconds: long enough to read/copy, short enough to limit exposure. */
export const REVEAL_AUTO_HIDE_MS = 20_000;

/** How long after a copy the clipboard is best-effort cleared. Frontend-only
 *  UX timer — no backend mirror. 30 seconds. */
export const CLIPBOARD_CLEAR_MS = 30_000;

/** Write re-auth grace window (password re-entry before a mutating write).
 *  Mirror of `desktop/src-tauri/src/constants.rs::REAUTH_WINDOW_DEFAULT_MS` — change both. */
export const REAUTH_WINDOW_DEFAULT_MS = 120_000;

/** Lower bound for `reauth_grace_window_ms`.
 *  Mirror of `desktop/src-tauri/src/constants.rs::REAUTH_WINDOW_MIN_MS` — change both. */
export const REAUTH_WINDOW_MIN_MS = 0;

/** Upper bound for `reauth_grace_window_ms`.
 *  Mirror of `desktop/src-tauri/src/constants.rs::REAUTH_WINDOW_MAX_MS` — change both. */
export const REAUTH_WINDOW_MAX_MS = 3_600_000;

/** Whether password re-auth before edits is required by default.
 *  Mirror of `desktop/src-tauri/src/constants.rs::REQUIRE_PASSWORD_DEFAULT` — change both.
 *  Secure-by-default: on. */
export const REQUIRE_PASSWORD_DEFAULT = true;
