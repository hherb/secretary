//! `VaultSession` — the live cryptographic state holder.
//!
//! See spec §6 (vault session lifecycle) for the full state machine. The
//! disciplines this module enforces:
//!
//! - `UnlockedSession::Drop` calls `manifest.wipe()` BEFORE `identity.wipe()`
//!   so any signature material the manifest holds is gone before the
//!   identity keys themselves are zeroized.
//! - `unlock()` rejects with `AlreadyUnlocked` if a session is in progress.
//! - `notify_activity()` is a silent no-op when locked.
//! - `with_unlocked<F>(f)` is the only path commands have to reach into
//!   the unlocked state — borrows the manifest immutably, returns `f`'s
//!   output or `AppError::NotUnlocked`.
//! - `device_data_dir` is injected at construction time so integration
//!   tests can drive a `TempDir`; Task 4's main.rs wiring threads
//!   `dirs::data_dir().expect(...)` once at process startup.

use std::path::{Path, PathBuf};

use secretary_ffi_bridge::vault::open_vault_with_password;
use secretary_ffi_bridge::{OpenVaultManifest, UnlockedIdentity};

use crate::auto_lock::{now_ms, IdleTracker};
use crate::errors::{AppError, AppWarning};
use crate::settings::{self, Settings};

/// The complete unlocked-state bundle. `Drop` wipes both bridge handles in
/// the documented order. Never construct directly — only via
/// [`VaultSession::unlock`].
pub struct UnlockedSession {
    pub identity: UnlockedIdentity,
    pub manifest: OpenVaultManifest,
    pub settings: Settings,
    /// Persistent per-vault device UUID, loaded/generated on unlock from
    /// `<device_data_dir>/secretary-desktop/devices/<vault_uuid_hex>.dev`.
    /// Required by the bridge's `save_block` for vector-clock semantics.
    pub device_uuid: [u8; 16],
    /// Non-fatal warnings produced during unlock (clamped-on-load values,
    /// unknown settings version, settings record shape mismatch). Logged
    /// via `tracing::warn!` at unlock time so they're visible in stderr;
    /// also retained here so Task 4's IPC layer can surface them to the
    /// frontend as a banner without an extra vault read.
    pub pending_warnings: Vec<AppWarning>,
    /// Absolute path the vault was opened from. Needed by `sync_now` to call
    /// the bridge `sync_vault`, which takes a folder path (a different entry
    /// point than the manifest handle). Plain value, no secret material — the
    /// `Drop` order (manifest.wipe → identity.wipe) is unaffected.
    pub vault_folder: PathBuf,
}

impl Drop for UnlockedSession {
    fn drop(&mut self) {
        // Order matters: the manifest holds signature material that references
        // the identity (verified owner card, IBK clone). Wipe the manifest
        // first so its inner state is gone before the identity itself is
        // zeroized — keeps the bridge's per-handle zeroize-on-drop discipline
        // intact even under panics.
        //
        // Both `wipe()` calls take `&self` (the bridge handles use interior
        // mutability via `Mutex<Option<_>>`), so `Drop` taking `&mut self`
        // is more access than strictly needed but matches the standard
        // Rust idiom.
        self.manifest.wipe();
        self.identity.wipe();
        // `settings` and `device_uuid` are plain value types with no secret
        // material; default Drop is sufficient.
    }
}

/// Outer session state. Wraps `UnlockedSession` in an `Option` so the
/// locked state is `inner = None`. Task 4 will register this as
/// `tauri::State<Mutex<VaultSession>>`; the timer thread in Task 5 takes
/// the same mutex each tick to check `should_auto_lock`.
pub struct VaultSession {
    inner: Option<UnlockedSession>,
    idle: IdleTracker,
    /// Parent directory for per-vault device UUID files. Injected at
    /// construction time so integration tests can drive a `TempDir` rather
    /// than polluting `~/Library/Application Support/`. Production callers
    /// pass `dirs::data_dir().expect("platform data_dir")` at app startup.
    device_data_dir: PathBuf,
}

impl VaultSession {
    /// Build a fresh locked session that will store per-vault device UUIDs
    /// under `device_data_dir`. The directory does not need to exist yet —
    /// [`settings::load_or_create_device_uuid_in`] creates the
    /// `secretary-desktop/devices/` subtree on first save.
    pub fn new(device_data_dir: PathBuf) -> Self {
        Self {
            inner: None,
            idle: IdleTracker::new(now_ms()),
            device_data_dir,
        }
    }

    /// `true` while a vault is unlocked; `false` from construction and after
    /// every `lock()` / auto-lock.
    pub fn is_unlocked(&self) -> bool {
        self.inner.is_some()
    }

    /// Last UI-activity timestamp (Unix milliseconds). Stays valid across
    /// the locked/unlocked transition; the timer thread reads it under the
    /// session mutex each tick.
    pub fn last_activity_ms(&self) -> u64 {
        self.idle.last_activity_ms
    }

    /// Absolute folder the current vault was opened from, or `None` if locked.
    /// Used by `verify_password` to re-run `open_vault_with_password` against
    /// the same folder for write re-auth.
    pub fn vault_folder(&self) -> Option<std::path::PathBuf> {
        self.inner.as_ref().map(|u| u.vault_folder.clone())
    }

    /// Current settings, or `Settings::default()` if locked.
    ///
    /// Returning a defensive default on the locked path (rather than
    /// panicking) lets the IPC layer race-safely surface "current value"
    /// to the frontend without coordinating a lock-state check first;
    /// the locked-state value is never displayed in practice because the
    /// Settings dialog itself is gated on `is_unlocked`.
    pub fn current_settings(&self) -> Settings {
        self.inner.as_ref().map(|u| u.settings).unwrap_or_default()
    }

    /// Non-fatal warnings produced during the most recent unlock. Empty
    /// while locked or when the settings record was clean. Task 4 wires
    /// this through `#[tauri::command] get_pending_warnings` so the
    /// frontend can render a banner alongside the manifest view.
    pub fn pending_warnings(&self) -> Vec<AppWarning> {
        self.inner
            .as_ref()
            .map(|u| u.pending_warnings.clone())
            .unwrap_or_default()
    }

    /// Mark UI activity. Silent no-op when locked — the timer thread is
    /// the only thing reading `last_activity_ms` while locked, and it
    /// shouldn't observe "user is active" inputs after the vault is gone.
    pub fn notify_activity(&mut self) {
        if self.inner.is_some() {
            self.idle.notify(now_ms());
        }
    }

    /// Attempt to unlock with a password. On success, populates `inner` with
    /// the bridge handles + the per-vault device UUID + the loaded settings.
    /// On failure, leaves the session locked and returns the typed error.
    ///
    /// Settings load failures (corrupt record, unknown version, IO error
    /// reading the block) are logged via `tracing::warn!` and fall back to
    /// `Settings::default()` — a broken settings record must not block
    /// vault access, since the user's only recourse is the Settings dialog
    /// which is itself gated on a successful unlock.
    pub fn unlock(&mut self, folder: &Path, password: &[u8]) -> Result<(), AppError> {
        if self.inner.is_some() {
            return Err(AppError::AlreadyUnlocked);
        }

        let output = open_vault_with_password(folder, password)?;
        let vault_uuid_bytes = output.manifest.vault_uuid();
        let device_uuid =
            settings::load_or_create_device_uuid_in(&self.device_data_dir, &vault_uuid_bytes)?;

        let (settings_val, pending_warnings) =
            match settings::load_from_vault(&output.identity, &output.manifest) {
                Ok((s, warnings)) => {
                    for w in &warnings {
                        tracing::warn!(
                            warning = ?w,
                            "non-fatal settings load issue during unlock"
                        );
                    }
                    (s, warnings)
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "settings load failed during unlock; falling back to defaults"
                    );
                    (Settings::default(), Vec::new())
                }
            };

        self.inner = Some(UnlockedSession {
            identity: output.identity,
            manifest: output.manifest,
            settings: settings_val,
            device_uuid,
            pending_warnings,
            vault_folder: folder.to_path_buf(),
        });
        // Reset the idle tracker to "now" so an old (pre-unlock) timestamp
        // doesn't trigger an immediate auto-lock on the first timer tick.
        self.idle = IdleTracker::new(now_ms());
        Ok(())
    }

    /// Explicit lock — drops `inner`, triggering the `UnlockedSession` Drop
    /// chain (manifest.wipe → identity.wipe). Idempotent: locking an
    /// already-locked session is a no-op.
    pub fn lock(&mut self) {
        self.inner = None;
    }

    /// Persist new settings to the vault. Validates bounds via
    /// [`settings::save_to_vault`] (which calls
    /// `settings::validate_save_value` before the bridge's `save_block`);
    /// on success, updates the in-memory `inner.settings` to match disk.
    pub fn set_settings(&mut self, new_settings: &Settings) -> Result<(), AppError> {
        self.with_unlocked_mut(|u| {
            settings::save_to_vault(&u.identity, &u.manifest, u.device_uuid, new_settings)?;
            u.settings = *new_settings;
            Ok(())
        })
    }

    /// Check if the session should auto-lock now. Called by the timer thread
    /// (Task 5) under the session mutex each tick.
    pub fn should_auto_lock(&self, threshold_ms: u64) -> bool {
        self.is_unlocked() && self.idle.is_expired(threshold_ms, now_ms())
    }

    /// Run a closure with read access to the unlocked state. Returns
    /// [`AppError::NotUnlocked`] if the session is locked.
    pub fn with_unlocked<F, T>(&self, f: F) -> Result<T, AppError>
    where
        F: FnOnce(&UnlockedSession) -> Result<T, AppError>,
    {
        match &self.inner {
            Some(u) => f(u),
            None => Err(AppError::NotUnlocked),
        }
    }

    /// Mutable variant for save-path commands (settings persistence).
    /// Returns [`AppError::NotUnlocked`] if the session is locked.
    pub fn with_unlocked_mut<F, T>(&mut self, f: F) -> Result<T, AppError>
    where
        F: FnOnce(&mut UnlockedSession) -> Result<T, AppError>,
    {
        match &mut self.inner {
            Some(u) => f(u),
            None => Err(AppError::NotUnlocked),
        }
    }

    /// Test helper: rewind the idle tracker so the session is expired against
    /// any positive `threshold_ms`. Used by `tests/session_integration.rs`
    /// to drive the auto-lock timer's `AutoLocked` path without sleeping.
    ///
    /// `#[doc(hidden)] pub fn` is the project workaround for `#[cfg(test)]`
    /// items not reaching integration tests (they're a separate compilation
    /// unit). Production code must NEVER call this — the `_for_test` suffix
    /// is the only marker; the doc-hidden flag keeps it out of rustdoc.
    #[doc(hidden)]
    pub fn force_expire_idle_tracker_for_test(&mut self) {
        self.idle.last_activity_ms = 0;
    }
}
