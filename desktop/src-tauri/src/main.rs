//! Secretary desktop client — Tauri 2 main entry point.
//!
//! D.1.1 walking skeleton. Modules (`auto_lock`, `commands`, `constants`,
//! `dtos`, `errors`, `session`, `settings`, `timer`) live in the sibling
//! library crate ([`secretary_desktop`]) so integration tests in
//! `tests/*.rs` can reach them. Task 4 wired the [`commands`] surface
//! into the Tauri `invoke_handler`; Task 5 adds the auto-lock timer
//! thread spawned from `Builder::setup`.

// Hide the console window on Windows in release builds. Cosmetic for D.1.1
// but the macro is canonical Tauri practice — keep it from day one.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use tauri::{Emitter, Manager};

use secretary_desktop::commands::lock::{
    vault_locked_payload, LOCK_REASON_AUTO, VAULT_LOCKED_EVENT,
};
use secretary_desktop::commands::{
    browse, contacts, create, delete, edit, lock, pick, reauth, settings, sync, unlock, vault,
};
use secretary_desktop::constants::AUTO_LOCK_TICK_MS;
use secretary_desktop::session::VaultSession;
use secretary_desktop::timer::{poison_should_log, tick, TickOutcome};

fn main() {
    // Init `tracing` subscriber for structured logs on stderr. Developer-
    // facing `detail` fields stripped from `AppError` at the IPC seam are
    // still logged at `warn` level here so they're visible to whoever is
    // running the desktop binary from a terminal. The env-filter falls
    // back to "info" if `RUST_LOG` is unset — quiet by default.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    // Resolve the platform-canonical data directory once at startup.
    // `dirs::data_dir()` returns `~/Library/Application Support` on macOS,
    // `~/.local/share` on Linux, `%APPDATA%` on Windows. The per-vault
    // device-UUID files land under `<data_dir>/secretary-desktop/devices/`
    // (see [`secretary_desktop::settings::load_or_create_device_uuid_in`]).
    //
    // Panicking here is appropriate: every platform we ship on (macOS,
    // Linux, Windows) returns `Some` for `data_dir()`; a `None` would
    // mean the user is running on an unsupported / broken platform where
    // no amount of degraded behaviour would be helpful.
    let device_data_dir = dirs::data_dir().expect(
        "platform data_dir() must return Some on macOS/Linux/Windows; \
         secretary-desktop cannot run without a persistent data directory",
    );

    tauri::Builder::default()
        // The dialog plugin powers `PathPicker.svelte`'s native folder-
        // selection dialog (frontend opens it via
        // `@tauri-apps/plugin-dialog`). Permissions for the JS side are
        // granted by `capabilities/default.json` (`dialog:allow-open`).
        .plugin(tauri_plugin_dialog::init())
        // The clipboard-manager plugin exposes the WRITE side of the OS
        // clipboard to the frontend's "copy secret" affordance. The JS
        // companion (`@tauri-apps/plugin-clipboard-manager`) is already
        // installed in `desktop/package.json`. WRITE-ONLY: the capability
        // in `capabilities/default.json` grants only
        // `clipboard-manager:allow-write-text`; no read permission is
        // issued — reading the clipboard is a sensitive capability for a
        // secrets manager.
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(Mutex::new(VaultSession::new(device_data_dir)))
        .invoke_handler(tauri::generate_handler![
            unlock::unlock_with_password,
            vault::list_blocks,
            vault::get_manifest,
            settings::get_settings,
            settings::set_settings,
            lock::lock,
            lock::notify_activity,
            browse::read_block,
            browse::reveal_field,
            create::create_vault,
            create::probe_create_target,
            pick::pick_vault_folder,
            pick::pick_contact_card,
            pick::pick_export_dir,
            edit::create_block,
            edit::rename_block,
            edit::save_record,
            edit::save_record_edit,
            edit::reveal_record,
            edit::move_record,
            delete::tombstone_record,
            delete::resurrect_record,
            delete::trash_block,
            delete::restore_block,
            delete::list_trashed_blocks,
            contacts::list_contacts,
            contacts::import_contact,
            contacts::share_block,
            contacts::revoke_block_from,
            contacts::export_contact_card,
            contacts::delete_contact_card,
            contacts::block_recipients,
            contacts::list_contact_blocks,
            sync::sync_status,
            sync::sync_now,
            sync::sync_commit_decisions,
            reauth::verify_password,
        ])
        .setup(|app| {
            // Spawn the auto-lock timer thread. It lives for the lifetime of
            // the process — the OS reclaims it on exit. No graceful join:
            // the thread sleeps between ticks and the body is pure (no
            // external resource that would leak), so abrupt termination
            // is fine for the D.1.1 walking skeleton.
            //
            // The `AppHandle` is `Clone` and cheap; it carries the state
            // manager so the thread can fetch the `Mutex<VaultSession>`
            // each tick.
            let app_handle = app.handle().clone();
            thread::Builder::new()
                .name("secretary-auto-lock-timer".to_string())
                .spawn(move || auto_lock_timer_loop(app_handle))
                .expect("OS must allow spawning the auto-lock timer thread");
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running Secretary tauri application");
}

/// OS thread that drives [`tick`] on a fixed interval. On
/// [`TickOutcome::AutoLocked`] emits the `vault-locked` Tauri event with
/// `{ "reason": "auto" }` so the frontend can render its toast.
///
/// Pulled out as a free function so the `setup` closure stays terse and the
/// loop body is easy to read top-down.
fn auto_lock_timer_loop(app: tauri::AppHandle) {
    let tick_interval = Duration::from_millis(AUTO_LOCK_TICK_MS);
    // One-shot latch: a poisoned session mutex stays poisoned for the life of
    // the process, so logging on every tick would spam `error!` once per
    // interval forever. Log the first time we observe `Poisoned`, then stay
    // quiet (#147).
    let mut poison_logged = false;
    loop {
        // Sleep *before* the first tick — at startup the session is always
        // locked, so an immediate first tick would be a wasted lock-and-
        // check. The 5 s startup grace also keeps a transiently slow boot
        // from racing the timer against `manage()`'s state registration.
        thread::sleep(tick_interval);

        let state = app.state::<Mutex<VaultSession>>();
        match tick(&state) {
            TickOutcome::AutoLocked => {
                emit_vault_locked(&app, "from auto-lock timer");
            }
            TickOutcome::PoisonedLocked => {
                // The mutex was poisoned while a vault was unlocked; `tick`
                // fail-secure force-locked it this tick. Tell the frontend so it
                // reflects the locked state, and log the underlying fault once.
                // The transition can only happen once (the session is `None`
                // afterwards), so this emit is not part of the anti-spam latch.
                emit_vault_locked(&app, "after poison force-lock");
                if poison_should_log(&mut poison_logged) {
                    tracing::error!(
                        "session mutex poisoned (a prior handler panicked while a vault was \
                         unlocked); vault force-locked, auto-lock timer cannot make progress \
                         until the process restarts"
                    );
                }
            }
            TickOutcome::Poisoned => {
                if poison_should_log(&mut poison_logged) {
                    tracing::error!(
                        "session mutex poisoned (a prior handler panicked while locked); \
                         auto-lock timer cannot make progress until the process restarts"
                    );
                }
            }
            TickOutcome::NoAction | TickOutcome::Skipped => {
                // No-op: either the session is still active, or another
                // command holds the mutex and we'll retry next tick.
            }
        }
    }
}

/// Emit the `vault-locked` Tauri event (`{ "reason": "auto" }`) from the timer
/// thread, logging a single `error!` if the emit fails. The `AutoLocked` and
/// `PoisonedLocked` tick outcomes share this path; `on_failure` names the
/// originating outcome so a failed emit is still attributable in the logs.
fn emit_vault_locked(app: &tauri::AppHandle, on_failure: &str) {
    if let Err(e) = app.emit(VAULT_LOCKED_EVENT, vault_locked_payload(LOCK_REASON_AUTO)) {
        tracing::error!(
            error = %e,
            outcome = on_failure,
            "failed to emit vault-locked event"
        );
    }
}
