//! Secretary desktop client — Tauri 2 main entry point.
//!
//! D.1.1 walking skeleton. Modules (`auto_lock`, `commands`, `constants`,
//! `dtos`, `errors`, `session`, `settings`) live in the sibling library
//! crate ([`secretary_desktop`]) so integration tests in `tests/*.rs`
//! can reach them. Task 4 wires the [`commands`] surface into the Tauri
//! `invoke_handler`; Task 5 will spawn the auto-lock timer thread.

// Hide the console window on Windows in release builds. Cosmetic for D.1.1
// but the macro is canonical Tauri practice — keep it from day one.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Mutex;

use secretary_desktop::commands::{lock, settings, unlock, vault};
use secretary_desktop::session::VaultSession;

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
        .manage(Mutex::new(VaultSession::new(device_data_dir)))
        .invoke_handler(tauri::generate_handler![
            unlock::unlock_with_password,
            vault::list_blocks,
            vault::get_manifest,
            settings::get_settings,
            settings::set_settings,
            lock::lock,
            lock::notify_activity,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Secretary tauri application");
}
