//! Secretary desktop client — Tauri 2 main entry point.
//!
//! D.1.1 walking skeleton. The modules (`auto_lock`, `constants`, `errors`,
//! `session`, `settings`) live in the sibling library crate
//! ([`secretary_desktop`]) so integration tests in `tests/*.rs` can reach
//! them. Tauri command handlers (Task 4) and the auto-lock timer thread
//! (Task 5) wire those modules into the Builder pipeline below.

// Hide the console window on Windows in release builds. Cosmetic for D.1.1
// but the macro is canonical Tauri practice — keep it from day one.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running Secretary tauri application");
}
