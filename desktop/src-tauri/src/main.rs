//! Secretary desktop client — Tauri 2 main entry point.
//!
//! D.1.1 walking skeleton: minimal "hello world" window. The session,
//! commands, and timer thread land in later tasks per
//! `docs/superpowers/plans/2026-05-27-d11-tauri-walking-skeleton.md`.

// Hide the console window on Windows in release builds. Cosmetic for D.1.1
// but the macro is canonical Tauri practice — keep it from day one.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running Secretary tauri application");
}
