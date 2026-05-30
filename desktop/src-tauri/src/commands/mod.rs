//! Tauri IPC command handlers.
//!
//! Each submodule defines one or two `#[tauri::command]` functions plus a
//! sibling `*_impl` helper that takes `&Mutex<VaultSession>` directly.
//! The split is deliberate:
//!
//! - The `#[tauri::command]` wrapper is a thin shell — extracts the state,
//!   the user-supplied arguments, optionally an `AppHandle` for event
//!   emission — and delegates to `*_impl`. Tauri's macro expansion is
//!   reachable only through the running runtime, so this layer is exercised
//!   by manual smoke + the eventual end-to-end Playwright run (D.1.2+).
//! - The `*_impl` helper is plain Rust: synchronous, takes a `&Mutex<...>`,
//!   returns `Result<T, AppError>`. Integration tests in
//!   `tests/ipc_integration.rs` drive these directly against the golden
//!   vault and against `tempfile::tempdir()` write-path vaults.
//!
//! This pattern is the project's chosen pragmatic alternative to
//! `tauri::test::mock_builder()` — see the Task 4 plan note. Pure
//! testable functions over runtime mocking; spec §5 still pins the wire
//! format via the DTO serde tests in [`crate::dtos`].

pub mod browse;
pub mod create;
pub mod edit;
pub mod lock;
pub mod settings;
pub mod unlock;
pub mod vault;
