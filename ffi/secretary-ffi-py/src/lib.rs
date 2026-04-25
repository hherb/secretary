#![forbid(unsafe_code)]
//! PyO3 binding stub. PyO3 macros are intentionally not wired up here yet —
//! they belong with the desktop client sub-project. This file exists so the
//! workspace builds end-to-end and the FFI crate has a place to grow.

/// Smoke test: returns the vault format version exposed by the core crate.
pub fn version() -> u16 {
    secretary_core::version::FORMAT_VERSION
}
