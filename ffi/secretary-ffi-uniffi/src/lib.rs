#![forbid(unsafe_code)]
//! uniffi binding stub. uniffi macros and the `.udl` file are intentionally
//! not wired up here yet — they belong with the iOS/Android client
//! sub-projects. This file exists so the workspace builds end-to-end.

/// Smoke test: returns the vault format version exposed by the core crate.
pub fn version() -> u16 {
    secretary_core::version::FORMAT_VERSION
}
