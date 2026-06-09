//! Proves the explicit-`state_dir` sync seams are part of the crate's
//! PUBLIC API (the surface the uniffi/pyo3 bindings project). An
//! integration test compiles as a downstream crate, so referencing a
//! `pub(crate)` item here fails to compile — which is exactly the gate
//! we want on these three functions' visibility.

use secretary_ffi_bridge::{sync_commit_decisions_in, sync_status_in, sync_vault_in};
use tempfile::TempDir;

#[test]
fn sync_status_in_is_public_and_reports_no_state_on_empty_dir() {
    let dir = TempDir::new().unwrap();
    let status = sync_status_in(dir.path(), [3u8; 16]).expect("status");
    assert!(!status.has_state);
}

#[test]
fn sync_vault_in_and_commit_decisions_in_are_public_symbols() {
    // Compile-time reachability is the assertion; take fn pointers so the
    // names must resolve as `pub` without staging a full vault here
    // (behaviour is covered by the in-module unit tests + the Python suite).
    // `type_complexity` is expected here: the full fn-pointer signatures are
    // the point of the test (they prove exact public-API shape).
    #[allow(clippy::type_complexity)]
    let _v: fn(
        &std::path::Path,
        &std::path::Path,
        secretary_core::crypto::secret::SecretBytes,
        u64,
    ) -> Result<
        secretary_ffi_bridge::SyncOutcomeDto,
        secretary_ffi_bridge::FfiVaultError,
    > = sync_vault_in;
    #[allow(clippy::type_complexity)]
    let _c: fn(
        &std::path::Path,
        &std::path::Path,
        secretary_core::crypto::secret::SecretBytes,
        Vec<secretary_ffi_bridge::VetoDecisionDto>,
        Vec<u8>,
        u64,
    ) -> Result<
        secretary_ffi_bridge::SyncOutcomeDto,
        secretary_ffi_bridge::FfiVaultError,
    > = sync_commit_decisions_in;
}
