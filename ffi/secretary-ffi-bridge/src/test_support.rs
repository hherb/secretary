//! Crate-wide `#[cfg(test)]` fixtures (#186): the golden-vault staging
//! helpers shared by every bridge unit-test module. Integration tests under
//! `tests/` cannot see this module (it is `cfg(test)`-gated on the lib
//! target); they use `secretary-test-utils` directly plus their own thin
//! open wrappers.
#![cfg(test)]

use std::path::PathBuf;

use secretary_test_utils::{copy_dir_to_tempdir, core_test_data_dir};

use crate::{open_vault_with_password, OpenVaultOutput};

/// Pinned password for `golden_vault_001` (kept honest by
/// [`vault_001_password_matches_inputs_json`] below, which asserts it
/// against the fixture's inputs JSON on every test run).
pub(crate) const VAULT_001_PASSWORD: &[u8] = b"correct horse battery staple";

/// Path to a committed fixture folder under `core/tests/data/`.
pub(crate) fn fixture_folder(name: &str) -> PathBuf {
    core_test_data_dir().join(name)
}

/// Open a writable copy of golden_vault_001 in a fresh tempdir. The tempdir
/// is returned so the caller keeps it alive for the test.
pub(crate) fn open_writable_golden_001() -> (tempfile::TempDir, OpenVaultOutput) {
    let tmp = copy_dir_to_tempdir(&fixture_folder("golden_vault_001"));
    let out = open_vault_with_password(tmp.path(), VAULT_001_PASSWORD)
        .expect("open writable copy of golden_vault_001");
    (tmp, out)
}

/// Drift detection for [`VAULT_001_PASSWORD`]: the pinned const must equal
/// the password recorded in `golden_vault_001_inputs.json` (the fixture's
/// source of truth). A fixture regeneration that changes the password fails
/// here with a direct message instead of as N opaque wrong-password errors.
#[test]
fn vault_001_password_matches_inputs_json() {
    assert_eq!(
        VAULT_001_PASSWORD,
        secretary_test_utils::golden_vault_001_password().as_slice(),
        "VAULT_001_PASSWORD drifted from golden_vault_001_inputs.json"
    );
}
