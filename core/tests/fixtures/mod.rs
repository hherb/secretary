//! Shared test fixtures used by the C.1 sync integration tests.
//! Re-uses the golden_vault_001 inputs JSON sourced by the existing
//! golden_vault_001 integration test.

use std::path::{Path, PathBuf};

use secretary_core::crypto::secret::SecretBytes;
use serde::Deserialize;

/// Mirrors the relevant subset of `Inputs` in
/// `core/tests/data/golden_vault_001_inputs.json`. Only the
/// `password` field is exposed via the public function below so
/// callers don't depend on the JSON's full shape.
#[derive(Deserialize)]
struct Inputs {
    password: String,
}

fn inputs_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("data");
    p.push("golden_vault_001_inputs.json");
    p
}

/// Loads the fixture password from `golden_vault_001_inputs.json` and
/// wraps it in a `SecretBytes` for `open_with_password`.
pub fn golden_vault_001_password() -> SecretBytes {
    let raw =
        std::fs::read_to_string(inputs_path()).expect("golden_vault_001_inputs.json must exist");
    let inputs: Inputs =
        serde_json::from_str(&raw).expect("golden_vault_001_inputs.json must be valid JSON");
    SecretBytes::new(inputs.password.into_bytes())
}

/// Decode the `vault_uuid` from a vault folder's `vault.toml`. Pinned
/// in the golden_vault_001 fixture builder; any drift surfaces here as
/// a decode failure rather than a hard-coded mismatch in callers.
///
/// Shared by the C.1 sync integration tests (`sync.rs`, `sync_ingest.rs`,
/// `sync_ingest_proptest.rs`, `sync_merge.rs`, `sync_merge_vetoes.rs`)
/// which all need the vault's UUID to build a `SyncState` bound to it.
///
/// `#[allow(dead_code)]` because `core/tests/fixtures/mod.rs` is compiled
/// once per `tests/*.rs` test binary; binaries that import the module
/// only for [`golden_vault_001_password`] (e.g. `open_vault.rs`) would
/// see this function as unused.
#[allow(dead_code)]
pub fn extract_vault_uuid(folder: &Path) -> [u8; 16] {
    let s = std::fs::read_to_string(folder.join("vault.toml"))
        .expect("vault.toml must exist in fixture folder");
    let vt = secretary_core::unlock::vault_toml::decode(&s).expect("decode vault.toml");
    vt.vault_uuid
}
