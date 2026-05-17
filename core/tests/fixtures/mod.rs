//! Shared test fixtures used by the C.1 sync integration tests.
//! Re-uses the golden_vault_001 inputs JSON sourced by the existing
//! golden_vault_001 integration test.

use std::path::PathBuf;

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
    let raw = std::fs::read_to_string(inputs_path())
        .expect("golden_vault_001_inputs.json must exist");
    let inputs: Inputs =
        serde_json::from_str(&raw).expect("golden_vault_001_inputs.json must be valid JSON");
    SecretBytes::new(inputs.password.into_bytes())
}
