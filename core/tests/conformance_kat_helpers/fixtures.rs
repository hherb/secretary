//! Path resolvers + KAT vector input-resolution helpers.

use std::path::PathBuf;

pub fn kat_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("conformance_kat.json")
}

pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
}

/// Resolves a `*_source` style input (e.g. `golden_vault_001_inputs.json:password`)
/// to its concrete bytes. Returns the UTF-8 bytes of the named JSON string field.
pub fn resolve_source(source: &str) -> Vec<u8> {
    let (file, field) = source
        .split_once(':')
        .unwrap_or_else(|| panic!("malformed source ref: {source}"));
    let path = fixtures_dir().join(file);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    let json: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()));
    let value = json
        .get(field)
        .unwrap_or_else(|| panic!("field '{field}' missing in {}", path.display()));
    value
        .as_str()
        .unwrap_or_else(|| panic!("field '{field}' in {} is not a string", path.display()))
        .as_bytes()
        .to_vec()
}

pub fn resolve_vault_dir(inputs: &serde_json::Value) -> PathBuf {
    if let Some(s) = inputs.get("vault_dir").and_then(|v| v.as_str()) {
        return fixtures_dir().join(s);
    }
    if let Some(s) = inputs.get("vault_dir_literal").and_then(|v| v.as_str()) {
        return PathBuf::from(s);
    }
    panic!(
        "inputs must carry one of vault_dir / vault_dir_literal: {}",
        inputs
    );
}

pub fn resolve_password(inputs: &serde_json::Value) -> Vec<u8> {
    if let Some(s) = inputs.get("password_source").and_then(|v| v.as_str()) {
        return resolve_source(s);
    }
    if let Some(s) = inputs.get("password_literal_utf8").and_then(|v| v.as_str()) {
        return s.as_bytes().to_vec();
    }
    panic!("open_vault_with_password vector missing password_* input");
}

pub fn resolve_mnemonic(inputs: &serde_json::Value) -> Vec<u8> {
    if let Some(s) = inputs.get("mnemonic_source").and_then(|v| v.as_str()) {
        return resolve_source(s);
    }
    if let Some(s) = inputs.get("mnemonic_literal_utf8").and_then(|v| v.as_str()) {
        return s.as_bytes().to_vec();
    }
    panic!("open_vault_with_recovery vector missing mnemonic_* input");
}
