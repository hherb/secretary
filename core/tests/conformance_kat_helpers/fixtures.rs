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

use std::path::Path;

/// Recursively copy `src` into `dst`. Mirrors the established pattern
/// in `ffi/secretary-ffi-bridge/tests/save_block.rs` (`copy_dir_recursive`).
fn copy_dir_recursive(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap_or_else(|e| {
        panic!(
            "failed to create dst dir {}: {e}",
            dst.display()
        )
    });
    for entry in std::fs::read_dir(src)
        .unwrap_or_else(|e| panic!("failed to read src dir {}: {e}", src.display()))
    {
        let entry = entry.unwrap();
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let ft = entry.file_type().unwrap();
        if ft.is_dir() {
            copy_dir_recursive(&from, &to);
        } else {
            std::fs::copy(&from, &to).unwrap_or_else(|e| {
                panic!(
                    "failed to copy {} → {}: {e}",
                    from.display(),
                    to.display()
                )
            });
        }
    }
}

/// Copy `<fixtures_dir>/<vault_name>/` into a fresh `tempfile::TempDir`
/// and return the TempDir handle. The caller MUST hold the TempDir for
/// the duration of any subsequent operations against the copy — dropping
/// it removes the directory.
#[allow(dead_code)]
pub fn copy_vault_to_tempdir(vault_name: &str) -> tempfile::TempDir {
    let src = fixtures_dir().join(vault_name);
    let tmp = tempfile::tempdir().expect("tempdir for writable vault");
    copy_dir_recursive(&src, tmp.path());
    tmp
}

/// Read the canonical-CBOR bytes of a contact card from a vault's
/// `contacts/` directory. `user_uuid_hex` is 32 lowercase hex chars
/// (no separators). The card filename on disk is the uuid in 8-4-4-4-12
/// hyphenated form (matches `tempfile::TempDir`'s contents copied from
/// `golden_vault_001/contacts/`).
#[allow(dead_code)]
pub fn read_contact_card_bytes(vault_dir: &Path, user_uuid_hex: &str) -> Vec<u8> {
    assert_eq!(
        user_uuid_hex.len(),
        32,
        "user_uuid_hex must be 32 chars, got {}",
        user_uuid_hex.len()
    );
    // Reshape "bf08a3300cd994b877e1a15baa28df35"
    //      → "bf08a330-0cd9-94b8-77e1-a15baa28df35.card"
    let h = user_uuid_hex;
    let hyphenated = format!(
        "{}-{}-{}-{}-{}.card",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    );
    let path = vault_dir.join("contacts").join(&hyphenated);
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "failed to read contact card {}: {e}",
            path.display()
        )
    })
}
