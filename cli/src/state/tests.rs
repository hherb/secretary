use super::*;
use tempfile::TempDir;

/// `canonical_hex` produces 32-char lowercase hex with no separator.
#[test]
fn canonical_hex_format() {
    let uuid = [0xab; 16];
    let hex = canonical_hex(uuid);
    assert_eq!(hex.len(), VAULT_UUID_HEX_LEN);
    assert_eq!(hex, "abababababababababababababababab");
}

/// `state_file_path` composes `<state-dir>/<hex>.state.cbor`.
#[test]
fn state_file_path_layout() {
    let dir = Path::new("/tmp/sync");
    let path = state_file_path(dir, [1; 16]);
    assert_eq!(
        path,
        PathBuf::from("/tmp/sync/01010101010101010101010101010101.state.cbor")
    );
}

/// `lock_file_path` composes `<state-dir>/<hex>.lock`.
#[test]
fn lock_file_path_layout() {
    let dir = Path::new("/tmp/sync");
    let path = lock_file_path(dir, [1; 16]);
    assert_eq!(
        path,
        PathBuf::from("/tmp/sync/01010101010101010101010101010101.lock")
    );
}

/// Load returns `SyncState::empty` when no file exists for the vault.
#[test]
fn load_missing_returns_empty() {
    let dir = TempDir::new().unwrap();
    let loaded = load(dir.path(), [9; 16]).unwrap();
    assert_eq!(loaded.vault_uuid, [9; 16]);
    assert!(loaded.highest_vector_clock_seen.is_empty());
}

/// Save + load round-trips byte-identically.
#[test]
fn save_load_roundtrip() {
    let dir = TempDir::new().unwrap();
    let state = SyncState::empty([7; 16]);
    save(dir.path(), &state).unwrap();
    let loaded = load(dir.path(), [7; 16]).unwrap();
    assert_eq!(loaded, state);
}

/// Loading a file whose internal vault_uuid mismatches the expected one
/// (e.g. operator copied a state file from a different vault) returns
/// the typed mismatch error.
#[test]
fn load_wrong_uuid_returns_mismatch_error() {
    let dir = TempDir::new().unwrap();
    let state = SyncState::empty([7; 16]);
    save(dir.path(), &state).unwrap();
    // Rename the file to make it look like the file for vault [9; 16].
    let from = state_file_path(dir.path(), [7; 16]);
    let to = state_file_path(dir.path(), [9; 16]);
    std::fs::rename(&from, &to).unwrap();
    let err = load(dir.path(), [9; 16]).unwrap_err();
    match err {
        StateError::VaultUuidMismatch {
            file_uuid_hex,
            expected_uuid_hex,
        } => {
            assert_eq!(file_uuid_hex, canonical_hex([7; 16]));
            assert_eq!(expected_uuid_hex, canonical_hex([9; 16]));
        }
        other => panic!("expected VaultUuidMismatch, got {other:?}"),
    }
}

/// First acquire succeeds; second concurrent acquire returns LockfileHeld.
#[test]
fn lockfile_collision_returns_held() {
    let dir = TempDir::new().unwrap();
    let _g1 = LockfileGuard::acquire(dir.path(), [3; 16]).expect("first acquire");
    let err = LockfileGuard::acquire(dir.path(), [3; 16]).unwrap_err();
    match err {
        StateError::LockfileHeld(path) => {
            assert_eq!(path, lock_file_path(dir.path(), [3; 16]));
        }
        other => panic!("expected LockfileHeld, got {other:?}"),
    }
}

/// Releasing the first guard (drop) allows a subsequent acquire to succeed.
#[test]
fn lockfile_releases_on_drop() {
    let dir = TempDir::new().unwrap();
    {
        let _g1 = LockfileGuard::acquire(dir.path(), [3; 16]).expect("first acquire");
    } // drop releases
    let _g2 = LockfileGuard::acquire(dir.path(), [3; 16]).expect("second acquire after first drop");
}

/// Different vault UUIDs do NOT collide on the lockfile (each vault
/// has its own lock).
#[test]
fn lockfile_different_vaults_dont_collide() {
    let dir = TempDir::new().unwrap();
    let _g1 = LockfileGuard::acquire(dir.path(), [3; 16]).expect("vault A");
    let _g2 = LockfileGuard::acquire(dir.path(), [4; 16]).expect("vault B");
}

/// `default_state_dir` returns Some on supported platforms; we only
/// assert it does not panic and that the path ends in `secretary/sync`
/// when returned.
#[test]
fn default_state_dir_ends_in_sync_subdir() {
    if let Some(dir) = default_state_dir() {
        assert!(
            dir.ends_with("secretary/sync"),
            "expected path ending in secretary/sync, got {dir:?}"
        );
    }
}

/// Loading a file that exists but holds non-CBOR bytes returns the
/// typed `Decode` error (and not e.g. `Io` or a panic). Exercises the
/// `StateError::Decode` arm directly.
#[test]
fn load_corrupt_bytes_returns_decode_error() {
    let dir = TempDir::new().unwrap();
    let path = state_file_path(dir.path(), [5; 16]);
    std::fs::write(&path, b"\xff\xff\xff\xff").unwrap();
    let err = load(dir.path(), [5; 16]).unwrap_err();
    assert!(
        matches!(err, StateError::Decode(_)),
        "expected Decode, got {err:?}"
    );
}

#[test]
fn is_within_detects_nested_and_rejects_sibling() {
    assert!(is_within(
        Path::new("/vault/sub/state"),
        Path::new("/vault")
    ));
    assert!(is_within(Path::new("/vault"), Path::new("/vault")));
    assert!(!is_within(Path::new("/other/state"), Path::new("/vault")));
}

#[test]
fn is_within_folds_parent_dir_escape() {
    // /vault/../else normalizes out of /vault.
    assert!(!is_within(Path::new("/vault/../else"), Path::new("/vault")));
}

#[test]
fn resolve_explicit_wins_even_if_no_os_default() {
    let got = resolve_state_dir(
        Some(PathBuf::from("/etc/secretary")),
        None,
        Path::new("/vault"),
    )
    .unwrap();
    assert_eq!(got, PathBuf::from("/etc/secretary"));
}

#[test]
fn resolve_falls_back_to_os_default() {
    let got = resolve_state_dir(
        None,
        Some(PathBuf::from("/home/u/.local")),
        Path::new("/vault"),
    )
    .unwrap();
    assert_eq!(got, PathBuf::from("/home/u/.local"));
}

#[test]
fn resolve_unresolvable_when_no_source() {
    let err = resolve_state_dir(None, None, Path::new("/vault")).unwrap_err();
    assert!(matches!(err, StateDirError::Unresolvable));
}

#[test]
fn resolve_rejects_state_dir_inside_vault() {
    let err = resolve_state_dir(
        Some(PathBuf::from("/vault/state")),
        None,
        Path::new("/vault"),
    )
    .unwrap_err();
    assert!(matches!(err, StateDirError::InsideVault { .. }));
}

#[cfg(unix)]
#[test]
fn create_dir_secure_sets_0700() {
    use std::os::unix::fs::PermissionsExt;
    let base = TempDir::new().unwrap();
    let dir = base.path().join("nested").join("sync");
    create_dir_secure(&dir).unwrap();
    let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, STATE_DIR_MODE);
}
