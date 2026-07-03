//! `repair_vault` command (#374).
//!
//! Mirrors `commands/unlock.rs::unlock_with_password` / `_impl`: the
//! `VaultFolder` approval gate runs first, then the plaintext-path
//! validation, then the actual bridge call under the session mutex. The one
//! shape difference from `unlock` is that repair needs the per-vault device
//! UUID *before* it can open the vault (the bridge's
//! `repair_vault_with_password` takes `device_uuid` as an input, not an
//! output) — see `VaultSession::repair`, which resolves it from `vault.toml`
//! via `read_vault_uuid_from_toml` up front.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use tauri::State;

use crate::commands::shared::lock_session;
use crate::commands::unlock::validate_vault_path;
use crate::dtos::ManifestDto;
use crate::errors::AppError;
use crate::path_auth::{MatchMode, PathPurpose};
use crate::secret_arg::Password;
use crate::session::VaultSession;

/// Read the plaintext `vault_uuid` field out of `<folder>/vault.toml` and
/// decode its canonical hyphenated form to 16 bytes.
///
/// Deliberately does NOT reuse `secretary_core::unlock::vault_toml::decode`:
/// that decoder requires the *full* `vault.toml` shape (`format_version`,
/// `suite_id`, `[kdf]` with a valid salt, ...) and errors on anything
/// missing — appropriate for the orchestrator's open path, but this call
/// site only needs the one field, before any bridge call has had a chance
/// to validate the rest of the file. Its internal hyphenated-UUID parser
/// (`parse_uuid_canonical`) is also private to that module, so it isn't
/// reachable from here without widening core's public surface — out of
/// scope for a desktop-only command. `parse_hyphenated_uuid` below is a
/// small local mirror of that same canonical-form check (36 bytes, hyphens
/// at 8/13/18/23, lowercase hex elsewhere).
pub(crate) fn read_vault_uuid_from_toml(folder: &Path) -> Result<[u8; 16], AppError> {
    let toml_path = folder.join("vault.toml");
    let text = std::fs::read_to_string(&toml_path).map_err(|e| AppError::Io {
        detail: format!("read vault.toml: {e}"),
    })?;
    let doc: toml::Value = text.parse().map_err(|e| AppError::VaultCorrupt {
        detail: format!("parse vault.toml: {e}"),
    })?;
    let uuid_str = doc
        .get("vault_uuid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::VaultCorrupt {
            detail: "vault.toml missing vault_uuid".into(),
        })?;
    parse_hyphenated_uuid(uuid_str).ok_or_else(|| AppError::VaultCorrupt {
        detail: "vault.toml vault_uuid malformed".into(),
    })
}

/// Decode the canonical RFC 4122 hyphenated textual UUID form
/// (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, lowercase hex) to 16 bytes.
/// Rejects any other length, grouping, or casing rather than guessing —
/// mirrors the strictness of core's (private) `vault_toml::parse_uuid_canonical`.
fn parse_hyphenated_uuid(s: &str) -> Option<[u8; 16]> {
    let b = s.as_bytes();
    if b.len() != 36 {
        return None;
    }
    for i in [8usize, 13, 18, 23] {
        if b[i] != b'-' {
            return None;
        }
    }
    let mut out = [0u8; 16];
    let mut byte_idx = 0;
    let mut i = 0;
    while i < b.len() {
        if matches!(i, 8 | 13 | 18 | 23) {
            i += 1;
            continue;
        }
        let hi = hex_nibble(b[i])?;
        let lo = hex_nibble(b[i + 1])?;
        out[byte_idx] = (hi << 4) | lo;
        byte_idx += 1;
        i += 2;
    }
    Some(out)
}

/// Convert a lowercase hex ASCII byte to its nibble value; `None` for
/// anything else (uppercase included — the canonical form is lowercase).
fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Tauri-side entry point. Thin delegating shell; logic lives in
/// [`repair_vault_impl`].
///
/// `password: Password` is the same zeroize-typed IPC boundary `unlock`
/// uses — see `unlock_with_password`'s doc comment.
#[tauri::command]
pub async fn repair_vault(
    state: State<'_, Mutex<VaultSession>>,
    folder_path: String,
    password: Password,
) -> Result<ManifestDto, AppError> {
    repair_vault_impl(state.inner(), &folder_path, password.expose())
}

/// Testable core. Synchronous, no Tauri runtime needed. Gates the folder
/// against the `VaultFolder` approval slot (same #353 discipline as
/// `unlock_with_password_impl`), validates the path shape, then delegates
/// to `VaultSession::repair` under the session mutex.
pub fn repair_vault_impl(
    state: &Mutex<VaultSession>,
    folder_path: &str,
    password: &[u8],
) -> Result<ManifestDto, AppError> {
    let folder = PathBuf::from(folder_path);
    // #353: the folder must be one the user picked via pick_vault_folder.
    {
        let session = lock_session(state)?;
        if !session.is_path_approved(PathPurpose::VaultFolder, &folder, MatchMode::Exact) {
            return Err(AppError::PathNotApproved {
                path: folder_path.to_string(),
            });
        }
    }
    validate_vault_path(&folder, folder_path)?;

    let mut session = lock_session(state)?;
    session.repair(&folder, password)?;

    session.with_unlocked(|u| {
        Ok(ManifestDto::from_manifest_with_warnings(
            &u.manifest,
            u.pending_warnings.clone(),
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_vault_uuid_from_toml() {
        let temp = tempfile::tempdir().unwrap();
        // A minimal vault.toml carrying a known vault_uuid.
        std::fs::write(
            temp.path().join("vault.toml"),
            b"vault_uuid = \"1f3a4b2c-9d8e-4f7a-b6c5-1a2b3c4d5e6f\"\n",
        )
        .unwrap();
        let got = read_vault_uuid_from_toml(temp.path()).unwrap();
        assert_eq!(
            got,
            [
                0x1f, 0x3a, 0x4b, 0x2c, 0x9d, 0x8e, 0x4f, 0x7a, 0xb6, 0xc5, 0x1a, 0x2b, 0x3c, 0x4d,
                0x5e, 0x6f
            ]
        );
    }

    #[test]
    fn missing_vault_uuid_field_errors() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("vault.toml"), b"[kdf]\n").unwrap();
        assert!(read_vault_uuid_from_toml(temp.path()).is_err());
    }

    #[test]
    fn unapproved_folder_is_rejected_before_validation() {
        // Mirrors `unlock.rs::unapproved_folder_is_rejected_before_validation`:
        // the #353 approval gate must reject before `validate_vault_path` (and
        // therefore before any bridge/session call) ever runs.
        let temp = tempfile::tempdir().expect("tempdir");
        let state = std::sync::Mutex::new(VaultSession::new(std::env::temp_dir()));
        let err = repair_vault_impl(&state, temp.path().to_str().unwrap(), b"pw")
            .expect_err("unapproved");
        assert!(
            matches!(err, AppError::PathNotApproved { .. }),
            "got {err:?}"
        );
    }
}
