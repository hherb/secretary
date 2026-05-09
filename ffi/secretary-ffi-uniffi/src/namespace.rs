//! uniffi namespace functions — the public API surface that maps directly
//! to the namespace block in `secretary.udl`. All the actual logic lives
//! in `secretary-ffi-bridge`; this layer adapts argument types (e.g. UTF-8
//! path validation, secret-arg zeroize-on-return) and translates bridge
//! errors into the uniffi-side `UnlockError` / `VaultError`.

use crate::errors::{UnlockError, VaultError};
use crate::wrappers::block::BlockReadOutput;
use crate::wrappers::identity::{CreateVaultOutput, MnemonicOutput, UnlockedIdentity};
use crate::wrappers::vault::{OpenVaultManifest, OpenVaultOutput};
use zeroize::Zeroize;

/// Unlock a vault using its master password. uniffi-projected.
///
/// # Errors
///
/// Returns [`UnlockError`] on failure. See the bridge crate's
/// [`FfiUnlockError`](secretary_ffi_bridge::FfiUnlockError) docs for the
/// thinned 5-variant rationale.
///
/// # Why `Arc<UnlockedIdentity>`?
///
/// uniffi marshals UDL `interface` types as refcounted handles on the
/// foreign side. The Rust signature must therefore return `Arc<T>` (uniffi
/// owns the refcount; the foreign caller's release decrements it). Without
/// the `Arc<>`, uniffi's generated scaffolding emits a type-mismatch error
/// (`expected Result<Arc<UnlockedIdentity>, ...>, found Result<UnlockedIdentity, _>`).
pub fn open_with_password(
    vault_toml_bytes: Vec<u8>,
    identity_bundle_bytes: Vec<u8>,
    mut password: Vec<u8>,
) -> Result<std::sync::Arc<UnlockedIdentity>, UnlockError> {
    // Mirrors the secretary-ffi-py wrapper's stack-residue discipline:
    // zero the password Vec after the bridge returns. The bridge already
    // zeroizes its SecretBytes copy; this wipes the projection-side
    // transient.
    let result = secretary_ffi_bridge::open_with_password(
        &vault_toml_bytes,
        &identity_bundle_bytes,
        &password,
    )
    .map(|inner| std::sync::Arc::new(UnlockedIdentity(inner)))
    .map_err(UnlockError::from);
    password.zeroize();
    result
}

/// Unlock a vault using its 24-word BIP-39 recovery phrase. uniffi-projected.
///
/// Mnemonic input is UTF-8-encoded bytes (`Vec<u8>`); the bridge's UTF-8
/// validation seam surfaces malformed-UTF-8 input as
/// [`UnlockError::InvalidMnemonic`] with `detail: "phrase contained
/// invalid UTF-8"`.
///
/// # Errors
///
/// Returns [`UnlockError`] on failure. See the bridge crate's
/// [`FfiUnlockError`](secretary_ffi_bridge::FfiUnlockError) docs for the
/// thinned 5-variant rationale.
pub fn open_with_recovery(
    vault_toml_bytes: Vec<u8>,
    identity_bundle_bytes: Vec<u8>,
    mut mnemonic: Vec<u8>,
) -> Result<std::sync::Arc<UnlockedIdentity>, UnlockError> {
    // Mirrors the open_with_password wrapper-side stack-residue discipline:
    // zero the mnemonic Vec after the bridge returns. The bridge takes &[u8]
    // and never retains; this Vec is the projection-side transient.
    let result = secretary_ffi_bridge::open_with_recovery(
        &vault_toml_bytes,
        &identity_bundle_bytes,
        &mnemonic,
    )
    .map(|inner| std::sync::Arc::new(UnlockedIdentity(inner)))
    .map_err(UnlockError::from);
    mnemonic.zeroize();
    result
}

/// Create a fresh v1 vault. uniffi-projected. (B.3b)
///
/// The bridge crate instantiates `OsRng` and
/// `Argon2idParams::V1_DEFAULT` internally; foreign callers cannot tune
/// either.
///
/// Returns a [`CreateVaultOutput`] containing on-disk byte artifacts and
/// two opaque handles ([`UnlockedIdentity`] and [`MnemonicOutput`]).
///
/// # Errors
///
/// Returns [`UnlockError`] on failure. See the bridge crate's
/// [`FfiUnlockError`](secretary_ffi_bridge::FfiUnlockError) docs for the
/// thinned 5-variant rationale.
pub fn create_vault(
    mut password: Vec<u8>,
    display_name: String,
    created_at_ms: u64,
) -> Result<CreateVaultOutput, UnlockError> {
    // Mirrors the open_with_password / open_with_recovery wrapper-side
    // stack-residue discipline: zero the password Vec after the bridge
    // returns. The bridge takes &[u8] and never retains; this Vec is the
    // projection-side transient.
    let result = secretary_ffi_bridge::create_vault(&password, &display_name, created_at_ms);
    password.zeroize();

    let bridge_out = result.map_err(UnlockError::from)?;

    let secretary_ffi_bridge::CreateVaultOutput {
        vault_toml_bytes,
        identity_bundle_bytes,
        identity,
        mnemonic,
    } = bridge_out;

    Ok(CreateVaultOutput {
        vault_toml_bytes,
        identity_bundle_bytes,
        identity: std::sync::Arc::new(UnlockedIdentity(identity)),
        mnemonic: std::sync::Arc::new(MnemonicOutput(mnemonic)),
    })
}

/// Open a vault folder using its master password. uniffi-projected. (B.4a)
///
/// `folder_path` is the UTF-8-encoded filesystem path to the vault folder as
/// bytes. Returns [`VaultError::FolderInvalid`] if the path contains invalid
/// UTF-8.
///
/// # Errors
///
/// Returns [`VaultError`] on failure. See the bridge crate's
/// [`FfiVaultError`](secretary_ffi_bridge::FfiVaultError) docs for the
/// thinned 6-variant rationale.
pub fn open_vault_with_password(
    folder_path: Vec<u8>,
    mut password: Vec<u8>,
) -> Result<OpenVaultOutput, VaultError> {
    // Compute the full result chain (path validation + bridge call) into a
    // single binding so we can zeroize the password BEFORE any `?`-propagation.
    // Both fallible paths produce the same Err type, so there is no lost
    // context in the match arms.
    let result: Result<secretary_ffi_bridge::OpenVaultOutput, VaultError> =
        match std::str::from_utf8(&folder_path) {
            Ok(s) => {
                let path = std::path::PathBuf::from(s);
                secretary_ffi_bridge::open_vault_with_password(&path, &password)
                    .map_err(VaultError::from)
            }
            Err(_) => Err(VaultError::FolderInvalid {
                detail: "folder path contained invalid UTF-8".to_string(),
            }),
        };

    // Zeroize unconditionally — runs on both success and error paths.
    password.zeroize();

    let bridge_out = result?;
    Ok(OpenVaultOutput {
        identity: std::sync::Arc::new(UnlockedIdentity(bridge_out.identity)),
        manifest: std::sync::Arc::new(OpenVaultManifest(bridge_out.manifest)),
    })
}

/// Open a vault folder using its 24-word BIP-39 recovery phrase. uniffi-projected. (B.4a)
///
/// `folder_path` is the UTF-8-encoded filesystem path as bytes.
/// `mnemonic` is the UTF-8-encoded phrase as bytes; the bridge's UTF-8
/// validation seam surfaces malformed-UTF-8 input as
/// [`VaultError::InvalidMnemonic`] with `detail: "phrase contained invalid UTF-8"`.
///
/// # Errors
///
/// Returns [`VaultError`] on failure.
pub fn open_vault_with_recovery(
    folder_path: Vec<u8>,
    mut mnemonic: Vec<u8>,
) -> Result<OpenVaultOutput, VaultError> {
    // Compute the full result chain (path validation + bridge call) into a
    // single binding so we can zeroize the mnemonic BEFORE any `?`-propagation.
    // Both fallible paths produce the same Err type, so there is no lost
    // context in the match arms.
    let result: Result<secretary_ffi_bridge::OpenVaultOutput, VaultError> =
        match std::str::from_utf8(&folder_path) {
            Ok(s) => {
                let path = std::path::PathBuf::from(s);
                secretary_ffi_bridge::open_vault_with_recovery(&path, &mnemonic)
                    .map_err(VaultError::from)
            }
            Err(_) => Err(VaultError::FolderInvalid {
                detail: "folder path contained invalid UTF-8".to_string(),
            }),
        };

    // Zeroize unconditionally — runs on both success and error paths.
    mnemonic.zeroize();

    let bridge_out = result?;
    Ok(OpenVaultOutput {
        identity: std::sync::Arc::new(UnlockedIdentity(bridge_out.identity)),
        manifest: std::sync::Arc::new(OpenVaultManifest(bridge_out.manifest)),
    })
}

/// Decrypt one block of an open vault and return its records. (B.4b)
///
/// `block_uuid` must be exactly 16 bytes; otherwise returns
/// [`VaultError::InvalidArgument`] (uniffi 0.31 has no native `ValueError`
/// equivalent at the namespace-fn level, so the FFI input-shape error
/// rides inside `VaultError` — but in a dedicated variant rather than
/// folded into `FolderInvalid`, which semantically means "your filesystem
/// path is wrong").
///
/// # Errors
///
/// - [`VaultError::InvalidArgument`] — wrong-length `block_uuid` (≠ 16 bytes).
/// - [`VaultError::BlockNotFound`] — UUID not in manifest's live blocks list.
/// - [`VaultError::CorruptVault`] — block file missing/malformed/decryption failed.
/// - [`VaultError::FolderInvalid`] — block file present but unreadable
///   for non-NotFound IO reasons.
pub fn read_block(
    identity: std::sync::Arc<UnlockedIdentity>,
    manifest: std::sync::Arc<OpenVaultManifest>,
    block_uuid: Vec<u8>,
) -> Result<std::sync::Arc<BlockReadOutput>, VaultError> {
    if block_uuid.len() != 16 {
        return Err(VaultError::InvalidArgument {
            detail: format!("block_uuid must be 16 bytes, got {}", block_uuid.len()),
        });
    }
    let mut uuid_array = [0u8; 16];
    uuid_array.copy_from_slice(&block_uuid);
    secretary_ffi_bridge::read_block(&identity.0, &manifest.0, &uuid_array)
        .map(|b| std::sync::Arc::new(BlockReadOutput(b)))
        .map_err(VaultError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------
    // B.4a memory-hygiene regression: invalid-UTF-8 folder_path must
    // return FolderInvalid regardless of whether the secret arg is valid.
    //
    // The structural fix (zeroize before `?`-propagation) is enforced by
    // code shape; these tests pin the observable error contract so that a
    // future refactor that re-introduces `?`-before-zeroize also breaks
    // a named test rather than silently regressing.
    // -------------------------------------------------------------------

    #[test]
    fn open_vault_with_password_invalid_utf8_path_returns_folder_invalid() {
        // \xff\xfe is invalid UTF-8; the function must return FolderInvalid
        // rather than panicking or returning a different variant.
        // OpenVaultOutput doesn't implement Debug (it holds Arc<opaque handles>),
        // so we match rather than calling unwrap_err().
        match open_vault_with_password(b"\xff\xfe".to_vec(), b"hunter2".to_vec()) {
            Err(VaultError::FolderInvalid { .. }) => {}
            Err(other) => panic!("expected FolderInvalid, got {other:?}"),
            Ok(_) => panic!("expected Err for invalid UTF-8 path"),
        }
    }

    #[test]
    fn open_vault_with_recovery_invalid_utf8_path_returns_folder_invalid() {
        // Mirror of the password variant — pins the mnemonic forwarder.
        match open_vault_with_recovery(
            b"\xff\xfe".to_vec(),
            b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_vec(),
        ) {
            Err(VaultError::FolderInvalid { .. }) => {}
            Err(other) => panic!("expected FolderInvalid, got {other:?}"),
            Ok(_) => panic!("expected Err for invalid UTF-8 path"),
        }
    }

    #[test]
    fn read_block_wrong_length_returns_invalid_argument() {
        // Pin the wrong-length-folds-to-InvalidArgument decision (PR #31
        // review feedback: was previously FolderInvalid, but that variant
        // semantically means "your filesystem path is wrong" — wrong-
        // length block_uuid is a programmer error and now surfaces through
        // the dedicated InvalidArgument variant instead).
        // Synthesize stub Arc<UnlockedIdentity> + Arc<OpenVaultManifest>
        // by routing through the real open path against golden_vault_001.
        // BlockReadOutput doesn't implement Debug (it holds zeroize-sensitive
        // wrappers), so we match rather than calling unwrap_err().
        let folder_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../core/tests/data/golden_vault_001");
        let folder_bytes = folder_path.to_str().unwrap().as_bytes().to_vec();
        let pwd = b"correct horse battery staple".to_vec();
        let out = open_vault_with_password(folder_bytes, pwd).unwrap();
        match read_block(out.identity, out.manifest, vec![0u8; 15]) {
            Err(VaultError::InvalidArgument { detail }) => {
                assert!(
                    detail.contains("16 bytes") && detail.contains("got 15"),
                    "detail did not mention length: {detail}",
                );
            }
            Err(other) => panic!("expected InvalidArgument for wrong-length, got {other:?}"),
            Ok(_) => panic!("expected Err for wrong-length block_uuid"),
        }
    }
}
