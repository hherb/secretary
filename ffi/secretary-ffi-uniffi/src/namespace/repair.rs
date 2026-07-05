//! uniffi namespace fns projecting the bridge's crash-recovery
//! `repair_vault_with_*` trio (#374). Each mirrors its `open_*` /
//! `open_with_device_secret` counterpart one-for-one — same folder-path
//! UTF-8 validation, same credential-length checks, same zeroize
//! discipline — but calls `secretary_ffi_bridge::repair_vault_with_*`
//! instead of the plain open path. See `docs/vault-format.md` §10 and
//! `core/src/vault/repair.rs` for the crash-recovery semantics; repair is
//! never a weaker open. Each bridge repair fn loads the local §10 rollback
//! baseline and passes it to core `repair_vault`, which runs the §10
//! rollback check on the COMMITTED manifest clock BEFORE adopting, ticking,
//! or writing anything — so a rollback is refused fail-closed without
//! mutating the vault (see `ffi/secretary-ffi-bridge/src/repair/orchestration.rs`
//! module docs for why this must happen pre-write rather than via a
//! post-write `enforce_rollback_resistance` call).

use zeroize::Zeroize;

use crate::errors::VaultError;
use crate::wrappers::vault::{OpenVaultManifest, OpenVaultOutput};

use super::uuid_from_vec;

/// Repair a crash-residue vault using its master password. uniffi-projected. (#374)
///
/// `folder_path` is the UTF-8-encoded filesystem path as bytes.
/// `device_uuid` must be exactly 16 bytes; otherwise returns
/// [`VaultError::InvalidArgument`]. `password` is zeroized unconditionally
/// on return.
///
/// # Errors
///
/// Returns [`VaultError`] on failure. [`VaultError::RepairRejected`] means
/// the on-disk residue failed one of the fail-closed adoption gates (hybrid
/// verify, header binding, clock freshness, or the recipient-widening
/// guard) — no change was written. Other variants mirror
/// [`super::open_vault_with_password`].
pub fn repair_with_password(
    folder_path: Vec<u8>,
    mut password: Vec<u8>,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> Result<OpenVaultOutput, VaultError> {
    // Length-check device_uuid BEFORE the fallible path chain so we can
    // zeroize password on this early-return arm too.
    let uuid_arr = match uuid_from_vec(&device_uuid, "device_uuid") {
        Ok(u) => u,
        Err(e) => {
            password.zeroize();
            return Err(e);
        }
    };

    // Compute the full result chain into a single binding so we can zeroize
    // the password BEFORE any `?`-propagation — mirrors open_vault_with_password.
    let result: Result<secretary_ffi_bridge::OpenVaultOutput, VaultError> =
        match std::str::from_utf8(&folder_path) {
            Ok(s) => {
                let path = std::path::PathBuf::from(s);
                // Approvals project upward in a later task (#374); this
                // entry point always fails closed on any recipient
                // widening for now.
                secretary_ffi_bridge::repair_vault_with_password(
                    &path,
                    &password,
                    &uuid_arr,
                    now_ms,
                    &[],
                )
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
        identity: std::sync::Arc::new(crate::wrappers::identity::UnlockedIdentity(
            bridge_out.identity,
        )),
        manifest: std::sync::Arc::new(OpenVaultManifest(bridge_out.manifest)),
    })
}

/// Repair a crash-residue vault using its 24-word BIP-39 recovery phrase.
/// uniffi-projected. (#374)
///
/// `folder_path` is the UTF-8-encoded filesystem path as bytes. `mnemonic`
/// is the UTF-8-encoded phrase as bytes; the bridge's UTF-8 validation seam
/// surfaces malformed-UTF-8 input as [`VaultError::InvalidMnemonic`].
/// `device_uuid` must be exactly 16 bytes; otherwise returns
/// [`VaultError::InvalidArgument`]. `mnemonic` is zeroized unconditionally
/// on return.
///
/// # Errors
///
/// Returns [`VaultError`] on failure. See [`repair_with_password`] for the
/// repair-specific error semantics.
pub fn repair_with_recovery(
    folder_path: Vec<u8>,
    mut mnemonic: Vec<u8>,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> Result<OpenVaultOutput, VaultError> {
    let uuid_arr = match uuid_from_vec(&device_uuid, "device_uuid") {
        Ok(u) => u,
        Err(e) => {
            mnemonic.zeroize();
            return Err(e);
        }
    };

    let result: Result<secretary_ffi_bridge::OpenVaultOutput, VaultError> =
        match std::str::from_utf8(&folder_path) {
            Ok(s) => {
                let path = std::path::PathBuf::from(s);
                // Approvals project upward in a later task (#374); this
                // entry point always fails closed on any recipient
                // widening for now.
                secretary_ffi_bridge::repair_vault_with_recovery(
                    &path,
                    &mnemonic,
                    &uuid_arr,
                    now_ms,
                    &[],
                )
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
        identity: std::sync::Arc::new(crate::wrappers::identity::UnlockedIdentity(
            bridge_out.identity,
        )),
        manifest: std::sync::Arc::new(OpenVaultManifest(bridge_out.manifest)),
    })
}

/// Repair a crash-residue vault using a per-device wrap secret. uniffi-projected. (#374)
///
/// `folder_path` is the UTF-8-encoded filesystem path as bytes.
/// `device_uuid` must be exactly 16 bytes; `device_secret` must be exactly
/// 32 bytes. Both are validated before the bridge call; `device_secret` is
/// zeroized on all paths.
///
/// # Errors
///
/// - [`VaultError::InvalidArgument`] — `device_uuid` ≠ 16 bytes or
///   `device_secret` ≠ 32 bytes.
/// - [`VaultError::FolderInvalid`] — `folder_path` contains invalid UTF-8.
/// - other variants mirror [`repair_with_password`] and
///   [`super::open_with_device_secret`].
pub fn repair_with_device_secret(
    folder_path: Vec<u8>,
    device_uuid: Vec<u8>,
    mut device_secret: Vec<u8>,
    now_ms: u64,
) -> Result<OpenVaultOutput, VaultError> {
    // Length pre-checks BEFORE UTF-8 validation so we can zeroize
    // device_secret on all early-return paths — mirrors open_with_device_secret.
    if device_uuid.len() != 16 {
        device_secret.zeroize();
        return Err(VaultError::InvalidArgument {
            detail: format!("device_uuid must be 16 bytes, got {}", device_uuid.len()),
        });
    }
    if device_secret.len() != 32 {
        device_secret.zeroize();
        return Err(VaultError::InvalidArgument {
            detail: format!(
                "device_secret must be 32 bytes, got {}",
                device_secret.len()
            ),
        });
    }

    let uuid_arr: [u8; 16] = device_uuid
        .as_slice()
        .try_into()
        .expect("len checked above");
    // `mut` so the [u8; 32] stack copy is zeroized IN PLACE below. Binding it
    // immutably and later doing `let mut secret_arr = secret_arr;` would COPY
    // the array (`[u8; 32]: Copy`) into a fresh slot and wipe only the copy,
    // leaving this original slot's 32 plaintext bytes as stack residue.
    let mut secret_arr: [u8; 32] = device_secret
        .as_slice()
        .try_into()
        .expect("len checked above");

    let result: Result<secretary_ffi_bridge::OpenVaultOutput, VaultError> =
        match std::str::from_utf8(&folder_path) {
            Ok(s) => {
                let path = std::path::PathBuf::from(s);
                // Approvals project upward in a later task (#374); this
                // entry point always fails closed on any recipient
                // widening for now.
                secretary_ffi_bridge::repair_vault_with_device_secret(
                    &path,
                    &uuid_arr,
                    &secret_arr,
                    now_ms,
                    &[],
                )
                .map_err(VaultError::from)
            }
            Err(_) => Err(VaultError::FolderInvalid {
                detail: "folder path contained invalid UTF-8".to_string(),
            }),
        };

    // Zeroize unconditionally — runs on both success and error paths.
    // secret_arr is [u8; 32] (Copy), so both the array and the source Vec
    // must be zeroized to prevent stack residue — same discipline as
    // open_with_device_secret / the bridge's derive_wrap_key pattern.
    secret_arr.zeroize();
    device_secret.zeroize();

    let bridge_out = result?;
    Ok(OpenVaultOutput {
        identity: std::sync::Arc::new(crate::wrappers::identity::UnlockedIdentity(
            bridge_out.identity,
        )),
        manifest: std::sync::Arc::new(OpenVaultManifest(bridge_out.manifest)),
    })
}
