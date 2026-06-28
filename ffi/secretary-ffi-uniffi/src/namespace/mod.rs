//! uniffi namespace functions — the public API surface that maps directly
//! to the namespace block in `secretary.udl`. All the actual logic lives
//! in `secretary-ffi-bridge`; this layer adapts argument types (e.g. UTF-8
//! path validation, secret-arg zeroize-on-return) and translates bridge
//! errors into the uniffi-side `UnlockError` / `VaultError`.

use crate::errors::{UnlockError, VaultError};
use crate::wrappers::block::BlockReadOutput;
use crate::wrappers::device::{DeviceEnrollOutput, DeviceSecretOutput};
use crate::wrappers::identity::{
    CreateVaultOutput, CreatedVaultInFolder, MnemonicOutput, UnlockedIdentity,
};
use crate::wrappers::vault::{OpenVaultManifest, OpenVaultOutput};
use zeroize::Zeroize;

mod block_crud;
pub use block_crud::{create_block, move_record, rename_block};

mod contacts;
pub use contacts::{import_contact_card, share_block_to};

mod record_edit;
pub use record_edit::{append_record, edit_record, resurrect_record, tombstone_record};

mod sync;
pub use sync::{sync_commit_decisions, sync_status, sync_vault};

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

/// Create a fresh v1 vault on disk in an existing empty `folder_path`.
/// uniffi-projected. (iOS create/import Slice 1.)
///
/// `folder_path` is the UTF-8-encoded filesystem path to an existing empty
/// directory. Writes all four canonical files and returns the one-shot
/// recovery mnemonic; the caller re-opens with `open_vault_with_password`
/// to browse (no auto-open). The bridge hardcodes `OsRng` +
/// `Argon2idParams::V1_DEFAULT`.
///
/// # Errors
///
/// Returns [`VaultError`]: `VaultFolderNotEmpty` if the directory contains
/// entries, `FolderInvalid` if the path is missing / unreadable / a file
/// (not a directory) / not valid UTF-8, `CorruptVault` on rare crypto
/// failure.
pub fn create_vault_in_folder(
    folder_path: Vec<u8>,
    mut password: Vec<u8>,
    display_name: String,
    created_at_ms: u64,
) -> Result<CreatedVaultInFolder, VaultError> {
    // Compute the full result chain into a single binding so the password
    // is zeroized BEFORE any `?`-propagation (mirrors open_vault_with_password).
    let result: Result<secretary_ffi_bridge::CreatedVaultInFolder, VaultError> =
        match std::str::from_utf8(&folder_path) {
            Ok(s) => {
                let path = std::path::PathBuf::from(s);
                secretary_ffi_bridge::create_vault_in_folder(
                    &path,
                    &password,
                    &display_name,
                    created_at_ms,
                )
                .map_err(VaultError::from)
            }
            Err(_) => Err(VaultError::FolderInvalid {
                detail: "folder path contained invalid UTF-8".to_string(),
            }),
        };

    password.zeroize();
    let bridge_out = result?;
    Ok(CreatedVaultInFolder {
        vault_uuid: bridge_out.vault_uuid.to_vec(),
        mnemonic: std::sync::Arc::new(MnemonicOutput(bridge_out.mnemonic)),
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
/// When `include_deleted` is false, tombstoned records are withheld (their
/// field handles are never built, so no secret bytes cross the FFI seam);
/// when true they are returned with `tombstone() == true`.
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
    include_deleted: bool,
) -> Result<std::sync::Arc<BlockReadOutput>, VaultError> {
    if block_uuid.len() != 16 {
        return Err(VaultError::InvalidArgument {
            detail: format!("block_uuid must be 16 bytes, got {}", block_uuid.len()),
        });
    }
    let mut uuid_array = [0u8; 16];
    uuid_array.copy_from_slice(&block_uuid);
    secretary_ffi_bridge::read_block(&identity.0, &manifest.0, &uuid_array, include_deleted)
        .map(|b| std::sync::Arc::new(BlockReadOutput(b)))
        .map_err(VaultError::from)
}

/// Encrypt and atomically persist one block of records. (B.4c)
///
/// `device_uuid` and `input.block_uuid` (and each `RecordInput.record_uuid`)
/// must be exactly 16 bytes; otherwise returns
/// [`VaultError::InvalidArgument`]. Same wrong-length-rides-inside-VaultError
/// rationale as [`read_block`].
///
/// Converts uniffi-flat input dictionaries to bridge-side types
/// ([`secretary_core::crypto::secret::SecretString`] / [`secretary_core::crypto::secret::SecretBytes`]
/// wrappers preserve zeroize-on-drop) and forwards to
/// [`secretary_ffi_bridge::save_block`].
///
/// # Errors
///
/// - [`VaultError::InvalidArgument`] — wrong-length `device_uuid`,
///   `input.block_uuid`, or any `RecordInput.record_uuid`.
/// - [`VaultError::CorruptVault`] — either handle has been wiped.
/// - [`VaultError::FolderInvalid`] — IO failure during atomic write.
/// - [`VaultError::SaveCryptoFailure`] — crypto / encoding failure on
///   already-validated inputs.
pub fn save_block(
    identity: std::sync::Arc<UnlockedIdentity>,
    manifest: std::sync::Arc<OpenVaultManifest>,
    input: crate::BlockInput,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> Result<(), VaultError> {
    let device_uuid = uuid_from_vec(&device_uuid, "device_uuid")?;
    let block_uuid = uuid_from_vec(&input.block_uuid, "input.block_uuid")?;

    let records = input
        .records
        .into_iter()
        .map(convert_record_input)
        .collect::<Result<Vec<_>, _>>()?;

    let bridge_input = secretary_ffi_bridge::BlockInput {
        block_uuid,
        block_name: input.block_name,
        records,
    };

    secretary_ffi_bridge::save_block(&identity.0, &manifest.0, bridge_input, device_uuid, now_ms)
        .map_err(VaultError::from)
}

/// Append one new recipient to an existing block — uniffi namespace fn
/// projection of [`secretary_ffi_bridge::share_block`].
///
/// Length-validates `block_uuid` and `device_uuid` namespace-side (16
/// bytes each); wrong lengths surface as
/// [`VaultError::InvalidArgument`] (mirrors `save_block`). All other
/// errors translate via the existing `From<FfiVaultError>` impl on
/// `VaultError`.
///
/// # Errors
///
/// - [`VaultError::InvalidArgument`] — wrong-length `block_uuid` or
///   `device_uuid`.
/// - [`VaultError::CardDecodeFailure`] — caller-supplied ContactCard
///   bytes failed canonical-CBOR decode.
/// - [`VaultError::CorruptVault`] — either handle has been wiped.
/// - [`VaultError::FolderInvalid`] — IO failure during atomic write.
/// - [`VaultError::BlockNotFound`] — `block_uuid` not in manifest.
/// - [`VaultError::NotAuthor`] — calling identity is not the block's author.
/// - [`VaultError::RecipientAlreadyPresent`] — `new_recipient` is already
///   in the block's recipient table.
/// - [`VaultError::MissingRecipientCard`] — `existing_recipient_cards`
///   missing a card whose fingerprint appears on disk.
/// - [`VaultError::SaveCryptoFailure`] — crypto / encoding failure on
///   already-validated inputs.
#[allow(clippy::too_many_arguments)]
pub fn share_block(
    identity: std::sync::Arc<UnlockedIdentity>,
    manifest: std::sync::Arc<OpenVaultManifest>,
    block_uuid: Vec<u8>,
    existing_recipient_cards: Vec<Vec<u8>>,
    new_recipient: Vec<u8>,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> Result<(), VaultError> {
    let block_uuid = uuid_from_vec(&block_uuid, "block_uuid")?;
    let device_uuid = uuid_from_vec(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::share_block(
        &identity.0,
        &manifest.0,
        block_uuid,
        &existing_recipient_cards,
        &new_recipient,
        device_uuid,
        now_ms,
    )
    .map_err(VaultError::from)
}

/// Move a live block into trash — uniffi namespace fn projection of
/// [`secretary_ffi_bridge::trash_block`]. See `docs/vault-format.md`
/// §7 for the normative sequence.
///
/// # Errors
///
/// - [`VaultError::InvalidArgument`] — wrong-length `block_uuid` or
///   `device_uuid`.
/// - [`VaultError::CorruptVault`] — either handle has been wiped.
/// - [`VaultError::BlockNotFound`] — `block_uuid` not in
///   `manifest.blocks`.
/// - [`VaultError::FolderInvalid`] — IO failure during the rename
///   or manifest atomic-write.
/// - [`VaultError::SaveCryptoFailure`] — crypto / encoding failure
///   on already-validated inputs.
pub fn trash_block(
    identity: std::sync::Arc<UnlockedIdentity>,
    manifest: std::sync::Arc<OpenVaultManifest>,
    block_uuid: Vec<u8>,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> Result<(), VaultError> {
    let block_uuid = uuid_from_vec(&block_uuid, "block_uuid")?;
    let device_uuid = uuid_from_vec(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::trash_block(&identity.0, &manifest.0, block_uuid, device_uuid, now_ms)
        .map_err(VaultError::from)
}

/// Restore the most recent trashed copy of a block — uniffi namespace
/// fn projection of [`secretary_ffi_bridge::restore_block`]. See
/// `docs/vault-format.md` §7.1 for the normative sequence.
///
/// # Errors
///
/// - [`VaultError::InvalidArgument`] — wrong-length `block_uuid` or
///   `device_uuid`.
/// - [`VaultError::BlockUuidAlreadyLive`] — `block_uuid` is currently
///   live; the caller must trash the live copy first.
/// - [`VaultError::BlockNotInTrash`] — no matching file in
///   `trash/<uuid>.cbor.enc.*` and no matching `TrashEntry`.
/// - [`VaultError::CorruptVault`] — the trashed file failed §6.1
///   hybrid-signature verification (folded from
///   `RestoreVerificationFailed`).
/// - [`VaultError::MissingRecipientCard`] — a wrap recipient cannot
///   be resolved to a `contact_uuid` via the contacts/-scan.
/// - [`VaultError::FolderInvalid`] — IO failure.
pub fn restore_block(
    identity: std::sync::Arc<UnlockedIdentity>,
    manifest: std::sync::Arc<OpenVaultManifest>,
    block_uuid: Vec<u8>,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> Result<(), VaultError> {
    let block_uuid = uuid_from_vec(&block_uuid, "block_uuid")?;
    let device_uuid = uuid_from_vec(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::restore_block(&identity.0, &manifest.0, block_uuid, device_uuid, now_ms)
        .map_err(VaultError::from)
}

/// Enrol a new device slot, writing `devices/<uuid>.wrap`. uniffi-projected. (B.2)
///
/// `folder_path` is the UTF-8-encoded filesystem path as bytes.
/// `password` is the master password; zeroized unconditionally on return.
///
/// # Errors
///
/// - [`VaultError::FolderInvalid`] — `folder_path` contains invalid UTF-8, or
///   an IO failure occurred during the atomic write.
/// - [`VaultError::WrongPasswordOrCorrupt`] — wrong password or corrupt vault files.
pub fn add_device_slot(
    folder_path: Vec<u8>,
    mut password: Vec<u8>,
) -> Result<DeviceEnrollOutput, VaultError> {
    // Compute the full result chain into a single binding so we can zeroize
    // the password BEFORE any `?`-propagation — mirrors open_vault_with_password.
    let result: Result<secretary_ffi_bridge::DeviceEnrollOutput, VaultError> =
        match std::str::from_utf8(&folder_path) {
            Ok(s) => {
                let path = std::path::PathBuf::from(s);
                secretary_ffi_bridge::add_device_slot(&path, &password).map_err(VaultError::from)
            }
            Err(_) => Err(VaultError::FolderInvalid {
                detail: "folder path contained invalid UTF-8".to_string(),
            }),
        };

    // Zeroize unconditionally — runs on both success and error paths.
    password.zeroize();

    let bridge_out = result?;
    Ok(DeviceEnrollOutput {
        device_uuid: bridge_out.device_uuid,
        device_secret: std::sync::Arc::new(DeviceSecretOutput(bridge_out.device_secret)),
    })
}

/// Open a vault folder using a per-device secret. uniffi-projected. (B.2)
///
/// `folder_path` is the UTF-8-encoded filesystem path as bytes.
/// `device_uuid` must be exactly 16 bytes; `device_secret` must be exactly 32 bytes.
/// Both are validated before the bridge call; `device_secret` is zeroized on all paths.
///
/// # Errors
///
/// - [`VaultError::InvalidArgument`] — `device_uuid` ≠ 16 bytes or `device_secret` ≠ 32 bytes.
/// - [`VaultError::FolderInvalid`] — `folder_path` contains invalid UTF-8.
/// - [`VaultError::DeviceSlotNotFound`] — no wrap file for this UUID.
/// - [`VaultError::WrongDeviceSecretOrCorrupt`] — AEAD tag failure.
/// - [`VaultError::DeviceUuidMismatch`] — vault-format §3a relabel integrity check failure.
pub fn open_with_device_secret(
    folder_path: Vec<u8>,
    device_uuid: Vec<u8>,
    mut device_secret: Vec<u8>,
) -> Result<OpenVaultOutput, VaultError> {
    // Length pre-checks BEFORE UTF-8 validation so we can zeroize device_secret
    // on all early-return paths.
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

    // Compute the full result chain into a single binding so we can zeroize
    // device_secret BEFORE any `?`-propagation — mirrors open_vault_with_password.
    let uuid_arr: [u8; 16] = device_uuid
        .as_slice()
        .try_into()
        .expect("len checked above");
    let secret_arr: [u8; 32] = device_secret
        .as_slice()
        .try_into()
        .expect("len checked above");

    let result: Result<secretary_ffi_bridge::OpenVaultOutput, VaultError> =
        match std::str::from_utf8(&folder_path) {
            Ok(s) => {
                let path = std::path::PathBuf::from(s);
                secretary_ffi_bridge::open_with_device_secret(&path, &uuid_arr, &secret_arr)
                    .map_err(VaultError::from)
            }
            Err(_) => Err(VaultError::FolderInvalid {
                detail: "folder path contained invalid UTF-8".to_string(),
            }),
        };

    // Zeroize unconditionally — runs on both success and error paths.
    // Note: secret_arr is [u8; 32] (Copy), so we must zeroize both the array
    // and the source Vec to prevent stack residue — same discipline as the
    // bridge's derive_wrap_key / derive_master_kek pattern in CLAUDE.md.
    let mut secret_arr = secret_arr;
    secret_arr.zeroize();
    device_secret.zeroize();

    let bridge_out = result?;
    Ok(OpenVaultOutput {
        identity: std::sync::Arc::new(UnlockedIdentity(bridge_out.identity)),
        manifest: std::sync::Arc::new(OpenVaultManifest(bridge_out.manifest)),
    })
}

/// Revoke a device slot by deleting `devices/<uuid>.wrap`. uniffi-projected. (B.2)
///
/// `folder_path` is the UTF-8-encoded filesystem path as bytes.
/// `device_uuid` must be exactly 16 bytes; otherwise returns
/// [`VaultError::InvalidArgument`].
///
/// # Errors
///
/// - [`VaultError::InvalidArgument`] — `device_uuid` ≠ 16 bytes.
/// - [`VaultError::FolderInvalid`] — `folder_path` contains invalid UTF-8 or IO failure.
/// - [`VaultError::DeviceSlotNotFound`] — no wrap file for this UUID.
pub fn remove_device_slot(folder_path: Vec<u8>, device_uuid: Vec<u8>) -> Result<(), VaultError> {
    let uuid_arr = uuid_from_vec(&device_uuid, "device_uuid")?;
    match std::str::from_utf8(&folder_path) {
        Ok(s) => {
            let path = std::path::PathBuf::from(s);
            secretary_ffi_bridge::remove_device_slot(&path, &uuid_arr).map_err(VaultError::from)
        }
        Err(_) => Err(VaultError::FolderInvalid {
            detail: "folder path contained invalid UTF-8".to_string(),
        }),
    }
}

/// Validate a 16-byte UUID slice; surface wrong length as
/// [`VaultError::InvalidArgument`] with the field name in the detail.
pub(crate) fn uuid_from_vec(bytes: &[u8], field: &str) -> Result<[u8; 16], VaultError> {
    bytes.try_into().map_err(|_| VaultError::InvalidArgument {
        detail: format!("{field} must be 16 bytes, got {}", bytes.len()),
    })
}

/// Convert a uniffi-side [`crate::RecordInput`] into a bridge-side
/// [`secretary_ffi_bridge::RecordInput`]. Wraps each field's payload in
/// the appropriate zeroize-on-drop secret carrier.
fn convert_record_input(
    r: crate::RecordInput,
) -> Result<secretary_ffi_bridge::RecordInput, VaultError> {
    use secretary_core::crypto::secret::{SecretBytes, SecretString};

    let record_uuid = uuid_from_vec(&r.record_uuid, "record_uuid")?;
    let fields = r
        .fields
        .into_iter()
        .map(|f| secretary_ffi_bridge::FieldInput {
            name: f.name,
            value: match f.value {
                crate::FieldInputValue::Text { text } => {
                    secretary_ffi_bridge::FieldInputValue::Text(SecretString::from(text))
                }
                crate::FieldInputValue::Bytes { data } => {
                    secretary_ffi_bridge::FieldInputValue::Bytes(SecretBytes::from(data))
                }
            },
        })
        .collect();

    Ok(secretary_ffi_bridge::RecordInput {
        record_uuid,
        record_type: r.record_type,
        tags: r.tags,
        fields,
    })
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
    fn create_vault_in_folder_invalid_utf8_path_returns_folder_invalid() {
        // 0xff\xfe is invalid UTF-8; the wrapper must reject before touching
        // the bridge / KDF. MnemonicOutput holds Arc<opaque> (no Debug), so
        // we match rather than calling unwrap_err().
        match create_vault_in_folder(
            b"\xff\xfe".to_vec(),
            b"pw".to_vec(),
            "X".to_string(),
            1_700_000_000_000,
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
        match read_block(out.identity, out.manifest, vec![0u8; 15], false) {
            Err(VaultError::InvalidArgument { detail }) => {
                assert!(
                    detail.contains("16 bytes") && detail.contains("got 15"),
                    "detail did not mention expected length markers",
                );
            }
            Err(other) => panic!("expected InvalidArgument for wrong-length, got {other:?}"),
            Ok(_) => panic!("expected Err for wrong-length block_uuid"),
        }
    }
}
