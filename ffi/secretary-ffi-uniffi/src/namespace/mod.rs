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
use crate::wrappers::purge::{EmptyTrashReport, PurgeReport};
use crate::wrappers::retention::{ExpiredEntry, RetentionPurgeReport};
use crate::wrappers::settings::Settings;
use crate::wrappers::trash::TrashedBlock;
use crate::wrappers::vault::{OpenVaultManifest, OpenVaultOutput};
use zeroize::Zeroize;

mod block_crud;
pub use block_crud::{create_block, move_record, rename_block};

mod contacts;
pub use contacts::{import_contact_card, share_block_to};

mod record_edit;
pub use record_edit::{append_record, edit_record, resurrect_record, tombstone_record};

mod repair;
pub use repair::{
    preview_repair_with_device_secret, preview_repair_with_password, preview_repair_with_recovery,
    repair_with_device_secret, repair_with_password, repair_with_recovery,
};

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
    password: &[u8],
) -> Result<std::sync::Arc<UnlockedIdentity>, UnlockError> {
    // `[ByRef] bytes` (#307): `password` is a zero-copy borrow of the
    // foreign caller's buffer (uniffi ForeignBytes) — no projection-side
    // Vec exists to zeroize, and the marshalling copies the pre-0.32
    // RustBuffer path allocated never exist. The foreign adapter owns the
    // buffer and its scrub (iOS withZeroizingData / Android direct
    // ByteBuffer zeroed after the call); the bridge zeroizes its own
    // SecretBytes copy.
    secretary_ffi_bridge::open_with_password(&vault_toml_bytes, &identity_bundle_bytes, password)
        .map(|inner| std::sync::Arc::new(UnlockedIdentity(inner)))
        .map_err(UnlockError::from)
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
    mnemonic: &[u8],
) -> Result<std::sync::Arc<UnlockedIdentity>, UnlockError> {
    // `[ByRef] bytes` (#307): zero-copy borrow of the foreign buffer —
    // see open_with_password for the ownership/scrub contract.
    secretary_ffi_bridge::open_with_recovery(&vault_toml_bytes, &identity_bundle_bytes, mnemonic)
        .map(|inner| std::sync::Arc::new(UnlockedIdentity(inner)))
        .map_err(UnlockError::from)
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
    password: &[u8],
    display_name: String,
    created_at_ms: u64,
) -> Result<CreateVaultOutput, UnlockError> {
    // `[ByRef] bytes` (#307): zero-copy borrow of the foreign buffer —
    // see open_with_password for the ownership/scrub contract.
    let result = secretary_ffi_bridge::create_vault(password, &display_name, created_at_ms);

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
    password: &[u8],
    display_name: String,
    created_at_ms: u64,
) -> Result<CreatedVaultInFolder, VaultError> {
    // `[ByRef] bytes` (#307): `password` is a zero-copy borrow of the
    // foreign buffer — nothing owned here to zeroize; see
    // open_with_password for the ownership/scrub contract.
    let result: Result<secretary_ffi_bridge::CreatedVaultInFolder, VaultError> =
        match std::str::from_utf8(&folder_path) {
            Ok(s) => {
                let path = std::path::PathBuf::from(s);
                secretary_ffi_bridge::create_vault_in_folder(
                    &path,
                    password,
                    &display_name,
                    created_at_ms,
                )
                .map_err(VaultError::from)
            }
            Err(_) => Err(VaultError::FolderInvalid {
                detail: "folder path contained invalid UTF-8".to_string(),
            }),
        };

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
    password: &[u8],
) -> Result<OpenVaultOutput, VaultError> {
    // `[ByRef] bytes` (#307): `password` is a zero-copy borrow of the
    // foreign buffer — nothing owned here to zeroize; see
    // open_with_password for the ownership/scrub contract.
    let result: Result<secretary_ffi_bridge::OpenVaultOutput, VaultError> =
        match std::str::from_utf8(&folder_path) {
            Ok(s) => {
                let path = std::path::PathBuf::from(s);
                secretary_ffi_bridge::open_vault_with_password(&path, password)
                    .map_err(VaultError::from)
            }
            Err(_) => Err(VaultError::FolderInvalid {
                detail: "folder path contained invalid UTF-8".to_string(),
            }),
        };

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
    mnemonic: &[u8],
) -> Result<OpenVaultOutput, VaultError> {
    // `[ByRef] bytes` (#307): `mnemonic` is a zero-copy borrow of the
    // foreign buffer — nothing owned here to zeroize; see
    // open_with_password for the ownership/scrub contract.
    let result: Result<secretary_ffi_bridge::OpenVaultOutput, VaultError> =
        match std::str::from_utf8(&folder_path) {
            Ok(s) => {
                let path = std::path::PathBuf::from(s);
                secretary_ffi_bridge::open_vault_with_recovery(&path, mnemonic)
                    .map_err(VaultError::from)
            }
            Err(_) => Err(VaultError::FolderInvalid {
                detail: "folder path contained invalid UTF-8".to_string(),
            }),
        };

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
/// - [`VaultError::BlockPurged`] — the `TrashEntry` is marked purged;
///   the ciphertext has been permanently deleted and cannot be restored.
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

/// Permanently purge a trashed block — uniffi namespace fn projection of
/// [`secretary_ffi_bridge::purge_block`]. See `docs/vault-format.md` §7
/// (purge extension, #399) for the normative sequence.
///
/// # Errors
///
/// - [`VaultError::InvalidArgument`] — wrong-length `block_uuid` or
///   `device_uuid`.
/// - [`VaultError::CorruptVault`] — either handle has been wiped.
/// - [`VaultError::BlockNotInTrash`] — no `TrashEntry` exists for
///   `block_uuid`.
/// - [`VaultError::FolderInvalid`] — IO failure during the manifest
///   atomic-write.
/// - [`VaultError::SaveCryptoFailure`] — crypto / encoding failure on
///   already-validated inputs.
pub fn purge_block(
    identity: std::sync::Arc<UnlockedIdentity>,
    manifest: std::sync::Arc<OpenVaultManifest>,
    block_uuid: Vec<u8>,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> Result<PurgeReport, VaultError> {
    let block_uuid = uuid_from_vec(&block_uuid, "block_uuid")?;
    let device_uuid = uuid_from_vec(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::purge_block(&identity.0, &manifest.0, block_uuid, device_uuid, now_ms)
        .map(|r| PurgeReport {
            block_uuid: r.block_uuid.to_vec(),
            was_shared: r.was_shared,
            recipient_count: r.recipient_count,
            files_removed: r.files_removed,
        })
        .map_err(VaultError::from)
}

/// List every not-yet-purged trashed block, projected by name — uniffi
/// namespace fn projection of [`secretary_ffi_bridge::list_trashed_blocks`].
/// See `ffi/secretary-ffi-bridge/src/trash/list.rs`.
///
/// # Errors
///
/// - [`VaultError::CorruptVault`] — the manifest handle has been wiped,
///   a not-yet-purged trash entry has no matching file on disk, or any
///   decrypt failure while recovering a block's name.
/// - [`VaultError::FolderInvalid`] — IO failure reading a trash file.
pub fn list_trashed_blocks(
    identity: std::sync::Arc<UnlockedIdentity>,
    manifest: std::sync::Arc<OpenVaultManifest>,
) -> Result<Vec<TrashedBlock>, VaultError> {
    secretary_ffi_bridge::list_trashed_blocks(&identity.0, &manifest.0)
        .map(|v| {
            v.into_iter()
                .map(|b| TrashedBlock {
                    block_uuid: b.block_uuid.to_vec(),
                    block_name: b.block_name,
                    tombstoned_at_ms: b.tombstoned_at_ms,
                    tombstoned_by: b.tombstoned_by.to_vec(),
                })
                .collect()
        })
        .map_err(VaultError::from)
}

/// Permanently purge every currently-trashed, not-already-purged,
/// not-live block in one batch — uniffi namespace fn projection of
/// [`secretary_ffi_bridge::empty_trash`]. See `docs/vault-format.md` §7
/// (purge extension, #399) for the normative sequence. Unlike
/// `purge_block`, this takes no `block_uuid` — it targets the entire
/// trash in one call.
///
/// # Errors
///
/// - [`VaultError::InvalidArgument`] — wrong-length `device_uuid`.
/// - [`VaultError::CorruptVault`] — either handle has been wiped.
/// - [`VaultError::FolderInvalid`] — IO failure during the manifest
///   atomic-write.
/// - [`VaultError::SaveCryptoFailure`] — crypto / encoding failure on
///   already-validated inputs.
pub fn empty_trash(
    identity: std::sync::Arc<UnlockedIdentity>,
    manifest: std::sync::Arc<OpenVaultManifest>,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> Result<EmptyTrashReport, VaultError> {
    let device_uuid = uuid_from_vec(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::empty_trash(&identity.0, &manifest.0, device_uuid, now_ms)
        .map(|r| EmptyTrashReport {
            purged_count: r.purged_count,
            shared_count: r.shared_count,
            owner_only_count: r.owner_only_count,
            unknown_count: r.unknown_count,
            files_removed: r.files_removed,
            files_failed: r.files_failed,
        })
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
    password: &[u8],
) -> Result<DeviceEnrollOutput, VaultError> {
    // `[ByRef] bytes` (#307): `password` is a zero-copy borrow of the
    // foreign buffer — nothing owned here to zeroize; see
    // open_with_password for the ownership/scrub contract.
    let result: Result<secretary_ffi_bridge::DeviceEnrollOutput, VaultError> =
        match std::str::from_utf8(&folder_path) {
            Ok(s) => {
                let path = std::path::PathBuf::from(s);
                secretary_ffi_bridge::add_device_slot(&path, password).map_err(VaultError::from)
            }
            Err(_) => Err(VaultError::FolderInvalid {
                detail: "folder path contained invalid UTF-8".to_string(),
            }),
        };

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
/// Both are validated before the bridge call. `device_secret` is a zero-copy
/// borrow of the foreign buffer (`[ByRef] bytes`, #307) — the foreign adapter
/// owns it and its scrub; the transient `[u8; 32]` stack copy made here is
/// zeroized on all paths.
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
    device_secret: &[u8],
) -> Result<OpenVaultOutput, VaultError> {
    if device_uuid.len() != 16 {
        return Err(VaultError::InvalidArgument {
            detail: format!("device_uuid must be 16 bytes, got {}", device_uuid.len()),
        });
    }
    if device_secret.len() != 32 {
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
    // `mut` so the [u8; 32] stack copy is zeroized IN PLACE below — a
    // re-binding `let mut` would copy the array and wipe only the copy.
    let mut secret_arr: [u8; 32] = device_secret.try_into().expect("len checked above");

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

    // Zeroize the transient stack copy unconditionally — the borrowed
    // `device_secret` itself is foreign-owned (scrubbed by the adapter).
    secret_arr.zeroize();

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

/// Validate a 32-byte slice (e.g. an `ApprovedWidening.file_fingerprint`);
/// surface wrong length as [`VaultError::InvalidArgument`] with the field
/// name in the detail. Mirrors [`uuid_from_vec`] exactly, for the 32-byte
/// case. (#374)
pub(crate) fn array32_from_vec(bytes: &[u8], field: &str) -> Result<[u8; 32], VaultError> {
    bytes.try_into().map_err(|_| VaultError::InvalidArgument {
        detail: format!("{field} must be 32 bytes, got {}", bytes.len()),
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

/// Pure preview of the entries retention auto-purge would remove — uniffi
/// projection of [`secretary_ffi_bridge::expired_trash_entries`]. No I/O;
/// returns an empty sequence on a wiped handle. `docs/vault-format.md`
/// §7 step 5 (#402).
pub fn expired_trash_entries(
    manifest: std::sync::Arc<OpenVaultManifest>,
    window_ms: u64,
    now_ms: u64,
) -> Vec<ExpiredEntry> {
    secretary_ffi_bridge::expired_trash_entries(&manifest.0, window_ms, now_ms)
        .into_iter()
        .map(|e| ExpiredEntry {
            block_uuid: e.block_uuid.to_vec(),
            tombstoned_at_ms: e.tombstoned_at_ms,
            age_ms: e.age_ms,
        })
        .collect()
}

/// Permanently purge every trashed block older than `window_ms` — uniffi
/// projection of [`secretary_ffi_bridge::auto_purge_expired`].
/// `docs/vault-format.md` §7 step 5 (#402).
///
/// # Errors
///
/// - [`VaultError::InvalidArgument`] — wrong-length `device_uuid`.
/// - [`VaultError::CorruptVault`] — either handle has been wiped.
/// - [`VaultError::FolderInvalid`] — IO failure during the manifest write.
/// - [`VaultError::SaveCryptoFailure`] — crypto / encoding failure on
///   already-validated inputs.
pub fn auto_purge_expired(
    identity: std::sync::Arc<UnlockedIdentity>,
    manifest: std::sync::Arc<OpenVaultManifest>,
    window_ms: u64,
    now_ms: u64,
    device_uuid: Vec<u8>,
) -> Result<RetentionPurgeReport, VaultError> {
    let device_uuid = uuid_from_vec(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::auto_purge_expired(
        &identity.0,
        &manifest.0,
        window_ms,
        now_ms,
        device_uuid,
    )
    .map(|r| RetentionPurgeReport {
        purged_count: r.purged_count,
        shared_count: r.shared_count,
        owner_only_count: r.owner_only_count,
        unknown_count: r.unknown_count,
        files_removed: r.files_removed,
        files_failed: r.files_failed,
        window_ms: r.window_ms,
    })
    .map_err(VaultError::from)
}

/// The v1 default retention window (90 days, in ms). uniffi has no UDL
/// `const`, so the value is exposed as a namespace fn reading the single
/// bridge-re-exported core const. `docs/vault-format.md` §7 step 5 (#402).
pub fn default_retention_window_ms() -> u64 {
    secretary_ffi_bridge::DEFAULT_RETENTION_WINDOW_MS
}

/// Read the vault settings record. uniffi projection of
/// `secretary_ffi_bridge::read_settings`; load warnings are not surfaced on
/// the mobile boundary (desktop reads them from the bridge directly).
///
/// # Errors
/// - [`VaultError::CorruptVault`] — a wiped handle.
/// - [`VaultError::FolderInvalid`] / [`VaultError::SaveCryptoFailure`] — read failure.
pub fn read_settings(
    identity: std::sync::Arc<UnlockedIdentity>,
    manifest: std::sync::Arc<OpenVaultManifest>,
) -> Result<Settings, VaultError> {
    secretary_ffi_bridge::read_settings(&identity.0, &manifest.0)
        .map(|(s, _warnings)| Settings::from(s))
        .map_err(VaultError::from)
}

/// Persist the vault settings record. uniffi projection of
/// `secretary_ffi_bridge::write_settings`. Validates bounds and `device_uuid`
/// length at this wrapper (→ `InvalidArgument`), per the input-validation
/// convention; the bridge trusts its caller for bounds.
///
/// # Errors
/// - [`VaultError::InvalidArgument`] — out-of-range settings or wrong-length `device_uuid`.
/// - [`VaultError::CorruptVault`] / [`VaultError::FolderInvalid`] / [`VaultError::SaveCryptoFailure`].
pub fn write_settings(
    identity: std::sync::Arc<UnlockedIdentity>,
    manifest: std::sync::Arc<OpenVaultManifest>,
    settings: Settings,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> Result<(), VaultError> {
    let device_uuid = uuid_from_vec(&device_uuid, "device_uuid")?;
    let bridge_settings = secretary_ffi_bridge::Settings::from(settings);
    secretary_ffi_bridge::validate_save_settings(&bridge_settings).map_err(|e| {
        VaultError::InvalidArgument {
            detail: format!("settings out of range: [{}, {}]", e.min, e.max),
        }
    })?;
    secretary_ffi_bridge::write_settings(
        &identity.0,
        &manifest.0,
        &bridge_settings,
        device_uuid,
        now_ms,
    )
    .map_err(VaultError::from)
}

/// Retention-window bound constants (uniffi has no UDL `const`). The default
/// is the pre-existing `default_retention_window_ms()` (#402); only the
/// min/max bounds are added here so there is exactly one function per value.
pub fn retention_window_min_ms() -> u64 {
    secretary_ffi_bridge::RETENTION_WINDOW_MIN_MS
}
pub fn retention_window_max_ms() -> u64 {
    secretary_ffi_bridge::RETENTION_WINDOW_MAX_MS
}
/// Re-auth-grace-window bound constants.
pub fn reauth_window_default_ms() -> u64 {
    secretary_ffi_bridge::REAUTH_WINDOW_DEFAULT_MS
}
pub fn reauth_window_min_ms() -> u64 {
    secretary_ffi_bridge::REAUTH_WINDOW_MIN_MS
}
pub fn reauth_window_max_ms() -> u64 {
    secretary_ffi_bridge::REAUTH_WINDOW_MAX_MS
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
        match open_vault_with_password(b"\xff\xfe".to_vec(), b"hunter2") {
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
            b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
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
            b"pw",
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
        let folder_path = secretary_test_utils::core_test_data_dir().join("golden_vault_001");
        let folder_bytes = folder_path.to_str().unwrap().as_bytes().to_vec();
        let out = open_vault_with_password(
            folder_bytes,
            &secretary_test_utils::golden_vault_001_password(),
        )
        .unwrap();
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

    #[test]
    fn write_settings_out_of_range_returns_invalid_argument() {
        // Bounds are validated at this uniffi wrapper (adversarial-IPC guard)
        // BEFORE any vault write, so an out-of-range value rejects without
        // mutating the vault — safe to run against the frozen golden fixture.
        let folder_path = secretary_test_utils::core_test_data_dir().join("golden_vault_001");
        let folder_bytes = folder_path.to_str().unwrap().as_bytes().to_vec();
        let out = open_vault_with_password(
            folder_bytes,
            &secretary_test_utils::golden_vault_001_password(),
        )
        .unwrap();
        // retention_window_ms below the 1-day floor is out of range.
        let bad = Settings {
            auto_lock_timeout_ms: 600_000,
            require_password_before_edits: true,
            reauth_grace_window_ms: 120_000,
            retention_window_ms: 999,
        };
        match write_settings(
            out.identity,
            out.manifest,
            bad,
            vec![0x07; 16],
            1_700_000_000_000,
        ) {
            Err(VaultError::InvalidArgument { detail }) => {
                assert!(detail.contains("out of range"), "detail was: {detail}");
            }
            Err(other) => panic!("expected InvalidArgument for out-of-range, got {other:?}"),
            Ok(()) => panic!("expected Err for out-of-range settings"),
        }
    }
}
