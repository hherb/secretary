//! uniffi namespace projection of the bridge's block-CRUD primitives.
//!
//! Three thin wrappers over `secretary_ffi_bridge::{create_block,
//! rename_block, move_record}`. Each length-validates its uuid arguments
//! (16 bytes each → otherwise [`VaultError::InvalidArgument`], mirroring
//! `save_block`/`trash_block`). `move_record` additionally enforces
//! `source_block_uuid != target_block_uuid` here (the bridge trusts its
//! caller on that precondition, per `move_record.rs`'s doc comment).

use super::uuid_from_vec;
use crate::errors::VaultError;
use crate::wrappers::identity::UnlockedIdentity;
use crate::wrappers::vault::OpenVaultManifest;

/// Create a new, empty block in an open vault. (block-CRUD slice)
///
/// `block_uuid` and `device_uuid` must each be exactly 16 bytes;
/// otherwise returns [`VaultError::InvalidArgument`].  The caller is
/// expected to supply a fresh CSPRNG-minted UUID; uniqueness is not
/// enforced at the bridge level (a collision would update the colliding
/// block in place rather than error, exactly as documented in
/// [`secretary_ffi_bridge::create_block`]).
///
/// Empty `block_name` is allowed (the spec permits empty block names).
///
/// # Errors
///
/// - [`VaultError::InvalidArgument`] — wrong-length uuid.
/// - [`VaultError::CorruptVault`] — either handle has been wiped.
/// - Save-tail surface ([`VaultError::FolderInvalid`] /
///   [`VaultError::SaveCryptoFailure`]).
pub fn create_block(
    identity: std::sync::Arc<UnlockedIdentity>,
    manifest: std::sync::Arc<OpenVaultManifest>,
    block_uuid: Vec<u8>,
    block_name: String,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> Result<(), VaultError> {
    let block_uuid = uuid_from_vec(&block_uuid, "block_uuid")?;
    let device_uuid = uuid_from_vec(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::create_block(
        &identity.0,
        &manifest.0,
        block_uuid,
        block_name,
        device_uuid,
        now_ms,
    )
    .map_err(VaultError::from)
}

/// Rename a block: replace only `block_name`, preserving every record and
/// all forward-compat `unknown` maps. (block-CRUD slice)
///
/// `block_uuid` and `device_uuid` must each be exactly 16 bytes;
/// otherwise returns [`VaultError::InvalidArgument`].
///
/// Empty `new_block_name` is allowed (the spec permits empty block names).
///
/// # Errors
///
/// - [`VaultError::InvalidArgument`] — wrong-length uuid.
/// - [`VaultError::BlockNotFound`] — `block_uuid` not in the manifest.
/// - [`VaultError::CorruptVault`] — decrypt failure / wiped handle.
/// - Save-tail surface ([`VaultError::FolderInvalid`] /
///   [`VaultError::SaveCryptoFailure`]).
pub fn rename_block(
    identity: std::sync::Arc<UnlockedIdentity>,
    manifest: std::sync::Arc<OpenVaultManifest>,
    block_uuid: Vec<u8>,
    new_block_name: String,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> Result<(), VaultError> {
    let block_uuid = uuid_from_vec(&block_uuid, "block_uuid")?;
    let device_uuid = uuid_from_vec(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::rename_block(
        &identity.0,
        &manifest.0,
        block_uuid,
        new_block_name,
        device_uuid,
        now_ms,
    )
    .map_err(VaultError::from)
}

/// Move a live record from one block to another under a caller-supplied UUID.
/// (block-CRUD slice)
///
/// All five uuid arguments (`source_block_uuid`, `target_block_uuid`,
/// `source_record_uuid`, `new_record_uuid`, `device_uuid`) must each be
/// exactly 16 bytes; otherwise returns [`VaultError::InvalidArgument`].
///
/// `source_block_uuid` and `target_block_uuid` must differ; passing the same
/// UUID for both returns [`VaultError::InvalidArgument`] (the bridge does not
/// check this itself — enforcement lives here).
///
/// Semantics are copy-before-delete: the copy lands in the target before the
/// source is tombstoned, so a mid-move crash leaves the source record
/// intact. `created_at_ms`, per-field `last_mod`/`device_uuid`, field values,
/// and all `unknown` maps (record / field level) are preserved; only
/// `record_uuid` and record-level `last_mod_ms` are fresh.
///
/// # Errors
///
/// - [`VaultError::InvalidArgument`] — wrong-length uuid OR same-block move.
/// - [`VaultError::BlockNotFound`] — `source_block_uuid` or `target_block_uuid`
///   not in the manifest.
/// - [`VaultError::RecordNotFound`] — no LIVE record with `source_record_uuid`
///   in the source block.
/// - [`VaultError::CorruptVault`] — decrypt failure / wiped handle.
/// - Save-tail surface ([`VaultError::FolderInvalid`] /
///   [`VaultError::SaveCryptoFailure`]).
#[allow(clippy::too_many_arguments)]
pub fn move_record(
    identity: std::sync::Arc<UnlockedIdentity>,
    manifest: std::sync::Arc<OpenVaultManifest>,
    source_block_uuid: Vec<u8>,
    target_block_uuid: Vec<u8>,
    source_record_uuid: Vec<u8>,
    new_record_uuid: Vec<u8>,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> Result<(), VaultError> {
    let source_block_uuid = uuid_from_vec(&source_block_uuid, "source_block_uuid")?;
    let target_block_uuid = uuid_from_vec(&target_block_uuid, "target_block_uuid")?;
    let source_record_uuid = uuid_from_vec(&source_record_uuid, "source_record_uuid")?;
    let new_record_uuid = uuid_from_vec(&new_record_uuid, "new_record_uuid")?;
    let device_uuid = uuid_from_vec(&device_uuid, "device_uuid")?;

    if source_block_uuid == target_block_uuid {
        return Err(VaultError::InvalidArgument {
            detail: "source_block_uuid and target_block_uuid must differ".to_string(),
        });
    }

    secretary_ffi_bridge::move_record(
        &identity.0,
        &manifest.0,
        source_block_uuid,
        target_block_uuid,
        source_record_uuid,
        new_record_uuid,
        device_uuid,
        now_ms,
    )
    .map_err(VaultError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::namespace::open_vault_with_password;

    fn open_writable_vault() -> (
        tempfile::TempDir,
        std::sync::Arc<crate::wrappers::identity::UnlockedIdentity>,
        std::sync::Arc<crate::wrappers::vault::OpenVaultManifest>,
    ) {
        let src = secretary_test_utils::core_test_data_dir().join("golden_vault_001");
        let tmp = secretary_test_utils::copy_dir_to_tempdir(&src);
        let folder_bytes = tmp.path().to_str().unwrap().as_bytes().to_vec();
        let out = open_vault_with_password(
            folder_bytes,
            &secretary_test_utils::golden_vault_001_password(),
        )
        .expect("open writable vault");
        (tmp, out.identity, out.manifest)
    }

    // -------------------------------------------------------------------
    // create_block: wrong-length uuid returns InvalidArgument
    // -------------------------------------------------------------------

    #[test]
    fn create_block_wrong_block_uuid_length_returns_invalid_argument() {
        let (_tmp, identity, manifest) = open_writable_vault();
        match create_block(
            identity,
            manifest,
            vec![0u8; 15],
            "test".to_string(),
            vec![0u8; 16],
            1_000,
        ) {
            Err(VaultError::InvalidArgument { detail }) => {
                assert!(
                    detail.contains("block_uuid") && detail.contains("16 bytes"),
                    "detail should mention field and expected size: {detail}"
                );
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn create_block_wrong_device_uuid_length_returns_invalid_argument() {
        let (_tmp, identity, manifest) = open_writable_vault();
        match create_block(
            identity,
            manifest,
            vec![0u8; 16],
            "test".to_string(),
            vec![0u8; 17],
            1_000,
        ) {
            Err(VaultError::InvalidArgument { detail }) => {
                assert!(
                    detail.contains("device_uuid") && detail.contains("16 bytes"),
                    "detail should mention field and expected size: {detail}"
                );
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // rename_block: wrong-length uuid returns InvalidArgument
    // -------------------------------------------------------------------

    #[test]
    fn rename_block_wrong_block_uuid_length_returns_invalid_argument() {
        let (_tmp, identity, manifest) = open_writable_vault();
        match rename_block(
            identity,
            manifest,
            vec![0u8; 10],
            "new".to_string(),
            vec![0u8; 16],
            1_000,
        ) {
            Err(VaultError::InvalidArgument { detail }) => {
                assert!(
                    detail.contains("block_uuid") && detail.contains("16 bytes"),
                    "detail: {detail}"
                );
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn rename_block_wrong_device_uuid_length_returns_invalid_argument() {
        let (_tmp, identity, manifest) = open_writable_vault();
        match rename_block(
            identity,
            manifest,
            vec![0u8; 16],
            "new".to_string(),
            vec![0u8; 17],
            1_000,
        ) {
            Err(VaultError::InvalidArgument { detail }) => {
                assert!(
                    detail.contains("device_uuid") && detail.contains("16 bytes"),
                    "detail should mention field and expected size: {detail}"
                );
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // move_record: wrong-length uuid returns InvalidArgument
    // -------------------------------------------------------------------

    #[test]
    fn move_record_wrong_uuid_length_returns_invalid_argument() {
        let (_tmp, identity, manifest) = open_writable_vault();
        match move_record(
            identity,
            manifest,
            vec![0u8; 15],
            vec![0u8; 16],
            vec![0u8; 16],
            vec![0u8; 16],
            vec![0u8; 16],
            1_000,
        ) {
            Err(VaultError::InvalidArgument { detail }) => {
                assert!(
                    detail.contains("source_block_uuid") && detail.contains("16 bytes"),
                    "detail: {detail}"
                );
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // move_record: same-block guard returns InvalidArgument
    // -------------------------------------------------------------------

    #[test]
    fn move_record_same_block_uuid_returns_invalid_argument() {
        let (_tmp, identity, manifest) = open_writable_vault();
        let same_uuid = vec![0x01u8; 16];
        match move_record(
            identity,
            manifest,
            same_uuid.clone(),
            same_uuid.clone(),
            vec![0u8; 16],
            vec![0u8; 16],
            vec![0u8; 16],
            1_000,
        ) {
            Err(VaultError::InvalidArgument { detail }) => {
                assert!(
                    detail.contains("source_block_uuid") && detail.contains("target_block_uuid"),
                    "detail should name both fields: {detail}"
                );
            }
            other => panic!("expected InvalidArgument for same-block move, got {other:?}"),
        }
    }
}
