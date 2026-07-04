//! Error → variant-name mapping + assertion helpers shared by the dispatch loop.

use super::types::{BridgeOrSyntheticErr, Expected};

pub fn variant_name_vault(e: &secretary_ffi_bridge::error::FfiVaultError) -> &'static str {
    use secretary_ffi_bridge::error::FfiVaultError as E;
    match e {
        E::WrongPasswordOrCorrupt => "WrongPasswordOrCorrupt",
        E::WrongMnemonicOrCorrupt => "WrongMnemonicOrCorrupt",
        E::InvalidMnemonic { .. } => "InvalidMnemonic",
        E::VaultMismatch => "VaultMismatch",
        E::CorruptVault { .. } => "CorruptVault",
        E::FolderInvalid { .. } => "FolderInvalid",
        E::BlockNotFound { .. } => "BlockNotFound",
        E::RecordNotFound { .. } => "RecordNotFound",
        E::SaveCryptoFailure { .. } => "SaveCryptoFailure",
        E::NotAuthor { .. } => "NotAuthor",
        E::RecipientAlreadyPresent => "RecipientAlreadyPresent",
        E::RecipientNotPresent => "RecipientNotPresent",
        E::CannotRevokeOwner => "CannotRevokeOwner",
        E::MissingRecipientCard { .. } => "MissingRecipientCard",
        E::CardDecodeFailure { .. } => "CardDecodeFailure",
        E::BlockUuidAlreadyLive { .. } => "BlockUuidAlreadyLive",
        E::BlockNotInTrash { .. } => "BlockNotInTrash",
        E::ContactAlreadyExists { .. } => "ContactAlreadyExists",
        E::ContactNotFound { .. } => "ContactNotFound",
        E::CannotDeleteOwnerContact => "CannotDeleteOwnerContact",
        E::SyncStateVaultMismatch => "SyncStateVaultMismatch",
        E::SyncStateCorrupt { .. } => "SyncStateCorrupt",
        E::SyncEvidenceStale => "SyncEvidenceStale",
        E::SyncInProgress => "SyncInProgress",
        E::SyncFailed { .. } => "SyncFailed",
        E::SyncDecisionsIncomplete => "SyncDecisionsIncomplete",
        E::DeviceSlotNotFound => "DeviceSlotNotFound",
        E::WrongDeviceSecretOrCorrupt => "WrongDeviceSecretOrCorrupt",
        E::DeviceUuidMismatch { .. } => "DeviceUuidMismatch",
        E::VaultFolderNotEmpty => "VaultFolderNotEmpty",
        E::VaultNeedsRepair { .. } => "VaultNeedsRepair",
        E::RepairRejected { .. } => "RepairRejected",
    }
}

pub fn vault_error_detail(e: &secretary_ffi_bridge::error::FfiVaultError) -> Option<&str> {
    use secretary_ffi_bridge::error::FfiVaultError as E;
    match e {
        E::InvalidMnemonic { detail } => Some(detail.as_str()),
        E::CorruptVault { detail } => Some(detail.as_str()),
        E::FolderInvalid { detail } => Some(detail.as_str()),
        E::SaveCryptoFailure { detail } => Some(detail.as_str()),
        E::CardDecodeFailure { detail } => Some(detail.as_str()),
        E::BlockUuidAlreadyLive { detail } => Some(detail.as_str()),
        E::BlockNotInTrash { detail } => Some(detail.as_str()),
        E::DeviceUuidMismatch { detail } => Some(detail.as_str()),
        E::RepairRejected { detail, .. } => Some(detail.as_str()),
        _ => None,
    }
}

pub fn assert_err(
    label: &str,
    actual_variant: &str,
    actual_detail: Option<&str>,
    expected: &Expected,
) {
    let Expected::Err {
        variant,
        detail_contains,
    } = expected
    else {
        panic!("{label}: assert_err called but vector.expected is Ok — programmer error in caller");
    };
    assert_eq!(actual_variant, variant, "{label}: variant mismatch");
    if let Some(needle) = detail_contains {
        let haystack = actual_detail.unwrap_or("");
        assert!(
            haystack.contains(needle.as_str()),
            "{label}: detail '{haystack}' does not contain '{needle}'"
        );
    }
}

pub fn read_block_err_variant(e: &BridgeOrSyntheticErr) -> &str {
    match e {
        BridgeOrSyntheticErr::Bridge(b) => variant_name_vault(b),
        BridgeOrSyntheticErr::Synthetic { variant, .. } => variant,
    }
}

pub fn read_block_err_detail(e: &BridgeOrSyntheticErr) -> Option<&str> {
    match e {
        BridgeOrSyntheticErr::Bridge(b) => vault_error_detail(b),
        BridgeOrSyntheticErr::Synthetic { detail, .. } => Some(detail.as_str()),
    }
}
