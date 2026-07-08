// Error variant name + detail extractors for VaultException.
//
// Enumerates every variant of VaultException. If uniffi adds a new variant,
// a new `is VaultException.XYZ` branch is needed here — the exhaustive
// `when` will fail to compile, acting as a tripwire the same way the
// Swift non-exhaustive-switch error does in ConformanceErrors.swift.

import uniffi.secretary.VaultException

internal fun vaultExceptionVariantName(e: VaultException): String = when (e) {
    is VaultException.WrongPasswordOrCorrupt -> "WrongPasswordOrCorrupt"
    is VaultException.WrongMnemonicOrCorrupt -> "WrongMnemonicOrCorrupt"
    is VaultException.InvalidMnemonic -> "InvalidMnemonic"
    is VaultException.VaultMismatch -> "VaultMismatch"
    is VaultException.CorruptVault -> "CorruptVault"
    is VaultException.FolderInvalid -> "FolderInvalid"
    is VaultException.BlockNotFound -> "BlockNotFound"
    is VaultException.InvalidArgument -> "InvalidArgument"
    is VaultException.SaveCryptoFailure -> "SaveCryptoFailure"
    is VaultException.NotAuthor -> "NotAuthor"
    is VaultException.RecipientAlreadyPresent -> "RecipientAlreadyPresent"
    is VaultException.RecipientNotPresent -> "RecipientNotPresent"
    is VaultException.CannotRevokeOwner -> "CannotRevokeOwner"
    is VaultException.MissingRecipientCard -> "MissingRecipientCard"
    is VaultException.CardDecodeFailure -> "CardDecodeFailure"
    is VaultException.BlockUuidAlreadyLive -> "BlockUuidAlreadyLive"
    is VaultException.BlockNotInTrash -> "BlockNotInTrash"
    is VaultException.BlockPurged -> "BlockPurged"
    is VaultException.RecordNotFound -> "RecordNotFound"
    is VaultException.ContactAlreadyExists -> "ContactAlreadyExists"
    is VaultException.ContactNotFound -> "ContactNotFound"
    is VaultException.CannotDeleteOwnerContact -> "CannotDeleteOwnerContact"
    is VaultException.SyncStateVaultMismatch -> "SyncStateVaultMismatch"
    is VaultException.SyncStateCorrupt -> "SyncStateCorrupt"
    is VaultException.SyncEvidenceStale -> "SyncEvidenceStale"
    is VaultException.SyncInProgress -> "SyncInProgress"
    is VaultException.SyncFailed -> "SyncFailed"
    is VaultException.SyncDecisionsIncomplete -> "SyncDecisionsIncomplete"
    is VaultException.DeviceSlotNotFound -> "DeviceSlotNotFound"
    is VaultException.WrongDeviceSecretOrCorrupt -> "WrongDeviceSecretOrCorrupt"
    is VaultException.DeviceUuidMismatch -> "DeviceUuidMismatch"
    is VaultException.VaultFolderNotEmpty -> "VaultFolderNotEmpty"
    is VaultException.VaultNeedsRepair -> "VaultNeedsRepair"
    is VaultException.RepairRejected -> "RepairRejected"
}

// Extract the detail string from VaultException variants that carry one.
// Returns null for variants that carry no detail (e.g. WrongPasswordOrCorrupt).
internal fun vaultExceptionDetail(e: VaultException): String? = when (e) {
    is VaultException.InvalidMnemonic -> e.detail
    is VaultException.CorruptVault -> e.detail
    is VaultException.FolderInvalid -> e.detail
    is VaultException.InvalidArgument -> e.detail
    is VaultException.SaveCryptoFailure -> e.detail
    is VaultException.CardDecodeFailure -> e.detail
    is VaultException.BlockUuidAlreadyLive -> e.detail
    is VaultException.BlockNotInTrash -> e.detail
    is VaultException.BlockPurged -> e.detail
    is VaultException.SyncStateCorrupt -> e.detail
    is VaultException.SyncFailed -> e.detail
    is VaultException.DeviceUuidMismatch -> e.detail
    is VaultException.RepairRejected -> e.detail
    // The remaining variants carry no detail string.
    is VaultException.WrongPasswordOrCorrupt,
    is VaultException.WrongMnemonicOrCorrupt,
    is VaultException.VaultMismatch,
    is VaultException.RecipientAlreadyPresent,
    is VaultException.RecipientNotPresent,
    is VaultException.CannotRevokeOwner,
    is VaultException.NotAuthor,
    is VaultException.MissingRecipientCard,
    is VaultException.BlockNotFound,
    is VaultException.RecordNotFound,
    // ContactAlreadyExists / ContactNotFound carry uuid_hex, not detail.
    is VaultException.ContactAlreadyExists,
    is VaultException.ContactNotFound,
    is VaultException.CannotDeleteOwnerContact,
    is VaultException.SyncStateVaultMismatch,
    is VaultException.SyncEvidenceStale,
    is VaultException.SyncInProgress,
    is VaultException.SyncDecisionsIncomplete,
    is VaultException.DeviceSlotNotFound,
    is VaultException.WrongDeviceSecretOrCorrupt,
    is VaultException.VaultFolderNotEmpty,
    // VaultNeedsRepair carries block_uuid_hex, not detail.
    is VaultException.VaultNeedsRepair -> null
}
