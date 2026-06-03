// Error variant name + detail extractors for VaultError.
//
// The match enumerates every variant of VaultError. If uniffi adds a new case
// the Swift compiler will emit a non-exhaustive-switch error — that's the
// intended tripwire.
//
// Mirrors the Rust variant_name_vault helper in core/tests/conformance_kat_helpers/errors.rs
// and the Kotlin vaultExceptionVariantName in ConformanceErrors.kt.

func vaultErrorName(_ e: VaultError) -> String {
    switch e {
    case .WrongPasswordOrCorrupt: return "WrongPasswordOrCorrupt"
    case .WrongMnemonicOrCorrupt: return "WrongMnemonicOrCorrupt"
    case .InvalidMnemonic: return "InvalidMnemonic"
    case .VaultMismatch: return "VaultMismatch"
    case .CorruptVault: return "CorruptVault"
    case .FolderInvalid: return "FolderInvalid"
    case .BlockNotFound: return "BlockNotFound"
    case .SaveCryptoFailure: return "SaveCryptoFailure"
    case .NotAuthor: return "NotAuthor"
    case .RecipientAlreadyPresent: return "RecipientAlreadyPresent"
    case .MissingRecipientCard: return "MissingRecipientCard"
    case .CardDecodeFailure: return "CardDecodeFailure"
    case .BlockUuidAlreadyLive: return "BlockUuidAlreadyLive"
    case .BlockNotInTrash: return "BlockNotInTrash"
    case .InvalidArgument: return "InvalidArgument"
    case .RecordNotFound: return "RecordNotFound"
    case .ContactAlreadyExists: return "ContactAlreadyExists"
    case .ContactNotFound: return "ContactNotFound"
    case .CannotDeleteOwnerContact: return "CannotDeleteOwnerContact"
    }
}

func vaultErrorDetail(_ e: VaultError) -> String? {
    switch e {
    case .InvalidMnemonic(let d): return d
    case .CorruptVault(let d): return d
    case .FolderInvalid(let d): return d
    case .SaveCryptoFailure(let d): return d
    case .CardDecodeFailure(let d): return d
    case .BlockUuidAlreadyLive(let d): return d
    case .BlockNotInTrash(let d): return d
    case .InvalidArgument(let d): return d
    default: return nil
    }
}
