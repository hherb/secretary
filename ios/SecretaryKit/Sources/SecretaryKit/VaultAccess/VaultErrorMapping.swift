import SecretaryVaultAccess

/// Map the uniffi `VaultError` onto the pure `VaultAccessError`. `internal` (not
/// public) so a vault-access mapping is never reused on a non-vault-access path
/// — same discipline as `UniffiVaultDeviceSlotPort.mapVaultError`.
///
/// CRITICAL: `WrongPasswordOrCorrupt` / `WrongMnemonicOrCorrupt` are the core's
/// deliberately-conflated anti-oracle variants. They map 1:1 and must NOT be
/// split into a "wrong credential" vs "corrupt" distinction here.
func mapVaultAccessError(_ e: VaultError) -> VaultAccessError {
    switch e {
    case .WrongPasswordOrCorrupt:           return .wrongPasswordOrCorrupt
    case .WrongMnemonicOrCorrupt:           return .wrongMnemonicOrCorrupt
    case .InvalidMnemonic(let detail):      return .invalidMnemonic(detail)
    case .VaultMismatch:                    return .vaultMismatch
    case .CorruptVault(let detail):         return .corruptVault(detail)
    case .BlockNotFound(let uuidHex):       return .blockNotFound(uuidHex)
    case .InvalidArgument(let detail):      return .invalidArgument(detail)
    case .FolderInvalid(let detail):        return .folderInvalid(detail)
    default:                                return .other(String(describing: e))
    }
}
