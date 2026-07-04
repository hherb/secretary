import SecretaryVaultAccess

/// Map the uniffi `VaultError` onto the pure `VaultAccessError`. `internal` (not
/// public) so a vault-access mapping is never reused on a non-vault-access path
/// — same discipline as `UniffiVaultDeviceSlotPort.mapVaultError`.
///
/// CRITICAL: `WrongPasswordOrCorrupt` / `WrongMnemonicOrCorrupt` are the core's
/// deliberately-conflated anti-oracle variants. They map 1:1 and must NOT be
/// split into a "wrong credential" vs "corrupt" distinction here.
///
/// `internal` (must be cross-file: both the open port and the session call it),
/// NOT `public`: do not call from non-vault-access paths (e.g. a future sync or
/// save path) — that would funnel a structurally-different `VaultError` through
/// these vault-access typed cases and misattribute the error.
internal func mapVaultAccessError(_ e: VaultError) -> VaultAccessError {
    switch e {
    case .WrongPasswordOrCorrupt:           return .wrongPasswordOrCorrupt
    case .WrongMnemonicOrCorrupt:           return .wrongMnemonicOrCorrupt
    case .InvalidMnemonic(let detail):      return .invalidMnemonic(detail)
    case .VaultMismatch:                    return .vaultMismatch
    case .CorruptVault(let detail):         return .corruptVault(detail)
    case .BlockNotFound(let uuidHex):       return .blockNotFound(uuidHex)
    case .RecordNotFound(let uuidHex):      return .recordNotFound(uuidHex)
    case .InvalidArgument(let detail):      return .invalidArgument(detail)
    case .FolderInvalid(let detail):        return .folderInvalid(detail)
    // Device-secret open failures. `WrongDeviceSecretOrCorrupt` and
    // `DeviceSlotNotFound` both fold into the SAME anti-oracle case: on this
    // path the user-facing action is identical ("the device key couldn't
    // open this vault, use your password"), so distinguishing them would
    // reintroduce an oracle. `DeviceUuidMismatch` is a header/filename-uuid
    // tamper/relabel signal, orthogonal to credentials, so it is surfaced
    // honestly and distinctly as `.corruptVault` (matches the coordinator's
    // `mapSlotErrors`, which treats it as a non-folded `.vault(...)`).
    case .WrongDeviceSecretOrCorrupt:       return .wrongDeviceSecretOrCorrupt
    case .DeviceSlotNotFound:               return .wrongDeviceSecretOrCorrupt
    case .DeviceUuidMismatch(let detail):   return .corruptVault(detail)
    // #374: the open path now promotes crash-residue (`BlockFingerprintMismatch`)
    // out of `CorruptVault` into these two dedicated arms. iOS ships no repair
    // UI yet, so both map back to `.corruptVault` — the same classification the
    // pre-#374 `CorruptVault` fold produced — rather than silently degrading
    // into the generic `default -> .other` bucket.
    case .VaultNeedsRepair(let blockUuidHex):
        return .corruptVault("crash residue in block \(blockUuidHex)")
    case .RepairRejected(let blockUuidHex, let detail):
        return .corruptVault("repair refused for block \(blockUuidHex): \(detail)")
    default:                                return .other(String(describing: e))
    }
}
