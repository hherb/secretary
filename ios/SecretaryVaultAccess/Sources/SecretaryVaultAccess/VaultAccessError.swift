import Foundation

/// Typed failures from opening or browsing a vault. The two "…OrCorrupt" cases
/// deliberately fold "wrong credential" together with "vault corruption": the
/// core (see `docs/.../crypto-design.md` + `error/unlock.rs`) refuses to let a
/// caller distinguish a wrong password from a tampered vault (anti-oracle).
/// Do NOT add a separate "wrong credential" case — that would reintroduce the
/// oracle this conflation exists to prevent.
public enum VaultAccessError: Error, Equatable {
    /// Password open failed: wrong password OR vault corruption (indistinguishable).
    case wrongPasswordOrCorrupt
    /// Recovery open failed: wrong phrase OR vault corruption (indistinguishable).
    case wrongMnemonicOrCorrupt
    /// Recovery phrase was malformed (bad word/length/UTF-8) — a format error,
    /// not a credential check, so it is safe to surface distinctly.
    case invalidMnemonic(String)
    /// Device-secret open failed: wrong device secret OR vault corruption
    /// (indistinguishable), OR the slot/uuid is inconsistent. Folded like the
    /// password/recovery "…OrCorrupt" cases — do NOT split.
    case wrongDeviceSecretOrCorrupt
    /// The opened vault's UUID did not match the expected one.
    case vaultMismatch
    /// A block file was present but undecryptable/undecodable.
    case corruptVault(String)
    /// Block UUID not found in the manifest's live blocks.
    case blockNotFound(String)
    /// Record UUID not found in the target block (for edit/tombstone/resurrect).
    case recordNotFound(String)
    /// FFI input-shape error (e.g. wrong-length UUID).
    case invalidArgument(String)
    /// Vault folder missing or unreadable.
    case folderInvalid(String)
    /// The vault changed on disk since it was opened; the write was refused.
    /// Sync, then retry.
    case vaultChangedOnDisk
    /// The vault on disk is older than this device's saved sync baseline (§10),
    /// so the open was refused. A restored backup or a storage provider serving
    /// a stale copy both produce it; the app cannot tell them apart. The only
    /// remedy is the user-confirmed reset behind a master-password unlock
    /// (`VaultOpenPort.resetSyncStateAndOpen`, #746). No payload.
    case rollbackDetected
    /// Biometric re-auth before a write failed or was cancelled. Carries a short
    /// human label derived from the underlying `DeviceUnlockError`. The write was
    /// NOT performed. Local to this Swift enum — NOT a Rust-bridge `FfiVaultError`.
    case reauthFailed(String)
    /// Any other / unmapped failure, carried as a string (never a raw panic).
    case other(String)
}

extension VaultAccessError: LocalizedError {
    /// Friendly, user-facing message for each case (#454). Surfacing this via
    /// `LocalizedError` lets every call site read `error.localizedDescription`
    /// instead of `String(describing:)` (which leaks the raw Swift case name) or
    /// falling back to Foundation's "The operation couldn't be completed." default.
    ///
    /// The associated diagnostic `String`s are deliberately NOT interpolated into
    /// the copy — they are technical detail (paths, uuids, underlying reasons)
    /// retained on the typed error's associated value for diagnostic inspection,
    /// never shown to the user (enforced by
    /// `testCarriedDiagnosticIsNeverInterpolatedIntoCopy`). Mirrors the clean-prose
    /// approach of `settingsErrorMessage`.
    ///
    /// Anti-oracle: the three folded "…OrCorrupt" cases each keep the
    /// vault-damage possibility explicitly visible, so the message can never be
    /// read as a definitive wrong-credential signal (crypto-design). Do NOT reword
    /// them to blame the credential alone.
    public var errorDescription: String? {
        switch self {
        case .wrongPasswordOrCorrupt:
            return "Couldn’t unlock the vault. The password may be incorrect, or the vault may be damaged."
        case .wrongMnemonicOrCorrupt:
            return "Couldn’t unlock the vault. The recovery phrase may be incorrect, or the vault may be damaged."
        case .invalidMnemonic:
            return "That recovery phrase isn’t valid. Check the words and try again."
        case .wrongDeviceSecretOrCorrupt:
            return "Couldn’t unlock the vault on this device. The saved device key may be invalid, or the vault may be damaged."
        case .vaultMismatch:
            return "This vault doesn’t match the one that was expected."
        case .corruptVault:
            return "The vault appears to be damaged and couldn’t be read."
        case .blockNotFound:
            return "That item is no longer in the vault."
        case .recordNotFound:
            return "That entry is no longer in the vault."
        case .invalidArgument:
            return "That value isn’t valid."
        case .folderInvalid:
            return "That folder isn’t a Secretary vault."
        case .vaultChangedOnDisk:
            return "This vault changed on another device since you opened it. Sync, then try again."
        case .rollbackDetected:
            return "This vault looks older than this device last saw. Unlock with your master password to review it."
        case .reauthFailed:
            return "Re-authentication didn’t complete, so the change wasn’t saved."
        case .other:
            return "Something went wrong. Please try again."
        }
    }
}
