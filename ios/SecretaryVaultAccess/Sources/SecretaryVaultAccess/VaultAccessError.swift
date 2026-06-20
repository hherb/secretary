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
    /// Biometric re-auth before a write failed or was cancelled. Carries a short
    /// human label derived from the underlying `DeviceUnlockError`. The write was
    /// NOT performed. Local to this Swift enum — NOT a Rust-bridge `FfiVaultError`.
    case reauthFailed(String)
    /// Any other / unmapped failure, carried as a string (never a raw panic).
    case other(String)
}
