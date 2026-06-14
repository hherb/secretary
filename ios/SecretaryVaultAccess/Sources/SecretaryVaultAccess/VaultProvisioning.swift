import Foundation

/// Wizard step for creating a brand-new vault. Holds only NON-secret data; the
/// recovery phrase is held privately by `VaultProvisioningViewModel`, never in
/// this (Equatable) value.
public enum VaultProvisioningStep: Equatable {
    /// Pick a parent location + type a vault name.
    case folder
    /// Enter display name + password + confirm. Carries the validated inputs
    /// from the folder step.
    case credentials(parent: URL, vaultName: String)
    /// The vault was created + its location persisted; show the recovery phrase.
    case mnemonic
    /// User acknowledged the phrase; the new vault is ready to open.
    case done(VaultLocation)
}

/// Typed failures surfaced by the create wizard. Maps from the FFI `VaultError`
/// (see SecretaryKit's `mapProvisioningError`) plus the local name-validation gate.
/// Note: name validation is caught client-side via `validateVaultName` before any
/// FFI call; there is no `invalidName` variant — FFI `InvalidArgument` maps to
/// `.createFailed("invalid argument: …")` instead.
public enum VaultProvisioningError: Error, Equatable {
    /// Password and confirm did not match (or were empty).
    case passwordMismatch
    /// A folder with that name already exists and is non-empty.
    case folderNotEmpty
    /// The chosen location could not be used (path invalid / unreadable).
    case folderInvalid(String)
    /// Any other create failure, with a diagnostic detail.
    case createFailed(String)
}

/// The product of a successful create: the persisted, openable location plus the
/// one-shot recovery-phrase bytes (UTF-8). The caller (view-model) owns zeroizing
/// `phrase` once the mnemonic step is dismissed.
public struct CreatedVault {
    public let location: VaultLocation
    public var phrase: [UInt8]

    public init(location: VaultLocation, phrase: [UInt8]) {
        self.location = location
        self.phrase = phrase
    }
}

/// Create boundary: mkdir a fresh subfolder named `vaultName` inside the
/// security-scoped `parent`, create a complete vault there via the FFI, build a
/// persistable bookmark, and return the location + recovery phrase. Throws
/// `VaultProvisioningError`. Implementations own all filesystem + FFI I/O so the
/// view-model is host-testable against a fake.
///
/// `async` because create runs Argon2id (CPU-heavy); implementations offload it
/// off the calling actor (see `SecretaryKit.runOffMainActor`).
public protocol VaultCreatePort {
    func create(parent: URL,
                vaultName: String,
                password: [UInt8],
                displayName: String) async throws -> CreatedVault
}

/// Import boundary: cheap, crypto-free check of whether `folder` looks like a
/// vault (contains `vault.toml`). Throws only on an unreadable folder.
public protocol VaultShapeProbe {
    func looksLikeVault(_ folder: URL) throws -> Bool
}

/// Outcome of considering a picked folder for import.
public enum ImportOutcome: Equatable {
    /// The folder is a vault; it has been persisted and is ready to open.
    case opened
    /// The folder does not contain a vault (no `vault.toml`).
    case notAVault
    /// The folder could not be inspected (unreadable / probe error).
    case unavailable(String)
}
