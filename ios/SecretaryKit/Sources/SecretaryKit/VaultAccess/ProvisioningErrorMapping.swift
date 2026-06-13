import Foundation
import SecretaryVaultAccess

/// Map a uniffi `VaultError` from a create call onto the wizard's typed
/// `VaultProvisioningError`. `VaultFolderNotEmpty` is structurally rare (we mkdir
/// a fresh subfolder) but mapped for the name-collides-with-existing-dir case.
func mapProvisioningError(_ e: VaultError) -> VaultProvisioningError {
    switch e {
    case .VaultFolderNotEmpty:
        return .folderNotEmpty
    case .FolderInvalid(let detail):
        return .folderInvalid(detail)
    case .InvalidArgument(let detail):
        // A name that passed Swift validation but the bridge rejected.
        return .createFailed("invalid argument: \(detail)")
    default:
        return .createFailed(String(describing: e))
    }
}
