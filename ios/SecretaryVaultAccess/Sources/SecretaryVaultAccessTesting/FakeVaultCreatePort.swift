import Foundation
import SecretaryVaultAccess

/// In-memory `VaultCreatePort` returning a pre-seeded result and spying on the
/// inputs the view-model forwarded.
public final class FakeVaultCreatePort: VaultCreatePort {
    private let result: Result<CreatedVault, VaultProvisioningError>
    public private(set) var lastVaultName: String?
    public private(set) var lastPassword: [UInt8]?
    public private(set) var lastDisplayName: String?

    public init(result: Result<CreatedVault, VaultProvisioningError>) {
        self.result = result
    }

    public func create(parent: URL,
                       vaultName: String,
                       password: [UInt8],
                       displayName: String) throws -> CreatedVault {
        lastVaultName = vaultName
        lastPassword = password
        lastDisplayName = displayName
        return try result.get()
    }
}
