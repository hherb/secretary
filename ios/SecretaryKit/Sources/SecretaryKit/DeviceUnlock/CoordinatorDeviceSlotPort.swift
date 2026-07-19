import Foundation
import SecretaryVaultAccess
import SecretaryDeviceUnlock

/// Real `DeviceSlotPort`: adapts the FFI-free `DeviceUnlockCoordinator` to the
/// pure package's port, translating `VaultSlotError` into `VaultAccessError`.
///
/// Lives in SecretaryKit for the same reason `EnclaveBiometricAuthorizer` does: it
/// is the only layer that depends on BOTH `SecretaryVaultAccess` and
/// `SecretaryDeviceUnlock`. Hoisting it into either package would create the
/// cross-dependency those packages deliberately avoid.
///
/// `vaultPath` is captured at construction so the port stays a two-member protocol
/// with no argument threading, and so the pure package never learns what a vault
/// path is. Construction is cheap (no Keychain I/O until `isEnrolled` is read or a
/// revocation runs), so a caller may build one per view update.
public struct CoordinatorDeviceSlotPort: DeviceSlotPort {
    private let coordinator: DeviceUnlockCoordinator
    private let vaultPath: Data

    public init(coordinator: DeviceUnlockCoordinator, vaultPath: Data) {
        self.coordinator = coordinator
        self.vaultPath = vaultPath
    }

    public var isEnrolled: Bool { coordinator.isEnrolled }

    public func forgetThisDevice() throws {
        do {
            try coordinator.disenroll(vaultPath: vaultPath)
        } catch let e as VaultSlotError {
            throw Self.mapSlotError(e)
        } catch {
            throw VaultAccessError.other(String(describing: error))
        }
    }

    /// `VaultSlotError` → `VaultAccessError`. Kept private and local (as
    /// `UniffiVaultDeviceSlotPort.mapVaultError` is) so this device-slot
    /// translation cannot be reused on unrelated paths.
    ///
    /// `.deviceSlotNotFound` is defensive only: `disenroll` already swallows it as
    /// already-gone before it can reach here. It is mapped rather than ignored so a
    /// future coordinator change cannot silently turn a real failure into success.
    private static func mapSlotError(_ e: VaultSlotError) -> VaultAccessError {
        switch e {
        case .deviceSlotNotFound:          return .other("device slot not found")
        case .wrongDeviceSecretOrCorrupt:  return .wrongDeviceSecretOrCorrupt
        case .deviceUuidMismatch(let d):   return .other(d)
        case .invalidArgument(let d):      return .invalidArgument(d)
        case .other(let d):                return .other(d)
        }
    }
}
