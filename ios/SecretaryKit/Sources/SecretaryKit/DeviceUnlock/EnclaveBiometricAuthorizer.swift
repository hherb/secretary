import Foundation
import SecretaryVaultAccess
import SecretaryDeviceUnlock

/// Real `BiometricAuthorizer`: proves presence by driving the Secure-Enclave
/// key-release (the SAME biometry-bound gate as device unlock). The released device
/// secret is zeroized and discarded — re-auth only needs the release to succeed.
public struct EnclaveBiometricAuthorizer: BiometricAuthorizer {
    private let enclave: DeviceSecretEnclave

    public init(enclave: DeviceSecretEnclave) { self.enclave = enclave }

    public var isEnrolled: Bool { enclave.isEnrolled }

    public func authorize(reason: String) async throws {
        var secret = try await enclave.release(reason: reason)
        // Overwrite the released bytes in place before they drop: re-auth only needed
        // the release to succeed, so the secret must not linger. Zeroing the `[UInt8]`
        // directly (not via a `Data` copy) keeps a single buffer to overwrite.
        for i in secret.indices { secret[i] = 0 }
    }
}
