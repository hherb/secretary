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
        // Overwrite the released copy: re-auth discards it (we only needed the gate).
        for i in secret.indices { secret[i] = 0 }
        _ = secret
    }
}
