/// A biometric-gated store for one 32-byte device secret. Conformers throw
/// `DeviceUnlockError` for every failure (biometric, corruption, OS errors).
public protocol DeviceSecretEnclave {
    var isEnrolled: Bool { get }
    /// Generate the hardware key if needed, wrap `secret`, persist the blob.
    /// Replaces any existing enrollment.
    func store(secret: [UInt8]) throws
    /// Biometric-gate, then release the secret. `async` because the real
    /// conformer drives an `LAContext` evaluation.
    func release(reason: String) async throws -> [UInt8]
    /// Delete the key + wrapped blob.
    func clear() throws
}
