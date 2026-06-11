/// A biometric-gated store for one 32-byte device secret. Conformers throw
/// `DeviceUnlockError` for every failure (biometric, corruption, OS errors).
public protocol DeviceSecretEnclave {
    var isEnrolled: Bool { get }
    /// Raw diagnostic from the most recent `release` failure ("domain=… code=…
    /// mappedTo=…"), for a UI to surface so the real Security-framework taxonomy
    /// can be observed (#202). nil after a successful release.
    var lastReleaseDiagnostic: String? { get }
    /// Generate the hardware key if needed, wrap `secret`, persist the blob.
    /// Replaces any existing enrollment.
    func store(secret: [UInt8]) throws
    /// Biometric-gate, then release the secret. `async` because the real
    /// conformer drives an `LAContext` evaluation.
    func release(reason: String) async throws -> [UInt8]
    /// Delete the key + wrapped blob.
    func clear() throws
}

public extension DeviceSecretEnclave {
    /// Conformers that capture no diagnostic report none — keeps the member
    /// additive (existing conformers compile unchanged).
    var lastReleaseDiagnostic: String? { nil }
}
