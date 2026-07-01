import Foundation

/// Pure orchestration over three injected ports. No I/O of its own.
///
/// Explicitly `Sendable` (its three ports are `Sendable`): a non-frozen public
/// struct does not export synthesized `Sendable` across the module boundary, and
/// a `@MainActor` view model sends it off-actor to call the `async` `unlock`
/// (#231).
public struct DeviceUnlockCoordinator: Sendable {
    let slotPort: VaultDeviceSlotPort
    let enclave: DeviceSecretEnclave
    let metadata: DeviceEnrollmentMetadataStore

    public init(slotPort: VaultDeviceSlotPort,
                enclave: DeviceSecretEnclave,
                metadata: DeviceEnrollmentMetadataStore) {
        self.slotPort = slotPort
        self.enclave = enclave
        self.metadata = metadata
    }

    /// Enroll this device: password-open + mint a slot, SE-wrap the secret,
    /// persist metadata. Transactional: any mid-flow failure rolls back so no
    /// orphan wrap file or enclave key survives.
    public func enroll(vaultPath: Data, vaultId: String, password: [UInt8]) throws {
        var slot = try mapSlotErrors { try slotPort.addDeviceSlot(vaultPath: vaultPath, password: password) }
        defer { zeroize(&slot.deviceSecret) }

        do {
            try enclave.store(secret: slot.deviceSecret)
        } catch {
            try? slotPort.removeDeviceSlot(vaultPath: vaultPath, deviceUuid: slot.deviceUuid)
            throw error
        }

        do {
            try metadata.save(DeviceEnrollment(vaultId: vaultId, deviceUuid: slot.deviceUuid))
        } catch {
            // Roll back best-effort and rethrow the ORIGINAL save error. The
            // rollback failures are swallowed (`try?`) deliberately: enrollment
            // already did not complete, so a residual SE key / wrap file is
            // recoverable — the next enroll's `store` replaces the key and mints
            // a fresh slot — and masking the real cause with a rollback error
            // would be worse than leaving a recoverable remnant.
            try? enclave.clear()
            try? slotPort.removeDeviceSlot(vaultPath: vaultPath, deviceUuid: slot.deviceUuid)
            throw error
        }
    }

    /// The most recent release diagnostic from the enclave (raw domain+code on a
    /// biometric/decrypt failure), for a UI to surface. Read immediately after a
    /// failed `unlock`; nil after a successful release.
    public var lastReleaseDiagnostic: String? { enclave.lastReleaseDiagnostic }

    /// True iff both the enclave holds a secret AND enrollment metadata exists.
    /// Non-throwing by contract, so a metadata read error reads as "not enrolled"
    /// (`try?` flattens both a thrown error and a nil load to `nil`).
    public var isEnrolled: Bool {
        enclave.isEnrolled && (try? metadata.load()) != nil
    }

    /// Disenroll this device: remove the vault slot (tolerating an already-gone
    /// slot), then clear the enclave key and metadata so no orphan survives.
    public func disenroll(vaultPath: Data) throws {
        if let enrollment = try metadata.load() {
            do {
                try slotPort.removeDeviceSlot(vaultPath: vaultPath, deviceUuid: enrollment.deviceUuid)
            } catch VaultSlotError.deviceSlotNotFound {
                // already gone — fine
            }
        }
        try enclave.clear()
        try metadata.clear()
    }

    /// Biometric-release the device secret for the enrolled vault WITHOUT opening
    /// the vault. Metadata guard runs BEFORE the enclave prompt (no prompt when
    /// not enrolled). The caller zeroizes `credential.secret` after the open.
    public func releaseCredential(reason: String) async throws -> DeviceSecretCredential {
        guard let enrollment = try metadata.load() else { throw DeviceUnlockError.notEnrolled }
        let secret = try await enclave.release(reason: reason) // throws DeviceUnlockError
        return DeviceSecretCredential(deviceUuid: enrollment.deviceUuid,
                                      secret: secret,
                                      enrolledVaultId: enrollment.vaultId)
    }

    /// Unlock: biometric-release the secret (via `releaseCredential`), then open
    /// the vault with it. Retains the `vaultId` guard so a stale enrollment for a
    /// different vault fails BEFORE the biometric prompt.
    public func unlock(vaultPath: Data, vaultId: String, reason: String) async throws -> OpenedVault {
        guard let enrollment = try metadata.load() else { throw DeviceUnlockError.notEnrolled }
        guard enrollment.vaultId == vaultId else { throw DeviceUnlockError.vaultSlotMismatch }

        var cred = try await releaseCredential(reason: reason)
        defer { zeroize(&cred.secret) }

        return try mapSlotErrors {
            try slotPort.openWithDeviceSecret(vaultPath: vaultPath,
                                              deviceUuid: cred.deviceUuid,
                                              deviceSecret: cred.secret)
        }
    }
}

/// Run a port call, translating `VaultSlotError` into the coordinator's typed
/// `DeviceUnlockError` semantics. Module-internal: `unlock` reuses it, and
/// `enroll`'s add path re-throws the mapped error through the caller's `try`.
internal func mapSlotErrors<R>(_ body: () throws -> R) throws -> R {
    do {
        return try body()
    } catch let e as VaultSlotError {
        switch e {
        case .deviceSlotNotFound:          throw DeviceUnlockError.vaultSlotMismatch
        case .wrongDeviceSecretOrCorrupt:  throw DeviceUnlockError.wrongDeviceSecretOrCorrupt
        default:                           throw DeviceUnlockError.vault(e)
        }
    }
}
