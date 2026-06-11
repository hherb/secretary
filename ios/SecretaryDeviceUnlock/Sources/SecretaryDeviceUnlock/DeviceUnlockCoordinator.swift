import Foundation

/// Pure orchestration over three injected ports. No I/O of its own.
public struct DeviceUnlockCoordinator {
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

    /// Unlock: biometric-release the secret, then open the vault with it.
    public func unlock(vaultPath: Data, vaultId: String, reason: String) async throws -> OpenedVault {
        guard let enrollment = try metadata.load() else { throw DeviceUnlockError.notEnrolled }
        guard enrollment.vaultId == vaultId else { throw DeviceUnlockError.vaultSlotMismatch }

        var secret = try await enclave.release(reason: reason) // throws DeviceUnlockError
        defer { zeroize(&secret) }

        return try mapSlotErrors {
            try slotPort.openWithDeviceSecret(vaultPath: vaultPath,
                                              deviceUuid: enrollment.deviceUuid,
                                              deviceSecret: secret)
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
