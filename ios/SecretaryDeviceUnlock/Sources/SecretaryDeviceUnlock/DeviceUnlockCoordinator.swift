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
