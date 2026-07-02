import Foundation
import SecretaryDeviceUnlock

/// A vault-scoped device-unlock bundle: the coordinator (enroll / isEnrolled /
/// unlock) and the SAME-keyed enclave (needed by the write-reauth gate's
/// `EnclaveBiometricAuthorizer`, which must act on this vault's Secure-Enclave
/// key). iOS analog of Android's `cloudDeviceUnlockCoordinator`.
public struct PerVaultDeviceUnlock {
    public let coordinator: DeviceUnlockCoordinator
    public let enclave: DeviceSecretEnclave
}

/// Build the per-vault device-unlock bundle for `vaultPath`. All Keychain state
/// (Secure-Enclave key, wrapped-secret blob, enrollment metadata) is namespaced
/// by `vaultKey(fromPath:)`, so one vault's enrollment is invisible to another's
/// coordinator — `coordinator.isEnrolled` is thus correct per vault.
public func makePerVaultDeviceUnlock(vaultPath: Data) -> PerVaultDeviceUnlock {
    let ids = perVaultDeviceUnlockIdentifiers(vaultPath: vaultPath)
    let enclave = SecureEnclaveDeviceSecretStore(
        keyTag: ids.seKeyTag,
        blobService: ids.blobService,
        blobAccount: ids.blobAccount)
    let metadata = KeychainEnrollmentMetadataStore(
        service: ids.enrollmentService,
        account: ids.enrollmentAccount)
    let coordinator = DeviceUnlockCoordinator(
        slotPort: UniffiVaultDeviceSlotPort(),
        enclave: enclave,
        metadata: metadata)
    return PerVaultDeviceUnlock(coordinator: coordinator, enclave: enclave)
}
