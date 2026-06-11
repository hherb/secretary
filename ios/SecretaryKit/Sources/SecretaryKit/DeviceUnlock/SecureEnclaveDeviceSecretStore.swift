import Foundation
import Security
import LocalAuthentication
import SecretaryDeviceUnlock

/// Real `DeviceSecretEnclave`: a non-exportable Secure Enclave P-256 key with a
/// biometry-bound access control wraps the 32-byte device secret via ECIES; the
/// SE private key never leaves the enclave. NOT covered by an automated test —
/// real Face ID / Touch ID needs a device (the #202 follow-up's manual proof).
public final class SecureEnclaveDeviceSecretStore: DeviceSecretEnclave {
    private let keyTag: Data
    private let blobService: String
    private let blobAccount: String
    private let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA256AESGCM

    public init(keyTag: String = "com.secretary.deviceSecret.seKey",
                blobService: String = "com.secretary.deviceSecret",
                blobAccount: String = "wrappedDeviceSecret") {
        self.keyTag = Data(keyTag.utf8)
        self.blobService = blobService
        self.blobAccount = blobAccount
    }

    public var isEnrolled: Bool { loadKey() != nil && ((try? loadBlob()) ?? nil) != nil }

    public func store(secret: [UInt8]) throws {
        let key = try ensureKey()
        guard let publicKey = SecKeyCopyPublicKey(key) else {
            throw DeviceUnlockError.enclave("no public key for SE private key")
        }
        guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, algorithm) else {
            throw DeviceUnlockError.enclave("ECIES algorithm unsupported")
        }
        var error: Unmanaged<CFError>?
        guard let cipher = SecKeyCreateEncryptedData(
            publicKey, algorithm, Data(secret) as CFData, &error) as Data? else {
            throw DeviceUnlockError.enclave(cfErrorString(error))
        }
        try saveBlob(cipher)
    }

    public func release(reason: String) async throws -> [UInt8] {
        guard let blob = try loadBlob() else { throw DeviceUnlockError.notEnrolled }
        let context = LAContext()
        context.localizedReason = reason
        guard let key = loadKey(context: context) else { throw DeviceUnlockError.notEnrolled }

        return try await withCheckedThrowingContinuation { continuation in
            // SecKeyCreateDecryptedData on an SE key triggers the biometric prompt.
            var error: Unmanaged<CFError>?
            guard let plain = SecKeyCreateDecryptedData(key, algorithm, blob as CFData, &error) as Data? else {
                continuation.resume(throwing: mapDecryptError(error))
                return
            }
            continuation.resume(returning: [UInt8](plain))
        }
    }

    public func clear() throws {
        let keyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag,
        ]
        let keyStatus = SecItemDelete(keyQuery as CFDictionary)
        guard keyStatus == errSecSuccess || keyStatus == errSecItemNotFound else {
            throw DeviceUnlockError.enclave("SecItemDelete(key) failed: \(keyStatus)")
        }
        let blobStatus = SecItemDelete(blobQuery() as CFDictionary)
        guard blobStatus == errSecSuccess || blobStatus == errSecItemNotFound else {
            throw DeviceUnlockError.enclave("SecItemDelete(blob) failed: \(blobStatus)")
        }
    }

    // MARK: - Key management

    private func ensureKey() throws -> SecKey {
        if let existing = loadKey() { return existing }

        var acError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &acError) else {
            throw DeviceUnlockError.enclave(cfErrorString(acError))
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: keyTag,
                kSecAttrAccessControl as String: access,
            ],
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw DeviceUnlockError.enclave(cfErrorString(error))
        }
        return key
    }

    private func loadKey(context: LAContext? = nil) -> SecKey? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]
        if let context { query[kSecUseAuthenticationContext as String] = context }
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else { return nil }
        // SecItemCopyMatching with kSecReturnRef guarantees a SecKey ref when
        // kSecClassKey is in the query and the call succeeds.
        return (item as! SecKey) // swiftlint:disable:this force_cast
    }

    // MARK: - Blob persistence (the ciphertext is already SE-encrypted)

    private func blobQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: blobService,
            kSecAttrAccount as String: blobAccount,
        ]
    }

    private func saveBlob(_ blob: Data) throws {
        // Defensive delete-before-add so `store` replaces any existing blob. The
        // status is intentionally not inspected: the only outcomes are success
        // or errSecItemNotFound, and any other real failure resurfaces as a
        // thrown error from the SecItemAdd below (e.g. errSecDuplicateItem).
        SecItemDelete(blobQuery() as CFDictionary)
        var attrs = blobQuery()
        attrs[kSecValueData as String] = blob
        attrs[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(attrs as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw DeviceUnlockError.enclave("SecItemAdd(blob) failed: \(status)")
        }
    }

    private func loadBlob() throws -> Data? {
        var query = blobQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:      return item as? Data
        case errSecItemNotFound: return nil
        default:                 throw DeviceUnlockError.enclave("SecItemCopyMatching(blob) failed: \(status)")
        }
    }

    // MARK: - Error mapping

    private func mapDecryptError(_ error: Unmanaged<CFError>?) -> DeviceUnlockError {
        guard let cf = error?.takeRetainedValue() else { return .wrappedSecretCorrupt }
        let nsError = cf as Error as NSError
        if nsError.domain == LAError.errorDomain, let code = LAError.Code(rawValue: nsError.code) {
            switch code {
            case .biometryNotAvailable:                         return .biometryUnavailable
            case .biometryNotEnrolled:                          return .biometryNotEnrolled
            case .biometryLockout:                              return .biometryLockout
            case .userCancel, .appCancel, .systemCancel:        return .userCancelled
            case .authenticationFailed:                         return .authenticationFailed
            default:                                            return .enclave(nsError.localizedDescription)
            }
        }
        return .wrappedSecretCorrupt
    }

    private func cfErrorString(_ error: Unmanaged<CFError>?) -> String {
        guard let cf = error?.takeRetainedValue() else { return "unknown Security.framework error" }
        return (cf as Error).localizedDescription
    }
}
