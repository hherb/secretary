import Foundation
import Security
import SecretaryDeviceUnlock

/// Real `DeviceEnrollmentMetadataStore`: persists the NON-secret enrollment
/// metadata (vaultId + 16-byte device uuid) in the Keychain as a generic
/// password item, this-device-only, with NO biometric gate (it is not secret).
public struct KeychainEnrollmentMetadataStore: DeviceEnrollmentMetadataStore {
    private let service: String
    private let account: String

    public init(service: String = "com.secretary.enrollment",
                account: String = "deviceEnrollment") {
        self.service = service
        self.account = account
    }

    private func baseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }

    public func load() throws -> DeviceEnrollment? {
        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let data = item as? Data else { return nil }
            return try decode(data)
        case errSecItemNotFound:
            return nil
        default:
            throw NSError(domain: "KeychainEnrollmentMetadataStore", code: Int(status))
        }
    }

    public func save(_ enrollment: DeviceEnrollment) throws {
        let data = try encode(enrollment)
        SecItemDelete(baseQuery() as CFDictionary)
        var attrs = baseQuery()
        attrs[kSecValueData as String] = data
        attrs[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(attrs as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw NSError(domain: "KeychainEnrollmentMetadataStore", code: Int(status))
        }
    }

    public func clear() throws {
        let status = SecItemDelete(baseQuery() as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw NSError(domain: "KeychainEnrollmentMetadataStore", code: Int(status))
        }
    }

    /// The device uuid is a fixed 16-byte value (32 hex chars on the wire).
    private static let deviceUuidByteCount = 16

    private struct Wire: Codable { let vaultId: String; let deviceUuidHex: String }

    private func encode(_ e: DeviceEnrollment) throws -> Data {
        let hex = e.deviceUuid.map { String(format: "%02x", $0) }.joined()
        return try JSONEncoder().encode(Wire(vaultId: e.vaultId, deviceUuidHex: hex))
    }

    private func decode(_ data: Data) throws -> DeviceEnrollment {
        let wire = try JSONDecoder().decode(Wire.self, from: data)
        let hex = wire.deviceUuidHex
        // Reject a corrupt/tampered item loudly rather than fabricating a wrong
        // uuid: a wrong-length or non-hex string must throw, not silently decode
        // to zero/truncated bytes (which would only surface as a confusing
        // vaultSlotMismatch much later).
        guard hex.count == Self.deviceUuidByteCount * 2 else {
            throw Self.decodeError("deviceUuid hex must be \(Self.deviceUuidByteCount * 2) chars, got \(hex.count)")
        }
        var bytes = [UInt8]()
        bytes.reserveCapacity(Self.deviceUuidByteCount)
        var i = hex.startIndex
        while i < hex.endIndex {
            let j = hex.index(i, offsetBy: 2) // safe: count is even (guarded above)
            guard let byte = UInt8(hex[i..<j], radix: 16) else {
                throw Self.decodeError("deviceUuid contains non-hex characters")
            }
            bytes.append(byte)
            i = j
        }
        return DeviceEnrollment(vaultId: wire.vaultId, deviceUuid: bytes)
    }

    private static func decodeError(_ message: String) -> NSError {
        NSError(domain: "KeychainEnrollmentMetadataStore",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: message])
    }
}
