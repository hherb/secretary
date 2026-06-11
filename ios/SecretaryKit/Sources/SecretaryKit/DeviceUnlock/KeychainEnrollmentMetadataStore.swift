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

    private struct Wire: Codable { let vaultId: String; let deviceUuidHex: String }

    private func encode(_ e: DeviceEnrollment) throws -> Data {
        let hex = e.deviceUuid.map { String(format: "%02x", $0) }.joined()
        return try JSONEncoder().encode(Wire(vaultId: e.vaultId, deviceUuidHex: hex))
    }

    private func decode(_ data: Data) throws -> DeviceEnrollment {
        let wire = try JSONDecoder().decode(Wire.self, from: data)
        var bytes = [UInt8]()
        var i = wire.deviceUuidHex.startIndex
        while i < wire.deviceUuidHex.endIndex {
            let j = wire.deviceUuidHex.index(i, offsetBy: 2)
            bytes.append(UInt8(wire.deviceUuidHex[i..<j], radix: 16) ?? 0)
            i = j
        }
        return DeviceEnrollment(vaultId: wire.vaultId, deviceUuid: bytes)
    }
}
