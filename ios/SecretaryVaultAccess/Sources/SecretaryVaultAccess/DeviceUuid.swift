// ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/DeviceUuid.swift
import Foundation
import Security

/// Resolves the 16-byte CRDT modifier UUID for a vault on this device. The edit
/// FFI stamps it onto every field a write touches. Non-secret (a public
/// per-device fingerprint), so it is NOT key material.
public protocol DeviceUuidProviding {
    /// `vaultHex`: lowercase, dash-less vault UUID hex. Returns 16 bytes.
    func deviceUuid(forVaultHex vaultHex: String) throws -> [UInt8]
}

public enum DeviceUuidStoreError: Error, Equatable {
    case entropyUnavailable(OSStatus)
    case corruptLength(Int)
}

/// File-backed `DeviceUuidProviding` mirroring desktop
/// `settings/io.rs::load_or_create_device_uuid_in`: random 16 bytes per
/// (install, vault), persisted as `<vaultHex>.dev`, read back on later calls so
/// one device == one CRDT fingerprint. iOS apps are single-process per vault, so
/// an atomic write + prior-existence check is sufficient (no cross-process race
/// to guard, unlike desktop's `persist_noclobber`). The file is excluded from
/// iCloud/iTunes backup so a restored backup does not clone the fingerprint.
public struct DeviceUuidStore: DeviceUuidProviding {
    /// 16 bytes — a UUID. Named to avoid a magic literal at the call sites.
    public static let uuidByteLen = 16

    private let directory: URL
    public init(directory: URL) { self.directory = directory }

    /// Production store under `Application Support/Secretary/devices/`.
    public static func applicationSupportDefault() throws -> DeviceUuidStore {
        let base = try FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true)
        return DeviceUuidStore(
            directory: base.appendingPathComponent("Secretary/devices", isDirectory: true))
    }

    public func deviceUuid(forVaultHex vaultHex: String) throws -> [UInt8] {
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true)
        let file = directory.appendingPathComponent("\(vaultHex).dev", isDirectory: false)
        if FileManager.default.fileExists(atPath: file.path) {
            return try Self.readUuid(at: file)
        }
        var uuid = [UInt8](repeating: 0, count: Self.uuidByteLen)
        let status = SecRandomCopyBytes(kSecRandomDefault, Self.uuidByteLen, &uuid)
        guard status == errSecSuccess else {
            throw DeviceUuidStoreError.entropyUnavailable(status)
        }
        do {
            // `.atomic` cannot be combined with `.withoutOverwriting` on Darwin
            // (Foundation raises a fatal error). A 16-byte write is effectively
            // atomic at the OS level; `.withoutOverwriting` alone is sufficient
            // to detect a concurrent same-launch write and converge on the winner.
            try Data(uuid).write(to: file, options: [.withoutOverwriting])
        } catch let e as NSError where e.code == NSFileWriteFileExistsError {
            return try Self.readUuid(at: file)  // lost a same-launch race; converge
        }
        excludeFromBackup(file)
        return uuid
    }

    /// Best-effort: backup exclusion is a correctness hint (don't clone the
    /// fingerprint via restore), not a security control, so a failure here is
    /// non-fatal — the UUID is still usable.
    private func excludeFromBackup(_ url: URL) {
        var mutableUrl = url
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? mutableUrl.setResourceValues(values)
    }

    private static func readUuid(at file: URL) throws -> [UInt8] {
        let bytes = [UInt8](try Data(contentsOf: file))
        guard bytes.count == uuidByteLen else {
            throw DeviceUuidStoreError.corruptLength(bytes.count)
        }
        return bytes
    }
}
