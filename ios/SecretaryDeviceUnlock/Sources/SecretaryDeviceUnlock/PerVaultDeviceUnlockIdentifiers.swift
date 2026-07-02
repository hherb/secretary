import Foundation
import CryptoKit

/// Length of a lowercase SHA-256 hex string (32 bytes × 2).
let sha256HexLength = 64

/// Stable per-vault namespace token: lowercase SHA-256 hex of the vault path
/// bytes. Pure — same path → same key; different path → (overwhelmingly)
/// different key. The iOS mirror of Android's `cloudVaultKey(treeUri)`.
///
/// Not security-critical: this is a namespacing hash for Keychain accounts, not
/// a KDF. Correctness (the opened vault matches the enrollment) is still enforced
/// by the coordinator's `vaultId` guard and the post-open UUID check.
public func vaultKey(fromPath vaultPath: Data) -> String {
    SHA256.hash(data: vaultPath)
        .map { String(format: "%02x", $0) }
        .joined()
}

/// The three Keychain identifiers that isolate one vault's device-unlock state
/// from another's. Services stay stable (all Secretary items share one service);
/// the per-vault key rides in the account / applicationTag.
public struct PerVaultDeviceUnlockIdentifiers: Equatable, Sendable {
    public let seKeyTag: String
    public let blobService: String
    public let blobAccount: String
    public let enrollmentService: String
    public let enrollmentAccount: String
}

/// Derive the per-vault Keychain identifiers for a vault path. Pure.
public func perVaultDeviceUnlockIdentifiers(vaultPath: Data) -> PerVaultDeviceUnlockIdentifiers {
    let key = vaultKey(fromPath: vaultPath)
    return PerVaultDeviceUnlockIdentifiers(
        seKeyTag: "com.secretary.deviceSecret.seKey.\(key)",
        blobService: "com.secretary.deviceSecret",
        blobAccount: "wrappedDeviceSecret.\(key)",
        enrollmentService: "com.secretary.enrollment",
        enrollmentAccount: "deviceEnrollment.\(key)")
}
