import XCTest
import CryptoKit
@testable import SecretaryDeviceUnlock

final class PerVaultDeviceUnlockIdentifiersTests: XCTestCase {
    // Fixed known-answer: SHA-256("secretary") lowercase hex.
    // Pinned vector (KAT-style) so a hashing change is caught, per the repo's
    // "KATs via fixtures / random elsewhere" discipline.
    private let sampleBytes = Data("secretary".utf8)
    private let sampleKey =
        "a8148532caf684760a38c6e5100fe4742cbe0c0030df36ad74a71abbad4d8369"

    func testVaultKeyIsPinnedSha256Hex() {
        XCTAssertEqual(vaultKey(fromPath: sampleBytes), sampleKey)
    }

    func testVaultKeyIsDeterministic() {
        XCTAssertEqual(vaultKey(fromPath: Data("/a/b/c".utf8)),
                       vaultKey(fromPath: Data("/a/b/c".utf8)))
    }

    func testDifferentPathsYieldDifferentKeys() {
        XCTAssertNotEqual(vaultKey(fromPath: Data("/vault/a".utf8)),
                          vaultKey(fromPath: Data("/vault/b".utf8)))
    }

    func testVaultKeyIsLowercaseHexOfExpectedLength() {
        let key = vaultKey(fromPath: Data("/some/path".utf8))
        XCTAssertEqual(key.count, sha256HexLength)
        XCTAssertTrue(key.allSatisfy { "0123456789abcdef".contains($0) })
    }

    func testIdentifiersCarryDocumentedPrefixesAndVaultKey() {
        let path = Data("/vault/a".utf8)
        let key = vaultKey(fromPath: path)
        let ids = perVaultDeviceUnlockIdentifiers(vaultPath: path)
        XCTAssertEqual(ids.seKeyTag, "com.secretary.deviceSecret.seKey.\(key)")
        XCTAssertEqual(ids.blobService, "com.secretary.deviceSecret")
        XCTAssertEqual(ids.blobAccount, "wrappedDeviceSecret.\(key)")
        XCTAssertEqual(ids.enrollmentService, "com.secretary.enrollment")
        XCTAssertEqual(ids.enrollmentAccount, "deviceEnrollment.\(key)")
    }

    func testDifferentVaultsYieldDistinctPerVaultIdentifiers() {
        let a = perVaultDeviceUnlockIdentifiers(vaultPath: Data("/vault/a".utf8))
        let b = perVaultDeviceUnlockIdentifiers(vaultPath: Data("/vault/b".utf8))
        XCTAssertNotEqual(a.seKeyTag, b.seKeyTag)
        XCTAssertNotEqual(a.blobAccount, b.blobAccount)
        XCTAssertNotEqual(a.enrollmentAccount, b.enrollmentAccount)
        // Stable, shared services group all Secretary items under one service.
        XCTAssertEqual(a.blobService, b.blobService)
        XCTAssertEqual(a.enrollmentService, b.enrollmentService)
    }
}
