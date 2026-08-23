// ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/DeviceUuidStoreTests.swift
import XCTest
@testable import SecretaryVaultAccess

final class DeviceUuidStoreTests: XCTestCase {
    private var dir: URL!

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("dev-uuid-\(UUID().uuidString)", isDirectory: true)
    }
    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: dir)
    }

    func testFirstCallMintsSixteenBytesAndPersists() throws {
        let store = DeviceUuidStore(directory: dir)
        let uuid = try store.deviceUuid(forVaultHex: "aa00aa00aa00aa00aa00aa00aa00aa00")
        XCTAssertEqual(uuid.count, 16)
        XCTAssertTrue(FileManager.default.fileExists(
            atPath: dir.appendingPathComponent("aa00aa00aa00aa00aa00aa00aa00aa00.dev").path))
    }

    func testSecondCallReturnsIdenticalBytes() throws {
        let store = DeviceUuidStore(directory: dir)
        let first = try store.deviceUuid(forVaultHex: "bb")
        let second = try store.deviceUuid(forVaultHex: "bb")
        XCTAssertEqual(first, second)
    }

    func testDistinctVaultsGetDistinctUuids() throws {
        let store = DeviceUuidStore(directory: dir)
        let a = try store.deviceUuid(forVaultHex: "01")
        let b = try store.deviceUuid(forVaultHex: "02")
        XCTAssertNotEqual(a, b)
    }

    func testLegacyUuidIsPreservedAndMigratedToCurrentDirectory() throws {
        let legacyDirectory = dir.appendingPathComponent("legacy", isDirectory: true)
        let currentDirectory = dir.appendingPathComponent("current", isDirectory: true)
        try FileManager.default.createDirectory(
            at: legacyDirectory, withIntermediateDirectories: true)
        let vaultHex = "cc"
        let legacyUuid = [UInt8](repeating: 0xA5, count: DeviceUuidStore.uuidByteLen)
        try Data(legacyUuid).write(
            to: legacyDirectory.appendingPathComponent("\(vaultHex).dev"))

        let store = DeviceUuidStore(
            directory: currentDirectory, legacyDirectory: legacyDirectory)
        let resolved = try store.deviceUuid(forVaultHex: vaultHex)

        XCTAssertEqual(resolved, legacyUuid)
        XCTAssertEqual(
            try Data(contentsOf: currentDirectory.appendingPathComponent("\(vaultHex).dev")),
            Data(legacyUuid))
    }
}
