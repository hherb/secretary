import XCTest
@testable import SecretaryKit
import SecretaryVaultAccess

/// A device-uuid provider that yields a fixed, known UUID so the test is
/// deterministic.
private struct FixedDeviceUuid: DeviceUuidProviding {
    let value: [UInt8]
    func deviceUuid(forVaultHex vaultHex: String) throws -> [UInt8] { value }
}

/// Real append/edit/tombstone/resurrect FFI on a simulator against a WRITABLE
/// copy of golden_vault_001. The golden vault is a frozen KAT — we copy it to a
/// tempdir and mutate the copy only.
final class RecordEditIntegrationTests: XCTestCase {
    private let goldenPassword = "correct horse battery staple"
    private var vaultCopy: URL!

    override func setUpWithError() throws {
        let bundled = try XCTUnwrap(
            Bundle.module.url(forResource: "golden_vault_001", withExtension: nil),
            "golden_vault_001 not bundled — run ios/scripts/build-xcframework.sh")
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("gv-edit-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        vaultCopy = tmp.appendingPathComponent("golden_vault_001", isDirectory: true)
        try FileManager.default.copyItem(at: bundled, to: vaultCopy)
    }
    override func tearDownWithError() throws {
        if let vaultCopy { try? FileManager.default.removeItem(at: vaultCopy.deletingLastPathComponent()) }
    }
    private var path: Data { Data(vaultCopy.path.utf8) }

    private func openSession(device: [UInt8]) throws -> UniffiVaultSession {
        let out = try SecretaryKit.openVaultWithPassword(
            folderPath: path, password: Data(goldenPassword.utf8))
        return UniffiVaultSession(output: out, deviceUuids: FixedDeviceUuid(value: device))
    }

    func testAddEditDeleteRestoreRoundTrip() throws {
        let device = [UInt8](repeating: 0x5A, count: 16)
        let session = try openSession(device: device)
        defer { session.wipe() }
        let block = try XCTUnwrap(session.blockSummaries().first).uuid

        // ADD a record with two text fields.
        let id = try session.appendRecord(blockUuid: block, content: RecordContentInput(
            recordType: "login", tags: ["work"],
            fields: [FieldContentInput(name: "user", value: .text("alice")),
                     FieldContentInput(name: "pass", value: .text("hunter2"))]))
        var rec = try XCTUnwrap(try session.readBlock(blockUuid: block).first { $0.uuid == id })
        XCTAssertFalse(rec.tombstone)

        // EDIT only "pass"; assert the new value round-trips.
        try session.editRecord(blockUuid: block, recordUuid: id, content: RecordContentInput(
            recordType: "login", tags: ["work"],
            fields: [FieldContentInput(name: "user", value: .text("alice")),
                     FieldContentInput(name: "pass", value: .text("s3cret!"))]))
        rec = try XCTUnwrap(try session.readBlock(blockUuid: block).first { $0.uuid == id })
        let pass = try XCTUnwrap(rec.fields.first { $0.name == "pass" })
        guard case .text(let v) = try pass.reveal() else { return XCTFail("expected text") }
        XCTAssertEqual(v, "s3cret!")

        // DELETE → record stays in the projection but tombstone() flips true.
        try session.tombstoneRecord(blockUuid: block, recordUuid: id)
        let afterDelete = try session.readBlock(blockUuid: block).first { $0.uuid == id }
        XCTAssertEqual(afterDelete?.tombstone, true)

        // RESTORE → tombstone() back to false.
        try session.resurrectRecord(blockUuid: block, recordUuid: id)
        let afterRestore = try session.readBlock(blockUuid: block).first { $0.uuid == id }
        XCTAssertEqual(afterRestore?.tombstone, false)
    }
}
