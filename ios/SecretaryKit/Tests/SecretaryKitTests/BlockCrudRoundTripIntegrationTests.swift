import XCTest
@testable import SecretaryKit
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Real-FFI round-trip: drive the REAL VaultBrowseViewModel over a REAL
/// UniffiVaultSession against a TEMP COPY of golden_vault_001 (never the tracked
/// fixture). create -> select source -> move -> read back the moved field value
/// from the KAT, and confirm the source record is tombstoned.
///
/// Staging pattern mirrors RecordEditIntegrationTests: cp -R the bundled fixture
/// into a fresh tempdir, open via SecretaryKit.openVaultWithPassword, inject a
/// FixedDeviceUuid so the test is deterministic.
@MainActor
final class BlockCrudRoundTripIntegrationTests: XCTestCase {
    private let goldenPassword = "correct horse battery staple"
    private var vaultCopy: URL!

    override func setUpWithError() throws {
        let bundled = try XCTUnwrap(
            Bundle.module.url(forResource: "golden_vault_001", withExtension: nil),
            "golden_vault_001 not bundled — run ios/scripts/build-xcframework.sh")
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("gv-blockcrud-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        vaultCopy = tmp.appendingPathComponent("golden_vault_001", isDirectory: true)
        try FileManager.default.copyItem(at: bundled, to: vaultCopy)
    }

    override func tearDownWithError() throws {
        if let vaultCopy {
            try? FileManager.default.removeItem(at: vaultCopy.deletingLastPathComponent())
        }
    }

    private var path: Data { Data(vaultCopy.path.utf8) }

    /// Device-uuid provider matching RecordEditIntegrationTests' FixedDeviceUuid pattern.
    private struct FixedDeviceUuid: DeviceUuidProviding {
        let value: [UInt8]
        func deviceUuid(forVaultHex vaultHex: String) throws -> [UInt8] { value }
    }

    func testCreateThenMoveRoundTripThroughViewModel() throws {
        // 1. Stage a writable temp copy + open via the real adapter.
        //    Block/field/value confirmed from golden_vault_001_inputs.json:
        //    block_name "Personal logins", field "username", value "owner@example.com".
        let device = [UInt8](repeating: 0x5A, count: 16)
        let out = try SecretaryKit.openVaultWithPassword(
            folderPath: path, password: Data(goldenPassword.utf8))
        let session = UniffiVaultSession(output: out, deviceUuids: FixedDeviceUuid(value: device))
        defer { session.wipe() }
        let vm = VaultBrowseViewModel(session: session)
        vm.loadBlocks()

        // 2. Create a fresh target block.
        vm.startCreateBlock()
        vm.confirmBlockName("Moved")
        XCTAssertNil(vm.error, "createBlock should not error")
        let target = try XCTUnwrap(
            vm.blocks.first { $0.name == "Moved" },
            "newly-created 'Moved' block not found in block list")

        // 3. Select the source block ("Personal logins") and grab its first live record.
        let source = try XCTUnwrap(
            vm.blocks.first { $0.name == "Personal logins" },
            "'Personal logins' block not found — golden_vault_001 fixture may be missing")
        vm.selectBlock(source)
        XCTAssertNil(vm.error, "readBlock on source should not error")
        let record = try XCTUnwrap(
            vm.visibleRecords.first,
            "expected at least one live record in 'Personal logins'")

        // 4. Move it.
        vm.startMoveRecord(record)
        vm.confirmMove(target: target)
        XCTAssertNil(vm.error, "moveRecord should not error")
        XCTAssertNil(vm.movingRecord, "movingRecord should be cleared after a successful move")

        // 5. Read back the TARGET: one live record whose KAT field value survived.
        vm.selectBlock(target)
        XCTAssertNil(vm.error, "readBlock on target should not error")
        let moved = try XCTUnwrap(
            vm.visibleRecords.first,
            "moved record not found in 'Moved' block")
        let field = try XCTUnwrap(
            moved.fields.first { $0.name == "username" },
            "expected 'username' field on the moved record")
        XCTAssertEqual(
            try field.reveal(), .text("owner@example.com"),
            "field value must match the KAT value from golden_vault_001_inputs.json")

        // 6. Source now shows the record tombstoned (withheld unless showDeleted).
        vm.selectBlock(source)
        XCTAssertNil(vm.error, "re-reading source block should not error")
        XCTAssertEqual(vm.visibleRecords.count, 0,
                       "source record must be tombstoned and hidden from the live view")
        vm.showDeleted = true
        XCTAssertEqual(vm.visibleRecords.count, 1,
                       "tombstoned source record must appear when showDeleted is true")
        XCTAssertTrue(
            vm.visibleRecords.first?.tombstone ?? false,
            "the source record must carry tombstone == true")
    }
}
