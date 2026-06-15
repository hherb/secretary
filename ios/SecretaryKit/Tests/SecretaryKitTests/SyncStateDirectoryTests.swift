import XCTest
import SecretaryKit

final class SyncStateDirectoryTests: XCTestCase {
    func testAppendsSecretarySyncUnderBaseAndCreates() throws {
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("synctest-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: base) }

        let dir = try defaultSyncStateDir(applicationSupport: base)

        XCTAssertEqual(dir.lastPathComponent, "sync")
        XCTAssertEqual(dir.deletingLastPathComponent().lastPathComponent, "secretary")
        var isDir: ObjCBool = false
        XCTAssertTrue(FileManager.default.fileExists(atPath: dir.path, isDirectory: &isDir))
        XCTAssertTrue(isDir.boolValue)
    }
}
