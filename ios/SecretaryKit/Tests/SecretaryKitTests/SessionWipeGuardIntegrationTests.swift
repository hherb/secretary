import XCTest
@testable import SecretaryKit
import SecretaryVaultAccess

/// #300: `UniffiVaultSession` must serialize FFI-handle access under a lock and a
/// `wiped` guard (mirror of the Android session, #250). After `wipe()`, the session
/// is closed: a write must short-circuit with a typed wiped-session error WITHOUT
/// touching the zeroized `identity`/`manifest` handles, and a `readBlock` must never
/// yield plaintext records. The lock's mutual exclusion under genuine concurrency is exercised separately by
/// `SessionConcurrencyIntegrationTests` (run under ThreadSanitizer via
/// `ios/scripts/run-ios-tsan.sh`); this file covers the single-threaded `wiped`-guard
/// semantics.
///
/// Opens a temp copy of the frozen `golden_vault_001` KAT (never mutates the
/// original), mirroring `RecordEditIntegrationTests`.
final class SessionWipeGuardIntegrationTests: XCTestCase {
    private let goldenPassword = "correct horse battery staple"
    private var vaultCopy: URL!

    /// A device-uuid provider yielding a fixed UUID so writes are deterministic.
    private struct FixedDeviceUuid: DeviceUuidProviding {
        let value: [UInt8]
        func deviceUuid(forVaultHex vaultHex: String) throws -> [UInt8] { value }
    }

    override func setUpWithError() throws {
        let bundled = try XCTUnwrap(
            Bundle.module.url(forResource: "golden_vault_001", withExtension: nil),
            "golden_vault_001 not bundled — run ios/scripts/build-xcframework.sh")
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("gv-wipeguard-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        vaultCopy = tmp.appendingPathComponent("golden_vault_001", isDirectory: true)
        try FileManager.default.copyItem(at: bundled, to: vaultCopy)
    }

    override func tearDownWithError() throws {
        if let vaultCopy { try? FileManager.default.removeItem(at: vaultCopy.deletingLastPathComponent()) }
    }

    private func openSession() throws -> UniffiVaultSession {
        let out = try SecretaryKit.openVaultWithPassword(
            folderPath: Data(vaultCopy.path.utf8), password: Data(goldenPassword.utf8))
        return UniffiVaultSession(
            output: out, deviceUuids: FixedDeviceUuid(value: [UInt8](repeating: 0x5A, count: 16)))
    }

    private func sampleRecord() -> RecordContentInput {
        RecordContentInput(
            recordType: "login", tags: ["work"],
            fields: [FieldContentInput(name: "user", value: .text("alice"))])
    }

    /// The teeth: a write on a wiped session throws the typed wiped-session error,
    /// short-circuiting BEFORE the FFI write touches the zeroized handles. Pre-fix,
    /// the write reached the FFI and threw a different (decrypt-on-dead-handle) error.
    func testWriteAfterWipeThrowsWipedSessionError() throws {
        let session = try openSession()
        let block = try XCTUnwrap(session.blockSummaries().first).uuid
        session.wipe()
        XCTAssertThrowsError(try session.appendRecord(blockUuid: block, content: sampleRecord())) { error in
            XCTAssertEqual(error as? VaultAccessError, .other("write on a wiped session"))
        }
    }

    /// A `readBlock` after `wipe()` must never return plaintext records — it either
    /// throws a typed error or returns an empty slice, but never yields data.
    func testReadBlockAfterWipeYieldsNoRecords() throws {
        let session = try openSession()
        let block = try XCTUnwrap(session.blockSummaries().first).uuid
        session.wipe()
        do {
            let records = try session.readBlock(blockUuid: block, includeDeleted: false)
            XCTAssertTrue(records.isEmpty, "a wiped session must not yield records")
        } catch {
            // Throwing a typed error is the equally-acceptable closed-session outcome.
        }
    }

    /// `wipe()` is idempotent: calling it twice is a safe no-op, and the session stays
    /// closed (a subsequent write still throws the wiped-session error).
    func testWipeIsIdempotent() throws {
        let session = try openSession()
        let block = try XCTUnwrap(session.blockSummaries().first).uuid
        session.wipe()
        session.wipe()
        XCTAssertThrowsError(try session.appendRecord(blockUuid: block, content: sampleRecord())) { error in
            XCTAssertEqual(error as? VaultAccessError, .other("write on a wiped session"))
        }
    }
}
