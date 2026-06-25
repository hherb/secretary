import XCTest
@testable import SecretaryKit
import SecretaryVaultAccess

/// #300 concurrency coverage: drive `UniffiVaultSession`'s lock-protected paths
/// (readBlock / wipe / writes) from multiple threads at once. Run under
/// ThreadSanitizer (`ios/scripts/run-ios-tsan.sh`) these prove the `NSLock` +
/// `wiped` guard actually serialize access to the mutable stored properties
/// `currentBlock`, `wiped`, and `cachedDeviceUuid`: with the lock TSan sees a clean
/// happens-before; remove the lock and TSan reports a data race here. Assertions are
/// deliberately timing-independent (no-crash + count/contents that hold under any
/// interleaving), so the tests are NOT flaky — only race *detection*, which TSan
/// does deterministically.
///
/// Opens a temp copy of the frozen `golden_vault_001` KAT (never mutates the
/// original), mirroring `SessionWipeGuardIntegrationTests`.
final class SessionConcurrencyIntegrationTests: XCTestCase {
    private let goldenPassword = "correct horse battery staple"
    private var vaultCopy: URL!

    /// Concurrent worker threads per scenario — large enough that accesses reliably
    /// overlap, small enough to keep the (TSan-slowed) run quick.
    private static let concurrentWorkers = 8
    /// Fresh sessions for the read-vs-wipe scenario: each session's `wipe()` is
    /// terminal, so every concurrent read-vs-wipe sample needs its own session.
    private static let wipeRaceSessions = 4

    /// Shares a non-`Sendable` value across threads. The unsafety is the POINT under
    /// test: `UniffiVaultSession`'s lock is what makes the concurrent access
    /// race-free. Confined to this test target.
    private final class UncheckedBox<T>: @unchecked Sendable {
        let value: T
        init(_ value: T) { self.value = value }
    }

    /// Thread-safe accumulator for results gathered across worker threads.
    private final class Collector<T>: @unchecked Sendable {
        private var items: [T] = []
        private let lock = NSLock()
        func add(_ item: T) { lock.withLock { items.append(item) } }
        var snapshot: [T] { lock.withLock { items } }
    }

    private struct FixedDeviceUuid: DeviceUuidProviding {
        let value: [UInt8]
        func deviceUuid(forVaultHex vaultHex: String) throws -> [UInt8] { value }
    }

    override func setUpWithError() throws {
        let bundled = try XCTUnwrap(
            Bundle.module.url(forResource: "golden_vault_001", withExtension: nil),
            "golden_vault_001 not bundled — run ios/scripts/build-xcframework.sh")
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("gv-concurrency-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        vaultCopy = tmp.appendingPathComponent("golden_vault_001", isDirectory: true)
        try FileManager.default.copyItem(at: bundled, to: vaultCopy)
    }

    override func tearDownWithError() throws {
        if let vaultCopy {
            try? FileManager.default.removeItem(at: vaultCopy.deletingLastPathComponent())
        }
    }

    private func openSession() throws -> UniffiVaultSession {
        let out = try SecretaryKit.openVaultWithPassword(
            folderPath: Data(vaultCopy.path.utf8), password: Data(goldenPassword.utf8))
        return UniffiVaultSession(
            output: out, deviceUuids: FixedDeviceUuid(value: [UInt8](repeating: 0x5A, count: 16)))
    }

    private func firstBlockUuid(_ session: UniffiVaultSession) throws -> [UInt8] {
        try XCTUnwrap(session.blockSummaries().first).uuid
    }

    /// Concurrent reads of the same block are race-free. Exercises the `currentBlock`
    /// evict-and-replace path under contention; every read sees the same fully
    /// decoded block as a single-threaded read.
    func testConcurrentReadsAreRaceFree() throws {
        let session = try openSession()
        let block = try firstBlockUuid(session)
        let baseline = try session.readBlock(blockUuid: block, includeDeleted: false).count
        let box = UncheckedBox(session)
        let blockBox = UncheckedBox(block)
        DispatchQueue.concurrentPerform(iterations: Self.concurrentWorkers) { _ in
            let records = (try? box.value.readBlock(blockUuid: blockBox.value, includeDeleted: false)) ?? []
            XCTAssertEqual(records.count, baseline, "a concurrent read saw a different record count")
        }
    }

    /// Concurrent reads racing one `wipe()` must not crash. Each read either returns
    /// records, returns empty, or throws — all valid open/closed outcomes. The
    /// assertion is reaching the end without a crash or a TSan report on the
    /// `currentBlock`/`wiped` race.
    func testConcurrentReadAndWipeAreRaceFree() throws {
        for _ in 0..<Self.wipeRaceSessions {
            let session = try openSession()
            let block = try firstBlockUuid(session)
            let box = UncheckedBox(session)
            let blockBox = UncheckedBox(block)
            let group = DispatchGroup()
            let queue = DispatchQueue(label: "secretary.concurrency.readwipe", attributes: .concurrent)
            for _ in 0..<Self.concurrentWorkers {
                queue.async(group: group) {
                    _ = try? box.value.readBlock(blockUuid: blockBox.value, includeDeleted: false)
                }
            }
            queue.async(group: group) { box.value.wipe() }
            group.wait()
        }
    }

    /// Concurrent writes are race-free and all land. Exercises `write()`
    /// serialization + the first-write `cachedDeviceUuid` memoization; every appended
    /// record is present on a final single-threaded read.
    func testConcurrentWritesAreRaceFree() throws {
        let session = try openSession()
        let block = try firstBlockUuid(session)
        let box = UncheckedBox(session)
        let blockBox = UncheckedBox(block)
        let appended = Collector<Data>()
        DispatchQueue.concurrentPerform(iterations: Self.concurrentWorkers) { i in
            let content = RecordContentInput(
                recordType: "login", tags: ["concurrent"],
                fields: [FieldContentInput(name: "idx", value: .text("\(i)"))])
            if let uuid = try? box.value.appendRecord(blockUuid: blockBox.value, content: content) {
                appended.add(Data(uuid))
            }
        }
        let got = appended.snapshot
        XCTAssertEqual(got.count, Self.concurrentWorkers, "every concurrent append must succeed")
        // All workers have finished (concurrentPerform joined), so read directly from
        // `session` — the same object as `box.value`, now with no concurrent access.
        let records = try session.readBlock(blockUuid: block, includeDeleted: false)
        let present = Set(records.map { Data($0.uuid) })
        for uuid in got {
            XCTAssertTrue(present.contains(uuid), "an appended record was missing after concurrent writes")
        }
    }
}
