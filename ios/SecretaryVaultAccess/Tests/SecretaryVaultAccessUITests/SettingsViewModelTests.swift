import XCTest
@testable import SecretaryVaultAccessUI
import SecretaryVaultAccess
import SecretaryVaultAccessTesting

@MainActor
final class SettingsViewModelTests: XCTestCase {
    private let t0 = MonotonicInstant(nanoseconds: 7_000_000)

    private func vs(autoLock: UInt64 = 600_000, requirePw: Bool = true,
                    graceMs: UInt64, retentionMs: UInt64) -> VaultSettings {
        VaultSettings(autoLockTimeoutMs: autoLock, requirePasswordBeforeEdits: requirePw,
                      reauthGraceWindowMs: graceMs, retentionWindowMs: retentionMs)
    }

    /// Records each `(window, seed)` built and returns a fresh `FakeWriteReauthGate`,
    /// so tests can inject a refusal and observe retargets (rebuild count/window).
    @MainActor
    private final class RecordingFactory {
        var builds: [(window: Duration, seed: MonotonicInstant?)] = []
        var gates: [FakeWriteReauthGate] = []
        func make(_ window: Duration, _ seed: MonotonicInstant?) -> WriteReauthGate {
            builds.append((window, seed))
            let g = FakeWriteReauthGate()
            gates.append(g)
            return g
        }
    }

    private func makeGate(_ f: RecordingFactory, window: Duration = .seconds(120)) -> RetargetableReauthGate {
        RetargetableReauthGate(window: window, initialAuthAt: nil, clock: { self.t0 }, makeDelegate: f.make)
    }

    // MARK: load

    func testLoadPopulatesControls() {
        let port = FakeSettingsPort(settings: vs(graceMs: 300_000, retentionMs: 30 * 86_400_000))
        let vm = SettingsViewModel(port: port, gate: makeGate(RecordingFactory()))
        vm.load()
        XCTAssertEqual(vm.retentionDays, 30)
        XCTAssertEqual(vm.graceMinutes, 5)
        XCTAssertNil(vm.error)
    }

    func testLoadFallsBackToDefaultsOnReadError() {
        let port = FakeSettingsPort(settings: vs(graceMs: 300_000, retentionMs: 30 * 86_400_000))
        port.failNextRead = .corruptVault("x")
        let vm = SettingsViewModel(port: port, gate: makeGate(RecordingFactory()))
        vm.load()
        XCTAssertEqual(vm.retentionDays, 90, "fallback to bounds default")
        XCTAssertEqual(vm.graceMinutes, 2)
        XCTAssertEqual(vm.error, .corruptVault("x"))
    }

    // MARK: clamp

    func testSettersClampToBounds() {
        let vm = SettingsViewModel(port: FakeSettingsPort(), gate: makeGate(RecordingFactory()))
        vm.setRetentionDays(0);    XCTAssertEqual(vm.retentionDays, 1)
        vm.setRetentionDays(9999); XCTAssertEqual(vm.retentionDays, 3650)
        vm.setRetentionDays(45);   XCTAssertEqual(vm.retentionDays, 45)
        vm.setGraceMinutes(-5);    XCTAssertEqual(vm.graceMinutes, 0)
        vm.setGraceMinutes(999);   XCTAssertEqual(vm.graceMinutes, 60)
        vm.setGraceMinutes(7);     XCTAssertEqual(vm.graceMinutes, 7)
    }

    func testBoundRangesComeFromProjectedBounds() {
        let vm = SettingsViewModel(port: FakeSettingsPort(), gate: makeGate(RecordingFactory()))
        XCTAssertEqual(vm.retentionDaysRange, 1...3650)
        XCTAssertEqual(vm.graceMinutesRange, 0...60)
    }

    // MARK: save success

    func testSaveWritesPreservesFieldsRetargetsAndBanners() async {
        // Seed non-default round-tripped fields to prove they survive the save.
        let port = FakeSettingsPort(settings: vs(autoLock: 300_000, requirePw: false,
                                                 graceMs: 300_000, retentionMs: 30 * 86_400_000))
        let f = RecordingFactory()
        let vm = SettingsViewModel(port: port, gate: makeGate(f))
        vm.load()
        vm.setRetentionDays(45)
        vm.setGraceMinutes(7)
        await vm.save()

        XCTAssertEqual(port.writtenSettings.count, 1)
        XCTAssertEqual(port.writtenSettings.last,
                       vs(autoLock: 300_000, requirePw: false,
                          graceMs: 7 * 60_000, retentionMs: 45 * 86_400_000),
                       "retention + grace updated; auto-lock + require-password preserved")
        XCTAssertEqual(vm.banner, settingsSavedBanner())
        XCTAssertNil(vm.error)
        XCTAssertEqual(f.builds.count, 2, "gate retargeted once on success")
        XCTAssertEqual(f.builds.last?.window, .milliseconds(7 * 60_000), "retargeted to the new grace window")
    }

    /// A retention-only save (grace window unchanged) must NOT retarget the gate:
    /// `retarget` reseeds presence to `now`, so retargeting on a grace-unchanged
    /// save would silently extend the unattended-write window past the user's last
    /// real auth. The write + banner still happen; only the (needless, weakening)
    /// reseed is skipped.
    func testRetentionOnlyChangeDoesNotRetargetGate() async {
        let port = FakeSettingsPort(settings: vs(graceMs: 120_000, retentionMs: 90 * 86_400_000))
        let f = RecordingFactory()
        let vm = SettingsViewModel(port: port, gate: makeGate(f))
        vm.load()                       // grace populated from persisted (2 min == makeGate's window)
        vm.setRetentionDays(45)         // change retention only; grace untouched
        await vm.save()

        XCTAssertEqual(port.writtenSettings.count, 1, "retention change still persisted")
        XCTAssertEqual(port.writtenSettings.last?.retentionWindowMs, 45 * 86_400_000)
        XCTAssertEqual(port.writtenSettings.last?.reauthGraceWindowMs, 120_000, "grace unchanged")
        XCTAssertEqual(f.builds.count, 1, "no retarget when the grace window did not change")
        XCTAssertEqual(vm.banner, settingsSavedBanner())
        XCTAssertNil(vm.error)
    }

    /// The two UI-less fields (auto-lock, require-password) must be re-read from
    /// disk at save time, never carried from a pre-load placeholder — even if the
    /// user somehow saves before a load ran, they are preserved, not clobbered.
    func testSaveReReadsUneditedFieldsEvenWithoutLoad() async {
        let port = FakeSettingsPort(settings: vs(autoLock: 300_000, requirePw: false,
                                                 graceMs: 300_000, retentionMs: 30 * 86_400_000))
        let vm = SettingsViewModel(port: port, gate: makeGate(RecordingFactory()))
        vm.setRetentionDays(45)                       // edit without a preceding load()
        await vm.save()
        XCTAssertEqual(port.writtenSettings.last?.autoLockTimeoutMs, 300_000,
                       "auto-lock re-read from disk, not a placeholder default")
        XCTAssertEqual(port.writtenSettings.last?.requirePasswordBeforeEdits, false,
                       "require-password re-read from disk, not forced true")
        XCTAssertEqual(port.writtenSettings.last?.retentionWindowMs, 45 * 86_400_000)
    }

    /// A failed pre-write re-read aborts the save (no write, no retarget) after
    /// the gate — nothing is clobbered.
    func testSaveAbortsWhenRereadFails() async {
        let port = FakeSettingsPort()
        let f = RecordingFactory()
        let vm = SettingsViewModel(port: port, gate: makeGate(f))
        vm.load()
        port.failNextRead = .corruptVault("x")        // the save's pre-write re-read throws
        await vm.save()
        XCTAssertEqual(vm.error, .corruptVault("x"))
        XCTAssertTrue(port.writtenSettings.isEmpty, "no write when the pre-write re-read fails")
        XCTAssertEqual(f.builds.count, 1, "no retarget")
        XCTAssertNil(vm.banner)
        XCTAssertEqual(f.gates[0].authorizeCount, 1, "gate consulted before the re-read")
    }

    // MARK: gate refusal

    func testGateRefusalDoesNotWriteRetargetOrBanner() async {
        let port = FakeSettingsPort()
        let f = RecordingFactory()
        let vm = SettingsViewModel(port: port, gate: makeGate(f))
        vm.load()
        vm.setGraceMinutes(30)
        f.gates[0].failNext = .reauthFailed("cancelled")   // the delegate built at init
        await vm.save()

        XCTAssertEqual(vm.error, .reauthFailed("cancelled"))
        XCTAssertTrue(port.writtenSettings.isEmpty, "no write on refused re-auth")
        XCTAssertEqual(f.builds.count, 1, "no retarget on refused re-auth")
        XCTAssertNil(vm.banner)
    }

    func testWriteFailureDoesNotRetargetOrBanner() async {
        let port = FakeSettingsPort()
        port.failNextWrite = .invalidArgument("out of range")
        let f = RecordingFactory()
        let vm = SettingsViewModel(port: port, gate: makeGate(f))
        vm.load()
        await vm.save()

        XCTAssertEqual(vm.error, .invalidArgument("out of range"))
        XCTAssertEqual(f.builds.count, 1, "no retarget when the write itself fails")
        XCTAssertNil(vm.banner)
        XCTAssertEqual(f.gates[0].authorizeCount, 1, "gate was consulted before the failing write")
    }

    // MARK: security — retarget strictly AFTER a successful save

    /// Pins the load-bearing ordering: the save is authorized against the
    /// pre-save window, THEN persisted, THEN the gate retargets to the new
    /// window. If retarget ran first, the widening could self-authorize.
    func testRetargetHappensAfterSaveAgainstPreSaveWindow() async {
        let log = Log()
        let port = LoggingSettingsPort(log: log,
                                       settings: vs(graceMs: 120_000, retentionMs: 90 * 86_400_000),
                                       bounds: FakeSettingsPort.defaultBounds)
        // Delegates log "authorize:<windowSeconds>"; the factory logs "build:<windowSeconds>".
        let gate = RetargetableReauthGate(window: .seconds(120), initialAuthAt: nil, clock: { self.t0 }) { w, _ in
            let label = "\(Int(w.components.seconds))"
            log.events.append("build:\(label)")
            return LoggingGate(label: label, log: log)
        }
        let vm = SettingsViewModel(port: port, gate: gate)
        vm.load()
        vm.setGraceMinutes(10)   // 600 s
        await vm.save()

        XCTAssertEqual(log.events, ["build:120", "authorize:120", "write", "build:600"],
                       "authorize against the pre-save 120s window, persist, THEN retarget to 600s")
    }

    // MARK: concurrency guard

    func testConcurrentSaveIsGuarded() async {
        let blocking = BlockingGate()
        let gate = RetargetableReauthGate(window: .seconds(120), initialAuthAt: nil,
                                          clock: { self.t0 }) { _, _ in blocking }
        let port = FakeSettingsPort()
        let vm = SettingsViewModel(port: port, gate: gate)
        vm.load()

        let first = Task { await vm.save() }
        while blocking.authorizeCount == 0 { await Task.yield() }   // wait until save 1 is at the gate
        XCTAssertTrue(vm.isWriting)
        await vm.save()                                            // save 2: guard → immediate no-op
        XCTAssertEqual(blocking.authorizeCount, 1, "second save never reached the gate")
        XCTAssertTrue(port.writtenSettings.isEmpty)
        blocking.resume()
        await first.value
        XCTAssertEqual(port.writtenSettings.count, 1, "first save completed exactly once")
    }
}

// MARK: - Ordering-test doubles
//
// `SettingsPort` has sync `throws` methods (nonisolated, like `TrashPort`), so a
// conformer cannot be `@MainActor`; these mirror the real `@unchecked Sendable`
// conformers. The tests drive them single-threaded on the main actor, so the
// shared `Log` sees appends in deterministic call order.

private final class Log: @unchecked Sendable {
    var events: [String] = []
}

/// A gate delegate that logs its window label on each authorize (so the ordering
/// test can see which window a save was authorized against).
@MainActor
private final class LoggingGate: WriteReauthGate {
    let label: String
    let log: Log
    init(label: String, log: Log) { self.label = label; self.log = log }
    func authorizeWrite(reason: String) async throws { log.events.append("authorize:\(label)") }
}

private final class LoggingSettingsPort: SettingsPort, @unchecked Sendable {
    let log: Log
    var settings: VaultSettings
    let bounds: SettingsBounds
    init(log: Log, settings: VaultSettings, bounds: SettingsBounds) {
        self.log = log; self.settings = settings; self.bounds = bounds
    }
    func readSettings() throws -> VaultSettings { settings }
    func writeSettings(_ s: VaultSettings) throws { log.events.append("write"); settings = s }
    func settingsBounds() -> SettingsBounds { bounds }
}

/// A gate delegate whose `authorizeWrite` suspends until `resume()`, so the test
/// can hold a save mid-flight and prove a concurrent save is guarded out.
@MainActor
private final class BlockingGate: WriteReauthGate {
    private var continuation: CheckedContinuation<Void, Error>?
    private(set) var authorizeCount = 0
    func authorizeWrite(reason: String) async throws {
        authorizeCount += 1
        try await withCheckedThrowingContinuation { self.continuation = $0 }
    }
    func resume() { continuation?.resume(); continuation = nil }
}
