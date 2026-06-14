# C.3 iOS folder-change detection (slice 2) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the iOS app a debounced, foreground-gated "remote changes detected" signal for an open vault's folder — host-tested pure core plus a real `NSFilePresenter` watcher — without running a sync pass or building UI.

**Architecture:** A pure `FolderChangeDetector` reducer (trailing-debounce + foreground-gate + self-write mute) and a pure `ChangeDetectionMonitor` (`@MainActor`) coordinate two injected ports — `FolderWatchPort` (OS change pulses) and `FlushScheduler` (debounce timer). Both ports are faked for deterministic host tests; `SecretaryKit` supplies thin real conformers (`PresenterFolderWatch`, `DispatchFlushScheduler`) + one simulator smoke test. Detect-only: a change sets an advisory `pendingChanges` flag — it never calls `runPass` (no password in hand after unlock).

**Tech Stack:** Swift (SwiftPM), XCTest, `@MainActor` concurrency, `Duration`/`DispatchTime` (monotonic), `NSFilePresenter`/`NSFileCoordinator`, `DispatchSourceTimer`.

**Spec:** `docs/superpowers/specs/2026-06-15-c3-ios-folder-change-detection-design.md`

---

## File Structure

Pure package — `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/`:
- `MonotonicInstant.swift` — monotonic instant value type + `Duration` ns helper + `ChangeDetectionTuning.defaultDebounceWindow`.
- `FolderChangeDetector.swift` — pure reducer; the decision logic.
- `FolderWatchPort.swift` — `FolderWatchPort` + `FlushScheduler` protocols.
- `ChangeDetectionMonitor.swift` — `@MainActor` glue coordinating detector + ports.

Test doubles — `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/`:
- `FakeFolderWatch.swift`, `ManualFlushScheduler.swift`.

Host tests — `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/`:
- `FolderChangeDetectorTests.swift`, `ChangeDetectionMonitorTests.swift`, `MonotonicInstantTests.swift`.

Real conformers — `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/`:
- `MonotonicClock.swift` — `MonotonicInstant.now()` over `DispatchTime`.
- `PresenterFolderWatch.swift`, `DispatchFlushScheduler.swift`, `ChangeMonitorFactory.swift`.

Sim test — `ios/SecretaryKit/Tests/SecretaryKitTests/`:
- `PresenterFolderWatchTests.swift`.

No `Package.swift` edits — SwiftPM globs `Sources/`/`Tests/`. SecretaryKit already depends on the `SecretaryVaultAccess` product.

---

## Task 1: `MonotonicInstant` value type + tuning constant

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/MonotonicInstant.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/MonotonicInstantTests.swift`

- [ ] **Step 1: Write the failing test**

```swift
// MonotonicInstantTests.swift
import XCTest
@testable import SecretaryVaultAccess

final class MonotonicInstantTests: XCTestCase {
    func testOrdersByNanoseconds() {
        XCTAssertLessThan(MonotonicInstant(nanoseconds: 1), MonotonicInstant(nanoseconds: 2))
    }

    func testAdvanceByDurationAddsWholeNanoseconds() {
        let t = MonotonicInstant(nanoseconds: 1_000)
        XCTAssertEqual(t.advanced(by: .milliseconds(2)), MonotonicInstant(nanoseconds: 2_001_000))
    }

    func testDurationToLaterInstantIsNonNegative() {
        let a = MonotonicInstant(nanoseconds: 1_000)
        let b = MonotonicInstant(nanoseconds: 4_000)
        XCTAssertEqual(a.duration(to: b), .nanoseconds(3_000))
    }

    func testDefaultDebounceWindowIsTwoSeconds() {
        XCTAssertEqual(ChangeDetectionTuning.defaultDebounceWindow, .milliseconds(2_000))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter MonotonicInstantTests`
Expected: FAIL — `cannot find 'MonotonicInstant' in scope`.

- [ ] **Step 3: Write minimal implementation**

```swift
// MonotonicInstant.swift
import Foundation

/// A point on a monotonic timeline, in nanoseconds since an arbitrary fixed
/// origin. Only ordering and differences are meaningful — never interpret as
/// wall-clock time. Keeps the detection core free of any real clock (real
/// instants are stamped by `SecretaryKit`'s `MonotonicInstant.now()`).
public struct MonotonicInstant: Comparable, Equatable, Sendable {
    public let nanoseconds: Int64
    public init(nanoseconds: Int64) { self.nanoseconds = nanoseconds }

    public static func < (lhs: Self, rhs: Self) -> Bool { lhs.nanoseconds < rhs.nanoseconds }

    /// This instant moved forward by `duration`.
    public func advanced(by duration: Duration) -> MonotonicInstant {
        MonotonicInstant(nanoseconds: nanoseconds + duration.wholeNanoseconds)
    }

    /// Gap from this instant to a (presumed later) one. Negative if `later` precedes self.
    public func duration(to later: MonotonicInstant) -> Duration {
        .nanoseconds(later.nanoseconds - nanoseconds)
    }
}

extension Duration {
    /// Whole nanoseconds (drops sub-nanosecond attoseconds). Internal helper for
    /// `MonotonicInstant` arithmetic.
    var wholeNanoseconds: Int64 {
        let (seconds, attoseconds) = components
        return seconds * 1_000_000_000 + attoseconds / 1_000_000_000
    }
}

/// Tunable constants for change detection. Injectable into `FolderChangeDetector`
/// so tests can use a tiny window; production uses the default.
public enum ChangeDetectionTuning {
    /// Trailing-debounce quiet period after the last folder pulse before the
    /// "remote changes detected" signal is raised.
    public static let defaultDebounceWindow: Duration = .milliseconds(2_000)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ios/SecretaryVaultAccess && swift test --filter MonotonicInstantTests`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/MonotonicInstant.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/MonotonicInstantTests.swift
git commit -m "feat(ios-watch): MonotonicInstant value type + debounce tuning constant"
```

---

## Task 2: `FolderChangeDetector` pure reducer

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/FolderChangeDetector.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/FolderChangeDetectorTests.swift`

- [ ] **Step 1: Write the failing test**

```swift
// FolderChangeDetectorTests.swift
import XCTest
@testable import SecretaryVaultAccess

final class FolderChangeDetectorTests: XCTestCase {
    private let window: Duration = .milliseconds(1_000)
    private func t(_ ns: Int64) -> MonotonicInstant { MonotonicInstant(nanoseconds: ns) }
    private func active() -> FolderChangeDetector {
        var d = FolderChangeDetector(debounceWindow: window)
        d.setActive(true)
        return d
    }

    func testSinglePulseRaisesPendingAfterWindow() {
        var d = active()
        d.recordPulse(at: t(0))
        XCTAssertEqual(d.nextFlushDeadline, t(1_000_000_000))   // 0 + 1s
        XCTAssertFalse(d.flush(now: t(999_000_000)))            // not quiet yet
        XCTAssertFalse(d.pendingChanges)
        XCTAssertTrue(d.flush(now: t(1_000_000_000)))           // quiet → raise (returns flipped=true)
        XCTAssertTrue(d.pendingChanges)
        XCTAssertNil(d.nextFlushDeadline)
    }

    func testBurstCoalescesToOneSignal() {
        var d = active()
        d.recordPulse(at: t(0))
        d.recordPulse(at: t(500_000_000))                      // within window → extends deadline
        XCTAssertEqual(d.nextFlushDeadline, t(1_500_000_000))
        XCTAssertFalse(d.flush(now: t(1_000_000_000)))         // old deadline; still noisy
        XCTAssertTrue(d.flush(now: t(1_500_000_000)))          // quiet from last pulse
        XCTAssertTrue(d.pendingChanges)
    }

    func testReorderedPulsesUseLatestInstant() {
        var d = active()
        d.recordPulse(at: t(500_000_000))
        d.recordPulse(at: t(0))                                // arrives late, earlier stamp
        XCTAssertEqual(d.nextFlushDeadline, t(1_500_000_000))  // max-instant wins
    }

    func testPulsesWhileInactiveAreDropped() {
        var d = FolderChangeDetector(debounceWindow: window)   // not active
        d.recordPulse(at: t(0))
        XCTAssertNil(d.nextFlushDeadline)
        XCTAssertFalse(d.flush(now: t(2_000_000_000)))
        XCTAssertFalse(d.pendingChanges)
    }

    func testGoingInactiveResetsPendingAndDeadline() {
        var d = active()
        d.recordPulse(at: t(0))
        _ = d.flush(now: t(1_000_000_000))
        XCTAssertTrue(d.pendingChanges)
        d.setActive(false)
        XCTAssertFalse(d.pendingChanges)
        XCTAssertNil(d.nextFlushDeadline)
    }

    func testMutedPulseIsIgnored() {
        var d = active()
        d.muteUntil(t(1_000_000_000))                          // suppress until 1s
        d.recordPulse(at: t(500_000_000))                      // before mute end → ignored
        XCTAssertNil(d.nextFlushDeadline)
        d.recordPulse(at: t(1_000_000_000))                    // at/after mute end → counts
        XCTAssertEqual(d.nextFlushDeadline, t(2_000_000_000))
    }

    func testAcknowledgeClearsThenLaterPulseReArms() {
        var d = active()
        d.recordPulse(at: t(0))
        _ = d.flush(now: t(1_000_000_000))
        d.acknowledge()
        XCTAssertFalse(d.pendingChanges)
        d.recordPulse(at: t(2_000_000_000))
        XCTAssertEqual(d.nextFlushDeadline, t(3_000_000_000))
    }

    func testFlushDoesNotDoubleFireWhilePending() {
        var d = active()
        d.recordPulse(at: t(0))
        XCTAssertTrue(d.flush(now: t(1_000_000_000)))
        XCTAssertFalse(d.flush(now: t(2_000_000_000)))         // already pending → no second flip
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter FolderChangeDetectorTests`
Expected: FAIL — `cannot find 'FolderChangeDetector' in scope`.

- [ ] **Step 3: Write minimal implementation**

```swift
// FolderChangeDetector.swift
import Foundation

/// Pure, deterministic reducer that turns a noisy stream of folder-change pulses
/// into a single debounced, foreground-gated "pending changes" signal. No real
/// clock or timer: callers supply instants and drive `flush`. Trailing debounce
/// — the signal is raised once the folder has been quiet for `debounceWindow`
/// after the last pulse.
///
/// Advisory + metadata-only: it sees timestamps, never record contents, and a
/// missed/spurious pulse never corrupts anything (sync reconciles truth).
public struct FolderChangeDetector: Sendable {
    public let debounceWindow: Duration
    public private(set) var isActive: Bool
    public private(set) var pendingChanges: Bool
    private var lastPulseAt: MonotonicInstant?
    private var muteBefore: MonotonicInstant?

    public init(debounceWindow: Duration = ChangeDetectionTuning.defaultDebounceWindow) {
        self.debounceWindow = debounceWindow
        self.isActive = false
        self.pendingChanges = false
    }

    /// Instant the monitor should next attempt a `flush`, or nil if nothing is
    /// armed (inactive, already pending, or no pulse seen).
    public var nextFlushDeadline: MonotonicInstant? {
        guard isActive, !pendingChanges, let last = lastPulseAt else { return nil }
        return last.advanced(by: debounceWindow)
    }

    /// Foreground/unlocked gate (ADR-0003 foreground-only). Going inactive resets
    /// detection state for a clean slate on next foreground.
    public mutating func setActive(_ active: Bool) {
        guard active != isActive else { return }
        isActive = active
        if !active {
            lastPulseAt = nil
            pendingChanges = false
        }
    }

    /// Record a watcher pulse. Dropped while inactive or muted. `max` keeps the
    /// armed deadline correct even if near-simultaneous pulses arrive out of order.
    public mutating func recordPulse(at instant: MonotonicInstant) {
        guard isActive else { return }
        if let mute = muteBefore, instant < mute { return }
        lastPulseAt = Swift.max(lastPulseAt ?? instant, instant)
    }

    /// Suppress pulses stamped strictly before `instant` (self-write window).
    public mutating func muteUntil(_ instant: MonotonicInstant) {
        muteBefore = instant
    }

    /// Attempt to raise the signal. Returns true iff this call flipped
    /// `pendingChanges` false→true, so the monitor fires `onChange` exactly once.
    @discardableResult
    public mutating func flush(now: MonotonicInstant) -> Bool {
        guard isActive, !pendingChanges, let last = lastPulseAt else { return false }
        guard now >= last.advanced(by: debounceWindow) else { return false }
        pendingChanges = true
        lastPulseAt = nil          // consumed; further pulses re-arm post-acknowledge
        return true
    }

    /// Caller consumed the signal. A later pulse re-arms.
    public mutating func acknowledge() {
        pendingChanges = false
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ios/SecretaryVaultAccess && swift test --filter FolderChangeDetectorTests`
Expected: PASS (8 tests).

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/FolderChangeDetector.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/FolderChangeDetectorTests.swift
git commit -m "feat(ios-watch): FolderChangeDetector pure debounce/gate/mute reducer"
```

---

## Task 3: `FolderWatchPort` + `FlushScheduler` protocols + fakes

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/FolderWatchPort.swift`
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeFolderWatch.swift`
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/ManualFlushScheduler.swift`

This task defines the seams the monitor (Task 4) is tested against; its own verification is that the fakes compile and a trivial conformance test passes.

- [ ] **Step 1: Write the failing test**

```swift
// Add to FolderChangeDetectorTests.swift's directory as PortFakesTests.swift
import XCTest
@testable import SecretaryVaultAccess
import SecretaryVaultAccessTesting

@MainActor
final class PortFakesTests: XCTestCase {
    func testFakeFolderWatchDeliversEmittedPulse() throws {
        let watch = FakeFolderWatch()
        var seen: MonotonicInstant?
        try watch.start(onPulse: { seen = $0 })
        XCTAssertTrue(watch.started)
        watch.emit(at: MonotonicInstant(nanoseconds: 42))
        XCTAssertEqual(seen, MonotonicInstant(nanoseconds: 42))
        watch.stop()
        XCTAssertEqual(watch.stopCount, 1)
        XCTAssertFalse(watch.started)
    }

    func testFakeFolderWatchStartThrowsConfiguredError() {
        let watch = FakeFolderWatch()
        struct Boom: Error {}
        watch.startError = Boom()
        XCTAssertThrowsError(try watch.start(onPulse: { _ in }))
    }

    func testManualSchedulerFiresPendingWorkOnce() {
        let scheduler = ManualFlushScheduler()
        var fired: MonotonicInstant?
        scheduler.schedule(after: .seconds(1)) { fired = $0 }
        XCTAssertEqual(scheduler.scheduledDelay, .seconds(1))
        scheduler.fire(at: MonotonicInstant(nanoseconds: 7))
        XCTAssertEqual(fired, MonotonicInstant(nanoseconds: 7))
        XCTAssertNil(scheduler.scheduledDelay)
    }

    func testManualSchedulerCancelDropsPendingWork() {
        let scheduler = ManualFlushScheduler()
        var fired = false
        scheduler.schedule(after: .seconds(1)) { _ in fired = true }
        scheduler.cancel()
        XCTAssertEqual(scheduler.cancelCount, 1)
        scheduler.fire(at: MonotonicInstant(nanoseconds: 1))
        XCTAssertFalse(fired)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter PortFakesTests`
Expected: FAIL — `cannot find 'FakeFolderWatch' in scope`.

- [ ] **Step 3: Write minimal implementation**

```swift
// FolderWatchPort.swift
import Foundation

/// Watches a folder and delivers a pulse (with the instant it was observed) on
/// each detected change. Callbacks are delivered on the main actor — real
/// conformers marshal OS callbacks onto it, so consumers need no extra hop.
public protocol FolderWatchPort: AnyObject {
    /// Begin watching. Throws if watching can't start (folder unreadable / scope lost).
    func start(onPulse: @escaping @MainActor (MonotonicInstant) -> Void) throws
    func stop()
}

/// Schedules a single debounce flush. `schedule` replaces any pending-but-unfired
/// work (one outstanding timer). The fire instant is passed to `work`. Callbacks
/// are delivered on the main actor.
public protocol FlushScheduler: AnyObject {
    func schedule(after delay: Duration, _ work: @escaping @MainActor (MonotonicInstant) -> Void)
    func cancel()
}
```

```swift
// FakeFolderWatch.swift
import Foundation
import SecretaryVaultAccess

/// In-memory `FolderWatchPort`. Tests call `emit` to deliver pulses on demand.
public final class FakeFolderWatch: FolderWatchPort {
    public private(set) var started = false
    public private(set) var stopCount = 0
    /// Set before `start` to make it throw.
    public var startError: Error?
    private var onPulse: (@MainActor (MonotonicInstant) -> Void)?

    public init() {}

    public func start(onPulse: @escaping @MainActor (MonotonicInstant) -> Void) throws {
        if let startError { throw startError }
        started = true
        self.onPulse = onPulse
    }

    public func stop() {
        stopCount += 1
        started = false
        onPulse = nil
    }

    /// Test hook: deliver a pulse to the registered callback.
    @MainActor public func emit(at instant: MonotonicInstant) { onPulse?(instant) }
}
```

```swift
// ManualFlushScheduler.swift
import Foundation
import SecretaryVaultAccess

/// In-memory `FlushScheduler`. Tests inspect `scheduledDelay` and call `fire`.
public final class ManualFlushScheduler: FlushScheduler {
    public private(set) var scheduledDelay: Duration?
    public private(set) var cancelCount = 0
    private var pending: (@MainActor (MonotonicInstant) -> Void)?

    public init() {}

    public func schedule(after delay: Duration,
                         _ work: @escaping @MainActor (MonotonicInstant) -> Void) {
        scheduledDelay = delay
        pending = work
    }

    public func cancel() {
        cancelCount += 1
        scheduledDelay = nil
        pending = nil
    }

    /// Test hook: fire the pending work with a chosen instant (no-op if cancelled).
    @MainActor public func fire(at instant: MonotonicInstant) {
        let work = pending
        pending = nil
        scheduledDelay = nil
        work?(instant)
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ios/SecretaryVaultAccess && swift test --filter PortFakesTests`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/FolderWatchPort.swift \
        ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeFolderWatch.swift \
        ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/ManualFlushScheduler.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/PortFakesTests.swift
git commit -m "feat(ios-watch): FolderWatchPort + FlushScheduler protocols + fakes"
```

---

## Task 4: `ChangeDetectionMonitor` (@MainActor glue)

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/ChangeDetectionMonitor.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/ChangeDetectionMonitorTests.swift`

- [ ] **Step 1: Write the failing test**

```swift
// ChangeDetectionMonitorTests.swift
import XCTest
@testable import SecretaryVaultAccess
import SecretaryVaultAccessTesting

@MainActor
final class ChangeDetectionMonitorTests: XCTestCase {
    private let window: Duration = .milliseconds(1_000)
    private func t(_ ns: Int64) -> MonotonicInstant { MonotonicInstant(nanoseconds: ns) }

    private func make(onChange: @escaping () -> Void = {})
        -> (ChangeDetectionMonitor, FakeFolderWatch, ManualFlushScheduler) {
        let watch = FakeFolderWatch()
        let scheduler = ManualFlushScheduler()
        let monitor = ChangeDetectionMonitor(
            detector: FolderChangeDetector(debounceWindow: window),
            watch: watch, scheduler: scheduler, onChange: onChange)
        return (monitor, watch, scheduler)
    }

    func testStartBeginsWatchingAndPulseSchedulesFlush() throws {
        let (monitor, watch, scheduler) = make()
        try monitor.start()
        XCTAssertTrue(watch.started)
        watch.emit(at: t(0))
        XCTAssertEqual(scheduler.scheduledDelay, window)        // armed to deadline
    }

    func testFlushRaisesPendingAndCallsOnChangeOnce() throws {
        var changes = 0
        let (monitor, watch, scheduler) = make(onChange: { changes += 1 })
        try monitor.start()
        watch.emit(at: t(0))
        scheduler.fire(at: t(1_000_000_000))
        XCTAssertTrue(monitor.pendingChanges)
        XCTAssertEqual(changes, 1)
    }

    func testBurstProducesSingleOnChange() throws {
        var changes = 0
        let (monitor, watch, scheduler) = make(onChange: { changes += 1 })
        try monitor.start()
        watch.emit(at: t(0))
        watch.emit(at: t(500_000_000))                          // re-arms to 1.5s
        scheduler.fire(at: t(1_000_000_000))                    // still noisy → re-arm, no fire
        XCTAssertFalse(monitor.pendingChanges)
        scheduler.fire(at: t(1_500_000_000))                    // quiet → fire
        XCTAssertEqual(changes, 1)
        XCTAssertTrue(monitor.pendingChanges)
    }

    func testStopCancelsSchedulerAndStopsWatch() throws {
        let (monitor, watch, scheduler) = make()
        try monitor.start()
        watch.emit(at: t(0))
        monitor.stop()
        XCTAssertGreaterThanOrEqual(scheduler.cancelCount, 1)
        XCTAssertEqual(watch.stopCount, 1)
        XCTAssertFalse(monitor.pendingChanges)
    }

    func testAcknowledgeResetsPending() throws {
        let (monitor, watch, scheduler) = make()
        try monitor.start()
        watch.emit(at: t(0))
        scheduler.fire(at: t(1_000_000_000))
        XCTAssertTrue(monitor.pendingChanges)
        monitor.acknowledge()
        XCTAssertFalse(monitor.pendingChanges)
    }

    func testStartPropagatesWatchError() {
        let (monitor, watch, _) = make()
        struct Boom: Error {}
        watch.startError = Boom()
        XCTAssertThrowsError(try monitor.start())
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter ChangeDetectionMonitorTests`
Expected: FAIL — `cannot find 'ChangeDetectionMonitor' in scope`.

- [ ] **Step 3: Write minimal implementation**

```swift
// ChangeDetectionMonitor.swift
import Foundation

/// Coordinates a `FolderChangeDetector` with a `FolderWatchPort` (OS pulses) and
/// a `FlushScheduler` (debounce timer), exposing an advisory `pendingChanges`
/// flag and an `onChange` callback for a future UI slice. `@MainActor`-isolated:
/// real conformers deliver their callbacks on the main actor, so all detector
/// mutation is serialized there with no extra locking.
///
/// Detect-only: a raised signal never triggers a sync pass (no password in hand
/// after unlock). Acting on it (re-prompt / sync-at-unlock) is slice 3.
@MainActor
public final class ChangeDetectionMonitor {
    private var detector: FolderChangeDetector
    private let watch: FolderWatchPort
    private let scheduler: FlushScheduler
    private let onChange: () -> Void

    /// True once a debounced change is awaiting the user; cleared by `acknowledge`.
    public private(set) var pendingChanges = false

    public init(detector: FolderChangeDetector, watch: FolderWatchPort,
                scheduler: FlushScheduler, onChange: @escaping () -> Void) {
        self.detector = detector
        self.watch = watch
        self.scheduler = scheduler
        self.onChange = onChange
    }

    /// Start watching + gate active. Throws if the watch port can't start.
    public func start() throws {
        detector.setActive(true)
        try watch.start(onPulse: { [weak self] instant in
            self?.handlePulse(at: instant)
        })
    }

    /// Stop watching, cancel any armed flush, gate inactive, clear the signal.
    public func stop() {
        scheduler.cancel()
        watch.stop()
        detector.setActive(false)
        pendingChanges = detector.pendingChanges
    }

    /// Consume the signal (a later change re-arms).
    public func acknowledge() {
        detector.acknowledge()
        pendingChanges = detector.pendingChanges
    }

    /// Suppress watcher pulses stamped before `instant` (self-write window).
    public func muteUntil(_ instant: MonotonicInstant) {
        detector.muteUntil(instant)
    }

    private func handlePulse(at instant: MonotonicInstant) {
        detector.recordPulse(at: instant)
        rearm(now: instant)
    }

    private func rearm(now: MonotonicInstant) {
        guard let deadline = detector.nextFlushDeadline else { scheduler.cancel(); return }
        scheduler.schedule(after: now.duration(to: deadline)) { [weak self] fireInstant in
            self?.handleFlush(now: fireInstant)
        }
    }

    private func handleFlush(now: MonotonicInstant) {
        if detector.flush(now: now) {
            pendingChanges = true
            onChange()
        } else {
            rearm(now: now)        // a later pulse moved the deadline
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ios/SecretaryVaultAccess && swift test --filter ChangeDetectionMonitorTests`
Expected: PASS (6 tests).

- [ ] **Step 5: Run the full pure-package suite (no regressions)**

Run: `cd ios/SecretaryVaultAccess && swift test`
Expected: PASS — all prior tests plus the new ones, 0 failures.

- [ ] **Step 6: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/ChangeDetectionMonitor.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/ChangeDetectionMonitorTests.swift
git commit -m "feat(ios-watch): ChangeDetectionMonitor coordinates detector + ports"
```

---

## Task 5: Real `SecretaryKit` conformers + sim smoke test

**Files:**
- Create: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/MonotonicClock.swift`
- Create: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/PresenterFolderWatch.swift`
- Create: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/DispatchFlushScheduler.swift`
- Create: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/ChangeMonitorFactory.swift`
- Test: `ios/SecretaryKit/Tests/SecretaryKitTests/PresenterFolderWatchTests.swift`

- [ ] **Step 1: Write the failing test (simulator integration)**

```swift
// PresenterFolderWatchTests.swift
import XCTest
@testable import SecretaryKit
import SecretaryVaultAccess

/// Drives the real NSFilePresenter watcher on a temp folder: a coordinated write
/// by another writer should pulse the monitor and (after a short debounce) flip
/// pendingChanges. One real-IO smoke test; logic is covered host-side.
@MainActor
final class PresenterFolderWatchTests: XCTestCase {
    func testCoordinatedWriteRaisesPendingChanges() throws {
        let folder = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }

        let changed = expectation(description: "pendingChanges raised")
        let monitor = makeChangeMonitor(
            folder: folder,
            debounceWindow: .milliseconds(100),
            onChange: { changed.fulfill() })
        try monitor.start()
        defer { monitor.stop() }

        // Write a file via a separate coordinator (filePresenter: nil) so our
        // registered presenter is notified of the external change.
        let target = folder.appendingPathComponent("block-0001.bin")
        let coordinator = NSFileCoordinator(filePresenter: nil)
        var coordError: NSError?
        coordinator.coordinate(writingItemAt: target, options: [], error: &coordError) { url in
            try? Data([0x01, 0x02, 0x03]).write(to: url)
        }
        XCTAssertNil(coordError)

        wait(for: [changed], timeout: 5.0)
        XCTAssertTrue(monitor.pendingChanges)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `IOS_SIM='iPhone 16' bash ios/scripts/run-ios-tests.sh` (or build just the SecretaryKit test target)
Expected: FAIL — `cannot find 'makeChangeMonitor' in scope`.

- [ ] **Step 3: Write minimal implementation**

```swift
// MonotonicClock.swift
import Foundation
import SecretaryVaultAccess

extension MonotonicInstant {
    /// Current monotonic instant from `DispatchTime` (uptime nanoseconds). Lives
    /// in SecretaryKit so the pure package stays free of any real clock.
    static func now() -> MonotonicInstant {
        MonotonicInstant(nanoseconds: Int64(bitPattern: DispatchTime.now().uptimeNanoseconds))
    }
}
```

```swift
// PresenterFolderWatch.swift
import Foundation
import SecretaryVaultAccess

/// Real `FolderWatchPort` over `NSFilePresenter`. Registers on the vault folder
/// and forwards every sub-item change as a pulse, stamped with the current
/// monotonic instant and delivered on the main actor. NSFilePresenter is the most
/// general fit for the security-scoped, possibly-iCloud folders the app opens via
/// bookmarks. (Future: NSMetadataQuery for iCloud-download-specific detection.)
public final class PresenterFolderWatch: NSObject, FolderWatchPort, NSFilePresenter {
    public let presentedItemURL: URL?
    public let presentedItemOperationQueue: OperationQueue
    private var onPulse: (@MainActor (MonotonicInstant) -> Void)?

    public init(folder: URL) {
        self.presentedItemURL = folder
        let queue = OperationQueue()
        queue.maxConcurrentOperationCount = 1   // serial; underlying thread is not main
        self.presentedItemOperationQueue = queue
        super.init()
    }

    public func start(onPulse: @escaping @MainActor (MonotonicInstant) -> Void) throws {
        self.onPulse = onPulse
        NSFileCoordinator.addFilePresenter(self)
    }

    public func stop() {
        NSFileCoordinator.removeFilePresenter(self)
        onPulse = nil
    }

    public func presentedSubitemDidChange(at url: URL) { pulse() }
    public func presentedItemDidChange() { pulse() }

    private func pulse() {
        let instant = MonotonicInstant.now()
        // Hop onto the main actor: the presenter queue is a background serial
        // queue, but the port contract delivers callbacks main-actor-isolated.
        Task { @MainActor [onPulse] in onPulse?(instant) }
    }
}
```

```swift
// DispatchFlushScheduler.swift
import Foundation
import SecretaryVaultAccess

/// Real `FlushScheduler` over a one-shot `DispatchSourceTimer` on the main queue.
/// `schedule` replaces any pending timer (single outstanding flush).
public final class DispatchFlushScheduler: FlushScheduler {
    private var timer: DispatchSourceTimer?

    public init() {}

    public func schedule(after delay: Duration,
                         _ work: @escaping @MainActor (MonotonicInstant) -> Void) {
        cancel()
        let timer = DispatchSource.makeTimerSource(queue: .main)
        timer.schedule(deadline: .now() + delay.asDispatchTimeInterval)
        timer.setEventHandler {
            let instant = MonotonicInstant.now()
            // Fired on the main queue (main thread) → safe to assume main-actor.
            MainActor.assumeIsolated { work(instant) }
        }
        self.timer = timer
        timer.resume()
    }

    public func cancel() {
        timer?.cancel()
        timer = nil
    }
}

private extension Duration {
    /// Non-negative `DispatchTimeInterval` in whole nanoseconds for timer scheduling.
    var asDispatchTimeInterval: DispatchTimeInterval {
        .nanoseconds(Int(Swift.max(0, wholeNanoseconds)))
    }
}
```

```swift
// ChangeMonitorFactory.swift
import Foundation
import SecretaryVaultAccess

/// Compose a ready-to-start `ChangeDetectionMonitor` over the real conformers for
/// `folder`. `debounceWindow` defaults to the production value; tests pass a tiny
/// window. Must be called on the main actor (the monitor is `@MainActor`).
@MainActor
public func makeChangeMonitor(
    folder: URL,
    debounceWindow: Duration = ChangeDetectionTuning.defaultDebounceWindow,
    onChange: @escaping () -> Void
) -> ChangeDetectionMonitor {
    ChangeDetectionMonitor(
        detector: FolderChangeDetector(debounceWindow: debounceWindow),
        watch: PresenterFolderWatch(folder: folder),
        scheduler: DispatchFlushScheduler(),
        onChange: onChange)
}
```

> Note on `wholeNanoseconds`: it is declared `internal` (no access modifier) in `MonotonicInstant.swift`, so it is visible to `DispatchFlushScheduler` only if both are in the same module. They are NOT (pure package vs SecretaryKit). Promote `wholeNanoseconds` to `public` in `MonotonicInstant.swift` as part of this task (one-line change: `public var wholeNanoseconds`), and re-run Task 1's tests to confirm still green.

- [ ] **Step 4: Run test to verify it passes**

Run: `IOS_SIM='iPhone 16' bash ios/scripts/run-ios-tests.sh`
Expected: `** TEST SUCCEEDED **` (includes `PresenterFolderWatchTests`) + `** BUILD SUCCEEDED **`.
If the NSFilePresenter notification proves flaky on the simulator, raise the `wait` timeout before weakening the assertion; do not delete the smoke test.

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/MonotonicClock.swift \
        ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/PresenterFolderWatch.swift \
        ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/DispatchFlushScheduler.swift \
        ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/ChangeMonitorFactory.swift \
        ios/SecretaryKit/Tests/SecretaryKitTests/PresenterFolderWatchTests.swift \
        ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/MonotonicInstant.swift
git commit -m "feat(ios-watch): real NSFilePresenter watcher + dispatch scheduler + factory"
```

---

## Task 6: Docs + full acceptance gauntlet

**Files:**
- Modify: `README.md` (iOS status rows)
- Modify: `ROADMAP.md` (C.3 slice-2 entry)

- [ ] **Step 1: Update README.md** — add a row/line noting iOS C.3 slice 2 (folder-change detection, detect-only signal) shipped, matching the brief dot-point style of the existing iOS status section. Keep it terse (no test-count walls).

- [ ] **Step 2: Update ROADMAP.md** — mark C.3 slice 2 (iOS folder-change detection) done; note slice 3 (sync UI: badge over `pendingChanges` + conflict modal) and the still-deferred `state_dir`/app-group path decision + password-availability policy as next.

- [ ] **Step 3: Run the full acceptance gauntlet**

```bash
cd ios/SecretaryVaultAccess && swift test           # all host tests, 0 failures
cd ../.. && IOS_SIM='iPhone 16' bash ios/scripts/run-ios-tests.sh   # sim + app build
git diff main...HEAD --name-only | grep -vE '^(ios/|docs/|README.md|ROADMAP.md)'   # expect empty
git diff main...HEAD --name-only | grep -E 'core/|ffi/|crypto-design|vault-format|conflict.rs|core/tests/data'  # expect empty
```
Expected: host suite green; `** TEST SUCCEEDED **` + `** BUILD SUCCEEDED **`; both guardrail greps empty (iOS/docs-only slice).

- [ ] **Step 4: Commit**

```bash
git add README.md ROADMAP.md
git commit -m "docs(ios-watch): README + ROADMAP for C.3 folder-change detection"
```

---

## Self-Review

**Spec coverage:**
- Pure detector (debounce/gate/mute/ack) → Task 2. ✓
- Two ports + fakes → Task 3. ✓
- Monitor glue + published `pendingChanges` + `onChange` → Task 4. ✓
- Real NSFilePresenter watcher + dispatch scheduler + factory + sim smoke → Task 5. ✓
- `MonotonicInstant` no-wall-clock core; real `.now()` in SecretaryKit → Tasks 1 + 5. ✓
- Detect-only (no `runPass`), foreground gate (ADR-0003), advisory metadata-only signal, self-write mute hook → encoded in Tasks 2/4 + docs. ✓
- Deferred (state_dir/app-group, UI, NSMetadataQuery) → not built; noted in Task 6 ROADMAP. ✓

**Placeholder scan:** No TBD/TODO; every code step shows full code. ✓

**Type consistency:** `MonotonicInstant`, `nextFlushDeadline`, `recordPulse(at:)`, `flush(now:)`, `muteUntil(_:)`, `acknowledge()`, `setActive(_:)`, `FolderWatchPort.start(onPulse:)`, `FlushScheduler.schedule(after:_:)`/`cancel()`, `ChangeDetectionMonitor(detector:watch:scheduler:onChange:)`, `makeChangeMonitor(folder:debounceWindow:onChange:)`, `MonotonicInstant.now()`, `wholeNanoseconds` (made `public` in Task 5) — names are consistent across all tasks. ✓

**Concurrency:** monitor + factory + fakes' test-hooks + tests are all `@MainActor`; port callback closures are `@escaping @MainActor`; real conformers hop via `Task { @MainActor }` / `MainActor.assumeIsolated` (main-queue). Keeps the zero Sendable/concurrency-warning bar. ✓
