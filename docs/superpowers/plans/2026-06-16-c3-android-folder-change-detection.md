# C.3 Android slice 3 — folder-change detection — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the Android app a debounced, foreground-gated, detect-only "remote changes detected" signal for an open vault's folder, as a faithful Kotlin mirror of iOS slice 2 (#230).

**Architecture:** A pure, host-tested debounce core (`FolderChangeDetector` + two injected ports + `ChangeDetectionMonitor`) in the Android-free `:vault-access` module, plus thin real adapters (`FileObserver` + main-`Looper` `Handler`) in `:kit`, proven by one emulator smoke test. The signal never runs a sync pass (no password in hand after unlock); slice 4 (Compose UI) consumes it.

**Tech Stack:** Kotlin (`:vault-access` = kotlin-jvm, JUnit 5; `:kit` = Android library, JUnit 4 instrumented), `kotlin.time.Duration`, `android.os.FileObserver` / `Handler` / `SystemClock`.

**Spec:** `docs/superpowers/specs/2026-06-16-c3-android-folder-change-detection-design.md`

**Conventions (from the existing code):**
- Package `org.secretary.sync` throughout; one public type per file; small focused files.
- Host tests: JUnit 5 — `import org.junit.jupiter.api.Test` + `org.junit.jupiter.api.Assertions.*`.
- Instrumented tests: JUnit 4 — `@RunWith(AndroidJUnit4::class)` + `org.junit.Assert.*`.
- `ByteArray` never compared with `==` (not relevant here — no byte arrays in this slice).
- Run commands from the `android/` directory. JVM unit tests accept `--tests`; `connectedDebugAndroidTest` does **not** (use `-Pandroid.testInstrumentationRunnerArguments.class=...`).
- Source dirs:
  - `:vault-access` main → `android/vault-access/src/main/kotlin/org/secretary/sync/`
  - `:vault-access` test → `android/vault-access/src/test/kotlin/org/secretary/sync/`
  - `:kit` main → `android/kit/src/main/kotlin/org/secretary/sync/`
  - `:kit` androidTest → `android/kit/src/androidTest/kotlin/org/secretary/sync/`

**File structure (created this slice):**

| File | Module | Responsibility |
|---|---|---|
| `MonotonicInstant.kt` | :vault-access main | Pure monotonic-time value class |
| `ChangeDetectionTuning.kt` | :vault-access main | Named `Duration` constants |
| `FolderChangeDetector.kt` | :vault-access main | Pure debounce reducer |
| `FolderWatchPort.kt` | :vault-access main | Watch seam interface |
| `FlushScheduler.kt` | :vault-access main | Debounce-timer seam interface |
| `ChangeDetectionMonitor.kt` | :vault-access main | Composes detector + ports |
| `MonotonicInstantTest.kt` | :vault-access test | |
| `FolderChangeDetectorTest.kt` | :vault-access test | |
| `FakeFolderWatch.kt` | :vault-access test | Test double for `FolderWatchPort` |
| `ManualFlushScheduler.kt` | :vault-access test | Test double for `FlushScheduler` |
| `ChangeDetectionMonitorTest.kt` | :vault-access test | |
| `MonotonicClock.kt` | :kit main | `monotonicNow()` (SystemClock) |
| `HandlerFlushScheduler.kt` | :kit main | `FlushScheduler` over main `Handler` |
| `FileObserverFolderWatch.kt` | :kit main | `FolderWatchPort` over `FileObserver` (root-only) |
| `ChangeMonitorFactory.kt` | :kit main | `makeChangeMonitor(folder, ...)` composition |
| `FolderWatchInstrumentedTest.kt` | :kit androidTest | Real-`FileObserver` emulator smoke |

No existing files are modified except `README.md` and `ROADMAP.md` (Task 7).

---

### Task 1: `MonotonicInstant` + `ChangeDetectionTuning` (pure value types)

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/sync/MonotonicInstant.kt`
- Create: `android/vault-access/src/main/kotlin/org/secretary/sync/ChangeDetectionTuning.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/sync/MonotonicInstantTest.kt`

- [ ] **Step 1: Write the failing test**

`android/vault-access/src/test/kotlin/org/secretary/sync/MonotonicInstantTest.kt`:
```kotlin
package org.secretary.sync

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.nanoseconds

class MonotonicInstantTest {
    @Test
    fun ordersByNanos() {
        assertTrue(MonotonicInstant(1) < MonotonicInstant(2))
        assertTrue(MonotonicInstant(5) > MonotonicInstant(2))
        assertEquals(MonotonicInstant(3), MonotonicInstant(3))
    }

    @Test
    fun advancedByAddsDuration() {
        val base = MonotonicInstant(1_000_000) // 1 ms
        assertEquals(MonotonicInstant(3_000_000), base.advancedBy(2.milliseconds))
    }

    @Test
    fun durationToIsSignedDifference() {
        val a = MonotonicInstant(1_000_000)
        val b = MonotonicInstant(4_000_000)
        assertEquals(3.milliseconds, a.durationTo(b))
        assertEquals((-3_000_000).nanoseconds, b.durationTo(a))
    }

    @Test
    fun tuningConstantsAreNamed() {
        assertEquals(2_000.milliseconds, ChangeDetectionTuning.defaultDebounceWindow)
        assertEquals(10_000.milliseconds, ChangeDetectionTuning.defaultSelfWriteMuteWindow)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run (from `android/`): `./gradlew :vault-access:test --tests "org.secretary.sync.MonotonicInstantTest"`
Expected: FAIL — unresolved reference `MonotonicInstant` / `ChangeDetectionTuning`.

- [ ] **Step 3: Write the implementations**

`android/vault-access/src/main/kotlin/org/secretary/sync/MonotonicInstant.kt`:
```kotlin
package org.secretary.sync

import kotlin.time.Duration
import kotlin.time.Duration.Companion.nanoseconds

/**
 * A point on a monotonic clock, in nanoseconds. Only ordering and differences are
 * meaningful — never interpreted as wall-clock time. Keeps the detection core
 * clock-free: host tests supply instants directly; the real conformer sources them
 * from SystemClock.elapsedRealtimeNanos() (see :kit MonotonicClock).
 */
@JvmInline
value class MonotonicInstant(val nanos: Long) : Comparable<MonotonicInstant> {
    override fun compareTo(other: MonotonicInstant): Int = nanos.compareTo(other.nanos)

    /** This instant moved forward by [duration]. */
    fun advancedBy(duration: Duration): MonotonicInstant =
        MonotonicInstant(nanos + duration.inWholeNanoseconds)

    /** The (signed) duration from this instant to [later]. */
    fun durationTo(later: MonotonicInstant): Duration = (later.nanos - nanos).nanoseconds
}
```

`android/vault-access/src/main/kotlin/org/secretary/sync/ChangeDetectionTuning.kt`:
```kotlin
package org.secretary.sync

import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * Named timing constants for folder-change detection (no magic numbers). Trailing
 * debounce raises the signal once the folder has been quiet for [defaultDebounceWindow]
 * after the last pulse; [defaultSelfWriteMuteWindow] sizes the self-write suppression
 * window a future writer (slice 4) can apply around its own record writes.
 */
object ChangeDetectionTuning {
    val defaultDebounceWindow: Duration = 2.seconds
    val defaultSelfWriteMuteWindow: Duration = 10.seconds
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :vault-access:test --tests "org.secretary.sync.MonotonicInstantTest"`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/sync/MonotonicInstant.kt \
        android/vault-access/src/main/kotlin/org/secretary/sync/ChangeDetectionTuning.kt \
        android/vault-access/src/test/kotlin/org/secretary/sync/MonotonicInstantTest.kt
git commit -m "feat(android-sync): MonotonicInstant + ChangeDetectionTuning (slice 3)"
```

---

### Task 2: `FolderChangeDetector` (pure debounce reducer)

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/sync/FolderChangeDetector.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/sync/FolderChangeDetectorTest.kt`

- [ ] **Step 1: Write the failing test**

`android/vault-access/src/test/kotlin/org/secretary/sync/FolderChangeDetectorTest.kt`:
```kotlin
package org.secretary.sync

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import kotlin.time.Duration.Companion.milliseconds

class FolderChangeDetectorTest {
    private val window = 100.milliseconds
    private fun at(ms: Long) = MonotonicInstant(ms * 1_000_000)
    private fun active() = FolderChangeDetector(window).apply { setActive(true) }

    @Test
    fun singlePulseBecomesPendingAfterWindow() {
        val d = active()
        d.recordPulse(at(0))
        assertFalse(d.flush(at(99)))           // not quiet long enough
        assertFalse(d.pendingChanges)
        assertTrue(d.flush(at(100)))           // exactly the window → transition
        assertTrue(d.pendingChanges)
    }

    @Test
    fun flushReturnsTrueOnlyOnTransition() {
        val d = active()
        d.recordPulse(at(0))
        assertTrue(d.flush(at(100)))
        assertFalse(d.flush(at(200)))          // already pending → no second transition
    }

    @Test
    fun burstWithinWindowCoalescesToOneSignal() {
        val d = active()
        d.recordPulse(at(0))
        d.recordPulse(at(50))                  // resets the quiet window to 50
        assertFalse(d.flush(at(100)))          // 100 < 50 + 100
        assertTrue(d.flush(at(150)))           // quiet since the last pulse
    }

    @Test
    fun outOfOrderPulsesKeepLatestDeadline() {
        val d = active()
        d.recordPulse(at(50))
        d.recordPulse(at(10))                  // earlier instant must not move the deadline back
        assertFalse(d.flush(at(120)))          // deadline is 50 + 100 = 150
        assertTrue(d.flush(at(150)))
    }

    @Test
    fun inactiveDropsPulses() {
        val d = FolderChangeDetector(window)   // never activated
        d.recordPulse(at(0))
        assertNull(d.nextFlushDeadline)
        assertFalse(d.flush(at(1000)))
    }

    @Test
    fun goingInactiveResetsState() {
        val d = active()
        d.recordPulse(at(0))
        assertTrue(d.flush(at(100)))
        d.setActive(false)
        assertFalse(d.pendingChanges)
        assertNull(d.nextFlushDeadline)
        d.setActive(true)
        assertNull(d.nextFlushDeadline)        // no leftover pulse
    }

    @Test
    fun muteSuppressesEarlierPulses() {
        val d = active()
        d.muteUntil(at(100))
        d.recordPulse(at(50))                  // before the mute instant → ignored
        assertNull(d.nextFlushDeadline)
        d.recordPulse(at(100))                 // at/after the mute instant → counts
        assertTrue(d.flush(at(200)))
    }

    @Test
    fun acknowledgeClearsPending() {
        val d = active()
        d.recordPulse(at(0))
        assertTrue(d.flush(at(100)))
        d.acknowledge()
        assertFalse(d.pendingChanges)
    }

    @Test
    fun acknowledgeReArmsPulsePreservedDuringPending() {
        val d = active()
        d.recordPulse(at(0))
        assertTrue(d.flush(at(100)))           // pending = true, pulse consumed
        d.recordPulse(at(120))                 // arrives while still pending → preserved
        assertNull(d.nextFlushDeadline)        // not armed while pending
        d.acknowledge()
        assertTrue(d.nextFlushDeadline == at(120).advancedBy(window))
        assertTrue(d.flush(at(220)))           // signals again from the preserved pulse
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :vault-access:test --tests "org.secretary.sync.FolderChangeDetectorTest"`
Expected: FAIL — unresolved reference `FolderChangeDetector`.

- [ ] **Step 3: Write the implementation**

`android/vault-access/src/main/kotlin/org/secretary/sync/FolderChangeDetector.kt`:
```kotlin
package org.secretary.sync

import kotlin.time.Duration

/**
 * Pure, deterministic reducer that turns a noisy stream of folder-change pulses into
 * a single debounced, foreground-gated "pending changes" signal. No real clock or
 * timer: callers supply instants and drive [flush]. Trailing debounce — the signal is
 * raised once the folder has been quiet for [debounceWindow] after the last pulse.
 *
 * Advisory + metadata-only: it sees timestamps, never record contents, and a
 * missed/spurious pulse never corrupts anything (sync reconciles truth). Mirror of the
 * iOS FolderChangeDetector; a Kotlin class with mutable private state stands in for the
 * Swift mutating struct.
 */
class FolderChangeDetector(
    val debounceWindow: Duration = ChangeDetectionTuning.defaultDebounceWindow,
) {
    var isActive: Boolean = false
        private set
    var pendingChanges: Boolean = false
        private set
    private var lastPulseAt: MonotonicInstant? = null
    private var muteBefore: MonotonicInstant? = null

    /**
     * Instant the monitor should next attempt a [flush], or null if nothing is armed
     * (inactive, already pending, or no pulse seen).
     */
    val nextFlushDeadline: MonotonicInstant?
        get() {
            if (!isActive || pendingChanges) return null
            val last = lastPulseAt ?: return null
            return last.advancedBy(debounceWindow)
        }

    /**
     * Foreground/unlocked gate (ADR-0003 foreground-only). Going inactive resets
     * detection state for a clean slate on next foreground.
     */
    fun setActive(active: Boolean) {
        if (active == isActive) return
        isActive = active
        if (!active) {
            lastPulseAt = null
            muteBefore = null
            pendingChanges = false
        }
    }

    /**
     * Record a watcher pulse. Dropped while inactive or muted. Keeping the max keeps
     * the armed deadline correct even if near-simultaneous pulses arrive out of order.
     * Deliberately does NOT guard on [pendingChanges]: a pulse arriving while pending is
     * preserved so [acknowledge] can re-arm it.
     */
    fun recordPulse(at: MonotonicInstant) {
        if (!isActive) return
        val mute = muteBefore
        if (mute != null && at < mute) return
        lastPulseAt = maxOf(lastPulseAt ?: at, at)
    }

    /** Suppress pulses stamped strictly before [instant] (self-write window). */
    fun muteUntil(instant: MonotonicInstant) {
        muteBefore = instant
    }

    /**
     * Attempt to raise the signal. Returns true iff this call flipped [pendingChanges]
     * false→true, so the monitor fires onChange exactly once.
     */
    fun flush(now: MonotonicInstant): Boolean {
        if (!isActive || pendingChanges) return false
        val last = lastPulseAt ?: return false
        if (now < last.advancedBy(debounceWindow)) return false
        pendingChanges = true
        lastPulseAt = null // consumed; further pulses re-arm post-acknowledge
        return true
    }

    /** Caller consumed the signal. A later (or preserved) pulse re-arms. */
    fun acknowledge() {
        pendingChanges = false
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :vault-access:test --tests "org.secretary.sync.FolderChangeDetectorTest"`
Expected: PASS (9 tests).

- [ ] **Step 5: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/sync/FolderChangeDetector.kt \
        android/vault-access/src/test/kotlin/org/secretary/sync/FolderChangeDetectorTest.kt
git commit -m "feat(android-sync): FolderChangeDetector pure debounce reducer (slice 3)"
```

---

### Task 3: Ports + test doubles (`FolderWatchPort`, `FlushScheduler`, `FakeFolderWatch`, `ManualFlushScheduler`)

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/sync/FolderWatchPort.kt`
- Create: `android/vault-access/src/main/kotlin/org/secretary/sync/FlushScheduler.kt`
- Create: `android/vault-access/src/test/kotlin/org/secretary/sync/FakeFolderWatch.kt`
- Create: `android/vault-access/src/test/kotlin/org/secretary/sync/ManualFlushScheduler.kt`
- Test: extend `android/vault-access/src/test/kotlin/org/secretary/sync/FakeFolderWatch.kt` is exercised via a small `PortDoublesTest`.
- Test: `android/vault-access/src/test/kotlin/org/secretary/sync/PortDoublesTest.kt`

> The two interfaces are trivial seams (no logic to test). The test doubles *do* carry
> logic (call counting, error injection, fire/emit), so they get a focused test that also
> serves as living documentation of how Task 4 drives them.

- [ ] **Step 1: Write the interfaces (no test yet — they have no behavior)**

`android/vault-access/src/main/kotlin/org/secretary/sync/FolderWatchPort.kt`:
```kotlin
package org.secretary.sync

/**
 * Seam over the OS folder watcher. A real conformer (see :kit FileObserverFolderWatch)
 * observes the vault folder and delivers a pulse per change; the fake drives pulses
 * directly. Conformers MUST deliver [onPulse] on the main thread so the monitor needs
 * no locking (mirrors the iOS @MainActor contract).
 */
interface FolderWatchPort {
    /** Begin watching; [onPulse] is invoked (on the main thread) per detected change.
     *  May throw if the folder can't be watched — the monitor surfaces it, no silent swallow. */
    fun start(onPulse: (MonotonicInstant) -> Unit)

    /** Stop watching. Idempotent. */
    fun stop()
}
```

`android/vault-access/src/main/kotlin/org/secretary/sync/FlushScheduler.kt`:
```kotlin
package org.secretary.sync

import kotlin.time.Duration

/**
 * Seam over a single debounce timer. A new [schedule] replaces any outstanding one
 * (single outstanding flush — trailing debounce). The work receives the actual fire
 * instant, keeping the monitor clock-free. Conformers fire on the main thread.
 */
interface FlushScheduler {
    fun schedule(after: Duration, work: (MonotonicInstant) -> Unit)
    fun cancel()
}
```

- [ ] **Step 2: Write the failing test for the doubles**

`android/vault-access/src/test/kotlin/org/secretary/sync/PortDoublesTest.kt`:
```kotlin
package org.secretary.sync

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import kotlin.time.Duration.Companion.milliseconds

class PortDoublesTest {
    @Test
    fun fakeWatchEmitsToRegisteredCallback() {
        val watch = FakeFolderWatch()
        var seen: MonotonicInstant? = null
        watch.start { seen = it }
        assertTrue(watch.started)
        assertEquals(1, watch.startCount)
        watch.emit(MonotonicInstant(42))
        assertEquals(MonotonicInstant(42), seen)
        watch.stop()
        assertFalse(watch.started)
        assertEquals(1, watch.stopCount)
    }

    @Test
    fun fakeWatchInjectedStartErrorLeavesItUnstarted() {
        val watch = FakeFolderWatch()
        val boom = IllegalStateException("no scope")
        watch.startError = boom
        val thrown = assertThrows(IllegalStateException::class.java) { watch.start {} }
        assertEquals("no scope", thrown.message)
        assertFalse(watch.started)
        assertEquals(0, watch.startCount)
    }

    @Test
    fun manualSchedulerFiresPendingWorkOnce() {
        val scheduler = ManualFlushScheduler()
        var fired: MonotonicInstant? = null
        scheduler.schedule(100.milliseconds) { fired = it }
        assertEquals(100.milliseconds, scheduler.scheduledDelay)
        assertTrue(scheduler.hasPending)
        scheduler.fire(MonotonicInstant(7))
        assertEquals(MonotonicInstant(7), fired)
        assertFalse(scheduler.hasPending)               // one-shot
    }

    @Test
    fun manualSchedulerCancelDropsPendingWork() {
        val scheduler = ManualFlushScheduler()
        scheduler.schedule(100.milliseconds) { error("should not fire") }
        scheduler.cancel()
        assertEquals(1, scheduler.cancelCount)
        assertFalse(scheduler.hasPending)
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `./gradlew :vault-access:test --tests "org.secretary.sync.PortDoublesTest"`
Expected: FAIL — unresolved `FakeFolderWatch` / `ManualFlushScheduler`.

- [ ] **Step 4: Write the test doubles**

`android/vault-access/src/test/kotlin/org/secretary/sync/FakeFolderWatch.kt`:
```kotlin
package org.secretary.sync

/**
 * In-memory [FolderWatchPort] for host tests. The test drives raw pulses via [emit].
 * [startError], if set, is thrown by [start] (before any state changes) to exercise the
 * monitor's start-failure roll-back path.
 */
class FakeFolderWatch : FolderWatchPort {
    var startCount: Int = 0
        private set
    var stopCount: Int = 0
        private set
    var startError: Throwable? = null
    private var onPulse: ((MonotonicInstant) -> Unit)? = null

    val started: Boolean get() = onPulse != null

    override fun start(onPulse: (MonotonicInstant) -> Unit) {
        startError?.let { throw it }
        this.onPulse = onPulse
        startCount++
    }

    override fun stop() {
        onPulse = null
        stopCount++
    }

    /** Deliver a pulse through the registered callback (simulates an OS event). */
    fun emit(at: MonotonicInstant) {
        val cb = onPulse ?: error("emit called while watch not started")
        cb(at)
    }
}
```

`android/vault-access/src/test/kotlin/org/secretary/sync/ManualFlushScheduler.kt`:
```kotlin
package org.secretary.sync

import kotlin.time.Duration

/**
 * In-memory [FlushScheduler] for host tests: the test controls when the pending work
 * fires and with which instant via [fire]. Models a one-shot timer — [fire] clears the
 * pending work before invoking it, so work that re-schedules (the monitor's re-arm) sets
 * a fresh pending entry.
 */
class ManualFlushScheduler : FlushScheduler {
    var scheduledDelay: Duration? = null
        private set
    var cancelCount: Int = 0
        private set
    private var pending: ((MonotonicInstant) -> Unit)? = null

    val hasPending: Boolean get() = pending != null

    override fun schedule(after: Duration, work: (MonotonicInstant) -> Unit) {
        scheduledDelay = after
        pending = work
    }

    override fun cancel() {
        pending = null
        cancelCount++
    }

    /** Fire the pending work at [at]. */
    fun fire(at: MonotonicInstant) {
        val work = pending ?: error("fire called with nothing scheduled")
        pending = null
        work(at)
    }
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `./gradlew :vault-access:test --tests "org.secretary.sync.PortDoublesTest"`
Expected: PASS (4 tests).

- [ ] **Step 6: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/sync/FolderWatchPort.kt \
        android/vault-access/src/main/kotlin/org/secretary/sync/FlushScheduler.kt \
        android/vault-access/src/test/kotlin/org/secretary/sync/FakeFolderWatch.kt \
        android/vault-access/src/test/kotlin/org/secretary/sync/ManualFlushScheduler.kt \
        android/vault-access/src/test/kotlin/org/secretary/sync/PortDoublesTest.kt
git commit -m "feat(android-sync): folder-watch ports + host test doubles (slice 3)"
```

---

### Task 4: `ChangeDetectionMonitor` (pure glue over the ports)

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/sync/ChangeDetectionMonitor.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/sync/ChangeDetectionMonitorTest.kt`

- [ ] **Step 1: Write the failing test**

`android/vault-access/src/test/kotlin/org/secretary/sync/ChangeDetectionMonitorTest.kt`:
```kotlin
package org.secretary.sync

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import kotlin.time.Duration.Companion.milliseconds

class ChangeDetectionMonitorTest {
    private val window = 100.milliseconds
    private fun at(ms: Long) = MonotonicInstant(ms * 1_000_000)

    private class Fixture {
        val watch = FakeFolderWatch()
        val scheduler = ManualFlushScheduler()
        var changes = 0
        val monitor = ChangeDetectionMonitor(
            detector = FolderChangeDetector(100.milliseconds),
            watch = watch,
            scheduler = scheduler,
            onChange = { changes++ },
        )
    }

    @Test
    fun pulseThenQuietFiresOnChangeOnce() {
        val f = Fixture()
        f.monitor.start()
        f.watch.emit(at(0))
        assertEquals(100.milliseconds, f.scheduler.scheduledDelay) // armed to deadline
        f.scheduler.fire(at(100))
        assertEquals(1, f.changes)
        assertTrue(f.monitor.pendingChanges)
    }

    @Test
    fun burstFiresOnChangeOnce() {
        val f = Fixture()
        f.monitor.start()
        f.watch.emit(at(0))
        f.watch.emit(at(40))
        f.watch.emit(at(80))
        // A flush that fires too early re-arms instead of signalling.
        f.scheduler.fire(at(100))     // 100 < 80 + 100 → re-arm
        assertEquals(0, f.changes)
        f.scheduler.fire(at(180))     // quiet since the last pulse
        assertEquals(1, f.changes)
    }

    @Test
    fun stopCancelsSchedulerAndStopsWatch() {
        val f = Fixture()
        f.monitor.start()
        f.watch.emit(at(0))
        f.monitor.stop()
        assertEquals(1, f.scheduler.cancelCount)
        assertEquals(1, f.watch.stopCount)
        assertFalse(f.monitor.pendingChanges)
    }

    @Test
    fun acknowledgeClearsAndReArmsPreservedPulse() {
        val f = Fixture()
        f.monitor.start()
        f.watch.emit(at(0))
        f.scheduler.fire(at(100))               // pending raised, changes == 1
        f.watch.emit(at(120))                   // arrives while pending → preserved
        f.monitor.acknowledge()
        assertFalse(f.monitor.pendingChanges)
        assertTrue(f.scheduler.hasPending)      // re-armed at zero delay
        assertEquals(Duration.ZERO, f.scheduler.scheduledDelay)
        f.scheduler.fire(at(300))               // fires the preserved pulse
        assertEquals(2, f.changes)
    }

    @Test
    fun startErrorRollsBackActiveGateAndRetrySucceeds() {
        val f = Fixture()
        f.watch.startError = IllegalStateException("denied")
        assertThrows(IllegalStateException::class.java) { f.monitor.start() }
        assertEquals(0, f.watch.startCount)
        // Clear the error and retry — must start cleanly (active gate was rolled back).
        f.watch.startError = null
        f.monitor.start()
        assertEquals(1, f.watch.startCount)
    }

    @Test
    fun doubleStartIsIdempotent() {
        val f = Fixture()
        f.monitor.start()
        f.monitor.start()
        assertEquals(1, f.watch.startCount)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :vault-access:test --tests "org.secretary.sync.ChangeDetectionMonitorTest"`
Expected: FAIL — unresolved `ChangeDetectionMonitor`.

- [ ] **Step 3: Write the implementation**

`android/vault-access/src/main/kotlin/org/secretary/sync/ChangeDetectionMonitor.kt`:
```kotlin
package org.secretary.sync

import kotlin.time.Duration

/**
 * Coordinates a [FolderChangeDetector] with a [FolderWatchPort] (OS pulses) and a
 * [FlushScheduler] (debounce timer), exposing an advisory [pendingChanges] flag and an
 * [onChange] callback for a future UI slice. Main-thread-confined: the real conformers
 * deliver their callbacks on the main thread, so all detector mutation is serialized
 * there with no extra locking (mirror of the iOS @MainActor ChangeDetectionMonitor).
 *
 * Detect-only: a raised signal never triggers a sync pass (no password in hand after
 * unlock). Acting on it (re-prompt / sync-at-unlock) is slice 4.
 */
class ChangeDetectionMonitor(
    private val detector: FolderChangeDetector,
    private val watch: FolderWatchPort,
    private val scheduler: FlushScheduler,
    private val onChange: () -> Unit,
) {
    /** True once a debounced change is awaiting the user; cleared by [acknowledge]/[stop]. */
    var pendingChanges: Boolean = false
        private set

    /**
     * Start watching + gate active. Ignored if already started. Re-throws (and rolls
     * back the active gate) if the watch port can't start, so a retry after a failure
     * starts from a clean state.
     */
    fun start() {
        if (detector.isActive) return // already started — ignore double-start
        detector.setActive(true)
        try {
            watch.start(::handlePulse)
        } catch (e: Throwable) {
            detector.setActive(false) // roll back so a retry starts clean
            throw e
        }
    }

    /** Stop watching, cancel any armed flush, gate inactive, clear the signal. */
    fun stop() {
        scheduler.cancel()
        watch.stop()
        detector.setActive(false) // clears the detector's pending signal (clean-slate reset)
        pendingChanges = false
    }

    /**
     * Consume the signal. If a pulse arrived while the signal was pending, the detector
     * preserved it (its deadline may already have elapsed), so re-arm a flush — the
     * scheduler supplies the real fire instant, keeping this layer clock-free. With no
     * preserved pulse this is a no-op.
     */
    fun acknowledge() {
        detector.acknowledge()
        pendingChanges = detector.pendingChanges
        if (detector.nextFlushDeadline != null) {
            scheduler.schedule(Duration.ZERO, ::handleFlush)
        }
    }

    /** Suppress watcher pulses stamped before [instant] (self-write window). */
    fun muteUntil(instant: MonotonicInstant) {
        detector.muteUntil(instant)
    }

    private fun handlePulse(instant: MonotonicInstant) {
        detector.recordPulse(instant)
        rearm(now = instant)
    }

    private fun rearm(now: MonotonicInstant) {
        val deadline = detector.nextFlushDeadline
        if (deadline == null) {
            scheduler.cancel()
            return
        }
        // Clamp: a real scheduler firing slightly past the deadline must not pass a
        // negative Duration to schedule (the contract is undefined for it).
        val delay = maxOf(Duration.ZERO, now.durationTo(deadline))
        scheduler.schedule(delay, ::handleFlush)
    }

    private fun handleFlush(now: MonotonicInstant) {
        if (detector.flush(now)) {
            pendingChanges = true
            onChange()
        } else {
            rearm(now) // a later pulse moved the deadline
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :vault-access:test --tests "org.secretary.sync.ChangeDetectionMonitorTest"`
Expected: PASS (6 tests).

- [ ] **Step 5: Run the whole `:vault-access` suite + commit**

Run: `./gradlew :vault-access:test`
Expected: PASS (existing sync tests + the 4 new files; 0 warnings).

```bash
git add android/vault-access/src/main/kotlin/org/secretary/sync/ChangeDetectionMonitor.kt \
        android/vault-access/src/test/kotlin/org/secretary/sync/ChangeDetectionMonitorTest.kt
git commit -m "feat(android-sync): ChangeDetectionMonitor over folder-watch ports (slice 3)"
```

---

### Task 5: Real `:kit` adapters (`MonotonicClock`, `HandlerFlushScheduler`, `FileObserverFolderWatch`, `ChangeMonitorFactory`)

**Files:**
- Create: `android/kit/src/main/kotlin/org/secretary/sync/MonotonicClock.kt`
- Create: `android/kit/src/main/kotlin/org/secretary/sync/HandlerFlushScheduler.kt`
- Create: `android/kit/src/main/kotlin/org/secretary/sync/FileObserverFolderWatch.kt`
- Create: `android/kit/src/main/kotlin/org/secretary/sync/ChangeMonitorFactory.kt`

> These wrap Android framework classes (`FileObserver`, `Handler`, `SystemClock`,
> `Looper`) and are thin glue. The project has no Robolectric, so they carry no host
> unit test — they are compile-checked here and proven on a real runtime by the
> instrumented smoke in Task 6 (mirrors iOS, where PresenterFolderWatch had only a
> simulator smoke). No new native/NDK wiring: this is pure Kotlin + framework.

- [ ] **Step 1: Write `MonotonicClock.kt`**

`android/kit/src/main/kotlin/org/secretary/sync/MonotonicClock.kt`:
```kotlin
package org.secretary.sync

import android.os.SystemClock

/**
 * Android monotonic time source for [MonotonicInstant]. Uses elapsedRealtimeNanos
 * (monotonic, counts during deep sleep, never wall-clock), so only ordering and
 * differences are meaningful — exactly the [MonotonicInstant] contract.
 */
fun monotonicNow(): MonotonicInstant = MonotonicInstant(SystemClock.elapsedRealtimeNanos())
```

- [ ] **Step 2: Write `HandlerFlushScheduler.kt`**

`android/kit/src/main/kotlin/org/secretary/sync/HandlerFlushScheduler.kt`:
```kotlin
package org.secretary.sync

import android.os.Handler
import android.os.Looper
import kotlin.time.Duration

/**
 * [FlushScheduler] over a main-Looper Handler. A new [schedule] cancels the prior one
 * (single outstanding flush — trailing debounce); the work fires on the main thread with
 * the actual fire instant from [now]. Mirror of the iOS DispatchFlushScheduler.
 *
 * [handler] and [now] are injectable so an instrumented test can supply a known Looper
 * and a deterministic clock; production uses the main Looper and SystemClock.
 */
class HandlerFlushScheduler(
    private val handler: Handler = Handler(Looper.getMainLooper()),
    private val now: () -> MonotonicInstant = ::monotonicNow,
) : FlushScheduler {
    private var pending: Runnable? = null

    override fun schedule(after: Duration, work: (MonotonicInstant) -> Unit) {
        cancel()
        val runnable = Runnable {
            pending = null
            work(now())
        }
        pending = runnable
        handler.postDelayed(runnable, after.inWholeMilliseconds)
    }

    override fun cancel() {
        pending?.let { handler.removeCallbacks(it) }
        pending = null
    }
}
```

- [ ] **Step 3: Write `FileObserverFolderWatch.kt`**

`android/kit/src/main/kotlin/org/secretary/sync/FileObserverFolderWatch.kt`:
```kotlin
package org.secretary.sync

import android.os.Build
import android.os.FileObserver
import android.os.Handler
import android.os.Looper
import java.io.File

/**
 * [FolderWatchPort] over a single non-recursive [android.os.FileObserver] on the vault
 * ROOT. FileObserver is non-recursive on all API levels, so this watches only the root's
 * immediate contents — which is sufficient: the top-level manifest.cbor.enc is re-signed
 * and rewritten (atomic rename) on every committed state advance (vault-format §4.4), so a
 * remote change always surfaces as a root-level event. A deep-only change with no manifest
 * rewrite is not a committed (sync-relevant) state.
 *
 * FileObserver delivers events on its own thread; each pulse is stamped with [now] and
 * marshalled onto [mainHandler] before [onPulse], so the monitor is only ever touched on
 * the main thread (mirror of iOS delivering on @MainActor).
 *
 * [mainHandler] and [now] are injectable for instrumented testing.
 */
class FileObserverFolderWatch(
    private val folder: File,
    private val mainHandler: Handler = Handler(Looper.getMainLooper()),
    private val now: () -> MonotonicInstant = ::monotonicNow,
) : FolderWatchPort {
    private companion object {
        // Create / write / move-in / move-out / delete events on the root's children.
        const val MASK = FileObserver.CREATE or FileObserver.MODIFY or
            FileObserver.MOVED_TO or FileObserver.MOVED_FROM or
            FileObserver.DELETE or FileObserver.CLOSE_WRITE
    }

    private var observer: FileObserver? = null

    override fun start(onPulse: (MonotonicInstant) -> Unit) {
        val obs = newObserver {
            val instant = now()
            mainHandler.post { onPulse(instant) }
        }
        observer = obs
        obs.startWatching()
    }

    override fun stop() {
        observer?.stopWatching()
        observer = null
    }

    private fun newObserver(onPulse: () -> Unit): FileObserver =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            object : FileObserver(folder, MASK) { // non-deprecated File ctor (API 29+), still non-recursive
                override fun onEvent(event: Int, path: String?) = onPulse()
            }
        } else {
            @Suppress("DEPRECATION") // String ctor: deprecated on 29+, identical non-recursive behavior
            object : FileObserver(folder.path, MASK) {
                override fun onEvent(event: Int, path: String?) = onPulse()
            }
        }
}
```

- [ ] **Step 4: Write `ChangeMonitorFactory.kt`**

`android/kit/src/main/kotlin/org/secretary/sync/ChangeMonitorFactory.kt`:
```kotlin
package org.secretary.sync

import java.io.File
import kotlin.time.Duration

/**
 * Composes the real adapters with a fresh [FolderChangeDetector] into a ready-to-start
 * [ChangeDetectionMonitor] for [folder]. Mirror of the iOS makeChangeMonitor factory.
 * Must be called on the main thread (the returned monitor is main-thread-confined).
 */
fun makeChangeMonitor(
    folder: File,
    debounceWindow: Duration = ChangeDetectionTuning.defaultDebounceWindow,
    onChange: () -> Unit,
): ChangeDetectionMonitor = ChangeDetectionMonitor(
    detector = FolderChangeDetector(debounceWindow),
    watch = FileObserverFolderWatch(folder),
    scheduler = HandlerFlushScheduler(),
    onChange = onChange,
)
```

- [ ] **Step 5: Compile-check `:kit` main sources**

Run: `./gradlew :kit:compileDebugKotlin`
Expected: BUILD SUCCESSFUL, 0 warnings.

- [ ] **Step 6: Commit**

```bash
git add android/kit/src/main/kotlin/org/secretary/sync/MonotonicClock.kt \
        android/kit/src/main/kotlin/org/secretary/sync/HandlerFlushScheduler.kt \
        android/kit/src/main/kotlin/org/secretary/sync/FileObserverFolderWatch.kt \
        android/kit/src/main/kotlin/org/secretary/sync/ChangeMonitorFactory.kt
git commit -m "feat(android-sync): real FileObserver/Handler folder-watch adapters (slice 3)"
```

---

### Task 6: Instrumented smoke test (real `FileObserver` on the emulator)

**Files:**
- Create: `android/kit/src/androidTest/kotlin/org/secretary/sync/FolderWatchInstrumentedTest.kt`

**Pre-req:** a booted emulator. `emulator`/`adb` are not on the bare PATH — use absolute paths:
```bash
"$HOME/Library/Android/sdk/emulator/emulator" -avd Medium_Phone_API_36.1 -no-snapshot -no-window -no-audio &
"$HOME/Library/Android/sdk/platform-tools/adb" wait-for-device
```

- [ ] **Step 1: Write the instrumented test**

`android/kit/src/androidTest/kotlin/org/secretary/sync/FolderWatchInstrumentedTest.kt`:
```kotlin
package org.secretary.sync

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.time.Duration.Companion.milliseconds

/**
 * Proves the real folder-watch wiring on a device: a real android.os.FileObserver on a
 * temp dir + a real main-Looper HandlerFlushScheduler, composed through a
 * ChangeDetectionMonitor. An external file write must pulse → debounce → raise onChange.
 * Host tests (with fakes) cannot touch FileObserver / Looper at all, so this is net-new
 * coverage. No golden vault / FFI / native .so needed — pure filesystem.
 *
 * The monitor is main-thread-confined, so start/stop run via runOnMainSync; the file
 * write happens on the test thread (simulating an external/remote writer). A short
 * debounce window keeps the test fast; a CountDownLatch + generous timeout absorbs
 * scheduler latency without flaking.
 */
@RunWith(AndroidJUnit4::class)
class FolderWatchInstrumentedTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private lateinit var dir: File
    private var monitor: ChangeDetectionMonitor? = null

    @After
    fun tearDown() {
        monitor?.let { m -> instrumentation.runOnMainSync { m.stop() } }
        if (::dir.isInitialized) dir.deleteRecursively()
    }

    @Test
    fun externalWriteRaisesDebouncedPendingChanges() {
        dir = File(
            instrumentation.targetContext.cacheDir,
            "folderwatch-${System.nanoTime()}",
        ).apply { mkdirs() }

        val changed = CountDownLatch(1)
        // Build + start the monitor on the main thread (its confinement contract).
        instrumentation.runOnMainSync {
            val m = makeChangeMonitor(
                folder = dir,
                debounceWindow = 150.milliseconds,
                onChange = { changed.countDown() },
            )
            m.start()
            monitor = m
        }

        // External write on the test thread → FileObserver fires → posts to main → pulse.
        File(dir, "manifest.cbor.enc").writeBytes(byteArrayOf(1, 2, 3))

        assertTrue(
            "onChange should fire within timeout after an external write",
            changed.await(10, TimeUnit.SECONDS),
        )
        instrumentation.runOnMainSync { assertTrue(monitor!!.pendingChanges) }
    }
}
```

- [ ] **Step 2: Run the instrumented test to verify it passes**

Run: `./gradlew :kit:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.sync.FolderWatchInstrumentedTest`
Expected: BUILD SUCCESSFUL — 1 instrumented test passes on the emulator.

> If it FAILS to even build with `--tests`, that flag is wrong for instrumented tests —
> use the `-Pandroid.testInstrumentationRunnerArguments.class=` form shown above.

- [ ] **Step 3: Run the full slice gauntlet**

```bash
# Host (NDK-free): existing sync tests + all new slice-3 host tests
./gradlew :vault-access:test :kit:testDebugUnitTest --rerun-tasks
# Instrumented: the new smoke + the existing slice-2b round-trip
./gradlew :kit:connectedDebugAndroidTest
```
Expected: both BUILD SUCCESSFUL, 0 warnings, 0 failures.

- [ ] **Step 4: Verify the change is additive only**

```bash
git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format' || echo "additive-only OK"
```
Expected: prints `additive-only OK` (no core/ffi/ios/format changes).

- [ ] **Step 5: Commit**

```bash
git add android/kit/src/androidTest/kotlin/org/secretary/sync/FolderWatchInstrumentedTest.kt
git commit -m "test(android-sync): emulator FileObserver folder-watch smoke (slice 3)"
```

---

### Task 7: Docs — README + ROADMAP

**Files:**
- Modify: `README.md` (Android C.3 status line)
- Modify: `ROADMAP.md` (Android slice 3 entry)

- [ ] **Step 1: Update README**

Find the Android C.3 status (the slice-2b emulator round-trip line) and add the slice-3 folder-watch line next to it, in the existing brief dot-point style (per the README-style preference: brief, audience-aware, no test-count walls). Example addition:
> - Folder-change detection (slice 3): host-tested debounce core + real `FileObserver` watcher (foreground-only, detect-only); emulator smoke ✅

- [ ] **Step 2: Update ROADMAP**

Mark Android C.3 slice 3 (folder-change detection) ✅ with a one-line summary; leave slice 4 (Compose sync UI) pending. Match the existing ROADMAP entry format for the iOS folder-change-detection slice.

- [ ] **Step 3: Verify the docs render + commit**

```bash
git add README.md ROADMAP.md
git commit -m "docs: README + ROADMAP — Android C.3 folder-change detection (slice 3)"
```

---

## Self-Review

**1. Spec coverage:**
- Pure core (`MonotonicInstant`, `ChangeDetectionTuning`, `FolderChangeDetector`, ports, `ChangeDetectionMonitor`) → Tasks 1–4. ✓
- Real adapters (`MonotonicClock`, `HandlerFlushScheduler`, `FileObserverFolderWatch` root-only, `ChangeMonitorFactory`) → Task 5. ✓
- Host tests (detector, monitor, doubles) + instrumented smoke → Tasks 1–4, 6. ✓
- Background-execution decision (foreground-only, WorkManager deferred) → documented in the spec; nothing to build (correctly no task). ✓
- Detect-only boundary (no ViewModel/hook/runPass) → respected; Task 5 factory's `onChange` is the only consumer seam. ✓
- README + ROADMAP → Task 7. ✓

**2. Placeholder scan:** No "TBD"/"add error handling"/"similar to Task N". README/ROADMAP edits (Task 7) reference the existing format rather than inventing text — acceptable since the exact surrounding lines are repo-specific and the style preference is documented.

**3. Type consistency:** `MonotonicInstant(nanos: Long)`, `advancedBy`/`durationTo`, `FolderChangeDetector(debounceWindow)` with `setActive`/`recordPulse`/`muteUntil`/`flush`/`acknowledge`/`nextFlushDeadline`/`isActive`/`pendingChanges`, `FolderWatchPort.start(onPulse)/stop`, `FlushScheduler.schedule(after, work)/cancel`, `ChangeDetectionMonitor(detector, watch, scheduler, onChange)` with `start/stop/acknowledge/muteUntil/pendingChanges`, `makeChangeMonitor(folder, debounceWindow, onChange)`, `monotonicNow()`. Names are used identically across tasks. ✓

**4. Ambiguity:** `FileObserver` event mask, the API 29 vs 26-28 constructor split (deprecation hygiene only), the main-thread-confinement contract, and the manual-fire test-double semantics are all spelled out.
