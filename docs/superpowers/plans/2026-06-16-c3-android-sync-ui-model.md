# C.3 Android slice 4 — host-tested sync-UI model Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the pure, host-tested *testable heart* of the Android sync UI — badge-state derivation, the `VaultSyncModel` state machine, the `WallClock` / `SyncMonitorHook` seams, decision-collection helpers, and the real `:kit` wiring — mirroring iOS slice 3, with no Compose rendering (deferred to slice 5).

**Architecture:** A pure-JVM `VaultSyncModel` in `:vault-access` (package `org.secretary.sync`) exposes `StateFlow`s and `suspend` methods, driving the existing `SyncCoordinator` and consuming the existing `ChangeDetectionMonitor`'s `pendingChanges` signal via a `pendingChangesRaised()` push. Two triggers (silent `syncAtUnlock`, interactive `runInteractivePass`/`resolve`) converge on one resolution path. Real adapters (`SystemWallClock`, `MonitorSyncHook`, a `makeVaultSync` factory) live in `:kit`.

**Tech Stack:** Kotlin 2.2.10 (JVM toolchain 21), `kotlinx-coroutines` (StateFlow + `runTest`), JUnit 5 (Jupiter) host tests. No androidx, no Compose, no FFI changes.

**Spec:** `docs/superpowers/specs/2026-06-16-c3-android-sync-ui-design.md`

**Plan-time refinement (noted, minor):** the spec sketched a `beginInteractiveSync()` method "exposing intent, no work yet." A method that only no-ops is a placeholder, and the spec also says the model carries no sheet-presentation state. So `beginInteractiveSync()` is **omitted** — the badge-tap → password-prompt trigger is purely slice-5 UI state; slice 5 collects the password and calls `model.runInteractivePass(password)` directly. Everything else matches the spec exactly.

**Conventions (verified against the existing module):**
- Host tests live in `<module>/src/test/kotlin/org/secretary/sync/`, JUnit 5 (`org.junit.jupiter.api.Test`, `org.junit.jupiter.api.Assertions.*`), coroutines via `kotlinx.coroutines.test.runTest`.
- The instant helper in monitor tests is `fun at(ms: Long) = MonotonicInstant(ms * 1_000_000)`.
- Existing fakes in `:vault-access/src/test`: `FakeVaultSyncPort` (FIFO `syncResults`/`commitResults` queues of `Result<SyncOutcome>`, single `statusResult`, recorded `syncCalls`/`commitCalls`/`statusCalls`).
- `:kit` test sources cannot see `:vault-access` test sources, so the `:kit` tests define their own tiny inline `FolderWatchPort`/`FlushScheduler` stubs.

**Run commands:**
- `:vault-access` host suite: `cd android && ./gradlew :vault-access:test`
- single class: `cd android && ./gradlew :vault-access:test --tests "org.secretary.sync.<Class>"`
- `:kit` host suite: `cd android && ./gradlew :kit:testDebugUnitTest`
- single class: `cd android && ./gradlew :kit:testDebugUnitTest --tests "org.secretary.sync.<Class>"`

> All commands assume you are in the worktree root `/Users/hherb/src/secretary/.worktrees/c3-android-sync-ui-model`. Each `cd android &&` is chained in one shell call (shell state does not persist between calls).

---

### Task 1: `SyncBadgeState` + pure derivation

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/sync/SyncBadgeState.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/sync/SyncBadgeStateTest.kt`

- [ ] **Step 1: Write the failing test**

Create `android/vault-access/src/test/kotlin/org/secretary/sync/SyncBadgeStateTest.kt`:

```kotlin
package org.secretary.sync

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class SyncBadgeStateTest {
    private fun status(lastWriteMs: ULong?) =
        SyncStatus(hasState = lastWriteMs != null, deviceClocks = emptyList(), lastStateWriteMs = lastWriteMs)

    @Test
    fun inProgressWinsOverEverything() {
        val badge = syncBadgeState(
            inProgress = true, pendingChanges = true, reviewNeeded = true, status = status(42uL),
        )
        assertEquals(SyncBadgeState.Syncing, badge)
    }

    @Test
    fun reviewNeededWinsOverChangesAndSynced() {
        val badge = syncBadgeState(
            inProgress = false, pendingChanges = true, reviewNeeded = true, status = status(42uL),
        )
        assertEquals(SyncBadgeState.ReviewNeeded, badge)
    }

    @Test
    fun changesDetectedWinsOverSynced() {
        val badge = syncBadgeState(
            inProgress = false, pendingChanges = true, reviewNeeded = false, status = status(42uL),
        )
        assertEquals(SyncBadgeState.ChangesDetected, badge)
    }

    @Test
    fun syncedCarriesLastStateWriteMs() {
        val badge = syncBadgeState(
            inProgress = false, pendingChanges = false, reviewNeeded = false, status = status(42uL),
        )
        assertEquals(SyncBadgeState.Synced(42uL), badge)
    }

    @Test
    fun neverSyncedWhenNoStateWrite() {
        val badge = syncBadgeState(
            inProgress = false, pendingChanges = false, reviewNeeded = false, status = status(null),
        )
        assertEquals(SyncBadgeState.NeverSynced, badge)
    }

    @Test
    fun neverSyncedWhenStatusNull() {
        val badge = syncBadgeState(
            inProgress = false, pendingChanges = false, reviewNeeded = false, status = null,
        )
        assertEquals(SyncBadgeState.NeverSynced, badge)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ./gradlew :vault-access:test --tests "org.secretary.sync.SyncBadgeStateTest"`
Expected: FAIL — compilation error, `syncBadgeState` / `SyncBadgeState` unresolved.

- [ ] **Step 3: Write minimal implementation**

Create `android/vault-access/src/main/kotlin/org/secretary/sync/SyncBadgeState.kt`:

```kotlin
package org.secretary.sync

/**
 * The advisory sync state shown on the badge. Mirror of the iOS SyncBadgeState
 * (docs/superpowers/specs/2026-06-15-c3-ios-sync-ui-design.md). Rendering — including the
 * relative "synced N min ago" label derived from [Synced.sinceMs] — is a slice-5 UI concern;
 * this type only carries the discrete state.
 */
sealed interface SyncBadgeState {
    /** No sync state has ever been written for this vault. */
    data object NeverSynced : SyncBadgeState

    /** Last successful state write at [sinceMs] (epoch millis), for a relative-time label. */
    data class Synced(val sinceMs: ULong) : SyncBadgeState

    /** The change monitor raised a debounced "remote changes detected" signal. */
    data object ChangesDetected : SyncBadgeState

    /** A prior pass surfaced a tombstone dispute awaiting the user's decision. */
    data object ReviewNeeded : SyncBadgeState

    /** A pass is currently running. */
    data object Syncing : SyncBadgeState
}

/**
 * Pure derivation of the badge from the model's flags + the latest status snapshot.
 * Precedence (highest first): syncing → review → changes → synced → never. The single
 * [reviewNeeded] input collapses the two ways a review can be pending (the model supplies
 * `reviewNeededFlag || pendingConflict != null`): the sync-at-unlock path raises the flag
 * with no stashed conflict (password dropped), while the interactive path stashes one.
 */
fun syncBadgeState(
    inProgress: Boolean,
    pendingChanges: Boolean,
    reviewNeeded: Boolean,
    status: SyncStatus?,
): SyncBadgeState {
    val sinceMs = status?.lastStateWriteMs
    return when {
        inProgress -> SyncBadgeState.Syncing
        reviewNeeded -> SyncBadgeState.ReviewNeeded
        pendingChanges -> SyncBadgeState.ChangesDetected
        sinceMs != null -> SyncBadgeState.Synced(sinceMs)
        else -> SyncBadgeState.NeverSynced
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd android && ./gradlew :vault-access:test --tests "org.secretary.sync.SyncBadgeStateTest"`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/sync/SyncBadgeState.kt \
        android/vault-access/src/test/kotlin/org/secretary/sync/SyncBadgeStateTest.kt
git commit -m "$(cat <<'EOF'
feat(android-sync): SyncBadgeState + pure derivation (slice 4)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: `WallClock` / `SyncMonitorHook` seams + host fakes

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/sync/WallClock.kt`
- Create: `android/vault-access/src/main/kotlin/org/secretary/sync/SyncMonitorHook.kt`
- Create: `android/vault-access/src/test/kotlin/org/secretary/sync/FakeWallClock.kt`
- Create: `android/vault-access/src/test/kotlin/org/secretary/sync/FakeSyncMonitorHook.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/sync/SyncSeamsTest.kt`

- [ ] **Step 1: Write the failing test**

Create `android/vault-access/src/test/kotlin/org/secretary/sync/SyncSeamsTest.kt`:

```kotlin
package org.secretary.sync

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class SyncSeamsTest {
    @Test
    fun fakeWallClockReturnsSeededValue() {
        val clock = FakeWallClock(currentMs = 1_234uL)
        assertEquals(1_234uL, clock.nowMs())
        clock.currentMs = 5_678uL
        assertEquals(5_678uL, clock.nowMs())
    }

    @Test
    fun fakeSyncMonitorHookCountsCalls() {
        val hook = FakeSyncMonitorHook()
        hook.muteSelfWrite()
        hook.muteSelfWrite()
        hook.acknowledge()
        assertEquals(2, hook.muteCount)
        assertEquals(1, hook.acknowledgeCount)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ./gradlew :vault-access:test --tests "org.secretary.sync.SyncSeamsTest"`
Expected: FAIL — `WallClock` / `SyncMonitorHook` / `FakeWallClock` / `FakeSyncMonitorHook` unresolved.

- [ ] **Step 3: Write minimal implementation**

Create `android/vault-access/src/main/kotlin/org/secretary/sync/WallClock.kt`:

```kotlin
package org.secretary.sync

/**
 * Wall-clock seam: milliseconds since the Unix epoch. Injected so the model can be host-tested
 * deterministically (a [SyncCoordinator] pass needs a `nowMs` for merge timestamps). The real
 * conformer is `:kit`'s SystemWallClock.
 */
interface WallClock {
    fun nowMs(): ULong
}
```

Create `android/vault-access/src/main/kotlin/org/secretary/sync/SyncMonitorHook.kt`:

```kotlin
package org.secretary.sync

/**
 * The model's outbound seam onto the change monitor. [muteSelfWrite] suppresses the detector's
 * self-write false positives around a sync pass's own manifest rewrite; [acknowledge] consumes
 * the pending-change signal after a clean pass. The inbound `pendingChanges` signal flows the
 * other way, pushed into the model via [VaultSyncModel.pendingChangesRaised]. The real conformer
 * is `:kit`'s MonitorSyncHook, wrapping ChangeDetectionMonitor.
 */
interface SyncMonitorHook {
    fun muteSelfWrite()
    fun acknowledge()
}
```

Create `android/vault-access/src/test/kotlin/org/secretary/sync/FakeWallClock.kt`:

```kotlin
package org.secretary.sync

/** Host-test [WallClock] returning a settable epoch-millis value. */
class FakeWallClock(var currentMs: ULong = 0uL) : WallClock {
    override fun nowMs(): ULong = currentMs
}
```

Create `android/vault-access/src/test/kotlin/org/secretary/sync/FakeSyncMonitorHook.kt`:

```kotlin
package org.secretary.sync

/** Host-test [SyncMonitorHook] that counts forwarded calls (spy). */
class FakeSyncMonitorHook : SyncMonitorHook {
    var muteCount: Int = 0
        private set
    var acknowledgeCount: Int = 0
        private set

    override fun muteSelfWrite() {
        muteCount++
    }

    override fun acknowledge() {
        acknowledgeCount++
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd android && ./gradlew :vault-access:test --tests "org.secretary.sync.SyncSeamsTest"`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/sync/WallClock.kt \
        android/vault-access/src/main/kotlin/org/secretary/sync/SyncMonitorHook.kt \
        android/vault-access/src/test/kotlin/org/secretary/sync/FakeWallClock.kt \
        android/vault-access/src/test/kotlin/org/secretary/sync/FakeSyncMonitorHook.kt \
        android/vault-access/src/test/kotlin/org/secretary/sync/SyncSeamsTest.kt
git commit -m "$(cat <<'EOF'
feat(android-sync): WallClock + SyncMonitorHook seams and host fakes (slice 4)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: Decision-collection helpers

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/sync/SyncDecisions.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/sync/SyncDecisionsTest.kt`

- [ ] **Step 1: Write the failing test**

Create `android/vault-access/src/test/kotlin/org/secretary/sync/SyncDecisionsTest.kt`:

```kotlin
package org.secretary.sync

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SyncDecisionsTest {
    private fun veto(uuid: String) =
        SyncVeto(uuid, "login", emptyList(), listOf("password"), 1uL, 2uL, "devhex")

    @Test
    fun collectDefaultsMissingToKeepLocalTrue() {
        val vetoes = listOf(veto("a"), veto("b"))
        val decisions = collectDecisions(vetoes, overrides = emptyMap())
        assertEquals(
            listOf(SyncVetoDecision("a", true), SyncVetoDecision("b", true)),
            decisions,
        )
    }

    @Test
    fun collectAppliesOverridesAndPreservesVetoOrder() {
        val vetoes = listOf(veto("a"), veto("b"), veto("c"))
        val decisions = collectDecisions(vetoes, overrides = mapOf("b" to false))
        assertEquals(
            listOf(
                SyncVetoDecision("a", true),
                SyncVetoDecision("b", false),
                SyncVetoDecision("c", true),
            ),
            decisions,
        )
    }

    @Test
    fun completeOnlyWhenEveryVetoHasExplicitOverride() {
        val vetoes = listOf(veto("a"), veto("b"))
        assertFalse(decisionsComplete(vetoes, overrides = mapOf("a" to true)))
        assertTrue(decisionsComplete(vetoes, overrides = mapOf("a" to true, "b" to false)))
    }

    @Test
    fun emptyVetoesAreTriviallyComplete() {
        assertTrue(decisionsComplete(emptyList(), overrides = emptyMap()))
        assertEquals(emptyList<SyncVetoDecision>(), collectDecisions(emptyList(), emptyMap()))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ./gradlew :vault-access:test --tests "org.secretary.sync.SyncDecisionsTest"`
Expected: FAIL — `collectDecisions` / `decisionsComplete` unresolved.

- [ ] **Step 3: Write minimal implementation**

Create `android/vault-access/src/main/kotlin/org/secretary/sync/SyncDecisions.kt`:

```kotlin
package org.secretary.sync

/**
 * Build the per-record veto decisions from the slice-5 UI's override map, one decision per veto
 * in veto order. A record with no explicit override defaults to `keepLocal = true` ("Keep mine",
 * the no-data-loss choice), matching desktop D.1.15.
 */
fun collectDecisions(
    vetoes: List<SyncVeto>,
    overrides: Map<String, Boolean>,
): List<SyncVetoDecision> =
    vetoes.map { SyncVetoDecision(it.recordUuidHex, overrides[it.recordUuidHex] ?: true) }

/**
 * True iff every veto has an explicit override entry. Mirrors the desktop "Apply enabled" gate;
 * slice 5 decides whether to require explicitness or allow the keep-mine default to stand.
 */
fun decisionsComplete(
    vetoes: List<SyncVeto>,
    overrides: Map<String, Boolean>,
): Boolean =
    vetoes.all { overrides.containsKey(it.recordUuidHex) }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd android && ./gradlew :vault-access:test --tests "org.secretary.sync.SyncDecisionsTest"`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/sync/SyncDecisions.kt \
        android/vault-access/src/test/kotlin/org/secretary/sync/SyncDecisionsTest.kt
git commit -m "$(cat <<'EOF'
feat(android-sync): collectDecisions/decisionsComplete helpers (slice 4)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: `VaultSyncModel` state machine

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/sync/VaultSyncModel.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/sync/VaultSyncModelTest.kt`

This is the heart. Write the full test suite first, watch it fail, then implement.

- [ ] **Step 1: Write the failing test**

Create `android/vault-access/src/test/kotlin/org/secretary/sync/VaultSyncModelTest.kt`:

```kotlin
package org.secretary.sync

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class VaultSyncModelTest {
    private val pw = byteArrayOf(9, 9, 9)

    private fun veto(uuid: String = "r1") =
        SyncVeto(uuid, "login", emptyList(), listOf("password"), 100uL, 200uL, "devhex")

    private class Fixture(statusWriteMs: ULong? = null) {
        val port = FakeVaultSyncPort().apply {
            statusResult = Result.success(
                SyncStatus(hasState = statusWriteMs != null, deviceClocks = emptyList(), lastStateWriteMs = statusWriteMs),
            )
        }
        val coordinator = SyncCoordinator(port, stateDir = "/state", vaultFolder = "/vault")
        val clock = FakeWallClock(currentMs = 1_000uL)
        val hook = FakeSyncMonitorHook()
        fun model(vaultUuid: ByteArray? = ByteArray(16) { 1 }) =
            VaultSyncModel(coordinator, clock, hook, vaultUuid)
    }

    @Test
    fun initialBadgeIsNeverSynced() {
        val f = Fixture()
        assertEquals(SyncBadgeState.NeverSynced, f.model().badge.value)
    }

    @Test
    fun pendingChangesRaisedFlipsBadgeToChangesDetected() {
        val f = Fixture()
        val m = f.model()
        m.pendingChangesRaised()
        assertEquals(SyncBadgeState.ChangesDetected, m.badge.value)
    }

    @Test
    fun syncAtUnlockCleanArmAcknowledgesAndStaysSilent() = runTest {
        val f = Fixture()
        f.port.syncResults += Result.success(SyncOutcome.MergedClean)
        val m = f.model()
        m.pendingChangesRaised() // simulate a prior detected change
        m.syncAtUnlock(pw)
        assertEquals(1, f.hook.muteCount)        // muted before the pass
        assertEquals(1, f.hook.acknowledgeCount) // acknowledged on the clean arm
        assertFalse(m.reviewNeeded.value)
        assertNull(m.pendingConflict.value)
        // pendingChanges consumed → badge falls back (no status write → NeverSynced)
        assertEquals(SyncBadgeState.NeverSynced, m.badge.value)
        assertEquals(1_000uL, f.port.syncCalls.single().nowMs) // nowMs from the wall clock
    }

    @Test
    fun syncAtUnlockConflictRaisesReviewWithoutSurfacingConflict() = runTest {
        val f = Fixture()
        f.port.syncResults += Result.success(
            SyncOutcome.ConflictsPending(listOf(veto()), emptyList(), byteArrayOf(7)),
        )
        val m = f.model()
        m.syncAtUnlock(pw)
        assertTrue(m.reviewNeeded.value)
        assertNull(m.pendingConflict.value)      // password dropped → no interactive conflict surfaced
        assertEquals(0, f.hook.acknowledgeCount) // not acknowledged (unresolved)
        assertEquals(SyncBadgeState.ReviewNeeded, m.badge.value)
    }

    @Test
    fun interactivePassConflictSurfacesPendingConflict() = runTest {
        val f = Fixture()
        f.port.syncResults += Result.success(
            SyncOutcome.ConflictsPending(listOf(veto()), emptyList(), byteArrayOf(7)),
        )
        val m = f.model()
        m.runInteractivePass(pw)
        assertEquals(PendingConflict(listOf(veto()), emptyList()), m.pendingConflict.value)
        assertTrue(m.reviewNeeded.value)
        assertEquals(SyncBadgeState.ReviewNeeded, m.badge.value)
    }

    @Test
    fun interactivePassCleanArmClearsAndAcknowledges() = runTest {
        val f = Fixture()
        f.port.syncResults += Result.success(SyncOutcome.AppliedAutomatically)
        val m = f.model()
        m.runInteractivePass(pw)
        assertNull(m.pendingConflict.value)
        assertFalse(m.reviewNeeded.value)
        assertEquals(1, f.hook.acknowledgeCount)
    }

    @Test
    fun resolveCleanArmClearsConflictAndAcknowledges() = runTest {
        val f = Fixture()
        f.port.syncResults += Result.success(
            SyncOutcome.ConflictsPending(listOf(veto()), emptyList(), byteArrayOf(7)),
        )
        f.port.commitResults += Result.success(SyncOutcome.MergedClean)
        val m = f.model()
        m.runInteractivePass(pw)
        m.resolve(listOf(SyncVetoDecision("r1", true)), pw)
        assertNull(m.pendingConflict.value)
        assertFalse(m.reviewNeeded.value)
        assertNull(m.lastError.value)
    }

    @Test
    fun resolveEvidenceStaleKeepsConflictAndSurfacesError() = runTest {
        val f = Fixture()
        f.port.syncResults += Result.success(
            SyncOutcome.ConflictsPending(listOf(veto()), emptyList(), byteArrayOf(7)),
        )
        f.port.commitResults += Result.failure(VaultSyncError.EvidenceStale)
        val m = f.model()
        m.runInteractivePass(pw)
        m.resolve(listOf(SyncVetoDecision("r1", true)), pw)
        assertEquals(PendingConflict(listOf(veto()), emptyList()), m.pendingConflict.value) // kept for retry
        assertEquals(VaultSyncError.EvidenceStale, m.lastError.value)
    }

    @Test
    fun wrongPasswordOnUnlockSurfacesErrorAndDoesNotAcknowledge() = runTest {
        val f = Fixture()
        f.port.syncResults += Result.failure(VaultSyncError.WrongPasswordOrCorrupt)
        val m = f.model()
        m.syncAtUnlock(pw)
        assertEquals(VaultSyncError.WrongPasswordOrCorrupt, m.lastError.value)
        assertEquals(0, f.hook.acknowledgeCount)
    }

    @Test
    fun cancelConflictClosesSheetButKeepsReviewBadge() = runTest {
        val f = Fixture()
        f.port.syncResults += Result.success(
            SyncOutcome.ConflictsPending(listOf(veto()), emptyList(), byteArrayOf(7)),
        )
        val m = f.model()
        m.runInteractivePass(pw)
        m.cancelConflict()
        assertNull(m.pendingConflict.value)               // sheet closed
        assertTrue(m.reviewNeeded.value)                  // still nagging
        assertEquals(SyncBadgeState.ReviewNeeded, m.badge.value)
    }

    @Test
    fun refreshStatusUpdatesSyncedLabel() = runTest {
        val f = Fixture(statusWriteMs = 555uL)
        val m = f.model()
        m.refreshStatus()
        assertEquals(SyncBadgeState.Synced(555uL), m.badge.value)
        assertTrue(f.port.statusCalls.isNotEmpty())
    }

    @Test
    fun refreshStatusNoopsWhenVaultUuidNull() = runTest {
        val f = Fixture(statusWriteMs = 555uL)
        val m = f.model(vaultUuid = null)
        m.refreshStatus()
        assertTrue(f.port.statusCalls.isEmpty())
        assertEquals(SyncBadgeState.NeverSynced, m.badge.value)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ./gradlew :vault-access:test --tests "org.secretary.sync.VaultSyncModelTest"`
Expected: FAIL — `VaultSyncModel` unresolved.

- [ ] **Step 3: Write minimal implementation**

Create `android/vault-access/src/main/kotlin/org/secretary/sync/VaultSyncModel.kt`:

```kotlin
package org.secretary.sync

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * The host-tested heart of the Android sync UI — the Kotlin mirror of the iOS VaultSyncViewModel
 * (docs/superpowers/specs/2026-06-15-c3-ios-sync-ui-design.md), minus rendering. It turns the
 * change-monitor signal + a SyncStatus snapshot + the result of a [SyncCoordinator] pass into a
 * [SyncBadgeState], and drives the two sync triggers that converge on one resolution path.
 *
 * Two triggers, one resolution path:
 *  - [syncAtUnlock]: a silent pass with the in-hand unlock password; auto-applying arms update the
 *    badge silently, a conflict only raises [reviewNeeded] (the password is dropped, never held
 *    across a modal at unlock).
 *  - [runInteractivePass] → [resolve]: the user re-enters a password; a conflict surfaces a
 *    [pendingConflict] for slice 5's sheet, which calls [resolve] with the collected decisions.
 *
 * Concurrency: main-thread-confined like the iOS @MainActor view model — callers invoke these
 * methods from the UI dispatcher. The underlying [SyncCoordinator] is Mutex-serialized across its
 * suspending port calls, so the model never drives concurrent passes. Do not drive [refreshStatus]
 * while a pass is in flight (it parks behind the coordinator mutex) — read status before/after.
 *
 * Secret hygiene: the password is a per-call argument, forwarded straight to the coordinator and
 * never stored on the model.
 */
class VaultSyncModel(
    private val coordinator: SyncCoordinator,
    private val wallClock: WallClock,
    private val monitorHook: SyncMonitorHook,
    private val vaultUuid: ByteArray?,
) {
    private val _badge = MutableStateFlow<SyncBadgeState>(SyncBadgeState.NeverSynced)
    val badge: StateFlow<SyncBadgeState> = _badge.asStateFlow()

    private val _isSyncing = MutableStateFlow(false)
    val isSyncing: StateFlow<Boolean> = _isSyncing.asStateFlow()

    private val _reviewNeeded = MutableStateFlow(false)
    val reviewNeeded: StateFlow<Boolean> = _reviewNeeded.asStateFlow()

    private val _pendingConflict = MutableStateFlow<PendingConflict?>(null)
    val pendingConflict: StateFlow<PendingConflict?> = _pendingConflict.asStateFlow()

    private val _lastError = MutableStateFlow<VaultSyncError?>(null)
    val lastError: StateFlow<VaultSyncError?> = _lastError.asStateFlow()

    private var pendingChanges: Boolean = false
    private var lastStatus: SyncStatus? = null

    /** The change monitor's onChange seam: a debounced remote change was detected. */
    fun pendingChangesRaised() {
        pendingChanges = true
        recomputeBadge()
    }

    /** Silent pass with the in-hand unlock password. A conflict only raises the review badge. */
    suspend fun syncAtUnlock(password: ByteArray) {
        runPass(password) { /* conflict: review only, no surfaced conflict */ _reviewNeeded.value = true }
    }

    /** Interactive pass: a conflict surfaces a [pendingConflict] for the resolution sheet. */
    suspend fun runInteractivePass(password: ByteArray) {
        runPass(password) { outcome -> surfaceConflict(outcome) }
    }

    /** Commit the user's veto decisions for the paused conflict. */
    suspend fun resolve(decisions: List<SyncVetoDecision>, password: ByteArray) {
        guardedPass {
            when (val outcome = coordinator.resolve(decisions, password, wallClock.nowMs())) {
                is SyncOutcome.ConflictsPending -> surfaceConflict(outcome) // re-stashed; keep sheet open
                else -> onCleanArm()
            }
        }
    }

    /** Close the resolution sheet without writing; the review badge keeps nagging. */
    fun cancelConflict() {
        _pendingConflict.value = null
        _lastError.value = null
        recomputeBadge()
    }

    /** Best-effort status refresh for the "synced N ago" label; failures keep the prior state. */
    suspend fun refreshStatus() {
        val uuid = vaultUuid ?: return
        try {
            lastStatus = coordinator.status(uuid)
            recomputeBadge()
        } catch (_: VaultSyncError) {
            // best-effort read; keep prior label
        }
    }

    /** Shared pass body: mute → run → dispatch the ConflictsPending arm to [onConflict], else clean. */
    private suspend fun runPass(password: ByteArray, onConflict: (SyncOutcome.ConflictsPending) -> Unit) {
        guardedPass {
            when (val outcome = coordinator.runPass(password, wallClock.nowMs())) {
                is SyncOutcome.ConflictsPending -> onConflict(outcome)
                else -> onCleanArm()
            }
        }
    }

    /** Wraps a pass with the syncing flag, the self-write mute, and typed-error capture. */
    private suspend fun guardedPass(body: suspend () -> Unit) {
        _lastError.value = null
        _isSyncing.value = true
        recomputeBadge()
        monitorHook.muteSelfWrite()
        try {
            body()
        } catch (e: VaultSyncError) {
            _lastError.value = e // surfaced; conflict context (if any) is preserved for retry
        } finally {
            _isSyncing.value = false
            recomputeBadge()
        }
    }

    private fun surfaceConflict(outcome: SyncOutcome.ConflictsPending) {
        _reviewNeeded.value = true
        _pendingConflict.value = PendingConflict(outcome.vetoes, outcome.collisions)
    }

    private fun onCleanArm() {
        monitorHook.acknowledge()
        pendingChanges = false
        _pendingConflict.value = null
        _reviewNeeded.value = false
    }

    private fun recomputeBadge() {
        _badge.value = syncBadgeState(
            inProgress = _isSyncing.value,
            pendingChanges = pendingChanges,
            reviewNeeded = _reviewNeeded.value || _pendingConflict.value != null,
            status = lastStatus,
        )
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd android && ./gradlew :vault-access:test --tests "org.secretary.sync.VaultSyncModelTest"`
Expected: PASS (12 tests).

- [ ] **Step 5: Run the full `:vault-access` suite to confirm no regressions**

Run: `cd android && ./gradlew :vault-access:test`
Expected: BUILD SUCCESSFUL, all pre-existing + new tests green.

- [ ] **Step 6: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/sync/VaultSyncModel.kt \
        android/vault-access/src/test/kotlin/org/secretary/sync/VaultSyncModelTest.kt
git commit -m "$(cat <<'EOF'
feat(android-sync): VaultSyncModel state machine (slice 4)

Two triggers (silent syncAtUnlock + interactive runInteractivePass/resolve)
converging on one resolution path; StateFlow surface; typed errors keep the
conflict context for retry; acknowledge only on clean arms.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: `:kit` real adapters — `SystemWallClock` + `MonitorSyncHook`

**Files:**
- Create: `android/kit/src/main/kotlin/org/secretary/sync/SystemWallClock.kt`
- Create: `android/kit/src/main/kotlin/org/secretary/sync/MonitorSyncHook.kt`
- Test: `android/kit/src/test/kotlin/org/secretary/sync/SystemWallClockTest.kt`
- Test: `android/kit/src/test/kotlin/org/secretary/sync/MonitorSyncHookTest.kt`

> `MonotonicInstant.advancedBy` is used here; `:kit`'s `monotonicNow()` (Android `SystemClock`) is the default clock but is injected so the host test can override it.

- [ ] **Step 1: Write the failing tests**

Create `android/kit/src/test/kotlin/org/secretary/sync/SystemWallClockTest.kt`:

```kotlin
package org.secretary.sync

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SystemWallClockTest {
    @Test
    fun nowMsTracksSystemClock() {
        val before = System.currentTimeMillis().toULong()
        val t = SystemWallClock().nowMs()
        val after = System.currentTimeMillis().toULong()
        assertTrue(t in before..after) { "nowMs $t not in [$before, $after]" }
    }
}
```

Create `android/kit/src/test/kotlin/org/secretary/sync/MonitorSyncHookTest.kt`:

```kotlin
package org.secretary.sync

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

class MonitorSyncHookTest {
    private fun at(ms: Long) = MonotonicInstant(ms * 1_000_000)

    // :kit test sources can't see :vault-access test fakes, so use minimal inline stubs over the
    // public FolderWatchPort / FlushScheduler interfaces.
    private class StubWatch : FolderWatchPort {
        var onPulse: ((MonotonicInstant) -> Unit)? = null
        override fun start(onPulse: (MonotonicInstant) -> Unit) { this.onPulse = onPulse }
        override fun stop() { onPulse = null }
    }

    private class StubScheduler : FlushScheduler {
        private var pending: ((MonotonicInstant) -> Unit)? = null
        override fun schedule(after: Duration, work: (MonotonicInstant) -> Unit) { pending = work }
        override fun cancel() { pending = null }
        fun fire(at: MonotonicInstant) { val w = pending; pending = null; w?.invoke(at) }
    }

    private class Rig {
        val watch = StubWatch()
        val scheduler = StubScheduler()
        var changes = 0
        val monitor = ChangeDetectionMonitor(
            detector = FolderChangeDetector(100.milliseconds),
            watch = watch,
            scheduler = scheduler,
            onChange = { changes++ },
        ).also { it.start() }
    }

    @Test
    fun muteSelfWriteSuppressesPulsesWithinWindow() {
        val rig = Rig()
        // mute pulses stamped before at(0) + 10s = at(10_000)
        val hook = MonitorSyncHook(rig.monitor, muteWindow = 10.seconds, now = { at(0) })
        hook.muteSelfWrite()
        rig.watch.onPulse!!(at(5_000)) // within the mute window → dropped by the detector
        rig.scheduler.fire(at(5_100))  // nothing armed → no-op
        assertEquals(0, rig.changes)
        assertFalse(rig.monitor.pendingChanges)
    }

    @Test
    fun acknowledgeForwardsAndClearsRaisedSignal() {
        val rig = Rig()
        rig.watch.onPulse!!(at(0))
        rig.scheduler.fire(at(100)) // quiet window elapsed → signal raised
        assertTrue(rig.monitor.pendingChanges)
        val hook = MonitorSyncHook(rig.monitor, now = { at(1_000) })
        hook.acknowledge()
        assertFalse(rig.monitor.pendingChanges)
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd android && ./gradlew :kit:testDebugUnitTest --tests "org.secretary.sync.SystemWallClockTest" --tests "org.secretary.sync.MonitorSyncHookTest"`
Expected: FAIL — `SystemWallClock` / `MonitorSyncHook` unresolved.

- [ ] **Step 3: Write minimal implementations**

Create `android/kit/src/main/kotlin/org/secretary/sync/SystemWallClock.kt`:

```kotlin
package org.secretary.sync

/**
 * Real [WallClock] over `System.currentTimeMillis()` (epoch millis). Used to stamp `nowMs` on
 * sync passes; the merge layer interprets it as wall-clock time.
 */
class SystemWallClock : WallClock {
    override fun nowMs(): ULong = System.currentTimeMillis().toULong()
}
```

Create `android/kit/src/main/kotlin/org/secretary/sync/MonitorSyncHook.kt`:

```kotlin
package org.secretary.sync

import kotlin.time.Duration

/**
 * Real [SyncMonitorHook] wrapping a [ChangeDetectionMonitor]. [muteSelfWrite] suppresses detector
 * pulses for [muteWindow] from now (so a sync pass's own manifest rewrite is not re-detected);
 * [acknowledge] consumes the monitor's pending-change signal after a clean pass. [now] defaults to
 * the Android monotonic clock and is injected only for host tests.
 */
class MonitorSyncHook(
    private val monitor: ChangeDetectionMonitor,
    private val muteWindow: Duration = ChangeDetectionTuning.defaultSelfWriteMuteWindow,
    private val now: () -> MonotonicInstant = ::monotonicNow,
) : SyncMonitorHook {
    override fun muteSelfWrite() {
        monitor.muteUntil(now().advancedBy(muteWindow))
    }

    override fun acknowledge() {
        monitor.acknowledge()
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd android && ./gradlew :kit:testDebugUnitTest --tests "org.secretary.sync.SystemWallClockTest" --tests "org.secretary.sync.MonitorSyncHookTest"`
Expected: PASS (1 + 2 tests).

- [ ] **Step 5: Commit**

```bash
git add android/kit/src/main/kotlin/org/secretary/sync/SystemWallClock.kt \
        android/kit/src/main/kotlin/org/secretary/sync/MonitorSyncHook.kt \
        android/kit/src/test/kotlin/org/secretary/sync/SystemWallClockTest.kt \
        android/kit/src/test/kotlin/org/secretary/sync/MonitorSyncHookTest.kt
git commit -m "$(cat <<'EOF'
feat(android-sync): SystemWallClock + MonitorSyncHook :kit adapters (slice 4)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: `makeVaultSync` composition factory

**Files:**
- Create: `android/kit/src/main/kotlin/org/secretary/sync/VaultSyncFactory.kt`

> Pure composition over Android `Looper` + the real `UniffiVaultSyncPort` + `makeChangeMonitor`; not host-testable (covered indirectly; an instrumented smoke is deferred to slice 5). No test in this task — it wires already-tested units. Verify it compiles via the `:kit` build.

- [ ] **Step 1: Write the factory**

Create `android/kit/src/main/kotlin/org/secretary/sync/VaultSyncFactory.kt`:

```kotlin
package org.secretary.sync

import android.os.Looper
import java.io.File

/**
 * Composes the real adapters into a ready-to-use [VaultSyncModel] + its backing
 * [ChangeDetectionMonitor] for an open vault. Mirror of the iOS makeVaultSync factory.
 *
 * Must be called on the main thread: the returned monitor is main-thread-confined and the model's
 * mutating methods are expected to run on the UI dispatcher. A fast-fail check enforces this so a
 * background-thread misuse crashes in development rather than producing a silently misconfigured
 * pair (the same discipline as [makeChangeMonitor]).
 *
 * The model↔monitor reference cycle (monitor.onChange → model.pendingChangesRaised, model → hook →
 * monitor) is harmless on the JVM: the garbage collector reclaims cycles, so — unlike iOS ARC — no
 * weak back-reference is needed. The caller owns the monitor's lifecycle: `start()` on unlock,
 * `stop()` on lock/background.
 *
 * @return the model and the monitor; the caller starts/stops the monitor and calls
 *   [VaultSyncModel.syncAtUnlock] once the unlock password is in hand.
 */
fun makeVaultSync(
    folder: File,
    stateDir: File,
    vaultUuid: ByteArray?,
    wallClock: WallClock = SystemWallClock(),
): Pair<VaultSyncModel, ChangeDetectionMonitor> {
    check(Looper.myLooper() == Looper.getMainLooper()) {
        "makeVaultSync must be called on the main thread"
    }
    val coordinator = SyncCoordinator(
        port = UniffiVaultSyncPort(),
        stateDir = stateDir.path,
        vaultFolder = folder.path,
    )
    lateinit var model: VaultSyncModel
    val monitor = makeChangeMonitor(folder) { model.pendingChangesRaised() }
    model = VaultSyncModel(
        coordinator = coordinator,
        wallClock = wallClock,
        monitorHook = MonitorSyncHook(monitor),
        vaultUuid = vaultUuid,
    )
    return model to monitor
}
```

- [ ] **Step 2: Verify the `:kit` module compiles**

Run: `cd android && ./gradlew :kit:compileDebugKotlin`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 3: Commit**

```bash
git add android/kit/src/main/kotlin/org/secretary/sync/VaultSyncFactory.kt
git commit -m "$(cat <<'EOF'
feat(android-sync): makeVaultSync composition factory (slice 4)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: Full gauntlet + docs (README + ROADMAP)

**Files:**
- Modify: `README.md`
- Modify: `ROADMAP.md`

- [ ] **Step 1: Run the full host gauntlet (both modules, no regressions)**

Run: `cd android && ./gradlew :vault-access:test :kit:testDebugUnitTest --rerun-tasks`
Expected: BUILD SUCCESSFUL, all suites green, 0 warnings.

- [ ] **Step 2: Run clippy-equivalent / lint check for the host path is N/A (Kotlin); confirm no new warnings**

Run: `cd android && ./gradlew :vault-access:compileTestKotlin :kit:compileDebugUnitTestKotlin`
Expected: BUILD SUCCESSFUL with no Kotlin warnings.

- [ ] **Step 3: Verify the additive-only guardrails**

Run:
```bash
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|.gitignore)'   # expect empty
git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'           # expect empty
```
Expected: both empty.

- [ ] **Step 4: Update README.md**

The README status table has Android C.3 rows; the most recent is the slice-3 row whose cell begins
`| Android app — folder-change detection (C.3 slice 3) |`. Add a new row **immediately after** that
slice-3 row, in the same `| <label> | ✅ (date): <desc> |` format. Use this row (keep it informative but
not a test-count wall, per the README-style preference):

```markdown
| Android app — sync-UI model (C.3 slice 4) | ✅ (2026-06-16): the host-tested heart of the Android sync UI, mirroring iOS slice 3 minus rendering. A pure FFI-free layer in `:vault-access` — `syncBadgeState` (5-state precedence), `VaultSyncModel` (StateFlow surface; two triggers — silent `syncAtUnlock` + interactive `runInteractivePass`/`resolve` — converging on one resolution path; metadata-only conflict surface; typed errors that keep the conflict context for retry; `acknowledge` only on clean arms), `WallClock` / `SyncMonitorHook` seams, and `collectDecisions`/`decisionsComplete` (per-record default "Keep mine") — all JUnit-5 host-tested via fakes. Real `:kit` wiring: `SystemWallClock`, `MonitorSyncHook` (wraps `ChangeDetectionMonitor`), and a `makeVaultSync` factory. The Compose render (badge, password sheet, conflict sheet) is slice 5. 100% additive Kotlin — no Rust / FFI-surface / on-disk-format change. |
```

Then update the slice-3 row's trailing sentence `Remaining C.3: the Android Compose UI.` →
`Remaining C.3: the Android Compose render (slice 5).` (if that exact trailing sentence is on the Android
slice-3 row; the iOS slice-2 row has a similar one — only change the Android slice-3 row).

- [ ] **Step 5: Update ROADMAP.md**

Three edits, mirroring the existing slice phrasing:

1. **Add a `[x]` checklist item** immediately after the slice-3 item (the line beginning
   `- [x] **Android app — folder-change detection (C.3 slice 3)**`):

```markdown
- [x] **Android app — sync-UI model (C.3 slice 4)** ✅ 2026-06-16 — the host-tested heart of the Android sync UI, the Android mirror of iOS slice 3 minus rendering. Pure FFI-free Kotlin in `:vault-access`: `syncBadgeState` (5-state precedence), `VaultSyncModel` (StateFlow surface; two triggers — silent `syncAtUnlock` + interactive `runInteractivePass`/`resolve` — on one resolution path; metadata-only conflict surface; typed errors keep the conflict context for retry; `acknowledge` only on clean arms), the `WallClock`/`SyncMonitorHook` seams, and `collectDecisions`/`decisionsComplete` (default "Keep mine"), all JUnit5-host-tested via fakes. Real `:kit` wiring: `SystemWallClock`, `MonitorSyncHook`, and a `makeVaultSync` factory. The Compose render is slice 5. 100% additive Kotlin — no Rust / FFI-surface / on-disk-format change. Spec + plan in [`docs/superpowers/specs/2026-06-16-c3-android-sync-ui-design.md`](docs/superpowers/specs/2026-06-16-c3-android-sync-ui-design.md) + [`docs/superpowers/plans/2026-06-16-c3-android-sync-ui-model.md`](docs/superpowers/plans/2026-06-16-c3-android-sync-ui-model.md).
```

2. **Add a sub-bullet** immediately after the slice-3 sub-bullet (the line beginning
   `  - **C.3 slice 3 (Android) — folder-change detection**`):

```markdown
  - **C.3 slice 4 (Android) — sync-UI model** ✅ 2026-06-16 — the host-tested heart (badge state + `VaultSyncModel` two-trigger/one-resolution state machine + `WallClock`/`SyncMonitorHook` seams + decision helpers) in `:vault-access`, plus real `:kit` wiring (`SystemWallClock`, `MonitorSyncHook`, `makeVaultSync`). Mirrors iOS slice 3 minus rendering; the Compose render is slice 5. No Rust / FFI-surface / on-disk-format change.
```

3. **Update the forward-reference** on the `- **C.3 remaining** ⏳` line: it currently reads
   `the Android Compose sync UI (slice 4 — badge, sync-at-unlock, conflict-resolution sheet)`. Change the
   slice number, since slice 4 is now the model and the render is slice 5:
   `the Android Compose sync render (slice 5 — badge, sync-at-unlock, conflict-resolution sheet, over the slice-4 model)`.

Also lightly refresh the prose summary lines that say the Android Compose UI is pending (the
`## Sub-project C` header line ~117, the progress-bar line ~23, and the C-overview paragraph ~17): where
they say "Compose UI pending", leave the *pending* status (the render is still pending) but they need no
slice-number surgery — only flip if a line explicitly enumerated slice 4 as the Compose UI.

- [ ] **Step 6: Commit**

```bash
git add README.md ROADMAP.md
git commit -m "$(cat <<'EOF'
docs: README + ROADMAP — Android C.3 sync-UI model (slice 4)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

## Definition of done

- `cd android && ./gradlew :vault-access:test :kit:testDebugUnitTest --rerun-tasks` → BUILD SUCCESSFUL, all suites green, 0 warnings.
- Both additive-only guardrail greps empty (no `core/`/`ffi/`/`ios/`/format change).
- New public surface: `SyncBadgeState` + `syncBadgeState`, `WallClock`, `SyncMonitorHook`, `VaultSyncModel`, `collectDecisions`/`decisionsComplete` (in `:vault-access`); `SystemWallClock`, `MonitorSyncHook`, `makeVaultSync` (in `:kit`).
- README + ROADMAP reflect slice 4 ✅ and slice 5 (Compose UI) pending.
- Each file stays well under 500 lines; one concept per file.

## Deferred to slice 5 (do NOT build here)

- The Compose app module, `androidx.lifecycle.ViewModel` wrapper, `@Composable` badge / password sheet / conflict-resolution sheet, the Compose UI-test harness, and the badge-tap → password-prompt trigger (`beginInteractiveSync` intent state).
- The "synced N min ago" relative-time rendering.
- Any instrumented/on-device coverage of the model wiring (no emulator surface exists until the app module lands).
- On-device veto round-trip (golden vault is single-device → never `ConflictsPending`; needs a seeded concurrent state).
