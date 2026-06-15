# C.3 (Android) — Sync orchestration core: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the pure, host-testable Kotlin sync orchestration core for the Android client — a faithful mirror of iOS slice 1 (#228) — plus the `android/` Gradle scaffold it lives in.

**Architecture:** A single Gradle `kotlin("jvm")` module `:vault-access` (no Android framework, no FFI) holds metadata-only value types, a `VaultSyncError` sealed hierarchy, a `VaultSyncPort` interface, and a `Mutex`-guarded `SyncCoordinator` that threads the two-call inspect→commit round-trip. The FFI adapter, folder-watch, and Compose UI are later slices.

**Tech Stack:** Kotlin 2.2.10, Gradle 8.14.3 (wrapper), kotlinx-coroutines 1.8.0, JUnit 5.10.2, `kotlinx-coroutines-test`. JDK 21.

**Spec:** [`docs/superpowers/specs/2026-06-15-c3-android-sync-orchestration-core-design.md`](../specs/2026-06-15-c3-android-sync-orchestration-core-design.md)

**Working directory:** the worktree root is `/Users/hherb/src/secretary/.worktrees/c3-android-sync-core`. All Gradle commands run inside its `android/` subdir. Shell state does NOT persist between commands — chain `cd` in one call or use the absolute path.

**Environment notes (already verified):**
- Network reaches Maven Central + Gradle services (HTTP 200), so dependency resolution works online; `~/.gradle` already caches the Gradle 8.14.3 distribution, Kotlin 2.2.10, coroutines 1.8.0, so most of it is fast/offline.
- No `gradle` on PATH. Bootstrap the wrapper once with the cached distribution's binary (Task 1).
- Package for all production + test Kotlin: `org.secretary.sync`.

---

### Task 1: Gradle scaffold + toolchain sanity test

Stand up the `android/` Gradle root and the `:vault-access` module, then prove the JUnit5 + coroutines-test toolchain runs via one throwaway sanity test.

**Files:**
- Create: `android/settings.gradle.kts`
- Create: `android/build.gradle.kts`
- Create: `android/gradle.properties`
- Create: `android/.gitignore`
- Create: `android/vault-access/build.gradle.kts`
- Create: `android/vault-access/src/test/kotlin/org/secretary/sync/ToolchainSanityTest.kt`

- [ ] **Step 1: Create `android/settings.gradle.kts`**

```kotlin
pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
        google()
    }
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
        google()
    }
}

rootProject.name = "secretary-android"

include(":vault-access")
```

- [ ] **Step 2: Create `android/build.gradle.kts`**

```kotlin
plugins {
    // Pure-JVM Kotlin only this slice; Android/Compose modules arrive in later slices.
    kotlin("jvm") version "2.2.10" apply false
}
```

- [ ] **Step 3: Create `android/gradle.properties`**

```properties
org.gradle.caching=true
org.gradle.parallel=true
kotlin.code.style=official
```

- [ ] **Step 4: Create `android/.gitignore`**

```gitignore
.gradle/
build/
```

- [ ] **Step 5: Create `android/vault-access/build.gradle.kts`**

```kotlin
plugins {
    kotlin("jvm")
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.0")

    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.0")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
}
```

- [ ] **Step 6: Create `android/vault-access/src/test/kotlin/org/secretary/sync/ToolchainSanityTest.kt`**

This is a throwaway canary proving the test toolchain (JUnit5 + coroutines-test) is wired. Task 2 deletes it.

```kotlin
package org.secretary.sync

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class ToolchainSanityTest {
    @Test
    fun junitRuns() {
        assertEquals(2, 1 + 1)
    }

    @Test
    fun coroutinesTestRuns() = runTest {
        assertEquals(4, suspendingDouble(2))
    }

    private suspend fun suspendingDouble(n: Int): Int = n * 2
}
```

- [ ] **Step 7: Bootstrap the Gradle wrapper using the cached distribution**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-core/android && \
GRADLE_BIN=$(find ~/.gradle/wrapper/dists/gradle-8.14.3-bin -name gradle -type f -path '*/bin/*' | head -1) && \
"$GRADLE_BIN" wrapper --gradle-version 8.14.3 --distribution-type bin
```
Expected: `BUILD SUCCESSFUL`; creates `android/gradlew`, `android/gradlew.bat`, `android/gradle/wrapper/gradle-wrapper.jar`, `android/gradle/wrapper/gradle-wrapper.properties`.

- [ ] **Step 8: Run the sanity test via the wrapper**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-core/android && ./gradlew :vault-access:test
```
Expected: `BUILD SUCCESSFUL`, 2 tests pass. (First run may download KGP 2.2.10 transitive bits + JUnit launcher — that's fine, network is available.)

- [ ] **Step 9: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-core && \
git add android/ && \
git commit -m "feat(c3-android): Gradle scaffold + :vault-access JVM module (slice 1)

First Gradle project in the repo. Pure kotlin(\"jvm\") module, host-tested
on JUnit5 + coroutines-test, no Android framework, no FFI. Wrapper pinned
to Gradle 8.14.3; Kotlin 2.2.10; coroutines 1.8.0.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: `SyncModels` — metadata-only value types

**Files:**
- Delete: `android/vault-access/src/test/kotlin/org/secretary/sync/ToolchainSanityTest.kt`
- Create: `android/vault-access/src/test/kotlin/org/secretary/sync/SyncModelsTest.kt`
- Create: `android/vault-access/src/main/kotlin/org/secretary/sync/SyncModels.kt`

- [ ] **Step 1: Delete the throwaway sanity test**

```bash
rm /Users/hherb/src/secretary/.worktrees/c3-android-sync-core/android/vault-access/src/test/kotlin/org/secretary/sync/ToolchainSanityTest.kt
```

- [ ] **Step 2: Write the failing test `SyncModelsTest.kt`**

```kotlin
package org.secretary.sync

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SyncModelsTest {
    @Test
    fun conflictsPendingEqualsByContent() {
        val a = SyncOutcome.ConflictsPending(emptyList(), emptyList(), byteArrayOf(1, 2, 3))
        val b = SyncOutcome.ConflictsPending(emptyList(), emptyList(), byteArrayOf(1, 2, 3))
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
    }

    @Test
    fun conflictsPendingDiffersByHash() {
        val a = SyncOutcome.ConflictsPending(emptyList(), emptyList(), byteArrayOf(1, 2, 3))
        val b = SyncOutcome.ConflictsPending(emptyList(), emptyList(), byteArrayOf(9))
        assertNotEquals(a, b)
    }

    @Test
    fun valueTypeEquality() {
        assertEquals(DeviceClock("aa", 1uL), DeviceClock("aa", 1uL))
        assertEquals(SyncVetoDecision("x", true), SyncVetoDecision("x", true))
        assertEquals(
            SyncStatus(true, listOf(DeviceClock("aa", 1uL)), 5uL),
            SyncStatus(true, listOf(DeviceClock("aa", 1uL)), 5uL),
        )
        assertEquals(
            PendingConflict(emptyList(), listOf(SyncCollision("r", listOf("f")))),
            PendingConflict(emptyList(), listOf(SyncCollision("r", listOf("f")))),
        )
    }

    @Test
    fun syncOutcomeObjectsAreDistinctSingletons() {
        assertTrue(SyncOutcome.MergedClean === SyncOutcome.MergedClean)
        assertTrue(SyncOutcome.MergedClean != SyncOutcome.NothingToDo)
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-core/android && ./gradlew :vault-access:test
```
Expected: FAIL — compilation error, unresolved references (`SyncOutcome`, `DeviceClock`, …).

- [ ] **Step 4: Write `SyncModels.kt`**

```kotlin
package org.secretary.sync

/** Vector-clock entry. Never secret — public metadata. */
data class DeviceClock(val deviceUuidHex: String, val counter: ULong)

/** Read-only sync status snapshot. */
data class SyncStatus(
    val hasState: Boolean,
    val deviceClocks: List<DeviceClock>,
    val lastStateWriteMs: ULong?,
)

/**
 * Tombstone-dispute projection. Field [fieldNames] are NAMES only — never values
 * (anti-oracle / metadata-only discipline).
 */
data class SyncVeto(
    val recordUuidHex: String,
    val recordType: String,
    val tags: List<String>,
    val fieldNames: List<String>,
    val localLastModMs: ULong,
    val peerTombstonedAtMs: ULong,
    val peerDeviceHex: String,
)

/** Field-level last-writer-wins collision notice (field NAMES only). */
data class SyncCollision(val recordUuidHex: String, val fieldNames: List<String>)

/** The caller's per-record veto decision. `keepLocal == true` rejects the peer tombstone. */
data class SyncVetoDecision(val recordUuidHex: String, val keepLocal: Boolean)

/** A paused pass's conflict detail, surfaced for interactive resolution. */
data class PendingConflict(val vetoes: List<SyncVeto>, val collisions: List<SyncCollision>)

/**
 * Result of one sync pass. Arms map 1:1 to the uniffi `SyncOutcomeDto` so the future
 * `UniffiVaultSyncPort` adapter is a straight transcription.
 */
sealed interface SyncOutcome {
    data object NothingToDo : SyncOutcome
    data object AppliedAutomatically : SyncOutcome
    data object SilentMerge : SyncOutcome
    data object MergedClean : SyncOutcome
    data object RollbackRejected : SyncOutcome

    /**
     * A tombstone dispute paused the pass without writing. [manifestHash] is the opaque
     * TOCTOU freshness token replayed into `commitDecisions`. Not a `data class`: it carries
     * a [ByteArray], so equality/hashing are content-based via explicit overrides.
     */
    class ConflictsPending(
        val vetoes: List<SyncVeto>,
        val collisions: List<SyncCollision>,
        val manifestHash: ByteArray,
    ) : SyncOutcome {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is ConflictsPending) return false
            return vetoes == other.vetoes &&
                collisions == other.collisions &&
                manifestHash.contentEquals(other.manifestHash)
        }

        override fun hashCode(): Int {
            var result = vetoes.hashCode()
            result = 31 * result + collisions.hashCode()
            result = 31 * result + manifestHash.contentHashCode()
            return result
        }

        override fun toString(): String =
            "ConflictsPending(vetoes=$vetoes, collisions=$collisions, " +
                "manifestHash=${manifestHash.size} bytes)"
    }
}
```

- [ ] **Step 5: Run test to verify it passes**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-core/android && ./gradlew :vault-access:test
```
Expected: `BUILD SUCCESSFUL`, 4 tests pass.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-core && \
git add android/vault-access/src && \
git commit -m "feat(c3-android): metadata-only sync value types (SyncModels)

DeviceClock/SyncStatus/SyncVeto/SyncCollision/SyncVetoDecision/PendingConflict
+ sealed SyncOutcome (arms map 1:1 to uniffi SyncOutcomeDto). ConflictsPending
overrides equals/hashCode for content-based ByteArray comparison.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: `VaultSyncError` sealed hierarchy

**Files:**
- Create: `android/vault-access/src/test/kotlin/org/secretary/sync/VaultSyncErrorTest.kt`
- Create: `android/vault-access/src/main/kotlin/org/secretary/sync/VaultSyncError.kt`

- [ ] **Step 1: Write the failing test `VaultSyncErrorTest.kt`**

```kotlin
package org.secretary.sync

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class VaultSyncErrorTest {
    @Test
    fun detailArmsCarryDetailAsMessage() {
        assertEquals("boom", VaultSyncError.Failed("boom").message)
        assertEquals("bad-state", VaultSyncError.StateCorrupt("bad-state").message)
        assertEquals("arg", VaultSyncError.InvalidArgument("arg").message)
    }

    @Test
    fun objectArmsAreSingletonThrowables() {
        assertSame(VaultSyncError.WrongPasswordOrCorrupt, VaultSyncError.WrongPasswordOrCorrupt)
        assertTrue(VaultSyncError.EvidenceStale is VaultSyncError)
        assertTrue(VaultSyncError.NoPendingConflict is Throwable)
        assertNull(VaultSyncError.InProgress.message)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-core/android && ./gradlew :vault-access:test
```
Expected: FAIL — unresolved reference `VaultSyncError`.

- [ ] **Step 3: Write `VaultSyncError.kt`**

```kotlin
package org.secretary.sync

/**
 * Errors raised by the sync surface. Deliberately SEPARATE from any future
 * `VaultAccessError`: the sync FFI returns a different `FfiVaultError`/`VaultException`
 * variant set, and folding the two would misattribute errors.
 *
 * [WrongPasswordOrCorrupt] is intentionally conflated (wrong password vs. vault corruption)
 * per the threat model's anti-oracle rule (§13). Do NOT split it.
 */
sealed class VaultSyncError(message: String? = null) : Exception(message) {
    /** Re-open failed: wrong password OR corrupt vault. Conflated on purpose (§13). */
    data object WrongPasswordOrCorrupt : VaultSyncError()

    /** Another sync is already running for this vault (per-vault FFI lockfile held). */
    data object InProgress : VaultSyncError()

    /** The sync-state cache belongs to a different vault. */
    data object StateVaultMismatch : VaultSyncError()

    /** The sync-state cache is corrupt. */
    data class StateCorrupt(val detail: String) : VaultSyncError(detail)

    /** The vault changed on disk mid-pass; the TOCTOU freshness gate tripped. Retry. */
    data object EvidenceStale : VaultSyncError()

    /** The supplied decisions did not cover the pending conflicts. */
    data object DecisionsIncomplete : VaultSyncError()

    /** A caller argument was malformed (e.g. wrong-length UUID/hash). */
    data class InvalidArgument(val detail: String) : VaultSyncError(detail)

    /** Any other sync failure. */
    data class Failed(val detail: String) : VaultSyncError(detail)

    /** Coordinator guard: `resolve` was called with no paused conflict stashed. */
    data object NoPendingConflict : VaultSyncError()
}
```

- [ ] **Step 4: Run test to verify it passes**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-core/android && ./gradlew :vault-access:test
```
Expected: `BUILD SUCCESSFUL`, all tests pass (6 total).

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-core && \
git add android/vault-access/src && \
git commit -m "feat(c3-android): VaultSyncError sealed hierarchy

Separate from VaultAccessError (anti-oracle §13); WrongPasswordOrCorrupt
stays conflated. Detail-bearing arms (StateCorrupt/InvalidArgument/Failed)
carry their detail as the Exception message.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: `VaultSyncPort` interface + `FakeVaultSyncPort`

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/sync/VaultSyncPort.kt`
- Create: `android/vault-access/src/test/kotlin/org/secretary/sync/FakeVaultSyncPort.kt`
- Create: `android/vault-access/src/test/kotlin/org/secretary/sync/FakeVaultSyncPortTest.kt`

- [ ] **Step 1: Write the failing test `FakeVaultSyncPortTest.kt`**

```kotlin
package org.secretary.sync

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class FakeVaultSyncPortTest {
    @Test
    fun seedsResultsAndSpiesOnInputs() = runTest {
        val fake = FakeVaultSyncPort()
        fake.syncResults += Result.success(SyncOutcome.MergedClean)

        val out = fake.sync("/state", "/vault", byteArrayOf(7), 42uL)

        assertEquals(SyncOutcome.MergedClean, out)
        val call = fake.syncCalls.single()
        assertEquals("/state", call.stateDir)
        assertEquals("/vault", call.vaultFolder)
        assertTrue(call.password.contentEquals(byteArrayOf(7)))
        assertEquals(42uL, call.nowMs)
    }

    @Test
    fun seededFailureIsThrown() = runTest {
        val fake = FakeVaultSyncPort()
        fake.commitResults += Result.failure(VaultSyncError.EvidenceStale)

        val err = runCatching {
            fake.commitDecisions("/s", "/v", byteArrayOf(), emptyList(), byteArrayOf(1), 1uL)
        }.exceptionOrNull()

        assertTrue(err is VaultSyncError.EvidenceStale)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-core/android && ./gradlew :vault-access:test
```
Expected: FAIL — unresolved references `FakeVaultSyncPort`, `VaultSyncPort`.

- [ ] **Step 3: Write `VaultSyncPort.kt`**

```kotlin
package org.secretary.sync

/**
 * The seam over the FFI sync surface. The future `UniffiVaultSyncPort` is the ONLY type
 * that imports the generated `uniffi.secretary` bindings; everything above this interface
 * is pure and host-tested with a fake.
 *
 * All methods are `suspend` for uniformity. The real adapter runs [sync] / [commitDecisions]
 * on a background dispatcher (they re-open the vault and run Argon2id); [status] is a cheap
 * disk read. [password] is passed per call and MUST NOT be retained by any implementation.
 *
 * Implementations signal failure by throwing [VaultSyncError].
 */
interface VaultSyncPort {
    suspend fun status(stateDir: String, vaultUuid: ByteArray): SyncStatus

    suspend fun sync(
        stateDir: String,
        vaultFolder: String,
        password: ByteArray,
        nowMs: ULong,
    ): SyncOutcome

    suspend fun commitDecisions(
        stateDir: String,
        vaultFolder: String,
        password: ByteArray,
        decisions: List<SyncVetoDecision>,
        manifestHash: ByteArray,
        nowMs: ULong,
    ): SyncOutcome
}
```

- [ ] **Step 4: Write `FakeVaultSyncPort.kt`**

```kotlin
package org.secretary.sync

/**
 * Scriptable in-memory [VaultSyncPort] for host tests. Seed per-method results (a queue,
 * dequeued FIFO) and inspect the recorded calls (spy). A seeded `Result.failure` is thrown,
 * mirroring how the real adapter surfaces [VaultSyncError].
 */
class FakeVaultSyncPort : VaultSyncPort {
    val syncResults: ArrayDeque<Result<SyncOutcome>> = ArrayDeque()
    val commitResults: ArrayDeque<Result<SyncOutcome>> = ArrayDeque()
    var statusResult: Result<SyncStatus> = Result.success(
        SyncStatus(hasState = false, deviceClocks = emptyList(), lastStateWriteMs = null),
    )

    val syncCalls: MutableList<SyncCall> = mutableListOf()
    val commitCalls: MutableList<CommitCall> = mutableListOf()
    val statusCalls: MutableList<ByteArray> = mutableListOf()

    data class SyncCall(
        val stateDir: String,
        val vaultFolder: String,
        val password: ByteArray,
        val nowMs: ULong,
    )

    data class CommitCall(
        val stateDir: String,
        val vaultFolder: String,
        val password: ByteArray,
        val decisions: List<SyncVetoDecision>,
        val manifestHash: ByteArray,
        val nowMs: ULong,
    )

    override suspend fun status(stateDir: String, vaultUuid: ByteArray): SyncStatus {
        statusCalls += vaultUuid
        return statusResult.getOrThrow()
    }

    override suspend fun sync(
        stateDir: String,
        vaultFolder: String,
        password: ByteArray,
        nowMs: ULong,
    ): SyncOutcome {
        syncCalls += SyncCall(stateDir, vaultFolder, password, nowMs)
        return syncResults.removeFirst().getOrThrow()
    }

    override suspend fun commitDecisions(
        stateDir: String,
        vaultFolder: String,
        password: ByteArray,
        decisions: List<SyncVetoDecision>,
        manifestHash: ByteArray,
        nowMs: ULong,
    ): SyncOutcome {
        commitCalls += CommitCall(stateDir, vaultFolder, password, decisions, manifestHash, nowMs)
        return commitResults.removeFirst().getOrThrow()
    }
}
```

- [ ] **Step 5: Run test to verify it passes**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-core/android && ./gradlew :vault-access:test
```
Expected: `BUILD SUCCESSFUL`, all tests pass (8 total).

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-core && \
git add android/vault-access/src && \
git commit -m "feat(c3-android): VaultSyncPort seam + scriptable FakeVaultSyncPort

The interface the future UniffiVaultSyncPort implements; the fake seeds
per-method result queues and spies on inputs for host tests.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: `SyncCoordinator` — the two-call round-trip

**Files:**
- Create: `android/vault-access/src/test/kotlin/org/secretary/sync/SyncCoordinatorTest.kt`
- Create: `android/vault-access/src/main/kotlin/org/secretary/sync/SyncCoordinator.kt`

- [ ] **Step 1: Write the failing test `SyncCoordinatorTest.kt`**

```kotlin
package org.secretary.sync

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SyncCoordinatorTest {
    private val pw = byteArrayOf(1, 2, 3)

    private fun coordinator(port: FakeVaultSyncPort) =
        SyncCoordinator(port, stateDir = "/state", vaultFolder = "/vault")

    @Test
    fun safeOutcomePassesThroughAndLeavesNoStash() = runTest {
        val port = FakeVaultSyncPort()
        port.syncResults += Result.success(SyncOutcome.MergedClean)
        val c = coordinator(port)

        assertEquals(SyncOutcome.MergedClean, c.runPass(pw, 100uL))
        assertNull(c.pendingConflict())
        val call = port.syncCalls.single()
        assertEquals("/state", call.stateDir)
        assertEquals("/vault", call.vaultFolder)
    }

    @Test
    fun conflictStashesTokenAndConflictDetail() = runTest {
        val port = FakeVaultSyncPort()
        val veto = SyncVeto("r1", "login", emptyList(), listOf("password"), 100uL, 200uL, "dev")
        port.syncResults += Result.success(
            SyncOutcome.ConflictsPending(listOf(veto), emptyList(), byteArrayOf(7, 7)),
        )
        val c = coordinator(port)

        val out = c.runPass(pw, 100uL)

        assertTrue(out is SyncOutcome.ConflictsPending)
        assertEquals(PendingConflict(listOf(veto), emptyList()), c.pendingConflict())
    }

    @Test
    fun resolveSendsStashedTokenAndClearsOnResolvedArm() = runTest {
        val port = FakeVaultSyncPort()
        val token = byteArrayOf(5, 5, 5)
        port.syncResults += Result.success(
            SyncOutcome.ConflictsPending(emptyList(), emptyList(), token),
        )
        port.commitResults += Result.success(SyncOutcome.MergedClean)
        val c = coordinator(port)
        c.runPass(pw, 100uL)

        val decisions = listOf(SyncVetoDecision("r1", true))
        assertEquals(SyncOutcome.MergedClean, c.resolve(decisions, pw, 200uL))

        val commit = port.commitCalls.single()
        assertTrue(commit.manifestHash.contentEquals(token))
        assertEquals(decisions, commit.decisions)
        assertNull(c.pendingConflict())
    }

    @Test
    fun resolveWithoutStashThrowsAndDoesNotCallPort() = runTest {
        val port = FakeVaultSyncPort()
        val c = coordinator(port)

        val err = runCatching { c.resolve(emptyList(), pw, 1uL) }.exceptionOrNull()

        assertTrue(err is VaultSyncError.NoPendingConflict)
        assertTrue(port.commitCalls.isEmpty())
    }

    @Test
    fun staleErrorPreservesStashSoRetryReusesToken() = runTest {
        val port = FakeVaultSyncPort()
        val token = byteArrayOf(8)
        port.syncResults += Result.success(
            SyncOutcome.ConflictsPending(emptyList(), emptyList(), token),
        )
        port.commitResults += Result.failure(VaultSyncError.EvidenceStale)
        port.commitResults += Result.success(SyncOutcome.MergedClean)
        val c = coordinator(port)
        c.runPass(pw, 1uL)

        val err = runCatching { c.resolve(emptyList(), pw, 2uL) }.exceptionOrNull()
        assertTrue(err is VaultSyncError.EvidenceStale)
        assertNotNull(c.pendingConflict())

        assertEquals(SyncOutcome.MergedClean, c.resolve(emptyList(), pw, 3uL))
        assertTrue(port.commitCalls.last().manifestHash.contentEquals(token))
        assertNull(c.pendingConflict())
    }

    @Test
    fun resolveReturningConflictReStashesNewToken() = runTest {
        val port = FakeVaultSyncPort()
        port.syncResults += Result.success(
            SyncOutcome.ConflictsPending(emptyList(), emptyList(), byteArrayOf(1)),
        )
        port.commitResults += Result.success(
            SyncOutcome.ConflictsPending(emptyList(), emptyList(), byteArrayOf(2)),
        )
        port.commitResults += Result.success(SyncOutcome.MergedClean)
        val c = coordinator(port)
        c.runPass(pw, 1uL)

        val out = c.resolve(emptyList(), pw, 2uL)
        assertTrue(out is SyncOutcome.ConflictsPending)

        c.resolve(emptyList(), pw, 3uL)
        assertTrue(port.commitCalls.last().manifestHash.contentEquals(byteArrayOf(2)))
    }

    @Test
    fun statusDelegatesToPort() = runTest {
        val port = FakeVaultSyncPort()
        port.statusResult = Result.success(SyncStatus(true, listOf(DeviceClock("aa", 3uL)), 999uL))
        val c = coordinator(port)

        val status = c.status(byteArrayOf(0))

        assertTrue(status.hasState)
        assertEquals(1, port.statusCalls.size)
    }

    @Test
    fun passwordIsForwardedToPortNotAltered() = runTest {
        val port = FakeVaultSyncPort()
        port.syncResults += Result.success(SyncOutcome.NothingToDo)
        val c = coordinator(port)

        c.runPass(pw, 1uL)

        assertTrue(port.syncCalls.single().password.contentEquals(pw))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-core/android && ./gradlew :vault-access:test
```
Expected: FAIL — unresolved reference `SyncCoordinator`.

- [ ] **Step 3: Write `SyncCoordinator.kt`**

```kotlin
package org.secretary.sync

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Threads the two-call inspect→commit sync round-trip and holds the freshness token +
 * conflict detail privately between the two calls. One coordinator drives one vault.
 *
 * Concurrency: guarded by a non-reentrant [Mutex] held ACROSS the suspending port call.
 * This intentionally diverges from the iOS reentrant `actor`: a second concurrent
 * `runPass`/`resolve` blocks until the first completes rather than interleaving — stronger
 * (non-interleaving) serialization. It cannot deadlock because the public methods never
 * call one another. The per-vault FFI lockfile (surfaced as [VaultSyncError.InProgress])
 * remains the cross-process guard; this [Mutex] is the in-process single-driver guarantee.
 *
 * Secret hygiene: the password is forwarded to the port per call and never retained. Only
 * the manifest-hash freshness token (not a secret) and conflict METADATA are stashed.
 */
class SyncCoordinator(
    private val port: VaultSyncPort,
    private val stateDir: String,
    private val vaultFolder: String,
) {
    private val mutex = Mutex()
    private var stashedToken: ByteArray? = null
    private var stashedConflict: PendingConflict? = null

    /** The conflict detail of a currently-paused pass, or null if none is stashed. */
    suspend fun pendingConflict(): PendingConflict? = mutex.withLock { stashedConflict }

    /** Read-only device-clock status. */
    suspend fun status(vaultUuid: ByteArray): SyncStatus =
        mutex.withLock { port.status(stateDir, vaultUuid) }

    /**
     * Run one inspect pass. On [SyncOutcome.ConflictsPending] the token + conflict are
     * stashed for [resolve]; every other arm clears any prior stash.
     */
    suspend fun runPass(password: ByteArray, nowMs: ULong): SyncOutcome = mutex.withLock {
        val outcome = port.sync(stateDir, vaultFolder, password, nowMs)
        applyStash(outcome)
        outcome
    }

    /**
     * Commit veto decisions for the paused pass, replaying the stashed freshness token.
     * Throws [VaultSyncError.NoPendingConflict] if nothing is stashed. A resolved arm clears
     * the stash; another [SyncOutcome.ConflictsPending] re-stashes the new token; a thrown
     * error (e.g. [VaultSyncError.EvidenceStale]) propagates and PRESERVES the stash so the
     * caller can retry `resolve` without a fresh `runPass`.
     */
    suspend fun resolve(
        decisions: List<SyncVetoDecision>,
        password: ByteArray,
        nowMs: ULong,
    ): SyncOutcome = mutex.withLock {
        val token = stashedToken ?: throw VaultSyncError.NoPendingConflict
        val outcome = port.commitDecisions(stateDir, vaultFolder, password, decisions, token, nowMs)
        applyStash(outcome)
        outcome
    }

    /** Stash on a paused pass; clear on any resolved/safe arm. Not called on a thrown error. */
    private fun applyStash(outcome: SyncOutcome) {
        if (outcome is SyncOutcome.ConflictsPending) {
            stashedToken = outcome.manifestHash
            stashedConflict = PendingConflict(outcome.vetoes, outcome.collisions)
        } else {
            stashedToken = null
            stashedConflict = null
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-core/android && ./gradlew :vault-access:test
```
Expected: `BUILD SUCCESSFUL`, all tests pass (16 total).

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-core && \
git add android/vault-access/src && \
git commit -m "feat(c3-android): SyncCoordinator two-call inspect->commit round-trip

Mutex-guarded; stashes the manifest-hash freshness token + conflict metadata
between runPass and resolve. Thrown errors preserve the stash for retry;
resolved arms clear it; a re-raised ConflictsPending re-stashes. Password
forwarded per call, never retained. Documents the deliberate divergence from
iOS's reentrant actor (Mutex held across the call = stronger serialization).

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Docs — README + ROADMAP

Reflect that the Android C.3 adapter has begun: slice 1 (pure orchestration core) shipped.

**Files:**
- Modify: `README.md`
- Modify: `ROADMAP.md`

- [ ] **Step 1: Update `README.md`**

Find the section describing Sub-project C / mobile adapters status (the same area that mentions the iOS C.3 stack). Add a brief dot-point noting the Android pure sync orchestration core (slice 1) landed — host-tested Kotlin `:vault-access` Gradle module mirroring iOS slice 1, no FFI/UI yet. Keep it brief per the README style (dot points, no test-count walls).

Exact insertion: locate the line mentioning the iOS C.3 sync stack under the Sub-project C status, and add immediately after it:

```markdown
- **Android (C.3, in progress):** pure Kotlin sync orchestration core — `android/vault-access`, a host-tested `kotlin("jvm")` Gradle module (the repo's first Gradle project) mirroring iOS slice 1: `VaultSyncPort`, `VaultSyncError`, `SyncCoordinator`, metadata-only value types. No FFI/folder-watch/Compose yet.
```

- [ ] **Step 2: Update `ROADMAP.md`**

In the Sub-project C section header and the C.3 checklist area (where the iOS slices are listed as ✅), add an Android slice-1 entry. Find the iOS C.3 checklist items (the two `- [x] **iOS app — …**` lines) and add after them:

```markdown
- [x] **Android app — sync orchestration core (C.3 slice 1)** ✅ 2026-06-15 — pure host-tested Kotlin over the (future) uniffi sync surface: metadata-only value types + `VaultSyncPort` + a dedicated `VaultSyncError` (separate from vault-access, §13 anti-oracle preserved) + a `Mutex`-guarded `SyncCoordinator` threading the two-call inspect→commit round-trip (freshness token held privately; password passed per call, never stored), all in `android/vault-access/`. The repo's first Gradle project — a `kotlin("jvm")` module host-tested on JUnit5 + coroutines-test (no emulator/NDK). The real `UniffiVaultSyncPort` adapter, folder-change detection (SAF + `WorkManager`), and Compose UI are later slices. 100% Kotlin — no Rust / on-disk-format / FFI-surface change. Spec + plan in [`docs/superpowers/specs/2026-06-15-c3-android-sync-orchestration-core-design.md`](docs/superpowers/specs/2026-06-15-c3-android-sync-orchestration-core-design.md) + [`docs/superpowers/plans/2026-06-15-c3-android-sync-orchestration-core.md`](docs/superpowers/plans/2026-06-15-c3-android-sync-orchestration-core.md).
```

Also update the Sub-project C status line / progress bar caption that currently reads `C.3 iOS ✅ … Android adapter pending` to reflect Android slice 1 started (e.g. `C.3 iOS ✅; Android orchestration core ✅ (adapter/UI pending)`). Match the existing wording style; do not invent new progress-bar glyphs.

- [ ] **Step 3: Verify the docs reference real paths**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-core && \
ls docs/superpowers/specs/2026-06-15-c3-android-sync-orchestration-core-design.md \
   docs/superpowers/plans/2026-06-15-c3-android-sync-orchestration-core.md
```
Expected: both paths listed (no error).

- [ ] **Step 4: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-core && \
git add README.md ROADMAP.md && \
git commit -m "docs(c3-android): note Android sync orchestration core (slice 1) in README + ROADMAP

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Final verification (run after all tasks)

- [ ] **Full test run is green**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-core/android && ./gradlew :vault-access:test
```
Expected: `BUILD SUCCESSFUL`, 16 tests pass, 0 failures.

- [ ] **Diff touches only the allowed surface**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-core && \
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md)'
```
Expected: empty (no `core/`, `ffi/`, `ios/`, on-disk-format, or crypto change).

- [ ] **No Rust/FFI/iOS surface touched**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-core && \
git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'
```
Expected: empty.

---

## Notes for the executor

- **TDD is mandatory.** Each task writes the failing test first, runs it red, then implements minimally, then green. Do not write implementation before the red test.
- **One concept per file**, all files well under 500 lines.
- **Gradle daemon:** the first `./gradlew` invocation starts a daemon and may download KGP 2.2.10 transitive artifacts + the JUnit launcher (network is available). Subsequent runs are fast.
- **If `./gradlew` ever reports a Kotlin/Gradle compatibility warning**, it is a warning not an error — the build still succeeds; do not "fix" it by bumping versions away from the cached pins without re-verifying the cache.
- **`ULong` everywhere** the spec uses `u64` — never narrow to `Long`, so the future FFI adapter is a straight copy.
- **Do not** add `:kit`/`:app` modules, Android Gradle Plugin, `jniLibs`, Compose, `SyncBadgeState`, a `ViewModel`, or a `WallClock` — those are explicitly later slices (§ spec).
