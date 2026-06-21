# Android Write Re-auth Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Require a biometric presence proof (throttled by a 30 s grace window) before every mutating vault write in the Android client, mirroring iOS #275.

**Architecture:** A pure, host-tested gate in `:vault-access` (`needsReauth` policy + `GraceWindowReauthGate`) sits in front of the two write chokepoints — `VaultBrowseModel.guardedWrite` and `RecordEditModel.commit`. The presence proof reuses the already-shipped device-unlock biometric path (`DeviceUnlockCoordinator.unlock` → `enclave.release` behind `BiometricPrompt`); the released secret is zeroized and discarded — only the act of releasing it proves biometry + Keystore-key integrity. The gate is a no-op when no device secret is enrolled (no regression for password-only users). No new cryptography; no FFI/UDL/core changes.

**Tech Stack:** Kotlin, `:vault-access` (kotlin-jvm, JUnit 5 + kotlinx-coroutines-test, host-tested), `:app` (Android, `androidx.biometric`, AndroidKeyStore), Gradle.

## Global Constraints

- **Android-only.** `core/`, `docs/crypto-design.md`, `docs/vault-format.md`, all `*.udl`, `secretary-ffi-py`, `desktop/`, `ios/` MUST stay untouched. Guardrail: `git diff main...HEAD --name-only` matches only `^android/` + `^docs/`.
- **No magic numbers.** The grace window is the named constant `ReauthWindow.V1_DEFAULT_MS = 30_000L`.
- **No new crypto, no FFI/UDL change.** Reuse the shipped `DeviceUnlockCoordinator` / `DeviceSecretEnclave`. The released secret is zeroized (`.fill(0)`) and discarded.
- **Pure functions in reusable modules.** `needsReauth` is a free function; the gate logic is host-testable over injected fakes + a clock lambda.
- **TDD.** Every task writes the failing test first, watches it fail, then implements.
- **Backward compatibility.** The `gate` constructor parameter on `VaultBrowseModel` / `RecordEditModel` defaults to `NoopReauthGate`, so all ~15 existing `VaultBrowseModel(session)` / `RecordEditModel(...)` construction sites keep compiling unchanged.
- **Host-test command** (run from `android/`): `./gradlew :vault-access:test`. Filter a class with `--tests "org.secretary.browse.<ClassName>"`.
- **File size:** keep each new file focused; one concept per file (<500 lines — all new files here are well under).

---

### Task 1: Pure re-auth policy (`needsReauth` + `ReauthWindow`)

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/Reauth.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/ReauthTest.kt`

**Interfaces:**
- Produces: `object ReauthWindow { const val V1_DEFAULT_MS: Long }` and `fun needsReauth(lastAuthAtMs: Long?, nowMs: Long, windowMs: Long): Boolean`.

- [ ] **Step 1: Write the failing test**

Create `android/vault-access/src/test/kotlin/org/secretary/browse/ReauthTest.kt`:

```kotlin
package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ReauthTest {
    private val window = 30_000L

    @Test
    fun `null lastAuth always needs reauth`() {
        assertTrue(needsReauth(lastAuthAtMs = null, nowMs = 0L, windowMs = window))
    }

    @Test
    fun `within the window does not need reauth`() {
        assertFalse(needsReauth(lastAuthAtMs = 1_000L, nowMs = 1_000L + 29_999L, windowMs = window))
    }

    @Test
    fun `exactly at the window boundary needs reauth (inclusive)`() {
        assertTrue(needsReauth(lastAuthAtMs = 1_000L, nowMs = 1_000L + window, windowMs = window))
    }

    @Test
    fun `past the window needs reauth`() {
        assertTrue(needsReauth(lastAuthAtMs = 1_000L, nowMs = 1_000L + window + 1L, windowMs = window))
    }

    @Test
    fun `a zero window always needs reauth (prompt before every write)`() {
        assertTrue(needsReauth(lastAuthAtMs = 5_000L, nowMs = 5_000L, windowMs = 0L))
    }

    @Test
    fun `the v1 default window is 30 seconds`() {
        org.junit.jupiter.api.Assertions.assertEquals(30_000L, ReauthWindow.V1_DEFAULT_MS)
    }
}
```

- [ ] **Step 2: Run the test, verify it fails**

Run (from `android/`): `./gradlew :vault-access:test --tests "org.secretary.browse.ReauthTest"`
Expected: FAIL — `Reauth.kt` does not exist (`unresolved reference: needsReauth` / `ReauthWindow`).

- [ ] **Step 3: Write the implementation**

Create `android/vault-access/src/main/kotlin/org/secretary/browse/Reauth.kt`:

```kotlin
package org.secretary.browse

/** Grace-window defaults for write re-authentication. Mirror of iOS `ReauthWindow.v1Default`. */
object ReauthWindow {
    /** Default seconds-as-millis a fresh presence proof stays valid before a write re-prompts.
     *  30 s matches the iOS biometric sibling; biometric prompts are fast, so a short window is
     *  low-friction. Not user-configurable in this slice (see the design doc, §2). */
    const val V1_DEFAULT_MS: Long = 30_000L
}

/**
 * Does a mutating write need a fresh presence proof?
 *
 * Pure policy — the single source of truth shared by every gate decision (host-tested in isolation).
 *
 * @param lastAuthAtMs epoch-millis of the last successful proof this session, or null if none yet.
 * @param nowMs        current epoch-millis.
 * @param windowMs     grace window; within it a write is silently authorized.
 * @return true if the user must re-prove presence:
 *   - `lastAuthAtMs == null`            → true  (never authed this session)
 *   - `nowMs - lastAuthAtMs >= window`  → true  (window elapsed; boundary INCLUSIVE)
 *   - otherwise                         → false (still inside the grace window)
 */
fun needsReauth(lastAuthAtMs: Long?, nowMs: Long, windowMs: Long): Boolean {
    if (lastAuthAtMs == null) return true
    return nowMs - lastAuthAtMs >= windowMs
}
```

- [ ] **Step 4: Run the test, verify it passes**

Run: `./gradlew :vault-access:test --tests "org.secretary.browse.ReauthTest"`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/browse/Reauth.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/ReauthTest.kt
git commit -m "feat(android): pure needsReauth policy + ReauthWindow constant"
```

---

### Task 2: Gate interfaces + `GraceWindowReauthGate` + `NoopReauthGate`

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/WriteReauthGate.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/GraceWindowReauthGateTest.kt`

**Interfaces:**
- Consumes: `needsReauth`, `ReauthWindow.V1_DEFAULT_MS` (Task 1); `DeviceUnlockError` (existing, in `DeviceUnlockError.kt`).
- Produces:
  - `interface WriteReauthGate { suspend fun authorizeWrite(reason: String); fun seed(nowMs: Long) {}; fun reset() {} }`
  - `interface BiometricAuthorizer { val isEnrolled: Boolean; suspend fun authorize(reason: String) }`
  - `class GraceWindowReauthGate(authorizer: BiometricAuthorizer, clock: () -> Long, windowMs: Long = ReauthWindow.V1_DEFAULT_MS) : WriteReauthGate`
  - `object NoopReauthGate : WriteReauthGate`

- [ ] **Step 1: Write the failing test**

Create `android/vault-access/src/test/kotlin/org/secretary/browse/GraceWindowReauthGateTest.kt`:

```kotlin
package org.secretary.browse

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** Records each authorize() call and can be scripted to throw a DeviceUnlockError. */
private class FakeBiometricAuthorizer(
    override val isEnrolled: Boolean = true,
    private val error: DeviceUnlockError? = null,
) : BiometricAuthorizer {
    val reasons = mutableListOf<String>()
    override suspend fun authorize(reason: String) {
        reasons += reason
        error?.let { throw it }
    }
}

class GraceWindowReauthGateTest {
    private var nowMs = 1_000L
    private fun clock(): Long = nowMs

    @Test
    fun `not enrolled is a no-op (never prompts)`() = runTest {
        val auth = FakeBiometricAuthorizer(isEnrolled = false)
        val gate = GraceWindowReauthGate(auth, ::clock, windowMs = 30_000L)
        gate.authorizeWrite("write")
        assertTrue(auth.reasons.isEmpty())
    }

    @Test
    fun `first write with no prior auth prompts and records the reason`() = runTest {
        val auth = FakeBiometricAuthorizer()
        val gate = GraceWindowReauthGate(auth, ::clock, windowMs = 30_000L)
        gate.authorizeWrite("Confirm deleting this entry")
        assertEquals(listOf("Confirm deleting this entry"), auth.reasons)
    }

    @Test
    fun `a write within the grace window is silent`() = runTest {
        val auth = FakeBiometricAuthorizer()
        val gate = GraceWindowReauthGate(auth, ::clock, windowMs = 30_000L)
        gate.authorizeWrite("first")        // prompts, advances lastAuth to now=1000
        nowMs = 1_000L + 29_999L
        gate.authorizeWrite("second")       // within window → silent
        assertEquals(listOf("first"), auth.reasons)
    }

    @Test
    fun `a write at or past the window prompts again`() = runTest {
        val auth = FakeBiometricAuthorizer()
        val gate = GraceWindowReauthGate(auth, ::clock, windowMs = 30_000L)
        gate.authorizeWrite("first")        // now=1000
        nowMs = 1_000L + 30_000L            // exactly the boundary
        gate.authorizeWrite("second")
        assertEquals(listOf("first", "second"), auth.reasons)
    }

    @Test
    fun `seed opens the grace window so the next write is silent`() = runTest {
        val auth = FakeBiometricAuthorizer()
        val gate = GraceWindowReauthGate(auth, ::clock, windowMs = 30_000L)
        gate.seed(nowMs)                    // just unlocked
        gate.authorizeWrite("write")        // within window of the seed → silent
        assertTrue(auth.reasons.isEmpty())
    }

    @Test
    fun `reset forces the next write to prompt again`() = runTest {
        val auth = FakeBiometricAuthorizer()
        val gate = GraceWindowReauthGate(auth, ::clock, windowMs = 30_000L)
        gate.seed(nowMs)
        gate.reset()
        gate.authorizeWrite("write")
        assertEquals(listOf("write"), auth.reasons)
    }

    @Test
    fun `a cancelled prompt throws and does NOT advance the window`() = runTest {
        val auth = FakeBiometricAuthorizer(error = DeviceUnlockError.UserCancelled)
        val gate = GraceWindowReauthGate(auth, ::clock, windowMs = 30_000L)
        assertThrows(DeviceUnlockError.UserCancelled::class.java) {
            kotlinx.coroutines.runBlocking { gate.authorizeWrite("write") }
        }
        // Window did not advance: a follow-up still prompts (would be silent if it had advanced).
        val ok = FakeBiometricAuthorizer()
        val gate2 = GraceWindowReauthGate(ok, ::clock, windowMs = 30_000L)
        gate2.authorizeWrite("again")
        assertEquals(listOf("again"), ok.reasons)
    }

    @Test
    fun `a failed prompt throws and does NOT advance the window`() = runTest {
        val auth = FakeBiometricAuthorizer(error = DeviceUnlockError.BiometryLockout)
        val gate = GraceWindowReauthGate(auth, ::clock, windowMs = 30_000L)
        assertThrows(DeviceUnlockError.BiometryLockout::class.java) {
            kotlinx.coroutines.runBlocking { gate.authorizeWrite("write") }
        }
        nowMs += 1L
        // Still no valid proof → the next write prompts again (same authorizer, set to succeed now is N/A;
        // assert by observing a second call IS attempted).
        assertThrows(DeviceUnlockError.BiometryLockout::class.java) {
            kotlinx.coroutines.runBlocking { gate.authorizeWrite("write2") }
        }
        assertEquals(listOf("write", "write2"), auth.reasons)
    }
}
```

- [ ] **Step 2: Run the test, verify it fails**

Run: `./gradlew :vault-access:test --tests "org.secretary.browse.GraceWindowReauthGateTest"`
Expected: FAIL — `WriteReauthGate` / `GraceWindowReauthGate` / `BiometricAuthorizer` unresolved.

- [ ] **Step 3: Write the implementation**

Create `android/vault-access/src/main/kotlin/org/secretary/browse/WriteReauthGate.kt`:

```kotlin
package org.secretary.browse

/**
 * The presence gate the write VMs depend on. `authorizeWrite` returns normally when the write may
 * proceed (gate disabled, within the grace window, or proof succeeded) and THROWS a
 * [DeviceUnlockError] when the user cancels or biometry fails. Mirror of iOS `WriteReauthGate`.
 *
 * `seed`/`reset` default to no-ops so [NoopReauthGate] and host tests need not implement them.
 */
interface WriteReauthGate {
    /** Prove presence for a write described by [reason]; throws [DeviceUnlockError] on cancel/failure. */
    suspend fun authorizeWrite(reason: String)

    /** Open the grace window at [nowMs] (call right after a successful unlock). */
    fun seed(nowMs: Long) {}

    /** Drop any prior proof so the next write prompts again (call on lock). */
    fun reset() {}
}

/**
 * The biometric presence primitive, abstracted so the gate is host-testable over a fake. The real
 * impl ([CoordinatorBiometricAuthorizer]) wraps the shipped device-unlock path.
 */
interface BiometricAuthorizer {
    /** True iff a device secret is enrolled (a Keystore key exists to release). Cheap, no prompt. */
    val isEnrolled: Boolean

    /** Prove presence (real impl: a biometric prompt explained by [reason]); throws
     *  [DeviceUnlockError] on cancel/lockout/failure. */
    suspend fun authorize(reason: String)
}

/**
 * Grace-window write gate. Active only when a device secret is enrolled; within [windowMs] of the
 * last successful proof a write is silently authorized. The proof timestamp advances ONLY on success,
 * so a cancelled/failed prompt never opens the window. Pure (no I/O); [clock] and [authorizer] are
 * injected for host tests. Mirror of iOS `GraceWindowReauthGate`.
 */
class GraceWindowReauthGate(
    private val authorizer: BiometricAuthorizer,
    private val clock: () -> Long,
    private val windowMs: Long = ReauthWindow.V1_DEFAULT_MS,
) : WriteReauthGate {
    private var lastAuthAtMs: Long? = null

    override suspend fun authorizeWrite(reason: String) {
        if (!authorizer.isEnrolled) return                          // no enrollment → no gate
        if (!needsReauth(lastAuthAtMs, clock(), windowMs)) return   // inside the grace window
        authorizer.authorize(reason)                                // throws on cancel/failure
        lastAuthAtMs = clock()                                      // advance ONLY on success
    }

    override fun seed(nowMs: Long) { lastAuthAtMs = nowMs }
    override fun reset() { lastAuthAtMs = null }
}

/** A gate that authorizes everything. The default for VMs constructed without write re-auth
 *  (host tests, and any session with no enrolled device secret). */
object NoopReauthGate : WriteReauthGate {
    override suspend fun authorizeWrite(reason: String) {}
}
```

- [ ] **Step 4: Run the test, verify it passes**

Run: `./gradlew :vault-access:test --tests "org.secretary.browse.GraceWindowReauthGateTest"`
Expected: PASS (8 tests).

- [ ] **Step 5: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/browse/WriteReauthGate.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/GraceWindowReauthGateTest.kt
git commit -m "feat(android): WriteReauthGate + GraceWindowReauthGate + NoopReauthGate"
```

---

### Task 3: `CoordinatorBiometricAuthorizer` (real proof over the shipped enclave)

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/CoordinatorBiometricAuthorizer.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/CoordinatorBiometricAuthorizerTest.kt`

**Interfaces:**
- Consumes: `BiometricAuthorizer` (Task 2); `DeviceUnlockCoordinator` + `UnlockCredential.DeviceSecret` + `DeviceUnlockError` (existing); test fakes `FakeVaultDeviceSlotPort` / `FakeDeviceSecretEnclave` / `FakeEnrollmentMetadataStore` (existing in `DeviceUnlockFakes.kt`).
- Produces: `class CoordinatorBiometricAuthorizer(coordinator: DeviceUnlockCoordinator, vaultId: String) : BiometricAuthorizer`.

**Note:** the proof is "release the device secret, then zeroize+discard it" — we never use the bytes. `DeviceUnlockCoordinator.unlock(vaultId, reason)` runs its guards (NotEnrolled / VaultSlotMismatch) BEFORE the biometric prompt and returns an `UnlockCredential.DeviceSecret` whose `.secret` is the released array.

- [ ] **Step 1: Write the failing test**

Create `android/vault-access/src/test/kotlin/org/secretary/browse/CoordinatorBiometricAuthorizerTest.kt`:

```kotlin
package org.secretary.browse

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** Enclave that hands back the SAME array instance it last released, so the test can prove the
 *  authorizer zeroized it after the proof. */
private class CapturingEnclave(private val secret: ByteArray = ByteArray(32) { 7 }) : DeviceSecretEnclave {
    var released: ByteArray? = null
        private set
    override val isEnrolled: Boolean = true
    override suspend fun store(secret: ByteArray) {}
    override suspend fun release(reason: String): ByteArray = secret.also { released = it }
    override suspend fun clear() {}
}

class CoordinatorBiometricAuthorizerTest {
    private val vaultId = "abcd"
    private fun coordinator(
        enclave: DeviceSecretEnclave,
        enrolled: Boolean = true,
    ): DeviceUnlockCoordinator {
        val metadata = FakeEnrollmentMetadataStore()
        if (enrolled) metadata.save(DeviceEnrollment(vaultId, ByteArray(16) { 1 }))
        return DeviceUnlockCoordinator(FakeVaultDeviceSlotPort(), enclave, metadata)
    }

    @Test
    fun `isEnrolled reflects the coordinator`() {
        val auth = CoordinatorBiometricAuthorizer(coordinator(FakeDeviceSecretEnclave().apply { }, enrolled = false), vaultId)
        assertFalse(auth.isEnrolled)
    }

    @Test
    fun `authorize releases the secret and zeroizes it`() = runTest {
        val enclave = CapturingEnclave()
        val auth = CoordinatorBiometricAuthorizer(coordinator(enclave), vaultId)
        auth.authorize("Confirm saving this entry")
        // The released array exists and was wiped after the proof.
        assertArrayEquals(ByteArray(32), enclave.released)
    }

    @Test
    fun `a release failure propagates as DeviceUnlockError`() = runTest {
        val enclave = FakeDeviceSecretEnclave(releaseError = DeviceUnlockError.UserCancelled)
        // FakeDeviceSecretEnclave.isEnrolled is false until store(); store a secret first so the
        // coordinator gets past its enrollment guard and reaches release().
        enclave.store(ByteArray(32) { 2 })
        val auth = CoordinatorBiometricAuthorizer(coordinator(enclave), vaultId)
        assertThrows(DeviceUnlockError.UserCancelled::class.java) {
            kotlinx.coroutines.runBlocking { auth.authorize("write") }
        }
    }

    @Test
    fun `authorize on a wrong-vault enrollment throws VaultSlotMismatch (guard before prompt)`() = runTest {
        val enclave = CapturingEnclave()
        val auth = CoordinatorBiometricAuthorizer(coordinator(enclave), vaultId = " ffff ".trim())
        // coordinator was built for vaultId="abcd"; authorizer asks for "ffff" → mismatch, no release.
        assertThrows(DeviceUnlockError.VaultSlotMismatch::class.java) {
            kotlinx.coroutines.runBlocking { auth.authorize("write") }
        }
        assertTrue(enclave.released == null)
    }
}
```

- [ ] **Step 2: Run the test, verify it fails**

Run: `./gradlew :vault-access:test --tests "org.secretary.browse.CoordinatorBiometricAuthorizerTest"`
Expected: FAIL — `CoordinatorBiometricAuthorizer` unresolved.

- [ ] **Step 3: Write the implementation**

Create `android/vault-access/src/main/kotlin/org/secretary/browse/CoordinatorBiometricAuthorizer.kt`:

```kotlin
package org.secretary.browse

/**
 * Real [BiometricAuthorizer] for write re-auth: proves presence by releasing the enrolled device
 * secret through the shipped [DeviceUnlockCoordinator] (which runs its NotEnrolled / VaultSlotMismatch
 * guards BEFORE the biometric prompt), then immediately zeroizes and discards the released bytes — we
 * need the *act* of releasing (proves biometry + Keystore-key integrity), not the secret itself.
 *
 * No new crypto: this is the exact path used to unlock the vault, reused as a presence proof.
 */
class CoordinatorBiometricAuthorizer(
    private val coordinator: DeviceUnlockCoordinator,
    private val vaultId: String,
) : BiometricAuthorizer {
    override val isEnrolled: Boolean get() = coordinator.isEnrolled

    override suspend fun authorize(reason: String) {
        val credential = coordinator.unlock(vaultId, reason) // throws DeviceUnlockError on cancel/fail
        credential.secret.fill(0)                            // zeroize + discard — proof was the release
    }
}
```

- [ ] **Step 4: Run the test, verify it passes**

Run: `./gradlew :vault-access:test --tests "org.secretary.browse.CoordinatorBiometricAuthorizerTest"`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/browse/CoordinatorBiometricAuthorizer.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/CoordinatorBiometricAuthorizerTest.kt
git commit -m "feat(android): CoordinatorBiometricAuthorizer (release-as-presence-proof, zeroized)"
```

---

### Task 4: Gate `VaultBrowseModel` writes + `VaultBrowseError.ReauthFailed`

**Files:**
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseError.kt` (add `ReauthFailed` arm)
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseModel.kt` (gate param; `guardedWrite` reason + gate call; thread reasons; reset on lock)
- Create test: `android/vault-access/src/test/kotlin/org/secretary/browse/VaultBrowseModelReauthTest.kt`

**Interfaces:**
- Consumes: `WriteReauthGate` / `NoopReauthGate` (Task 2), `DeviceUnlockError` (existing).
- Produces:
  - `data class VaultBrowseError.ReauthFailed(val detail: String)`.
  - `VaultBrowseModel(session, gate: WriteReauthGate = NoopReauthGate)` — new 2nd param (defaulted).
  - All four browse write methods (`delete`, `restore`, `confirmMove`, `confirmBlockName`) now route through the gate via `guardedWrite(reason, reload, op)`.

**Add a shared test fake** — append this class to the new test file (used here and in Task 5):

```kotlin
/** Records each authorizeWrite reason; optionally throws the scripted error. */
class RecordingReauthGate(private val error: DeviceUnlockError? = null) : WriteReauthGate {
    val reasons = mutableListOf<String>()
    override suspend fun authorizeWrite(reason: String) {
        reasons += reason
        error?.let { throw it }
    }
}
```

- [ ] **Step 1: Write the failing test**

Create `android/vault-access/src/test/kotlin/org/secretary/browse/VaultBrowseModelReauthTest.kt`:

```kotlin
package org.secretary.browse

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** Records each authorizeWrite reason; optionally throws the scripted error. */
class RecordingReauthGate(private val error: DeviceUnlockError? = null) : WriteReauthGate {
    val reasons = mutableListOf<String>()
    override suspend fun authorizeWrite(reason: String) {
        reasons += reason
        error?.let { throw it }
    }
}

@OptIn(ExperimentalCoroutinesApi::class)
class VaultBrowseModelReauthTest {
    private val block = BlockSummaryView(ByteArray(16) { 0x4c }, "Logins", 1u, 2u)
    private val rec = RecordSummaryView(
        hexOfBytes(ByteArray(16) { 0x33 }), "login", listOf("t"), 1u, 2u, false,
        listOf(textField("u", "secret")),
    )
    private fun fake() = FakeVaultSession("abcd", listOf(block), mapOf(block.uuidHex to listOf(rec)))

    @Test
    fun `delete authorizes with the delete reason before writing`() = runTest {
        val f = fake()
        val gate = RecordingReauthGate()
        val model = VaultBrowseModel(f, gate)
        model.loadBlocks(); model.selectBlock(block)
        model.delete(rec)
        assertEquals(listOf("Confirm deleting this entry"), gate.reasons)
        assertEquals(1, f.tombstoned.size)
    }

    @Test
    fun `confirmBlockName create authorizes with the create reason`() = runTest {
        val f = fake()
        val gate = RecordingReauthGate()
        val model = VaultBrowseModel(f, gate)
        model.loadBlocks(); model.startCreateBlock()
        model.confirmBlockName("Work")
        assertEquals(listOf("Confirm creating this block"), gate.reasons)
        assertEquals(listOf("Work"), f.created)
    }

    @Test
    fun `confirmBlockName rename authorizes with the rename reason`() = runTest {
        val f = fake()
        val gate = RecordingReauthGate()
        val model = VaultBrowseModel(f, gate)
        model.loadBlocks(); model.startRenameBlock(block)
        model.confirmBlockName("Passwords")
        assertEquals(listOf("Confirm renaming this block"), gate.reasons)
        assertEquals(listOf(block.uuidHex to "Passwords"), f.renamed)
    }

    @Test
    fun `a cancelled reauth writes nothing and keeps the dialog open with no error`() = runTest {
        val f = fake()
        val gate = RecordingReauthGate(error = DeviceUnlockError.UserCancelled)
        val model = VaultBrowseModel(f, gate)
        model.loadBlocks(); model.startCreateBlock()
        model.confirmBlockName("Work")
        assertTrue(f.created.isEmpty())                                   // no write
        assertTrue(model.blockNameDialog.value is BlockNameDialogState.CreateBlock) // dialog stays open
        assertNull(model.error.value)                                    // cancel is silent
    }

    @Test
    fun `a failed reauth surfaces ReauthFailed and writes nothing`() = runTest {
        val f = fake()
        val gate = RecordingReauthGate(error = DeviceUnlockError.BiometryLockout)
        val model = VaultBrowseModel(f, gate)
        model.loadBlocks(); model.startCreateBlock()
        model.confirmBlockName("Work")
        assertTrue(f.created.isEmpty())
        assertTrue(model.error.value is VaultBrowseError.ReauthFailed)
        assertTrue(model.blockNameDialog.value is BlockNameDialogState.CreateBlock)
    }

    @Test
    fun `confirmMove cancelled keeps the picker open and writes nothing`() = runTest {
        val src = BlockSummaryView(ByteArray(16) { 0x11 }, "Src", 1u, 2u)
        val tgt = BlockSummaryView(ByteArray(16) { 0x22 }, "Tgt", 1u, 2u)
        val mv = RecordSummaryView(hexOfBytes(ByteArray(16) { 0x33 }), "login", listOf("t"), 1u, 2u, false,
            listOf(textField("u", "secret")))
        val f = FakeVaultSession("abcd", listOf(src, tgt), mapOf(src.uuidHex to listOf(mv)))
        val gate = RecordingReauthGate(error = DeviceUnlockError.UserCancelled)
        val model = VaultBrowseModel(f, gate)
        model.loadBlocks(); model.selectBlock(src); model.startMoveRecord(mv)
        model.confirmMove(tgt)
        assertTrue(f.moved.isEmpty())
        assertEquals(mv, model.movingRecord.value)   // picker still open
    }

    @Test
    fun `lock resets the gate so the next write prompts again`() = runTest {
        // A GraceWindowReauthGate seeded open would normally be silent; lock() must reset it.
        var now = 1_000L
        val auth = object : BiometricAuthorizer {
            override val isEnrolled = true
            val reasons = mutableListOf<String>()
            override suspend fun authorize(reason: String) { reasons += reason }
        }
        val gate = GraceWindowReauthGate(auth, { now }, windowMs = 30_000L)
        gate.seed(now)
        val f = fake()
        val model = VaultBrowseModel(f, gate)
        model.loadBlocks()
        model.lock()                                  // must call gate.reset()
        model.loadBlocks(); model.startCreateBlock()
        model.confirmBlockName("Work")
        assertEquals(listOf("Confirm creating this block"), auth.reasons) // prompted (window was reset)
    }
}
```

- [ ] **Step 2: Run the test, verify it fails**

Run: `./gradlew :vault-access:test --tests "org.secretary.browse.VaultBrowseModelReauthTest"`
Expected: FAIL — `VaultBrowseError.ReauthFailed` unresolved + the 2-arg `VaultBrowseModel(f, gate)` ctor does not exist.

- [ ] **Step 3a: Add the `ReauthFailed` arm**

In `android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseError.kt`, add this arm after `SaveCryptoFailure` (before `Failed`):

```kotlin
    /** A mutating write was refused because the biometric presence proof failed (lockout / hardware
     *  unavailable / not-a-match). Distinct from [Failed]; safe to surface. A user *cancel* is NOT
     *  this — cancel aborts silently and leaves the originating dialog open. */
    data class ReauthFailed(val detail: String) : VaultBrowseError(detail)
```

- [ ] **Step 3b: Add the gate parameter + wire `guardedWrite`**

In `android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseModel.kt`:

Change the class header (line 31) from:

```kotlin
class VaultBrowseModel(private val session: VaultSession) {
```

to:

```kotlin
class VaultBrowseModel(
    private val session: VaultSession,
    private val gate: WriteReauthGate = NoopReauthGate,
) {
```

Replace `delete` / `restore` (lines 137–143) with reason-carrying calls:

```kotlin
    /** Soft-delete [record] (after a presence proof), then re-read the selected block. */
    suspend fun delete(record: RecordSummaryView) =
        commitThenReload("Confirm deleting this entry") { block ->
            session.tombstoneRecord(block.uuid, hexToBytes(record.uuidHex))
        }

    /** Restore [record] (after a presence proof), then re-read. */
    suspend fun restore(record: RecordSummaryView) =
        commitThenReload("Confirm restoring this entry") { block ->
            session.resurrectRecord(block.uuid, hexToBytes(record.uuidHex))
        }
```

Replace `guardedWrite` (lines 176–190) with the gated version (note the new first param + the gate block before `op()`):

```kotlin
    private suspend fun guardedWrite(
        reason: String,
        reload: suspend () -> Unit,
        op: suspend () -> Unit,
    ) {
        if (_writing.value) return
        _writing.value = true
        try {
            try {
                gate.authorizeWrite(reason)
            } catch (e: DeviceUnlockError.UserCancelled) {
                return // silent: no write, no error; the originating dialog stays open (op never ran)
            } catch (e: DeviceUnlockError) {
                _error.value = VaultBrowseError.ReauthFailed(e.toString())
                return
            }
            try {
                op()
            } catch (e: VaultBrowseError) {
                _error.value = e
                return
            }
            reload()
        } finally {
            _writing.value = false
        }
    }
```

Replace `commitThenReload` (lines 198–201) to thread the reason:

```kotlin
    private suspend fun commitThenReload(reason: String, op: suspend (BlockSummaryView) -> Unit) {
        val block = _selectedBlock.value ?: return
        guardedWrite(reason, reload = { selectBlock(block) }) { op(block) }
    }
```

In `confirmMove` (line 235) change the `guardedWrite(...)` call to pass the reason:

```kotlin
        guardedWrite("Confirm moving this entry", reload = { selectBlock(source) }) {
            session.moveRecord(source.uuid, target.uuid, hexToBytes(record.uuidHex))
            _movingRecord.value = null
        }
```

In `confirmBlockName` (line 253) compute the reason from the dialog state and pass it:

```kotlin
        val reason = when (dialog) {
            BlockNameDialogState.CreateBlock -> "Confirm creating this block"
            is BlockNameDialogState.RenameBlock -> "Confirm renaming this block"
        }
        guardedWrite(reason, reload = { loadBlocks() }) {
            when (dialog) {
                BlockNameDialogState.CreateBlock -> session.createBlock(trimmed)
                is BlockNameDialogState.RenameBlock -> session.renameBlock(dialog.blockUuid, trimmed)
            }
            _blockNameDialog.value = null
        }
```

In `lock()` (the second one, at line 271) add `gate.reset()` as the first statement:

```kotlin
    fun lock() {
        gate.reset()
        _revealed.value = emptyMap()
        // … rest unchanged …
```

- [ ] **Step 4: Run the test, verify it passes (and the existing browse tests still pass)**

Run: `./gradlew :vault-access:test --tests "org.secretary.browse.VaultBrowseModelReauthTest" --tests "org.secretary.browse.VaultBrowseModelBlockCrudTest" --tests "org.secretary.browse.VaultBrowseModelTest"`
Expected: PASS — new reauth tests green; the existing block-CRUD + browse tests still green (they use the defaulted `NoopReauthGate`).

- [ ] **Step 5: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseError.kt \
        android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseModel.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/VaultBrowseModelReauthTest.kt
git commit -m "feat(android): gate VaultBrowseModel writes behind WriteReauthGate; add ReauthFailed"
```

---

### Task 5: Gate `RecordEditModel.commit` + thread the gate from `VaultBrowseModel`

**Files:**
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/RecordEditModel.kt` (gate param + gate call in `commit`)
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseModel.kt` (`startAdd` / `startEdit` pass `gate`)
- Create test: `android/vault-access/src/test/kotlin/org/secretary/browse/RecordEditModelReauthTest.kt`

**Interfaces:**
- Consumes: `WriteReauthGate` / `NoopReauthGate` / `RecordingReauthGate` (Tasks 2 & 4), `DeviceUnlockError`, `VaultBrowseError.ReauthFailed` (Task 4).
- Produces: `RecordEditModel(session, blockUuid, mode, gate: WriteReauthGate = NoopReauthGate)` — new 4th param (defaulted); `commit()` proves presence after validation, before the FFI write.

- [ ] **Step 1: Write the failing test**

Create `android/vault-access/src/test/kotlin/org/secretary/browse/RecordEditModelReauthTest.kt`:

```kotlin
package org.secretary.browse

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RecordEditModelReauthTest {
    private val block = BlockSummaryView(ByteArray(16) { 0x4c }, "Logins", 1u, 2u)
    private fun fake() = FakeVaultSession("abcd", listOf(block))

    private fun addModel(gate: WriteReauthGate, f: FakeVaultSession) =
        RecordEditModel(f, block.uuid, RecordEditModel.Mode.Add, gate).apply {
            setRecordType("login"); addField(); setFieldName(0, "user"); setFieldRawText(0, "alice")
        }

    @Test
    fun `commit authorizes with the save reason before writing`() = runTest {
        val f = fake()
        val gate = RecordingReauthGate()
        val model = addModel(gate, f)
        model.commit()
        assertEquals(listOf("Confirm saving this entry"), gate.reasons)
        assertEquals(1, f.appended.size)
        assertTrue(model.committed.value)
    }

    @Test
    fun `a cancelled reauth writes nothing, sets no error, and does not commit`() = runTest {
        val f = fake()
        val gate = RecordingReauthGate(error = DeviceUnlockError.UserCancelled)
        val model = addModel(gate, f)
        model.commit()
        assertTrue(f.appended.isEmpty())
        assertFalse(model.committed.value)   // form stays open
        assertNull(model.error.value)        // cancel is silent
    }

    @Test
    fun `a failed reauth surfaces ReauthFailed and writes nothing`() = runTest {
        val f = fake()
        val gate = RecordingReauthGate(error = DeviceUnlockError.BiometryUnavailable)
        val model = addModel(gate, f)
        model.commit()
        assertTrue(f.appended.isEmpty())
        assertFalse(model.committed.value)
        assertTrue(model.error.value is VaultBrowseError.ReauthFailed)
    }

    @Test
    fun `the gate is consulted only AFTER validation (invalid input never prompts)`() = runTest {
        val f = fake()
        val gate = RecordingReauthGate()
        // duplicate field names → validation error before any gate call
        val model = RecordEditModel(f, block.uuid, RecordEditModel.Mode.Add, gate).apply {
            setRecordType("login")
            addField(); setFieldName(0, "dup"); setFieldRawText(0, "a")
            addField(); setFieldName(1, "dup"); setFieldRawText(1, "b")
        }
        model.commit()
        assertTrue(gate.reasons.isEmpty())                          // never prompted
        assertTrue(model.error.value is VaultBrowseError.InvalidArgument)
        assertTrue(f.appended.isEmpty())
    }
}
```

- [ ] **Step 2: Run the test, verify it fails**

Run: `./gradlew :vault-access:test --tests "org.secretary.browse.RecordEditModelReauthTest"`
Expected: FAIL — the 4-arg `RecordEditModel(...)` ctor does not exist.

- [ ] **Step 3a: Add the gate param + gate call to `RecordEditModel`**

In `android/vault-access/src/main/kotlin/org/secretary/browse/RecordEditModel.kt`, change the class header (lines 32–36) from:

```kotlin
class RecordEditModel(
    private val session: VaultSession,
    private val blockUuid: ByteArray,
    val mode: Mode,
) {
```

to:

```kotlin
class RecordEditModel(
    private val session: VaultSession,
    private val blockUuid: ByteArray,
    val mode: Mode,
    private val gate: WriteReauthGate = NoopReauthGate,
) {
```

In `commit()` insert the gate call AFTER validation and BEFORE the write `try` block. The body becomes (replacing lines 128–150):

```kotlin
        _inFlight.value = true
        try {
            val content = buildContent() ?: return // sets _error on hex failure
            content.validate()?.let {
                _error.value = mapValidation(it)
                return
            }
            try {
                gate.authorizeWrite("Confirm saving this entry")
            } catch (e: DeviceUnlockError.UserCancelled) {
                return // silent: no write, no error; the edit form stays open
            } catch (e: DeviceUnlockError) {
                _error.value = VaultBrowseError.ReauthFailed(e.toString())
                return
            }
            try {
                when (val m = mode) {
                    Mode.Add -> session.appendRecord(blockUuid, content)
                    is Mode.Edit -> session.editRecord(blockUuid, m.recordUuid, content)
                }
                _error.value = null
                _committed.value = true
            } catch (e: VaultBrowseError) {
                _error.value = e
            } catch (e: CancellationException) {
                throw e // never swallow coroutine cancellation (commit is suspend)
            } catch (e: Exception) {
                _error.value = VaultBrowseError.Failed(e.toString())
            }
        } finally {
            _inFlight.value = false
        }
```

- [ ] **Step 3b: Thread the gate from `VaultBrowseModel` into the edit model**

In `android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseModel.kt`, update `startAdd` (line 148) and `startEdit` (line 155) to pass `gate`:

```kotlin
    fun startAdd() {
        val block = _selectedBlock.value ?: return
        _editing.value = RecordEditModel(session, block.uuid, RecordEditModel.Mode.Add, gate)
    }
```

```kotlin
    fun startEdit(record: RecordSummaryView) {
        val block = _selectedBlock.value ?: return
        val model = RecordEditModel(session, block.uuid, RecordEditModel.Mode.Edit(hexToBytes(record.uuidHex)), gate)
        model.load(record)
        _editing.value = model
    }
```

- [ ] **Step 4: Run the test, verify it passes (and existing edit tests still pass)**

Run: `./gradlew :vault-access:test --tests "org.secretary.browse.RecordEditModelReauthTest" --tests "org.secretary.browse.RecordEditModelTest"`
Expected: PASS — new reauth tests green; existing `RecordEditModelTest` still green (defaulted `NoopReauthGate`).

- [ ] **Step 5: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/browse/RecordEditModel.kt \
        android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseModel.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/RecordEditModelReauthTest.kt
git commit -m "feat(android): gate RecordEditModel.commit behind WriteReauthGate"
```

---

### Task 6: Wire the real gate into `:app` + verify the whole Android build

**Files:**
- Modify: `android/app/src/main/kotlin/org/secretary/app/BrowseSession.kt` (`openBrowseWithSync` accepts + injects + seeds the gate)
- Modify: `android/app/src/main/kotlin/org/secretary/app/AppRoot.kt` (build a `GraceWindowReauthGate` per unlock, pass it down)
- Create test: `android/app/src/androidTest/kotlin/org/secretary/app/WriteReauthInstrumentedTest.kt`

**Interfaces:**
- Consumes: `GraceWindowReauthGate` + `CoordinatorBiometricAuthorizer` (Tasks 2 & 3), the existing `DeviceUnlockCoordinator` built in `AppRoot` (line 66), `openBrowseWithSync` (existing).
- Produces: `openBrowseWithSync(..., gate: WriteReauthGate = NoopReauthGate)` — a new trailing defaulted param; the production call passes a freshly-built `GraceWindowReauthGate`.

**Why a per-unlock gate instance:** `AppRoot.unlockAndOpen` runs once per unlock and builds the `BrowseSession`. Constructing the gate there (over the already-present `coordinator` + `vaultId`) gives one gate instance per session, holding `lastAuthAtMs` for that session's lifetime; lock tears down the session and the next unlock builds a fresh gate.

- [ ] **Step 1: Modify `openBrowseWithSync` to accept, inject, and seed the gate**

In `android/app/src/main/kotlin/org/secretary/app/BrowseSession.kt`:

Add imports:

```kotlin
import org.secretary.browse.NoopReauthGate
import org.secretary.browse.WriteReauthGate
```

Change the signature (line 39) and body (lines 46–48) to thread + seed the gate:

```kotlin
suspend fun openBrowseWithSync(
    openPort: VaultOpenPort,
    folder: File,
    stateDir: File,
    vaultUuid: ByteArray,
    credential: UnlockCredential,
    gate: WriteReauthGate = NoopReauthGate,
): BrowseSession {
    val session = openWithCredential(openPort, folder.path, credential)
    val browseModel = VaultBrowseModel(session, gate)
    gate.seed(System.currentTimeMillis()) // just unlocked → open the grace window
    browseModel.loadBlocks()
    val (syncModel, monitor) = makeVaultSync(folder, stateDir, vaultUuid)
    return BrowseSession(
        browse = VaultBrowseViewModel(browseModel),
        sync = VaultSyncViewModel(syncModel),
        monitor = monitor,
    )
}
```

- [ ] **Step 2: Build the real gate in `AppRoot.unlockAndOpen` and pass it down**

In `android/app/src/main/kotlin/org/secretary/app/AppRoot.kt`:

Add imports:

```kotlin
import org.secretary.browse.CoordinatorBiometricAuthorizer
import org.secretary.browse.GraceWindowReauthGate
```

In `unlockAndOpen` (the `openBrowseWithSync(...)` call at lines 205–206), build and pass the gate:

```kotlin
        val writeReauthGate = GraceWindowReauthGate(
            authorizer = CoordinatorBiometricAuthorizer(coordinator, vaultId),
            clock = { System.currentTimeMillis() },
        )
        val session = openBrowseWithSync(
            uniffiVaultOpenPort(deviceUuids), folder, stateDir, uuid, credential, writeReauthGate)
```

(The `coordinator` and `vaultId` are already parameters of `unlockAndOpen`.)

- [ ] **Step 3: Verify the ENTIRE Android project compiles + all host tests pass**

This is the cross-module checkpoint for the new `VaultBrowseError.ReauthFailed` arm. Run (from `android/`):

```bash
./gradlew :vault-access:test :browse-ui:test :app:compileDebugKotlin :kit:compileDebugKotlin :sync-ui:compileDebugKotlin
```

Expected: BUILD SUCCESSFUL. If any module has an exhaustive `when (e: VaultBrowseError)` without an `else` (the audit during planning found none in production code), the compiler flags it here — add a `ReauthFailed` branch (UI: render like any other error, e.g. `error::class.simpleName`) and re-run.

- [ ] **Step 4: Add the instrumented presence-proof test**

Create `android/app/src/androidTest/kotlin/org/secretary/app/WriteReauthInstrumentedTest.kt`. This proves the real `CoordinatorBiometricAuthorizer` over the real `KeystoreDeviceSecretEnclave` with an auto-approving biometric gate (no on-device biometric in CI), mirroring the iOS host-tested-authorizer pattern:

```kotlin
package org.secretary.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.secretary.browse.CoordinatorBiometricAuthorizer
import org.secretary.browse.DeviceEnrollment
import org.secretary.browse.DeviceUnlockCoordinator
import org.secretary.browse.FileDeviceEnrollmentMetadataStore
import org.secretary.browse.GraceWindowReauthGate
import org.secretary.browse.KeystoreDeviceSecretEnclave
import org.secretary.browse.UniffiVaultDeviceSlotPort
import java.io.File

@RunWith(AndroidJUnit4::class)
class WriteReauthInstrumentedTest {
    @Test
    fun graceWindowGate_isEnrolledFalse_isNoOp_whenNotEnrolled() = runBlocking {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        val dir = File(ctx.noBackupFilesDir, "writereauth-test").apply { mkdirs() }
        // Auto-approving gate (no biometric prompt in CI): the cipher passes through unchanged.
        val enclave = KeystoreDeviceSecretEnclave(dir = dir, gate = { cipher, _ -> cipher })
        val metadata = FileDeviceEnrollmentMetadataStore(dir)
        val coordinator = DeviceUnlockCoordinator(UniffiVaultDeviceSlotPort(), enclave, metadata)
        val authorizer = CoordinatorBiometricAuthorizer(coordinator, vaultId = "deadbeef")
        val gate = GraceWindowReauthGate(authorizer, clock = { System.currentTimeMillis() })

        // Not enrolled → the gate authorizes silently (no exception, no prompt).
        gate.authorizeWrite("smoke")
        assertTrue("not-enrolled gate must be a no-op", !authorizer.isEnrolled)

        enclave.clear(); metadata.clear()
    }
}
```

Note: confirm the `KeystoreDeviceSecretEnclave` constructor's gate-seam parameter name/type by checking `android/kit/src/main/kotlin/org/secretary/browse/KeystoreDeviceSecretEnclave.kt` and the existing `app/src/main/kotlin/org/secretary/app/BiometricPromptGate.kt` (`biometricPromptGate(...)`); adjust the `gate = { cipher, _ -> cipher }` literal to match the `BiometricGate` typealias if needed.

- [ ] **Step 5: Run the instrumented test (emulator/device) — optional in CI, required for on-device sign-off**

Run (from `android/`, with an emulator/device attached; adb on absolute path per project memory):

```bash
./gradlew :app:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.app.WriteReauthInstrumentedTest
```

Expected: PASS. If no device is attached, skip and record it in the handoff (host tests are the primary gate; the real-biometric prompt is the manual checklist below).

- [ ] **Step 6: Commit**

```bash
git add android/app/src/main/kotlin/org/secretary/app/BrowseSession.kt \
        android/app/src/main/kotlin/org/secretary/app/AppRoot.kt \
        android/app/src/androidTest/kotlin/org/secretary/app/WriteReauthInstrumentedTest.kt
git commit -m "feat(android): wire GraceWindowReauthGate into the app unlock/open path"
```

---

### Task 7: Docs, guardrails, full sweep

**Files:**
- Modify: `README.md` (write-reauth status: now iOS + desktop + Android)
- Modify: `ROADMAP.md` (Android write-reauth done; OS-biometric-without-enrollment + configurable settings still pending)

- [ ] **Step 1: Update README + ROADMAP**

In `README.md`, find the write-reauth / per-platform status note (the same note desktop #278 updated) and add Android to the platforms that have write re-auth. Keep it brief (dot points), per the project's README style.

In `ROADMAP.md`, mark Android write re-auth as shipped; note the deferred follow-ups (configurable/persisted grace-window settings; a presence proof for password-only/no-enrollment sessions).

- [ ] **Step 2: Run the full host-test sweep + lint**

Run (from `android/`):

```bash
./gradlew :vault-access:test :browse-ui:test :sync-ui:test
./gradlew :app:compileDebugKotlin :kit:compileDebugKotlin
```

Expected: BUILD SUCCESSFUL, all host tests green.

- [ ] **Step 3: Verify the guardrails (Android-only, no spec/FFI/core/ios/desktop drift)**

Run (from the worktree root):

```bash
git diff main...HEAD --name-only | grep -E 'core/|crypto-design|vault-format|\.udl|secretary-ffi-py|^ios/|^desktop/'   # MUST be empty
git diff main...HEAD --name-only | grep -E '^android/'                                                                  # non-empty (expected)
```

Expected: the first command prints nothing; the second lists the android changes.

- [ ] **Step 4: Commit**

```bash
git add README.md ROADMAP.md
git commit -m "docs: write re-auth now covers Android (iOS + desktop + Android)"
```

---

## Manual on-device checklist (handoff — not CI-automatable)

With a fingerprint/face enrolled on the device AND a device secret enrolled in the app ("remember this device" at unlock):

1. Unlock, then immediately edit a record and save → **no prompt** (within the 30 s seeded grace window).
2. Wait > 30 s, then save an edit → **biometric prompt appears**; on success the write commits.
3. Trigger a write, then **cancel** the prompt → the record/block/edit dialog **stays open**, nothing is written, no error banner.
4. Trigger a write and **fail** biometry (wrong finger until lockout) → write refused, a `ReauthFailed` error is surfaced, dialog stays open.
5. With **no device secret enrolled** (password-only unlock, "remember this device" unchecked) → writes proceed with **no prompt** (no regression).
6. Background the app (locks) and re-unlock → the first post-unlock write is silent (re-seeded), confirming the per-session gate reset.

---

## Self-Review

**1. Spec coverage** (against `docs/superpowers/specs/2026-06-21-android-write-reauth-design.md`):
- §3.1 pure policy (`needsReauth` + `ReauthWindow`) → Task 1. ✓
- §3.2 gate interfaces + `GraceWindowReauthGate` + `NoopReauthGate` → Task 2. ✓
- §3.3 real authorizer (`CoordinatorBiometricAuthorizer`, release-as-proof, zeroized) → Task 3. ✓
- §4 injection chokepoints (`guardedWrite` reason param + `RecordEditModel.commit`) + reason strings (§4.1) → Tasks 4 & 5. ✓
- §4.2 construction & lifetime (per-session gate, threaded into edit model, seeded at open) → Tasks 5 & 6. ✓
- §5 error handling (cancel silent / other → `ReauthFailed` / not-enrolled no-op) → Tasks 4 & 5; §5.1 cross-module build → Task 6 Step 3; §5.2 seed/reset → Tasks 2/4/6. ✓
- §6 testing (pure / gate / VM / instrumented / manual) → Tasks 1–6 + manual checklist. ✓
- §7 scope boundary + §8 acceptance → Task 7 guardrails. ✓

**2. Placeholder scan:** No "TBD"/"handle edge cases"/"similar to Task N"; every code step shows full code. The only soft spot is Task 6 Step 4's note to confirm the `KeystoreDeviceSecretEnclave` gate-seam param shape — this is a verification instruction with the exact files to check, not a placeholder.

**3. Type consistency:** `WriteReauthGate.authorizeWrite(reason: String)` / `seed(nowMs: Long)` / `reset()`, `BiometricAuthorizer.isEnrolled` + `authorize(reason)`, `GraceWindowReauthGate(authorizer, clock, windowMs)`, `NoopReauthGate`, `CoordinatorBiometricAuthorizer(coordinator, vaultId)`, `VaultBrowseError.ReauthFailed(detail)`, `VaultBrowseModel(session, gate)`, `RecordEditModel(session, blockUuid, mode, gate)`, `guardedWrite(reason, reload, op)`, `commitThenReload(reason, op)` — names/signatures are consistent across all tasks and match the real call sites read during planning (`VaultBrowseModel.kt`, `RecordEditModel.kt`, `BrowseSession.kt`, `AppRoot.kt`, `DeviceUnlockCoordinator.kt`).
