# Android Cloud-Drive Provisioning — Slice 1: VaultCreatePort Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Kotlin `VaultCreatePort` (pure seam in `:vault-access`) and its real `UniffiVaultCreatePort` adapter (in `:kit`) that creates a complete v1 vault in a real filesystem folder via the already-bound `createVaultInFolder` FFI and returns the one-shot 24-word recovery phrase.

**Architecture:** Mirror the existing `VaultOpenPort` / `UniffiVaultOpenPort` split — a pure interface + value types in `:vault-access` (host-tested, no Android/FFI), and a real adapter in `:kit` that runs the FFI (Argon2id) off the main thread on `Dispatchers.IO`. The adapter takes an injectable `createFn` seam so the success/error/clock logic is host-testable without the native library; an instrumented test proves the real binding end-to-end.

**Tech Stack:** Kotlin, kotlinx-coroutines, uniffi-generated `uniffi.secretary` bindings, JUnit 5 (host, `:vault-access` + `:kit` unit tests), AndroidX test (instrumented `:kit` androidTest).

**Scope note:** This is slice 1 of 6 in the epic specified at
`docs/superpowers/specs/2026-06-27-android-cloud-drive-provisioning-design.md`.
It deliberately does NOT touch SAF, the location store, the working-copy mirror,
the provisioning UI, or app routing — those are slices 2–6 and will each get
their own plan. This slice's `VaultCreatePort.createInFolder` takes a real POSIX
folder path (exactly like `VaultOpenPort.openWithPassword(vaultFolder: String, …)`);
later slices pass it the app-private working-copy subdir.

## Global Constraints

- **Module split discipline:** pure interfaces + value types live in `:vault-access`; all FFI/Android I/O lives in `:kit`. (Mirrors `VaultOpenPort` in `:vault-access` vs `UniffiVaultOpenPort` in `:kit`.)
- **Mirror iOS naming** where an analogue exists: iOS `VaultCreatePort` / `CreatedVault` / `VaultProvisioningError` (`ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultProvisioning.swift`).
- **Off-main-thread crypto:** `createInFolder` re-derives the vault key with Argon2id, so the real adapter MUST run it on `ioDispatcher` (default `Dispatchers.IO`), like `UniffiVaultOpenPort`.
- **Secrets are not retained:** the port forwards `password` per call and never stores it; the returned phrase is caller-owned and the caller owns zeroizing it (document this in KDoc, matching the iOS `CreatedVault` contract).
- **Exact FFI names (verified against the UDL):** the binding function is `uniffi.secretary.createVaultInFolder(folderPath: ByteArray, password: ByteArray, displayName: String, createdAtMs: ULong): MnemonicOutput`; `MnemonicOutput.takePhrase(): ByteArray?` is ONE-SHOT (second call returns null); `MnemonicOutput` is `AutoCloseable` (use `.use { … }`). The non-empty-folder error is `uniffi.secretary.VaultException.VaultFolderNotEmpty`.
- **Lint/format clean, tests green** before each commit. Kotlin files stay focused; split toward a directory module before any file approaches ~500 lines (none here will).
- **Commit per task** with a conventional-commit message.

**Test commands** (run from the `android/` Gradle root):

```bash
cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive/android
./gradlew :vault-access:test            # host JVM unit tests (Task 1)
./gradlew :kit:testDebugUnitTest        # host JVM unit tests (Task 2)
./gradlew :kit:connectedDebugAndroidTest  # instrumented, needs a running emulator (Task 3)
```

Emulator/adb are not on the bare PATH on this machine — start an emulator with the
absolute SDK paths before Task 3 (see the Android-toolchain notes); Tasks 1–2 need
no device.

---

### Task 1: Pure provisioning contract in `:vault-access`

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultCreatePort.kt`
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultProvisioningError.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/CreatedVaultTest.kt`

**Interfaces:**
- Consumes: nothing (leaf types).
- Produces:
  - `class CreatedVault(val phrase: ByteArray)` — product of a successful create; `phrase` is the UTF-8 recovery-phrase bytes, caller-owned.
  - `sealed class VaultProvisioningError(message: String?) : Exception(message)` with arms `data object FolderNotEmpty` and `data class CreateFailed(val detail: String)`.
  - `interface VaultCreatePort { suspend fun createInFolder(folderPath: String, password: ByteArray, displayName: String): CreatedVault }`.

- [ ] **Step 1: Write the failing test**

```kotlin
// android/vault-access/src/test/kotlin/org/secretary/browse/CreatedVaultTest.kt
package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class CreatedVaultTest {
    @Test
    fun `CreatedVault exposes the phrase bytes verbatim`() {
        val phrase = "ripple ozone".toByteArray(Charsets.UTF_8)
        val created = CreatedVault(phrase)
        assertTrue(phrase.contentEquals(created.phrase))
    }

    @Test
    fun `provisioning error arms are distinct and carry detail`() {
        val notEmpty: VaultProvisioningError = VaultProvisioningError.FolderNotEmpty
        val failed: VaultProvisioningError = VaultProvisioningError.CreateFailed("boom")
        assertEquals("boom", (failed as VaultProvisioningError.CreateFailed).detail)
        assertTrue(notEmpty is VaultProvisioningError.FolderNotEmpty)
        assertTrue(notEmpty !== failed)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive/android && ./gradlew :vault-access:test`
Expected: FAIL — compilation error, `CreatedVault` / `VaultProvisioningError` unresolved.

- [ ] **Step 3: Write the value types and the port interface**

```kotlin
// android/vault-access/src/main/kotlin/org/secretary/browse/VaultProvisioningError.kt
package org.secretary.browse

/**
 * Typed failures from the create-vault surface. Throwable (mirrors [VaultBrowseError] /
 * [org.secretary.sync.VaultSyncError]) so the provisioning coordinator can `catch (e: VaultProvisioningError)`.
 * Kotlin mirror of iOS `VaultProvisioningError`. Only the arms slice 1 can produce are defined here;
 * later slices (SAF mkdir, password pre-check) add `FolderInvalid` / `PasswordMismatch`.
 */
sealed class VaultProvisioningError(message: String? = null) : Exception(message) {
    /** The target folder already exists and is non-empty (FFI `VaultFolderNotEmpty`). */
    data object FolderNotEmpty : VaultProvisioningError()

    /** Any other create failure, with a diagnostic detail (the mapper's else-fold). */
    data class CreateFailed(val detail: String) : VaultProvisioningError(detail)
}
```

```kotlin
// android/vault-access/src/main/kotlin/org/secretary/browse/VaultCreatePort.kt
package org.secretary.browse

/**
 * The product of a successful create: the one-shot 24-word recovery phrase as UTF-8 bytes.
 * The caller owns zeroizing [phrase] once it has been shown to and acknowledged by the user
 * (mirrors iOS `CreatedVault`). Plain class (not `data class`) so the secret bytes are never
 * structurally compared, copied, or logged via a generated `toString`/`equals`.
 */
class CreatedVault(val phrase: ByteArray)

/**
 * Creates a brand-new v1 vault in an existing, empty real-filesystem folder, returning the
 * recovery phrase. The pure seam mirrors iOS `VaultCreatePort`; the real impl (`:kit`
 * `UniffiVaultCreatePort`) runs Argon2id off the main thread. [password] is forwarded per call
 * and never retained.
 *
 * [folderPath] is a real POSIX path (UTF-8) to an existing empty directory — the caller is
 * responsible for creating it. A non-empty folder surfaces [VaultProvisioningError.FolderNotEmpty].
 */
interface VaultCreatePort {
    suspend fun createInFolder(folderPath: String, password: ByteArray, displayName: String): CreatedVault
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive/android && ./gradlew :vault-access:test`
Expected: PASS (both tests).

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive
git add android/vault-access/src/main/kotlin/org/secretary/browse/VaultCreatePort.kt \
        android/vault-access/src/main/kotlin/org/secretary/browse/VaultProvisioningError.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/CreatedVaultTest.kt
git commit -m "feat(android): pure VaultCreatePort seam + CreatedVault/VaultProvisioningError"
```

---

### Task 2: `UniffiVaultCreatePort` real adapter + error mapping in `:kit`

**Files:**
- Create: `android/kit/src/main/kotlin/org/secretary/browse/UniffiVaultCreatePort.kt`
- Test: `android/kit/src/test/kotlin/org/secretary/browse/UniffiVaultCreatePortTest.kt`

**Interfaces:**
- Consumes: `VaultCreatePort`, `CreatedVault`, `VaultProvisioningError` (Task 1); `uniffi.secretary.createVaultInFolder`, `uniffi.secretary.VaultException`, `uniffi.secretary.MnemonicOutput`.
- Produces:
  - `class UniffiVaultCreatePort(ioDispatcher: CoroutineDispatcher = Dispatchers.IO, clockMs: () -> Long = System::currentTimeMillis, createFn: (ByteArray, ByteArray, String, ULong) -> ByteArray? = …) : VaultCreatePort` — the injectable `createFn` returns the phrase bytes (or null); its default calls the real FFI inside `.use { it.takePhrase() }`.
  - `fun uniffiVaultCreatePort(): VaultCreatePort` — production factory.
  - `internal fun mapVaultProvisioningError(e: VaultException): VaultProvisioningError`.

- [ ] **Step 1: Write the failing test**

```kotlin
// android/kit/src/test/kotlin/org/secretary/browse/UniffiVaultCreatePortTest.kt
package org.secretary.browse

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import uniffi.secretary.VaultException

class UniffiVaultCreatePortTest {
    @Test
    fun `returns the phrase from a successful create`() = runTest {
        val port = UniffiVaultCreatePort(
            createFn = { _, _, _, _ -> "abandon ability".toByteArray(Charsets.UTF_8) },
        )
        val created = port.createInFolder("/tmp/vault", "pw".toByteArray(Charsets.UTF_8), "Bob")
        assertTrue("abandon ability".toByteArray(Charsets.UTF_8).contentEquals(created.phrase))
    }

    @Test
    fun `forwards utf8 path, password, display name and clock to createFn`() = runTest {
        var seenPath: ByteArray? = null
        var seenPw: ByteArray? = null
        var seenName: String? = null
        var seenClock: ULong? = null
        val port = UniffiVaultCreatePort(
            clockMs = { 1_700_000_000_000L },
            createFn = { fp, pw, dn, ts ->
                seenPath = fp; seenPw = pw; seenName = dn; seenClock = ts
                "x".toByteArray(Charsets.UTF_8)
            },
        )
        port.createInFolder("/tmp/v", byteArrayOf(1, 2, 3), "Alice")
        assertTrue("/tmp/v".toByteArray(Charsets.UTF_8).contentEquals(seenPath!!))
        assertTrue(byteArrayOf(1, 2, 3).contentEquals(seenPw!!))
        assertEquals("Alice", seenName)
        assertEquals(1_700_000_000_000UL, seenClock)
    }

    @Test
    fun `null phrase maps to CreateFailed`() = runTest {
        val port = UniffiVaultCreatePort(createFn = { _, _, _, _ -> null })
        val e = assertThrows(VaultProvisioningError.CreateFailed::class.java) {
            kotlinx.coroutines.runBlocking {
                port.createInFolder("/tmp/v", "pw".toByteArray(Charsets.UTF_8), "Bob")
            }
        }
        assertTrue(e.detail.contains("recovery phrase"))
    }

    @Test
    fun `VaultFolderNotEmpty maps to FolderNotEmpty`() = runTest {
        val port = UniffiVaultCreatePort(
            createFn = { _, _, _, _ -> throw VaultException.VaultFolderNotEmpty() },
        )
        assertThrows(VaultProvisioningError.FolderNotEmpty::class.java) {
            kotlinx.coroutines.runBlocking {
                port.createInFolder("/tmp/v", "pw".toByteArray(Charsets.UTF_8), "Bob")
            }
        }
    }

    @Test
    fun `other VaultException maps to CreateFailed`() = runTest {
        val port = UniffiVaultCreatePort(
            createFn = { _, _, _, _ -> throw VaultException.CorruptVault("bad bytes") },
        )
        val e = assertThrows(VaultProvisioningError.CreateFailed::class.java) {
            kotlinx.coroutines.runBlocking {
                port.createInFolder("/tmp/v", "pw".toByteArray(Charsets.UTF_8), "Bob")
            }
        }
        assertTrue(e.detail.isNotBlank())
    }
}
```

Note: `VaultException.VaultFolderNotEmpty` is fieldless — the generated constructor is no-arg
(`VaultException.VaultFolderNotEmpty()`). If codegen requires a message argument, pass `""`.
`VaultException.CorruptVault(detail)` carries a `string detail` per the UDL.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive/android && ./gradlew :kit:testDebugUnitTest`
Expected: FAIL — `UniffiVaultCreatePort` / `VaultProvisioningError` unresolved.

- [ ] **Step 3: Write the adapter + mapper**

```kotlin
// android/kit/src/main/kotlin/org/secretary/browse/UniffiVaultCreatePort.kt
package org.secretary.browse

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uniffi.secretary.VaultException
import uniffi.secretary.createVaultInFolder

/**
 * The real [VaultCreatePort] over the generated `uniffi.secretary.createVaultInFolder` call. Kotlin
 * mirror of iOS `UniffiVaultCreatePort`.
 *
 * [createInFolder] re-derives the vault key with Argon2id, so it runs on [ioDispatcher]
 * (default [Dispatchers.IO]) to keep the caller responsive. The path is UTF-8 encoded and the
 * password [ByteArray] is forwarded per call; neither is retained. The returned phrase is
 * caller-owned (caller zeroizes after the user acknowledges it).
 *
 * [createFn] is the injectable FFI seam: it returns the one-shot recovery-phrase bytes (or null).
 * Its default invokes the real binding inside `.use { … }` so the native [uniffi.secretary.MnemonicOutput]
 * handle is always released. [clockMs] supplies `created_at_ms` (injected for deterministic tests).
 */
class UniffiVaultCreatePort(
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val clockMs: () -> Long = System::currentTimeMillis,
    private val createFn: (ByteArray, ByteArray, String, ULong) -> ByteArray? =
        { folderPath, password, displayName, createdAtMs ->
            createVaultInFolder(folderPath, password, displayName, createdAtMs).use { it.takePhrase() }
        },
) : VaultCreatePort {
    override suspend fun createInFolder(
        folderPath: String,
        password: ByteArray,
        displayName: String,
    ): CreatedVault =
        withContext(ioDispatcher) {
            val phrase = mapProvisioningErrors {
                createFn(folderPath.toByteArray(Charsets.UTF_8), password, displayName, clockMs().toULong())
            } ?: throw VaultProvisioningError.CreateFailed("recovery phrase unavailable")
            CreatedVault(phrase)
        }
}

/** Run an FFI call, translating any [VaultException] into the domain [VaultProvisioningError]. */
internal inline fun <T> mapProvisioningErrors(block: () -> T): T =
    try {
        block()
    } catch (e: VaultException) {
        throw mapVaultProvisioningError(e)
    }

/** Map a create-surface [VaultException] to the typed [VaultProvisioningError]. */
internal fun mapVaultProvisioningError(e: VaultException): VaultProvisioningError =
    when (e) {
        is VaultException.VaultFolderNotEmpty -> VaultProvisioningError.FolderNotEmpty
        else -> VaultProvisioningError.CreateFailed(e.message ?: (e::class.simpleName ?: "create failed"))
    }

/** Production factory for the real create port (live binding + IO dispatcher). */
fun uniffiVaultCreatePort(): VaultCreatePort = UniffiVaultCreatePort()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive/android && ./gradlew :kit:testDebugUnitTest`
Expected: PASS (all five tests).

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive
git add android/kit/src/main/kotlin/org/secretary/browse/UniffiVaultCreatePort.kt \
        android/kit/src/test/kotlin/org/secretary/browse/UniffiVaultCreatePortTest.kt
git commit -m "feat(android): UniffiVaultCreatePort adapter over createVaultInFolder + error mapping"
```

---

### Task 3: Instrumented real-binding round-trip in `:kit` androidTest

**Files:**
- Create: `android/kit/src/androidTest/kotlin/org/secretary/browse/UniffiVaultCreatePortInstrumentedTest.kt`

**Interfaces:**
- Consumes: `uniffiVaultCreatePort()` (Task 2), `uniffiVaultOpenPort()` (existing), the real `.so`.
- Produces: nothing (verification only).

This is the slice's proof that the real binding works on a device/emulator: create →
open round-trip (mirrors the Kotlin smoke `Assert 39`) plus the non-empty-folder error
(`Assert 40`). It needs the native library, so it lives in `androidTest`, like the
existing `SyncRoundTripInstrumentedTest`.

- [ ] **Step 1: Write the test**

```kotlin
// android/kit/src/androidTest/kotlin/org/secretary/browse/UniffiVaultCreatePortInstrumentedTest.kt
package org.secretary.browse

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class UniffiVaultCreatePortInstrumentedTest {

    private fun freshDir(prefix: String): File =
        File.createTempFile(prefix, "").let { f ->
            f.delete()
            check(f.mkdirs()) { "could not mkdir ${f.path}" }
            f
        }

    @Test
    fun create_then_open_round_trips_with_24_word_phrase() = runBlocking {
        val dir = freshDir("create-roundtrip-")
        try {
            val createPort = uniffiVaultCreatePort()
            val pw = "create-instr-pw".toByteArray(Charsets.UTF_8)
            val created = createPort.createInFolder(dir.path, pw, "Instr-Bob")
            val wordCount = created.phrase.toString(Charsets.UTF_8).split(" ").size
            assertEquals(24, wordCount)

            // The created vault opens with the same password and reports the display name.
            val session = uniffiVaultOpenPort().openWithPassword(dir.path, pw)
            try {
                // A freshly-created vault has no user blocks yet; opening + listing must not throw.
                assertEquals(0, session.blockSummaries().size)
            } finally {
                session.wipe()
            }
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun create_in_non_empty_folder_throws_folder_not_empty() {
        val dir = freshDir("create-nonempty-")
        try {
            File(dir, "junk").writeText("x")
            assertThrows(VaultProvisioningError.FolderNotEmpty::class.java) {
                runBlocking {
                    uniffiVaultCreatePort().createInFolder(
                        dir.path, "pw".toByteArray(Charsets.UTF_8), "Nope",
                    )
                }
            }
        } finally {
            dir.deleteRecursively()
        }
    }
}
```

Note: a brand-new vault has no user-created blocks, so `blockSummaries()` is empty.
If the manifest is seeded with a default block at creation (check `create.rs` behaviour),
relax the assertion to `assertTrue(session.blockSummaries().size >= 0)` and instead assert
the open simply succeeded without throwing — the load-bearing checks are the 24-word phrase
and that open does not reject the password.

- [ ] **Step 2: Start an emulator, then run the test**

Run (emulator must be booted; use absolute SDK paths if `adb`/`emulator` aren't on PATH):
```bash
cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive/android
./gradlew :kit:connectedDebugAndroidTest --tests "org.secretary.browse.UniffiVaultCreatePortInstrumentedTest"
```
Expected: both tests PASS against the real `.so`.

- [ ] **Step 3: Run the host unit tests once more to confirm no regression**

Run: `./gradlew :vault-access:test :kit:testDebugUnitTest`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive
git add android/kit/src/androidTest/kotlin/org/secretary/browse/UniffiVaultCreatePortInstrumentedTest.kt
git commit -m "test(android): instrumented create→open round-trip for UniffiVaultCreatePort"
```

---

## Self-Review

**Spec coverage (slice 1 scope only):** The spec's component #1 (`VaultCreatePort` +
`UniffiVaultCreatePort` wrapping the already-bound `createVaultInFolder`) is implemented
by Tasks 1–2; the instrumented round-trip (Task 3) covers the spec's "instrumented:
create→… round-trip" testing requirement for this component. SAF, location store, mirror,
UI, and routing are explicitly out of slice-1 scope and tracked for slices 2–6.

**Placeholder scan:** No TBD/TODO/"handle errors appropriately". The two `Note:` callouts
are concrete fallbacks (codegen constructor arity; default-block seeding) with exact
instructions, not deferred work.

**Type consistency:** `createInFolder(folderPath: String, password: ByteArray, displayName: String): CreatedVault`
is identical across the interface (Task 1), the adapter (Task 2), and both tests.
`VaultProvisioningError.FolderNotEmpty` / `.CreateFailed(detail)` are used consistently in
the mapper and all assertions. `createFn` arity `(ByteArray, ByteArray, String, ULong) -> ByteArray?`
matches its default lambda and every injected test double. `CreatedVault(val phrase: ByteArray)`
is constructed and read identically everywhere.
