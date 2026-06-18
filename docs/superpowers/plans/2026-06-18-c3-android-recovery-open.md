# C.3 Android — recovery-phrase open path: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a second unlock credential on Android — the 24-word BIP-39 recovery phrase — alongside the existing password open, both reaching the unified `BrowseWithSyncScreen`.

**Architecture:** A sealed `UnlockCredential` (`Password` | `Recovery`) threads *which secret* through a pure `openWithCredential` dispatch over `VaultOpenPort`. The `:kit` adapter wraps the already-generated `openVaultWithRecovery` binding. Because Android sync is password-keyed, a recovery-opened session reaches the same browse+sync screen but shows a status-only badge (no auto-sync); the post-open action is chosen by a pure `dispatchPostOpenSync` helper. Mirrors iOS's `UnlockViewModel.Mode` + optional-password `onUnlocked`.

**Tech Stack:** Kotlin, Jetbrains Compose, Gradle multi-module (`:vault-access` pure / `:kit` FFI adapter / `:app`), uniffi 0.31 generated bindings, JUnit5 (host) + AndroidJUnit4 (instrumented).

## Global Constraints

- **Android-only.** No `core/` / `ffi/` / `ios/` / `crypto-design` / `vault-format` / UDL edits. `open_vault_with_recovery` is already in the Rust UDL and is generated into the Kotlin bindings at build time (`android/kit` regenerates from the live cdylib — never committed).
- **Anti-oracle (§13):** `WrongRecoveryOrCorrupt` stays conflated (wrong phrase vs corruption). Do NOT split it. `InvalidRecoveryPhrase(detail)` is a separate *format* error only.
- **Secret hygiene:** the credential payload `ByteArray` is zeroized on every exit of `unlockAndOpen` (`finally`). No phrase retained for sync.
- **TDD:** test-first every task. **No magic numbers.** **Pure free functions in reusable modules** where logic is non-trivial. Files stay under 500 lines.
- **Verify variant names at first build:** the generated Kotlin `VaultException.WrongMnemonicOrCorrupt` / `VaultException.InvalidMnemonic` (with `.detail`) are confirmed against the Rust UDL but re-verify on first `:kit:test` (uniffi codegen has renamed things before — see the uniffi-codegen-rename memo).
- **Host test commands** run from `android/`. Connected tests need a running emulator and reject `--tests` (use `-Pandroid.testInstrumentationRunnerArguments.class=<FQN>`).

---

### Task 1: Pure `RecoveryPhrase.normalize` (`:vault-access`)

Mirror of iOS `RecoveryPhrase.normalize`: lowercase, split on any whitespace run, drop empties, rejoin single-spaced. Pure free function in a reusable module.

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/RecoveryPhrase.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/RecoveryPhraseTest.kt`

**Interfaces:**
- Produces: `object RecoveryPhrase { fun normalize(raw: String): String }`

- [ ] **Step 1: Write the failing test**

```kotlin
package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class RecoveryPhraseTest {
    @Test
    fun `collapses internal whitespace runs to single spaces`() {
        assertEquals("alpha bravo charlie", RecoveryPhrase.normalize("alpha   bravo\tcharlie"))
    }

    @Test
    fun `trims leading and trailing whitespace`() {
        assertEquals("alpha bravo", RecoveryPhrase.normalize("  alpha bravo  "))
    }

    @Test
    fun `lowercases mixed-case input`() {
        assertEquals("alpha bravo", RecoveryPhrase.normalize("Alpha BRAVO"))
    }

    @Test
    fun `collapses newlines and tabs as whitespace`() {
        assertEquals("one two three", RecoveryPhrase.normalize("one\ntwo\t\nthree"))
    }

    @Test
    fun `leaves an already-clean phrase unchanged`() {
        val clean = "wall annual clay zebra"
        assertEquals(clean, RecoveryPhrase.normalize(clean))
    }

    @Test
    fun `an all-whitespace string normalizes to empty`() {
        assertEquals("", RecoveryPhrase.normalize("   \t\n "))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.RecoveryPhraseTest'`
Expected: FAIL — `RecoveryPhrase` unresolved reference.

- [ ] **Step 3: Write minimal implementation**

```kotlin
package org.secretary.browse

/**
 * Normalizes a user-typed BIP-39 recovery phrase before it is handed to the FFI: lowercases,
 * splits on any whitespace run, drops empty tokens, and rejoins single-spaced. The canonical
 * BIP-39 word list is all-lowercase and single-space-joined, so this removes the most common
 * copy/paste and keyboard auto-capitalization noise without altering the words themselves.
 * Pure — no side effects. Mirror of iOS `RecoveryPhrase.normalize`.
 */
object RecoveryPhrase {
    fun normalize(raw: String): String =
        raw.lowercase()
            .split(Regex("\\s+"))
            .filter { it.isNotEmpty() }
            .joinToString(" ")
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.RecoveryPhraseTest'`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/browse/RecoveryPhrase.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/RecoveryPhraseTest.kt
git commit -m "feat(android): pure RecoveryPhrase.normalize for the recovery open path"
```

---

### Task 2: `VaultOpenPort.openWithRecovery` + `UnlockCredential` + pure `openWithCredential` dispatch (`:vault-access`)

Add the recovery method to the port seam, extend the fake to record it, introduce the sealed credential type, and the pure open-dispatch that the `:app` layer (and host tests) drive. `openBrowseWithSync` cannot be host-tested (it calls Looper-gated `makeVaultSync`), so this pure dispatch is the host-testable seam proving "recovery routes to `openWithRecovery`".

**Files:**
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultOpenPort.kt` (add method)
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/UnlockCredential.kt`
- Modify: `android/vault-access/src/test/kotlin/org/secretary/browse/FakeVaultBrowse.kt` (extend `FakeVaultOpenPort`)
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/UnlockCredentialTest.kt`

**Interfaces:**
- Consumes: `VaultOpenPort`, `VaultSession`, `FakeVaultOpenPort` (Task-existing).
- Produces:
  - `interface VaultOpenPort { ...; suspend fun openWithRecovery(vaultFolder: String, phrase: ByteArray): VaultSession }`
  - `sealed interface UnlockCredential { val secret: ByteArray; class Password(override val secret: ByteArray); class Recovery(override val secret: ByteArray) }`
  - `suspend fun openWithCredential(openPort: VaultOpenPort, vaultFolder: String, credential: UnlockCredential): VaultSession`
  - `FakeVaultOpenPort` now records `openedWithPassword: List<ByteArray>` and `openedWithRecovery: List<ByteArray>`, with a `recoveryError` seam.

- [ ] **Step 1: Add the port method (no standalone test — infra for the dispatch)**

In `VaultOpenPort.kt`, add to the `interface VaultOpenPort`:

```kotlin
interface VaultOpenPort {
    suspend fun openWithPassword(vaultFolder: String, password: ByteArray): VaultSession

    /**
     * Opens a vault folder with its 24-word BIP-39 recovery phrase. [phrase] is the UTF-8 bytes of
     * the (normalized) phrase, forwarded per call and never retained. The real impl runs Argon2id
     * off the main thread, like [openWithPassword]. Mirror of iOS `VaultOpenPort.openWithRecovery`.
     */
    suspend fun openWithRecovery(vaultFolder: String, phrase: ByteArray): VaultSession
}
```

- [ ] **Step 2: Extend `FakeVaultOpenPort` to implement + record the recovery open**

Replace the `FakeVaultOpenPort` class at the bottom of `FakeVaultBrowse.kt` with:

```kotlin
/**
 * Scriptable [VaultOpenPort]: returns [session] or throws the matching error; records every open by
 * credential kind so dispatch tests can assert which path fired with which bytes.
 */
class FakeVaultOpenPort(
    private val session: VaultSession = FakeVaultSession("00", emptyList()),
    private val openError: VaultBrowseError? = null,
    private val recoveryError: VaultBrowseError? = null,
) : VaultOpenPort {
    val openedFolders: MutableList<String> = mutableListOf()
    /** Copies of the password bytes seen by each openWithPassword call, in order. */
    val openedWithPassword: MutableList<ByteArray> = mutableListOf()
    /** Copies of the phrase bytes seen by each openWithRecovery call, in order. */
    val openedWithRecovery: MutableList<ByteArray> = mutableListOf()

    override suspend fun openWithPassword(vaultFolder: String, password: ByteArray): VaultSession {
        openedFolders += vaultFolder
        openedWithPassword += password.copyOf()
        openError?.let { throw it }
        return session
    }

    override suspend fun openWithRecovery(vaultFolder: String, phrase: ByteArray): VaultSession {
        openedFolders += vaultFolder
        openedWithRecovery += phrase.copyOf()
        recoveryError?.let { throw it }
        return session
    }
}
```

- [ ] **Step 3: Write the failing dispatch test**

Create `UnlockCredentialTest.kt`:

```kotlin
package org.secretary.browse

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class UnlockCredentialTest {
    @Test
    fun `a password credential opens via openWithPassword with the password bytes`() = runTest {
        val port = FakeVaultOpenPort()
        openWithCredential(port, "/vault", UnlockCredential.Password(byteArrayOf(1, 2, 3)))
        assertEquals(1, port.openedWithPassword.size)
        assertArrayEquals(byteArrayOf(1, 2, 3), port.openedWithPassword[0])
        assertTrue(port.openedWithRecovery.isEmpty(), "recovery path must not fire for a password credential")
    }

    @Test
    fun `a recovery credential opens via openWithRecovery with the phrase bytes`() = runTest {
        val port = FakeVaultOpenPort()
        openWithCredential(port, "/vault", UnlockCredential.Recovery(byteArrayOf(7, 7, 9)))
        assertEquals(1, port.openedWithRecovery.size)
        assertArrayEquals(byteArrayOf(7, 7, 9), port.openedWithRecovery[0])
        assertTrue(port.openedWithPassword.isEmpty(), "password path must not fire for a recovery credential")
    }

    @Test
    fun `secret exposes the underlying bytes for both arms`() {
        assertArrayEquals(byteArrayOf(4, 5), UnlockCredential.Password(byteArrayOf(4, 5)).secret)
        assertArrayEquals(byteArrayOf(6), UnlockCredential.Recovery(byteArrayOf(6)).secret)
    }
}
```

- [ ] **Step 4: Run test to verify it fails**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.UnlockCredentialTest'`
Expected: FAIL — `UnlockCredential` / `openWithCredential` unresolved.

- [ ] **Step 5: Write minimal implementation**

Create `UnlockCredential.kt`:

```kotlin
package org.secretary.browse

/**
 * Which secret the user supplied at the unlock screen. A single sealed type carries the credential
 * so the `when` over it is the one place that decides how to open (and, in `:app`, how to sync).
 * The exhaustive match makes the recovery branch impossible to forget. Mirror of iOS
 * `UnlockViewModel.Mode { password, recovery }`.
 *
 * [secret] is the credential bytes (password UTF-8, or normalized phrase UTF-8). The caller owns
 * zeroizing it after the open returns.
 */
sealed interface UnlockCredential {
    val secret: ByteArray

    class Password(override val secret: ByteArray) : UnlockCredential
    class Recovery(override val secret: ByteArray) : UnlockCredential
}

/**
 * Opens the vault with the supplied [credential]. Pure dispatch over [openPort] — no sync assembly,
 * no zeroize (the caller owns [credential]'s bytes). The host-testable seam for "which credential
 * routes to which open" ([openBrowseWithSync] itself is not host-testable: it calls Looper-gated
 * makeVaultSync).
 */
suspend fun openWithCredential(
    openPort: VaultOpenPort,
    vaultFolder: String,
    credential: UnlockCredential,
): VaultSession = when (credential) {
    is UnlockCredential.Password -> openPort.openWithPassword(vaultFolder, credential.secret)
    is UnlockCredential.Recovery -> openPort.openWithRecovery(vaultFolder, credential.secret)
}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.UnlockCredentialTest'`
Expected: PASS (3 tests).

- [ ] **Step 7: Run the whole module to confirm the fake change broke nothing**

Run: `cd android && ./gradlew :vault-access:test`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 8: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/browse/VaultOpenPort.kt \
        android/vault-access/src/main/kotlin/org/secretary/browse/UnlockCredential.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/FakeVaultBrowse.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/UnlockCredentialTest.kt
git commit -m "feat(android): UnlockCredential + openWithCredential dispatch; VaultOpenPort.openWithRecovery seam"
```

---

### Task 3: `:kit` adapter `openWithRecovery` + recovery error variants + mapping

Implement the real recovery open over the generated `openVaultWithRecovery`, add the two domain error variants, and map the two recovery `VaultException` arms.

**Files:**
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseError.kt` (add 2 variants)
- Modify: `android/kit/src/main/kotlin/org/secretary/browse/BrowseMapping.kt` (add 2 arms)
- Modify: `android/kit/src/main/kotlin/org/secretary/browse/UniffiVaultOpenPort.kt` (implement `openWithRecovery` + seam + factories)
- Test: `android/kit/src/test/kotlin/org/secretary/browse/BrowseMappingTest.kt` (add 2 assertions)

**Interfaces:**
- Consumes: `VaultException.WrongMnemonicOrCorrupt`, `VaultException.InvalidMnemonic` (`.detail`), `uniffi.secretary.openVaultWithRecovery` (generated).
- Produces:
  - `VaultBrowseError.WrongRecoveryOrCorrupt` (object), `VaultBrowseError.InvalidRecoveryPhrase(val detail: String)`
  - `UniffiVaultOpenPort.openWithRecovery` over `openVaultWithRecovery`, with an injectable `recoveryFn` seam.

- [ ] **Step 1: Add the two domain error variants**

In `VaultBrowseError.kt`, add inside the sealed class (after `WrongPasswordOrCorrupt`):

```kotlin
    /** Recovery open failed: wrong phrase OR corrupt vault. Conflated on purpose (§13). */
    data object WrongRecoveryOrCorrupt : VaultBrowseError()

    /** The recovery phrase was malformed (bad word / wrong length / invalid UTF-8) — a format
     *  error, distinct from the conflated [WrongRecoveryOrCorrupt]. Safe to surface to the user. */
    data class InvalidRecoveryPhrase(val detail: String) : VaultBrowseError(detail)
```

- [ ] **Step 2: Write the failing mapping test**

In `BrowseMappingTest.kt`, add a new test method:

```kotlin
    @Test
    fun `maps the recovery-relevant arms to their domain counterparts`() {
        assertEquals(
            VaultBrowseError.WrongRecoveryOrCorrupt,
            mapVaultBrowseError(VaultException.WrongMnemonicOrCorrupt()),
        )
        assertEquals(
            VaultBrowseError.InvalidRecoveryPhrase("bad word"),
            mapVaultBrowseError(VaultException.InvalidMnemonic("bad word")),
        )
    }
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd android && ./gradlew :kit:test --tests 'org.secretary.browse.BrowseMappingTest'`
Expected: FAIL — the mapper folds these arms into `Failed` (assertEquals mismatch). **If instead it fails to compile on `VaultException.WrongMnemonicOrCorrupt` / `.InvalidMnemonic`**, the generated binding renamed them — inspect `android/kit/build/generated/uniffi/uniffi/secretary/secretary.kt` for the real names and adjust (see the codegen-rename memo).

- [ ] **Step 4: Add the two mapping arms**

In `BrowseMapping.kt`, add **before** the `else ->` line in `mapVaultBrowseError`:

```kotlin
    is VaultException.WrongMnemonicOrCorrupt -> VaultBrowseError.WrongRecoveryOrCorrupt
    is VaultException.InvalidMnemonic -> VaultBrowseError.InvalidRecoveryPhrase(e.detail)
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd android && ./gradlew :kit:test --tests 'org.secretary.browse.BrowseMappingTest'`
Expected: PASS.

- [ ] **Step 6: Implement the adapter `openWithRecovery` + seam + factories**

In `UniffiVaultOpenPort.kt`:

Add the import near the other generated-binding imports:

```kotlin
import uniffi.secretary.openVaultWithRecovery
```

Replace the `UniffiVaultOpenPort` class declaration + body with (adds the `recoveryFn` seam and the method):

```kotlin
class UniffiVaultOpenPort(
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val deviceUuids: DeviceUuidProvider? = null,
    private val openFn: (ByteArray, ByteArray) -> OpenVaultOutput = ::openVaultWithPassword,
    private val recoveryFn: (ByteArray, ByteArray) -> OpenVaultOutput = ::openVaultWithRecovery,
) : VaultOpenPort {
    override suspend fun openWithPassword(vaultFolder: String, password: ByteArray): VaultSession =
        withContext(ioDispatcher) {
            val output = mapErrors { openFn(vaultFolder.toByteArray(Charsets.UTF_8), password) }
            UniffiVaultSession(output, ioDispatcher, deviceUuids)
        }

    override suspend fun openWithRecovery(vaultFolder: String, phrase: ByteArray): VaultSession =
        withContext(ioDispatcher) {
            val output = mapErrors { recoveryFn(vaultFolder.toByteArray(Charsets.UTF_8), phrase) }
            UniffiVaultSession(output, ioDispatcher, deviceUuids)
        }
}
```

(The two `uniffiVaultOpenPort(...)` factory functions at the bottom of the file need no change — they use named/default args.)

- [ ] **Step 7: Compile the module (the adapter has no new host unit test; it is exercised on-device in Task 7)**

Run: `cd android && ./gradlew :kit:compileDebugKotlin :kit:test`
Expected: BUILD SUCCESSFUL; `:kit:test` green (mapping test included).

- [ ] **Step 8: Confirm `:vault-access` still green after the error-type addition**

Run: `cd android && ./gradlew :vault-access:test`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 9: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseError.kt \
        android/kit/src/main/kotlin/org/secretary/browse/BrowseMapping.kt \
        android/kit/src/main/kotlin/org/secretary/browse/UniffiVaultOpenPort.kt \
        android/kit/src/test/kotlin/org/secretary/browse/BrowseMappingTest.kt
git commit -m "feat(android): :kit openWithRecovery over openVaultWithRecovery + recovery error mapping"
```

---

### Task 4: `:app` pure `dispatchPostOpenSync` helper

Choose the post-open sync action from the credential: password → background sync-at-unlock; recovery → status refresh only (no password to feed the password-keyed sync). Pure (takes two lambdas), host-tested without FFI.

**Files:**
- Create: `android/app/src/main/kotlin/org/secretary/app/PostOpenSync.kt`
- Test: `android/app/src/test/kotlin/org/secretary/app/PostOpenSyncTest.kt`

**Interfaces:**
- Consumes: `org.secretary.browse.UnlockCredential` (Task 2).
- Produces: `fun dispatchPostOpenSync(credential: UnlockCredential, onPassword: (ByteArray) -> Unit, onRecovery: () -> Unit)`

- [ ] **Step 1: Write the failing test**

```kotlin
package org.secretary.app

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.secretary.browse.UnlockCredential

class PostOpenSyncTest {
    @Test
    fun `a password credential fires onPassword with the secret and never onRecovery`() {
        var pwSeen: ByteArray? = null
        var recoveryFired = false
        dispatchPostOpenSync(
            UnlockCredential.Password(byteArrayOf(1, 2, 3)),
            onPassword = { pwSeen = it },
            onRecovery = { recoveryFired = true },
        )
        assertArrayEquals(byteArrayOf(1, 2, 3), pwSeen)
        assertFalse(recoveryFired, "recovery action must not fire for a password credential")
    }

    @Test
    fun `a recovery credential fires onRecovery only`() {
        var pwFired = false
        var recoveryFired = false
        dispatchPostOpenSync(
            UnlockCredential.Recovery(byteArrayOf(9)),
            onPassword = { pwFired = true },
            onRecovery = { recoveryFired = true },
        )
        assertTrue(recoveryFired)
        assertFalse(pwFired, "password action must not fire for a recovery credential")
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ./gradlew :app:testDebugUnitTest --tests 'org.secretary.app.PostOpenSyncTest'`
Expected: FAIL — `dispatchPostOpenSync` unresolved.

- [ ] **Step 3: Write minimal implementation**

```kotlin
package org.secretary.app

import org.secretary.browse.UnlockCredential

/**
 * Chooses the post-open sync action from the unlock credential. Android sync is password-keyed
 * (the SyncCoordinator re-opens the vault with the password per call), so a recovery-opened session
 * has no password to drive a sync pass: it refreshes status only. A password-opened session fires
 * the background sync-at-unlock. The exhaustive `when` makes the recovery case impossible to forget;
 * keeping it pure (lambdas, no FFI/VM) makes it host-testable. Mirrors iOS's optional-password
 * `onUnlocked` (`if let password { syncAtUnlock } else { refreshStatus }`).
 *
 * @param onPassword invoked with the password bytes (caller launches the background sync pass).
 * @param onRecovery invoked with no secret (caller refreshes the status badge).
 */
fun dispatchPostOpenSync(
    credential: UnlockCredential,
    onPassword: (ByteArray) -> Unit,
    onRecovery: () -> Unit,
) = when (credential) {
    is UnlockCredential.Password -> onPassword(credential.secret)
    is UnlockCredential.Recovery -> onRecovery()
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd android && ./gradlew :app:testDebugUnitTest --tests 'org.secretary.app.PostOpenSyncTest'`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add android/app/src/main/kotlin/org/secretary/app/PostOpenSync.kt \
        android/app/src/test/kotlin/org/secretary/app/PostOpenSyncTest.kt
git commit -m "feat(android): pure dispatchPostOpenSync — password syncs, recovery refreshes status"
```

---

### Task 5: `:app` `openBrowseWithSync(credential)` + `AppRoot` wiring

Switch `openBrowseWithSync` and `unlockAndOpen` from a raw `password` to an `UnlockCredential`, route the open through `openWithCredential`, and pick the post-open action via `dispatchPostOpenSync`. Update the existing instrumented smoke to pass a `Password` credential. No new host test (these depend on `makeVaultSync`/Context); covered by Task 4's dispatch test + Task 7's smokes + existing tests recompiling.

**Files:**
- Modify: `android/app/src/main/kotlin/org/secretary/app/BrowseSession.kt`
- Modify: `android/app/src/main/kotlin/org/secretary/app/AppRoot.kt`
- Modify: `android/app/src/androidTest/kotlin/org/secretary/app/OpenBrowseWithSyncSmokeTest.kt` (call-site update only)

**Interfaces:**
- Consumes: `openWithCredential`, `UnlockCredential` (Task 2); `dispatchPostOpenSync` (Task 4); `launchSyncAtUnlock` (existing); `VaultSyncViewModel.refreshStatus()` / `syncAtUnlock(...)` (existing).
- Produces: `suspend fun openBrowseWithSync(openPort, folder, stateDir, vaultUuid, credential: UnlockCredential): BrowseSession` (the `password: ByteArray` param is replaced by `credential`).

- [ ] **Step 1: Update `openBrowseWithSync` to take a credential**

In `BrowseSession.kt`, add the import and replace the function. Imports — add:

```kotlin
import org.secretary.browse.UnlockCredential
import org.secretary.browse.openWithCredential
```

Replace `openBrowseWithSync`:

```kotlin
/**
 * Opens the vault for browsing with the supplied [credential] and assembles the sync model+monitor
 * for the same folder.
 *
 * MUST be called on the main thread: [makeVaultSync] is Looper-gated. The open suspends and hops to
 * IO internally, returning to the caller's (main) dispatcher afterward, so [makeVaultSync] is still
 * on main.
 *
 * Does NOT zeroize the credential bytes and does NOT launch sync-at-unlock — the caller owns both
 * (see AppRoot: it zeroizes after handing a copy to launchSyncAtUnlock, and only for the password
 * credential; a recovery open has no password to sync with).
 *
 * @throws the typed open errors from [VaultOpenPort] (e.g. WrongPasswordOrCorrupt /
 *   WrongRecoveryOrCorrupt / InvalidRecoveryPhrase) — the caller catches and returns to Unlock.
 */
suspend fun openBrowseWithSync(
    openPort: VaultOpenPort,
    folder: File,
    stateDir: File,
    vaultUuid: ByteArray,
    credential: UnlockCredential,
): BrowseSession {
    val session = openWithCredential(openPort, folder.path, credential)
    val browseModel = VaultBrowseModel(session)
    browseModel.loadBlocks()
    val (syncModel, monitor) = makeVaultSync(folder, stateDir, vaultUuid)
    return BrowseSession(
        browse = VaultBrowseViewModel(browseModel),
        sync = VaultSyncViewModel(syncModel),
        monitor = monitor,
    )
}
```

- [ ] **Step 2: Rewire `AppRoot.unlockAndOpen` to a credential**

In `AppRoot.kt`:

Add the import:

```kotlin
import org.secretary.browse.UnlockCredential
```

Change the `Route.Unlock` arm to pass an `UnlockCredential` from the screen:

```kotlin
        is Route.Unlock -> UnlockScreen(onUnlock = { credential ->
            scope.launch { route = unlockAndOpen(context, scope, credential) }
        })
```

Replace `unlockAndOpen` with:

```kotlin
/**
 * Opens the vault for browsing with [credential], assembles the sync model+monitor, fires the
 * post-open sync action ([dispatchPostOpenSync]: password → background sync-at-unlock; recovery →
 * status refresh, since Android sync is password-keyed), and returns the Browse route. Runs on the
 * main `scope` (Argon2id hops to IO inside the open port; makeVaultSync inside [openBrowseWithSync]
 * requires main — satisfied here).
 *
 * Secret hygiene: the credential bytes are zeroized in a `finally` wrapping the whole body — on
 * every exit (success, open failure, early provisioning throw). For the password credential the
 * background sync-at-unlock receives a COPY ([launchSyncAtUnlock]); zeroizing the original here
 * cannot corrupt that copy, and because [openBrowseWithSync] awaits the open the zeroize cannot race
 * the Argon2id that consumes the original. The recovery credential hands no copy to a background
 * job, so its bytes are fully owned here.
 */
private suspend fun unlockAndOpen(
    context: Context,
    scope: CoroutineScope,
    credential: UnlockCredential,
): Route {
    try {
        val folder = AppVaultProvisioning.stageGoldenVault(context)
        val deviceUuids = FileDeviceUuidStore(File(context.noBackupFilesDir, "devices"))
        val stateDir = syncStateDir(context.filesDir).apply { mkdirs() }
        val uuid = AppVaultProvisioning.goldenVaultUuid(context)
        val session = openBrowseWithSync(
            uniffiVaultOpenPort(deviceUuids), folder, stateDir, uuid, credential)
        // Password → background sync-at-unlock from a COPY (deliberately outlives Browse disposal:
        // it opens its own vault handle and never touches the browse session; binding it to the
        // Browse scope would cancel the in-flight Argon2id on background). Recovery → status refresh
        // only: Android sync is password-keyed, so a recovery session has no password to sync with;
        // the user syncs manually via the badge re-prompt.
        dispatchPostOpenSync(
            credential,
            onPassword = { pw -> launchSyncAtUnlock(scope, pw, session.sync::syncAtUnlock) },
            onRecovery = { session.sync.refreshStatus() },
        )
        return Route.Browse(session)
    } catch (e: Exception) {
        Log.w(TAG, "unlock/open failed; returning to unlock screen", e)
        return Route.Unlock
    } finally {
        credential.secret.fill(0) // zeroize on every exit; the password background copy is independent
    }
}
```

- [ ] **Step 3: Update the existing instrumented smoke's call site**

In `OpenBrowseWithSyncSmokeTest.kt`, add the import:

```kotlin
import org.secretary.browse.UnlockCredential
```

Change the `openBrowseWithSync` call to wrap the password in a credential:

```kotlin
        val openPw = goldenPassword.toByteArray()
        val session = withContext(Dispatchers.Main) {
            openBrowseWithSync(
                uniffiVaultOpenPort(deviceUuids), folder, stateDir, uuid,
                UnlockCredential.Password(openPw))
        }
        openPw.fill(0)
```

- [ ] **Step 4: Compile `:app` + run host unit tests**

Run: `cd android && ./gradlew :app:compileDebugKotlin :app:testDebugUnitTest`
Expected: BUILD SUCCESSFUL; existing host tests + `PostOpenSyncTest` green. (The instrumented smoke compiles in Step 5's connected run.)

- [ ] **Step 5: Compile the instrumented sources**

Run: `cd android && ./gradlew :app:compileDebugAndroidTestKotlin`
Expected: BUILD SUCCESSFUL (proves the smoke call-site update compiles without a device).

- [ ] **Step 6: Commit**

```bash
git add android/app/src/main/kotlin/org/secretary/app/BrowseSession.kt \
        android/app/src/main/kotlin/org/secretary/app/AppRoot.kt \
        android/app/src/androidTest/kotlin/org/secretary/app/OpenBrowseWithSyncSmokeTest.kt
git commit -m "feat(android): thread UnlockCredential through openBrowseWithSync + unlockAndOpen"
```

---

### Task 6: `:app` `UnlockScreen` Password/Recovery toggle

Add a segmented Password/Recovery toggle; recovery mode shows a multi-line unmasked phrase field, normalized on submit. The callback now emits an `UnlockCredential`.

**Files:**
- Modify: `android/app/src/main/kotlin/org/secretary/app/UnlockScreen.kt`
- Test: `android/app/src/androidTest/kotlin/org/secretary/app/UnlockScreenRecoveryUiTest.kt`

**Interfaces:**
- Consumes: `UnlockCredential` (Task 2), `RecoveryPhrase.normalize` (Task 1).
- Produces: `@Composable fun UnlockScreen(onUnlock: (UnlockCredential) -> Unit)` with a mode toggle whose test tags are `mode-password`, `mode-recovery`, `password-field`, `recovery-field`, `unlock-button`.

- [ ] **Step 1: Write the failing instrumented UI test**

Create `UnlockScreenRecoveryUiTest.kt`:

```kotlin
package org.secretary.app

import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.secretary.browse.UnlockCredential

class UnlockScreenRecoveryUiTest {
    @get:Rule val composeRule = createComposeRule()

    @Test
    fun recoveryMode_submitsANormalizedRecoveryCredential() {
        var captured: UnlockCredential? = null
        composeRule.setContent { UnlockScreen(onUnlock = { captured = it }) }

        // Switch to recovery mode, type a noisy phrase, submit.
        composeRule.onNodeWithTag("mode-recovery").performClick()
        composeRule.onNodeWithTag("recovery-field").performTextInput("  Alpha   BRAVO  ")
        composeRule.onNodeWithTag("unlock-button").performClick()

        val cred = captured
        assertTrue("expected a Recovery credential", cred is UnlockCredential.Recovery)
        // Normalized: lowercased, single-spaced, trimmed, UTF-8.
        assertArrayEquals("alpha bravo".toByteArray(Charsets.UTF_8), cred!!.secret)
    }

    @Test
    fun passwordMode_submitsAPasswordCredential() {
        var captured: UnlockCredential? = null
        composeRule.setContent { UnlockScreen(onUnlock = { captured = it }) }

        composeRule.onNodeWithTag("password-field").performTextInput("hunter2")
        composeRule.onNodeWithTag("unlock-button").performClick()

        val cred = captured
        assertTrue("expected a Password credential", cred is UnlockCredential.Password)
        assertArrayEquals("hunter2".toByteArray(Charsets.UTF_8), cred!!.secret)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run (emulator must be running): `cd android && ./gradlew :app:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.app.UnlockScreenRecoveryUiTest`
Expected: FAIL — `onUnlock` type mismatch / missing test tags (compile or assertion failure).

- [ ] **Step 3: Rewrite `UnlockScreen` with the toggle**

Replace the whole file `UnlockScreen.kt`:

```kotlin
package org.secretary.app

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import org.secretary.browse.RecoveryPhrase
import org.secretary.browse.UnlockCredential

/** The two unlock credentials the screen can produce. */
private enum class UnlockMode { Password, Recovery }

/**
 * Unlock surface for the walking skeleton: a Password/Recovery segmented toggle. Password mode is a
 * masked single-line field; recovery mode is a multi-line, unmasked 24-word phrase field (a dotted
 * 24-word phrase is unreadable, and the unlock moment is already trusted under FLAG_SECURE). On
 * submit it hands an [UnlockCredential] to [onUnlock] — password bytes, or the phrase normalized via
 * [RecoveryPhrase.normalize] then UTF-8 encoded. Mirror of iOS `UnlockViewModel.Mode` + segmented
 * control.
 *
 * Password hygiene: Compose `TextField` is String-backed, so the typed String lingers until GC —
 * acceptable for this demo skeleton (same tradeoff as the password field). The credential's byte
 * buffer IS zeroized by [AppRoot] after the open pass.
 */
@Composable
fun UnlockScreen(onUnlock: (UnlockCredential) -> Unit) {
    var mode by remember { mutableStateOf(UnlockMode.Password) }
    var password by remember { mutableStateOf("") }
    var phrase by remember { mutableStateOf("") }

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("Secretary — demo vault")

        SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
            SegmentedButton(
                selected = mode == UnlockMode.Password,
                onClick = { mode = UnlockMode.Password },
                shape = SegmentedButtonDefaults.itemShape(index = 0, count = 2),
                modifier = Modifier.testTag("mode-password"),
            ) { Text("Password") }
            SegmentedButton(
                selected = mode == UnlockMode.Recovery,
                onClick = { mode = UnlockMode.Recovery },
                shape = SegmentedButtonDefaults.itemShape(index = 1, count = 2),
                modifier = Modifier.testTag("mode-recovery"),
            ) { Text("Recovery phrase") }
        }

        when (mode) {
            UnlockMode.Password -> OutlinedTextField(
                value = password,
                onValueChange = { password = it },
                label = { Text("Vault password") },
                visualTransformation = PasswordVisualTransformation(),
                singleLine = true,
                modifier = Modifier.fillMaxWidth().testTag("password-field"),
            )
            UnlockMode.Recovery -> OutlinedTextField(
                value = phrase,
                onValueChange = { phrase = it },
                label = { Text("24-word recovery phrase") },
                singleLine = false,
                minLines = 3,
                modifier = Modifier.fillMaxWidth().testTag("recovery-field"),
            )
        }

        Button(
            onClick = {
                val credential = when (mode) {
                    UnlockMode.Password ->
                        UnlockCredential.Password(password.toByteArray(Charsets.UTF_8))
                    UnlockMode.Recovery ->
                        UnlockCredential.Recovery(
                            RecoveryPhrase.normalize(phrase).toByteArray(Charsets.UTF_8))
                }
                onUnlock(credential)
            },
            enabled = when (mode) {
                UnlockMode.Password -> password.isNotEmpty()
                UnlockMode.Recovery -> phrase.isNotBlank()
            },
            modifier = Modifier.fillMaxWidth().testTag("unlock-button"),
        ) {
            Text(if (mode == UnlockMode.Password) "Unlock & Sync" else "Unlock")
        }
    }
}
```

- [ ] **Step 4: Run the UI test to verify it passes**

Run: `cd android && ./gradlew :app:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.app.UnlockScreenRecoveryUiTest`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add android/app/src/main/kotlin/org/secretary/app/UnlockScreen.kt \
        android/app/src/androidTest/kotlin/org/secretary/app/UnlockScreenRecoveryUiTest.kt
git commit -m "feat(android): UnlockScreen Password/Recovery toggle emitting UnlockCredential"
```

---

### Task 7: `goldenRecoveryPhrase` provisioning + on-device recovery open smoke

Read the golden recovery phrase from the bundled inputs JSON (no hardcoded literal), then prove the real `.so` opens `golden_vault_001` via the recovery mnemonic and reaches the block list.

**Files:**
- Modify: `android/app/src/main/kotlin/org/secretary/app/AppVaultProvisioning.kt` (add `goldenRecoveryPhrase`)
- Create: `android/app/src/androidTest/kotlin/org/secretary/app/OpenWithRecoverySmokeTest.kt`

**Interfaces:**
- Consumes: `RecoveryPhrase.normalize` (Task 1), `openBrowseWithSync(..., credential)` (Task 5), `UnlockCredential.Recovery` (Task 2).
- Produces: `AppVaultProvisioning.goldenRecoveryPhrase(context): String` (reads `recovery_mnemonic_phrase` from `golden_vault_001_inputs.json`).

- [ ] **Step 1: Locate the golden phrase source (sanity check, not a code step)**

Confirm `core/tests/data/golden_vault_001_inputs.json` contains `"recovery_mnemonic_phrase"` (it does, as of this plan) and that the app bundles that file as `INPUTS_ASSET` (it does — `goldenVaultUuid` already reads it). If the key is absent, STOP and surface it — do not invent a phrase.

Run: `grep -n recovery_mnemonic_phrase core/tests/data/golden_vault_001_inputs.json`
Expected: one line with the 24-word phrase.

- [ ] **Step 2: Add the provisioning helper**

In `AppVaultProvisioning.kt`, add after `goldenVaultUuid`:

```kotlin
    /** The golden vault's 24-word BIP-39 recovery phrase, read from the bundled inputs JSON
     *  (single source of truth — a published KAT, not a real secret). */
    fun goldenRecoveryPhrase(context: Context): String {
        val json = try {
            context.assets.open(INPUTS_ASSET).bufferedReader().use { it.readText() }
        } catch (e: IOException) {
            throw IllegalStateException(
                "$INPUTS_ASSET not bundled in the APK — the stageGoldenVaultForApp Gradle task did not run",
                e,
            )
        }
        return JSONObject(json).getString("recovery_mnemonic_phrase")
    }
```

- [ ] **Step 3: Write the failing on-device smoke**

Create `OpenWithRecoverySmokeTest.kt`:

```kotlin
package org.secretary.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.secretary.browse.FileDeviceUuidStore
import org.secretary.browse.RecoveryPhrase
import org.secretary.browse.UnlockCredential
import org.secretary.browse.uniffiVaultOpenPort
import java.io.File

/**
 * On-device proof that the recovery-phrase open path works over the REAL
 * libsecretary_ffi_uniffi.so: open golden_vault_001 with its bundled 24-word recovery phrase and
 * reach the block list (mirrors OpenBrowseWithSyncSmokeTest, but via the recovery credential).
 */
@RunWith(AndroidJUnit4::class)
class OpenWithRecoverySmokeTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val toClean = mutableListOf<File>()

    @After fun cleanup() {
        toClean.forEach { it.deleteRecursively() }
        File(context.filesDir, "golden_vault_001").deleteRecursively()
    }

    @Test
    fun opensGoldenVaultViaRecoveryPhrase_reachesBlockList() = runBlocking {
        val folder = AppVaultProvisioning.stageGoldenVault(context)
        val deviceUuids = FileDeviceUuidStore(File(context.noBackupFilesDir, "devices-${System.nanoTime()}"))
        val stateBase = File(context.cacheDir, "run-${System.nanoTime()}")
        val stateDir = syncStateDir(stateBase).apply { mkdirs() }
        toClean += stateBase
        val uuid = AppVaultProvisioning.goldenVaultUuid(context)

        val phraseBytes = RecoveryPhrase.normalize(AppVaultProvisioning.goldenRecoveryPhrase(context))
            .toByteArray(Charsets.UTF_8)
        val session = withContext(Dispatchers.Main) {
            openBrowseWithSync(
                uniffiVaultOpenPort(deviceUuids), folder, stateDir, uuid,
                UnlockCredential.Recovery(phraseBytes))
        }
        phraseBytes.fill(0)

        assertTrue("recovery open reached the block list", session.browse.blocks.value.isNotEmpty())

        withContext(Dispatchers.Main) { session.browse.lock() }
    }
}
```

- [ ] **Step 4: Run the smoke (emulator running) — verify it passes**

Run: `cd android && ./gradlew :app:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.app.OpenWithRecoverySmokeTest`
Expected: PASS — the block list is non-empty after a recovery open over the real `.so`.

- [ ] **Step 5: Commit**

```bash
git add android/app/src/main/kotlin/org/secretary/app/AppVaultProvisioning.kt \
        android/app/src/androidTest/kotlin/org/secretary/app/OpenWithRecoverySmokeTest.kt
git commit -m "test(android): on-device recovery-phrase open smoke over the real .so"
```

---

### Task 8: Docs — README + ROADMAP rows

Record the slice in the two living docs (per the project's `/nextsession` closeout). The handoff doc + symlink are authored at session close, not here.

**Files:**
- Modify: `README.md` (Android status section — add a recovery-open row, mirroring the existing slice rows)
- Modify: `ROADMAP.md` (C.3 Android line + the recovery-open entry)

- [ ] **Step 1: Add the README row**

In `README.md`, in the Android status table (the same table that holds the sync-on-browse row), add a row after the sync-on-browse row:

```markdown
| Android app — recovery-phrase open (C.3 recovery-open) | ✅ (2026-06-18): a second unlock credential — the 24-word BIP-39 recovery phrase — alongside the password open, both reaching the unified `BrowseWithSyncScreen`. A sealed `UnlockCredential` (`Password`/`Recovery`) threads the credential through a pure `openWithCredential` dispatch; `:kit` wraps the already-generated `openVaultWithRecovery`. Because Android sync is password-keyed, a recovery-opened session shows a **status-only** sync badge (no auto-sync pass) and syncs manually via the badge re-prompt — mirroring iOS's optional-password `onUnlocked`. New typed errors `WrongRecoveryOrCorrupt` (conflated, anti-oracle §13) + `InvalidRecoveryPhrase`. Host-tested normalize/dispatch/mapping + an on-device recovery-open smoke over the real `.so`. Android-only; no `core` / `ffi` / on-disk-format change. |
```

- [ ] **Step 2: Add the ROADMAP entry**

In `ROADMAP.md`, append to the C.3 Android narrative line (after the sync-on-browse entry) a parallel `recovery-phrase open ✅ shipped 2026-06-18` clause, and add a bullet under the C.3 phase-plan list:

```markdown
  - **C.3 recovery-phrase open (Android)** ✅ 2026-06-18 — a second unlock credential (24-word BIP-39 recovery phrase) alongside the password open; both reach the unified `BrowseWithSyncScreen`. Sealed `UnlockCredential` + pure `openWithCredential` dispatch; `:kit` `openWithRecovery` over the generated `openVaultWithRecovery`; new `WrongRecoveryOrCorrupt` (conflated §13) + `InvalidRecoveryPhrase` typed errors. Recovery sessions get a status-only sync badge (Android sync is password-keyed) and sync manually via the badge re-prompt, mirroring iOS. Host-tested + an on-device recovery-open smoke. Android-only; no `core` / `ffi` / on-disk-format / UDL change. Spec + plan in [`docs/superpowers/specs/2026-06-18-c3-android-recovery-open-design.md`](docs/superpowers/specs/2026-06-18-c3-android-recovery-open-design.md) + [`docs/superpowers/plans/2026-06-18-c3-android-recovery-open.md`](docs/superpowers/plans/2026-06-18-c3-android-recovery-open.md).
```

- [ ] **Step 3: Sanity-check the docs render**

Run: `grep -n "recovery-phrase open\|recovery-open" README.md ROADMAP.md`
Expected: the new rows appear in both files.

- [ ] **Step 4: Commit**

```bash
git add README.md ROADMAP.md
git commit -m "docs: README + ROADMAP rows for C.3 Android recovery-phrase open"
```

---

## Final verification (after all tasks)

- [ ] **Host suites green**

Run: `cd android && ./gradlew :vault-access:test :kit:test :app:testDebugUnitTest :browse-ui:test`
Expected: BUILD SUCCESSFUL.

- [ ] **Connected suites green (emulator running)**

Run: `cd android && PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" ./gradlew :app:connectedDebugAndroidTest`
Expected: all `:app` instrumented tests pass (existing smokes + `UnlockScreenRecoveryUiTest` + `OpenWithRecoverySmokeTest`).

- [ ] **Guardrails empty**

```bash
git diff main...HEAD --name-only | grep -E 'core/|ffi/|crypto-design|vault-format'                   # empty
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)' # empty (no ios/)
```

---

## Self-Review (plan vs spec)

**Spec coverage:**
- §3 FFI surface (recovery already generated) → Task 3 wraps `openVaultWithRecovery`. ✓
- §4 password-keyed-sync constraint (recovery → status-only) → Task 4 `dispatchPostOpenSync` + Task 5 wiring + Task 7 reaches `BrowseWithSyncScreen`. ✓
- §5 Approach A sealed `UnlockCredential` + `openWithCredential` → Task 2. ✓
- §5.1 `RecoveryPhrase.normalize` → Task 1. ✓
- §5.2 port + adapter + `recoveryFn` seam → Tasks 2, 3. ✓
- §5.3 error mapping (2 arms, conflated `WrongRecoveryOrCorrupt`, format `InvalidRecoveryPhrase`) → Task 3. ✓
- §5.5 UI toggle + multi-line unmasked recovery field + normalize on submit → Task 6. ✓
- §6 secret hygiene (zeroize the credential in `finally`; no phrase to a background job) → Task 5. ✓
- §7 testing (host normalize/mapping/dispatch + on-device recovery smoke) → Tasks 1, 3, 2, 4, 7. ✓
- §7 golden mnemonic located in fixtures, fail loudly if absent → Task 7 Step 1 + `goldenRecoveryPhrase`. ✓
- §8 guardrails → Final verification. ✓

**Placeholder scan:** none — every code step shows full code; every run step shows the command + expected outcome.

**Type consistency:** `UnlockCredential` (`secret`/`Password`/`Recovery`), `openWithCredential`, `dispatchPostOpenSync(onPassword/onRecovery)`, `openBrowseWithSync(..., credential)`, `VaultBrowseError.WrongRecoveryOrCorrupt`/`InvalidRecoveryPhrase`, `goldenRecoveryPhrase`, and the test tags (`mode-recovery`, `recovery-field`, `unlock-button`) are used consistently across tasks.
