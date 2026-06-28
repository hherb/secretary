# Android cloud-drive Slice 4 — provisioning view models + screens + AppRoot routing — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the Android vault-provisioning UI — two pure host-tested view models (`:vault-access`), two Compose screens + SAF folder-picker launchers + `AppRoot` routing (`:app`) — over the Slice-1 `VaultCreatePort` and Slice-2 `VaultLocationStore`.

**Architecture:** Pure plain-class view models (mutable `state`/`step` mutated by methods, mirroring `DeviceUnlockViewModel`/`DeviceSettingsViewModel`) live in `:vault-access` and are host-tested against in-memory fakes. The Compose screens + routing live in `:app`. The SAF working-copy lifecycle (materialize/flush) stays Slice 5; Create round-trips locally this slice and cloud-open is an explicit, labelled seam.

**Tech Stack:** Kotlin, JUnit 5 (Jupiter) + `kotlinx-coroutines-test` for host tests, Jetpack Compose (material3) + `activity-compose` `OpenDocumentTree` for screens, `androidx.documentfile` (already in `:kit`).

## Global Constraints

- **No core `src/`, no FFI surface, no on-disk-format / spec / `conformance.py` / KAT change.** This slice is Kotlin/Android only (`:vault-access` + `:app`, plus one tiny `:kit` helper).
- **Pure logic in `:vault-access`** (zero Android/Compose imports there); **Android/Compose only in `:app`**; **Android-bound SAF/DocumentFile only in `:kit`**.
- **TDD:** every behaviour change starts with a failing test (RED proven) before implementation.
- **Files under ~500 lines;** one concept per file; split before approaching the threshold.
- **Secret hygiene:** the recovery-phrase `ByteArray` is zeroize-owned (wiped on ack/cancel). Display `String`s are the documented best-effort tradeoff. `password`/`confirm` are caller-owned, never retained.
- **Host test command (from `android/`):** `./gradlew :vault-access:test` and `./gradlew :kit:testDebugUnitTest`.
- **No magic numbers:** name-length cap etc. as named `const val`.
- **Mirror existing patterns:** view models like `DeviceSettingsViewModel`; screens like `UnlockScreen`; fakes like the `SafVaultLocationStoreTest` seam style.

---

### Task 1: `VaultSelectionState` + `VaultSelectionViewModel` (pure, host-tested)

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultSelectionState.kt`
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultSelectionViewModel.kt`
- Create (test fake): `android/vault-access/src/test/kotlin/org/secretary/browse/ProvisioningFakes.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/VaultSelectionViewModelTest.kt`

**Interfaces:**
- Consumes: existing `VaultLocationStore` (`load(): VaultLocation?`, `persist(location)`, `clear()`, `isAvailable(location): Boolean`), existing `VaultLocation(displayName, treeUri)`.
- Produces: `sealed interface VaultSelectionState { Empty; Located(displayName: String); Unavailable(reason: String) }`; `class VaultSelectionViewModel(store: VaultLocationStore)` with `val state: VaultSelectionState` and `loadPersisted()`, `recordSelection(location: VaultLocation)`, `markUnavailable(reason: String)`, `chooseDifferent()`; `const val PERMISSION_REVOKED_REASON`. Test fake `FakeVaultLocationStore` (reused by Task 4).

- [ ] **Step 1: Write the failing test**

`VaultSelectionViewModelTest.kt`:

```kotlin
package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class VaultSelectionViewModelTest {
    private val location = VaultLocation("My Vault", "content://x/tree/y")

    @Test
    fun `empty when nothing persisted`() {
        val vm = VaultSelectionViewModel(FakeVaultLocationStore())
        vm.loadPersisted()
        assertEquals(VaultSelectionState.Empty, vm.state)
    }

    @Test
    fun `located when an available location is persisted`() {
        val vm = VaultSelectionViewModel(FakeVaultLocationStore(stored = location, available = true))
        vm.loadPersisted()
        assertEquals(VaultSelectionState.Located("My Vault"), vm.state)
    }

    @Test
    fun `unavailable when the persisted location's permission is gone`() {
        val vm = VaultSelectionViewModel(FakeVaultLocationStore(stored = location, available = false))
        vm.loadPersisted()
        assertTrue(vm.state is VaultSelectionState.Unavailable)
    }

    @Test
    fun `unavailable is preserved across a re-load`() {
        val vm = VaultSelectionViewModel(FakeVaultLocationStore(stored = location, available = false))
        vm.loadPersisted()
        // Even if the store would now report it available, a surfaced Unavailable survives.
        vm.loadPersisted()
        assertTrue(vm.state is VaultSelectionState.Unavailable)
    }

    @Test
    fun `recordSelection persists and locates`() {
        val store = FakeVaultLocationStore()
        val vm = VaultSelectionViewModel(store)
        vm.recordSelection(location)
        assertEquals(listOf(location), store.persisted)
        assertEquals(VaultSelectionState.Located("My Vault"), vm.state)
    }

    @Test
    fun `chooseDifferent clears the store and goes empty`() {
        val store = FakeVaultLocationStore(stored = location)
        val vm = VaultSelectionViewModel(store)
        vm.chooseDifferent()
        assertTrue(store.cleared)
        assertEquals(VaultSelectionState.Empty, vm.state)
    }

    @Test
    fun `markUnavailable surfaces the reason and retains the location`() {
        val store = FakeVaultLocationStore(stored = location)
        val vm = VaultSelectionViewModel(store)
        vm.markUnavailable("offline")
        assertEquals(VaultSelectionState.Unavailable("offline"), vm.state)
        assertTrue(!store.cleared) // retained, not cleared
    }
}
```

Also create `ProvisioningFakes.kt` with `FakeVaultLocationStore`:

```kotlin
package org.secretary.browse

/** In-memory [VaultLocationStore] for host tests. Records persists + clear so the view-model
 *  tests can assert forwarding and ordering. */
class FakeVaultLocationStore(
    private var stored: VaultLocation? = null,
    private val available: Boolean = true,
) : VaultLocationStore {
    val persisted = mutableListOf<VaultLocation>()
    var cleared = false
        private set

    override fun load(): VaultLocation? = stored
    override fun persist(location: VaultLocation) {
        stored = location
        persisted.add(location)
    }
    override fun clear() {
        stored = null
        cleared = true
    }
    override fun isAvailable(location: VaultLocation): Boolean = available
}
```

- [ ] **Step 2: Run test to verify it fails**

Run (from `android/`): `./gradlew :vault-access:test --tests '*VaultSelectionViewModelTest'`
Expected: FAIL — `VaultSelectionState` / `VaultSelectionViewModel` unresolved.

- [ ] **Step 3: Write minimal implementation**

`VaultSelectionState.kt`:

```kotlin
package org.secretary.browse

/**
 * What the vault-selection screen shows. [Empty] — nothing remembered. [Located] — a remembered,
 * accessible vault (offer Open). [Unavailable] — a remembered vault whose SAF permission is gone
 * or whose open failed (offer re-pick); the reason survives a screen re-appear so the screen never
 * lies about being openable. Kotlin mirror of iOS `VaultSelectionState`.
 */
sealed interface VaultSelectionState {
    data object Empty : VaultSelectionState
    data class Located(val displayName: String) : VaultSelectionState
    data class Unavailable(val reason: String) : VaultSelectionState
}
```

`VaultSelectionViewModel.kt`:

```kotlin
package org.secretary.browse

/** User-safe reason shown when a remembered vault's SAF grant is no longer held. */
const val PERMISSION_REVOKED_REASON =
    "This vault's folder is no longer accessible — re-pick it to continue."

/**
 * Drives the vault-selection screen over a [VaultLocationStore]. Plain class with a mutable [state]
 * field (mirrors `DeviceSettingsViewModel`); `AppRoot` bridges it into Compose. Fully host-testable —
 * holds only the injected store. Mirror of iOS `VaultSelectionViewModel`, minus iOS `beginAccess` /
 * shape-probe: resolving a SAF tree to an operable path is the working-copy materialize step (Slice 5).
 */
class VaultSelectionViewModel(private val store: VaultLocationStore) {
    var state: VaultSelectionState = VaultSelectionState.Empty
        private set

    /**
     * Recompute state from the persisted store. A surfaced [VaultSelectionState.Unavailable] is
     * preserved, NOT silently downgraded — a failed open's reason must survive a re-appear, or the
     * user gets an Open button that just fails again. The user clears it via [chooseDifferent] or a
     * fresh [recordSelection].
     */
    fun loadPersisted() {
        if (state is VaultSelectionState.Unavailable) return
        val loc = store.load()
        state = when {
            loc == null -> VaultSelectionState.Empty
            !store.isAvailable(loc) -> VaultSelectionState.Unavailable(PERMISSION_REVOKED_REASON)
            else -> VaultSelectionState.Located(loc.displayName)
        }
    }

    /** Remember a freshly picked vault and locate it. */
    fun recordSelection(location: VaultLocation) {
        store.persist(location)
        state = VaultSelectionState.Located(location.displayName)
    }

    /**
     * Surface [reason] as [VaultSelectionState.Unavailable] (e.g. a Slice-5 materialize/permission
     * failure). The remembered location is RETAINED — losing the user's selection silently would be
     * wrong; they re-pick or choose-different explicitly.
     */
    fun markUnavailable(reason: String) {
        state = VaultSelectionState.Unavailable(reason)
    }

    /** Forget the remembered vault and return to empty. */
    fun chooseDifferent() {
        store.clear()
        state = VaultSelectionState.Empty
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :vault-access:test --tests '*VaultSelectionViewModelTest'`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/browse/VaultSelectionState.kt \
        android/vault-access/src/main/kotlin/org/secretary/browse/VaultSelectionViewModel.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/ProvisioningFakes.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/VaultSelectionViewModelTest.kt
git commit -m "feat(android): VaultSelectionViewModel + state (cloud-drive provisioning, slice 4)"
```

---

### Task 2: `validateVaultName` + `VaultNameError` (pure)

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultName.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/VaultNameTest.kt`

**Interfaces:**
- Produces: `sealed interface VaultNameValidation { Valid(name: String); Invalid(error: VaultNameError) }`; `sealed class VaultNameError : Exception { Blank; TooLong; IllegalCharacters }`; `fun validateVaultName(raw: String): VaultNameValidation`; `const val MAX_VAULT_NAME_LENGTH = 64`.

- [ ] **Step 1: Write the failing test**

```kotlin
package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class VaultNameTest {
    private fun invalidArm(raw: String): VaultNameError {
        val v = validateVaultName(raw)
        assertTrue(v is VaultNameValidation.Invalid, "expected invalid for <$raw>")
        return (v as VaultNameValidation.Invalid).error
    }

    @Test
    fun `trims and accepts a normal name`() {
        assertEquals(VaultNameValidation.Valid("My Vault"), validateVaultName("  My Vault  "))
    }

    @Test
    fun `blank rejected`() {
        assertTrue(invalidArm("   ") is VaultNameError.Blank)
    }

    @Test
    fun `over-length rejected`() {
        assertTrue(invalidArm("x".repeat(MAX_VAULT_NAME_LENGTH + 1)) is VaultNameError.TooLong)
    }

    @Test
    fun `path separators rejected`() {
        assertTrue(invalidArm("a/b") is VaultNameError.IllegalCharacters)
        assertTrue(invalidArm("a\\b") is VaultNameError.IllegalCharacters)
    }

    @Test
    fun `dot names rejected`() {
        assertTrue(invalidArm(".") is VaultNameError.IllegalCharacters)
        assertTrue(invalidArm("..") is VaultNameError.IllegalCharacters)
    }

    @Test
    fun `control and nul chars rejected`() {
        assertTrue(invalidArm("a b") is VaultNameError.IllegalCharacters)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :vault-access:test --tests '*VaultNameTest'`
Expected: FAIL — unresolved references.

- [ ] **Step 3: Write minimal implementation**

`VaultName.kt`:

```kotlin
package org.secretary.browse

/** Upper bound on a typed vault name (it becomes a folder name + a display label). */
const val MAX_VAULT_NAME_LENGTH = 64

/** Outcome of validating a typed vault name. */
sealed interface VaultNameValidation {
    data class Valid(val name: String) : VaultNameValidation
    data class Invalid(val error: VaultNameError) : VaultNameValidation
}

/**
 * Why a typed vault name was rejected, with user-safe copy. Throwable to match the other
 * `:vault-access` error families, though it is normally consumed as a value via [VaultNameValidation].
 */
sealed class VaultNameError(message: String) : Exception(message) {
    data object Blank : VaultNameError("Enter a name for the vault.")
    data object TooLong : VaultNameError("That name is too long.")
    data object IllegalCharacters :
        VaultNameError("A vault name can't contain / or \\, or be just \".\" or \"..\".")
}

/**
 * Validate a typed vault name for use as both a folder name and a display label. Trims surrounding
 * whitespace, then rejects blank, over-[MAX_VAULT_NAME_LENGTH], path separators (`/` `\`), the
 * dot-only names (`.` `..`, which would collide with directory entries), and control / NUL chars.
 * Pure — no side effects. Mirror of iOS `validateVaultName`.
 */
fun validateVaultName(raw: String): VaultNameValidation {
    val name = raw.trim()
    if (name.isEmpty()) return VaultNameValidation.Invalid(VaultNameError.Blank)
    if (name.length > MAX_VAULT_NAME_LENGTH) return VaultNameValidation.Invalid(VaultNameError.TooLong)
    val illegal = name == "." || name == ".." ||
        name.any { it == '/' || it == '\\' || it == ' ' || it.isISOControl() }
    if (illegal) return VaultNameValidation.Invalid(VaultNameError.IllegalCharacters)
    return VaultNameValidation.Valid(name)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :vault-access:test --tests '*VaultNameTest'`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/browse/VaultName.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/VaultNameTest.kt
git commit -m "feat(android): validateVaultName + VaultNameError (cloud-drive provisioning, slice 4)"
```

---

### Task 3: `MnemonicWord` + `groupMnemonic` (pure)

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/MnemonicDisplay.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/MnemonicDisplayTest.kt`

**Interfaces:**
- Produces: `data class MnemonicWord(index: Int, word: String)`; `fun groupMnemonic(phrase: ByteArray): List<MnemonicWord>` (1-based numbering; input `ByteArray` not mutated).

- [ ] **Step 1: Write the failing test**

```kotlin
package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class MnemonicDisplayTest {
    @Test
    fun `numbers words from one and splits on whitespace`() {
        val rows = groupMnemonic("alpha bravo  charlie".toByteArray(Charsets.UTF_8))
        assertEquals(
            listOf(MnemonicWord(1, "alpha"), MnemonicWord(2, "bravo"), MnemonicWord(3, "charlie")),
            rows,
        )
    }

    @Test
    fun `does not mutate the input phrase`() {
        val phrase = "alpha bravo".toByteArray(Charsets.UTF_8)
        val copy = phrase.copyOf()
        groupMnemonic(phrase)
        assertTrue(phrase.contentEquals(copy))
    }

    @Test
    fun `handles a full 24-word phrase`() {
        val words = (1..24).joinToString(" ") { "w$it" }
        val rows = groupMnemonic(words.toByteArray(Charsets.UTF_8))
        assertEquals(24, rows.size)
        assertEquals(MnemonicWord(24, "w24"), rows.last())
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :vault-access:test --tests '*MnemonicDisplayTest'`
Expected: FAIL — unresolved references.

- [ ] **Step 3: Write minimal implementation**

`MnemonicDisplay.kt`:

```kotlin
package org.secretary.browse

/** One numbered word of a recovery phrase, for on-screen display. [word] is an un-zeroizable
 *  String — the accepted best-effort tradeoff for showing a phrase the user must read. */
data class MnemonicWord(val index: Int, val word: String)

/**
 * Number the words of a UTF-8 recovery [phrase] for display (1-based). Splits on any whitespace run
 * and drops empties — the canonical BIP-39 phrase is single-space-joined, this tolerates display
 * noise. Pure: the input [phrase] `ByteArray` is read, never mutated (its zeroize lifetime is owned
 * by the caller — `VaultProvisioningViewModel`). Note that decoding to a `String` copies the bytes
 * into an un-zeroizable buffer; that is the documented display tradeoff.
 */
fun groupMnemonic(phrase: ByteArray): List<MnemonicWord> =
    String(phrase, Charsets.UTF_8)
        .split(Regex("\\s+"))
        .filter { it.isNotEmpty() }
        .mapIndexed { i, w -> MnemonicWord(index = i + 1, word = w) }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :vault-access:test --tests '*MnemonicDisplayTest'`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/browse/MnemonicDisplay.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/MnemonicDisplayTest.kt
git commit -m "feat(android): groupMnemonic + MnemonicWord display helper (cloud-drive provisioning, slice 4)"
```

---

### Task 4: `VaultProvisioningStep` + `VaultProvisioningViewModel` (pure, host-tested)

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultProvisioningStep.kt`
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultProvisioningViewModel.kt`
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultProvisioningError.kt` (add `PasswordMismatch` arm)
- Modify (test fake): `android/vault-access/src/test/kotlin/org/secretary/browse/ProvisioningFakes.kt` (add `FakeVaultCreatePort`)
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/VaultProvisioningViewModelTest.kt`

**Interfaces:**
- Consumes: existing `VaultCreatePort.createInFolder(folderPath, password, displayName): CreatedVault`, `CreatedVault(phrase: ByteArray)`, `VaultLocationStore`, `VaultLocation`, `VaultProvisioningError`, and Tasks 2–3 (`validateVaultName`, `VaultNameValidation`, `VaultNameError`, `groupMnemonic`, `MnemonicWord`).
- Produces: `sealed interface VaultProvisioningStep { Folder; Credentials(treeUri, vaultName); Mnemonic; Done(location: VaultLocation) }`; `class VaultProvisioningViewModel(createPort, store)` with `step`, `nameError`, `error`, `isCreating`, `mnemonicRows`, and `chooseFolder(treeUri, vaultName)`, `suspend create(folderPath, password, confirm)`, `acknowledgeMnemonic()`, `cancel()`; `internal fun passwordsMatch(a, b)`; new `VaultProvisioningError.PasswordMismatch`.

- [ ] **Step 1: Write the failing test**

First add `FakeVaultCreatePort` to `ProvisioningFakes.kt`:

```kotlin
/** In-memory [VaultCreatePort] for host tests. Records each call and hands the VM the EXACT phrase
 *  buffer it returns (via [lastReturnedPhrase]) so a zeroize-on-ack assertion can inspect it. */
class FakeVaultCreatePort(
    private val phrase: ByteArray = "alpha bravo charlie".toByteArray(Charsets.UTF_8),
    private val error: VaultProvisioningError? = null,
) : VaultCreatePort {
    data class Call(val folderPath: String, val displayName: String, val passwordSize: Int)
    val calls = mutableListOf<Call>()
    var lastReturnedPhrase: ByteArray? = null
        private set

    override suspend fun createInFolder(
        folderPath: String,
        password: ByteArray,
        displayName: String,
    ): CreatedVault {
        calls.add(Call(folderPath, displayName, password.size))
        error?.let { throw it }
        val buf = phrase.copyOf()
        lastReturnedPhrase = buf
        return CreatedVault(buf)
    }
}
```

`VaultProvisioningViewModelTest.kt`:

```kotlin
package org.secretary.browse

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class VaultProvisioningViewModelTest {
    private val tree = "content://x/tree/y"
    private fun pw(s: String) = s.toByteArray(Charsets.UTF_8)

    private fun vm(
        createPort: VaultCreatePort = FakeVaultCreatePort(),
        store: VaultLocationStore = FakeVaultLocationStore(),
    ) = VaultProvisioningViewModel(createPort, store)

    @Test
    fun `chooseFolder rejects an invalid name and stays on folder`() {
        val m = vm()
        m.chooseFolder(tree, "a/b")
        assertTrue(m.nameError is VaultNameError.IllegalCharacters)
        assertEquals(VaultProvisioningStep.Folder, m.step)
    }

    @Test
    fun `chooseFolder accepts a valid name and advances to credentials`() {
        val m = vm()
        m.chooseFolder(tree, "  My Vault ")
        assertNull(m.nameError)
        assertEquals(VaultProvisioningStep.Credentials(tree, "My Vault"), m.step)
    }

    @Test
    fun `create with mismatched passwords surfaces PasswordMismatch and stays on credentials`() = runTest {
        val m = vm()
        m.chooseFolder(tree, "My Vault")
        m.create("/tmp/work", pw("a"), pw("b"))
        assertEquals(VaultProvisioningError.PasswordMismatch, m.error)
        assertTrue(m.step is VaultProvisioningStep.Credentials)
    }

    @Test
    fun `create persists the location and reveals the mnemonic`() = runTest {
        val store = FakeVaultLocationStore()
        val port = FakeVaultCreatePort(phrase = "one two three".toByteArray())
        val m = VaultProvisioningViewModel(port, store)
        m.chooseFolder(tree, "My Vault")
        m.create("/tmp/work", pw("pw"), pw("pw"))
        // Persist happened with the Credentials treeUri + vaultName, BEFORE the mnemonic reveal.
        assertEquals(listOf(VaultLocation("My Vault", tree)), store.persisted)
        assertEquals(VaultProvisioningStep.Mnemonic, m.step)
        assertEquals(3, m.mnemonicRows?.size)
        // The port was called with the resolved folder path + the vault name as displayName.
        assertEquals(FakeVaultCreatePort.Call("/tmp/work", "My Vault", 2), port.calls.single())
    }

    @Test
    fun `create is re-entrancy-guarded`() = runTest {
        val store = FakeVaultLocationStore()
        val port = FakeVaultCreatePort()
        val m = VaultProvisioningViewModel(port, store)
        m.chooseFolder(tree, "My Vault")
        m.create("/tmp/work", pw("pw"), pw("pw")) // first → Mnemonic
        m.create("/tmp/work", pw("pw"), pw("pw")) // second → ignored (not in Credentials anymore)
        assertEquals(1, port.calls.size)
    }

    @Test
    fun `create maps FolderNotEmpty to error`() = runTest {
        val port = FakeVaultCreatePort(error = VaultProvisioningError.FolderNotEmpty)
        val m = VaultProvisioningViewModel(port, FakeVaultLocationStore())
        m.chooseFolder(tree, "My Vault")
        m.create("/tmp/work", pw("pw"), pw("pw"))
        assertEquals(VaultProvisioningError.FolderNotEmpty, m.error)
        assertTrue(m.step is VaultProvisioningStep.Credentials)
        assertFalse(m.isCreating)
    }

    @Test
    fun `acknowledge zeroizes the phrase and completes with the location`() = runTest {
        val store = FakeVaultLocationStore()
        val port = FakeVaultCreatePort(phrase = "alpha bravo".toByteArray())
        val m = VaultProvisioningViewModel(port, store)
        m.chooseFolder(tree, "My Vault")
        m.create("/tmp/work", pw("pw"), pw("pw"))
        m.acknowledgeMnemonic()
        assertNull(m.mnemonicRows)
        assertEquals(VaultProvisioningStep.Done(VaultLocation("My Vault", tree)), m.step)
        // The exact buffer the VM retained is wiped.
        assertTrue(port.lastReturnedPhrase!!.all { it == 0.toByte() })
    }

    @Test
    fun `acknowledge with a missing stored location surfaces a store fault`() = runTest {
        // Store accepts persist but reports nothing on load (simulated by a store that drops it).
        val droppingStore = object : VaultLocationStore {
            override fun load(): VaultLocation? = null
            override fun persist(location: VaultLocation) {}
            override fun clear() {}
            override fun isAvailable(location: VaultLocation) = true
        }
        val m = VaultProvisioningViewModel(FakeVaultCreatePort(), droppingStore)
        m.chooseFolder(tree, "My Vault")
        m.create("/tmp/work", pw("pw"), pw("pw"))
        m.acknowledgeMnemonic()
        assertTrue(m.error is VaultProvisioningError.CreateFailed)
        assertTrue(m.step is VaultProvisioningStep.Mnemonic) // did not advance to Done
    }

    @Test
    fun `cancel zeroizes the retained phrase`() = runTest {
        val port = FakeVaultCreatePort(phrase = "alpha bravo".toByteArray())
        val m = VaultProvisioningViewModel(port, FakeVaultLocationStore())
        m.chooseFolder(tree, "My Vault")
        m.create("/tmp/work", pw("pw"), pw("pw"))
        m.cancel()
        assertNull(m.mnemonicRows)
        assertTrue(port.lastReturnedPhrase!!.all { it == 0.toByte() })
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :vault-access:test --tests '*VaultProvisioningViewModelTest'`
Expected: FAIL — `VaultProvisioningStep`, `VaultProvisioningViewModel`, `VaultProvisioningError.PasswordMismatch` unresolved.

- [ ] **Step 3: Write minimal implementation**

First add the `PasswordMismatch` arm to `VaultProvisioningError.kt` (insert before `CreateFailed`, and update the class doc's "later slices add" note):

```kotlin
    /** The typed password and its confirmation did not match (UI pre-check, never from the FFI). */
    data object PasswordMismatch : VaultProvisioningError()
```

> Before committing, grep for any exhaustive `when` over `VaultProvisioningError` arms that a new
> arm would break: `rg 'when\s*\([^)]*VaultProvisioningError' android` and
> `rg 'is VaultProvisioningError\.' android`. The mapper in `:kit` (`UniffiVaultCreatePort`) only
> *produces* `FolderNotEmpty`/`CreateFailed`, so it is unaffected. Fix any genuine exhaustive
> consumer found; expected result is none.

`VaultProvisioningStep.kt`:

```kotlin
package org.secretary.browse

/**
 * The create-vault wizard's position. [Folder] — pick a parent SAF tree + type a name. [Credentials]
 * — carries the picked [treeUri] + validated [vaultName] while the user enters a password. [Mnemonic]
 * — the created vault's recovery phrase is being shown. [Done] — finished; carries the persisted
 * [location] so `AppRoot` can route to open. Kotlin mirror of iOS `VaultProvisioningStep`.
 */
sealed interface VaultProvisioningStep {
    data object Folder : VaultProvisioningStep
    data class Credentials(val treeUri: String, val vaultName: String) : VaultProvisioningStep
    data object Mnemonic : VaultProvisioningStep
    data class Done(val location: VaultLocation) : VaultProvisioningStep
}
```

`VaultProvisioningViewModel.kt`:

```kotlin
package org.secretary.browse

/** Plain value compare of the typed password and its confirmation. Not constant-time, and it need
 *  not be: both are caller-owned local buffers (user-typed), neither is compared against a stored
 *  secret. */
internal fun passwordsMatch(a: ByteArray, b: ByteArray): Boolean = a.contentEquals(b)

/**
 * Drives the create-vault wizard over a [VaultCreatePort] + [VaultLocationStore]. Plain class with
 * mutable published fields (mirrors `DeviceSettingsViewModel`); `AppRoot` bridges them into Compose.
 * Fully host-testable — holds only injected ports. The CPU-heavy Argon2id create is offloaded off
 * the main thread inside the port impl (`:kit` `UniffiVaultCreatePort`), so [create] only suspends.
 * Mirror of iOS `VaultProvisioningViewModel`, adapted to the Android `createInFolder(folderPath, …)`
 * port (the caller resolves + creates the empty working dir; this VM does not touch the filesystem).
 */
class VaultProvisioningViewModel(
    private val createPort: VaultCreatePort,
    private val store: VaultLocationStore,
) {
    var step: VaultProvisioningStep = VaultProvisioningStep.Folder
        private set
    var nameError: VaultNameError? = null
        private set
    var error: VaultProvisioningError? = null
        private set
    var isCreating: Boolean = false
        private set
    var mnemonicRows: List<MnemonicWord>? = null
        private set

    /** The one-shot recovery phrase, retained only between [create] and [acknowledgeMnemonic]/[cancel]. */
    private var phrase: ByteArray? = null

    /** Validate the typed name; advance to [VaultProvisioningStep.Credentials] or publish [nameError]. */
    fun chooseFolder(treeUri: String, vaultName: String) {
        error = null
        when (val v = validateVaultName(vaultName)) {
            is VaultNameValidation.Invalid -> nameError = v.error
            is VaultNameValidation.Valid -> {
                nameError = null
                step = VaultProvisioningStep.Credentials(treeUri, v.name)
            }
        }
    }

    /**
     * Create the vault: re-entrancy-guarded; confirm-match the password; call the port; persist the
     * location BEFORE revealing the phrase (a crash mid-flow then leaves an openable + remembered
     * vault); advance to [VaultProvisioningStep.Mnemonic]. [folderPath] is a fresh EMPTY directory
     * the caller has created (port contract). The caller owns zeroizing its own [password]/[confirm].
     */
    suspend fun create(folderPath: String, password: ByteArray, confirm: ByteArray) {
        if (isCreating) return
        val creds = step as? VaultProvisioningStep.Credentials ?: return
        error = null
        if (!passwordsMatch(password, confirm)) {
            error = VaultProvisioningError.PasswordMismatch
            return
        }
        isCreating = true
        try {
            val created = createPort.createInFolder(folderPath, password, creds.vaultName)
            store.persist(VaultLocation(creds.vaultName, creds.treeUri)) // persist BEFORE mnemonic
            phrase = created.phrase
            mnemonicRows = groupMnemonic(created.phrase)
            step = VaultProvisioningStep.Mnemonic
        } catch (e: VaultProvisioningError) {
            error = e
        } catch (e: Exception) {
            error = VaultProvisioningError.CreateFailed(e.message ?: e.toString())
        } finally {
            isCreating = false
        }
    }

    /** User confirmed they wrote down the phrase: wipe it + the rows, complete with the location. A
     *  null load now is a real store fault (the location was persisted during [create]) — surface it
     *  rather than stranding the user (no silent failure). */
    fun acknowledgeMnemonic() {
        if (step !is VaultProvisioningStep.Mnemonic) return
        wipePhrase()
        val loc = store.load()
        if (loc == null) {
            error = VaultProvisioningError.CreateFailed("vault location unavailable after create")
            return
        }
        step = VaultProvisioningStep.Done(loc)
    }

    /** Abandon the wizard: scrub the retained phrase + rows. Safe from any step. */
    fun cancel() = wipePhrase()

    private fun wipePhrase() {
        phrase?.fill(0)
        phrase = null
        mnemonicRows = null
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :vault-access:test --tests '*VaultProvisioningViewModelTest'`
Expected: PASS (9 tests). Then run the whole module: `./gradlew :vault-access:test` — all green.

- [ ] **Step 5: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/browse/VaultProvisioningStep.kt \
        android/vault-access/src/main/kotlin/org/secretary/browse/VaultProvisioningViewModel.kt \
        android/vault-access/src/main/kotlin/org/secretary/browse/VaultProvisioningError.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/ProvisioningFakes.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/VaultProvisioningViewModelTest.kt
git commit -m "feat(android): VaultProvisioningViewModel + step machine (cloud-drive provisioning, slice 4)"
```

---

### Task 5: `:kit` tree-display-name helper (seam, host-tested)

**Files:**
- Create: `android/kit/src/main/kotlin/org/secretary/browse/TreeDisplayName.kt`
- Test: `android/kit/src/test/kotlin/org/secretary/browse/TreeDisplayNameTest.kt`

**Interfaces:**
- Produces: `internal fun treeDisplayNameOrFallback(name: String?): String`; `fun displayNameForTree(context: Context, treeUri: Uri): String` (Android-bound factory, deferred-tested).

- [ ] **Step 1: Write the failing test**

```kotlin
package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class TreeDisplayNameTest {
    @Test
    fun `uses the provider name when present`() {
        assertEquals("Vaults", treeDisplayNameOrFallback("Vaults"))
    }

    @Test
    fun `falls back when the name is null`() {
        assertEquals("Cloud folder", treeDisplayNameOrFallback(null))
    }

    @Test
    fun `falls back when the name is blank`() {
        assertEquals("Cloud folder", treeDisplayNameOrFallback("   "))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :kit:testDebugUnitTest --tests '*TreeDisplayNameTest'`
Expected: FAIL — `treeDisplayNameOrFallback` unresolved.

- [ ] **Step 3: Write minimal implementation**

`TreeDisplayName.kt`:

```kotlin
package org.secretary.browse

import android.content.Context
import android.net.Uri
import androidx.documentfile.provider.DocumentFile

/** User-safe label when a SAF provider exposes no display name for a picked tree. */
internal const val TREE_DISPLAY_NAME_FALLBACK = "Cloud folder"

/** Pure: pick the provider's [name] if it is present and non-blank, else a safe fallback. Host-tested. */
internal fun treeDisplayNameOrFallback(name: String?): String =
    name?.takeIf { it.isNotBlank() } ?: TREE_DISPLAY_NAME_FALLBACK

/**
 * Resolve a human-readable label for a picked SAF tree [treeUri]. Android-bound (DocumentFile);
 * verified on-device, not host-tested (the pure fallback in [treeDisplayNameOrFallback] is). Used by
 * `AppRoot` to label a freshly picked folder. Mirrors the `SafCloudFolderPort` factory split (the
 * Android-bound piece lives behind a thin function; the decision logic is the host-tested pure part).
 */
fun displayNameForTree(context: Context, treeUri: Uri): String =
    treeDisplayNameOrFallback(DocumentFile.fromTreeUri(context, treeUri)?.name)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :kit:testDebugUnitTest --tests '*TreeDisplayNameTest'`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add android/kit/src/main/kotlin/org/secretary/browse/TreeDisplayName.kt \
        android/kit/src/test/kotlin/org/secretary/browse/TreeDisplayNameTest.kt
git commit -m "feat(android): tree display-name helper for the SAF picker (cloud-drive provisioning, slice 4)"
```

---

### Task 6: `VaultSelectionScreen` composable + instrumented test (`:app`)

**Files:**
- Create: `android/app/src/main/kotlin/org/secretary/app/VaultSelectionScreen.kt`
- Test: `android/app/src/androidTest/kotlin/org/secretary/app/VaultSelectionScreenUiTest.kt`

**Interfaces:**
- Consumes: `VaultSelectionState` (Task 1).
- Produces: `@Composable fun VaultSelectionScreen(state: VaultSelectionState, onCreate: () -> Unit, onOpen: () -> Unit, onChooseDifferent: () -> Unit, onPickFolder: () -> Unit, onDemo: () -> Unit)`. testTags: `create-vault`, `open-vault`, `choose-different`, `pick-folder`, `open-demo`, `selection-reason`.

> **Build/test note:** `:app` is the Android app module; its tests are instrumented (emulator). The
> per-task gate here is `./gradlew :app:compileDebugKotlin` clean + the instrumented test authored;
> the instrumented suite is run on the emulator at branch-review time (the user's toolchain has an
> AVD). Follow the existing `UnlockScreenDeviceUiTest` / `DeviceSettingsScreenUiTest` patterns.

- [ ] **Step 1: Write the failing instrumented test**

```kotlin
package org.secretary.app

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import org.junit.Rule
import org.junit.Test
import org.secretary.browse.VaultSelectionState

class VaultSelectionScreenUiTest {
    @get:Rule val rule = createComposeRule()

    @Test
    fun empty_state_offers_create_and_demo() {
        var created = false
        rule.setContent {
            VaultSelectionScreen(
                state = VaultSelectionState.Empty,
                onCreate = { created = true }, onOpen = {}, onChooseDifferent = {},
                onPickFolder = {}, onDemo = {},
            )
        }
        rule.onNodeWithTag("create-vault").assertIsDisplayed().performClick()
        rule.onNodeWithTag("open-demo").assertIsDisplayed()
        assert(created)
    }

    @Test
    fun located_state_offers_open() {
        var opened = false
        rule.setContent {
            VaultSelectionScreen(
                state = VaultSelectionState.Located("My Vault"),
                onCreate = {}, onOpen = { opened = true }, onChooseDifferent = {},
                onPickFolder = {}, onDemo = {},
            )
        }
        rule.onNodeWithTag("open-vault").assertIsDisplayed().performClick()
        rule.onNodeWithTag("choose-different").assertIsDisplayed()
        assert(opened)
    }

    @Test
    fun unavailable_state_shows_reason_and_repick() {
        rule.setContent {
            VaultSelectionScreen(
                state = VaultSelectionState.Unavailable("offline"),
                onCreate = {}, onOpen = {}, onChooseDifferent = {},
                onPickFolder = {}, onDemo = {},
            )
        }
        rule.onNodeWithTag("selection-reason").assertIsDisplayed()
        rule.onNodeWithTag("pick-folder").assertIsDisplayed()
    }
}
```

- [ ] **Step 2: Verify it fails (compile error: `VaultSelectionScreen` unresolved)**

Run: `./gradlew :app:compileDebugKotlin`
Expected: FAIL — `VaultSelectionScreen` unresolved.

- [ ] **Step 3: Write the composable**

```kotlin
package org.secretary.app

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import org.secretary.browse.VaultSelectionState

/**
 * Entry screen: choose what vault to open. Renders [VaultSelectionState]; all logic lives in
 * `VaultSelectionViewModel`. The cloud-open path ([onOpen]) is wired in `AppRoot` to the Slice-5
 * materialize-then-unlock seam; this slice's working open paths are Create and the demo vault.
 * Mirror of iOS `VaultSelectionScreen`.
 */
@Composable
fun VaultSelectionScreen(
    state: VaultSelectionState,
    onCreate: () -> Unit,
    onOpen: () -> Unit,
    onChooseDifferent: () -> Unit,
    onPickFolder: () -> Unit,
    onDemo: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("Secretary")
        when (state) {
            is VaultSelectionState.Empty -> {
                Text("No vault selected yet.")
                Button(onClick = onCreate, modifier = Modifier.fillMaxWidth().testTag("create-vault")) {
                    Text("Create new vault")
                }
                OutlinedButton(onClick = onPickFolder, modifier = Modifier.fillMaxWidth().testTag("pick-folder")) {
                    Text("Open an existing vault folder")
                }
                OutlinedButton(onClick = onDemo, modifier = Modifier.fillMaxWidth().testTag("open-demo")) {
                    Text("Open the demo vault")
                }
            }
            is VaultSelectionState.Located -> {
                Text(state.displayName)
                Button(onClick = onOpen, modifier = Modifier.fillMaxWidth().testTag("open-vault")) {
                    Text("Open")
                }
                OutlinedButton(onClick = onChooseDifferent, modifier = Modifier.fillMaxWidth().testTag("choose-different")) {
                    Text("Choose a different vault")
                }
            }
            is VaultSelectionState.Unavailable -> {
                Text(state.reason, modifier = Modifier.testTag("selection-reason"))
                Button(onClick = onPickFolder, modifier = Modifier.fillMaxWidth().testTag("pick-folder")) {
                    Text("Re-pick folder")
                }
                OutlinedButton(onClick = onDemo, modifier = Modifier.fillMaxWidth().testTag("open-demo")) {
                    Text("Open the demo vault")
                }
            }
        }
    }
}
```

- [ ] **Step 4: Verify it compiles; run the instrumented test on the emulator**

Run: `./gradlew :app:compileDebugKotlin` → BUILD SUCCESSFUL.
Branch-level (emulator): `./gradlew :app:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.app.VaultSelectionScreenUiTest`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add android/app/src/main/kotlin/org/secretary/app/VaultSelectionScreen.kt \
        android/app/src/androidTest/kotlin/org/secretary/app/VaultSelectionScreenUiTest.kt
git commit -m "feat(android): VaultSelectionScreen (cloud-drive provisioning, slice 4)"
```

---

### Task 7: `CreateVaultWizardScreen` composable + instrumented test (`:app`)

**Files:**
- Create: `android/app/src/main/kotlin/org/secretary/app/CreateVaultWizardScreen.kt`
- Test: `android/app/src/androidTest/kotlin/org/secretary/app/CreateVaultWizardScreenUiTest.kt`

**Interfaces:**
- Consumes: `VaultProvisioningStep`, `VaultNameError`, `VaultProvisioningError`, `MnemonicWord` (Tasks 2–4).
- Produces: `@Composable fun CreateVaultWizardScreen(step: VaultProvisioningStep, nameError: VaultNameError?, error: VaultProvisioningError?, isCreating: Boolean, mnemonicRows: List<MnemonicWord>?, onPickParent: () -> Unit, pickedFolderLabel: String?, onChooseFolder: (vaultName: String) -> Unit, onCreate: (password: String, confirm: String) -> Unit, onAcknowledge: () -> Unit, onCancel: () -> Unit)`. testTags: `wizard-name`, `wizard-pick-parent`, `wizard-next`, `wizard-name-error`, `wizard-password`, `wizard-confirm`, `wizard-create`, `wizard-error`, `mnemonic-grid`, `wizard-ack`, `wizard-cancel`.

> Same build/test note as Task 6 (instrumented; emulator at branch level).

- [ ] **Step 1: Write the failing instrumented test**

```kotlin
package org.secretary.app

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import org.junit.Rule
import org.junit.Test
import org.secretary.browse.MnemonicWord
import org.secretary.browse.VaultNameError
import org.secretary.browse.VaultProvisioningStep

class CreateVaultWizardScreenUiTest {
    @get:Rule val rule = createComposeRule()

    @Test
    fun folder_step_reports_name_and_pick() {
        var chosenName: String? = null
        rule.setContent {
            CreateVaultWizardScreen(
                step = VaultProvisioningStep.Folder, nameError = null, error = null,
                isCreating = false, mnemonicRows = null,
                onPickParent = {}, pickedFolderLabel = "Vaults",
                onChooseFolder = { chosenName = it }, onCreate = { _, _ -> },
                onAcknowledge = {}, onCancel = {},
            )
        }
        rule.onNodeWithTag("wizard-name").performTextInput("My Vault")
        rule.onNodeWithTag("wizard-next").performClick()
        assert(chosenName == "My Vault")
    }

    @Test
    fun folder_step_shows_name_error() {
        rule.setContent {
            CreateVaultWizardScreen(
                step = VaultProvisioningStep.Folder, nameError = VaultNameError.Blank, error = null,
                isCreating = false, mnemonicRows = null,
                onPickParent = {}, pickedFolderLabel = null,
                onChooseFolder = {}, onCreate = { _, _ -> }, onAcknowledge = {}, onCancel = {},
            )
        }
        rule.onNodeWithTag("wizard-name-error").assertIsDisplayed()
    }

    @Test
    fun mnemonic_step_shows_grid_and_acknowledges() {
        var acked = false
        rule.setContent {
            CreateVaultWizardScreen(
                step = VaultProvisioningStep.Mnemonic, nameError = null, error = null,
                isCreating = false,
                mnemonicRows = listOf(MnemonicWord(1, "alpha"), MnemonicWord(2, "bravo")),
                onPickParent = {}, pickedFolderLabel = null,
                onChooseFolder = {}, onCreate = { _, _ -> },
                onAcknowledge = { acked = true }, onCancel = {},
            )
        }
        rule.onNodeWithTag("mnemonic-grid").assertIsDisplayed()
        rule.onNodeWithTag("wizard-ack").performClick()
        assert(acked)
    }
}
```

- [ ] **Step 2: Verify it fails (compile error)**

Run: `./gradlew :app:compileDebugKotlin`
Expected: FAIL — `CreateVaultWizardScreen` unresolved.

- [ ] **Step 3: Write the composable**

```kotlin
package org.secretary.app

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
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
import org.secretary.browse.MnemonicWord
import org.secretary.browse.VaultNameError
import org.secretary.browse.VaultProvisioningError
import org.secretary.browse.VaultProvisioningStep

/**
 * Create-vault wizard. Renders [VaultProvisioningStep]; all logic lives in
 * `VaultProvisioningViewModel`. `AppRoot` resolves the empty working dir and bridges the VM's fields
 * in. Password fields are String-backed (the typed String lingers until GC — same accepted tradeoff
 * as `UnlockScreen`); the credential byte buffers are owned + zeroized by `AppRoot`. Mirror of iOS
 * `CreateVaultWizardView`.
 */
@Composable
fun CreateVaultWizardScreen(
    step: VaultProvisioningStep,
    nameError: VaultNameError?,
    error: VaultProvisioningError?,
    isCreating: Boolean,
    mnemonicRows: List<MnemonicWord>?,
    onPickParent: () -> Unit,
    pickedFolderLabel: String?,
    onChooseFolder: (vaultName: String) -> Unit,
    onCreate: (password: String, confirm: String) -> Unit,
    onAcknowledge: () -> Unit,
    onCancel: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("Create a new vault")
        when (step) {
            is VaultProvisioningStep.Folder -> {
                var name by remember { mutableStateOf("") }
                OutlinedButton(onClick = onPickParent, modifier = Modifier.fillMaxWidth().testTag("wizard-pick-parent")) {
                    Text(pickedFolderLabel?.let { "Folder: $it" } ?: "Choose a cloud folder")
                }
                OutlinedTextField(
                    value = name, onValueChange = { name = it },
                    label = { Text("Vault name") },
                    modifier = Modifier.fillMaxWidth().testTag("wizard-name"),
                )
                nameError?.let { Text(it.message ?: "Invalid name", modifier = Modifier.testTag("wizard-name-error")) }
                Button(onClick = { onChooseFolder(name) }, modifier = Modifier.fillMaxWidth().testTag("wizard-next")) {
                    Text("Next")
                }
            }
            is VaultProvisioningStep.Credentials -> {
                var password by remember { mutableStateOf("") }
                var confirm by remember { mutableStateOf("") }
                OutlinedTextField(
                    value = password, onValueChange = { password = it },
                    label = { Text("Password") }, visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth().testTag("wizard-password"),
                )
                OutlinedTextField(
                    value = confirm, onValueChange = { confirm = it },
                    label = { Text("Confirm password") }, visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth().testTag("wizard-confirm"),
                )
                error?.let { Text(it.message ?: "Create failed", modifier = Modifier.testTag("wizard-error")) }
                Button(
                    onClick = { onCreate(password, confirm) },
                    enabled = !isCreating,
                    modifier = Modifier.fillMaxWidth().testTag("wizard-create"),
                ) { Text(if (isCreating) "Creating…" else "Create vault") }
            }
            is VaultProvisioningStep.Mnemonic -> {
                Text("Write down these 24 words. They are the only way to recover this vault.")
                Column(modifier = Modifier.testTag("mnemonic-grid"), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    mnemonicRows.orEmpty().forEach { Text("${it.index}. ${it.word}") }
                }
                error?.let { Text(it.message ?: "Error", modifier = Modifier.testTag("wizard-error")) }
                Button(onClick = onAcknowledge, modifier = Modifier.fillMaxWidth().testTag("wizard-ack")) {
                    Text("I've written it down")
                }
            }
            is VaultProvisioningStep.Done -> {
                Text("Vault ready.")
            }
        }
        OutlinedButton(onClick = onCancel, modifier = Modifier.fillMaxWidth().testTag("wizard-cancel")) {
            Text("Cancel")
        }
    }
}
```

- [ ] **Step 4: Verify it compiles; run the instrumented test on the emulator**

Run: `./gradlew :app:compileDebugKotlin` → BUILD SUCCESSFUL.
Branch-level (emulator): `./gradlew :app:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.app.CreateVaultWizardScreenUiTest`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add android/app/src/main/kotlin/org/secretary/app/CreateVaultWizardScreen.kt \
        android/app/src/androidTest/kotlin/org/secretary/app/CreateVaultWizardScreenUiTest.kt
git commit -m "feat(android): CreateVaultWizardScreen (cloud-drive provisioning, slice 4)"
```

---

### Task 8: `AppRoot` routing — Selection entry + Create wizard + demo preserved + cloud-open seam (`:app`)

**Files:**
- Modify: `android/app/src/main/kotlin/org/secretary/app/AppRoot.kt`
- Create: `android/app/src/main/kotlin/org/secretary/app/ProvisioningRouting.kt` (the new Selection/Wizard route handling + the working-dir resolver, to keep `AppRoot.kt` under ~500 lines)
- Test: `android/app/src/test/kotlin/org/secretary/app/WorkingDirResolverTest.kt` (host — the pure working-dir path logic)

**Interfaces:**
- Consumes: `VaultSelectionViewModel`/`VaultSelectionState`, `VaultProvisioningViewModel`/`VaultProvisioningStep`, `VaultSelectionScreen`, `CreateVaultWizardScreen`, `SafVaultLocationStore`, `UniffiVaultCreatePort`, `displayNameForTree`, existing `unlockAndOpen`/`stageGoldenVault`.
- Produces: a `Route.Selection` entry + `Route.CreateWizard`; `internal fun workingVaultDir(filesDir: File, vaultName: String): File` (pure-ish path builder, host-tested); a named `cloud-open` seam (`fun materializeThenUnlock(...)`-shaped TODO surfaced as `markUnavailable(CLOUD_OPEN_DEFERRED_REASON)` this slice).

> **Decision encoded:** cloud-open is NOT functional this slice. `onOpen` for a remembered cloud
> location calls `selectionVm.markUnavailable(CLOUD_OPEN_DEFERRED_REASON)` ("Syncing from your cloud
> folder arrives in the next update.") — an honest, labelled affordance, not a dead button. Create
> (local working dir) and the demo are the working open paths. Slice 5 replaces the seam with
> `VaultMirror.materialize` → unlock.

- [ ] **Step 1: Write the failing host test (working-dir resolver)**

`WorkingDirResolverTest.kt`:

```kotlin
package org.secretary.app

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File

class WorkingDirResolverTest {
    @Test
    fun `working dir is a fresh empty child of files-working keyed by name`() {
        val files = File.createTempFile("files", "").let { it.delete(); it.mkdirs(); it }
        // Pre-populate a stale dir to prove it is reset.
        val stale = File(files, "working/My Vault").apply { mkdirs(); File(this, "junk").writeText("x") }
        assertTrue(File(stale, "junk").exists())

        val dir = workingVaultDir(files, "My Vault")

        assertEquals(File(files, "working/My Vault"), dir)
        assertTrue(dir.isDirectory)
        assertTrue(dir.list()!!.isEmpty()) // emptied for the createInFolder contract
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run (from `android/`): `./gradlew :app:testDebugUnitTest --tests '*WorkingDirResolverTest'`
Expected: FAIL — `workingVaultDir` unresolved.

- [ ] **Step 3: Write the resolver + routing**

`ProvisioningRouting.kt` (new file; resolver + helpers, keeps `AppRoot.kt` small):

```kotlin
package org.secretary.app

import java.io.File

/** User-safe copy for the not-yet-wired cloud-open path (Slice 5 replaces the seam with materialize). */
const val CLOUD_OPEN_DEFERRED_REASON = "Syncing from your cloud folder arrives in the next update."

/**
 * The empty working directory the core creates a new vault into (`createInFolder`'s contract is an
 * existing empty dir). A fresh child of `filesDir/working/` keyed by the validated [vaultName]
 * (no path separators — validated upstream). Any stale directory from a prior interrupted create is
 * reset so the create never sees a non-empty target. The cloud flush of this dir is Slice 5.
 */
internal fun workingVaultDir(filesDir: File, vaultName: String): File {
    val dir = File(filesDir, "working/$vaultName")
    dir.deleteRecursively()
    dir.mkdirs()
    return dir
}
```

Then modify `AppRoot.kt`:
1. Add to the `Route` sealed interface:

```kotlin
    data object Selection : Route
    data object CreateWizard : Route
```

2. Change the initial route from `Route.Unlock` to `Route.Selection`:

```kotlin
    var route by remember { mutableStateOf<Route>(Route.Selection) }
```

3. Build the provisioning view models + store + create-port + SAF launcher near the other `remember`s:

```kotlin
    val locationStore = remember { safVaultLocationStore(context) }
    val selectionVm = remember(locationStore) { VaultSelectionViewModel(locationStore) }
    var selectionState by remember { mutableStateOf<VaultSelectionState>(VaultSelectionState.Empty) }
    val provisioningVm = remember(locationStore) {
        VaultProvisioningViewModel(uniffiVaultCreatePort(), locationStore)
    }
    // mirror the VM's published fields into Compose state on each recomposition trigger
    var provStep by remember { mutableStateOf<VaultProvisioningStep>(VaultProvisioningStep.Folder) }
    var pickedTreeUri by remember { mutableStateOf<String?>(null) }
    var pickedFolderLabel by remember { mutableStateOf<String?>(null) }

    val pickFolderLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocumentTree(),
    ) { uri ->
        if (uri != null) {
            pickedTreeUri = uri.toString()
            pickedFolderLabel = displayNameForTree(context, uri)
        }
    }

    LaunchedEffect(route) {
        if (route is Route.Selection) { selectionVm.loadPersisted(); selectionState = selectionVm.state }
    }
```

4. Add the `Route.Selection` and `Route.CreateWizard` arms to the top-level `when (val r = route)` (full handlers — Selection screen wiring, wizard wiring with the working-dir resolve + offload, demo + cloud-open seam):

```kotlin
        is Route.Selection -> VaultSelectionScreen(
            state = selectionState,
            onCreate = {
                pickedTreeUri = null; pickedFolderLabel = null
                route = Route.CreateWizard
            },
            onOpen = {
                // Slice-5 seam: cloud open needs materialize. Surface an honest, labelled affordance.
                selectionVm.markUnavailable(CLOUD_OPEN_DEFERRED_REASON)
                selectionState = selectionVm.state
            },
            onChooseDifferent = { selectionVm.chooseDifferent(); selectionState = selectionVm.state },
            onPickFolder = { pickFolderLauncher.launch(null) },
            onDemo = {
                // The existing, working demo open path (unchanged).
                scope.launch {
                    route = unlockAndOpen(
                        context, scope,
                        UnlockCredential.Password(AppVaultProvisioning.goldenPassword(context).toByteArray()),
                        enrollAfter = false, coordinator, vaultId,
                    )
                }
            },
        )
        is Route.CreateWizard -> CreateVaultWizardScreen(
            step = provStep,
            nameError = provisioningVm.nameError,
            error = provisioningVm.error,
            isCreating = provisioningVm.isCreating,
            mnemonicRows = provisioningVm.mnemonicRows,
            onPickParent = { pickFolderLauncher.launch(null) },
            pickedFolderLabel = pickedFolderLabel,
            onChooseFolder = { name ->
                val tree = pickedTreeUri
                if (tree == null) {
                    Toast.makeText(context, "Choose a cloud folder first.", Toast.LENGTH_SHORT).show()
                } else {
                    provisioningVm.chooseFolder(tree, name)
                    provStep = provisioningVm.step
                }
            },
            onCreate = { password, confirm ->
                val pwBytes = password.toByteArray()
                val confirmBytes = confirm.toByteArray()
                val creds = provisioningVm.step as? VaultProvisioningStep.Credentials
                if (creds != null) {
                    val workingDir = workingVaultDir(context.filesDir, creds.vaultName)
                    scope.launch {
                        try {
                            provisioningVm.create(workingDir.path, pwBytes, confirmBytes)
                        } finally {
                            pwBytes.fill(0); confirmBytes.fill(0)
                        }
                        provStep = provisioningVm.step
                    }
                }
            },
            onAcknowledge = {
                provisioningVm.acknowledgeMnemonic()
                val done = provisioningVm.step as? VaultProvisioningStep.Done
                if (done != null) {
                    // Open the freshly created LOCAL working copy (cloud flush = Slice 5). Re-derive
                    // its path from the same resolver so the open targets the exact created dir.
                    val workingDir = File(context.filesDir, "working/${done.location.displayName}")
                    scope.launch {
                        route = unlockAndOpenFolder(context, scope, workingDir, coordinator, vaultId)
                    }
                } else {
                    provStep = provisioningVm.step // surfaces the store-fault error on the mnemonic step
                }
            },
            onCancel = { provisioningVm.cancel(); route = Route.Selection },
        )
```

5. The existing demo open path uses `unlockAndOpen(... stageGoldenVault ...)`. Add a sibling
   `unlockAndOpenFolder(context, scope, folder, coordinator, vaultId)` that opens an ALREADY-staged
   real folder (factor the body of `unlockAndOpen` after `stageGoldenVault` into it; `unlockAndOpen`
   then calls `stageGoldenVault` and delegates). This avoids duplicating the open/sync assembly.

```kotlin
private suspend fun unlockAndOpenFolder(
    context: Context,
    scope: CoroutineScope,
    folder: File,
    coordinator: DeviceUnlockCoordinator,
    vaultId: String,
): Route {
    // For a freshly created vault we don't know the user's password as bytes here (it was zeroized
    // after create), so route to the Unlock screen for this folder instead of auto-opening.
    return Route.UnlockFolder(folder)
}
```

> **Refinement:** the cleanest honest behaviour after create is to route to the existing
> `UnlockScreen` bound to the new folder (the user just set the password; unlocking it confirms the
> round-trip and avoids carrying the password bytes further). Add a `Route.UnlockFolder(val folder: File)`
> arm that renders `UnlockScreen` and, on submit, calls `unlockAndOpen`-style open against `folder`.
> The demo path stays on the golden-vault `unlockAndOpen`. Keep the `Route.Unlock` golden path intact.

- [ ] **Step 4: Verify the host resolver test passes + `:app` compiles**

Run: `./gradlew :app:testDebugUnitTest --tests '*WorkingDirResolverTest'` → PASS.
Run: `./gradlew :app:compileDebugKotlin` → BUILD SUCCESSFUL.

- [ ] **Step 5: Commit**

```bash
git add android/app/src/main/kotlin/org/secretary/app/AppRoot.kt \
        android/app/src/main/kotlin/org/secretary/app/ProvisioningRouting.kt \
        android/app/src/test/kotlin/org/secretary/app/WorkingDirResolverTest.kt
git commit -m "feat(android): AppRoot routing — selection entry + create wizard + cloud-open seam (cloud-drive provisioning, slice 4)"
```

---

### Task 9: README + ROADMAP capability entry

**Files:**
- Modify: `README.md`
- Modify: `ROADMAP.md`

**Interfaces:** none (docs).

- [ ] **Step 1: Locate the Android status sections**

Run: `rg -n 'Android' README.md ROADMAP.md` and read the surrounding Android status block in each.

- [ ] **Step 2: Add the capability entry (brief, accurate, audience-aware)**

In each file's Android section, add a single dot point matching the existing style, worded so it
does NOT overclaim — the provisioning **UI + routing** ships now; the **cloud working-copy
round-trip** (materialize/flush) lands in the next slice. Example wording (adapt to each file's
voice; do not paste verbatim if the surrounding bullets differ):

> - Vault provisioning UI: create-new-vault wizard and folder selection screen with `AppRoot`
>   routing (the cloud-drive working-copy sync that completes open/create lands in the following
>   slice).

Keep it to one or two dot points per [[feedback_readme_style]] — no test-count walls.

- [ ] **Step 3: Verify the docs render and are accurate**

Re-read the edited blocks; confirm no claim that cloud open/sync is functional yet.

- [ ] **Step 4: Commit**

```bash
git add README.md ROADMAP.md
git commit -m "docs: Android vault provisioning UI capability entry (cloud-drive provisioning, slice 4)"
```

---

## Self-Review

**Spec coverage:**
- View models (row #4): Tasks 1 (`VaultSelectionViewModel`) + 4 (`VaultProvisioningViewModel`). ✓
- Screens + SAF launchers + AppRoot routing (row #5): Tasks 6, 7, 8 + the launcher in Task 8; `:kit` name helper Task 5. ✓
- Pure helpers (`validateVaultName`, `groupMnemonic`): Tasks 2, 3. ✓
- Demo entry preserved: Task 8 (`onDemo` → existing `unlockAndOpen`; `Route.Unlock` golden path intact). ✓
- Cloud-open = Slice-5 seam (no dead button): Task 8 (`CLOUD_OPEN_DEFERRED_REASON`). ✓
- Create round-trips locally: Task 8 (`workingVaultDir` + create → `UnlockFolder`). ✓
- README/ROADMAP entry now, accurately worded: Task 9. ✓
- Testing: host VM/helper tests (Tasks 1–5, 8-resolver); instrumented screen tests (Tasks 6–7, emulator at branch level). ✓
- No core/FFI/format/spec/KAT change: enforced by Global Constraints; verify with the branch diff at review. ✓

**Placeholder scan:** No "TBD/TODO-implement-later". The one explicit *deferral* (cloud-open seam) is an intentional, named, tested behaviour, not a placeholder.

**Type consistency:** `VaultSelectionState` arms (`Empty`/`Located`/`Unavailable`) consistent across Tasks 1, 6, 8. `VaultProvisioningStep` arms (`Folder`/`Credentials(treeUri,vaultName)`/`Mnemonic`/`Done(location)`) consistent across Tasks 4, 7, 8. `VaultProvisioningError.PasswordMismatch` added in Task 4, consumed in Task 7's screen. `createInFolder(folderPath, password, displayName)` matches the existing Slice-1 port. `groupMnemonic(ByteArray)` / `MnemonicWord(index, word)` consistent Tasks 3, 4, 7.

**Risk note for the executor:** Task 8 is the integration task and the largest; its exact `AppRoot`
edits depend on the current file (read it fresh before editing). Keep `AppRoot.kt` under ~500 lines by
moving the new route handlers' helpers into `ProvisioningRouting.kt`; if `AppRoot.kt` still approaches
the threshold, extract the Selection/Wizard `when` arms into `@Composable` functions in that file.
