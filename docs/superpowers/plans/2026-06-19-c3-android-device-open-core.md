# C.3 Android device-secret open — slice 1 (pure core + FFI adapter) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give an enrolled Android device a third unlock credential — a per-device wrap secret — so it can open the vault without the password or recovery phrase, delivered as the pure, host-tested orchestration plus the real `:kit` FFI adapter, proven end-to-end against the real `.so` with a fake in-memory enclave. (No biometric, no UI — that is slice 2.)

**Architecture:** Mirror iOS's pure `SecretaryDeviceUnlock`: a `DeviceUnlockCoordinator` orchestrating three ports — `VaultDeviceSlotPort` (slot mint/remove FFI), `DeviceSecretEnclave` (secret store/release, biometric in slice 2), `DeviceEnrollmentMetadataStore` (non-secret enrollment metadata). The device *open* itself joins the existing `VaultOpenPort` as `openWithDeviceSecret` and flows through the existing `openWithCredential` pipeline via a new `UnlockCredential.DeviceSecret` arm; the coordinator's `unlock` returns that credential rather than opening directly.

**Tech Stack:** Kotlin, Gradle multi-module (`:vault-access` pure JVM / `:kit` Android+uniffi / `:app`), JUnit5 (jupiter) + kotlinx-coroutines-test for host tests, AndroidJUnit4 + a running emulator for the instrumented test, uniffi-generated `uniffi.secretary` bindings (already include the device functions — regenerated from the cdylib at build time, never committed).

## Global Constraints

- **Android-only.** No change to `core/`, `ffi/`, `ios/`, the on-disk format, or the UDL. The device FFI (`add_device_slot` / `open_with_device_secret` / `remove_device_slot`) is already in the UDL and generated into the Kotlin bindings at build time.
- **Anti-oracle (threat-model §13):** `WrongDeviceSecretOrCorrupt` stays conflated — a payload-free `data object`. Do NOT split wrong-secret from corruption.
- **Exhaustive `when` over `UnlockCredential`, no `else`** — a future credential must be a compile error, not a silent drop.
- **`mapVaultBrowseError`:** add explicit arms ABOVE the `else` fold (the `else` silently swallows new arms — file carries a maintainer warning).
- **Secret hygiene:** `add_device_slot`'s one-shot `DeviceSecretOutput` is `take_secret()`-ed once then `wipe()`-d in a `finally`. The coordinator zeroizes its `EnrolledSlot.secret` copy in `enroll`'s `finally`; `enclave.store` MUST copy (so the caller may zeroize after it returns). On `unlock`, secret ownership passes to the returned credential — the caller zeroizes it.
- **File-size / one-concept-per-file:** each new type is its own file; all stay well under 500 lines.
- **Package:** all new `:vault-access` and `:kit` files are in package `org.secretary.browse` (matching the existing unlock/open code).
- **TDD:** test first, watch it fail (Kotlin: a reference to an undefined symbol fails compilation — that is the red), implement minimally, watch it pass, commit.

**Worktree:** all work happens in `/Users/hherb/src/secretary/.worktrees/c3-android-device-open-core` on branch `feature/c3-android-device-open-core`. Gradle runs from its `android/` subdir.

**Commands (copy exactly):**
```bash
# Host suites (no emulator):
cd /Users/hherb/src/secretary/.worktrees/c3-android-device-open-core/android && ./gradlew :vault-access:test
cd /Users/hherb/src/secretary/.worktrees/c3-android-device-open-core/android && ./gradlew :kit:test
# Instrumented (emulator must be running; pin the emulator — a physical device may also be attached):
cd /Users/hherb/src/secretary/.worktrees/c3-android-device-open-core/android && \
  ANDROID_SERIAL=emulator-5554 PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :app:connectedDebugAndroidTest
# One instrumented test by FQN (connectedAndroidTest rejects --tests):
#   ... ./gradlew :app:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.app.OpenWithDeviceSecretSmokeTest
```

---

### Task 1: `VaultBrowseError` device variants + `:kit` error mapping

**Files:**
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseError.kt`
- Modify: `android/kit/src/main/kotlin/org/secretary/browse/BrowseMapping.kt`
- Test: `android/kit/src/test/kotlin/org/secretary/browse/BrowseMappingTest.kt` (extend)

**Interfaces:**
- Produces: `VaultBrowseError.WrongDeviceSecretOrCorrupt` (object), `VaultBrowseError.DeviceSlotNotFound` (object), `VaultBrowseError.DeviceUuidMismatch(detail: String)`; `mapVaultBrowseError` handles the three `VaultException` device arms.
- Consumes: generated `uniffi.secretary.VaultException.{WrongDeviceSecretOrCorrupt, DeviceSlotNotFound, DeviceUuidMismatch}` (constructible in a host test without loading the `.so`).

- [ ] **Step 1: Write the failing test** — append to `BrowseMappingTest.kt`:

```kotlin
    @Test
    fun `maps the device-secret-relevant arms to their domain counterparts`() {
        assertEquals(
            VaultBrowseError.WrongDeviceSecretOrCorrupt,
            mapVaultBrowseError(VaultException.WrongDeviceSecretOrCorrupt()),
        )
        assertEquals(
            VaultBrowseError.DeviceSlotNotFound,
            mapVaultBrowseError(VaultException.DeviceSlotNotFound()),
        )
        assertEquals(
            VaultBrowseError.DeviceUuidMismatch("relabelled"),
            mapVaultBrowseError(VaultException.DeviceUuidMismatch("relabelled")),
        )
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-device-open-core/android && ./gradlew :kit:test`
Expected: FAIL — compilation error, `VaultBrowseError.WrongDeviceSecretOrCorrupt` unresolved.

- [ ] **Step 3a: Add the variants** — in `VaultBrowseError.kt`, after the `InvalidRecoveryPhrase` block (keep the recovery group together) add:

```kotlin
    /** Device-secret open failed: wrong device secret OR corrupt wrap/vault. Conflated on purpose (§13). */
    data object WrongDeviceSecretOrCorrupt : VaultBrowseError()

    /** No `devices/<uuid>.wrap` slot for the requested device UUID (benign "no such device"). */
    data object DeviceSlotNotFound : VaultBrowseError()

    /** The wrap file's header device_uuid ≠ the lookup UUID (§3a relabel-integrity check). A
     *  structural-integrity signal, safe to surface. */
    data class DeviceUuidMismatch(val detail: String) : VaultBrowseError(detail)
```

- [ ] **Step 3b: Add the mapping arms** — in `BrowseMapping.kt`, immediately ABOVE the `else ->` line, add:

```kotlin
    is VaultException.WrongDeviceSecretOrCorrupt -> VaultBrowseError.WrongDeviceSecretOrCorrupt
    is VaultException.DeviceSlotNotFound -> VaultBrowseError.DeviceSlotNotFound
    is VaultException.DeviceUuidMismatch -> VaultBrowseError.DeviceUuidMismatch(e.detail)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-device-open-core/android && ./gradlew :kit:test`
Expected: PASS. (If a variant name is unresolved, the generated bindings renamed it — check the build output for the actual `VaultException.*` name and the `.detail` property name; one-line fix per the uniffi-codegen-rename memo.)

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-device-open-core
git add android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseError.kt \
        android/kit/src/main/kotlin/org/secretary/browse/BrowseMapping.kt \
        android/kit/src/test/kotlin/org/secretary/browse/BrowseMappingTest.kt
git commit -m "feat(android): VaultBrowseError device-secret arms + :kit mapping"
```

---

### Task 2: `UnlockCredential.DeviceSecret` arm + `VaultOpenPort.openWithDeviceSecret` seam

**Files:**
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/UnlockCredential.kt`
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultOpenPort.kt`
- Modify: `android/vault-access/src/test/kotlin/org/secretary/browse/FakeVaultBrowse.kt` (extend `FakeVaultOpenPort`)
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/UnlockCredentialTest.kt` (extend)

**Interfaces:**
- Consumes: `FakeVaultOpenPort` (existing scriptable port).
- Produces:
  - `UnlockCredential.DeviceSecret(deviceUuid: ByteArray /*16*/, override val secret: ByteArray /*32*/)`.
  - `openWithCredential` routes `DeviceSecret` → `openPort.openWithDeviceSecret(vaultFolder, deviceUuid, secret)`.
  - `VaultOpenPort.openWithDeviceSecret(vaultFolder: String, deviceUuid: ByteArray, deviceSecret: ByteArray): VaultSession`.
  - `FakeVaultOpenPort.openedWithDeviceSecret: MutableList<Pair<ByteArray, ByteArray>>` (uuid to secret copies) and ctor param `deviceSecretError: VaultBrowseError? = null`.

- [ ] **Step 1: Write the failing test** — append to `UnlockCredentialTest.kt`:

```kotlin
    @Test
    fun `a device-secret credential opens via openWithDeviceSecret with the uuid and secret`() = runTest {
        val port = FakeVaultOpenPort()
        val uuid = ByteArray(16) { it.toByte() }
        openWithCredential(port, "/vault", UnlockCredential.DeviceSecret(uuid, byteArrayOf(9, 8, 7)))
        assertEquals(1, port.openedWithDeviceSecret.size)
        assertArrayEquals(uuid, port.openedWithDeviceSecret[0].first)
        assertArrayEquals(byteArrayOf(9, 8, 7), port.openedWithDeviceSecret[0].second)
        assertTrue(port.openedWithPassword.isEmpty(), "password path must not fire for a device-secret credential")
        assertTrue(port.openedWithRecovery.isEmpty(), "recovery path must not fire for a device-secret credential")
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-device-open-core/android && ./gradlew :vault-access:test`
Expected: FAIL — compilation error, `UnlockCredential.DeviceSecret` / `openWithDeviceSecret` / `openedWithDeviceSecret` unresolved.

- [ ] **Step 3a: Add the credential arm + dispatch** — in `UnlockCredential.kt`, add to the sealed interface body (after `Recovery`):

```kotlin
    /** A per-device wrap secret released from the device enclave. [deviceUuid] (16 bytes) locates the
     *  `devices/<uuid>.wrap` slot; [secret] (32 bytes) is the raw device secret. The caller owns
     *  zeroizing [secret] after the open returns. */
    class DeviceSecret(
        val deviceUuid: ByteArray,
        override val secret: ByteArray,
    ) : UnlockCredential
```

and add the dispatch arm to the `when` in `openWithCredential` (before the closing brace, keeping it exhaustive):

```kotlin
    is UnlockCredential.DeviceSecret ->
        openPort.openWithDeviceSecret(vaultFolder, credential.deviceUuid, credential.secret)
```

- [ ] **Step 3b: Add the port seam** — in `VaultOpenPort.kt`, add to the `VaultOpenPort` interface (after `openWithRecovery`):

```kotlin
    /**
     * Opens a vault folder with a per-device wrap secret. [deviceUuid] is the 16-byte slot UUID;
     * [deviceSecret] is the raw 32-byte secret, forwarded per call and never retained. Goes through
     * the same manifest verify-before-decrypt as the password/recovery paths (never a weaker open).
     * Mirror of iOS `VaultDeviceSlotPort.openWithDeviceSecret`.
     */
    suspend fun openWithDeviceSecret(
        vaultFolder: String,
        deviceUuid: ByteArray,
        deviceSecret: ByteArray,
    ): VaultSession
```

- [ ] **Step 3c: Extend the fake** — in `FakeVaultBrowse.kt`, in `FakeVaultOpenPort`: add the ctor param `deviceSecretError: VaultBrowseError? = null,` (after `recoveryError`), the recording list, and the override:

```kotlin
    /** (uuid, secret) copies seen by each openWithDeviceSecret call, in order. */
    val openedWithDeviceSecret: MutableList<Pair<ByteArray, ByteArray>> = mutableListOf()

    override suspend fun openWithDeviceSecret(
        vaultFolder: String,
        deviceUuid: ByteArray,
        deviceSecret: ByteArray,
    ): VaultSession {
        openedFolders += vaultFolder
        openedWithDeviceSecret += deviceUuid.copyOf() to deviceSecret.copyOf()
        deviceSecretError?.let { throw it }
        return session
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-device-open-core/android && ./gradlew :vault-access:test`
Expected: PASS (all `UnlockCredentialTest` cases green; the exhaustive `when` now covers three arms).

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-device-open-core
git add android/vault-access/src/main/kotlin/org/secretary/browse/UnlockCredential.kt \
        android/vault-access/src/main/kotlin/org/secretary/browse/VaultOpenPort.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/FakeVaultBrowse.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/UnlockCredentialTest.kt
git commit -m "feat(android): UnlockCredential.DeviceSecret arm + VaultOpenPort.openWithDeviceSecret seam"
```

---

### Task 3: Coordinator ports, value types, error type, and in-memory fakes

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultDeviceSlotPort.kt`
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/DeviceSecretEnclave.kt`
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/DeviceEnrollmentMetadataStore.kt`
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/DeviceUnlockError.kt`
- Create: `android/vault-access/src/test/kotlin/org/secretary/browse/DeviceUnlockFakes.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/DeviceUnlockFakesTest.kt`

**Interfaces:**
- Produces (consumed by Tasks 4–8):
  - `EnrolledSlot(val deviceUuid: ByteArray, val secret: ByteArray)`.
  - `interface VaultDeviceSlotPort { suspend fun addDeviceSlot(vaultFolder, password): EnrolledSlot; suspend fun removeDeviceSlot(vaultFolder, deviceUuid) }`.
  - `interface DeviceSecretEnclave { val isEnrolled: Boolean; suspend fun store(secret); suspend fun release(reason): ByteArray; suspend fun clear() }`.
  - `DeviceEnrollment(val vaultId: String, val deviceUuid: ByteArray)` + `interface DeviceEnrollmentMetadataStore { load(): DeviceEnrollment?; save(e); clear() }`.
  - `sealed class DeviceUnlockError : Exception` with `NotEnrolled`, `VaultSlotMismatch`, `BiometryUnavailable`, `BiometryNotEnrolled`, `BiometryLockout`, `UserCancelled`, `AuthenticationFailed`, `WrappedSecretCorrupt`, `Enclave(detail)`.
  - Test fakes: `FakeVaultDeviceSlotPort`, `FakeDeviceSecretEnclave`, `FakeEnrollmentMetadataStore`.

- [ ] **Step 1: Write the failing test** — create `DeviceUnlockFakesTest.kt`:

```kotlin
package org.secretary.browse

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class DeviceUnlockFakesTest {
    @Test
    fun `enclave store then release round-trips a COPY and clear empties it`() = runTest {
        val enclave = FakeDeviceSecretEnclave()
        assertFalse(enclave.isEnrolled)
        val source = byteArrayOf(1, 2, 3, 4)
        enclave.store(source)
        source.fill(0) // caller zeroizes its array; the enclave must hold its own copy
        assertTrue(enclave.isEnrolled)
        assertArrayEquals(byteArrayOf(1, 2, 3, 4), enclave.release("why"))
        enclave.clear()
        assertFalse(enclave.isEnrolled)
    }

    @Test
    fun `slot port records adds and removes and supports error injection`() = runTest {
        val port = FakeVaultDeviceSlotPort(
            deviceUuid = ByteArray(16) { 7 },
            issuedSecret = ByteArray(32) { 9 },
        )
        val slot = port.addDeviceSlot("/vault", byteArrayOf(0))
        assertArrayEquals(ByteArray(16) { 7 }, slot.deviceUuid)
        assertEquals(1, port.addCalls.size)
        port.removeDeviceSlot("/vault", slot.deviceUuid)
        assertEquals(1, port.removeCalls.size)
    }

    @Test
    fun `metadata store loads what it saved and clears`() {
        val store = FakeEnrollmentMetadataStore()
        assertNull(store.load())
        store.save(DeviceEnrollment("golden", ByteArray(16) { 3 }))
        assertEquals("golden", store.load()!!.vaultId)
        store.clear()
        assertNull(store.load())
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-device-open-core/android && ./gradlew :vault-access:test`
Expected: FAIL — compilation error, the fakes / ports / types are unresolved.

- [ ] **Step 3a: Create `VaultDeviceSlotPort.kt`:**

```kotlin
package org.secretary.browse

/**
 * The FFI seam for device-slot management (mint / revoke). Separate from [VaultOpenPort] because the
 * device *open* is a credential open (it lives on [VaultOpenPort.openWithDeviceSecret]); this port is
 * slot lifecycle only. The real impl (`:kit` `UniffiVaultDeviceSlotPort`) wraps `add_device_slot` /
 * `remove_device_slot`. Mirror of the mint/remove half of iOS `VaultDeviceSlotPort`.
 *
 * Implementations throw [VaultBrowseError] (e.g. [VaultBrowseError.DeviceSlotNotFound] from
 * [removeDeviceSlot] when the slot is already gone).
 */
interface VaultDeviceSlotPort {
    /** Password-open the vault and mint a fresh device slot, writing `devices/<uuid>.wrap`. Returns
     *  the new 16-byte UUID + the raw 32-byte secret. The caller owns zeroizing [EnrolledSlot.secret]. */
    suspend fun addDeviceSlot(vaultFolder: String, password: ByteArray): EnrolledSlot

    /** Revoke a device slot (delete `devices/<uuid>.wrap`). Throws [VaultBrowseError.DeviceSlotNotFound]
     *  if the slot does not exist. */
    suspend fun removeDeviceSlot(vaultFolder: String, deviceUuid: ByteArray)
}

/** A freshly-minted device slot: its 16-byte [deviceUuid] (non-secret) and raw 32-byte [secret]. */
class EnrolledSlot(val deviceUuid: ByteArray, val secret: ByteArray)
```

- [ ] **Step 3b: Create `DeviceSecretEnclave.kt`:**

```kotlin
package org.secretary.browse

/**
 * Stores the raw 32-byte device secret and releases it on demand. In slice 1 this is faked
 * in-memory; in slice 2 the real impl is an Android Keystore/StrongBox key whose [release] is gated
 * by `BiometricPrompt` (hence [release] is `suspend`). Mirror of iOS `DeviceSecretEnclave`.
 *
 * Implementations throw [DeviceUnlockError] (e.g. [DeviceUnlockError.UserCancelled] from a cancelled
 * biometric prompt, [DeviceUnlockError.WrappedSecretCorrupt] from real ciphertext corruption).
 */
interface DeviceSecretEnclave {
    /** True iff a secret is stored. A cheap, non-prompting check (no biometric). */
    val isEnrolled: Boolean

    /** Store [secret], taking an internal COPY — the caller may zeroize its array after this returns. */
    suspend fun store(secret: ByteArray)

    /** Release the stored secret (slice 2: behind a biometric prompt explained by [reason]). The
     *  returned array is caller-owned; the caller zeroizes it after use. */
    suspend fun release(reason: String): ByteArray

    /** Drop the stored secret. Idempotent. */
    suspend fun clear()
}
```

- [ ] **Step 3c: Create `DeviceEnrollmentMetadataStore.kt`:**

```kotlin
package org.secretary.browse

/**
 * Persists the NON-secret device-enrollment metadata (which vault, which slot UUID) so [unlock] can
 * detect a stale enrollment before touching the enclave. In slice 1 faked in-memory; in slice 2 a
 * small Keystore-free store (e.g. encrypted prefs). Mirror of iOS `DeviceEnrollmentMetadataStore`.
 */
interface DeviceEnrollmentMetadataStore {
    fun load(): DeviceEnrollment?
    fun save(enrollment: DeviceEnrollment)
    fun clear()
}

/** Non-secret enrollment metadata: the opaque [vaultId] token and the 16-byte slot [deviceUuid]. */
class DeviceEnrollment(val vaultId: String, val deviceUuid: ByteArray)
```

- [ ] **Step 3d: Create `DeviceUnlockError.kt`:**

```kotlin
package org.secretary.browse

/**
 * Errors from the device-unlock coordinator + enclave. Throwable so callers can `catch`. The
 * coordinator itself raises [NotEnrolled] / [VaultSlotMismatch]; the remaining arms are raised by a
 * real [DeviceSecretEnclave] (slice 2) and propagated unchanged. Mirror of iOS `DeviceUnlockError`.
 *
 * (Open-time failures — wrong secret / corrupt / slot-gone — surface as [VaultBrowseError] from the
 * shared `openWithCredential` pipeline, NOT here, because the coordinator returns a credential
 * instead of opening.)
 */
sealed class DeviceUnlockError(message: String? = null) : Exception(message) {
    /** No enrollment metadata — the device was never enrolled (or was disenrolled). */
    data object NotEnrolled : DeviceUnlockError()

    /** The stored enrollment is for a different vault than the one requested. */
    data object VaultSlotMismatch : DeviceUnlockError()

    /** Biometry hardware/feature unavailable on this device. */
    data object BiometryUnavailable : DeviceUnlockError()

    /** No biometric is enrolled on the device. */
    data object BiometryNotEnrolled : DeviceUnlockError()

    /** Too many failed attempts — biometry is temporarily locked out. */
    data object BiometryLockout : DeviceUnlockError()

    /** The user cancelled the biometric prompt. */
    data object UserCancelled : DeviceUnlockError()

    /** The biometric attempt failed (not a match). */
    data object AuthenticationFailed : DeviceUnlockError()

    /** The wrapped secret could not be decrypted — actual ciphertext corruption (never an auth failure). */
    data object WrappedSecretCorrupt : DeviceUnlockError()

    /** Any other Keystore/enclave error. */
    data class Enclave(val detail: String) : DeviceUnlockError(detail)
}
```

- [ ] **Step 3e: Create the fakes `DeviceUnlockFakes.kt`:**

```kotlin
package org.secretary.browse

/**
 * In-memory [VaultDeviceSlotPort] for host tests. Records every add/remove; returns a fresh COPY of
 * [issuedSecret] from each [addDeviceSlot] (so a coordinator that zeroizes its slot copy cannot
 * corrupt the fake's source); supports per-method error injection.
 */
class FakeVaultDeviceSlotPort(
    private val deviceUuid: ByteArray = ByteArray(16) { 1 },
    private val issuedSecret: ByteArray = ByteArray(32) { 2 },
    private val addError: Throwable? = null,
    private val removeError: Throwable? = null,
) : VaultDeviceSlotPort {
    val addCalls: MutableList<String> = mutableListOf()
    val removeCalls: MutableList<ByteArray> = mutableListOf()
    /** The exact array handed to the most recent caller (so a test can assert it was zeroized). */
    var lastIssuedSecret: ByteArray? = null
        private set

    override suspend fun addDeviceSlot(vaultFolder: String, password: ByteArray): EnrolledSlot {
        addCalls += vaultFolder
        addError?.let { throw it }
        val secret = issuedSecret.copyOf()
        lastIssuedSecret = secret
        return EnrolledSlot(deviceUuid.copyOf(), secret)
    }

    override suspend fun removeDeviceSlot(vaultFolder: String, deviceUuid: ByteArray) {
        removeCalls += deviceUuid.copyOf()
        removeError?.let { throw it }
    }
}

/** In-memory [DeviceSecretEnclave]: holds a COPY of the stored secret; supports error injection. */
class FakeDeviceSecretEnclave(
    private val storeError: Throwable? = null,
    private val releaseError: Throwable? = null,
) : DeviceSecretEnclave {
    private var stored: ByteArray? = null
    override val isEnrolled: Boolean get() = stored != null

    override suspend fun store(secret: ByteArray) {
        storeError?.let { throw it }
        stored = secret.copyOf()
    }

    override suspend fun release(reason: String): ByteArray {
        releaseError?.let { throw it }
        return stored?.copyOf() ?: throw DeviceUnlockError.NotEnrolled
    }

    override suspend fun clear() {
        stored?.fill(0)
        stored = null
    }
}

/** In-memory [DeviceEnrollmentMetadataStore]; supports save-error injection for rollback tests. */
class FakeEnrollmentMetadataStore(
    private val saveError: Throwable? = null,
) : DeviceEnrollmentMetadataStore {
    private var enrollment: DeviceEnrollment? = null
    override fun load(): DeviceEnrollment? = enrollment
    override fun save(enrollment: DeviceEnrollment) {
        saveError?.let { throw it }
        this.enrollment = enrollment
    }
    override fun clear() { enrollment = null }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-device-open-core/android && ./gradlew :vault-access:test`
Expected: PASS (`DeviceUnlockFakesTest` green).

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-device-open-core
git add android/vault-access/src/main/kotlin/org/secretary/browse/VaultDeviceSlotPort.kt \
        android/vault-access/src/main/kotlin/org/secretary/browse/DeviceSecretEnclave.kt \
        android/vault-access/src/main/kotlin/org/secretary/browse/DeviceEnrollmentMetadataStore.kt \
        android/vault-access/src/main/kotlin/org/secretary/browse/DeviceUnlockError.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/DeviceUnlockFakes.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/DeviceUnlockFakesTest.kt
git commit -m "feat(android): device-unlock coordinator ports, types, error + in-memory fakes"
```

---

### Task 4: `DeviceUnlockCoordinator.enroll` (transactional) + `isEnrolled`

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/DeviceUnlockCoordinator.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/DeviceUnlockCoordinatorTest.kt`

**Interfaces:**
- Consumes: `VaultDeviceSlotPort`, `DeviceSecretEnclave`, `DeviceEnrollmentMetadataStore`, `EnrolledSlot`, `DeviceEnrollment` (Task 3); the fakes (Task 3).
- Produces:
  - `class DeviceUnlockCoordinator(slotPort, enclave, metadata)`.
  - `suspend fun enroll(folder: String, vaultId: String, password: ByteArray)` — `addDeviceSlot` → `enclave.store` → `metadata.save`; rolls back on any failure; zeroizes the slot secret in `finally`.
  - `val isEnrolled: Boolean`.

- [ ] **Step 1: Write the failing test** — create `DeviceUnlockCoordinatorTest.kt`:

```kotlin
package org.secretary.browse

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class DeviceUnlockCoordinatorTest {
    private val uuid = ByteArray(16) { 5 }
    private val secret = ByteArray(32) { 6 }

    @Test
    fun `enroll mints, stores a copy, saves metadata, and zeroizes the slot secret`() = runTest {
        val slot = FakeVaultDeviceSlotPort(deviceUuid = uuid, issuedSecret = secret)
        val enclave = FakeDeviceSecretEnclave()
        val metadata = FakeEnrollmentMetadataStore()
        val coordinator = DeviceUnlockCoordinator(slot, enclave, metadata)

        coordinator.enroll("/vault", "golden", byteArrayOf(0))

        assertTrue(enclave.isEnrolled, "enclave holds the secret")
        assertArrayEquals(secret, enclave.release("x"), "enclave kept its OWN copy of the real bytes")
        assertArrayEquals(ByteArray(32), slot.lastIssuedSecret, "coordinator zeroized the slot's secret array")
        assertEquals("golden", metadata.load()!!.vaultId)
        assertArrayEquals(uuid, metadata.load()!!.deviceUuid)
        assertTrue(coordinator.isEnrolled)
    }

    @Test
    fun `enroll rolls back the slot when the enclave store fails`() = runTest {
        val slot = FakeVaultDeviceSlotPort(deviceUuid = uuid, issuedSecret = secret)
        val enclave = FakeDeviceSecretEnclave(storeError = DeviceUnlockError.Enclave("boom"))
        val metadata = FakeEnrollmentMetadataStore()
        val coordinator = DeviceUnlockCoordinator(slot, enclave, metadata)

        assertThrows(DeviceUnlockError.Enclave::class.java) {
            kotlinx.coroutines.runBlocking { coordinator.enroll("/vault", "golden", byteArrayOf(0)) }
        }
        assertEquals(1, slot.removeCalls.size, "the just-minted slot was removed")
        assertArrayEquals(uuid, slot.removeCalls[0])
        assertFalse(coordinator.isEnrolled, "metadata was never saved")
    }

    @Test
    fun `enroll rolls back enclave and slot when metadata save fails, rethrowing the original error`() = runTest {
        val slot = FakeVaultDeviceSlotPort(deviceUuid = uuid, issuedSecret = secret)
        val enclave = FakeDeviceSecretEnclave()
        val metadata = FakeEnrollmentMetadataStore(saveError = IllegalStateException("disk full"))
        val coordinator = DeviceUnlockCoordinator(slot, enclave, metadata)

        val thrown = assertThrows(IllegalStateException::class.java) {
            kotlinx.coroutines.runBlocking { coordinator.enroll("/vault", "golden", byteArrayOf(0)) }
        }
        assertEquals("disk full", thrown.message)
        assertFalse(enclave.isEnrolled, "enclave was cleared")
        assertEquals(1, slot.removeCalls.size, "the slot was removed")
        assertFalse(coordinator.isEnrolled)
    }
}

```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-device-open-core/android && ./gradlew :vault-access:test`
Expected: FAIL — `DeviceUnlockCoordinator` unresolved.

- [ ] **Step 3: Create `DeviceUnlockCoordinator.kt`** (enroll + isEnrolled only; `unlock`/`disenroll` arrive in Tasks 5–6):

```kotlin
package org.secretary.browse

/**
 * Pure orchestration of device enrollment / unlock / disenroll over three injected ports. No I/O of
 * its own. Mirror of iOS `DeviceUnlockCoordinator`, with ONE deliberate divergence: [unlock] returns
 * an [UnlockCredential.DeviceSecret] (the caller opens via `openWithCredential`) rather than opening
 * directly — so open-time errors surface as [VaultBrowseError] from the shared pipeline, consistent
 * with the password/recovery paths.
 */
class DeviceUnlockCoordinator(
    private val slotPort: VaultDeviceSlotPort,
    private val enclave: DeviceSecretEnclave,
    private val metadata: DeviceEnrollmentMetadataStore,
) {
    /** True iff BOTH the enclave holds a secret AND enrollment metadata is present. */
    val isEnrolled: Boolean
        get() = enclave.isEnrolled && runCatching { metadata.load() }.getOrNull() != null

    /**
     * Mint a device slot, store its secret in the enclave, and record the enrollment — transactionally.
     * On enclave-store failure the slot is removed; on metadata-save failure both the enclave and the
     * slot are rolled back and the ORIGINAL save error is rethrown. The slot's secret copy is zeroized
     * on every exit. [password] is owned by the caller (forwarded to `addDeviceSlot`, not zeroized here).
     */
    suspend fun enroll(folder: String, vaultId: String, password: ByteArray) {
        val slot = slotPort.addDeviceSlot(folder, password)
        try {
            try {
                enclave.store(slot.secret)
            } catch (e: Throwable) {
                runCatching { slotPort.removeDeviceSlot(folder, slot.deviceUuid) }
                throw e
            }
            try {
                metadata.save(DeviceEnrollment(vaultId, slot.deviceUuid))
            } catch (e: Throwable) {
                runCatching { enclave.clear() }
                runCatching { slotPort.removeDeviceSlot(folder, slot.deviceUuid) }
                throw e
            }
        } finally {
            slot.secret.fill(0)
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-device-open-core/android && ./gradlew :vault-access:test`
Expected: PASS (3 enroll cases + isEnrolled green).

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-device-open-core
git add android/vault-access/src/main/kotlin/org/secretary/browse/DeviceUnlockCoordinator.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/DeviceUnlockCoordinatorTest.kt
git commit -m "feat(android): DeviceUnlockCoordinator.enroll (transactional) + isEnrolled"
```

---

### Task 5: `DeviceUnlockCoordinator.unlock` (guards + release → credential)

**Files:**
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/DeviceUnlockCoordinator.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/DeviceUnlockCoordinatorTest.kt` (extend)

**Interfaces:**
- Produces: `suspend fun unlock(vaultId: String, reason: String): UnlockCredential.DeviceSecret` — guards (`NotEnrolled` if no metadata; `VaultSlotMismatch` if vaultId differs) BEFORE `enclave.release`, then wraps the released secret + the metadata's deviceUuid into the credential. Propagates any `DeviceUnlockError` from `release`.

- [ ] **Step 1: Write the failing test** — append to `DeviceUnlockCoordinatorTest.kt`:

```kotlin
    @Test
    fun `unlock throws NotEnrolled and never touches the enclave when no metadata`() = runTest {
        val enclave = FakeDeviceSecretEnclave(releaseError = IllegalStateException("must not be called"))
        val coordinator = DeviceUnlockCoordinator(FakeVaultDeviceSlotPort(), enclave, FakeEnrollmentMetadataStore())
        assertThrows(DeviceUnlockError.NotEnrolled::class.java) {
            kotlinx.coroutines.runBlocking { coordinator.unlock("golden", "why") }
        }
    }

    @Test
    fun `unlock throws VaultSlotMismatch when the enrolled vaultId differs, before release`() = runTest {
        val metadata = FakeEnrollmentMetadataStore().apply { save(DeviceEnrollment("OTHER", uuid)) }
        val enclave = FakeDeviceSecretEnclave(releaseError = IllegalStateException("must not be called"))
        enclave.store(secret) // enclave is enrolled, but the vaultId guard must fire first
        val coordinator = DeviceUnlockCoordinator(FakeVaultDeviceSlotPort(), enclave, metadata)
        assertThrows(DeviceUnlockError.VaultSlotMismatch::class.java) {
            kotlinx.coroutines.runBlocking { coordinator.unlock("golden", "why") }
        }
    }

    @Test
    fun `unlock returns a DeviceSecret credential carrying the released secret and slot uuid`() = runTest {
        val metadata = FakeEnrollmentMetadataStore().apply { save(DeviceEnrollment("golden", uuid)) }
        val enclave = FakeDeviceSecretEnclave().apply { store(secret) }
        val coordinator = DeviceUnlockCoordinator(FakeVaultDeviceSlotPort(), enclave, metadata)
        val cred = coordinator.unlock("golden", "why")
        assertArrayEquals(uuid, cred.deviceUuid)
        assertArrayEquals(secret, cred.secret)
    }

    @Test
    fun `unlock propagates a biometric error from the enclave after the guards pass`() = runTest {
        val metadata = FakeEnrollmentMetadataStore().apply { save(DeviceEnrollment("golden", uuid)) }
        val enclave = FakeDeviceSecretEnclave(releaseError = DeviceUnlockError.UserCancelled)
        enclave.store(secret)
        val coordinator = DeviceUnlockCoordinator(FakeVaultDeviceSlotPort(), enclave, metadata)
        assertThrows(DeviceUnlockError.UserCancelled::class.java) {
            kotlinx.coroutines.runBlocking { coordinator.unlock("golden", "why") }
        }
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-device-open-core/android && ./gradlew :vault-access:test`
Expected: FAIL — `unlock` unresolved.

- [ ] **Step 3: Add `unlock`** — in `DeviceUnlockCoordinator.kt`, after `enroll`:

```kotlin
    /**
     * Release the device secret (slice 2: behind a biometric prompt) and wrap it into an
     * [UnlockCredential.DeviceSecret]. Guards run BEFORE [DeviceSecretEnclave.release] so a stale /
     * wrong-vault enrollment never triggers a biometric prompt: [DeviceUnlockError.NotEnrolled] if no
     * metadata, [DeviceUnlockError.VaultSlotMismatch] if the enrolled vaultId differs. The returned
     * credential owns the secret; the CALLER opens via `openWithCredential` and zeroizes it.
     */
    suspend fun unlock(vaultId: String, reason: String): UnlockCredential.DeviceSecret {
        val enrollment = metadata.load() ?: throw DeviceUnlockError.NotEnrolled
        if (enrollment.vaultId != vaultId) throw DeviceUnlockError.VaultSlotMismatch
        val secret = enclave.release(reason)
        return UnlockCredential.DeviceSecret(enrollment.deviceUuid, secret)
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-device-open-core/android && ./gradlew :vault-access:test`
Expected: PASS (4 new unlock cases green).

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-device-open-core
git add android/vault-access/src/main/kotlin/org/secretary/browse/DeviceUnlockCoordinator.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/DeviceUnlockCoordinatorTest.kt
git commit -m "feat(android): DeviceUnlockCoordinator.unlock (guards + release to credential)"
```

---

### Task 6: `DeviceUnlockCoordinator.disenroll` (idempotent revocation)

**Files:**
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/DeviceUnlockCoordinator.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/DeviceUnlockCoordinatorTest.kt` (extend)

**Interfaces:**
- Produces: `suspend fun disenroll(folder: String)` — removes the slot (tolerating `VaultBrowseError.DeviceSlotNotFound`), clears the enclave + metadata. No orphan survives; safe to call when not enrolled.

- [ ] **Step 1: Write the failing test** — append to `DeviceUnlockCoordinatorTest.kt`:

```kotlin
    @Test
    fun `disenroll removes the slot and clears enclave and metadata`() = runTest {
        val slot = FakeVaultDeviceSlotPort(deviceUuid = uuid, issuedSecret = secret)
        val enclave = FakeDeviceSecretEnclave()
        val metadata = FakeEnrollmentMetadataStore()
        val coordinator = DeviceUnlockCoordinator(slot, enclave, metadata)
        coordinator.enroll("/vault", "golden", byteArrayOf(0))

        coordinator.disenroll("/vault")

        assertEquals(1, slot.removeCalls.size)
        assertArrayEquals(uuid, slot.removeCalls[0])
        assertFalse(enclave.isEnrolled)
        assertFalse(coordinator.isEnrolled)
    }

    @Test
    fun `disenroll tolerates an already-gone slot`() = runTest {
        val slot = FakeVaultDeviceSlotPort(
            deviceUuid = uuid, issuedSecret = secret,
            removeError = VaultBrowseError.DeviceSlotNotFound,
        )
        val enclave = FakeDeviceSecretEnclave().apply { store(secret) }
        val metadata = FakeEnrollmentMetadataStore().apply { save(DeviceEnrollment("golden", uuid)) }
        val coordinator = DeviceUnlockCoordinator(slot, enclave, metadata)

        coordinator.disenroll("/vault") // must NOT throw

        assertFalse(enclave.isEnrolled)
        assertFalse(coordinator.isEnrolled)
    }

    @Test
    fun `disenroll on a never-enrolled coordinator is a no-op`() = runTest {
        val slot = FakeVaultDeviceSlotPort()
        val coordinator = DeviceUnlockCoordinator(slot, FakeDeviceSecretEnclave(), FakeEnrollmentMetadataStore())
        coordinator.disenroll("/vault")
        assertEquals(0, slot.removeCalls.size, "no metadata → nothing to remove")
        assertFalse(coordinator.isEnrolled)
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-device-open-core/android && ./gradlew :vault-access:test`
Expected: FAIL — `disenroll` unresolved.

- [ ] **Step 3: Add `disenroll`** — in `DeviceUnlockCoordinator.kt`, after `unlock`:

```kotlin
    /**
     * Revoke this device's enrollment, idempotently. Removes the slot (a
     * [VaultBrowseError.DeviceSlotNotFound] is swallowed — already-gone is success; any other
     * [VaultBrowseError] propagates), then best-effort clears the enclave + metadata. Safe when not
     * enrolled (nothing to remove). No orphan survives.
     */
    suspend fun disenroll(folder: String) {
        val enrollment = metadata.load()
        if (enrollment != null) {
            try {
                slotPort.removeDeviceSlot(folder, enrollment.deviceUuid)
            } catch (e: VaultBrowseError.DeviceSlotNotFound) {
                // already gone — fine
            }
        }
        runCatching { enclave.clear() }
        runCatching { metadata.clear() }
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-device-open-core/android && ./gradlew :vault-access:test`
Expected: PASS (3 new disenroll cases green; full `:vault-access` suite green).

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-device-open-core
git add android/vault-access/src/main/kotlin/org/secretary/browse/DeviceUnlockCoordinator.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/DeviceUnlockCoordinatorTest.kt
git commit -m "feat(android): DeviceUnlockCoordinator.disenroll (idempotent revocation)"
```

---

### Task 7: `:kit` real adapters — `UniffiVaultOpenPort.openWithDeviceSecret` + `UniffiVaultDeviceSlotPort`

**Files:**
- Modify: `android/kit/src/main/kotlin/org/secretary/browse/UniffiVaultOpenPort.kt`
- Create: `android/kit/src/main/kotlin/org/secretary/browse/UniffiVaultDeviceSlotPort.kt`

**Interfaces:**
- Consumes: generated `uniffi.secretary.{openWithDeviceSecret, addDeviceSlot, removeDeviceSlot, DeviceEnrollOutput, OpenVaultOutput}`; the file-level `mapErrors` (promoted to `internal` here).
- Produces: `UniffiVaultOpenPort.openWithDeviceSecret(...)`; `UniffiVaultDeviceSlotPort : VaultDeviceSlotPort`.

**No host test** — both call the real FFI. Build-verified here; behaviour is proven by the instrumented round-trip in Task 8 (stated explicitly so the no-test status is intentional, not an omission).

- [ ] **Step 1: Implement `openWithDeviceSecret` on `UniffiVaultOpenPort`** — in `UniffiVaultOpenPort.kt`:

  Add the import (aliased — the bare name collides with the override):
```kotlin
import uniffi.secretary.openWithDeviceSecret as ffiOpenWithDeviceSecret
```
  Add a constructor seam (after `recoveryFn`):
```kotlin
    private val deviceSecretFn: (ByteArray, ByteArray, ByteArray) -> OpenVaultOutput = ::ffiOpenWithDeviceSecret,
```
  Add the override (after `openWithRecovery`):
```kotlin
    override suspend fun openWithDeviceSecret(
        vaultFolder: String,
        deviceUuid: ByteArray,
        deviceSecret: ByteArray,
    ): VaultSession =
        withContext(ioDispatcher) {
            val output = mapErrors {
                deviceSecretFn(vaultFolder.toByteArray(Charsets.UTF_8), deviceUuid, deviceSecret)
            }
            UniffiVaultSession(output, ioDispatcher, deviceUuids)
        }
```
  And promote the file-level mapper so the sibling adapter file can reuse it — change:
```kotlin
private inline fun <T> mapErrors(block: () -> T): T =
```
  to:
```kotlin
internal inline fun <T> mapErrors(block: () -> T): T =
```

- [ ] **Step 2: Create `UniffiVaultDeviceSlotPort.kt`:**

```kotlin
package org.secretary.browse

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uniffi.secretary.DeviceEnrollOutput
import uniffi.secretary.addDeviceSlot as ffiAddDeviceSlot
import uniffi.secretary.removeDeviceSlot as ffiRemoveDeviceSlot

/**
 * The real [VaultDeviceSlotPort] over the generated `add_device_slot` / `remove_device_slot`. Runs on
 * [ioDispatcher] (add_device_slot password-opens the vault → Argon2id). The one-shot
 * `DeviceSecretOutput` is `takeSecret()`-ed once then `wipe()`-d in a `finally` so the bridge retains
 * nothing (mirror of iOS's `defer { out.deviceSecret.wipe() }`). The FFI fns are injectable seams
 * defaulting to the real bindings.
 */
class UniffiVaultDeviceSlotPort(
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val addFn: (ByteArray, ByteArray) -> DeviceEnrollOutput = ::ffiAddDeviceSlot,
    private val removeFn: (ByteArray, ByteArray) -> Unit = ::ffiRemoveDeviceSlot,
) : VaultDeviceSlotPort {
    override suspend fun addDeviceSlot(vaultFolder: String, password: ByteArray): EnrolledSlot =
        withContext(ioDispatcher) {
            mapErrors {
                val out = addFn(vaultFolder.toByteArray(Charsets.UTF_8), password)
                try {
                    val taken = out.deviceSecret.takeSecret()
                        ?: throw VaultBrowseError.Failed("device secret handle was empty (already taken?)")
                    // take_secret() is declared `sequence<u8>?` → a boxed list; convert to ByteArray.
                    // (`it.toByte()` is valid whether the element type is UByte or Byte.)
                    val secret = taken.map { it.toByte() }.toByteArray()
                    EnrolledSlot(out.deviceUuid, secret)
                } finally {
                    out.deviceSecret.wipe()
                }
            }
        }

    override suspend fun removeDeviceSlot(vaultFolder: String, deviceUuid: ByteArray) =
        withContext(ioDispatcher) {
            mapErrors { removeFn(vaultFolder.toByteArray(Charsets.UTF_8), deviceUuid) }
        }
}
```

- [ ] **Step 3: Build to verify it compiles**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-device-open-core/android && ./gradlew :kit:test`
Expected: PASS (compiles + existing `:kit` host suite still green; no new host test in this task).
If `takeSecret()` / `wipe()` / `deviceUuid` / `deviceSecret` are unresolved or mistyped, inspect the generated `DeviceEnrollOutput` / `DeviceSecretOutput` in the build output and adjust names (uniffi-codegen-rename memo).

- [ ] **Step 4: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-device-open-core
git add android/kit/src/main/kotlin/org/secretary/browse/UniffiVaultOpenPort.kt \
        android/kit/src/main/kotlin/org/secretary/browse/UniffiVaultDeviceSlotPort.kt
git commit -m "feat(android): :kit UniffiVaultDeviceSlotPort + openWithDeviceSecret adapter"
```

---

### Task 8: On-device round-trip — `goldenPassword` + `OpenWithDeviceSecretSmokeTest`

**Files:**
- Modify: `android/app/src/main/kotlin/org/secretary/app/AppVaultProvisioning.kt` (add `goldenPassword`)
- Create: `android/app/src/androidTest/kotlin/org/secretary/app/DeviceUnlockTestDoubles.kt` (instrumented-side in-memory enclave + metadata)
- Create: `android/app/src/androidTest/kotlin/org/secretary/app/OpenWithDeviceSecretSmokeTest.kt`

**Interfaces:**
- Consumes: `DeviceUnlockCoordinator`, `UniffiVaultDeviceSlotPort`, `uniffiVaultOpenPort(deviceUuids)`, `openWithCredential`, `VaultBrowseError.DeviceSlotNotFound`, `DeviceUnlockError.NotEnrolled`, `AppVaultProvisioning`.
- Produces: `AppVaultProvisioning.goldenPassword(context): String`.

Note: the instrumented test cannot reuse the `:vault-access` test fakes (test source sets are not shared across modules), so it carries its own minimal in-memory enclave/metadata. The slot port and open are REAL (`.so`).

- [ ] **Step 1: Add the `goldenPassword` reader** — in `AppVaultProvisioning.kt`, after `goldenRecoveryPhrase`:

```kotlin
    /** The golden vault's password, read from the bundled inputs JSON (single source of truth — a
     *  published KAT, not a real secret, like [goldenRecoveryPhrase]). */
    fun goldenPassword(context: Context): String =
        loadInputsJson(context).getString("password")
```

- [ ] **Step 2: Create the instrumented-side doubles** `DeviceUnlockTestDoubles.kt`:

```kotlin
package org.secretary.app

import org.secretary.browse.DeviceEnrollment
import org.secretary.browse.DeviceEnrollmentMetadataStore
import org.secretary.browse.DeviceSecretEnclave
import org.secretary.browse.DeviceUnlockError

/** In-memory enclave for the instrumented round-trip (the real Keystore/biometric enclave is slice 2). */
class InMemoryDeviceSecretEnclave : DeviceSecretEnclave {
    private var stored: ByteArray? = null
    override val isEnrolled: Boolean get() = stored != null
    override suspend fun store(secret: ByteArray) { stored = secret.copyOf() }
    override suspend fun release(reason: String): ByteArray =
        stored?.copyOf() ?: throw DeviceUnlockError.NotEnrolled
    override suspend fun clear() { stored?.fill(0); stored = null }
}

/** In-memory enrollment metadata for the instrumented round-trip. */
class InMemoryEnrollmentMetadataStore : DeviceEnrollmentMetadataStore {
    private var enrollment: DeviceEnrollment? = null
    override fun load(): DeviceEnrollment? = enrollment
    override fun save(enrollment: DeviceEnrollment) { this.enrollment = enrollment }
    override fun clear() { enrollment = null }
}
```

- [ ] **Step 3: Write the failing instrumented test** `OpenWithDeviceSecretSmokeTest.kt`:

```kotlin
package org.secretary.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.secretary.browse.DeviceUnlockCoordinator
import org.secretary.browse.DeviceUnlockError
import org.secretary.browse.FileDeviceUuidStore
import org.secretary.browse.UniffiVaultDeviceSlotPort
import org.secretary.browse.VaultBrowseError
import org.secretary.browse.openWithCredential
import org.secretary.browse.uniffiVaultOpenPort
import java.io.File

/**
 * On-device proof that the device-secret enrol → open → disenroll round-trip works over the REAL
 * libsecretary_ffi_uniffi.so, with a fake in-memory enclave standing in for biometric hardware
 * (mirror of iOS DeviceUnlockIntegrationTests). The real biometric Keystore enclave + UI is slice 2.
 */
@RunWith(AndroidJUnit4::class)
class OpenWithDeviceSecretSmokeTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val toClean = mutableListOf<File>()

    @After fun cleanup() {
        toClean.forEach { it.deleteRecursively() }
        File(context.filesDir, "golden_vault_001").deleteRecursively()
    }

    @Test
    fun enrolOpenDisenroll_roundTripsOverRealSo() = runBlocking {
        val folder = AppVaultProvisioning.stageGoldenVault(context)
        val deviceUuids = FileDeviceUuidStore(File(context.noBackupFilesDir, "devices-${System.nanoTime()}"))
            .also { toClean += File(context.noBackupFilesDir, "devices-${System.nanoTime()}") }
        val goldenUuidHex = hexLower(AppVaultProvisioning.goldenVaultUuid(context))

        val openPort = uniffiVaultOpenPort(deviceUuids)
        val slotPort = UniffiVaultDeviceSlotPort()
        val enclave = InMemoryDeviceSecretEnclave()
        val metadata = InMemoryEnrollmentMetadataStore()
        val coordinator = DeviceUnlockCoordinator(slotPort, enclave, metadata)

        // Enrol: mints devices/<uuid>.wrap on the staged (writable) copy via the golden password.
        val password = AppVaultProvisioning.goldenPassword(context).toByteArray(Charsets.UTF_8)
        coordinator.enroll(folder.path, "golden", password)
        password.fill(0)
        assertTrue("enrolled after addDeviceSlot", coordinator.isEnrolled)

        // Unlock → credential → open over the real .so; assert the opened vault is the golden one.
        val cred = coordinator.unlock("golden", "smoke")
        val capturedUuid = cred.deviceUuid.copyOf()
        val session = openWithCredential(openPort, folder.path, cred)
        cred.secret.fill(0)
        assertEquals(goldenUuidHex, session.vaultUuidHex())
        session.wipe()

        // Disenroll: removes the wrap file; subsequent state must reflect "no such device".
        coordinator.disenroll(folder.path)
        assertFalse("disenrolled", coordinator.isEnrolled)

        val reopen = runCatching { openPort.openWithDeviceSecret(folder.path, capturedUuid, ByteArray(32)) }
        assertTrue(
            "reopen after disenroll must fail DeviceSlotNotFound, was ${reopen.exceptionOrNull()}",
            reopen.exceptionOrNull() is VaultBrowseError.DeviceSlotNotFound,
        )
        val reUnlock = runCatching { coordinator.unlock("golden", "smoke") }
        assertTrue(
            "unlock after disenroll must be NotEnrolled",
            reUnlock.exceptionOrNull() is DeviceUnlockError.NotEnrolled,
        )
    }
}

/** Lowercase hex of a byte array (matches VaultSession.vaultUuidHex()). */
private fun hexLower(bytes: ByteArray): String =
    bytes.joinToString("") { "%02x".format(it) }
```

- [ ] **Step 4: Run the test to verify it fails (then passes)**

First failure (red): `goldenPassword` / `UniffiVaultDeviceSlotPort` unresolved if Steps 1–2 were skipped — but with Steps 1–2 in place, run it for real:

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-device-open-core/android && \
  ANDROID_SERIAL=emulator-5554 PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :app:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.app.OpenWithDeviceSecretSmokeTest
```
Expected: PASS. (If `session.vaultUuidHex()` differs, check `hexLower` casing matches `UniffiVaultSession.vaultUuidHex()` — both are lowercase. If the golden JSON key is not `password`, fix Step 1 to the actual key — confirmed present as `password` at plan time.)

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-device-open-core
git add android/app/src/main/kotlin/org/secretary/app/AppVaultProvisioning.kt \
        android/app/src/androidTest/kotlin/org/secretary/app/DeviceUnlockTestDoubles.kt \
        android/app/src/androidTest/kotlin/org/secretary/app/OpenWithDeviceSecretSmokeTest.kt
git commit -m "test(android): on-device device-secret enrol/open/disenroll round-trip over real .so"
```

---

### Task 9: Docs — README + ROADMAP rows

**Files:**
- Modify: `README.md`
- Modify: `ROADMAP.md`

**Interfaces:** none (documentation).

- [ ] **Step 1: Locate the existing C.3 Android rows** — find where the recovery-open slice (2026-06-19) is recorded:

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-device-open-core
grep -nE 'recovery|C\.3 Android|device-secret|device secret' README.md ROADMAP.md
```

- [ ] **Step 2: Add a concise row/line** in each, matching the surrounding style (dot-point, brief — per the README-style preference). Record: "C.3 Android device-secret open — slice 1: pure `DeviceUnlockCoordinator` + ports + `:kit` FFI adapter, proven against the real `.so` with a fake in-memory enclave; real biometric Keystore enclave + UI = slice 2. (2026-06-19)". Keep it to one line each; do NOT add test-count walls.

- [ ] **Step 3: Verify the guardrails are still empty**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-device-open-core
git diff main...HEAD --name-only | grep -E 'core/|ffi/|crypto-design|vault-format'                    # expect empty
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)'  # expect empty (no ios/)
```
Expected: both empty.

- [ ] **Step 4: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-device-open-core
git add README.md ROADMAP.md
git commit -m "docs: C.3 Android device-secret open slice 1 (README + ROADMAP)"
```

---

## Final verification (run before handoff)

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-device-open-core/android && ./gradlew :vault-access:test :kit:test    # host green
cd /Users/hherb/src/secretary/.worktrees/c3-android-device-open-core/android && \
  ANDROID_SERIAL=emulator-5554 PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :app:connectedDebugAndroidTest                                                                               # incl. the device-secret smoke
```
Plus the two guardrail greps from Task 9 Step 3.

## Self-Review notes (against the spec)

- **Spec §2 in-scope items** → Task 1 (errors+mapping), Task 2 (credential arm+seam), Task 3 (ports/types/fakes), Tasks 4–6 (coordinator), Task 7 (`:kit` adapters), Task 8 (round-trip). ✓
- **Spec §5.1 credential arm** → Task 2. **§5.2 coordinator + slot port** → Tasks 3–6. **§5.3 error mapping** → Task 1. ✓
- **Spec §6 secret hygiene** → one-shot `take_secret`+`wipe` (Task 7), enroll `finally` zeroize + store-copies (Task 4 test asserts both via `lastIssuedSecret` zeroed + enclave keeps real bytes), caller zeroizes credential (Task 8). ✓
- **Spec §7 tests** → host: dispatch (T2), mapping (T1), coordinator enroll/unlock/disenroll/isEnrolled (T4–6); instrumented round-trip (T8). ✓
- **Spec §8 guardrails** → Task 9 Step 3. ✓
- **Type consistency:** `EnrolledSlot(deviceUuid, secret)`, `DeviceEnrollment(vaultId, deviceUuid)`, `unlock(vaultId, reason)` (no `folder` — open is the caller's job), `disenroll(folder)`, `VaultBrowseError.DeviceSlotNotFound` (object, catchable type) consistent across Tasks 3–8. ✓
- **No-placeholder scan:** every code step shows complete code; the only "confirm at build" notes are the documented uniffi-codegen-rename guard and the golden-JSON `password` key (verified present at plan time). ✓
