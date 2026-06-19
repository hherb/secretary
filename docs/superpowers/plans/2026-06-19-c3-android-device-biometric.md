# C.3 Android — real biometric device open (slice 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An enrolled Android device opens `golden_vault_001` via its per-device wrap slot, with the 32-byte device secret released only behind a real `BiometricPrompt`, reaching `BrowseWithSyncScreen`.

**Architecture:** Three layers mirroring iOS. `vault-access` (pure, host-tested) gains a `DeviceUnlockViewModel` state machine. `:kit` (Android lib, device-tested) gains the real `KeystoreDeviceSecretEnclave` (AES-256-GCM Keystore key, `release` gated by an injected `BiometricGate`) + a `FileDeviceEnrollmentMetadataStore`. `:app` supplies the real `BiometricPrompt`-backed gate, flips `MainActivity` to `FragmentActivity`, adds the `UnlockScreen` affordances, and wires `AppRoot`. The device-secret credential flows through the slice-1 `openWithCredential` pipeline unchanged.

**Tech Stack:** Kotlin, Android Keystore (`AndroidKeyStore`), `androidx.biometric:BiometricPrompt` + `CryptoObject`, Jetpack Compose, JUnit5 (host) + AndroidJUnit4 (instrumented), kotlinx-coroutines-test.

## Global Constraints

- **Android-only.** No change to `core/` / `ffi/` / `ios/` / on-disk format / UDL. Guardrail (verified empty at close): `git diff main...HEAD --name-only | grep -E 'core/|ffi/|crypto-design|vault-format'` → empty; `git diff main...HEAD --name-only | grep -vE '^(android/|docs/)'` → empty.
- **Reuse the slice-1 `DeviceUnlockError` taxonomy** (`android/vault-access/src/main/kotlin/org/secretary/browse/DeviceUnlockError.kt`) — it already has `NotEnrolled`, `VaultSlotMismatch`, `BiometryUnavailable`, `BiometryNotEnrolled`, `BiometryLockout`, `UserCancelled`, `AuthenticationFailed`, `WrappedSecretCorrupt`, `Enclave(detail)`. Do NOT add variants.
- **Reuse the slice-1 ports/types** unchanged: `DeviceSecretEnclave`, `DeviceEnrollmentMetadataStore` + `DeviceEnrollment(vaultId: String, deviceUuid: ByteArray)`, `VaultDeviceSlotPort`, `UnlockCredential.DeviceSecret(deviceUuid, secret)`, `DeviceUnlockCoordinator(slotPort, enclave, metadata)`.
- **Secret hygiene:** every secret-bearing `ByteArray` is zeroized (`fill(0)`) by its owner after use. The enclave stores an internal copy and the caller may zeroize its array after `store` returns (port contract). `release` returns a caller-owned array.
- **No hardcoded crypto values in tests:** generate dummy secrets via `java.security.SecureRandom` (repo CodeQL convention).
- **Module package** for new `:kit` files: `org.secretary.browse` (the `:kit` namespace is `org.secretary.sync` but its Kotlin lives under `org.secretary.browse`).
- **minSdk = 26, compileSdk = 36.** Keystore key-gen calls that are API >26 MUST be version-guarded (`Build.VERSION.SDK_INT`).
- **Commit after every task** (frequent commits). Run the relevant test gate before committing.

---

## File Structure

**`vault-access` (pure, host-tested):**
- Create `android/vault-access/src/main/kotlin/org/secretary/browse/DeviceUnlockViewModel.kt` — the state machine (no Android imports).
- Create `android/vault-access/src/test/kotlin/org/secretary/browse/DeviceUnlockViewModelTest.kt` — host tests over the slice-1 fakes.

**`:kit` (Android lib):**
- Create `android/kit/src/main/kotlin/org/secretary/browse/FileDeviceEnrollmentMetadataStore.kt` — pure file I/O; host-testable.
- Create `android/kit/src/test/kotlin/org/secretary/browse/FileDeviceEnrollmentMetadataStoreTest.kt` — host tests (`@TempDir`).
- Create `android/kit/src/main/kotlin/org/secretary/browse/KeystoreDeviceSecretEnclave.kt` — real enclave + `BiometricGate` typealias + `KeystoreKeyConfig`.
- Create `android/kit/src/androidTest/kotlin/org/secretary/browse/KeystoreDeviceSecretEnclaveTest.kt` — instrumented round-trip (no-auth key config + passthrough gate).

**`:app` (Activity + UI):**
- Create `android/app/src/main/kotlin/org/secretary/app/BiometricErrorMapping.kt` — pure `mapBiometricError(errorCode: Int): DeviceUnlockError`.
- Create `android/app/src/test/kotlin/org/secretary/app/BiometricErrorMappingTest.kt` — host tests.
- Create `android/app/src/main/kotlin/org/secretary/app/BiometricPromptGate.kt` — the real gate (Activity-bound; compile-verified).
- Modify `android/app/src/main/kotlin/org/secretary/app/MainActivity.kt` — `ComponentActivity` → `FragmentActivity`.
- Modify `android/app/build.gradle.kts` — add `androidx.biometric` + `androidx.fragment`.
- Modify `android/app/src/main/kotlin/org/secretary/app/UnlockScreen.kt` — remember checkbox + biometric-unlock button.
- Create `android/app/src/androidTest/kotlin/org/secretary/app/UnlockScreenDeviceUiTest.kt` — instrumented Compose test for the new affordances.
- Modify `android/app/src/main/kotlin/org/secretary/app/AppRoot.kt` — construct coordinator + enroll path + biometric path.

**Docs:**
- Modify `README.md`, `ROADMAP.md`.

---

## Task 1: `DeviceUnlockViewModel` (pure state machine, host-tested)

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/DeviceUnlockViewModel.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/DeviceUnlockViewModelTest.kt`

**Interfaces:**
- Consumes: `DeviceUnlockCoordinator(slotPort, enclave, metadata)` with `val isEnrolled: Boolean`, `suspend fun enroll(folder, vaultId, password)`, `suspend fun unlock(vaultId, reason): UnlockCredential.DeviceSecret`; `DeviceUnlockError`; `UnlockCredential.DeviceSecret`. Test fakes: `FakeVaultDeviceSlotPort`, `FakeDeviceSecretEnclave(storeError, releaseError)`, `FakeEnrollmentMetadataStore(saveError)` (all in `android/vault-access/src/test/kotlin/org/secretary/browse/DeviceUnlockFakes.kt`).
- Produces: `DeviceUnlockViewModel(coordinator)` with `val state: DeviceUnlockState`; `fun refresh()`; `suspend fun enroll(folder, vaultId, password)`; `suspend fun unlockWithBiometrics(folder, vaultId, reason, onCredential: suspend (UnlockCredential.DeviceSecret) -> Unit)`. Sealed `DeviceUnlockState { Unenrolled; Enrolled; Prompting; Failed(error: DeviceUnlockError) }`.

- [ ] **Step 1: Write the failing test**

```kotlin
package org.secretary.browse

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class DeviceUnlockViewModelTest {
    private val folder = "/tmp/vault"
    private val vaultId = "00112233445566778899aabbccddeeff"

    private fun coordinator(
        slotPort: VaultDeviceSlotPort = FakeVaultDeviceSlotPort(),
        enclave: DeviceSecretEnclave = FakeDeviceSecretEnclave(),
        metadata: DeviceEnrollmentMetadataStore = FakeEnrollmentMetadataStore(),
    ) = DeviceUnlockCoordinator(slotPort, enclave, metadata)

    @Test
    fun refresh_unenrolled_whenNoSecretOrMetadata() {
        val vm = DeviceUnlockViewModel(coordinator())
        vm.refresh()
        assertEquals(DeviceUnlockState.Unenrolled, vm.state)
    }

    @Test
    fun enroll_thenRefresh_isEnrolled() = runTest {
        val vm = DeviceUnlockViewModel(coordinator())
        vm.enroll(folder, vaultId, "pw".toByteArray())
        assertEquals(DeviceUnlockState.Enrolled, vm.state)
    }

    @Test
    fun unlock_success_emitsCredentialAndReturnsToEnrolled() = runTest {
        val vm = DeviceUnlockViewModel(coordinator())
        vm.enroll(folder, vaultId, "pw".toByteArray())
        var received: UnlockCredential.DeviceSecret? = null
        vm.unlockWithBiometrics(folder, vaultId, "reason") { received = it }
        assertTrue(received != null)
        assertEquals(DeviceUnlockState.Enrolled, vm.state)
    }

    @Test
    fun unlock_cancelled_entersFailed_withoutEmitting() = runTest {
        val enclave = FakeDeviceSecretEnclave(releaseError = DeviceUnlockError.UserCancelled)
        val metadata = FakeEnrollmentMetadataStore()
        val vm = DeviceUnlockViewModel(coordinator(enclave = enclave, metadata = metadata))
        vm.enroll(folder, vaultId, "pw".toByteArray())
        var emitted = false
        vm.unlockWithBiometrics(folder, vaultId, "reason") { emitted = true }
        assertTrue(!emitted)
        val failed = vm.state as DeviceUnlockState.Failed
        assertSame(DeviceUnlockError.UserCancelled, failed.error)
    }

    @Test
    fun unlock_wrongVault_entersFailedMismatch_withoutTouchingEnclave() = runTest {
        // enrolled for vaultId, but unlock requests a different vault → guard fires before release.
        val enclave = FakeDeviceSecretEnclave(releaseError = DeviceUnlockError.Enclave("must not be called"))
        val metadata = FakeEnrollmentMetadataStore()
        val vm = DeviceUnlockViewModel(coordinator(enclave = enclave, metadata = metadata))
        vm.enroll(folder, vaultId, "pw".toByteArray())
        vm.unlockWithBiometrics(folder, "ffffffffffffffffffffffffffffffff", "reason") {}
        assertSame(DeviceUnlockError.VaultSlotMismatch, (vm.state as DeviceUnlockState.Failed).error)
    }

    @Test
    fun enroll_failure_entersFailed() = runTest {
        val enclave = FakeDeviceSecretEnclave(storeError = DeviceUnlockError.Enclave("keystore boom"))
        val vm = DeviceUnlockViewModel(coordinator(enclave = enclave))
        vm.enroll(folder, vaultId, "pw".toByteArray())
        assertTrue(vm.state is DeviceUnlockState.Failed)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.DeviceUnlockViewModelTest'`
Expected: FAIL — `DeviceUnlockViewModel` / `DeviceUnlockState` unresolved.

- [ ] **Step 3: Write minimal implementation**

```kotlin
package org.secretary.browse

/**
 * Pure UI state for the device-unlock surface. The screen renders from [state]; all enroll/unlock
 * decisions live here, so the full matrix is host-tested over the in-memory fakes. Mirror of iOS
 * `DeviceUnlockViewModel`. The VM never opens the vault — [unlockWithBiometrics] hands the resulting
 * credential to [onCredential] (AppRoot opens via the slice-1 pipeline).
 */
sealed interface DeviceUnlockState {
    /** No enrollment — the screen offers password/recovery (+ the "remember" checkbox). */
    data object Unenrolled : DeviceUnlockState
    /** Enrolled — the screen offers "Unlock with biometrics". */
    data object Enrolled : DeviceUnlockState
    /** A biometric prompt is in flight (disable the button). */
    data object Prompting : DeviceUnlockState
    /** A recoverable failure to surface for display; the screen returns to Enrolled/Unenrolled. */
    data class Failed(val error: DeviceUnlockError) : DeviceUnlockState
}

class DeviceUnlockViewModel(private val coordinator: DeviceUnlockCoordinator) {
    var state: DeviceUnlockState = DeviceUnlockState.Unenrolled
        private set

    /** Cheap, prompt-free recompute of Unenrolled vs Enrolled. */
    fun refresh() {
        state = if (coordinator.isEnrolled) DeviceUnlockState.Enrolled else DeviceUnlockState.Unenrolled
    }

    /** Enroll this device. [password] is caller-owned (forwarded to the coordinator, not zeroized here). */
    suspend fun enroll(folder: String, vaultId: String, password: ByteArray) {
        state = try {
            coordinator.enroll(folder, vaultId, password)
            DeviceUnlockState.Enrolled
        } catch (e: DeviceUnlockError) {
            DeviceUnlockState.Failed(e)
        }
    }

    /**
     * Release the device secret behind the biometric prompt (inside the coordinator's enclave) and
     * hand the credential to [onCredential]. Guards (NotEnrolled/VaultSlotMismatch) run before the
     * prompt. On any [DeviceUnlockError] → [DeviceUnlockState.Failed] and [onCredential] is NOT called.
     */
    suspend fun unlockWithBiometrics(
        folder: String,
        vaultId: String,
        reason: String,
        onCredential: suspend (UnlockCredential.DeviceSecret) -> Unit,
    ) {
        state = DeviceUnlockState.Prompting
        val credential = try {
            coordinator.unlock(vaultId, reason)
        } catch (e: DeviceUnlockError) {
            state = DeviceUnlockState.Failed(e)
            return
        }
        onCredential(credential)
        state = DeviceUnlockState.Enrolled
    }
}
```

Note: `folder` is unused by `unlockWithBiometrics`'s coordinator call (the coordinator's `unlock` takes only `vaultId, reason`); it's kept in the signature for symmetry with `enroll`/future disenroll wiring. If clippy/lint flags an unused param, prefix `_folder` — but keep the parameter so AppRoot's call sites are uniform.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.DeviceUnlockViewModelTest'`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/browse/DeviceUnlockViewModel.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/DeviceUnlockViewModelTest.kt
git commit -m "feat(android): DeviceUnlockViewModel state machine (C.3 slice 2)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: `FileDeviceEnrollmentMetadataStore` (real metadata store, host-tested)

**Files:**
- Create: `android/kit/src/main/kotlin/org/secretary/browse/FileDeviceEnrollmentMetadataStore.kt`
- Test: `android/kit/src/test/kotlin/org/secretary/browse/FileDeviceEnrollmentMetadataStoreTest.kt`

**Interfaces:**
- Consumes: `DeviceEnrollmentMetadataStore` interface; `DeviceEnrollment(vaultId: String, deviceUuid: ByteArray)`.
- Produces: `FileDeviceEnrollmentMetadataStore(dir: File)` implementing `load()/save()/clear()`. On-disk format: `[4-byte BE vaultId-len][vaultId UTF-8][16-byte deviceUuid]` in `dir/enrollment`. `load()` returns `null` for absent/short/malformed/wrong-uuid-length (conservative under-report, iOS parity). `save()` is atomic (temp + rename). Non-secret; not zeroized.

- [ ] **Step 1: Write the failing test**

```kotlin
package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File

class FileDeviceEnrollmentMetadataStoreTest {
    private val uuid = ByteArray(16) { it.toByte() }
    private val vaultId = "00112233445566778899aabbccddeeff"

    @Test
    fun load_returnsNull_whenAbsent(@TempDir dir: File) {
        assertNull(FileDeviceEnrollmentMetadataStore(dir).load())
    }

    @Test
    fun saveThenLoad_roundTrips(@TempDir dir: File) {
        val store = FileDeviceEnrollmentMetadataStore(dir)
        store.save(DeviceEnrollment(vaultId, uuid))
        val loaded = store.load()!!
        assertEquals(vaultId, loaded.vaultId)
        assertArrayEquals(uuid, loaded.deviceUuid)
    }

    @Test
    fun clear_removesEnrollment(@TempDir dir: File) {
        val store = FileDeviceEnrollmentMetadataStore(dir)
        store.save(DeviceEnrollment(vaultId, uuid))
        store.clear()
        assertNull(store.load())
    }

    @Test
    fun load_returnsNull_whenMalformed(@TempDir dir: File) {
        File(dir, "enrollment").writeBytes(byteArrayOf(1, 2, 3))
        assertNull(FileDeviceEnrollmentMetadataStore(dir).load())
    }

    @Test
    fun save_overwritesPrevious(@TempDir dir: File) {
        val store = FileDeviceEnrollmentMetadataStore(dir)
        store.save(DeviceEnrollment("aaaa", ByteArray(16) { 9 }))
        store.save(DeviceEnrollment(vaultId, uuid))
        val loaded = store.load()!!
        assertEquals(vaultId, loaded.vaultId)
        assertArrayEquals(uuid, loaded.deviceUuid)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ./gradlew :kit:test --tests 'org.secretary.browse.FileDeviceEnrollmentMetadataStoreTest'`
Expected: FAIL — class unresolved.

- [ ] **Step 3: Write minimal implementation**

```kotlin
package org.secretary.browse

import java.io.File
import java.nio.ByteBuffer

/**
 * Real [DeviceEnrollmentMetadataStore]: persists the NON-secret enrollment ([vaultId] token + 16-byte
 * [DeviceEnrollment.deviceUuid]) to a single file under [dir]. Format: 4-byte big-endian vaultId
 * length, the vaultId UTF-8 bytes, then exactly 16 uuid bytes. [load] returns null for any
 * absent / short / malformed / wrong-uuid-length file (a conservative under-report, mirroring iOS's
 * `try? metadata.load()`). [save] writes atomically (temp + rename). Non-secret → not zeroized
 * (vault-format §3a: the uuid is a loggable filename stem). Keystore-free, so host-testable.
 */
class FileDeviceEnrollmentMetadataStore(private val dir: File) : DeviceEnrollmentMetadataStore {
    private val file: File get() = File(dir, FILE_NAME)

    override fun load(): DeviceEnrollment? {
        val f = file
        if (!f.exists()) return null
        val bytes = runCatching { f.readBytes() }.getOrNull() ?: return null
        if (bytes.size < HEADER_LEN + UUID_LEN) return null
        val vaultIdLen = ByteBuffer.wrap(bytes, 0, HEADER_LEN).int
        if (vaultIdLen < 0 || bytes.size != HEADER_LEN + vaultIdLen + UUID_LEN) return null
        val vaultId = String(bytes, HEADER_LEN, vaultIdLen, Charsets.UTF_8)
        val uuid = bytes.copyOfRange(HEADER_LEN + vaultIdLen, HEADER_LEN + vaultIdLen + UUID_LEN)
        return DeviceEnrollment(vaultId, uuid)
    }

    override fun save(enrollment: DeviceEnrollment) {
        require(enrollment.deviceUuid.size == UUID_LEN) { "deviceUuid must be $UUID_LEN bytes" }
        dir.mkdirs()
        val vaultIdBytes = enrollment.vaultId.toByteArray(Charsets.UTF_8)
        val out = ByteBuffer.allocate(HEADER_LEN + vaultIdBytes.size + UUID_LEN)
            .putInt(vaultIdBytes.size)
            .put(vaultIdBytes)
            .put(enrollment.deviceUuid)
            .array()
        val tmp = File(dir, "$FILE_NAME.tmp")
        tmp.writeBytes(out)
        check(tmp.renameTo(file)) { "atomic rename of enrollment metadata failed" }
    }

    override fun clear() {
        file.delete()
    }

    private companion object {
        const val FILE_NAME = "enrollment"
        const val HEADER_LEN = 4
        const val UUID_LEN = 16
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd android && ./gradlew :kit:test --tests 'org.secretary.browse.FileDeviceEnrollmentMetadataStoreTest'`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add android/kit/src/main/kotlin/org/secretary/browse/FileDeviceEnrollmentMetadataStore.kt \
        android/kit/src/test/kotlin/org/secretary/browse/FileDeviceEnrollmentMetadataStoreTest.kt
git commit -m "feat(android): FileDeviceEnrollmentMetadataStore (C.3 slice 2)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: `KeystoreDeviceSecretEnclave` + `BiometricGate` (real enclave, instrumented)

**Files:**
- Create: `android/kit/src/main/kotlin/org/secretary/browse/KeystoreDeviceSecretEnclave.kt`
- Test: `android/kit/src/androidTest/kotlin/org/secretary/browse/KeystoreDeviceSecretEnclaveTest.kt`

**Interfaces:**
- Consumes: `DeviceSecretEnclave` interface; `DeviceUnlockError`.
- Produces: `typealias BiometricGate = suspend (cipher: javax.crypto.Cipher, reason: String) -> javax.crypto.Cipher`; `data class KeystoreKeyConfig(requireAuth: Boolean, strongBox: Boolean)` with `KeystoreKeyConfig.PRODUCTION` (requireAuth=true, strongBox=true) and `KeystoreKeyConfig.TEST_NO_AUTH` (both false); `KeystoreDeviceSecretEnclave(dir: File, gate: BiometricGate, keyAlias: String = ..., keyConfig: KeystoreKeyConfig = PRODUCTION)` implementing `isEnrolled`/`store`/`release`/`clear`.

**Why an injectable key config:** an auth-required Keystore key cannot be exercised headlessly — `Cipher.doFinal` throws `UserNotAuthenticatedException` without a real `BiometricPrompt.CryptoObject` auth. The instrumented test injects `TEST_NO_AUTH` to prove the wrap/unwrap/blob/clear/corrupt mechanics on the emulator with a passthrough gate. The real `PRODUCTION` config (auth-required + StrongBox-best-effort) is proven by the manual `adb emu finger` proof in Task 6. This is the same split iOS used (its simulator test used a fake enclave).

- [ ] **Step 1: Write the failing test**

```kotlin
package org.secretary.browse

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.SecureRandom
import javax.crypto.Cipher

/**
 * Instrumented round-trip of the REAL Keystore-backed enclave, using the TEST_NO_AUTH key config so
 * the AES/GCM wrap/unwrap runs headlessly (an auth-required key would need a live BiometricPrompt).
 * The real auth-required PRODUCTION config is proven by the manual adb-emu-finger walking skeleton.
 */
@RunWith(AndroidJUnit4::class)
class KeystoreDeviceSecretEnclaveTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val dirs = mutableListOf<File>()
    private val passthrough: BiometricGate = { cipher: Cipher, _: String -> cipher }

    private fun freshEnclave(): KeystoreDeviceSecretEnclave {
        val dir = File(context.noBackupFilesDir, "ds-test-${System.nanoTime()}").apply { mkdirs() }
        dirs += dir
        return KeystoreDeviceSecretEnclave(
            dir = dir,
            gate = passthrough,
            keyAlias = "org.secretary.test.deviceSecret.${System.nanoTime()}",
            keyConfig = KeystoreKeyConfig.TEST_NO_AUTH,
        )
    }

    @After fun cleanup() = dirs.forEach { it.deleteRecursively() }

    @Test
    fun storeThenRelease_roundTrips() = runBlocking {
        val enclave = freshEnclave()
        val secret = ByteArray(32).also { SecureRandom().nextBytes(it) }
        assertFalse(enclave.isEnrolled)
        enclave.store(secret.copyOf())
        assertTrue(enclave.isEnrolled)
        val released = enclave.release("test")
        assertArrayEquals(secret, released)
        enclave.clear()
    }

    @Test
    fun clear_dropsEnrollment() = runBlocking {
        val enclave = freshEnclave()
        enclave.store(ByteArray(32).also { SecureRandom().nextBytes(it) })
        enclave.clear()
        assertFalse(enclave.isEnrolled)
    }

    @Test
    fun release_corruptBlob_throwsWrappedSecretCorrupt() = runBlocking {
        val dir = File(context.noBackupFilesDir, "ds-corrupt-${System.nanoTime()}").apply { mkdirs() }
        dirs += dir
        val alias = "org.secretary.test.deviceSecret.corrupt.${System.nanoTime()}"
        val enclave = KeystoreDeviceSecretEnclave(dir, passthrough, alias, KeystoreKeyConfig.TEST_NO_AUTH)
        enclave.store(ByteArray(32).also { SecureRandom().nextBytes(it) })
        // Flip the last ciphertext byte → GCM tag check fails.
        val blob = File(dir, "blob")
        val bytes = blob.readBytes()
        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 0xFF).toByte()
        blob.writeBytes(bytes)
        try {
            enclave.release("test")
            fail("expected WrappedSecretCorrupt")
        } catch (e: DeviceUnlockError.WrappedSecretCorrupt) {
            // expected
        }
        enclave.clear()
    }
}
```

- [ ] **Step 2: Run test to verify it fails (emulator running)**

Run: `cd android && ANDROID_SERIAL=emulator-5554 ./gradlew :kit:connectedDebugAndroidTest --tests 'org.secretary.browse.KeystoreDeviceSecretEnclaveTest'`
Expected: FAIL — `KeystoreDeviceSecretEnclave` / `BiometricGate` / `KeystoreKeyConfig` unresolved (compile error).

- [ ] **Step 3: Write minimal implementation**

```kotlin
package org.secretary.browse

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.io.File
import java.nio.ByteBuffer
import java.security.KeyStore
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** The biometric gate: takes an initialized [Cipher] (and a [reason] to show) and returns it
 *  authorized (in production, after a BiometricPrompt(CryptoObject) auth). The :kit enclave routes
 *  both store (one enroll prompt) and release through it; the real impl lives in :app. */
typealias BiometricGate = suspend (cipher: Cipher, reason: String) -> Cipher

/** Keystore key security parameters. PRODUCTION binds the key to a strong biometric per use and
 *  prefers StrongBox; TEST_NO_AUTH is for headless instrumented mechanics tests only. */
data class KeystoreKeyConfig(val requireAuth: Boolean, val strongBox: Boolean) {
    companion object {
        val PRODUCTION = KeystoreKeyConfig(requireAuth = true, strongBox = true)
        val TEST_NO_AUTH = KeystoreKeyConfig(requireAuth = false, strongBox = false)
    }
}

/**
 * Real [DeviceSecretEnclave]: an AES-256-GCM key in the AndroidKeyStore wraps the 32-byte device
 * secret; the ciphertext+IV blob lives under [dir]. With [KeystoreKeyConfig.PRODUCTION] the key is
 * bound to a strong biometric for every use, so [store] (at enroll) and [release] (at each unlock)
 * each route their Cipher through [gate], which presents a BiometricPrompt. Android cannot scope
 * auth to decryption only for a symmetric key, hence the one enroll-time prompt.
 *
 * Mirror of iOS `SecureEnclaveDeviceSecretStore`. Keystore needs a device → instrumented-test-only.
 * [isEnrolled] checks ONLY the blob (never the key) so it never risks a prompt (iOS parity).
 */
class KeystoreDeviceSecretEnclave(
    private val dir: File,
    private val gate: BiometricGate,
    private val keyAlias: String = DEFAULT_ALIAS,
    private val keyConfig: KeystoreKeyConfig = KeystoreKeyConfig.PRODUCTION,
) : DeviceSecretEnclave {

    private val blobFile: File get() = File(dir, BLOB_NAME)

    override val isEnrolled: Boolean get() = blobFile.exists()

    override suspend fun store(secret: ByteArray) {
        val key = ensureKey()
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val authorized = gate(cipher, STORE_REASON)
        val ct = authorized.doFinal(secret)
        val iv = authorized.iv
        dir.mkdirs()
        val out = ByteBuffer.allocate(1 + iv.size + ct.size)
            .put(iv.size.toByte()).put(iv).put(ct).array()
        val tmp = File(dir, "$BLOB_NAME.tmp")
        tmp.writeBytes(out)
        check(tmp.renameTo(blobFile)) { "atomic rename of secret blob failed" }
    }

    override suspend fun release(reason: String): ByteArray {
        val blob = blobFile.takeIf { it.exists() }?.readBytes() ?: throw DeviceUnlockError.NotEnrolled
        val ivLen = blob[0].toInt()
        val iv = blob.copyOfRange(1, 1 + ivLen)
        val ct = blob.copyOfRange(1 + ivLen, blob.size)
        val key = loadKey() ?: throw DeviceUnlockError.NotEnrolled
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        val authorized = gate(cipher, reason)
        return try {
            authorized.doFinal(ct)
        } catch (e: AEADBadTagException) {
            throw DeviceUnlockError.WrappedSecretCorrupt
        }
    }

    override suspend fun clear() {
        // Best-effort BOTH deletes before surfacing failure (revocation must make maximal progress).
        val blobDeleted = !blobFile.exists() || blobFile.delete()
        val keyDeleted = runCatching {
            KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }.deleteEntry(keyAlias)
        }.isSuccess
        check(blobDeleted) { "failed to delete secret blob" }
        check(keyDeleted) { "failed to delete Keystore entry" }
    }

    private fun loadKey(): SecretKey? {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return ks.getKey(keyAlias, null) as? SecretKey
    }

    private fun ensureKey(): SecretKey {
        loadKey()?.let { return it }
        return generateKey(strongBox = keyConfig.strongBox)
    }

    private fun generateKey(strongBox: Boolean): SecretKey {
        val builder = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
        if (keyConfig.requireAuth) {
            builder.setUserAuthenticationRequired(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                // API 30+: require a strong biometric for every use (timeout 0 = per-use auth).
                builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            }
            // API 26-29: setUserAuthenticationRequired(true) alone yields per-use CryptoObject auth.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                builder.setInvalidatedByBiometricEnrollment(true)
            }
        }
        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        return try {
            generator.init(builder.build())
            generator.generateKey()
        } catch (e: StrongBoxUnavailableException) {
            // Emulator / devices without StrongBox: retry without it.
            generateKey(strongBox = false)
        }
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val DEFAULT_ALIAS = "org.secretary.deviceSecret.aesKey"
        const val BLOB_NAME = "blob"
        const val GCM_TAG_BITS = 128
        const val STORE_REASON = "Enable biometric unlock for this device"
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd android && ANDROID_SERIAL=emulator-5554 ./gradlew :kit:connectedDebugAndroidTest --tests 'org.secretary.browse.KeystoreDeviceSecretEnclaveTest'`

Note: if `--tests` is rejected for connected tests (see [[project_secretary_android_instrumented_test_gotchas]]), use `-Pandroid.testInstrumentationRunnerArguments.class=org.secretary.browse.KeystoreDeviceSecretEnclaveTest` instead.
Expected: PASS (3 tests) on the emulator.

- [ ] **Step 5: Commit**

```bash
git add android/kit/src/main/kotlin/org/secretary/browse/KeystoreDeviceSecretEnclave.kt \
        android/kit/src/androidTest/kotlin/org/secretary/browse/KeystoreDeviceSecretEnclaveTest.kt
git commit -m "feat(android): KeystoreDeviceSecretEnclave + BiometricGate (C.3 slice 2)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: `BiometricPromptGate` + `mapBiometricError` + FragmentActivity + deps

**Files:**
- Create: `android/app/src/main/kotlin/org/secretary/app/BiometricErrorMapping.kt`
- Test: `android/app/src/test/kotlin/org/secretary/app/BiometricErrorMappingTest.kt`
- Create: `android/app/src/main/kotlin/org/secretary/app/BiometricPromptGate.kt`
- Modify: `android/app/src/main/kotlin/org/secretary/app/MainActivity.kt`
- Modify: `android/app/build.gradle.kts`

**Interfaces:**
- Consumes: `DeviceUnlockError`; `BiometricGate` (from `:kit`, package `org.secretary.browse`); `androidx.biometric.BiometricPrompt`.
- Produces: `fun mapBiometricError(errorCode: Int): DeviceUnlockError`; `fun biometricPromptGate(activity: FragmentActivity, title: String): BiometricGate`.

- [ ] **Step 1: Add dependencies + flip MainActivity to FragmentActivity**

Add to `android/app/build.gradle.kts` `dependencies { ... }` (near the activity-compose line):

```kotlin
    // BiometricPrompt + CryptoObject for the device-secret unlock gate. Pulls androidx.fragment
    // transitively; declared explicitly because MainActivity extends FragmentActivity.
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.fragment:fragment-ktx:1.8.5")
```

Edit `android/app/src/main/kotlin/org/secretary/app/MainActivity.kt`:
- Replace `import androidx.activity.ComponentActivity` with `import androidx.fragment.app.FragmentActivity`.
- Replace `class MainActivity : ComponentActivity()` with `class MainActivity : FragmentActivity()`.
- Update the KDoc first line to "The single Activity (a `FragmentActivity`, required by `androidx.biometric`) for the walking skeleton."
- `setContent` stays (FragmentActivity is a ComponentActivity, so activity-compose's `setContent` extension still resolves).

- [ ] **Step 2: Write the failing test**

```kotlin
package org.secretary.app

import androidx.biometric.BiometricPrompt
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.secretary.browse.DeviceUnlockError

class BiometricErrorMappingTest {
    @Test fun userCanceled_mapsToUserCancelled() {
        assertEquals(DeviceUnlockError.UserCancelled, mapBiometricError(BiometricPrompt.ERROR_USER_CANCELED))
    }
    @Test fun negativeButton_mapsToUserCancelled() {
        assertEquals(DeviceUnlockError.UserCancelled, mapBiometricError(BiometricPrompt.ERROR_NEGATIVE_BUTTON))
    }
    @Test fun lockout_mapsToBiometryLockout() {
        assertEquals(DeviceUnlockError.BiometryLockout, mapBiometricError(BiometricPrompt.ERROR_LOCKOUT))
        assertEquals(DeviceUnlockError.BiometryLockout, mapBiometricError(BiometricPrompt.ERROR_LOCKOUT_PERMANENT))
    }
    @Test fun noBiometricEnrolled_mapsToBiometryNotEnrolled() {
        assertEquals(DeviceUnlockError.BiometryNotEnrolled, mapBiometricError(BiometricPrompt.ERROR_NO_BIOMETRICS))
    }
    @Test fun hardwareUnavailable_mapsToBiometryUnavailable() {
        assertEquals(DeviceUnlockError.BiometryUnavailable, mapBiometricError(BiometricPrompt.ERROR_HW_UNAVAILABLE))
        assertEquals(DeviceUnlockError.BiometryUnavailable, mapBiometricError(BiometricPrompt.ERROR_NO_HARDWARE))
    }
    @Test fun unknownCode_mapsToAuthenticationFailed() {
        assertEquals(DeviceUnlockError.AuthenticationFailed, mapBiometricError(Int.MAX_VALUE))
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd android && ./gradlew :app:testDebugUnitTest --tests 'org.secretary.app.BiometricErrorMappingTest'`
Expected: FAIL — `mapBiometricError` unresolved.

- [ ] **Step 4: Write minimal implementation**

`android/app/src/main/kotlin/org/secretary/app/BiometricErrorMapping.kt`:

```kotlin
package org.secretary.app

import androidx.biometric.BiometricPrompt
import org.secretary.browse.DeviceUnlockError

/**
 * Pure mapping from an [androidx.biometric.BiometricPrompt] error code to the slice-1
 * [DeviceUnlockError] taxonomy. Host-tested. Cancel/negative → [DeviceUnlockError.UserCancelled];
 * lockout → [DeviceUnlockError.BiometryLockout]; no-biometric → [DeviceUnlockError.BiometryNotEnrolled];
 * hardware → [DeviceUnlockError.BiometryUnavailable]; anything else → [DeviceUnlockError.AuthenticationFailed].
 */
fun mapBiometricError(errorCode: Int): DeviceUnlockError = when (errorCode) {
    BiometricPrompt.ERROR_USER_CANCELED,
    BiometricPrompt.ERROR_NEGATIVE_BUTTON,
    BiometricPrompt.ERROR_CANCELED -> DeviceUnlockError.UserCancelled
    BiometricPrompt.ERROR_LOCKOUT,
    BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> DeviceUnlockError.BiometryLockout
    BiometricPrompt.ERROR_NO_BIOMETRICS -> DeviceUnlockError.BiometryNotEnrolled
    BiometricPrompt.ERROR_HW_UNAVAILABLE,
    BiometricPrompt.ERROR_HW_NOT_PRESENT,
    BiometricPrompt.ERROR_NO_HARDWARE -> DeviceUnlockError.BiometryUnavailable
    else -> DeviceUnlockError.AuthenticationFailed
}
```

`android/app/src/main/kotlin/org/secretary/app/BiometricPromptGate.kt`:

```kotlin
package org.secretary.app

import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.suspendCancellableCoroutine
import org.secretary.browse.BiometricGate
import org.secretary.browse.DeviceUnlockError
import javax.crypto.Cipher
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * The real [BiometricGate] for `:app`: presents a strong-biometric [BiometricPrompt] bound to the
 * enclave's [Cipher] via [BiometricPrompt.CryptoObject], and resumes the suspend fn with the
 * authorized cipher (the one inside the auth result, NOT the input — only it is unlocked). Errors map
 * via [mapBiometricError]; a non-match (`onAuthenticationFailed`) is advisory and does NOT resume —
 * the prompt stays up until success, a hard error, or cancel.
 *
 * Must run on the main thread (BiometricPrompt requirement) — call from a main-dispatched coroutine.
 */
fun biometricPromptGate(activity: FragmentActivity, title: String): BiometricGate =
    { cipher: Cipher, reason: String ->
        suspendCancellableCoroutine { cont ->
            val executor = ContextCompat.getMainExecutor(activity)
            val prompt = BiometricPrompt(
                activity,
                executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        val authorized = result.cryptoObject?.cipher
                        if (authorized != null) {
                            cont.resume(authorized)
                        } else {
                            cont.resumeWithException(DeviceUnlockError.Enclave("no cipher in auth result"))
                        }
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        if (cont.isActive) cont.resumeWithException(mapBiometricError(errorCode))
                    }
                    // onAuthenticationFailed (single non-match) is intentionally not handled: the
                    // prompt remains until success / a terminal error / cancel.
                },
            )
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setSubtitle(reason)
                .setNegativeButtonText("Use password")
                .setAllowedAuthenticators(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .build()
            prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
        }
    }
```

- [ ] **Step 5: Run test to verify it passes + app compiles**

Run: `cd android && ./gradlew :app:testDebugUnitTest --tests 'org.secretary.app.BiometricErrorMappingTest' && ./gradlew :app:compileDebugKotlin`
Expected: tests PASS (8 tests); compile SUCCESS (FragmentActivity + biometric resolve).

- [ ] **Step 6: Commit**

```bash
git add android/app/src/main/kotlin/org/secretary/app/BiometricErrorMapping.kt \
        android/app/src/test/kotlin/org/secretary/app/BiometricErrorMappingTest.kt \
        android/app/src/main/kotlin/org/secretary/app/BiometricPromptGate.kt \
        android/app/src/main/kotlin/org/secretary/app/MainActivity.kt \
        android/app/build.gradle.kts
git commit -m "feat(android): BiometricPromptGate + error mapping + FragmentActivity (C.3 slice 2)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: `UnlockScreen` affordances (remember checkbox + biometric-unlock button)

**Files:**
- Modify: `android/app/src/main/kotlin/org/secretary/app/UnlockScreen.kt`
- Test: `android/app/src/androidTest/kotlin/org/secretary/app/UnlockScreenDeviceUiTest.kt`

**Interfaces:**
- Consumes: `UnlockCredential`, `RecoveryPhrase` (existing).
- Produces: an updated `UnlockScreen(isEnrolled: Boolean, onUnlock: (UnlockCredential) -> Unit, onEnrollChoice: (Boolean) -> Unit, onBiometricUnlock: () -> Unit)`. New test tags: `remember-device` (checkbox, password mode, only when `!isEnrolled`), `biometric-unlock` (button, only when `isEnrolled`).

- [ ] **Step 1: Write the failing test**

```kotlin
package org.secretary.app

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.secretary.browse.UnlockCredential

class UnlockScreenDeviceUiTest {
    @get:Rule val composeRule = createComposeRule()

    @Test
    fun enrolled_showsBiometricUnlockButton_andInvokesCallback() {
        var biometricTapped = false
        composeRule.setContent {
            UnlockScreen(
                isEnrolled = true,
                onUnlock = {},
                onEnrollChoice = {},
                onBiometricUnlock = { biometricTapped = true },
            )
        }
        composeRule.onNodeWithTag("biometric-unlock").assertIsDisplayed().performClick()
        assertTrue(biometricTapped)
    }

    @Test
    fun notEnrolled_passwordMode_showsRememberCheckbox_andReportsChoice() {
        var lastChoice: Boolean? = null
        composeRule.setContent {
            UnlockScreen(
                isEnrolled = false,
                onUnlock = {},
                onEnrollChoice = { lastChoice = it },
                onBiometricUnlock = {},
            )
        }
        composeRule.onNodeWithTag("remember-device").assertIsDisplayed().performClick()
        assertTrue(lastChoice == true)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ANDROID_SERIAL=emulator-5554 ./gradlew :app:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.app.UnlockScreenDeviceUiTest`
Expected: FAIL — `UnlockScreen` signature mismatch / tags absent.

- [ ] **Step 3: Update `UnlockScreen`**

Change the signature and body of `android/app/src/main/kotlin/org/secretary/app/UnlockScreen.kt`:

- New signature:
```kotlin
@Composable
fun UnlockScreen(
    isEnrolled: Boolean,
    onUnlock: (UnlockCredential) -> Unit,
    onEnrollChoice: (Boolean) -> Unit,
    onBiometricUnlock: () -> Unit,
) {
```
- Add `var remember by remember { mutableStateOf(false) }` alongside the existing `mode`/`password`/`phrase` state.
- Immediately after the `Text("Secretary — demo vault")` line, when `isEnrolled`, render the biometric button:
```kotlin
        if (isEnrolled) {
            Button(
                onClick = onBiometricUnlock,
                modifier = Modifier.fillMaxWidth().testTag("biometric-unlock"),
            ) { Text("Unlock with biometrics") }
        }
```
- Inside `UnlockMode.Password ->` branch, AFTER the `OutlinedTextField`, when `!isEnrolled`, render the checkbox row (import `androidx.compose.foundation.layout.Row`, `androidx.compose.material3.Checkbox`, `androidx.compose.ui.Alignment`):
```kotlin
            if (!isEnrolled) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(
                        checked = remember,
                        onCheckedChange = { remember = it; onEnrollChoice(it) },
                        modifier = Modifier.testTag("remember-device"),
                    )
                    Text("Remember this device with biometrics")
                }
            }
```
  > Note: `Password` mode's `OutlinedTextField` + this checkbox must both live inside the `when` arm. Because the existing arm is a single expression (`UnlockMode.Password -> OutlinedTextField(...)`), wrap it in a `Column { ... }` so the arm holds both the field and the checkbox row.
- The existing `onUnlock(credential)` Button and `Recovery` arm are unchanged.
- Update the KDoc to mention the new affordances + that `onEnrollChoice` carries the "remember" intent for AppRoot to enroll after a password unlock.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd android && ANDROID_SERIAL=emulator-5554 ./gradlew :app:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.app.UnlockScreenDeviceUiTest`
Expected: PASS (2 tests).

Also fix the existing `UnlockScreenRecoveryUiTest` call site if it constructs `UnlockScreen(...)` with the old signature — pass `isEnrolled = false, onEnrollChoice = {}, onBiometricUnlock = {}`. Run it to confirm: same connected-test command with `...class=org.secretary.app.UnlockScreenRecoveryUiTest` → PASS.

- [ ] **Step 5: Commit**

```bash
git add android/app/src/main/kotlin/org/secretary/app/UnlockScreen.kt \
        android/app/src/androidTest/kotlin/org/secretary/app/UnlockScreenDeviceUiTest.kt \
        android/app/src/androidTest/kotlin/org/secretary/app/UnlockScreenRecoveryUiTest.kt
git commit -m "feat(android): UnlockScreen biometric affordances (C.3 slice 2)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: `AppRoot` wiring + on-device biometric proof

**Files:**
- Modify: `android/app/src/main/kotlin/org/secretary/app/AppRoot.kt`

**Interfaces:**
- Consumes: `DeviceUnlockCoordinator`, `DeviceUnlockViewModel`, `KeystoreDeviceSecretEnclave`, `FileDeviceEnrollmentMetadataStore`, `UniffiVaultDeviceSlotPort`, `biometricPromptGate`, `AppVaultProvisioning.{stageGoldenVault, goldenVaultUuid, goldenPassword}`, `hexOfBytes`, the existing `openBrowseWithSync`/`dispatchPostOpenSync`/`unlockAndOpen` helpers, `UnlockCredential`.
- Produces: an `AppRoot` whose Unlock route constructs the coordinator once (real enclave + gate + metadata + slot port), enrolls when "remember" was chosen on a password unlock, and routes a biometric unlock through `unlockAndOpen`.

> This task is glue; its proof is the manual on-device round-trip (Steps 4–5), not a host test. The pure decisions are already covered by Tasks 1 & 4.

- [ ] **Step 1: Wire the coordinator + enroll path + biometric path**

Edit `AppRoot.kt`:
- The `AppRoot()` composable needs the hosting `FragmentActivity` to build the gate. Obtain it: `val activity = LocalContext.current as FragmentActivity` (import `androidx.fragment.app.FragmentActivity`). (MainActivity is now a FragmentActivity — Task 4.)
- Build the coordinator + VM once with `remember`:
```kotlin
    val vaultId = remember { hexOfBytes(AppVaultProvisioning.goldenVaultUuid(context)) }
    val coordinator = remember(activity) {
        val gate = biometricPromptGate(activity, title = "Unlock Secretary")
        val enclave = KeystoreDeviceSecretEnclave(
            dir = File(context.noBackupFilesDir, "devicesecret"),
            gate = gate,
        )
        val metadata = FileDeviceEnrollmentMetadataStore(File(context.noBackupFilesDir, "devicesecret"))
        DeviceUnlockCoordinator(UniffiVaultDeviceSlotPort(), enclave, metadata)
    }
    val deviceVm = remember(coordinator) { DeviceUnlockViewModel(coordinator) }
    LaunchedEffect(coordinator) { deviceVm.refresh() }
```
- The `Route.Unlock` arm renders `UnlockScreen` with the new params. Track the "remember" choice in a `var rememberDevice by remember { mutableStateOf(false) }`:
```kotlin
        is Route.Unlock -> UnlockScreen(
            isEnrolled = deviceVm.state is DeviceUnlockState.Enrolled,
            onUnlock = { credential ->
                scope.launch { route = unlockAndOpen(context, scope, credential, enrollAfter = rememberDevice, coordinator, vaultId) }
            },
            onEnrollChoice = { rememberDevice = it },
            onBiometricUnlock = {
                scope.launch {
                    deviceVm.unlockWithBiometrics(
                        folder = AppVaultProvisioning.stageGoldenVault(context).path,
                        vaultId = vaultId,
                        reason = "Unlock your vault",
                    ) { credential -> route = unlockAndOpen(context, scope, credential, enrollAfter = false, coordinator, vaultId) }
                }
            },
        )
```
- Extend `unlockAndOpen` to optionally enroll after a successful password open. Add params `enrollAfter: Boolean`, `coordinator: DeviceUnlockCoordinator`, `vaultId: String`. After `openBrowseWithSync` succeeds and BEFORE the `finally` zeroize, when `credential is UnlockCredential.Password && enrollAfter`, enroll (non-fatal):
```kotlin
        if (enrollAfter && credential is UnlockCredential.Password) {
            try {
                coordinator.enroll(folder, vaultId, credential.secret)
            } catch (e: Exception) {
                Log.w(TAG, "device enroll failed; password open still succeeded", e)
            }
        }
```
  (The existing `finally { credential.secret.fill(0) }` still zeroizes after enroll copies it into the enclave. Enroll runs on the main `scope`; the coordinator's `addDeviceSlot` hops to IO internally — same offload contract as the open. The `folder` here is the already-staged folder used for the open.)
- The biometric path reuses `unlockAndOpen` with the `DeviceSecret` credential → `openBrowseWithSync` → `dispatchPostOpenSync` (DeviceSecret arm → status-only, slice 1). No change to `dispatchPostOpenSync`.

- [ ] **Step 2: Build the app**

Run: `cd android && ./gradlew :app:compileDebugKotlin :app:assembleDebug`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 3: Run the full host suite + the connected smoke regressions**

Run:
```bash
cd android && ./gradlew :vault-access:test :kit:test :app:testDebugUnitTest :browse-ui:test
ANDROID_SERIAL=emulator-5554 ./gradlew :app:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.app.OpenWithDeviceSecretSmokeTest
```
Expected: host BUILD SUCCESSFUL; the slice-1 device-secret smoke still PASS (regression — the credential pipeline is unchanged).

- [ ] **Step 4: Manual on-device biometric proof (emulator fingerprint)**

Prereqs (emulator with a fingerprint enrolled in Settings → Security):
```bash
export PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH"
cd android && ANDROID_SERIAL=emulator-5554 ./gradlew :app:installDebug
adb -s emulator-5554 shell am start -n org.secretary.app/.MainActivity
```
Procedure:
1. In the app (Password mode), type the golden password, CHECK "Remember this device with biometrics", tap "Unlock & Sync". At the enroll-time biometric prompt, approve: `adb -s emulator-5554 emu finger touch 1`. Confirm you reach `BrowseWithSyncScreen`.
2. Background + kill: `adb -s emulator-5554 shell am force-stop org.secretary.app`.
3. Relaunch (`am start ...`). Confirm "Unlock with biometrics" is shown. Tap it; at the prompt run `adb -s emulator-5554 emu finger touch 1`. Confirm you reach `BrowseWithSyncScreen`.
4. Negative check: relaunch, tap "Unlock with biometrics", then cancel the prompt (tap "Use password" or `adb ... emu finger touch 2` for a non-match then cancel). Confirm the app stays on the unlock screen (no crash, `UserCancelled` surfaced).

Record the result (device model + API) in the handoff. This is the acceptance gate (the real-biometric analogue of iOS #202).

- [ ] **Step 5: Commit**

```bash
git add android/app/src/main/kotlin/org/secretary/app/AppRoot.kt
git commit -m "feat(android): AppRoot device-biometric enroll + unlock wiring (C.3 slice 2)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 7: Docs (README + ROADMAP)

**Files:**
- Modify: `README.md`
- Modify: `ROADMAP.md`

- [ ] **Step 1: Update README + ROADMAP**

- In `README.md`, find the C.3 device-open slice-1 line/dot-point added by `#262` and add a sibling marking slice 2 ✅: real Android biometric device open (Keystore-gated `BiometricPrompt`, on-device proof). Keep it a brief dot-point (per [[feedback_readme_style]] — no test-count walls).
- In `ROADMAP.md`, flip the C.3 "device-open slice 2 (biometric + UI)" row from planned → ✅ 2026-06-19, mirroring how the slice-1 row was marked.

- [ ] **Step 2: Verify the guardrails are still empty**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-device-biometric
git diff main...HEAD --name-only | grep -E 'core/|ffi/|crypto-design|vault-format'   # expect empty
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md)'  # expect empty (no ios/)
```
Expected: both empty.

- [ ] **Step 3: Commit**

```bash
git add README.md ROADMAP.md
git commit -m "docs: C.3 Android real biometric device open slice 2 (README + ROADMAP)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review (completed during planning)

**Spec coverage:**
- §3.1 `DeviceUnlockViewModel` → Task 1. ✅
- §3.2 `KeystoreDeviceSecretEnclave` + `BiometricGate` → Task 3; `FileDeviceEnrollmentMetadataStore` → Task 2. ✅
- §3.2.1 gate seam (store + release route through gate; auto-approving in test) → Task 3 (passthrough gate + injectable `KeystoreKeyConfig` for headless mechanics; the auth-required path proven manually in Task 6). ✅
- §3.3 `BiometricPromptGate` → Task 4; `MainActivity` → FragmentActivity + biometric dep → Task 4; `UnlockScreen` affordances → Task 5; `AppRoot` wiring → Task 6. ✅
- §4 data flow (enroll-after-password / biometric-unlock) → Task 6. ✅
- §5 error handling: guards-before-release → covered by Task 1 tests; `BiometricPrompt`→`DeviceUnlockError` mapping → Task 4; `WrappedSecretCorrupt` on AEAD failure → Task 3 test; non-fatal enroll → Task 6. ✅
- §6 testing: host VM (Task 1), instrumented enclave (Task 3), manual proof (Task 6). ✅
- §7 open items: lockout case — resolved (taxonomy already has `BiometryLockout`, no new variant); enroll-prompt validated in Task 6 manual proof; CodeQL random dummy — Task 3 uses `SecureRandom`. ✅
- §8 guardrails → Task 7 Step 2. ✅

**Spec deviation (intentional, documented):** the spec's "auto-approving gate" alone is insufficient because an auth-required key blocks `doFinal` headlessly; Task 3 therefore also injects a non-auth `KeystoreKeyConfig` for the instrumented mechanics test, with the real config proven manually. This strengthens, not weakens, the spec intent (real Keystore crypto IS exercised on-device).

**Type consistency:** `DeviceUnlockState` (Unenrolled/Enrolled/Prompting/Failed) consistent across Tasks 1, 5, 6. `BiometricGate = suspend (Cipher, String) -> Cipher` consistent Tasks 3, 4. `KeystoreKeyConfig.{PRODUCTION,TEST_NO_AUTH}` consistent Task 3. `mapBiometricError(Int): DeviceUnlockError` consistent Task 4. `UnlockScreen(isEnrolled, onUnlock, onEnrollChoice, onBiometricUnlock)` consistent Tasks 5, 6. `DeviceEnrollment(vaultId: String, deviceUuid: ByteArray)` matches slice-1 source.

**Placeholder scan:** no TBD/TODO; every code step shows full code; commands have expected output.
