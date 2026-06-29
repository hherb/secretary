# Cloud-vault device enrollment + biometric write-reauth — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring the Android cloud-drive vault path to biometric write-reauth parity with iOS — a device can be enrolled against a cloud working copy (opt-in), and writes to that cloud vault are gated by a `GraceWindowReauthGate` with a real biometric prompt.

**Architecture:** Approach A — a per-vault DeviceUnlock factory. The pure `:vault-access` layer (`DeviceUnlockCoordinator`, `GraceWindowReauthGate`, `CoordinatorBiometricAuthorizer`, the three port interfaces) is **unchanged**. The work is keying + wiring in `:app`, reusing the already-parameterized `:kit` stores (`KeystoreDeviceSecretEnclave(dir, gate, keyAlias)`, `FileDeviceEnrollmentMetadataStore(dir)`) under a per-vault namespace keyed by the existing `cloudVaultKey(treeUri)`. Cloud open stays password-based (write-reauth only); the demo path is byte-identical (zero migration).

**Tech Stack:** Kotlin, Android (Gradle modules `:vault-access`, `:kit`, `:app`), AndroidKeyStore + BiometricPrompt, SAF (`DocumentsProvider`), JUnit host tests + instrumented (`androidTest`) tests, uniffi FFI bridge (unchanged).

## Global Constraints

- **No core `src/` / on-disk-format / spec / `conformance.py` / conflict-KAT / observable-byte / FFI-surface change.** Kotlin/Android only.
- **Conformance must stay 27/27** (Kotlin + Swift): `bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh` and `.../swift/run_conformance.sh`.
- **Rust gate must stay clean** even though no Rust changes: `cargo fmt --all --check` and `cargo clippy --release --workspace --tests -- -D warnings`.
- **Demo path unchanged** — `noBackupFilesDir/devicesecret/` + `KeystoreDeviceSecretEnclave.DEFAULT_ALIAS` keep their current paths; cloud uses a `cloud/<key>/` sub-namespace.
- **Keying primitive:** `cloudVaultKey(treeUri)` (`app/.../ProvisioningRouting.kt:29`) — a stable hash of the cloud treeUri, the SAME key used for the working dir + pending-flush marker.
- **Monotonic clock only** for the grace window — `SystemClock.elapsedRealtime()`, never wall-clock (NTP/user-clock immune). 30s window = `ReauthWindow.V1_DEFAULT_MS`.
- **No magic numbers**; **files under 500 lines** (extract `CloudDeviceUnlock.kt` + `CloudDeviceEnroll.kt` rather than growing `CloudVaultOpen.kt`/`AppRoot.kt`).
- **Secret hygiene:** `password`/`secret` byte arrays are zeroized by the existing owners; the enroll path forwards the caller-owned password (does not zeroize it — `openCloudBrowse`'s `finally` does, as today).
- **Working-dir discipline:** all commands run from the worktree `/Users/hherb/src/secretary/.worktrees/android-cloud-vault-biometric-reauth`; `cd android` for Gradle. Edits target the `.worktrees/...` path, not the main repo.

## File structure

| File | Responsibility | New? |
|---|---|---|
| `android/app/src/main/kotlin/org/secretary/app/CloudDeviceUnlock.kt` | Per-vault keying (pure path/alias helpers), the `CloudDeviceUnlock` holder + `cloudDeviceUnlockCoordinator(...)` factory, and the pure `cloudReauthRoute(...)` gate-decision. | Create |
| `android/app/src/main/kotlin/org/secretary/app/CloudDeviceEnroll.kt` | `cloudEnrollThisDevice(...)` — atomic enroll-with-flush orchestration (rollback on flush failure, idempotent skip). | Create |
| `android/app/src/main/kotlin/org/secretary/app/CloudVaultOpen.kt` | `cloudCoordinator` refactored to accept a prebuilt mirror; `openCloudBrowse` gains the device-unlock + enroll wiring, replaces the hardcoded `NoopReauthGate`; `openCloudTarget` threads `rememberDevice`. | Modify |
| `android/app/src/main/kotlin/org/secretary/app/AppRoot.kt` | Thread `rememberDevice` from the cloud `onUnlock` branch into `openCloudTarget`. | Modify |
| `android/app/src/test/kotlin/org/secretary/app/CloudReauthRouteTest.kt` | Host: `cloudReauthRoute` decision table + path/alias keying. | Create |
| `android/app/src/test/kotlin/org/secretary/app/CloudDeviceEnrollTest.kt` | Host: enroll-with-flush over a real `DeviceUnlockCoordinator` built on fakes (rollback, idempotent skip). | Create |
| `android/app/src/androidTest/kotlin/org/secretary/app/CloudDeviceEnrollInstrumentedTest.kt` | Instrumented: keyed Keystore two-key isolation + cloud enroll round-trip over real SAF + write-reauth over a cloud vault (auto-approve gate). | Create |

---

### Task 1: `cloudReauthRoute` + per-vault keying helpers (pure, host-tested)

**Files:**
- Create: `android/app/src/main/kotlin/org/secretary/app/CloudDeviceUnlock.kt`
- Test: `android/app/src/test/kotlin/org/secretary/app/CloudReauthRouteTest.kt`

**Interfaces:**
- Consumes: `cloudVaultKey(treeUri)` (`ProvisioningRouting.kt`), `java.io.File`.
- Produces:
  - `enum class GateChoice { GRACE_WINDOW, NOOP }`
  - `fun cloudReauthRoute(enclaveEnrolled: Boolean, openVaultId: String, metadataVaultId: String?): GateChoice`
  - `fun cloudDeviceSecretDir(noBackupBase: File, cloudKey: String): File`  → `File(noBackupBase, "devicesecret/cloud/$cloudKey")`
  - `fun cloudDeviceKeyAlias(cloudKey: String): String` → `"$CLOUD_DEVICE_ALIAS_PREFIX$cloudKey"`
  - `const val CLOUD_DEVICE_ALIAS_PREFIX = "secretary.devicesecret.cloud."`

- [ ] **Step 1: Write the failing test**

```kotlin
package org.secretary.app

import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

class CloudReauthRouteTest {
    @Test fun unenrolled_uses_noop() {
        assertEquals(GateChoice.NOOP, cloudReauthRoute(enclaveEnrolled = false, openVaultId = "abcd", metadataVaultId = "abcd"))
    }

    @Test fun enrolled_matching_vault_uses_grace_window() {
        assertEquals(GateChoice.GRACE_WINDOW, cloudReauthRoute(enclaveEnrolled = true, openVaultId = "abcd", metadataVaultId = "abcd"))
    }

    @Test fun enrolled_mismatched_vault_uses_noop() {
        // stale enrollment for a treeUri whose underlying vault changed → don't block writes
        assertEquals(GateChoice.NOOP, cloudReauthRoute(enclaveEnrolled = true, openVaultId = "abcd", metadataVaultId = "ef01"))
    }

    @Test fun enrolled_null_metadata_uses_noop() {
        assertEquals(GateChoice.NOOP, cloudReauthRoute(enclaveEnrolled = true, openVaultId = "abcd", metadataVaultId = null))
    }

    @Test fun device_secret_dir_is_namespaced_by_key() {
        val base = File("/data/nobackup")
        assertEquals(File("/data/nobackup/devicesecret/cloud/KEY123"), cloudDeviceSecretDir(base, "KEY123"))
    }

    @Test fun device_dir_differs_per_key() {
        val base = File("/data/nobackup")
        assert(cloudDeviceSecretDir(base, "A") != cloudDeviceSecretDir(base, "B"))
    }

    @Test fun key_alias_is_prefixed_and_per_key() {
        assertEquals("secretary.devicesecret.cloud.KEY123", cloudDeviceKeyAlias("KEY123"))
        assert(cloudDeviceKeyAlias("A") != cloudDeviceKeyAlias("B"))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ./gradlew :app:testDebugUnitTest --tests 'org.secretary.app.CloudReauthRouteTest'`
Expected: FAIL — `cloudReauthRoute` / `GateChoice` / helpers unresolved.

- [ ] **Step 3: Write minimal implementation** (the `CloudDeviceUnlock`/factory parts come in Task 2; this step adds only the pure functions)

```kotlin
package org.secretary.app

import java.io.File

/** Which write-reauth gate the cloud open path should use, decided purely from enrollment state. */
enum class GateChoice { GRACE_WINDOW, NOOP }

/** Alias prefix for the per-cloud-vault Keystore key (kept distinct from the demo DEFAULT_ALIAS). */
const val CLOUD_DEVICE_ALIAS_PREFIX = "secretary.devicesecret.cloud."

/**
 * Decide the write-reauth gate for a cloud open. Pure: the caller reads [enclaveEnrolled]
 * (`enclave.isEnrolled`) and [metadataVaultId] (`metadata.load()?.vaultId`) and passes them in.
 *
 * A [GateChoice.GRACE_WINDOW] is returned ONLY when a secret is enrolled AND the stored enrollment
 * is for THIS [openVaultId] — a stale enrollment (different vault behind the same treeUri, or no
 * metadata) falls back to [GateChoice.NOOP] so writes are not blocked by a mismatched slot
 * (which would otherwise throw `VaultSlotMismatch` on every write).
 */
fun cloudReauthRoute(enclaveEnrolled: Boolean, openVaultId: String, metadataVaultId: String?): GateChoice =
    if (enclaveEnrolled && metadataVaultId != null && metadataVaultId == openVaultId) {
        GateChoice.GRACE_WINDOW
    } else {
        GateChoice.NOOP
    }

/** Per-cloud-vault device-secret dir (enclave blob + metadata), namespaced under the demo's parent. */
fun cloudDeviceSecretDir(noBackupBase: File, cloudKey: String): File =
    File(noBackupBase, "devicesecret/cloud/$cloudKey")

/** Per-cloud-vault Keystore key alias. */
fun cloudDeviceKeyAlias(cloudKey: String): String = "$CLOUD_DEVICE_ALIAS_PREFIX$cloudKey"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd android && ./gradlew :app:testDebugUnitTest --tests 'org.secretary.app.CloudReauthRouteTest'`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
git add android/app/src/main/kotlin/org/secretary/app/CloudDeviceUnlock.kt \
        android/app/src/test/kotlin/org/secretary/app/CloudReauthRouteTest.kt
git commit -m "feat(android): cloudReauthRoute + per-vault device-secret keying (pure)"
```

---

### Task 2: `CloudDeviceUnlock` holder + factory

**Files:**
- Modify: `android/app/src/main/kotlin/org/secretary/app/CloudDeviceUnlock.kt`

**Interfaces:**
- Consumes: `KeystoreDeviceSecretEnclave(dir, gate, keyAlias)`, `FileDeviceEnrollmentMetadataStore(dir)`, `UniffiVaultDeviceSlotPort()`, `DeviceUnlockCoordinator`, `biometricPromptGate(activity, title)` (`BiometricPromptGate.kt`), `DeviceSecretEnclave`, `DeviceEnrollmentMetadataStore`, `cloudDeviceSecretDir`, `cloudDeviceKeyAlias` (Task 1).
- Produces:
  - `class CloudDeviceUnlock(val coordinator: DeviceUnlockCoordinator, enclave: DeviceSecretEnclave, metadata: DeviceEnrollmentMetadataStore)` with `val enclaveEnrolled: Boolean` and `val metadataVaultId: String?`.
  - `fun cloudDeviceUnlockCoordinator(activity: FragmentActivity, noBackupBase: File, cloudKey: String): CloudDeviceUnlock`

This task is thin platform glue (Keystore + Context); it has no host unit test of its own — the keying is host-tested in Task 1 (paths/alias) and the live construction is exercised end-to-end by the instrumented round-trip in Task 5. Verify by compiling `:app`.

- [ ] **Step 1: Add the holder + factory** to `CloudDeviceUnlock.kt`

```kotlin
import androidx.fragment.app.FragmentActivity
import org.secretary.browse.DeviceEnrollmentMetadataStore
import org.secretary.browse.DeviceSecretEnclave
import org.secretary.browse.DeviceUnlockCoordinator
import org.secretary.browse.FileDeviceEnrollmentMetadataStore
import org.secretary.browse.KeystoreDeviceSecretEnclave
import org.secretary.browse.UniffiVaultDeviceSlotPort

/**
 * A cloud vault's device-unlock surface: the [coordinator] (enroll/unlock/disenroll) plus cheap,
 * non-prompting reads of enrollment state used to pick the write-reauth gate. The enclave + metadata
 * are namespaced per cloud vault (by [cloudVaultKey]) so demo and multiple cloud vaults hold
 * independent secrets with no cross-talk.
 */
class CloudDeviceUnlock(
    val coordinator: DeviceUnlockCoordinator,
    private val enclave: DeviceSecretEnclave,
    private val metadata: DeviceEnrollmentMetadataStore,
) {
    /** True iff a secret blob exists for this cloud vault (cheap; never prompts). */
    val enclaveEnrolled: Boolean get() = enclave.isEnrolled

    /** The vaultId this device is enrolled against, or null if no metadata. Never prompts. */
    val metadataVaultId: String? get() = runCatching { metadata.load() }.getOrNull()?.vaultId
}

/**
 * Build the per-cloud-vault [CloudDeviceUnlock] keyed by [cloudKey]. The enclave + metadata live under
 * [cloudDeviceSecretDir]; the Keystore key uses [cloudDeviceKeyAlias]. The biometric gate is the same
 * production [biometricPromptGate] the demo uses (titled for cloud unlock).
 */
fun cloudDeviceUnlockCoordinator(
    activity: FragmentActivity,
    noBackupBase: File,
    cloudKey: String,
): CloudDeviceUnlock {
    val dir = cloudDeviceSecretDir(noBackupBase, cloudKey)
    val enclave = KeystoreDeviceSecretEnclave(
        dir = dir,
        gate = biometricPromptGate(activity, title = "Unlock Secretary"),
        keyAlias = cloudDeviceKeyAlias(cloudKey),
    )
    val metadata = FileDeviceEnrollmentMetadataStore(dir)
    val coordinator = DeviceUnlockCoordinator(UniffiVaultDeviceSlotPort(), enclave, metadata)
    return CloudDeviceUnlock(coordinator, enclave, metadata)
}
```

- [ ] **Step 2: Verify `:app` compiles**

Run: `cd android && ./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 3: Commit**

```bash
git add android/app/src/main/kotlin/org/secretary/app/CloudDeviceUnlock.kt
git commit -m "feat(android): CloudDeviceUnlock holder + per-vault factory"
```

---

### Task 3: `cloudEnrollThisDevice` — atomic enroll-with-flush (host-tested)

**Files:**
- Create: `android/app/src/main/kotlin/org/secretary/app/CloudDeviceEnroll.kt`
- Test: `android/app/src/test/kotlin/org/secretary/app/CloudDeviceEnrollTest.kt`

**Interfaces:**
- Consumes: `DeviceUnlockCoordinator` (`enroll(folder, vaultId, password)`, `disenroll(folder)`, `isEnrolled`), and the existing ports `VaultDeviceSlotPort` / `DeviceSecretEnclave` / `DeviceEnrollmentMetadataStore` (constructed with fakes in the test).
- Produces (returns `Unit`, throws on hard failure — caller treats as non-fatal):
  - `suspend fun cloudEnrollThisDevice(coordinator: DeviceUnlockCoordinator, alreadyEnrolledForThisVault: Boolean, workingDirPath: String, vaultId: String, password: ByteArray, flushWorkingToCloud: suspend () -> Unit)`

Semantics: idempotent skip when `alreadyEnrolledForThisVault` (the caller precomputes it as `enclave.isEnrolled && metadata.load()?.vaultId == vaultId`, avoiding any widening of the coordinator's API); else `coordinator.enroll(...)` then `flushWorkingToCloud()`; if the flush throws, `coordinator.disenroll(workingDirPath)` (full rollback) and rethrow.

- [ ] **Step 1: Write the failing test**

```kotlin
package org.secretary.app

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.secretary.browse.DeviceEnrollment
import org.secretary.browse.DeviceEnrollmentMetadataStore
import org.secretary.browse.DeviceSecretEnclave
import org.secretary.browse.DeviceUnlockCoordinator
import org.secretary.browse.EnrolledSlot
import org.secretary.browse.VaultDeviceSlotPort

private class FakeSlotPort(var failAdd: Boolean = false) : VaultDeviceSlotPort {
    val added = mutableListOf<ByteArray>()
    val removed = mutableListOf<ByteArray>()
    override suspend fun addDeviceSlot(vaultFolder: String, password: ByteArray): EnrolledSlot {
        if (failAdd) throw RuntimeException("addDeviceSlot failed")
        val uuid = ByteArray(16) { 0x11 }
        added += uuid
        return EnrolledSlot(uuid, ByteArray(32) { 0x22 })
    }
    override suspend fun removeDeviceSlot(vaultFolder: String, deviceUuid: ByteArray) { removed += deviceUuid }
}

private class FakeEnclave : DeviceSecretEnclave {
    private var blob: ByteArray? = null
    override val isEnrolled: Boolean get() = blob != null
    override suspend fun store(secret: ByteArray) { blob = secret.copyOf() }
    override suspend fun release(reason: String): ByteArray = blob!!.copyOf()
    override suspend fun clear() { blob = null }
}

private class FakeMetadata : DeviceEnrollmentMetadataStore {
    private var e: DeviceEnrollment? = null
    override fun load(): DeviceEnrollment? = e
    override fun save(enrollment: DeviceEnrollment) { e = enrollment }
    override fun clear() { e = null }
}

class CloudDeviceEnrollTest {
    private fun coordinator(slot: FakeSlotPort, enclave: FakeEnclave, meta: FakeMetadata) =
        DeviceUnlockCoordinator(slot, enclave, meta)

    @Test fun happy_path_enrolls_and_flushes() = runBlocking {
        val slot = FakeSlotPort(); val enclave = FakeEnclave(); val meta = FakeMetadata()
        var flushed = false
        cloudEnrollThisDevice(coordinator(slot, enclave, meta), alreadyEnrolledForThisVault = false, "/wd", "abcd", ByteArray(8) { 1 }) { flushed = true }
        assertTrue(enclave.isEnrolled)
        assertEquals("abcd", meta.load()?.vaultId)
        assertTrue(flushed)
        assertEquals(1, slot.added.size)
        assertEquals(0, slot.removed.size)
    }

    @Test fun flush_failure_rolls_back_fully() = runBlocking {
        val slot = FakeSlotPort(); val enclave = FakeEnclave(); val meta = FakeMetadata()
        try {
            cloudEnrollThisDevice(coordinator(slot, enclave, meta), alreadyEnrolledForThisVault = false, "/wd", "abcd", ByteArray(8) { 1 }) {
                throw RuntimeException("flush to cloud failed")
            }
            fail("expected the flush failure to propagate")
        } catch (e: RuntimeException) {
            assertEquals("flush to cloud failed", e.message)
        }
        // Full rollback: enclave cleared, metadata cleared, slot removed — no orphan enrollment.
        assertFalse(enclave.isEnrolled)
        assertNull(meta.load())
        assertEquals(1, slot.removed.size)
    }

    @Test fun already_enrolled_for_same_vault_is_a_noop_skip() = runBlocking {
        val slot = FakeSlotPort(); val enclave = FakeEnclave(); val meta = FakeMetadata()
        // Pre-enroll for "abcd".
        cloudEnrollThisDevice(coordinator(slot, enclave, meta), alreadyEnrolledForThisVault = false, "/wd", "abcd", ByteArray(8) { 1 }) {}
        var flushedAgain = false
        val alreadyEnrolled = enclave.isEnrolled && meta.load()?.vaultId == "abcd"
        cloudEnrollThisDevice(coordinator(slot, enclave, meta), alreadyEnrolledForThisVault = alreadyEnrolled, "/wd", "abcd", ByteArray(8) { 1 }) { flushedAgain = true }
        // No second slot minted, no second flush.
        assertEquals(1, slot.added.size)
        assertFalse(flushedAgain)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ./gradlew :app:testDebugUnitTest --tests 'org.secretary.app.CloudDeviceEnrollTest'`
Expected: FAIL — `cloudEnrollThisDevice` unresolved.

- [ ] **Step 3: Write minimal implementation**

```kotlin
package org.secretary.app

import org.secretary.browse.DeviceUnlockCoordinator

/**
 * Enrol this device against a cloud working copy, ATOMICALLY including the cloud round-trip.
 *
 * 1. If [alreadyEnrolledForThisVault], do nothing (avoids minting a duplicate slot on re-open). The
 *    caller computes it as `enclave.isEnrolled && metadata.load()?.vaultId == vaultId` — keeping the
 *    metadata read at the call site so this function takes no extra dependency and stays pure-ish.
 * 2. `coordinator.enroll` mints `devices/<uuid>.wrap` into the working copy, stores the secret in the
 *    keyed Keystore enclave, and saves keyed metadata (its own internal rollback covers slot/enclave/
 *    metadata failures).
 * 3. [flushWorkingToCloud] pushes the new wrap file to the cloud (the THROWING `mirror.flush()`, not
 *    `afterCommit` which swallows). If it throws, the slot lives only locally — a half-enrolled state
 *    that the next materialize would silently invalidate — so we [DeviceUnlockCoordinator.disenroll]
 *    to roll the whole enrollment back, then rethrow. This is the one deliberate deviation from the
 *    #327 "set marker, retry later" pattern: a partially-enrolled device is worse than an un-enrolled
 *    one.
 *
 * [password] is caller-owned (forwarded to enroll, not zeroized here — the caller's `finally` does it).
 */
suspend fun cloudEnrollThisDevice(
    coordinator: DeviceUnlockCoordinator,
    alreadyEnrolledForThisVault: Boolean,
    workingDirPath: String,
    vaultId: String,
    password: ByteArray,
    flushWorkingToCloud: suspend () -> Unit,
) {
    if (alreadyEnrolledForThisVault) return

    coordinator.enroll(workingDirPath, vaultId, password)
    try {
        flushWorkingToCloud()
    } catch (e: Throwable) {
        runCatching { coordinator.disenroll(workingDirPath) }
        throw e
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd android && ./gradlew :app:testDebugUnitTest --tests 'org.secretary.app.CloudDeviceEnrollTest'`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add android/app/src/main/kotlin/org/secretary/app/CloudDeviceEnroll.kt \
        android/app/src/test/kotlin/org/secretary/app/CloudDeviceEnrollTest.kt
git commit -m "feat(android): cloudEnrollThisDevice atomic enroll-with-flush (host-tested)"
```

---

### Task 4: Wire the cloud gate + enroll into `openCloudBrowse` / `openCloudTarget`

**Files:**
- Modify: `android/app/src/main/kotlin/org/secretary/app/CloudVaultOpen.kt`

**Interfaces:**
- Consumes: Task 1–3 outputs (`cloudReauthRoute`, `GateChoice`, `cloudDeviceUnlockCoordinator`, `CloudDeviceUnlock`, `cloudEnrollThisDevice`), `GraceWindowReauthGate`, `CoordinatorBiometricAuthorizer`, `NoopReauthGate`, `VaultMirror`, `VaultMirrorWorkingCopy`, `WorkingCopyMirror`, `safCloudFolderPort`, `SystemClock.elapsedRealtime`, `FragmentActivity`.
- Produces: `openCloudTarget(...)` gains an `enrollThisDevice: Boolean` parameter; `cloudCoordinator(...)` refactored to accept a prebuilt `WorkingCopyMirror`.

Detailed wiring (this is the integration task — read the current `CloudVaultOpen.kt` before editing):

1. **Refactor `cloudCoordinator`** to accept the mirror so the caller can also hand the throwing flush to `openCloudBrowse`:
```kotlin
internal fun cloudCoordinator(
    context: Context,
    location: VaultLocation,
    mirror: WorkingCopyMirror,
    openAndSync: suspend () -> BrowseSession,
): VaultWorkingCopyCoordinator<BrowseSession> {
    val markerName = "${cloudVaultKey(location.treeUri)}.pending-flush"
    val markerFile = File(syncStateDir(context.filesDir), markerName)
    return VaultWorkingCopyCoordinator(mirror, FilePendingFlushMarker(markerFile), openAndSync)
}
```

2. **`openCloudBrowse`** — replace the `NoopReauthGate` comment block + call with the gate decision, seed, and the post-open enroll (before the `finally` zeroize). New params: `activity: FragmentActivity`, `enrollThisDevice: Boolean`, `flushWorkingToCloud: suspend () -> Unit`.
```kotlin
val deviceUnlock = cloudDeviceUnlockCoordinator(activity, context.noBackupFilesDir, cloudVaultKey(location.treeUri))
val openVaultId = location.vaultUuidHex
val gate: WriteReauthGate = when (cloudReauthRoute(deviceUnlock.enclaveEnrolled, openVaultId, deviceUnlock.metadataVaultId)) {
    GateChoice.GRACE_WINDOW -> GraceWindowReauthGate(
        authorizer = CoordinatorBiometricAuthorizer(deviceUnlock.coordinator, openVaultId),
        clock = { SystemClock.elapsedRealtime() },
    )
    GateChoice.NOOP -> NoopReauthGate
}
val session = openBrowseWithSync(
    uniffiVaultOpenPort(deviceUuids), workingDir, stateDir,
    vaultUuid = if (vaultId.isEmpty()) ByteArray(0) else hexToBytesPublic(vaultId),
    credential = credential,
    gate = gate,
    onCommit = { coordinator.afterCommit() },
    onVaultUuidLearned = onVaultUuidLearned,
)
gate.seed(SystemClock.elapsedRealtime())
session.sync.refreshStatus()
if (enrollThisDevice && credential is UnlockCredential.Password) {
    try {
        val learnedVaultId = session.vaultUuidHex()   // the resolved uuid; openVaultId may have been empty
        cloudEnrollThisDevice(
            coordinator = deviceUnlock.coordinator,
            alreadyEnrolledForThisVault = deviceUnlock.enclaveEnrolled && deviceUnlock.metadataVaultId == learnedVaultId,
            workingDirPath = workingDir.path,
            vaultId = learnedVaultId,
            password = credential.secret,
            flushWorkingToCloud = flushWorkingToCloud,
        )
    } catch (e: Exception) {
        Log.w(TAG, "cloud device enroll failed; password open still succeeded", e)
        // Non-fatal: route to Browse regardless (mirrors demo unlockAndOpen).
    }
}
return session
```
   > `session.vaultUuidHex()` is already used inside `openBrowseWithSync`; calling it here on the live session is safe (it snapshots at construction). Confirm the accessor name when editing.

3. **`openCloudTarget`** — build the mirror once, pass it to `cloudCoordinator`, thread `enrollThisDevice` + the throwing flush into `openCloudBrowse`:
```kotlin
internal suspend fun openCloudTarget(
    context: Context,
    activity: FragmentActivity,
    target: CloudVaultTarget,
    credential: UnlockCredential,
    enrollThisDevice: Boolean,
    locationStore: VaultLocationStore,
    selectionVm: VaultSelectionViewModel,
): Route {
    var location = target.location
    val mirror = VaultMirrorWorkingCopy(VaultMirror(safCloudFolderPort(context, location.treeUri)), target.workingDir)
    lateinit var coordinator: VaultWorkingCopyCoordinator<BrowseSession>
    coordinator = cloudCoordinator(context, location, mirror) {
        openCloudBrowse(
            context = context,
            activity = activity,
            workingDir = target.workingDir,
            credential = credential,
            coordinator = coordinator,
            location = location,
            enrollThisDevice = enrollThisDevice,
            flushWorkingToCloud = { mirror.flush() },   // throwing flush for atomic enroll
            onVaultUuidLearned = { learnedHex -> /* unchanged */ },
        )
    }
    /* try/catch/finally body unchanged */
}
```

- [ ] **Step 1: Apply the three edits above** to `CloudVaultOpen.kt`.

- [ ] **Step 2: Compile `:app` (main + test + androidTest targets)**

Run: `cd android && ./gradlew :app:compileDebugKotlin :app:compileDebugUnitTestKotlin :app:compileDebugAndroidTestKotlin`
Expected: BUILD FAILED at `AppRoot.kt` (the `openCloudTarget` call site now needs `activity` + `enrollThisDevice`) — that is fixed in Task 5. Confirm the ONLY errors are at the `AppRoot.kt` call site, not inside `CloudVaultOpen.kt`.

- [ ] **Step 3: Commit** (compiles after Task 5; commit the cohesive change together)

Deferred to Task 5's commit (the two files must compile together).

---

### Task 5: Thread `rememberDevice` from the cloud unlock screen (`AppRoot.kt`)

**Files:**
- Modify: `android/app/src/main/kotlin/org/secretary/app/AppRoot.kt`

**Interfaces:**
- Consumes: `openCloudTarget(context, activity, target, credential, enrollThisDevice, locationStore, selectionVm)` (Task 4), the existing `activity`, `rememberDevice`, `selectionVm` in scope.

The "Remember this device" checkbox ALREADY renders on the cloud unlock screen (`UnlockScreen` shows it whenever `isEnrolled == false`, and cloud forces `isEnrolled = r.cloudTarget == null && ...` → false). The gap is only that the cloud `onUnlock` branch does not pass the choice through.

- [ ] **Step 1: Update the cloud branch of `onUnlock`** (around `AppRoot.kt:288-296`)

```kotlin
route = if (target != null) {
    openCloudTarget(context, activity, target, credential, enrollThisDevice = rememberDevice, locationStore, selectionVm).also {
        selectionState = selectionVm.state
    }
} else {
    unlockAndOpen(context, scope, credential, enrollAfter = rememberDevice, coordinator, vaultId)
}
```

- [ ] **Step 2: Update the comment** on the `isEnrolled` line (`AppRoot.kt:282-284`) to reflect that the *checkbox* is now live for cloud (only the biometric-OPEN button stays hidden — open is password-only this session):

```kotlin
// The biometric-OPEN button is demo-only (cloud open stays password-based this session), so hide it
// for a cloud target. The "Remember this device" checkbox (shown when !isEnrolled) IS live for cloud:
// ticking it enrolls a device secret for write-reauth after the password open (see openCloudTarget).
isEnrolled = r.cloudTarget == null && deviceState is DeviceUnlockState.Enrolled,
```

- [ ] **Step 3: Compile + run all host tests**

Run: `cd android && ./gradlew :app:compileDebugAndroidTestKotlin :vault-access:test :kit:testDebugUnitTest :app:testDebugUnitTest`
Expected: BUILD SUCCESSFUL; all host tests green (incl. Task 1 + Task 3 suites).

- [ ] **Step 4: Commit Tasks 4 + 5 together**

```bash
git add android/app/src/main/kotlin/org/secretary/app/CloudVaultOpen.kt \
        android/app/src/main/kotlin/org/secretary/app/AppRoot.kt
git commit -m "feat(android): wire cloud write-reauth gate + opt-in device enroll"
```

---

### Task 6: Instrumented — keyed Keystore isolation + cloud enroll round-trip + write-reauth over SAF

**Files:**
- Create: `android/app/src/androidTest/kotlin/org/secretary/app/CloudDeviceEnrollInstrumentedTest.kt`

**Interfaces:**
- Consumes: `TestCloudDocumentsProvider` / `TestCloudTree.install(context)` (from slice 6, `:kit` androidTest — confirm the package + whether it is reachable from `:app` androidTest; if not, build the SAF working copy with the same helper the slice-6 `:app` instrumented tests use), `KeystoreDeviceSecretEnclave(dir, gate = { c, _ -> c }, keyAlias)` with `KeystoreKeyConfig.TEST_NO_AUTH`, `FileDeviceEnrollmentMetadataStore`, `UniffiVaultDeviceSlotPort`, `DeviceUnlockCoordinator`, `GraceWindowReauthGate`, `CoordinatorBiometricAuthorizer`, `VaultMirror`/`VaultMirrorWorkingCopy`.

Three instrumented tests (auto-approving `BiometricGate = { cipher, _ -> cipher }`, `TEST_NO_AUTH` so no real prompt):

1. **`keyedEnclaves_twoKeys_isolated`** — two `KeystoreDeviceSecretEnclave` over two `cloudDeviceSecretDir(base, "A")` / `"B"` dirs + two `cloudDeviceKeyAlias` aliases; store distinct secrets; assert each releases its own, and clearing one leaves the other enrolled. Proves per-vault isolation.

2. **`cloudEnroll_roundTrips_wrapThroughSaf`** — stage a real golden working copy, install the SAF test tree, flush working→cloud, then run `cloudEnrollThisDevice` (mint slot → `mirror.flush()`); wipe the working dir; `mirror.materialize()`; assert `devices/<uuid>.wrap` is present in the rematerialized working copy. Proves the slot round-trips through real SAF.

3. **`cloudWriteReauth_gracewindow`** — build a `GraceWindowReauthGate` over a `CoordinatorBiometricAuthorizer` for the enrolled cloud vault with a controllable fake clock; assert: a write within the window does NOT call `authorize`; a write past `V1_DEFAULT_MS` DOES (auto-approved here). (Mirror the existing `WriteReauthInstrumentedTest` structure.)

- [ ] **Step 1: Write the three instrumented tests** (model them on `WriteReauthInstrumentedTest.kt` + `CloudWorkingCopyLifecycleInstrumentedTest.kt` from slice 6 for the SAF + coordinator setup).

- [ ] **Step 2: Run on the emulator (authoritative)**

```bash
~/Library/Android/sdk/platform-tools/adb devices   # confirm emulator-5554 is up
cd android && ANDROID_SERIAL=emulator-5554 ./gradlew :app:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.app.CloudDeviceEnrollInstrumentedTest
```
Expected: 3/3 pass. (If `TestCloudDocumentsProvider` is `:kit`-only and not reachable from `:app` androidTest, place the round-trip test in `:kit` androidTest instead and run `:kit:connectedDebugAndroidTest` — see [[project_secretary_conformance_scripts_dont_compile_kit]] for the module-reachability gotcha.)

- [ ] **Step 3: Run the FULL instrumented suite to prove no regression**

```bash
cd android && ANDROID_SERIAL=emulator-5554 ./gradlew :kit:connectedDebugAndroidTest :app:connectedDebugAndroidTest
```
Expected: all green (slice-6 baseline 56/56 + the new tests).

- [ ] **Step 4: Commit**

```bash
git add android/app/src/androidTest/kotlin/org/secretary/app/CloudDeviceEnrollInstrumentedTest.kt
git commit -m "test(android): keyed-enclave isolation + cloud enroll SAF round-trip + write-reauth"
```

---

### Task 7: Full verification gate (host + conformance + Rust + lint)

**Files:** none (verification only).

- [ ] **Step 1: Rust gate (no Rust change, must stay clean)**

```bash
cargo fmt --all --check && cargo clippy --release --workspace --tests -- -D warnings
```
Expected: clean.

- [ ] **Step 2: Conformance 27/27 both**

```bash
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
```
Expected: 27/27 each.

- [ ] **Step 3: Android host gate + both `:app` compile targets**

```bash
cd android && ./gradlew :vault-access:test :kit:testDebugUnitTest :app:testDebugUnitTest \
  :app:compileDebugKotlin :app:compileDebugAndroidTestKotlin
```
Expected: green.

- [ ] **Step 4: Kotlin lint / detekt if configured** (run whatever the repo's Android lint gate is; mirror what slice 6 ran). Fix any new warnings (no deferred debt — see [[feedback_act_on_issues_dont_mention]]).

- [ ] **Step 5: Commit** any lint fixes (if none, skip).

---

### Task 8: On-device biometric proof (manual — RedMagic 11 Pro)

**Files:** none (manual verification; user taps the biometric prompt).

> **This is the step that needs the RedMagic plugged in.** Ask the user to connect it (serial `912607710061`); `adb`/`emulator` need absolute paths; logcat is blocked on the RedMagic (production device).

- [ ] **Step 1: Build + install the debug app on the RedMagic**

```bash
~/Library/Android/sdk/platform-tools/adb devices   # confirm 912607710061
cd android && ANDROID_SERIAL=912607710061 ./gradlew :app:installDebug
```

- [ ] **Step 2: Manual flow (user drives):**
  1. Open/create a cloud vault (SAF folder), unlock with password, tick **"Remember this device"** → confirm the one-time biometric enroll prompt appears and the open succeeds.
  2. Make a record edit immediately → confirm it commits **silently** (within the 30s grace window).
  3. Wait > 30s, make another edit → confirm a **real biometric prompt** appears; approving commits, cancelling blocks the write with no data change.
  4. Reopen the cloud vault → confirm the device is still enrolled (slot round-tripped via SAF) and write-reauth is active.

- [ ] **Step 3: Record the result** in the handoff (device, OS, pass/fail per step). `:kit` instrumented also runs on the RedMagic:

```bash
cd android && ANDROID_SERIAL=912607710061 ./gradlew :kit:connectedDebugAndroidTest
```
Expected: green (the `:app` Compose-UI instrumented tests are known to fail on the RedMagic per the slice-6 baton — that is pre-existing and device-specific; do not block on it).

---

### Task 9: Docs + handoff

**Files:**
- Modify: `README.md`, `ROADMAP.md` (only if the session changed user-visible status — likely a one-line "Android: cloud-vault biometric write-reauth" note).
- Create: `docs/handoffs/2026-06-29-android-cloud-vault-biometric-reauth-shipped.md`; retarget `NEXT_SESSION.md` symlink.

- [ ] **Step 1: Update README.md / ROADMAP.md** if warranted (brief; dot points per [[feedback_readme_style]]).
- [ ] **Step 2: Author the handoff** (shipped SHAs, next steps w/ acceptance, open decisions/risks, exact resume commands) and retarget the symlink in one commit on the feature branch (per [[feedback_next_session_in_pr]]).
- [ ] **Step 3: Push + open PR** (per [[feedback_baton_push_and_open_pr_default]]).

---

## Self-review (completed by author)

**Spec coverage:** ✅ per-vault keyed enrollment (Tasks 1–2), atomic enroll-with-flush incl. rollback (Task 3), gate wiring + cloudReauthRoute mismatch guard (Tasks 1, 4), opt-in checkbox (Task 5), instrumented SAF round-trip + isolation + write-reauth (Task 6), on-device proof (Task 8), unchanged-gates verification (Task 7), docs (Task 9). Write-reauth-only / cloud-open-stays-password honored (no device-secret open path added). Demo path untouched (separate unkeyed dir).

**Placeholder scan:** none. (An earlier draft of Task 3 carried a `coordinatorMetadataVaultId` placeholder; it was removed — `cloudEnrollThisDevice` takes the precomputed `alreadyEnrolledForThisVault: Boolean` directly.)

**Type consistency:** `cloudReauthRoute(enclaveEnrolled, openVaultId, metadataVaultId)` and `GateChoice.{GRACE_WINDOW,NOOP}` used consistently in Tasks 1/4; `cloudEnrollThisDevice(coordinator, alreadyEnrolledForThisVault, workingDirPath, vaultId, password, flushWorkingToCloud)` consistent in Tasks 3/4 (final signature per the Task-3 note); `cloudCoordinator(context, location, mirror, openAndSync)` consistent in Task 4; `openCloudTarget(context, activity, target, credential, enrollThisDevice, locationStore, selectionVm)` consistent in Tasks 4/5.

**Risk to re-verify during execution:** the exact `session.vaultUuidHex()` accessor name and whether `TestCloudDocumentsProvider` is reachable from `:app` androidTest (Task 6 Step 2 contingency).
