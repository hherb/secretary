# C.3 Android Sync Emulator Round-Trip (slice 2b) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the `:kit` native sync surface works on a real arm64 Android runtime by round-tripping `golden_vault_001` through the real `UniffiVaultSyncPort` and `SyncCoordinator` on the emulator.

**Architecture:** Additive `androidTest` only. A Gradle Copy task stages the golden vault (from `core/tests/data`, gitignored target) into the test APK assets; the arm64 `.so` already reaches the test APK via the existing `cargoNdkBuildArm64` → `mergeDebugAndroidTestJniLibFolders` hook. A test helper copies the bundled asset tree to a writable `cacheDir` temp at runtime; two instrumented JUnit4 tests drive the real native sync calls.

**Tech Stack:** Kotlin, AGP 8.13.2, AndroidJUnit4 instrumentation (`androidx.test`), uniffi 0.31 Kotlin bindings, cargo-ndk 3.5.4, arm64 emulator `Medium_Phone_API_36.1`.

---

## Pinned facts (verified, do not re-derive)

- AndroidTest asset-merge task: **`mergeDebugAndroidTestAssets`** (verified via `./gradlew :kit:tasks --all`).
- AndroidTest native-lib merge task: **`mergeDebugAndroidTestJniLibFolders`** — already covered by the existing `tasks.matching { it.name.endsWith("JniLibFolders") }.configureEach { dependsOn(cargoNdkBuildArm64) }` in `build.gradle.kts`. **No new native-build wiring.**
- Instrumented tests run **JUnit4** (`@RunWith(AndroidJUnit4::class)`, `org.junit.Test`/`Before`/`After`), a separate world from the JUnit5 host unit tests. No runner conflict.
- `SyncCoordinator` constructor: `SyncCoordinator(port: VaultSyncPort, stateDir: String, vaultFolder: String)`; methods `suspend fun runPass(password: ByteArray, nowMs: ULong): SyncOutcome` and `suspend fun status(vaultUuid: ByteArray): SyncStatus`.
- `UniffiVaultSyncPort()` constructs with all-real defaults (no native lib touched until a method is called).
- Golden vault password: `"correct horse battery staple"`; pinned `vault_uuid`: `00112233-4455-6677-8899-aabbccddeeff`; both live in `core/tests/data/golden_vault_001_inputs.json`.
- Emulator/adb are NOT on the bare PATH — use `$HOME/Library/Android/sdk/emulator/emulator` and `$HOME/Library/Android/sdk/platform-tools/adb`. AVD name: `Medium_Phone_API_36.1`.

## File structure

- **Modify** `android/kit/build.gradle.kts` — add `stageGoldenVaultForAndroidTest` Copy task + hook to `mergeDebugAndroidTestAssets`; add `androidTestImplementation` deps; add `testInstrumentationRunner`.
- **Modify** `android/.gitignore` — ignore `kit/src/androidTest/assets/`.
- **Create** `android/kit/src/androidTest/kotlin/org/secretary/sync/GoldenVaultStaging.kt` — recursive asset→cacheDir copy + pinned-UUID parse.
- **Create** `android/kit/src/androidTest/kotlin/org/secretary/sync/SyncRoundTripInstrumentedTest.kt` — Test A (raw port) + Test B (coordinator).
- **Modify** `README.md`, `ROADMAP.md` — slice 2b status.
- **Modify** handoff doc + `NEXT_SESSION.md` symlink (final task).

---

## Task 1: Build wiring — stage the golden vault into the androidTest APK

**Files:**
- Modify: `android/kit/build.gradle.kts`
- Modify: `android/.gitignore`

- [ ] **Step 1: Ignore the staged assets**

Append to `android/.gitignore`:

```gitignore

# cargo-ndk staged native libs are ignored above; the androidTest golden-vault
# fixture is likewise staged at build time from core/tests/data (never committed).
kit/src/androidTest/assets/
```

- [ ] **Step 2: Add the instrumentation runner + androidTest deps**

In `android/kit/build.gradle.kts`, inside `android { defaultConfig { ... } }` add the runner:

```kotlin
    defaultConfig {
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
```

In the `dependencies { ... }` block, add the androidTest dependencies (place after the existing `testRuntimeOnly(...)` line):

```kotlin
    // Instrumented (on-device) tests run JUnit4 via the AndroidJUnitRunner — a separate
    // world from the JUnit5 host unit tests above. runBlocking drives the real suspend
    // FFI calls on real dispatchers (no virtual-time scheduler — this is an integration test).
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test:core:1.6.1")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("junit:junit:4.13.2")
```

- [ ] **Step 3: Add the fixture-staging Copy task**

In `android/kit/build.gradle.kts`, after the `cargoNdkBuildArm64` block (near the end of the file), add:

```kotlin
// --- androidTest fixture staging ------------------------------------------

// Stage golden_vault_001 (+ its inputs JSON) from the canonical core/tests/data
// location into the androidTest assets. The destination is gitignored: the tracked
// fixture stays the single source of truth (no committed duplicate of a frozen KAT),
// mirroring how iOS stages it via build-xcframework.sh. Declared inputs/outputs let
// Gradle skip the copy when the fixture is unchanged.
val stageGoldenVaultForAndroidTest by tasks.registering(Copy::class) {
    val fixtureRoot = repoRoot.resolve("core/tests/data")
    from(fixtureRoot.resolve("golden_vault_001")) { into("golden_vault_001") }
    from(fixtureRoot.resolve("golden_vault_001_inputs.json"))
    into(layout.projectDirectory.dir("src/androidTest/assets"))
}

// The androidTest asset merge must see the staged fixture.
tasks.matching { it.name == "mergeDebugAndroidTestAssets" }.configureEach {
    dependsOn(stageGoldenVaultForAndroidTest)
}
```

- [ ] **Step 4: Build the androidTest APK (no emulator) and verify contents**

Run (from `android/`):

```bash
./gradlew :kit:assembleDebugAndroidTest
```

Expected: `BUILD SUCCESSFUL`. Then verify the APK packs BOTH the staged fixture and the arm64 `.so`:

```bash
unzip -l kit/build/outputs/apk/androidTest/debug/kit-debug-androidTest.apk | grep -E 'golden_vault_001/manifest.cbor.enc|lib/arm64-v8a/libsecretary_ffi_uniffi.so'
```

Expected: both lines present (the vault assets are under `assets/golden_vault_001/...`; the native lib under `lib/arm64-v8a/...`). If the APK path differs, find it with `find kit/build/outputs/apk/androidTest -name '*.apk'`.

- [ ] **Step 5: Confirm the host unit-test path stays NDK-free**

```bash
./gradlew :kit:testDebugUnitTest --dry-run | grep -q cargoNdkBuildArm64 && echo LEAK || echo "host tests NDK-free"
```

Expected: `host tests NDK-free` (the staging task and the cross-build must NOT be dragged onto `testDebugUnitTest`).

- [ ] **Step 6: Commit**

```bash
git add android/kit/build.gradle.kts android/.gitignore
git commit -m "build(C.3 Android): stage golden vault + androidTest deps for emulator round-trip"
```

---

## Task 2: `GoldenVaultStaging` helper + Test A (raw port round-trip)

**Files:**
- Create: `android/kit/src/androidTest/kotlin/org/secretary/sync/GoldenVaultStaging.kt`
- Create: `android/kit/src/androidTest/kotlin/org/secretary/sync/SyncRoundTripInstrumentedTest.kt`

- [ ] **Step 1: Write the staging helper**

Create `android/kit/src/androidTest/kotlin/org/secretary/sync/GoldenVaultStaging.kt`:

```kotlin
package org.secretary.sync

import android.content.Context
import org.json.JSONObject
import java.io.File

/**
 * AndroidTest helper: stages a WRITABLE copy of golden_vault_001 from the test APK
 * assets onto the device, and reads the pinned vault UUID. The tracked fixture is never
 * opened directly — only the per-test cacheDir copy is, so a frozen KAT is never mutated.
 */
object GoldenVaultStaging {
    private const val VAULT_ASSET = "golden_vault_001"
    private const val INPUTS_ASSET = "golden_vault_001_inputs.json"
    private const val UUID_BYTES = 16

    /** Recursively copy the bundled golden vault into a fresh unique dir under cacheDir. */
    fun stageWritableVault(context: Context): File {
        val dest = File(context.cacheDir, "gv-${System.nanoTime()}/$VAULT_ASSET")
        copyAsset(context, VAULT_ASSET, dest)
        return dest
    }

    /** A fresh empty sync-state dir under cacheDir. */
    fun freshStateDir(context: Context): File =
        File(context.cacheDir, "state-${System.nanoTime()}").apply { mkdirs() }

    /** The pinned 16-byte vault UUID, parsed from the bundled inputs JSON (single source of truth). */
    fun goldenVaultUuid(context: Context): ByteArray {
        val json = context.assets.open(INPUTS_ASSET).bufferedReader().use { it.readText() }
        val hex = JSONObject(json).getString("vault_uuid").replace("-", "")
        return ByteArray(UUID_BYTES) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }

    // AssetManager.list() returns the children of a directory, or an empty array for a
    // leaf file. The golden vault has no empty directories, so empty-children == file.
    private fun copyAsset(context: Context, assetPath: String, dest: File) {
        val children = context.assets.list(assetPath) ?: emptyArray()
        if (children.isEmpty()) {
            dest.parentFile?.mkdirs()
            context.assets.open(assetPath).use { input ->
                dest.outputStream().use { input.copyTo(it) }
            }
        } else {
            dest.mkdirs()
            for (child in children) copyAsset(context, "$assetPath/$child", File(dest, child))
        }
    }
}
```

- [ ] **Step 2: Write Test A (raw port) — assert the NothingToDo hypothesis**

Create `android/kit/src/androidTest/kotlin/org/secretary/sync/SyncRoundTripInstrumentedTest.kt`:

```kotlin
package org.secretary.sync

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * The first on-device exercise of the native sync surface: a real libsecretary_ffi_uniffi.so
 * load + uniffi marshalling + SyncOutcome/SyncStatus mapping, round-tripped against a writable
 * copy of golden_vault_001 on the arm64 emulator. Host tests (with fakes) cannot touch any of this.
 */
@RunWith(AndroidJUnit4::class)
class SyncRoundTripInstrumentedTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val goldenPassword = "correct horse battery staple".toByteArray()

    // nowMs is only consulted as the merge timestamp on a clean concurrent merge; a single-device
    // pass never reaches that arm. Pinned to the golden vault's clock domain for determinism.
    private val mergeClockMs = 2_000_000_000_000uL

    private val toClean = mutableListOf<File>()

    @After fun cleanup() = toClean.forEach { it.deleteRecursively() }

    private fun stageVault(): File =
        GoldenVaultStaging.stageWritableVault(context).also { toClean += it.parentFile!! }

    private fun stateDir(): File =
        GoldenVaultStaging.freshStateDir(context).also { toClean += it }

    @Test
    fun rawPort_statusThenSync_roundTripsThroughNativeFfi() = runBlocking {
        val vault = stageVault()
        val state = stateDir()
        val uuid = GoldenVaultStaging.goldenVaultUuid(context)
        val port = UniffiVaultSyncPort()

        val before = port.status(state.path, uuid)
        assertFalse("fresh state dir reports no sync state", before.hasState)

        // The headline proof: native load + uniffi call + DTO→domain mapping.
        val outcome = port.sync(state.path, vault.path, goldenPassword, mergeClockMs)
        assertEquals(SyncOutcome.NothingToDo, outcome)

        val after = port.status(state.path, uuid)
        assertFalse("NothingToDo writes no state", after.hasState)
    }
}
```

- [ ] **Step 3: Boot the emulator (if not already running)**

```bash
"$HOME/Library/Android/sdk/emulator/emulator" -avd Medium_Phone_API_36.1 -no-snapshot -no-window &
"$HOME/Library/Android/sdk/platform-tools/adb" wait-for-device
# Wait until boot completes:
until [ "$("$HOME/Library/Android/sdk/platform-tools/adb" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ]; do sleep 2; done
echo "emulator booted"
```

- [ ] **Step 4: Run Test A on the emulator — characterize the outcome arm**

```bash
./gradlew :kit:connectedDebugAndroidTest --tests "org.secretary.sync.SyncRoundTripInstrumentedTest"
```

Expected: `BUILD SUCCESSFUL`, test passes. **If the `assertEquals(SyncOutcome.NothingToDo, ...)` fails**, the failure message prints the ACTUAL arm. This is the characterization step — do NOT force it green:
  1. Update the assertion to the observed arm.
  2. Update the `after.hasState` assertion to match (an advancing arm writes state → `hasState == true`).
  3. Add a one-line comment recording the observed arm + why, and note it in the handoff (§4 of the spec — a spec/code disagreement is a finding, not a test to bend).

- [ ] **Step 5: Commit**

```bash
git add android/kit/src/androidTest/kotlin/org/secretary/sync/GoldenVaultStaging.kt \
        android/kit/src/androidTest/kotlin/org/secretary/sync/SyncRoundTripInstrumentedTest.kt
git commit -m "test(C.3 Android): emulator round-trip of UniffiVaultSyncPort over golden vault"
```

---

## Task 3: Test B — `SyncCoordinator` over the real port

**Files:**
- Modify: `android/kit/src/androidTest/kotlin/org/secretary/sync/SyncRoundTripInstrumentedTest.kt`

- [ ] **Step 1: Add Test B to the existing test class**

Add this method inside `SyncRoundTripInstrumentedTest` (after `rawPort_...`). Use the SAME observed outcome arm Task 2 pinned (shown here as `NothingToDo`; replace if Task 2 found a different arm):

```kotlin
    @Test
    fun coordinator_overRealPort_runsAPassOnDevice() = runBlocking {
        val vault = stageVault()
        val state = stateDir()
        val coordinator = SyncCoordinator(UniffiVaultSyncPort(), state.path, vault.path)

        // Proves the assembled slice-1 (pure core) + slice-2a (adapter) stack on device.
        val outcome = coordinator.runPass(goldenPassword, mergeClockMs)
        assertEquals(SyncOutcome.NothingToDo, outcome)
    }
```

- [ ] **Step 2: Run both instrumented tests on the emulator**

```bash
./gradlew :kit:connectedDebugAndroidTest --tests "org.secretary.sync.SyncRoundTripInstrumentedTest"
```

Expected: `BUILD SUCCESSFUL`, both tests pass. Reports at `kit/build/reports/androidTests/connected/`.

- [ ] **Step 3: Commit**

```bash
git add android/kit/src/androidTest/kotlin/org/secretary/sync/SyncRoundTripInstrumentedTest.kt
git commit -m "test(C.3 Android): emulator round-trip of SyncCoordinator over the real port"
```

---

## Task 4: Full gauntlet + docs

**Files:**
- Modify: `README.md`
- Modify: `ROADMAP.md`

- [ ] **Step 1: Run the full acceptance gauntlet**

```bash
cd android
# Host path unchanged:
./gradlew :vault-access:test :kit:testDebugUnitTest --rerun-tasks   # 22 + 14 host tests, 0 warnings
# Emulator round-trip (emulator booted):
./gradlew :kit:connectedDebugAndroidTest                            # both instrumented tests pass
cd ..
# Scope guardrails (expect empty):
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|.gitignore)'
git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'
```

- [ ] **Step 2: Update README.md**

Find the Android C.3 status line/row (the slice-2a "real adapter ✅" entry added last session) and extend it to record the on-device round-trip. Keep it brief (dot points, audience = curious contributor). Example edit — adjust to match the actual surrounding prose:

```markdown
- Android sync: real `UniffiVaultSyncPort` adapter (`:kit`, uniffi + arm64 cargo-ndk),
  host-tested; **on-device round-trip proven on the arm64 emulator** (golden vault →
  `status`/`sync` through the native `.so`). Folder-watch + Compose UI pending.
```

Verify the exact current wording first: `grep -n "UniffiVaultSyncPort\|Android sync\|cargo-ndk" README.md`.

- [ ] **Step 3: Update ROADMAP.md**

Find the Android C.3 slice rows (slice 2a ✅ / slice 2b ⏳ from last session) and flip slice 2b to ✅. Verify first: `grep -n "slice 2\|2b\|emulator\|round-trip" ROADMAP.md`. Set the 2b entry to done, e.g.:

```markdown
  - slice 2b — emulator instrumented round-trip ✅ (golden vault → native `UniffiVaultSyncPort` +
    `SyncCoordinator` on `Medium_Phone_API_36.1`)
```

- [ ] **Step 4: Commit**

```bash
git add README.md ROADMAP.md
git commit -m "docs(C.3 Android): slice-2b status — emulator round-trip proven"
```

---

## Task 5: Handoff + symlink retarget

**Files:**
- Create: `docs/handoffs/2026-06-16-c3-android-sync-emulator-roundtrip-shipped.md`
- Modify: `NEXT_SESSION.md` (symlink retarget)

- [ ] **Step 1: Write the handoff doc** capturing (1) what shipped with commit SHAs, (2) what's next (slice 3 folder-detection + slice 4 Compose UI) with acceptance criteria, (3) open decisions/risks (incl. any characterized-arm finding from Task 2), (4) exact resume commands (cd, branch, test command), (5) the symlink note. Follow the structure of the prior handoff (`docs/handoffs/<prev>.md`).

- [ ] **Step 2: Retarget the symlink and verify**

```bash
ln -snf docs/handoffs/2026-06-16-c3-android-sync-emulator-roundtrip-shipped.md NEXT_SESSION.md
ls -la NEXT_SESSION.md   # shows -> target
head -3 NEXT_SESSION.md  # reads handoff content transparently
```

- [ ] **Step 3: Commit**

```bash
git add docs/handoffs/2026-06-16-c3-android-sync-emulator-roundtrip-shipped.md NEXT_SESSION.md
git commit -m "docs(C.3 Android): slice-2b baton handoff + retarget NEXT_SESSION symlink"
```

---

## Risk: emulator won't boot headless this session

If the AVD will not boot in this environment, the tests + wiring are still correct and host-compile/lint-clean (Task 1's `assembleDebugAndroidTest` gate runs without an emulator and proves the APK packs both fixture and `.so`). In that case: keep everything, and document the un-run `connectedDebugAndroidTest` gate explicitly in the handoff as a stated risk — do NOT claim the on-device gate passed. (Per the spec §7 and [[feedback_verify_deferred_items]].)
