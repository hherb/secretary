# Android cloud-drive Slice 6 — instrumented E2E + offline/conflict tests + #327 fix — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close epic #321 by proving the SAF working-copy lifecycle end-to-end on the emulator (real `libsecretary_ffi_uniffi.so` + real SAF via a test `DocumentsProvider`) and fixing the #327 offline-create data-loss gap with a materialize-clobber guard.

**Architecture:** A temp-dir-backed, fault-injectable test `DocumentsProvider` (in `:kit` `androidTest`) provides a real `content://` tree without the interactive picker, so the production wiring (`safCloudFolderPort` → `VaultMirror` → `VaultWorkingCopyCoordinator` → uniffi open/sync) runs against real SAF. The #327 fix is two pure `:vault-access` changes (a verify-after-set escalation in `createThenOpen`, and a `materialize()` refusal to pull from a manifest-less cloud) plus `:app` handling, all host-tested first.

**Tech Stack:** Kotlin, Gradle (AGP), AndroidX Test (`AndroidJUnit4`, `InstrumentationRegistry`), JUnit5 (host tests in `:vault-access`), JUnit4 (instrumented), Android SAF (`DocumentsProvider`, `DocumentsContract`, `DocumentFile`, `ContentResolver`), Rust core via uniffi.

## Global Constraints

- **No core `src/` change, no on-disk-format / spec / `conformance.py` / conflict-KAT / observable-byte / FFI-surface change.** This slice is tests + Kotlin coordinator/mirror robustness fixes only. Conformance stays 27/27 untouched.
- **Module split:** pure ordering/guard logic in `:vault-access` (host-tested, JUnit5); SAF/FFI adapters + instrumented tests in `:kit`; UI/wiring in `:app`. **No merge logic in Kotlin** — convergence is the Rust core's job.
- **TDD, RED proven before GREEN.** Every behavior change starts with a failing test.
- **`PendingFlushMarker.set()` stays best-effort; `afterCommit` never throws.** Only `createThenOpen` gains the verify-after-set escalation.
- **Files stay focused; split toward a directory module before ~500 lines.** Shared instrumented helpers live in their own files (mirror `GoldenVaultStaging.kt`).
- **Manifest constant:** `MANIFEST_FILENAME = "manifest.cbor.enc"` (in `org.secretary.mirror`, `VaultMirrorPlanner.kt:7`). A conflict-copy sibling is any folder file whose name `starts_with(MANIFEST_FILENAME)` and is not exactly equal (`core/src/sync/ingest.rs::enumerate_manifest_siblings`).
- **Worktree:** `/Users/hherb/src/secretary/.worktrees/android-cloud-drive-slice6-instrumented-e2e`, branch `feature/android-cloud-drive-slice6-instrumented-e2e`. All commands use absolute paths; `cd android && ./gradlew …` chained in one Bash call.
- **Emulator:** `emulator-5554` is already running. `adb`/`emulator` are NOT on bare PATH — use `~/Library/Android/sdk/platform-tools/adb`. Instrumented runs: `connectedAndroidTest` rejects `--tests`; filter with `-Pandroid.testInstrumentationRunnerArguments.class=<FQCN>`. AndroidX test deps require `android.useAndroidX=true` (already set).

---

## Commands reference (used throughout)

```bash
# Host tests (JVM, no device) — fast inner loop
cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-slice6-instrumented-e2e/android && \
  ./gradlew :vault-access:test :kit:testDebugUnitTest :app:testDebugUnitTest

# One host test class
cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-slice6-instrumented-e2e/android && \
  ./gradlew :vault-access:test --tests 'org.secretary.mirror.VaultWorkingCopyCoordinatorTest'

# Compile :app (catches cross-module exhaustive-when breaks)
cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-slice6-instrumented-e2e/android && \
  ./gradlew :app:compileDebugKotlin :app:compileDebugAndroidTestKotlin

# Instrumented test class on the running emulator (builds the .so via cargo-ndk first)
cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-slice6-instrumented-e2e/android && \
  ./gradlew :kit:connectedDebugAndroidTest \
    -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.mirror.SafCloudFolderPortInstrumentedTest
```

---

## Task 1: #327a — `PendingFlushNotPersisted` + verify-after-set in `createThenOpen` (pure)

**Files:**
- Modify: `android/vault-access/src/main/kotlin/org/secretary/mirror/VaultWorkingCopyCoordinator.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/mirror/VaultWorkingCopyCoordinatorTest.kt`

**Interfaces:**
- Consumes: existing `WorkingCopyMirror` (`materialize()`/`flush()` → `MirrorReport`), `PendingFlushMarker` (`isSet()`/`set()`/`clear()`).
- Produces: `class PendingFlushNotPersisted(val createdVaultUuidHex: String, cause: Throwable) : Exception(...)` (in `org.secretary.mirror`), thrown by `createThenOpen` when `marker.set()` did not persist. `:app` (Task 3) catches it.

- [ ] **Step 1: Write the failing test.** Add to `VaultWorkingCopyCoordinatorTest.kt`. Extend the existing `FakeMarker` pattern with a marker whose `set()` is a no-op so `isSet()` stays false:

```kotlin
private class NeverPersistsMarker : PendingFlushMarker {
    override fun isSet() = false
    override fun set() { /* simulate a swallowed I/O failure: nothing persists */ }
    override fun clear() {}
}

@Test fun createThenOpen_escalates_when_marker_cannot_persist() = runTest {
    val order = mutableListOf<String>()
    val coord = VaultWorkingCopyCoordinator(
        RecordingMirror(order, flushFails = true), NeverPersistsMarker()
    ) { order.add("open"); "S" }
    var thrown: Throwable? = null
    try {
        coord.createThenOpen("deadbeef") { order.add("persist") }
    } catch (e: PendingFlushNotPersisted) {
        thrown = e
    }
    assertTrue(thrown is PendingFlushNotPersisted, "marker-not-persisted on the create path must escalate")
    assertEquals("deadbeef", (thrown as PendingFlushNotPersisted).createdVaultUuidHex)
    assertEquals(listOf("flush"), order) // never persisted / opened
}

@Test fun createThenOpen_failure_with_persisting_marker_throws_original_not_escalated() = runTest {
    // Regression guard: the normal (marker persists) offline-create path keeps throwing the raw
    // push error, NOT the escalation — :app routes it to a normal retry.
    val order = mutableListOf<String>()
    val marker = FakeMarker(set = false) // FakeMarker.set() DOES persist (isSet() flips true)
    val coord = VaultWorkingCopyCoordinator(RecordingMirror(order, flushFails = true), marker) { "S" }
    var thrown: Throwable? = null
    try { coord.createThenOpen("deadbeef") { } } catch (e: Throwable) { thrown = e }
    assertTrue(thrown is VaultMirrorException, "marker persisted → original push error propagates")
    assertTrue(marker.isSet())
}
```

- [ ] **Step 2: Run to verify it fails.**
Run: `cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-slice6-instrumented-e2e/android && ./gradlew :vault-access:test --tests 'org.secretary.mirror.VaultWorkingCopyCoordinatorTest'`
Expected: FAIL — `PendingFlushNotPersisted` unresolved reference.

- [ ] **Step 3: Implement.** In `VaultWorkingCopyCoordinator.kt`, add the exception type (top of file, after imports) and edit `createThenOpen`'s catch:

```kotlin
/**
 * Thrown by [VaultWorkingCopyCoordinator.createThenOpen] when an offline-create push fails AND the
 * pending-flush marker could not be persisted (best-effort [PendingFlushMarker.set] swallowed an
 * I/O failure). On this one path the marker is the load-bearing guard against a later
 * materialize-clobber of the only copy of the freshly-created vault, so its loss is escalated
 * louder than a normal (recoverable) offline-create failure. (#327)
 */
class PendingFlushNotPersisted(val createdVaultUuidHex: String, cause: Throwable) :
    Exception("offline-created vault $createdVaultUuidHex could not be synced or marked for retry", cause)
```

In `createThenOpen`, replace the catch body:

```kotlin
} catch (e: Exception) {
    marker.set()
    if (!marker.isSet()) {
        // The marker is the load-bearing guard for the offline-create reopen path; if it could not
        // persist, escalate so :app can warn instead of silently leaving the vault unprotected. (#327)
        throw PendingFlushNotPersisted(createdVaultUuidHex, e)
    }
    throw e
}
```

- [ ] **Step 4: Run to verify it passes (whole class, including the 7 prior tests).**
Run: `cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-slice6-instrumented-e2e/android && ./gradlew :vault-access:test --tests 'org.secretary.mirror.VaultWorkingCopyCoordinatorTest'`
Expected: PASS (9 tests).

- [ ] **Step 5: Commit.**

```bash
cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-slice6-instrumented-e2e && \
git add android/vault-access/src/main/kotlin/org/secretary/mirror/VaultWorkingCopyCoordinator.kt \
        android/vault-access/src/test/kotlin/org/secretary/mirror/VaultWorkingCopyCoordinatorTest.kt && \
git commit -m "fix(android): createThenOpen escalates PendingFlushNotPersisted when marker write fails (#327)"
```

---

## Task 2: #327b — `materialize()` refuses to pull from a manifest-less cloud (pure)

**Files:**
- Modify: `android/vault-access/src/main/kotlin/org/secretary/mirror/VaultMirror.kt:materialize`
- Test: `android/vault-access/src/test/kotlin/org/secretary/mirror/VaultMirrorTest.kt`

**Interfaces:**
- Consumes: `CloudFolderPort` (faked by `FakeCloudFolderPort`), `MANIFEST_FILENAME`, `MirrorReport`.
- Produces: `materialize()` becomes a no-op (`MirrorReport(emptyList(), emptyList())`) when the cloud lacks `manifest.cbor.enc` AND the working copy has it. Unchanged otherwise. This is the load-bearing safety fix that makes the reopen path safe even if the marker was lost.

- [ ] **Step 1: Write the failing tests.** Add to `VaultMirrorTest.kt`:

```kotlin
@Test fun materialize_refuses_to_clobber_working_copy_when_cloud_has_no_manifest(@TempDir workingDir: File) {
    // An offline-created vault: full vault in the working copy, cloud empty (push never landed).
    File(workingDir, MANIFEST_FILENAME).writeBytes(byteArrayOf(1, 2, 3))
    File(workingDir, "blocks").mkdirs()
    File(workingDir, "blocks/x.cbor.enc").writeBytes(byteArrayOf(9))
    val cloud = FakeCloudFolderPort(emptyMap()) // manifest-less cloud
    val report = VaultMirror(cloud).materialize(workingDir)
    assertEquals(emptyList<String>(), report.copied)
    assertEquals(emptyList<String>(), report.deleted) // NOTHING deleted — the vault is preserved
    assertTrue(File(workingDir, MANIFEST_FILENAME).exists(), "un-pushed vault must survive materialize")
    assertTrue(File(workingDir, "blocks/x.cbor.enc").exists())
}

@Test fun materialize_still_pulls_normally_when_cloud_has_a_manifest(@TempDir workingDir: File) {
    // A real cloud vault → a fresh device pulls it in full (existing behavior, regression guard).
    val cloud = FakeCloudFolderPort(mapOf(
        MANIFEST_FILENAME to byteArrayOf(7),
        "blocks/y.cbor.enc" to byteArrayOf(8),
    ))
    val report = VaultMirror(cloud).materialize(workingDir)
    assertTrue(report.copied.contains(MANIFEST_FILENAME))
    assertTrue(File(workingDir, MANIFEST_FILENAME).exists())
    assertTrue(File(workingDir, "blocks/y.cbor.enc").exists())
}
```

(Use the import style already in `VaultMirrorTest.kt`; `@TempDir` is `org.junit.jupiter.api.io.TempDir`.)

- [ ] **Step 2: Run to verify the first fails.**
Run: `cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-slice6-instrumented-e2e/android && ./gradlew :vault-access:test --tests 'org.secretary.mirror.VaultMirrorTest'`
Expected: FAIL — `materialize_refuses_to_clobber…` deletes the working manifest (report.deleted non-empty / file gone).

- [ ] **Step 3: Implement the guard.** In `VaultMirror.materialize`, after reading both sides and before `planMirror`:

```kotlin
fun materialize(workingDir: File): MirrorReport = runPass("materialize") {
    val cloudFiles = readCloud()
    val workingFiles = readWorking(workingDir)
    // Guard (#327): a cloud folder with no manifest is not a valid vault to pull from (empty /
    // never-pushed / mid-create). Pulling it over a populated working copy would DELETE an
    // un-pushed vault — e.g. an offline-created vault whose push failed and whose pending-flush
    // marker could not be persisted. Decline the invalid pull: no-op, leaving the working copy
    // intact so it reaches the cloud on the next flush. This never moves merge logic into Kotlin.
    if (!cloudFiles.containsKey(MANIFEST_FILENAME) && workingFiles.containsKey(MANIFEST_FILENAME)) {
        return@runPass MirrorReport(emptyList(), emptyList())
    }
    val plan = planMirror(fingerprints(cloudFiles), fingerprints(workingFiles))
    execute(
        plan,
        source = cloudFiles,
        applyCopy = { path, bytes -> writeWorking(workingDir, path, bytes) },
        applyDelete = { path -> deleteWorking(workingDir, path) },
    )
}
```

- [ ] **Step 4: Run to verify the whole class passes.**
Run: `cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-slice6-instrumented-e2e/android && ./gradlew :vault-access:test --tests 'org.secretary.mirror.VaultMirrorTest'`
Expected: PASS (existing tests + 2 new).

- [ ] **Step 5: Commit.**

```bash
cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-slice6-instrumented-e2e && \
git add android/vault-access/src/main/kotlin/org/secretary/mirror/VaultMirror.kt \
        android/vault-access/src/test/kotlin/org/secretary/mirror/VaultMirrorTest.kt && \
git commit -m "fix(android): materialize refuses to pull from a manifest-less cloud — no offline-create clobber (#327)"
```

---

## Task 3: #327c — `:app` handles `PendingFlushNotPersisted` distinctly

**Files:**
- Modify: `android/app/src/main/kotlin/org/secretary/app/CloudVaultOpen.kt:openCloudTarget`
- Test: `android/app/src/test/kotlin/org/secretary/app/CloudCreateErrorRoutingTest.kt` (new — pure routing helper)

**Interfaces:**
- Consumes: `PendingFlushNotPersisted` (Task 1), existing `Route` sealed type, `CloudVaultTarget`.
- Produces: a pure helper `internal fun cloudOpenFailureRoute(error: Throwable, target: CloudVaultTarget): CloudOpenFailure` returning a small value type distinguishing the two cases, so the routing decision is host-testable without `Context`/FFI. `openCloudTarget`'s catch calls it.

- [ ] **Step 1: Write the failing test.** Create `CloudCreateErrorRoutingTest.kt`:

```kotlin
package org.secretary.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.secretary.browse.VaultLocation
import org.secretary.mirror.PendingFlushNotPersisted
import org.secretary.mirror.VaultMirrorException
import java.io.File

class CloudCreateErrorRoutingTest {
    private fun target() = CloudVaultTarget(
        VaultLocation("V", "content://tree/x", ""), File("/tmp/wc"), isCreate = true,
    )

    @Test fun pendingFlushNotPersisted_is_flagged_as_unsynced_create() {
        val r = cloudOpenFailureRoute(PendingFlushNotPersisted("deadbeef", RuntimeException("io")), target())
        assertTrue("must surface the un-synced-create warning", r.createdButNotSynced)
        assertTrue("must stay on the create target (no materialize on reopen)", r.target.isCreate)
    }

    @Test fun ordinary_failure_is_a_plain_retry() {
        val r = cloudOpenFailureRoute(VaultMirrorException("offline"), target())
        assertEquals(false, r.createdButNotSynced)
        assertTrue(r.target.isCreate)
    }
}
```

- [ ] **Step 2: Run to verify it fails.**
Run: `cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-slice6-instrumented-e2e/android && ./gradlew :app:testDebugUnitTest --tests 'org.secretary.app.CloudCreateErrorRoutingTest'`
Expected: FAIL — `cloudOpenFailureRoute` / `CloudOpenFailure` unresolved.

- [ ] **Step 3: Implement the helper + wire it.** In `CloudVaultOpen.kt`, add near the top:

```kotlin
/**
 * The decision for a failed cloud open/create, factored out of [openCloudTarget] so it is
 * host-testable without a Context. [createdButNotSynced] is true only for [PendingFlushNotPersisted]
 * (an offline-created vault that could neither sync nor be marked for retry — warn the user). The
 * [target] is always returned with `isCreate` unchanged so a reopen retries the push (never a
 * materialize that could clobber the un-pushed vault — the materialize guard backs this up).
 */
internal data class CloudOpenFailure(val target: CloudVaultTarget, val createdButNotSynced: Boolean)

internal fun cloudOpenFailureRoute(error: Throwable, target: CloudVaultTarget): CloudOpenFailure =
    CloudOpenFailure(target, createdButNotSynced = error is PendingFlushNotPersisted)
```

Add the import `import org.secretary.mirror.PendingFlushNotPersisted`. Then update `openCloudTarget`'s catch to use it and emit a distinct log on the un-synced-create case (keep returning `Route.Unlock(cloudTarget = target)`; the existing routing already preserves `isCreate=true`):

```kotlin
} catch (e: Exception) {
    val failure = cloudOpenFailureRoute(e, target)
    if (failure.createdButNotSynced) {
        Log.w(TAG, "cloud vault CREATED but not synced and not marked for retry — user must not lose it", e)
    } else {
        Log.w(TAG, "cloud open/create failed; returning to unlock with same target", e)
    }
    Route.Unlock(cloudTarget = failure.target)
} finally {
```

(A user-facing toast/banner for `createdButNotSynced` is wired at the `AppRoot` `Route.Unlock` render in Task 8's polish if the reviewer wants it; the log + preserved routing is the load-bearing behavior.)

- [ ] **Step 4: Run to verify host tests pass + :app compiles.**
Run: `cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-slice6-instrumented-e2e/android && ./gradlew :app:testDebugUnitTest --tests 'org.secretary.app.CloudCreateErrorRoutingTest' :app:compileDebugKotlin`
Expected: PASS + BUILD SUCCESSFUL.

- [ ] **Step 5: Commit.**

```bash
cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-slice6-instrumented-e2e && \
git add android/app/src/main/kotlin/org/secretary/app/CloudVaultOpen.kt \
        android/app/src/test/kotlin/org/secretary/app/CloudCreateErrorRoutingTest.kt && \
git commit -m "fix(android): :app surfaces PendingFlushNotPersisted distinctly, preserves no-materialize routing (#327)"
```

---

## Task 4: Test `DocumentsProvider` + androidTest manifest + tree-URI helper + provider self-test

**Files:**
- Create: `android/kit/src/androidTest/AndroidManifest.xml`
- Create: `android/kit/src/androidTest/kotlin/org/secretary/mirror/TestCloudDocumentsProvider.kt`
- Create: `android/kit/src/androidTest/kotlin/org/secretary/mirror/TestCloudTree.kt` (helper: install temp root, build tree URI, grant to self, fault hook accessor)
- Create (self-test): `android/kit/src/androidTest/kotlin/org/secretary/mirror/TestCloudDocumentsProviderTest.kt`

**Interfaces:**
- Produces:
  - `TestCloudDocumentsProvider` — a `DocumentsProvider` over a temp dir at authority `org.secretary.kit.test.documents`.
  - `object TestCloudTree`:
    - `fun install(context: Context): TreeHandle` — point the provider at a fresh temp root, return a handle.
    - `class TreeHandle(val treeUri: String, val rootDir: File)` — `treeUri` is the `content://` string for `safCloudFolderPort`.
    - fault control: `var failWritePaths: Set<String>`, `var deleteReturnsFalsePaths: Set<String>`, `var failCreatePaths: Set<String>` (static on the provider, reset by `install`).
- Consumes (later tasks): `safCloudFolderPort(context, handle.treeUri)`.

**Notes for the implementer (on-device iteration expected):** A `DocumentsProvider` in the `androidTest` APK is reached in-process by the instrumentation. Register it `android:exported="false"` (same-UID access) with `android:grantUriPermissions="true"`. Build the tree URI with `DocumentsContract.buildTreeDocumentUri(AUTHORITY, ROOT_DOC_ID)`. If `ContentResolver` access is denied, call `context.grantUriPermission(context.packageName, Uri.parse(treeUri), FLAG_GRANT_READ_URI_PERMISSION or FLAG_GRANT_WRITE_URI_PERMISSION)` in `install`. The self-test below is the RED that drives getting registration/permission right before any shim test depends on it. Implement `queryRoots`, `queryDocument`, `queryChildDocuments`, `openDocument` (`"r"` / `"w"` / `"wt"` via `ParcelFileDescriptor.open` on the backing temp file), `createDocument` (file + `Document.MIME_TYPE_DIR`), `deleteDocument`. Map document IDs to relative paths under the temp root (e.g. doc id = relative path, root doc id = `""` or `"root"`).

- [ ] **Step 1: Write the failing self-test.** `TestCloudDocumentsProviderTest.kt`:

```kotlin
package org.secretary.mirror

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class TestCloudDocumentsProviderTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun port_over_test_provider_round_trips_via_real_saf() {
        val tree = TestCloudTree.install(context)
        val port = safCloudFolderPort(context, tree.treeUri) // REAL DocumentFile + ContentResolver
        port.write("blocks/a.cbor.enc", byteArrayOf(1, 2, 3))
        assertTrue(port.list().contains("blocks/a.cbor.enc"))
        assertArrayEquals(byteArrayOf(1, 2, 3), port.read("blocks/a.cbor.enc"))
        port.delete("blocks/a.cbor.enc")
        assertTrue(!port.list().contains("blocks/a.cbor.enc"))
    }
}
```

- [ ] **Step 2: Run to verify it fails.**
Run: `cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-slice6-instrumented-e2e/android && ./gradlew :kit:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.mirror.TestCloudDocumentsProviderTest`
Expected: FAIL — provider/helper unresolved (or, once stubbed, a SAF resolution/permission error to iterate on).

- [ ] **Step 3: Implement the manifest, provider, and helper.**

`android/kit/src/androidTest/AndroidManifest.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <provider
            android:name="org.secretary.mirror.TestCloudDocumentsProvider"
            android:authorities="org.secretary.kit.test.documents"
            android:exported="false"
            android:grantUriPermissions="true" />
    </application>
</manifest>
```

Implement `TestCloudDocumentsProvider.kt` (temp-dir-backed; `companion object` holding the current root `File` + the three fault `Set<String>` fields, settable by `TestCloudTree`). `openDocument` honors `failWritePaths` (throw `FileNotFoundException` for a `"w"`/`"wt"` open of a faulted path) and `createDocument` honors `failCreatePaths`; `deleteDocument` returns/throws to model `deleteReturnsFalsePaths` (since SAF surfaces a failed delete, model it so `DocumentFile.delete()` returns `false` — e.g. do not remove the backing file and return without success per the provider contract that yields `false`). Keep the file focused; if it nears ~400 lines, split the path↔docId mapping into a sibling file.

Implement `TestCloudTree.kt` with `install` creating a fresh temp root (`File(context.cacheDir, "saftree-" + System.nanoTime())`), resetting fault sets, building + granting the tree URI.

- [ ] **Step 4: Run to verify the self-test passes.**
Run: `cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-slice6-instrumented-e2e/android && ./gradlew :kit:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.mirror.TestCloudDocumentsProviderTest`
Expected: PASS (1 test). Iterate on registration/permission until green.

- [ ] **Step 5: Commit.**

```bash
cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-slice6-instrumented-e2e && \
git add android/kit/src/androidTest/AndroidManifest.xml \
        android/kit/src/androidTest/kotlin/org/secretary/mirror/TestCloudDocumentsProvider.kt \
        android/kit/src/androidTest/kotlin/org/secretary/mirror/TestCloudTree.kt \
        android/kit/src/androidTest/kotlin/org/secretary/mirror/TestCloudDocumentsProviderTest.kt && \
git commit -m "test(android): test-only DocumentsProvider over a temp dir for real-SAF instrumented tests"
```

---

## Task 5: `SafCloudFolderPortInstrumentedTest` — factory on-device branches

**Files:**
- Create: `android/kit/src/androidTest/kotlin/org/secretary/mirror/SafCloudFolderPortInstrumentedTest.kt`

**Interfaces:**
- Consumes: `TestCloudTree.install`, `safCloudFolderPort`, fault hooks from Task 4.
- Produces: nothing (leaf test).

Covers the branches in `safCloudFolderPort` (`SafCloudFolderPort.kt`) that host fakes can't reach: nested directory walk + create, `findOrCreate` overwrite (delete-then-create), the `deleteFile`-returns-false guard, idempotent delete-of-absent, and the `"wt"` truncating overwrite.

- [ ] **Step 1: Write the failing tests.**

```kotlin
package org.secretary.mirror

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SafCloudFolderPortInstrumentedTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun write_creates_nested_dirs_then_list_walks_them() {
        val tree = TestCloudTree.install(context)
        val port = safCloudFolderPort(context, tree.treeUri)
        port.write("blocks/deep/b.cbor.enc", byteArrayOf(5))
        port.write(MANIFEST_FILENAME, byteArrayOf(6))
        val listed = port.list().toSet()
        assertTrue(listed.contains("blocks/deep/b.cbor.enc"))
        assertTrue(listed.contains(MANIFEST_FILENAME))
    }

    @Test fun write_overwrites_via_delete_then_create_with_truncation() {
        val tree = TestCloudTree.install(context)
        val port = safCloudFolderPort(context, tree.treeUri)
        port.write("m", byteArrayOf(1, 2, 3, 4))
        port.write("m", byteArrayOf(9)) // shorter — proves "wt" truncation, no stale tail
        assertArrayEquals(byteArrayOf(9), port.read("m"))
    }

    @Test fun delete_of_absent_is_a_noop() {
        val tree = TestCloudTree.install(context)
        val port = safCloudFolderPort(context, tree.treeUri)
        port.delete("nope") // must not throw (CloudFolderPort.delete contract)
    }

    @Test fun delete_that_returns_false_on_existing_file_is_surfaced() {
        val tree = TestCloudTree.install(context)
        val port = safCloudFolderPort(context, tree.treeUri)
        port.write("stuck", byteArrayOf(1))
        tree.deleteReturnsFalsePaths = setOf("stuck")
        val e = assertThrows(CloudFolderException::class.java) { port.delete("stuck") }
        assertTrue(e.message!!.contains("cannot delete"))
    }

    @Test fun overwrite_when_delete_returns_false_is_surfaced_not_silently_forked() {
        val tree = TestCloudTree.install(context)
        val port = safCloudFolderPort(context, tree.treeUri)
        port.write("dup", byteArrayOf(1))
        tree.deleteReturnsFalsePaths = setOf("dup")
        val e = assertThrows(CloudFolderException::class.java) { port.write("dup", byteArrayOf(2)) }
        assertTrue(e.message!!.contains("cannot overwrite"))
    }
}
```

- [ ] **Step 2: Run to verify it fails.**
Run: `cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-slice6-instrumented-e2e/android && ./gradlew :kit:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.mirror.SafCloudFolderPortInstrumentedTest`
Expected: FAIL initially (assertions or fault-hook wiring); iterate on the provider's fault modeling until each branch is exercised.

- [ ] **Step 3: Implement.** No production change expected — `safCloudFolderPort` already has these branches. If a fault mode isn't expressible by the provider, extend `TestCloudDocumentsProvider`'s fault handling (Task 4 file) minimally and re-run.

- [ ] **Step 4: Run to verify it passes.**
Run: the same command as Step 2.
Expected: PASS (5 tests).

- [ ] **Step 5: Commit.**

```bash
cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-slice6-instrumented-e2e && \
git add android/kit/src/androidTest/kotlin/org/secretary/mirror/SafCloudFolderPortInstrumentedTest.kt \
        android/kit/src/androidTest/kotlin/org/secretary/mirror/TestCloudDocumentsProvider.kt && \
git commit -m "test(android): instrumented SafCloudFolderPort factory branches over real SAF"
```

---

## Task 6: `CloudWorkingCopyLifecycleInstrumentedTest` — create→flush→materialize→open + offline retry + #327

**Files:**
- Create: `android/kit/src/androidTest/kotlin/org/secretary/mirror/CloudLifecycleStaging.kt` (helpers: build a `VaultMirrorWorkingCopy` over a `TestCloudTree`, create a vault into a working dir via `uniffiVaultCreatePort`, a `FilePendingFlushMarker` at a chosen path)
- Create: `android/kit/src/androidTest/kotlin/org/secretary/mirror/CloudWorkingCopyLifecycleInstrumentedTest.kt`

**Interfaces:**
- Consumes: `TestCloudTree`, `safCloudFolderPort`, `VaultMirror`, `VaultMirrorWorkingCopy`, `VaultWorkingCopyCoordinator`, `FilePendingFlushMarker`, `uniffiVaultCreatePort()` (`createInFolder(path, pw, name) -> CreatedVault` with `.vaultUuid`), `PendingFlushNotPersisted`.
- Produces: nothing (leaf test).

This exercises the coordinator over the REAL mirror + REAL SAF, with `openAndSync` supplied as a lambda that asserts the working dir is materialized (do NOT require the full uniffi open here — keep `openAndSync` a thin verifier that reads `MANIFEST_FILENAME` from the working dir; the full open+sync FFI path is already covered by `SyncRoundTripInstrumentedTest`). This isolates the lifecycle ordering over real SAF.

- [ ] **Step 1: Write the failing tests.**

```kotlin
package org.secretary.mirror

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.secretary.browse.uniffiVaultCreatePort
import java.io.File
import java.nio.file.Files

@RunWith(AndroidJUnit4::class)
class CloudWorkingCopyLifecycleInstrumentedTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private fun freshDir(p: String) = Files.createTempDirectory(p).toFile()

    private fun coordinator(tree: TestCloudTree.TreeHandle, workingDir: File, markerFile: File, opened: MutableList<String>) =
        VaultWorkingCopyCoordinator(
            VaultMirrorWorkingCopy(VaultMirror(safCloudFolderPort(context, tree.treeUri)), workingDir),
            FilePendingFlushMarker(markerFile),
        ) {
            // openAndSync stand-in: assert the working copy is materialized
            opened.add("open")
            assertTrue("materialized working copy must hold a manifest", File(workingDir, MANIFEST_FILENAME).exists())
            "S"
        }

    @Test fun create_flush_then_reopen_materializes_from_cloud() = runBlocking {
        val tree = TestCloudTree.install(context)
        val workingDir = freshDir("wc-create-")
        val created = uniffiVaultCreatePort().createInFolder(workingDir.path, "pw".toByteArray(), "Lifecycle")
        val opened = mutableListOf<String>()
        // createThenOpen pushes working→cloud, then opens
        coordinator(tree, workingDir, File(freshDir("mk-"), "m"), opened)
            .createThenOpen(bytesToHex(created.vaultUuid)) { /* persist no-op */ }
        assertTrue("cloud must now hold the manifest", safCloudFolderPort(context, tree.treeUri).list().contains(MANIFEST_FILENAME))

        // A fresh device: empty working dir, reopen pulls the whole vault
        val freshWorking = freshDir("wc-reopen-")
        coordinator(tree, freshWorking, File(freshDir("mk2-"), "m"), opened).openExisting()
        assertTrue(File(freshWorking, MANIFEST_FILENAME).exists())
    }

    @Test fun offline_create_then_reopen_does_not_clobber_when_marker_lost() = runBlocking {
        val tree = TestCloudTree.install(context)
        val workingDir = freshDir("wc-offline-")
        val created = uniffiVaultCreatePort().createInFolder(workingDir.path, "pw".toByteArray(), "Offline")
        // Force the create push to fail: fault ALL writes to the cloud.
        tree.failWritePaths = setOf("*")
        // Point the marker at an UNWRITABLE path (parent is a regular file) so set() cannot persist.
        val markerParent = File(freshDir("mk-bad-"), "afile").apply { writeBytes(byteArrayOf(0)) }
        val badMarker = File(markerParent, "m") // parent is a file → mkdirs/createNewFile fail
        val opened = mutableListOf<String>()
        val coord = coordinator(tree, workingDir, badMarker, opened)
        assertThrows(PendingFlushNotPersisted::class.java) {
            runBlocking { coord.createThenOpen(bytesToHex(created.vaultUuid)) { } }
        }
        // The offline-created vault still lives in the working copy …
        assertTrue(File(workingDir, MANIFEST_FILENAME).exists())
        // … and a reopen over the (still manifest-less) cloud must NOT clobber it.
        tree.failWritePaths = emptySet()
        coordinator(tree, workingDir, File(freshDir("mk-ok-"), "m"), opened).openExisting()
        assertTrue("materialize guard preserves the un-pushed vault", File(workingDir, MANIFEST_FILENAME).exists())
    }
}
```

(Provide `bytesToHex` in `CloudLifecycleStaging.kt` if no public helper exists; reuse `hexOfBytes`/`hexToBytesPublic` from `org.secretary.browse` if accessible. The `"*"` write-fault wildcard is a `TestCloudTree` convenience added in Task 4 or here.)

- [ ] **Step 2: Run to verify it fails.**
Run: `cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-slice6-instrumented-e2e/android && ./gradlew :kit:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.mirror.CloudWorkingCopyLifecycleInstrumentedTest`
Expected: FAIL — helpers unresolved / fault wildcard missing; iterate.

- [ ] **Step 3: Implement helpers** (`CloudLifecycleStaging.kt`) and any `TestCloudTree` additions (the `"*"` write-fault wildcard, hex helper). No production change beyond what Tasks 1–2 already shipped.

- [ ] **Step 4: Run to verify it passes.**
Run: same as Step 2.
Expected: PASS (2 tests).

- [ ] **Step 5: Commit.**

```bash
cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-slice6-instrumented-e2e && \
git add android/kit/src/androidTest/kotlin/org/secretary/mirror/CloudLifecycleStaging.kt \
        android/kit/src/androidTest/kotlin/org/secretary/mirror/CloudWorkingCopyLifecycleInstrumentedTest.kt \
        android/kit/src/androidTest/kotlin/org/secretary/mirror/TestCloudTree.kt && \
git commit -m "test(android): instrumented working-copy lifecycle — create/flush/materialize/open + offline-create no-clobber (#327)"
```

---

## Task 7: `TwoWorkingCopiesConflictInstrumentedTest` — full-content convergence over one SAF tree

**Files:**
- Create: `android/kit/src/androidTest/kotlin/org/secretary/mirror/TwoWorkingCopiesConflictInstrumentedTest.kt`

**Interfaces:**
- Consumes: `TestCloudTree`, `safCloudFolderPort`, `VaultMirror`, the uniffi open path to (a) commit a record edit and (b) read record fields back. Reuse the edit/read pattern from `android/kit/src/androidTest/kotlin/org/secretary/browse/RevealResidencyInstrumentedTest.kt` and `android/app/src/androidTest/kotlin/org/secretary/app/BlockCrudRoundTripUiTest.kt` (open via `openBrowseWithSync` / the uniffi open port, mutate via the browse VM's commit path, read fields back).
- Produces: nothing (leaf test).

**Conflict construction (the key bit):** the shim's `flush()` overwrites the cloud manifest and never forks, so the test plays the role of the cloud provider:

1. Stage a base vault into the cloud tree (`GoldenVaultStaging` content copied into the `TestCloudTree` root, or create one and flush it).
2. Working copy A: `materialize` → open → commit edit α (e.g. set field F to "A") → flush A's `manifest.cbor.enc` + A's changed block to the cloud (canonical).
3. Working copy B: branch from the SAME base — it must `materialize` BEFORE A's flush (or re-materialize the base bytes), then open with the same password → commit edit β (set a different field G to "B", or the same record/different field) → this yields B's own `manifest.cbor.enc` + block in B's working dir.
4. **Simulate the provider:** write B's `manifest.cbor.enc` bytes into the cloud tree as a sibling named `"manifest.cbor.enc (conflicted copy)"` and copy B's changed block (uuid-named — no collision) into the cloud `blocks/`.
5. A `materialize` → `sync_once` (via open) ingests + merges the sibling; B `materialize` (canonical + sibling) → merges.
6. **Assert full content convergence:** read the merged record from both A's and B's working copies after the merge; both contain both edits (α and β) and are byte-identical at the record-field level.

- [ ] **Step 1: Write the failing test** (structure above; concrete field names depend on the staged vault's records — read them first via the open path, mirroring `BlockCrudRoundTripUiTest`). Assert each side sees both α and β and that A's and B's read-back field sets are equal.

- [ ] **Step 2: Run to verify it fails.**
Run: `cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-slice6-instrumented-e2e/android && ./gradlew :kit:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.mirror.TwoWorkingCopiesConflictInstrumentedTest`
Expected: FAIL — iterate on the open/edit/read wiring and the sibling construction.

- [ ] **Step 3: Implement** the test + any small staging helper. No production change. If reading record content requires a helper not present, add it to `CloudLifecycleStaging.kt`.

- [ ] **Step 4: Run to verify it passes.**
Run: same as Step 2.
Expected: PASS — both working copies converge to identical merged content.

- [ ] **Step 5: Commit.**

```bash
cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-slice6-instrumented-e2e && \
git add android/kit/src/androidTest/kotlin/org/secretary/mirror/TwoWorkingCopiesConflictInstrumentedTest.kt \
        android/kit/src/androidTest/kotlin/org/secretary/mirror/CloudLifecycleStaging.kt && \
git commit -m "test(android): two working copies over one SAF tree converge to identical merged content"
```

---

## Task 8: Full suite run + Slice-4 screen tests + docs + close #327

**Files:**
- Modify: `README.md`, `ROADMAP.md`
- (Optional polish) `android/app/src/main/kotlin/org/secretary/app/AppRoot.kt` — a toast/banner for `createdButNotSynced` if the reviewer wants user-facing surfacing.

- [ ] **Step 1: Run the full host gate.**
Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-slice6-instrumented-e2e/android && \
  ./gradlew :vault-access:test :kit:testDebugUnitTest :app:testDebugUnitTest \
            :app:compileDebugKotlin :app:compileDebugAndroidTestKotlin
```
Expected: all green / BUILD SUCCESSFUL.

- [ ] **Step 2: Run the full instrumented suite on the emulator** (new Slice-6 classes + the existing suite incl. the 7 Slice-4 screen tests).
Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-slice6-instrumented-e2e/android && \
  ./gradlew :kit:connectedDebugAndroidTest :app:connectedDebugAndroidTest
```
Expected: all green. Record any pre-existing flake explicitly (do not silently skip). Confirm `VaultSelectionScreenUiTest` + `CreateVaultWizardScreenUiTest` (the Slice-4 screens) pass.

- [ ] **Step 3: Rust + conformance sanity (no FFI change this slice, so these must be unchanged).**
Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-slice6-instrumented-e2e && \
  cargo fmt --all --check && \
  cargo clippy --release --workspace --tests -- -D warnings && \
  bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh && \
  bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
```
Expected: clean; both conformance suites 27/27.

- [ ] **Step 4: Update README.md + ROADMAP.md** — mark the Android cloud-drive provisioning epic complete: provisioning + working-copy round-trip now **instrumented-proven E2E on the emulator** (create→flush→materialize→open, offline-create no-clobber, two-copies full-content convergence over real SAF), and #327 fixed. Keep entries brief (dot points), accurately scoped (real-device biometric + interactive-picker UiAutomator remain out of scope).

- [ ] **Step 5: Commit docs.**

```bash
cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-slice6-instrumented-e2e && \
git add README.md ROADMAP.md && \
git commit -m "docs: Android cloud-drive epic complete — slice 6 instrumented E2E + #327 fixed"
```

(Closing #321 + #327 happens at PR merge via the PR body `Closes #321` / `Closes #327`.)

---

## Self-Review

**Spec coverage:**
- Test `DocumentsProvider` strategy → Task 4. ✓
- `SafCloudFolderPort` on-device branches → Task 5. ✓
- create→flush→materialize→open + offline-flush-retry + offline-create→reopen (#327 trigger) → Task 6. ✓
- two-copies full-content convergence → Task 7. ✓
- #327 fix: coordinator escalation (Task 1) + materialize-clobber guard (Task 2) + `:app` handling (Task 3). ✓
- marker-write-failure branch instrumented → Task 6 (`offline_create_then_reopen_does_not_clobber_when_marker_lost`). ✓
- Slice-4 screen tests + existing suite run → Task 8. ✓
- README/ROADMAP → Task 8. ✓
- No core/spec/format/conformance/FFI change; conformance 27/27 verified → Task 8 Step 3. ✓

**Placeholder scan:** No "TBD"/"handle edge cases". Instrumented test bodies are concrete; the few "iterate on-device" notes are honest about the SAF-registration reality, not hand-waved logic — each has a concrete RED self-test gating it.

**Type consistency:** `PendingFlushNotPersisted(createdVaultUuidHex, cause)` defined Task 1, consumed Tasks 3/6. `materialize()` no-op guard (Task 2) relied on by Task 6's no-clobber test. `TestCloudTree.install → TreeHandle(treeUri, rootDir)` + fault sets defined Task 4, used Tasks 5/6/7. `MANIFEST_FILENAME` used consistently. `safCloudFolderPort(context, treeUri)` signature matches `SafCloudFolderPort.kt:43`. `VaultWorkingCopyCoordinator(mirror, marker) { openAndSync }` matches the constructor.
