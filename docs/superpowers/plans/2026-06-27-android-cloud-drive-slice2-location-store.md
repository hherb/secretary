# Android Cloud-Drive Provisioning — Slice 2: VaultLocationStore Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Kotlin `VaultLocationStore` (pure port + value type + codec in `:vault-access`) and its real `SafVaultLocationStore` adapter (in `:kit`) that remembers ONE vault location — a SAF tree URI string plus display name — in SharedPreferences, taking a durable persistable-URI permission, and reports whether that permission is still granted.

**Architecture:** Mirror the existing `:vault-access` (pure, host-tested, no Android) / `:kit` (real adapter) split used by Slice 1's `VaultCreatePort` / `UniffiVaultCreatePort`. The pure layer holds the `VaultLocation` value type, the `VaultLocationStore` interface, and a reversible `VaultLocationCodec` (single-blob encode/decode). The real `SafVaultLocationStore` carries NO Android types in its own body — it takes four String-based function seams (read/write the pref, take/check the SAF permission) so all logic is host-testable with fakes; the live SAF + SharedPreferences wiring lives only in a `safVaultLocationStore(context)` factory exercised on-device.

**Tech Stack:** Kotlin, JUnit 5 (Jupiter) host unit tests in `:vault-access` and `:kit`, Android Storage Access Framework (`ContentResolver.takePersistableUriPermission` / `persistedUriPermissions`), SharedPreferences.

**Scope note:** This is slice 2 of 6 in the epic specified at
`docs/superpowers/specs/2026-06-27-android-cloud-drive-provisioning-design.md`
(epic tracking issue: #321). It deliberately does NOT touch the working-copy
mirror, the provisioning UI, app routing, or `SyncState` keying — those are slices
3–6. Per the brainstorm decisions: `VaultLocation` carries only `{displayName,
treeUri}` (no `vault_uuid` — it is unknown at persist time and `SyncState` keying
is a Slice-5 concern); the store exposes an `isAvailable` boolean probe (the honest
Slice-2 surface for the spec's "stale permission → re-pick" path), NOT iOS's
`beginAccess → path` (there is no real path until working-copy *materialize*, a
later slice).

## Global Constraints

- **Module split discipline:** pure interface + value type + codec live in `:vault-access`; all Android/SAF I/O lives in `:kit`. (Mirrors `VaultCreatePort` in `:vault-access` vs `UniffiVaultCreatePort` in `:kit`.)
- **Mirror iOS naming** where an analogue exists: iOS `VaultLocation` / `VaultLocationStore` (`ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/`), `BookmarkVaultLocationStore` (`ios/SecretaryKit/.../VaultAccess/BookmarkVaultLocationStore.swift`).
- **No secrets in this surface:** a tree URI + folder name carry no key material, so `VaultLocation` is a `data class` (value equality is useful + safe), NOT the plain-class treatment secret-bearing `CreatedVault` required. Nothing here is zeroized.
- **Injected-seam testability:** `SafVaultLocationStore`'s own body references NO Android types — it takes four String-based function seams, exactly like Slice 1's `createFn`. Android (`Context` / `Uri` / `ContentResolver` / `SharedPreferences`) appears ONLY in the `safVaultLocationStore(context)` factory.
- **No magic strings/numbers:** prefs name, prefs key, and the codec version are named constants.
- **Conservative decode:** `decodeVaultLocation` returns `null` for anything malformed (mirrors `FileDeviceEnrollmentMetadataStore.load`'s under-report posture) — never throws.
- **Synchronous, no coroutines:** location ops do no crypto (no Argon2), so — like iOS and `FileDeviceEnrollmentMetadataStore` — the interface is plain `fun`, not `suspend`.
- **No instrumented test this slice (documented, not silent):** a real persistable *tree* URI requires driving the system SAF picker (UiAutomator), not automatable in a unit slice. The live `takePersistableUriPermission` round-trip is covered by Slice 6's instrumented E2E. (Slice 1 had an instrumented test only because the FFI `.so` create is automatable; SAF grants are not.)
- **Tests green** before each commit; Kotlin files stay focused (both new source files are well under 100 lines). **Commit per task** with a conventional-commit message.

**Test commands** (run from the `android/` Gradle root in THIS worktree):

```bash
cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-locstore/android
./gradlew :vault-access:test            # host JVM unit tests (Task 1)
./gradlew :kit:testDebugUnitTest        # host JVM unit tests (Task 2)
```

No emulator/device is needed for either task.

---

### Task 1: Pure layer — `VaultLocation`, `VaultLocationStore`, `VaultLocationCodec` (`:vault-access`)

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultLocation.kt`
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultLocationStore.kt`
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultLocationCodec.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/VaultLocationCodecTest.kt`

**Interfaces:**
- Consumes: nothing (new pure layer).
- Produces (Task 2 relies on these exact names/types):
  - `data class VaultLocation(val displayName: String, val treeUri: String)`
  - `interface VaultLocationStore { fun load(): VaultLocation?; fun persist(location: VaultLocation); fun clear(); fun isAvailable(location: VaultLocation): Boolean }`
  - `fun encodeVaultLocation(location: VaultLocation): String`
  - `fun decodeVaultLocation(encoded: String): VaultLocation?`

- [ ] **Step 1: Write the failing test**

Create `android/vault-access/src/test/kotlin/org/secretary/browse/VaultLocationCodecTest.kt`:

```kotlin
package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class VaultLocationCodecTest {
    private val tree = "content://com.android.externalstorage.documents/tree/primary%3AVault"

    @Test
    fun `round-trips a typical location`() {
        val loc = VaultLocation("My Vault", tree)
        assertEquals(loc, decodeVaultLocation(encodeVaultLocation(loc)))
    }

    @Test
    fun `round-trips a display name containing the colon delimiter`() {
        val loc = VaultLocation("a:b:c", tree)
        assertEquals(loc, decodeVaultLocation(encodeVaultLocation(loc)))
    }

    @Test
    fun `round-trips an empty display name`() {
        val loc = VaultLocation("", tree)
        assertEquals(loc, decodeVaultLocation(encodeVaultLocation(loc)))
    }

    @Test
    fun `decodes null for a wrong version tag`() {
        assertNull(decodeVaultLocation("v2:3:abc$tree"))
    }

    @Test
    fun `decodes null for a missing length delimiter`() {
        assertNull(decodeVaultLocation("v1:abc"))
    }

    @Test
    fun `decodes null for a non-numeric length`() {
        assertNull(decodeVaultLocation("v1:x:abc"))
    }

    @Test
    fun `decodes null when payload is shorter than the declared name length`() {
        assertNull(decodeVaultLocation("v1:99:short"))
    }

    @Test
    fun `decodes null for an empty string`() {
        assertNull(decodeVaultLocation(""))
    }

    @Test
    fun `VaultLocation is value-equal (deliberate data class, unlike CreatedVault)`() {
        assertEquals(VaultLocation("n", "u"), VaultLocation("n", "u"))
        assertNotEquals(VaultLocation("n", "u"), VaultLocation("n", "v"))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-locstore/android && ./gradlew :vault-access:test`
Expected: FAIL — compilation error, `VaultLocation` / `encodeVaultLocation` / `decodeVaultLocation` unresolved.

- [ ] **Step 3: Write minimal implementation**

Create `android/vault-access/src/main/kotlin/org/secretary/browse/VaultLocation.kt`:

```kotlin
package org.secretary.browse

/**
 * A remembered vault location: a human-readable [displayName] plus the SAF tree URI
 * string [treeUri] returned by the Android Storage Access Framework picker.
 *
 * Neither field is secret — the tree URI is a path-style `content://` token with no
 * key material, and the name is a folder label — so persisting this type (e.g. in
 * SharedPreferences) carries no secret-residue risk. No vault key or credential ever
 * flows through it. A plain `data class` (unlike secret-bearing `CreatedVault`)
 * because value equality / `toString` are useful and safe here. Kotlin mirror of iOS
 * `VaultLocation`.
 */
data class VaultLocation(val displayName: String, val treeUri: String)
```

Create `android/vault-access/src/main/kotlin/org/secretary/browse/VaultLocationStore.kt`:

```kotlin
package org.secretary.browse

/**
 * Persists ONE remembered vault location and reports whether its SAF permission is
 * still granted. The port keeps the platform persistence + SAF permission machinery
 * behind a boundary so the (later) selection view-model is host-testable against a
 * fake. Single-vault by design (this slice): [persist] replaces any prior location.
 *
 * Kotlin mirror of iOS `VaultLocationStore`, minus iOS's `beginAccess`: on Android a
 * SAF tree exposes no real filesystem path, so resolving a location to an operable
 * path is the working-copy *materialize* step (a later slice), not this store's job.
 */
interface VaultLocationStore {
    /** The remembered location, or null if none has been selected. */
    fun load(): VaultLocation?

    /** Remember [location], replacing any prior one. */
    fun persist(location: VaultLocation)

    /** Forget the remembered location. */
    fun clear()

    /**
     * Whether the persistable SAF permission for [location] is still held (the tree has
     * not been revoked / the granting provider uninstalled). The selection screen uses a
     * false result to prompt a re-pick (mirrors iOS's stale-bookmark `.unavailable`).
     */
    fun isAvailable(location: VaultLocation): Boolean
}
```

Create `android/vault-access/src/main/kotlin/org/secretary/browse/VaultLocationCodec.kt`:

```kotlin
package org.secretary.browse

/**
 * Pure, reversible encoding of a [VaultLocation] to/from a single persisted string
 * (one atomic SharedPreferences value, so a location can never half-persist with a URI
 * but no name). Free functions, no Android dependency → fully host-testable.
 *
 * Format: `"<VERSION>:<displayName.length>:<displayName><treeUri>"`. The display name is
 * length-prefixed (UTF-16 code units, matching `String.length` / `String.substring`) so
 * it needs no escaping and may contain any character — including the `:` delimiter. The
 * only structural delimiters are the version tag and the single colon after the length
 * digits.
 */

/** Codec format version; bump when the encoding changes so old blobs decode to null. */
internal const val VAULT_LOCATION_CODEC_VERSION = "v1"

/** Encode [location] to its persisted string form. */
fun encodeVaultLocation(location: VaultLocation): String =
    "$VAULT_LOCATION_CODEC_VERSION:${location.displayName.length}:${location.displayName}${location.treeUri}"

/**
 * Decode a string produced by [encodeVaultLocation]. Returns null for anything malformed
 * — wrong/absent version tag, missing length delimiter, non-numeric or negative length, or
 * a payload shorter than the declared name length — a conservative under-report mirroring
 * `FileDeviceEnrollmentMetadataStore.load`. Never throws.
 */
fun decodeVaultLocation(encoded: String): VaultLocation? {
    val prefix = "$VAULT_LOCATION_CODEC_VERSION:"
    if (!encoded.startsWith(prefix)) return null
    val rest = encoded.substring(prefix.length)
    val colon = rest.indexOf(':')
    if (colon < 0) return null
    val nameLen = rest.substring(0, colon).toIntOrNull() ?: return null
    if (nameLen < 0) return null
    val payload = rest.substring(colon + 1)
    if (payload.length < nameLen) return null
    val displayName = payload.substring(0, nameLen)
    val treeUri = payload.substring(nameLen)
    return VaultLocation(displayName, treeUri)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-locstore/android && ./gradlew :vault-access:test`
Expected: PASS — all 9 `VaultLocationCodecTest` cases green.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-locstore
git add android/vault-access/src/main/kotlin/org/secretary/browse/VaultLocation.kt \
        android/vault-access/src/main/kotlin/org/secretary/browse/VaultLocationStore.kt \
        android/vault-access/src/main/kotlin/org/secretary/browse/VaultLocationCodec.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/VaultLocationCodecTest.kt
git commit -m "feat(android): pure VaultLocationStore port + VaultLocation + codec (:vault-access)"
```

---

### Task 2: Real adapter — `SafVaultLocationStore` + `safVaultLocationStore` factory (`:kit`)

**Files:**
- Create: `android/kit/src/main/kotlin/org/secretary/browse/SafVaultLocationStore.kt`
- Test: `android/kit/src/test/kotlin/org/secretary/browse/SafVaultLocationStoreTest.kt`

**Interfaces:**
- Consumes (from Task 1): `VaultLocation`, `VaultLocationStore`, `encodeVaultLocation`, `decodeVaultLocation`.
- Produces:
  - `class SafVaultLocationStore(readPref: () -> String?, writePref: (String?) -> Unit, takePermission: (String) -> Unit, hasPermission: (String) -> Boolean) : VaultLocationStore`
  - `fun safVaultLocationStore(context: Context): VaultLocationStore`

- [ ] **Step 1: Write the failing test**

Create `android/kit/src/test/kotlin/org/secretary/browse/SafVaultLocationStoreTest.kt`:

```kotlin
package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SafVaultLocationStoreTest {
    private val location = VaultLocation("My Vault", "content://x/tree/y")

    /** In-memory seams recording interactions for ordering/forwarding assertions. */
    private class Fakes(initialPref: String? = null) {
        var pref: String? = initialPref
        val events = mutableListOf<String>()
        val permitted = mutableSetOf<String>()

        fun store(): SafVaultLocationStore = SafVaultLocationStore(
            readPref = { pref },
            writePref = { blob -> events.add("write:$blob"); pref = blob },
            takePermission = { uri -> events.add("take:$uri"); permitted.add(uri) },
            hasPermission = { uri -> uri in permitted },
        )
    }

    @Test
    fun `persist takes the permission before writing the pref`() {
        val f = Fakes()
        f.store().persist(location)
        assertEquals(
            listOf("take:content://x/tree/y", "write:${encodeVaultLocation(location)}"),
            f.events,
        )
    }

    @Test
    fun `load decodes the persisted blob`() {
        val f = Fakes(initialPref = encodeVaultLocation(location))
        assertEquals(location, f.store().load())
    }

    @Test
    fun `load returns null when nothing is persisted`() {
        assertNull(Fakes().store().load())
    }

    @Test
    fun `load returns null for a malformed blob`() {
        assertNull(Fakes(initialPref = "garbage").store().load())
    }

    @Test
    fun `clear writes null and load then returns null`() {
        val f = Fakes(initialPref = encodeVaultLocation(location))
        val store = f.store()
        store.clear()
        assertNull(f.pref)
        assertNull(store.load())
    }

    @Test
    fun `persist replaces a prior location`() {
        val store = Fakes().store()
        store.persist(VaultLocation("old", "content://x/tree/old"))
        store.persist(location)
        assertEquals(location, store.load())
    }

    @Test
    fun `isAvailable forwards to the permission probe`() {
        val store = Fakes().store()
        assertFalse(store.isAvailable(location))
        store.persist(location)
        assertTrue(store.isAvailable(location))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-locstore/android && ./gradlew :kit:testDebugUnitTest`
Expected: FAIL — compilation error, `SafVaultLocationStore` unresolved.

- [ ] **Step 3: Write minimal implementation**

Create `android/kit/src/main/kotlin/org/secretary/browse/SafVaultLocationStore.kt`:

```kotlin
package org.secretary.browse

import android.content.Context
import android.content.Intent
import android.net.Uri

/**
 * The real [VaultLocationStore] over SharedPreferences + the SAF persistable-URI
 * permission grant. Kotlin mirror of iOS `BookmarkVaultLocationStore`.
 *
 * The class body holds NO Android types: it is constructed from four String-based
 * function seams so the persist/load/clear/availability logic (encode/decode plus the
 * take-permission-before-write ordering) is host-testable with fakes, exactly like
 * Slice 1's `createFn` seam. The live SAF + SharedPreferences wiring lives only in the
 * [safVaultLocationStore] factory, exercised on-device.
 *
 * @param readPref returns the persisted blob, or null if none.
 * @param writePref persists the blob, or clears it when given null.
 * @param takePermission acquires a durable (persistable) read+write grant for the tree URI string.
 * @param hasPermission reports whether a durable grant for the tree URI string is still held.
 */
class SafVaultLocationStore(
    private val readPref: () -> String?,
    private val writePref: (String?) -> Unit,
    private val takePermission: (String) -> Unit,
    private val hasPermission: (String) -> Boolean,
) : VaultLocationStore {
    override fun load(): VaultLocation? = readPref()?.let { decodeVaultLocation(it) }

    override fun persist(location: VaultLocation) {
        // Acquire the durable grant BEFORE recording the location: never persist a tree
        // URI we have not secured persistable access to.
        takePermission(location.treeUri)
        writePref(encodeVaultLocation(location))
    }

    override fun clear() = writePref(null)

    override fun isAvailable(location: VaultLocation): Boolean = hasPermission(location.treeUri)
}

/**
 * Production factory wiring the real SAF + SharedPreferences seams from [context]. The
 * only Android-bound code in this file; not host-tested (covered on-device / by Slice
 * 6's instrumented E2E).
 */
fun safVaultLocationStore(context: Context): VaultLocationStore {
    val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    val resolver = context.contentResolver
    val grantFlags = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
    return SafVaultLocationStore(
        readPref = { prefs.getString(KEY_LOCATION, null) },
        writePref = { blob ->
            val editor = prefs.edit()
            if (blob == null) editor.remove(KEY_LOCATION) else editor.putString(KEY_LOCATION, blob)
            editor.apply()
        },
        takePermission = { uri -> resolver.takePersistableUriPermission(Uri.parse(uri), grantFlags) },
        hasPermission = { uri ->
            val target = Uri.parse(uri)
            resolver.persistedUriPermissions.any {
                it.uri == target && it.isReadPermission && it.isWritePermission
            }
        },
    )
}

private const val PREFS_NAME = "secretary.vault.location"
private const val KEY_LOCATION = "location"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-locstore/android && ./gradlew :kit:testDebugUnitTest`
Expected: PASS — all 7 `SafVaultLocationStoreTest` cases green. (The `safVaultLocationStore` factory is not exercised here; its Android calls run only on-device.)

- [ ] **Step 5: Verify the whole module still builds and host suites are green**

Run: `cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-locstore/android && ./gradlew :vault-access:test :kit:testDebugUnitTest`
Expected: BUILD SUCCESSFUL — both host suites green (Task 1 + Task 2).

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-locstore
git add android/kit/src/main/kotlin/org/secretary/browse/SafVaultLocationStore.kt \
        android/kit/src/test/kotlin/org/secretary/browse/SafVaultLocationStoreTest.kt
git commit -m "feat(android): SafVaultLocationStore adapter + factory (:kit)"
```

---

## Self-Review

**Spec coverage** (against the epic spec's Slice-2 row + brainstorm decisions):
- `VaultLocationStore` pure port — Task 1. ✅
- `SafVaultLocationStore` real adapter persisting tree URI + display name, `takePersistableUriPermission` — Task 2. ✅
- iOS analogue (`BookmarkVaultLocationStore`) mirrored — both tasks. ✅
- Brainstorm decision: value type = `{displayName, treeUri}`, no `vault_uuid` — Task 1. ✅
- Brainstorm decision: `isAvailable` probe (not `beginAccess → path`) — Task 1 interface, Task 2 forwarding. ✅
- Brainstorm decision: injected SAF seam + host-testable codec — Task 1 codec, Task 2 four-seam class. ✅
- Spec testing row "location-store serialization (host)" — `VaultLocationCodecTest`. ✅
- Spec error-handling "stale permission → Unavailable" surface — `isAvailable`. ✅
- Instrumented coverage deferred to Slice 6 — documented in Global Constraints. ✅

**Placeholder scan:** none — all code blocks are complete.

**Type consistency:** `VaultLocation(displayName, treeUri)`, `encodeVaultLocation` / `decodeVaultLocation`, and the four seam signatures `(() -> String?, (String?) -> Unit, (String) -> Unit, (String) -> Boolean)` are identical across Task 1 (produced), Task 2 (consumed + tests), and the factory.
