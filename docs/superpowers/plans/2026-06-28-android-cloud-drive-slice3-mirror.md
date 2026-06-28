# Android cloud-drive Slice 3 — `CloudFolderPort` + pure `VaultMirrorPlanner` + `VaultMirror` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the SAF working-copy *mirror mechanism* — a path-less cloud-folder port, the pure file-diff planner that is its host-testable heart, and the orchestrator that mirrors a vault folder between a real-filesystem working copy and the cloud folder — block-first, byte-for-byte.

**Architecture:** A new package `org.secretary.mirror`, split across the existing two modules. `:vault-access` (pure, host-tested kotlin-jvm) holds the `CloudFolderPort` interface, the pure `VaultMirrorPlanner`, the `sha256Hex` content hash, and the `VaultMirror` orchestrator (which touches the working copy via plain `java.io.File` — the established `DeviceUuid` precedent — and the cloud only through the port). `:kit` holds the real `SafCloudFolderPort` adapter, seam-structured exactly like `SafVaultLocationStore` so its delegation + error-folding is host-tested while the unavoidable Android DocumentFile traversal lives only in a factory (deferred-tested to Slice 6).

**Tech Stack:** Kotlin (jvmToolchain 21), JUnit 5 (host unit tests, `useJUnitPlatform`), `java.security.MessageDigest` + `java.util.HexFormat` (JDK 17+, available under toolchain 21), `androidx.documentfile` (SAF, `:kit` factory only).

## Global Constraints

- **Slice 3 is the mirror *mechanism* only.** When the mirror is *called* (flush-after-commit, pending-flush retry, session wiring) is Slice 5; view models/screens are Slice 4; the instrumented real-SAF round-trip is Slice 6. Do not wire the mirror into any session, view model, or screen in this slice.
- **No core `src/` change, no FFI surface change, no on-disk-format / spec / `conformance.py` / KAT change.** Kotlin/Android only.
- **Module split discipline:** pure logic + ports in `:vault-access` (`package org.secretary.mirror`); the real SAF adapter in `:kit` (`package org.secretary.mirror`). The core owns CRDT merge — **no merge logic in Kotlin**; the mirror only moves bytes.
- **Stateless content-hash diff** (the approved Slice-3 decision): each mirror pass hashes both sides; the local-sidecar flush optimization is explicitly deferred to Slice 5. Do not add persistent mirror state in this slice.
- **No magic numbers / strings:** name the manifest filename and the digest length as `const val`s.
- **Crypto values in tests must be computed at runtime, not hardcoded** (CodeQL "hardcoded cryptographic value"): assert `sha256Hex` by determinism/difference properties, never against a literal digest.
- **House test style:** JUnit 5, backtick test-method names, in-memory fakes that record an ordered `events`/call list for ordering assertions (mirror `VaultLocationCodecTest` / `SafVaultLocationStoreTest`). A test double `FakeX` gets its own `FakeXTest` (mirror `FakeVaultBrowseTest`).
- **File size:** keep each file focused and well under ~500 lines; one concept per file.
- **README.md / ROADMAP.md unchanged** — internal plumbing slice, no observable Android capability yet (consistent with Slices 1–2 and the README brevity convention).

**Acceptance gate (whole branch), run from `android/`:**
```bash
./gradlew :vault-access:test          # host — planner + content-hash + orchestrator + fake suites green
./gradlew :kit:testDebugUnitTest      # host — SafCloudFolderPort seam suite green
```
No emulator/device needed this slice.

---

### Task 1: `sha256Hex` content hash

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/mirror/ContentHash.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/mirror/ContentHashTest.kt`

**Interfaces:**
- Consumes: nothing.
- Produces: `fun sha256Hex(bytes: ByteArray): String` — lowercase-hex SHA-256 (64 chars). Used by Task 4's fingerprinting.

- [ ] **Step 1: Write the failing test**

`android/vault-access/src/test/kotlin/org/secretary/mirror/ContentHashTest.kt`:
```kotlin
package org.secretary.mirror

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ContentHashTest {
    @Test
    fun `is deterministic for the same input`() {
        val data = "block-ciphertext".toByteArray()
        assertEquals(sha256Hex(data), sha256Hex(data.copyOf()))
    }

    @Test
    fun `differs for different input`() {
        assertNotEquals(sha256Hex(byteArrayOf(1, 2, 3)), sha256Hex(byteArrayOf(1, 2, 4)))
    }

    @Test
    fun `is 64 lowercase hex characters`() {
        val hex = sha256Hex(ByteArray(0))
        assertEquals(64, hex.length)
        assertTrue(hex.all { it in '0'..'9' || it in 'a'..'f' })
    }

    @Test
    fun `same-length different-content inputs hash differently (the re-encryption case)`() {
        val a = ByteArray(100) { 0 }
        val b = ByteArray(100) { i -> if (i == 50) 1 else 0 }
        assertNotEquals(sha256Hex(a), sha256Hex(b))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run (from `android/`): `./gradlew :vault-access:test --tests "org.secretary.mirror.ContentHashTest"`
Expected: FAIL — compilation error, `sha256Hex` unresolved.

- [ ] **Step 3: Write minimal implementation**

`android/vault-access/src/main/kotlin/org/secretary/mirror/ContentHash.kt`:
```kotlin
package org.secretary.mirror

import java.security.MessageDigest
import java.util.HexFormat

/**
 * Lowercase-hex SHA-256 of [bytes]. [VaultMirror] uses it to decide whether a working-copy
 * file and its cloud-folder counterpart hold identical content: every block rewrite
 * re-encrypts with a fresh nonce, so equal byte *length* does not imply equal content, and a
 * content hash is the only reliable same-or-different signal. Pure + deterministic
 * (`MessageDigest` is JVM-standard), so fully host-testable with no Android dependency.
 */
fun sha256Hex(bytes: ByteArray): String =
    HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :vault-access:test --tests "org.secretary.mirror.ContentHashTest"`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/mirror/ContentHash.kt \
        android/vault-access/src/test/kotlin/org/secretary/mirror/ContentHashTest.kt
git commit -m "feat(android): sha256Hex content hash for the SAF mirror (slice 3)"
```

---

### Task 2: `VaultMirrorPlanner` — the pure diff heart

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/mirror/VaultMirrorPlanner.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/mirror/VaultMirrorPlannerTest.kt`

**Interfaces:**
- Consumes: nothing (operates purely on maps).
- Produces:
  - `const val MANIFEST_FILENAME = "manifest.cbor.enc"`
  - `data class FileFingerprint(val size: Long, val sha256: String)`
  - `sealed interface MirrorOp { val relativePath: String }` with `data class Copy(override val relativePath: String)` and `data class Delete(override val relativePath: String)`
  - `fun planMirror(source: Map<String, FileFingerprint>, dest: Map<String, FileFingerprint>): List<MirrorOp>`

- [ ] **Step 1: Write the failing test**

`android/vault-access/src/test/kotlin/org/secretary/mirror/VaultMirrorPlannerTest.kt`:
```kotlin
package org.secretary.mirror

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class VaultMirrorPlannerTest {
    private fun fp(seed: Int) = FileFingerprint(seed.toLong(), "hash$seed")
    private val manifestA = mapOf(MANIFEST_FILENAME to fp(1))

    @Test
    fun `copies a file present in source but absent from dest`() {
        val plan = planMirror(source = mapOf("blocks/a.cbor.enc" to fp(1)), dest = emptyMap())
        assertEquals(listOf(MirrorOp.Copy("blocks/a.cbor.enc")), plan)
    }

    @Test
    fun `copies a file whose fingerprint differs (same size, different hash)`() {
        val plan = planMirror(
            source = mapOf("blocks/a.cbor.enc" to FileFingerprint(10, "new")),
            dest = mapOf("blocks/a.cbor.enc" to FileFingerprint(10, "old")),
        )
        assertEquals(listOf(MirrorOp.Copy("blocks/a.cbor.enc")), plan)
    }

    @Test
    fun `skips a file with an identical fingerprint`() {
        val same = mapOf("blocks/a.cbor.enc" to fp(7))
        assertEquals(emptyList<MirrorOp>(), planMirror(source = same, dest = same))
    }

    @Test
    fun `deletes a file present in dest but absent from source`() {
        val plan = planMirror(source = emptyMap(), dest = mapOf("blocks/gone.cbor.enc" to fp(1)))
        assertEquals(listOf(MirrorOp.Delete("blocks/gone.cbor.enc")), plan)
    }

    @Test
    fun `copies the manifest last among copies (block-first invariant)`() {
        val plan = planMirror(
            source = mapOf(
                MANIFEST_FILENAME to fp(1),
                "blocks/a.cbor.enc" to fp(2),
                "blocks/b.cbor.enc" to fp(3),
            ),
            dest = emptyMap(),
        )
        assertEquals(
            listOf(
                MirrorOp.Copy("blocks/a.cbor.enc"),
                MirrorOp.Copy("blocks/b.cbor.enc"),
                MirrorOp.Copy(MANIFEST_FILENAME),
            ),
            plan,
        )
    }

    @Test
    fun `emits all deletes after all copies`() {
        val plan = planMirror(
            source = mapOf(MANIFEST_FILENAME to fp(1), "blocks/keep.cbor.enc" to fp(2)),
            dest = mapOf("blocks/old.cbor.enc" to fp(9)),
        )
        val lastCopyIndex = plan.indexOfLast { it is MirrorOp.Copy }
        val firstDeleteIndex = plan.indexOfFirst { it is MirrorOp.Delete }
        assertTrue(lastCopyIndex < firstDeleteIndex, "all copies must precede any delete: $plan")
        assertEquals(MirrorOp.Copy(MANIFEST_FILENAME), plan[lastCopyIndex])
    }

    @Test
    fun `preserves vault-relative subdirectory paths`() {
        val plan = planMirror(source = mapOf("contacts/x.cbor.enc" to fp(1)), dest = emptyMap())
        assertEquals(listOf(MirrorOp.Copy("contacts/x.cbor.enc")), plan)
    }

    @Test
    fun `an empty source plans deletes for every dest file`() {
        val plan = planMirror(source = emptyMap(), dest = mapOf("a" to fp(1), "b" to fp(2)))
        assertEquals(listOf(MirrorOp.Delete("a"), MirrorOp.Delete("b")), plan)
    }

    @Test
    fun `two empty sides plan nothing`() {
        assertEquals(emptyList<MirrorOp>(), planMirror(emptyMap(), emptyMap()))
    }

    @Test
    fun `orders copies and deletes deterministically by path`() {
        val plan = planMirror(
            source = mapOf("blocks/c.cbor.enc" to fp(1), "blocks/a.cbor.enc" to fp(2)),
            dest = mapOf("blocks/z.cbor.enc" to fp(3), "blocks/m.cbor.enc" to fp(4)),
        )
        assertEquals(
            listOf(
                MirrorOp.Copy("blocks/a.cbor.enc"),
                MirrorOp.Copy("blocks/c.cbor.enc"),
                MirrorOp.Delete("blocks/m.cbor.enc"),
                MirrorOp.Delete("blocks/z.cbor.enc"),
            ),
            plan,
        )
    }

    @Test
    fun `manifest-only change plans just the manifest copy`() {
        val plan = planMirror(
            source = mapOf(MANIFEST_FILENAME to fp(2), "blocks/a.cbor.enc" to fp(5)),
            dest = manifestA + ("blocks/a.cbor.enc" to fp(5)),
        )
        assertEquals(listOf(MirrorOp.Copy(MANIFEST_FILENAME)), plan)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :vault-access:test --tests "org.secretary.mirror.VaultMirrorPlannerTest"`
Expected: FAIL — `planMirror`/`MirrorOp`/`FileFingerprint`/`MANIFEST_FILENAME` unresolved.

- [ ] **Step 3: Write minimal implementation**

`android/vault-access/src/main/kotlin/org/secretary/mirror/VaultMirrorPlanner.kt`:
```kotlin
package org.secretary.mirror

/**
 * The vault manifest filename. Written LAST on every mirror pass so a destination never holds
 * a manifest referencing a block that has not yet been copied (vault-format §9 write ordering).
 */
const val MANIFEST_FILENAME = "manifest.cbor.enc"

/**
 * Content fingerprint of one file: byte [size] plus lowercase-hex SHA-256 [sha256]. Two files
 * are identical iff their fingerprints are equal. (Size alone is insufficient — re-encryption
 * keeps the length but changes the bytes — so the hash is the load-bearing field.)
 */
data class FileFingerprint(val size: Long, val sha256: String)

/** One step of a mirror plan, addressed by vault-relative POSIX [relativePath]. */
sealed interface MirrorOp {
    val relativePath: String

    /** Copy the file from the source side to the destination side (create or overwrite). */
    data class Copy(override val relativePath: String) : MirrorOp

    /** Delete the file from the destination side (it is absent from the source). */
    data class Delete(override val relativePath: String) : MirrorOp
}

/**
 * Pure diff of two vault file-sets, producing an ordered plan that brings [dest] into
 * byte-identical agreement with [source]. The same function serves both directions: flush
 * passes `source = working, dest = cloud`; materialize passes `source = cloud, dest = working`.
 *
 * A file is **copied** when it is present in [source] and either absent from [dest] or carries
 * a different fingerprint. A file present in [dest] but absent from [source] is **deleted**.
 *
 * Ordering enforces the block-first invariant (vault-format §9): every non-manifest copy is
 * emitted before the [MANIFEST_FILENAME] copy, and every delete is emitted after all copies.
 * So a destination is never left with a manifest pointing at a not-yet-written block, nor with
 * a still-referenced block deleted before the superseding manifest lands — both broken windows;
 * the only intermediate states this ordering allows are the recoverable ones (the core's
 * fingerprint recheck tolerates a new block under a stale manifest). Within each group, order
 * is by path so plans are deterministic and reproducible.
 */
fun planMirror(
    source: Map<String, FileFingerprint>,
    dest: Map<String, FileFingerprint>,
): List<MirrorOp> {
    val copies = source.keys.filter { path -> source[path] != dest[path] }.sorted()
    val (manifestCopies, blockCopies) = copies.partition { it == MANIFEST_FILENAME }
    val deletes = dest.keys.filter { it !in source }.sorted()
    return buildList {
        blockCopies.forEach { add(MirrorOp.Copy(it)) }
        manifestCopies.forEach { add(MirrorOp.Copy(it)) }
        deletes.forEach { add(MirrorOp.Delete(it)) }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :vault-access:test --tests "org.secretary.mirror.VaultMirrorPlannerTest"`
Expected: PASS (11 tests).

- [ ] **Step 5: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/mirror/VaultMirrorPlanner.kt \
        android/vault-access/src/test/kotlin/org/secretary/mirror/VaultMirrorPlannerTest.kt
git commit -m "feat(android): pure VaultMirrorPlanner with block-first ordering (slice 3)"
```

---

### Task 3: `CloudFolderPort` interface + `FakeCloudFolderPort` test double

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/mirror/CloudFolderPort.kt`
- Create (test source): `android/vault-access/src/test/kotlin/org/secretary/mirror/FakeCloudFolderPort.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/mirror/FakeCloudFolderPortTest.kt`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `interface CloudFolderPort { fun list(): List<String>; fun read(relativePath: String): ByteArray; fun write(relativePath: String, bytes: ByteArray); fun delete(relativePath: String) }`
  - `class CloudFolderException(message: String) : Exception(message)`
  - test double `class FakeCloudFolderPort(initial: Map<String, ByteArray> = emptyMap()) : CloudFolderPort` with `var failWith: String?`, `fun snapshot(): Map<String, ByteArray>`, and `val writeOrder: List<String>` (records the order of `write`/`delete` calls — used by Task 4's ordering assertion).

- [ ] **Step 1: Write the failing test**

First the test double, `android/vault-access/src/test/kotlin/org/secretary/mirror/FakeCloudFolderPort.kt`:
```kotlin
package org.secretary.mirror

/**
 * In-memory [CloudFolderPort] for host tests: a path→bytes map with call-order recording and
 * optional fault injection. [writeOrder] records every mutating call (`write:`/`delete:`) so a
 * test can assert the block-first execution order; [failWith], when set, makes every operation
 * throw [CloudFolderException] (the revoked-permission / provider-error path).
 */
class FakeCloudFolderPort(initial: Map<String, ByteArray> = emptyMap()) : CloudFolderPort {
    private val files = LinkedHashMap<String, ByteArray>().apply { putAll(initial) }
    val writeOrder = mutableListOf<String>()
    var failWith: String? = null

    fun snapshot(): Map<String, ByteArray> = files.toMap()

    override fun list(): List<String> = guard { files.keys.toList() }

    override fun read(relativePath: String): ByteArray = guard {
        files[relativePath]?.copyOf() ?: throw CloudFolderException("no such file: $relativePath")
    }

    override fun write(relativePath: String, bytes: ByteArray) = guard {
        writeOrder.add("write:$relativePath")
        files[relativePath] = bytes.copyOf()
    }

    override fun delete(relativePath: String) = guard {
        writeOrder.add("delete:$relativePath")
        files.remove(relativePath)
        Unit
    }

    private fun <T> guard(block: () -> T): T {
        failWith?.let { throw CloudFolderException(it) }
        return block()
    }
}
```

Then `android/vault-access/src/test/kotlin/org/secretary/mirror/FakeCloudFolderPortTest.kt`:
```kotlin
package org.secretary.mirror

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class FakeCloudFolderPortTest {
    @Test
    fun `write then read round-trips the bytes`() {
        val port = FakeCloudFolderPort()
        port.write("blocks/a.cbor.enc", byteArrayOf(1, 2, 3))
        assertArrayEquals(byteArrayOf(1, 2, 3), port.read("blocks/a.cbor.enc"))
    }

    @Test
    fun `list reflects writes and deletes`() {
        val port = FakeCloudFolderPort(mapOf("a" to byteArrayOf(0)))
        port.write("b", byteArrayOf(0))
        port.delete("a")
        assertEquals(listOf("b"), port.list())
    }

    @Test
    fun `reading a missing file throws CloudFolderException`() {
        assertThrows(CloudFolderException::class.java) { FakeCloudFolderPort().read("nope") }
    }

    @Test
    fun `deleting a missing file is a no-op`() {
        val port = FakeCloudFolderPort()
        port.delete("nope")
        assertFalse(port.snapshot().containsKey("nope"))
    }

    @Test
    fun `failWith makes every operation throw`() {
        val port = FakeCloudFolderPort()
        port.failWith = "revoked"
        assertThrows(CloudFolderException::class.java) { port.list() }
    }

    @Test
    fun `writeOrder records mutating calls in order`() {
        val port = FakeCloudFolderPort(mapOf("old" to byteArrayOf(0)))
        port.write("blocks/a.cbor.enc", byteArrayOf(1))
        port.delete("old")
        assertEquals(listOf("write:blocks/a.cbor.enc", "delete:old"), port.writeOrder)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :vault-access:test --tests "org.secretary.mirror.FakeCloudFolderPortTest"`
Expected: FAIL — `CloudFolderPort`/`CloudFolderException` unresolved (the interface does not exist yet).

- [ ] **Step 3: Write minimal implementation**

`android/vault-access/src/main/kotlin/org/secretary/mirror/CloudFolderPort.kt`:
```kotlin
package org.secretary.mirror

/**
 * Read/write access to a vault folder that has no real filesystem path — on Android the SAF
 * `content://` tree behind a cloud-drive folder (Drive/Dropbox/OneDrive). Files are addressed
 * by vault-relative POSIX path (`"manifest.cbor.enc"`, `"blocks/<uuid>.cbor.enc"`); the impl
 * maps these onto its storage (a SAF DocumentFile subtree). Pure seam — the real impl is
 * `:kit`'s `SafCloudFolderPort`; host tests use the in-memory `FakeCloudFolderPort`.
 */
interface CloudFolderPort {
    /**
     * Every file under the folder, recursively, as vault-relative POSIX paths. Directories
     * themselves are not returned. Order is unspecified ([VaultMirror] sorts via the planner).
     */
    fun list(): List<String>

    /** Full contents of the file at [relativePath]. */
    fun read(relativePath: String): ByteArray

    /** Create or overwrite the file at [relativePath] with [bytes], creating parent
     *  directories as needed. */
    fun write(relativePath: String, bytes: ByteArray)

    /** Remove the file at [relativePath]; a no-op if it is already absent. */
    fun delete(relativePath: String)
}

/**
 * Thrown by [CloudFolderPort] implementations when a backing-store operation fails — a revoked
 * SAF permission, a provider I/O error, or a missing file on read. The one checked boundary
 * [VaultMirror] folds into `VaultMirrorException`, so callers never see a raw provider
 * exception. Mirrors `org.secretary.browse.DeviceUuidException`.
 */
class CloudFolderException(message: String) : Exception(message)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :vault-access:test --tests "org.secretary.mirror.FakeCloudFolderPortTest"`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/mirror/CloudFolderPort.kt \
        android/vault-access/src/test/kotlin/org/secretary/mirror/FakeCloudFolderPort.kt \
        android/vault-access/src/test/kotlin/org/secretary/mirror/FakeCloudFolderPortTest.kt
git commit -m "feat(android): CloudFolderPort seam + in-memory fake (slice 3)"
```

---

### Task 4: `VaultMirror` orchestrator

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/mirror/VaultMirror.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/mirror/VaultMirrorTest.kt`

**Interfaces:**
- Consumes: `sha256Hex` (Task 1); `FileFingerprint` / `MirrorOp` / `MANIFEST_FILENAME` / `planMirror` (Task 2); `CloudFolderPort` / `CloudFolderException` / `FakeCloudFolderPort` (Task 3).
- Produces:
  - `data class MirrorReport(val copied: List<String>, val deleted: List<String>)`
  - `class VaultMirrorException(message: String) : Exception(message)`
  - `class VaultMirror(private val cloud: CloudFolderPort)` with `fun materialize(workingDir: File): MirrorReport` (cloud→working) and `fun flush(workingDir: File): MirrorReport` (working→cloud).

- [ ] **Step 1: Write the failing test**

`android/vault-access/src/test/kotlin/org/secretary/mirror/VaultMirrorTest.kt`:
```kotlin
package org.secretary.mirror

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.io.TempDir
import org.junit.jupiter.api.Test
import java.io.File

class VaultMirrorTest {
    @TempDir
    lateinit var workingDir: File

    private fun writeWorking(relativePath: String, bytes: ByteArray) {
        val f = File(workingDir, relativePath)
        f.parentFile?.mkdirs()
        f.writeBytes(bytes)
    }

    @Test
    fun `flush copies a new working file to the cloud`() {
        writeWorking("blocks/a.cbor.enc", byteArrayOf(1, 2, 3))
        val cloud = FakeCloudFolderPort()
        val report = VaultMirror(cloud).flush(workingDir)
        assertEquals(listOf("blocks/a.cbor.enc"), report.copied)
        assertArrayEquals(byteArrayOf(1, 2, 3), cloud.snapshot().getValue("blocks/a.cbor.enc"))
    }

    @Test
    fun `flush writes blocks before the manifest (block-first)`() {
        writeWorking(MANIFEST_FILENAME, byteArrayOf(9))
        writeWorking("blocks/a.cbor.enc", byteArrayOf(1))
        writeWorking("blocks/b.cbor.enc", byteArrayOf(2))
        val cloud = FakeCloudFolderPort()
        VaultMirror(cloud).flush(workingDir)
        assertEquals(
            listOf("write:blocks/a.cbor.enc", "write:blocks/b.cbor.enc", "write:$MANIFEST_FILENAME"),
            cloud.writeOrder,
        )
    }

    @Test
    fun `flush deletes a cloud orphan after copying, and only after`() {
        writeWorking(MANIFEST_FILENAME, byteArrayOf(9))
        val cloud = FakeCloudFolderPort(mapOf("blocks/old.cbor.enc" to byteArrayOf(7)))
        val report = VaultMirror(cloud).flush(workingDir)
        assertEquals(listOf("blocks/old.cbor.enc"), report.deleted)
        assertFalse(cloud.snapshot().containsKey("blocks/old.cbor.enc"))
        val lastWrite = cloud.writeOrder.indexOfLast { it.startsWith("write:") }
        val theDelete = cloud.writeOrder.indexOf("delete:blocks/old.cbor.enc")
        assertTrue(lastWrite < theDelete, "delete must follow all writes: ${cloud.writeOrder}")
    }

    @Test
    fun `flush is a no-op when both sides already agree`() {
        writeWorking("blocks/a.cbor.enc", byteArrayOf(1))
        val cloud = FakeCloudFolderPort()
        VaultMirror(cloud).flush(workingDir)   // first flush populates the cloud
        cloud.writeOrder.clear()
        val report = VaultMirror(cloud).flush(workingDir)
        assertEquals(emptyList<String>(), report.copied)
        assertEquals(emptyList<String>(), report.deleted)
        assertTrue(cloud.writeOrder.isEmpty())
    }

    @Test
    fun `materialize pulls cloud files into the working dir, subdirs included`() {
        val cloud = FakeCloudFolderPort(
            mapOf(
                MANIFEST_FILENAME to byteArrayOf(9),
                "blocks/a.cbor.enc" to byteArrayOf(1, 2),
            ),
        )
        val report = VaultMirror(cloud).materialize(workingDir)
        assertTrue(report.copied.containsAll(listOf(MANIFEST_FILENAME, "blocks/a.cbor.enc")))
        assertArrayEquals(byteArrayOf(1, 2), File(workingDir, "blocks/a.cbor.enc").readBytes())
        assertArrayEquals(byteArrayOf(9), File(workingDir, MANIFEST_FILENAME).readBytes())
    }

    @Test
    fun `materialize deletes a working file absent from the cloud`() {
        writeWorking("blocks/stale.cbor.enc", byteArrayOf(5))
        val cloud = FakeCloudFolderPort(mapOf(MANIFEST_FILENAME to byteArrayOf(9)))
        VaultMirror(cloud).materialize(workingDir)
        assertFalse(File(workingDir, "blocks/stale.cbor.enc").exists())
    }

    @Test
    fun `flush then materialize into a fresh working copy converges byte-for-byte`() {
        writeWorking(MANIFEST_FILENAME, byteArrayOf(9))
        writeWorking("blocks/a.cbor.enc", byteArrayOf(1, 2, 3))
        writeWorking("contacts/c.cbor.enc", byteArrayOf(4))
        val cloud = FakeCloudFolderPort()
        VaultMirror(cloud).flush(workingDir)

        val fresh = File(workingDir.parentFile, "fresh").also { it.mkdirs() }
        VaultMirror(cloud).materialize(fresh)
        assertArrayEquals(byteArrayOf(9), File(fresh, MANIFEST_FILENAME).readBytes())
        assertArrayEquals(byteArrayOf(1, 2, 3), File(fresh, "blocks/a.cbor.enc").readBytes())
        assertArrayEquals(byteArrayOf(4), File(fresh, "contacts/c.cbor.enc").readBytes())
    }

    @Test
    fun `a cloud failure during flush surfaces as VaultMirrorException`() {
        writeWorking("blocks/a.cbor.enc", byteArrayOf(1))
        val cloud = FakeCloudFolderPort().apply { failWith = "revoked" }
        val e = assertThrows(VaultMirrorException::class.java) { VaultMirror(cloud).flush(workingDir) }
        assertTrue(e.message!!.contains("flush failed"))
    }

    @Test
    fun `materialize over a missing working dir creates it from the cloud`() {
        val missing = File(workingDir, "not-yet")
        val cloud = FakeCloudFolderPort(mapOf("blocks/a.cbor.enc" to byteArrayOf(1)))
        VaultMirror(cloud).materialize(missing)
        assertArrayEquals(byteArrayOf(1), File(missing, "blocks/a.cbor.enc").readBytes())
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :vault-access:test --tests "org.secretary.mirror.VaultMirrorTest"`
Expected: FAIL — `VaultMirror`/`MirrorReport`/`VaultMirrorException` unresolved.

- [ ] **Step 3: Write minimal implementation**

`android/vault-access/src/main/kotlin/org/secretary/mirror/VaultMirror.kt`:
```kotlin
package org.secretary.mirror

import java.io.File
import java.io.IOException

/**
 * What a mirror pass did: the vault-relative paths it [copied] and [deleted] on the
 * destination side. `copied` is empty and `deleted` is empty exactly when both sides already
 * agreed. A later slice's UI uses this for the "saved / synced" indicator.
 */
data class MirrorReport(val copied: List<String>, val deleted: List<String>)

/**
 * Thrown when a mirror pass cannot complete — a working-copy I/O failure or an underlying
 * [CloudFolderException]. One typed boundary so the Slice-5 lifecycle caller folds a single
 * error. Mirrors `org.secretary.browse.DeviceUuidException`.
 */
class VaultMirrorException(message: String) : Exception(message)

/**
 * Mirrors a vault folder between a real-filesystem working copy and a path-less [cloud] folder
 * (the SAF working-copy shim). Stateless: each pass content-hashes both sides, diffs via
 * [planMirror], and executes the plan block-first. The local-sidecar flush optimization is a
 * Slice-5 concern; here correctness comes first, so flush re-reads the cloud to fingerprint it.
 *
 * The only platform dependency is [CloudFolderPort] (faked in host tests) plus `java.io.File`
 * for the working copy (a real temp dir in host tests) — the `DeviceUuid` precedent. Both
 * passes buffer each side's file contents in memory once and reuse them for execution (one read
 * per file); streaming for very large vaults is a future optimization, not needed for a
 * personal secrets vault.
 */
class VaultMirror(private val cloud: CloudFolderPort) {

    /** Pull cloud → working: bring [workingDir] into byte-identical agreement with [cloud]. */
    fun materialize(workingDir: File): MirrorReport = runPass("materialize") {
        val cloudFiles = readCloud()
        val workingFiles = readWorking(workingDir)
        val plan = planMirror(fingerprints(cloudFiles), fingerprints(workingFiles))
        execute(
            plan,
            source = cloudFiles,
            applyCopy = { path, bytes -> writeWorking(workingDir, path, bytes) },
            applyDelete = { path -> deleteWorking(workingDir, path) },
        )
    }

    /** Push working → cloud: bring [cloud] into agreement with [workingDir], block-first. */
    fun flush(workingDir: File): MirrorReport = runPass("flush") {
        val workingFiles = readWorking(workingDir)
        val cloudFiles = readCloud()
        val plan = planMirror(fingerprints(workingFiles), fingerprints(cloudFiles))
        execute(
            plan,
            source = workingFiles,
            applyCopy = { path, bytes -> cloud.write(path, bytes) },
            applyDelete = { path -> cloud.delete(path) },
        )
    }

    private inline fun runPass(label: String, block: () -> MirrorReport): MirrorReport = try {
        block()
    } catch (e: CloudFolderException) {
        throw VaultMirrorException("$label failed: ${e.message}")
    } catch (e: IOException) {
        throw VaultMirrorException("$label failed: ${e.message}")
    }

    private fun execute(
        plan: List<MirrorOp>,
        source: Map<String, ByteArray>,
        applyCopy: (String, ByteArray) -> Unit,
        applyDelete: (String) -> Unit,
    ): MirrorReport {
        val copied = mutableListOf<String>()
        val deleted = mutableListOf<String>()
        for (op in plan) when (op) {
            is MirrorOp.Copy -> {
                applyCopy(op.relativePath, source.getValue(op.relativePath))
                copied.add(op.relativePath)
            }
            is MirrorOp.Delete -> {
                applyDelete(op.relativePath)
                deleted.add(op.relativePath)
            }
        }
        return MirrorReport(copied, deleted)
    }

    private fun readCloud(): Map<String, ByteArray> = cloud.list().associateWith { cloud.read(it) }

    private fun fingerprints(files: Map<String, ByteArray>): Map<String, FileFingerprint> =
        files.mapValues { (_, bytes) -> FileFingerprint(bytes.size.toLong(), sha256Hex(bytes)) }

    private fun readWorking(workingDir: File): Map<String, ByteArray> {
        if (!workingDir.isDirectory) return emptyMap()
        val base = workingDir.toPath()
        return workingDir.walkTopDown()
            .filter { it.isFile }
            .associate { file ->
                base.relativize(file.toPath()).toString().replace(File.separatorChar, '/') to file.readBytes()
            }
    }

    private fun writeWorking(workingDir: File, relativePath: String, bytes: ByteArray) {
        val target = File(workingDir, relativePath)
        target.parentFile?.mkdirs()
        target.writeBytes(bytes)
    }

    private fun deleteWorking(workingDir: File, relativePath: String) {
        File(workingDir, relativePath).delete()
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :vault-access:test --tests "org.secretary.mirror.VaultMirrorTest"`
Expected: PASS (9 tests).

- [ ] **Step 5: Run the whole `:vault-access` host suite (no regressions)**

Run: `./gradlew :vault-access:test`
Expected: PASS — all prior suites plus the four new `org.secretary.mirror` suites.

- [ ] **Step 6: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/mirror/VaultMirror.kt \
        android/vault-access/src/test/kotlin/org/secretary/mirror/VaultMirrorTest.kt
git commit -m "feat(android): VaultMirror orchestrator (materialize/flush, block-first) (slice 3)"
```

---

### Task 5: `SafCloudFolderPort` real adapter + factory (`:kit`)

**Files:**
- Modify: `android/kit/build.gradle.kts` (add the `androidx.documentfile` dependency)
- Create: `android/kit/src/main/kotlin/org/secretary/mirror/SafCloudFolderPort.kt`
- Test: `android/kit/src/test/kotlin/org/secretary/mirror/SafCloudFolderPortTest.kt`

**Interfaces:**
- Consumes: `CloudFolderPort` / `CloudFolderException` (Task 3, via the `:vault-access` api dependency `:kit` already declares).
- Produces:
  - `class SafCloudFolderPort(listFiles: () -> List<String>, readFile: (String) -> ByteArray, writeFile: (String, ByteArray) -> Unit, deleteFile: (String) -> Unit) : CloudFolderPort` — seam-based, zero Android types in the class body, folds any non-`CloudFolderException` into `CloudFolderException`.
  - `fun safCloudFolderPort(context: Context, treeUri: String): CloudFolderPort` — the production factory (only Android-bound code; not host-tested).

- [ ] **Step 1: Add the SAF dependency**

In `android/kit/build.gradle.kts`, inside the `dependencies { … }` block, add alongside the other `implementation(...)` lines:
```kotlin
    // SAF tree traversal for SafCloudFolderPort (slice 3). 1.0.1 is the current stable release;
    // used only by the safCloudFolderPort factory — the seam-based class body holds no SAF types.
    implementation("androidx.documentfile:documentfile:1.0.1")
```

- [ ] **Step 2: Write the failing test**

`android/kit/src/test/kotlin/org/secretary/mirror/SafCloudFolderPortTest.kt`:
```kotlin
package org.secretary.mirror

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class SafCloudFolderPortTest {
    /** In-memory seams recording interactions, mirroring SafVaultLocationStoreTest.Fakes. */
    private class Fakes {
        val files = linkedMapOf<String, ByteArray>("blocks/a.cbor.enc" to byteArrayOf(1, 2))
        val events = mutableListOf<String>()
        var failNext: Boolean = false

        fun port(): SafCloudFolderPort = SafCloudFolderPort(
            listFiles = { maybeFail(); events.add("list"); files.keys.toList() },
            readFile = { path -> maybeFail(); events.add("read:$path"); files.getValue(path) },
            writeFile = { path, bytes -> maybeFail(); events.add("write:$path"); files[path] = bytes },
            deleteFile = { path -> maybeFail(); events.add("delete:$path"); files.remove(path); Unit },
        )

        private fun maybeFail() {
            if (failNext) throw IllegalStateException("provider boom")
        }
    }

    @Test
    fun `list forwards to the seam`() {
        val f = Fakes()
        assertEquals(listOf("blocks/a.cbor.enc"), f.port().list())
        assertEquals(listOf("list"), f.events)
    }

    @Test
    fun `read forwards the path and returns the bytes`() {
        val f = Fakes()
        assertArrayEquals(byteArrayOf(1, 2), f.port().read("blocks/a.cbor.enc"))
        assertEquals(listOf("read:blocks/a.cbor.enc"), f.events)
    }

    @Test
    fun `write forwards the path and bytes`() {
        val f = Fakes()
        f.port().write("manifest.cbor.enc", byteArrayOf(9))
        assertEquals(listOf("write:manifest.cbor.enc"), f.events)
        assertArrayEquals(byteArrayOf(9), f.files.getValue("manifest.cbor.enc"))
    }

    @Test
    fun `delete forwards the path`() {
        val f = Fakes()
        f.port().delete("blocks/a.cbor.enc")
        assertEquals(listOf("delete:blocks/a.cbor.enc"), f.events)
    }

    @Test
    fun `a seam failure is folded into CloudFolderException`() {
        val f = Fakes().apply { failNext = true }
        val e = assertThrows(CloudFolderException::class.java) { f.port().list() }
        assertEquals(true, e.message!!.contains("SAF list failed"))
    }

    @Test
    fun `a seam-thrown CloudFolderException passes through unwrapped`() {
        val port = SafCloudFolderPort(
            listFiles = { throw CloudFolderException("already typed") },
            readFile = { throw CloudFolderException("x") },
            writeFile = { _, _ -> },
            deleteFile = { },
        )
        val e = assertThrows(CloudFolderException::class.java) { port.list() }
        assertEquals("already typed", e.message)
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `./gradlew :kit:testDebugUnitTest --tests "org.secretary.mirror.SafCloudFolderPortTest"`
Expected: FAIL — `SafCloudFolderPort` unresolved.

- [ ] **Step 4: Write minimal implementation**

`android/kit/src/main/kotlin/org/secretary/mirror/SafCloudFolderPort.kt`:
```kotlin
package org.secretary.mirror

import android.content.Context
import android.net.Uri
import androidx.documentfile.provider.DocumentFile

/**
 * The real [CloudFolderPort] over a SAF `content://` tree (a cloud-drive folder). Kotlin sibling
 * of `org.secretary.browse.SafVaultLocationStore`: the class body holds NO Android types — it is
 * constructed from four function seams, so the delegation + error-folding to [CloudFolderException]
 * is host-tested with fakes. All DocumentFile / ContentResolver traversal lives only in the
 * [safCloudFolderPort] factory (exercised on-device / by Slice 6's instrumented E2E).
 *
 * Any seam exception that is not already a [CloudFolderException] is folded into one, so a caller
 * (`VaultMirror`) sees a single typed boundary regardless of which provider error occurred.
 */
class SafCloudFolderPort(
    private val listFiles: () -> List<String>,
    private val readFile: (String) -> ByteArray,
    private val writeFile: (String, ByteArray) -> Unit,
    private val deleteFile: (String) -> Unit,
) : CloudFolderPort {
    override fun list(): List<String> = fold("list") { listFiles() }
    override fun read(relativePath: String): ByteArray = fold("read $relativePath") { readFile(relativePath) }
    override fun write(relativePath: String, bytes: ByteArray) = fold("write $relativePath") { writeFile(relativePath, bytes) }
    override fun delete(relativePath: String) = fold("delete $relativePath") { deleteFile(relativePath) }

    private inline fun <T> fold(op: String, block: () -> T): T = try {
        block()
    } catch (e: CloudFolderException) {
        throw e
    } catch (e: Exception) {
        throw CloudFolderException("SAF $op failed: ${e.message}")
    }
}

/**
 * Production factory wiring the real SAF DocumentFile traversal from [context] + [treeUri]. The
 * only Android-bound code in this file; not host-tested (covered on-device / by Slice 6). Paths
 * are vault-relative POSIX (`"blocks/<uuid>.cbor.enc"`); the factory splits on `/` to resolve or
 * create each path segment under the picked tree.
 */
fun safCloudFolderPort(context: Context, treeUri: String): CloudFolderPort {
    val resolver = context.contentResolver

    fun root(): DocumentFile =
        DocumentFile.fromTreeUri(context, Uri.parse(treeUri))
            ?: throw CloudFolderException("cannot resolve SAF tree: $treeUri")

    fun resolve(relativePath: String): DocumentFile? {
        var node: DocumentFile? = root()
        for (segment in relativePath.split('/')) {
            node = node?.findFile(segment) ?: return null
        }
        return node
    }

    fun walk(dir: DocumentFile, prefix: String, out: MutableList<String>) {
        for (child in dir.listFiles()) {
            val name = child.name ?: continue
            val path = if (prefix.isEmpty()) name else "$prefix/$name"
            if (child.isDirectory) walk(child, path, out) else out.add(path)
        }
    }

    fun findOrCreate(relativePath: String): DocumentFile {
        val segments = relativePath.split('/')
        var node = root()
        for (dirName in segments.dropLast(1)) {
            node = node.findFile(dirName)?.takeIf { it.isDirectory }
                ?: node.createDirectory(dirName)
                ?: throw CloudFolderException("cannot create directory $dirName in $relativePath")
        }
        val fileName = segments.last()
        // Overwrite means delete-then-create: SAF has no truncate-open primitive.
        node.findFile(fileName)?.delete()
        return node.createFile("application/octet-stream", fileName)
            ?: throw CloudFolderException("cannot create file $relativePath")
    }

    return SafCloudFolderPort(
        listFiles = { mutableListOf<String>().also { walk(root(), "", it) } },
        readFile = { path ->
            val doc = resolve(path) ?: throw CloudFolderException("no such file: $path")
            resolver.openInputStream(doc.uri)?.use { it.readBytes() }
                ?: throw CloudFolderException("cannot open $path for read")
        },
        writeFile = { path, bytes ->
            val doc = findOrCreate(path)
            resolver.openOutputStream(doc.uri, "wt")?.use { it.write(bytes) }
                ?: throw CloudFolderException("cannot open $path for write")
        },
        deleteFile = { path -> resolve(path)?.delete() },
    )
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `./gradlew :kit:testDebugUnitTest --tests "org.secretary.mirror.SafCloudFolderPortTest"`
Expected: PASS (6 tests).

- [ ] **Step 6: Commit**

```bash
git add android/kit/build.gradle.kts \
        android/kit/src/main/kotlin/org/secretary/mirror/SafCloudFolderPort.kt \
        android/kit/src/test/kotlin/org/secretary/mirror/SafCloudFolderPortTest.kt
git commit -m "feat(android): SafCloudFolderPort SAF adapter + factory (slice 3)"
```

---

### Task 6: Whole-branch verification gate

**Files:** none (verification only).

- [ ] **Step 1: Run the full host suites for both modules**

Run (from `android/`):
```bash
./gradlew :vault-access:test :kit:testDebugUnitTest
```
Expected: BUILD SUCCESSFUL — all suites green, including the new `org.secretary.mirror` suites in both modules and every pre-existing suite (no regressions).

- [ ] **Step 2: Confirm scope discipline**

Verify no file outside `android/` changed and no core/FFI/spec/format file was touched:
```bash
git diff --name-only main...HEAD
```
Expected: only paths under `android/vault-access/src/.../mirror/`, `android/kit/src/.../mirror/`, `android/kit/build.gradle.kts`, and this plan doc. No `core/`, `ffi/`, `docs/*.md` (spec), or `*.json` KAT changes.

---

## Self-Review

**Spec coverage (design component 3 = `CloudFolderPort` + pure `VaultMirrorPlanner` + `VaultMirror`, SAF impl in `:kit`):**
- `CloudFolderPort` (list/read/write/delete over SAF) → Task 3 (interface) + Task 5 (SAF impl). ✓
- Pure `VaultMirrorPlanner` (which files to move, **block-first ordering**, **changed-file detection**) → Task 2 (planner ordering) + Task 1 (`sha256Hex`, the change-detection signal). ✓
- `VaultMirror` orchestrator (materialize → operate-elsewhere → flush) → Task 4. ✓
- "Fully host-testable with zero Android dependencies" for the planner → Tasks 1–4 are all `:vault-access` host tests with a fake port + temp dir. ✓
- "All SAF specifics behind `CloudFolderPort`" → only Task 5's factory holds DocumentFile. ✓
- Stateless content-hash diff; sidecar deferred to Slice 5 → stated in Global Constraints + Task 4 KDoc. ✓
- Slice boundary (no lifecycle wiring / view models / screens / instrumented tests) → Global Constraints + Task 6 scope check. ✓

**Placeholder scan:** No TBD/TODO; every code step shows complete code; every test step shows the actual assertions. ✓

**Type consistency:** `FileFingerprint(size: Long, sha256: String)`, `MirrorOp.Copy/Delete(relativePath)`, `planMirror(source, dest)`, `MANIFEST_FILENAME`, `CloudFolderPort.{list,read,write,delete}`, `CloudFolderException(message)`, `MirrorReport(copied, deleted)`, `VaultMirrorException(message)`, `VaultMirror(cloud).{materialize,flush}(workingDir)`, `FakeCloudFolderPort(initial).{snapshot,writeOrder,failWith}`, `sha256Hex(bytes)`, `SafCloudFolderPort(listFiles, readFile, writeFile, deleteFile)`, `safCloudFolderPort(context, treeUri)` — names/signatures are used identically across Tasks 1–6. ✓
