# RetryingCloudFolderPort Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden Android cloud-vault flush/materialize against eventually-consistent SAF providers (Google Drive, #330) with a bounded retry-with-backoff + read-back-verify `CloudFolderPort` decorator.

**Architecture:** A new `RetryingCloudFolderPort` decorator wraps any `CloudFolderPort` (delegating to an inner port) and adds bounded retry on `CloudFolderException` plus, for `write`, a post-write read-back byte-equality verify. `VaultMirror`, the `CloudFolderPort` interface, and the `safCloudFolderPort` factory are unchanged; production wiring is a one-line wrap in `openCloudTarget`.

**Tech Stack:** Kotlin (`kotlin("jvm")` module `:vault-access`), JUnit 5 (Jupiter) host tests, Gradle.

## Global Constraints

- Kotlin/Android only. NO change to on-disk format, crypto spec, `conformance.py`, conflict KATs, observable bytes, or the FFI surface. Conformance stays 27/27 (not re-run by this slice; unaffected).
- No magic numbers — every retry/backoff value is a named field or companion constant.
- `RetryingCloudFolderPort` must stay host-testable: no `android.util.Log`, no Android types in the class body. The `sleep` and `onRetry` seams default to `Thread::sleep` / `{}`.
- Files under 500 lines; one concept per file.
- TDD: failing test first, minimal impl, frequent commits. Pure functions in reusable modules.
- Worktree: `.worktrees/android-cloud-saf-retry-330`, branch `feature/android-cloud-saf-retry-330`. All gradle commands run from `android/` inside that worktree.
- Test framework is JUnit 5 — import `org.junit.jupiter.api.*` (matching `VaultMirrorTest`).

---

### Task 1: `RetryPolicy` + `backoffDelayMs` (pure backoff schedule)

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/mirror/RetryingCloudFolderPort.kt` (this task adds only the policy + pure fn; the class lands in Task 3)
- Test: `android/vault-access/src/test/kotlin/org/secretary/mirror/BackoffDelayTest.kt`

**Interfaces:**
- Produces:
  - `data class RetryPolicy(val maxAttempts: Int, val baseDelayMs: Long, val maxDelayMs: Long)` with `companion object { val CLOUD_DEFAULT = RetryPolicy(maxAttempts = 5, baseDelayMs = 250, maxDelayMs = 2000) }`
  - `fun backoffDelayMs(attempt: Int, policy: RetryPolicy): Long` — 1-based `attempt`, exponential `baseDelayMs * 2^(attempt-1)` capped at `maxDelayMs`.

- [ ] **Step 1: Write the failing test**

Create `android/vault-access/src/test/kotlin/org/secretary/mirror/BackoffDelayTest.kt`:

```kotlin
package org.secretary.mirror

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class BackoffDelayTest {
    private val policy = RetryPolicy.CLOUD_DEFAULT // base=250, max=2000, attempts=5

    @Test
    fun `backoff is exponential then capped at maxDelay`() {
        assertEquals(250L, backoffDelayMs(1, policy))   // 250 * 2^0
        assertEquals(500L, backoffDelayMs(2, policy))   // 250 * 2^1
        assertEquals(1000L, backoffDelayMs(3, policy))  // 250 * 2^2
        assertEquals(2000L, backoffDelayMs(4, policy))  // 250 * 2^3 = 2000, == cap
        assertEquals(2000L, backoffDelayMs(5, policy))  // 250 * 2^4 = 4000, capped to 2000
        assertEquals(2000L, backoffDelayMs(99, policy))  // large attempt stays capped, no overflow
    }

    @Test
    fun `CLOUD_DEFAULT has the documented values`() {
        assertEquals(5, RetryPolicy.CLOUD_DEFAULT.maxAttempts)
        assertEquals(250L, RetryPolicy.CLOUD_DEFAULT.baseDelayMs)
        assertEquals(2000L, RetryPolicy.CLOUD_DEFAULT.maxDelayMs)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ./gradlew :vault-access:test --tests "org.secretary.mirror.BackoffDelayTest"`
Expected: FAIL — `RetryPolicy` / `backoffDelayMs` unresolved (compile error).

- [ ] **Step 3: Write minimal implementation**

Create `android/vault-access/src/main/kotlin/org/secretary/mirror/RetryingCloudFolderPort.kt`:

```kotlin
package org.secretary.mirror

/**
 * Backoff schedule + attempt budget for [RetryingCloudFolderPort]. No magic numbers: every value
 * is a named field; [CLOUD_DEFAULT] is the production policy tuned for Google Drive's
 * eventually-consistent SAF DocumentsProvider (#330).
 */
data class RetryPolicy(val maxAttempts: Int, val baseDelayMs: Long, val maxDelayMs: Long) {
    init {
        require(maxAttempts >= 1) { "maxAttempts must be >= 1" }
        require(baseDelayMs >= 0) { "baseDelayMs must be >= 0" }
        require(maxDelayMs >= baseDelayMs) { "maxDelayMs must be >= baseDelayMs" }
    }

    companion object {
        /** 250 / 500 / 1000 / 2000 / (2000) ms across 5 attempts — worst case ~5.75 s of waiting. */
        val CLOUD_DEFAULT = RetryPolicy(maxAttempts = 5, baseDelayMs = 250, maxDelayMs = 2000)
    }
}

/** Cap the left-shift exponent so a large [attempt] cannot overflow the Long shift; any value at or
 *  past this point already exceeds [RetryPolicy.maxDelayMs] and is clamped to it. */
private const val MAX_BACKOFF_SHIFT = 32

/**
 * Pure: the delay in ms to wait AFTER a 1-based [attempt] fails, before the next attempt. Exponential
 * `baseDelayMs * 2^(attempt-1)`, clamped to [RetryPolicy.maxDelayMs].
 */
fun backoffDelayMs(attempt: Int, policy: RetryPolicy): Long {
    require(attempt >= 1) { "attempt is 1-based, got $attempt" }
    val shift = (attempt - 1).coerceAtMost(MAX_BACKOFF_SHIFT)
    val raw = policy.baseDelayMs shl shift
    return raw.coerceAtMost(policy.maxDelayMs)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd android && ./gradlew :vault-access:test --tests "org.secretary.mirror.BackoffDelayTest"`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
cd android && git add vault-access/src/main/kotlin/org/secretary/mirror/RetryingCloudFolderPort.kt \
  vault-access/src/test/kotlin/org/secretary/mirror/BackoffDelayTest.kt
git commit -m "feat(android): RetryPolicy + pure backoffDelayMs schedule (#330)"
```

---

### Task 2: Extend `FakeCloudFolderPort` with count-scoped fault injection

**Files:**
- Modify: `android/vault-access/src/test/kotlin/org/secretary/mirror/FakeCloudFolderPort.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/mirror/FakeCloudFolderPortTest.kt` (extend)

**Interfaces:**
- Consumes: existing `FakeCloudFolderPort` (path→bytes map, `writeOrder`, `failWith`).
- Produces (added to `FakeCloudFolderPort`, all additive — existing fields unchanged):
  - `val callLog: MutableList<String>` — every op as `"list"`, `"read:<path>"`, `"write:<path>"`, `"delete:<path>"`.
  - `var failNextN: Int` (default 0) — the next N ops throw `CloudFolderException`, then succeed.
  - `var readMissNextN: Int` (default 0) — the next N `read` calls report the file missing (throw `CloudFolderException`) even when it is present, simulating write-succeeded-but-not-yet-visible.

- [ ] **Step 1: Write the failing test**

Append to `android/vault-access/src/test/kotlin/org/secretary/mirror/FakeCloudFolderPortTest.kt` (add the imports below if not already present at the top of that file):

```kotlin
// add to the existing imports if missing:
//   import org.junit.jupiter.api.Assertions.assertEquals
//   import org.junit.jupiter.api.Assertions.assertThrows
//   import org.junit.jupiter.api.Assertions.assertTrue
//   import org.junit.jupiter.api.Test

    @Test
    fun `failNextN throws for the next N ops then succeeds`() {
        val fake = FakeCloudFolderPort()
        fake.failNextN = 2
        assertThrows(CloudFolderException::class.java) { fake.list() }
        assertThrows(CloudFolderException::class.java) { fake.list() }
        assertEquals(emptyList<String>(), fake.list()) // 3rd op succeeds
    }

    @Test
    fun `readMissNextN reports a present file as missing for N reads then returns it`() {
        val fake = FakeCloudFolderPort(mapOf("blocks/a.cbor.enc" to byteArrayOf(7)))
        fake.readMissNextN = 1
        assertThrows(CloudFolderException::class.java) { fake.read("blocks/a.cbor.enc") }
        assertEquals(7, fake.read("blocks/a.cbor.enc")[0]) // 2nd read sees it
    }

    @Test
    fun `callLog records every op in order`() {
        val fake = FakeCloudFolderPort()
        fake.write("blocks/a.cbor.enc", byteArrayOf(1))
        fake.read("blocks/a.cbor.enc")
        fake.delete("blocks/a.cbor.enc")
        fake.list()
        assertTrue(
            fake.callLog == listOf("write:blocks/a.cbor.enc", "read:blocks/a.cbor.enc", "delete:blocks/a.cbor.enc", "list"),
            "callLog was ${fake.callLog}",
        )
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ./gradlew :vault-access:test --tests "org.secretary.mirror.FakeCloudFolderPortTest"`
Expected: FAIL — `failNextN` / `readMissNextN` / `callLog` unresolved.

- [ ] **Step 3: Write minimal implementation**

Replace the body of `android/vault-access/src/test/kotlin/org/secretary/mirror/FakeCloudFolderPort.kt` with (preserves `writeOrder` + `failWith` exactly; adds `callLog`, `failNextN`, `readMissNextN`, and a labeled guard):

```kotlin
package org.secretary.mirror

/**
 * In-memory [CloudFolderPort] for host tests: a path→bytes map with call recording and fault
 * injection. [writeOrder] records mutating calls (`write:`/`delete:`) for block-first ordering
 * assertions; [callLog] records EVERY op (incl. reads/lists) for retry/verify assertions.
 *
 * Fault injection: [failWith] makes every op throw (revoked-permission path); [failNextN] makes the
 * next N ops throw then succeed (transient eventual-consistency failure); [readMissNextN] makes the
 * next N reads report a present file as missing (write-succeeded-but-not-yet-visible).
 */
class FakeCloudFolderPort(initial: Map<String, ByteArray> = emptyMap()) : CloudFolderPort {
    private val files = LinkedHashMap<String, ByteArray>().apply { putAll(initial) }
    val writeOrder = mutableListOf<String>()
    val callLog = mutableListOf<String>()
    var failWith: String? = null
    var failNextN: Int = 0
    var readMissNextN: Int = 0

    fun snapshot(): Map<String, ByteArray> = files.toMap()

    override fun list(): List<String> = guard("list") { files.keys.toList() }

    override fun read(relativePath: String): ByteArray = guard("read:$relativePath") {
        if (readMissNextN > 0) {
            readMissNextN--
            throw CloudFolderException("no such file: $relativePath")
        }
        files[relativePath]?.copyOf() ?: throw CloudFolderException("no such file: $relativePath")
    }

    override fun write(relativePath: String, bytes: ByteArray) = guard("write:$relativePath") {
        writeOrder.add("write:$relativePath")
        files[relativePath] = bytes.copyOf()
    }

    override fun delete(relativePath: String) = guard("delete:$relativePath") {
        writeOrder.add("delete:$relativePath")
        files.remove(relativePath)
        Unit
    }

    private fun <T> guard(opLabel: String, block: () -> T): T {
        callLog.add(opLabel)
        failWith?.let { throw CloudFolderException(it) }
        if (failNextN > 0) {
            failNextN--
            throw CloudFolderException("injected transient failure ($opLabel)")
        }
        return block()
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd android && ./gradlew :vault-access:test --tests "org.secretary.mirror.FakeCloudFolderPortTest"`
Expected: PASS (all existing + 3 new tests). The whole `:vault-access:test` must also stay green (existing `VaultMirrorTest` uses `writeOrder`/`failWith` unchanged):
Run: `cd android && ./gradlew :vault-access:test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd android && git add vault-access/src/test/kotlin/org/secretary/mirror/FakeCloudFolderPort.kt \
  vault-access/src/test/kotlin/org/secretary/mirror/FakeCloudFolderPortTest.kt
git commit -m "test(android): count-scoped fault injection in FakeCloudFolderPort (#330)"
```

---

### Task 3: `RetryingCloudFolderPort.write` — retry + read-back verify

**Files:**
- Modify: `android/vault-access/src/main/kotlin/org/secretary/mirror/RetryingCloudFolderPort.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/mirror/RetryingCloudFolderPortTest.kt`

**Interfaces:**
- Consumes: `RetryPolicy`, `backoffDelayMs` (Task 1); `FakeCloudFolderPort` with `failNextN`/`readMissNextN`/`callLog` (Task 2); `CloudFolderPort`, `CloudFolderException`.
- Produces:
  - `class RetryingCloudFolderPort(inner: CloudFolderPort, policy: RetryPolicy = RetryPolicy.CLOUD_DEFAULT, sleep: (Long) -> Unit = Thread::sleep, onRetry: (String) -> Unit = {}) : CloudFolderPort`
  - `write` overrides with retry + read-back verify (this task). `list`/`read`/`delete` arrive in Task 4 — until then they are stubbed by `inner` delegation so the class compiles (see Step 3).

- [ ] **Step 1: Write the failing test**

Create `android/vault-access/src/test/kotlin/org/secretary/mirror/RetryingCloudFolderPortTest.kt`:

```kotlin
package org.secretary.mirror

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class RetryingCloudFolderPortTest {
    // Fast, deterministic policy: 3 attempts, 10ms base, 40ms cap — no real waiting (sleep is faked).
    private val fastPolicy = RetryPolicy(maxAttempts = 3, baseDelayMs = 10, maxDelayMs = 40)

    private class Recorder {
        val sleeps = mutableListOf<Long>()
        val retries = mutableListOf<String>()
    }

    private fun port(inner: CloudFolderPort, rec: Recorder, policy: RetryPolicy = fastPolicy) =
        RetryingCloudFolderPort(inner, policy, sleep = { rec.sleeps.add(it) }, onRetry = { rec.retries.add(it) })

    @Test
    fun `write succeeds after transient throws, sleeping the backoff schedule`() {
        val fake = FakeCloudFolderPort()
        fake.failNextN = 2 // first two write attempts throw, third succeeds
        val rec = Recorder()
        port(fake, rec).write("blocks/a.cbor.enc", byteArrayOf(1, 2, 3))
        assertArrayEquals(byteArrayOf(1, 2, 3), fake.snapshot().getValue("blocks/a.cbor.enc"))
        assertEquals(listOf(10L, 20L), rec.sleeps) // backoff after attempt 1 and 2
        assertEquals(2, rec.retries.size)
    }

    @Test
    fun `write retries when the read-back is not yet visible`() {
        val fake = FakeCloudFolderPort()
        fake.readMissNextN = 1 // write lands, but first read-back reports missing
        val rec = Recorder()
        port(fake, rec).write("blocks/a.cbor.enc", byteArrayOf(9))
        assertArrayEquals(byteArrayOf(9), fake.snapshot().getValue("blocks/a.cbor.enc"))
        assertEquals(listOf(10L), rec.sleeps) // one backoff before the visible read-back
    }

    @Test
    fun `write that never verifies throws after maxAttempts with bounded sleeps`() {
        val fake = FakeCloudFolderPort()
        fake.failWith = "provider down" // every op throws, forever
        val rec = Recorder()
        assertThrows(CloudFolderException::class.java) {
            port(fake, rec).write("blocks/a.cbor.enc", byteArrayOf(1))
        }
        assertEquals(listOf(10L, 20L), rec.sleeps) // 3 attempts → 2 backoffs, then rethrow
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ./gradlew :vault-access:test --tests "org.secretary.mirror.RetryingCloudFolderPortTest"`
Expected: FAIL — `RetryingCloudFolderPort` unresolved.

- [ ] **Step 3: Write minimal implementation**

Append to `android/vault-access/src/main/kotlin/org/secretary/mirror/RetryingCloudFolderPort.kt`:

```kotlin
/**
 * A [CloudFolderPort] decorator that absorbs eventually-consistent SAF providers (e.g. Google Drive,
 * #330) with bounded retry-with-backoff on [CloudFolderException] and, for [write], a post-write
 * read-back byte-equality verify. Host-testable: the class body holds no Android types; [sleep] and
 * [onRetry] are seams (default `Thread::sleep` / no-op, so there is no `android.util.Log` dependency).
 *
 * Only [CloudFolderException] is retried — the typed boundary the inner SAF port folds every provider
 * error into. A permanent failure (revoked permission) also folds to it; retrying simply burns the
 * bounded budget and rethrows, which is acceptable given the provider is eventually-consistent.
 */
class RetryingCloudFolderPort(
    private val inner: CloudFolderPort,
    private val policy: RetryPolicy = RetryPolicy.CLOUD_DEFAULT,
    private val sleep: (Long) -> Unit = Thread::sleep,
    private val onRetry: (String) -> Unit = {},
) : CloudFolderPort {

    // list/read/delete gain retry in Task 4; for now delegate so the class compiles.
    override fun list(): List<String> = inner.list()
    override fun read(relativePath: String): ByteArray = inner.read(relativePath)
    override fun delete(relativePath: String) = inner.delete(relativePath)

    /**
     * Write then read-back-verify. One attempt = `inner.write` + `inner.read` + byte-equality. A
     * throw, an invisible read-back, or a mismatch retries the whole attempt (re-write is an
     * idempotent overwrite). Plain `contentEquals` — these are ciphertext blocks, not secrets that
     * need a constant-time compare.
     */
    override fun write(relativePath: String, bytes: ByteArray) {
        retrying("write $relativePath") {
            inner.write(relativePath, bytes)
            val readBack = inner.read(relativePath)
            if (!readBack.contentEquals(bytes)) {
                throw CloudFolderException("read-back mismatch: $relativePath")
            }
        }
    }

    private inline fun <T> retrying(op: String, block: () -> T): T {
        var attempt = 1
        while (true) {
            try {
                return block()
            } catch (e: CloudFolderException) {
                if (attempt >= policy.maxAttempts) {
                    throw CloudFolderException("$op failed after ${policy.maxAttempts} attempts: ${e.message}")
                }
                onRetry("$op attempt $attempt/${policy.maxAttempts} failed: ${e.message}")
                sleep(backoffDelayMs(attempt, policy))
                attempt++
            }
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd android && ./gradlew :vault-access:test --tests "org.secretary.mirror.RetryingCloudFolderPortTest"`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
cd android && git add vault-access/src/main/kotlin/org/secretary/mirror/RetryingCloudFolderPort.kt \
  vault-access/src/test/kotlin/org/secretary/mirror/RetryingCloudFolderPortTest.kt
git commit -m "feat(android): RetryingCloudFolderPort write retry + read-back verify (#330)"
```

---

### Task 4: `RetryingCloudFolderPort` — retry `list`/`read`/`delete` (delete has no read-back)

**Files:**
- Modify: `android/vault-access/src/main/kotlin/org/secretary/mirror/RetryingCloudFolderPort.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/mirror/RetryingCloudFolderPortTest.kt`

**Interfaces:**
- Consumes: everything from Task 3.
- Produces: `list`/`read`/`delete` now route through `retrying(...)`; `delete` issues NO read-back.

- [ ] **Step 1: Write the failing test**

Append these methods to `RetryingCloudFolderPortTest`:

```kotlin
    @Test
    fun `read retries transient failures then returns the bytes`() {
        val fake = FakeCloudFolderPort(mapOf("manifest.cbor.enc" to byteArrayOf(5)))
        fake.failNextN = 2
        val rec = Recorder()
        assertArrayEquals(byteArrayOf(5), port(fake, rec).read("manifest.cbor.enc"))
        assertEquals(listOf(10L, 20L), rec.sleeps)
    }

    @Test
    fun `list retries transient failures then returns the listing`() {
        val fake = FakeCloudFolderPort(mapOf("manifest.cbor.enc" to byteArrayOf(5)))
        fake.failNextN = 1
        val rec = Recorder()
        assertEquals(listOf("manifest.cbor.enc"), port(fake, rec).list())
        assertEquals(listOf(10L), rec.sleeps)
    }

    @Test
    fun `read rethrows after exhausting attempts on a permanent failure`() {
        val fake = FakeCloudFolderPort()
        fake.failWith = "revoked"
        val rec = Recorder()
        assertThrows(CloudFolderException::class.java) { port(fake, rec).read("x") }
        assertEquals(listOf(10L, 20L), rec.sleeps)
    }

    @Test
    fun `delete retries on exception but issues no read-back`() {
        val fake = FakeCloudFolderPort(mapOf("blocks/old.cbor.enc" to byteArrayOf(7)))
        fake.failNextN = 1
        val rec = Recorder()
        port(fake, rec).delete("blocks/old.cbor.enc")
        assertEquals(listOf(10L), rec.sleeps)
        assertEquals(0, fake.callLog.count { it.startsWith("read:") }, "delete must not read-back: ${fake.callLog}")
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ./gradlew :vault-access:test --tests "org.secretary.mirror.RetryingCloudFolderPortTest"`
Expected: FAIL — `read`/`list`/`delete` currently delegate without retry, so the `failNextN` cases throw instead of retrying (no sleeps recorded).

- [ ] **Step 3: Write minimal implementation**

In `RetryingCloudFolderPort.kt`, replace the three delegating overrides with retrying ones:

```kotlin
    override fun list(): List<String> = retrying("list") { inner.list() }

    override fun read(relativePath: String): ByteArray =
        retrying("read $relativePath") { inner.read(relativePath) }

    // No read-back verify: delete is idempotent, and a stale-still-present file is re-deleted on the
    // next flush pass — it never corrupts the vault — whereas a lost write loses data. Verifying
    // absence would mean treating a "no such file" read as the success signal, uglier than the
    // negligible risk it removes.
    override fun delete(relativePath: String) =
        retrying("delete $relativePath") { inner.delete(relativePath) }
```

(Delete the three earlier `// list/read/delete gain retry in Task 4` delegating lines.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd android && ./gradlew :vault-access:test --tests "org.secretary.mirror.RetryingCloudFolderPortTest"`
Expected: PASS (7 tests total).

- [ ] **Step 5: Commit**

```bash
cd android && git add vault-access/src/main/kotlin/org/secretary/mirror/RetryingCloudFolderPort.kt \
  vault-access/src/test/kotlin/org/secretary/mirror/RetryingCloudFolderPortTest.kt
git commit -m "feat(android): retry list/read/delete (delete has no read-back) (#330)"
```

---

### Task 5: Integration — `VaultMirror.flush` over a flaky retrying port

**Files:**
- Test: `android/vault-access/src/test/kotlin/org/secretary/mirror/RetryingCloudFolderPortTest.kt`

**Interfaces:**
- Consumes: `VaultMirror` (`flush(workingDir)`), `RetryingCloudFolderPort`, `FakeCloudFolderPort`.

- [ ] **Step 1: Write the failing test**

Append to `RetryingCloudFolderPortTest` (and add `import org.junit.jupiter.api.io.TempDir` and `import java.io.File` to the top of the file):

```kotlin
    @org.junit.jupiter.api.Test
    fun `VaultMirror flush over a flaky retrying port pushes every file`(@TempDir workingDir: File) {
        File(workingDir, "manifest.cbor.enc").writeBytes(byteArrayOf(9))
        File(workingDir, "blocks").mkdirs()
        File(workingDir, "blocks/a.cbor.enc").writeBytes(byteArrayOf(1, 2))
        val fake = FakeCloudFolderPort()
        fake.failNextN = 3 // a few transient hiccups spread across list/write ops
        val rec = Recorder()
        val mirror = VaultMirror(port(fake, rec))
        val report = mirror.flush(workingDir)
        assertEquals(2, report.copied.size, "both files pushed")
        assertArrayEquals(byteArrayOf(9), fake.snapshot().getValue("manifest.cbor.enc"))
        assertArrayEquals(byteArrayOf(1, 2), fake.snapshot().getValue("blocks/a.cbor.enc"))
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ./gradlew :vault-access:test --tests "org.secretary.mirror.RetryingCloudFolderPortTest"`
Expected: PASS already if Tasks 3-4 are complete (the retry seam composes with `VaultMirror`). If it FAILS, the retry budget (`fastPolicy.maxAttempts = 3`) was exhausted by a single op — confirm `failNextN = 3` is spread across ≥3 distinct ops (list + 2 writes); the manifest+1 block flush issues `list` then two `write`s (each write also reads-back), so 3 injected failures land on 3 separate ops and each is absorbed within the 3-attempt budget. This step is the explicit composition check.

- [ ] **Step 3: (no new impl)**

This task adds only an integration test proving the decorator composes with `VaultMirror`. No production code changes.

- [ ] **Step 4: Run the full module suite**

Run: `cd android && ./gradlew :vault-access:test`
Expected: PASS (all mirror tests including the new integration test).

- [ ] **Step 5: Commit**

```bash
cd android && git add vault-access/src/test/kotlin/org/secretary/mirror/RetryingCloudFolderPortTest.kt
git commit -m "test(android): VaultMirror.flush composes with RetryingCloudFolderPort (#330)"
```

---

### Task 6: Wire into production `openCloudTarget` + docs

**Files:**
- Modify: `android/app/src/main/kotlin/org/secretary/app/CloudVaultOpen.kt:211`
- Modify: `android/README.md`

**Interfaces:**
- Consumes: `RetryingCloudFolderPort` (Task 3-4), `safCloudFolderPort` (existing), `Log`/`TAG` (existing in `CloudVaultOpen.kt`).

- [ ] **Step 1: Wire the decorator into the production mirror**

In `android/app/src/main/kotlin/org/secretary/app/CloudVaultOpen.kt`, add the import alongside the other `org.secretary.mirror.*` imports:

```kotlin
import org.secretary.mirror.RetryingCloudFolderPort
```

Then change the `mirror` construction (currently at line ~211):

```kotlin
    val mirror = VaultMirrorWorkingCopy(VaultMirror(safCloudFolderPort(context, location.treeUri)), target.workingDir)
```

to wrap the SAF port in the retrying decorator, surfacing retries to logcat (the app layer may use `Log`; the decorator itself stays log-free):

```kotlin
    val mirror = VaultMirrorWorkingCopy(
        VaultMirror(
            RetryingCloudFolderPort(
                safCloudFolderPort(context, location.treeUri),
                onRetry = { Log.i(TAG, it) },
            ),
        ),
        target.workingDir,
    )
```

- [ ] **Step 2: Verify the app compiles (host gate)**

Run: `cd android && ./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 3: Add the supported-providers doc note**

Append to `android/README.md`:

```markdown

## Cloud vault storage (SAF providers)

A cloud vault lives in a folder the user picks through the Android system file picker (Storage
Access Framework). Any provider that exposes a `DocumentsProvider` works, but consistency guarantees
vary:

- **Supported / tested:** the on-device test provider and local document trees — strongly consistent.
- **Best-effort (eventually-consistent):** Google Drive and similar cloud providers cache directory
  listings and defer writes, so a create/sync can fail on the first attempt and succeed on retry.
  `RetryingCloudFolderPort` (vault-access) wraps the SAF port with bounded retry-with-backoff plus a
  read-back verify on every write, which makes these providers usable at the cost of a slower first
  write. See [#330](https://github.com/hherb/secretary/issues/330).

A native provider SDK path (e.g. Dropbox OAuth) — strongly consistent, but pulling a third-party SDK
into the secrets process — is tracked separately as an additive `CloudFolderPort` implementation in
[#334](https://github.com/hherb/secretary/issues/334).
```

- [ ] **Step 4: Run the full host gate**

Run:
```bash
cd android && ./gradlew :vault-access:test :kit:testDebugUnitTest :app:testDebugUnitTest \
  :app:compileDebugKotlin :app:compileDebugAndroidTestKotlin
```
Expected: all green.

- [ ] **Step 5: Commit**

```bash
cd android && git add app/src/main/kotlin/org/secretary/app/CloudVaultOpen.kt README.md
git commit -m "feat(android): wire RetryingCloudFolderPort into cloud open + document SAF providers (#330)"
```

---

## Self-Review notes

- **Spec coverage:** decorator (Tasks 3-4), `RetryPolicy`/`backoffDelayMs` no-magic-numbers (Task 1), per-op behavior incl. delete-no-verify (Task 4), flaky-fake fault injection (Task 2), all listed tests (Tasks 1-5), production wiring + docs (Task 6). The spec's "out of scope" (no `looksLikeVault`, no native SDK, no format/FFI change) is respected — no task touches those.
- **Type consistency:** `RetryPolicy(maxAttempts, baseDelayMs, maxDelayMs)`, `backoffDelayMs(attempt, policy)`, `RetryingCloudFolderPort(inner, policy, sleep, onRetry)`, `FakeCloudFolderPort.failNextN/readMissNextN/callLog` are used identically across tasks.
- **On-device:** optional RedMagic Google-Drive validation is not a gate (host tests with the flaky fake prove the behavior). If run, it is a manual post-merge check, not a plan task.
