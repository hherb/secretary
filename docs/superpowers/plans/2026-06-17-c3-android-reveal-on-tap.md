# C.3 Android slice 8 — reveal-on-tap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add per-field reveal-on-tap to the Android browse screen — tap a field to expose its plaintext via the FFI `expose_text`/`expose_bytes`, with 30s auto-hide, tap-to-hide, and lock-on-background — mirroring the proven iOS reveal architecture.

**Architecture:** Evolve slice 7's metadata-only browse so each `RecordSummaryView` carries `RevealableField`s whose `reveal` lambda captures a retained `FieldHandle`. `:vault-access` (pure) gains reveal value-types + reveal/hide/hideAll on `VaultBrowseModel`; `:kit`'s `UniffiVaultSession` retains open `BlockReadOutput`s and wires the real expose closures; `:browse-ui` adds reveal UI + auto-hide; `:app` is unchanged (its `ON_STOP` lock already wipes the session).

**Tech Stack:** Kotlin, coroutines (1.8.0 strict pin), Jetpack Compose (compose-bom 2025.05.00), JUnit5 (host), JUnit4 + Compose UI test (instrumented), uniffi-generated `uniffi.secretary.*` bindings.

## Global Constraints

- **No `core/` / `ffi/` / `ios/` / on-disk-format change.** Both guardrail greps must be empty:
  - `git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)'`
  - `git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'`
- **No magic numbers.** `RevealPolicy.autoHideSeconds = 30`; `MILLIS_PER_SECOND = 1000L` — named constants only.
- **Single secret-pull boundary.** The ONLY `expose_text`/`expose_bytes` call sites in the codebase must be inside the `RevealableField.reveal` lambda in `:kit`. A reviewer confirms this.
- **Mirror iOS exactly** for hide policy (30s auto-hide, per-field tap-hide, lock-on-background = full session wipe; no hide-on-`ON_PAUSE`).
- **`:vault-access` host tests are JUnit5** (`useJUnitPlatform`); `:kit` host tests JUnit5; `:browse-ui` host tests JUnit5; instrumented tests JUnit4 on the arm64 emulator with the real `.so`.
- **Conventions:** `:vault-access` package `org.secretary.browse`; `:kit` browse adapter package `org.secretary.browse`; `:browse-ui` package `org.secretary.browse.ui`. `:browse-ui` depends only on `:vault-access` (never `:kit`).
- **TDD, frequent commits.** Each task: failing test → run-fail → implement → run-pass → commit. FFI-boundary code that cannot be host-tested (opaque `Record`/`FieldHandle`) is proven by the on-device smoke (Task 8); its pure helpers are still TDD'd.
- **Build dir discipline:** all gradle commands run from `<worktree>/android`. The worktree is `.worktrees/c3-android-reveal-on-tap`.

**Golden-vault known values** (for Task 8, from `core/tests/data/golden_vault_001_inputs.json`):
- Password: `correct horse battery staple`
- Sole block uuidHex: `112233445566778899aabbccddeeff00`, name "Personal logins"
- Record uuidHex: `33445566778899aabbccddeeff001122`, type `login`
- Text field `username` → `owner@example.com`; text field `password` → `hunter2`

---

### Task 1: Reveal value types + RevealPolicy (`:vault-access`)

Purely additive — introduces the new types the rest of the slice builds on. The project stays green.

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/Reveal.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/RevealTest.kt`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `sealed interface RevealedValue { data class Text(val value: String); class Bytes(val value: ByteArray) }`
  - `enum class FieldKind { Text, Bytes }`
  - `class RevealableField(val name: String, val kind: FieldKind, val reveal: () -> RevealedValue)`
  - `object RevealPolicy { const val autoHideSeconds: Long = 30 }`

- [ ] **Step 1: Write the failing test**

`android/vault-access/src/test/kotlin/org/secretary/browse/RevealTest.kt`:
```kotlin
package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RevealTest {
    @Test
    fun `RevealPolicy auto-hide is a named 30 second constant`() {
        assertEquals(30L, RevealPolicy.autoHideSeconds)
    }

    @Test
    fun `RevealedValue Text uses value equality`() {
        assertEquals(RevealedValue.Text("hunter2"), RevealedValue.Text("hunter2"))
        assertNotEquals(RevealedValue.Text("hunter2"), RevealedValue.Text("other"))
    }

    @Test
    fun `RevealedValue Bytes compares by content not reference`() {
        val a = RevealedValue.Bytes(byteArrayOf(1, 2, 3))
        val b = RevealedValue.Bytes(byteArrayOf(1, 2, 3))
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
        assertNotEquals(a, RevealedValue.Bytes(byteArrayOf(1, 2, 4)))
    }

    @Test
    fun `RevealableField calls its reveal lambda on demand only`() {
        var calls = 0
        val field = RevealableField("password", FieldKind.Text) {
            calls++
            RevealedValue.Text("hunter2")
        }
        assertEquals(0, calls)                       // not eager
        assertEquals(RevealedValue.Text("hunter2"), field.reveal())
        assertEquals(1, calls)
        assertEquals(FieldKind.Text, field.kind)
        assertTrue(field.name == "password")
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.RevealTest'`
Expected: FAIL — `Reveal.kt` types unresolved (compilation error).

- [ ] **Step 3: Write minimal implementation**

`android/vault-access/src/main/kotlin/org/secretary/browse/Reveal.kt`:
```kotlin
package org.secretary.browse

/**
 * A revealed (decrypted) field value. Holds plaintext — callers must drop it promptly (see
 * [VaultBrowseModel], which clears it on hide / reload / lock). Mirror of iOS `RevealedValue`.
 *
 * [Bytes] defines structural equality via `contentEquals`: a `data class` over a [ByteArray] gives
 * referential equals/hashCode (Kotlin caveat), which would break test assertions and dedup.
 */
sealed interface RevealedValue {
    data class Text(val value: String) : RevealedValue

    class Bytes(val value: ByteArray) : RevealedValue {
        override fun equals(other: Any?): Boolean =
            this === other || (other is Bytes && value.contentEquals(other.value))

        override fun hashCode(): Int = value.contentHashCode()
    }
}

/** Whether a field's payload is text or raw bytes. Mirror of iOS `FieldView.Kind`. */
enum class FieldKind { Text, Bytes }

/**
 * One field of a record. [name] and [kind] are non-secret metadata; [reveal] materializes the
 * plaintext ON DEMAND only — the real adapter wires it to the FFI `expose_text`/`expose_bytes`, so
 * plaintext is never eagerly decrypted. NOT a data class (it holds a closure). Mirror of iOS
 * `FieldView`.
 */
class RevealableField(
    val name: String,
    val kind: FieldKind,
    val reveal: () -> RevealedValue,
)

/**
 * Policy constants for revealing secret field values. Auto-hide is driven by the Compose layer
 * (`BrowseScreen` attaches a `LaunchedEffect` that delays this interval then calls the view model's
 * `hide`). A named constant — never a magic number in the view. Mirror of iOS `RevealPolicy`.
 */
object RevealPolicy {
    /** How long a revealed value stays visible before the UI auto-hides it. */
    const val autoHideSeconds: Long = 30
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.RevealTest'`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/browse/Reveal.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/RevealTest.kt
git commit -m "feat(android): reveal value types + RevealPolicy in :vault-access"
```

---

### Task 2: Evolve `RecordSummaryView` + wire the `:kit` reveal closures

Replace `RecordSummaryView`'s stored `fieldNames: List<String>` with `fields: List<RevealableField>` (computed `fieldNames` kept for render helpers), and repoint every construction site so the project compiles green. The `:kit` adapter gains the **real secret-pull boundary**: retain each `BlockReadOutput`, build one `RevealableField` per field whose `reveal` calls `expose_*` on demand, and wipe all retained blocks before manifest/identity.

This is the single security-critical task — its review gate verifies: (a) the only `expose_*` call sites are inside the reveal lambda, (b) `wipe()` order is blocks → manifest → identity, (c) an in-range `null` from `recordAt`/`fieldAt` surfaces as `CorruptVault`, never a silent drop.

**Files:**
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/BrowseModels.kt`
- Modify: `android/vault-access/src/test/kotlin/org/secretary/browse/BrowseModelsTest.kt`
- Modify: `android/vault-access/src/test/kotlin/org/secretary/browse/FakeVaultBrowse.kt`
- Modify: `android/vault-access/src/test/kotlin/org/secretary/browse/VaultBrowseModelTest.kt`
- Create: `android/kit/src/main/kotlin/org/secretary/browse/FieldKindMapping.kt`
- Modify: `android/kit/src/main/kotlin/org/secretary/browse/UniffiVaultOpenPort.kt`
- Create: `android/kit/src/test/kotlin/org/secretary/browse/FieldKindMappingTest.kt`
- Modify: `android/browse-ui/src/test/kotlin/org/secretary/browse/FakeVaultSession.kt`
- Modify: `android/browse-ui/src/test/kotlin/org/secretary/browse/ui/VaultBrowseViewModelTest.kt`
- Modify: `android/browse-ui/src/test/kotlin/org/secretary/browse/ui/BrowseRenderHelpersTest.kt`

**Interfaces:**
- Consumes: `RevealableField`, `FieldKind`, `RevealedValue` (Task 1).
- Produces:
  - `data class RecordSummaryView(uuidHex, type, tags, createdAtMs, lastModMs, tombstone, fields: List<RevealableField>) { val fieldNames: List<String> get() = fields.map { it.name } }`
  - `:kit` free fn `fieldKindOf(isText: Boolean): FieldKind`
  - test helper `fun textField(name: String, value: String): RevealableField` (added in each test source that builds records)

- [ ] **Step 1: Write the failing tests**

First the pure `:kit` helper test — `android/kit/src/test/kotlin/org/secretary/browse/FieldKindMappingTest.kt`:
```kotlin
package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class FieldKindMappingTest {
    @Test
    fun `isText true maps to Text kind`() {
        assertEquals(FieldKind.Text, fieldKindOf(isText = true))
    }

    @Test
    fun `isText false maps to Bytes kind`() {
        assertEquals(FieldKind.Bytes, fieldKindOf(isText = false))
    }
}
```

Then update `BrowseModelsTest.kt` — replace the `record summary` test to use `fields` and assert the computed `fieldNames`:
```kotlin
    @Test
    fun `record summary carries metadata and derives field names from fields`() {
        val rec = RecordSummaryView(
            uuidHex = "deadbeef",
            type = "login",
            tags = listOf("personal"),
            createdAtMs = 10u,
            lastModMs = 20u,
            tombstone = false,
            fields = listOf(
                RevealableField("username", FieldKind.Text) { RevealedValue.Text("u") },
                RevealableField("password", FieldKind.Text) { RevealedValue.Text("p") },
            ),
        )
        assertEquals("login", rec.type)
        assertEquals(listOf("username", "password"), rec.fieldNames)   // computed
        assertTrue(rec.tags.contains("personal"))
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd android && ./gradlew :vault-access:test :kit:testDebugUnitTest`
Expected: FAIL — `fieldKindOf` unresolved; `RecordSummaryView(... fields = ...)` does not compile (constructor still takes `fieldNames`).

- [ ] **Step 3: Evolve `RecordSummaryView`**

In `android/vault-access/src/main/kotlin/org/secretary/browse/BrowseModels.kt`, replace the `RecordSummaryView` declaration:
```kotlin
/**
 * View of one record. Metadata (type/tags/timestamps/tombstone) is non-secret. Each [RevealableField]
 * carries the field NAME (metadata) plus an on-demand `reveal` lambda — plaintext is materialized
 * only when the user taps (slice 8). [fieldNames] is a computed convenience over [fields] so render
 * helpers stay unchanged. Mirror of iOS `RecordView` (whose `fields` carry the reveal closures).
 *
 * Stays a data class: a reload returns the SAME RevealableField instances from the fake, so
 * structural equality over [fields] (referential on each closure-bearing field) still holds in tests.
 */
data class RecordSummaryView(
    val uuidHex: String,
    val type: String,
    val tags: List<String>,
    val createdAtMs: ULong,
    val lastModMs: ULong,
    val tombstone: Boolean,
    val fields: List<RevealableField>,
) {
    /** Field names in iteration order — metadata only (derived from [fields]). */
    val fieldNames: List<String> get() = fields.map { it.name }
}
```

- [ ] **Step 4: Add the `:kit` `fieldKindOf` helper + wire reveal closures**

Create `android/kit/src/main/kotlin/org/secretary/browse/FieldKindMapping.kt`:
```kotlin
package org.secretary.browse

/** Pure map from the FFI `FieldHandle.isText()` flag to the domain [FieldKind]. */
fun fieldKindOf(isText: Boolean): FieldKind = if (isText) FieldKind.Text else FieldKind.Bytes
```

In `android/kit/src/main/kotlin/org/secretary/browse/UniffiVaultOpenPort.kt`:

1. Add imports:
```kotlin
import uniffi.secretary.BlockReadOutput
import uniffi.secretary.FieldHandle
```
2. In `UniffiVaultSession`, add a retained-blocks field and STOP closing the block in `readBlock`:
```kotlin
    /** Decrypted blocks retained so the per-field reveal closures (which capture a FieldHandle)
     *  stay valid until wipe(). Mirror of iOS UniffiVaultSession.openBlocks. */
    private val openBlocks: MutableList<BlockReadOutput> = mutableListOf()

    override suspend fun readBlock(blockUuid: ByteArray, includeDeleted: Boolean): List<RecordSummaryView> =
        withContext(ioDispatcher) {
            mapErrors {
                val block = ffiReadBlock(identity, manifest, blockUuid, includeDeleted)
                openBlocks += block   // retained (NO .use{}) — reveal closures depend on it
                val count = block.recordCount().toInt()
                (0 until count).map { i ->
                    val rec = block.recordAt(i.toULong())
                        ?: throw VaultBrowseError.CorruptVault("recordAt($i) returned null on an open block")
                    toRecordView(rec)
                }
            }
        }
```
3. Replace `toRecordSummaryView` with `toRecordView` (builds reveal closures):
```kotlin
    /** Map one decrypted [Record] handle to a view whose fields reveal plaintext ON DEMAND.
     *  The ONLY place expose_text/expose_bytes is called (inside each field's reveal lambda). */
    private fun toRecordView(record: Record): RecordSummaryView {
        val fieldCount = record.fieldCount().toInt()
        val fields = (0 until fieldCount).map { j ->
            val handle = record.fieldAt(j.toULong())
                ?: throw VaultBrowseError.CorruptVault("fieldAt($j) returned null on an open record")
            buildRevealableField(handle)
        }
        return RecordSummaryView(
            uuidHex = hexOfBytes(record.recordUuid()),
            type = record.recordType(),
            tags = record.tags(),
            createdAtMs = record.createdAtMs(),
            lastModMs = record.lastModMs(),
            tombstone = record.tombstone(),
            fields = fields,
        )
    }

    /** The secret-pull boundary: captures [handle]; calls expose_* only when reveal() is invoked. */
    private fun buildRevealableField(handle: FieldHandle): RevealableField {
        val kind = fieldKindOf(handle.isText())
        return RevealableField(name = handle.name(), kind = kind) {
            when (kind) {
                FieldKind.Text -> RevealedValue.Text(
                    handle.exposeText() ?: throw VaultBrowseError.CorruptVault("text field could not be exposed"))
                FieldKind.Bytes -> RevealedValue.Bytes(
                    handle.exposeBytes() ?: throw VaultBrowseError.CorruptVault("bytes field could not be exposed"))
            }
        }
    }
```
4. Update `wipe()` to close retained blocks first (delete the old `toRecordSummaryView` free function at the bottom of the file):
```kotlin
    override fun wipe() {
        // Order mirrors iOS: blocks (cascade zeroize to records + fields) → manifest → identity.
        openBlocks.forEach { it.wipe() }
        openBlocks.clear()
        manifest.wipe()
        identity.wipe()
    }
```
Remove the now-unused `import uniffi.secretary.readBlock as ffiReadBlock`? No — `ffiReadBlock` is still used. Keep the `Record` import; remove the old private `toRecordSummaryView(record: Record)` free function entirely (replaced by the method `toRecordView`).

- [ ] **Step 5: Repoint the remaining construction sites (keep the project green)**

In `android/vault-access/src/test/kotlin/org/secretary/browse/FakeVaultBrowse.kt`, add a top-level test helper and leave the `FakeVaultSession` API unchanged:
```kotlin
/** Build a text field whose reveal returns a canned value (host tests only). */
fun textField(name: String, value: String): RevealableField =
    RevealableField(name, FieldKind.Text) { RevealedValue.Text(value) }
```
In `VaultBrowseModelTest.kt`, change the `recs` fixture:
```kotlin
    private val recs = listOf(
        RecordSummaryView("aa", "login", listOf("p"), 1u, 2u, false, listOf(textField("username", "u"))),
    )
```
In `android/browse-ui/src/test/kotlin/org/secretary/browse/FakeVaultSession.kt`, add the same `textField` helper (browse-ui test source can't see vault-access test source):
```kotlin
fun textField(name: String, value: String): RevealableField =
    RevealableField(name, FieldKind.Text) { RevealedValue.Text(value) }
```
In `VaultBrowseViewModelTest.kt`, change the `recs` fixture the same way:
```kotlin
    private val recs = listOf(
        RecordSummaryView("aa", "login", listOf("p"), 1u, 2u, false, listOf(textField("username", "u"))),
    )
```
In `BrowseRenderHelpersTest.kt`, change the `rec` builder's last argument:
```kotlin
    private fun rec(type: String, tags: List<String>, tombstone: Boolean = false) =
        RecordSummaryView("aa", type, tags, 1u, 2u, tombstone, listOf(textField("username", "u")))
```
Add to `BrowseRenderHelpersTest.kt` imports: `import org.secretary.browse.FieldKind`, `import org.secretary.browse.RevealableField`, `import org.secretary.browse.RevealedValue`, and define a private `textField` helper at file scope (browse-ui.ui package), OR reuse the one in the test `org.secretary.browse` package via import. Simplest: define a private helper in this file:
```kotlin
private fun textField(name: String, value: String) =
    RevealableField(name, FieldKind.Text) { RevealedValue.Text(value) }
```

- [ ] **Step 6: Run the full host suite to verify green**

Run: `cd android && ./gradlew :vault-access:test :kit:testDebugUnitTest :browse-ui:test`
Expected: PASS — `FieldKindMappingTest` (2), `RevealTest` (4), updated `BrowseModelsTest`, `VaultBrowseModelTest`, `VaultBrowseViewModelTest`, `BrowseRenderHelpersTest` all green; `:kit` compiles with the retained-blocks adapter.

- [ ] **Step 7: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/browse/BrowseModels.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/ \
        android/kit/src/main/kotlin/org/secretary/browse/ \
        android/kit/src/test/kotlin/org/secretary/browse/FieldKindMappingTest.kt \
        android/browse-ui/src/test/kotlin/org/secretary/browse/
git commit -m "feat(android): RecordSummaryView carries RevealableField; :kit retains blocks + wires expose_* on demand"
```

---

### Task 3: `VaultBrowseModel` reveal / hide / hideAll (`:vault-access`)

The pure coordinator gains a `revealed` map and reveal/hide seams; `selectBlock`, `clearSelection`, and `lock` clear it first.

**Files:**
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseModel.kt`
- Modify: `android/vault-access/src/test/kotlin/org/secretary/browse/VaultBrowseModelTest.kt`

**Interfaces:**
- Consumes: `RecordSummaryView.fields`, `RevealableField`, `RevealedValue`, `VaultBrowseError`.
- Produces:
  - `val revealed: StateFlow<Map<String, RevealedValue>>`
  - `fun reveal(record: RecordSummaryView, field: RevealableField)`
  - `fun hide(recordUuidHex: String, fieldName: String)`
  - `fun hideAll()`
  - reveal key format `"<recordUuidHex>/<fieldName>"`

- [ ] **Step 1: Write the failing tests**

Append to `VaultBrowseModelTest.kt` (add imports `assertEquals`/`assertTrue` already present):
```kotlin
    private val pwField = textField("password", "hunter2")
    private val revealRecs = listOf(
        RecordSummaryView("33445566778899aabbccddeeff001122", "login", emptyList(), 1u, 2u, false, listOf(pwField)),
    )
    private fun revealModel(): VaultBrowseModel {
        val s = FakeVaultSession("abcd", listOf(block), mapOf(block.uuidHex to revealRecs))
        return VaultBrowseModel(s)
    }

    @Test
    fun `reveal materializes a field value into the revealed map`() = runTest {
        val model = revealModel()
        val rec = revealRecs.first()
        model.reveal(rec, pwField)
        assertEquals(
            RevealedValue.Text("hunter2"),
            model.revealed.value["${rec.uuidHex}/password"],
        )
    }

    @Test
    fun `hide removes exactly one revealed field`() = runTest {
        val model = revealModel()
        val rec = revealRecs.first()
        model.reveal(rec, pwField)
        model.hide(rec.uuidHex, "password")
        assertTrue(model.revealed.value.isEmpty())
    }

    @Test
    fun `hideAll clears every revealed field`() = runTest {
        val model = revealModel()
        val rec = revealRecs.first()
        model.reveal(rec, pwField)
        model.hideAll()
        assertTrue(model.revealed.value.isEmpty())
    }

    @Test
    fun `selectBlock clears any previously revealed value`() = runTest {
        val model = revealModel()
        val rec = revealRecs.first()
        model.reveal(rec, pwField)
        model.selectBlock(block)
        assertTrue(model.revealed.value.isEmpty())
    }

    @Test
    fun `lock clears revealed values as well as wiping`() = runTest {
        val model = revealModel()
        model.reveal(revealRecs.first(), pwField)
        model.lock()
        assertTrue(model.revealed.value.isEmpty())
    }

    @Test
    fun `a reveal lambda that throws routes to error and leaves revealed empty`() = runTest {
        val model = revealModel()
        val rec = revealRecs.first()
        val boom = RevealableField("password", FieldKind.Text) {
            throw VaultBrowseError.CorruptVault("expose failed")
        }
        model.reveal(rec, boom)
        assertTrue(model.error.value is VaultBrowseError.CorruptVault)
        assertTrue(model.revealed.value.isEmpty())
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.VaultBrowseModelTest'`
Expected: FAIL — `reveal`/`hide`/`hideAll`/`revealed` unresolved.

- [ ] **Step 3: Implement on `VaultBrowseModel`**

Add to `VaultBrowseModel.kt`:
```kotlin
    private val _revealed = MutableStateFlow<Map<String, RevealedValue>>(emptyMap())
    /** Currently-revealed plaintext, keyed "<recordUuidHex>/<fieldName>". Cleared on
     *  selectBlock / clearSelection / lock. Mirror of iOS VaultBrowseViewModel.revealed. */
    val revealed: StateFlow<Map<String, RevealedValue>> = _revealed.asStateFlow()

    /**
     * Composite reveal-map key. Collision-safe: [recordUuidHex] is always exactly 32 lowercase hex
     * chars (charset [0-9a-f]), so it can never contain the "/" separator nor alias another
     * (record, field) pair even though field names are arbitrary vault-supplied strings.
     */
    private fun revealKey(recordUuidHex: String, fieldName: String): String = "$recordUuidHex/$fieldName"

    /** Materialize one field's plaintext on explicit user action (invokes [RevealableField.reveal]). */
    fun reveal(record: RecordSummaryView, field: RevealableField) {
        try {
            _revealed.value = _revealed.value + (revealKey(record.uuidHex, field.name) to field.reveal())
        } catch (e: VaultBrowseError) {
            _error.value = e
        }
    }

    /** Drop one revealed field. */
    fun hide(recordUuidHex: String, fieldName: String) {
        _revealed.value = _revealed.value - revealKey(recordUuidHex, fieldName)
    }

    /** Drop all revealed plaintext (e.g. on backgrounding) without locking. */
    fun hideAll() {
        _revealed.value = emptyMap()
    }
```
Add `_revealed.value = emptyMap()` as the FIRST line of `selectBlock` (inside, before the try), of `clearSelection`, and of `lock`. (A reload/back/lock must never carry a stale reveal.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.VaultBrowseModelTest'`
Expected: PASS (all original + 6 new).

- [ ] **Step 5: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseModel.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/VaultBrowseModelTest.kt
git commit -m "feat(android): VaultBrowseModel reveal/hide/hideAll + clear-on-reload/lock"
```

---

### Task 4: `VaultBrowseViewModel` reveal forwarding (`:browse-ui`)

The thin Compose bridge re-exposes the `revealed` flow and forwards the reveal seams.

**Files:**
- Modify: `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/VaultBrowseViewModel.kt`
- Modify: `android/browse-ui/src/test/kotlin/org/secretary/browse/ui/VaultBrowseViewModelTest.kt`

**Interfaces:**
- Consumes: `VaultBrowseModel.revealed/reveal/hide/hideAll`.
- Produces:
  - `val revealed: StateFlow<Map<String, RevealedValue>>`
  - `fun reveal(record: RecordSummaryView, field: RevealableField)`
  - `fun hide(recordUuidHex: String, fieldName: String)`
  - `fun hideAll()`

- [ ] **Step 1: Write the failing tests**

Append to `VaultBrowseViewModelTest.kt`:
```kotlin
    @Test
    fun `reveal forwards to the model and publishes the revealed value`() = runTest {
        val pw = textField("password", "hunter2")
        val rec = RecordSummaryView("ab", "login", emptyList(), 1u, 2u, false, listOf(pw))
        val m = VaultBrowseModel(FakeVaultSession("abcd", listOf(block), mapOf(block.uuidHex to listOf(rec))))
        val vm = VaultBrowseViewModel(m)
        vm.reveal(rec, pw)
        assertEquals(RevealedValue.Text("hunter2"), vm.revealed.value["ab/password"])
    }

    @Test
    fun `hide and hideAll forward to the model`() = runTest {
        val pw = textField("password", "hunter2")
        val rec = RecordSummaryView("ab", "login", emptyList(), 1u, 2u, false, listOf(pw))
        val m = VaultBrowseModel(FakeVaultSession("abcd", listOf(block), mapOf(block.uuidHex to listOf(rec))))
        val vm = VaultBrowseViewModel(m)
        vm.reveal(rec, pw)
        vm.hide("ab", "password")
        assertTrue(vm.revealed.value.isEmpty())
        vm.reveal(rec, pw)
        vm.hideAll()
        assertTrue(vm.revealed.value.isEmpty())
    }
```
Add imports: `import org.junit.jupiter.api.Assertions.assertTrue`, `import org.secretary.browse.RevealedValue`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd android && ./gradlew :browse-ui:test --tests 'org.secretary.browse.ui.VaultBrowseViewModelTest'`
Expected: FAIL — `reveal`/`hide`/`hideAll`/`revealed` unresolved on the VM.

- [ ] **Step 3: Implement on `VaultBrowseViewModel`**

Add to `VaultBrowseViewModel.kt` (imports `RecordSummaryView`, `RevealableField`, `RevealedValue` from `org.secretary.browse`):
```kotlin
    val revealed: StateFlow<Map<String, RevealedValue>> = model.revealed

    /** Materialize one field's plaintext (user tap). */
    fun reveal(record: RecordSummaryView, field: RevealableField) = model.reveal(record, field)

    /** Hide one revealed field (user tap or auto-hide). */
    fun hide(recordUuidHex: String, fieldName: String) = model.hide(recordUuidHex, fieldName)

    /** Hide all revealed fields. */
    fun hideAll() = model.hideAll()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd android && ./gradlew :browse-ui:test --tests 'org.secretary.browse.ui.VaultBrowseViewModelTest'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add android/browse-ui/src/main/kotlin/org/secretary/browse/ui/VaultBrowseViewModel.kt \
        android/browse-ui/src/test/kotlin/org/secretary/browse/ui/VaultBrowseViewModelTest.kt
git commit -m "feat(android): VaultBrowseViewModel reveal/hide/hideAll forwarding"
```

---

### Task 5: `revealedText` render helper (`:browse-ui`)

Pure formatter: text shown as-is, bytes as hex.

**Files:**
- Modify: `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/BrowseRenderHelpers.kt`
- Modify: `android/browse-ui/src/test/kotlin/org/secretary/browse/ui/BrowseRenderHelpersTest.kt`

**Interfaces:**
- Consumes: `RevealedValue`, `hexOfBytes`.
- Produces: `fun revealedText(value: RevealedValue): String`

- [ ] **Step 1: Write the failing test**

Append to `BrowseRenderHelpersTest.kt`:
```kotlin
    @Test
    fun `revealed text value is shown as-is`() {
        assertEquals("hunter2", revealedText(RevealedValue.Text("hunter2")))
    }

    @Test
    fun `revealed bytes value is shown as lowercase hex`() {
        assertEquals("00ff10", revealedText(RevealedValue.Bytes(byteArrayOf(0, 0xff.toByte(), 0x10))))
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ./gradlew :browse-ui:test --tests 'org.secretary.browse.ui.BrowseRenderHelpersTest'`
Expected: FAIL — `revealedText` unresolved.

- [ ] **Step 3: Implement**

Add to `BrowseRenderHelpers.kt` (import `org.secretary.browse.RevealedValue`, `org.secretary.browse.hexOfBytes`):
```kotlin
/** Human-readable form of a revealed value: text as-is, bytes as lowercase hex. */
fun revealedText(value: RevealedValue): String = when (value) {
    is RevealedValue.Text -> value.value
    is RevealedValue.Bytes -> hexOfBytes(value.value)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd android && ./gradlew :browse-ui:test --tests 'org.secretary.browse.ui.BrowseRenderHelpersTest'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add android/browse-ui/src/main/kotlin/org/secretary/browse/ui/BrowseRenderHelpers.kt \
        android/browse-ui/src/test/kotlin/org/secretary/browse/ui/BrowseRenderHelpersTest.kt
git commit -m "feat(android): revealedText render helper (text as-is, bytes as hex)"
```

---

### Task 6: `BrowseScreen` reveal UI + auto-hide (`:browse-ui`)

Each field row gets a reveal/hide toggle; a revealed value shows `revealedText` and starts a keyed auto-hide timer. `autoHideMillis` is an injectable screen param (named-constant default) so the Compose UI test (Task 7) injects a short value.

**Files:**
- Modify: `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/BrowseScreen.kt`

**Interfaces:**
- Consumes: `VaultBrowseViewModel.revealed/reveal/hide`, `RecordSummaryView.fields`, `revealedText`, `RevealPolicy.autoHideSeconds`.
- Produces: `@Composable fun BrowseScreen(viewModel, autoHideMillis: Long = RevealPolicy.autoHideSeconds * MILLIS_PER_SECOND)`; test tags `reveal-<recordUuidHex>-<fieldName>` and `value-<recordUuidHex>-<fieldName>`.

- [ ] **Step 1: Implement the reveal UI (no host test — covered by Task 7 instrumented test)**

This task has no host unit test (Compose rendering is verified by the instrumented test in Task 7). Edit `BrowseScreen.kt`:

1. Add a file-scope constant and imports:
```kotlin
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.platform.testTag
import kotlinx.coroutines.delay
import org.secretary.browse.RecordSummaryView
import org.secretary.browse.RevealPolicy

/** Milliseconds per second — auto-hide policy is expressed in seconds; Compose delay takes millis. */
private const val MILLIS_PER_SECOND: Long = 1000L
```
2. Change the signature:
```kotlin
@Composable
fun BrowseScreen(
    viewModel: VaultBrowseViewModel,
    autoHideMillis: Long = RevealPolicy.autoHideSeconds * MILLIS_PER_SECOND,
) {
```
3. Collect the revealed map near the other `collectAsStateWithLifecycle` calls:
```kotlin
    val revealed by viewModel.revealed.collectAsStateWithLifecycle()
```
4. Pass `revealed`, `autoHideMillis`, and the VM reveal/hide callbacks down to `RecordRow`, and replace `RecordRow` to render per-field rows. Replace the existing `RecordRow` composable with:
```kotlin
@Composable
private fun RecordRow(
    record: RecordSummaryView,
    revealed: Map<String, RevealedValue>,
    autoHideMillis: Long,
    onReveal: (RecordSummaryView, RevealableField) -> Unit,
    onHide: (String, String) -> Unit,
) {
    Column(modifier = Modifier.fillMaxWidth().padding(vertical = 10.dp)) {
        Text(recordTitle(record), style = MaterialTheme.typography.bodyLarge)
        record.fields.forEach { field ->
            val key = "${record.uuidHex}/${field.name}"
            val value = revealed[key]
            FieldRow(
                record = record,
                field = field,
                value = value,
                autoHideMillis = autoHideMillis,
                onReveal = onReveal,
                onHide = onHide,
            )
        }
    }
}

@Composable
private fun FieldRow(
    record: RecordSummaryView,
    field: RevealableField,
    value: RevealedValue?,
    autoHideMillis: Long,
    onReveal: (RecordSummaryView, RevealableField) -> Unit,
    onHide: (String, String) -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(field.name, style = MaterialTheme.typography.bodySmall)
            if (value != null) {
                Text(
                    text = revealedText(value),
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.testTag("value-${record.uuidHex}-${field.name}"),
                )
            }
        }
        TextButton(
            onClick = {
                if (value == null) onReveal(record, field) else onHide(record.uuidHex, field.name)
            },
            modifier = Modifier.testTag("reveal-${record.uuidHex}-${field.name}"),
        ) {
            Text(if (value == null) "Reveal" else "Hide")
        }
    }
    // Auto-hide: keyed on the revealed value's presence so re-revealing restarts the timer.
    if (value != null) {
        LaunchedEffect(record.uuidHex, field.name, value) {
            delay(autoHideMillis)
            onHide(record.uuidHex, field.name)
        }
    }
}
```
5. Update the `items(records.orEmpty(), ...)` call to pass the new args:
```kotlin
                items(records.orEmpty(), key = { it.uuidHex }) { r ->
                    RecordRow(
                        record = r,
                        revealed = revealed,
                        autoHideMillis = autoHideMillis,
                        onReveal = viewModel::reveal,
                        onHide = viewModel::hide,
                    )
                    HorizontalDivider()
                }
```
6. Add imports for `RevealableField` (`org.secretary.browse.RevealableField`) and `RevealedValue` (`org.secretary.browse.RevealedValue`).

- [ ] **Step 2: Verify it compiles + host suite still green**

Run: `cd android && ./gradlew :browse-ui:test`
Expected: PASS (no new host tests; existing ones unaffected; compilation succeeds).

- [ ] **Step 3: Commit**

```bash
git add android/browse-ui/src/main/kotlin/org/secretary/browse/ui/BrowseScreen.kt
git commit -m "feat(android): BrowseScreen per-field reveal/hide UI + keyed auto-hide"
```

---

### Task 7: Instrumented Compose UI test for reveal/hide/auto-hide (`:browse-ui`)

Drives `BrowseScreen` with a fake-backed ViewModel on the emulator. Proves the tap-gesture + auto-hide wiring.

**Files:**
- Create: `android/browse-ui/src/androidTest/kotlin/org/secretary/browse/ui/BrowseScreenRevealTest.kt`
- Create: `android/browse-ui/src/androidTest/kotlin/org/secretary/browse/FakeVaultSession.kt` (instrumented source set has no access to the unit-test `FakeVaultSession`)

**Interfaces:**
- Consumes: `BrowseScreen`, `VaultBrowseViewModel`, `VaultBrowseModel`, `FakeVaultSession`, test tags from Task 6.
- Produces: nothing downstream.

- [ ] **Step 1: Add an instrumented-source `FakeVaultSession` + reveal field helper**

`android/browse-ui/src/androidTest/kotlin/org/secretary/browse/FakeVaultSession.kt`:
```kotlin
package org.secretary.browse

/** Instrumented-source VaultSession double (androidTest can't see the unit-test fake). */
class FakeVaultSession(
    private val vaultUuidHex: String,
    private val blocks: List<BlockSummaryView>,
    private val recordsByBlockHex: Map<String, List<RecordSummaryView>> = emptyMap(),
) : VaultSession {
    var wiped: Boolean = false
        private set

    override fun vaultUuidHex(): String = vaultUuidHex
    override fun blockSummaries(): List<BlockSummaryView> = blocks
    override suspend fun readBlock(blockUuid: ByteArray, includeDeleted: Boolean): List<RecordSummaryView> =
        recordsByBlockHex[hexOfBytes(blockUuid)] ?: emptyList()
    override fun wipe() { wiped = true }
}

fun textField(name: String, value: String): RevealableField =
    RevealableField(name, FieldKind.Text) { RevealedValue.Text(value) }
```

- [ ] **Step 2: Write the Compose UI test**

`android/browse-ui/src/androidTest/kotlin/org/secretary/browse/ui/BrowseScreenRevealTest.kt`:
```kotlin
package org.secretary.browse.ui

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import org.junit.Rule
import org.junit.Test
import org.secretary.browse.BlockSummaryView
import org.secretary.browse.FakeVaultSession
import org.secretary.browse.RecordSummaryView
import org.secretary.browse.VaultBrowseModel
import org.secretary.browse.textField

class BrowseScreenRevealTest {
    @get:Rule val composeRule = createComposeRule()

    private val recUuid = "33445566778899aabbccddeeff001122"
    private val block = BlockSummaryView(ByteArray(16) { 0x4c }, "Logins", 1u, 2u)
    private val rec = RecordSummaryView(
        recUuid, "login", emptyList(), 1u, 2u, false, listOf(textField("password", "hunter2")),
    )

    private fun viewModel(): VaultBrowseViewModel {
        val session = FakeVaultSession("abcd", listOf(block), mapOf(block.uuidHex to listOf(rec)))
        return VaultBrowseViewModel(VaultBrowseModel(session))
    }

    private fun openBlock(vm: VaultBrowseViewModel, autoHideMillis: Long) {
        composeRule.setContent { BrowseScreen(viewModel = vm, autoHideMillis = autoHideMillis) }
        composeRule.runOnIdle { vm.loadBlocks() }
        composeRule.onNodeWithText("Logins").performClick()       // select the block
        composeRule.waitForIdle()
    }

    @Test
    fun tapReveal_showsValue_thenTapHide_removesIt() {
        val vm = viewModel()
        openBlock(vm, autoHideMillis = 60_000L)                   // long timer: won't auto-fire
        composeRule.onNodeWithTag("reveal-$recUuid-password").performClick()
        composeRule.onNodeWithTag("value-$recUuid-password").assertIsDisplayed()
        composeRule.onNodeWithTag("reveal-$recUuid-password").performClick()  // now "Hide"
        composeRule.onNodeWithTag("value-$recUuid-password").assertDoesNotExist()
    }

    @Test
    fun revealedValue_autoHidesAfterTheInterval() {
        val vm = viewModel()
        openBlock(vm, autoHideMillis = 300L)                      // short timer
        composeRule.onNodeWithTag("reveal-$recUuid-password").performClick()
        composeRule.onNodeWithTag("value-$recUuid-password").assertIsDisplayed()
        // The auto-hide LaunchedEffect fires after 300ms; waitUntil polls until the node is gone.
        composeRule.waitUntil(timeoutMillis = 5_000L) {
            composeRule.onAllNodesWithTag("value-$recUuid-password").fetchSemanticsNodes().isEmpty()
        }
    }
}
```
Add the imports used by the assertions: `import androidx.compose.ui.test.assertDoesNotExist`, `import androidx.compose.ui.test.onAllNodesWithTag`, `import androidx.compose.ui.test.onNodeWithText`.

- [ ] **Step 3: Run on the emulator (must be running)**

Run:
```bash
cd android && PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :browse-ui:connectedDebugAndroidTest
```
Expected: BUILD SUCCESSFUL — `BrowseScreenRevealTest` 2/2 on the arm64 emulator.

- [ ] **Step 4: Commit**

```bash
git add android/browse-ui/src/androidTest/
git commit -m "test(android): instrumented Compose UI test for reveal/hide/auto-hide"
```

---

### Task 8: On-device reveal smoke against the golden vault (`:app`)

Proves the real `expose_*` path end-to-end: open `golden_vault_001`, read its block, reveal the `password` field, assert the plaintext is `hunter2`.

**Files:**
- Modify: `android/app/src/androidTest/kotlin/org/secretary/app/OpenBrowseSmokeTest.kt`

**Interfaces:**
- Consumes: `uniffiVaultOpenPort`, `VaultBrowseModel.reveal/revealed`, `RevealedValue`, golden-vault known values (Global Constraints).
- Produces: nothing downstream.

- [ ] **Step 1: Add the reveal smoke test**

Append a test to `OpenBrowseSmokeTest.kt` (add imports `import org.secretary.browse.RevealedValue`):
```kotlin
    @Test
    fun reveal_passwordField_exposesKnownPlaintext() = runBlocking {
        val folder = AppVaultProvisioning.stageGoldenVault(context)
        val session = uniffiVaultOpenPort().openWithPassword(folder.path, goldenPassword.toByteArray())
        val model = VaultBrowseModel(session)
        model.loadBlocks()
        model.selectBlock(model.blocks.value.first())

        val record = model.selectedRecords.value!!.first { it.type == "login" }
        val password = record.fields.first { it.name == "password" }
        model.reveal(record, password)

        assertEquals(
            RevealedValue.Text("hunter2"),
            model.revealed.value["${record.uuidHex}/password"],
        )

        model.lock()
        assertTrue("lock clears revealed values", model.revealed.value.isEmpty())
    }
```
Add `import org.junit.Assert.assertEquals` to the file.

- [ ] **Step 2: Run on the emulator (must be running)**

Run:
```bash
cd android && PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :app:connectedDebugAndroidTest
```
Expected: BUILD SUCCESSFUL — `OpenBrowseSmokeTest` 3/3 (the 2 slice-7 cases + reveal) on the arm64 emulator.

- [ ] **Step 3: Commit**

```bash
git add android/app/src/androidTest/kotlin/org/secretary/app/OpenBrowseSmokeTest.kt
git commit -m "test(android): on-device reveal smoke — golden-vault password exposes hunter2"
```

---

## Final gauntlet (run before opening the PR)

```bash
cd android && ./gradlew :vault-access:test :kit:testDebugUnitTest :browse-ui:test :app:test
#   → BUILD SUCCESSFUL (host JUnit5)
cd android && PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :browse-ui:connectedDebugAndroidTest :app:connectedDebugAndroidTest
#   → BUILD SUCCESSFUL: BrowseScreenRevealTest 2/2 + OpenBrowseSmokeTest 3/3 on the arm64 emulator
# Guardrails (both empty):
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)'
git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'
```

Then update `README.md` + `ROADMAP.md` (Android C.3 slice 8 ✅ reveal-on-tap) and the handoff doc + retargeted `NEXT_SESSION.md` symlink, committed on the branch before the PR.

## Self-review notes (coverage check)

- **Spec §1 reveal value-types + RevealPolicy** → Task 1. **`RecordSummaryView` evolution** → Task 2.
- **Spec §1 reveal map + reveal/hide/hideAll + clear-on-reload/lock** → Task 3.
- **Spec §2 retain open blocks + reveal closures + corrupt-null + wipe order** → Task 2.
- **Spec §3 VM forwarding** → Task 4; **render helper** → Task 5; **BrowseScreen + auto-hide** → Task 6.
- **Spec §4 `:app` unchanged** → no task needed (verified by Task 8 lock-clears-revealed assertion).
- **Spec testing: host suites** → Tasks 1–5; **instrumented Compose UI** → Task 7; **on-device reveal smoke** → Task 8.
- **Single secret-pull boundary** → Task 2 (`buildRevealableField` is the only `expose_*` site); reviewer confirms.
- Type consistency: `fieldKindOf` (Task 2) ↔ used in Task 2 adapter; `revealKey` format `"$uuidHex/$name"` consistent across Tasks 3/4/6/8; `RevealedValue.Bytes` content-equality (Task 1) relied on by Tasks 5/7.
