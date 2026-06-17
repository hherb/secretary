# C.3 Android slice 10 — record editing/adding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the Android client a record **edit** and **add** path mirroring the iOS `RecordEditViewModel` form (text + bytes-as-hex fields, editable tags, kind picker, reveal-into-form on edit), built on slice 9's write infrastructure.

**Architecture:** Pure Android-layer projection of the existing `append_record`/`edit_record` FFI surface (already in the UDL + Rust bridge). A new nested pure `RecordEditModel` (host-tested in `:vault-access`) owns the form logic; `VaultBrowseModel` gains an `editing` flow selecting a third UI state on the existing hand-rolled `BrowseScreen` state machine. The `:kit` `UniffiVaultSession` gains the two real writers via the proven `write { dev, now -> … }` idiom.

**Tech Stack:** Kotlin, Gradle multi-module (`:vault-access` pure JUnit5 / `:kit` FFI / `:browse-ui` Compose / `:app`), Jetpack Compose, kotlinx-coroutines, uniffi-generated `uniffi.secretary` bindings.

## Global Constraints

- **No core/ffi/format change.** `append_record`/`edit_record`/`RecordContent`/`FieldInput`/`FieldInputValue` already exist in `ffi/secretary-ffi-uniffi/src/secretary.udl` and the Rust bridge (tested in `ffi/secretary-ffi-bridge/tests/edit.rs`). This slice touches only `android/` + docs.
- **Guardrail greps must stay empty** (run before final commit):
  - `git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)'` → empty
  - `git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'` → empty
- **Pure functions in reusable modules; no magic numbers; files under ~500 lines** (split proactively — one concept per file).
- **Secret hygiene:** the edit form holds revealed plaintext as `String` for the edit duration (accepted, scoped, matches iOS); released on cancel/commit/lock. `lock()` MUST clear `editing`.
- **Writes serialize under the existing `sessionLock` + `wiped`-first guard.** Fresh record UUID minted via `SecureRandom` in the `:kit` adapter, never the pure model. Device-uuid + `now_ms` resolved inside the session.
- **Failed write leaves the visible list intact** (re-read on success only).
- **No new `VaultBrowseError` arms** — validation errors are pure `InvalidArgument`; FFI errors reuse slice-9's `RecordNotFound`/`SaveCryptoFailure`/`CorruptVault`/`Failed`.
- **JUnit5 (jupiter)** for `:vault-access` and `:kit` host tests; backtick test-method names; `runTest` for suspend tests.
- **`kotlinx-coroutines` is exact-pinned** (`1.8.0`) — do not add caret ranges.
- **Tests use generated/runtime values, not hardcoded crypto** — record/field plaintext in tests is fine (non-crypto); never hardcode key/nonce bytes.

## File Structure

**Create:**
- `android/vault-access/src/main/kotlin/org/secretary/browse/RecordContentInput.kt` — pure input value types + `validate()`.
- `android/vault-access/src/main/kotlin/org/secretary/browse/RecordEditModel.kt` — `EditableField` + pure `RecordEditModel` (form state, load, commit).
- `android/vault-access/src/test/kotlin/org/secretary/browse/RecordContentInputTest.kt`
- `android/vault-access/src/test/kotlin/org/secretary/browse/HexFormatTest.kt`
- `android/vault-access/src/test/kotlin/org/secretary/browse/RecordEditModelTest.kt`
- `android/kit/src/main/kotlin/org/secretary/browse/RecordContentMapping.kt` — `toFfi(RecordContentInput): uniffi.secretary.RecordContent`.
- `android/kit/src/test/kotlin/org/secretary/browse/RecordContentMappingTest.kt`
- `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/RecordEditForm.kt` — the Compose edit form.
- `android/browse-ui/src/androidTest/kotlin/org/secretary/browse/ui/RecordEditFormTest.kt`

**Modify:**
- `android/vault-access/src/main/kotlin/org/secretary/browse/HexFormat.kt` — add `parseHexLenient`.
- `android/vault-access/src/main/kotlin/org/secretary/browse/VaultOpenPort.kt` — add `appendRecord`/`editRecord` to `VaultSession`.
- `android/vault-access/src/test/kotlin/org/secretary/browse/FakeVaultBrowse.kt` — implement the two new methods + audit lists.
- `android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseModel.kt` — `editing` flow + `startAdd`/`startEdit`/`cancelEdit`/`onEditCommitted`; `lock()` clears editing.
- `android/vault-access/src/test/kotlin/org/secretary/browse/VaultBrowseModelTest.kt` — editing-flow tests.
- `android/kit/src/main/kotlin/org/secretary/browse/UniffiVaultOpenPort.kt` — generic `write<T>`, `appendRecord`/`editRecord` impls, imports.
- `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/VaultBrowseViewModel.kt` — forward editing entry points.
- `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/BrowseScreen.kt` — third state + Add/edit affordances.
- `android/app/src/androidTest/kotlin/org/secretary/app/OpenBrowseSmokeTest.kt` — append + edit round-trip.
- `README.md`, `ROADMAP.md` — slice-10 ✅.

---

### Task 1: Pure input types + validation + lenient hex parse

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/RecordContentInput.kt`
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/HexFormat.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/RecordContentInputTest.kt`, `android/vault-access/src/test/kotlin/org/secretary/browse/HexFormatTest.kt`

**Interfaces:**
- Produces:
  - `sealed interface FieldContentValue { data class Text(val value: String); class Bytes(val value: ByteArray) }`
  - `data class FieldContentInput(val name: String, val value: FieldContentValue)`
  - `data class RecordContentInput(val recordType: String, val tags: List<String>, val fields: List<FieldContentInput>) { fun validate(): RecordContentInputError? }`
  - `sealed interface RecordContentInputError { data object EmptyFieldName; data class DuplicateFieldName(val name: String) }`
  - `fun parseHexLenient(s: String): ByteArray?` (in `HexFormat.kt`)
- Consumes: nothing (leaf task).

- [ ] **Step 1: Write the failing tests**

`android/vault-access/src/test/kotlin/org/secretary/browse/RecordContentInputTest.kt`:
```kotlin
package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class RecordContentInputTest {
    private fun text(name: String) = FieldContentInput(name, FieldContentValue.Text("v"))

    @Test
    fun `valid content returns null`() {
        val c = RecordContentInput("login", listOf("personal"), listOf(text("user"), text("pass")))
        assertNull(c.validate())
    }

    @Test
    fun `empty fields is allowed`() {
        assertNull(RecordContentInput("note", emptyList(), emptyList()).validate())
    }

    @Test
    fun `blank field name is rejected`() {
        val c = RecordContentInput("login", emptyList(), listOf(text("   ")))
        assertEquals(RecordContentInputError.EmptyFieldName, c.validate())
    }

    @Test
    fun `duplicate field name is rejected`() {
        val c = RecordContentInput("login", emptyList(), listOf(text("user"), text("user")))
        assertEquals(RecordContentInputError.DuplicateFieldName("user"), c.validate())
    }
}
```

`android/vault-access/src/test/kotlin/org/secretary/browse/HexFormatTest.kt`:
```kotlin
package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class HexFormatTest {
    @Test
    fun `round-trips lowercase hex`() {
        val bytes = byteArrayOf(0x00, 0x0f, 0x10.toByte(), 0xff.toByte())
        assertArrayEquals(bytes, parseHexLenient(hexOfBytes(bytes)))
    }

    @Test
    fun `accepts uppercase and whitespace`() {
        assertArrayEquals(byteArrayOf(0xAB.toByte(), 0xCD.toByte()), parseHexLenient("AB CD"))
    }

    @Test
    fun `empty string parses to empty bytes`() {
        assertArrayEquals(ByteArray(0), parseHexLenient(""))
    }

    @Test
    fun `odd length is rejected`() {
        assertNull(parseHexLenient("abc"))
    }

    @Test
    fun `non-hex char is rejected`() {
        assertNull(parseHexLenient("zz"))
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-record-edit/android && ./gradlew :vault-access:test --tests 'org.secretary.browse.RecordContentInputTest' --tests 'org.secretary.browse.HexFormatTest'`
Expected: FAIL — unresolved references `RecordContentInput`, `parseHexLenient`, etc.

- [ ] **Step 3: Create `RecordContentInput.kt`**

```kotlin
package org.secretary.browse

/**
 * A field's plaintext value to write. [Text] is keyboard plaintext; [Bytes] is raw bytes (the edit
 * UI enters/edits these as hex). Mirrors the FFI `FieldInputValue` without naming it, keeping this
 * package FFI-free. Mirror of iOS `FieldContentValue`.
 *
 * [Bytes] defines structural equality via `contentEquals` (a data class over a [ByteArray] gives
 * referential equals/hashCode, which would break test assertions) — same caveat as [RevealedValue.Bytes].
 */
sealed interface FieldContentValue {
    data class Text(val value: String) : FieldContentValue

    class Bytes(val value: ByteArray) : FieldContentValue {
        override fun equals(other: Any?): Boolean =
            this === other || (other is Bytes && value.contentEquals(other.value))

        override fun hashCode(): Int = value.contentHashCode()
    }
}

/** One field to write: a non-secret [name] + a [value]. Mirrors FFI `FieldInput`. */
data class FieldContentInput(val name: String, val value: FieldContentValue)

/**
 * Full desired content of a record to add or edit. Mirrors FFI `RecordContent`. `record_uuid`,
 * `created_at_ms`, per-field clocks and forward-compat `unknown` maps are intentionally NOT here —
 * the bridge edit primitives own those (mint-on-add / preserve-on-edit). Mirror of iOS
 * `RecordContentInput`.
 */
data class RecordContentInput(
    val recordType: String,
    val tags: List<String>,
    val fields: List<FieldContentInput>,
) {
    /**
     * Pure pre-commit validation. `null` == valid. Field names must be non-blank and unique (the
     * bridge diffs fields by name on edit, so two same-named fields would alias). Record type and
     * tags are unconstrained; empty [fields] is allowed.
     */
    fun validate(): RecordContentInputError? {
        val seen = HashSet<String>()
        for (f in fields) {
            if (f.name.isBlank()) return RecordContentInputError.EmptyFieldName
            if (!seen.add(f.name)) return RecordContentInputError.DuplicateFieldName(f.name)
        }
        return null
    }
}

/** Why a [RecordContentInput] is not writable. Surfaced inline in the edit UI. */
sealed interface RecordContentInputError {
    data object EmptyFieldName : RecordContentInputError
    data class DuplicateFieldName(val name: String) : RecordContentInputError
}
```

- [ ] **Step 4: Add `parseHexLenient` to `HexFormat.kt`**

Append to `android/vault-access/src/main/kotlin/org/secretary/browse/HexFormat.kt`:
```kotlin
/**
 * Parse a hex string to bytes, leniently: whitespace is stripped (so users can paste spaced hex)
 * and digits are case-insensitive. Returns `null` if the cleaned string has odd length or any
 * non-hex character. Inverse of [hexOfBytes] for the byte-field edit affordance; mirror of iOS
 * `RecordEditViewModel.parseHex`. Unlike [hexToBytes] (trusted, throwing), this is for USER input.
 */
fun parseHexLenient(s: String): ByteArray? {
    val cleaned = s.filterNot { it.isWhitespace() }
    if (cleaned.length % 2 != 0) return null
    val out = ByteArray(cleaned.length / 2)
    for (i in out.indices) {
        val hi = Character.digit(cleaned[i * 2], 16)
        val lo = Character.digit(cleaned[i * 2 + 1], 16)
        if (hi < 0 || lo < 0) return null
        out[i] = ((hi shl 4) or lo).toByte()
    }
    return out
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-record-edit/android && ./gradlew :vault-access:test --tests 'org.secretary.browse.RecordContentInputTest' --tests 'org.secretary.browse.HexFormatTest'`
Expected: PASS (9 tests).

- [ ] **Step 6: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/browse/RecordContentInput.kt \
        android/vault-access/src/main/kotlin/org/secretary/browse/HexFormat.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/RecordContentInputTest.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/HexFormatTest.kt
git commit -m "feat(android): pure record-content input types + lenient hex parse"
```

---

### Task 2: `VaultSession.appendRecord`/`editRecord` contract + fake

**Files:**
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultOpenPort.kt`
- Modify: `android/vault-access/src/test/kotlin/org/secretary/browse/FakeVaultBrowse.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/FakeVaultBrowseTest.kt`

**Interfaces:**
- Consumes: `RecordContentInput`, `FieldContentValue` (Task 1).
- Produces:
  - `suspend fun VaultSession.appendRecord(blockUuid: ByteArray, content: RecordContentInput): ByteArray` (returns minted 16-byte uuid)
  - `suspend fun VaultSession.editRecord(blockUuid: ByteArray, recordUuid: ByteArray, content: RecordContentInput)`
  - On `FakeVaultSession`: `val appended: MutableList<Pair<String, RecordContentInput>>`, `val edited: MutableList<Triple<String, String, RecordContentInput>>` (blockHex, recordHex, content).

- [ ] **Step 1: Write the failing test**

Create `android/vault-access/src/test/kotlin/org/secretary/browse/FakeVaultBrowseTest.kt` if absent, else append. (A `FakeVaultBrowseTest.kt` already exists — append these methods to the existing class; if structure differs, add a new test class `FakeVaultSessionWriteTest` in the same file.)
```kotlin
package org.secretary.browse

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class FakeVaultSessionWriteTest {
    private val block = BlockSummaryView(ByteArray(16) { 0x4c }, "Logins", 1u, 2u)
    private val existing = RecordSummaryView(
        "aa".repeat(16), "login", emptyList(), 1u, 2u, false, listOf(textField("user", "u")),
    )

    private fun session() =
        FakeVaultSession("abcd", listOf(block), mapOf(block.uuidHex to listOf(existing)))

    @Test
    fun `appendRecord records content and re-read shows the new record`() = runTest {
        val s = session()
        val content = RecordContentInput("note", listOf("t"), listOf(
            FieldContentInput("body", FieldContentValue.Text("hello"))))
        val uuid = s.appendRecord(block.uuid, content)
        assertEquals(16, uuid.size)
        assertEquals(1, s.appended.size)
        val records = s.readBlock(block.uuid, includeDeleted = false)
        assertTrue(records.any { it.type == "note" })
    }

    @Test
    fun `editRecord records the edit for the right uuid`() = runTest {
        val s = session()
        val content = RecordContentInput("login", emptyList(), listOf(
            FieldContentInput("user", FieldContentValue.Text("changed"))))
        s.editRecord(block.uuid, hexToBytes(existing.uuidHex), content)
        assertEquals(1, s.edited.size)
        assertEquals(existing.uuidHex, s.edited.first().second)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-record-edit/android && ./gradlew :vault-access:test --tests 'org.secretary.browse.FakeVaultSessionWriteTest'`
Expected: FAIL — `appendRecord`/`editRecord` unresolved.

- [ ] **Step 3: Add the interface methods**

In `android/vault-access/src/main/kotlin/org/secretary/browse/VaultOpenPort.kt`, inside `interface VaultSession`, after `resurrectRecord`:
```kotlin
    /**
     * Append a new record built from [content] to the block; returns the freshly-minted 16-byte
     * record UUID. The UUID is minted INSIDE the impl (SecureRandom in the real adapter) so the pure
     * model stays deterministic. Device-uuid + now-ms are resolved inside the impl.
     */
    suspend fun appendRecord(blockUuid: ByteArray, content: RecordContentInput): ByteArray

    /**
     * Replace one live record's editable part (type / tags / fields) with [content]. `record_uuid`,
     * `created_at_ms`, per-field clocks and `unknown` maps are preserved by the bridge. Device-uuid +
     * now-ms are resolved inside the impl. `RecordNotFound` if no live record with [recordUuid].
     */
    suspend fun editRecord(blockUuid: ByteArray, recordUuid: ByteArray, content: RecordContentInput)
```

- [ ] **Step 4: Implement them on `FakeVaultSession`**

In `android/vault-access/src/test/kotlin/org/secretary/browse/FakeVaultBrowse.kt`, add audit lists near `tombstoned`/`resurrected`:
```kotlin
    /** (blockHex, content) of each appendRecord call, in order. */
    val appended: MutableList<Pair<String, RecordContentInput>> = mutableListOf()
    /** (blockHex, recordHex, content) of each editRecord call, in order. */
    val edited: MutableList<Triple<String, String, RecordContentInput>> = mutableListOf()
    private var nextFakeUuidByte: Int = 0xA0
```
and add the overrides after `resurrectRecord`:
```kotlin
    override suspend fun appendRecord(blockUuid: ByteArray, content: RecordContentInput): ByteArray {
        writeError?.let { throw it }
        val blockHex = hexOfBytes(blockUuid)
        appended += blockHex to content
        // Mint a deterministic distinct uuid for the fake (real adapter uses SecureRandom).
        val uuid = ByteArray(16) { (nextFakeUuidByte and 0xff).toByte() }
        nextFakeUuidByte += 1
        val list = records.getOrPut(blockHex) { mutableListOf() }
        list += RecordSummaryView(
            uuidHex = hexOfBytes(uuid),
            type = content.recordType,
            tags = content.tags,
            createdAtMs = 0u,
            lastModMs = 0u,
            tombstone = false,
            fields = content.fields.map { it.toRevealableField() },
        )
        return uuid
    }

    override suspend fun editRecord(blockUuid: ByteArray, recordUuid: ByteArray, content: RecordContentInput) {
        writeError?.let { throw it }
        val blockHex = hexOfBytes(blockUuid)
        val recordHex = hexOfBytes(recordUuid)
        edited += Triple(blockHex, recordHex, content)
        val list = records[blockHex] ?: return
        val i = list.indexOfFirst { it.uuidHex == recordHex }
        if (i < 0) throw VaultBrowseError.RecordNotFound(recordHex)
        list[i] = list[i].copy(
            type = content.recordType,
            tags = content.tags,
            fields = content.fields.map { it.toRevealableField() },
        )
    }
```
and add a private helper at file scope (below the class):
```kotlin
/** Turn an input field into a canned RevealableField for the fake's re-read. */
private fun FieldContentInput.toRevealableField(): RevealableField = when (val v = value) {
    is FieldContentValue.Text -> RevealableField(name, FieldKind.Text) { RevealedValue.Text(v.value) }
    is FieldContentValue.Bytes -> RevealableField(name, FieldKind.Bytes) { RevealedValue.Bytes(v.value) }
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-record-edit/android && ./gradlew :vault-access:test --tests 'org.secretary.browse.FakeVaultSessionWriteTest'`
Expected: PASS (2 tests).

- [ ] **Step 6: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/browse/VaultOpenPort.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/FakeVaultBrowse.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/FakeVaultBrowseTest.kt
git commit -m "feat(android): VaultSession.appendRecord/editRecord contract + fake"
```

---

### Task 3: Pure `RecordEditModel` (the form heart)

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/RecordEditModel.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/RecordEditModelTest.kt`

**Interfaces:**
- Consumes: `VaultSession.appendRecord/editRecord` (Task 2), `RecordContentInput`/`FieldContentValue`/`RecordContentInputError` (Task 1), `parseHexLenient`/`hexOfBytes` (Task 1), `RecordSummaryView`/`RevealableField`/`RevealedValue`/`FieldKind`/`VaultBrowseError` (existing).
- Produces:
  - `data class EditableField(val id: Long, val name: String, val kind: FieldKind, val rawText: String)`
  - `class RecordEditModel(session, blockUuid: ByteArray, mode: Mode)` with `sealed interface Mode { data object Add; data class Edit(val recordUuid: ByteArray) }`
  - StateFlows: `recordType`, `tags`, `fields`, `error`, `committed`, `loadFailed`
  - Mutators: `setRecordType(String)`, `addField()`, `removeField(id: Long)`, `setFieldName(id, String)`, `setFieldKind(id, FieldKind)`, `setFieldRawText(id, String)`, `addTag()`, `setTag(index: Int, String)`, `removeTag(index: Int)`
  - `fun load(record: RecordSummaryView)`, `suspend fun commit()`

- [ ] **Step 1: Write the failing tests**

`android/vault-access/src/test/kotlin/org/secretary/browse/RecordEditModelTest.kt`:
```kotlin
package org.secretary.browse

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RecordEditModelTest {
    private val block = BlockSummaryView(ByteArray(16) { 0x4c }, "Logins", 1u, 2u)

    private fun session(writeError: VaultBrowseError? = null, records: List<RecordSummaryView> = emptyList()) =
        FakeVaultSession("abcd", listOf(block), mapOf(block.uuidHex to records), writeError = writeError)

    private fun addModel(s: FakeVaultSession) =
        RecordEditModel(s, block.uuid, RecordEditModel.Mode.Add)

    @Test
    fun `add commit appends content and sets committed`() = runTest {
        val s = session()
        val m = addModel(s)
        m.setRecordType("note")
        m.addField()
        m.setFieldName(0, "body")
        m.setFieldRawText(0, "hello")
        m.commit()
        assertTrue(m.committed.value)
        assertNull(m.error.value)
        assertEquals("note", s.appended.single().second.recordType)
        assertEquals("body", s.appended.single().second.fields.single().name)
    }

    @Test
    fun `bytes field parses hex on commit`() = runTest {
        val s = session()
        val m = addModel(s)
        m.setRecordType("key")
        m.addField()
        m.setFieldName(0, "raw")
        m.setFieldKind(0, FieldKind.Bytes)
        m.setFieldRawText(0, "ab cd")
        m.commit()
        assertTrue(m.committed.value)
        val v = s.appended.single().second.fields.single().value as FieldContentValue.Bytes
        assertEquals(listOf<Byte>(0xAB.toByte(), 0xCD.toByte()), v.value.toList())
    }

    @Test
    fun `invalid hex blocks the write with a typed error`() = runTest {
        val s = session()
        val m = addModel(s)
        m.addField()
        m.setFieldName(0, "raw")
        m.setFieldKind(0, FieldKind.Bytes)
        m.setFieldRawText(0, "zz")
        m.commit()
        assertFalse(m.committed.value)
        assertTrue(m.error.value is VaultBrowseError.InvalidArgument)
        assertTrue(s.appended.isEmpty())
    }

    @Test
    fun `duplicate field name blocks the write`() = runTest {
        val s = session()
        val m = addModel(s)
        m.addField(); m.setFieldName(0, "user")
        m.addField(); m.setFieldName(1, "user")
        m.commit()
        assertFalse(m.committed.value)
        assertTrue(m.error.value is VaultBrowseError.InvalidArgument)
        assertTrue(s.appended.isEmpty())
    }

    @Test
    fun `load reveals fields into the form`() {
        val rec = RecordSummaryView(
            "bb".repeat(16), "login", listOf("personal"), 1u, 2u, false,
            listOf(
                RevealableField("user", FieldKind.Text) { RevealedValue.Text("alice") },
                RevealableField("salt", FieldKind.Bytes) { RevealedValue.Bytes(byteArrayOf(0xAB.toByte())) },
            ),
        )
        val s = session(records = listOf(rec))
        val m = RecordEditModel(s, block.uuid, RecordEditModel.Mode.Edit(hexToBytes(rec.uuidHex)))
        m.load(rec)
        assertFalse(m.loadFailed.value)
        assertEquals("login", m.recordType.value)
        assertEquals(listOf("personal"), m.tags.value)
        assertEquals("alice", m.fields.value[0].rawText)
        assertEquals("ab", m.fields.value[1].rawText) // bytes → lowercase hex
        assertEquals(FieldKind.Bytes, m.fields.value[1].kind)
    }

    @Test
    fun `edit commit edits the right record`() = runTest {
        val rec = RecordSummaryView(
            "bb".repeat(16), "login", emptyList(), 1u, 2u, false,
            listOf(RevealableField("user", FieldKind.Text) { RevealedValue.Text("alice") }),
        )
        val s = session(records = listOf(rec))
        val m = RecordEditModel(s, block.uuid, RecordEditModel.Mode.Edit(hexToBytes(rec.uuidHex)))
        m.load(rec)
        m.setFieldRawText(0, "bob")
        m.commit()
        assertTrue(m.committed.value)
        assertEquals(rec.uuidHex, s.edited.single().second)
        assertEquals("bob", (s.edited.single().third.fields.single().value as FieldContentValue.Text).value)
    }

    @Test
    fun `load failure sets loadFailed and commit is a no-op`() = runTest {
        val rec = RecordSummaryView(
            "cc".repeat(16), "login", emptyList(), 1u, 2u, false,
            listOf(RevealableField("user", FieldKind.Text) {
                throw VaultBrowseError.CorruptVault("cannot expose")
            }),
        )
        val s = session(records = listOf(rec))
        val m = RecordEditModel(s, block.uuid, RecordEditModel.Mode.Edit(hexToBytes(rec.uuidHex)))
        m.load(rec)
        assertTrue(m.loadFailed.value)
        assertTrue(m.error.value is VaultBrowseError.CorruptVault)
        m.commit()
        assertFalse(m.committed.value)
        assertTrue(s.edited.isEmpty())
    }

    @Test
    fun `ffi failure surfaces error and does not set committed`() = runTest {
        val s = session(writeError = VaultBrowseError.SaveCryptoFailure("boom"))
        val m = addModel(s)
        m.setRecordType("note")
        m.commit()
        assertFalse(m.committed.value)
        assertTrue(m.error.value is VaultBrowseError.SaveCryptoFailure)
    }

    @Test
    fun `removeField and tag mutators work`() {
        val s = session()
        val m = addModel(s)
        m.addField(); m.setFieldName(0, "a")
        m.addField(); m.setFieldName(1, "b")
        m.removeField(0)
        assertEquals(listOf("b"), m.fields.value.map { it.name })
        m.addTag(); m.setTag(0, "x")
        assertEquals(listOf("x"), m.tags.value)
        m.removeTag(0)
        assertTrue(m.tags.value.isEmpty())
    }
}
```

Note: `setFieldName(0, …)` uses the field's **id** (the first added field has `id == 0L`). See Step 3 — ids are a deterministic monotonic counter starting at 0.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-record-edit/android && ./gradlew :vault-access:test --tests 'org.secretary.browse.RecordEditModelTest'`
Expected: FAIL — `RecordEditModel` unresolved.

- [ ] **Step 3: Create `RecordEditModel.kt`**

```kotlin
package org.secretary.browse

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * One editable field row. [rawText] holds plaintext for [FieldKind.Text] fields and a hex string for
 * [FieldKind.Bytes] fields (the only byte-entry affordance this slice). [id] is a stable synthetic
 * key for Compose list stability — a monotonic counter, NOT crypto, never reaching the vault. Mirror
 * of iOS `EditableField`.
 */
data class EditableField(
    val id: Long,
    val name: String = "",
    val kind: FieldKind = FieldKind.Text,
    val rawText: String = "",
)

/**
 * Drives the add/edit record form. Host-testable with [FakeVaultSession]. Pure mirror of iOS
 * `RecordEditViewModel` (which is a Combine ObservableObject); here the form state is exposed as
 * [StateFlow]s with explicit mutators, consistent with [VaultBrowseModel]. On a successful [commit]
 * it sets [committed] (the screen dismisses + the browse model re-reads); on failure it sets a typed
 * [error] and writes nothing.
 *
 * Secret hygiene: [fields]'s [EditableField.rawText] holds revealed plaintext for the edit duration
 * (accepted, scoped — matches iOS). The owning [VaultBrowseModel] drops this model on
 * cancel / commit / lock.
 */
class RecordEditModel(
    private val session: VaultSession,
    private val blockUuid: ByteArray,
    val mode: Mode,
) {
    /** Add a brand-new record, or replace an existing one identified by its 16-byte UUID. */
    sealed interface Mode {
        data object Add : Mode
        data class Edit(val recordUuid: ByteArray) : Mode
    }

    private val _recordType = MutableStateFlow("")
    val recordType: StateFlow<String> = _recordType.asStateFlow()

    private val _tags = MutableStateFlow<List<String>>(emptyList())
    val tags: StateFlow<List<String>> = _tags.asStateFlow()

    private val _fields = MutableStateFlow<List<EditableField>>(emptyList())
    val fields: StateFlow<List<EditableField>> = _fields.asStateFlow()

    private val _error = MutableStateFlow<VaultBrowseError?>(null)
    val error: StateFlow<VaultBrowseError?> = _error.asStateFlow()

    private val _committed = MutableStateFlow(false)
    val committed: StateFlow<Boolean> = _committed.asStateFlow()

    private val _loadFailed = MutableStateFlow(false)
    /** Set by [load] on a reveal failure; while true, [commit] refuses to write (never clobber a
     *  record we could not fully read). A fresh model (always built per-edit) starts clean. */
    val loadFailed: StateFlow<Boolean> = _loadFailed.asStateFlow()

    private var nextFieldId: Long = 0

    fun setRecordType(value: String) { _recordType.value = value }

    /** Append a blank field row with a fresh deterministic [EditableField.id]. */
    fun addField() {
        _fields.value = _fields.value + EditableField(id = nextFieldId++)
    }

    fun removeField(id: Long) { _fields.value = _fields.value.filterNot { it.id == id } }

    fun setFieldName(id: Long, name: String) = mutateField(id) { it.copy(name = name) }
    fun setFieldKind(id: Long, kind: FieldKind) = mutateField(id) { it.copy(kind = kind) }
    fun setFieldRawText(id: Long, rawText: String) = mutateField(id) { it.copy(rawText = rawText) }

    private inline fun mutateField(id: Long, transform: (EditableField) -> EditableField) {
        _fields.value = _fields.value.map { if (it.id == id) transform(it) else it }
    }

    fun addTag() { _tags.value = _tags.value + "" }
    fun setTag(index: Int, value: String) {
        _tags.value = _tags.value.toMutableList().also { if (index in it.indices) it[index] = value }
    }
    fun removeTag(index: Int) {
        _tags.value = _tags.value.toMutableList().also { if (index in it.indices) it.removeAt(index) }
    }

    /**
     * Prefill from an existing record for editing, revealing each field into a row (text → plaintext,
     * bytes → lowercase hex). A reveal that throws is captured into [error] + [loadFailed] instead of
     * propagating. Mirror of iOS `RecordEditViewModel.load`.
     */
    fun load(record: RecordSummaryView) {
        try {
            _recordType.value = record.type
            _tags.value = record.tags
            _fields.value = record.fields.map { field ->
                when (val revealed = field.reveal()) {
                    is RevealedValue.Text -> EditableField(nextFieldId++, field.name, FieldKind.Text, revealed.value)
                    is RevealedValue.Bytes -> EditableField(nextFieldId++, field.name, FieldKind.Bytes, hexOfBytes(revealed.value))
                }
            }
            _loadFailed.value = false
        } catch (e: VaultBrowseError) {
            _error.value = e
            _loadFailed.value = true
        } catch (e: Exception) {
            _error.value = VaultBrowseError.Failed(e.toString())
            _loadFailed.value = true
        }
    }

    /**
     * Build → validate → write. Sets [committed] on success; sets [error] and writes nothing on any
     * validation or FFI failure. Refuses to run while [loadFailed]. Mirror of iOS
     * `RecordEditViewModel.commit`.
     */
    suspend fun commit() {
        if (_loadFailed.value) return
        val content = buildContent() ?: return // sets _error on hex failure
        content.validate()?.let {
            _error.value = mapValidation(it)
            return
        }
        try {
            when (val m = mode) {
                Mode.Add -> session.appendRecord(blockUuid, content)
                is Mode.Edit -> session.editRecord(blockUuid, m.recordUuid, content)
            }
            _error.value = null
            _committed.value = true
        } catch (e: VaultBrowseError) {
            _error.value = e
        }
    }

    /** Map the form rows to input fields, parsing hex for byte fields. Returns null + sets [error]
     *  on the first invalid-hex field; drops blank tags. */
    private fun buildContent(): RecordContentInput? {
        val built = ArrayList<FieldContentInput>(_fields.value.size)
        for (f in _fields.value) {
            val value = when (f.kind) {
                FieldKind.Text -> FieldContentValue.Text(f.rawText)
                FieldKind.Bytes -> {
                    val bytes = parseHexLenient(f.rawText)
                        ?: run {
                            _error.value = VaultBrowseError.InvalidArgument("field '${f.name}' is not valid hex")
                            return null
                        }
                    FieldContentValue.Bytes(bytes)
                }
            }
            built += FieldContentInput(f.name, value)
        }
        val cleanTags = _tags.value.map { it.trim() }.filter { it.isNotEmpty() }
        return RecordContentInput(_recordType.value, cleanTags, built)
    }

    private fun mapValidation(v: RecordContentInputError): VaultBrowseError = when (v) {
        RecordContentInputError.EmptyFieldName -> VaultBrowseError.InvalidArgument("a field name is empty")
        is RecordContentInputError.DuplicateFieldName -> VaultBrowseError.InvalidArgument("duplicate field name: ${v.name}")
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-record-edit/android && ./gradlew :vault-access:test --tests 'org.secretary.browse.RecordEditModelTest'`
Expected: PASS (9 tests).

- [ ] **Step 5: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/browse/RecordEditModel.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/RecordEditModelTest.kt
git commit -m "feat(android): pure RecordEditModel (add/edit form heart)"
```

---

### Task 4: `VaultBrowseModel` editing state machine

**Files:**
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseModel.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/VaultBrowseModelTest.kt`

**Interfaces:**
- Consumes: `RecordEditModel` (Task 3), `session`/`selectBlock`/`lock` (existing).
- Produces on `VaultBrowseModel`:
  - `val editing: StateFlow<RecordEditModel?>`
  - `fun startAdd()`, `fun startEdit(record: RecordSummaryView)`, `fun cancelEdit()`, `suspend fun onEditCommitted()`
  - `lock()` additionally clears `editing`.

- [ ] **Step 1: Write the failing tests**

Append to `android/vault-access/src/test/kotlin/org/secretary/browse/VaultBrowseModelTest.kt` (new methods inside the existing class):
```kotlin
    @Test
    fun `startAdd publishes an Add edit model on the selected block`() = runTest {
        val model = VaultBrowseModel(session())
        model.loadBlocks()
        model.selectBlock(block)
        model.startAdd()
        val editing = model.editing.value
        assertEquals(RecordEditModel.Mode.Add, editing?.mode)
    }

    @Test
    fun `startEdit publishes an Edit model prefilled from the record`() = runTest {
        val model = VaultBrowseModel(session())
        model.loadBlocks()
        model.selectBlock(block)
        val rec = model.selectedRecords.value!!.first()
        model.startEdit(rec)
        val editing = model.editing.value!!
        assertTrue(editing.mode is RecordEditModel.Mode.Edit)
        assertEquals(rec.type, editing.recordType.value)
    }

    @Test
    fun `cancelEdit clears the editing model`() = runTest {
        val model = VaultBrowseModel(session())
        model.loadBlocks(); model.selectBlock(block); model.startAdd()
        model.cancelEdit()
        assertNull(model.editing.value)
    }

    @Test
    fun `onEditCommitted clears editing and re-reads the block`() = runTest {
        val s = session()
        val model = VaultBrowseModel(s)
        model.loadBlocks(); model.selectBlock(block); model.startAdd()
        // Simulate a committed append directly on the session, then signal commit.
        s.appendRecord(block.uuid, RecordContentInput("note", emptyList(), emptyList()))
        model.onEditCommitted()
        assertNull(model.editing.value)
        assertTrue(model.selectedRecords.value!!.any { it.type == "note" })
    }

    @Test
    fun `lock clears editing`() = runTest {
        val model = VaultBrowseModel(session())
        model.loadBlocks(); model.selectBlock(block); model.startAdd()
        model.lock()
        assertNull(model.editing.value)
    }
```
(These reference the existing test's `block`/`session()` helpers. The existing `VaultBrowseModelTest` already defines `block`, `recs`, and `session(...)` — reuse them. If `session()` has no records, `startEdit`/`selectedRecords.first()` needs at least one record; ensure the helper's `recs` is non-empty, which it is.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-record-edit/android && ./gradlew :vault-access:test --tests 'org.secretary.browse.VaultBrowseModelTest'`
Expected: FAIL — `editing`/`startAdd`/etc. unresolved.

- [ ] **Step 3: Add the editing state machine to `VaultBrowseModel`**

After the `showDeleted` flow block (around line 40), add:
```kotlin
    private val _editing = MutableStateFlow<RecordEditModel?>(null)
    /** Non-null when an add/edit form is open — the third UI state (alongside block-list /
     *  record-list). Cleared on cancelEdit / commit / lock. Mirror of iOS's edit-sheet presentation. */
    val editing: StateFlow<RecordEditModel?> = _editing.asStateFlow()
```
After the `restore` method, add:
```kotlin
    /** Open a blank add form for the selected block. No-op if no block is selected. */
    fun startAdd() {
        val block = _selectedBlock.value ?: return
        _editing.value = RecordEditModel(session, block.uuid, RecordEditModel.Mode.Add)
    }

    /** Open an edit form prefilled from [record] (reveals its fields into the form). No-op if no
     *  block is selected. */
    fun startEdit(record: RecordSummaryView) {
        val block = _selectedBlock.value ?: return
        val model = RecordEditModel(session, block.uuid, RecordEditModel.Mode.Edit(hexToBytes(record.uuidHex)))
        model.load(record)
        _editing.value = model
    }

    /** Dismiss the edit form without writing (drops its in-memory plaintext). */
    fun cancelEdit() { _editing.value = null }

    /** Called after a successful commit: drop the form and re-read the selected block so the list
     *  reflects the new/edited record (re-read on success only, like commitThenReload). */
    suspend fun onEditCommitted() {
        _editing.value = null
        _selectedBlock.value?.let { selectBlock(it) }
    }
```
In `lock()`, add `_editing.value = null` (with the other resets):
```kotlin
    fun lock() {
        _revealed.value = emptyMap()
        _editing.value = null
        session.wipe()
        _blocks.value = emptyList()
        _selectedBlock.value = null
        _selectedRecords.value = null
        _error.value = null
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-record-edit/android && ./gradlew :vault-access:test`
Expected: PASS (whole `:vault-access` suite green, including the 5 new methods).

- [ ] **Step 5: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseModel.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/VaultBrowseModelTest.kt
git commit -m "feat(android): VaultBrowseModel editing state machine (start/cancel/commit/lock)"
```

---

### Task 5: `:kit` real writers + `RecordContent` mapping

**Files:**
- Create: `android/kit/src/main/kotlin/org/secretary/browse/RecordContentMapping.kt`
- Modify: `android/kit/src/main/kotlin/org/secretary/browse/UniffiVaultOpenPort.kt`
- Test: `android/kit/src/test/kotlin/org/secretary/browse/RecordContentMappingTest.kt`

**Interfaces:**
- Consumes: `RecordContentInput`/`FieldContentValue` (Task 1), generated `uniffi.secretary.RecordContent`/`FieldInput`/`FieldInputValue`/`appendRecord`/`editRecord`.
- Produces: `internal fun toFfi(content: RecordContentInput): RecordContent`; `UniffiVaultSession.appendRecord`/`editRecord`.

- [ ] **Step 1: Write the failing test (toFfi mapping, host-runnable, no .so)**

`android/kit/src/test/kotlin/org/secretary/browse/RecordContentMappingTest.kt`:
```kotlin
package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import uniffi.secretary.FieldInputValue

class RecordContentMappingTest {
    @Test
    fun `maps record type, tags and text-or-bytes fields`() {
        val input = RecordContentInput(
            recordType = "login",
            tags = listOf("personal"),
            fields = listOf(
                FieldContentInput("user", FieldContentValue.Text("alice")),
                FieldContentInput("salt", FieldContentValue.Bytes(byteArrayOf(0xAB.toByte(), 0xCD.toByte()))),
            ),
        )
        val ffi = toFfi(input)
        assertEquals("login", ffi.recordType)
        assertEquals(listOf("personal"), ffi.tags)
        assertEquals("user", ffi.fields[0].name)
        assertEquals(FieldInputValue.Text("alice"), ffi.fields[0].value)
        val bytesValue = ffi.fields[1].value as FieldInputValue.Bytes
        assertTrue(byteArrayOf(0xAB.toByte(), 0xCD.toByte()).contentEquals(bytesValue.data))
    }
}
```
(If the generated `FieldInputValue.Text`/`Bytes` data-class equality does not hold structurally for `Bytes` — uniffi generates a `data class` over `ByteArray` — keep the `as` + `contentEquals` assertion shown for the Bytes arm; the Text arm's structural equality is fine.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-record-edit/android && ./gradlew :kit:testDebugUnitTest --tests 'org.secretary.browse.RecordContentMappingTest'`
Expected: FAIL — `toFfi` unresolved.

- [ ] **Step 3: Create `RecordContentMapping.kt`**

```kotlin
package org.secretary.browse

import uniffi.secretary.FieldInput
import uniffi.secretary.FieldInputValue
import uniffi.secretary.RecordContent

/**
 * Pure [RecordContentInput] → generated [RecordContent] mapping for the record edit/add write path.
 * The FFI bridge wraps both payloads in zeroize-on-drop SecretString / SecretBytes; the foreign-side
 * String / ByteArray are the caller's to clear (the edit form drops them on cancel/commit/lock).
 * Mirror of iOS `UniffiVaultSession.toFfi`.
 */
internal fun toFfi(content: RecordContentInput): RecordContent =
    RecordContent(
        recordType = content.recordType,
        tags = content.tags,
        fields = content.fields.map { f ->
            FieldInput(
                name = f.name,
                value = when (val v = f.value) {
                    is FieldContentValue.Text -> FieldInputValue.Text(v.value)
                    is FieldContentValue.Bytes -> FieldInputValue.Bytes(v.value)
                },
            )
        },
    )
```

- [ ] **Step 4: Add the writers + generic `write` to `UniffiVaultOpenPort.kt`**

Add imports near the other `uniffi.secretary` imports:
```kotlin
import java.security.SecureRandom
import uniffi.secretary.appendRecord as ffiAppendRecord
import uniffi.secretary.editRecord as ffiEditRecord
```
Change `write` to be generic (so `appendRecord` can return the minted UUID). Replace the existing `private suspend fun write(...)` with:
```kotlin
    private suspend fun <T> write(body: (deviceUuid: ByteArray, nowMs: ULong) -> T): T =
        withContext(ioDispatcher) {
            mapErrors {
                synchronized(sessionLock) {
                    if (wiped) throw VaultBrowseError.Failed("write on a wiped session")
                    val dev = deviceUuid()
                    body(dev, System.currentTimeMillis().toULong())
                }
            }
        }
```
(The existing `tombstoneRecord`/`resurrectRecord` bodies return `Unit`, so `T` infers `Unit` — no change needed there.)

Add the two new overrides after `resurrectRecord`:
```kotlin
    /** Mint a fresh 16-byte record UUID (SecureRandom — never in the pure model), append, return it. */
    override suspend fun appendRecord(blockUuid: ByteArray, content: RecordContentInput): ByteArray =
        write { dev, now ->
            val recordUuid = ByteArray(16).also { SecureRandom().nextBytes(it) }
            ffiAppendRecord(identity, manifest, blockUuid, recordUuid, toFfi(content), dev, now)
            recordUuid
        }

    override suspend fun editRecord(blockUuid: ByteArray, recordUuid: ByteArray, content: RecordContentInput) =
        write { dev, now -> ffiEditRecord(identity, manifest, blockUuid, recordUuid, toFfi(content), dev, now) }
```

- [ ] **Step 5: Run the mapping test + kit host suite**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-record-edit/android && ./gradlew :kit:testDebugUnitTest`
Expected: PASS (mapping test + existing kit host tests). The `appendRecord`/`editRecord` bodies are compiled here (exercised on-device in Task 8).

- [ ] **Step 6: Commit**

```bash
git add android/kit/src/main/kotlin/org/secretary/browse/RecordContentMapping.kt \
        android/kit/src/main/kotlin/org/secretary/browse/UniffiVaultOpenPort.kt \
        android/kit/src/test/kotlin/org/secretary/browse/RecordContentMappingTest.kt
git commit -m "feat(android): :kit appendRecord/editRecord writers + RecordContent mapping"
```

---

### Task 6: Compose edit form + ViewModel forwarding + BrowseScreen third state

**Files:**
- Create: `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/RecordEditForm.kt`
- Modify: `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/VaultBrowseViewModel.kt`
- Modify: `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/BrowseScreen.kt`

**Interfaces:**
- Consumes: `VaultBrowseModel.editing`/`startAdd`/`startEdit`/`cancelEdit`/`onEditCommitted` (Task 4), `RecordEditModel` (Task 3), `FieldKind` (existing).
- Produces on `VaultBrowseViewModel`: `val editing: StateFlow<RecordEditModel?>`, `fun startAdd()`, `fun startEdit(record)`, `fun cancelEdit()`, `fun commitEdit()`, `fun onEditCommitted()`. New composable `RecordEditForm(model: RecordEditModel, onCommit: () -> Unit, onCancel: () -> Unit)`.

- [ ] **Step 1: Add forwarding to `VaultBrowseViewModel`**

Add imports: `import org.secretary.browse.RecordEditModel`. Add members after `restore`:
```kotlin
    val editing: StateFlow<RecordEditModel?> = model.editing

    /** Open a blank add form for the selected block. */
    fun startAdd() = model.startAdd()

    /** Open an edit form prefilled from [record]. */
    fun startEdit(record: RecordSummaryView) = model.startEdit(record)

    /** Dismiss the edit form without writing. */
    fun cancelEdit() = model.cancelEdit()

    /** Run the open form's commit (suspend) on the view-model scope. */
    fun commitEdit() {
        viewModelScope.launch { model.editing.value?.commit() }
    }

    /** After a successful commit: drop the form + re-read the block. */
    fun onEditCommitted() {
        viewModelScope.launch { model.onEditCommitted() }
    }
```

- [ ] **Step 2: Create `RecordEditForm.kt`**

```kotlin
package org.secretary.browse.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.secretary.browse.EditableField
import org.secretary.browse.FieldKind
import org.secretary.browse.RecordEditModel

/**
 * The add/edit record form — the third [BrowseScreen] state. Binds directly to the pure
 * [RecordEditModel]'s StateFlows and calls its mutators on each edit; [onCommit] / [onCancel] are the
 * suspend-bridged actions owned by the view model. Mirror of iOS `RecordEditScreen`.
 */
@Composable
fun RecordEditForm(
    model: RecordEditModel,
    onCommit: () -> Unit,
    onCancel: () -> Unit,
) {
    val recordType by model.recordType.collectAsStateWithLifecycle()
    val tags by model.tags.collectAsStateWithLifecycle()
    val fields by model.fields.collectAsStateWithLifecycle()
    val error by model.error.collectAsStateWithLifecycle()
    val loadFailed by model.loadFailed.collectAsStateWithLifecycle()

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            TextButton(onClick = onCancel, modifier = Modifier.testTag("cancel-record")) { Text("Cancel") }
            TextButton(
                onClick = onCommit,
                enabled = !loadFailed,
                modifier = Modifier.testTag("save-record"),
            ) { Text("Save") }
        }
        error?.let {
            Text(
                text = "Couldn't save: ${it::class.simpleName}",
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium,
            )
        }
        OutlinedTextField(
            value = recordType,
            onValueChange = model::setRecordType,
            label = { Text("Type") },
            modifier = Modifier.fillMaxWidth().testTag("record-type-input"),
        )
        LazyColumn(modifier = Modifier.fillMaxSize()) {
            items(tags.indices.toList()) { i ->
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    OutlinedTextField(
                        value = tags[i],
                        onValueChange = { model.setTag(i, it) },
                        label = { Text("Tag") },
                        modifier = Modifier.weight(1f).testTag("tag-$i"),
                    )
                    TextButton(onClick = { model.removeTag(i) }) { Text("Remove") }
                }
            }
            item {
                TextButton(onClick = model::addTag, modifier = Modifier.testTag("add-tag")) { Text("Add tag") }
                HorizontalDivider()
            }
            items(fields, key = { it.id }) { field ->
                FieldEditor(field, model)
                HorizontalDivider()
            }
            item {
                TextButton(onClick = model::addField, modifier = Modifier.testTag("add-field")) { Text("Add field") }
            }
        }
    }
}

@Composable
private fun FieldEditor(field: EditableField, model: RecordEditModel) {
    Column(modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            OutlinedTextField(
                value = field.name,
                onValueChange = { model.setFieldName(field.id, it) },
                label = { Text("Name") },
                modifier = Modifier.weight(1f).testTag("field-name-${field.id}"),
            )
            TextButton(onClick = { model.removeField(field.id) }) { Text("Remove") }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(
                selected = field.kind == FieldKind.Text,
                onClick = { model.setFieldKind(field.id, FieldKind.Text) },
                label = { Text("Text") },
                modifier = Modifier.testTag("field-kind-text-${field.id}"),
            )
            FilterChip(
                selected = field.kind == FieldKind.Bytes,
                onClick = { model.setFieldKind(field.id, FieldKind.Bytes) },
                label = { Text("Bytes (hex)") },
                modifier = Modifier.testTag("field-kind-bytes-${field.id}"),
            )
        }
        OutlinedTextField(
            value = field.rawText,
            onValueChange = { model.setFieldRawText(field.id, it) },
            label = { Text(if (field.kind == FieldKind.Bytes) "hex bytes" else "value") },
            modifier = Modifier.fillMaxWidth().testTag("field-value-${field.id}"),
        )
    }
}
```

- [ ] **Step 3: Wire the third state into `BrowseScreen`**

In `BrowseScreen`, add `import androidx.compose.runtime.LaunchedEffect` (already imported) and collect `editing`:
```kotlin
    val editing by viewModel.editing.collectAsStateWithLifecycle()
```
At the very top of the `Column` body (before the `error?.let { … }` block), branch to the form when editing is open:
```kotlin
        val editModel = editing
        if (editModel != null) {
            val committed by editModel.committed.collectAsStateWithLifecycle()
            LaunchedEffect(committed) { if (committed) viewModel.onEditCommitted() }
            RecordEditForm(
                model = editModel,
                onCommit = viewModel::commitEdit,
                onCancel = viewModel::cancelEdit,
            )
            return@Column
        }
```
Add an "Add record" button on the record-list view. Inside the `else` branch (block selected), in the header `Row` that currently holds the block label + Back button, add an Add button — change that Row to include it, e.g. after the `Text(blockLabel(block), …)`:
```kotlin
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton(
                        onClick = { viewModel.startAdd() },
                        modifier = Modifier.testTag("add-record"),
                    ) { Text("Add") }
                    TextButton(onClick = { viewModel.back() }) { Text("Back") }
                }
```
(Replace the existing lone `TextButton(onClick = { viewModel.back() }) { Text("Back") }` with this grouping Row.)

Add a per-row edit button. In `RecordRow`, the `onDelete`/`onRestore` are passed in; add an `onEdit: (RecordSummaryView) -> Unit` parameter and, in the live branch (where the Delete button renders), wrap Delete + Edit in a Row:
```kotlin
            } else {
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    TextButton(
                        onClick = { onEdit(record) },
                        modifier = Modifier.testTag("edit-${record.uuidHex}"),
                    ) { Text("Edit") }
                    TextButton(
                        onClick = { onDelete(record) },
                        modifier = Modifier.testTag("delete-${record.uuidHex}"),
                    ) { Text("Delete") }
                }
            }
```
Thread `onEdit = viewModel::startEdit` from the `RecordRow(...)` call site, and add `onEdit: (RecordSummaryView) -> Unit` to `RecordRow`'s parameter list. Add `import androidx.compose.foundation.layout.Arrangement` is already present.

- [ ] **Step 4: Build the module to verify it compiles**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-record-edit/android && ./gradlew :browse-ui:compileDebugKotlin :browse-ui:test`
Expected: BUILD SUCCESSFUL (host suite unaffected; instrumented test added in Task 7).

- [ ] **Step 5: Commit**

```bash
git add android/browse-ui/src/main/kotlin/org/secretary/browse/ui/RecordEditForm.kt \
        android/browse-ui/src/main/kotlin/org/secretary/browse/ui/VaultBrowseViewModel.kt \
        android/browse-ui/src/main/kotlin/org/secretary/browse/ui/BrowseScreen.kt
git commit -m "feat(android): Compose record edit form + BrowseScreen add/edit affordances"
```

---

### Task 7: Instrumented Compose test (add + edit flows)

**Files:**
- Test: `android/browse-ui/src/androidTest/kotlin/org/secretary/browse/ui/RecordEditFormTest.kt`

**Interfaces:**
- Consumes: `BrowseScreen`, `VaultBrowseViewModel`, `FakeVaultSession` (test double), `RecordEditForm`.

- [ ] **Step 1: Write the instrumented test**

```kotlin
package org.secretary.browse.ui

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import org.junit.Rule
import org.junit.Test
import org.secretary.browse.BlockSummaryView
import org.secretary.browse.FakeVaultSession
import org.secretary.browse.RecordSummaryView
import org.secretary.browse.VaultBrowseModel
import org.secretary.browse.textField

class RecordEditFormTest {
    @get:Rule val composeRule = createComposeRule()

    private val recUuid = "33445566778899aabbccddeeff001122"
    private val block = BlockSummaryView(ByteArray(16) { 0x4c }, "Logins", 1u, 2u)
    private val existing = RecordSummaryView(
        recUuid, "login", emptyList(), 1u, 2u, false, listOf(textField("user", "alice")),
    )

    private fun fakeAndVm(): Pair<FakeVaultSession, VaultBrowseViewModel> {
        val session = FakeVaultSession("abcd", listOf(block), mapOf(block.uuidHex to listOf(existing)))
        return session to VaultBrowseViewModel(VaultBrowseModel(session))
    }

    private fun openBlock(vm: VaultBrowseViewModel) {
        composeRule.setContent { BrowseScreen(viewModel = vm, autoHideMillis = 60_000L) }
        composeRule.runOnIdle { vm.loadBlocks() }
        composeRule.onNodeWithText("Logins").performClick()
        composeRule.waitForIdle()
    }

    @Test
    fun add_newRecord_appearsInList() {
        val (fake, vm) = fakeAndVm()
        openBlock(vm)
        composeRule.onNodeWithTag("add-record").performClick()
        composeRule.waitForIdle()
        composeRule.onNodeWithTag("record-type-input").performTextInput("note")
        composeRule.onNodeWithTag("add-field").performClick()
        composeRule.waitForIdle()
        composeRule.onNodeWithTag("field-name-0").performTextInput("body")
        composeRule.onNodeWithTag("field-value-0").performTextInput("hello")
        composeRule.onNodeWithTag("save-record").performClick()
        composeRule.waitForIdle()
        // Form dismissed + new record present.
        assert(fake.appended.size == 1)
        composeRule.onNodeWithText("note").assertIsDisplayed()
    }

    @Test
    fun edit_existingRecord_recordsTheEdit() {
        val (fake, vm) = fakeAndVm()
        openBlock(vm)
        composeRule.onNodeWithTag("edit-$recUuid").performClick()
        composeRule.waitForIdle()
        // Field 0 prefilled with the revealed plaintext; change it.
        composeRule.onNodeWithTag("field-value-0").performTextInput("bob")
        composeRule.onNodeWithTag("save-record").performClick()
        composeRule.waitForIdle()
        assert(fake.edited.size == 1)
        assert(fake.edited.first().second == recUuid)
    }
}
```
Note: `performTextInput` appends; for the edit case the assertion only checks an edit was recorded for the right uuid, so the exact resulting string doesn't matter. If a future assertion needs an exact value, clear first with `performTextClearance()`.

- [ ] **Step 2: Run the instrumented test (emulator must be running)**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-record-edit/android && \
  PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :browse-ui:connectedDebugAndroidTest --tests 'org.secretary.browse.ui.RecordEditFormTest'
```
Expected: PASS (2 tests). Also confirm the existing `BrowseScreenSoftDeleteTest`/`BrowseScreenRevealTest` still pass (the `RecordRow` signature changed):
```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-record-edit/android && \
  PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :browse-ui:connectedDebugAndroidTest
```
Expected: all `:browse-ui` instrumented tests green.

- [ ] **Step 3: Commit**

```bash
git add android/browse-ui/src/androidTest/kotlin/org/secretary/browse/ui/RecordEditFormTest.kt
git commit -m "test(android): instrumented add/edit form flows"
```

---

### Task 8: `:app` on-device smoke (real `.so` append + edit round-trip)

**Files:**
- Modify: `android/app/src/androidTest/kotlin/org/secretary/app/OpenBrowseSmokeTest.kt`

**Interfaces:**
- Consumes: real `uniffiVaultOpenPort(deviceUuids)`, `VaultSession.appendRecord/editRecord`, `RecordContentInput`, staged golden vault.

- [ ] **Step 1: Add the two smoke tests**

Append to `OpenBrowseSmokeTest`:
```kotlin
    @Test
    fun append_thenReadShowsNewRecord() = runBlocking {
        val folder = AppVaultProvisioning.stageGoldenVault(context)
        val deviceUuids = org.secretary.browse.FileDeviceUuidStore(
            File(context.noBackupFilesDir, "devices-${System.nanoTime()}"))
        val session = org.secretary.browse.uniffiVaultOpenPort(deviceUuids)
            .openWithPassword(folder.path, goldenPassword.toByteArray())
        val model = VaultBrowseModel(session)
        model.loadBlocks()
        val block = model.blocks.value.first()
        model.selectBlock(block)

        val content = org.secretary.browse.RecordContentInput(
            recordType = "smoke-note",
            tags = listOf("smoke"),
            fields = listOf(org.secretary.browse.FieldContentInput(
                "body", org.secretary.browse.FieldContentValue.Text("appended"))),
        )
        session.appendRecord(block.uuid, content)
        model.selectBlock(block) // re-read

        val added = model.selectedRecords.value!!.first { it.type == "smoke-note" }
        model.reveal(added, added.fields.first { it.name == "body" })
        assertEquals(
            RevealedValue.Text("appended"),
            model.revealed.value["${added.uuidHex}/body"],
        )
        model.lock()
    }

    @Test
    fun edit_thenReadShowsChange() = runBlocking {
        val folder = AppVaultProvisioning.stageGoldenVault(context)
        val deviceUuids = org.secretary.browse.FileDeviceUuidStore(
            File(context.noBackupFilesDir, "devices-${System.nanoTime()}"))
        val session = org.secretary.browse.uniffiVaultOpenPort(deviceUuids)
            .openWithPassword(folder.path, goldenPassword.toByteArray())
        val model = VaultBrowseModel(session)
        model.loadBlocks()
        val block = model.blocks.value.first()
        model.selectBlock(block)

        val target = model.selectedRecords.value!!.first { it.type == "login" }
        val content = org.secretary.browse.RecordContentInput(
            recordType = "login",
            tags = target.tags,
            fields = listOf(org.secretary.browse.FieldContentInput(
                "password", org.secretary.browse.FieldContentValue.Text("edited-secret"))),
        )
        session.editRecord(block.uuid, org.secretary.browse.hexToBytesPublic(target.uuidHex), content)
        model.selectBlock(block) // re-read

        val edited = model.selectedRecords.value!!.first { it.uuidHex == target.uuidHex }
        model.reveal(edited, edited.fields.first { it.name == "password" })
        assertEquals(
            RevealedValue.Text("edited-secret"),
            model.revealed.value["${edited.uuidHex}/password"],
        )
        model.lock()
    }
```
**Note on `hexToBytes`:** the existing `hexToBytes` in `HexFormat.kt` is `internal`, so `:app` cannot call it. Add a thin public wrapper in `HexFormat.kt` (do this as the first edit of this task):
```kotlin
/** Public façade over [hexToBytes] for trusted callers outside the module (e.g. on-device smoke
 *  tests that hold a [RecordSummaryView.uuidHex]). Same trusted-input contract. */
fun hexToBytesPublic(hex: String): ByteArray = hexToBytes(hex)
```
(Alternatively widen `hexToBytes` to `public`; the wrapper keeps the trusted-input doc explicit and avoids changing the existing symbol's visibility used elsewhere.)

- [ ] **Step 2: Run the smoke tests (emulator running)**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-record-edit/android && \
  PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :app:connectedDebugAndroidTest
```
Expected: `OpenBrowseSmokeTest` all green (existing 4 + new 2) + `MakeVaultSyncSmokeTest` 2/2.

- [ ] **Step 3: Commit**

```bash
git add android/app/src/androidTest/kotlin/org/secretary/app/OpenBrowseSmokeTest.kt \
        android/vault-access/src/main/kotlin/org/secretary/browse/HexFormat.kt
git commit -m "test(android): on-device append/edit round-trip against staged golden vault"
```

---

### Task 9: Full gauntlet, guardrails, docs

**Files:**
- Modify: `README.md`, `ROADMAP.md`

- [ ] **Step 1: Run the full host gauntlet**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-record-edit/android && \
  ./gradlew :vault-access:test :kit:testDebugUnitTest :browse-ui:test :app:test
```
Expected: BUILD SUCCESSFUL.

- [ ] **Step 2: Run the full instrumented gauntlet (emulator running)**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-record-edit/android && \
  PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :browse-ui:connectedDebugAndroidTest :app:connectedDebugAndroidTest
```
Expected: all green (`RecordEditFormTest` 2/2, `BrowseScreenSoftDeleteTest` 2/2, `BrowseScreenRevealTest` 2/2, `OpenBrowseSmokeTest` 6/6, `MakeVaultSyncSmokeTest` 2/2).

- [ ] **Step 3: Verify guardrails are empty**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-record-edit && \
  git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)' ; \
  git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'
```
Expected: both produce NO output.

- [ ] **Step 4: Update `README.md` + `ROADMAP.md`**

Add the Android C.3 slice 10 ✅ (record edit/add) entry alongside the existing slice-9 status lines (follow the established brief dot-point style; no test-count walls). Exact wording is at the implementer's discretion but must state: record add + edit (text + bytes-as-hex), mirrors iOS, no core/ffi change.

- [ ] **Step 5: Commit**

```bash
git add README.md ROADMAP.md
git commit -m "docs: README + ROADMAP for Android C.3 slice 10 (record edit/add)"
```

---

## Self-Review

**1. Spec coverage:**
- Pure input types + validation → Task 1. ✅
- `parseHex` (bytes-as-hex) → Task 1. ✅
- `VaultSession.appendRecord/editRecord` contract + fake → Task 2. ✅
- `RecordEditModel` (add/edit/load/commit, exact iOS parity incl. loadFailed) → Task 3. ✅
- `editing` state machine + `lock()` clears editing → Task 4. ✅
- `:kit` real writers (SecureRandom mint, `write`+`wiped` guard, no new error arms) + `toFfi` → Task 5. ✅
- Compose form (Type/Tags/Fields/kind picker/add-delete), Add button, per-row edit → Task 6. ✅
- Instrumented add/edit flows → Task 7. ✅
- On-device real-`.so` append + edit round-trip (staged golden vault) → Task 8. ✅
- Guardrails + docs → Task 9. ✅

**2. Placeholder scan:** No TBD/TODO; every code step shows full code; README wording is intentionally implementer's-discretion (style is established + memory-noted), all other steps are concrete. ✅

**3. Type consistency:**
- `RecordEditModel.Mode.Add` / `Mode.Edit(recordUuid: ByteArray)` — consistent across Tasks 3/4/6. ✅
- `appendRecord(blockUuid, content): ByteArray` / `editRecord(blockUuid, recordUuid, content)` — consistent across Tasks 2/3/5/8. ✅
- `setFieldName/Kind/RawText(id: Long, …)`, `addField()`, `removeField(id)`, `addTag/setTag/removeTag` — consistent across Tasks 3/6. ✅
- `toFfi(content): RecordContent` (internal, `:kit`) — Task 5. ✅
- testTags (`add-record`, `edit-<uuidHex>`, `record-type-input`, `field-name-<id>`, `field-value-<id>`, `save-record`, `cancel-record`, `add-field`) — consistent Tasks 6/7. ✅
- `hexToBytesPublic` introduced in Task 8 for the `:app` boundary (the existing `hexToBytes` is `internal`). ✅

## Execution Handoff

After this plan is saved, the executor picks an approach (see below).
