# C.3 Android slice 8 — reveal-on-tap (per-field expose, auto-hide, lock-on-background)

**Date:** 2026-06-17
**Status:** Approved design (brainstorm complete)
**Branch:** `feature/c3-android-reveal-on-tap` (worktree `.worktrees/c3-android-reveal-on-tap`)
**Base:** `main` @ `162c5e2` (slice 7 merged as #249)

## Goal

The first Android slice where a **secret value crosses the adapter**. Browsing stays
metadata-only until the user explicitly taps a field; then the retained `FieldHandle`
materializes that one value on demand via `expose_text` / `expose_bytes`. A revealed
value auto-hides after a fixed interval, can be tapped to hide immediately, and is
dropped — along with the whole session — when the app is backgrounded.

This mirrors the **proven iOS reveal architecture** (`UniffiVaultSession` retains open
`BlockReadOutput`s; each `FieldView` carries an on-demand `reveal` closure;
`VaultBrowseViewModel` owns a `revealed` map and `hide`/`hideAll`/`lock` seams;
`RevealPolicy.autoHideSeconds = 30`). It evolves slice 7's metadata-only `RecordSummaryView`
to carry per-field reveal capability and reverses slice 7's "close the block immediately"
choice into iOS's "retain open blocks until wipe".

## Key scope finding: no `ffi/` or Rust changes

The entire reveal FFI surface is **already exposed via uniffi** and used by iOS:

- `read_block(identity, manifest, block_uuid, include_deleted) -> BlockReadOutput`
- `Record.field_count()` / `.field_names()` / `.field_at(idx)` / `.field_by_name(name)` → `FieldHandle`
- `FieldHandle.name()` / `.is_text()` / `.is_bytes()` / `.expose_text()` / `.expose_bytes()` / `.wipe()`
- `BlockReadOutput.wipe()` cascades zeroize to every contained record + field.

`:kit`'s Gradle build already runs `uniffi-bindgen` over the whole `secretary.udl`, so the
Kotlin bindings for `Record` / `FieldHandle` (`fieldAt`, `fieldByName`, `isText`,
`exposeText`, `exposeBytes`) are already generated. Slice 7 simply never called them. This
is therefore a **pure Kotlin-port + Compose-UI slice** — no edits under `core/`, `ffi/`,
or `ios/`, and no on-disk format change.

## Decisions (locked in brainstorming)

1. **Mirror iOS: retain open blocks.** `readBlock` keeps each `BlockReadOutput` alive for
   the session; each field's `reveal` lambda captures the `FieldHandle` and calls
   `expose_*` on tap; `wipe()` closes all retained blocks. Chosen over re-decrypt-on-reveal
   because the master key (`UnlockedIdentity`) is resident in **both** models, and an
   attacker who can read the master key from memory can decrypt any block at will — so the
   re-decrypt variant buys essentially no security while diverging from iOS and adding a new
   FFI port method. Parity + simplicity win.
2. **Mirror iOS hide policy exactly.** Auto-hide after `RevealPolicy.autoHideSeconds = 30`
   (named constant, no magic number), driven by the Compose layer; per-field tap-to-hide;
   `hideAll` seam. Lock-on-background (the slice-7 `ON_STOP` → `model.lock()` → full session
   wipe → return to Unlock) already redacts revealed values — `lock()` additionally clears
   the reveal map. **No** lighter hide-on-`ON_PAUSE`: a single, strong background behavior,
   matching iOS lock semantics. `FLAG_SECURE` already blacks out the app-switcher thumbnail.
3. **Reveal-only scope.** This slice adds reveal/hide/auto-hide of field values and nothing
   else. **No** show-deleted toggle, **no** edit/delete/restore — those remain a distinct
   later slice (iOS browse parity), exactly as separated in the slice-7 baton.
4. **Add instrumented Compose UI tests.** Unlike slices 6/7, this slice introduces genuinely
   novel interactive UI (tap-to-reveal, tap-to-hide, auto-hide timer) where the
   render+gesture wiring is the risk. A small instrumented Compose UI test joins the
   host-tested ViewModel + the instrumented FFI smoke. Closes the slice-7 "no Compose UI
   test" gap for the part that warrants it.

## Architecture

Layering follows the established Android stack
(`:vault-access` pure → `:kit` FFI adapter → `:browse-ui` → `:app`). All four existing
slice-7 types/files evolve in place; one new policy constant and two new value types are added.

### Section 1 — Pure seam (`:vault-access`, package `org.secretary.browse`)

Host-tested (JUnit5) with fakes; no Android or FFI dependencies. Mirrors iOS's
`RevealedValue` / `FieldView` / `RecordView` / `RevealPolicy`.

```kotlin
/** A revealed (decrypted) field value. Holds plaintext — drop promptly (see VaultBrowseModel).
 *  Mirror of iOS `RevealedValue`. */
sealed interface RevealedValue {
    data class Text(val value: String) : RevealedValue
    // Bytes wraps a ByteArray; structural equality is via contentEquals (custom equals/hashCode),
    // because a data class over ByteArray gives referential equality (Kotlin ByteArray caveat).
    class Bytes(val value: ByteArray) : RevealedValue { /* equals/hashCode via contentEquals */ }
}

enum class FieldKind { Text, Bytes }

/** One field of a record. `name`/`kind` are non-secret metadata; `reveal` materializes the
 *  plaintext ON DEMAND only (the real adapter wires it to expose_text/expose_bytes).
 *  NOT a data class — it holds a closure. Mirror of iOS `FieldView`. */
class RevealableField(
    val name: String,
    val kind: FieldKind,
    val reveal: () -> RevealedValue,
)

/** Named policy constant — never a magic number in the view. Mirror of iOS `RevealPolicy`. */
object RevealPolicy {
    const val autoHideSeconds: Long = 30
}
```

`RecordSummaryView` **evolves** to carry reveal capability (mirror of iOS `RecordView`):

```kotlin
// Was a `data class` with `fieldNames: List<String>`. Now a regular class holding
// `fields: List<RevealableField>`; identity stays `uuidHex`. `fieldNames` becomes a
// computed convenience so existing render helpers keep working.
class RecordSummaryView(
    val uuidHex: String,
    val type: String,
    val tags: List<String>,
    val createdAtMs: ULong,
    val lastModMs: ULong,
    val tombstone: Boolean,
    val fields: List<RevealableField>,
) {
    val fieldNames: List<String> get() = fields.map { it.name }
}
```

`BlockSummaryView`, `VaultBrowseError`, `VaultOpenPort`, `VaultSession` are **unchanged**
from slice 7 (the seam interface signatures are stable; only the `RecordSummaryView` payload
that `readBlock` returns gains the reveal lambdas).

`VaultBrowseModel` **gains** a reveal map and reveal/hide seams (mirror of iOS
`VaultBrowseViewModel`'s reveal logic):

```kotlin
class VaultBrowseModel(private val session: VaultSession) {
    // ...existing blocks / selectedBlock / selectedRecords / error flows unchanged...

    /** Currently-revealed plaintext, keyed "<recordUuidHex>/<fieldName>". Kept small +
     *  short-lived; cleared on selectBlock / clearSelection / lock. */
    val revealed: StateFlow<Map<String, RevealedValue>>

    /** Materialize one field's plaintext on explicit user action (calls field.reveal()). */
    fun reveal(record: RecordSummaryView, field: RevealableField)
    fun hide(recordUuidHex: String, fieldName: String)
    fun hideAll()
    // selectBlock / clearSelection / lock now clear `revealed` first (a reload never carries
    // a stale reveal). lock() clears reveals THEN wipes the session.
}
```

- **Key construction** `"$recordUuidHex/$fieldName"`: collision-safe because `recordUuidHex`
  is always exactly 32 lowercase hex chars (charset `[0-9a-f]`), so it can never contain the
  `/` separator nor alias another `(record, field)` pair even though field names are
  arbitrary vault-supplied strings (same rationale documented on iOS).
- `reveal` catches a thrown `VaultBrowseError` and routes it to `error` (a corrupt/wiped
  field surfaces typed, never crashes).

### Section 2 — Real adapter (`:kit`, package `org.secretary.browse`)

`UniffiVaultSession` **evolves** to retain open blocks and build reveal closures (mirror of
iOS `UniffiVaultSession`):

```kotlin
class UniffiVaultSession(output: OpenVaultOutput, ioDispatcher: CoroutineDispatcher) {
    private val openBlocks = mutableListOf<BlockReadOutput>()  // retained for reveal closures

    override suspend fun readBlock(blockUuid: ByteArray, includeDeleted: Boolean):
        List<RecordSummaryView> = withContext(ioDispatcher) {
        mapErrors {
            val block = ffiReadBlock(identity, manifest, blockUuid, includeDeleted)
            openBlocks += block                       // NO .use{} — kept alive until wipe()
            val count = block.recordCount().toInt()
            (0 until count).map { i ->
                val rec = block.recordAt(i.toULong())
                    ?: throw VaultBrowseError.CorruptVault("recordAt($i) returned null")
                toRecordView(rec)
            }
        }
    }

    private fun toRecordView(rec: Record): RecordSummaryView {
        val fieldCount = rec.fieldCount().toInt()
        val fields = (0 until fieldCount).map { j ->
            val h = rec.fieldAt(j.toULong())
                ?: throw VaultBrowseError.CorruptVault("fieldAt($j) returned null")
            val kind = if (h.isText()) FieldKind.Text else FieldKind.Bytes
            RevealableField(name = h.name(), kind = kind) {
                // expose_* ON DEMAND; the owning BlockReadOutput is retained in openBlocks.
                when (kind) {
                    FieldKind.Text -> RevealedValue.Text(
                        h.exposeText() ?: throw VaultBrowseError.CorruptVault("text expose failed"))
                    FieldKind.Bytes -> RevealedValue.Bytes(
                        h.exposeBytes() ?: throw VaultBrowseError.CorruptVault("bytes expose failed"))
                }
            }
        }
        return RecordSummaryView(/* metadata */, fields = fields)
    }

    override fun wipe() {
        openBlocks.forEach { it.wipe() }   // cascade zeroize to records + fields, FIRST
        openBlocks.clear()
        manifest.wipe()
        identity.wipe()                    // identity LAST (order mirrors iOS)
    }
}
```

- An in-range `null` from `recordAt`/`fieldAt` on a freshly-decrypted block is treated as
  **corruption** (`VaultBrowseError.CorruptVault`), never a silent drop — mirror of iOS.
- `BrowseMapping.kt` keeps `mapVaultBrowseError` / `mapBlockSummary` unchanged. The
  metadata-extraction part of `toRecordView` can be host-tested via the existing mapper-test
  pattern; the actual `expose_*` is FFI and is proven by the on-device smoke (§Testing).
- `UniffiVaultOpenPort` / `uniffiVaultOpenPort()` factory unchanged.

### Section 3 — Browse UI (`:browse-ui`, package `org.secretary.browse.ui`)

`VaultBrowseViewModel` **gains** reveal forwarding:

```kotlin
class VaultBrowseViewModel(model: VaultBrowseModel) : ViewModel() {
    // ...existing flows unchanged...
    val revealed: StateFlow<Map<String, RevealedValue>> = model.revealed
    fun reveal(record: RecordSummaryView, field: RevealableField) = model.reveal(record, field)
    fun hide(recordUuidHex: String, fieldName: String) = model.hide(recordUuidHex, fieldName)
    fun hideAll() = model.hideAll()
}
```

`BrowseScreen` field rows gain a reveal/hide affordance and an auto-hide timer:

```kotlin
@Composable
fun BrowseScreen(
    viewModel: VaultBrowseViewModel,
    autoHideMillis: Long = RevealPolicy.autoHideSeconds * MILLIS_PER_SECOND, // injectable for tests
)
```

- A field row shows `name` + kind, and a reveal toggle. When revealed it shows the value:
  text as-is; bytes as hex via the existing `hexOfBytes` helper.
- **Auto-hide** uses `LaunchedEffect(revealKey) { delay(autoHideMillis); viewModel.hide(...) }`
  — the effect is keyed on the reveal so re-revealing restarts the timer. `autoHideMillis` is
  an injectable screen parameter so the instrumented Compose UI test injects a short value
  instead of waiting 30 s (mirror of iOS, where auto-hide is the view layer driving the
  unit-tested `hide` seam).
- Pure render helpers (host-tested) gain `revealedText(value: RevealedValue): String`
  (text → as-is; bytes → hex) and a per-field label helper; `recordTitle` / `blockLabel`
  unchanged.

### Section 4 — App wiring (`:app`)

**Unchanged.** Slice 7 already binds the `ON_STOP` lifecycle observer that calls
`model.lock()` and routes to `Route.Unlock`. `lock()` now also clears the reveal map, so
revealed values vanish on background with no new `:app` wiring. `MainActivity` keeps
`FLAG_SECURE`. `unlockAndBrowse` and the route are untouched.

## Testing (TDD — test first per task)

- **Host JUnit5 `:vault-access`** —
  - `RevealedValue` / `RevealableField` / `RevealPolicy` value-type tests
    (`Bytes.equals` via `contentEquals`; `autoHideSeconds == 30`).
  - `VaultBrowseModelTest` (extended): `reveal` populates `revealed` with the field's
    canned value; `hide` removes one key; `hideAll` clears; `selectBlock`/`clearSelection`/
    `lock` each clear `revealed` first; a `reveal` lambda that throws routes to `error`.
  - `FakeVaultSession` gains `RevealableField`s with canned reveal lambdas.
- **Host JUnit5 `:kit`** — `BrowseMappingTest` extended for `FieldKind` mapping
  (`isText` → `Text` / `Bytes`); a fake-`Record`-driven test that `toRecordView` builds one
  `RevealableField` per `fieldAt` and surfaces an in-range `null` as `CorruptVault`. (The real
  `expose_*` is FFI — proven on-device.)
- **Host JUnit5 `:browse-ui`** — `VaultBrowseViewModelTest` extended (reveal/hide/hideAll
  forward to model; `revealed` flow re-exposed) + `BrowseRenderHelpersTest` extended
  (`revealedText`: text as-is, bytes as hex).
- **Instrumented JUnit4 Compose UI `:browse-ui`** (NEW) — drive `BrowseScreen` with a fake
  ViewModel/model: tap a field → its value node appears; tap hide → value node gone;
  inject a short `autoHideMillis` → value node disappears after the delay.
- **Instrumented JUnit4 `:app`** (real `.so`, arm64 emulator) — extend the smoke:
  open `golden_vault_001`, read a block, **reveal a known field, assert the exposed
  plaintext** (proves the real `expose_*` path end-to-end on device). Exact assertion value
  is read from the golden vault's known contents during implementation; if no field value is
  reliably known, fall back to asserting non-empty + correct `FieldKind`. The slice-7
  `OpenBrowseSmokeTest` (happy path + wrong-password) stays green.

## Acceptance

```bash
cd android && ./gradlew :vault-access:test :kit:testDebugUnitTest :browse-ui:test :app:test
#   → BUILD SUCCESSFUL (host JUnit5, no emulator/NDK)
cd android && ./gradlew :browse-ui:connectedDebugAndroidTest :app:connectedDebugAndroidTest
#   → BUILD SUCCESSFUL: Compose reveal UI test + reveal smoke green on the arm64 emulator (real .so)
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)'   # empty
git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'                # empty
```

## Deferred (named, not lost)

- **Show-deleted toggle**, swipe delete/restore, edit sheet (iOS browse parity).
- **Recovery-phrase and device-secret open paths** (this slice stays password-only).
- **Sync-badge re-integration** onto `BrowseScreen` (`AppSyncStateDir` is retained for this).
- **On-device veto round-trip** still needs a seeded concurrent state
  ([[project_secretary_sync_veto_needs_seeded_state]]); unrelated to reveal but carried.
- **Optional `WorkManager` background detection** (deferred from slice 3).

## Risks / notes

- **A revealed value lands in a Kotlin `String`/`ByteArray`** (non-zeroizable — same
  documented residue limitation as iOS and the unlock password field). Mitigation: keep the
  reveal map as small and short-lived as possible (cleared on hide / auto-hide / reload /
  lock); `RevealedValue.Bytes` callers should `fill(0)` their copies where feasible. The
  underlying `SecretString`/`SecretBytes` in the `FieldHandle` is **not** wiped by an
  `expose_*` call; it is wiped by `BlockReadOutput.wipe()` on `lock()`.
- **Retaining open blocks means the whole selected block's plaintext is decrypted in
  memory** (in zeroize-typed `SecretString`/`SecretBytes`) until `lock()`/wipe. Accepted in
  brainstorming: the master key is resident regardless, so this is not a meaningful
  additional exposure (see Decision 1). Documented so a future reader doesn't "fix" it back
  to per-reveal re-decrypt.
- **Lock-on-background wipes the whole session** → returning from background re-prompts for
  the password (one more Argon2id). Matches iOS lock semantics; documented so it isn't
  "optimized" into a weaker keep-alive.
- **`RecordSummaryView` is no longer a `data class`** (it holds reveal closures). Tests must
  assert on `uuidHex` / `type` / `fieldNames` / `tombstone`, not on structural `==`. The name
  is retained from slice 7 for continuity even though the type now carries reveal capability.
- A reviewer should confirm the **only** `expose_text`/`expose_bytes` call sites are inside
  the `RevealableField.reveal` lambda in `:kit` — the secret-pull boundary stays a single,
  auditable location.
