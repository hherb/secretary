# Android Trash browser — retention/purge/empty-trash parity (minus settings)

**Date:** 2026-07-11
**Status:** Approved (design), ready for implementation plan
**Branch:** `feature/android-trash-browser` (off `main` @ `d235c592`, after #412 merged)
**Sub-project:** D (platform UIs) — Android native (Jetpack Compose over uniffi)

## Summary

Build the **native Android (Jetpack Compose) Trash browser** — the Android mirror of the
already-shipped, already-reviewed iOS Trash browser (#412) and desktop reference (#409/#410).
Feature scope is identical to iOS: list trashed blocks, restore, delete-forever, empty-trash, and
run-retention-now against the **fixed 90-day default** — **minus** the retention-window *setting*
(deferred, same as iOS; needs a settings subsystem, see "Out of scope").

**This slice adds NO new FFI, NO `core`/crypto/on-disk-format change, NO new `VaultBrowseError`
variant, NO `manifest_version` bump. `#![forbid(unsafe_code)]` intact.** Every trash/retention
function is already projected on the Kotlin uniffi surface (`list_trashed_blocks`,
`expired_trash_entries`, `auto_purge_expired`, `purge_block`, `empty_trash`, `restore_block`,
`default_retention_window_ms`), live since #402/#399/#406. This is pure downstream Android consumption.

## Reference (parity source)

The iOS slice is the authoritative reference; the Android build is a faithful mirror:

- Pure value types + port: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/TrashModels.swift`
- Pure formatting helpers: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/TrashFormatting.swift`
- Host-tested VM: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/TrashViewModel.swift`
- Real adapter: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSession+Trash.swift`
- SwiftUI screen: `ios/SecretaryApp/Sources/TrashScreen.swift`

The Android equivalents mirror the existing Android browse layering (`VaultBrowseModel` /
`UniffiVaultSession` / `BrowseScreen`), not iOS structure verbatim — Compose idioms and Kotlin
visibility rules differ from SwiftUI/Swift.

## Requirements

Functional (parity with iOS #412):

1. **List** all not-yet-purged trashed blocks, newest-first by tombstone time, each showing the
   block name + "trashed `yyyy-MM-dd`".
2. **Restore** one trashed block (`restore_block`) — per-row action, behind the write-reauth gate.
3. **Delete forever** one trashed block (`purge_block`) — per-row action, confirm dialog, gated.
4. **Empty trash** (`empty_trash`) — top-bar action, shown only when the list is non-empty, single
   confirm, gated.
5. **Run retention now** — preview the expired set (`expired_trash_entries`) against the fixed
   90-day default (`default_retention_window_ms`), then commit (`auto_purge_expired`). The preview
   is an **ungated read**; the commit is gated.
6. Reached from a **Trash action on the browse top bar** (visible with the block list).

Non-functional / invariants (must be preserved and provable):

- **No record plaintext crosses the FFI boundary for trash ops.** Only block names + counts. The
  adapter never calls a decrypt / read-record FFI function.
- **Every destructive write is gated**; `previewRetention` / `listTrashedBlocks` are provably
  ungated reads.
- **Reports are discarded** (parity with iOS/desktop): the reloaded/updated list is the success
  signal. The `TrashPort` returns the report DTOs (ready for #411), but the VM discards them.
  Surfacing "Purged N items" is the separate cross-platform issue #411 — out of scope here.
- Trash ops honor the **same `sessionLock` + `wiped` guard** as existing session writes.
- **No new `VaultBrowseError` / no new FFI error variant / no format / no `manifest_version` change.**

## Architecture (bottom-up, one concept per file)

### 1. `:vault-access` — pure, host-tested (JVM, no emulator)

Package `org.secretary.browse` (alongside the existing browse models).

**`TrashModels.kt`** — value types + the port interface:

- `data class TrashedBlockInfo(blockUuid: ByteArray, blockName: String, tombstonedAtMs: Long,
  tombstonedBy: ByteArray)` with a `uuidHex` computed property (lowercase, no dashes — stable
  Compose `key`). `equals`/`hashCode` hand-written (ByteArray) per the existing `RenameBlock` idiom.
- `data class ExpiredEntryInfo(blockUuid: ByteArray, tombstonedAtMs: Long, ageMs: Long)`.
- `data class PurgeResultInfo(blockUuid: ByteArray, wasShared: Boolean?, recipientCount: Int?,
  filesRemoved: Int)`.
- `data class EmptyTrashReportInfo(purgedCount, sharedCount, ownerOnlyCount, unknownCount,
  filesRemoved, filesFailed: Int)`.
- `data class RetentionReportInfo(...same six... + windowMs: Long)`.
- `interface TrashPort` — 7 methods mirroring the Swift protocol:
  - `fun listTrashedBlocks(): List<TrashedBlockInfo>` (throws `VaultBrowseError`)
  - `fun expiredTrashEntries(windowMs: Long): List<ExpiredEntryInfo>` (non-throwing; adapter
    supplies `now`)
  - `fun defaultRetentionWindowMs(): Long`
  - `suspend fun restoreBlock(uuid: ByteArray)` (throws)
  - `suspend fun purgeBlock(uuid: ByteArray): PurgeResultInfo` (throws)
  - `suspend fun emptyTrash(): EmptyTrashReportInfo` (throws)
  - `suspend fun autoPurgeExpired(windowMs: Long): RetentionReportInfo` (throws)

  Write methods are `suspend` (the real adapter offloads the FFI write to the IO dispatcher, like
  `VaultSession.tombstoneRecord`). `listTrashedBlocks` and `expiredTrashEntries` are synchronous
  reads (in-memory manifest metadata; mirror `blockSummaries()`).

  > **Kotlin numeric note:** uniffi projects the Rust `u64`/`u32`/`u16` as Kotlin `ULong`/`UInt`/
  > `UShort`. The pure value types use signed `Long`/`Int` for idiomatic host-test ergonomics; the
  > `:kit` adapter does the `.toLong()`/`.toInt()` narrowing at the FFI boundary (ms timestamps and
  > counts are far below the signed ceiling). This mirrors how the existing `BlockSummaryView` holds
  > `Long` while the uniffi `BlockSummary` yields `ULong`.

**`TrashFormatting.kt`** — pure free functions, exact parity with iOS/desktop:

- `const val MS_PER_DAY = 86_400_000L`
- `fun msToDays(ms: Long): Long = (ms + MS_PER_DAY / 2) / MS_PER_DAY` (integer round-half-up,
  parity with desktop `Math.round(ms / MS_PER_DAY)` and iOS `msToDays`).
- `fun sortTrashed(entries: List<TrashedBlockInfo>): List<TrashedBlockInfo>` — newest-first by
  `tombstonedAtMs` (`sortedByDescending`).
- `fun formatTrashedWhen(ms: Long): String` — absolute `yyyy-MM-dd` in **UTC** via a fixed
  `DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(ZoneOffset.UTC)` over
  `Instant.ofEpochMilli(ms)`. Deliberately deterministic (fixed pattern + UTC) so the helper is
  host-testable without a fixed clock/zone. **Same UTC trade-off + #413 caveat as iOS** (a block
  trashed near local midnight can render the adjacent calendar day; locale-aware parity tracked in
  #413). Document this in the KDoc verbatim to the iOS note.
- `fun emptyTrashConfirmBody(count: Int): String` — parity: `"The 1 item"` vs `"All N items"` +
  `" in trash will be permanently deleted. This cannot be undone."`.
- `fun retentionSummary(entries: List<ExpiredEntryInfo>, windowMs: Long): String` — parity: empty →
  `"No trashed items are older than {days} days."`; else
  `"{n} {item|items} trashed more than {days} days ago will be permanently deleted (oldest:
  {oldestDays} days)."` where `oldestDays = msToDays(entries.maxOf { ageMs })`.

**`TrashBrowseModel.kt`** — host-tested VM, `StateFlow`-based, mirroring `VaultBrowseModel`'s
`guardedWrite` re-entrancy + reauth discipline:

- Constructor: `TrashBrowseModel(port: TrashPort, gate: WriteReauthGate = NoopReauthGate)`.
- Flows: `entries: StateFlow<List<TrashedBlockInfo>>`, `error: StateFlow<VaultBrowseError?>`,
  `writing: StateFlow<Boolean>`, `preview: StateFlow<List<ExpiredEntryInfo>?>`.
- `val retentionWindowMs: Long get() = port.defaultRetentionWindowMs()`.
- `fun load()` — `entries = sortTrashed(port.listTrashedBlocks())`; typed failure → `error`.
- `fun previewRetention()` — **ungated**: `preview = port.expiredTrashEntries(port.defaultRetentionWindowMs())`.
- `fun clearPreview()` — `preview = null` (stale-flash guard when the sheet reopens — iOS parity).
- `suspend fun restore(uuid)`, `suspend fun purge(uuid)`, `suspend fun emptyTrash()`,
  `suspend fun runRetention()` — each routes through a private `guardedWrite(reason) { ... }` that
  mirrors `VaultBrowseModel.guardedWrite`:
  - `if (writing) return`; set `_writing = true` **before** the gate await; `finally { _writing = false }`.
  - `gate.authorizeWrite(reason)`; `DeviceUnlockError.UserCancelled` → silent return (no error, no
    write); other `DeviceUnlockError` → `error = ReauthFailed(...)`, return. **`CancellationException`
    must NOT be caught** (copy the `VaultBrowseModel` catch-ordering comment verbatim).
  - Run the op; typed `VaultBrowseError` → `error`, return (list untouched). Success → `load()`
    (reload) and the report is discarded.
  - Reason strings mirror iOS: `"Confirm restoring this block"`, `"Confirm permanently deleting this
    block"`, `"Confirm permanently deleting all trashed blocks"`, `"Confirm permanently deleting
    expired trash"`.

**Tests (`:vault-access/src/test`):**

- `FakeTrashPort.kt` — records calls, returns seeded lists/reports, can be primed to throw a typed
  `VaultBrowseError` per method; a settable `reauthGate` double. Mirror of iOS `FakeTrashPort`.
- `TrashBrowseModelTest.kt` — gate parity (cancel → silent, no reload; failure → error, list
  intact), re-entrancy (`writing` blocks a concurrent op), report-discard (success reloads the
  list), preview is ungated + `clearPreview`.
- `TrashFormattingTest.kt` — `msToDays` round-half-up boundary, `sortTrashed`, `formatTrashedWhen`
  UTC KATs, `emptyTrashConfirmBody` singular/plural, `retentionSummary` empty/one/many + oldest.

### 2. `:kit` — real adapter over the generated bindings

Conform the real `UniffiVaultSession` to `TrashPort` **in the class body** of
`UniffiVaultOpenPort.kt` (declaration becomes `class UniffiVaultSession(...) : VaultSession,
TrashPort`). This is the functional analogue of iOS `UniffiVaultSession+Trash.swift` — but see the
**Kotlin conformance constraint** below for why it is in-class rather than a separate extension file:

- `listTrashedBlocks()` → `uniffi.secretary.listTrashedBlocks(identity, manifest)` under the read
  path (mirror `blockSummaries()`'s `synchronized(sessionLock)` + `wiped` empty-return + `mapErrors`),
  mapping each `TrashedBlock` to `TrashedBlockInfo` (`.toLong()` on `tombstonedAtMs`).
- `expiredTrashEntries(windowMs)` → `uniffi.secretary.expiredTrashEntries(manifest, windowMs.toULong(),
  System.currentTimeMillis().toULong())`, mapped to `ExpiredEntryInfo`. **Ungated, non-throwing**
  (returns `emptyList()` if `wiped`).
- `defaultRetentionWindowMs()` → `uniffi.secretary.defaultRetentionWindowMs().toLong()`.
- `restoreBlock` / `purgeBlock` / `emptyTrash` / `autoPurgeExpired` → route through the session's
  existing `write { dev, now -> ... }` helper (device-uuid + now resolution, `sessionLock`, `wiped`
  guard, `mapErrors`), returning the mapped report DTO for the write-returning ones.

  > **Kotlin conformance constraint (why in-class, no visibility widening):** unlike Swift —
  > where `extension UniffiVaultSession: TrashPort` in a separate file provides the conformance —
  > **Kotlin cannot satisfy an interface via extension functions.** Interface `override` members
  > MUST live in the class body. So the 7 `TrashPort` overrides go directly into `UniffiVaultSession`,
  > where they see the `private` `identity` / `manifest` / `write` / `sessionLock` / `wiped` members
  > for free. **No member is widened to `internal`** — the security-sensitive handles stay `private`.
  > This is *stricter* than the iOS build (which widened to `internal` for its extension file); the
  > Android build keeps the handles fully encapsulated. Cost: `UniffiVaultOpenPort.kt` grows ~60
  > lines (289 → ~350, well under the 500-line guideline) and hosts the trash concern alongside the
  > session. The lock-discipline invariant still holds verbatim — every trash op reuses the existing
  > `write`/read-guard, adding no new handle-access pattern (carry this as a comment on the trash
  > block of overrides).

**`BrowseMapping.kt`** — add two explicit arms above the `else` fold (per the file's MAINTAINER
WARNING — a new op-relevant arm gets an explicit branch, never the silent `Failed` fold):

```kotlin
is VaultException.BlockNotInTrash -> VaultBrowseError.BlockNotFound(e.detail)
is VaultException.BlockPurged     -> VaultBrowseError.BlockNotFound(e.detail)
```

Parity with iOS mapping `BlockNotInTrash`/`BlockPurged` → `.blockNotFound`. Reuses the existing
`BlockNotFound` arm — **no new `VaultBrowseError` case**. (Note: `VaultException.BlockNotFound`
carries `uuidHex`; `BlockNotInTrash`/`BlockPurged` carry `detail` — pass `e.detail` into the
`BlockNotFound(uuidHex: String)` payload, which is a free-text identifier field, acceptable for a
best-effort "this block is gone" surface.)

### 3. `:browse-ui` — Compose UI

**`TrashScreen.kt`** (package `org.secretary.browse.ui`, alongside `BrowseScreen.kt`):

- `@Composable fun TrashScreen(model: TrashBrowseModel, onBack: () -> Unit)`. Collects the flows
  via `collectAsState()`. `LaunchedEffect(Unit) { model.load() }`.
- `Scaffold` + `TopAppBar` with:
  - a back navigation icon (`onBack`),
  - an **Empty-trash** action, shown only when `entries.isNotEmpty()`, → `AlertDialog`
    (`emptyTrashConfirmBody(entries.size)`) → `model.emptyTrash()`,
  - a **Run-retention-now** action → opens the retention `ModalBottomSheet`.
- Body: `LazyColumn` over `entries` keyed by `uuidHex`. Empty state: a centered "Trash is empty"
  message. Each row: block name + `"trashed ${formatTrashedWhen(it.tombstonedAtMs)}"`, with
  **trailing Restore (↺) + Delete-forever (🗑) icon buttons**. Restore → `model.restore(uuid)`
  (immediate, gated). Delete-forever → `AlertDialog` confirm → `model.purge(uuid)`. All row buttons
  disabled while `writing`.
- **Retention `ModalBottomSheet`** (material3): on open, `model.previewRetention()`; shows
  `retentionSummary(preview ?: emptyList(), retentionWindowMs)` (loading state while `preview ==
  null`); a **Purge-expired** confirm button → `model.runRetention()`; `Cancel`/dismiss →
  `model.clearPreview()`. On `onDismiss`, `clearPreview()` (stale-flash guard, iOS parity).
- Errors: surface `error` via the existing browse error affordance (Snackbar/text — match
  `BrowseScreen`'s pattern for consistency).

Compose UI is exercised by `:browse-ui/src/androidTest` instrumented tests (mirror
`BrowseScreenSoftDeleteTest`) over a `FakeTrashPort`-backed model — a stretch/nice-to-have; the
host-tested VM carries the logic coverage. (Confirm scope in the plan; the load-bearing tests are
the host `:vault-access` ones.)

### 4. `:app` — entry wiring

- Add a **Trash action to the browse top bar** in the browse-with-sync composition
  (`BrowseWithSyncScreen.kt` / wherever the browse `TopAppBar` is assembled), visible when the block
  list is shown (no block selected), navigating to `TrashScreen`.
- Wire the real `TrashPort` (the live `UniffiVaultSession`, which now conforms) + the existing
  `GraceWindowReauthGate` used by the browse write path. Mirror iOS's `makeTrashViewModel()` factory
  placement — construct the `TrashBrowseModel` at the navigation boundary from the already-open
  session + gate. **No new session; no second FFI open.**
- Cross-module `when` discipline: no new sealed arm is introduced, so no `:app`/`:kit` exhaustive-
  `when` breakage (contrast [[project_secretary_android_sealed_when_cross_module]]). Still build
  `:app` in the same task per [[project_secretary_conformance_scripts_dont_compile_kit]].

## Out of scope (deferred, tracked)

- **Retention-window *setting*** (per-vault, replacing the fixed 90-day default): needs vault-settings
  read/write projected on uniffi (`retention_window_ms`) + an Android Settings screen (none exists) —
  a settings-subsystem introduction, filed as its own slice (mirror of the deferred iOS half; see
  [[project_secretary_ios_settings_ffi_gap]]).
- **Surfacing purge counts** ("Purged N items") from the report DTOs → cross-platform issue **#411**
  (the `TrashPort` DTOs are plumbed and ready).
- **Locale-aware trashed-date** (vs the UTC `yyyy-MM-dd` used here) → **#413** (cross-platform with iOS).
- Manual GUI smoke on-device/emulator against a **temp copy** of a staged vault with old trash
  (settings live in the vault — [[feedback_smoke_test_temp_copy_golden_vault]]) + a biometric
  spot-check on the destructive ops — human-only.

## Testing strategy

- **Load-bearing:** `:vault-access` host `test` (JVM, no emulator) — `TrashBrowseModelTest` (gate
  parity, re-entrancy, report-discard, ungated preview), `TrashFormattingTest` (formatting KATs).
- **Compile gates (same task):** `:kit`, `:browse-ui`, `:app` must all compile after the FFI-adapter
  + UI additions (Kotlin won't flag a non-exhaustive `when` regression across modules, and a uniffi
  return-shape consumer can compile in isolation while `:app` breaks —
  [[project_secretary_conformance_scripts_dont_compile_kit]]).
- **No Rust change** — no need to run the Rust workspace suite beyond confirming `core`/`ffi` were
  not touched. The `BrowseMapping.kt` arms consume existing `VaultException.BlockNotInTrash`/
  `BlockPurged` variants already on the Kotlin surface.
- **Optional:** a `:browse-ui` instrumented `TrashScreen` test over `FakeTrashPort` (nice-to-have;
  decide in the plan).

## Risks & open decisions

1. **`:kit` `TrashPort` conformance is in-class, no visibility widening** — Kotlin cannot conform to
   an interface via an extension file (unlike Swift), so the 7 overrides live in the
   `UniffiVaultSession` class body and keep `identity`/`manifest`/`write`/`sessionLock`/`wiped`
   fully `private`. Stricter than the iOS build (which widened to `internal`). **Resolved.**
2. **Report discard** — deliberate parity cut; #411 surfaces counts cross-platform later. The DTOs
   are plumbed now so #411 is UI-only.
3. **UTC trashed-date** — deliberate (host-testable pure helper); #413 for locale-aware parity.
4. **Signed `Long`/`Int` in pure types vs uniffi `ULong`/`UInt`** — narrowing at the adapter
   boundary; ms + counts are well below the signed ceiling (mirrors existing `BlockSummaryView`).
5. **Instrumented UI test scope** — the host VM tests are load-bearing; the Compose instrumented
   test is a nice-to-have decided in the plan.

## Acceptance

- Feature parity with iOS #412 (list / restore / delete-forever / empty-trash / run-retention @ 90d)
  reachable from a browse top-bar Trash action, all destructive ops gated, preview ungated.
- No new FFI, no `core`/crypto/format change, no new `VaultBrowseError` variant, no `manifest_version`
  bump, `#![forbid(unsafe_code)]` intact.
- `:vault-access` host `test` green; `:kit` + `:browse-ui` + `:app` compile green.
- Reports discarded (parity); DTOs plumbed for #411.
