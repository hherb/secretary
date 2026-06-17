# C.3 Android slice 7 — vault open/browse port + metadata-only browse screen

**Date:** 2026-06-17
**Status:** Approved design (brainstorm complete)
**Branch:** `feature/c3-android-open-browse` (worktree `.worktrees/c3-android-open-browse`)
**Base:** `main` @ `965fbd7` (slice 6 merged as #248)

## Goal

The first Android slice where the user can **open** a vault, not just sync it. After
unlock, the app calls `open_vault_with_password`, then shows a Compose `BrowseScreen`
that lists the vault's blocks and, for a selected block, the contained records'
titles/types/tags — **metadata only, no secret values**. This proves the
open → read → render pipeline end-to-end on-device against the staged
`golden_vault_001` reference vault.

This mirrors the iOS open/browse architecture (`VaultOpenPort` / `VaultSession` /
`VaultBrowseViewModel`) but delivers only the metadata-first layer; reveal-on-tap and
the full secret lifecycle are deferred (see **Deferred**).

## Key scope finding: no `ffi/` or Rust changes

The entire open/browse FFI surface is **already exposed via uniffi** and used by iOS:

- `open_vault_with_password(folder_path, password) -> OpenVaultOutput` (`identity` + `manifest`)
- `OpenVaultManifest.block_count()` / `.block_summaries()` / `.find_block(uuid)`
- `read_block(identity, manifest, block_uuid, include_deleted) -> BlockReadOutput`
- `BlockReadOutput.record_count()` / `.record_at(idx)` → `Record`
- `Record.record_uuid()` / `.record_type()` / `.tags()` / `.created_at_ms()` /
  `.last_mod_ms()` / `.tombstone()` / `.field_names()` (metadata; **no `expose_*`**)

`:kit`'s Gradle build already runs `uniffi-bindgen` over the whole `secretary.udl`, so
the Kotlin bindings for `OpenVaultManifest` / `BlockReadOutput` / `Record` / `FieldHandle`
are already generated. This is therefore a **pure Kotlin-port + Compose-UI slice** —
no edits under `core/`, `ffi/`, or `ios/`, and no on-disk format change.

## Decisions (locked in brainstorming)

1. **Metadata-only browse.** This slice lists blocks + record titles/types/tags/field-names.
   It NEVER calls `expose_text`/`expose_bytes`. Smallest secret-handling surface; matches
   the slice-6 baton's stated acceptance ("list record titles … reveal-on-tap later").
2. **Browse-only post-unlock flow.** Unlock → `open_vault_with_password` →
   `BrowseScreen`. One Argon2id at unlock. Mirrors iOS, where sync is on-demand, not
   at-unlock. The existing sync flow (`:sync-ui`, `makeVaultSync`, `SyncScreen`, their
   tests) stays in the repo but is **not wired into `:app`'s route this slice**.
3. **New `:browse-ui` module** for the browse Compose UI, parallel to `:sync-ui`,
   depending only on `:vault-access`. No churn to existing `:sync-ui`. `:app` depends on
   both.
4. **Lock-on-background.** `ON_STOP` wipes the session (`model.lock()`) and returns to
   Unlock; re-entry requires the password again. `FLAG_SECURE` is already set on the
   activity. No folder monitor in this browse-only flow.

## Architecture

Layering follows the established Android stack
(`:vault-access` pure → `:kit` FFI adapter → UI module → `:app`).

### Section 1 — Pure seam (`:vault-access`, package `org.secretary.browse`)

Host-tested (JUnit5) with fakes; no Android or FFI dependencies. Mirrors iOS's pure seam.

```kotlin
interface VaultOpenPort {
    suspend fun openWithPassword(vaultFolder: String, password: ByteArray): VaultSession
}

interface VaultSession {
    fun vaultUuidHex(): String
    fun blockSummaries(): List<BlockSummaryView>
    fun readBlock(blockUuid: ByteArray, includeDeleted: Boolean): List<RecordSummaryView>
    fun wipe()
}

class BlockSummaryView(
    val uuid: ByteArray,            // raw 16 bytes — needed to call read_block
    val name: String,
    val createdAtMs: ULong,
    val lastModifiedMs: ULong,
) {
    val uuidHex: String get() = uuid.joinToString("") { "%02x".format(it) }
    // NOT a data class: a data class over a ByteArray gives referential equals/hashCode.
    // Identity for tests/UI keys is uuidHex; equals/hashCode (if needed) derive from it.
}

data class RecordSummaryView(
    val uuidHex: String,
    val type: String,
    val tags: List<String>,
    val createdAtMs: ULong,
    val lastModMs: ULong,
    val tombstone: Boolean,
    val fieldNames: List<String>,   // names are metadata; values are NOT read this slice
)

// Throwable (mirrors VaultSyncError : Exception) so the model can `catch (e: VaultBrowseError)`.
sealed class VaultBrowseError(message: String? = null) : Exception(message) {
    data object WrongPasswordOrCorrupt : VaultBrowseError()      // VaultException.WrongPasswordOrCorrupt
    data object VaultMismatch : VaultBrowseError()               // VaultException.VaultMismatch
    data class CorruptVault(val detail: String) : VaultBrowseError(detail)   // VaultException.CorruptVault
    data class FolderInvalid(val detail: String) : VaultBrowseError(detail)  // VaultException.FolderInvalid
    data class BlockNotFound(val uuidHex: String) : VaultBrowseError(uuidHex) // VaultException.BlockNotFound
    data class InvalidArgument(val detail: String) : VaultBrowseError(detail) // VaultException.InvalidArgument
    data class Failed(val detail: String) : VaultBrowseError(detail)          // else-fold (toString)
}
```

`VaultBrowseModel` — the pure coordinator (main-thread-confined, mirrors iOS
`VaultBrowseViewModel`'s coordinator role; the single owner of the `VaultSession`):

```kotlin
class VaultBrowseModel(private val session: VaultSession) {
    val blocks: StateFlow<List<BlockSummaryView>>
    val selectedBlock: StateFlow<BlockSummaryView?>
    val selectedRecords: StateFlow<List<RecordSummaryView>?>
    val error: StateFlow<VaultBrowseError?>

    fun loadBlocks()                               // reads manifest summaries (no decryption)
    suspend fun selectBlock(block: BlockSummaryView) // read_block → records (metadata only)
    fun clearSelection()                           // back to block list
    fun lock()                                     // session.wipe() + clear all state
}
```

- `loadBlocks()` is synchronous (manifest summaries are already decrypted in memory).
- `selectBlock` is `suspend` (defensive — `read_block` touches disk/AEAD; keep it
  off the hot path consistent with the sync port's IO discipline). Records are
  metadata-only views; no field plaintext is materialized.
- `lock()` wipes the session and resets every `StateFlow` to its empty state.

### Section 2 — Real adapter (`:kit`, package `org.secretary.browse`)

Only place that imports `uniffi.secretary.*` for the browse path. Mirrors
`UniffiVaultSyncPort` patterns (injected-fn seam for host mapper tests, IO offload of
Argon2id).

```kotlin
class UniffiVaultOpenPort(
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val openFn: (ByteArray, ByteArray) -> OpenVaultOutput = ::openVaultWithPassword,
) : VaultOpenPort {
    override suspend fun openWithPassword(vaultFolder: String, password: ByteArray): VaultSession
    // runs openFn on ioDispatcher (Argon2id); maps VaultException -> VaultBrowseError;
    // wraps OpenVaultOutput in UniffiVaultSession
}

class UniffiVaultSession(output: OpenVaultOutput) : VaultSession {
    // owns UnlockedIdentity + OpenVaultManifest
    override fun vaultUuidHex(): String
    override fun blockSummaries(): List<BlockSummaryView>
    override fun readBlock(blockUuid: ByteArray, includeDeleted: Boolean): List<RecordSummaryView>
        // calls uniffi readBlock(identity, manifest, blockUuid, includeDeleted);
        // maps Record metadata + field_names() -> RecordSummaryView; NEVER calls expose_*
    override fun wipe()  // cascade-wipe manifest + identity (+ any retained block output)
}
```

Pure DTO mappers extracted as free functions and host-tested:

- `mapBlockSummary(uniffi BlockSummary) -> BlockSummaryView`
- `mapRecord(Record) -> RecordSummaryView`
- `mapVaultException(VaultException) -> VaultBrowseError`

`:kit` exposes a factory `uniffiVaultOpenPort(): VaultOpenPort` for `:app` to obtain the
real port.

### Section 3 — Browse UI (new `:browse-ui` module, package `org.secretary.browse.ui`)

Compose library, depends only on `:vault-access` (FFI-free, like `:sync-ui`).

```kotlin
class VaultBrowseViewModel(private val model: VaultBrowseModel) : ViewModel() {
    val blocks: StateFlow<List<BlockSummaryView>> = model.blocks
    val selectedBlock: StateFlow<BlockSummaryView?> = model.selectedBlock
    val selectedRecords: StateFlow<List<RecordSummaryView>?> = model.selectedRecords
    val error: StateFlow<VaultBrowseError?> = model.error

    fun loadBlocks()
    fun selectBlock(block: BlockSummaryView)  // launches model.selectBlock in viewModelScope
    fun back()                                 // model.clearSelection()
}

@Composable fun BrowseScreen(viewModel: VaultBrowseViewModel)
```

- `BrowseScreen`: when no block selected, render the block list (tap → `selectBlock`);
  when a block is selected, render its record-title list with a back affordance to the
  block list. Stateless sub-composables (`BlockRow`, `RecordRow`).
- Pure render helpers (host-tested), no clock/side-effects:
  - `recordTitle(record: RecordSummaryView): String` — human label (type, first tag if any)
  - `blockLabel(block: BlockSummaryView): String`
  - relative-time formatting for created/modified (a small pure helper; may copy the
    `:sync-ui` `relativeSyncedLabel` shape rather than create a cross-module dependency)

### Section 4 — App wiring (`:app`)

- `AppRoot` route: replace `Route.Sync(...)` with `Route.Browse(viewModel)`.
- Unlock coroutine (`unlockAndOpen`, replacing `unlockAndSync`):
  1. `AppVaultProvisioning.stageGoldenVault(context)` (unchanged; crash-safe staging)
  2. `val port = uniffiVaultOpenPort()`
  3. `val session = port.openWithPassword(folder.path, password)` (Argon2id on IO)
  4. `val model = VaultBrowseModel(session); model.loadBlocks()`
  5. `Route.Browse(VaultBrowseViewModel(model))`
  - `finally { password.fill(0) }` — zeroize on **every** exit (success, error, early throw).
  - provisioning/open failure → log + return to `Route.Unlock` (no uncaught-coroutine crash).
- **Lock-on-background:** the `Route.Browse` composition binds a lifecycle observer;
  `ON_STOP` calls `model.lock()` (session wipe) and sets `route = Unlock`.
- `MainActivity` keeps `FLAG_SECURE`. No folder monitor in this flow.
- `:sync-ui`, `makeVaultSync`, `SyncScreen`, and their tests remain in the repo and on
  the build path (still compiled, still host/instrumented-tested); they are simply not
  referenced by `AppRoot` this slice. Re-integrating a sync badge onto `BrowseScreen`
  is a named follow-up.

## Testing (TDD — test first per task)

- **Host JUnit5 `:vault-access`** — `VaultBrowseModelTest` with `FakeVaultOpenPort` /
  `FakeVaultSession`: `loadBlocks` populates `blocks`; `selectBlock` populates
  `selectedRecords`; unknown block → `BlockNotFound`; `lock()` wipes the fake session and
  resets every flow; open error → typed `error`.
- **Host JUnit5 `:kit`** — mapper tests via injected fakes: `mapRecord` (metadata +
  field-names, tombstone true/false), `mapBlockSummary`, `mapVaultException` →
  each `VaultBrowseError` arm. (Mirrors `UniffiVaultSyncPortTest` / `VaultSyncErrorMappingTest`.)
- **Host JUnit5 `:browse-ui`** — `VaultBrowseViewModelTest` (flow forwarding,
  `selectBlock`/`back` delegate to model) + `BrowseRenderHelpersTest` (pure label funcs).
- **Instrumented JUnit4 `:app`** (real `.so`, arm64 emulator) — `OpenBrowseSmokeTest`:
  - open `golden_vault_001` with the correct password → `blockSummaries()` non-empty;
  - `readBlock(firstBlock)` → record list non-empty, each `RecordSummaryView` has a
    non-empty `type` and a stable `uuidHex`;
  - open with a wrong password → `VaultBrowseError.WrongPasswordOrCorrupt`.

## Acceptance

```bash
cd android && ./gradlew :vault-access:test :kit:testDebugUnitTest :browse-ui:test :app:test
#   → BUILD SUCCESSFUL (host JUnit5, no emulator/NDK)
cd android && ./gradlew :app:connectedDebugAndroidTest
#   → BUILD SUCCESSFUL, OpenBrowseSmokeTest green on the arm64 emulator (real .so)
git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'
#   → empty (no core/ffi/ios/format change)
```

## Deferred (named, not lost)

- **Reveal-on-tap** + per-field `expose_text`/`expose_bytes`, hide/auto-hide timer,
  background redaction of revealed plaintext (the full iOS secret lifecycle).
- **Show-deleted toggle**, swipe delete/restore, edit sheet (iOS browse parity).
- **Recovery-phrase and device-secret open paths** (this slice is password-only).
- **Sync-badge re-integration** onto `BrowseScreen` (unify browse + the slice-5 sync
  flow into one screen).
- **Folder monitor** in the browse flow.
- **On-device veto round-trip** still needs a seeded concurrent state
  ([[project_secretary_sync_veto_needs_seeded_state]]); unrelated to browse but carried.

## Risks / notes

- Lock-on-background wipes the whole session, so returning from background re-prompts for
  the password (one more Argon2id). Acceptable and matches iOS lock semantics; documented
  so a future reader doesn't "optimize" it into a weaker keep-alive.
- `golden_vault_001` is single-device, so blocks/records are stable and non-empty — the
  smoke test can assert non-emptiness without seeding.
- `field_names()` is read as metadata; the design must keep `expose_*` strictly out of
  this slice's call graph (enforced by the metadata-only `RecordSummaryView` having no
  value field). A reviewer should confirm no `expose_text`/`expose_bytes` call exists.
