# C.3 Android slice 9: soft-delete lifecycle — design

**Date:** 2026-06-17
**Status:** approved (brainstorm), pre-implementation
**Branch:** `feature/c3-android-soft-delete` (worktree `.worktrees/c3-android-soft-delete`), from `main` @ `4def5ea`

## Summary

The first Android slice that **writes** to a vault. It adds the soft-delete lifecycle to the
Compose browse surface — a **Show-deleted** toggle, per-row **Delete** (tombstone) and **Restore**
(resurrect) actions — and, underneath, the **device-UUID + write infrastructure** that every future
Android write (edit, add) will reuse. It mirrors the iOS `VaultBrowseViewModel` delete / restore /
`showDeleted` surface, minus the edit view-model.

**No `core` / `ffi` / `ios` / on-disk-format change.** The uniffi write surface
(`tombstoneRecord` / `resurrectRecord`) and the `read_block` `includeDeleted` gate already exist and
are exercised by iOS; this slice only projects them onto Android. Both guardrail greps stay empty.

## Scope

**In scope**

- A `Show deleted` toggle on the record list; toggling re-reads the selected block with the new
  `includeDeleted` flag (the client never holds withheld data and never filters tombstones itself).
- Per-row **Delete** (live records) and **Restore** (tombstoned records, only reachable while
  show-deleted is on).
- The device-UUID provider + the session write seam + typed write-error surface — the reusable
  write foundation.

**Out of scope (deferred to slice 10: edit/add)**

- Editing field values and adding new records (`RecordContentInput` / `FieldContentInput`,
  `RecordEditViewModel`, the edit Form/sheet UI). None of that ships here.

**Non-goals**

- No swipe-to-dismiss gesture — explicit per-row buttons (matches the established reveal/hide idiom
  and is trivial to drive in the instrumented Compose test).
- No delete-confirmation dialog — soft delete is reversible in one tap (Restore), mirroring iOS.

## Architecture

The existing four-module split is preserved; each piece lands in the module that matches its purity.

### `:vault-access` (package `org.secretary.browse`) — pure, host-tested JUnit5

- **`DeviceUuidProvider`** (new interface) — the pure seam, like `VaultOpenPort`:
  ```kotlin
  interface DeviceUuidProvider {
      /** vaultHex: lowercase, dash-less vault-UUID hex. Returns exactly 16 bytes. */
      fun deviceUuid(vaultHex: String): ByteArray
  }
  ```
  The 16-byte CRDT modifier UUID the edit FFI stamps onto every field a write touches. Non-secret
  (a public per-device fingerprint), so NOT key material.

- **`FileDeviceUuidStore(directory: File)`** (new, file-backed `DeviceUuidProvider`) — mirrors iOS
  `DeviceUuidStore` and desktop `settings/io.rs::load_or_create_device_uuid_in`: random 16 bytes per
  `(install, vault)` via `java.security.SecureRandom`, persisted as `<vaultHex>.dev`, read back on
  later calls so one device == one CRDT fingerprint. Converges on the existing file if a same-launch
  write lost a race (read-back-on-exists); rejects a corrupt-length file with a typed error. Pure
  `java.io.File` I/O → host-tested with a JUnit5 `@TempDir`. A named constant
  (`DEVICE_UUID_BYTE_LEN = 16`) avoids the magic literal.

- **`VaultSession`** (interface) gains two writers — device-UUID/now-ms resolution stays *inside* the
  real implementation, never on the pure interface (iOS-identical):
  ```kotlin
  suspend fun tombstoneRecord(blockUuid: ByteArray, recordUuid: ByteArray)
  suspend fun resurrectRecord(blockUuid: ByteArray, recordUuid: ByteArray)
  ```
  `suspend` because the real impl offloads the AEAD save-tail to IO.

- **`VaultBrowseModel`** gains:
  - `showDeleted: StateFlow<Boolean>` + `setShowDeleted(value: Boolean)` — on a real change, if a
    block is selected, re-reads it with the new flag.
  - `selectBlock` reads with `includeDeleted = showDeleted.value` (no longer hardcoded `false`).
  - `delete(record)` / `restore(record)` via a private `commitThenReload` helper: run the session
    write against the selected block's UUID, then re-read. **A failed write leaves `_selectedRecords`
    intact** and surfaces only `_error` (a rejected delete must not blank the visible list — mirror
    iOS). Clears reveals on the post-write re-read (the existing `selectBlock`/reload path already
    does).

### `:kit` (package `org.secretary.browse`) — FFI adapters, host-tested where pure

- **`UniffiVaultOpenPort`** constructor gains a `DeviceUuidProvider`; it passes the provider to each
  `UniffiVaultSession` it builds. A production factory overload
  `uniffiVaultOpenPort(deviceUuids: DeviceUuidProvider)` is added; the existing no-arg factory stays
  for read-only callers (or is updated — see Wiring).

- **`UniffiVaultSession`** implements the two writers:
  - Resolve + cache the device UUID lazily on the first write (read-only sessions never touch write
    infra), via the injected `DeviceUuidProvider`, keyed by `vaultUuidHex()`.
  - Stamp `now_ms = System.currentTimeMillis()`.
  - Call the uniffi `tombstoneRecord` / `resurrectRecord`.
  - Run **under the existing `sessionLock` + `wiped` guard**: a write that loses the race to a
    concurrent `wipe()` (the slice-7 `ON_STOP` lock-on-background) must observe `wiped` and refuse
    rather than touch zeroized handles. Offloaded to `ioDispatcher`.
  - The write does NOT mutate `openBlocks` directly; the model re-reads the block afterwards (a fresh
    `readBlock` appends a new `BlockReadOutput`). (Stale prior `BlockReadOutput`s remain retained
    until `wipe()` — the same #251 cross-platform accumulation already documented for navigation; not
    widened here.)

- **`BrowseMapping.kt`** (`mapVaultBrowseError`) gains explicit `RecordNotFound` (+ `SaveCryptoFailure`)
  arms above the `else`-fold, so write failures surface typed instead of as the opaque `Failed`.
  (The exact uniffi arm names are confirmed against the generated bindings during implementation; if
  `SaveCryptoFailure` is not a distinct arm it folds to `Failed` as today and is noted.)

- **`VaultBrowseError`** gains matching `RecordNotFound` (and, if mapped, `SaveCryptoFailure`)
  variants.

### `:browse-ui` (package `org.secretary.browse.ui`) — FFI-free Compose

- **`VaultBrowseViewModel`** re-exposes `showDeleted` and forwards `setShowDeleted`, `delete`,
  `restore` (launched on `viewModelScope` since the model writers are `suspend`).

- **`BrowseScreen`**: a `Show deleted` `Switch`/toggle in the record-list header (tagged
  `toggle-show-deleted`); each row gets a **Delete** button (live record) or a **Restore** button
  (tombstoned record). Buttons tagged `delete-<uuidHex>` / `restore-<uuidHex>` for the instrumented
  test. The `(deleted)` title marker already renders via `recordTitle` (existing).

### `:app`

`AppRoot` constructs `FileDeviceUuidStore(File(context.noBackupFilesDir, "devices"))` —
`noBackupFilesDir` is Android's backup-exclusion equivalent of iOS `excludeFromBackup`, so a restored
device backup does not clone the CRDT fingerprint — and injects it into the open port
(`uniffiVaultOpenPort(deviceUuids)`). Otherwise unchanged; the slice-7 `ON_STOP` lock already wipes
the session.

## Data flow

1. **Show-deleted toggle:** user flips the toggle → VM `setShowDeleted` → model re-reads the selected
   block with `includeDeleted` → list re-renders. The Rust `read_block` gate withholds/includes
   tombstoned records; the client never filters.
2. **Delete:** tap Delete on a live row → VM → model `delete(record)` → `session.tombstoneRecord` →
   re-read selected block → row vanishes from the default (live-only) view.
3. **Restore:** with show-deleted on, tap Restore on a tombstoned row → `session.resurrectRecord` →
   re-read → row returns to the live set.

## Error handling

- Write failures (`RecordNotFound` — e.g. a peer already deleted it; save-tail failures) surface as a
  typed `VaultBrowseError` in the existing error banner. The visible list is **not** blanked on a
  failed mutation (`commitThenReload` only re-reads on success).
- A `DeviceUuidProvider` I/O failure (corrupt-length file, entropy/IO error) surfaces as a typed
  error — never silently swallowed (a write must not proceed with a bad fingerprint).
- The `WrongPasswordOrCorrupt` conflation (threat-model §13) is untouched.

## Testing (mirrors the slice-8 gauntlet)

**Host JUnit5**
- `FileDeviceUuidStore`: fresh create returns 16 random bytes + persists; second call reads the same
  bytes back; corrupt-length file → typed error; converge-on-existing. (Random via `SecureRandom`,
  never hardcoded — per the repo's hardcoded-crypto-value rule.)
- `VaultBrowseModel`: `setShowDeleted(true)` re-reads with `includeDeleted = true`; `delete` calls
  `session.tombstoneRecord` then re-reads; `restore` calls `resurrectRecord` then re-reads; a write
  that throws leaves `selectedRecords` intact and sets `error`. (`FakeVaultSession` gains the two
  writers, recording calls + simulating tombstone/resurrect on its in-memory records.)
- `:kit` error mapper: `RecordNotFound` (+ `SaveCryptoFailure` if mapped) → the typed variant.

**Instrumented Compose (`:browse-ui`, `connectedDebugAndroidTest`)**
- New `BrowseScreenSoftDeleteTest` (fake-backed, real Compose): toggle reveals a deleted row; Delete
  removes a live row from the list; Restore on a deleted row (show-deleted on) restores it.

**On-device (`:app`, `connectedDebugAndroidTest`)**
- New case in / alongside `OpenBrowseSmokeTest`: real `.so` round-trip on the staged golden-vault
  **copy** — open → tombstone a record → re-read default view (record gone) → toggle includeDeleted
  re-read (record present with `(deleted)` marker) → resurrect → default view (record back). The
  staged copy lives in `filesDir` and is re-provisioned per test (existing idempotent
  `stageGoldenVault` + `deleteRecursively`), so writes never touch the frozen repo fixture.

**Guardrails (both must be empty)**
```
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)'
git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'
```

## Deliberate decisions (so a future reader does not "fix" them)

- **Device UUID under `noBackupFilesDir`, resolved per-vault, cached per session** — Android's
  backup-exclusion equivalent of iOS; one device == one CRDT fingerprint; a restored backup must not
  clone it.
- **`FileDeviceUuidStore` lives in `:vault-access` (pure), not `:kit`** — it is pure `java.io` +
  `SecureRandom`, host-testable with `@TempDir`, exactly as iOS keeps `DeviceUuidStore` in its pure
  module. `:kit` only supplies the directory at the `:app` edge.
- **No client-side tombstone filtering** — the Rust `read_block` gate is the single source of truth;
  the client re-reads with the flag and renders what it gets.
- **Soft delete is reversible → no confirm dialog** (mirror iOS).
- **Explicit buttons, not swipe** — testable, matches the reveal/hide idiom.
- **Writes serialize under the existing `sessionLock` + `wiped` guard** — a write racing
  `ON_STOP` lock-on-background must not touch zeroized FFI handles.
- **Failed mutation leaves the visible list intact** — only `error` updates; the re-read happens on
  success only (mirror iOS `commitThenReload`).

## Risks

- **First Android write path.** Save-tail (atomic manifest + block rewrite) runs on-device for the
  first time on Android; the on-device smoke proves the real round-trip end-to-end.
- **`now_ms` clock trust.** `System.currentTimeMillis()` is wall-clock; CRDT correctness already
  tolerates skew (vector clocks order causally, the death clock handles ties). Same trust model as
  iOS `Date()`.
- **Carried, not widened:** #251 (cross-platform `openBlocks` decrypted-plaintext accumulation) — a
  post-write re-read appends another `BlockReadOutput`; same residency tradeoff, not changed here.
