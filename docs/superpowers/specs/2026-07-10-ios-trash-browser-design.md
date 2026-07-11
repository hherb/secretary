# iOS Trash browser — retention/purge parity (minus settings)

**Date:** 2026-07-10
**Slice:** D (platform UIs) — iOS native SwiftUI. First of the mobile retention/purge/empty-trash slices; Android mirror follows separately.
**Status:** design approved (brainstorm), pre-plan.

## 1. Purpose & scope

The Tauri 2 desktop client ships the complete reference for trash management
(list trashed blocks → restore / delete-forever per block, empty-trash, and a
"run retention now" preview→commit dialog, all behind a re-auth gate). The
native iOS app has **no trash surface at all** today — only record-level
soft-delete. This slice brings the desktop trash browser to iOS, native over
uniffi, deferring only the retention-window *setting* (which drags in a whole
settings subsystem that does not yet exist on iOS).

### In scope

- **FFI projection** of `list_trashed_blocks` + `TrashedBlock` onto **both**
  uniffi and pyo3 (the one trash function that is currently bridge-only), and a
  regeneration of the committed Swift bindings / `Secretary.xcframework`.
- A native SwiftUI **Trash screen**: list all trashed blocks, per-block
  **restore** and **delete-forever**, **empty-trash**, and **run-retention-now**
  (preview → commit) against the **fixed 90-day default** window
  (`default_retention_window_ms()`).
- All destructive ops gated by the existing Face ID `WriteReauthGate`
  (grace-window parity with desktop — no new gate code).

### Out of scope (explicitly deferred)

- The **retention-window setting** — requires projecting vault-settings
  read/write onto uniffi *and* a Settings screen on iOS (neither exists). A
  follow-up slice.
- The **Android** mirror (its own slice).
- Any **auto / scheduled** retention (a deferred ADR + threat-model decision).
- Surfacing actual **purge counts** in the UI post-op (#411 — cross-cutting
  across desktop + mobile; out of this slice).
- The #408 write-gate-scanner comment-naivety work (desktop tooling).

## 2. Layers touched (bottom-up)

| Layer | Change |
|---|---|
| `ffi/secretary-ffi-bridge` | **none** — `list_trashed_blocks` + `TrashedBlock` already exist here (`src/trash/list.rs`). |
| `ffi/secretary-ffi-uniffi` | **project** `list_trashed_blocks`: new `TrashedBlock` UDL dictionary + `[Throws=VaultError] sequence<TrashedBlock> list_trashed_blocks(...)`, a `wrappers/trash.rs` value type, a `namespace/mod.rs` fn, `lib.rs` re-export. |
| `ffi/secretary-ffi-py` | **project** the same onto the existing `src/trash.rs` + register in `lib.rs`. |
| Swift bindings / `Secretary.xcframework` | **regenerate** — also surfaces the already-UDL'd `purgeBlock` / `emptyTrash` / `expiredTrashEntries` / `autoPurgeExpired` / `defaultRetentionWindowMs` (present in the UDL/namespace since #399/#402 but absent from the committed `secretary.swift`). |
| `SecretaryVaultAccess` (pure, FFI-free) | new `TrashPort` protocol, Swift value types, `TrashViewModel`, pure copy/format helpers, a `FakeTrashPort`. |
| `SecretaryKit` (adapter) | `UniffiVaultSession` conforms to `TrashPort` against the new/existing uniffi free functions, reusing its `write { dev, now in … }` helper. |
| `SecretaryApp` | new `TrashScreen` + `TrashedBlockRow` + confirm dialogs + retention sheet; entry point from `VaultBrowseScreen`. |

## 3. FFI projection — `list_trashed_blocks`

The bridge already provides
`list_trashed_blocks(identity, manifest) -> Result<Vec<TrashedBlock>, FfiVaultError>`
(`ffi/secretary-ffi-bridge/src/trash/list.rs:79`). `TrashedBlock` carries
`{ block_uuid: [u8;16], block_name: String, tombstoned_at_ms: u64,
tombstoned_by: [u8;16] }`. It decrypts each newest trash file only far enough to
read `block_name`, then drops (zeroizes) the plaintext — **record material never
escapes**; only the name (already non-secret, present in manifest summaries) is
projected. Purged entries are skipped; a not-yet-purged entry with a missing
file is a typed `CorruptVault`.

Projection mirrors the existing `expired_trash_entries` / `ExpiredEntry` pattern
exactly:

- **UDL** (`secretary.udl`):
  ```
  dictionary TrashedBlock {
      bytes block_uuid;       // 16 bytes
      string block_name;
      u64 tombstoned_at_ms;
      bytes tombstoned_by;    // 16 bytes
  };
  [Throws=VaultError]
  sequence<TrashedBlock> list_trashed_blocks(UnlockedIdentity identity, OpenVaultManifest manifest);
  ```
- **Errors:** only `CorruptVault` / `FolderInvalid` — **both already existing
  `FfiVaultError` variants**. No new variant ⇒ no Swift/Kotlin
  `ConformanceErrors.{swift,kt}` harness churn, no workspace-wide
  exhaustive-match obligation.
- **uniffi:** new `wrappers/trash.rs` `TrashedBlock` value type
  (`block_uuid: Vec<u8>`, `block_name: String`, `tombstoned_at_ms: u64`,
  `tombstoned_by: Vec<u8>`) + a `namespace/mod.rs` fn converting bridge↔value
  type; `lib.rs` re-export.
- **pyo3:** add to the existing `ffi/secretary-ffi-py/src/trash.rs`; register in
  `lib.rs`.
- **No plaintext widening:** the projection copies only the four scalar/name
  fields — identical guarantee to the bridge.

### Fork ⓐ (decided): no cross-language KAT change

`list_trashed_blocks` is a by-name read, not a byte-format or CRDT-merge change,
so `conformance.py` / `conformance_kat.json` are **not** touched (they cover
crypto + merge KATs). Coverage comes from a pyo3 pytest instead.

## 4. iOS port surface

### Fork ⓑ (decided): a dedicated `TrashPort`, conformed by the same adapter

`VaultSession` already abstracts the opened vault; `UniffiVaultSession` already
resolves `device_uuid` / `now_ms` in one `write { dev, now in … }` helper. Trash
ops are the same vault + same handles. Rather than bloat `VaultSession`, add a
small dedicated protocol:

```swift
protocol TrashPort {
    func listTrashedBlocks() throws -> [TrashedBlockInfo]
    func expiredTrashEntries(windowMs: UInt64, nowMs: UInt64) -> [ExpiredEntryInfo] // non-throwing
    func restoreBlock(uuid: [UInt8]) throws
    func purgeBlock(uuid: [UInt8]) throws -> PurgeResultInfo
    func emptyTrash() throws -> EmptyTrashReportInfo
    func autoPurgeExpired(windowMs: UInt64) throws -> RetentionReportInfo
    func defaultRetentionWindowMs() -> UInt64
}
```

Conformed by the **same** `UniffiVaultSession` object (which reuses its `write`
helper for the device-uuid/now-ms resolution + `VaultError` → `VaultAccessError`
mapping). This gives `TrashViewModel` a minimal, independently-fakeable
dependency (one concept per file, per the split-early preference).

Swift value types (pure, `Sendable`, in `SecretaryVaultAccess`, so the generated
FFI DTOs never leak into the pure package): `TrashedBlockInfo`,
`ExpiredEntryInfo`, `RetentionReportInfo`, `PurgeResultInfo`,
`EmptyTrashReportInfo`. Each carries only the scalar/name fields of its FFI
counterpart (§ desktop DTO map).

## 5. iOS view model — `TrashViewModel` (pure, host-tested)

`@MainActor ObservableObject` in `SecretaryVaultAccessUI`; dependencies
`TrashPort` + `WriteReauthGate` + a `nowMs: () -> UInt64` clock. Mirrors
`VaultBrowseViewModel.reauthedWrite(reason:onSuccess:op:)` (`:114-140`):

- `load()` — generation-guarded `listTrashedBlocks()` → `@Published entries`,
  newest-first.
- `restore(uuid)` / `purge(uuid)` / `emptyTrash()` / `runRetention()` — each:
  set `isWriting` re-entrancy guard **before** the gate await →
  `await gate.authorizeWrite(reason:)` → on the gate's refusal-throw, abort
  silently (leave dialog open, clock not advanced) → run the op → reload.
  Empty-trash's report is **discarded** (empty list = the success signal;
  parity with desktop + per-block purge).
- `previewRetention()` — ungated read → drives the retention sheet summary
  against `defaultRetentionWindowMs()`.
- Reasons mirror desktop strings verbatim ("Confirm restoring this block",
  "Confirm permanently deleting this block", "Confirm permanently deleting all
  trashed blocks", "Confirm permanently deleting expired trash").

### Pure helpers (free functions, TDD, no FFI/UI)

Direct ports of desktop `lib/trash.ts` + `lib/retention.ts`:
`sortTrashed(entries)` (newest-first by `tombstonedAtMs`),
`formatTrashedWhen(ms)`, `emptyTrashConfirmBody(count)` (singular "The 1
item…" / plural "All N items…"), `retentionSummary(entries, windowMs)`,
`msToDays` / `MS_PER_DAY`. Host-tested with no dependencies.

## 6. iOS SwiftUI

- **Entry point — Fork ⓒ (decided): push-navigation from the browse toolbar.**
  A toolbar item (trash icon) in `VaultBrowseScreen`'s `.primaryAction` group
  pushes `TrashScreen` via `NavigationLink` (it's a full list view, not a quick
  action — a sheet would be wrong).
- **`TrashScreen`:** a `List` of `TrashedBlockRow` (block name + "trashed
  <relative-date>", with **Restore** and **Delete forever** as swipe/context
  actions); an **"Empty trash"** toolbar button shown **only when the list is
  non-empty**; a **"Run retention now"** button opening the retention sheet.
- **Confirm dialogs:** native `alert` / `confirmationDialog` with
  role `.destructive`. Copy mirrors desktop verbatim:
  - per-block delete-forever: title "Delete forever?", body
    `"<name>" will be permanently deleted. This cannot be undone.`
  - empty-trash: title "Empty trash?", body from `emptyTrashConfirmBody(count)`.
  - retention sheet: `retentionSummary` text + a danger button "Purge N items";
    the previewed N is indicative (bridge recomputes at commit — same caveat as
    desktop `RetentionDialog`).
- Each destructive button's action calls the corresponding `TrashViewModel`
  method (which internally hits the gate before the FFI write).

## 7. Re-auth gating

Reuse the **shipped** `GraceWindowReauthGate` instance already built in the
composition root (`SecretaryApp.swift:191-196` password path /
`DeviceUnlockOpen.swift:56-61` device path) and handed to
`VaultBrowseViewModel`; hand the **same instance** to `TrashViewModel`.
Grace-window parity with desktop (within 30 s of the last auth, no re-prompt).
**No new gate code.**

## 8. Testing strategy

- **pyo3 pytest** for `list_trashed_blocks`: happy path (name projection),
  already-purged entry skipped, not-yet-purged entry with missing file →
  `CorruptVault`.
- **Host `swift test`** (`SecretaryVaultAccess`, pre-xcframework, fast) for
  `TrashViewModel` + pure helpers via `FakeTrashPort` + the existing
  `FakeWriteReauthGate`: gate-cancel aborts the write and leaves state
  untouched; reload-after-op; newest-first sort; each copy helper (singular /
  plural / empty); empty-trash discards its report; `previewRetention` populates
  the summary.
- **Rust workspace:** `cargo test --release --workspace`, `cargo clippy
  --release --workspace --tests -- -D warnings`, `cargo fmt --all -- --check`,
  `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace`, lean-binding
  guard (`--self-test` then real).
- **uniffi conformance runners** (Swift + Kotlin `run_conformance.sh`) — they
  recompile the generated harness, confirming the new `list_trashed_blocks`
  binding compiles on both. Build **`:kit` + `:app`** too (a uniffi signature
  add can break the Kotlin Gradle modules invisibly to cargo/clippy).
- **`run-ios-tests.sh`** — the full iOS suite incl. the xcframework rebuild (the
  known multi-minute, silent build — run backgrounded with log-poll, not a
  blocking watchdog).

## 9. Risks & open items

- **xcframework regen is the long pole.** The build is multi-minute and silent;
  it must be run backgrounded with log-polling (per the repo watchdog note),
  and any Kotlin `:kit`/`:app` breakage from the new uniffi signature is only
  caught by building those modules — not by cargo/clippy.
- **Retention preview count is indicative, not committed** (bridge recomputes at
  commit time) — same honest-count caveat as desktop; #411 (surface actual
  purge counts) is the cross-cutting fix and is out of this slice.
- **No `core` / crypto / on-disk-format / KEM / signature-site / equal-clock
  change; no `manifest_version` bump; no new `FfiVaultError` variant.
  `#![forbid(unsafe_code)]` intact.** The bridge trash logic is unchanged; this
  slice only projects an existing bridge fn and builds UI on top.

## 10. Deferred follow-ups (named)

1. iOS retention-window **setting** (settings FFI projection + Settings screen).
2. **Android** trash-browser mirror.
3. #411 — surface actual purge/empty-trash/retention counts post-op
   (cross-platform).
4. Auto/scheduled retention (ADR + threat-model first).
