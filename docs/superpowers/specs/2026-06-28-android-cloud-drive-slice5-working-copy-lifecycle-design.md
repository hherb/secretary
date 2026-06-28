# Android cloud-drive provisioning — Slice 5: working-copy lifecycle

- **Date:** 2026-06-28
- **Status:** Approved design (pre-implementation)
- **Sub-project:** D.4 (Android native app) — epic [#321](https://github.com/hherb/secretary/issues/321)
- **Branch:** `feature/android-cloud-drive-working-copy-lifecycle`
- **Parent design:** [`2026-06-27-android-cloud-drive-provisioning-design.md`](2026-06-27-android-cloud-drive-provisioning-design.md) (component row #6, slicing item 5)

## Goal

Make the Android cloud-drive vault actually round-trip. Slice 4 shipped the
provisioning UI with two honest seams: opening a remembered cloud location was a
labelled `markUnavailable(CLOUD_OPEN_DEFERRED_REASON)`, and creating a vault
returned to the selection screen with the vault merely *remembered* (not opened).
Slice 5 replaces both seams with the real **working-copy lifecycle**:

> per session, **materialize** (SAF cloud → app-private working copy) →
> **sync** (`sync_vault_in` against the working copy) → **operate** (existing
> browse/CRUD) → **flush** (working copy → SAF, block-first, after every commit),
> governed by one ordering rule: **push-before-pull**.

The sync engine, the CRDT merge, and the SAF mirror mechanisms all already exist
(Slices 1–3 + the already-bound Android sync orchestration). Slice 5 wires them
together at the right times and proves the ordering invariant.

## What already exists (Slice 5 calls into, does not rebuild)

- **SAF mirror mechanisms (Slice 3):** `VaultMirror.materialize(workingDir)` /
  `VaultMirror.flush(workingDir)` (`:vault-access` `org.secretary.mirror`), the
  pure `VaultMirrorPlanner.planMirror` (block-first ordering), and
  `CloudFolderPort` with the real `safCloudFolderPort(context, treeUri)` factory
  (`:kit`). `flush()` already diffs changed files by SHA-256 fingerprint and
  executes block-first — the caller does not compute the changed set.
- **Sync orchestration (already bound on Android):** `makeVaultSync(folder,
  stateDir, vaultUuid)` + the uniffi `UniffiVaultSyncPort` (`syncStatus` /
  `syncVault` / `syncCommitDecisions`), backed by the bridge `sync_vault_in`,
  which internally runs `sync_once` + persists `SyncState` + ingests conflict-copy
  siblings. **folder = the working copy** is the only change Slice 5 makes here.
- **Open/session (Slices prior):** `VaultOpenPort` / `UniffiVaultSession`
  (`vaultUuidHex()`, the write methods), `openBrowseWithSync(openPort, folder,
  stateDir, vaultUuid, credential, gate)`.
- **Location store (Slice 2):** `VaultLocationStore` / `SafVaultLocationStore`
  (persist tree URI + display name, `takePersistableUriPermission`).
- **Create port (Slice 1):** `VaultCreatePort` / `UniffiVaultCreatePort` →
  `CreatedVault(phrase)`.
- **Provisioning UI (Slice 4):** `VaultSelectionViewModel`,
  `VaultProvisioningViewModel`, `VaultSelectionScreen`, `CreateVaultWizardScreen`,
  `AppRoot` routing with the two seams Slice 5 replaces.

## Decisions settled at brainstorm

| Decision | Choice | Rationale |
|---|---|---|
| Source of `vault_uuid` for SyncState keying + location persistence | **Extend the create FFI**: `CreatedVault` returns `vault_uuid` (16 bytes); for open, read it from `VaultSession.vaultUuidHex()` | Authoritative source (`core::unlock::CreatedVault.identity.vault_uuid()`), additive, no on-disk-format parsing leaking into Kotlin |
| Per-session sync pass | **Reuse the existing `sync_vault_in` / `makeVaultSync`** pointed at the working copy | It already does `sync_once` + `SyncState` persist + conflict-copy ingest; no new FFI surface, no duplicated orchestration in Kotlin |
| flush-after-commit changed-set | **Call `VaultMirror.flush()`**, which diffs changed files itself | The mechanism already computes the block-first changed set; the hook only schedules it |
| Local-sidecar flush optimization (deferred from Slice 3) | **Stay deferred** | Correctness first: re-reading the cloud to fingerprint each flush is correct, only extra SAF reads; revisit only if SAF latency bites |
| Coordinator placement | **Pure-ish coordinator in `:vault-access`** with injected seams | Makes the push-before-pull ordering invariant host-testable with order-recording fakes — no Android/SAF/FFI needed |

## Two additive data extensions

### `CreatedVault` gains `vaultUuid: ByteArray` (16 bytes)

- **Rust:** the bridge create function + the uniffi create record return
  `vault_uuid` (from `core::unlock::CreatedVault`'s `identity.vault_uuid()`).
- **Kotlin:** `UniffiVaultCreatePort` reads both phrase + uuid; `CreatedVault`
  carries `vaultUuid` alongside the (still secret, never compared/logged) phrase.
- **Cross-binding obligation:** regenerating the uniffi record means the **iOS
  `UniffiVaultCreatePort.swift`** and the **pyo3 create site** must compile
  against the new field. The plan threads every binding site (same discipline as
  a `FfiVaultError` change, though this is a record field, not an error variant —
  `cargo`/`clippy` see the Rust + Kotlin/Swift compile, but run the Swift +
  Kotlin conformance scripts to be sure nothing observable shifted). Purely
  additive; `create` is not part of `conformance_kat.json`.

### `VaultLocation` gains `vaultUuidHex: String`

- `SafVaultLocationStore` serialization bumps to carry it. No released app ⇒ no
  production migration burden, but `load()` tolerates a missing uuid (an older
  blob → empty uuid → "learn it on first open from the session").

## Architecture

```
   SAF cloud folder                 app-private working copy            core (unchanged)
   content:// tree   ──materialize─▶  files/working/<uuid>/  ──path──▶ open / sync_vault_in /
   (Drive/Dropbox)   ◀──flush───────  (real POSIX path)                 save_block
                                              ▲
                       VaultWorkingCopyCoordinator (:vault-access, pure-ish)
                       enforces push-before-pull; calls injected seams
```

### `VaultWorkingCopyCoordinator` (`:vault-access`)

Depends only on injected seams (each a small interface so a host fake can record
call order): a `VaultMirror`-shaped mirror (materialize/flush), an open seam, a
sync seam, and a `PendingFlushMarker` (read/set/clear a sentinel in the working
dir).

- **`openExisting(location, workingDir, …)` — enforces push-before-pull:**
  1. **If the pending-flush marker is set → `flush(working→cloud)` FIRST**, then
     clear the marker. *(keystone — nothing earlier guarantees this ordering.)*
  2. `materialize(cloud→working)`.
  3. open/unlock the working copy → sync seam (`sync_vault_in` /
     `makeVaultSync`, folder = working copy) → hand off to browse.
- **`createThenOpen(...)`:** create writes into a fresh working subdir →
  `flush(working→new cloud child)` → persist location (now with `vaultUuid`) →
  open the working copy into browse (closes the create-then-Selection seam).
- **flush-after-commit:** after each successful browse mutation, enqueue a
  background `flush()`. On **flush failure → set the pending-flush marker**
  (non-blocking "saved locally, not yet synced"); the next `openExisting` retries
  it before pulling.

### Why push-before-pull (recap from parent design)

The shim never merges. Flushing after every commit keeps the working copy
normally clean. If a flush failed (offline), the working copy holds un-pushed
edits; on the next open the marker forces the push first, then the pull. If both
sides changed offline, our push lands our manifest where a peer manifest already
exists → the cloud provider writes a `manifest (conflicted copy).cbor.enc`
sibling → the next sync pass authenticates and CRDT-merges it — exactly the
desktop / `two_instance_convergence` path. Merge stays entirely in the audited
core.

## `:app` wiring (`AppRoot`)

- **Cloud-open seam** (`markUnavailable(CLOUD_OPEN_DEFERRED_REASON)`) →
  `coordinator.openExisting(...)`: build a `SafCloudFolderPort` from the
  location's `treeUri`, into `workingVaultDir(filesDir, vaultUuidHex)`, then into
  the existing `openBrowseWithSync`.
- **Create-then-Selection seam** → `coordinator.createThenOpen(...)`: open the
  new working copy into browse.
- **Demo path untouched:** golden vault staged to app-private storage; no cloud,
  no mirror.
- Background flush runs off the main thread (existing dispatcher pattern); a
  small in-flight / pending indicator surfaces flush state.

## Working-copy directory keying

- **Open existing:** `workingVaultDir(filesDir, vaultUuidHex)` — keyed by uuid
  (known from the persisted location).
- **Create:** writes into a fresh name-keyed working subdir (uuid is not known
  until create returns); once `CreatedVault.vaultUuid` is known, the location is
  persisted with it and `SyncState` is keyed by it. (If a later cleanup wants
  uuid-keyed dirs uniformly, that is a non-blocking follow-up — the create dir is
  app-private and single-vault per name.)

## Error handling (typed, not assumed)

- **SAF permission revoked / stale** → location load `Unavailable` → re-pick
  (already wired in Slice 4).
- **Flush failure (offline / SAF error)** → keep the working-copy edit, set the
  pending marker, show a non-blocking "saved locally, not yet synced" badge,
  retry on next op/open.
- **Partial flush** (block out, manifest not) → the core recovers via the
  fingerprint recheck on open (`vault-format.md` §9); the retry completes it.
- **Conflict on sync** → existing conflict sheet → `sync_commit_decisions`
  (against the working copy) → flush. (Existing path; no new merge logic.)

Every security-relevant surface (typed error / null surface on the FFI extension,
the flush-failure → marker path) is proven by a test, not assumed.

## Testing

- **Host (JVM, no device) — this slice's gate:** `VaultWorkingCopyCoordinator`
  with order-recording fakes:
  - **push-before-pull keystone:** with the marker set, `flush` is invoked
    **before** `materialize`.
  - pending-flush retry clears the marker after a successful push.
  - `openExisting` with no pending marker → `materialize` then open then sync,
    in that order, no spurious flush.
  - `createThenOpen` → create → flush → persist-location(with uuid) → open.
  - flush-after-commit enqueues `flush`; flush failure → marker set.
  - SyncState / working-dir keyed by `vault_uuid`.
  - `VaultLocation` round-trips `vaultUuidHex`; `load()` tolerates a missing uuid.
  - Rust unit test: `vault_uuid` round-trips through the bridge + uniffi create
    DTO and equals the opened session's uuid.
- **Instrumented (real `.so` + real SAF) → Slice 6** (as the parent design
  slices it): create→flush→materialize→open round-trip; offline-flush-then-retry;
  two working copies over one SAF tree for conflict-copy ingest (mirrors
  `cli/tests/two_instance_convergence.rs`). Also run the 7 authored Slice-4
  instrumented screen tests on the emulator there if not already run.

## File layout (one concept per file, < 500 lines)

- `:vault-access` (`org.secretary.mirror` / `org.secretary.browse`):
  `VaultWorkingCopyCoordinator.kt`, `PendingFlushMarker.kt` (port + any pure
  marker logic); extend `VaultLocation.kt` (`vaultUuidHex`) and `VaultCreatePort.kt`
  (`CreatedVault.vaultUuid`).
- `:kit`: `FilePendingFlushMarker.kt` (sentinel file in the working dir); extend
  `UniffiVaultCreatePort.kt` (read uuid) and `SafVaultLocationStore.kt`
  (serialize uuid).
- `:app`: `AppRoot` seam replacement + flush-after-commit hook (split a helper
  file if `AppRoot` approaches the threshold).
- Rust: bridge + uniffi create DTO gains `vault_uuid`; thread the Swift + pyo3
  create sites.

## Out of scope (this slice)

- Instrumented E2E / offline / conflict-copy device tests → **Slice 6**.
- Local-sidecar flush optimization (cloud re-read avoidance) → deferred.
- A non-vault-shape probe before `recordSelection` (needs a SAF read) → Slice 5/6
  materialize work makes this natural later; not required here.
- Any change to the core, the on-disk format, `conformance.py`, the conflict
  KATs, or observable bytes. (The FFI create DTO gaining a field is additive and
  not part of `conformance_kat.json`.)

## Acceptance template (per slice)

TDD with RED proven; typed-error / null surface proven not assumed on the FFI +
flush-failure paths; host gate green (the keystone push-before-pull test is
mandatory); pure logic in `:vault-access`, FFI + Android in `:kit`; **no merge
logic in Kotlin** — the core owns CRDT.

## Key references

- Slice-3 mirror: `android/vault-access/src/main/kotlin/org/secretary/mirror/{VaultMirror,VaultMirrorPlanner,CloudFolderPort}.kt`, `android/kit/.../mirror/SafCloudFolderPort.kt`.
- Android sync orchestration: `android/app/.../BrowseSession.kt` (`openBrowseWithSync`, `makeVaultSync`), `android/kit/.../UniffiVaultSyncPort.kt`.
- Create FFI: `ffi/secretary-ffi-bridge` create fn, `ffi/secretary-ffi-uniffi` create record, `core/src/unlock/mod.rs` (`CreatedVault`).
- SyncState persistence convention: `cli/src/state.rs` (`state_file_path`, CBOR), `core/src/sync/state.rs`.
- Parent design + topology: `docs/superpowers/specs/2026-06-27-android-cloud-drive-provisioning-design.md`, `cli/tests/two_instance_convergence.rs`, `docs/adr/0003-cloud-folder-sync.md`.
