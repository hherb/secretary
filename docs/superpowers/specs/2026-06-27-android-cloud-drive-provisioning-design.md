# Android cloud-drive vault provisioning + SAF working-copy shim

- **Date:** 2026-06-27
- **Status:** Approved design (pre-implementation)
- **Sub-project:** D.4 (Android native app)
- **Branch:** `feature/android-cloud-drive-provisioning`

## Goal

Make the Android app usable for real personal use: let the user **open their own
vault** and **create a new vault**, stored in a **cloud-drive folder** (Google
Drive / Dropbox / OneDrive) so it stays in sync with the iOS and desktop clients.
Today the Android app can only open the bundled `golden_vault_001` demo staged
into app-private storage — there is no folder picker and no create-vault flow.

This is the first item in the agreed roadmap order for reaching usable private
iOS + Android apps. iOS already has the equivalent (file picker + create wizard);
this brings Android to parity, with one Android-specific complication described
below.

## The core constraint

The Rust core (`secretary-core`) does direct POSIX filesystem I/O — `std::fs`
plus atomic `rename(2)` via `tempfile::NamedTempFile::persist`
(`core/src/vault/io.rs`). **There is no storage-abstraction seam** (no VFS trait,
no `Read`/`Write` bound) to plug an alternate backend into.

Android cloud-drive apps expose their synced folders **only through the Storage
Access Framework (SAF)** as `content://` URIs with a stream API — there is no
real filesystem path behind them. Therefore the core cannot operate on a SAF
folder directly.

iOS does not hit this: Files-provider folders (iCloud Drive, Dropbox) resolve to
real file URLs that `std::fs` can use, so the iOS app passes the picked folder's
path straight to the core. Android needs a shim.

This constraint forecloses the two "clever" alternatives:

- **FUSE / virtual-FS mount over SAF** — Android does not allow unprivileged FUSE
  for apps. Rejected.
- **Lazy / on-demand fetch** — would require intercepting the core's individual
  file reads; there is no trait to hook. Rejected.

The only viable shape is a **full POSIX working copy** in app-private storage that
the core operates on, mirrored to and from the SAF cloud folder.

## How sync works (confirmed model)

The sync engine requires no new work; the shim reuses it untouched.

- A vault is a **folder of files** (`vault.toml`, `identity.bundle.enc`,
  `manifest.cbor.enc`, `blocks/<uuid>.cbor.enc`, `contacts/`, `devices/`,
  `trash/`). On a record edit, only **`manifest.cbor.enc` and the one changed
  block file** are rewritten; everything else is immutable after creation.
  (`docs/vault-format.md` §1, §4.4, §6.5, §9.)
- The deployment model is **one shared vault folder + a per-device `SyncState`
  file**. An external sync tool (the cloud-drive app) physically copies one
  device's updated files into every other device's copy of the folder.
  (`docs/adr/0003-cloud-folder-sync.md`; `cli/tests/two_instance_convergence.rs`
  uses exactly this topology — two daemons, one shared `vault_dir`, separate
  `--state-dir`.)
- `sync_once(vault_folder, identity, state, now_ms)` (`core/src/sync/once.rs`) is
  a near-pure comparison of the folder's manifest vector clock against the
  caller-persisted `SyncState`. Equal → `NothingToDo`; incoming dominates →
  `AppliedAutomatically`; concurrent → ingest authenticated conflict-copy
  siblings (`manifest.cbor.enc*`) and CRDT-merge; incoming dominated →
  `RollbackRejected`.
- **Convergence requires only a file copy** into the shared folder, not a special
  network protocol. The peer's next `sync_once` reads the new bytes and merges.
  Record-level merge is field-LWW with a death clock; deletions are sticky
  (tombstone-on-tie). (`docs/crypto-design.md` §10–11; `core/src/vault/conflict.rs`.)

## Architecture

```
   SAF cloud folder                 app-private working copy            core (unchanged)
   content:// tree   ──materialize─▶  /data/.../working/<uuid>/  ──path──▶ open/unlock/
   (Drive/Dropbox)   ◀──flush───────  (real POSIX path)                   sync_once/save_block
```

Per session: **materialize** (copy SAF tree → working copy) → **`sync_once`**
against the working copy (folds in peer changes + any conflict-copy siblings the
cloud created) → **operate** (existing browse/CRUD, unchanged) → **flush** (copy
changed files, **block-first**, working copy → SAF) after each commit.

Every interesting invariant stays where it already lives: atomicity (the core's
`tempfile::persist` into the working copy), CRDT merge (the existing sync engine),
hybrid verify-before-decrypt (unchanged). The shim is only responsible for *which
bytes to move, and in what order*.

### The shim's central invariant: push-before-pull

The shim never merges. It guarantees one ordering rule so the existing sync engine
plus the cloud provider's own conflict-copy mechanism do all merging:

> **Before pulling cloud→working, always flush any pending local edits
> working→cloud.**

Because we flush after every commit, the working copy is normally clean. If a
flush failed (offline), the working copy holds un-pushed edits; on the next open
we retry the push **first**, then pull. If both sides changed while offline, our
push lands our manifest where a peer manifest already exists → the cloud provider
creates a `manifest (conflicted copy).cbor.enc` sibling → the next `sync_once`
against the working copy authenticates and CRDT-merges it. This is exactly the
desktop path and the `two_instance_convergence` topology, so merge semantics stay
entirely inside the audited core.

## Components

Following the existing `:vault-access` (pure, host-tested) / `:kit` (real adapters,
FFI + Android) split.

| # | Component | Module | iOS analogue |
|---|---|---|---|
| 1 | `VaultCreatePort` + `UniffiVaultCreatePort` (wraps already-bound `createVaultInFolder`) | port in `:vault-access`, impl in `:kit` | `UniffiVaultCreatePort.swift` |
| 2 | `VaultLocationStore` + `SafVaultLocationStore` (persist tree URI + display name + vault_uuid; `takePersistableUriPermission`) | port in `:vault-access`, impl in `:kit` | `BookmarkVaultLocationStore.swift` |
| 3 | `CloudFolderPort` (list / read / write / delete over SAF) + `VaultMirrorPlanner` (**pure** free functions) + `VaultMirror` orchestrator | ports + pure logic in `:vault-access`, SAF impl in `:kit` | *(Android-only; no iOS equivalent)* |
| 4 | `VaultSelectionViewModel`, `VaultProvisioningViewModel` | `:vault-access` UI | `VaultSelectionViewModel.swift`, `VaultProvisioningViewModel.swift` |
| 5 | `VaultSelectionScreen`, `CreateVaultWizardScreen`, SAF picker launchers, `AppRoot` routing | `:app` | `VaultSelectionScreen.swift`, `CreateVaultWizardView.swift` |
| 6 | Working-copy lifecycle (materialize→sync→operate→flush) + flush-after-commit hook in `UniffiVaultSession` + pending-flush retry | `:kit` + `:app` | *(re-points existing sync at the working copy)* |

`VaultMirrorPlanner` is where the non-trivial logic concentrates (which files to
move, block-first ordering, changed-file detection) and is fully host-testable
with zero Android dependencies. All SAF specifics live behind `CloudFolderPort`.

Per project convention, design each new file as a focused unit and split toward a
directory module before any file approaches ~500 lines.

## Settled decisions

| Decision | Choice | Rationale |
|---|---|---|
| Storage model | Full POSIX working copy in app-private storage, mirrored to/from SAF | Only viable shape given no VFS seam in the core |
| Sync transport | Cloud drive (Drive/Dropbox/OneDrive) on every device | User decision; iOS + desktop reach it natively, Android via this shim |
| Flush granularity | Changed-files-only (manifest + differing blocks), **block-first** | A partial flush leaves cloud with new-block + stale-manifest, which the core already recovers from via fingerprint recheck (`vault-format.md` §9) |
| Flush trigger | After every commit, off the main thread | Safest against Android process-kill; small in-flight indicator covers SAF latency |
| Pull trigger | On open + manual "Sync now" + on foreground | SAF gives no reliable change notification and cloud providers do not push |
| Merge ownership | Entirely in the core; shim only enforces push-before-pull | Keeps CRDT semantics in the audited Rust, not in Kotlin |

## Data flows

- **Open existing:** load location → retry-pending-flush → materialize SAF→working
  → `sync_once(working, state)`, persist `SyncState` (app-private, keyed by
  vault_uuid) → unlock(working) → browse.
- **Create new:** pick parent tree (`ACTION_OPEN_DOCUMENT_TREE`) →
  `createVaultInFolder` into a fresh working subdir → flush working→new SAF child
  dir → persist location → show 24-word recovery phrase → open.
- **Edit:** `save_block(working)` → enqueue flush of {manifest + changed block},
  block-first → background flush to SAF → in-flight indicator clears.
- **Sync now / on foreground:** flush-pending → materialize → `sync_once` →
  refresh; on conflict → existing conflict sheet → `sync_commit_decisions(working)`
  → flush.

## Error handling

- **SAF permission revoked / stale** → location load returns `Unavailable` →
  selection screen prompts re-pick (mirrors iOS stale-bookmark `.unavailable`).
- **Flush failure (offline / SAF error)** → keep edit in working copy, mark
  pending, show a non-blocking "saved locally, not yet synced" badge, retry on
  next op/open.
- **Partial flush** (block out, manifest not) → cloud recovers via the core's
  fingerprint recheck on open; the retry completes it.
- **Create into a non-empty target** → `FolderNotEmpty` (mirrors iOS).

## Testing

- **Host (JVM, no device):** `VaultMirrorPlanner` (materialize/flush plans,
  block-first ordering, changed-file detection); view-model state machines with
  fake ports; location-store serialization.
- **Instrumented (emulator, real `.so` + real SAF):** create→flush→materialize→open
  round-trip; offline-flush-then-retry; two working copies sharing one SAF tree to
  exercise conflict-copy ingest (mirrors `cli/tests/two_instance_convergence.rs`).

## Out of scope

- Real-device biometric verification on a physical Android phone (separate
  roadmap step, tracked independently).
- Multi-recipient contact import / block sharing UI.
- Autofill / browser integration.
- A SAF-free real-folder (Syncthing / All-Files-Access) storage mode — the
  push-before-pull design does not preclude adding it later as an alternate
  `CloudFolderPort`/location-store implementation.
- Play Store release infrastructure.

## Suggested slicing (each its own PR, review loop intact)

1. `VaultCreatePort` + `UniffiVaultCreatePort` (smallest; unblocks create).
2. `VaultLocationStore` + `SafVaultLocationStore`.
3. `CloudFolderPort` + pure `VaultMirrorPlanner` + `VaultMirror`.
4. Provisioning view models + screens + `AppRoot` routing (keep the demo entry).
5. Working-copy lifecycle + sync re-pointing + flush-after-commit + pending-flush
   retry.
6. Instrumented E2E + offline/conflict tests.

A tracking GitHub issue (epic) will be filed when implementation starts.

## Key references

- `core/src/vault/io.rs` — `write_atomic` / `tempfile::persist` (the real-path requirement).
- `core/src/sync/once.rs`, `core/src/sync/ingest.rs`, `core/src/sync/state.rs` — sync engine + conflict-copy ingest + `SyncState`.
- `docs/vault-format.md` §1, §4.4, §6.5, §9 — folder layout + mutation pattern + write ordering.
- `docs/crypto-design.md` §10–11 — manifest fork detection + record CRDT merge.
- `docs/adr/0003-cloud-folder-sync.md` — the shared-folder deployment model.
- `cli/tests/two_instance_convergence.rs` — the real-world topology this mirrors.
- iOS reference: `ios/SecretaryApp/Sources/{VaultSelectionScreen,CreateVaultWizardView}.swift`, `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/{UniffiVaultCreatePort,BookmarkVaultLocationStore}.swift`.
- Android current state: `android/app/src/main/kotlin/org/secretary/app/{AppRoot,AppVaultProvisioning}.kt`, `android/kit/src/main/kotlin/org/secretary/browse/UniffiVaultOpenPort.kt`, `android/vault-access/src/main/kotlin/org/secretary/browse/VaultOpenPort.kt`.
