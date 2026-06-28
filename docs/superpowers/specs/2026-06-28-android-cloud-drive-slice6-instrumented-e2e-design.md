# Android cloud-drive provisioning — Slice 6: instrumented E2E + offline/conflict tests + #327 fix

- **Date:** 2026-06-28
- **Status:** Approved design (pre-implementation)
- **Sub-project:** D.4 (Android native app)
- **Epic:** [#321](https://github.com/hherb/secretary/issues/321) — Android cloud-drive vault provisioning (SAF working-copy shim)
- **Slice:** 6 of 6 — the final slice, closes the epic
- **Branch:** `feature/android-cloud-drive-slice6-instrumented-e2e`
- **Parent design:** `docs/superpowers/specs/2026-06-27-android-cloud-drive-provisioning-design.md` (component row #6, "Testing")

## Goal

Slices 1–5 built and host/compile-tested the SAF working-copy shim that lets the
POSIX-only Rust core operate on a path-less cloud-drive folder, governed by the
**push-before-pull** ordering rule. Every ordering invariant is proven host-side
with order-recording fakes, but the **real materialize/flush over `content://`**
and the **on-device-only branches of `safCloudFolderPort`** are unverified on a
device. This slice closes that gap with **instrumented tests** (emulator, real
`libsecretary_ffi_uniffi.so` + real SAF) and fixes one latent data-safety gap
([#327](https://github.com/hherb/secretary/issues/327)) surfaced by the Slice-5
review whose validation requires exactly this real-SAF coverage.

Out of this slice: nothing new ships to users. It is test coverage plus one
small Kotlin coordinator robustness fix.

## The core constraint for instrumented SAF testing

Production SAF tree URIs come from the **interactive system document picker**
(`ACTION_OPEN_DOCUMENT_TREE`). Driving that picker in an automated test (via
UiAutomator) is slow and historically flaky across API levels and picker UI
revisions. We do not want flaky tests in the instrumented gate.

**Decision — a test-only `DocumentsProvider` as the SAF backend.** A minimal
`DocumentsProvider` is shipped in the `androidTest` source set, backed by a temp
directory. Tests build its tree URI directly with
`DocumentsContract.buildTreeDocumentUri` and grant it to self. This drives the
**real** SAF stack end-to-end — `DocumentFile.fromTreeUri`,
`ContentResolver.openInputStream`, `openOutputStream("wt")`,
`DocumentsContract` create/delete — i.e. exactly the on-device-only code in
`safCloudFolderPort`. The only thing faked is the backing store, which is how
AndroidX itself tests SAF (`StubProvider`). The result is deterministic,
CI-friendly, and faithful to the production SAF code path.

The interactive-picker + `takePersistableUriPermission` real-grant round-trip is
deliberately **not** covered here (it would reintroduce picker flakiness); it is
exercised in normal manual use and the persistable-permission call itself is a
one-liner already wired in `SafVaultLocationStore` (Slice 2).

## Architecture

```
   TestCloudDocumentsProvider              app-private working copies          core (real .so)
   content://<authority>/tree/<id>  ──materialize─▶  filesDir/working/<key>/  ──path──▶ open/unlock/
   (temp-dir-backed, fault-injectable)◀──flush──────  (real POSIX path)               sync_once/save_block
```

The instrumented tests assemble the **real** production wiring from Slice 5
(`safCloudFolderPort` → `VaultMirror`/`VaultMirrorWorkingCopy` →
`VaultWorkingCopyCoordinator` → the uniffi open/sync ports) and point the cloud
end at the test provider's tree URI instead of a picked Drive/Dropbox folder.
Nothing in `:vault-access`/`:kit`/`:app` production code is special-cased for the
test — the only substitution is the SAF backend behind the `content://` URI.

## Components

| # | Component | Module / source set | Purpose |
|---|---|---|---|
| 1 | `TestCloudDocumentsProvider` + tree-URI helper + fault hook | `:kit` `androidTest` | Real SAF backend over a temp dir; deterministic; injects write/delete/create faults for the offline + `deleteFile`-returns-false branches |
| 2 | `SafCloudFolderPortInstrumentedTest` | `:kit` `androidTest` | Factory branch coverage: directory walk + create, `findOrCreate` overwrite (delete-then-create), `deleteFile`-returns-false guard, idempotent delete-absent, read/write `"wt"` round-trip |
| 3 | `CloudWorkingCopyLifecycleInstrumentedTest` | `:kit` `androidTest` | create→flush→materialize→open round-trip (real `.so` + real SAF); offline-flush-then-retry; **createThenOpen offline-create→reopen** (the #327 trigger) |
| 4 | `TwoWorkingCopiesConflictInstrumentedTest` | `:kit` `androidTest` | Two working dirs over ONE SAF tree → conflict-copy ingest + CRDT merge → **full content convergence** assertion (mirrors `cli/tests/two_instance_convergence.rs`) |
| 5 | `PendingFlushNotPersisted` + `createThenOpen` verify-after-set (#327) | `:vault-access` (pure) | After `marker.set()` on a failed offline-create push, re-check `isSet()`; if still false, throw the distinct typed error instead of the raw push exception |
| 6 | Materialize-clobber guard + `:app` handling of `PendingFlushNotPersisted` | `:vault-access` + `:app` | Make `openExisting` refuse to materialize over an un-pushed working copy when the marker is absent (the reachable route-2 clobber); `:app` surfaces a distinct "created but not yet synced" signal |
| 7 | Run-only confirmation | — | The 7 Slice-4 screen tests + the existing instrumented suite pass on the emulator |

Per project convention, design each new test file as a focused unit; split toward
a directory module before any file approaches ~500 lines. Shared instrumented
helpers (vault staging, the test provider, tree-URI construction) live in their
own files reused across the test classes, mirroring `GoldenVaultStaging.kt`.

## The test DocumentsProvider

A `DocumentsProvider` subclass registered in the `androidTest` manifest under a
test authority, backed by a `File` temp root handed in at test setup. It
implements the minimal SAF surface the shim exercises:

- `queryRoots` / `queryDocument` / `queryChildDocuments` — so `DocumentFile`
  traversal (`listFiles`, `findFile`, `isDirectory`) works.
- `openDocument` — `"r"` and `"w"`/`"wt"` modes via `ParcelFileDescriptor`, so
  `ContentResolver.openInputStream`/`openOutputStream("wt")` round-trip real
  bytes.
- `createDocument` (file + dir) and `deleteDocument` — so `findOrCreate`'s
  directory creation + overwrite-by-delete-then-create and the `deleteFile` seam
  hit real provider calls.

**Fault injection.** A test-controlled hook (a settable predicate keyed by op +
path) lets a test force: the next `openDocument("w")` to throw (simulate an
offline flush failure); `deleteDocument` to return `false` on an existing file
(the `findOrCreate` overwrite guard and the `deleteFile`-returns-false guard);
`createDocument` to fail. This makes the offline and error branches deterministic
without depending on real network/disk conditions.

The provider's tree URI is built with
`DocumentsContract.buildTreeDocumentUri(authority, rootDocId)` and granted to the
instrumentation process; no `ACTION_OPEN_DOCUMENT_TREE` UI is launched.

## #327 fix — verify the offline-create marker actually persisted

### The gap (from the issue)

`createThenOpen` protects an **offline-created** vault: when the initial
`mirror.flush()` (working→cloud push) fails, the new vault lives ONLY in the
working dir; `marker.set()` makes the next `openExisting()` do push-before-pull
instead of materialize-first. But `FilePendingFlushMarker.set()` is best-effort
and swallows all I/O exceptions (correct for the must-not-throw background
`afterCommit` path). On the **critical** create path, a swallowed `set()` failure
silently voids the data-loss guard.

### The fix

Keep the `PendingFlushMarker.set()` contract unchanged (still best-effort, for
`afterCommit`). Strengthen only `createThenOpen`:

```kotlin
} catch (e: Exception) {
    marker.set()
    if (!marker.isSet()) {
        // The offline-created vault has NO retry guard: escalate louder than a
        // normal (recoverable) offline-create push failure.
        throw PendingFlushNotPersisted(createdVaultUuidHex, e)
    }
    throw e
}
```

`PendingFlushNotPersisted` is a distinct exception carrying the uuid and the
original push cause. This is pure ordering logic, host-tested in `:vault-access`
with a failing-marker fake (a `PendingFlushMarker` whose `set()` is a no-op so
`isSet()` stays false).

### Why the marker is load-bearing (corrected)

An offline-created vault **is** persisted as a remembered location *before* the
push: `store.persist(...)` runs in `VaultProvisioningViewModel.create()`
("persist BEFORE mnemonic") and again via `recordSelection` at `onAcknowledge`,
both while the vault exists only in the working dir. So after a failed
offline-create push there are **two** reopen routes, not one:

1. **In-memory retry** — the user submits a credential on the Unlock screen they
   are already on: `cloudTarget.isCreate=true` → `createThenOpen` retries the push,
   never materializes. Safe regardless of the marker.
2. **Selection-screen Open** — the user backs out / kills the app, later taps
   "Open": `locationStore.load()` → `CloudVaultTarget(isCreate=false)` →
   `openExisting()` → `materialize()`. This route does push-before-pull **only**
   `if (marker.isSet())`. If the marker silently failed to persist, it skips the
   flush and materializes the empty/peer cloud over the working copy, deleting the
   only copy of the freshly-created vault. **Irrecoverable.**

So the marker is genuinely load-bearing for route 2, and #327 is a real,
reachable data-loss bug — not merely a missing warning.

### `:app` / coordinator handling

The coordinator escalation (`PendingFlushNotPersisted` when `isSet()` stays false
after `set()`) is necessary but **not sufficient** — `:app` must actually prevent
the route-2 materialize-clobber, not just log it. The guard (exact mechanism
chosen in the implementation plan; all are pure/host-testable):

- **Chosen — `VaultMirror.materialize()` refuses to pull from a manifest-less
  cloud.** A cloud folder with no `manifest.cbor.enc` is not a valid vault to pull
  from (it is empty / never-pushed / mid-create). When the cloud lacks a manifest
  but the working copy has one, `materialize()` is a no-op (returns an empty
  `MirrorReport`) rather than deleting the un-pushed working copy. This closes the
  clobber at the exact mechanism, independent of how the marker was lost, and
  avoids the stale-overwrite hazard a blanket "flush-if-populated" guard would
  introduce (pushing an older local manifest over a newer peer one). It does not
  move merge logic into Kotlin — it only declines an invalid pull. The
  freshly-created vault stays intact locally and reaches the cloud on the next
  `afterCommit` flush.
- Alternatives considered: defer `store.persist` until the first successful push
  (removes route 2 for un-pushed vaults, but changes the create UX — the vault no
  longer appears in the list until synced); or have `openExisting` actively flush
  the un-pushed working copy up on this branch (needs the mirror to expose
  manifest-presence; the no-op guard plus the existing marker path already prevent
  data loss without the extra interface surface).

`:app` additionally surfaces a distinct "created but not yet synced" signal on
`PendingFlushNotPersisted`. The chosen guard + the routing branch are
host-tested at the `:vault-access`/`:app` layers.

### Instrumented coverage of the marker-write-failure branch

Point a real `FilePendingFlushMarker` at an unwritable path (its parent is a
regular file, so `mkdirs()`/`createNewFile()` fail), drive `createThenOpen` with
a flush that fails against the test provider, and assert `PendingFlushNotPersisted`
is thrown and the working copy still holds the freshly-created vault (not
clobbered).

## Data flows exercised end-to-end (real `.so` + real SAF)

- **Create round-trip:** `createVaultInFolder` into a fresh working dir →
  `createThenOpen` flush working→test-provider tree → reopen via `openExisting`
  (materialize tree→working → open+sync) → record content matches.
- **Offline flush retry:** commit an edit → `afterCommit` flush fails (fault) →
  marker set → next `openExisting` flushes first (push-before-pull) → tree now
  holds the edit → second working copy materializes and sees it.
- **Offline create→reopen (#327 trigger):** create with the first flush forced to
  fail → marker set (happy) → reopen via the **selection-screen Open route**
  (`openExisting`) → push-before-pull pushes the un-pushed vault up, no clobber →
  success. Plus the marker-write-failure variant → `PendingFlushNotPersisted` and
  `openExisting` still refuses to materialize over the un-pushed working copy (the
  load-bearing-marker clobber is closed at the materialize guard, not just signaled).
- **Two-copies conflict:** working copies A and B both materialize the same base
  tree, then each commits a divergent edit (same vault owner, two devices). The
  shim's `flush()` *overwrites* the cloud manifest, so it does NOT itself create a
  fork — the **cloud provider** is the conflict-copy creator in production. The
  test therefore **simulates the provider**: A flushes (canonical
  `manifest.cbor.enc` + A's block), then the test writes B's manifest into the tree
  as a sibling named `manifest.cbor.enc (conflicted copy)` (any name
  `starts_with("manifest.cbor.enc")` is detected by `enumerate_manifest_siblings`
  in `core/src/sync/ingest.rs`) plus B's block. Each side then `openExisting()` →
  `materialize()` pulls the canonical + sibling + both blocks (the planner treats
  the sibling as just another file) → `sync_once` authenticates + ingests the
  sibling → CRDT-merges → **both working copies converge to identical merged record
  content.**

## Error handling

- A forced flush failure surfaces as a thrown exception from `mirror.flush()`,
  folded to `CloudFolderException` by `safCloudFolderPort` — the existing typed
  boundary; the coordinator's marker logic reacts to it.
- `deleteFile`-returns-false (provider returns `false` on an existing doc) →
  `CloudFolderException("cannot delete …")` / `("cannot overwrite …")`, proving
  the shim never silently diverges the cloud from the working copy.
- `PendingFlushNotPersisted` is the one new typed error, handled distinctly in
  `:app` (above).

## Testing strategy

- **TDD throughout (RED proven), subagent-driven** — per-task implementer
  (RED→GREEN→commit) → per-task spec+quality review → fix loop → whole-branch
  review on opus → fix wave, in the project-local worktree. Mirrors Slices 3–5.
- **Host (JVM):** the #327 `createThenOpen` verify-after-set logic (failing-marker
  fake); the `:app` `PendingFlushNotPersisted` routing branch.
- **Instrumented (emulator, real `.so` + real SAF):** components #2–#4 above plus
  the marker-write-failure branch.
- **Run-only:** the 7 Slice-4 screen tests + the existing instrumented suite green
  on `emulator-5554`.

### Invariants preserved
- Pure ordering logic stays in `:vault-access`; FFI/SAF/Android in `:kit`;
  UI/wiring in `:app`. **No merge logic in Kotlin** — convergence is proven by the
  core via the two-copies test.
- **No core `src/` change, no on-disk-format / spec / `conformance.py` /
  conflict-KAT / observable-byte change.** This slice is tests + one Kotlin
  coordinator robustness fix + one new typed Kotlin error.
- `PendingFlushMarker.set()` stays best-effort; `afterCommit` still never throws.

## Out of scope

- Interactive-picker / `takePersistableUriPermission` real-grant UiAutomator test
  (picker flakiness; manual-use + Slice-2 wiring cover it).
- Cloud-vault biometric write-reauth (separate later slice; `NoopReauthGate`
  remains correct for an un-enrolled cloud vault).
- Vault-shape probe before `recordSelection` (belongs with materialize hardening;
  treeUri-keying already makes a wrong pick non-destructive).
- Real-device (physical phone) runs; multi-recipient sharing UI; autofill; Play
  Store infra.

## Acceptance

- TDD (RED proven) for every new test and the #327 fix.
- Instrumented gate green on the emulator: components #2–#4 + the
  marker-write-failure branch.
- Host gate green: the #327 `:vault-access` logic + the `:app` routing branch.
- The push-before-pull, offline-create-retry, and two-copies full-content
  convergence behaviors proven **end-to-end on real SAF**, not just host-side.
- `:vault-access:test` + `:kit:testDebugUnitTest` + `:app:testDebugUnitTest` +
  both `:app` compile targets green; Kotlin + Swift conformance 27/27 unchanged
  (no FFI surface change this slice).
- Epic #321 closeable; #327 closed.

## Key references

- `docs/superpowers/specs/2026-06-27-android-cloud-drive-provisioning-design.md` — parent design (row #6).
- `android/kit/src/main/kotlin/org/secretary/mirror/SafCloudFolderPort.kt` — the factory whose on-device branches this covers.
- `android/vault-access/src/main/kotlin/org/secretary/mirror/VaultWorkingCopyCoordinator.kt` — `createThenOpen`/`openExisting`/`afterCommit` (#327 fix site).
- `android/kit/src/main/kotlin/org/secretary/mirror/FilePendingFlushMarker.kt` — best-effort marker (contract unchanged).
- `android/app/src/main/kotlin/org/secretary/app/CloudVaultOpen.kt` — `:app` open/create routing (#327 `:app` branch).
- `android/kit/src/androidTest/kotlin/org/secretary/sync/{SyncRoundTripInstrumentedTest,GoldenVaultStaging}.kt` — the established instrumented pattern (real `.so` + staged vault) this extends.
- `cli/tests/two_instance_convergence.rs` — the conflict topology the two-copies test mirrors.
- AndroidX `DocumentsProvider` / `DocumentsContract` SAF testing (`StubProvider` pattern).
