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
| 6 | `:app` distinct handling of `PendingFlushNotPersisted` | `:app` | Catch it distinctly: keep `isCreate=true` (no materialize on reopen), surface a louder "created but neither synced nor marked for retry" signal |
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

### `:app` handling

`openCloudTarget`'s catch currently folds every failure into
`Route.Unlock(cloudTarget = target)` with `isCreate` unchanged (still `true`).
That routing is already safe for the in-memory reopen (a created-but-unpushed
vault is never persisted as a remembered location — `persistLocation` runs only
after a successful push — so its only reopen path is the in-memory `cloudTarget`
with `isCreate=true`, which retries `createThenOpen` = push, no materialize). The
fix adds a **distinct branch** for `PendingFlushNotPersisted`: log/surface a
louder "created but neither synced nor marked for retry — do not lose your
recovery phrase" signal, while preserving `isCreate=true` (never route this case
through a path that could `materialize()` an empty cloud over the working copy).
Host-tested at the `:app` routing layer.

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
  fail → marker set (happy) → reopen retries push → success; plus the
  marker-write-failure variant → `PendingFlushNotPersisted` + no clobber.
- **Two-copies conflict:** working copy A and B both materialize the same tree,
  each commits a divergent edit while "offline", both flush → the test provider
  ends with a `manifest (conflicted copy)…` sibling (or both flush in sequence
  producing the fork) → each side's next `openExisting` → `sync_once` ingests +
  CRDT-merges → **both working copies converge to identical merged content.**

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
