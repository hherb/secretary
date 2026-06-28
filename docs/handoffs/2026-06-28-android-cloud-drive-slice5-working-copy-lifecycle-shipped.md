# NEXT_SESSION.md — Android cloud-drive provisioning, Slice 5 (working-copy lifecycle) ✅ SHIPPED (PR opening)

**Session date:** 2026-06-28. Resumed the **Android cloud-drive vault-provisioning epic** ([#321](https://github.com/hherb/secretary/issues/321)) from the Slice-4 baton (Slice 4, PR #325, merged @ `f0e1499a`). This session shipped **Slice 5 of 6 — the working-copy lifecycle**: the SAF working-copy round-trip (materialize → sync → operate → flush) wrapped around the already-bound Android sync orchestration, governed by **push-before-pull**, replacing the two Slice-4 seams. Executed subagent-driven (fresh implementer per task → spec+quality review per task → fix loop → whole-branch review on opus → fix wave) in project-local worktree `.worktrees/android-cloud-drive-working-copy-lifecycle`, branch `feature/android-cloud-drive-working-copy-lifecycle` (cut from `main` @ `f0e1499a`). Mostly Kotlin/Android + one additive FFI change; **no core `src/`, no on-disk-format / spec / `conformance.py` / conflict-KAT / observable-byte change** (the create FFI gained a `vault_uuid` field — additive, not in `conformance_kat.json`).

## (1) What we shipped this session

**Slice 5 — the working-copy lifecycle.** Android can now **open a remembered cloud-drive vault** and **open a freshly-created vault into Browse** via the SAF working-copy round-trip. The merge/CRDT stays entirely in the Rust core; the new Kotlin only decides which bytes move and in what order.

- **Additive FFI — `create_vault_in_folder` returns `vault_uuid`:** the bridge recovers the uuid by decoding the just-written `vault.toml` via core's existing `unlock::vault_toml::decode` (no core-signature change; desktop's `create.rs` caller untouched). Threaded through uniffi (Kotlin+Swift `CreatedVaultInFolder` dictionary), pyo3 (2-tuple), and the iOS Swift call site (`.mnemonic`). Both conformance suites stay **27/27**.
- **`VaultLocation.vaultUuidHex` + codec v2** (`:vault-access`): default `""` (= uuid not yet known) so Slice-4 call sites compile unchanged; codec v2 carries the uuid, decodes v1 blobs tolerantly to `""`, and is overflow-safe (Long-cast length guard).
- **`CreatedVault.vaultUuid`** (`:vault-access`/`:kit`): the create port surfaces the uuid; the provisioning VM threads `hexOfBytes(uuid)` into `Done.location.vaultUuidHex`. `CreatedVault` stays a plain class (phrase never structurally compared/logged); phrase zeroize preserved.
- **`PendingFlushMarker` port + `FilePendingFlushMarker`** (`:vault-access`/`:kit`): a durable one-bit "working copy holds un-pushed edits" flag. Lives **outside** the working copy (in the app-private sync-state dir) — `VaultMirror` mirrors *every* file under the working dir, so a marker inside it would be pushed to the cloud and deleted on materialize.
- **`VaultWorkingCopyCoordinator`** (`:vault-access`, the heart): pure, host-tested, enforces **push-before-pull**. `openExisting()` = (marker set → flush → clear) → materialize → openAndSync; a failed pending-flush **aborts before materialize and leaves the marker set** (never pull over un-pushed edits). `createThenOpen()` = flush → persist → open, and (post-review fix) **sets the marker on a failed push** so an offline-created vault is never clobbered. `afterCommit()` flushes, clears on success / sets marker on failure, never throws. Keystone host test asserts call **order** `[flush, materialize, open]`, not just counts.
- **`VaultBrowseModel.onCommit` flush-after-commit hook** (`:vault-access`): injected `onCommit: suspend () -> Unit = {}` fires once after each successful committing mutation (both choke points: `guardedWrite` + `onEditCommitted`), not on reads/failed writes. Default no-op keeps the demo path unchanged.
- **`:app` wiring** (`AppRoot` + new `CloudVaultOpen.kt`): both Slice-4 seams replaced. **Credential routing = the existing Unlock screen** for both cloud paths (user decision): opening a remembered cloud vault prompts; the freshly-created vault re-prompts once after the recovery phrase (desktop "no auto-open" precedent). The cloud working dir **and** pending-flush marker are keyed by `cloudVaultKey` = **SHA-256(treeUri)** (stable per cloud folder, identical for create/create-then-open/open) — so un-pushed edits never orphan across the learn-the-uuid-on-first-open transition and two imported vaults never collide. **Per-device `SyncState` stays keyed by the real `vault_uuid`** (learned-on-open, persisted back). Demo golden-vault path is provably untouched.

**TDD throughout (subagent-driven).** Per task: implementer (RED→GREEN→commit) → spec+quality review → fix loop. New host tests across `:vault-access`/`:kit`: coordinator 7 (incl. the push-before-pull keystone + the createThenOpen-marker-on-failure regression), codec (overflow + v1/v2), pending-marker, CreatedVault uuid, onCommit (both hook sites), `WorkingDirResolverTest` 9 (treeUri-keying stability/no-collision). FFI: bridge uuid round-trip test + isolated `CreatedVaultInFolder` wrapper test.

**Reviews & fixes.** Every task reviewed (spec+quality) clean after fixes. In-task fixes: codec integer-overflow guard; dropped a dead `createdVaultUuid` field; added the second onCommit hook-site test. **Whole-branch review (opus) found one Important data-safety gap** — `createThenOpen` didn't set the pending-flush marker on a failed push, so an **offline-created vault could be silently wiped** by a materialize-first reopen; **fixed** (`7836495`) + regression test. Worthwhile minors closed (isolated uniffi wrapper test; unused test field). Cosmetic comment nits + NoopReauthGate-on-cloud (deferred by design) consciously skipped.

**Branch commits** (off `main` @ `f0e1499a`):
| SHA | What |
|---|---|
| `5021758` | docs: slice-5 design |
| `74fed93` | docs: slice-5 plan |
| `9e6ca45` | feat(ffi): bridge `create_vault_in_folder` returns `vault_uuid` |
| `58693fb` | feat(ffi): thread `vault_uuid` through uniffi + pyo3 + iOS |
| `11e342e` | feat: `VaultLocation.vaultUuidHex` + codec v2 |
| `a832e75` | fix: overflow-safe codec length guard |
| `699c981` | fix: `:kit` `UniffiVaultCreatePort` for new return type (incidental) |
| `22e7873` | feat: `CreatedVault.vaultUuid` + VM threads it |
| `43250fe` | refactor: drop dead `createdVaultUuid` field |
| `2b9c447` | feat: `PendingFlushMarker` + file-backed impl |
| `0ca1ca0` | feat: `VaultWorkingCopyCoordinator` (push-before-pull keystone) |
| `ba037b0` | feat: `VaultBrowseModel.onCommit` hook |
| `6c1b358` | test: cover `onEditCommitted` onCommit hook |
| `95fc836` | feat: `:app` wire cloud open + create-then-open + flush-after-commit |
| `293deb9` | fix: key cloud working dir + marker by treeUri (no orphan) |
| `51c59de` | docs: README/ROADMAP slice-5 entry |
| `7836495` | fix: `createThenOpen` sets marker on failed push (no offline-create data loss) |
| `3da9f5a` | test(ffi): isolated `CreatedVaultInFolder` wrapper test |
| `27d4630` | test: drop unused `FakeMarker.events` field |
| `5b39ec1` | style(ffi): cargo fmt the wrapper test |
| (+ handoff commit) | this baton + retargeted `NEXT_SESSION.md` symlink |

### Acceptance (verified this session, in the worktree)
```bash
cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-working-copy-lifecycle
cargo fmt --all --check                                   # clean
cargo clippy --release --workspace --tests -- -D warnings # clean
cargo test --release -p secretary-ffi-bridge -p secretary-ffi-uniffi -p secretary-ffi-py  # green
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh   # 27/27
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh    # 27/27
cd android && ./gradlew :vault-access:test :kit:testDebugUnitTest :app:testDebugUnitTest \
  :app:compileDebugKotlin :app:compileDebugAndroidTestKotlin    # all green / BUILD SUCCESSFUL
```
Branch scope confirmed: `android/` + `ffi/` (additive create DTO) + one iOS Swift line + `docs/` + `README.md`/`ROADMAP.md`. **No emulator run this session** — the SAF/`.so` end-to-end round-trip is Slice 6 (instrumented).

## (2) What's next
**Slice 5 is done (PR open). Continue the epic with Slice 6 — the final slice.** From the design spec `docs/superpowers/specs/2026-06-27-android-cloud-drive-provisioning-design.md` (component row #6 testing) + this slice's spec:

6. **Instrumented E2E + offline/conflict device tests** (emulator, real `.so` + real SAF):
   - **create → flush → materialize → open** round-trip on a SAF tree.
   - **offline-flush-then-retry**: a failed flush sets the pending marker; next open does push-before-pull. **Include the `createThenOpen` offline-create → reopen scenario** (the real-world trigger for the data-loss gap fixed this slice).
   - **two working copies over one SAF tree** for conflict-copy ingest (mirrors `cli/tests/two_instance_convergence.rs`).
   - Exercise the on-device-only SAF factory paths the host suite can't reach (`SafCloudFolderPort` `findOrCreate` overwrite + `deleteFile`-returns-false branches; the Slice-2 real-SAF `takePersistableUriPermission` round-trip).
   - **Also run the 7 authored Slice-4 instrumented screen tests** on the emulator if not already run at the Slice-4 merge.

**Acceptance template:** TDD (RED proven); instrumented gate green on the emulator; pure logic stays in `:vault-access`, FFI+Android in `:kit`, no merge logic in Kotlin; the push-before-pull + offline-create-retry behaviors proven end-to-end (not just host-side).

## (3) Open decisions and risks
- **End-to-end SAF/`.so` behavior is host/compile-tested only this slice** (by design — Slice 6 is the instrumented slice). The coordinator's ordering invariants are proven host-side with order-recording fakes, but the real materialize/flush over `content://` is unverified on a device until Slice 6. Low risk (the mirror mechanisms shipped + were instrumented-tested in Slice 3; this slice only sequences their calls).
- **Cloud path uses `NoopReauthGate`** — no per-write biometric re-auth over a cloud vault yet (the device-secret enrollment is against the demo/local vault). Deferred deliberately; a `GraceWindowReauthGate` with no enrolled secret behaves identically today. Revisit when cloud-vault device enrollment lands.
- **No vault-shape probe before `recordSelection`** (iOS has `looksLikeVault`). A non-vault SAF folder can be remembered, then Open → materialize pulls whatever is there. The treeUri-keying makes this non-destructive (no orphan), but a real probe (needs a SAF read) belongs with Slice 6's materialize work.
- **`workingVaultDir(filesDir, vaultName)` (the name-keyed create dir) was retired** in favor of `cloudWorkingVaultDir(filesDir, treeUri, reset)` — all cloud working dirs + markers are now treeUri-keyed. SyncState remains `vault_uuid`-keyed (unchanged Rust sync layer). Don't reintroduce uuid-keyed working dirs — it reopens the offline-create/learn-uuid orphan class.
- **README.md / ROADMAP.md updated** this slice, scoped so they do **not** overclaim (provisioning + working-copy round-trip wired + host/compile-tested; instrumented E2E lands in Slice 6).
- **Post-review fix (`/review` of PR #326):** a created vault's `cloudTarget.isCreate` was carried unchanged into the live `Route.Browse` and re-carried on backgrounding (ON_STOP → `Route.Unlock`), so every reopen ran `createThenOpen` (flush working→cloud, open **without** `materialize()`) — this device would never pull another device's remote edits after the first create session. Fixed in `openCloudTarget` by setting `isCreate = false` on the success `Route.Browse` route, so reopens route through `openExisting()` (materialize → open). `:app` recompiles green. Slice 6's E2E should cover create → background → remote-edit-on-another-device → reopen → remote edit is materialized.
- **Filed [#327](https://github.com/hherb/secretary/issues/327)** (slice-6 hardening): `FilePendingFlushMarker.set()` swallows I/O failures even on the critical `createThenOpen` offline-create path, so a failed marker write silently voids the data-loss guard. Low probability (app-private internal dir); a robust fix needs the real-SAF offline E2E deferred to Slice 6.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# If this PR merged, remove the worktree + branch:
#   git worktree remove .worktrees/android-cloud-drive-working-copy-lifecycle && git branch -D feature/android-cloud-drive-working-copy-lifecycle
git worktree list && git status -s
# Start Slice 6 from the design spec (component row #6 testing): instrumented E2E + offline/conflict device
# tests on the emulator (create→flush→materialize→open; offline-flush-retry incl. createThenOpen offline-create→reopen;
# two-working-copies conflict-copy ingest; on-device SAF factory branches). brainstorm → plan → subagent-driven execute.
# Work continues under #321. Android toolchain on this machine: emulator/adb need absolute paths (not on bare PATH).
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; symlink retargeted in the same commit on the feature branch (new path → no add/add conflict; `main` updates cleanly on merge). Per [[feedback_next_session_in_pr]] / [[feedback_next_session_main_authoritative]] the baton rides inside the PR — do **not** sync to `main` during the pause window.

## Closing inventory
- **State on close:** PR opening on `feature/android-cloud-drive-working-copy-lifecycle` (21 commits: 2 design/plan + 19 feat/fix/test/docs/style + handoff). Worktree `.worktrees/android-cloud-drive-working-copy-lifecycle`. Epic issue #321.
- **Acceptance:** Rust fmt + workspace clippy clean; FFI crate tests green; Kotlin + Swift conformance 27/27; Android `:vault-access:test` + `:kit:testDebugUnitTest` + `:app:testDebugUnitTest` green; both `:app` compile targets green. Whole-branch review (opus): one Important data-safety finding fixed + regression-tested; minors triaged (fixed or consciously skipped). Instrumented E2E is Slice 6.
- **README.md / ROADMAP.md:** updated (Slice-5 working-copy lifecycle, accurately scoped). **CLAUDE.md:** unchanged.
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-06-28-android-cloud-drive-slice5-working-copy-lifecycle-shipped.md`.
