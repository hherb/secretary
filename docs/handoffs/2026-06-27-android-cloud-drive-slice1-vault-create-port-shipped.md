# NEXT_SESSION.md — Android cloud-drive provisioning, Slice 1 (VaultCreatePort) ✅ SHIPPED (PR opening)

**Session date:** 2026-06-27. Began with a "take stock" of what's left for usable private iOS + Android apps (both are already functional walking skeletons with full CRUD + unlock + sync; the FFI write surface is complete). Agreed roadmap order: **(1) Android vault provisioning → (2) verify Android biometric on a physical phone → (3) iOS device-unlock routing + trash/restore polish.** Started item (1). Executed in project-local worktree `.worktrees/android-cloud-drive`, branch `feature/android-cloud-drive-provisioning` (cut from `main` @ `4e2f993d`).

**Status:** ✅ **SHIPPED Slice 1 of 6 — branch `feature/android-cloud-drive-provisioning`, PR opening.** Kotlin/Android only. **No core `src/` change, no FFI surface change (wraps the already-bound `createVaultInFolder`), no on-disk-format / spec / `conformance.py` / KAT change.**

## (1) What we shipped this session

**Context — the epic.** Android can currently only open the bundled `golden_vault_001` demo; there is no folder picker and no create-vault flow. The user wants the vault to live in a **cloud-drive folder** (Drive/Dropbox/OneDrive) synced across iOS + Android + desktop. The hard constraint: the Rust core does direct POSIX I/O (`std::fs` + `tempfile::persist`) with **no storage-abstraction seam**, but Android cloud-drive apps expose folders only via SAF `content://` (no real path). The approved design is a **SAF working-copy shim** — operate on an app-private POSIX working copy, mirror to/from the SAF folder, with a **push-before-pull** invariant so the existing sync engine + the cloud provider's conflict-copy mechanism do all merging (no merge logic in Kotlin).

- **Design spec:** [`docs/superpowers/specs/2026-06-27-android-cloud-drive-provisioning-design.md`](../superpowers/specs/2026-06-27-android-cloud-drive-provisioning-design.md) — full architecture, the 6-slice plan, foreclosed alternatives (FUSE/lazy-fetch rejected — no VFS seam), error handling, testing.
- **Slice-1 plan:** [`docs/superpowers/plans/2026-06-27-android-cloud-drive-slice1-vault-create-port.md`](../superpowers/plans/2026-06-27-android-cloud-drive-slice1-vault-create-port.md).

**Slice 1 (this PR) — the `VaultCreatePort`.** The smallest reviewable increment: the ability to *create* a vault from Kotlin (unblocks the create wizard in slice 4). Mirrors the existing `VaultOpenPort` / `UniffiVaultOpenPort` split exactly.

- **Pure contract (`:vault-access`, package `org.secretary.browse`):**
  - `interface VaultCreatePort { suspend fun createInFolder(folderPath: String, password: ByteArray, displayName: String): CreatedVault }` — takes a real POSIX path, like `VaultOpenPort.openWithPassword`. Slice 5's working-copy lifecycle will pass the app-private working subdir to the same call; the SAF mirror sits *above* this port (no rework).
  - `class CreatedVault(val phrase: ByteArray)` — **plain class, not `data class`** (no generated `toString`/`equals`/`copy` over the secret phrase bytes; caller owns zeroizing).
  - `sealed class VaultProvisioningError` with **only** `FolderNotEmpty` + `CreateFailed(detail)` (YAGNI — `FolderInvalid`/`PasswordMismatch` belong to the SAF-mkdir and wizard slices).
- **Real adapter (`:kit`):** `UniffiVaultCreatePort` — wraps `uniffi.secretary.createVaultInFolder`, runs Argon2id on `ioDispatcher` via `withContext`, releases the native `MnemonicOutput` handle via `.use { it.takePhrase() }`. Injectable `createFn` seam (returns `ByteArray?`) makes the success/error/clock logic host-testable without the `.so`. Error mapping: `VaultFolderNotEmpty → FolderNotEmpty`, else → `CreateFailed`; null phrase → `CreateFailed("recovery phrase unavailable")` — byte-identical to the iOS `mapProvisioningError` contract.

**TDD throughout (subagent-driven: implementer → spec+quality review per task → whole-branch review).**
- Host: `CreatedVaultTest` (2), `UniffiVaultCreatePortTest` (5: happy path, arg+clock forwarding, null→CreateFailed, VaultFolderNotEmpty→FolderNotEmpty, other→CreateFailed).
- Instrumented (real `.so` on emulator-5554 / API 36): create→open round-trip asserts 24-word phrase + `blockSummaries().size == 0` (a fresh vault has empty `blocks` — confirmed `orchestrators.rs:294`); non-empty folder → `FolderNotEmpty`.

**Reviews.** Per-task reviews clean (spec ✅ + quality approved). Whole-branch review (opus): **Ready to merge: Yes**, no Critical/Important; independently re-ran host tests green. Six Minor carry-overs: **five fixed** in-branch (one commit each) — `assertSame` no-copy proof, KDoc path-behavior note, dropped nested `runBlocking` to match the sibling sync-test idiom, KDoc link reflow, atomic `Files.createTempDirectory` (removes a `freshDir` delete→mkdir TOCTOU). **One intentionally skipped:** zeroizing the *test* password `ByteArray` — the literal is interned in the class constant pool, so zeroizing the copy is theater with no production relevance ([[feedback_security_no_assumptions]] — the deferral is proven, not assumed). Fix diff re-reviewed: approved, negative tests cannot silently pass (null-sentinel + `assertTrue` fails on no-throw).

**Branch commits** (off `main` @ `4e2f993d`):
| SHA | What |
|---|---|
| `1fa27ccc` | docs: design spec (SAF working-copy shim, push-before-pull) |
| `4f96a700` | docs: slice-1 plan |
| `af42882e` | feat: pure `VaultCreatePort` + `CreatedVault` + `VaultProvisioningError` (`:vault-access`) |
| `25bdb6a9` | feat: `UniffiVaultCreatePort` adapter + error mapping (`:kit`) |
| `a3ff9f6f` | test: instrumented create→open round-trip |
| `615e5452`..`94bc966c` | 5 carry-over Minor fixes (one per commit) |
| (+ handoff commit) | this baton + retargeted `NEXT_SESSION.md` symlink |

### Acceptance (verified this session, in the worktree)
```bash
cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive/android
./gradlew :vault-access:test :kit:testDebugUnitTest          # BUILD SUCCESSFUL — host 2+5 green
export ANDROID_SDK_ROOT=/Users/hherb/Library/Android/sdk ANDROID_HOME=/Users/hherb/Library/Android/sdk
./gradlew :kit:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.browse.UniffiVaultCreatePortInstrumentedTest  # 2/2 on emulator-5554
```
(`connectedAndroidTest` rejects `--tests`; use the `-P…class=` filter — project Android gotcha.)

## (2) What's next
**Slice 1 is done (PR open). Continue the epic with Slice 2.** Each slice is its own plan + PR through the review loop. Remaining slices (from the design spec):
2. `VaultLocationStore` + `SafVaultLocationStore` (persist the SAF tree URI + `takePersistableUriPermission`; mirror iOS `BookmarkVaultLocationStore`).
3. `CloudFolderPort` + pure `VaultMirrorPlanner` + `VaultMirror` (the SAF↔working-copy mirror; **block-first** flush ordering).
4. Provisioning view models + `VaultSelectionScreen` / `CreateVaultWizardScreen` + `AppRoot` routing (keep the demo entry).
5. Working-copy lifecycle: materialize → `sync_once` → operate → **flush-after-every-commit** + pending-flush retry (push-before-pull).
6. Instrumented E2E + offline-flush + conflict-copy-ingest tests (two working copies over one SAF tree, mirroring `cli/tests/two_instance_convergence.rs`).

**Also still on the top-level roadmap (after the epic, or in parallel):** verify Android biometric/Keystore on a **physical** phone (only iPhone has the on-device proof today); iOS device-unlock routing decision + trash/restore UI on both platforms.

**Acceptance template:** TDD (RED proven), typed-error surface proven not assumed on security paths, host + instrumented gate green, pure logic in `:vault-access` / FFI+Android in `:kit`, no merge logic in Kotlin (the core owns CRDT).

**File a tracking epic issue** when starting Slice 2 (none exists yet — confirmed no open Android-provisioning issue).

## (3) Open decisions and risks
- **Storage model (resolved by user):** all-cloud-drive on every device → Android needs the SAF working-copy shim (chosen over real-folder/Syncthing and over "app-private now"). Slices 2–6 build it. Syncthing avoids the shim but the user wants native cloud-drive; the design keeps a real-folder `CloudFolderPort` impl possible as a later additive option.
- **Slice-1 seam is forward-compatible:** taking `folderPath: String` (a real path) means the shim sits *above* this port; the create call is unchanged when slice 5 hands it the working-copy subdir.
- **Risk:** low. Slice 1 adds two new Kotlin files + tests, wraps an already-shipped FFI, changes no core/FFI/format. No observable byte/semantics change.
- **Generated-binding ktlint noise** (`Unable to auto-format secretary.kt`) is on the **uniffi-generated** file, pre-existing, not this slice's code.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# If this PR merged, remove the worktree + branch:
#   git worktree remove .worktrees/android-cloud-drive && git branch -D feature/android-cloud-drive-provisioning
git worktree list && git status -s
# Start Slice 2 from the design spec's component table; brainstorm → plan → subagent-driven execute.
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; symlink retargeted in the same commit on the feature branch (new path → no add/add conflict; `main` updates cleanly on merge). Per [[feedback_next_session_in_pr]] / [[feedback_next_session_main_authoritative]] the baton rides inside the PR — do **not** sync to `main` during the pause window.

## Closing inventory
- **State on close:** PR opening on `feature/android-cloud-drive-provisioning` (10 commits: 2 docs + 3 feat/test + 5 fixes + handoff). Worktree `.worktrees/android-cloud-drive`.
- **Acceptance:** host `:vault-access:test` + `:kit:testDebugUnitTest` green; instrumented `:kit:connectedDebugAndroidTest` 2/2 on emulator-5554; whole-branch review approved; carry-over fixes re-reviewed clean.
- **README.md / ROADMAP.md / CLAUDE.md:** unchanged (slice 1 of an in-flight epic; no new product capability or documented command yet — per [[feedback_readme_style]]).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-06-27-android-cloud-drive-slice1-vault-create-port-shipped.md`.
