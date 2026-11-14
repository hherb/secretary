# NEXT_SESSION.md: SilentMerge commits its merge; desktop and Android on session sync

Branch `feature/silent-merge-commit`, worktree `.worktrees/silent-merge-commit`,
base `aa34d4f2` (`main`, the #101 merge). The PR is open; see
`gh pr list --head feature/silent-merge-commit`.

Design decision (asked and answered at session start): #730 uses option (a).
A SilentMerge pass writes its merge, as crypto-design §10 already requires.
No spec edit was needed.

---

## (1) What shipped

| SHA | What |
|---|---|
| `0c403a1f` | #730: the four CLI passes commit a manifest-only merge on the SilentMerge arm (`commit_manifest_only_merge`), and every merge commit folds the prior highest-seen clock into the written clock (`commit_merge`). The bridge session refresh uses the post-pass clock on every refreshing arm (`Baseline::PrePass` deleted). |
| `4377f412` | #732 desktop: `sync_now` / `sync_commit_decisions` take no password and call `sync_*_with_session`. `needs_refresh` is deleted. Sync now and Apply sit behind `authorizeWrite`. `SyncPasswordDialog` is deleted, and SilentMerge is a plain success. |
| `48be81ae` | #733 Android: no password or folder anywhere in the sync stack. `UniffiVaultSyncPort(session)` runs through `UniffiVaultSession.syncThroughSession` / `commitDecisionsThroughSession`. `refreshIfNeeded`, `refreshFromDisk`, the password sheet, `dispatchPostOpenSync` and `launchSyncAtUnlock` are deleted. Gate on Sync now and Apply (new `VaultSyncError.ReauthFailed`). Sync-at-unlock runs for every unlock kind. Inline error line under the badge. |
| `6a3705f7` | iOS and KAT doc comments that described the lockout. |
| `0d83c528` | README, ROADMAP, CLAUDE.md (#101 invariant bullet), rustdoc private-link fix. |
| (this commit) | This handoff and the symlink retarget. |

**Evidence for #730:**
- `ffi/secretary-ffi-bridge/src/sync/session/silent_merge_tests.rs`, 3 tests.
  All three failed before the fix with the issue's exact symptoms: the repeat
  pass returned `RollbackRejected`, and the disk clock lacked the local entry.
- `scripts/mutate.py`, two rows, both `RED_AS_EXPECTED` (self-test 20/20):
  - Dropping the local-clock fold reds `a_silent_merge_writes_a_manifest_carrying_the_local_clock`.
  - Restoring the old no-write fast path reds the two repeat-pass tests.
- On device: `SyncRoundTripInstrumentedTest.silentMerge_thenRepeatPass_thenWrite_onDevice`
  (two working copies, each adding its own block) goes SilentMerge, then
  NothingToDo, then the write succeeds.
- Desktop: `sync_now_after_a_silent_merge_lets_the_next_write_succeed`.

**Gates on this branch, each exit 0:**
- `cargo fmt --check`
- clippy `-D warnings`
- `cargo test --release --workspace`
- rustdoc `-D warnings` (rerun after the fix)
- `conformance.py`
- Hygiene guards, each with its self-test: payload, test-support placement,
  secret-slot, lean binding, ci wiring, iOS public-log, Android log
- `pnpm test` (783), `svelte-check`, `eslint`
- Gradle unit tests: `:vault-access`, `:sync-ui`, `:kit`, `:app`
- Gradle compiles: `:browse-ui`, `:app`, and every androidTest source set
- `swift build` of SecretaryVaultAccess (iOS changes are comments only)

**Instrumented tests, run on `Medium_Phone_API_36.1`:**
- kit: 4/4 (`SyncRoundTripInstrumentedTest`, `TwoWorkingCopiesConflictInstrumentedTest`).
- sync-ui: `SyncScreenUiTest`.
- app: `MakeVaultSyncSmokeTest` (2), `OpenBrowseWithSyncSmokeTest`,
  `OpenWithRecoverySmokeTest`, `BlockCrudRoundTripUiTest`,
  `BrowseWithSyncSettingsEntryUiTest`.
- Fails, pre-existing: `BrowseWithSyncScreenUiTest` (line 65, the "Blocks"
  header). It fails identically on a clean `origin/main` checkout; filed as #743.

**Not run:**
- `swift test` (no Swift code changed).
- Swift/Kotlin conformance runners (#728).
- pyo3 pytest (#501, #738).
- No manual GUI pass on desktop or Android.

## (2) What is next

1. **Merge this PR.** Acceptance: all 25 required checks green.
2. **Manual GUI pass, desktop and Android** (never done for this branch):
   - Sync now with the re-auth gate enabled prompts once, then syncs.
   - Cancelling the prompt syncs nothing.
   - A conflict's Apply prompts again only outside the grace window.
   - Android: a biometric unlock now syncs at unlock.
   Use a throwaway vault, never the fixture.
3. **#744**: §10 says a merge adds "+1 for the merging device"; no merge
   ticks. Ask the user first: amend §10, or thread a device UUID through the
   sync API in every layer.
4. **#736** iOS browse VM blocks the main actor; **#734** rollback-specific
   refresh message; **#740** / **#741** / **#742** from the #101 review.
   Before working #741 (Android refresh wiring untested), check whether it
   still applies: the code it was about is deleted.
5. **#737 / #729** size caps; **#738** pyo3 retention test; **#731**
   auto-sync on folder change; **#743** the pre-existing UI test failure.
6. Carried over: #649, #683, the nested non-map sweep, #677, #668 / #693
   (spec questions, ask the user), #699 / #701-#705.

## (3) Open decisions and risks

- **#744 is a spec divergence** that predates this branch. The merged clock
  is the LUB with no tick. That is enough for #730: on a concurrent relation
  the LUB strictly dominates both inputs.
- **Android `UniffiVaultSession` holds its session lock across a whole sync
  pass.** `refreshFromDisk` already held it across a verify. A pass runs on
  `Dispatchers.IO`, but `wipe()` on lock-on-background waits on the main
  thread for an in-flight pass. With no Argon2id in the pass this is short,
  but nobody has measured it on a large vault.
- **Behaviour change: Android sync-at-unlock now runs on biometric and
  recovery unlocks too** (the iOS behaviour). The cloud open path still only
  refreshes status at unlock, unchanged.
- **Android "Sync now" is gated only when a device secret is enrolled.**
  That is the existing `GraceWindowReauthGate` rule for every write; a
  password-only session syncs without a prompt, as it writes without one.
- **#741 and #742 may be partly obsolete** (see (2)); verify before working them.
- **Worktrees.** The temp `origin/main` worktree used for #743 is removed.
  These are carried over; ask before deleting any of them:
  - `.worktrees/session-sync` (merged; holds an untracked `target-fixwave/`),
  - the two detached `.claude/worktrees/` checkouts,
  - the branch `backup-pre-reword-1787543234`.

## (4) How to resume

```bash
cd /Users/hherb/src/secretary/.worktrees/silent-merge-commit
pwd && git branch --show-current     # feature/silent-merge-commit
git fetch origin && git log --oneline HEAD..origin/main
gh pr checks "$(gh pr list --head feature/silent-merge-commit --json number -q '.[0].number')"
cargo test --release --workspace
(cd desktop && pnpm test)
(cd android && ./gradlew :vault-access:test :sync-ui:testDebugUnitTest :kit:testDebugUnitTest :app:testDebugUnitTest)
cargo test --release -p secretary-ffi-bridge --lib silent_merge_tests
```

## (5) Where this document lives

This file. `NEXT_SESSION.md` at the repo root is a symlink to it, retargeted
in the same commit that creates this file.
