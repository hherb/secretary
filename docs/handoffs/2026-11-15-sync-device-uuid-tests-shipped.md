# NEXT_SESSION.md: per-app sync device-UUID tests (#749) and #743

Branch `feature/sync-device-uuid-tests`, worktree
`.worktrees/sync-device-uuid-tests`, base `b9964e9d` (`main`, the #752
merge). The PR is open; see `gh pr list --head feature/sync-device-uuid-tests`.

Decisions taken at session start:
- **Task: #749 + #743.**
- **#751 ruling: tick once.** An N-way merge is one merge event. Recorded on
  #751; not implemented yet (see (2)).
- **Cleanup.** The four merged worktrees and their local branches are
  removed: `session-sync`, `silent-merge-commit`, `merge-clock-tick` and
  `sync-state-reset`. The two detached `.claude/worktrees/` and the branch
  `backup-pre-reword-1787543234` are kept.

## (1) What shipped

All of it is test code. No production, spec, FFI or fixture change.

| SHA | What |
|---|---|
| `790bd09e` | **Desktop**: `tests/sync_device_uuid_integration.rs`. A SilentMerge through `sync_now_in_impl` must put `{device UUID, 1}` on the disk clock. The UUID is read from the per-vault device file, not from the session. |
| `b22fa1d5` | **Android**: `SyncRoundTripInstrumentedTest.silentMerge_ticksTheSessionsOwnDeviceUuid_onDevice`. Two golden copies; A writes once, then merges, so A's entry must be 2. `GoldenVaultStaging.openSession` takes an optional `device`. |
| `279384d8` | **iOS**: `UniffiVaultSessionSyncTests.testSilentMergeTicksTheSessionsOwnDeviceUuid`, same shape as the Android test. |
| `db6c258d` | **#743**: `BrowseWithSyncScreenUiTest` asserted the old header "Blocks". #541 (`6e65ca8d`) renamed it "Your vault". Root cause and runs are recorded on #743. |
| `a0709238` | ROADMAP entry, this handoff, and the symlink retarget. |
| (PR review) | **Desktop commit path**: `ipc_integration.rs::sync_commit_decisions_refreshes_session_so_next_write_succeeds` now also requires `{device UUID, 1}` on the disk clock after the commit, since `sync_commit_core` forwards `u.device_uuid` from its own call site. The Android commit path has the same gap and is noted on #748 (item 4); iOS shares one `syncLocked` for sync and commit. |

**Where the Android and iOS tests read the clock.** No FFI exposes the disk
manifest clock, so they read `sync_status`'s saved clock. The bridge sets that
to the clock it wrote. `a_silent_merge_writes_a_manifest_carrying_the_local_clock`
pins saved == disk on the password entry point (`sync_vault_in`); the session
entry point these tests use shares its `run_locked_pass` save, and nothing
pins saved == disk on the session entry point itself. The desktop tests read
the disk directly.

**Mutations.** Each test reds when its app passes a zero UUID:
- **D1 (desktop):** `[0u8; 16]` in `commands/sync.rs`. `scripts/mutate.py`
  reports `RED_AS_EXPECTED` (self-test 20/20). The spec is in the session
  scratchpad, not committed.
- **D2 (desktop commit, PR review):** `[0u8; 16]` in place of `u.device_uuid`
  in `sync_commit_core`'s `Some(d)` arm. `scripts/mutate.py` reports
  `RED_AS_EXPECTED` on `sync_commit_decisions_refreshes_session_so_next_write_succeeds`.
- **A1 (Android):** `ByteArray(16)` in `UniffiVaultOpenPort.kt`
  `syncThroughSession`. Done by hand: `expected:<2> but was:<1>`.
- **I1 (iOS):** `Data(count: 16)` in `UniffiVaultSession+Sync.swift` `sync`.
  Done by hand: `("1") is not equal to ("2")`.

The harness supports only Rust and Python, which is why A1 and I1 were done by
hand. Both files were restored, with sha1 checked before and after.

**Gates run, each exit 0:**
- `cargo fmt --all --check`
- `cargo clippy --release --workspace --tests -- -D warnings`
- The new desktop test
- Both platform log-hygiene guards
- `build-xcframework.sh`
- iOS `swift test --filter UniffiVaultSessionSyncTests`: 7/7
- Android `:kit:connectedDebugAndroidTest` on `SyncRoundTripInstrumentedTest`: 4/4
- Android `:app:connectedDebugAndroidTest`, full suite: 44/44

**Not run locally:** the full `cargo test --release --workspace`, the full
`swift test`, desktop `pnpm test`, and the Android JVM suites. None of those
gates touch the changed files; CI runs the Rust and desktop ones.

## (2) What is next

1. **Merge this PR.** Acceptance: all 25 required checks green.
2. **#751, ruled "tick once".** Acceptance:
   - `prepare_merge` folds a block's conflict copies with
     `merge_vector_clocks` and ticks the merging device once at the end;
   - crypto-design §11.2 gains a sentence on N-way merges;
   - a test pins +1 for N ≥ 3 concurrent copies, and reds under the current
     per-fold tick;
   - `conformance.py`'s `merge/` and `conflict_kat.json` are checked for an
     N-way case. If one changes, regenerate and review the diff.

   This is a merge-semantics change, so the spec edit comes first.
3. **Manual GUI pass** (needs the user at the devices, carried over from
   #752):
   - Build a poisoned device: sync a vault copy once, restore an older copy
     of its `manifest.cbor.enc`, then unlock.
   - The reset prompt should appear, and "Reset and open" should open the vault.
   - Desktop and Android have still never had the #745 pass either.
4. **#737 / #729**: size caps.
5. **Carried over:** #753, #754, #755, #756, #736, #734, #740 / #741 /
   #742, #747 / #748, #738, #731, #649, #683, #677, and #668 / #693 (spec
   questions), and #699 / #701-#705.

## (3) Open decisions and risks

- **The Android and iOS tests read the saved state, not the disk.** If the
  bridge ever saved a clock different from the one it wrote, they would
  still pass. The bridge test named in (1) pins those two together on the
  password entry point only; the session entry point is covered because it
  shares `run_locked_pass`, not by a test of its own.
- **The Android commit path is unpinned for its device UUID.** Noted on #748
  (item 4), which already tracks that `commitDecisionsThroughSession` has no
  on-device test.
- **The #752 badge-assertion failure did not reproduce.** The test passed
  alone and in the full suite. If it comes back, it is an ordering or flake
  issue, not the header.
- **#743 and #749 are closed in code.** The issues stay open until a human
  closes them.
- **Instrumented tests still do not run in CI.** #743 went stale for 12
  weeks because of that.

## (4) How to resume

```bash
cd /Users/hherb/src/secretary/.worktrees/sync-device-uuid-tests
pwd && git branch --show-current     # feature/sync-device-uuid-tests
git fetch origin && git log --oneline HEAD..origin/main
gh pr checks "$(gh pr list --head feature/sync-device-uuid-tests --json number -q '.[0].number')"
cargo test --release -p secretary-desktop --test sync_device_uuid_integration
(cd ios/SecretaryKit && swift test --filter UniffiVaultSessionSyncTests)   # needs ios/scripts/build-xcframework.sh first
(cd android && ./gradlew :kit:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.sync.SyncRoundTripInstrumentedTest)
```

For #751, start in `core/src/sync/prepare.rs` (the per-`copy_env` loop) and
in the Concurrent arm of `core/src/vault/conflict.rs`.

## (5) Where this document lives

This file. `NEXT_SESSION.md` at the repo root is a symlink to it, retargeted
in the same commit that creates this file.
