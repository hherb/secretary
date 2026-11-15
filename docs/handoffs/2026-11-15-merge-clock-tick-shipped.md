# NEXT_SESSION.md: a sync merge ticks the merging device (#744)

Branch `feature/merge-clock-tick`, worktree `.worktrees/merge-clock-tick`,
base `2dbb79e0` (`main`, the #745 merge). The PR is open; see
`gh pr list --head feature/merge-clock-tick`.

Decisions asked and answered at session start:
- **#744: thread a device UUID through the sync API** so the code matches
  crypto-design §10 / §11.2 ("plus one for the merging device"). No spec
  edit.
- **#746: an explicit, user-confirmed "reset sync state for this vault"
  action on each platform.** Recorded on the issue; not started.
- **CLI device UUID: both.** Load or create one per vault in the state dir,
  with a `--device-uuid` override.

---

## (1) What shipped

| SHA | What |
|---|---|
| `b1ab0694` | **core**: `prepare_merge(.., merging_device)` records it on `DraftMerge.merging_device`. Block merges tick it; before, they ticked the owner's `user_uuid`. `commit_with_decisions` ticks the manifest clock as the last change to it, after any caller fold, and returns that clock as the new `SyncState`. **cli**: the four passes take `merging_device`. New `cli/src/device.rs` loads or creates `<state-dir>/<vault_hex>.device` under the lockfile; `--device-uuid <32 hex>` overrides it. **bridge**: all four sync entry points (and their `_in` seams) take `device_uuid: [u8; 16]`. **uniffi / pyo3**: take `bytes device_uuid` and validate the length. **desktop**: passes `u.device_uuid`. |
| `d3a23754` | Android `UniffiVaultSession` and iOS `UniffiVaultSession+Sync.swift` resolve the per-vault device UUID their writes use, under the session lock, and pass it to session sync. A resolve failure is `VaultSyncError.Failed`. |
| `a429745d` | README row, ROADMAP entry, and a CLAUDE.md note under "CRDT merge": the manifest tick is the last change to the commit's clock. |
| `a9df5d95` | This handoff and the symlink retarget. |
| (review fix) | PR #750 review, all findings fixed in one commit: see "Review fixes" below. |

**Evidence:**
- `core/tests/sync_merge_tick.rs`, 3 tests:
  - a fresh merging-device entry;
  - an existing entry incremented (3 becomes 4);
  - a block merge ticks the device, not `user_uuid`.
- `cli/tests/pipeline_integration.rs`:
  - `run_one_ticks_the_merging_device_after_folding_the_prior_clock`: a prior entry of 5 is written as 6.
  - The silent-merge test now also asserts the tick.
- Bridge `a_silent_merge_ticks_the_callers_device_uuid`: the session and password entry points both forward their `device_uuid`.
- Binding tests reject a wrong-length `device_uuid`:
  - uniffi: `sync_vault_wrong_length_device_uuid_is_invalid_argument`;
  - pyo3: `test_sync_vault_wrong_length_device_uuid_raises_value_error`.
- `scripts/mutate.py` (self-test 20/20), two rows, both `RED_AS_EXPECTED`, each
  gated on `cargo test --release -p secretary-core --test sync_merge_tick`
  (so the counts are that target's only):
  - T1, dropping the manifest tick, reds the two manifest tests;
  - T2, restoring the `user_uuid` block tick, reds the block test.

**Review fixes (PR #750 review):**
- pyo3 `sync_vault` / `sync_commit_decisions` wrapped the password only after
  the fallible `device_uuid` check, so a wrong-length UUID freed it unwiped
  (the #513/#518 E3 window). Now wrapped first.
- `commit_with_decisions` ticks before step 5's block writes, so an overflow
  fails before any file is written. Overflow maps to `VaultError::ClockOverflow`
  on both the manifest and block paths (`conflict::conflict_to_vault_error`);
  the block path was `InvalidArgument`.
- `cli/src/device.rs`: fsync before `persist_noclobber`; I/O errors name the
  path; a malformed file's error says how to recover.
- New tests: bridge `a_commit_decisions_merge_ticks_the_callers_device_uuid`
  (both commit entry points, manifest and block clock), three
  `secretary-sync once` tests (device file created and reused, `--device-uuid`
  bypasses it, a malformed file fails and is left alone), `--device-uuid`
  parse, and the malformed unit test now checks the file is untouched.
- Stale or overclaiming docs fixed in `draft.rs`, `outcomes.rs`,
  `conflict.rs`, `passes.rs`, `prepare.rs`, the bindings, `state.rs`,
  CLAUDE.md, README and ROADMAP.

**Gates, each exit 0:**
- `cargo fmt --check`
- Both clippy runs (`--tests` and without)
- rustdoc `-D warnings`
- `cargo test --release --workspace`: 105 binaries, 2311 passed, 0 failed
- All seven hygiene guards plus their self-tests: lean binding, iOS public log, Android log, payload, test-support placement, secret slot, ci wiring
- Gradle:
  - unit tests for `:kit`, `:vault-access`, `:sync-ui` and `:app`;
  - `:app` and `:kit` androidTest compiles;
  - `:kit:connectedDebugAndroidTest` on `Medium_Phone_API_36.1`: 25/25, including `silentMerge_thenRepeatPass_thenWrite_onDevice`.
- iOS:
  - `build-xcframework.sh`;
  - SecretaryKit `swift build` and `swift test` (59 XCTest).
- pyo3:
  - `maturin develop --release`;
  - `pytest tests/test_sync.py`: 8 passed.

**Not run:**
- `conformance.py`: no Python, spec or fixture changed.
- `pnpm test`: no TypeScript changed.
- The `:app` instrumented tests.
- The Swift/Kotlin conformance runners (#728). The manual smoke runners (`tests/{swift,kotlin}/SmokeSync`) were updated but not executed.
- No manual GUI pass.

## (2) What is next

1. **Merge this PR.** Acceptance: all 25 required checks green.
2. **#746: a reset-sync-state action** (decided: option 2). Acceptance:
   - Each platform (desktop, Android, iOS; and the CLI, if wanted) offers an explicit, confirmed action that deletes this vault's sync-state file.
   - It is behind the write re-auth gate.
   - After it, the next open accepts the current signed manifest, and a test proves a pre-#730 poisoned device recovers through it.
   - Ask first: does it sit in settings, or on the rollback-refused error?
3. **#749**: one test per app that a SilentMerge's written clock contains the session's device UUID at counter 1.
4. **Manual GUI pass, desktop and Android**. Still never done since #745; see the previous handoff's list.
5. **#736**, **#734**, **#740** / **#741** / **#742**, **#747** / **#748**.
6. **#737 / #729** size caps. #744 grew three over-cap production files (`core/src/sync/prepare.rs`, `cli/src/daemon.rs`, `cli/src/main.rs`); they are noted on #737. It also grew two over-cap test files (`cli/tests/sync_pass_integration.rs`, `core/tests/sync_helpers/mod.rs`) and pushed two past 500 (`core/tests/sync_merge.rs`, `core/tests/sync_merge_vetoes.rs`, each 495 -> 501). Also #738, #731, #743.
7. **#751** (spec question, ask the user): N concurrent copies of one block tick its clock N times, the manifest once. Filed from the PR #750 review; behaviour predates #744.
8. Carried over: #649, #683, #677, #668 / #693 (spec questions, ask the user), #699 / #701-#705.

## (3) Open decisions and risks

- **Behaviour change: written merge clocks gain an entry per merging device.**
  - Every merge now adds `this device: +1` to the manifest clock (once) and to a block clock on each concurrent per-block fold step (so N concurrent copies of one block add N).
  - Older clients read such clocks fine (a clock is a list of entries), and no fixture pins a merge clock.
  - Vaults that merged before this keep their old `user_uuid` entries on block clocks. These are harmless: just another component.
- **The CLI and an app on one machine are two devices** for the same vault: separate UUIDs and separate counters. That is correct for vector clocks.
  - The CLI's `.device` file sits beside its state file. Deleting the state dir gives the CLI a new device UUID, which only adds a new clock entry.
- **Android sessions with no device-UUID provider can no longer sync**: they now fail with `VaultSyncError.Failed`. Every production construction passes a provider (`AppRoot.kt`, `CloudVaultOpen.kt`); only `OpenBrowseSmokeTest` builds one without, and it does not sync.
- **#744 is closed in code.** The GitHub issue stays open until a human closes it (this repo's `(#N)` convention).
- **Worktrees** carried over (ask before deleting): `.worktrees/session-sync`, `.worktrees/silent-merge-commit` (merged), the two detached `.claude/worktrees/`, and the branch `backup-pre-reword-1787543234`.

## (4) How to resume

```bash
cd /Users/hherb/src/secretary/.worktrees/merge-clock-tick
pwd && git branch --show-current     # feature/merge-clock-tick
git fetch origin && git log --oneline HEAD..origin/main
gh pr checks "$(gh pr list --head feature/merge-clock-tick --json number -q '.[0].number')"
cargo test --release --workspace
cargo test --release -p secretary-core --test sync_merge_tick
cargo test --release -p secretary-cli --test pipeline_integration
cargo test --release -p secretary-ffi-bridge --lib silent_merge
(cd android && ./gradlew :vault-access:test :sync-ui:testDebugUnitTest :kit:testDebugUnitTest :app:testDebugUnitTest)
```

## (5) Where this document lives

This file. `NEXT_SESSION.md` at the repo root is a symlink to it, retargeted
in the same commit that creates this file.
