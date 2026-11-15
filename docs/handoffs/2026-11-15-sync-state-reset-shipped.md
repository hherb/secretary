# NEXT_SESSION.md: reset sync state from a refused open (#746)

Branch `feature/sync-state-reset`, worktree `.worktrees/sync-state-reset`,
base `4f4b7dbb` (`main`, the #750 merge). The PR is open; see
`gh pr list --head feature/sync-state-reset`.

Decisions asked and answered at session start (recorded on #746):
- **Placement: on the refused open**, not in settings. A poisoned device's
  open is refused, so it never reaches settings.
- **CLI: document only.** Its rollback log line names the state file.
- **One PR, all platforms.**
- **Android gap: fix it here.** Found while designing: the bridge's open
  check read `dirs::data_dir()/secretary/sync`, but Android's sync writes
  `filesDir/sync-state`, so §10 was inactive at open on Android.

No spec edit: crypto-design §10 and vault-format §10 already require an
explicit "I am restoring from a backup; accept anyway" override. This
implements it.

---

## (1) What shipped

| SHA | What |
|---|---|
| `4edf9464` | **bridge**: `FfiVaultError::RollbackDetected`, now raised by the app-facing open check (it was folded into `CorruptVault`; other `VaultError::Rollback` paths still fold). `vault/reset.rs`: `reset_sync_state_and_open_with_password[_in]` does a full password open, then deletes the state file under the lockfile, then returns the handles. `state_dir.rs`: `set_platform_state_dir`, a once-per-process override that every implicit-dir path resolves through (open check, repair gate, password sync, `sync_status`). **cli**: `state::delete`. **uniffi**: the variant plus both functions. **pyo3** and the desktop `AppError`: the variant. The KAT helper and the Swift/Kotlin conformance error switches are updated. |
| `1be43f2f` | The CLI rollback log line names `<state-dir>/<vault-uuid-hex>.state.cbor` as the manual remedy. The core `VaultError::Rollback` doc points at the implementation. |
| `894b2ff9` | **Desktop**: `reset_sync_state_and_unlock` command, which shares the unlock path's approval gate, path validation and session setup. `Unlock.svelte` adds the prompt. `writeCommands.ts` classifies the command as `session`. |
| `a72a40ab` | **iOS + macOS**: `VaultAccessError.rollbackDetected`, `UnlockViewModel` `.rollbackResetPrompt`, `VaultOpenPort.resetSyncStateAndOpen`, and both unlock views. |
| `207a0c21` | **Android**: `MainActivity.onCreate` calls `installPlatformSyncStateDir`. `VaultBrowseError.RollbackDetected`, the `UnlockScreen` dialog, and `UnlockCredential.Password(resetSyncState = true)`, which routes to `resetSyncStateAndOpenWithPassword`. |
| `bfc79bd9` | README row, ROADMAP entry, a CLAUDE.md note, and the `cli/src/state.rs` tests moved verbatim to `state/tests.rs` (20 state tests before and after). |
| (this commit) | This handoff and the symlink retarget. |

**How it behaves:**
- **Password unlock.** All four apps show the same copy:
  - Title: "This vault looks older than expected"
  - Buttons: "Reset and open" and "Cancel"
  - Confirm reuses the password still in the field.
  - Cancel calls nothing.
- **Biometric or recovery-phrase unlock.** The app shows the error and says to unlock with the master password. It never offers the reset.
- **Why password only.** There is no device-secret reset, so a biometric prompt alone cannot drop rollback protection.

**Evidence:**
- Bridge `vault::reset` tests:
  - a poisoned device recovers;
  - a wrong password leaves the file alone;
  - a held lockfile leaves the file alone.
- Bridge `tests/platform_state_dir.rs`: the override reaches the open check, then the reset recovers. It runs in its own binary because the override is set once per process.
- Desktop `tests/reset_sync_state_integration.rs` (3 tests) and `tests/UnlockRollback.test.ts` (5 tests).
- Swift:
  - 7 `UnlockViewModelTests`;
  - mapping and description tests;
  - `ResetSyncStateOpenTests`: real FFI, a golden-vault copy and a temp state dir.
- Android:
  - JVM: `UnlockCredentialTest`, `BrowseMappingTest`, `UniffiVaultOpenPortResetTest`, `UnlockMessagesTest`, `AppSyncStateDirTest`.
  - Emulator: `UnlockScreenRollbackUiTest` (3 tests) and `:kit` `RollbackResetInstrumentedTest`. With the startup setter removed, the latter fails (`expected:<RollbackDetected> but was:<null>`), as Android did before #746.
- `scripts/mutate.py` (self-test 20/20), two rows, both `RED_AS_EXPECTED`:
  - R1: wiping the state before authentication reds `a_wrong_password_leaves_the_state_file_alone`.
  - R2: ignoring the override reds `the_override_reaches_the_open_check_and_the_reset_recovers`.
  - The spec is not committed; it is in this session's scratchpad.

**Gates, each exit 0:**
- `cargo fmt --check`
- Both clippy runs (`--tests` and without)
- rustdoc `-D warnings`
- `cargo build --release --workspace`
- `cargo test --release --workspace`: 107 binaries, 2329 passed, 0 failed
- All seven hygiene guards plus their self-tests
- Desktop:
  - `pnpm test`: 796/796;
  - `svelte-check`: 0 errors;
  - eslint.
- iOS (agent-run):
  - `build-xcframework.sh`;
  - `swift test`: SecretaryVaultAccess 183, SecretaryKit 62;
  - `build-app.sh` and `build-macos-app.sh`.
- Android (agent-run):
  - the JVM suites: 610 tests;
  - `:app:assembleDebug` and both androidTest compiles;
  - `:kit:connectedDebugAndroidTest`: 26/26.

**Not green, or not run:**
- `:app:connectedDebugAndroidTest`: 43/44. `BrowseWithSyncScreenUiTest` fails on its first sync-badge assertion. #743 records a failure of this test on `main` ("Blocks" header not displayed). This run's assertion differs, and nobody re-ran it on `main`.
- The Swift and Kotlin conformance runners fail to load or link the macOS dylib ("mis-aligned LINKEDIT string pool"). This is #728, a toolchain issue that predates this branch. The Swift harness type-checks against the new bindings.
- pyo3 `pytest`: not run. Only an exception class was added; the pytest suite is not in CI (#501).
- `conformance.py`: no spec, Python or fixture change.
- No manual GUI pass on any platform.

## (2) What is next

1. **Merge this PR.** Acceptance: all 25 required checks green.
2. **Manual GUI pass** (desktop, Android, iOS). To build a poisoned device:
   - sync a vault copy once;
   - restore an older copy of its `manifest.cbor.enc`;
   - unlock. You should get the prompt, then "Reset and open" opens the vault.
   - Also confirm a biometric unlock shows the "use your master password" message.
   - Desktop and Android have still never had the #745 pass either.
3. **#743**: re-run `BrowseWithSyncScreenUiTest` on `main` to see whether the sync-badge failure is the same bug.
4. **#749**: one test per app that a SilentMerge's written clock contains the session's device UUID.
5. **#751** (spec question, ask the user): N concurrent copies of one block tick its clock N times.
6. **#737 / #729** size caps. This PR grew four over-cap files; they are listed on #737.
7. #736, #734, #740 / #741 / #742, #747 / #748, #738, #731. Carried over: #649, #683, #677, #668 / #693 (spec questions), #699 / #701-#705.

## (3) Open decisions and risks

- **The reset accepts whatever signed manifest is on disk**, including a genuinely replayed old one. The copy warns about this and it needs the master password plus a click, but a user who confirms through a real attack loses that rollback detection.
- **Android now enforces §10 at open.** A device that synced to a newer clock and then sees an older disk now gets the prompt instead of a silent open. That is correct, but it is new behaviour for Android users.
- **`set_platform_state_dir` is once per process.**
  - Tests that need it run in their own binary or process.
  - The Android `:kit` instrumented test uses a fixed dir and cleans up the golden vault's baseline afterwards.
  - A new bridge path that calls `secretary_cli::state::default_state_dir()` directly reopens the Android gap (CLAUDE.md note).
- **The iOS `SecretaryDeviceUnlock` package's `UniffiVaultDeviceSlotPort`** still folds a rollback into `.other`. Its only user, `DeviceUnlockScreen`, is not wired into either app.
- **#746 is closed in code.** The issue stays open until a human closes it.
- **Worktrees** carried over (ask before deleting): `.worktrees/session-sync`, `.worktrees/silent-merge-commit`, `.worktrees/merge-clock-tick` (merged), the two detached `.claude/worktrees/`, and the branch `backup-pre-reword-1787543234`.

## (4) How to resume

```bash
cd /Users/hherb/src/secretary/.worktrees/sync-state-reset
pwd && git branch --show-current     # feature/sync-state-reset
git fetch origin && git log --oneline HEAD..origin/main
gh pr checks "$(gh pr list --head feature/sync-state-reset --json number -q '.[0].number')"
cargo test --release --workspace
cargo test --release -p secretary-ffi-bridge --lib vault::reset
cargo test --release -p secretary-ffi-bridge --test platform_state_dir
(cd desktop && pnpm test)
(cd ios/SecretaryVaultAccess && swift test)
(cd android && ./gradlew :vault-access:test :kit:testDebugUnitTest :app:testDebugUnitTest)
```

## (5) Where this document lives

This file. `NEXT_SESSION.md` at the repo root is a symlink to it, retargeted
in the same commit that creates this file.
