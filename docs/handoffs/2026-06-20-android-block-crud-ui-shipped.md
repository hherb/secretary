# NEXT_SESSION.md — Android block-CRUD UI affordance ✅ (SHIPPED — all gates green; PR to open)

**Session date:** 2026-06-20. Flow: `/nextsession` → the prior baton (pyo3 block-CRUD projection, PR #267) had **already been squash-merged** to `main` (`19a1ddc2`) by a parallel session. I flagged the collision, did the housekeeping (removed the merged `pyo3-block-crud` worktree + branch; left `hardcore-robinson` / `d4-browser-autofill` untouched), then the user chose the handoff's named next item — **wire the block-CRUD ops into a platform UI** — and picked **Android first**. Full brainstorm → spec → plan → subagent-driven execution (8 tasks, per-task spec+quality review, final whole-branch review) → this handoff.

**Status:** ✅ **code-complete; all gates green.** Branch `feature/android-block-crud-ui` (worktree `.worktrees/android-block-crud-ui`), branched from `main` @ `19a1ddc2`. **`core/`, the crypto/vault spec, all `*.udl`, pyo3, and iOS are untouched** — this is an Android-UI-only slice over the already-shipped uniffi block-CRUD ops. PR to open (see §4).

## (1) What we shipped this session

**The central idea:** the three block-CRUD ops (`create_block` / `rename_block` / `move_record`) were FFI-only (uniffi PR #266 + pyo3 #267) with no platform affordance. This slice wires them into the **Android** Compose browse UI via dialogs, completing the tier end-to-end on one platform.

| Layer | What landed |
|---|---|
| **Port** (`:vault-access` `VaultOpenPort.kt`) | `VaultSession` gains `createBlock(name): ByteArray`, `renameBlock(uuid, name)`, `moveRecord(src, tgt, recUuid): ByteArray` — UUIDs minted inside the impl, mirroring `appendRecord`. |
| **Real adapter** (`:kit` `UniffiVaultOpenPort.kt`) | `UniffiVaultSession` implements the three via the existing `write { dev, now -> }` helper (device-uuid + now-ms resolved inside, serialized under `sessionLock`, wipe-race guarded) + `SecureRandom`. |
| **Pure model** (`:vault-access` `VaultBrowseModel.kt`) | New dialog state `blockNameDialog` (sealed `CreateBlock`/`RenameBlock`) + `movingRecord`; actions `startCreateBlock`/`startRenameBlock`/`cancelBlockNameDialog`/`confirmBlockName` (blank-name → `InvalidArgument`, no write) + `startMoveRecord`/`cancelMove`/`confirmMove` (same-block guard → `InvalidArgument`; re-reads the SOURCE after a move). Refactored `commitThenReload` → shared `guardedWrite(reload, op)` (behavior-preserving). `lock()` resets both dialogs. Dialog cleared only INSIDE the success lambda → a failed write keeps the dialog/picker open. |
| **androidx VM** (`:browse-ui` `VaultBrowseViewModel.kt`) | Thin re-expose of `blockNameDialog`/`movingRecord` + launch of the suspend actions on `viewModelScope`. |
| **Compose UI** (`:browse-ui` `BrowseScreen.kt` + new `BlockCrudDialogs.kt`) | "New block" header button, per-block "Rename", per-record "Move" (all disabled while `writing`); `BlockNameDialog` + `MovePickerDialog` (picker excludes the source; title names the record being moved). Dialogs render at the top of the `Column` so an early `return@Column` can't skip them. testTags: `new-block`, `rename-<hex>`, `move-<hex>`, `block-name-field`/`-confirm`/`-cancel`, `move-target-<hex>`, `move-cancel`, `back-to-blocks`. |
| **Tests** | Host: `VaultBrowseModelBlockCrudTest` (create/rename/move happy + blank-name + same-block guard + write-failure-keeps-dialog-open + re-entrancy + lock reset), `FakeVaultBrowseTest` fake behavior, `VaultBrowseViewModelTest` delegation. Instrumented: `BlockCrudUiTest` (`:browse-ui`, dialog interactions over the fake) + `BlockCrudRoundTripUiTest` (`:app`, REAL uniffi session over a staged golden vault: create→move→read-back asserting `assertTextEquals("owner@example.com")` from the KAT → tombstone in source). |
| **Docs** | README row 203 (Android block-CRUD UI affordance) + ROADMAP entry 158, both matching neighbor style. Spec + plan under `docs/superpowers/`. |

**Branch commits (squash-merge collapses to one on `main`):**
`6dfcbaa` spec · `d423969` plan · `d63f394` port+adapter+fakes · `93db16f` model create+guardedWrite · `2293324` task-2 fix · `faf7949` model rename · `77c368d` model move+lock · `f6edbe7` VM delegation · `7e7d674` UI buttons+dialogs · `2071190` UI fix · `42e0ac6` instrumented round-trip · `c5bd653` task-7 hardening · `b286279` README+ROADMAP · `d3e8307` final-review M1 fix.

### Acceptance (all green this session)
```
# Host (no emulator), from the worktree:
cd /Users/hherb/src/secretary/.worktrees/android-block-crud-ui/android
./gradlew :vault-access:test :browse-ui:test --rerun-tasks            # BUILD SUCCESSFUL (36 executed)

# Instrumented (emulator emulator-5554 / API 36 was running this session):
./gradlew :browse-ui:connectedAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.browse.ui.BlockCrudUiTest          # 3/3
./gradlew :app:connectedAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.app.BlockCrudRoundTripUiTest       # 1/1 (real-FFI round-trip)

# Guardrails (both EMPTY this slice):
git diff main...HEAD --name-only | grep -E 'core/|crypto-design|vault-format|\.udl|secretary-ffi-py|ios/'   # empty
git diff main...HEAD --name-only | grep -E '\.rs$|Cargo'                                                     # empty
```

### Deliberate design decisions (so a future reader doesn't "fix" them)
- **Dialogs, not inline-edit/multi-select/drag-drop** (YAGNI; user-chosen). Create/rename = one name dialog; move = a block-picker dialog excluding the source.
- **UUIDs minted in the impl** (`SecureRandom` in the real adapter; deterministic counters in the fakes) so the pure model stays deterministic — matches `appendRecord`.
- **Input validation in the model wrapper, not the bridge** ([[project_secretary_input_validation_at_binding_wrapper]]): blank-name + same-block-move guards surface `VaultBrowseError.InvalidArgument`. **No new `FfiVaultError`/`VaultBrowseError` variant** — every error these ops throw pre-existed and is already mapped; conformance/Swift/Kotlin harnesses untouched ([[project_secretary_ffivaulterror_workspace_match]] did NOT apply).
- **`guardedWrite` refactor** shares the re-entrancy + on-success-only-reload + error-preservation core between record writes (delete/restore/edit) and block-list writes (create/rename/move). Behavior-preserving; full `:vault-access` suite re-run with `--rerun-tasks` proves no regression.
- **`startMoveRecord` has no no-selected-block guard** — the plan's prose and its own verbatim test contradicted; deferred to the tests. Safety is preserved by `confirmMove`'s `source ?: return` and the picker only being reachable from the record-list state. (Confirmed safe by two reviewers.)
- **Move semantics**: `move_record` is copy-to-target-under-a-FRESH-uuid + tombstone-in-source. Read-back asserts on the field *value*, not the uuid; the source shows the record tombstoned (visible with show-deleted on).

## (2) What's next
- **Open + squash-merge this PR** (§4), then housekeeping (remove this worktree + branch).
- **iOS mirror slice** — the same three affordances over the iOS SwiftUI browse stack (`VaultBrowseViewModel` / `VaultSession` / `RecordEditViewModel`), which is architecturally parallel to Android. **Acceptance:** host-tested VM logic (`swift test`) + an on-device/simulator create→move→read-back round-trip through the UI.
- **iOS biometric re-auth before a write** — separate follow-up (ROADMAP C.3 remaining; carried since the #261 baton).
- **On-device sync veto round-trip** still needs a seeded concurrent state ([[project_secretary_sync_veto_needs_seeded_state]]).

**Open follow-up issues (carried):** #224 / #234 / #192 / #193 / #190 / #189 / #186 / #161 / #162 / #167 / #251 / #252 / #255. (#251 — decrypted-block residency — is the `openBlocks` lifetime, distinct from this slice; the move path adds no new residency.)

## (3) Open decisions and risks
- **Instrumented acceptance depends on a running emulator.** `adb`/`emulator` are not on the bare PATH on this machine ([[project_secretary_android_toolchain]]); use absolute paths (`/Users/hherb/Library/Android/sdk/...`) or a booted AVD. Gradle `connectedAndroidTest` finds the running emulator automatically. The aggregate `:browse-ui:test` lifecycle task does NOT accept `--tests`; use the concrete `:browse-ui:testDebugUnitTest --tests ...` for a single host class ([[project_secretary_android_instrumented_test_gotchas]]).
- **`AppVaultProvisioning.stageGoldenVault` is idempotent** (returns the existing staged copy if present). A prior `:app` instrumented run that crashed *after* staging but *before* `@After` cleanup could leave a mutated staged vault, making the next round-trip fail at "no live record in source." Pre-existing design shared across `:app` tests — a clean emulator/snapshot per CI run avoids it. Worth a `@Before` purge if it ever flakes.
- **Single-record fixture assumption**: the round-trip moves the first live record of "Personal logins" (golden vault has exactly one). Fine while the fixture is frozen; extending the golden vault would need the test updated.
- **No cross-language / Rust run needed.** Android-UI-only over already-reviewed uniffi ops; guardrails empty by construction, so the Swift/Kotlin conformance + smoke runners add no signal beyond the gradle gauntlet.

## (4) Exact commands to resume
```bash
# 0) Push the branch + open the PR (this session left it committed but unpushed):
cd /Users/hherb/src/secretary/.worktrees/android-block-crud-ui
git push -u origin feature/android-block-crud-ui
gh pr create --fill   # base main

# Re-run the gauntlet before merge (emulator must be booted for the instrumented runs):
cd android
./gradlew :vault-access:test :browse-ui:test --rerun-tasks
./gradlew :browse-ui:connectedAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.browse.ui.BlockCrudUiTest
./gradlew :app:connectedAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.app.BlockCrudRoundTripUiTest

# Guardrails (empty this slice):
cd /Users/hherb/src/secretary/.worktrees/android-block-crud-ui
git diff main...HEAD --name-only | grep -E 'core/|crypto-design|vault-format|\.udl|secretary-ffi-py|ios/'   # empty
git diff main...HEAD --name-only | grep -E '\.rs$|Cargo'                                                     # empty

# 1) After the PR merges, housekeeping (from the MAIN checkout, not this worktree):
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/android-block-crud-ui && git branch -D feature/android-block-crud-ui
git worktree prune && git worktree list   # leaves hardcore-robinson + d4-browser-autofill untouched
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Authored once; the symlink is the pointer. Both this handoff + the retargeted symlink are committed on the feature branch ([[feedback_next_session_in_pr]]). If you resume this branch for fixups, first `git fetch origin && git merge origin/main` (branch-version-wins on the handoff path) before editing ([[feedback_next_session_main_authoritative]]).

## Closing inventory
- **Branch on close:** `main` @ `19a1ddc2`; `feature/android-block-crud-ui` committed through `d3e8307`. PR to open per §4. Squash-merge → one commit on `main`.
- **Acceptance:** green — host `:vault-access:test :browse-ui:test` (36 executed, no failures); instrumented `BlockCrudUiTest` 3/3 + `BlockCrudRoundTripUiTest` 1/1 (real-FFI round-trip) on emulator. Guardrails empty (no `core/` / spec / `.udl` / pyo3 / iOS / Rust).
- **Reviews:** per-task spec+quality reviews all clean (3 small fix loops: Task 2 write-failure test + `--rerun-tasks`; Task 6 used the unused `record` param; Task 7 stable Back testTag + `assertTextEquals`). Final whole-branch review (opus): **Ready to merge = YES**, no Critical/Important; the one Minor (M1, weak `confirmMove` delegation assertion) fixed in `d3e8307`.
- **README.md / ROADMAP.md:** both updated.
- **NEXT_SESSION.md:** symlink retargeted to this file.
