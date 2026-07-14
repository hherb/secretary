# NEXT_SESSION.md — Mobile: hide per-record Move affordance when no other block (#429) ✅ SHIPPED (PR TBD)

**Session date:** 2026-07-14, resuming from `main` @ `6b933305` (after #430 / #273 merged). This session shipped **#429** — the Android + iOS parity follow-on to desktop #273. Branch `feature/mobile-move-parity-429` off `main` @ `6b933305`; worktree `.worktrees/mobile-move-parity-429/`. Executed brainstorm → spec → plan → inline TDD (4 tasks) → clean code review → ship. Spec: [docs/superpowers/specs/2026-07-14-mobile-move-parity-429-design.md](../superpowers/specs/2026-07-14-mobile-move-parity-429-design.md). Plan: [docs/superpowers/plans/2026-07-14-mobile-move-parity-429.md](../superpowers/plans/2026-07-14-mobile-move-parity-429.md).

**Mobile UI only (Kotlin/Compose + Swift/SwiftUI). No `core` / crypto / FFI / on-disk-format / error-variant change; `#![forbid(unsafe_code)]` untouched (no Rust touched at all).**

## (1) What we shipped this session

### #429 — hide the per-record Move affordance on Android + iOS when the vault has ≤ 1 live block
Parity mirror of #273: in a single-block vault the Move action opened the move-target picker only to dead-end at its "No other blocks" empty state. Now hidden on both mobile platforms. **Approach (same shape as #273):** derive the live-block count from the `blocks` collection each browse VM **already holds** (no extra FFI/IPC) and gate the Move affordance on a pure `hasMoveTargets(blockCount) = blockCount >= MIN_BLOCKS_TO_MOVE` (named const **= 2**; no magic number).

- **Android** — `BrowseRenderHelpers.kt`: pure `hasMoveTargets(blockCount: Int)`. `BrowseScreen.kt`: `RecordRow` gains a `canMove: Boolean` param; Move `TextButton` wrapped `if (canMove)`; call site computes `canMove = hasMoveTargets(blocks.size)`. Host unit (`BrowseRenderHelpersTest`, 0/1→false, 2/3→true) + new instrumented render test (`BrowseScreenMoveButtonTest`: single-block → no `move-<uuid>`, Edit/Delete still shown; 2-block → shown).
- **iOS** — new `MovePolicy.swift` (FFI-free `SecretaryVaultAccess`; pure `MovePolicy.hasMoveTargets(blockCount:)`, `minBlocksToMove = 2`). `VaultBrowseViewModel.swift`: computed `hasMoveTargets = MovePolicy.hasMoveTargets(blockCount: blocks.count)`. `VaultBrowseScreen.swift`: Move swipe `Button` wrapped `if viewModel.hasMoveTargets`. Host units (`MovePolicyTests` boundary values + `VaultBrowseViewModelTests` 1-block→false, 2-block→true).

**Correctness note (tighter than desktop):** on mobile the count feeding the gate and the count feeding the picker are the *literal same* `blocks` collection (desktop had two projections — `manifest.blockCount` vs `listBlocks()` — that merely agree). Reviewer confirmed each picker filters the source block out (`BlockCrudDialogs.kt:70`, `BlockCrudViews.swift:24`), so `>= 2` == "≥1 distinct target remains." Still a **UX layer only** — the picker empty-state + Rust `move_record_impl` same-block guard remain authoritative and are untouched.

### Branch commits (off `main` @ `6b933305`, in order)
- `99fcc7d6` design doc (spec)
- `a1e111f3` implementation plan
- `8d151139` **Task 1** — Android pure `hasMoveTargets` guard + host unit tests
- `564baaf2` **Task 2** — Android gate (`canMove` on `RecordRow`) + instrumented render test
- `7dc379c6` **Task 3** — iOS pure `MovePolicy` + host unit tests
- `af96c58b` **Task 4** — iOS VM `hasMoveTargets` property + SwiftUI swipe gate + host VM test
- _(this commit)_ handoff doc + symlink retarget

### Acceptance (all met, verified this session)
```bash
# Android host unit (fast, no emulator):
cd android && ./gradlew :browse-ui:testDebugUnitTest            # BUILD SUCCESSFUL
# Android instrumented render (emulator emulator-5554 was up):
./gradlew :browse-ui:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.browse.ui.BrowseScreenMoveButtonTest,org.secretary.browse.ui.BrowseScreenSoftDeleteTest   # 5/5 pass
# iOS host (fast, FFI-free):
cd ios/SecretaryVaultAccess && swift test                        # 280 tests, 0 failures
# iOS SwiftUI compile proof (xcframework was warmed in background):
bash ios/scripts/build-app.sh                                    # ** BUILD SUCCEEDED **
```
Code review (pr-review-toolkit:code-reviewer over the `main...HEAD` android/+ios/ diff): **clean, no findings at confidence ≥ 80** — threshold correctness (source-inclusive count + picker filters source), Android reactivity (`collectAsStateWithLifecycle` + `canMove` computed at the item call site), iOS reactivity (`@Published blocks` + computed property re-evaluated on `objectWillChange`), and test soundness all confirmed with re-run evidence.

## (2) What's next — pick a new slice

**Verify liveness first** ([[project_secretary_stale_but_done_issues]] — grep/git-log each candidate before starting; the tracker carries fixed-but-unclosed issues). Genuinely-open candidates as of this handoff (all verified OPEN 2026-07-14 at session start):

- **#277 — desktop OS-biometric write re-auth (macOS Touch ID)** — the biggest-remaining D.1 item; desktop still re-auths by password only. `authorizeWrite` is the single injection point. Meaty, multi-session, hardware-verification heavy — brainstorm/spec deliberately before committing a session.
- **#417 — mobile Trash purge-notice render-layer test (Compose/SwiftUI)** — the iOS render-assertion infra gap. This session's iOS Move gate (`VaultBrowseScreen.swift`) is a *new instance of the same class* (SwiftUI one-liner gated on a host-tested VM prop, no literal render assertion) — folding a general iOS render-assertion decision (ViewInspector host dep vs a SecretaryApp XCUITest target) into #417 would cover both. Needs a test-infra decision.
- **#90 — Rust test-helper dedup** — ~13 files each define their own `fn copy_dir_recursive`; consolidate into one shared helper. Low-risk, good Rust-module practice.
- **#269 — Android duplicate-name guard on block create/rename** — small Kotlin feature in `:browse-ui`.
- Security **#383** — still upstream-blocked (`quick-xml 0.39` via `plist` → `tauri`); re-check on the next Tauri bump; do not start.
- Any user-prioritized slice.

## (3) Open decisions and risks
- **`canMove` is a required Compose param (Android), `hasMoveTargets` a computed VM prop (iOS).** Chose a `canMove: Boolean` param over making `onMove` nullable (desktop's `{#if onMove}` idiom) because Android's `RecordRow` had no existing `onMove != null` gate — a boolean is the smaller, clearer change. iOS mirrors desktop's "VM computes, view gates" split.
- **The `>= 2` guard is a UX layer, not a safety boundary.** The picker empty-state (`MovePickerDialog` / `MoveTargetPickerSheet`) and the Rust `move_record_impl` same-block rejection remain authoritative. **Do not** remove either on the theory that the affordance is now hidden. On mobile the gate and picker read the *same* `blocks` collection, so they cannot diverge.
- **iOS SwiftUI gate has no literal render test (accepted).** Consistent with the repo's documented iOS constraint (SwiftUI screens aren't host-testable; pure/host-testable logic lives in the VM, which *is* tested at both boundaries). Same accepted gap class as #417; recorded in the spec's out-of-scope section. Not a defect — a `move-<uuid>` XCUITest would run only on a simulator, off the `run-ios-tests.sh` host path.
- **CI coverage gap (pre-existing, not this PR's to fix):** `test.yml` android-host runs only `:vault-access:test`; `:browse-ui` host + instrumented tests run **locally only** (as all instrumented tests do here). Verified green on the local emulator this session. No ktlint/detekt/spotless config exists → no separate Kotlin style gate.
- **README / ROADMAP: no change** — cosmetic polish on an already-documented feature (`move_record` shipped ✅ on all three platforms; README line 177 already documents the FFI primitive). Same precedent as #273/#422 (neither added an entry). Verified neither file needs an edit.
- **Other in-flight worktrees exist** (parallel sessions — do not touch): `.worktrees/d4-browser-autofill`, `.worktrees/desktop-block-crud-ui`, `.worktrees/timer-poison-147`, plus two detached `.claude/worktrees/*`. This session created + will leave `.worktrees/mobile-move-parity-429` (drop it after the PR merges); it also removed the merged `hide-move-button-273` worktree at start.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After the PR merges, drop the branch + worktree (squash-merge leaves it "not fully merged"):
#   git worktree remove .worktrees/mobile-move-parity-429 && git branch -D feature/mobile-move-parity-429
git worktree list && git status -s
# If resuming THIS branch for fixups (bind histories first — closes the add/add gap on the handoff doc):
#   cd .worktrees/mobile-move-parity-429 && git fetch origin && git merge origin/main
# Re-run this branch's local gates any time it is live (from the worktree):
#   cd android && ./gradlew :browse-ui:testDebugUnitTest
#   ./gradlew :browse-ui:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.browse.ui.BrowseScreenMoveButtonTest   # needs emulator
#   cd ios/SecretaryVaultAccess && swift test
# CI status for the PR:
#   gh pr checks <PR#>
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; the symlink retargeted in the same commit on the feature branch (new path → no add/add conflict; `main` updates cleanly on merge). The handoff rides inside the PR — do **not** sync to `main` during the pause window ([[feedback_next_session_main_authoritative]]). If resuming this branch for fixups, first `git fetch origin && git merge origin/main` (branch version wins on this doc) before editing.

## Closing inventory
- **State on close:** PR open on `feature/mobile-move-parity-429` (worktree `.worktrees/mobile-move-parity-429`). Branch commits: spec + plan + 4 task commits + handoff. Code review clean.
- **Acceptance:** all gates green — Android host (`:browse-ui:testDebugUnitTest`), Android instrumented (5/5 on emulator), iOS host (280 swift tests), iOS app build; code review no findings. Threshold `>= 2` proven correct (source-inclusive; picker filters source).
- **Next:** pick a new slice — #277 (biggest D.1), #417 iOS render-infra (now covers this session's gate too), #90 Rust dedup, #269 Android dup-name, or user priority. **Verify liveness first.**
- **README / ROADMAP:** no change (cosmetic polish on an already-documented feature).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-07-14-mobile-move-parity-429-shipped.md`.
