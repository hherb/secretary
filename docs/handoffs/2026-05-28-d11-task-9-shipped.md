# NEXT_SESSION.md — D.1.1 Task 9 (Settings dialog + auto-lock timeout editor) shipped

**Session date:** 2026-05-28 (sixth D.1.1 slice of the day; continues immediately from the Task 8 session that landed via PR #155 at `329d315` on `main`. This session lands the Settings dialog and finally enables the gear icon that has been sitting disabled in the TopBar since Task 8.)
**Status:** D.1.1 Task 9 PR open on branch `feature/d11-task-9`. Predecessors on `main`: D.1.1 spec + ADR 0007 (PR #130, `a5d85b9`), Task 1 scaffold (PR #131, `e329087`), Task 2 pure modules (PR #137, `a3ee9e9`), Task 3 VaultSession (PR #142, `6f984d4`), Task 4 IPC commands + DTOs (PR #143, `9217602`), Task 5 auto-lock timer (PR #146, `16721c5`), Task 6 frontend pure modules (PR #148, `ca5d0e5`), Task 7 Unlock route + PathPicker (PR #152, `37fd30e`), Task 8 Vault route + leaf components (PR #155, `329d315`).

## (1) What we shipped this session

Four code commits (split for review readability) + this baton. Per [[feedback_split_files_proactively]] the SettingsDialog component is in its own file (one concept per file); per the project's [[feedback_test_crypto_random_not_hardcoded]] discipline carrying through to "no magic numbers", the Rust-side auto-lock bounds are mirrored via a typed `lib/constants.ts` module rather than copy-pasted hex / numeric literals.

| Commit | Subject | What it lands |
|---|---|---|
| `ff43ef6` | `refactor(d11): settingsUpdated transition helper for in-place settings replacement` | New legal edge `unlocked → unlocked` in the SessionState state machine via `settingsUpdated(newSettings)`. Manifest reference is preserved (same object identity) so downstream `$derived` selectors keyed on it don't churn — only `currentSettings` consumers see a change. The helper replaces the plan's `sessionState.set({...$sessionState, settings})` raw-mutation pattern, which can't compile post-#150 (PR #152 demoted the writable to non-exported `_internal`). Adds 4 tests in `stores.test.ts` (1 legal-transition pin + 3 illegal-from-each-non-unlocked-state) — same coverage pattern Tasks 7-8 established for `unlockFailed` / `lockFailed`. Vitest 156 (was 152). |
| `16310d6` | `feat(d11): lib/constants.ts mirroring Rust auto-lock bounds` | New `desktop/src/lib/constants.ts` mirroring `desktop/src-tauri/src/constants.rs`'s `AUTO_LOCK_MIN_MS = 60_000`, `AUTO_LOCK_MAX_MS = 86_400_000`, `AUTO_LOCK_DEFAULT_MS = 600_000`, plus a new `MS_PER_MINUTE = 60_000` for the minutes↔ms conversion in the dialog. The IPC layer carries no constants, so the wire crosses a duplication; drift would silently let the frontend accept values the backend rejects with `AppError::SettingsOutOfRange` (surfacing as a confusing UX bug — the user sees the UI accept the value, then sees an error toast). New `constants.test.ts` pins 4 *structural* invariants (min < default < max, whole-minute multiples, positivity, MS_PER_MINUTE arithmetic) rather than re-proving tautologies. Vitest 160 (was 156). |
| `81a5b28` | `feat(d11): Task 9 — SettingsDialog component with auto-lock timeout editor` | The single new component. Native `<dialog>` overlay with one integer-minutes input. Pre-populates from `currentSettings`; defensive AUTO_LOCK_DEFAULT_MS fallback when locked (shouldn't happen at runtime; defends against a future regression in the open-state guard). Client-side validation surfaces the SAME typed `{ code: 'settings_out_of_range', min, max }` AppError the backend returns on out-of-range input — `userMessageFor` renders identical copy for both client- and server-side rejection paths, so the user experience is consistent regardless of which gate fires. Save flow: validate → `setSettings` IPC (ms) → `settingsUpdated` store helper → onClose. Cancel reverts local edit + onClose. IPC rejections locally narrow non-AppError shapes to `{ code: 'internal' }` (defence in depth; `call()` in `ipc.ts` already coerces). New `tests/setup.ts` polyfills `HTMLDialogElement.showModal/close` for JSDOM 25 (jsdom/jsdom#3294 — `<dialog>` element exists but the imperative API doesn't). 17 new SettingsDialog tests covering open/closed state, initial value derivation (3), Save happy path (3), Cancel flow (1), client-side validation (3 — below min, above max, non-integer), IPC error path (2 — typed AppError + non-AppError coercion), accessibility (2). Vitest 177 (was 160). |
| `7f231e1` | `feat(d11): Task 9 — wire SettingsDialog into TopBar + Vault` | TopBar gains a required `onOpenSettings: () => void` prop and drops the permanent `disabled` attribute on the gear button — clicking it now fires the callback. Vault.svelte owns the `settingsOpen = $state(false)` and instantiates `<SettingsDialog bind:open={settingsOpen} onClose={...} />` at the bottom of the unlocked branch, threading `onOpenSettings={() => (settingsOpen = true)}` into TopBar. TopBar.test.ts: 1 test inverted (gear now enabled), 1 new test (click fires onOpenSettings), 1 tweaked (title attr is a real hover hint, not deferred-functionality copy). Vault.test.ts: +2 wiring tests (dialog mounts in closed state; clicking gear opens it). `.top-bar__settings` style loses `cursor: not-allowed` + `opacity: 0.6` and gains a `:hover` state. Vitest 180 (was 177). |
| TBD | `docs(d11): Task 9 handoff baton` | This file + symlink retarget. |

### Gauntlet (live, performed — post-fixup totals)

```
Rust:           PASSED 1053 FAILED 0 IGNORED 10    # unchanged — Task 9 is frontend-only
cargo clippy --release --workspace --tests -- -D warnings   → clean
cargo fmt --all -- --check                                  → clean
uv run core/tests/python/conformance.py                     → PASS
uv run core/tests/python/spec_test_name_freshness.py        → PASS (97 resolved, 0 unresolved, 25 suppressed)

Frontend:       Vitest 180 / 0 (13 files: errors=26, ipc=13, auto_lock=12, stores=45,
                constants=4, PathPicker=8, BlockCard=8, LockButton=9, TopBar=7,
                Unlock=9, Vault=14, SettingsDialog=17, App=8)
pnpm typecheck                                              → clean
pnpm svelte-check                                           → 237 files, 0 errors, 0 warnings
pnpm lint                                                   → clean
```

Plan-vs-actual on Vitest counts: plan-target was ~8-12 new tests; actual is **28 new** (stores +4, constants +4, SettingsDialog +17, Vault +2, TopBar +1 net). Surplus split:

- **`settingsUpdated` (+4 in stores.test.ts):** 1 legal + 3 illegal-from-each-non-unlocked-state. Same coverage pattern as `lockFailed` (Task 8) and `unlockFailed` (Task 7).
- **constants (+4 in new constants.test.ts):** structural invariants (min < default < max, whole-minute, positivity, arithmetic) — not tautologies. Drift detector for the Rust ↔ TS bounds duplication.
- **SettingsDialog (+17):** open/closed state (3), initial value (3 including the locked-state fallback edge case + min/max/step attribute pins), Save happy path (3 — IPC arg, store update, onClose), Cancel flow (1), client-side validation (3), IPC error path (2 — typed + non-AppError coercion), a11y (2 — button types + heading).
- **Vault (+2 in Vault.test.ts):** dialog-mounts-closed pin + clicking-gear-opens pin. Covers the wiring contract between TopBar and the dialog instance.
- **TopBar (+1 net in TopBar.test.ts):** 1 added test (click fires onOpenSettings), 1 inverted test (gear is no longer disabled), 1 tweaked (title attr is now a hover hint not a deferred-functionality note). Net +1 file count.

### Plan execution trace (for the reviewer)

The plan as-written has several places where Task 8's batons flagged predictable drift; this session adapted:

1. **`sessionState.set({...$sessionState, settings: {...}})` raw mutation** wouldn't compile post-#150. Replaced with the new `settingsUpdated(newSettings)` typed helper — symmetric with `lockFailed` / `unlockFailed`. The helper's *manifest-preserving* contract (same object identity) is intentional: downstream `$derived` selectors keyed on the manifest don't fire from a settings-only change.
2. **Plan's `AUTO_LOCK_MIN_MIN = 1`, `AUTO_LOCK_MAX_MIN = 1440` literal constants in the component** would create a triple-duplication site (Rust + TS-constant + dialog-inline). Replaced with the `lib/constants.ts` module — the dialog imports the ms-valued constants and divides by `MS_PER_MINUTE` inline at the call site. One source of truth across the wire, with a unit-test invariant pinning the structural relationships.
3. **`<style>` block in SettingsDialog.svelte** would re-trigger the Vite 6 / Vitest `preprocessCSS` bug (#153 carryover). All styles in `src/theme.css` per the [[feedback_split_files_proactively]] convention — appended a `.settings-dialog*` block (~85 LOC) and modified `.top-bar__settings` (lost the not-allowed/opacity disabled-styling, gained a hover state).
4. **JSDOM doesn't implement `HTMLDialogElement.showModal/.close`.** New `tests/setup.ts` polyfills the imperative API narrowly enough for component tests — sets/clears the `open` attribute, dispatches the `close` event from `.close()`. Composed via `setupFiles: ['./tests/setup.ts']` in `vitest.config.ts`; the `svelteTesting()` plugin still appends its own auto-cleanup setup file. Production code is unchanged — the polyfill never ships.
5. **`isAppError` is already exported from `ipc.ts`** as of Task 8's fixup commit. The dialog imports it for the local non-AppError-coercion narrowing path (avoiding the `e as AppError` cast pattern that was the principal Task 8 review finding).
6. **No `pnpm tauri dev` smoke this session.** Same gap as Tasks 7-8 — no UI environment in this session. Task 10's smoke (Toast for auto-lock notice) exercises the same unlock → settings → save → wait-for-idle path en route, so a regression in the Task 9 dialog or the underlying `setSettings`/`settingsUpdated` integration surfaces there. Manual `pnpm tauri dev` walk-through before merge is short: unlock → click gear → dialog opens → change to 5 min → Save → close → re-open gear → see "5", lock + re-unlock → still 5.

### Per-component TDD discipline

Each new file landed with its test in the same commit, tests written first → ran red → implementation → ran green. The `settingsUpdated` helper went red on 4 of 4 before implementation. The SettingsDialog component first went red on 15 of 17 (the 2 that passed even without the component were resolution-failure exempt tests that the file-not-found path triggered an unexpected pass on; once the file existed they went red as expected with `showModal is not a function`, then green after the JSDOM polyfill landed). The TopBar+Vault wiring went red on 2 of 2 before implementation.

### Code-review fixups

`/review` on PR #156 flagged six items (1 medium, 3 low, 2 nit). All applied in-PR per [[feedback_fix_all_review_issues]] in one fixup commit on top of the four code commits + this baton update:

1. **Medium — `onclose={cancel}` re-entrance after Save.** The dialog wired the native `close` event directly to `cancel`, so when the parent flipped `bind:open` to false the `$effect` would call `dialogEl.close()`, which fires `close`, which re-ran cancel — silently double-invoking `onClose()` on every Save. Existing unit tests didn't catch it because the test mock for `onClose` doesn't propagate back to a real `open` prop (only Vault.svelte's `bind:open` would). Fixed by introducing `onNativeClose() { if (open) cancel(); }` — Escape-from-real-browser still hits cancel (open is true at that point), but parent-initiated closes (open already false) are no-ops. New test in `SettingsDialog.test.ts` uses `rerender({ open: false })` to simulate the bindable feedback loop and pins `onClose` to a single call.
2. **Low — race-guard around `settingsUpdated` post-IPC.** If a `vault-locked` event lands between `setSettings` firing and resolving (auto-lock at the boundary), the session has already left `unlocked` and `settingsUpdated` would throw via the illegal-transition guard. The backend persisted the value either way. Save now peeks `$sessionState.status` after the IPC and skips `settingsUpdated` if non-unlocked; `onClose()` still fires (the dialog is about to unmount anyway in production via Vault leaving `unlocked`). New test in `SettingsDialog.test.ts` stages the race via `setSettingsMock.mockImplementationOnce` that resets the store to `locked` before resolving.
3. **Low — polyfill `close()` event firing unconditionally.** Real `HTMLDialogElement.close()` only fires the `close` event when the dialog was actually open; the polyfill in `tests/setup.ts` fired unconditionally. Guarded with a `wasOpen` capture before removing the attribute. No behaviour change in existing tests (none exercise the closed-then-re-closed path) but the polyfill now matches the spec narrowly enough that the onclose-re-entrance fix above continues to hold under any future test that does.
4. **Doc nit — stores.ts `settingsUpdated` reactivity comment.** Original wording said downstream `$derived` selectors "don't churn"; with Svelte 5's fine-grained reactivity the selectors will re-evaluate (the outer state reference changed), they just produce identical values so consumers see no change. Rewrote the comment to describe the real mechanism. Also added a one-line note pointing future callers at the post-IPC race pattern Save() now uses.
5. **Minor — `MIN_MIN` / `MAX_MIN` / `DEFAULT_MIN` constant naming.** Renamed to `MIN_MINUTES` / `MAX_MINUTES` / `DEFAULT_MINUTES` for clarity. Pure rename; references updated at all three call sites (validator, $effect re-seed, `<input min={…} max={…}>`).
6. **Test surplus.** Two new tests landed alongside the medium + low fixes: `parent-driven close after Save does not re-trigger cancel via the native close event` and `Save when the session has raced to locked mid-IPC skips settingsUpdated and still closes`. SettingsDialog tests now total 19 (was 17). Frontend Vitest total **182 / 0** (was 180).

Post-fixup gauntlet (re-ran in full):

```
Rust:           PASSED 1053 FAILED 0 IGNORED 10
cargo clippy --release --workspace --tests -- -D warnings   → clean
cargo fmt --all -- --check                                  → clean
uv run core/tests/python/conformance.py                     → PASS
uv run core/tests/python/spec_test_name_freshness.py        → PASS

Frontend:       Vitest 182 / 0 (13 files; SettingsDialog now 19, all others unchanged)
pnpm typecheck                                              → clean
pnpm svelte-check                                           → 237 files, 0 errors, 0 warnings
pnpm lint                                                   → clean
```

## (2) What's next — D.1.1 Task 10 (App.svelte orchestration — event listener + Toast + activity tracking)

Per the plan, Task 10 closes the session lifecycle loop on the frontend:

- App.svelte subscribes to the backend's `vault-locked` Tauri event so explicit + auto-lock both transition the UI authoritatively (the backend is the source of truth per spec §7; today's Task 8 leaves a brief `locking` state that only completes if a `vault-locked` event arrives).
- New `Toast.svelte` component renders the auto-lock notice from spec §12 (auto-dismiss after 5s, manual × button).
- Activity tracking (mousemove/keydown → debounced `notifyActivity` IPC) starts on unlock + stops on lock, via the `startActivityTracking()` helper already in `lib/auto_lock.ts` from Task 6.

**Files (per the plan):**

- Create: `desktop/src/components/Toast.svelte` — fixed-position banner top-right; reads from `$autoLockNotice` store; auto-dismisses on 5s timeout; × button for manual dismiss.
- Modify: `desktop/src/App.svelte` — `onMount` subscribes to `vault-locked` event; calls `vaultLocked(reason)` on payload arrival. `$effect` starts/stops activity tracking when entering/leaving `unlocked`. `onDestroy` cleanup.
- New tests: `desktop/tests/Toast.test.ts`.
- Modify tests: `desktop/tests/App.test.ts` (add `vault-locked` event subscription + activity-tracking lifecycle tests).

**Acceptance criteria for Task 10:**

- Gauntlet: Rust **1053 / 0 / 10** (unchanged — Task 10 is frontend-only, backend event already emits per Task 5). Vitest **182 + N** where N ≈ 8-14 (Toast rendering + auto-dismiss + manual dismiss + App event-listener subscription + payload-to-vaultLocked wiring + activity-tracking start/stop on unlock/lock).
- `pnpm tauri dev` smoke: full lifecycle — unlock golden vault → open settings → set auto-lock to 1 min → Save → stop touching → ~70s later vault auto-locks → Toast slides in with "Vault auto-locked due to inactivity" → 5s later Toast dismisses → re-unlock + click Lock manually → screen transitions to Unlock immediately + NO toast (toast is only for `reason === 'idle'`, per the existing `autoLockNotice` discriminated union).
- ESLint + svelte-check clean.

**Estimate:** ~60-90 min (one new component + App.svelte event-listener wiring + activity-tracking lifecycle + tests).

## (3) Open decisions and risks

### Plan adaptations (worth flagging to the reviewer)

1. **`settingsUpdated(newSettings)` typed helper added to the state machine.** The plan's raw `sessionState.set(...)` mutation wouldn't compile post-#150. The helper closes the gap and pins a coverage pattern symmetric with `lockFailed` / `unlockFailed`. Manifest-preserving by design — settings changes alone should not invalidate `$derived` selectors keyed on the manifest.
2. **`lib/constants.ts` module instead of inline literals.** No magic numbers, no triple-duplication. Structural invariants pinned in `constants.test.ts` so a drift bug between Rust and TS surfaces in tests rather than at runtime.
3. **JSDOM polyfill via `tests/setup.ts`.** Narrow, spec-faithful, doesn't touch production code. The alternative (avoiding `showModal()` entirely and just toggling the `open` attribute manually) would push browser-compatibility concerns into the component for the sake of test ergonomics — wrong tradeoff.
4. **No `lib/format.ts` extraction for minute / ms conversion.** The conversion is inline at three call sites in SettingsDialog (initial value, validation, save) plus the test file. All four are co-located logically with the dialog's purpose; promoting to a helper module would be premature per [[feedback_pure_functions]]'s "second call site" trigger. The `lib/constants.ts` module captures the constant; the arithmetic is the local logic.
5. **Required `onOpenSettings` prop on TopBar** (not optional with a fallback to "disabled"). Cleaner contract: a TopBar instance always knows where to open settings, because TopBar only mounts when a vault is unlocked, and settings always makes sense in that context. Removes the conditional `disabled` branching from the component.

### Decisions settled

- **Dialog state owned by Vault.svelte, not lifted to App.svelte.** Settings is only meaningful when a vault is unlocked; lifting the open/close state to App would require Vault to communicate it back down, adding ceremony without benefit. Vault is the natural owner.
- **`<SettingsDialog>` is always rendered (with `open={false}`) rather than conditionally mounted via `{#if settingsOpen}`.** Three reasons: (1) the native `<dialog>` element's `open` attribute is the proper API for "is this visible"; (2) keeping the same DOM node alive across open/close prevents Svelte from re-running the `$effect` that drives `showModal/close` and avoids a flash of stale state; (3) the test `clicking the TopBar settings gear opens the dialog` would have to mount + then check, instead of the simpler always-mounted + check `hasAttribute('open')` pattern.
- **Validation rejects non-integer values even though the input is `type="number"` with `step="1"`.** Browser spinner enforces it but paste / programmatic value changes can bypass; defence in depth at the validate-on-Save layer. Test pin `Save with a non-integer value rejects` covers this.
- **Client-side validation wraps the rejection in the SAME `settings_out_of_range` AppError the backend uses,** so `userMessageFor` produces consistent copy regardless of which gate fires. Carried this pattern forward from the plan — it's a strong UX choice; flagged here as a deliberate keep, not an oversight.
- **No `lockFailed`-style helper for `set_settings` rejection.** Settings save is `unlocked → unlocked` (same state, just different settings) on success, and on failure the state doesn't transition at all — local component error state is sufficient. The user sees the error inline in the dialog and can fix-and-retry or Cancel.
- **No close-on-Escape handler beyond what `<dialog>` natively provides.** The `onclose={cancel}` callback covers the native Escape behavior (browsers fire `close` event when Escape is pressed); the polyfill in `setup.ts` also fires the `close` event from `.close()` so test coverage is automatic.

### Risks carried forward

- **`pnpm tauri dev` smoke still deferred to Task 10 or to a manual pre-merge walk-through.** Mitigation: Task 10's smoke exercises the same unlock → Vault → Settings → Save path en route to the auto-lock notice toast; a capability or IPC-wiring regression in Task 9 surfaces there.
- **Vite 6 `preprocessCSS` bug** — workaround (centralised theme.css) is permanent until upstream fix. Tracking: #153. Task 9 added ~85 LOC to `theme.css` for the new `.settings-dialog*` block.
- **Carry-forward: password handling at the IPC boundary is not yet zeroize-typed** (Task 4 risk). Unchanged — Unlock.svelte still binds to a JS `string`.
- **Carry-forward: `AppError::KdfTooWeak` still has no producer.** Unchanged.
- **Carry-forward: bridge `RecordInput.record_type` workaround** (issue #141). Unchanged.

### Issues currently open (carry-over)

- #37, #117, #120, #122, #123 — none affected by Task 9.
- #38, #45, #75, #76, #78, #79, #81, #87, #88, #90, #95, #98 — none affected.
- #139 — desktop: `AppError` lacks `Deserialize`. Unchanged.
- #140 — desktop: `parse_settings_field` text-only invariant. Unchanged.
- #141 — bridge: `RecordInput` lacks `record_type` field. Unchanged.
- #144 — desktop: Argon2id KDF runs under IPC mutex during unlock. Unchanged.
- #145 — desktop: no recovery path for unlock-time settings warnings. **Partially addressed:** the dialog now provides the *mechanism* for recovery — a user opening Settings and saving any value will overwrite the corrupt/clamped record. The issue's broader concern (banner-to-dialog deep-link, automatic "open settings to fix" actionHint button) is unchanged; Task 9 deliberately scoped to the editor itself. Leave open.
- #153 — desktop: re-migrate component styles back to component `<style>` blocks once the Vite/Vitest `preprocessCSS` bug clears. Task 9 added ~85 LOC to `theme.css`.
- #154 — desktop: replace emoji icons with inline SVG before D.1.1 ships externally. Task 9 introduces no new emoji (gear + lock already existed in Task 8); same fix surface.

### Issues filed during this session

None. The session's surprises (JSDOM dialog gap, plan's outdated `sessionState.set` calls, plan's inline-constants pattern) were all resolved in-PR per [[feedback_act_on_issues_dont_mention]] and [[feedback_fix_all_review_issues]].

### Housekeeping (stale worktrees on disk)

Carry-over from prior batons. After this Task 9 PR merges, the Task 8 worktree (still on disk per the prior baton) and this Task 9 worktree should be cleaned up.

```bash
# From /Users/hherb/src/secretary, after the present (Task 9) PR merges:
git worktree remove .worktrees/c1-1b-sync-merge   && git branch -D feature/c1-1b-task-17
git worktree remove .worktrees/c2-task-1-spec     && git branch -D feature/c2-task-1-spec
for n in 1 2 3 4 5 6 7 8 9 10; do
  git worktree remove .worktrees/c2-task-$n       && git branch -D feature/c2-task-$n
done
git worktree remove .worktrees/d11-tauri-spec     && git branch -D feature/d11-tauri-spec
git worktree remove .worktrees/d11-task-3         && git branch -D feature/d11-task-3
git worktree remove .worktrees/d11-task-4         && git branch -D feature/d11-task-4
git worktree remove .worktrees/d11-task-5         && git branch -D feature/d11-task-5
git worktree remove .worktrees/d11-task-6         && git branch -D feature/d11-task-6
git worktree remove .worktrees/d11-task-8         && git branch -D feature/d11-task-8
# Keep .worktrees/d11-task-9 until this PR merges; remove after.
```

## (4) Exact commands to resume (Task 10)

```bash
# After this Task 9 PR (feature/d11-task-9) merges:
cd /Users/hherb/src/secretary
git fetch --prune origin
git status --short              # expect: clean
git checkout main
git pull --ff-only origin main

# Re-baseline the gauntlet on fresh main:
cargo test --release --workspace --no-fail-fast 2>&1 | grep "^test result:" | awk '$3=="ok." {p+=$4; f+=$6; i+=$8} END {printf "Rust totals → PASSED: %d FAILED: %d IGNORED: %d\n", p, f, i}'
# Expect: PASSED: 1053 FAILED: 0 IGNORED: 10

# Frontend baseline on main:
cd desktop
pnpm install
pnpm test                       # expect: 182 passing
pnpm typecheck                  # clean
pnpm svelte-check               # 237 files, 0 errors
pnpm lint                       # clean
cd ..

# Set up the Task 10 worktree:
git worktree add .worktrees/d11-task-10 -b feature/d11-task-10 main
cd .worktrees/d11-task-10/desktop
pnpm install

# Open the plan and follow Task 10 step-by-step:
#   docs/superpowers/plans/2026-05-27-d11-tauri-walking-skeleton.md
# Search for "## Task 10:" — each step block is self-contained.

# After Toast.svelte + App.svelte updates + Vitest component tests:
cd ..   # back to .worktrees/d11-task-10/
cargo test --release --workspace --no-fail-fast 2>&1 | grep "^test result:" | awk '$3=="ok." {p+=$4; f+=$6; i+=$8} END {printf "Rust totals → PASSED: %d FAILED: %d IGNORED: %d\n", p, f, i}'
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py
cd desktop
pnpm test                       # expect 182 + Task-10 surplus (plan-target ~8-14 new)
pnpm typecheck
pnpm svelte-check
pnpm lint
```

## Closing inventory

- **Branch state on close:** `main` at `329d315` (D.1.1 Task 8 PR #155 merged earlier today). `feature/d11-task-9` carries 4 code commits + 1 review-fixup commit + this baton + a merge from `origin/main` that absorbed the `e97dd1a` pause-window baton sync. Squash-merge collapses to one commit on `main`.
- **Workspace tests on `feature/d11-task-9` (post-review-fixup):** Rust **1053 passed + 10 ignored** (unchanged — fixups were frontend-only). Vitest **182 passed** (errors=26, ipc=13, auto_lock=12, stores=45, constants=4, PathPicker=8, BlockCard=8, LockButton=9, TopBar=7, Unlock=9, Vault=14, SettingsDialog=19, App=8) — new gauntlet baseline.
- **README.md:** unchanged. Per prior batons, per-task status flips during D.1.1 implementation are noise until D.1.1 ships end-to-end (Task 12). The existing "D.1.1 walking skeleton … in design" covers the implementation phase as a whole.
- **ROADMAP.md:** unchanged. Same logic as README.
- **CLAUDE.md:** unchanged this session.
- **NEXT_SESSION.md:** symlink retargeted to this file.
- **`docs/adr/`:** unchanged.
- **`desktop/src/lib/`:** new `constants.ts`; `stores.ts` gains `settingsUpdated` transition helper (+ legal-edge graph updated in header).
- **`desktop/src/`:** new `components/SettingsDialog.svelte`. `components/TopBar.svelte` modified (drops disabled gear, adds `onOpenSettings` prop). `routes/Vault.svelte` modified (instantiates SettingsDialog + threads onOpenSettings to TopBar).
- **`desktop/src/theme.css`:** appended `.settings-dialog*` block (~85 LOC). Modified `.top-bar__settings` (lost disabled-styling, gained hover state).
- **`desktop/tests/`:** new `constants.test.ts`, `SettingsDialog.test.ts`, `setup.ts` (polyfill). Extended `stores.test.ts` (+4), `TopBar.test.ts` (+1 net), `Vault.test.ts` (+2).
- **`desktop/vitest.config.ts`:** added `setupFiles: ['./tests/setup.ts']` for JSDOM polyfill.
- **Open issues:** see §(3); **zero closed by this PR**. (Task 9 was scoped to the dialog itself; #145's broader recovery-path concern remains open even though the dialog now provides the editing mechanism.)
- **Open PRs:** PR for this task being opened now (after baton commit).
- **Worktrees on disk:** stale worktrees listed in §(3) can be cleaned up at any pause; `feature/d11-task-9` stays until merge.
- **This file:** the live baton for the Task 9 close. The next slice opens with `docs/handoffs/<date>-d11-task-10-shipped.md`.
