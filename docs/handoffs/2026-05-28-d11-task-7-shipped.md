# NEXT_SESSION.md — D.1.1 Task 7 (Unlock route + PathPicker + vault-locked listener) shipped

**Session date:** 2026-05-28 (fourth D.1.1 slice of the day; continues immediately from the Task 6 session that landed via PR #148 at `ca5d0e5` on `main`. This session lands the first user-visible Svelte components and closes both issues filed during the PR #148 review: #149 (`vault-locked` event listener) and #150 (SessionState state-machine wrapper).)
**Status:** D.1.1 Task 7 PR open on branch `feature/d11-task-7`. Predecessors on `main`: D.1.1 spec + ADR 0007 (PR #130, `a5d85b9`), D.1.1 Task 1 scaffold (PR #131, `e329087`), D.1.1 Task 2 pure modules (PR #137, `a3ee9e9`), D.1.1 Task 3 VaultSession (PR #142, `6f984d4`), D.1.1 Task 4 IPC commands + DTOs (PR #143, `9217602`), D.1.1 Task 5 auto-lock timer (PR #146, `16721c5`), D.1.1 Task 6 frontend pure modules (PR #148, `ca5d0e5`).

## (1) What we shipped this session

The first three commits land Task 7 proper — the Unlock route, PathPicker leaf, theme.css tokens, and the Tauri dialog plugin backend wiring. The fourth commit closes #149 by wiring the `vault-locked` Tauri event listener into App.svelte's `onMount`, and the fifth (chronologically first) closes #150 by demoting the raw `sessionState` writable to internal and exposing only legal-transition helpers. Both issues were filed during PR #148's review and were deliberately scoped to Task 7 per their authoring (user confirmed both as in-scope for this PR at session start).

| Commit | Subject | What it lands |
|---|---|---|
| `681205a` | `refactor(d11): SessionState state-machine wrapper (closes #150)` | Demote `writable<SessionState>` to non-exported `_internal`; expose `Readable<SessionState>` + transition helpers (`beginUnlock`, `unlockSucceeded`, `unlockFailed`, `beginLock`, `vaultLocked`). `unlocking` / `locking` variants now carry `startedAt: number`. Illegal edges throw in dev (`import.meta.env.DEV`), log to `console.error` + no-op in prod. Tests: 31 (was 10) covering every legal transition, illegal-edge rejection per variant, dev-vs-prod branching, the authoritative `vaultLocked` from each state, and the derived/notice stores. `_resetSessionStateForTest` is the underscore-prefixed escape hatch (matches the `_resetActivityTrackingForTest` convention from `auto_lock.ts`). Adds `src/vite-env.d.ts` for `import.meta.env` typing. |
| `27bdb02` | `feat(d11): Task 7 — wire tauri-plugin-dialog for PathPicker` | Backend half. `desktop/src-tauri/Cargo.toml`: add `tauri-plugin-dialog = "2"` (resolves 2.7.1). `desktop/src-tauri/src/main.rs`: register via `.plugin(tauri_plugin_dialog::init())`. `desktop/src-tauri/capabilities/default.json`: new file; Tauri 2 auto-picks up `capabilities/*.json`. Grants `core:default` + `dialog:allow-open` only — least-privilege per CLAUDE.md security guidance. |
| `2d56d55` | `feat(d11): Task 7 — theme.css + PathPicker component + Vitest harness for components` | `desktop/src/theme.css`: CSS custom-property tokens (color, spacing, radius, typography, shadow) + dark-mode override block + `.path-picker` component class. `desktop/src/components/PathPicker.svelte`: small leaf wrapping `@tauri-apps/plugin-dialog`'s `open({ directory: true })`; emits the path through `onSelect`. `desktop/tests/PathPicker.test.ts`: 8 tests using `@testing-library/svelte`'s `render()` + `fireEvent.click()` with `vi.hoisted` for the dialog-plugin mock. `vitest.config.ts`: add `svelteTesting()` from `@testing-library/svelte/vite` (wires browser resolve conditions + noExternal + auto-cleanup). devDeps: bump `@sveltejs/vite-plugin-svelte` 4 → 5 (v4 peer-deps Vite 5; we're on Vite 6); add `@testing-library/svelte@^5`, `@testing-library/jest-dom@^6`, `@testing-library/user-event@^14`. |
| `9b61a68` | `feat(d11): Task 7 — Unlock route + form submission lifecycle` | `desktop/src/routes/Unlock.svelte`: first user-visible route. Renders the folder picker + password field + submit button, threads submission through `beginUnlock` → `unlockWithPassword` → `getSettings` → `unlockSucceeded` / `unlockFailed`. Password cleared from `bind:value` immediately on success (shrinks DOM-residue lifetime; JS can't zeroize but we can shorten). `submit()` short-circuits when invalid or already in-flight, preventing a double Argon2id derivation on stray Enter. Inline error reads `userMessageFor($sessionState.lastError)` so adding a Rust variant without a TS counterpart still breaks tsc compile via the existing exhaustiveness check. Tests: 8 covering initial-render shape, disabled→enabled transition, happy-path IPC sequence, password clearing, `wrong_password` (title) + `vault_path_not_found` (path in detail) error paths, and empty-fields submit guard. `theme.css` grows the `.unlock*` block (~80 LOC). |
| `b726611` | `feat(d11): App.svelte router + vault-locked event listener (closes #149)` | App.svelte routes on `$sessionState.status` (renders `<Unlock />` when locked / unlocking / locking; placeholder vault view when unlocked — real BlockList lands in Task 8). `onMount` installs `listen('vault-locked', …)` with unmount-race-safe pattern: a closure-local `unmounted` flag lets a late `listen` resolve detach itself if it lands after the cleanup ran. Maps backend reason (`'explicit'` / `'auto'`) to AutoLockNotice reason (`'manual'` / `'idle'`) via a small const table, then calls `vaultLocked(notice)` which transitions + raises the notice in one shot. Tests: 7 covering router rendering, listener installation, the two reason mappings, the mid-flight race (`vaultLocked` from `unlocking` lands safely thanks to the authoritative transition), and the unmount-time detach. |

**Commits on `feature/d11-task-7`** (5 originals + 1 baton):

| SHA | Subject |
|---|---|
| `681205a` | `refactor(d11): SessionState state-machine wrapper (closes #150)` |
| `27bdb02` | `feat(d11): Task 7 — wire tauri-plugin-dialog for PathPicker` |
| `2d56d55` | `feat(d11): Task 7 — theme.css + PathPicker component + Vitest harness for components` |
| `9b61a68` | `feat(d11): Task 7 — Unlock route + form submission lifecycle` |
| `b726611` | `feat(d11): App.svelte router + vault-locked event listener (closes #149)` |
| TBD | `docs(d11): Task 7 handoff baton` |

Post-squash-merge SHA on `main` will differ.

### Gauntlet (live, performed)

```
Rust:           PASSED 1053 FAILED 0 IGNORED 10    # unchanged — Task 7 backend touch is Tauri-plugin-dialog dep only
cargo clippy --release --workspace --tests -- -D warnings   → clean
cargo fmt --all -- --check                                  → clean
uv run core/tests/python/conformance.py                     → PASS
uv run core/tests/python/spec_test_name_freshness.py        → PASS

Frontend:       Vitest 105 / 0 (7 files: errors=26, ipc=13, auto_lock=12, stores=31, PathPicker=8, Unlock=8, App=7)
pnpm typecheck                                              → clean
pnpm svelte-check                                           → 224 files, 0 errors, 0 warnings
pnpm lint                                                   → clean
```

Plan-vs-actual on Vitest counts: plan predicted **~12** new tests for Task 7 ("4 + 4 + 4" sketch); actual is **44 new** (`stores.test.ts` grew 10 → 31 = +21; new files PathPicker=8, Unlock=8, App=7 = 23). Surplus split:

- `stores.test.ts`: +21 from the #150 state-machine wrapper landing. Every legal transition is pinned plus at least one illegal-edge case per variant plus the dev-vs-prod branching of the assertion plus the authoritative `vaultLocked` from each of four states. None of this surface existed before #150.
- `PathPicker.test.ts`: 8 — open() options shape pin, string-return → onSelect, null-return (cancel) is no-op, disabled blocks click, non-string array return defensive ignore, plus three rendering pins (placeholder, readonly attribute, current-value rendering).
- `Unlock.test.ts`: 8 — initial render (heading/label/button), disabled→enabled on field fills, happy-path IPC sequence + state landing, password clearing, two error-path payloads (`wrong_password` title, `vault_path_not_found` path-in-detail), and empty-fields submit guard.
- `App.test.ts`: 7 — router locked → Unlock, unlocked → placeholder, listener mounted, reason mapping ×2, mid-flight race, unmount-time detach.

The surplus is intentional; under-counting was a plan-sketch slip.

### Plan execution trace (for the reviewer)

- Plan Step 1 (worktree) ✅ executed; Step 2 (backend plugin) ✅; Step 3 (`theme.css`) ✅ with adaptation #1 (component classes in theme.css rather than `<style>` blocks); Step 4 (PathPicker.svelte) ✅; Step 5 (Unlock.svelte) ✅ with adaptation #2 (transition helpers, not direct `.set()`); Step 6 (App.svelte) ✅ extended with #149 listener; Step 7 (manual `pnpm tauri dev` smoke) deliberately skipped — no UI environment available in this session (called out as a follow-up below); Step 8 (gauntlet + commit) ✅.
- File sizes (all comfortably under the 500-LOC threshold): stores.ts=159, App.svelte=58, Unlock.svelte=92, PathPicker.svelte=39, theme.css=189. Tests: stores.test=276, Unlock.test=146, PathPicker.test=109, App.test=137.
- Per-module TDD discipline: each new file landed with its test in the same commit. Tests written first → ran red → implementation → ran green. The state-machine wrapper commit alone went red on 31 of 31 before implementation.

### Fixup pass — PR #152 review (this same session)

After the initial five-commit push, an in-review pass surfaced seven small items. Five were fixable in-PR; two are tracked as follow-up issues:

| Item | Fix |
|---|---|
| `tauri-plugin-dialog = "2"` (caret range) vs project's exact-pin convention for security-critical deps | Added a comment in [`desktop/src-tauri/Cargo.toml`](../../desktop/src-tauri/Cargo.toml) justifying the caret: UI-only plugin, no key material crosses it (folder-path strings are already inside the trust boundary), no security guarantee rides on a specific 2.x patch. |
| `INITIAL_STATE` was a shared object reference between the initial writable and `_resetSessionStateForTest` — a test that mutated `.lastError` would have mutated the module-level constant | Replaced with an `initialState()` factory so each call yields a fresh object. |
| `Unlock.svelte` cleared `password` only on success, leaving the failed-attempt string in DOM state until the next keystroke | Moved `password = ''` into the `finally` block so the binding clears on both paths. Added a Vitest pin for the failure path (`106 / 0` passing, was 105). |
| `Unlock.test.ts` used a triple `await Promise.resolve()` to flush the IPC chain — brittle if the chain grows another await link | Replaced with `await waitFor(() => expect(...))` from `@testing-library/svelte` across `Unlock.test.ts`, `PathPicker.test.ts` (positive cases), and `App.test.ts`. Negative cases in `PathPicker.test.ts` (cancellation + multi-select misuse) settle the awaited mock promise explicitly via `await openMock.mock.results[0].value` rather than `Promise.resolve()`. |
| `warnSpy` variable name spied on `console.error`, not `console.warn` | Renamed to `errorSpy` in [`desktop/tests/stores.test.ts`](../../desktop/tests/stores.test.ts). |
| `theme.css` centralization works around a Vite 6/Vitest bug but spreads visual rules away from their owning components | Filed as #153 (revisit after upstream fix). |
| Emoji `🔐` icon renders inconsistently across platforms (especially Linux without an emoji font) | Filed as #154 (replace with inline SVG before D.1.1 ships externally). |

Gauntlet after fixup (re-run, fully green):

```
Rust:           PASSED 1053 FAILED 0 IGNORED 10
cargo clippy --release --workspace --tests -- -D warnings   → clean
cargo fmt --all -- --check                                  → clean
uv run core/tests/python/conformance.py                     → PASS
uv run core/tests/python/spec_test_name_freshness.py        → PASS

Frontend:       Vitest 106 / 0 (+1 password-clear-on-failure pin)
pnpm typecheck                                              → clean
pnpm svelte-check                                           → 224 files, 0 errors, 0 warnings
pnpm lint                                                   → clean
```

## (2) What's next — D.1.1 Task 8 (Vault route + BlockCard + LockButton)

Per the plan, Task 8 lands the second user-visible route — the post-unlock screen with top bar (vault label + settings gear + lock button) + vertical stack of BlockCards. Clicks on cards are stubbed (D.1.2 wires them up). LockButton calls the `lock` IPC; the frontend waits for the `vault-locked` event (already wired by #149 in this PR) before transitioning to locked — backend reality is source of truth per spec §7.

**Files (per the plan):**

- Create: `desktop/src/routes/Vault.svelte` — top bar + vertical stack of BlockCard.
- Create: `desktop/src/components/BlockCard.svelte` — single block summary card.
- Create: `desktop/src/components/LockButton.svelte` — calls `beginLock()` then `lock()` IPC; visibly enters "Locking…" pending state until the `vault-locked` event arrives.
- Create: `desktop/src/components/TopBar.svelte` — vault label + settings gear (stub) + LockButton.
- Modify: `desktop/src/App.svelte` — render `<Vault />` instead of the placeholder when unlocked.
- Modify: `desktop/src/theme.css` — append `.vault*`, `.block-card*`, `.lock-button*`, `.top-bar*` blocks.
- New tests: `desktop/tests/Vault.test.ts`, `desktop/tests/BlockCard.test.ts`, `desktop/tests/LockButton.test.ts`, `desktop/tests/TopBar.test.ts`.

**Acceptance criteria for Task 8:**

- Gauntlet: Rust **1053 / 0 / 10** (unchanged — Task 8 is frontend-only), Vitest **105 + N** where N ≈ 12-16 component tests across the new files.
- `pnpm tauri dev` smoke: unlock the golden vault → BlockList renders with the block summaries from `listBlocks()` → click LockButton → button shows "Locking…" → `vault-locked` event from backend → screen swaps back to Unlock.
- LockButton enters `locking` state via `beginLock()` BEFORE awaiting the IPC; the `vault-locked` listener (App.svelte) handles the eventual transition. Rollback path: if `lock()` IPC throws, today's wrapper has no `lockFailed` helper — see decisions §(3) below.
- ESLint + svelte-check clean.

**Estimate:** ~90–120 min (4 small Svelte components + Vault route + theme.css extensions + 4 Vitest test files).

## (3) Open decisions and risks

### Plan adaptations (worth flagging to the reviewer)

1. **Component styles centralised in `theme.css`, not in component `<style>` blocks.** Vite 6's internal `preprocessCSS` trips a `PartialEnvironment` proxy bug under Vitest (`new Proxy(this, …)` fails because the constructor's `this` isn't fully constructed when called from a partial-config code path). Symptoms: every `.svelte` file with a `<style>` block crashes the test suite at the preprocess step, regardless of style content. Verified across `@sveltejs/vite-plugin-svelte` 4.0.4 AND 5.1.1; the bug is in vite itself. Workarounds considered: pin Vite to 5.x (would block Vite-6-required deps later), patch `@sveltejs/vite-plugin-svelte`, write a vite plugin to short-circuit `preprocessCSS`. The chosen path — moving all component styles into `theme.css` as global `.<component> { … }` classes — is the lowest-risk fix AND has a side-benefit: every visual choice is reviewable in one file rather than spread across components. The convention is documented in a comment at the top of `theme.css`. Trade-off accepted: no per-component scoping → name collisions in theory; mitigated by the `.<component>__<part>` BEM-light convention.
2. **`Unlock.svelte` uses transition helpers, not raw `sessionState.set(...)`.** The plan's `Unlock.svelte` sketch called `sessionState.set({...})` directly, but #150 demotes the writable to internal. The submit handler now reads `beginUnlock() → unlockWithPassword(...) → getSettings() → unlockSucceeded(manifest, settings)` (or `unlockFailed(err)` on throw). Cleaner anyway — the plan's `sessionState.set({ status: 'unlocking', lastError: null })` would have been a type error (the `unlocking` variant has no `lastError` field).
3. **`getSettings` imported statically, not via dynamic `import()`.** The plan had a `const { getSettings } = await import('../lib/ipc')` mid-function for some reason. Static `import { getSettings } from '../lib/ipc'` at the top is the obvious choice — Vite tree-shakes either way, and the dynamic form trips the no-loss-of-mockability surface.
4. **No `pnpm tauri dev` smoke this session.** The plan's Step 7 calls for a manual smoke — open the dialog, unlock the golden vault, etc. This session has no UI environment available, so the smoke is deferred. The component-level Vitest tests cover the form logic + IPC contract; the Tauri-event side is mocked. A `pnpm tauri dev` smoke before merge would close the gap; alternatively, it can ride in Task 8's smoke (which exercises the same unlock path en route to BlockList).
5. **`@sveltejs/vite-plugin-svelte` 4 → 5.** Vite 6 (already a project dep from Task 1) requires vite-plugin-svelte v5. v4 silently no-ops on certain hooks in Vite 6, which is why the test suite started failing on Svelte rune emission once a real component landed. The bump is a no-op for runtime semantics — purely a peer-dep alignment.
6. **`@testing-library/svelte` v5 + `svelteTesting()` companion plugin.** v5 of testing-library/svelte ships its runes mode helpers as `.svelte.js` files in node_modules, which the Svelte plugin can't compile without the `svelteTesting()` companion that adds the `browser` resolve condition AND the `ssr.noExternal` list. Documented at the top of `vitest.config.ts`. Required for any future component tests too.

### Decisions settled

- **`vaultLocked` is authoritative — accepts from any state.** The backend's `vault-locked` event is the source of truth (spec §7). Even if the frontend is mid-flight in `unlocking`, an arriving event transitions us to `locked`. The user re-tries from a clean state, which is correct: the backend has decided to lock and the frontend follows.
- **Illegal transitions throw in dev, log + no-op in prod.** Per the user-authored issue #150 body. Vitest runs with `import.meta.env.DEV === true` so the dev-throw branch is covered by tests; the prod-log branch gets a dedicated test that uses `vi.stubEnv('DEV', false)` to flip the runtime environment. The argument for failing loud everywhere (per [[feedback_security_no_assumptions]]) was weighed against the user's authored guidance — the prod path **does** log at `console.error` so it's not silent; the no-op-instead-of-throw branch keeps a frontend state-machine bug from DOS-ing the user. Backend remains the source of truth either way.
- **No `lockFailed` rollback helper in the state machine.** The `lock` IPC is infallible by spec (lock is idempotent; it always wipes the session). If a future transport-level error needs handling, add a new helper then. Currently the `locking → unlocked` edge isn't a documented legal transition; deferred until Task 8 surfaces it (if it does).
- **`startedAt: number` on `unlocking` / `locking` variants** but no consumer yet. Tasks 8–10 will use it to detect stuck transitions and surface a "this is taking longer than usual" toast. Landing the field now means consumers don't need a coordinated schema migration when they wire up the toast.
- **`@testing-library/svelte` v5 + `svelteTesting()` is the component-test toolchain.** The baton (Task 6) noted the choice between this and `@vitest/browser` (real-browser via Playwright); v5 of testing-library handles Svelte 5 runes well, and jsdom is cheaper for CI. Realism trade-off cashed in at Task 11's e2e suite.

### Risks carried forward

- **`pnpm tauri dev` smoke deferred.** See plan-adaptation #4. The Vitest suite covers the form lifecycle behaviourally but doesn't catch e.g. Tauri capability misconfiguration. Mitigation: Task 8's smoke walks the same unlock path; a regression in the capability setup surfaces there. Manual verification before merge is also straightforward (5 minutes of `pnpm tauri dev` + clicking through the unlock flow).
- **Vite 6 `preprocessCSS` bug.** See plan-adaptation #1. The workaround (centralised stylesheet) is a permanent restriction on the project — adding a `<style>` block to any future component will break the test suite. Cost of the restriction: low (visual rules co-located in `theme.css` is arguably cleaner than per-component scoping anyway). Cost of fixing the upstream bug: monitor `@sveltejs/vite-plugin-svelte` ≥ 6 + Vite ≥ 7 release notes — when the bug is fixed upstream, per-component styles can land without test-harness penalty.
- **Carry-forward: password handling at the IPC boundary is not yet zeroize-typed** (Task 4 risk). Unchanged; Unlock.svelte still binds to a JS `string`. The lifetime is shrunk to "from input to submit", but mid-flight Argon2id (the dominant time window) still holds the string in memory.
- **Carry-forward: `AppError::KdfTooWeak` still has no producer.** Unchanged.
- **Carry-forward: bridge `RecordInput.record_type` workaround** (issue #141). Unchanged.

### Issues closed by this PR

- **#149** (vault-locked event listener) — App.svelte's `onMount` installs the listener; the `reason` field maps to AutoLockNotice; `sessionState` transitions via authoritative `vaultLocked()`.
- **#150** (SessionState transition helpers) — `sessionState` demoted to `Readable<SessionState>`; mutations gate through transition helpers; illegal edges throw in dev / log in prod.

### Issues currently open (carry-over)

- #37, #117, #120, #122, #123 — none affected by Task 7.
- #38, #45, #75, #76, #78, #79, #81, #87, #88, #90, #95, #98 — none affected.
- #139 — desktop: `AppError` lacks `Deserialize`. Same status as before.
- #140 — desktop: `parse_settings_field` text-only invariant. Status unchanged.
- #141 — bridge: `RecordInput` lacks `record_type` field. Status unchanged.
- #144 — desktop: Argon2id KDF runs under IPC mutex during unlock. Status unchanged; still deferred to D.1.4+.
- #145 — desktop: no recovery path for unlock-time settings warnings. Status unchanged; still deferred.

### Issues filed during this PR's fixup pass

- **#153** — desktop: re-migrate component styles from `theme.css` back to component `<style>` blocks once the upstream Vite/Vitest `preprocessCSS` bug clears.
- **#154** — desktop: replace the emoji `🔐` unlock icon with inline SVG before D.1.1 ships externally.

### Housekeeping (stale worktrees on disk)

Carry-over from prior batons. After this Task 7 PR merges, the freshly-shipped Task 6 worktree should be cleaned up too.

```bash
# From /Users/hherb/src/secretary, after the present (Task 7) PR merges:
git worktree remove .worktrees/c1-1b-sync-merge   && git branch -D feature/c1-1b-task-17
git worktree remove .worktrees/c2-task-1-spec     && git branch -D feature/c2-task-1-spec
for n in 1 2 3 4 5 6 7 8 9 10; do
  git worktree remove .worktrees/c2-task-$n       && git branch -D feature/c2-task-$n
done
git worktree remove .worktrees/d11-tauri-spec     && git branch -D feature/d11-tauri-spec
git worktree remove .worktrees/d11-task-3         && git branch -D feature/d11-task-3
git worktree remove .worktrees/d11-task-4         && git branch -D feature/d11-task-4
git worktree remove .worktrees/d11-task-5         && git branch -D feature/d11-task-5
git worktree remove .worktrees/d11-task-6         && git branch -D feature/d11-task-6   # Task 6 PR #148 merged at ca5d0e5
# Keep .worktrees/d11-task-7 until this PR merges; remove after.
```

## (4) Exact commands to resume (Task 8)

```bash
# After this Task 7 PR (feature/d11-task-7) merges:
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
pnpm install                    # picks up the locked devDeps from this PR
pnpm test                       # expect: 105 passing
pnpm typecheck                  # clean
pnpm svelte-check               # 224 files, 0 errors
pnpm lint                       # clean
cd ..

# Set up the Task 8 worktree:
git worktree add .worktrees/d11-task-8 -b feature/d11-task-8 main
cd .worktrees/d11-task-8/desktop
pnpm install

# Open the plan and follow Task 8 step-by-step:
#   docs/superpowers/plans/2026-05-27-d11-tauri-walking-skeleton.md
# Search for "## Task 8:" — each step block is self-contained.

# After Vault.svelte / BlockCard.svelte / LockButton.svelte / TopBar.svelte
# + Vitest component tests:
cd ..   # back to .worktrees/d11-task-8/
cargo test --release --workspace --no-fail-fast 2>&1 | grep "^test result:" | awk '$3=="ok." {p+=$4; f+=$6; i+=$8} END {printf "Rust totals → PASSED: %d FAILED: %d IGNORED: %d\n", p, f, i}'
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py
cd desktop
pnpm test                       # expect 105 + Task-8 surplus (plan-target ~12-16 new)
pnpm typecheck
pnpm svelte-check
pnpm lint
```

## Closing inventory

- **Branch state on close:** `main` at `ca5d0e5` (D.1.1 Task 6 PR #148 merged earlier today). `feature/d11-task-7` carries 5 code commits (one per logical unit: #150 wrapper, backend dialog plugin, theme + PathPicker + harness, Unlock route, App.svelte + #149 listener) + this baton. Squash-merge collapses to one commit on `main`.
- **Workspace tests on `feature/d11-task-7`:** Rust **1053 passed + 10 ignored** (unchanged — backend touch is a dep addition + plugin registration). Vitest **106 passed** post-fixup (errors=26, ipc=13, auto_lock=12, stores=31, PathPicker=8, Unlock=9, App=7) — new gauntlet baseline.
- **README.md:** unchanged. Per prior batons, per-task status flips during D.1.1 implementation are noise until D.1.1 ships end-to-end (Task 12). The existing "D.1.1 walking skeleton … in design" covers the implementation phase as a whole.
- **ROADMAP.md:** unchanged. Same logic as README.
- **CLAUDE.md:** unchanged this session.
- **NEXT_SESSION.md:** symlink retargeted to this file.
- **`docs/adr/`:** unchanged.
- **`desktop/src/lib/`:** `stores.ts` rewritten for the state-machine wrapper; `vite-env.d.ts` added.
- **`desktop/src/`:** new `App.svelte` (router + listener), `theme.css`, `components/PathPicker.svelte`, `routes/Unlock.svelte`.
- **`desktop/tests/`:** new `PathPicker.test.ts`, `Unlock.test.ts`, `App.test.ts`; `stores.test.ts` rewritten for the new API.
- **`desktop/vitest.config.ts`:** add `svelteTesting()` plugin.
- **`desktop/package.json`:** +3 devDeps (`@testing-library/svelte`, `@testing-library/jest-dom`, `@testing-library/user-event`), bump `@sveltejs/vite-plugin-svelte` 4 → 5.
- **`desktop/pnpm-lock.yaml`:** new packages for testing-library + Svelte-5-compat plugin tree.
- **`desktop/src-tauri/Cargo.toml`:** + `tauri-plugin-dialog = "2"`.
- **`desktop/src-tauri/src/main.rs`:** + `.plugin(tauri_plugin_dialog::init())`.
- **`desktop/src-tauri/capabilities/default.json`:** new file (`core:default` + `dialog:allow-open`).
- **Open issues:** see §(3); **two closed by this PR (#149, #150)**.
- **Open PRs:** PR for this task being opened now (after baton commit).
- **Worktrees on disk:** stale worktrees listed in §(3) can be cleaned up at any pause; `feature/d11-task-7` stays until merge.
- **This file:** the live baton for the Task 7 close. The next slice opens with `docs/handoffs/<date>-d11-task-8-shipped.md`.
