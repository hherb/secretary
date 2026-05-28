# NEXT_SESSION.md — D.1.1 Task 6 (frontend pure modules + Vitest harness) shipped

**Session date:** 2026-05-28 (third D.1.1 slice of the day; continues immediately from the Task 5 session that landed via PR #146 at `16721c5` on `main`. This session establishes the TypeScript layer every Svelte component in Tasks 7–10 will import: typed IPC wrappers, error → user-message translation, session-state Svelte stores, debounced activity tracker, plus the Vitest + ESLint flat-config harness that wires the frontend into the project's "always green" discipline.)
**Status:** D.1.1 Task 6 authored on branch `feature/d11-task-6`; PR to be opened at end of session. Predecessors on `main`: D.1.1 spec + ADR 0007 (PR #130, `a5d85b9`), D.1.1 Task 1 scaffold (PR #131, `e329087`), D.1.1 Task 2 pure modules (PR #137, `a3ee9e9`), D.1.1 Task 3 VaultSession (PR #142, `6f984d4`), D.1.1 Task 4 IPC commands + DTOs (PR #143, `9217602`), D.1.1 Task 5 auto-lock timer (PR #146, `16721c5`).

## (1) What we shipped this session

Adds the desktop frontend's pure-TS layer. Four small modules in [`desktop/src/lib/`](../../desktop/src/lib/) carry the typed surface every Svelte component in Tasks 7–10 will consume; three Vitest suites in [`desktop/tests/`](../../desktop/tests/) pin the behavioural contract; the harness (Vitest config, jsdom env, ESLint flat config + plugins, `typecheck` npm script) wires the frontend into the gauntlet so `cargo test`-style discipline reaches into the TS layer from now on.

| Artifact | Path | Notes |
|---|---|---|
| `errors.ts` — typed `AppError` + `AppWarning` discriminated union + `userMessageFor` translator | [`desktop/src/lib/errors.ts`](../../desktop/src/lib/errors.ts) | 13-variant `AppError` mirrors `src-tauri/src/errors.rs::AppError` exactly (`#[serde(tag = "code", rename_all = "snake_case")]`). 3-variant `AppWarning` mirrors `src-tauri/src/errors.rs::AppWarning`. `userMessageFor` is an exhaustive `switch` — adding a Rust variant without a TS counterpart breaks the discriminated union and tsc rejects compile. The `MS_PER_SECOND = 1_000` constant is named (no magic numbers in the ms→s conversions). ≈124 LOC. |
| `errors.test.ts` — 22 tests pinning every variant + payload-surfacing | [`desktop/tests/errors.test.ts`](../../desktop/tests/errors.test.ts) | `it.each` over 13 `AppError` variants and 3 `AppWarning` variants guarantees every code path produces a non-empty title — silent fall-through to a blank toast becomes a test failure. 6 additional payload-surfacing pins (`vault_path_not_found` shows the path, `wrong_password` mentions Caps Lock, `kdf_too_weak` shows both KiB numbers, `settings_out_of_range` shows seconds (not ms), `settings_unknown_version` shows the version string, `settings_clamped` shows both seconds). 95 LOC. |
| `ipc.ts` — typed wrappers for all 7 Tauri commands | [`desktop/src/lib/ipc.ts`](../../desktop/src/lib/ipc.ts) | DTO interfaces (`BlockSummaryDto`, `ManifestDto`, `SettingsDto`) match the Rust `#[serde(rename_all = "camelCase")]` DTOs in `src-tauri/src/dtos.rs` field-for-field. The `call<T>` helper centralises the rejection-path → typed-AppError conversion: `isAppError` type-guard preserves typed rejections; non-typed rejections (panics, plain strings) are wrapped as `{ code: 'internal' }` so the UI layer always gets an exhaustive shape. Tauri 2's snake-case-to-camelCase IPC convention means we send `folderPath` for the Rust `folder_path` arg. 81 LOC. |
| `ipc.test.ts` — 10 tests pinning argument shape + return shape + error path | [`desktop/tests/ipc.test.ts`](../../desktop/tests/ipc.test.ts) | Uses `vi.hoisted` for the `invokeMock` capture (mandatory pattern — see §(3) Plan adaptations #2). 3 arg-shape pins (`unlockWithPassword` sends camelCase `folderPath`, `setSettings` nests under `settings:`, argument-less commands invoke with `undefined`), 3 return-shape pins, 4 error-path pins (typed `AppError` round-trip preserving payload, bare-string rejection wrapped, object-without-`code` rejection wrapped). 124 LOC. |
| `stores.ts` — Svelte stores for session state | [`desktop/src/lib/stores.ts`](../../desktop/src/lib/stores.ts) | `SessionState` is a discriminated union (`locked` / `unlocking` / `unlocked` / `locking`) so the App.svelte router can `switch ($s.status)` instead of branching on bag-of-booleans. `autoLockNotice` is a short-lived toast surface for the `vault-locked` event with `reason: "auto"` (the Toast component in Task 7 reads + clears on timeout). `currentSettings` is a derived store that returns `null` whenever not unlocked. 29 LOC, no tests — purely declarative store wiring with no logic to pin (component-level integration tests in Tasks 8–10 will exercise the subscriptions). |
| `auto_lock.ts` — document-level activity tracker with rate-limit | [`desktop/src/lib/auto_lock.ts`](../../desktop/src/lib/auto_lock.ts) | `startActivityTracking()` installs `mousemove` + `keydown` listeners on `document` and rate-limits calls to `ipc.notifyActivity()` at `ACTIVITY_NOTIFY_MIN_INTERVAL_MS = 2_000` (mirror of `src-tauri/src/constants.rs::ACTIVITY_NOTIFY_MIN_INTERVAL_MS`). Leading-edge fire (first event triggers immediately) + trailing-edge `setTimeout` for events arriving during the debounce window. Returns a cleanup function; calling `startActivityTracking` twice tears down the prior installation. `_resetActivityTrackingForTest()` underscore-prefixed escape hatch for Vitest. 84 LOC. |
| `auto_lock.test.ts` — 8 tests pinning the rate-limit + cleanup contract | [`desktop/tests/auto_lock.test.ts`](../../desktop/tests/auto_lock.test.ts) | `vi.hoisted` for the `notifyActivityMock` capture, `vi.useFakeTimers()` per test so `Date.now()` and `setTimeout` are deterministic. Pins: leading-edge mousemove + keydown both fire immediately, debounce-window suppresses re-fire, post-window event fires again, trailing-edge debounced event fires via the scheduled `setTimeout`, cleanup detaches listeners, cleanup cancels a pending debounce timer, double-start tears down the prior installation. 92 LOC. |
| `vitest.config.ts` — Vitest harness pointing at `tests/**/*.test.ts` | [`desktop/vitest.config.ts`](../../desktop/vitest.config.ts) | Loads `@sveltejs/vite-plugin-svelte` (already in devDeps from Task 1) so future component tests can import `.svelte` files without further config. `environment: 'jsdom'` is required by `auto_lock.test.ts` which dispatches DOM events; the other suites would run under `node` but a single environment is simpler than per-file overrides. `globals: false` — tests `import { describe, it, expect } from 'vitest'` explicitly (no ambient globals). 20 LOC. |
| `eslint.config.js` — ESLint flat config | [`desktop/eslint.config.js`](../../desktop/eslint.config.js) | Flat config (`eslint.config.js`) rather than the plan's `.eslintrc.cjs` — ESLint 9+ drops legacy `.eslintrc.*` support. Uses the unified `typescript-eslint` v8 package rather than the split `@typescript-eslint/parser` + `@typescript-eslint/eslint-plugin` form (modern recommended layout). Browser + Node globals declared explicitly; `_`-prefixed args / vars are ignored (matches the underscore-prefix convention used by `_resetActivityTrackingForTest`). 32 LOC. |
| `package.json` — devDep additions + `typecheck` script | [`desktop/package.json`](../../desktop/package.json) | New devDeps: `@eslint/js@^9`, `eslint@^9`, `jsdom@^25`, `typescript-eslint@^8`. New script: `typecheck: "tsc --noEmit"` (the plan implied `pnpm tsc --noEmit` but didn't add it as a named script; adding it makes the gauntlet line a stable name rather than a pnpm-version-dependent invocation). Existing `vitest@^2`, `svelte-check@^4`, `typescript@^5`, `svelte@^5`, `vite@^6` unchanged. |
| `pnpm-lock.yaml` — locked transitive graph for the new devDeps | [`desktop/pnpm-lock.yaml`](../../desktop/pnpm-lock.yaml) | +241 packages on disk (mostly ESLint plugin tree and jsdom's parse5/whatwg-encoding dependencies). One deprecated subdep warning: `whatwg-encoding@3.1.1` — accepted, pulled in transitively by jsdom@25; replaced by whatwg-encoding@4 in jsdom@26+ which we'll get in a future bump. |

**Commits on `feature/d11-task-6`** (3 originals + 1 baton):

| SHA | Subject |
|---|---|
| `17680d6` | `chore(d11): Task 6 — Vitest harness + ESLint flat config + errors module` |
| `37cf26a` | `feat(d11): Task 6 — typed IPC wrappers + Svelte session stores` |
| `88fe1e5` | `feat(d11): Task 6 — debounced activity tracker (auto_lock.ts)` |
| TBD | `docs(d11): Task 6 handoff baton` |

Post-squash-merge SHA on `main` will differ.

### Gauntlet (live, performed)

```
Rust:           PASSED 1053 FAILED 0 IGNORED 10    # baseline unchanged — Task 6 is TS-only
cargo clippy --release --workspace --tests -- -D warnings   → clean
cargo fmt --all -- --check                                  → clean
uv run core/tests/python/conformance.py                     → PASS
uv run core/tests/python/spec_test_name_freshness.py        → PASS

Frontend:       Vitest 40 / 0 (3 files: errors=22, ipc=10, auto_lock=8)
pnpm typecheck                                              → clean
pnpm svelte-check                                           → 184 files, 0 errors, 0 warnings
pnpm lint                                                   → clean
```

Plan predicted **~12 Vitest tests** ("4 (errors) + 4 (ipc) + 4 (auto_lock)"); actual is **40** (errors=22, ipc=10, auto_lock=8). Surplus split:

- `errors.test.ts`: +18 over the plan's "4". The plan's sketch counted the `it.each(variants)` block as one test, but `it.each` generates one test per variant — 13 for `AppError` + 3 for `AppWarning` = 16 generated tests, plus 6 hand-written payload-surfacing pins. The result is **non-negotiable coverage of every wire-format variant**, which Tasks 7–10's components will rely on; under-counting was a plan-sketch slip, not a TDD principle to relax.
- `ipc.test.ts`: +6 over the plan's "4". The plan's sketch had 4 tests; the surplus comes from extending coverage from 1 happy-path command to all 7 (3 arg-shape tests cover `unlockWithPassword`, `setSettings`, and the argument-less `lock` / `notifyActivity` pair; 3 return-shape tests cover `listBlocks`, `getManifest`, `getSettings`), and from the error path (2 typed-error pins, 2 non-typed-wrap pins). The plan-implied "1 test per command" surface would have left e.g. `setSettings`'s argument-nesting (`{ settings: dto }` vs `dto` directly) unpinned — a regression there would be silent at the type checker.
- `auto_lock.test.ts`: +4 over the plan's "4". Added the `keydown` leading-edge pin (the plan only covered `mousemove`), an explicit trailing-edge debounce pin (`setTimeout`-scheduled notify fires when the window expires), a "cleanup cancels pending debounce timer" pin (a regression where cleanup forgets to `clearTimeout` would still emit one notify after unmount), and a "double-start tears down prior installation" pin (the source code documents this invariant; the test pins it).

Surplus tests are good news per the plan's prediction-tracking note: Task 7's Vitest baseline becomes **40 / 0** rather than **~12 / 0**, and the cumulative gauntlet baseline becomes **Rust 1053 / TS 40**.

### Plan execution trace (for the reviewer)

- Plan Steps 1–13 followed with adaptations called out in §(3); Step 6 (manual dev-tools smoke) is N/A for a Vitest-only task.
- Step 11 (frontend gauntlet) and Step 12 (combined gauntlet) executed; results above.
- File sizes (all comfortably under the 500-LOC CLAUDE.md threshold): errors.ts=124, ipc.ts=81, auto_lock.ts=84, stores.ts=29, errors.test.ts=95, ipc.test.ts=124, auto_lock.test.ts=92, vitest.config.ts=20, eslint.config.js=32.
- Per-module TDD discipline: the first commit lands the harness (Vitest config + ESLint config + devDeps) alongside the `errors` module + its tests so the suite is green from the very first commit; subsequent commits add `ipc + stores` then `auto_lock` with their tests, each compiling + passing independently — verified by running `pnpm test && pnpm typecheck && pnpm lint` after each commit before moving to the next.

## (2) What's next — D.1.1 Task 7 (Unlock route + PathPicker component)

Per the plan (Task 7 begins right after this Task 6 section in [`docs/superpowers/plans/2026-05-27-d11-tauri-walking-skeleton.md`](docs/superpowers/plans/2026-05-27-d11-tauri-walking-skeleton.md)), Task 7 lands the first user-visible Svelte components: the unlock route + a `PathPicker` component that wraps `@tauri-apps/plugin-dialog`'s folder picker.

**Files (per the plan):**

- Create: `desktop/src/routes/Unlock.svelte` — folder-picker + password field + "Unlock" button; on submit calls `ipc.unlockWithPassword(...)` and on success transitions `sessionState` to `unlocking → unlocked`.
- Create: `desktop/src/lib/components/PathPicker.svelte` — thin wrapper over the Tauri dialog plugin. Emits `change` with the selected path; the parent (`Unlock.svelte`) binds the path into the `sessionState.locked` view.
- Create: `desktop/src/lib/components/Toast.svelte` — listens to `autoLockNotice` store + `sessionState.lastError` and renders the `userMessageFor(err)` shape from `errors.ts`. (The plan threads this through Tasks 7–10; landing the file in Task 7 is the natural insertion point.)
- Create: `desktop/tests/Unlock.test.ts` — component-level Vitest test using `@testing-library/svelte` (new devDep) + mocked `ipc`.
- Modify: `desktop/src/App.svelte` — wire `sessionState` switch on `status`; render `<Unlock />` when locked, `<BlockList />` (Task 8) when unlocked.

**Acceptance criteria for Task 7 (from the plan + Task 6's outputs):**

- Gauntlet: Rust **1053 / 0 / 10** (unchanged), Vitest **40 + N** where N is the Task 7 component tests (plan-targeted: 4–6 covering the unlock submit happy path, wrong-password path, vault-path-not-found path, PathPicker emits-change, and Toast renders userMessageFor output).
- `pnpm tauri dev` smoke: app launches → unlock screen renders → folder picker opens → password field accepts input → submit either succeeds (transitions to BlockList, which is Task 8's placeholder until then) or shows the typed error toast.
- Type pin: the `Unlock.svelte` submit handler exhaustively narrows `AppError` (or relies on `userMessageFor`'s exhaustiveness check) — `tsc` rejects compile if a new Rust variant lands without a TS counterpart.
- ESLint: clean. svelte-check: 0 errors (it will now have something real to check, vs the 184-files-zero-errors baseline of Task 6).

**Open Task-7 questions** (worth thinking about during the worktree-add window):

1. **`@testing-library/svelte` vs `@vitest/browser` for component tests.** `@testing-library/svelte` is the de-facto choice for jsdom-mode component tests (matches the React Testing Library mental model); `@vitest/browser` would run the components in a real headless browser via Playwright. The plan defaults to (a) `@testing-library/svelte` (cheaper, fits the existing jsdom env, faster CI). (b) is more realistic but adds Playwright as a dep and changes the test-run shape from "pure Vitest" to "Vitest-with-browser-pool". Pick (a) unless something specific demands (b) — the e2e suite in Task 11 is where real-browser realism earns its keep.
2. **Toast component placement.** The plan threads the Toast through Tasks 7–10 without a single landing point. Landing it in Task 7 (where the first user-visible component appears that has an error path to surface) keeps the per-task surface coherent. Push back if the plan author intended Task 9 / 10.
3. **PathPicker — keyboard accessibility.** `@tauri-apps/plugin-dialog`'s `open({ directory: true })` returns a string path (no Tauri-side keyboard nav). The Svelte wrapper needs a keyboard-accessible button (not a div-with-onclick); make sure ESLint's `jsx-a11y`-equivalent for Svelte (svelte-eslint-plugin rules) catches this. If we don't pull in svelte-eslint-plugin in Task 7, the rule is on Task 11's e2e accessibility sweep.

**Estimate:** ~90–120 min (3 small Svelte components + 1 router wire-up + Vitest component tests + `@testing-library/svelte` dep + first svelte-eslint-plugin block).

## (3) Open decisions and risks

### Plan adaptations (worth flagging to the reviewer)

1. **ESLint flat config (`eslint.config.js`), not `.eslintrc.cjs`.** ESLint 9+ drops legacy `.eslintrc.*` config support; ESLint 10 removed it entirely. The plan's `.eslintrc.cjs` would have errored out at first invocation. Flat config is the future-proof shape (`eslint.config.js` is the standard filename), and the unified `typescript-eslint` v8 package (vs the split `@typescript-eslint/parser` + `@typescript-eslint/eslint-plugin`) is the recommended modern layout. Net effect: identical lint coverage with a config that won't bit-rot.
2. **`vi.hoisted` for mock-factory captures.** The plan's `tests/ipc.test.ts` sketch declared `const invokeMock = vi.fn()` at module scope and referenced it inside the `vi.mock(...)` factory closure. Vitest hoists `vi.mock` calls to the top of the file but their factory bodies run BEFORE module-scope `const` initializers — a temporal-dead-zone reference. `vi.hoisted(() => ({ invokeMock: vi.fn() }))` is the canonical fix (the hoisted block runs before the mock factory). Same pattern applied in `auto_lock.test.ts`. The plan author would have hit this on first run.
3. **`typecheck` npm script added.** Plan said `pnpm tsc --noEmit` (Step 11) but didn't surface it in `package.json`. Adding `"typecheck": "tsc --noEmit"` to scripts means the gauntlet line in §(4) is `pnpm typecheck` (a stable name) rather than `pnpm tsc --noEmit` (which silently picks up the wrong `tsc` if a future pnpm version changes binary-lookup semantics). Same `typecheck` script becomes the e2e-suite gate in Task 11.
4. **Vitest test count: 40 vs the plan's predicted "12".** Not a code adaptation — a plan-sketch slip on `it.each` counting (see Gauntlet section). The surplus is intentional coverage and stays.
5. **`@eslint/js` v9 (not v10).** `pnpm view eslint version` reports `10.4.0` is available, but pinning to `^9` keeps the typescript-eslint v8 surface within its officially-tested ESLint range. v10 jump deferred to a deliberate dep bump after typescript-eslint v9 lands.
6. **`.gitignore` exception for `desktop/src/lib/`.** The repo's `.gitignore` carries an unscoped `lib/` line (a Python distribution-packaging artefact from the original .gitignore template) which silently masked `desktop/src/lib/*.ts` — `git status` reported the directory missing, and an unguarded first commit would have left the four production modules out of the PR. Fixed by adding `!desktop/src/lib/` + `!desktop/src/lib/**` exception lines next to the original `lib/` rule with a comment explaining the relationship. The repo has no other `lib/` directory (verified by find) so the broader rule still acts as intended for any future Python tooling that creates one.

None of the adaptations change the plan's specified file contents materially; #1 + #5 are tooling-version reality, #2 + #3 are correctness fixes, #4 is a measurement note, #6 is a gitignore-collision fix that prevents a silent file-loss bug.

### Decisions settled

- **Pure modules: no DOM, no Svelte components, no I/O.** All four `src/lib/*.ts` files are import-only-from-stdlib-or-`./<peer>`. `auto_lock.ts` is the only one that touches `document`, and it does so behind the explicit `startActivityTracking()` entry point — no top-level side effects. This means: (a) Vitest can mock the peer modules cleanly via `vi.mock`; (b) Tasks 7–10 can refactor Svelte components without touching the pure layer.
- **`isAppError` type guard rather than `instanceof`.** Tauri rejections cross the IPC seam as plain JSON; there is no class to `instanceof`-check against. The shape check (`'code' in err && typeof err.code === 'string'`) is the structurally-correct discriminator and matches what the Rust side emits.
- **`environment: 'jsdom'` globally, not per-file.** Only `auto_lock.test.ts` needs the DOM (it dispatches `MouseEvent`); the others would run fine under `node`. Single env means one config file vs three `// @vitest-environment node` directives sprinkled at the top of test files. The jsdom startup overhead is ~200 ms total per Vitest run — negligible at this scale.
- **`MS_PER_SECOND` named constant.** `60_000 / 1_000 → 60` and `86_400_000 / 1_000 → 86_400` in the `userMessageFor` body use the explicit constant rather than a literal `1000`. Per the project's no-magic-numbers principle (`feedback_pure_functions` + project CLAUDE.md). A `MS_PER_HOUR` / `MS_PER_DAY` follow-up is unnecessary — those would belong in a future shared units module if more conversions appear.
- **`stores.ts` has no test.** It's purely declarative store wiring (no logic to pin). Component-level integration tests in Tasks 8–10 will exercise the subscriptions; a unit test that asserts `writable<X>({...}).subscribe((s) => ...)` would be testing Svelte's `writable`, not our code.

### Risks carried forward

- **`AppError` discriminator strings on the TS side and `#[serde(tag = "code")]` on the Rust side are coupled by hand.** Adding a Rust variant without a TS counterpart breaks the discriminated union exhaustiveness in `userMessageFor`, but adding the strings in the *wrong order* (e.g. a typo `kdf_to_weak` vs `kdf_too_weak`) would compile fine on both sides and only surface at runtime as a fall-through to the default branch — which TypeScript's exhaustive switch DOES catch (the type narrows to `never`), so the typo path is type-rejected. Net risk: the only way to slip a mismatch is a string typo where both Rust and TS make the same typo. Mitigation: the wire-format pins in `commands/lock.rs::tests` from Task 5 and the IPC integration tests in `tests/ipc_integration.rs` from Task 4 cover the Rust side; the TS-side discriminated union is its own check. Issue #139 (Rust `AppError` lacks `Deserialize`) blocks a fully-mechanical round-trip pin; revisit when #139 is addressed.
- **`@tauri-apps/api/core` module path is unmocked in production.** The `vi.mock('@tauri-apps/api/core', ...)` mock is per-test-file only. If a future test file imports `ipc.ts` without setting up the mock, the import will fail at module-load (no Tauri runtime in jsdom). Mitigation: only import `ipc.ts` from files that mock the module, or add a global setup file in Task 7 if more test files start importing it.
- **Carry-forward: password handling at the IPC boundary is not yet zeroize-typed** (Task 4 risk). Unchanged in Task 6. The TS side's `password: string` argument is also not zeroized — JS has no `Sensitive<T>` equivalent within reach. Will surface again in Task 7 (the Unlock component holds the password string in a Svelte `bind:value` until submit).
- **Carry-forward: `AppError::KdfTooWeak` still has no producer.** Unchanged.
- **Carry-forward: bridge `RecordInput.record_type` workaround** (issue #141). Unchanged.

### Issues currently open (carry-over)

- #37, #117, #120, #122, #123 — none affected by Task 6.
- #38, #45, #75, #76, #78, #79, #81, #87, #88, #90, #95, #98 — none affected.
- #139 — desktop: `AppError` lacks `Deserialize`. Surfaces again in Task 6 as the discriminated-union-by-hand risk above; still relevant.
- #140 — desktop: `parse_settings_field` text-only invariant. Status unchanged.
- #141 — bridge: `RecordInput` lacks `record_type` field. Status unchanged.
- #144 — desktop: Argon2id KDF runs under IPC mutex during unlock. Status unchanged; still deferred to D.1.4+.
- #145 — desktop: no recovery path for unlock-time settings warnings. Status unchanged; still deferred.

### Housekeeping (stale worktrees on disk)

Carry-over from prior batons. After this Task 6 PR merges, the freshly-shipped Task 5 worktree should be cleaned up too.

```bash
# From /Users/hherb/src/secretary, after the present (Task 6) PR merges:
git worktree remove .worktrees/c1-1b-sync-merge   && git branch -D feature/c1-1b-task-17
git worktree remove .worktrees/c2-task-1-spec     && git branch -D feature/c2-task-1-spec
for n in 1 2 3 4 5 6 7 8 9 10; do
  git worktree remove .worktrees/c2-task-$n       && git branch -D feature/c2-task-$n
done
git worktree remove .worktrees/d11-tauri-spec     && git branch -D feature/d11-tauri-spec
git worktree remove .worktrees/d11-task-3         && git branch -D feature/d11-task-3
git worktree remove .worktrees/d11-task-4         && git branch -D feature/d11-task-4
git worktree remove .worktrees/d11-task-5         && git branch -D feature/d11-task-5   # Task 5 PR #146 merged at 16721c5
# Keep .worktrees/d11-task-6 until this PR merges; remove after.
```

## (4) Exact commands to resume (Task 7)

```bash
# After this Task 6 PR (feature/d11-task-6) merges:
cd /Users/hherb/src/secretary
git fetch --prune origin
git status --short              # expect: clean
git checkout main
git pull --ff-only origin main

# Re-baseline the gauntlet on fresh main:
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
# Expect: PASSED: 1053 FAILED: 0 IGNORED: 10

# Frontend baseline on main (new from Task 6 onwards):
cd desktop
pnpm install                    # picks up the locked devDeps from this PR
pnpm test                       # expect: 40 passing
pnpm typecheck                  # clean
pnpm svelte-check               # 184 files, 0 errors
pnpm lint                       # clean
cd ..

# Set up the Task 7 worktree:
git worktree add .worktrees/d11-task-7 -b feature/d11-task-7 main
cd .worktrees/d11-task-7/desktop
pnpm install

# Open the plan and follow Task 7 step-by-step:
#   docs/superpowers/plans/2026-05-27-d11-tauri-walking-skeleton.md
# Search for "## Task 7:" — each step block is self-contained.

# After Unlock.svelte / PathPicker.svelte / Toast.svelte + Vitest component tests:
cd ..   # back to .worktrees/d11-task-7/
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py
cd desktop
pnpm test                       # expect 40 + Task-7 surplus
pnpm typecheck
pnpm svelte-check
pnpm lint
```

## Closing inventory

- **Branch state on close:** `main` at `16721c5` (D.1.1 Task 5 PR #146 merged earlier today). `feature/d11-task-6` carries 3 code commits on top (vitest harness + errors + eslint, ipc + stores, auto_lock) plus this baton commit.
- **Workspace tests on `feature/d11-task-6`:** Rust **1053 passed + 10 ignored** (unchanged — Task 6 is TS-only). Vitest **40 passed** (errors=22, ipc=10, auto_lock=8) — new gauntlet baseline.
- **README.md:** unchanged. Per the prior baton's standing pattern, per-task status flips on a sub-project in early implementation phase would be noise; the existing "D.1.1 walking skeleton ... in design" covers the implementation phase as a whole until D.1.1 ships end-to-end (Task 12).
- **ROADMAP.md:** unchanged. Same logic as README.
- **CLAUDE.md:** unchanged this session.
- **NEXT_SESSION.md:** symlink retargeted to this file.
- **`docs/adr/`:** unchanged.
- **`desktop/src/lib/`:** new `errors.ts`, `ipc.ts`, `stores.ts`, `auto_lock.ts` (≈318 LOC total).
- **`desktop/tests/`:** new `errors.test.ts`, `ipc.test.ts`, `auto_lock.test.ts` (≈311 LOC total).
- **`desktop/vitest.config.ts`:** new (20 LOC).
- **`desktop/eslint.config.js`:** new (32 LOC).
- **`desktop/package.json`:** +4 devDeps (`@eslint/js`, `eslint`, `jsdom`, `typescript-eslint`), +1 script (`typecheck`).
- **`desktop/pnpm-lock.yaml`:** +241 packages, mostly ESLint plugin tree and jsdom's parse5/whatwg-encoding subgraph.
- **`desktop/src-tauri/`:** untouched in Task 6 — frontend-only slice.
- **`desktop/src/` (Svelte components):** untouched — Task 7 lands the first components.
- **Open issues:** see §(3) — none closed with this PR; no new issues opened.
- **Open PRs:** one to be opened at end of this session (D.1.1 Task 6 — frontend pure modules + Vitest harness).
- **Worktrees on disk:** stale worktrees listed in §(3) can be cleaned up at any pause; `feature/d11-task-6` stays until merge.
- **This file:** the live baton for the Task 6 close. The next slice opens with `docs/handoffs/<date>-d11-task-7-shipped.md`.
