# NEXT_SESSION.md — D.1.1 Task 5 (auto-lock timer + `vault-locked` event) shipped

**Session date:** 2026-05-28 (continues immediately from the D.1.1 Task 4 session earlier the same day; Task 4 landed via PR #143 at `9217602` on `main`. This session spawns the OS-thread auto-lock timer that ticks every 5 s, calls the pure `timer::tick` body, and emits a Tauri `vault-locked` event with `{ "reason": "auto" }` when the configured idle threshold expires.)
**Status:** D.1.1 Task 5 authored on branch `feature/d11-task-5`; PR to be opened at end of session. Predecessors on `main`: D.1.1 spec + ADR 0007 (PR #130, `a5d85b9`), D.1.1 Task 1 scaffold (PR #131, `e329087`), D.1.1 Task 2 pure modules (PR #137, `a3ee9e9`), D.1.1 Task 3 VaultSession (PR #142, `6f984d4`), D.1.1 Task 4 IPC commands + DTOs (PR #143, `9217602`).

## (1) What we shipped this session

Adds the auto-lock timer subsystem. One new module ([`timer`](../../desktop/src-tauri/src/timer.rs)) carrying the pure tick body, plus a thread-spawning `setup` closure in `main.rs` that drives it on a fixed 5 s interval and emits the `vault-locked` Tauri event with `reason: "auto"` when the session passes its `auto_lock_timeout_ms` threshold.

| Artifact | Path | Notes |
|---|---|---|
| Timer module | [`desktop/src-tauri/src/timer.rs`](../../desktop/src-tauri/src/timer.rs) | `TickOutcome ∈ {NoAction, AutoLocked, Skipped}` + `pub fn tick(&Mutex<VaultSession>) -> TickOutcome`. Acquires the mutex via `try_lock` (non-blocking — a long-running IPC command never stalls the timer thread), reads the threshold from `session.current_settings().auto_lock_timeout_ms` inside the same critical section, calls `should_auto_lock(threshold_ms)`, locks the session if expired. **5 unit tests**: locked-session → NoAction, locked-session-unchanged after tick (idempotency), contended-mutex → Skipped, contended-tick-fast (`try_lock` rather than `lock` enforcement, ~50 ms wall clock), and an enum-distinct-variants sanity check. ~145 LOC, well under the 500 threshold. |
| Test helper on `VaultSession` | [`desktop/src-tauri/src/session.rs`](../../desktop/src-tauri/src/session.rs) | New `#[doc(hidden)] pub fn force_expire_idle_tracker_for_test(&mut self)` — rewinds `idle.last_activity_ms` to 0 so the next tick is guaranteed expired against any positive threshold. `#[doc(hidden)] pub` because `#[cfg(test)]` items don't reach integration tests (separate compilation unit; project-standard workaround documented in `project_secretary_cfg_test_not_propagated`). Strict `_for_test` suffix + doc-hidden flag keeps it out of rustdoc; production code never calls it. |
| Lock-event constant | [`desktop/src-tauri/src/commands/lock.rs`](../../desktop/src-tauri/src/commands/lock.rs) | New `pub const LOCK_REASON_AUTO: &str = "auto"` next to the existing `LOCK_REASON_EXPLICIT`. **4 new unit tests** pin the wire-format contract: `VAULT_LOCKED_EVENT` literal (`"vault-locked"`), both reason constants (`"explicit"` / `"auto"`), and the two `serde_json::json!` payloads as exact `to_string()` matches. Pinning the JSON shape here means the timer thread itself doesn't need its own wire-format assertion; a regression that pretty-prints by default or changes the field name surfaces in `cargo test`, not at Svelte runtime in Task 6. |
| Main wiring | [`desktop/src-tauri/src/main.rs`](../../desktop/src-tauri/src/main.rs) | `tauri::Builder::default().setup(...)` clones the `AppHandle`, spawns a named OS thread `"secretary-auto-lock-timer"` via `thread::Builder::new().name(...).spawn(...)` so it shows up in tooling. The new `fn auto_lock_timer_loop(app: AppHandle)` is a free function (TDD-friendly, top-down readable) that sleeps `AUTO_LOCK_TICK_MS` (5 s) per iteration, calls `tick(&app.state::<Mutex<VaultSession>>())`, and on `TickOutcome::AutoLocked` emits the `vault-locked` event with `{ "reason": "auto" }`. Emit errors are `tracing::error!`-logged (and only logged — the timer keeps running; a transient frontend disconnect mustn't kill the auto-lock). NoAction / Skipped are explicit match arms so a future refactor can't accidentally fall through. |
| Lib re-export | [`desktop/src-tauri/src/lib.rs`](../../desktop/src-tauri/src/lib.rs) | Added `pub mod timer;` so `main.rs` + integration tests can reach it. |
| Integration tests | [`desktop/src-tauri/tests/session_integration.rs`](../../desktop/src-tauri/tests/session_integration.rs) | **3 new tests** driving `tick` against a real unlocked golden-vault session: `timer_tick_auto_locks_expired_unlocked_session` (force-expire idle tracker + tick → `AutoLocked` + session.is_unlocked() == false), `timer_tick_no_action_on_unlocked_not_yet_expired` (fresh unlock + tick → `NoAction` + still unlocked), `timer_tick_reads_threshold_from_current_settings` (pins the design adaptation — `tick` reads `auto_lock_timeout_ms` from `current_settings()` inside the same lock acquisition; a regression to `threshold_ms = 0` would lock the fresh session and fail this test). Hermetic — each test injects its own `TempDir` for the device-UUID file. |

**Commits on `feature/d11-task-5`** (3 originals + 1 baton):

| SHA | Subject |
|---|---|
| TBD | `feat(d11): Task 5 — timer module + TickOutcome + tick() with unit tests` |
| TBD | `feat(d11): Task 5 — force-expire test helper + timer integration tests` |
| TBD | `feat(d11): Task 5 — LOCK_REASON_AUTO + auto-lock timer thread + lock.rs wire-format tests` |
| TBD | `docs(d11): Task 5 handoff baton` |

Post-squash-merge SHA on `main` will differ.

### Gauntlet (live, performed)

```
PASSED: 1053 FAILED: 0 IGNORED: 10        # baseline was 1041 / 0 / 10
cargo clippy --release --workspace --tests -- -D warnings   → clean
cargo fmt --all -- --check                                  → clean
uv run core/tests/python/conformance.py                     → PASS
uv run core/tests/python/spec_test_name_freshness.py        → PASS
```

Plan predicted **+5–7** tests (1041 → ~1046–48). Actual was **+12** (1053) — surplus split:

- `timer::tests`: +5 instead of the plan-implied +3. Added `locked_session_unchanged_by_tick` (idempotency pin — a regression where the locked-no-op path accidentally mutates state would slip the plan's 3-test surface), `contended_tick_does_not_block` (a 50 ms wall-clock budget on the contended path — guards against a future `lock()` regression that would block the timer thread forever if any IPC command hung), and `tick_outcome_distinct_variants` (cheap enum-distinctness check that catches a future "merge AutoLocked into NoAction" refactor at the assertion layer rather than at Task 6 wire-up).
- `commands::lock::tests`: +4 net-new (this module had no tests pre-Task-5). One test pins the kebab-case event name (`"vault-locked"` — Svelte's `listen('vault-locked', ...)` in Task 6 depends on this exact string), one pins both reason discriminator strings, and two pin the exact `serde_json::json!({...}).to_string()` output for `"explicit"` and `"auto"`. The last pair lifts the wire-format pin out of the timer thread so the runtime body doesn't need its own assertion.
- `tests/session_integration.rs`: +3 instead of the plan-implied +2. Added the `timer_tick_reads_threshold_from_current_settings` pin (see §(3) Plan adaptations) — proves that the design-adapted `tick` signature reads the threshold from settings rather than passing it as a parameter; without it, an "easier" refactor back to the plan's `tick(_, 0)` shape would be silent at compile time.

Per the plan's prediction-tracking note: surplus tests are good news; Task 6's gauntlet baseline becomes **1053 / 0 / 10** rather than **1048 / 0 / 10**.

### Plan execution trace (for the reviewer)

- Plan Steps 1–7 followed with adaptations called out in §(3); Step 6 (manual dev-tools smoke) deferred — the unit + integration suite covers the state machine + payload + idempotency; a manual `pnpm tauri dev` smoke is a Task 12 acceptance-sweep item rather than per-task work.
- Step 7 (full gauntlet) executed; result above.
- Commit + push + PR (analogue of Task 4's Step 12) executed at the end of this session.
- File sizes (all comfortably under the 500-LOC CLAUDE.md threshold): timer.rs ≈ 145 LOC, main.rs ≈ 117 LOC (up from 60), session.rs ≈ 250 LOC (+13 for helper), commands/lock.rs ≈ 137 LOC (+57 for constant + test module), tests/session_integration.rs ≈ 446 LOC (+117 for 3 new timer tests + module-import block).
- Per-module TDD discipline preserved: the timer commit carries its own unit tests (5); the helper-plus-integration commit carries the 3 integration tests that depend on it; the final wiring commit carries the lock.rs wire-format tests (4) alongside the constant + thread-spawn it pins. Each commit compiles + passes its own scope independently — verified by running `cargo test` after each commit.

## (2) What's next — D.1.1 Task 6 (frontend pure modules + Vitest harness)

Per the plan (Task 6 begins at line 3098 of [`docs/superpowers/plans/2026-05-27-d11-tauri-walking-skeleton.md`](docs/superpowers/plans/2026-05-27-d11-tauri-walking-skeleton.md)), Task 6 establishes the TypeScript layer that every Svelte component in Tasks 7–10 will import. All four modules are pure (no DOM, no Svelte components, no I/O) and Vitest-testable.

**Files (per the plan):**

- Create: `desktop/src/lib/ipc.ts` — typed wrappers over `@tauri-apps/api/core::invoke` for each of the 7 backend commands (`unlock_with_password`, `list_blocks`, `get_manifest`, `get_settings`, `set_settings`, `lock`, `notify_activity`).
- Create: `desktop/src/lib/stores.ts` — Svelte stores for app-level state (`isUnlocked`, `manifest`, `settings`, `error`, `warnings`).
- Create: `desktop/src/lib/errors.ts` — discriminated-union mirror of `AppError` + `AppWarning` (the Rust shape) + a `userMessageFor(err: AppError): UserMessage` translator that the Toast component will use. **Crucially: the discriminator strings (`vault_path_not_found`, `wrong_password`, etc.) must exactly match `AppError::tag = "code"` on the Rust side.**
- Create: `desktop/src/lib/auto_lock.ts` — debounced activity tracker (`notify_activity` IPC fire-rate-limited to `ACTIVITY_NOTIFY_MIN_INTERVAL_MS = 2 s` per Task 2's constant; pin the same constant in TS).
- Create: `desktop/tests/ipc.test.ts`, `desktop/tests/errors.test.ts`, `desktop/tests/auto_lock.test.ts`.
- Modify: `desktop/package.json` — add `vitest`, `jsdom`, `@vitest/ui`; add `test:unit` script.
- Create: `desktop/vitest.config.ts`.
- Create: `desktop/.eslintrc.cjs` — ESLint flat-config for the TS surface (the Rust gauntlet has had clippy from day one; the TS side needs its analogue).

**Acceptance criteria for Task 6 (from the plan + Task 5's outputs):**

- Gauntlet count goes from **1053 → ~1053 + N_Rust** (Vitest tests don't run through `cargo test`; the TS suite is its own command). Plan-targeted Vitest count: ~12–15 tests across `ipc.test.ts` (6), `errors.test.ts` (6 — one per `AppError` variant), `auto_lock.test.ts` (3).
- The TS `AppError` discriminator strings **must match** the Rust `#[serde(tag = "code")]` rename rules. Wire-format pin: the integration tests in `desktop/src-tauri/tests/ipc_integration.rs` (from Task 4) already validate the Rust side; Task 6 verifies the TS side independently and the two pins must agree.
- The TS event listener for `vault-locked` (added in Task 10's `App.svelte`, sketched in Task 6's stores) must consume both `{"reason": "explicit"}` and `{"reason": "auto"}` payloads — Task 5 pins both shapes on the Rust side.
- New gauntlet command: `pnpm --filter desktop test:unit` (or whatever name the plan settles on). Must be added to the project's gauntlet ritual.

**Open Task-6 questions** (worth thinking about during the worktree-add window):

1. **Vitest in the Rust gauntlet?** Currently the gauntlet is Rust-only (`cargo test` + `cargo clippy` + `cargo fmt` + `uv run` for conformance). Task 6 introduces a Vitest pass that needs to run with the same "always green" discipline. Options: (a) add a `pnpm --filter desktop test:unit` line to every gauntlet rehearsal in this baton (verbose but explicit); (b) wrap the gauntlet in a top-level script (`scripts/gauntlet.sh`?) — invasive and overdue; (c) defer until Task 11 / 12 when the e2e suite arrives. The plan defaults to (a); push back if `(b)` is the right shape for the long run.
2. **`AppError` deserializer in TS.** Issue #139 (Rust `AppError` lacks `Deserialize`) is the symmetric problem on the Rust side; Task 4's `ipc_integration.rs` works around it with `serde_json::Value`. Task 6 can either (a) hand-roll a TS discriminated-union parser, (b) generate it from the Rust source via a tiny build script, or (c) defer until Issue #139 is resolved and the Rust side can both serialize and deserialize `AppError`. (a) is the plan's default; the maintenance cost is one TS file kept in sync with one Rust enum.

**Estimate:** ~90–120 min (3–4 small TS modules + Vitest config + ESLint config). The novelty isn't the TS — it's wiring Vitest into the project's discipline.

## (3) Open decisions and risks

### Plan adaptations (worth flagging to the reviewer)

1. **`tick(&Mutex<VaultSession>)` rather than `tick(&Mutex<VaultSession>, threshold_ms)`.** The plan's sketch took the auto-lock threshold as an explicit parameter and left the threshold read to `main.rs`'s thread loop. That forced a choice between (a) acquiring the mutex twice per tick (racing if the user changes settings between the two acquisitions) or (b) inlining the tick body in `main.rs` and bypassing the pure module entirely. Task 5 chooses a third option: `tick` reads the threshold from `session.current_settings()` inside the same lock acquisition that calls `should_auto_lock`. The pure-function surface stays testable, and there's no race window. The baton's "Open Task-5 question" explicitly called this out and recommended Option (a) (single lock acquisition); this is that.
2. **`force_expire_idle_tracker_for_test` is `#[doc(hidden)] pub fn`, not `#[cfg(test)] pub fn`.** Integration tests are a separate compilation unit; `#[cfg(test)]` items on the lib are invisible to `tests/*.rs`. The project-standard workaround is `#[doc(hidden)] pub` with a `_for_test` suffix — documented in the saved memory and now used in `session.rs`. The plan offered both shapes; we went with the project-standard one.
3. **Wire-format tests landed in `commands/lock.rs::tests`, not `timer::tests`.** The plan's sketch had the timer thread emit the event directly with a literal `{"reason": "auto"}`. Task 5 lifts the literal into `LOCK_REASON_AUTO` (next to `LOCK_REASON_EXPLICIT`) and pins the JSON `to_string()` shape in `commands/lock.rs::tests` rather than in the timer module. Rationale: the timer thread itself is a runtime body in `main.rs` (not a pure function), so its wire-format assertion would be hard to reach without `tauri::test::mock_builder()`. Lifting the pin one layer down to `lock.rs` (where the constant lives) means the JSON shape is verified by `cargo test` without spinning up a Tauri runtime.
4. **Thread named `"secretary-auto-lock-timer"`.** The plan used a bare `thread::spawn(...)`. Using `thread::Builder::new().name(...).spawn(...)` adds the name to OS-level tooling (`top -H`, `ps -L`, debugger thread list, future tokio-console integration) at near-zero cost. The `.expect(...)` on `spawn` is appropriate: a Linux/macOS/Windows OS that refuses to create a thread at startup is a failure mode where degraded behaviour isn't useful.

None of the adaptations change the spec or the architectural decisions in ADR 0007. All four are encounters with reality that the plan author couldn't have predicted without the live attempt.

### Decisions settled

- **Auto-lock event payload uses `{ "reason": "auto" }`**, matching the `LOCK_REASON_EXPLICIT` / `LOCK_REASON_AUTO` constant pair in `commands/lock.rs`. The plan's draft used `{ "reason": "idle" }` in one spot — Task 5's choice mirrors the baton's stated convention and the lock.rs module doc-comment that already names the two reasons.
- **Timer thread lifecycle: no graceful join.** The thread sleeps on a fixed 5 s tick and the body is pure (no external resources to leak — the mutex is owned by the Tauri state manager, the `AppHandle` is reference-counted). Abrupt termination on process exit is fine for the D.1.1 walking skeleton. A graceful-shutdown channel becomes interesting if a future task adds resource-holding inside the tick body (network sync, file I/O); flag at that point.
- **Tick interval is the named constant `AUTO_LOCK_TICK_MS = 5_000`** (lives in `constants.rs`, sourced from Task 2). The `tick_interval = Duration::from_millis(AUTO_LOCK_TICK_MS)` is computed once before the loop so the per-iteration cost is just a `Duration::clone`.
- **Emit errors only logged, never panicked.** The timer thread keeps running on `app.emit(...)` failure. A transient frontend disconnect (e.g. dev tools window closed while the timer was about to fire) mustn't kill the auto-lock — the next tick will retry, and meanwhile the session is correctly locked on the backend. `tracing::error!` makes the failure observable in stderr without escalating.

### Risks carried forward

- **No mechanical test of the actual event emission.** The wire-format pin (4 tests in `lock.rs`) verifies the JSON `to_string()` shape; the timer's state-machine pin (3 integration tests) verifies `tick` returns `AutoLocked` and mutates the session. But the runtime body in `main::auto_lock_timer_loop` — `app.emit(VAULT_LOCKED_EVENT, ...)` — is not covered by `cargo test`. The only way to mechanically pin it would be a Tauri-runtime test via `tauri::test::mock_builder()`, which the project has explicitly opted out of (Task 4's plan note). Risk: a typo in the event name or a swapped reason key in the emit call site would compile, pass all tests, and only show as a missed toast in Task 7's manual smoke. **Mitigation:** the constants (`VAULT_LOCKED_EVENT`, `LOCK_REASON_AUTO`) used in the emit call are imported from `commands::lock`, so the wire-format pins in `lock.rs::tests` catch typos in the constants themselves; only typos in the `serde_json::json!({"reason": LOCK_REASON_AUTO})` macro shape (e.g. spelled "reasn") would slip through. Acceptable for D.1.1; revisit at Task 11 (e2e smoke).
- **Carry-forward: password handling at the IPC boundary is not yet zeroize-typed** (Task 4 risk). Unchanged in Task 5.
- **Carry-forward: `AppError::KdfTooWeak` still has no producer.** Unchanged.
- **Carry-forward: bridge `RecordInput.record_type` workaround** (issue #141). Unchanged.

### Issues currently open (carry-over)

- #37, #117, #120, #122, #123 — none affected by Task 5.
- #38, #45, #75, #76, #78, #79, #81, #87, #88, #90, #95, #98 — none affected.
- #139 — desktop: `AppError` lacks `Deserialize`. Status unchanged from Task 4: still relevant; will surface again in Task 6 when the TS side needs to round-trip error payloads.
- #140 — desktop: `parse_settings_field` text-only invariant. Status unchanged.
- #141 — bridge: `RecordInput` lacks `record_type` field. Status unchanged.
- #144 — desktop: Argon2id KDF runs under IPC mutex during unlock. Status unchanged; still deferred to D.1.4+.
- #145 — desktop: no recovery path for unlock-time settings warnings. Status unchanged; still deferred.

### Housekeeping (stale worktrees on disk)

Carry-over from prior batons. Remaining stale worktrees that can be removed at any pause:

```bash
# From /Users/hherb/src/secretary, after the present PR merges:
git worktree remove .worktrees/c1-1b-sync-merge   && git branch -D feature/c1-1b-task-17
git worktree remove .worktrees/c2-task-1-spec     && git branch -D feature/c2-task-1-spec
for n in 1 2 3 4 5 6 7 8 9 10; do
  git worktree remove .worktrees/c2-task-$n       && git branch -D feature/c2-task-$n
done
git worktree remove .worktrees/d11-tauri-spec     && git branch -D feature/d11-tauri-spec
git worktree remove .worktrees/d11-task-3         && git branch -D feature/d11-task-3
git worktree remove .worktrees/d11-task-4         && git branch -D feature/d11-task-4
# Keep .worktrees/d11-task-5 until this PR merges; remove after.
```

## (4) Exact commands to resume (Task 6)

```bash
# After this Task 5 PR (feature/d11-task-5) merges:
cd /Users/hherb/src/secretary
git fetch --prune origin
git status --short              # expect: clean
git checkout main
git pull --ff-only origin main

# Re-baseline the gauntlet on fresh main (expect 1053 / 0 / 10):
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'

# Set up the Task 6 worktree:
git worktree add .worktrees/d11-task-6 -b feature/d11-task-6 main
cd .worktrees/d11-task-6/desktop

# Open the plan and follow Task 6 step-by-step:
#   docs/superpowers/plans/2026-05-27-d11-tauri-walking-skeleton.md
# Search for "## Task 6:" (line ~3098). Each step block is self-contained.

# After ipc.ts / stores.ts / errors.ts / auto_lock.ts + Vitest tests:
cd ..   # back to .worktrees/d11-task-6/
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py

# NEW gauntlet step from Task 6 onwards (Vitest):
pnpm --dir desktop install
pnpm --dir desktop test:unit    # exact command name TBD by Task 6's package.json
```

## Closing inventory

- **Branch state on close:** `main` at `9217602` (D.1.1 Task 4 PR #143 merged earlier today). `feature/d11-task-5` carries 3 code commits on top (timer module + helper + integration tests + main wiring) plus this baton commit.
- **Workspace tests on `feature/d11-task-5`:** **1053 passed + 10 ignored** (+12 over the post-Task-4 baseline of 1041).
- **README.md:** unchanged. Per the prior baton's standing pattern, per-task status flips on a sub-project in early implementation phase would be noise; the existing "D.1.1 walking skeleton ... in design" covers the implementation phase as a whole until D.1.1 ships end-to-end (Task 12).
- **ROADMAP.md:** unchanged. Same logic as README.
- **CLAUDE.md:** unchanged this session.
- **NEXT_SESSION.md:** symlink retargeted to this file.
- **`docs/adr/`:** unchanged.
- **`desktop/src-tauri/src/`:** new `timer.rs` (≈145 LOC), `session.rs` gains the `force_expire_idle_tracker_for_test` helper (+13 LOC), `commands/lock.rs` gains `LOCK_REASON_AUTO` + a 4-test wire-format module (+57 LOC), `main.rs` expanded (+57 LOC: timer-thread spawn + `auto_lock_timer_loop`), `lib.rs` gains `pub mod timer;` (+1 LOC).
- **`desktop/src-tauri/tests/`:** `session_integration.rs` gains 3 timer integration tests + the `use secretary_desktop::timer::{tick, TickOutcome};` block (+117 LOC).
- **`desktop/src-tauri/Cargo.toml`:** unchanged this session.
- **`desktop/src/` (Svelte):** untouched in Task 5; Task 6 is the first slice that lands TS code.
- **Open issues:** see §(3) — none closed with this PR; no new issues opened.
- **Open PRs:** one to be opened at end of this session (D.1.1 Task 5 — auto-lock timer + `vault-locked` event).
- **Worktrees on disk:** stale worktrees listed in §(3) can be cleaned up at any pause; `feature/d11-task-5` stays until merge.
- **This file:** the live baton for the Task 5 close. The next slice opens with `docs/handoffs/<date>-d11-task-6-shipped.md`.
