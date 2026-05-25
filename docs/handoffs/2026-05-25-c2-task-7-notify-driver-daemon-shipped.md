# NEXT_SESSION.md — C.2 Task 7 (`notify_driver` + `daemon` loop) shipped

**Session date:** 2026-05-25 (C.2 Task 7 — `cli/src/watcher/notify_driver.rs` + `cli/src/daemon.rs`: the `notify::RecommendedWatcher` event source plus the closure-shaped daemon orchestration loop. Pure-orchestration core + production composition helper. No `main.rs` hook — that lands in Task 9 once signal handling (Task 8) is wired.). **Updated 2026-05-26** to absorb PR-review fixup pass (5 issues addressed in-place, 2 deferred to GitHub issues #122 + #123).
**Status:** C.2 Task 7 ✅ on branch `feature/c2-task-7`; PR pending. Tasks 8-10 queued.

## (1) What we shipped this session

One commit on `feature/c2-task-7` carrying the seventh code slice of C.2 — the `notify` integration plus the daemon event loop. Two new files under `cli/src/` (one under `cli/src/watcher/`, one at the crate root), plus the wiring lines in [`cli/src/watcher/mod.rs`](../../cli/src/watcher/mod.rs) and [`cli/src/lib.rs`](../../cli/src/lib.rs). The daemon is a single-threaded blocking loop per spec §D3 — no async runtime.

| Artifact | Path | Notes |
|---|---|---|
| Notify driver | [`cli/src/watcher/notify_driver.rs`](../../cli/src/watcher/notify_driver.rs) | New (~200 LOC). `NotifyWatcher::start(folder)` wraps `notify::RecommendedWatcher` + `std::sync::mpsc::Receiver`. `NotifyWatcher::poll(timeout) → Option<WatcherEvent>` blocks up to `timeout`, drains an in-channel burst on first relevant event, returns `Some(SyncCandidate)` or `None`. Pure `is_sync_relevant` predicate filters `EventKind::Access` (file reads — not a change) AND events whose paths all match the canonical partial-download table (spec §D6 partial-download gate at the watcher layer). 7 unit tests: 2 against a real watcher (smoke write surfaces SyncCandidate; quiet folder times out as None) + 5 against the predicate (Access filtered; Modify relevant; all-partial filtered; mixed partial+real relevant; pathless events relevant). |
| Daemon loop | [`cli/src/daemon.rs`](../../cli/src/daemon.rs) | New (~460 LOC including tests; ~210 LOC of code + ~250 LOC of tests). `run<P, S>(config, poll, on_sync)` is pure orchestration — `P: FnMut(Duration) -> Option<WatcherEvent>` is the event source, `S: FnMut()` is the sync action. Unit tests drive the loop with a `ScriptedPoller` (scripts events; sleeps the timeout when the slot is `None` so real wall-clock advances the deadlines) and a `SyncCounter` (records fires). `run_against_vault(...)` is the production composition helper: starts a `NotifyWatcher`, then calls `run` with closures that do `wait_for_ready` → `run_one` per fire. `compute_wait` is a pure free function picking the smallest of (remaining debounce window, remaining poll interval, shutdown poll interval). 15 unit tests: 5 for `compute_wait`, 8 for `run` (immediate-shutdown / shutdown-event / single-event / burst-collapse / separate-bursts / periodic-poll / mid-loop-flag-flip / polltick-ignored), 1 for `now_ms`, 1 for `notify_start_to_sync_error`. |
| Watcher submodule wiring | [`cli/src/watcher/mod.rs`](../../cli/src/watcher/mod.rs) | One-line addition (`pub mod notify_driver;`) next to the existing `debounce` and `ready` re-exports. The submodule's doc comment cross-reference to "Task 7" now resolves intra-crate. |
| Library surface wiring | [`cli/src/lib.rs`](../../cli/src/lib.rs) | One-line addition (`pub mod daemon;`) next to the existing `args`, `exit`, `pipeline`, `state`, `unlock`, `veto`, `watcher` re-exports. Production consumers reach the daemon under `secretary_cli::daemon::*`. |

**Commit:** `C.2 Task 7 — notify driver + daemon event loop` (see `git log feature/c2-task-7` for the local pre-merge SHA; the post-squash-merge SHA on `main` will differ). A follow-up review-fixup commit lands on the same branch (see §"Review fixup pass" below). 25 new tests across the two new modules after the fixup (7 notify_driver + 18 daemon); workspace 904 → 929. No issue closes with this commit; #37 (Sub-project C umbrella) advances by one more C.2 slice. Two follow-up issues filed: #122 (daemon.rs ~770 LOC — consider directory module split) and #123 (test timing-flake mitigation).

### Review fixup pass (2026-05-26)

Code review surfaced six observations on the initial commit; five were addressed in-place on `feature/c2-task-7` as a follow-up fixup commit, two filed as deferred GitHub issues. All five in-place fixes are self-contained, do not change the public API beyond the documented `DaemonConfig` additions, and ship with new unit tests where applicable.

| Review issue | Resolution | Where |
|---|---|---|
| `is_sync_relevant` — `paths.is_empty()` early return relies on vacuous-truth gotcha that a "simplifying" reader might fold away. | Added a four-line comment explaining the inverted vacuous-`all()` semantic and that the explicit early return must stay. | [`cli/src/watcher/notify_driver.rs`](../../cli/src/watcher/notify_driver.rs) `is_sync_relevant`. |
| `NotifyWatcher::poll` swallows `RecvTimeoutError::Disconnected` and `TryRecvError::Disconnected` silently — should be impossible (the `_watcher` sender stays alive) but if it ever fires, the daemon would stop receiving events with no signal. | Both Disconnected arms now emit `tracing::error!` before returning. Different message text per call site so the operator can tell which path tripped. | [`cli/src/watcher/notify_driver.rs`](../../cli/src/watcher/notify_driver.rs) `NotifyWatcher::poll`. |
| `SHUTDOWN_POLL_INTERVAL` was a module-private const; tests had to pay the full 1 s per loop iteration, which slowed `run_exits_when_shutdown_flag_flips_mid_loop` to ~2 s. Future signal-handler work might also want to tune it. | Renamed to `pub const DEFAULT_SHUTDOWN_POLL_INTERVAL` and added `DaemonConfig::shutdown_poll_interval: Duration` field. Tests override to `TEST_SHUTDOWN_INTERVAL = 200 ms` (constrained `≥ TEST_POLL_INTERVAL` so it never fragments scripted `None` slots). A `debug_assert!` in `run_against_vault` rejects zero to flag misconfiguration that would otherwise busy-spin the watcher. | [`cli/src/daemon.rs`](../../cli/src/daemon.rs) `DaemonConfig`, `run_against_vault`. |
| `run_against_vault`'s `wait_for_ready → Ok(false)` path logged at debug-only — a continuously-modified vault folder would silently never sync. | Added a saturating-counter `consecutive_not_ready: u32` captured in the `on_sync` closure; resets on `Ok(true)`. New `pub const READY_NOT_READY_WARN_THRESHOLD: u32 = 5` and a pure helper `note_not_ready_and_should_warn` extracted for unit-testability. A single `tracing::warn!` fires exactly once at the threshold and stays silent on subsequent skips until the next successful `Ok(true)` resets the counter. 3 new unit tests pin the fire-once-at-threshold + reset + u32::MAX-saturation semantics. | [`cli/src/daemon.rs`](../../cli/src/daemon.rs) `READY_NOT_READY_WARN_THRESHOLD`, `note_not_ready_and_should_warn`, `run_against_vault::on_sync`. |
| `daemon.rs` at 641 LOC was already over the 500-LOC threshold; the fixup pass adds another ~130 LOC, taking it to ~770. Splitting requires non-trivial restructure. | Filed as [#122](https://github.com/hherb/secretary/issues/122) for follow-up — directory-module candidate shape proposed but no immediate action. Inline-tests pattern matches the rest of the `cli/` crate, so the threshold is a soft signal rather than a blocker. | Tracked, not in-scope. |
| Behavioural daemon tests use 50–200 ms wall-clock windows — could flake under loaded CI runners. | Filed as [#123](https://github.com/hherb/secretary/issues/123) with the symptom signature + mitigation (bump constants 2–4×). No flake observed; speculative. | Tracked, not in-scope. |

Gauntlet on close-of-fixup: **PASSED: 929 FAILED: 0 IGNORED: 10**, clippy + fmt + conformance + spec-freshness all clean.

### Plan ↔ reality reconciliations

Three deliberate deviations from the plan, all validated up-front via a brainstorming question to the user before code went in (selected option: **"Redesign the loop"**):

| Plan note | Reality | Resolution |
|---|---|---|
| Plan code's daemon match had `DebounceDecision::AlreadyPending => continue,`. | That variant was removed in Task 6's PR-review fixup pass (see Task-6 handoff §"Plan-deviation"). The plan's arm would have produced a compile error. | Removed the dead arm. Daemon's match now covers only the two real variants (`Schedule`/`Reschedule`) and folds both into "update `debounce_pending`, no immediate fire". |
| Plan code's daemon did `std::thread::sleep(delay)` inside the `match decision { Schedule \| Reschedule => ... }` arm to wait the debounce window. | This blocks the loop for the full window (~500 ms by default), so (a) new events during the sleep can't extend the window, (b) `shutdown_flag` can't be checked, (c) the semantic degrades to **leading-edge-with-burst-coalescing**, contradicting Task 6's debounce module doc + its 5 unit tests that pin **trailing-edge** semantics. | Replaced the sleep with **`poll`'s own timeout as the debounce timer**. The loop computes `wait = min(remaining_debounce, remaining_poll, shutdown_poll_interval)` and calls `poll(wait)`. Returning before the deadline = new event → extend window; returning at the deadline (None) = window elapsed → top of next iteration sees `now - pending >= window` → fire. Exactly the trailing-edge semantic the debounce module documents. The redesign also let the daemon support cancellation latency ≤ `SHUTDOWN_POLL_INTERVAL` (1 s) regardless of debounce window length. |
| Plan code's daemon test was a compile-only stub that bound two unused values and returned without exercising the loop. | A compile-only test violates the project's "proper inline documentation and unit tests mandatory" principle. The handoff acceptance criterion also called for "one-event-end-to-end + shutdown-event-exits-cleanly + debounce-collapses-burst" tests. | Restructured the daemon to be **closure-shaped** (`run<P, S>` takes a poll closure + an on_sync closure) so unit tests can inject a `ScriptedPoller` + a `SyncCounter` without spinning up a real watcher or a real vault. Shipped 8 `run` behavioural tests covering all three handoff scenarios plus 5 corner cases (immediate-shutdown / mid-loop-flag-flip / periodic-poll-only / etc.). The production composition (`run_against_vault`) is the only thing that calls `wait_for_ready` + `run_one`, and its tests are deferred to Task 10's golden-vault-backed integration suite — the same split the plan calls out. |

Plan also said "Hook the `run` subcommand's stub in `cli/src/main.rs` to `daemon::run`" — deferred to Task 9 (subcommand dispatch wiring). `main.rs` still stubs through to `eprintln!("secretary-sync run: not yet implemented")` because the full wire-up requires `unlock` + `state::load` + `state::acquire_lockfile` orchestration that Task 9 is scoped to assemble. Without signal handling (Task 8) the daemon also can't be cleanly Ctrl-C'd from `main.rs`, so hooking it now would ship a non-Ctrl-C-stoppable binary. The handoff acceptance criterion was aspirational; the plan's literal Steps 1-3 don't include `main.rs` changes either. Task 8 + Task 9 together do the real wire-up.

The plan estimated 2 new tests (1 notify_driver smoke + 1 daemon compile-shape) for a workspace bump of 854 → 856. The 854 baseline was stale (drifted from the actual 904 in Task 6 close), and the 2-test estimate was tied to the now-rejected compile-only stub. Actual after the 2026-05-26 fixup pass: **25 new tests** (7 notify_driver + 18 daemon); workspace **904 → 929**.

### Gauntlet snapshot at session close

```
PASSED: 929 FAILED: 0 IGNORED: 10
clippy --release --workspace --tests -- -D warnings   clean
fmt --all -- --check                                  clean
uv run core/tests/python/conformance.py               PASS
uv run core/tests/python/spec_test_name_freshness.py  PASS (96 resolved / 0 unresolved / 2 suppressed)
```

Baseline 904 came from Task 6 close. Task 7 added 25 new tests (after the 2026-05-26 review-fixup pass):
- `watcher::notify_driver::tests::*` — 7 tests (5 predicate-level + 2 against a real `notify` watcher).
- `daemon::tests::*` — 18 tests (5 `compute_wait` pure-function + 8 `run` behavioural + 3 `note_not_ready_and_should_warn` semantic pins added in the fixup pass + 1 `now_ms` plausibility + 1 `notify_start_to_sync_error` mapping pin).

## (2) What's next — start C.2 Task 8

After this PR merges, the next slice is **C.2 Task 8: logging + signal handling (`cli/src/logging.rs` + `cli/src/signal.rs`)** ([`docs/superpowers/plans/2026-05-23-c2-headless-sync-cli.md`](../superpowers/plans/2026-05-23-c2-headless-sync-cli.md) §"Task 8").

### Acceptance criteria for Task 8

- [ ] New `cli/src/logging.rs` (~80–120 LOC): initialises `tracing-subscriber` with `EnvFilter` + human / json formats keyed off `CommonArgs::log_format` and `--verbose`. Pure init function plus a small builder; no global state beyond what `tracing-subscriber` itself owns.
- [ ] New `cli/src/signal.rs` (~60–100 LOC): exposes `install_shutdown_handler() -> Arc<AtomicBool>` using `signal-hook` (already in `cli/Cargo.toml`). Hooks SIGINT + SIGTERM; flips the flag the daemon already polls (`DaemonConfig::shutdown_flag`).
- [ ] New `cli/src/lib.rs` lines: `pub mod logging;` + `pub mod signal;` (Task 5 established the lib.rs pattern; Tasks 6 + 7 added `watcher` + `daemon`; Task 8 adds two more).
- [ ] Unit tests: logging — at minimum, EnvFilter parses from `--verbose=N` correctly; signal — register / un-register without leaking the handler, and the flag flips on a synthetic signal raise (test-only). The signal harness is the trickier bit because Rust's test runner already installs its own signal handlers; gate signal-handler tests behind `cfg(test)` + a one-test-at-a-time discipline (no `#[test(parallel = false)]` available, but `signal-hook` itself supports installing-and-uninstalling cleanly so tests can be careful).
- [ ] Gauntlet target: **PASSED: 929 + N FAILED: 0 IGNORED: 10**. Absolute base is now 929 (bumped from 904 by Task 7's 22 original new tests + 3 added in the 2026-05-26 fixup pass).
- [ ] Clippy, fmt, conformance, spec freshness all clean.

### Plan handoff

Full step-by-step in [`docs/superpowers/plans/2026-05-23-c2-headless-sync-cli.md`](../superpowers/plans/2026-05-23-c2-headless-sync-cli.md) §"Task 8". The plan's Task 8 bundles logging + signal as initialisation-time concerns. Both are small + small — keep each as a single file under the 500-LOC threshold.

## (3) Open decisions and risks

### Decisions settled during this session

- **`daemon::run` is closure-shaped (`P: FnMut(Duration) → Option<WatcherEvent>`, `S: FnMut()`), not trait-driven.** Pure functions in reusable modules per project preference. The closure shape lets tests inject a `ScriptedPoller` + a `SyncCounter` without `Box<dyn ...>` overhead or a `MockEventSource` struct, and lets the production composition (`run_against_vault`) inline the `NotifyWatcher::poll` and `wait_for_ready` + `run_one` calls without an indirection.
- **Trailing-edge debounce in the daemon honours Task 6's documented semantic.** The redesign uses `poll`'s timeout as the debounce timer; the previous plan's `std::thread::sleep` degraded to leading-edge-with-burst-coalescing and would have rendered Task 6's 5 trailing-edge unit tests semantically misleading.
- **`compute_wait` is a pure free function pulled out of the loop body.** Smallest-of three deadlines (remaining debounce, remaining poll interval, shutdown poll interval). Five pure unit tests pin it against drift — independently of the harder-to-test loop body.
- **`DEFAULT_SHUTDOWN_POLL_INTERVAL = 1 s` is the loop's default worst-case cancellation latency.** Balances operator-visible Ctrl-C responsiveness against per-iteration overhead. The flag is checked at every loop iteration, and `poll` blocks at most this long when nothing else (debounce / periodic poll) is closer. **Per-instance override** lives on `DaemonConfig::shutdown_poll_interval: Duration` (introduced by the 2026-05-26 fixup pass); tests set it to 200 ms so flag-flip assertions complete in well under a second. A `debug_assert!` in `run_against_vault` rejects zero to flag misconfiguration that would busy-spin the watcher.
- **`READY_NOT_READY_WARN_THRESHOLD = 5` consecutive `wait_for_ready → Ok(false)` returns trigger a single warn-level log.** Added by the 2026-05-26 fixup pass to surface stuck-folder conditions that would otherwise stay invisible at debug verbosity. The counter resets on the next `Ok(true)`, so a transient stable window followed by another stuck stretch re-fires the warn — one signal per stuck streak. The `note_not_ready_and_should_warn` helper is unit-tested in three places (fire-exactly-once-at-threshold, refire-after-reset, saturate-at-u32::MAX).
- **`is_sync_relevant` in `notify_driver` filters partial-download patterns at the watcher layer.** `*.icloud` / `*.crdownload` writes never cross into the debounce window. Pairs with Task 6's `ready::matches_partial_pattern` table — same canonical filename list, applied earlier in the pipeline. The handoff acceptance criterion called for "partial-download gate"; this is one half of it (the other half — folder-level size-stability via `wait_for_ready` — runs in `run_against_vault`'s `on_sync` closure).
- **`run_against_vault` calls `wait_for_ready(vault_folder, &RealClock, ready_window)` before each sync.** Treats the folder's metadata stability as a coarse-grained post-debounce safety check; on macOS / Linux the folder mtime changes with every contents change inside, so a still-changing folder yields `Ok(false)` and the sync is skipped that round. The default `ready_window` is 2000 ms (`RunArgs::ready_window_ms`), which adds latency to each sync attempt — acceptable for v1; if operator complaints surface, `--ready-window-ms 0` is the documented mitigation.
- **`WatcherEvent::PollTick` is never emitted by the production `NotifyWatcher`.** Only synthetic test event sources produce it. The periodic-poll path is driven by `compute_wait`'s `poll_interval` arm + the top-of-loop `last_poll_at` check, not by a notify-side event. The variant stays in the enum because tests use it to verify the `match` arm is wired correctly.
- **`SyncError::Vault(VaultError::Io { context: "notify watcher start failed", source: ... })` is the mapping for `NotifyWatcher::start` failure.** Pins the `context` value so the caller's exit-code mapper (Task 1) gets a deterministic surface to grep against. One unit test in `daemon::tests` pins this mapping.
- **`now_ms` saturates on overflow** (the year 584,556,000 ad infinitum is not the user's problem). Pinned by a unit test that floors at 2024-01-01 and ceilings at year 3000.
- **`main.rs` hook DEFERRED to Task 9.** Without signal handling (Task 8) the daemon can't be cleanly Ctrl-C'd; without `unlock` + `state::load` + `state::acquire_lockfile` orchestration (Task 9 composition), `daemon::run_against_vault` doesn't have its inputs. Shipping a `main.rs` hook in Task 7 would either duplicate Task 8's work or land a daemon that hangs forever on SIGINT.

### Decisions carried forward (unchanged from Task 6 close)

- D1-D10 from the spec are still settled.
- `--veto-policy=fail`, `--decisions-file`, `--exit-on-error`, `status`, `init` subcommands all deferred to future C.2.x slices.
- Windows is best-effort per D10 (no CI runner planned for C.2 implementation).
- Clean-room conformance harness for `cli/` deferred to C.4 or a future C.2.x slice.
- The `from_sync_error` mapper's exit-code surface (Task 1): every `SyncError` variant without a dedicated code maps to `GenericError = 1`; bijection-failure variants do NOT get distinct codes (CLI bugs, not operator-recoverable).
- fs4 dep retained over stdlib `File::try_lock` until workspace MSRV bumps past 1.89.
- `SecretBytes::new(buf)` over `SecretBytes::from(slice) + zeroize` for owned-buffer unlock paths (Task 3 — still in force).
- `TtyVetoUx` EOF latch + breadcrumb (Task 4) + safe-default `KeepLocal` on empty/error input + silent prompt-write failures: all in force.
- Pipeline contract (Task 5): `run_one` returns `Result<RunOutcome, SyncError>`; `RunOutcome` has 5 variants; state-mutation contract is documented + tested.
- Watcher pure pieces (Task 6): `WatcherEvent` is a 3-variant payload-less enum (`SyncCandidate` / `PollTick` / `ShutdownRequested`); `DebounceDecision` is 2 variants (`Schedule` / `Reschedule`), no `AlreadyPending`; `Clock` trait + `RealClock` live in `ready.rs`; `PARTIAL_BASENAMES` comparison is `eq_ignore_ascii_case`; `PARTIAL_SUFFIXES` lookup lowercases the basename; `PARTIAL_PREFIXES = [".~", "~$"]` only (no `"."`).

### Risks carried into Task 8

- **`signal-hook` ↔ Rust test runner interaction.** Rust's `#[test]` harness installs its own signal handlers (for `--test-threads=1` cancellation, etc.). Installing/uninstalling SIGINT/SIGTERM handlers inside a test must not leave the harness in a broken state. The Task 8 plan calls out using `signal-hook::flag::register` (which is non-replacing — it chains to any prior handler) and an RAII guard for cleanup. Tests will need to be careful about parallel execution; gating one signal test behind a `serial_test::serial` annotation (or equivalent) is the standard mitigation if `cargo test` parallelism turns out to interfere. The dep is already in `cli/Cargo.toml` as of Task 1.
- **`tracing-subscriber` global state.** `tracing-subscriber::registry()` and its `set_global_default` are process-global; calling them more than once panics. Tests that exercise the logging init must either run in isolation (subprocess per test) or hold a `OnceLock` guard so the second init is a no-op. The plan suggests a `try_init` helper that returns `Result<(), TryInitError>` so the production callsite can fail-fast at startup while tests tolerate "already initialised".

### Issues currently open

- #37 — Sub-project C umbrella. C.2 Tasks 1-6 ✅ in PRs #112, #114, #115, #116, #118, #119; Task 7 pending PR (#121).
- #117 — `TtyVetoUx` re-prompt loop has no max-attempts cap. Low-priority defensive-coding fix; still queued, not in scope for Task 8.
- #120 — `matches_partial_pattern` allocates per call via `to_ascii_lowercase`. Filed during PR #119 review; performance-only, no correctness or security impact. Pick up if a profiler ever flags it; not in scope for Task 8.
- **#122** — *new* — `cli/src/daemon.rs` at ~770 LOC (post-fixup) is over the 500-LOC threshold. Candidate directory-module shape captured in the issue. Pick up as a standalone cleanup PR or when Task 8/9 add more daemon code.
- **#123** — *new* — daemon behavioural tests use 50–200 ms wall-clock windows. Speculative CI-flake risk; mitigation (2–4× constant bump) documented. No observed flake yet.
- #38, #45, #75, #76, #78, #79, #81, #87, #88, #90, #95, #98 — none block C.2 Task 8.

### Housekeeping note (stale worktrees on disk)

After this PR:
- `/Users/hherb/src/secretary` — `main` (clean post-merge).
- `/Users/hherb/src/secretary/.worktrees/c1-1b-sync-merge` — branch `feature/c1-1b-task-17`, remote gone. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-1-spec` — branch `feature/c2-task-1-spec`, remote gone. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-1` — branch `feature/c2-task-1`, remote gone. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-2` — branch `feature/c2-task-2`, remote gone. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-3` — branch `feature/c2-task-3`, remote gone. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-4` — branch `feature/c2-task-4`, remote gone. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-5` — branch `feature/c2-task-5`, remote gone. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-6` — branch `feature/c2-task-6`, remote gone after #119 merged. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-7` — **this session's work**; keep until PR merges, then remove.

```bash
# One-line each (run from /Users/hherb/src/secretary):
git worktree remove .worktrees/c1-1b-sync-merge && git branch -D feature/c1-1b-task-17
git worktree remove .worktrees/c2-task-1-spec   && git branch -D feature/c2-task-1-spec
git worktree remove .worktrees/c2-task-1        && git branch -D feature/c2-task-1
git worktree remove .worktrees/c2-task-2        && git branch -D feature/c2-task-2
git worktree remove .worktrees/c2-task-3        && git branch -D feature/c2-task-3
git worktree remove .worktrees/c2-task-4        && git branch -D feature/c2-task-4
git worktree remove .worktrees/c2-task-5        && git branch -D feature/c2-task-5
git worktree remove .worktrees/c2-task-6        && git branch -D feature/c2-task-6
```

Cleanup is one-line each and does NOT block Task 8.

## (4) Exact commands to resume

```bash
# After this C.2 Task 7 PR (feature/c2-task-7) merges:
cd /Users/hherb/src/secretary
git fetch --prune origin
git status --short                       # expect: clean (modulo NEXT_SESSION.md sync, see below)
git checkout main
git pull --ff-only origin main

# Verify gauntlet on fresh main (expect 929 / 0 / 10 — same as session close after the 2026-05-26 fixup pass):
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3

# Start Task 8:
git worktree add .worktrees/c2-task-8 -b feature/c2-task-8 main
cd .worktrees/c2-task-8

# Open the plan and follow Task 8 line-by-line:
#   docs/superpowers/plans/2026-05-23-c2-headless-sync-cli.md §"Task 8"
# Task 8 ships two new files (cli/src/logging.rs + cli/src/signal.rs)
# plus the `pub mod logging;` + `pub mod signal;` lines in lib.rs.
# Signal hooks SIGINT + SIGTERM and returns an Arc<AtomicBool> the
# daemon already polls (DaemonConfig::shutdown_flag).
```

## Closing inventory

- **Branch state on close:** `main` at `132e15f` (PR #119 squash-merged). `feature/c2-task-7` carries one commit on top (Task 7 code + tests + handoff + symlink).
- **Workspace tests on `feature/c2-task-7`:** 929 passed + 10 ignored (904 base + 25 new tests: 7 in `watcher::notify_driver::tests` + 18 in `daemon::tests`, including the 3 added in the 2026-05-26 fixup pass). Clippy + fmt + Python conformance + spec freshness all clean.
- **README.md:** unchanged this session — Task 7 ships internal pure-function scaffolding (no operator-visible surface change yet). The C.2 status line in README still implies "queued"; promoting it to "in progress" is deferred until Task 9 wires the subcommands so `secretary-sync` actually runs.
- **ROADMAP.md:** unchanged this session — same reason; ROADMAP's progress bar still calls C.2 "queued". Bump deferred to Task 9 close.
- **CLAUDE.md:** unchanged this session — no new convention; daemon submodule is local to `cli/` and doesn't generalise to repo-wide guidance. (The "trailing-edge debounce" semantic was already captured in Task 6's `cli/src/watcher/debounce.rs` module-level doc.)
- **NEXT_SESSION.md:** symlink retargeted to this file.
- **Open issues:** see §(3) — none close with this PR; none block Task 8.
- **Open PRs:** one to be opened at end of this session (C.2 Task 7).
- **Worktrees on disk:** see §(3) housekeeping.
- **Frozen baton snapshots:** all 24 prior C.1.1b + C.2-design + C.2-task-1/2/3/4/5/6 handoffs at [`docs/handoffs/`](.) — preserved unchanged.
- **This file:** the live baton for C.2 Task 7 close.
