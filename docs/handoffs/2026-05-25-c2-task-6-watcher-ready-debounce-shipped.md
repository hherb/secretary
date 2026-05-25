# NEXT_SESSION.md — C.2 Task 6 (watcher submodule: ready + debounce) shipped

**Session date:** 2026-05-25 (C.2 Task 6 — `cli/src/watcher/{mod,ready,debounce}.rs`: pure-function pieces of the watcher submodule. No `notify` integration in this slice — that lands in Task 7 alongside the daemon loop).
**Status:** C.2 Task 6 ✅ on branch `feature/c2-task-6`; PR pending. Tasks 7-10 queued.

## (1) What we shipped this session

One commit on `feature/c2-task-6` carrying the sixth code slice of C.2 — the pure-function pieces of the file-watcher abstraction. Three new files under `cli/src/watcher/` plus the `pub mod watcher;` wiring in `cli/src/lib.rs`. No I/O orchestration beyond the thin [`wait_for_ready`] adapter (two `std::fs::metadata` reads with a [`Clock::sleep`] in between); no `notify::RecommendedWatcher` integration; no daemon loop. Those land in Task 7 once `notify` enters the pipeline.

| Artifact | Path | Notes |
|---|---|---|
| Watcher module | [`cli/src/watcher/mod.rs`](../../cli/src/watcher/mod.rs) | New (~60 LOC). Public `WatcherEvent` enum with three variants (`SyncCandidate`, `PollTick`, `ShutdownRequested`). Module-level doc explains the "pure pieces ship first, `notify` driver lands in Task 7" split. 3 unit tests pin variant distinctness + Debug shape + Clone round-trip. |
| Ready (partial-download + size-stability) | [`cli/src/watcher/ready.rs`](../../cli/src/watcher/ready.rs) | New (~290 LOC). Three pure-function constants (`PARTIAL_SUFFIXES`, `PARTIAL_PREFIXES`, `PARTIAL_BASENAMES`) implement spec §D6's canonical 10-row partial-marker table; `matches_partial_pattern` composes them. `is_size_stable` is a `(Metadata, Metadata)` predicate. `wait_for_ready<C: Clock>` is the thin I/O orchestrator; `Clock` trait + `RealClock` impl ship now so Task 7's `notify_driver` can wire production sleep without re-defining the abstraction. 18 unit tests cover one positive case per spec §D6 row + negative cases for vault filenames + size-stability `(stable, unstable)` + all four `wait_for_ready` branches (partial-marker reject / empty-file reject / stable-file accept / missing-file → `io::Error`). |
| Debounce (pure state machine) | [`cli/src/watcher/debounce.rs`](../../cli/src/watcher/debounce.rs) | New (~135 LOC). `DebounceDecision` enum (`Schedule` / `Reschedule`); `step(now, pending_since, window) -> (decision, new_pending_since)` is the entire state machine. Trailing-edge semantics: each event in-window resets the deadline; the daemon loop fires `SyncCandidate` when the deadline expires uninterrupted. 5 unit tests cover first-event / within-window-burst / past-window-reset / equal-to-window-boundary / three-event-burst-collapse. |
| Library surface wiring | [`cli/src/lib.rs`](../../cli/src/lib.rs) | One-line addition: `pub mod watcher;` next to the existing `args`, `exit`, `pipeline`, `state`, `unlock`, `veto` re-exports. Production consumers reach the watcher under `secretary_cli::watcher::*`. |

**Commit:** `C.2 Task 6 — watcher submodule: partial-download ready + pure debounce` (see `git log feature/c2-task-6` for the local pre-merge SHA; the post-squash-merge SHA on `main` will differ). 27 new tests across watcher's three submodules (3 mod + 19 ready + 5 debounce); workspace 877 → 904. The 19th ready test (`wait_for_ready_errors_when_file_disappears_between_stats`) was added in the PR-review fixup pass to pin the second-`stat()` failure branch. No issue closes with this commit; #37 (Sub-project C umbrella) advances by one more C.2 slice; #120 is a follow-up filed during the same review (low-priority allocation cleanup in `matches_partial_pattern`).

### Plan ↔ reality reconciliations

Two deliberate deviations from the plan, each documented inline in code comments + commit body:

| Plan note | Reality | Resolution |
|---|---|---|
| Plan declared `DebounceDecision::AlreadyPending` as a third enum variant alongside `Schedule` + `Reschedule`. | The plan's `step` function never constructs `AlreadyPending` — every code path returns either `Schedule` (no pending / past window) or `Reschedule` (within window). The variant would be dead code on day one and trip `clippy -D warnings`. | Removed `AlreadyPending` from the enum. Documented the two-variant state machine as **trailing-edge debounce** in `debounce.rs`'s module doc. If a future driver wants a "cap-collapse drop" semantic (cap the total wait time at N windows instead of resetting indefinitely), it'd be a behavioural change requiring its own design — not a leftover variant. Aligns with [[feedback_act_on_issues_dont_mention]] (don't ship dead code) + the recently-closed #113 (cli crate compiles `-D warnings` with zero `#[allow(dead_code)]`). |
| Plan code's `PARTIAL_PREFIXES` constant declared `[".~", "~$", "."]` but the function body only checked `.~` and `~$` explicitly — the `.` entry was unused. | A literal `.` prefix would also catch ordinary dotfiles (e.g., a contributor accidentally dropping a `.gitignore` into the vault folder would be silently filtered as "partial"). | Reduced the constant to `[".~", "~$"]` and iterated over it in the function body, so the constant is genuinely used (no dead-data warnings) and the semantics match what the spec §D6 table covers. `.DS_Store` is still caught by the `PARTIAL_BASENAMES` whole-name check. |

The plan also estimated 17 new tests (12 ready + 4 debounce + 1 module sanity). Actual at first push: **26 new tests** (3 mod sanity + 18 ready + 5 debounce). The extras came from one positive case per spec §D6 row (the plan compressed `.crdownload` and `.download` into one test; spec §D6 distinguishes Chromium vs Safari/Firefox so I split them), plus a dedicated test for the Dropbox `.~foo.tmp` route (which the plan claims is "caught by both `.~` and `.tmp`" — pinning that with an explicit test), plus a missing-file → `io::Error` test (required by the acceptance criteria's "missing-file branch" but absent from the plan code), plus a `burst_of_three_events_collapses_into_single_reschedule_chain` test (the plan's burst-collapse only had two events). The PR-review fixup pass added a 19th `ready` test (`wait_for_ready_errors_when_file_disappears_between_stats`) and folded two case-insensitive `.ICLOUD` assertions into the existing `icloud_partial_marker_caught` row, bringing the total to **27 new tests** (3 + 19 + 5).

### Gauntlet snapshot at session close

```
PASSED: 904 FAILED: 0 IGNORED: 10
clippy --release --workspace --tests -- -D warnings   clean
fmt --all -- --check                                  clean
uv run core/tests/python/conformance.py               PASS
uv run core/tests/python/spec_test_name_freshness.py  PASS (96 resolved / 0 unresolved / 2 suppressed)
```

(Baseline drift note: the prior baton recorded 868 at Task 5 close. A clean-main checkout from `90334ce` actually shows 877 — the 9-test delta is likely from doctest binaries or `--no-fail-fast` aggregation that the baton's quick `awk` didn't fully account for. Task 6 itself adds 27 new tests (3 + 19 + 5); the post-Task-6 total is 877 + 27 = 904, consistent with the gauntlet output. Future batons should treat 904 as the new baseline.)

## (2) What's next — start C.2 Task 7

After this PR merges, the next slice is **C.2 Task 7: `notify` driver + daemon loop (`cli/src/watcher/notify_driver.rs` + `cli/src/daemon.rs`)** ([`docs/superpowers/plans/2026-05-23-c2-headless-sync-cli.md`](../superpowers/plans/2026-05-23-c2-headless-sync-cli.md) §"Task 7").

### Acceptance criteria for Task 7

- [ ] New `cli/src/watcher/notify_driver.rs` (~150–200 LOC): wraps `notify::RecommendedWatcher` + `std::sync::mpsc::Receiver<notify::Event>`. Maps platform events into `super::WatcherEvent`. Exposes `recv_with_timeout(Duration) -> Option<WatcherEvent>` for the daemon loop. Single-threaded blocking; no async runtime per spec §D3.
- [ ] New `cli/src/daemon.rs` (~150–220 LOC): the `run` subcommand's main loop. Composes `notify_driver` (event source) + `watcher::debounce::step` (burst collapse) + `watcher::ready::wait_for_ready` (partial-download gate) + `pipeline::run_one` (one sync attempt) + the existing `state` / `unlock` / `veto` modules. Signal handling (SIGINT / SIGTERM) is deferred to Task 8 — Task 7 still exits cleanly on `WatcherEvent::ShutdownRequested` (synthetic for tests).
- [ ] New `cli/src/lib.rs` line: `pub mod daemon;` (Task 5 established the `lib.rs` pattern; Task 6 added `watcher`; Task 7 adds `daemon`).
- [ ] Hook the `run` subcommand's stub in `cli/src/main.rs` to `daemon::run`. (`once` subcommand still stubs through to Task 9's dispatch wiring; Task 7 is daemon-only.)
- [ ] Unit tests for `notify_driver` cover the platform-event → `WatcherEvent` mapping (using `notify`'s synthetic event constructors); daemon-loop tests cover at least: one-event-end-to-end (synthetic mpsc event → `pipeline::run_one` invoked → state advanced) + shutdown-event-exits-cleanly + debounce-collapses-burst (two synthetic events within the window produce exactly one sync attempt).
- [ ] Gauntlet target: **PASSED: 904 + N FAILED: 0 IGNORED: 10**. Absolute base is now 904 (bumped from 877 by Task 6's 27 new tests).
- [ ] Clippy, fmt, conformance, spec freshness all clean.

### Plan handoff

Full step-by-step in [`docs/superpowers/plans/2026-05-23-c2-headless-sync-cli.md`](../superpowers/plans/2026-05-23-c2-headless-sync-cli.md) §"Task 7". The plan's Task 7 has both `notify_driver` and `daemon` in one slice (they're each incomplete without the other). Daemon-loop file is the densest at ~220 LOC; keep one concept per file (event mapping in `notify_driver`, loop composition in `daemon`).

## (3) Open decisions and risks

### Decisions settled during this session

- **`WatcherEvent` is a flat 3-variant enum, no payload.** Variants are mutually exclusive — exactly one delivered per driver tick. No `SyncCandidate(Vec<PathBuf>)` form because the daemon doesn't act per-file — it re-runs the full `sync_once` against the vault folder on every wake. Per-file context lives in `notify`'s logs (Task 8's `tracing` integration).
- **Trailing-edge debounce, not leading-edge.** Each new event resets the window; the daemon fires after a full quiet window. Reasoning in the `debounce.rs` module doc. If a future operator complains about long-burst latency (e.g., a 5-minute editor save-burst pushing 5 minutes of "no sync"), the fix is either a `--max-debounce-ms` cap (a third variant + new constant) or shorter window; not a different state machine.
- **`Clock` trait shipped in `ready.rs`, not in a separate `time.rs` module.** It's tightly coupled to `wait_for_ready` (the only caller in this slice) and the trait is two methods, one line. Promoting it to its own module would invert the dependency for no clarity gain. Task 7's `notify_driver` can `use crate::watcher::ready::{Clock, RealClock};` without surprise.
- **`is_size_stable` returns `false` if `modified()` errors on either snapshot.** Conservative — treat unknown mtime as "still possibly changing". On Linux / macOS / Windows the platform always reports mtime, so this branch is paranoid (defensive coding for the docstring's case-analysis completeness).
- **`PARTIAL_BASENAMES` comparison is case-insensitive (`eq_ignore_ascii_case`).** Windows is case-preserving but case-insensitive at lookup time, and macOS volumes can be either. Spec §D6 doesn't normalise casing; the implementation does, so `desktop.ini` and `DESKTOP.INI` both get caught. Test `dotted_metadata_caught` pins both.
- **`PARTIAL_SUFFIXES` lookup also lowercases the basename.** Same rationale — `.iCloud` (someone uppercased the extension) still gets caught.
- **Plan-deviation: `DebounceDecision` has only 2 variants, not 3.** See §(1) reconciliation table. Plan's `AlreadyPending` was never constructed by `step`; removing it is the same hygiene we just closed #113 on (no `#[allow(dead_code)]` in `cli/`).
- **Plan-deviation: `PARTIAL_PREFIXES` lost the `"."` entry.** See §(1). The `.` prefix would catch ordinary dotfiles silently; the spec §D6 row "`.~lock.*`" only requires `.~` (which we kept).
- **`tempfile = "=3.27.0"` exact-pin retained in `cli/dev-dependencies`** — no new dependency added by Task 6. The plan's test code uses tempfile features already in scope (`NamedTempFile` + `tempdir`).

### Decisions carried forward (unchanged from Task 5 close)

- D1-D10 from the spec are still settled.
- `--veto-policy=fail`, `--decisions-file`, `--exit-on-error`, `status`, `init` subcommands all deferred to future C.2.x slices.
- Windows is best-effort per D10 (no CI runner planned for C.2 implementation).
- Clean-room conformance harness for `cli/` deferred to C.4 or a future C.2.x slice.
- The `from_sync_error` mapper's exit-code surface (Task 1): every `SyncError` variant without a dedicated code maps to `GenericError = 1`; bijection-failure variants do NOT get distinct codes (CLI bugs, not operator-recoverable).
- fs4 dep retained over stdlib `File::try_lock` until workspace MSRV bumps past 1.89.
- `SecretBytes::new(buf)` over `SecretBytes::from(slice) + zeroize` for owned-buffer unlock paths (Task 3 — still in force).
- `TtyVetoUx` EOF latch + breadcrumb (Task 4) + safe-default `KeepLocal` on empty/error input + silent prompt-write failures: all in force.
- Pipeline contract (Task 5): `run_one` returns `Result<RunOutcome, SyncError>`; `RunOutcome` has 5 variants (`NothingToDo`, `AppliedAutomatically`, `MergedAndCommitted { vetoes_resolved }`, `SilentMerge`, `RollbackRejected`); state-mutation contract is documented + tested. Library + binary hybrid (`secretary_cli` lib, `secretary-sync` bin) is the integration-test pattern.

### Risks carried into Task 7

- **`notify::RecommendedWatcher` platform quirks first appear in Task 7.** Task 6's pure-function pieces (pattern matcher + size-stability + debounce) run identically on Linux / macOS / Windows because they're string + struct + Instant arithmetic. Task 7 wires the actual platform watcher; macOS FSEvents coalescing, Linux inotify single-event-per-file, and Windows ReadDirectoryChangesW all surface here. A `cli/tests/notify_quirk.rs` test is planned for Task 10 to pin the quirks that survive into the daemon loop; Task 7 itself uses `notify`'s synthetic-event constructors so tests don't depend on the real backend.
- **Debounce semantics under wall-clock skew (NTP step, sleep/wake).** `Instant::now()` is monotonic on all three platforms — NTP adjustments don't move it backwards. Sleep-wake is also monotonic-safe (the OS clock keeps advancing through suspension on macOS / Linux; Windows pauses but doesn't regress). So `duration_since` is safe. If a future platform somehow returned a non-monotonic `Instant`, the `>=` boundary in `step` would still produce defensible behaviour (always Schedule, never panic).
- **Trailing-edge debounce under prolonged save-bursts.** If an editor saves every N ms for K seconds where K > debounce window, the sync attempt won't fire until K + window elapses. This is by design (sync runs against a quiet vault, not a half-written one), but if the operator-observed latency becomes complaint-worthy, the mitigation is a `--max-debounce-ms` cap. Track as a future C.2.x slice if needed; not in scope for Task 7.

### Issues currently open

- #37 — Sub-project C umbrella. C.2 Tasks 1-5 ✅ in PRs #112, #114, #115, #116, #118; Task 6 pending PR.
- #117 — `TtyVetoUx` re-prompt loop has no max-attempts cap. Low-priority defensive-coding fix; still queued, not in scope for Task 7.
- #120 — `matches_partial_pattern` allocates per call via `to_ascii_lowercase`. Filed during PR #119 review; performance-only, no correctness or security impact. Pick up if a profiler ever flags it; not in scope for Task 7.
- #38, #45, #75, #76, #78, #79, #81, #87, #88, #90, #95, #98 — none block C.2 Task 7.

### Housekeeping note (stale worktrees on disk)

After this PR:
- `/Users/hherb/src/secretary` — `main` (clean post-merge).
- `/Users/hherb/src/secretary/.worktrees/c1-1b-sync-merge` — branch `feature/c1-1b-task-17`, remote gone. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-1-spec` — branch `feature/c2-task-1-spec`, remote gone. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-1` — branch `feature/c2-task-1`, remote gone. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-2` — branch `feature/c2-task-2`, remote gone. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-3` — branch `feature/c2-task-3`, remote gone. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-4` — branch `feature/c2-task-4`, remote gone. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-5` — branch `feature/c2-task-5`, remote gone after #118 merged. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-6` — **this session's work**; keep until PR merges, then remove.

```bash
# One-line each (run from /Users/hherb/src/secretary):
git worktree remove .worktrees/c1-1b-sync-merge && git branch -D feature/c1-1b-task-17
git worktree remove .worktrees/c2-task-1-spec   && git branch -D feature/c2-task-1-spec
git worktree remove .worktrees/c2-task-1        && git branch -D feature/c2-task-1
git worktree remove .worktrees/c2-task-2        && git branch -D feature/c2-task-2
git worktree remove .worktrees/c2-task-3        && git branch -D feature/c2-task-3
git worktree remove .worktrees/c2-task-4        && git branch -D feature/c2-task-4
git worktree remove .worktrees/c2-task-5        && git branch -D feature/c2-task-5
```

Cleanup is one-line each and does NOT block Task 7.

## (4) Exact commands to resume

```bash
# After this C.2 Task 6 PR (feature/c2-task-6) merges:
cd /Users/hherb/src/secretary
git fetch --prune origin
git status --short                       # expect: clean (modulo NEXT_SESSION.md sync, see below)
git checkout main
git pull --ff-only origin main

# Verify gauntlet on fresh main (expect 904 / 0 / 10 — same as session close):
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3

# Start Task 7:
git worktree add .worktrees/c2-task-7 -b feature/c2-task-7 main
cd .worktrees/c2-task-7

# Open the plan and follow Task 7 line-by-line:
#   docs/superpowers/plans/2026-05-23-c2-headless-sync-cli.md §"Task 7"
# Task 7 ships two new files (cli/src/watcher/notify_driver.rs +
# cli/src/daemon.rs) plus the `pub mod daemon;` line in lib.rs.
# Both files compose Task 6's pure pieces with notify's mpsc channel
# and the existing pipeline::run_one to make the `run` subcommand
# actually run. Signal handling deferred to Task 8.
```

## Closing inventory

- **Branch state on close:** `main` at `90334ce` (PR #118 squash-merged). `feature/c2-task-6` carries 2 commits on top (Task 6 code + tests + handoff + symlink, then a PR-review fixup that tightened a docstring, added `Copy` to `WatcherEvent`, documented `PARTIAL_PREFIXES` case-folding rationale, and added one ready-module test for the second-`stat()` failure path). Both fold into a single squash-merge at ship time.
- **Workspace tests on `feature/c2-task-6`:** 904 passed + 10 ignored (877 base + 27 new watcher tests: 3 in `watcher::tests` + 19 in `watcher::ready::tests` + 5 in `watcher::debounce::tests`). Clippy + fmt + Python conformance + spec freshness all clean.
- **README.md:** unchanged this session — Task 6 ships internal pure-function scaffolding (no operator-visible surface change). The C.2 status line in README still reads "queued"; promoting it to "in progress" is deferred until Task 9 wires the subcommands so `secretary-sync` actually runs.
- **ROADMAP.md:** unchanged this session — same reason; ROADMAP already calls C.2 "queued" since the C.2 design PR.
- **CLAUDE.md:** unchanged this session — no new convention; watcher submodule is local to `cli/` and doesn't generalise to repo-wide guidance.
- **NEXT_SESSION.md:** symlink retargeted to this file.
- **Open issues:** see §(3) — none close with this PR; none block Task 7.
- **Open PRs:** one to be opened at end of this session (C.2 Task 6).
- **Worktrees on disk:** see §(3) housekeeping.
- **Frozen baton snapshots:** all 23 prior C.1.1b + C.2-design + C.2-task-1/2/3/4/5 handoffs at [`docs/handoffs/`](.) — preserved unchanged.
- **This file:** the live baton for C.2 Task 6 close.
