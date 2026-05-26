# NEXT_SESSION.md — C.2 Task 8 (`logging` + `signal`) shipped

**Session date:** 2026-05-26 (C.2 Task 8 — `cli/src/logging.rs` + `cli/src/signal.rs`: tracing-subscriber init with a verbosity ladder, plus a SIGINT/SIGTERM → `Arc<AtomicBool>` shutdown-flag installer with an RAII guard for clean teardown. Both modules are init-time concerns consumed by `main.rs` (Task 9). No `main.rs` hook here — Task 9 wires the full dispatch.).
**Status:** C.2 Task 8 ✅ on branch `feature/c2-task-8`; PR pending. Tasks 9–10 queued.

## (1) What we shipped this session

One commit on `feature/c2-task-8` carrying the eighth code slice of C.2 — the logging and signal-handling supporting modules. Two new files under `cli/src/` plus the wiring lines in [`cli/src/lib.rs`](../../cli/src/lib.rs) and a one-section change in [`cli/Cargo.toml`](../../cli/Cargo.toml) to gate `signal-hook` under `[target.'cfg(unix)'.dependencies]`.

| Artifact | Path | Notes |
|---|---|---|
| Logging | [`cli/src/logging.rs`](../../cli/src/logging.rs) | New (~150 LOC). Two-layer design so the verbosity-ladder logic is unit-testable without touching process-global state: `resolve_directive(verbose: u8) -> &'static str` is the pure mapper (`0 → info/warn`, `1 → debug/info`, `≥2 → debug/debug`), `try_init(verbose, format)` is the side-effectful production entry point that builds the `EnvFilter` (honouring `RUST_LOG` if set), then installs the global subscriber via `fmt::SubscriberBuilder::try_init`. Returns `Result<&'static str, TryInitError>` — the boxed error from upstream — so a second-init failure is non-panicking. 8 unit tests covering the three rung values, saturation past `-vv`, and `EnvFilter::try_new` parseability of each directive constant. |
| Signal handling | [`cli/src/signal.rs`](../../cli/src/signal.rs) | New (~250 LOC including tests). `install_shutdown_handlers() -> io::Result<ShutdownGuard>` wraps `signal_hook::flag::register` for `DEFAULT_SHUTDOWN_SIGNALS` (SIGINT + SIGTERM on Unix; empty on non-Unix). `install_shutdown_handlers_for(&[i32])` is the test-facing surface (also re-used by `install_shutdown_handlers` itself). `ShutdownGuard` owns the `Vec<SigId>` and unregisters on drop. `registered_count() -> usize` exposes a test-friendly invariant probe without leaking the internal `SigId` collection. 6 unit tests under `#[cfg(all(test, unix))]` (empty-set / default-set / drop-unregisters / signal-raises-flag / flag-stays-set / signal-order-pin) all guarded by a `Mutex<()>` so the kernel signal table stays deterministic under parallel `cargo test`. The drop test uses two guards on `SIGUSR1` and verifies that raising the signal flips only the second guard's flag — a safety net because `SIGUSR1`'s default disposition is "terminate", so raising it with no active handler would kill the test runner. |
| Library surface wiring | [`cli/src/lib.rs`](../../cli/src/lib.rs) | Two-line addition (`pub mod logging;` + `pub mod signal;`) keeping the alphabetical order. Production consumers reach the modules under `secretary_cli::logging::*` and `secretary_cli::signal::*`. |
| Cargo manifest | [`cli/Cargo.toml`](../../cli/Cargo.toml) | Moved `signal-hook = "0.3"` from `[dependencies]` to `[target.'cfg(unix)'.dependencies]` per spec §D10 and CLAUDE.md `feedback_windows_not_primary`. The `thiserror = "2"` line moved one position to keep the deps block coherent. |

**Commit:** `C.2 Task 8 — logging + signal handling` (see `git log feature/c2-task-8` for the local pre-merge SHA; the post-squash-merge SHA on `main` will differ). 14 new tests across the two new modules (8 logging + 6 signal); workspace **929 → 943**. No issue closes with this commit; #37 (Sub-project C umbrella) advances by one more C.2 slice.

### Plan ↔ reality reconciliations

Three deliberate deviations from the plan, all driven by the project's "proper inline documentation and unit tests mandatory" principle plus the handoff §"Risks carried into Task 8" callouts:

| Plan note | Reality | Resolution |
|---|---|---|
| Plan's `logging.rs` had a single unit test that pinned the directive constant strings (`assert_eq!(DEFAULT_FILTER, "secretary_sync=info,secretary_core=warn")`). | A constant-equality assertion does not validate behaviour — it would still pass if the directive was syntactically broken. The Task-7 handoff §"Risks carried into Task 8" called out `tracing_subscriber` global-state friction and recommended a `try_init` helper; the natural pairing is to split the verbosity-ladder logic out as a pure function and test the directive parseability. | Split the module into a pure `resolve_directive(u8) -> &'static str` plus a side-effectful `try_init(u8, LogFormat) -> Result<_, TryInitError>`. Shipped 8 unit tests: 4 over `resolve_directive` (each rung + saturation), 3 over `EnvFilter::try_new` parseability of each directive constant, 1 distinctness assertion catching the copy-paste regression where two rungs accidentally resolve to the same string. |
| Plan's `signal.rs` had zero unit tests. | The handoff §"Acceptance criteria" called out "signal — register / un-register without leaking the handler, and the flag flips on a synthetic signal raise (test-only)". A module with no tests would violate the project's "proper inline documentation and unit tests mandatory" principle. | Added a `ShutdownGuard` RAII type with `registered_count()` as a public probe so tests can assert installation invariants without breaching encapsulation, plus `install_shutdown_handlers_for(&[i32])` as a test-facing surface accepting an arbitrary signal set. 6 unit tests gated under `#[cfg(all(test, unix))]` and serialised with a `Mutex<()>` (process-global signal-disposition table). Tests register on `SIGUSR1` rather than SIGINT/SIGTERM so they don't race with the Rust test harness's own signal handling. |
| Plan's `try_init` used `tracing_subscriber::util::TryInitError`. | That type is for layered subscribers (`registry().with(layer).try_init()`); the plan's `fmt().with_env_filter(filter).try_init()` path uses the `fmt::SubscriberBuilder` inherent `try_init`, which returns `Result<(), Box<dyn Error + Send + Sync>>`. The plan's code does not compile. | Aliased `pub type TryInitError = Box<dyn std::error::Error + Send + Sync + 'static>;` to match the upstream return shape verbatim. Surfacing the upstream error string ("a global default trace dispatcher has already been set") is more useful to operators than a custom-wrapped variant. |

The plan estimated 1 new test for a workspace bump of 856→857. The 856 baseline was stale (drifted from the actual 929 at Task 7 close), and the 1-test estimate was tied to the now-rejected constant-equality test. Actual: **14 new tests** (8 logging + 6 signal); workspace **929 → 943**.

### Gauntlet snapshot at session close

```
PASSED: 943 FAILED: 0 IGNORED: 10
clippy --release --workspace --tests -- -D warnings   clean
fmt --all -- --check                                  clean
uv run core/tests/python/conformance.py               PASS
uv run core/tests/python/spec_test_name_freshness.py  PASS (96 resolved / 0 unresolved / 2 suppressed)
```

Baseline 929 came from Task 7 close. Task 8 added 14 new tests:
- `logging::tests::*` — 8 tests (4 `resolve_directive` rungs + 3 `EnvFilter::try_new` parseability + 1 distinctness pin).
- `signal::tests::*` — 6 tests gated `#[cfg(all(test, unix))]` (empty-set guard / default-set count / drop-unregisters / raised-signal-flips-flag / flag-stays-set / SIGINT-then-SIGTERM order pin).

## (2) What's next — start C.2 Task 9

After this PR merges, the next slice is **C.2 Task 9: wire `main.rs` end-to-end + `once` integration tests** ([`docs/superpowers/plans/2026-05-23-c2-headless-sync-cli.md`](../superpowers/plans/2026-05-23-c2-headless-sync-cli.md) §"Task 9"). This is the task that turns the library pieces into a working binary.

### Acceptance criteria for Task 9

- [ ] `cli/src/main.rs` rewrite (~140 LOC): parse args via `clap::Parser`, install logging via `logging::try_init`, install signal handlers via `signal::install_shutdown_handlers`, read password via `unlock::*`, open vault via `core::unlock::open_with_password`, resolve state dir + acquire lockfile via `state::*`, dispatch to either `pipeline::run_one` (for `once`) or `daemon::run_against_vault` (for `run`). Map `SyncError` to `ExitCode`. Drop the `--non-interactive without --password-stdin` early reject (already covered by `args::CommonArgs::validate`).
- [ ] New `cli/tests/once_integration.rs` (~620 LOC est., per the plan's File Structure table): `assert_cmd`-driven end-to-end tests covering the `once` subcommand against a temp-copy of `core/tests/data/golden_vault_001/`. Plan estimates ~16 tests covering: happy path (no remote changes), happy path with concurrent detection auto-merge, lockfile contention (two-instance race), `--password-stdin` from a piped Reader, `--non-interactive` without stdin (UsageError exit 2), missing vault folder (GenericError exit 1), invalid password (GenericError exit 1), `--state-dir` override path, and the veto cases (`KeepLocal` / `AcceptTombstone` decisions both routed through `AutoKeepLocalVetoUx`).
- [ ] Gauntlet target: **PASSED: 943 + N FAILED: 0 IGNORED: 10**. Absolute base is now 943.
- [ ] Clippy, fmt, conformance, spec freshness all clean.
- [ ] The Task-9 PR is also the first one where `secretary-sync once <folder>` actually runs end-to-end on a real vault. Manually smoke-test against `core/tests/data/golden_vault_001/` from the worktree before pushing.

### Plan handoff

Full step-by-step in [`docs/superpowers/plans/2026-05-23-c2-headless-sync-cli.md`](../superpowers/plans/2026-05-23-c2-headless-sync-cli.md) §"Task 9". The plan's Task 9 has the longest scope of any C.2 slice — bundle `main.rs` dispatch + integration tests + the manual smoke-test, but each subtask is small and independent. Use the plan's exact `main.rs` skeleton as the starting point; the constants (`MANIFEST_FILENAME`, `VAULT_TOML_FILENAME`, `IDENTITY_BUNDLE_FILENAME`) are already named.

## (3) Open decisions and risks

### Decisions settled during this session

- **`resolve_directive` is a pure free function returning `&'static str`.** No allocation, no env read, no global state. Fully unit-testable. Saturates at `-vv` (count ≥ 2) — no `trace` ladder rung in v1; pinned by `resolve_directive_saturates_at_double_verbose` against `u8::MAX`.
- **`try_init` returns the upstream's boxed error verbatim, aliased as `TryInitError`.** A typed wrapper would inflate the surface for a failure mode that operators see exactly once at startup (already-installed). The upstream error string is more useful than a custom variant.
- **`fmt::SubscriberBuilder::try_init` chosen over `SubscriberInitExt::try_init`.** The latter is for layered subscribers (`registry().with(layer).try_init()`); the simple `fmt().with_env_filter(...).try_init()` path uses the inherent method and returns `Box<dyn Error>`. The plan's import of `tracing_subscriber::util::TryInitError` produced a compile error; the fix was the type alias above.
- **`RUST_LOG` overrides the directive when set.** `EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(directive))` — the operator can always force a different filter without recompiling. The handoff baton mentions this as a `try_init` semantic.
- **`ShutdownGuard` is RAII; drop unregisters every installed handler.** `signal_hook::low_level::unregister` is called for each `SigId` on drop. The Drop impl is `#[cfg(unix)]`-gated; on non-Unix the guard is a no-op container.
- **`install_shutdown_handlers_for(signals: &[i32])` is the parametric core; the no-arg variant just calls it with `DEFAULT_SHUTDOWN_SIGNALS`.** Tests exercise the parametric form against `SIGUSR1` — a signal the test harness doesn't use, so the `Mutex<()>` lock is enough to serialise tests within a binary. Avoids the "raising SIGINT in a test runner that already handles SIGINT" race.
- **`DEFAULT_SHUTDOWN_SIGNALS` is `[SIGINT, SIGTERM]` on Unix and `[]` on non-Unix.** The empty-on-non-Unix branch lets call sites iterate without `cfg`-gating their own code. `install_shutdown_handlers_for(&[])` is a smoke-test surface; production calls the no-arg variant.
- **`signal-hook` gated under `[target.'cfg(unix)'.dependencies]`.** Per spec §D10 + `feedback_windows_not_primary`. Non-Unix builds get a `tracing::warn!` at install time and a permanently-false flag. Operators on non-Unix terminate via Task Manager.
- **Tests use `signal_hook::low_level::raise(SIGUSR1)` rather than `libc::raise`.** No new `libc` dep; the `signal-hook` crate is already in deps under `cfg(unix)`. The `raise` call is synchronous on Unix — the handler runs before `raise` returns — but the polling loop with a 500 ms timeout / 5 ms interval is a defensive belt-and-braces for CI loaded runners.
- **`SIGNAL_TEST_LOCK: Mutex<()>` serialises every signal test.** The kernel signal-disposition table is process-global; parallel tests without the lock can observe partially-installed state (e.g. install → register → another test runs in parallel and reads the table before the second register completes). The handoff §"Risks carried into Task 8" called this out explicitly.
- **`drop_unregisters_handlers` uses two `SIGUSR1` guards.** Raising `SIGUSR1` with no installed handler triggers the default disposition (terminate) — and the first version of this test did exactly that and killed the test binary on signal 30 (macOS's SIGUSR1). The fix: install guard A on SIGUSR1, save a clone of its flag, drop guard A, install guard B on SIGUSR1, raise the signal, then assert only guard B's flag flipped. Guard B's active registration is the safety net that keeps the test runner alive.

### Decisions carried forward (unchanged from Task 7 close)

- D1–D10 from the spec are still settled.
- `--veto-policy=fail`, `--decisions-file`, `--exit-on-error`, `status`, `init` subcommands all deferred to future C.2.x slices.
- Windows is best-effort per D10 (no CI runner planned for C.2 implementation; non-Unix signal stub returns a permanently-false flag).
- Clean-room conformance harness for `cli/` deferred to C.4 or a future C.2.x slice.
- The `from_sync_error` mapper's exit-code surface (Task 1): every `SyncError` variant without a dedicated code maps to `GenericError = 1`; bijection-failure variants do NOT get distinct codes (CLI bugs, not operator-recoverable).
- fs4 dep retained over stdlib `File::try_lock` until workspace MSRV bumps past 1.89.
- `SecretBytes::new(buf)` over `SecretBytes::from(slice) + zeroize` for owned-buffer unlock paths (Task 3 — still in force).
- `TtyVetoUx` EOF latch + breadcrumb (Task 4) + safe-default `KeepLocal` on empty/error input + silent prompt-write failures: all in force.
- Pipeline contract (Task 5): `run_one` returns `Result<RunOutcome, SyncError>`; `RunOutcome` has 5 variants; state-mutation contract is documented + tested.
- Watcher pure pieces (Task 6): `WatcherEvent` is a 3-variant payload-less enum; `DebounceDecision` is 2 variants, no `AlreadyPending`; `Clock` trait + `RealClock` live in `ready.rs`; partial-pattern matchers `eq_ignore_ascii_case`-compare.
- Daemon shape (Task 7): closure-shaped `run<P, S>(config, poll, on_sync)`; `compute_wait` pure; `DEFAULT_SHUTDOWN_POLL_INTERVAL = 1 s`; `READY_NOT_READY_WARN_THRESHOLD = 5`; `WatcherEvent::PollTick` test-only; `now_ms` saturates on overflow; `main.rs` hook deferred to Task 9.

### Risks carried into Task 9

- **`tracing_subscriber` global-state interaction with integration tests.** `assert_cmd` spawns the binary as a subprocess — each invocation gets its own process, so `try_init`'s "already installed" failure mode never trips. The risk is purely intra-test (running `try_init` twice in the same `cargo test` binary), and Task 8 sidesteps it by exercising only the pure `resolve_directive` surface. Task 9's integration tests are subprocess-based so the issue does not recur.
- **Signal handlers + `assert_cmd` flow.** When Task 9's integration tests run `secretary-sync once <folder>` via `Command::cargo_bin("secretary-sync")`, the spawned process installs its own signal handlers via `signal::install_shutdown_handlers`. Those handlers do NOT interfere with the parent test runner — they're a different process. No lock needed across tests.
- **Lockfile contention in two-instance integration test (Task 9 / Task 10).** When the test spawns two `secretary-sync once` instances against the same vault folder, the second one must hit `ExitCode::LockfileHeld` (= exit 3). Task 2's `LockfileGuard::acquire` already routes through `fs4::FileExt::try_lock`, so the contention path is already covered at the unit-test layer — Task 9 just composes them.
- **`once` integration test golden vault setup.** Each test must copy `core/tests/data/golden_vault_001/` to a `tempfile::TempDir` because the test mutates the manifest. The copy must be done with `std::fs::copy` rather than `std::fs::create_dir_all + write` to preserve mtimes (though `wait_for_ready` doesn't run in `once` mode, so this is a defensive note for any future `run`-mode integration test).
- **`secretary-sync run` smoke test (deferred to Task 10).** The `run` subcommand's daemon loop cannot be killed via `assert_cmd::Command` because the test won't wait beyond a configurable timeout. Task 10 (two-instance convergence) will spawn `run` with a short-lived `tokio::process::Child` and explicitly send SIGTERM after a quiescence window. Not Task 9's scope.

### Issues currently open

- #37 — Sub-project C umbrella. C.2 Tasks 1–7 ✅ in PRs #112, #114, #115, #116, #118, #119, #121. Task 8 pending PR.
- #117 — `TtyVetoUx` re-prompt loop has no max-attempts cap. Low-priority defensive-coding fix; still queued, not in scope for Task 9.
- #120 — `matches_partial_pattern` allocates per call via `to_ascii_lowercase`. Filed during PR #119 review; performance-only, no correctness or security impact. Pick up if a profiler ever flags it.
- #122 — `cli/src/daemon.rs` at ~770 LOC is over the 500-LOC threshold. Filed by Task 7 fixup pass; candidate directory-module shape captured. Pick up as a standalone cleanup PR or when Task 9 adds more daemon code.
- #123 — daemon behavioural tests use 50–200 ms wall-clock windows. Filed by Task 7 fixup pass; speculative CI-flake risk. No observed flake yet.
- #38, #45, #75, #76, #78, #79, #81, #87, #88, #90, #95, #98 — none block C.2 Task 9.

### Housekeeping note (stale worktrees on disk)

After this PR:
- `/Users/hherb/src/secretary` — `main` (clean post-merge).
- `/Users/hherb/src/secretary/.worktrees/c1-1b-sync-merge` — branch `feature/c1-1b-task-17`, remote gone. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-1-spec` — branch `feature/c2-task-1-spec`, remote gone. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-{1..7}` — branches `feature/c2-task-{1..7}`, remote gone after each PR merged. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-8` — **this session's work**; keep until PR merges, then remove.

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
git worktree remove .worktrees/c2-task-7        && git branch -D feature/c2-task-7
```

Cleanup is one-line each and does NOT block Task 9.

## (4) Exact commands to resume

```bash
# After this C.2 Task 8 PR (feature/c2-task-8) merges:
cd /Users/hherb/src/secretary
git fetch --prune origin
git status --short                       # expect: clean (modulo NEXT_SESSION.md sync, see below)
git checkout main
git pull --ff-only origin main

# Verify gauntlet on fresh main (expect 943 / 0 / 10 — same as session close):
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3

# Start Task 9:
git worktree add .worktrees/c2-task-9 -b feature/c2-task-9 main
cd .worktrees/c2-task-9

# Open the plan and follow Task 9 line-by-line:
#   docs/superpowers/plans/2026-05-23-c2-headless-sync-cli.md §"Task 9"
# Task 9 rewrites cli/src/main.rs (~140 LOC) and adds cli/tests/once_integration.rs (~620 LOC).
# Task 9 is the first task where `secretary-sync once <folder>` actually runs end-to-end —
# smoke-test against core/tests/data/golden_vault_001/ before pushing.
```

## Closing inventory

- **Branch state on close:** `main` at `ee680e7` (post-Task-7 fixup pass on `main`). `feature/c2-task-8` carries one commit on top (Task 8 code + tests + handoff + symlink).
- **Workspace tests on `feature/c2-task-8`:** 943 passed + 10 ignored (929 base + 14 new tests: 8 in `logging::tests` + 6 in `signal::tests`). Clippy + fmt + Python conformance + spec freshness all clean.
- **README.md:** unchanged this session — Task 8 ships internal supporting modules with no operator-visible surface change. The C.2 progress line in README still describes C.1.1b as the latest delivered milestone; promoting it to "C.2 ✅" is deferred until Task 10.
- **ROADMAP.md:** to be bumped in a follow-up commit after the Task 8 PR opens — the "C.2 Tasks 1–7/10 ✅" → "1–8/10 ✅" line + the per-task PR list need the actual Task 8 PR number, which isn't allocated until `gh pr create` returns.
- **CLAUDE.md:** unchanged this session — no new convention; logging + signal are local to `cli/` and don't generalise to repo-wide guidance.
- **NEXT_SESSION.md:** symlink retargeted to this file.
- **Open issues:** see §(3) — none close with this PR; none block Task 9.
- **Open PRs:** one to be opened at end of this session (C.2 Task 8).
- **Worktrees on disk:** see §(3) housekeeping.
- **Frozen baton snapshots:** all 25 prior C.1.1b + C.2-design + C.2-task-1/2/3/4/5/6/7 handoffs at [`docs/handoffs/`](.) — preserved unchanged.
- **This file:** the live baton for C.2 Task 8 close.
