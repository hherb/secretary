# NEXT_SESSION.md — C.2 Task 9 (`main.rs` dispatch + `once` integration) shipped

**Session date:** 2026-05-26 (C.2 Task 9 — `cli/src/main.rs` rewritten from a 41-LOC stub into a 240-LOC dispatch front-end that wires args validation, logging init, password sourcing, vault unlock, state load, lockfile acquire, and pipeline / daemon dispatch into a working binary. New `cli/tests/once_integration.rs` exercises the full binary end-to-end via `assert_cmd` against `core/tests/data/golden_vault_001/`. Incidental fix: `logging::try_init` now writes to stderr instead of stdout (the `tracing-subscriber::fmt()` default).).
**Status:** C.2 Task 9 ✅ on branch `feature/c2-task-9`; PR pending. Task 10 queued.

## (1) What we shipped this session

One commit on `feature/c2-task-9` carrying the ninth code slice of C.2 — the first task that produces a binary that runs end-to-end against a real vault. The plan's headline ask is `main.rs` + `cli/tests/once_integration.rs`; the actual work also touches two adjacent files (a stderr-fix in `cli/src/logging.rs` and two test updates in `cli/tests/main_validate.rs`) for reasons captured in the "Plan ↔ reality reconciliations" table below.

| Artifact | Path | Notes |
|---|---|---|
| Main dispatch | [`cli/src/main.rs`](../../cli/src/main.rs) | Rewrite (41 → 240 LOC). `main()` parses args + maps the inner `run(Cli) -> ExitCode` to a `process::ExitCode`. `run()` is the early-exit ladder: validation (eprintln + UsageError before logging init), logging init (`try_init` failure is a non-fatal warning), password read (`--password-stdin` or TTY via `unlock::*`), `vault.toml` + `identity.bundle.enc` read, `open_with_password` unlock, `parse_vault_uuid` re-derive (the `UnlockedIdentity` struct does NOT surface `vault_uuid`; it carries the IBK + identity bundle, which is the secret material), state-dir resolution (`--state-dir` → `dirs::data_dir()` → `.` fallback), state load, lockfile acquire, dispatch to `once` or `run` subcommand, post-run `state::save`. Five named constants (`VAULT_TOML_FILENAME`, `IDENTITY_BUNDLE_FILENAME`, `STATE_DIR_FALLBACK`) + nine free helper functions (`decompose`, `resolve_state_dir`, `parse_vault_uuid`, `read_password`, `fail_generic`, `dispatch_once_subcommand`, `dispatch_run_subcommand`, `outcome_to_exit_code`, `now_ms`). No `unsafe`, no global state. |
| Integration tests | [`cli/tests/once_integration.rs`](../../cli/tests/once_integration.rs) | New (~365 LOC). 12 tests: happy path on fresh state, second-call NothingToDo, wrong-password exit 1 + typed Display on stderr, non-interactive without `--password-stdin` exit 2, empty piped stdin exit 1, missing vault folder exit 1, state-file created at expected path, lockfile created at expected path, `--help` lists both subcommands, `--log-format=json` happy path, `-v` + `-vv` accepted, `--state-dir` flag honoured (file lands in tempdir). Helper functions: `core_test_data_dir()` (workspace root via `CARGO_MANIFEST_DIR.parent()`), `copy_dir_recursive()` (mirrors `pipeline_integration.rs`'s helper), `stage_golden_vault()` (returns owning TempDir + vault path), `run_once_with_password()` (assert_cmd shortcut). The password is hard-coded as a `const &str` per the file's docstring rationale — drift caught by `cli/tests/pipeline_integration.rs::golden_vault_password()` which reads the canonical JSON. |
| Logging stderr fix | [`cli/src/logging.rs`](../../cli/src/logging.rs) | Add `.with_writer(std::io::stderr)` to both `LogFormat::Human` and `LogFormat::Json` arms of `try_init`. `tracing-subscriber::fmt()`'s default writer is stdout, which would pollute `secretary-sync once vault > out` redirection and break the Unix convention that diagnostics live on stderr. Caught by `cli/tests/main_validate.rs` (its expectations are stderr-based) the moment Task 9's first call to `tracing::error!` landed in the wrong stream. The two pre-existing tests have been updated to match the new Task-9 behaviour (no more "not yet implemented" stub message). |
| main_validate test updates | [`cli/tests/main_validate.rs`](../../cli/tests/main_validate.rs) | Two of four tests refreshed for the Task 9 dispatch: `once_password_stdin_alone_passes_args_validation` and `once_non_interactive_with_password_stdin_passes_args_validation` previously asserted exit 1 + stderr "not yet implemented" (the stub-body marker). Now they pass empty piped stdin (`.write_stdin("")`) and assert exit 1 + stderr "password is empty" — same validation-passes semantic, now exercising the live unlock-read failure path that landed in this PR. |

**Commit:** `C.2 Task 9 — main.rs end-to-end + once integration tests` (see `git log feature/c2-task-9` for the local pre-merge SHA; the post-squash-merge SHA on `main` will differ). 12 new integration tests; workspace **943 → 955** (12 once_integration adds; main_validate's count stays at 4). No issue closes with this commit; #37 (Sub-project C umbrella) advances by one more C.2 slice.

### Plan ↔ reality reconciliations

Eight deliberate deviations from the plan, driven by the actual library APIs as they exist on `main` (the plan's `main.rs` skeleton drifted from real names + types over the eight prior tasks):

| Plan note | Reality | Resolution |
|---|---|---|
| Plan imports `secretary_cli::logging` and calls `logging::init(verbose, format)`. | Task 8 shipped `logging::try_init` (returning `Result<&'static str, TryInitError>`) so a second-init failure is recoverable. There is no `logging::init`. | Use `logging::try_init`; treat the (rare) second-init error as a warning to stderr and proceed. |
| Plan uses `IDENTITY_BUNDLE_FILENAME = "identity.bundle.cbor"`. | The on-disk file is `identity.bundle.enc` (AEAD-sealed; spec §5 of `docs/vault-format.md`). Confirmed by `ls core/tests/data/golden_vault_001/` and by [`cli/tests/pipeline_integration.rs:47`](../../cli/tests/pipeline_integration.rs#L47). | Const set to `"identity.bundle.enc"`; doc-comment explicitly calls out the `.enc` extension. |
| Plan accesses `identity.vault.vault_uuid` after `open_with_password`. | `UnlockedIdentity` has no `vault` field — only `identity_block_key` and `identity: IdentityBundle`. `IdentityBundle` has a `user_uuid` but no `vault_uuid`. The canonical `vault_uuid` lives in `vault.toml`. | Added `parse_vault_uuid(&[u8])` helper that re-decodes the already-read `vault_toml_bytes` via `vault_toml::decode` to extract `vault_uuid`. Local typed `ParseVaultUuidError` mirrors `UnlockError`'s UTF-8-vs-decode distinction. Re-parse is cheap (small TOML) and keeps the call site honest about where the canonical UUID comes from. |
| Plan calls `daemon::run(&vault_folder, &identity, &password, &mut state, &mut ux, config)`. | `daemon::run` is the closure-shaped loop (`run<P, S>(config, poll, on_sync)`); the production seam is `daemon::run_against_vault(vault, identity, password, state, ux, config, ready_window)`. | Call `daemon::run_against_vault` directly; `ready_window` is a separate `Duration` arg (NOT a `DaemonConfig` field). |
| Plan's `DaemonConfig` has `debounce`, `poll_interval`, `ready_window`, `shutdown_flag`, and `#[cfg(any(test, feature = "testing"))] max_iterations`. | The actual `DaemonConfig` has `debounce`, `poll_interval`, `shutdown_poll_interval`, `shutdown_flag` — no `ready_window`, no `max_iterations`. `shutdown_poll_interval` is required and must be `> 0` (debug_assert in `run_against_vault`). | Construct `DaemonConfig` with the four real fields; use `DEFAULT_SHUTDOWN_POLL_INTERVAL` (re-exported from `cli/src/daemon.rs`); pass `ready_window` separately. |
| Plan calls `signal::install_shutdown_handlers()` and stores the return as `shutdown_flag` (`Arc<AtomicBool>`) directly into `DaemonConfig`. | Task 8 returns `ShutdownGuard`, not the raw flag. The flag is reached via `guard.flag()` (`&Arc<AtomicBool>`). The guard's `Drop` impl unregisters the handlers; it MUST outlive the daemon loop. | Bind `let guard = signal::install_shutdown_handlers()?;`, pass `guard.flag().clone()` to `DaemonConfig::shutdown_flag`, keep `guard` alive across the `daemon::run_against_vault` call. |
| Plan's `main.rs` has an inline `if common.non_interactive && !common.password_stdin { ... return UsageError; }` check. | Task 1's `CommonArgs::validate()` already covers this with the typed `ArgsValidationError::NonInteractiveWithoutStdin` variant; `cli/tests/main_validate.rs` asserts the exit-2 contract independently. Duplicating the check would risk drift. | Call `common.validate()` once; surface `ArgsValidationError` via `eprintln!("error: {e}")` + `ExitCode::UsageError`. Validation runs BEFORE `logging::try_init` so the stderr layout stays canonical for the operator. |
| Plan's integration tests load the password via `const GOLDEN_VAULT_PASSWORD: &str = include_str!("../../core/tests/data/golden_vault_001_password");`. | No such file exists. The password is in `core/tests/data/golden_vault_001_inputs.json` (the cross-language conformance vector). | Hard-code `const GOLDEN_VAULT_PASSWORD: &str = "correct horse battery staple"` per the file's doc-comment rationale. Drift caught by `cli/tests/pipeline_integration.rs::golden_vault_password()` which parses the JSON directly — that's the canonical source-of-truth for regeneration. |

Additionally, one fix was made to a Task-8 module that the plan didn't mention but Task 9 immediately exposed:

| Issue | Fix |
|---|---|
| `tracing-subscriber::fmt()` writes to stdout by default, polluting `secretary-sync once vault > out` redirection and breaking the Unix convention that diagnostics live on stderr. | Added `.with_writer(std::io::stderr)` to both arms of `cli/src/logging.rs::try_init`. Per `CLAUDE.md` "incidental issues — fix or file, never just mention", and per `feedback_act_on_issues_dont_mention`, this is a fix-in-task rather than a follow-up issue. |

The plan estimated ~12 integration tests for a workspace bump of 857→869. The 857 baseline was stale (drifted from the actual 943 at Task 8 close); the test count came out at exactly 12. Actual workspace: **943 → 955** (12 new once_integration tests; the two updated main_validate tests stay at the 4-test count they already had).

### Gauntlet snapshot at session close

```
PASSED: 955 FAILED: 0 IGNORED: 10
clippy --release --workspace --tests -- -D warnings   clean
fmt --all -- --check                                  clean
uv run core/tests/python/conformance.py               PASS
uv run core/tests/python/spec_test_name_freshness.py  PASS (96 resolved / 0 unresolved / 2 suppressed)
```

Baseline 943 came from Task 8 close. Task 9 added 12 new integration tests under `cli/tests/once_integration.rs`; the two `cli/tests/main_validate.rs` test bodies were updated in place (count unchanged at 4).

### Manual smoke-test against `golden_vault_001` (Task 9's plan acceptance criterion #4)

The plan explicitly requires a manual smoke-test of `secretary-sync once <folder>` against the golden vault before pushing. Run from the worktree against an ephemeral copy:

```bash
# Happy path → exit 0; state + lock files materialise in the state-dir.
VAULT=$(mktemp -d) && STATE=$(mktemp -d)
cp -R core/tests/data/golden_vault_001/. "$VAULT/"
echo "correct horse battery staple" | \
  ./target/release/secretary-sync once --password-stdin --non-interactive \
    --state-dir "$STATE" "$VAULT"
echo "EXIT=$?"  # → 0
ls "$STATE"     # → 00112233445566778899aabbccddeeff.{lock,state.cbor}
rm -rf "$VAULT" "$STATE"

# Wrong password → exit 1; typed Display on stderr.
VAULT=$(mktemp -d) && STATE=$(mktemp -d)
cp -R core/tests/data/golden_vault_001/. "$VAULT/"
echo "wrong-password" | \
  ./target/release/secretary-sync once --password-stdin --non-interactive \
    --state-dir "$STATE" "$VAULT"
# → ERROR secretary_sync: vault unlock failed: wrong password or vault corruption
# → EXIT=1
rm -rf "$VAULT" "$STATE"

# Usage error (validate triggers before any I/O) → exit 2.
./target/release/secretary-sync once --non-interactive /tmp/nonexistent
# → error: --non-interactive requires --password-stdin to provide the password
# → EXIT=2
```

All three paths verified during this session; the same three paths are also pinned by `cli/tests/once_integration.rs` (happy / wrong-password / usage-error).

## (2) What's next — start C.2 Task 10

After this PR merges, the next slice is **C.2 Task 10: two-instance convergence + `notify` quirk + README + ROADMAP + handoff** ([`docs/superpowers/plans/2026-05-23-c2-headless-sync-cli.md`](../superpowers/plans/2026-05-23-c2-headless-sync-cli.md) §"Task 10"). This is the final C.2 slice and the one that closes the umbrella.

### Acceptance criteria for Task 10

- [ ] New `cli/tests/two_instance_convergence.rs` — explicit ROADMAP acceptance criterion. Spawn two `secretary-sync run` daemons against the same vault folder via short-lived `tokio::process::Child` (one in each of two tempdir state-dirs to avoid the lockfile-held collision), let them watch a shared vault tempdir, mutate the vault from a third process, send SIGTERM to both after a quiescence window, then assert both state files converged to the same `highest_vector_clock_seen`.
- [ ] New `cli/tests/notify_quirk.rs` — explicit ROADMAP acceptance criterion. Cross-platform `notify`-quirk pin: assert the behaviour we observed during C.2 Task 6/7 (the spec's `WatcherEvent::SyncCandidate` semantic vs the raw `notify` event types per platform) is exercised in CI on both macOS (FSEvents) and Linux (inotify). Implementation-wise this is mostly a `notify::Watcher::new` + write-to-tempdir + `recv_timeout` smoke; the value is that any future `notify` major bump regression surfaces in CI.
- [ ] README.md update — move the Sub-project C row from "C.1.1b ✅" to "C.2 ✅". The current row is one of the longest in the README; per `feedback_readme_style` keep the new bullet terse (one or two clauses) and move detail into ROADMAP.
- [ ] ROADMAP.md update — flip "C.2 Tasks 1–9/10 ✅" to "C.2 ✅" on the progress bar, retire the per-task PR list down to a single summary bullet, advance the Sub-project C status line. Bump the Task 10 PR # into the C.2 bullet once `gh pr create` returns.
- [ ] NEXT_SESSION.md handoff baton retargeted to a new `docs/handoffs/2026-MM-DD-c2-shipped.md`. This is the final C.2 baton; the next session after Task 10 will be either C.3 (mobile adapters) or D.1 (desktop UI) per the user's call.
- [ ] Gauntlet target: **PASSED: 955 + N FAILED: 0 IGNORED: 10**. Absolute base is now 955. The plan estimated 2 new integration test files (~3–5 tests each), so somewhere in the 960–965 range is the expected landing zone.
- [ ] Clippy, fmt, conformance, spec freshness all clean.

### Plan handoff

Full step-by-step in [`docs/superpowers/plans/2026-05-23-c2-headless-sync-cli.md`](../superpowers/plans/2026-05-23-c2-headless-sync-cli.md) §"Task 10". Task 10's scope is "closes the C.2 loop" — three docs updates (README + ROADMAP + handoff) plus two integration tests, no new library code in `cli/src/*.rs`. The two integration tests are the spec's commitment that "we tested convergence across two instances" + "we pinned the cross-platform `notify` quirk in CI", both of which would otherwise be lost in the daemon's unit-test coverage.

## (3) Open decisions and risks

### Decisions settled during this session

- **`parse_vault_uuid` is a free function with its own local `ParseVaultUuidError`.** Rather than importing all of `UnlockError`, the local enum has just the two variants the call site distinguishes (NotUtf8 vs Decode). Mirrors `UnlockError`'s UTF-8 split for log-message symmetry without coupling `main.rs` to the wider unlock-error surface.
- **`STATE_DIR_FALLBACK = "."`** for the `--state-dir` unset / no `dirs::data_dir()` case. The alternative — error out — would break minimal headless installs (no `$HOME`, no XDG vars). The operator can pin a real location via `--state-dir` once they notice the state-file sprawl in their CWD.
- **Logging writes to stderr (not stdout).** `tracing-subscriber::fmt()`'s default is stdout, which contradicts the Unix convention. Both `LogFormat::Human` and `LogFormat::Json` paths now `.with_writer(std::io::stderr)`. Fixed in this PR.
- **`fail_generic(format_args!(...))` helper.** Eliminates the repetitive `error!(...); return ExitCode::GenericError` pair throughout `run()`. Uses `std::fmt::Arguments` so the call sites stay zero-alloc.
- **Validation runs BEFORE logging init.** The eprintln keeps the stderr layout deterministic for the operator who hit `--non-interactive` without `--password-stdin`; the tracing envelope would otherwise mangle the typed Display.
- **`dispatch_once_subcommand` and `dispatch_run_subcommand` are separate functions.** They have different return types under the hood: `once` returns `Result<RunOutcome, SyncError>` (so the `RollbackRejected` arm can map to its dedicated exit code); `run` returns `Result<(), SyncError>` (clean shutdown is `Success`, daemon errors get the SyncError mapping). Unifying the two would require a synthetic `RunOutcome::DaemonExited` variant that exists nowhere else.
- **`now_ms()` is local to `main.rs` rather than imported from `cli/src/daemon.rs`.** Five lines of code, locally scoped; exposing a `now_ms` API on the daemon module would inflate the public surface for no win. The duplication is intentional.
- **Hard-coded `GOLDEN_VAULT_PASSWORD: &str = "correct horse battery staple"` in `cli/tests/once_integration.rs`.** Drift caught by `cli/tests/pipeline_integration.rs::golden_vault_password()` which parses the canonical JSON. Keeps each test self-contained without pulling `serde_json` into the integration suite.
- **12 integration tests under one file rather than split per subcommand path.** `cli/tests/main_validate.rs` already covers the args-layer validation contract (Task 1). `cli/tests/pipeline_integration.rs` covers the `run_one` library API directly. `cli/tests/once_integration.rs` is the only place the actual `secretary-sync` binary is driven end-to-end; keeping all 12 tests in one file keeps the file structure parallel to the other two and avoids per-test-file boilerplate (the `core_test_data_dir`, `copy_dir_recursive`, `stage_golden_vault`, `run_once_with_password` helpers are reused 12 times across the file's tests).

### Decisions carried forward (unchanged from Task 8 close)

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
- Daemon shape (Task 7): closure-shaped `run<P, S>(config, poll, on_sync)`; `compute_wait` pure; `DEFAULT_SHUTDOWN_POLL_INTERVAL = 1 s`; `READY_NOT_READY_WARN_THRESHOLD = 5`; `WatcherEvent::PollTick` test-only; `now_ms` saturates on overflow; production seam is `run_against_vault(... config, ready_window)`.
- Logging shape (Task 8): pure `resolve_directive(u8) -> &'static str` + side-effectful `try_init`; `TryInitError` aliased to the upstream boxed error; `RUST_LOG` overrides directive when set; v1 saturates at `-vv`. Task 9 added: stderr writer.
- Signal shape (Task 8): `install_shutdown_handlers() -> io::Result<ShutdownGuard>`; `ShutdownGuard::flag() -> &Arc<AtomicBool>`; drop unregisters every installed handler; non-Unix returns an empty guard with a permanently-false flag.

### Risks carried into Task 10

- **Two-instance convergence test wall-clock budget.** The convergence test must spawn two daemons, drive them to a stable state, send SIGTERM, and assert both state files match. A naive implementation would burn 5+ seconds of wall-clock per run. The Task 7 handoff's existing daemon-loop tests use 50–200 ms windows (see #123); Task 10 should follow the same pattern (short debounce + short ready_window) and use the existing `compute_wait` semantics rather than `std::thread::sleep`-pause tricks.
- **`notify` quirk test must run on both macOS and Linux CI.** The current CI matrix is Linux + macOS (per `feedback_windows_not_primary`). The notify-quirk test is meaningful only because cross-platform behaviour differs; running it on only one platform would defeat its purpose. Task 10 should explicitly assert in the test body that both backends exhibit the expected behaviour, OR use `#[cfg(target_os = "...")]` gates to split per-platform expectations.
- **README C-row prose budget.** The current Sub-project C row is the longest in the README (one line, ~900 chars). Per `feedback_readme_style` the Task-10 update should make it shorter, not longer — describe C.2 ✅ in one or two clauses + move per-task detail into ROADMAP. The user reviewed the ROADMAP terseness in the recent `ee680e7 docs: tighten ROADMAP.md` commit and will likely want symmetric README treatment.
- **`logging::try_init` second-init path.** When the binary is re-exec'd inside an already-instrumented test runner (or when a future C.2.x slice spawns the binary as a child of itself), the second `try_init` call returns `TryInitError`. The current handling is a stderr warning + proceed; this is correct for production but may need attention if Task 10's convergence test runs the binary inside the same process (it won't — `assert_cmd` spawns subprocesses — but the path is worth flagging).
- **`state::save` after `dispatch_run_subcommand` returns Err.** The daemon's `run_against_vault` returns `Err(SyncError)` on a fatal pipeline error; `main.rs` still calls `state::save` afterwards. The `run_one` state-mutation contract guarantees `state` is unchanged on `Err` (the daemon's `on_sync` closure swallows pipeline errors via `tracing::warn!` and continues), so the final save is correct in all observable cases — but if a future refactor changes that, the state-file could regress to a partial post-error state. Worth a re-read when Task 10 touches the daemon loop.

### Issues currently open

- #37 — Sub-project C umbrella. C.2 Tasks 1–8 ✅ in PRs #112, #114, #115, #116, #118, #119, #121, #124. Task 9 pending PR.
- #117 — `TtyVetoUx` re-prompt loop has no max-attempts cap. Low-priority defensive-coding fix; still queued, not in scope for Task 10.
- #120 — `matches_partial_pattern` allocates per call via `to_ascii_lowercase`. Filed during PR #119 review; performance-only, no correctness or security impact. Pick up if a profiler ever flags it.
- #122 — `cli/src/daemon.rs` at ~770 LOC is over the 500-LOC threshold. Filed by Task 7 fixup pass; candidate directory-module shape captured. Task 10 should consider folding this in alongside the two-instance convergence test, since both touch daemon code.
- #123 — daemon behavioural tests use 50–200 ms wall-clock windows. Filed by Task 7 fixup pass; speculative CI-flake risk. No observed flake yet. Task 10's convergence test will use similar windows; if a flake materialises during Task 10 CI, this is the parent issue to update.
- #38, #45, #75, #76, #78, #79, #81, #87, #88, #90, #95, #98 — none block C.2 Task 10.

### Housekeeping note (stale worktrees on disk)

After this PR:
- `/Users/hherb/src/secretary` — `main` (clean post-merge).
- `/Users/hherb/src/secretary/.worktrees/c1-1b-sync-merge` — branch `feature/c1-1b-task-17`, remote gone. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-1-spec` — branch `feature/c2-task-1-spec`, remote gone. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-{1..8}` — branches `feature/c2-task-{1..8}`, remote gone after each PR merged. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-9` — **this session's work**; keep until PR merges, then remove.

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
git worktree remove .worktrees/c2-task-8        && git branch -D feature/c2-task-8
```

Cleanup is one-line each and does NOT block Task 10.

## (4) Exact commands to resume

```bash
# After this C.2 Task 9 PR (feature/c2-task-9) merges:
cd /Users/hherb/src/secretary
git fetch --prune origin
git status --short                       # expect: clean (modulo NEXT_SESSION.md sync, see below)
git checkout main
git pull --ff-only origin main

# Verify gauntlet on fresh main (expect 955 / 0 / 10 — same as session close):
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3

# Start Task 10:
git worktree add .worktrees/c2-task-10 -b feature/c2-task-10 main
cd .worktrees/c2-task-10

# Open the plan and follow Task 10 line-by-line:
#   docs/superpowers/plans/2026-05-23-c2-headless-sync-cli.md §"Task 10"
# Task 10 adds cli/tests/two_instance_convergence.rs + cli/tests/notify_quirk.rs,
# bumps README + ROADMAP, and retargets NEXT_SESSION.md. This is the C.2 closer.
```

## Closing inventory

- **Branch state on close:** `main` at `2e47116` (Task 8 PR #124 merged). `feature/c2-task-9` carries one commit on top (Task 9 code + tests + handoff + symlink + ROADMAP bump).
- **Workspace tests on `feature/c2-task-9`:** 955 passed + 10 ignored (943 base + 12 new tests in `cli/tests/once_integration.rs`; 2 tests in `cli/tests/main_validate.rs` updated in place). Clippy + fmt + Python conformance + spec freshness all clean.
- **README.md:** unchanged this session — per Task 8 handoff's deliberate decision, promotion of the Sub-project C row from "C.1.1b ✅" to "C.2 ✅" is deferred until Task 10 closes the umbrella.
- **ROADMAP.md:** bumped this session. Tasks 1–8/10 → Tasks 1–9/10 in the status line, progress bar, and the C.2 row. Task 9 PR # is NOT yet allocated (it goes in alongside the next commit after `gh pr create` returns; or alternatively, can be folded into the Task 10 ROADMAP sweep).
- **CLAUDE.md:** unchanged this session — no new convention; `main.rs` dispatch wiring is local to `cli/` and doesn't generalise to repo-wide guidance.
- **NEXT_SESSION.md:** symlink retargeted to this file.
- **Open issues:** see §(3) — none close with this PR; none block Task 10. #122 (daemon LOC) is a strong candidate to fold into Task 10 since both touch daemon code.
- **Open PRs:** one to be opened at end of this session (C.2 Task 9).
- **Worktrees on disk:** see §(3) housekeeping.
- **Frozen baton snapshots:** all 26 prior C.1.1b + C.2-design + C.2-task-1/2/3/4/5/6/7/8 handoffs at [`docs/handoffs/`](.) — preserved unchanged.
- **This file:** the live baton for C.2 Task 9 close.
