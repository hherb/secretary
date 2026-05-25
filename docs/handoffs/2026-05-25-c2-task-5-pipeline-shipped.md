# NEXT_SESSION.md — C.2 Task 5 (pipeline + lib/bin split) shipped

**Session date:** 2026-05-25 (C.2 Task 5 — `cli/src/pipeline.rs`: `run_one` + `RunOutcome` + lib/bin split + #113 cleanup + `--non-interactive ↔ --password-stdin` validation).
**Status:** C.2 Task 5 ✅ on branch `feature/c2-task-5`; PR pending. Tasks 6-10 queued.

## (1) What we shipped this session

One commit on `feature/c2-task-5` carrying the fifth code slice of C.2 — the pipeline orchestrator that composes `sync_once → prepare_merge → veto UX → commit_with_decisions` behind a single function. Both subcommands (`once` and `run`) will consume this exact entry point in the upcoming tasks. The slice also promotes the cli crate to library+binary so integration tests can drive the pipeline directly through `secretary_cli::*` (Task 5's `cli/tests/pipeline_integration.rs` is the first end-to-end test that crosses the library boundary), lifts the umbrella `#[allow(dead_code)]` set queued by issue [#113](https://github.com/hherb/secretary/issues/113), and adds the args-layer validation for the `--non-interactive ↔ --password-stdin` flag-pair so the failure surfaces before any vault I/O.

| Artifact | Path | Notes |
|---|---|---|
| Pipeline module | [`cli/src/pipeline.rs`](../../cli/src/pipeline.rs) | New. `pub fn run_one(&Path, &UnlockedIdentity, &SecretBytes, &mut SyncState, &mut dyn VetoUx, u64) -> Result<RunOutcome, SyncError>`. Five-variant `RunOutcome` enum (`NothingToDo`, `AppliedAutomatically`, `MergedAndCommitted { vetoes_resolved: usize }`, `SilentMerge`, `RollbackRejected`) plus the documented state-mutation contract (which arms advance `state`, which don't). 9 unit tests pin variant equality + Debug shape + Clone round-trip + the `MergedAndCommitted` payload-discrimination contract. |
| Library surface | [`cli/src/lib.rs`](../../cli/src/lib.rs) | New. Re-exports `args`, `exit`, `pipeline`, `state`, `unlock`, `veto` so integration tests can reach them. Production consumers still run the `secretary-sync` binary. |
| Cargo manifest | [`cli/Cargo.toml`](../../cli/Cargo.toml) | Added `[lib] name = "secretary_cli" path = "src/lib.rs"` ahead of the existing `[[bin]]` block. Binary target unchanged. |
| Binary entry | [`cli/src/main.rs`](../../cli/src/main.rs) | Switched from inline `mod` declarations to `use secretary_cli::{args, exit};`. Subcommand bodies remain stubs (the dispatch + `pipeline::run_one` wiring lands in Task 9). |
| Args validation | [`cli/src/args.rs`](../../cli/src/args.rs) | New `ArgsValidationError::NonInteractiveWithoutStdin` typed-error variant + `CommonArgs::validate()` method. Mirrors `UnlockReadError::NonInteractiveWithoutStdin` at the args layer so the failure fires before any unlock attempt. 5 new unit tests cover the accept/reject matrix (default-flags, `--password-stdin` alone, both-flags, `--non-interactive` alone on `once`, `--non-interactive` alone on `run`). |
| Dead-code cleanup | [`cli/src/{exit,state,unlock}.rs`](../../cli/src/), [`cli/src/veto/{mod,interactive,noninteractive}.rs`](../../cli/src/veto/) | All `#[allow(dead_code)]` TODO(#113) markers removed. The cli crate now compiles `-D warnings` with zero allowances. |
| Integration tests | [`cli/tests/pipeline_integration.rs`](../../cli/tests/pipeline_integration.rs) | New. 4 tests against a fresh-copied `golden_vault_001` tempdir: `run_one_returns_applied_automatically_on_fresh_state` (+ state advanced); `run_one_returns_nothing_to_do_on_second_call` (+ state unchanged); `run_one_returns_rollback_rejected_when_state_dominates` (+ state NOT advanced); `run_one_threads_autokeeplocal_through_dyn_boundary` (the trait-object boundary smoke). Fixture access mirrors `core/tests/fixtures/mod.rs` — `golden_vault_001_inputs.json` for the password, `core/tests/data/golden_vault_001/` for the on-disk vault, via the `cli/`-relative workspace-root path. |

**Commit:** `97dfe85 C.2 Task 5 — pipeline (one sync attempt) + lib/bin split`. 18 new tests across cli (9 pipeline unit + 5 args validation unit + 4 integration); workspace 850 → 868. Issue #113 closes with this commit.

### Plan ↔ reality reconciliations

Three deliberate deviations from the plan, all documented in the commit body:

| Plan note | Reality | Resolution |
|---|---|---|
| Plan code referenced `core/tests/data/golden_vault_001_password` file (line 1539). | No such file exists — the password lives at the `password` key inside `golden_vault_001_inputs.json` (verified by reading `core/tests/fixtures/mod.rs::golden_vault_001_password`). | Read the inputs JSON and string-scan for the `"password":` key. Avoids dragging `serde_json` into `cli/dev-dependencies` for a single fixture, and matches the pattern already used by the `fixtures` helper that lives in `core/tests/` (and isn't reachable cross-crate). |
| Plan code referenced `identity.bundle.cbor` (line 1572). | Actual fixture file is `identity.bundle.enc`. | Used the actual filename. |
| Plan code referenced `unlocked.vault.vault_uuid` (line 1577). | `UnlockedIdentity` has no `vault` field — it carries `identity_block_key` + `identity: IdentityBundle`. | Re-decode `vault.toml` via `secretary_core::unlock::vault_toml::decode` to recover the `vault_uuid`. Same approach as `core/tests/fixtures/mod.rs::extract_vault_uuid`. |

Plan acceptance line for tests was "2 new integration tests; workspace 835→837". Actual: **18 new tests; workspace 850 → 868**. The baseline (850) accumulated through Tasks 1-4. The test mix expanded beyond the plan's literal 2 to satisfy the baton's broader acceptance criteria ("each outcome variant + each veto policy + state-update side effects + the no-op happy paths. Plan expects ~15-20 new tests"):

- **Pipeline unit tests (9)** — variant equality + Debug + Clone round-trip + `MergedAndCommitted` payload discrimination. Pure (no vault I/O). These are the cheapest possible regression guards on the `RunOutcome` shape.
- **Args validation tests (5)** — accept/reject matrix for `--non-interactive ↔ --password-stdin` including the `run` subcommand parity (the validation lives on `CommonArgs`, shared by both subcommands).
- **Integration tests (4)** — see the `cli/tests/pipeline_integration.rs` table row above.

Concurrent-path coverage (`MergedAndCommitted`, `SilentMerge`) is deferred to Task 10's two-instance convergence tests, which can stage the necessary conflict-copy fixtures end-to-end via two cli processes rather than reproducing the `sync_helpers` machinery cross-crate. The unit + integration tests in this slice cover the dispatch arms that don't need a concurrent setup; the merge-arm correctness is already pinned by the core's `sync_merge*` integration tests + proptests.

### Gauntlet snapshot at session close

```
PASSED: 868 FAILED: 0 IGNORED: 10
clippy --release --workspace --tests -- -D warnings   clean
fmt --all -- --check                                  clean
uv run core/tests/python/conformance.py               PASS
uv run core/tests/python/spec_test_name_freshness.py  PASS (96 resolved / 0 unresolved / 2 suppressed)
```

## (2) What's next — start C.2 Task 6

After this PR merges, the next slice is **C.2 Task 6: Watcher submodule — partial-download ready + debounce (`cli/src/watcher/{mod,ready,debounce}.rs`)** ([`docs/superpowers/plans/2026-05-23-c2-headless-sync-cli.md`](../superpowers/plans/2026-05-23-c2-headless-sync-cli.md) §"Task 6").

### Acceptance criteria for Task 6

- [ ] New `cli/src/watcher/mod.rs` (~70 LOC): `WatcherEvent` enum + driver trait surface.
- [ ] New `cli/src/watcher/ready.rs` (~190 LOC): `matches_partial_pattern` (pure pattern matcher for Dropbox / iCloud / Syncthing partial-download filename suffixes), `is_size_stable` (size + mtime stability probe), `wait_for_ready` (composes the two). Per ADR-0003 partial-download detection.
- [ ] New `cli/src/watcher/debounce.rs` (~140 LOC): pure state machine that collapses a notify event burst into a single `should_sync_now` signal — `idle → pending(deadline)` transitions, deadline driven by `--debounce-ms`.
- [ ] New `cli/src/main.rs` line: `mod watcher;` (in the library, not the binary — Task 5 already established the `lib.rs` pattern).
- [ ] Pure-function unit tests for each new file: pattern matcher covers each cloud's known partial-suffix list (Dropbox `.tmp` / iCloud `.icloud` / Syncthing `~syncthing~`); size-stability probe covers grow-then-stable + stable-throughout + missing-file branches; debounce state machine covers single-event + burst-collapse + post-deadline-emit + reset-on-new-event-after-emit.
- [ ] Gauntlet target: **PASSED: 868 + N FAILED: 0 IGNORED: 10**. Absolute base is now 868 (bumped from 850 by Task 5's 18 new tests).
- [ ] Clippy, fmt, conformance, spec freshness all clean.

### Plan handoff

Full step-by-step in [`docs/superpowers/plans/2026-05-23-c2-headless-sync-cli.md`](../superpowers/plans/2026-05-23-c2-headless-sync-cli.md) §"Task 6". Three sub-files (mod / ready / debounce) keep each below the 500-LOC threshold; the debounce file is the densest at ~140 LOC and is the only one with non-trivial state (the others are pure functions).

## (3) Open decisions and risks

### Decisions settled during this session

- **`run_one` returns `Result<RunOutcome, SyncError>`** (not `Result<(ExitCode, RunOutcome), SyncError>`) so the dispatch caller in Task 9 owns the `RunOutcome → ExitCode` mapping. Keeps `pipeline` ignorant of exit-code semantics; mirrors the spec's "pure pipeline, I/O at edges" principle.
- **`RunOutcome::MergedAndCommitted { vetoes_resolved: usize }`** keeps the operator-visible metric inline rather than in a sibling struct. The discriminant test (`merged_and_committed_ne_when_counts_differ`) pins this — a future refactor that drops the count or boxes it into a struct trips the test.
- **`RunOutcome::SilentMerge` is distinct from `MergedAndCommitted { vetoes_resolved: 0 }`.** Both denote "concurrent state detected, ended successfully", but SilentMerge means the diff plan itself was empty (no diverging blocks survived authentication — just a clock advance); MergedAndCommitted means the diff plan was non-empty AND every divergence merged without tombstone fights. The two are observably different to the operator (commit happened in one, not the other) and to the daemon loop (filesystem state changed in one, not the other).
- **State mutation contract is documented + tested.** NothingToDo + RollbackRejected leave `state` byte-for-byte unchanged; AppliedAutomatically + SilentMerge + MergedAndCommitted advance it. The integration tests pin all three of those (advances + NothingToDo-no-mutation + RollbackRejected-no-mutation).
- **Library + binary hybrid.** The `[lib]` target is `secretary_cli` (underscored — Rust crate-name convention); the `[[bin]]` target is `secretary-sync` (hyphenated — CLI invocation convention). Both modules see the same `src/` tree; the binary's `main.rs` uses `use secretary_cli::{args, exit};`.
- **`ArgsValidationError` lives in `args` module, not `unlock`.** The args-layer error type runs at parse time, not at unlock time. The two error types share a variant name (`NonInteractiveWithoutStdin`) to make the contract obvious, but they're distinct types because they fire at different lifecycle stages. Task 9's `main.rs` dispatch will map `ArgsValidationError` → `ExitCode::UsageError` (2) and `UnlockReadError::NonInteractiveWithoutStdin` → `ExitCode::UsageError` (2) — same exit code, different sites.
- **Fixture access via workspace-relative path.** `cli/tests/` reads `../core/tests/data/golden_vault_001/` because `core/tests/fixtures/mod.rs` is a per-test-binary module and not reachable across crates. The pattern is documented at the top of `cli/tests/pipeline_integration.rs` so a future contributor doesn't try the broken cross-crate import.

### Decisions carried forward (unchanged from Task 4 close)

- D1-D10 from the spec are still settled.
- `--veto-policy=fail`, `--decisions-file`, `--exit-on-error`, `status`, `init` subcommands all deferred to future C.2.x slices.
- Windows is best-effort per D10 (no CI runner planned for C.2 implementation).
- Clean-room conformance harness for `cli/` deferred to C.4 or a future C.2.x slice.
- The `from_sync_error` mapper's exit-code surface (Task 1): every `SyncError` variant without a dedicated code maps to `GenericError = 1`; bijection-failure variants do NOT get distinct codes (CLI bugs, not operator-recoverable).
- fs4 dep retained over stdlib `File::try_lock` until workspace MSRV bumps past 1.89.
- `SecretBytes::new(buf)` over `SecretBytes::from(slice) + zeroize` for owned-buffer unlock paths (Task 3 — still in force).
- `TtyVetoUx` EOF latch + breadcrumb (Task 4) + safe-default `KeepLocal` on empty/error input + silent prompt-write failures: all in force.

### Risks carried into Task 6

- **Cross-platform `notify` quirks land in Task 7.** Task 6's `watcher::ready` / `watcher::debounce` files are pure-function logic and run identically on Linux / macOS / Windows. The actual `notify::RecommendedWatcher` integration (Task 7) is where platform quirks surface (macOS FSEvents coalescing, Linux inotify single-event-per-file, Windows ReadDirectoryChangesW); a `cli/tests/notify_quirk.rs` test is planned for Task 10 to pin those.
- **Concurrent + merge paths in `run_one` are not unit-tested.** The dispatch logic for `SyncOutcome::ConcurrentDetected` (silent-merge fast path + merge-and-commit) is exercised only by `core/tests/sync_merge*.rs` tests against the lower-level functions, not against `run_one` itself. Task 10's two-instance convergence test will close that gap end-to-end through two `secretary-sync` processes.
- **`pipeline_integration.rs` password extraction uses string-scan.** The `golden_vault_001_inputs.json` schema is stable, and the test reads only the `password` key — but a future change to that JSON's shape (e.g. nesting password under `unlock.password`) would silently fail the `find("\"password\":")` lookup. Mitigation: the JSON schema is single-sourced in `core/tests/fixtures/mod.rs::Inputs`; a structural change there would change all callers in lockstep.

### Issues currently open

- #37 — Sub-project C umbrella. C.2 Tasks 1-4 ✅ in PRs #112, #114, #115, #116; Task 5 pending PR.
- ~~#113~~ — **Closed by this commit.** All `cli/` `#[allow(dead_code)]` markers lifted; cli crate compiles `-D warnings` with zero allowances.
- #117 — `TtyVetoUx` re-prompt loop has no max-attempts cap. Low-priority defensive-coding fix; still queued, not in scope for Task 6.
- #38, #45, #75, #76, #78, #79, #81, #87, #88, #90, #95, #98 — none block C.2 Task 6.

### Housekeeping note (stale worktrees on disk)

After this PR:
- `/Users/hherb/src/secretary` — `main` (clean post-merge).
- `/Users/hherb/src/secretary/.worktrees/c1-1b-sync-merge` — branch `feature/c1-1b-task-17`, remote gone. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-1-spec` — branch `feature/c2-task-1-spec`, remote gone. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-1` — branch `feature/c2-task-1`, remote gone. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-2` — branch `feature/c2-task-2`, remote gone. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-3` — branch `feature/c2-task-3`, remote gone. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-4` — branch `feature/c2-task-4`, remote gone. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-5` — **this session's work**; keep until PR merges, then remove.

```bash
# One-line each (run from /Users/hherb/src/secretary):
git worktree remove .worktrees/c1-1b-sync-merge && git branch -D feature/c1-1b-task-17
git worktree remove .worktrees/c2-task-1-spec   && git branch -D feature/c2-task-1-spec
git worktree remove .worktrees/c2-task-1        && git branch -D feature/c2-task-1
git worktree remove .worktrees/c2-task-2        && git branch -D feature/c2-task-2
git worktree remove .worktrees/c2-task-3        && git branch -D feature/c2-task-3
git worktree remove .worktrees/c2-task-4        && git branch -D feature/c2-task-4
```

Cleanup is one-line each and does NOT block Task 6.

## (4) Exact commands to resume

```bash
# After this C.2 Task 5 PR (feature/c2-task-5) merges:
cd /Users/hherb/src/secretary
git fetch --prune origin
git status --short                       # expect: clean (modulo NEXT_SESSION.md sync, see below)
git checkout main
git pull --ff-only origin main

# Verify gauntlet on fresh main (expect 868 / 0 / 10 — same as session close):
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3

# Start Task 6:
git worktree add .worktrees/c2-task-6 -b feature/c2-task-6 main
cd .worktrees/c2-task-6

# Open the plan and follow Task 6 line-by-line:
#   docs/superpowers/plans/2026-05-23-c2-headless-sync-cli.md §"Task 6"
# Task 6 is three new pure-function files under cli/src/watcher/ —
# ready (partial-download pattern matcher + size stability probe),
# debounce (state machine), and mod (WatcherEvent enum + driver
# trait). All three stay well under the 500-LOC threshold; the actual
# notify::RecommendedWatcher integration lands in Task 7.
```

## Closing inventory

- **Branch state on close:** `main` at `cedd04c` (PR #116 squash-merged). `feature/c2-task-5` carries 1 commit on top (Task 5 code + tests + cleanup).
- **Workspace tests on `feature/c2-task-5`:** 868 passed + 10 ignored (850 base + 18 new cli tests: 9 in `pipeline::tests` + 5 in `args::tests::validate_*` + 4 in `cli/tests/pipeline_integration.rs`). Clippy + fmt + Python conformance + spec freshness all clean.
- **README.md:** unchanged this session — Task 5 ships internal scaffolding + lib/bin split; no user-visible behavior. Plan defers README update to Task 10.
- **ROADMAP.md:** unchanged this session — same reason; ROADMAP already calls C.2 "queued" since the C.2 design PR.
- **CLAUDE.md:** unchanged this session — no new convention; pipeline + lib/bin split are local to `cli/` and don't generalise to repo-wide guidance.
- **NEXT_SESSION.md:** symlink retargeted to this file.
- **Open issues:** see §(3) — #113 closes with this PR; none block Task 6.
- **Open PRs:** one to be opened at end of this session (C.2 Task 5).
- **Worktrees on disk:** see §(3) housekeeping.
- **Frozen baton snapshots:** all 22 prior C.1.1b + C.2-design + C.2-task-1/2/3/4 handoffs at [`docs/handoffs/`](.) — preserved unchanged.
- **This file:** the live baton for C.2 Task 5 close.
