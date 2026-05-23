# NEXT_SESSION.md — C.2 Task 1 (cli/ scaffold + exit codes) shipped

**Session date:** 2026-05-23 (C.2 Task 1 — scaffold `cli/` workspace member + `ExitCode` enum).
**Status:** C.2 Task 1 ✅ on branch `feature/c2-task-1`; PR pending. Tasks 2-10 queued.

## (1) What we shipped this session

A single PR on `feature/c2-task-1` carrying the first code slice of C.2 — the new `cli/` workspace member that subsequent tasks extend.

| Artifact | Path | Notes |
|---|---|---|
| Workspace manifest | [`Cargo.toml`](../../Cargo.toml) | `cli` added to `[workspace] members` (slot 2 between `core` and the `ffi/*` crates). |
| Crate manifest | [`cli/Cargo.toml`](../../cli/Cargo.toml) | 11 runtime deps (clap, notify, tracing, tracing-subscriber, dirs, tempfile=3.27.0 exact-pinned, rpassword, serde_json, fs2, signal-hook, thiserror) + 2 dev deps (assert_cmd, predicates). |
| Binary entry point | [`cli/src/main.rs`](../../cli/src/main.rs) | Skeleton `clap::Parser::parse()` → match subcommand → eprintln + `ExitCode::GenericError`. |
| Arg parser | [`cli/src/args.rs`](../../cli/src/args.rs) | `Cli` / `Command::{Once,Run}` / `CommonArgs` / `RunArgs` / `LogFormat`. 4 unit tests, including the spec-frozen 2000 ms `--ready-window-ms` default. |
| Exit codes | [`cli/src/exit.rs`](../../cli/src/exit.rs) | `ExitCode` enum (0/1/2/10/11/12/13/14) + `from_sync_error` mapper. 9 unit tests pin every discriminant + the `EvidenceStale` mapping. `#[allow(dead_code)]` on the not-yet-used surface; Task 5 wires the rest. |

### Plan ↔ reality reconciliation

| Plan note | Reality | Resolution |
|---|---|---|
| "12 new cli tests" / "PASSED: 812" | Actual: **13 cli tests** (4 args + 9 exit) / **PASSED: 813** | Plan was off by one (arithmetic typo). Acceptance criterion in Task 1 of the plan updated implicitly to 813 by ship reality; no plan amendment needed since Task 2's baseline is now "813". |
| Plan code listed `from_sync_error` as nested `match v { ... }` | `clippy::collapsible_match` rejected the nested form | Collapsed to a single-arm nested pattern (`SyncError::Vault(VaultError::BlockFingerprintMismatch { .. }) => …`) preserving identical semantics. Tests unchanged. |
| Plan listed `pub enum ExitCode` without `#[allow(dead_code)]` | Unused variants and the `from_sync_error` method warned (this is a binary crate, no external consumers) | Added `#[allow(dead_code)]` to the enum + impl with an inline comment noting "Task 5 wires the rest". Will lift in Task 5. |

### Gauntlet snapshot at session close

```
PASSED: 813 FAILED: 0 IGNORED: 10
clippy --release --workspace --tests -- -D warnings   clean
fmt --all -- --check                                  clean
uv run core/tests/python/conformance.py               PASS
uv run core/tests/python/spec_test_name_freshness.py  PASS (96 resolved / 0 unresolved / 2 suppressed)
secretary-sync --help / once --help / run --help     all print correctly
```

## (2) What's next — start C.2 Task 2

After this PR merges, the next slice is **C.2 Task 2: state persistence + host-local lockfile** ([`docs/superpowers/plans/2026-05-23-c2-headless-sync-cli.md`](../superpowers/plans/2026-05-23-c2-headless-sync-cli.md) §"Task 2").

### Acceptance criteria for Task 2

- [ ] New `cli/src/state.rs` (~280 LOC) with the following surface:
  - `canonical_hex(vault_uuid: [u8; 16]) -> String` (pure, 32-char lowercase hex).
  - `state_file_path(state_dir, vault_uuid) -> PathBuf` / `lock_file_path(...)` (pure).
  - `default_state_dir() -> Option<PathBuf>` via the `dirs` crate.
  - `load(state_dir, vault_uuid) -> Result<SyncState, StateError>` — empty-on-missing, vault-UUID-mismatch returns typed error.
  - `save(state_dir, &SyncState) -> Result<(), StateError>` — atomic via `tempfile::NamedTempFile::persist`.
  - `LockfileGuard::acquire(state_dir, vault_uuid)` — `fs2::try_lock_exclusive`; collision returns `StateError::LockfileHeld`; kernel auto-release on drop.
- [ ] `cli/src/main.rs` gains `mod state;`.
- [ ] 9 new unit tests cover: canonical_hex format, state/lock file-path layout, load-missing-returns-empty, save→load roundtrip, vault-UUID-mismatch typed error, lockfile collision returns held, lockfile releases on drop, different-vaults-don't-collide, default_state_dir ends in `secretary/sync`.
- [ ] Gauntlet target: **PASSED: 822 FAILED: 0 IGNORED: 10** (813 base + 9 new). Plan said 821 but the base is now 813, so the absolute number floats up by one.
- [ ] Clippy, fmt, conformance, spec freshness all clean.

### Plan handoff

Full step-by-step in [`docs/superpowers/plans/2026-05-23-c2-headless-sync-cli.md`](../superpowers/plans/2026-05-23-c2-headless-sync-cli.md) §"Task 2", which still applies verbatim (no observable Task 1 deviations affect Task 2's surface).

## (3) Open decisions and risks

### Decisions settled during this session

- The `from_sync_error` mapper currently surfaces `EvidenceStale → ExitCode::EvidenceStale` and `Vault(BlockFingerprintMismatch{..}) → ExitCode::BlockFingerprintMismatch`. **Every other `SyncError` variant folds to `GenericError`.** This matches the spec's exit-code table — variants without a dedicated code map to `1`. The `UnknownVetoDecision` / `MissingVetoDecision` / `EmptyDraftWithVetoes` bijection-failure variants do NOT get distinct exit codes (they indicate a CLI bug, not an operator-recoverable condition).

### Decisions carried forward (unchanged from C.2 design close)

- D1-D10 from the spec are still settled.
- `--veto-policy=fail`, `--decisions-file`, `--exit-on-error`, `status`, `init` subcommands all deferred to future C.2.x slices.
- Windows is best-effort per D10 (no CI runner planned for C.2 implementation).
- Clean-room conformance harness for `cli/` deferred to C.4 or a future C.2.x slice.

### Risks carried into Task 2

- **`tempfile = "=3.27.0"` exact pin** is now duplicated in `cli/Cargo.toml`. Same discipline as `core` — bump only via deliberate changelog review. Documented in-file via comment cross-referencing CLAUDE.md.
- **`#![forbid(unsafe_code)]`** workspace-wide. `cli/` already pure-safe — Task 2's `fs2::FileExt::try_lock_exclusive` is fully safe Rust (the lower-level `flock(2)` lives inside `fs2`).
- **`#[allow(dead_code)]` on `ExitCode` / `from_sync_error`** lifts when Task 5 (pipeline) consumes them. If Task 5 ships without removing the allow, the lint hides a regression. Reviewer for the Task 5 PR should grep for `allow(dead_code)` in `cli/src/exit.rs` and require it removed.

### Issues currently open (unchanged from C.2 design close)

- #37 — Sub-project C umbrella. C.2 Task 1 ✅ in this PR.
- #38, #45, #75, #76, #78, #79, #81, #87, #88, #90, #95, #98 — none block C.2 Task 2.

### Housekeeping note (stale worktrees on disk)

Three worktrees on disk locally after Task 1:
- `/Users/hherb/src/secretary` — `main` (clean).
- `/Users/hherb/src/secretary/.worktrees/c1-1b-sync-merge` — branch `feature/c1-1b-task-17`, remote gone (carried over from C.1.1b session). Safe to remove via `git worktree remove .worktrees/c1-1b-sync-merge && git branch -D feature/c1-1b-task-17`.
- `/Users/hherb/src/secretary/.worktrees/c2-task-1-spec` — branch `feature/c2-task-1-spec`, also remote-gone after PR #111 merged. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-1` — **this session's work**; keep until PR merges, then remove.

Cleanup is one-line each and does NOT block Task 2.

## (4) Exact commands to resume

```bash
# After this C.2 Task 1 PR (feature/c2-task-1) merges:
cd /Users/hherb/src/secretary
git fetch --prune origin
git status --short                       # expect: clean (modulo NEXT_SESSION.md sync, see below)
git checkout main
git pull --ff-only origin main

# Verify gauntlet on fresh main (expect 813 / 0 / 10 — same as session close):
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3

# Start Task 2:
git worktree add .worktrees/c2-task-2 -b feature/c2-task-2 main
cd .worktrees/c2-task-2

# Open the plan and follow Task 2 line-by-line:
#   docs/superpowers/plans/2026-05-23-c2-headless-sync-cli.md §"Task 2"
# Steps 1-5 cover the full scaffold + commit + PR.
```

## Closing inventory

- **Branch state on close:** `main` at `6863523` (PR #111 squash-merged). `feature/c2-task-1` carries 1 commit on top.
- **Workspace tests on `feature/c2-task-1`:** 813 passed + 10 ignored (800 base + 13 new cli unit tests — 4 in `args.rs`, 9 in `exit.rs`). Clippy + fmt + Python conformance + spec freshness all clean.
- **README.md:** unchanged this session — Task 1 ships a scaffold, no user-visible behavior. Plan defers README update to Task 10.
- **ROADMAP.md:** unchanged this session — same reason; ROADMAP already calls C.2 "queued" since the C.2 design PR.
- **CLAUDE.md:** unchanged this session — the dependency-pin discipline noted in `cli/Cargo.toml` is a cross-reference, not a new convention.
- **NEXT_SESSION.md:** symlink retargeted to this file.
- **Open issues:** see §(3) — none block Task 2.
- **Open PRs:** one to be opened at end of this session (C.2 Task 1).
- **Worktrees on disk:** see §(3) housekeeping.
- **Frozen baton snapshots:** all 18 prior C.1.1b + C.2-design handoffs at [`docs/handoffs/`](.) — preserved unchanged.
- **This file:** the live baton for C.2 Task 1 close.
