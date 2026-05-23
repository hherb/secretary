# NEXT_SESSION.md — C.2 Task 2 (state persistence + host-local lockfile) shipped

**Session date:** 2026-05-23 (C.2 Task 2 — `cli/src/state.rs`: SyncState CBOR persistence + per-vault flock-based lockfile).
**Status:** C.2 Task 2 ✅ on branch `feature/c2-task-2`; PR pending. Tasks 3-10 queued.

## (1) What we shipped this session

A single commit on `feature/c2-task-2` carrying the second code slice of C.2 — the per-vault state-file + lockfile primitives that subsequent tasks consume.

| Artifact | Path | Notes |
|---|---|---|
| State module | [`cli/src/state.rs`](../../cli/src/state.rs) | New, ~230 LOC. `canonical_hex` / `state_file_path` / `lock_file_path` / `default_state_dir` (pure helpers). `load` (single-syscall `fs::read` with `ErrorKind::NotFound` → empty-state; vault-UUID mismatch typed error). `save` (atomic via `tempfile::NamedTempFile::persist`, same `=3.27.0` pin). `LockfileGuard` RAII type via `fs4::FileExt::try_lock` UFCS form. 11 unit tests. |
| CLI entry point | [`cli/src/main.rs`](../../cli/src/main.rs) | One-line change: `mod state;` registered alongside the existing `mod args; mod exit;`. |
| Crate manifest | [`cli/Cargo.toml`](../../cli/Cargo.toml) | `fs4` comment updated to reflect the actual API used (`FileExt::try_lock`) + the MSRV rationale for keeping the dep instead of switching to stdlib's stabilized `File::try_lock`. |

Commits:
- `b8d3c0a` — "C.2 Task 2 — state persistence + host-local lockfile" (initial slice).
- *(this commit)* — post-review touch-up: tighten `load` to a single-syscall `fs::read` with `ErrorKind::NotFound` (closes a benign TOCTOU window where `Path::exists` could race a non-`secretary-sync` deleter, since the per-vault lockfile only excludes our own binary). Adds one new test (`load_corrupt_bytes_returns_decode_error`) exercising the `StateError::Decode` arm directly. Workspace 823 → 824.

A third nit from review — switching `canonical_hex` to the `hex` crate — was checked-and-skipped: `core/Cargo.toml` declares `hex` only under `[dev-dependencies]`; runtime hex sites in `core` (`identity/fingerprint.rs::hex_form`, `unlock/vault_toml.rs::hex_nibble`) hand-roll the encoding. The current `canonical_hex` follows the established convention.

### Plan ↔ reality reconciliations

Three deliberate deviations from the plan, all noted in the commit message + PR body:

| Plan note | Reality | Resolution |
|---|---|---|
| `SyncState::to_cbor_bytes` / `from_cbor_bytes` | Actual API: `to_canonical_cbor` / `from_canonical_cbor` ([`core/src/sync/state.rs:87`](../../core/src/sync/state.rs#L87) / [`core/src/sync/state.rs:132`](../../core/src/sync/state.rs#L132)) | Used the actual method names. No plan amendment needed — the names are equivalent in intent. |
| `fs4::fs_std::FileExt::try_lock_exclusive` | fs4 1.x reorganized: the trait is `fs4::FileExt` (re-exported at crate root, no `fs_std` module); the exclusive try-variant is `try_lock()` returning `Result<(), fs4::TryLockError>` | Plan explicitly flagged this verification as required at impl time. Code uses `fs4::{FileExt as Fs4FileExt, TryLockError}` + UFCS call (`Fs4FileExt::try_lock(&file)`) because stdlib 1.89 stabilized an inherent `File::try_lock` that shadows the trait method (workspace MSRV is 1.87, so we can't rely on the stdlib form). |
| "9 new tests" / target PASSED: 822 | Actual: **10 new tests** / **PASSED: 823** | Plan body listed 10 tests but the prose count said 9 — same arithmetic-off-by-one as Task 1 (where 13 vs 12 was reconciled the same way). No plan amendment; Task 3 baseline becomes "823" by ship reality. |

### Gauntlet snapshot at session close

```
PASSED: 824 FAILED: 0 IGNORED: 10
clippy --release --workspace --tests -- -D warnings   clean
fmt --all -- --check                                  clean
uv run core/tests/python/conformance.py               PASS
uv run core/tests/python/spec_test_name_freshness.py  PASS (96 resolved / 0 unresolved / 2 suppressed)
```

(`fmt` ran once with `--check` and surfaced a single re-wrap on a long
`expect("...")` line in a test; `cargo fmt --all` applied it before commit.)

## (2) What's next — start C.2 Task 3

After this PR merges, the next slice is **C.2 Task 3: Unlock module** ([`docs/superpowers/plans/2026-05-23-c2-headless-sync-cli.md`](../superpowers/plans/2026-05-23-c2-headless-sync-cli.md) §"Task 3").

### Acceptance criteria for Task 3

- [ ] New `cli/src/unlock.rs` (~180 LOC) with the following surface:
  - `PasswordSource<'a, R: Read>` enum (`Tty` / `Stream(&'a mut R)`).
  - `read_password_from_reader<R: Read>(reader: &mut R) -> Result<SecretBytes, UnlockReadError>` — strips one trailing `\n` or `\r\n`; empty after strip → `UnlockReadError::Empty`.
  - `UnlockReadError` enum: `NonInteractiveWithoutStdin`, `Io(#[from] io::Error)`, `Empty`.
  - TTY path uses `rpassword::prompt_password(PASSWORD_PROMPT)`; stream path uses the pure-function helper above.
- [ ] `cli/src/main.rs` gains `mod unlock;`.
- [ ] N unit tests cover: roundtrip from `Cursor<Vec<u8>>`, trailing `\n` strip, trailing `\r\n` strip, empty-after-strip returns `Empty`, no-trailing-newline preserved verbatim. Plan text says "5 tests"; per Task 2's reconciliation pattern, the actual count may float by ±1 depending on body vs prose.
- [ ] Gauntlet target: **PASSED: 824 + N FAILED: 0 IGNORED: 10**. Absolute base is now 824 (not the plan's 821/822) — bumped from 823 by the post-review `load_corrupt_bytes_returns_decode_error` test.
- [ ] Clippy, fmt, conformance, spec freshness all clean.

### Plan handoff

Full step-by-step in [`docs/superpowers/plans/2026-05-23-c2-headless-sync-cli.md`](../superpowers/plans/2026-05-23-c2-headless-sync-cli.md) §"Task 3", which still applies — Task 2's three reconciliations do not affect Task 3's surface (unlock is a separate module with no dep on state.rs).

## (3) Open decisions and risks

### Decisions settled during this session

- **fs4 dep retained, not swapped for stdlib `File::try_lock`.** Stdlib stabilized the inherent method in Rust 1.89, but our workspace `rust-version = "1.87"` is below that. Switching to stdlib would force a workspace MSRV bump, which is a meaningfully larger change than this task's scope. The fs4 trait call uses UFCS (`Fs4FileExt::try_lock(&file)`) to remain unambiguous on any toolchain ≥ 1.87. If a future task wants to revisit MSRV, fs4 can be dropped in one line at that point.
- **`StateError::VaultUuidMismatch` carries both hex strings (`file_uuid_hex` + `expected_uuid_hex`)**, not just the typed variant — so the displayed error gives operators enough context to identify which file is wrong without re-running with extra logging. Costs ~32 chars per error; negligible. Tested by `load_wrong_uuid_returns_mismatch_error`.
- **`LockfileGuard` derives `Debug`** — required so the test `assert!(matches!(err, StateError::LockfileHeld(_)))` compiles via `unwrap_err()`. Holds a `File` (which itself derives `Debug`) + a `PathBuf`; no secrets.

### Decisions carried forward (unchanged from C.2 Task 1 close)

- D1-D10 from the spec are still settled.
- `--veto-policy=fail`, `--decisions-file`, `--exit-on-error`, `status`, `init` subcommands all deferred to future C.2.x slices.
- Windows is best-effort per D10 (no CI runner planned for C.2 implementation).
- Clean-room conformance harness for `cli/` deferred to C.4 or a future C.2.x slice.
- The `from_sync_error` mapper's exit-code surface (Task 1 design): every `SyncError` variant without a dedicated code maps to `GenericError = 1`; bijection-failure variants (`UnknownVetoDecision` / `MissingVetoDecision` / `EmptyDraftWithVetoes`) do NOT get distinct codes because they indicate CLI bugs, not operator-recoverable conditions.

### Risks carried into Task 3

- **`#[allow(dead_code)]` on `StateError` / `load` / `save` / `LockfileGuard`** lifts when Task 5 (pipeline) consumes them. Tracked at issue [#113](https://github.com/hherb/secretary/issues/113) alongside the Task 1 `ExitCode` / `from_sync_error` allowances; the `TODO(#113):` markers in `cli/src/state.rs` annotate every suppression site.
- **`tempfile = "=3.27.0"` exact pin** is in `cli/Cargo.toml` already (added in Task 1). Task 2's `save()` is the first consumer in `cli/`. Same discipline as `core` — bump only via deliberate changelog review.
- **No `cli/` integration tests yet.** Task 2 ships unit tests only, which exercise the I/O paths via `tempfile::TempDir`. End-to-end CLI testing arrives in Task 10's `assert_cmd`-driven `cli/tests/once_integration.rs`.

### Issues currently open

- #37 — Sub-project C umbrella. C.2 Tasks 1-2 ✅ in PRs #112 and (pending #).
- #113 — C.2 Task 5 cleanup checklist (filed during Task 1 PR review): lift `#[allow(dead_code)]` in `cli/src/exit.rs` + `cli/src/state.rs`, and add `--non-interactive` ↔ `--password-stdin` validation. Task 2 added more allowances under the same TODO(#113) marker — same cleanup obligation.
- #38, #45, #75, #76, #78, #79, #81, #87, #88, #90, #95, #98 — none block C.2 Task 3.

### Housekeeping note (stale worktrees on disk)

After this PR:
- `/Users/hherb/src/secretary` — `main` (clean post-merge).
- `/Users/hherb/src/secretary/.worktrees/c1-1b-sync-merge` — branch `feature/c1-1b-task-17`, remote gone. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-1-spec` — branch `feature/c2-task-1-spec`, remote gone. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-1` — branch `feature/c2-task-1`, remote gone after PR #112 merged. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-2` — **this session's work**; keep until PR merges, then remove.

```bash
# One-line each (run from /Users/hherb/src/secretary):
git worktree remove .worktrees/c1-1b-sync-merge && git branch -D feature/c1-1b-task-17
git worktree remove .worktrees/c2-task-1-spec   && git branch -D feature/c2-task-1-spec
git worktree remove .worktrees/c2-task-1        && git branch -D feature/c2-task-1
```

Cleanup is one-line each and does NOT block Task 3.

## (4) Exact commands to resume

```bash
# After this C.2 Task 2 PR (feature/c2-task-2) merges:
cd /Users/hherb/src/secretary
git fetch --prune origin
git status --short                       # expect: clean (modulo NEXT_SESSION.md sync, see below)
git checkout main
git pull --ff-only origin main

# Verify gauntlet on fresh main (expect 824 / 0 / 10 — same as session close):
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3

# Start Task 3:
git worktree add .worktrees/c2-task-3 -b feature/c2-task-3 main
cd .worktrees/c2-task-3

# Open the plan and follow Task 3 line-by-line:
#   docs/superpowers/plans/2026-05-23-c2-headless-sync-cli.md §"Task 3"
# Steps 1-5 cover the full scaffold + commit + PR.
```

## Closing inventory

- **Branch state on close:** `main` at `968aee1` (PR #112 squash-merged). `feature/c2-task-2` carries 1 commit (`b8d3c0a`) on top.
- **Workspace tests on `feature/c2-task-2`:** 824 passed + 10 ignored (813 base + 11 new cli `state` unit tests; the 11th is `load_corrupt_bytes_returns_decode_error`, added during post-review touch-up). Clippy + fmt + Python conformance + spec freshness all clean.
- **README.md:** unchanged this session — Task 2 ships internal scaffolding (state/lockfile primitives), no user-visible behavior. Plan defers README update to Task 10.
- **ROADMAP.md:** unchanged this session — same reason; ROADMAP already calls C.2 "queued" since the C.2 design PR.
- **CLAUDE.md:** unchanged this session — the `tempfile` exact-pin discipline noted in `cli/Cargo.toml` is a cross-reference, not a new convention.
- **NEXT_SESSION.md:** symlink retargeted to this file.
- **Open issues:** see §(3) — none block Task 3.
- **Open PRs:** one to be opened at end of this session (C.2 Task 2).
- **Worktrees on disk:** see §(3) housekeeping.
- **Frozen baton snapshots:** all 19 prior C.1.1b + C.2-design + C.2-task-1 handoffs at [`docs/handoffs/`](.) — preserved unchanged.
- **This file:** the live baton for C.2 Task 2 close.
