# NEXT_SESSION.md — C.2 Task 3 (unlock module) shipped

**Session date:** 2026-05-23 (C.2 Task 3 — `cli/src/unlock.rs`: `PasswordSource` enum + reader/TTY password sourcing).
**Status:** C.2 Task 3 ✅ on branch `feature/c2-task-3`; PR pending. Tasks 4-10 queued.

## (1) What we shipped this session

A single commit on `feature/c2-task-3` carrying the third code slice of C.2 — the password-sourcing primitives. The TTY path is a thin `rpassword` wrapper; the `--password-stdin` path is a pure-function (`Cursor`-testable) reader. Both funnel bytes into a freshly allocated [`SecretBytes`] via [`SecretBytes::new`], moving ownership of the underlying allocation so the password never lingers in an unzeroized location after the function returns.

| Artifact | Path | Notes |
|---|---|---|
| Unlock module | [`cli/src/unlock.rs`](../../cli/src/unlock.rs) | New, ~200 LOC. `UnlockReadError` (3 variants: `NonInteractiveWithoutStdin`, `Io`, `Empty`). `PasswordSource<'a, R: Read>` enum (`Tty` / `Stream(&mut R)`). `read_password_from_reader<R: Read>(&mut R) -> Result<SecretBytes, _>` strips exactly one `\n` or `\r\n`, returns `Empty` if the remainder is empty. `read_password_from_tty() -> Result<SecretBytes, _>` calls `rpassword::prompt_password("Vault password: ")`. 9 unit tests. |
| CLI entry point | [`cli/src/main.rs`](../../cli/src/main.rs) | One-line change: `mod unlock;` registered alongside the existing `mod args; mod exit; mod state;`. |

Commits:
- *(this commit)* — "C.2 Task 3 — unlock module: TTY + stdin password sourcing" on `feature/c2-task-3`.

### Plan ↔ reality reconciliations

Three deliberate deviations from the plan, all noted in the commit body:

| Plan note | Reality | Resolution |
|---|---|---|
| `SecretBytes::from(buf.as_slice())` + `zeroize::Zeroize::zeroize(&mut buf)` | `SecretBytes::new(buf)` (ownership move) | The plan's pattern would have required adding `zeroize` as a direct dep of `cli/Cargo.toml` AND double-allocated (`From<&[u8]>` calls `bytes.to_vec()`). `SecretBytes::new(Vec<u8>)` takes ownership of the original allocation; the `ZeroizeOnDrop` derive on `SecretBytes` wipes the entire `capacity` slice on drop, including bytes past `len` (e.g. the popped trailing-newline byte). Single allocation, no new dep, aligned with CLAUDE.md §"Memory hygiene: zeroize discipline". |
| `cargo test -p secretary-cli --lib unlock` | `cargo test -p secretary-cli unlock` | `cli/` is binary-only (`[[bin]]` in `Cargo.toml`, no `lib.rs`). The `--lib` filter errors with "no library targets found in package `secretary-cli`". Drop the filter; cargo runs the binary's unit tests by default. |
| "5 tests" (plan prose) / "N unit tests" (acceptance) | **9 unit tests** / **PASSED: 833** | Two additional edge-case tests beyond the plan body: `reader_lone_cr_is_preserved` (lone `\r` is NOT stripped — only `\r\n`) and `reader_crlf_only_errors_as_empty` (a bare `\r\n` reduces to empty). These close the line-ending strip's branch coverage. Same `±1` reconciliation pattern as Tasks 1 and 2. |

### Gauntlet snapshot at session close

```
PASSED: 833 FAILED: 0 IGNORED: 10
clippy --release --workspace --tests -- -D warnings   clean
fmt --all -- --check                                  clean
uv run core/tests/python/conformance.py               PASS
uv run core/tests/python/spec_test_name_freshness.py  PASS (96 resolved / 0 unresolved / 2 suppressed)
```

(`fmt --check` initially flagged a long `#[allow(dead_code)] // TODO(...):` line that rustfmt rewrapped onto two lines splitting the attribute from the next `#[derive(...)]`. Tightened the TODO comment to the brief form `// TODO(#113): consumed by Task 5 pipeline.` to match the state.rs convention; `fmt --check` then re-ran clean.)

## (2) What's next — start C.2 Task 4

After this PR merges, the next slice is **C.2 Task 4: Veto trait + non-interactive + interactive impls** ([`docs/superpowers/plans/2026-05-23-c2-headless-sync-cli.md`](../superpowers/plans/2026-05-23-c2-headless-sync-cli.md) §"Task 4").

### Acceptance criteria for Task 4

- [ ] New `cli/src/veto/mod.rs` (~60 LOC):
  - `VetoUx` trait with `fn decide(&mut self, vetoes: &[RecordTombstoneVeto]) -> Vec<VetoDecision>`.
  - `pub mod interactive;` + `pub mod noninteractive;`.
- [ ] New `cli/src/veto/noninteractive.rs` (~70 LOC):
  - `AutoKeepLocalVetoUx` unit struct, `impl VetoUx` returning `Vec<VetoDecision::KeepLocal>` preserving order.
  - 2 unit tests (empty input, multi-veto preservation of `record_id` order).
- [ ] New `cli/src/veto/interactive.rs` (~140 LOC):
  - `TtyVetoUx<R: BufRead, W: Write>` generic over reader/writer for testability.
  - Prompts per-record `y/n`; empty line = `KeepLocal` (safe default); invalid input re-prompts.
  - Scripted-reader tests covering `y`, `n`, empty, invalid+re-prompt.
- [ ] `cli/src/main.rs` gains `mod veto;`.
- [ ] Gauntlet target: **PASSED: 833 + N FAILED: 0 IGNORED: 10**. Absolute base is now 833 (bumped from 824 by Task 3's 9 new tests).
- [ ] Clippy, fmt, conformance, spec freshness all clean.

### Plan handoff

Full step-by-step in [`docs/superpowers/plans/2026-05-23-c2-headless-sync-cli.md`](../superpowers/plans/2026-05-23-c2-headless-sync-cli.md) §"Task 4", which still applies — Task 3's three reconciliations do not affect Task 4's surface (veto is a separate module tree with no dep on unlock.rs).

## (3) Open decisions and risks

### Decisions settled during this session

- **`SecretBytes::new(buf)` over `SecretBytes::from(slice) + zeroize`.** Take ownership of the `Vec<u8>` once; `ZeroizeOnDrop` on `SecretBytes` wipes the entire backing slice (including bytes past `len`, e.g. the popped newline) when the wrapper drops. Avoids the double allocation and the direct `zeroize` dep in `cli/Cargo.toml`. Same pattern adopted for the TTY path: `String::into_bytes()` moves the inner `Vec<u8>` out of `rpassword`'s returned `String`.
- **Lone `\r` is NOT stripped.** Only `\r\n` (and `\n`) count as a line ending. A bare `\r` is preserved verbatim — protects passwords that legitimately end in `\r`. Tested by `reader_lone_cr_is_preserved`.
- **Empty stdin → typed `Empty` error, not silent empty password.** Bare `\n` and `\r\n` also reduce to empty after strip and return `Empty`. Surfaces the "you forgot to pipe a password" mistake at the read site instead of downstream as a less obvious unlock failure. Tested by three separate cases.
- **TTY prompt constant is `"Vault password: "`** — trailing space intentional since `rpassword::prompt_password` does not append one.

### Decisions carried forward (unchanged from C.2 Task 2 close)

- D1-D10 from the spec are still settled.
- `--veto-policy=fail`, `--decisions-file`, `--exit-on-error`, `status`, `init` subcommands all deferred to future C.2.x slices.
- Windows is best-effort per D10 (no CI runner planned for C.2 implementation).
- Clean-room conformance harness for `cli/` deferred to C.4 or a future C.2.x slice.
- The `from_sync_error` mapper's exit-code surface (Task 1): every `SyncError` variant without a dedicated code maps to `GenericError = 1`; bijection-failure variants do NOT get distinct codes (CLI bugs, not operator-recoverable).
- fs4 dep retained over stdlib `File::try_lock` until workspace MSRV bumps past 1.89.

### Risks carried into Task 4

- **`#[allow(dead_code)]` on `UnlockReadError` / `PasswordSource` / `read_password_from_reader` / `read_password_from_tty`** lifts when Task 5 (pipeline) consumes them. Tracked at issue [#113](https://github.com/hherb/secretary/issues/113) alongside the Task 1 `ExitCode` / `from_sync_error` and Task 2 `state.rs` allowances; all share the same `TODO(#113): consumed by Task 5 pipeline.` marker form.
- **`UnlockReadError::NonInteractiveWithoutStdin` is constructed by no code yet.** It's the typed error Task 5's `--non-interactive ↔ --password-stdin` flag validation will return. Same `#[allow(dead_code)]` umbrella as the rest of the enum. Issue #113 will lift it.
- **No `cli/` integration tests yet.** Task 3 ships unit tests only. End-to-end CLI testing (via `assert_cmd`) arrives in Task 10's `cli/tests/once_integration.rs`.

### Issues currently open

- #37 — Sub-project C umbrella. C.2 Tasks 1-3 ✅ in PRs #112, #114, and (pending #).
- #113 — C.2 Task 5 cleanup checklist: lift `#[allow(dead_code)]` in `cli/src/exit.rs`, `cli/src/state.rs`, and now `cli/src/unlock.rs`; add `--non-interactive` ↔ `--password-stdin` validation. Task 3 added more allowances under the same TODO(#113) marker — same cleanup obligation.
- #38, #45, #75, #76, #78, #79, #81, #87, #88, #90, #95, #98 — none block C.2 Task 4.

### Housekeeping note (stale worktrees on disk)

After this PR:
- `/Users/hherb/src/secretary` — `main` (clean post-merge).
- `/Users/hherb/src/secretary/.worktrees/c1-1b-sync-merge` — branch `feature/c1-1b-task-17`, remote gone. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-1-spec` — branch `feature/c2-task-1-spec`, remote gone. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-1` — branch `feature/c2-task-1`, remote gone. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-2` — branch `feature/c2-task-2`, remote gone after PR #114 merged. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-3` — **this session's work**; keep until PR merges, then remove.

```bash
# One-line each (run from /Users/hherb/src/secretary):
git worktree remove .worktrees/c1-1b-sync-merge && git branch -D feature/c1-1b-task-17
git worktree remove .worktrees/c2-task-1-spec   && git branch -D feature/c2-task-1-spec
git worktree remove .worktrees/c2-task-1        && git branch -D feature/c2-task-1
git worktree remove .worktrees/c2-task-2        && git branch -D feature/c2-task-2
```

Cleanup is one-line each and does NOT block Task 4.

## (4) Exact commands to resume

```bash
# After this C.2 Task 3 PR (feature/c2-task-3) merges:
cd /Users/hherb/src/secretary
git fetch --prune origin
git status --short                       # expect: clean (modulo NEXT_SESSION.md sync, see below)
git checkout main
git pull --ff-only origin main

# Verify gauntlet on fresh main (expect 833 / 0 / 10 — same as session close):
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3

# Start Task 4:
git worktree add .worktrees/c2-task-4 -b feature/c2-task-4 main
cd .worktrees/c2-task-4

# Open the plan and follow Task 4 line-by-line:
#   docs/superpowers/plans/2026-05-23-c2-headless-sync-cli.md §"Task 4"
# Steps 1-5 cover the full scaffold + commit + PR.
```

## Closing inventory

- **Branch state on close:** `main` at `e6c9d4f` (PR #114 squash-merged). `feature/c2-task-3` carries 1 commit on top.
- **Workspace tests on `feature/c2-task-3`:** 833 passed + 10 ignored (824 base + 9 new cli `unlock` unit tests). Clippy + fmt + Python conformance + spec freshness all clean.
- **README.md:** unchanged this session — Task 3 ships internal scaffolding (password-sourcing primitives), no user-visible behavior. Plan defers README update to Task 10.
- **ROADMAP.md:** unchanged this session — same reason; ROADMAP already calls C.2 "queued" since the C.2 design PR.
- **CLAUDE.md:** unchanged this session — the zeroize-discipline note (Task 3's `SecretBytes::new(buf)` ownership-move pattern) is already in CLAUDE.md's "Memory hygiene: zeroize discipline" section; no new convention.
- **NEXT_SESSION.md:** symlink retargeted to this file.
- **Open issues:** see §(3) — none block Task 4.
- **Open PRs:** one to be opened at end of this session (C.2 Task 3).
- **Worktrees on disk:** see §(3) housekeeping.
- **Frozen baton snapshots:** all 20 prior C.1.1b + C.2-design + C.2-task-1/2 handoffs at [`docs/handoffs/`](.) — preserved unchanged.
- **This file:** the live baton for C.2 Task 3 close.
