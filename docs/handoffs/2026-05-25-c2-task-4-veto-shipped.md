# NEXT_SESSION.md — C.2 Task 4 (veto UX) shipped

**Session date:** 2026-05-25 (C.2 Task 4 — `cli/src/veto/`: `VetoUx` trait + non-interactive (`AutoKeepLocalVetoUx`) + interactive (`TtyVetoUx`) impls).
**Status:** C.2 Task 4 ✅ on branch `feature/c2-task-4`; PR pending. Tasks 5-10 queued.

## (1) What we shipped this session

One commit on `feature/c2-task-4` carrying the fourth code slice of C.2 — the veto-adjudication strategy layer. `prepare_merge` returns `Vec<RecordTombstoneVeto>` for the records where a peer would tombstone something the local side has live; `commit_with_decisions` needs that resolved to `Vec<VetoDecision>` preserving the `record_id ↔ record_id` bijection. The CLI dispatches the two operational modes (`--non-interactive` headless vs. default interactive TTY) through one trait so the upcoming pipeline (Task 5) consumes either via `&mut dyn VetoUx` without ordering churn.

| Artifact | Path | Notes |
|---|---|---|
| Veto module root | [`cli/src/veto/mod.rs`](../../cli/src/veto/mod.rs) | New, 39 LOC. `pub trait VetoUx { fn decide(&mut self, vetoes: &[RecordTombstoneVeto]) -> Vec<VetoDecision> }`. Object-safe (the pipeline will hold it as `&mut dyn VetoUx`). `pub mod interactive` + `pub mod noninteractive`. |
| Non-interactive impl | [`cli/src/veto/noninteractive.rs`](../../cli/src/veto/noninteractive.rs) | New, 81 LOC. `pub struct AutoKeepLocalVetoUx` (unit struct, stateless). `impl VetoUx` maps every veto → `VetoDecision::KeepLocal { record_id: v.record_id }` preserving slice order. 2 unit tests: empty-input no-op, multi-veto order preservation. Spec §D4 safe default. |
| Interactive impl | [`cli/src/veto/interactive.rs`](../../cli/src/veto/interactive.rs) | New, 236 LOC. `pub struct TtyVetoUx<R: BufRead, W: Write>` generic over reader/writer so tests drive the prompt via `Cursor` without a real TTY (production wires `stdin().lock()` + `stderr().lock()`). Per-veto `y/Y/yes` → `KeepLocal`, `n/N/no` → `AcceptTombstone`, empty line → `KeepLocal` (documented safe default), invalid input → re-prompt with `(please answer y or n)` hint. I/O read error mid-reply also lands on `KeepLocal` (irreversibility argument — see (3) below). 11 unit tests covering all six reply forms + EOF + invalid+re-prompt + hint inspection + multi-veto bijection + empty-slice no-op. |
| CLI entry point | [`cli/src/main.rs`](../../cli/src/main.rs) | One-line change: `mod veto;` registered alongside the existing `mod args; mod exit; mod state; mod unlock;`. |

Commits:
- *(this commit)* — "C.2 Task 4 — veto UX trait + non-interactive + interactive impls" on `feature/c2-task-4`. 13 new unit tests; workspace 836 → 849.

### Plan ↔ reality reconciliations

Three deliberate deviations from the plan, all noted in the commit body:

| Plan note | Reality | Resolution |
|---|---|---|
| `"Record {} would be tombstoned by peer. Keep local? [y/n]"` (plan prompt) | `"Record {} would be tombstoned by peer. Keep local? [y/n] (empty = KeepLocal)"` | Surfacing the safe default in the prompt itself: spec §D4 makes empty-input → `KeepLocal` policy-significant, so a user who doesn't read the spec sees the consequence next to the question. Pure UX; no semantics change. The hint string is parameterised by a `DEFAULT_DECISION_LABEL` constant for a single source of truth across the prompt and the doc comment. |
| Plan acceptance: 7 unit tests; workspace 828 → 835. | **13 unit tests; workspace 836 → 849.** | Plan baseline (828) predates Task 3's +12. Beyond the plan's 5 happy-path interactive tests + 2 noninteractive: `scripted_uppercase_y_returns_keep_local`, `scripted_word_yes_returns_keep_local`, `scripted_word_no_returns_accept_tombstone` (close the `[y/Y/yes]` / `[n/N/no]` synonym branches each as their own test rather than implicit-only), `scripted_eof_with_no_input_defaults_to_keep_local` (`Ok(0)` from `read_line` reaches the empty-line branch), `invalid_input_reprompt_writes_hint_to_writer` (asserts the `(please answer y or n)` hint actually flushes to the writer — branch coverage that the plan's pass/fail tests skip), `empty_veto_slice_returns_empty_without_touching_io` (boundary: zero-element loop must not write any prompts). Same `±N` reconciliation pattern as Tasks 1–3. |
| `cargo test --release -p secretary-cli --lib veto` | `cargo test --release -p secretary-cli veto` | `cli/` is binary-only (no `lib.rs`). The `--lib` filter errors with "no library targets found". Drop the filter; cargo runs the binary's unit tests by default. Same correction as Task 3. |

### Gauntlet snapshot at session close

```
PASSED: 849 FAILED: 0 IGNORED: 10
clippy --release --workspace --tests -- -D warnings   clean
fmt --all -- --check                                  clean
uv run core/tests/python/conformance.py               PASS
uv run core/tests/python/spec_test_name_freshness.py  PASS (96 resolved / 0 unresolved / 2 suppressed)
```

## (2) What's next — start C.2 Task 5

After this PR merges, the next slice is **C.2 Task 5: Pipeline (`cli/src/pipeline.rs`) — one sync attempt** ([`docs/superpowers/plans/2026-05-23-c2-headless-sync-cli.md`](../superpowers/plans/2026-05-23-c2-headless-sync-cli.md) §"Task 5").

### Acceptance criteria for Task 5

- [ ] New `cli/src/pipeline.rs` (~320 LOC):
  - `pub fn run_one(identity: &UnlockedIdentity, password: &SecretBytes, state: &mut SyncState, vault_folder: &Path, ux: &mut dyn VetoUx, now_ms: u64) -> Result<RunOutcome, PipelineError>`.
  - Calls `sync_once`, dispatches the returned outcome (NoChange / OurWriteOnly / TheirsOnly / Concurrent), invokes `prepare_merge` + the `VetoUx::decide` adjudication + `commit_with_decisions` on the concurrent path, and updates `SyncState` in place.
  - `RunOutcome` enum the caller logs + maps to `ExitCode` (the `from_sync_error` mapper in `cli/src/exit.rs` already handles error → code).
  - Lifts the `#[allow(dead_code)]` on `cli/src/exit.rs`, `cli/src/state.rs`, `cli/src/unlock.rs`, and `cli/src/veto/` items it consumes (this is the umbrella deletion #113 has been queuing up).
- [ ] New `cli/src/main.rs` registers `mod pipeline;`.
- [ ] Add `--non-interactive` ↔ `--password-stdin` flag-pair validation at the args-parse layer (the typed-error site for `UnlockReadError::NonInteractiveWithoutStdin`).
- [ ] Pipeline-level unit tests: each outcome variant + each veto policy + state-update side effects + the no-op happy paths. Plan expects ~15-20 new tests.
- [ ] Gauntlet target: **PASSED: 849 + N FAILED: 0 IGNORED: 10**. Absolute base is now 849 (bumped from 836 by Task 4's 13 new tests).
- [ ] Clippy, fmt, conformance, spec freshness all clean.

### Plan handoff

Full step-by-step in [`docs/superpowers/plans/2026-05-23-c2-headless-sync-cli.md`](../superpowers/plans/2026-05-23-c2-headless-sync-cli.md) §"Task 5", which still applies — Task 4's three reconciliations do not affect Task 5's surface (pipeline orchestrates the modules; the trait API is what the plan specified).

## (3) Open decisions and risks

### Decisions settled during this session

- **Object-safe `VetoUx` trait** so the pipeline can choose the impl at runtime behind `&mut dyn VetoUx`. No associated types, no generic methods. The trait method takes `&mut self` so `TtyVetoUx` can mutate its reader/writer through the same handle.
- **Empty input → `KeepLocal`** (interactive) is policy-significant per spec §D4 and is now surfaced in the prompt itself (`(empty = KeepLocal)`). A user who didn't read the spec still sees what hitting Enter will do.
- **I/O read error mid-reply → `KeepLocal`.** Reasoning: `AcceptTombstone` is irreversible (the record is gone on the next commit); `KeepLocal` is recoverable (operator re-runs and sees the same prompt). With the trait method returning `Vec<VetoDecision>` (not `Result<...>`), the only places to absorb a read failure are panic, escalate via re-design, or fall back to the safe default. The plan picked the safe default and this implementation preserves it; see the `DEFAULT_DECISION_LABEL` constant + module-doc comment for the in-source justification.
- **Per-veto reply parsing is loop-local.** `let mut line = String::new();` is declared INSIDE the inner re-prompt `loop`, so a fresh buffer is allocated each re-prompt — `read_line` appends, so reusing the buffer across re-prompts would corrupt the next reply. Tested by `invalid_input_reprompts_then_accepts_valid` (b"maybe\ny\n" → first read gets "maybe\n", re-prompt buffer is fresh, second read gets "y\n").
- **TtyVetoUx is generic over `BufRead + Write`** (not just `Read + Write`) because `read_line` is on `BufRead`. Production callers wrap `stdin().lock()` in `BufReader` first.

### Decisions carried forward (unchanged from Task 3 close)

- D1-D10 from the spec are still settled.
- `--veto-policy=fail`, `--decisions-file`, `--exit-on-error`, `status`, `init` subcommands all deferred to future C.2.x slices.
- Windows is best-effort per D10 (no CI runner planned for C.2 implementation).
- Clean-room conformance harness for `cli/` deferred to C.4 or a future C.2.x slice.
- The `from_sync_error` mapper's exit-code surface (Task 1): every `SyncError` variant without a dedicated code maps to `GenericError = 1`; bijection-failure variants do NOT get distinct codes (CLI bugs, not operator-recoverable).
- fs4 dep retained over stdlib `File::try_lock` until workspace MSRV bumps past 1.89.
- `SecretBytes::new(buf)` over `SecretBytes::from(slice) + zeroize` for owned-buffer unlock paths (Task 3 — still in force).

### Risks carried into Task 5

- **`#[allow(dead_code)]` on `VetoUx` / `AutoKeepLocalVetoUx` / `TtyVetoUx` / `TtyVetoUx::new`** lifts when Task 5 (pipeline) consumes them. Tracked at issue [#113](https://github.com/hherb/secretary/issues/113) alongside the Task 1/2/3 allowances; all share the `TODO(#113): consumed by Task 5 pipeline.` marker form.
- **`AcceptTombstone` codepath in `TtyVetoUx` only fires on explicit `n`/`N`/`no` input.** Any future change to "default the policy" must be conscious of the irreversibility — record loss is permanent. The `DEFAULT_DECISION_LABEL` constant + module-doc comment together encode this invariant.
- **No `cli/` integration tests yet.** Task 4 ships unit tests only. End-to-end CLI testing (via `assert_cmd`) arrives in Task 10's `cli/tests/once_integration.rs`.

### Issues currently open

- #37 — Sub-project C umbrella. C.2 Tasks 1-3 ✅ in PRs #112, #114, #115; Task 4 pending PR.
- #113 — C.2 Task 5 cleanup checklist: lift `#[allow(dead_code)]` in `cli/src/exit.rs`, `cli/src/state.rs`, `cli/src/unlock.rs`, **and now `cli/src/veto/`**; add `--non-interactive` ↔ `--password-stdin` validation. Task 4 added more allowances under the same TODO(#113) marker — same cleanup obligation.
- #38, #45, #75, #76, #78, #79, #81, #87, #88, #90, #95, #98 — none block C.2 Task 5.

### Housekeeping note (stale worktrees on disk)

After this PR:
- `/Users/hherb/src/secretary` — `main` (clean post-merge).
- `/Users/hherb/src/secretary/.worktrees/c1-1b-sync-merge` — branch `feature/c1-1b-task-17`, remote gone. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-1-spec` — branch `feature/c2-task-1-spec`, remote gone. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-1` — branch `feature/c2-task-1`, remote gone. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-2` — branch `feature/c2-task-2`, remote gone. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-3` — branch `feature/c2-task-3`, remote gone after PR #115 merged. Safe to remove.
- `/Users/hherb/src/secretary/.worktrees/c2-task-4` — **this session's work**; keep until PR merges, then remove.

```bash
# One-line each (run from /Users/hherb/src/secretary):
git worktree remove .worktrees/c1-1b-sync-merge && git branch -D feature/c1-1b-task-17
git worktree remove .worktrees/c2-task-1-spec   && git branch -D feature/c2-task-1-spec
git worktree remove .worktrees/c2-task-1        && git branch -D feature/c2-task-1
git worktree remove .worktrees/c2-task-2        && git branch -D feature/c2-task-2
git worktree remove .worktrees/c2-task-3        && git branch -D feature/c2-task-3
```

Cleanup is one-line each and does NOT block Task 5.

## (4) Exact commands to resume

```bash
# After this C.2 Task 4 PR (feature/c2-task-4) merges:
cd /Users/hherb/src/secretary
git fetch --prune origin
git status --short                       # expect: clean (modulo NEXT_SESSION.md sync, see below)
git checkout main
git pull --ff-only origin main

# Verify gauntlet on fresh main (expect 849 / 0 / 10 — same as session close):
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3

# Start Task 5:
git worktree add .worktrees/c2-task-5 -b feature/c2-task-5 main
cd .worktrees/c2-task-5

# Open the plan and follow Task 5 line-by-line:
#   docs/superpowers/plans/2026-05-23-c2-headless-sync-cli.md §"Task 5"
# This is the longest task (320 LOC pipeline + N unit tests). Plan steps include
# the umbrella deletion of `#[allow(dead_code)]` markers (#113) as the pipeline
# starts consuming the args/exit/state/unlock/veto modules.
```

## Closing inventory

- **Branch state on close:** `main` at `7fc1c61` (PR #115 squash-merged). `feature/c2-task-4` carries 1 commit on top.
- **Workspace tests on `feature/c2-task-4`:** 849 passed + 10 ignored (836 base + 13 new cli `veto` unit tests: 11 in `interactive.rs` + 2 in `noninteractive.rs`). Clippy + fmt + Python conformance + spec freshness all clean.
- **README.md:** unchanged this session — Task 4 ships internal scaffolding (veto UX trait + impls), no user-visible behavior. Plan defers README update to Task 10.
- **ROADMAP.md:** unchanged this session — same reason; ROADMAP already calls C.2 "queued" since the C.2 design PR.
- **CLAUDE.md:** unchanged this session — no new convention; veto trait + Cursor-based test pattern are local to `cli/src/veto/` and don't generalise to repo-wide guidance.
- **NEXT_SESSION.md:** symlink retargeted to this file.
- **Open issues:** see §(3) — none block Task 5.
- **Open PRs:** one to be opened at end of this session (C.2 Task 4).
- **Worktrees on disk:** see §(3) housekeeping.
- **Frozen baton snapshots:** all 21 prior C.1.1b + C.2-design + C.2-task-1/2/3 handoffs at [`docs/handoffs/`](.) — preserved unchanged.
- **This file:** the live baton for C.2 Task 4 close.
