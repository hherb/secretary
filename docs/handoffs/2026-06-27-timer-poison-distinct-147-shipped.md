# NEXT_SESSION.md — #147 timer-mutex poisoning distinct from contention ✅ SHIPPED (PR opening)

**Session date:** 2026-06-27 (fifth session of the day). Started from a clean baton — the prior session's #103 EvidenceStale TOCTOU block-write test merged to `main` as `fb02d614` (PR #318). Synced `main`, pruned four merged worktrees (#318/#317/#316/#315), picked **#147** from the collision-free shortlist (user chose it from the options: desktop Rust with real security-path substance). Executed in project-local worktree `.worktrees/timer-poison-147`, branch `feature/timer-poison-distinct-147` (cut from `origin/main` @ `fb02d614`).

**Status:** ✅ **SHIPPED — branch `feature/timer-poison-distinct-147`, PR opening.** Desktop-crate only. **No core `src/` change, no FFI / on-disk-format / spec / `conformance.py` / KAT-JSON change, no observable byte/CRDT-semantics change.** Closes #147.

## (1) What we shipped this session

**The gap (#147, surfaced by PR #146 review).** [`timer::tick`](desktop/src-tauri/src/timer.rs) acquired the session mutex via `try_lock()` and collapsed **both** `Err` modes into `TickOutcome::Skipped`:
1. `TryLockError::WouldBlock` — another caller holds the mutex (benign, self-healing; the next tick retries).
2. `TryLockError::Poisoned` — a prior IPC handler panicked while holding the mutex.

Unlike the command `*_impl`s (which map poison → `AppError::Internal` and surface it to a caller), the timer thread has **no caller**. So a poisoned session mutex silently stalled the auto-lock timer **forever** with no operator-visible signal — a security-relevant "deadlock of purpose" (a vault that should auto-lock never does, and nothing says why).

**The fix (design: variant + one-shot log, user-chosen over the issue's minimal in-`tick` log).**
- New `TickOutcome::Poisoned` variant, returned distinctly from a `match try_lock()` Poisoned arm. **`tick` stays pure** (the module's documented "no I/O" contract is preserved) — it *reports* the condition; the loop edge does the logging. This was deliberately chosen over the issue's primary sketch (log inside `tick`) because in-`tick` logging would (a) break the pure-function contract and (b) spam `error!` on **every** tick once poisoned (per [[feedback_pure_functions]]).
- New pure `poison_should_log(&mut bool) -> bool` one-shot latch (in `timer.rs`, the testable module). A poisoned mutex stays poisoned for the process lifetime, so the loop emits `Poisoned` every tick; the latch returns `true` exactly once so [`main.rs`'s `auto_lock_timer_loop`](desktop/src-tauri/src/main.rs) logs a **single** `tracing::error!`, then stays quiet. Keeping the anti-spam decision in a pure fn makes it unit-testable without driving the binary's infinite timer loop.
- `main.rs` loop edge: new `TickOutcome::Poisoned` arm calls `poison_should_log` + logs once; `NoAction | Skipped` arm unchanged.

**TDD + mutation-verified (not assumed).** Both tests written test-first (watched RED — compile error for the missing variant/fn — before GREEN):
- `tick_returns_poisoned_when_mutex_poisoned`: poisons the mutex via panic-while-locked (the established `commands::shared` pattern; `thread::scope` borrows the local mutex without an `Arc`, `.join()` swallows the expected `Err(panicked)`), asserts `mutex.is_poisoned()` then `tick() == Poisoned`.
- `poison_should_log_fires_exactly_once`: first call `true` + latch flips; next 5 calls `false` (proves the anti-spam contract).
- **Mutation test:** reverting the `Poisoned` arm to `=> Skipped` (the pre-#147 bug) makes `tick_returns_poisoned_when_mutex_poisoned` fail on the **assertion** (`left == right`), not a compile error — proving the test is a real behavior guard, non-vacuous. Mutant reverted; `grep MUTANT` clean; final diff is the intended 2-file change.

**Code review (pr-review-toolkit:code-reviewer on the commit diff): clean, no material issues.** Confirmed: exhaustive `match` over `TryLockError` and over all four `TickOutcome` variants (a future fifth variant fails to compile rather than fall through); poison initially treated as report-only; purity preserved; TDD/mutation claims verified. **Superseded by a pre-merge follow-up** (see §3): a later review showed report-only strands unlocked key material in memory after a panic, so the timer now fails secure — `into_inner()` + force-lock to *discard* (not resume) the session. `lock()` is `inner = None`, so this is safe on a half-mutated session.

**Branch commits** (off `main` @ `fb02d614`):
| SHA | What |
|---|---|
| `3ef3157e` | **fix(#147)**: surface session-mutex poisoning distinctly from contention in `timer::tick` (`Poisoned` variant + pure `poison_should_log` latch + `main.rs` loop edge + 2 TDD tests) |
| (+ handoff commit) | this baton + retargeted `NEXT_SESSION.md` symlink |

### Acceptance (verified this session, in the worktree)
```bash
cd /Users/hherb/src/secretary/.worktrees/timer-poison-147
cargo test --release --workspace                              # exit 0 — ALL green
cargo test --release -p secretary-desktop                    # 130+58+17 pass, 0 failed
cargo clippy --release -p secretary-desktop --tests -- -D warnings   # clean
cargo fmt --all -- --check                                   # clean
```
- New timer tests: 7 pass (was 5). Mutation check: confirmed the new assertion fails when the invariant breaks.
- **File-size discipline:** `timer.rs` 217 LOC (< 500); no split needed.

## (2) What's next
**This item is done (PR open). Pick a fresh item.** Active parallel worktrees this session (avoid collisions): `.claude/worktrees/hardcore-robinson-373901` (D.3 iOS XCFramework #200), `.worktrees/d4-browser-autofill` (D.4), `.worktrees/desktop-block-crud-ui`. Collision-free candidates from the carried backlog:
- **#117** — cap the `TtyVetoUx` re-prompt loop at N invalid replies, default to safe `KeepLocal` (CLI Rust; defensive — a pathological piped reader currently hangs `decide` forever).
- **#105** — group multi-arg test-helper signatures into param structs (`sync_helpers` + `sync_merge_vetoes`); test-only, continues #183's transposition-safety theme.
- Pick a fresh meaty-Rust item from the carried backlog below (user is a Rust novice learning on this project; prefers core Rust with real security-path substance).

**Acceptance criteria template:** a failing test/build (or mutation test) reproducing the gap on `main`, the typed-error/enforcement surface *proven* not assumed (security paths, [[feedback_verify_deferred_items]] / [[feedback_security_no_assumptions]]), the platform's full test gate green, spec/`conformance.py` updated in lockstep if observable bytes/semantics change.

**Open follow-up issues (carried):** #307 / #290 / #284 / #280 / #277 / #273 / #269 / #255 / #247 / #246 / #234 / #232 / #224 / #218 / #186 / #167 / #162 / #161 / #160 / #159 / #158 / #145 / #144 / #140 / #139 / #138 / #135 / #134 / #133 / #132 / #129 / #127 / #126 / #123 / #122 / #120 / #117 / #105 / #147 (now closed).

## (3) Open decisions and risks
- **Design fork (resolved by user):** the variant + one-shot-log approach was chosen over the issue's minimal in-`tick` log. Rationale: keeps the documented pure-function contract and avoids per-tick `error!` spam. The latch lives in `timer.rs` (pure, testable) so the `main.rs` binary loop stays thin.
- **Poison fails secure: recovered *to lock*, never *to resume* (revised before merge).** Earlier in this session the timer only *reported* poison; a follow-up review (see below) flagged that a panic while a vault was **unlocked** would strand the resident key material in memory until process exit. `tick` now calls `PoisonError::into_inner()` on the poisoned guard and **force-locks** the session (`PoisonedLocked` → `main.rs` emits `vault-locked` once + logs once; the already-locked case stays `Poisoned` → log only). This is *not* the "resume on a half-mutated session" anti-pattern the conservative posture warned against: [`VaultSession::lock`](desktop/src-tauri/src/session.rs) is `inner = None`, so force-locking **discards** the session (running the wipe/zeroize Drop chain) rather than trusting or reading it — it cannot panic and leaves no secrets resident. Proven by `timer_tick_force_locks_poisoned_unlocked_session` (asserts `!is_unlocked()` after the tick), mutation-verified (removing `session.lock()` fails the secrets-zeroized assertion, not a compile error).
- **Pre-existing freshness FAIL is NOT mine.** `uv run core/tests/python/spec_test_name_freshness.py` reports 3 unresolved citations (`origin_binding` / `registrable_domain` / `exact_origin` in `docs/threat-model.md`) — the **#290** D.4 design-concept false-positives, already failing on `main`. My change touches no docs and adds no citations.
- **README.md / ROADMAP.md / CLAUDE.md unchanged (deliberate).** Observability hardening on a desktop path adds no product capability and is not a roadmap slice; per [[feedback_readme_style]] status sections avoid test-count walls. No new documented command (runs under the existing `cargo test`).
- **Risk:** low. Behavior change is additive (new variant + one new log line on a previously-silent failure mode); the benign `Skipped`/`NoAction`/`AutoLocked` paths are byte-for-byte unchanged.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# If #147 PR merged, remove this worktree + branch:
#   git worktree remove .worktrees/timer-poison-147 && git branch -D feature/timer-poison-distinct-147
git worktree list && git status -s

# Re-verify this session's work (from the worktree if the PR is still open):
cd .worktrees/timer-poison-147
cargo test --release -p secretary-desktop --lib timer::
cargo clippy --release -p secretary-desktop --tests -- -D warnings
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; symlink retargeted in the same commit on the feature branch. New-path handoff → no add/add conflict. Branch cut from `origin/main` (`fb02d614`); at handoff time `origin/main` is an ancestor of `HEAD` (verified via `git merge-base --is-ancestor`), so no history-binding merge was needed.

## Closing inventory
- **State on close:** PR opening on `feature/timer-poison-distinct-147` (`3ef3157e` fix + handoff commit). Worktree `.worktrees/timer-poison-147`.
- **Acceptance:** `cargo test --release --workspace` exit 0 (all green); desktop crate full suite green; clippy `-D warnings` clean; fmt clean. New tests TDD + mutation-verified non-vacuous. Code review clean. Diff is 2 files (`timer.rs`, `main.rs`), +100/-8.
- **README.md / ROADMAP.md / CLAUDE.md:** unchanged (rationale in §3).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-06-27-timer-poison-distinct-147-shipped.md`.
