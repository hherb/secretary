# NEXT_SESSION.md — once-mode RunOutcome forensic logging (#295) ✅ SHIPPED (PR opening)

**Session date:** 2026-06-25. Started from a clean baton — PR #302 (`224af0e1`, the #210 fuzz-monitor loopback bind) had already merged to `main`, so the prior handoff's "PR opening" item was done. Removed the merged worktree/branch (`fuzz-monitor-loopback` / `fix/fuzz-monitor-loopback-bind`). User picked **#295** (the only `[bug]`-labelled carried item, small pure-Rust/CLI) over the two new `security` follow-ups **#300** (iOS `readBlock`/`wipe` race) and **#299** (uniffi lowering-buffer scrub). Executed via **TDD** (red→green) in the project-local worktree `.worktrees/once-log-outcome`.

**Status:** ✅ **SHIPPED — branch `fix/once-mode-log-outcome`, PR opening.** Single focused code commit; full `cargo test --workspace` + clippy `-D warnings` + fmt all green; reviewed clean by `code-reviewer`.

## (1) What we shipped this session

One pure-Rust/CLI forensic-logging gap — **no Rust-core / on-disk-format / spec change**; `conformance.py` + the Swift/Kotlin conformance harnesses untouched; no `FfiVaultError` variant; zero `core/` files touched.

**#295 — `once` mode didn't log `RunOutcome` forensics beyond the exit code.** `cli/src/main.rs::dispatch_once_subcommand` mapped a successful `RunOutcome` straight to an `ExitCode` via `outcome_to_exit_code` and emitted **no** operator-visible log line. So on a single-shot `once` invocation, a rejected manifest rollback (threat-model §3.1 attack indicator, carrying the **disk-vs-local vector clocks**) surfaced only as exit code 10, and an auto-resolved tombstone-veto count (`MergedAndCommitted { vetoes_resolved > 0 }`) was invisible except to a caller inspecting committed state. The daemon `run` loop already logs both via the pure-classifier-backed `daemon::log_outcome` (#207); `once` was deliberately deferred out of that PR's scope and filed as #295.

**Fix (logging-only).** Make `daemon::log_outcome` `pub`, and route the `once` `Ok` arm through a new `once_ok_exit_code(outcome)` seam in `main.rs` that calls `daemon::log_outcome(&outcome)` **before** mapping to the exit code — reusing the daemon's existing pure `outcome_log` classifier, so the `once` and `run` paths cannot drift. Exit-code mapping (`outcome_to_exit_code`, unchanged) and on-disk byte/merge semantics are untouched.

**Branch commit** (off `main` @ `224af0e1`):
| SHA | What |
|---|---|
| `c8d357ae` | **fix(cli)**: log RunOutcome forensics on once-mode dispatch (#295) — `pub log_outcome` + `once_ok_exit_code` seam + 3 tests |
| (+ handoff commit) | this baton + retargeted `NEXT_SESSION.md` symlink |

**Tests added (TDD red→green):** 3 cases in `cli/src/main.rs` `mod tests`, driven by an in-module capturing `tracing` subscriber (`CaptureWriter` + `tracing::subscriber::with_default`, thread-local so it can't collide with the global `logging` init or parallel test threads) — no new dependency (`tracing-subscriber` is already a `daemon`-feature dep):
- `once_logs_rollback_forensics_not_just_exit_code` — the teeth: on `RunOutcome::RollbackRejected` the once path must emit `"manifest rollback rejected"` **and** the `disk_clock`/`local_clock` fields (fixture uses non-degenerate clocks `[0x11;16]/ctr 7` vs `[0x22;16]/ctr 4`). Failed on pre-fix code (`got: ""`).
- `once_logs_auto_resolved_veto_count` — `MergedAndCommitted { vetoes_resolved: 2 }` must log `"auto-resolved 2 tombstone"`. Failed on pre-fix code.
- `once_silent_arms_emit_no_warning` — the four no-op arms (`NothingToDo` / `AppliedAutomatically` / `SilentMerge` / `MergedAndCommitted { vetoes_resolved: 0 }`) emit no warning and stay `Success`. (Passed pre-fix; regression guard.)

### Acceptance (verified this session, not assumed)
```bash
cd /Users/hherb/src/secretary/.worktrees/once-log-outcome
cargo test --release -p secretary-cli --bin secretary-sync   # 5 passed (3 new)
cargo test --release --workspace                             # green (exit 0)
cargo clippy --release --workspace --tests -- -D warnings    # clean
cargo fmt --all --check                                       # clean
```
**RED→GREEN proof:** with the seam in place but `daemon::log_outcome` not yet called, the two behavioral tests failed with `got: ""` (empty log); adding the one-line `daemon::log_outcome(&outcome)` turned them green. **No Rust-core / format / conformance surface changed** → `test.yml` + `rust-lint.yml` + CodeQL unaffected; Swift/Kotlin conformance harnesses not in play.

## (2) What's next
**#295 done (PR open). Pick a fresh item.** Strongest carried/new candidates:
- **#300** (`security`, iOS) — `UniffiVaultSession.readBlock`/`wipe()` race on `currentBlock` (no lock vs Android's `sessionLock`). Likely resolves to *prove + document* the main-actor invariant (iOS callers are `@MainActor`-serialized; `wipe()` is idempotent), or mirror Android's lock if any off-actor `wipe()` path exists. #251 follow-up.
- **#299** (`security`, FFI) — uniffi's generated lowering buffer for password/phrase isn't zeroized (residue beyond the adapter-owned `Data` that #229/#298 already scrub). Open-ended research: may dead-end in a documented upstream-uniffi limitation in the memory-hygiene memo. #229 follow-up.
- **#290** — allowlist the 3 D.4 freshness false-positives (`origin_binding`/`registrable_domain`/`exact_origin`); **check first** — `.worktrees/d4-browser-autofill` was still active at handoff (`52d99aa3`).

**Acceptance criteria template for the next pick:** a failing test that reproduces the gap on `main`, the typed-error/enforcement surface *proven* not assumed (security paths), full `cargo test --workspace` + clippy `-D warnings` green, and spec/`conformance.py` updated in lockstep if observable bytes/semantics change.

**Open follow-up issues (carried):** #300 / #299 / #290 / #284 / #280 / #277 / #273 / #272 / #269 / #255 / #252 / #247 / #246 / #234 / #232 / #231 / #224 / #218 / #193 / #192 / #190 / #189 / #186 / #183. (#295 now closed by this PR; #210 closed by #302; #251/#229 closed by #298.)

## (3) Open decisions and risks
- **`pub fn log_outcome` is the minimal sharing surface.** `main.rs` is the `secretary-sync` *binary* crate; `daemon` lives in the `secretary_cli` *lib* crate, so the shared emitter must be `pub` (not `pub(crate)`) to be reachable. The new rustdoc names both call sites (`after_sync`, `once_ok_exit_code`) so the visibility is intentional, not accidental. Don't narrow it back.
- **`once_ok_exit_code` seam is what makes the log testable.** A bare `daemon::log_outcome(&outcome)` inlined in the `Ok` arm couldn't be asserted without standing up a real vault + `run_one`. The seam takes `RunOutcome` directly, so the capturing-subscriber test reaches it. Don't inline it back into `dispatch_once_subcommand`.
- **Reuses the daemon's pure classifier — no duplicate logic.** The decision of *what* to log stays in `daemon::outcome_log` (already exhaustively unit-tested in `daemon.rs`); `once` only borrows the thin emitter. So the `once`/`run` forensic output can't diverge. Don't add a parallel `once`-specific classifier.
- **README / ROADMAP unchanged (deliberate).** #295 adds **no new capability** — pure forensic-observability hardening of already-shipped CLI behavior. Neither file references `once`-mode, `log_outcome`, or #295 (grep-confirmed), so both stay accurate. (Matches the prior pure-hardening rationale for #210/#251/#229.)
- **Risk:** none to behavior. The fix only *adds* `warn!` lines on the `once` rollback/veto arms (silent arms unchanged, exit codes unchanged, no disk writes). Worst case is two extra log lines an operator now actually sees on a `once` attack-indicator — which is the point.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# If PR merged: branch + worktree .worktrees/once-log-outcome can be removed:
#   git worktree remove .worktrees/once-log-outcome && git branch -D fix/once-mode-log-outcome
git worktree list && git status -s

# Re-run this fix's gate locally (from the worktree if the PR is still open):
cd .worktrees/once-log-outcome
cargo test --release -p secretary-cli --bin secretary-sync   # 5 passed
cargo test --release --workspace                             # green
cargo clippy --release --workspace --tests -- -D warnings    # clean
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; symlink retargeted in the same commit on the feature branch. New-path handoff → no add/add conflict. Branch was cut from current `origin/main` (`224af0e1`) and `origin/main` had **not** advanced at handoff time (verified: `origin/main` == HEAD == merge-base), so no history-binding merge was needed this session.

## Closing inventory
- **State on close:** PR opening on `fix/once-mode-log-outcome` (1 code commit `c8d357ae` + handoff). Worktree `.worktrees/once-log-outcome`.
- **Acceptance:** local GREEN — 5/5 bin tests (3 new), full `cargo test --workspace` exit 0, clippy `-D warnings` clean, fmt clean; reviewed clean by `code-reviewer`. RED→GREEN proven (empty-log failure → one-line fix). Zero `core/` touched → conformance / Swift/Kotlin harnesses unaffected.
- **README.md / ROADMAP.md:** unchanged (rationale in §3 — forensic-observability hardening, no capability/milestone change).
- **CLAUDE.md:** unchanged (no architectural guidance affected).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-06-25-once-mode-log-outcome-shipped.md`.
