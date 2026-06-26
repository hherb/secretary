# NEXT_SESSION.md — #193 pipeline.rs refactor (dedup + real-race test + submodule split) ✅ SHIPPED (PR opening)

**Session date:** 2026-06-26. Started from a clean baton — PR #299 (uniffi value-marshalling secret residue) had merged to `main` as `debdb5a9` (#306); removed the merged worktree/branch (`.worktrees/uniffi-secret-residue` / `docs/uniffi-secret-residue-299`). User picked **#193** (CLI pipeline refactor — a Rust-learning task, zero platform-worktree collision). Also closed **#272** as verified-stale (see §1). Executed in project-local worktree `.worktrees/pipeline-refactor-193`, branch `refactor/pipeline-submodule-193`.

**Status:** ✅ **SHIPPED — branch `refactor/pipeline-submodule-193`, PR opening.** Pure internal refactor + one regression test of the already-✅ C.2 CLI sync pipeline. **No behavior change, no public-API change, no `core`/FFI/on-disk-format/`conformance.py` change.** `Closes #193` rides in the PR body.

## (1) What we shipped this session

**Housekeeping first — closed #272 (stale).** `cargo fmt --all --check` passes clean on `main` (exit 0); the rustfmt drift #272 reported was fixed by `f498206c` (#288), which also added the fmt/clippy CI gate. Closed with that evidence.

**#193 — three subtasks** (follow-ups deferred from the D.1.15 interactive-conflict-resolution Task-3 review), each its own commit:

1. **Extract `gather_copy_clocks` helper** — the 5-line conflict-copy clock gather feeding `silent_merge_clock` was copy-pasted into all four sync passes (`run_one`, `sync_pass_pause_on_conflict`, `sync_pass_inspect`, `sync_pass_commit_decisions`). Now one pure `gather_copy_clocks(&VaultBundle) -> Vec<&[VectorClockEntry]>` beside `silent_merge_clock`. No behavior change; existing integration tests are the guard.

2. **Pipeline-level real-race `EvidenceStale` test** — `commit_decisions_stale_token_is_rejected` *fakes* staleness by XOR-flipping a token byte (disk stays fresh). Added `commit_decisions_real_concurrent_manifest_rewrite_is_rejected`: a concurrent writer genuinely re-signs the canonical manifest under a **fresh runtime-generated nonce** (`rand`, not a literal — per [[feedback_test_crypto_random_not_hardcoded]]) between call-1 (inspect) and call-2 (commit), same merge shape, different bytes, while the operator holds the **genuine** call-1 token. The recomputed hash no longer matches → early freshness gate trips with `EvidenceStale`, no write. This pins the gate's *other* operand to the live `sync_once` recompute (the byte-flip test only pins that the token is consulted). **Proven a real guard:** mutating the gate to `manifest_hash != manifest_hash` turns *both* staleness tests red; the correct gate keeps them green (verified, then reverted).

3. **Split `pipeline.rs` (~840 lines) into a `pipeline/` submodule** — over the project's ~500-line heuristic ([[feedback_split_files_proactively]]). Natural cut, no behavior change:
   - `pipeline/outcomes.rs` — the 3 outcome enums (`RunOutcome`/`SyncPassOutcome`/`InspectOutcome`) + `RunOutcome::advanced_state` + their pure variant-level tests.
   - `pipeline/passes.rs` — the 4 sync passes + `gather_copy_clocks` + `silent_merge_clock` + the LUB-contract tests.
   - `pipeline/mod.rs` — the seam: module docs + `pub use` re-exports, so `pipeline::{run_one, RunOutcome, sync_pass_*, InspectOutcome, SyncPassOutcome}` is byte-for-byte unchanged for `daemon.rs` / `main.rs` / the integration tests.

**Branch commits** (off `main` @ `debdb5a9`):
| SHA | What |
|---|---|
| `8cacd6e4` | **refactor(cli)**: extract `gather_copy_clocks`, dedup 4 sync passes |
| `94b6fbeb` | **test(cli)**: pipeline-level real-race `EvidenceStale` guard |
| `ae9eab1c` | **refactor(cli)**: split `pipeline.rs` into a `pipeline/` submodule |
| `2ac50b55` | **style(cli)**: rustfmt the new real-race test (clippy-clean but un-fmt'd in `94b6fbeb`) |
| (+ handoff commit) | this baton + retargeted `NEXT_SESSION.md` symlink |

### Acceptance (verified this session, in the worktree)
```bash
cd /Users/hherb/src/secretary/.worktrees/pipeline-refactor-193
cargo clippy --release --workspace --tests -- -D warnings   # clean
cargo fmt --all --check                                      # clean (exit 0)
cargo test --release --workspace                             # all green, 0 failed
# the real-race guard specifically:
cargo test --release -p secretary-cli --test sync_pass_integration \
  commit_decisions_real_concurrent_manifest_rewrite_is_rejected   # ok
```
- cli lib **154** + all integration suites green; full workspace test suite green.
- `cargo doc`: **no new** broken intra-doc links (14 pre-existing on `main`, 14 after — the `outcomes`/`passes` private-module links I briefly introduced were caught and fixed to plain code spans before commit).

## (2) What's next
**#193 done (PR open). Pick a fresh item.** Carried candidates (collision status as of this session):
- **#290** — allowlist the 3 D.4 freshness false-positives (`origin_binding`/`registrable_domain`/`exact_origin` in `threat-model.md`). Trivial (3 allowlist entries, precedent exists), but **still collision-risky**: `.worktrees/d4-browser-autofill` (`claude/intelligent-davinci-hriple`) is active — coordinate first.
- **#252** (Android) — `UniffiVaultSession` read-only path (`blockSummaries`/`vaultUuidHex`) lacks the wiped guard; mirrors the iOS #304 hardening for Kotlin. No pipeline collision.
- **#231** (iOS) — enable `-strict-concurrency=complete` on the SwiftPM targets; natural follow-on to the #300 TSan work.
- **#92** (docs) — clean up the **28 pre-existing `cargo doc` warnings** (14 are in `secretary-cli`: `watcher::*` unresolved links, `pipeline::run_one` from `daemon`/`main`/`unlock`, `log_outcome`/`start`/`run_against_vault` linking private items). Surfaced again this session; **already filed as #92** — a good self-contained docs slice. NB: `cargo doc -D warnings` is **not** a CI gate today.

**Acceptance criteria template:** a failing test reproducing the gap on `main`, the typed-error/enforcement surface *proven* not assumed (security paths, [[feedback_verify_deferred_items]]), the platform's full test gate green, spec/`conformance.py` updated in lockstep if observable bytes/semantics change.

**Open follow-up issues (carried):** #290 / #284 / #280 / #277 / #273 / #269 / #255 / #252 / #247 / #246 / #234 / #232 / #231 / #224 / #218 / #192 / #190 / #189 / #186 / #183 / #92. (#272 closed this session; #193 closing via this PR.)

## (3) Open decisions and risks
- **#272 closed this session** (verified-stale, evidence above). Was carried as "closeable" in the prior baton — done.
- **README / ROADMAP unchanged (deliberate).** A pure internal refactor + regression test of the already-✅ C.2 CLI pipeline is no capability/milestone — matches the #210/#251/#229/#300 pure-hardening precedent (contrast #261/D.1.10, actual features that *did* get doc lines). No public API, behavior, or on-disk-format change.
- **The real-race test is complementary, not a replacement.** It keeps the byte-flip `commit_decisions_stale_token_is_rejected` test — together they pin both operands of the freshness gate (token consulted *and* recompute is live). The `commit_with_decisions` *internal* second gate only catches a disk change *during* commit (between `prepare_merge` and write); the early gate is the only thing covering "disk moved between call-1 and call-2", which is exactly what the new test exercises.
- **Risk:** none to product behavior (refactor preserves the public API verbatim; the split is a git rename + two new files; the only logic touched is the helper extraction, guarded by the unchanged integration suite).
- **Process note (parallel-session hazard hit & recovered, twice):** the Edit/Write tools resolve `file_path` literally — a bare `/Users/hherb/src/secretary/cli/...` path edits the **main repo**, not the worktree, even with Bash cwd in the worktree. Symptom: a rebuild "passes" without recompiling + worktree `git status` clean after an edit. Recovered both times (`cp` modified main file → worktree, `git checkout --` in main; trees were identical from the same base). **Lesson saved as [[feedback_edit_tool_targets_main_not_worktree]]: always spell out `.worktrees/<name>/...` in file-tool paths.**

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# If PR merged: branch + worktree can be removed:
#   git worktree remove .worktrees/pipeline-refactor-193 && git branch -D refactor/pipeline-submodule-193
git worktree list && git status -s

# Re-verify this session's gate (from the worktree if the PR is still open):
cd .worktrees/pipeline-refactor-193
cargo clippy --release --workspace --tests -- -D warnings
cargo test --release -p secretary-cli
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; symlink retargeted in the same commit on the feature branch. New-path handoff → no add/add conflict. Branch cut from `origin/main` (`debdb5a9`); `origin/main` had **not** advanced at handoff time (verified `origin/main` == merge-base == `debdb5a9`), so no history-binding merge was needed.

## Closing inventory
- **State on close:** PR opening on `refactor/pipeline-submodule-193` (`8cacd6e4` dedup + `94b6fbeb` test + `ae9eab1c` split + `2ac50b55` fmt + handoff). Worktree `.worktrees/pipeline-refactor-193`.
- **Acceptance:** clippy + fmt + full workspace test all green; no new broken doc links; zero `core`/FFI/on-disk-format/`conformance.py` touched → all language gates unaffected. `#193` closes via the PR; `#272` closed directly.
- **README.md / ROADMAP.md:** unchanged (rationale in §3).
- **CLAUDE.md:** unchanged.
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-06-26-pipeline-refactor-193-shipped.md`.
