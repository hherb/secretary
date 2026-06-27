# NEXT_SESSION.md — #103 EvidenceStale TOCTOU block-write half ✅ SHIPPED (PR opening)

**Session date:** 2026-06-27 (fourth session of the day). Started from a clean baton — the prior session's SecretaryApp Swift 6 work merged to `main` as `50f1b330` (PR #317). Synced `main`, picked **#103** from the collision-free backlog (user chose it from the options shortlist: core Rust, sync-merge security path, pure TDD). Executed in project-local worktree `.worktrees/sync-toctou-block-writes-103`, branch `feature/sync-toctou-block-writes-103` (cut from `origin/main` @ `50f1b330`).

**Status:** ✅ **SHIPPED — branch `feature/sync-toctou-block-writes-103`, PR opening.** Test-only. **No `src/` change, no FFI / on-disk-format / spec / `conformance.py` / KAT-JSON change, no observable byte/semantics change.** Closes #103.

## (1) What we shipped this session

**The gap (#103, surfaced by PR #102 self-review).** `commit_with_decisions` runs a D5 TOCTOU freshness re-check at step 2 of its prologue ([core/src/sync/commit/write.rs:119-121](core/src/sync/commit/write.rs#L119-L121)): it BLAKE3-hashes the on-disk manifest envelope and aborts with `SyncError::EvidenceStale` if it diverges from `draft.manifest_hash`. Crucially, step 2 runs **before** step 5's per-block `rewrite_one_block` loop ([write.rs:133-149](core/src/sync/commit/write.rs#L133-L149)), so a mid-flight manifest mutation must leave the disk *completely* untouched — no manifest write AND no block write.

The Task-12 test `commit_with_decisions_stale_manifest_hash_aborts_with_no_disk_writes` ([core/tests/sync_merge.rs:409](core/tests/sync_merge.rs#L409)) proved only the **manifest half**: it uses the empty-divergence fixture (`bundle.diverging_blocks` empty), so step 5 had no block writes queued and manifest byte-equality was the single commit-point check. The **block half** was structurally correct but unproven by test.

**The fix — a divergence-bearing companion test.** New `commit_with_decisions_stale_manifest_with_diverging_blocks_writes_no_block_files` in a new binary [core/tests/sync_merge_toctou.rs](core/tests/sync_merge_toctou.rs):
- Builds the `fresh_vault_two_concurrent_blocks` fixture (canonical record `[0xAA]@100` vs sibling `[0xBB]@200`, distinct UUIDs → clean union, no vetoes) so `bundle.diverging_blocks` is **non-empty** (asserted — guards against a vacuous test) and `plan.diverging_blocks.contains(&block_uuid)` (the snapshot block is one step 5 *would* rewrite).
- Opens the same `prepare_merge → mutate-manifest → commit_with_decisions` race window. The mutation re-emits the canonical manifest with **identical logical content but a fresh AEAD nonce** (`SIBLING_NONCE_D` vs the fixture's `CANONICAL_NONCE_A`): the envelope bytes — hence the BLAKE3 hash — change, so step 2 trips, while `open_vault` (step 1) still accepts it (block entries / fingerprints / signature unchanged). This cleanly isolates "any envelope change → freshness fires" with no clock-domination concerns.
- Asserts `Err(EvidenceStale)`, then **NEW for #103**: the diverging block file is byte-identical across the failed commit (step 5 never persisted a tempfile), plus the manifest is byte-identical too (the complete short-circuit).

**Mutation-tested (not assumed).** Temporarily moved the freshness early-return to *after* the block-rewrite loop → the new test failed on **exactly** the block-bytes assertion (`"EvidenceStale must abort BEFORE any block re-encrypt; diverging block bytes changed"`), not the `EvidenceStale` match. This proves the new assertion is a real ordering guard, not vacuous. Mutation reverted; `git diff core/src/sync/commit/write.rs` is empty (verified).

**Supporting refactor.** Lifted the pure `live_record` helper into the shared `sync_helpers` module (it was about to be duplicated; `sync_merge_crash.rs` now calls `sync_helpers::live_record` too, and its now-unused `BTreeMap`/`SecretString`/`RecordField`/`RecordFieldValue` imports were trimmed) per [[feedback_pure_functions]].

**Branch commits** (off `main` @ `50f1b330`):
| SHA | What |
|---|---|
| `a11748d8` | **test(#103)**: prove EvidenceStale TOCTOU abort writes no block files (new `sync_merge_toctou.rs` + `live_record` lift to `sync_helpers` + `sync_merge_crash.rs` dedup) |
| (+ handoff commit) | this baton + retargeted `NEXT_SESSION.md` symlink |

### Acceptance (verified this session, in the worktree)
```bash
cd /Users/hherb/src/secretary/.worktrees/sync-toctou-block-writes-103
cargo test --release --workspace                       # ALL green, 0 failed
cargo clippy --release --workspace --tests -- -D warnings   # clean
cargo fmt --all -- --check                             # clean
```
- New + affected binaries: `sync_merge_toctou` (new test passes), `sync_merge_crash` (6 pass after the `live_record` lift), `sync_merge` (9 pass, Task-12 manifest-half untouched).
- Full workspace: every `test result:` line shows `0 failed`.
- **File-size discipline:** `sync_merge.rs` left untouched at 495 LOC (< 500); new test in its own binary per the split-by-concept precedent (`sync_merge_vetoes.rs`, `sync_merge_crash.rs`).

## (2) What's next
**This item is done (PR open). Pick a fresh item.** Active parallel worktrees this session (avoid collisions): `.worktrees/d4-browser-autofill` (D.4), `.worktrees/desktop-block-crud-ui`, `.claude/worktrees/hardcore-robinson-373901` (D.3 iOS XCFramework #200). Stale/merged worktrees still on disk (removable once their PRs are confirmed merged — see §4): `.worktrees/secretaryapp-swift6` (#317 ✅), `.worktrees/trash-list-memo-172` (#315 ✅), `.worktrees/parse-trash-dup-uuid` (#316 ✅). Collision-free candidates:
- **#147** — `timer::tick` should surface mutex **poisoning** distinctly from contention (desktop Rust; a poisoned session mutex silently stops the auto-lock timer forever — add a `tracing::error!` + a `tracing-test` assertion). Mild collision risk with the active desktop worktree — check `desktop/src-tauri/src/timer.rs` isn't being touched there first.
- **#117** — cap the `TtyVetoUx` re-prompt loop at N invalid replies, default to safe `KeepLocal` (CLI Rust; defensive).
- **#105** — group multi-arg test-helper signatures into param structs (`sync_helpers` + `sync_merge_vetoes`); test-only, continues #183's transposition-safety theme.
- Pick a fresh meaty-Rust item from the carried backlog below (user is a Rust novice learning on this project; prefers core Rust with real security-path substance).

**Acceptance criteria template:** a failing test/build (or mutation test) reproducing the gap on `main`, the typed-error/enforcement surface *proven* not assumed (security paths, [[feedback_verify_deferred_items]] / [[feedback_security_no_assumptions]]), the platform's full test gate green, spec/`conformance.py` updated in lockstep if observable bytes/semantics change.

**Open follow-up issues (carried):** #307 / #290 / #284 / #280 / #277 / #273 / #269 / #255 / #247 / #246 / #234 / #232 / #224 / #218 / #186 / #167 / #162 / #161 / #160 / #159 / #158 / #147 / #145 / #144 / #140 / #139 / #138 / #135 / #134 / #133 / #132 / #129 / #127 / #126 / #123 / #122 / #120 / #117 / #105 / #103 (now closed).

## (3) Open decisions and risks
- **Pre-existing freshness FAIL is NOT mine.** `uv run core/tests/python/spec_test_name_freshness.py` reports 3 unresolved citations (`origin_binding` / `registrable_domain` / `exact_origin` in `docs/threat-model.md` L234). These are the **#290** D.4 design-concept false-positives — already failing on `main`, collision-risky to fix while `.worktrees/d4-browser-autofill` is active. My change touches no docs and adds no citations.
- **Race-window design choice (deliberate):** re-emit the manifest with the **same logical content + a fresh AEAD nonce**, rather than bumping the vector clock like the Task-12 manifest-half test does. Reusing the fixture's own canonical clock guarantees `open_vault` (step 1) still accepts it (no clock-domination edge cases), so the failure provably fires from the step-2 BLAKE3 re-check on the envelope-byte change — the cleanest isolation of the property under test.
- **Vacuity guarded two ways:** (a) the test asserts `!bundle.diverging_blocks.is_empty()` + `plan.diverging_blocks.contains(&block_uuid)` so step 5 genuinely has block writes to short-circuit; (b) the mutation test (check moved after the block loop) confirmed the new assertion *fails* when the invariant breaks.
- **README.md / ROADMAP.md unchanged (deliberate).** A core test-coverage regression guard adds no product capability and is not a roadmap slice; per [[feedback_readme_style]] status sections avoid test-count walls. CLAUDE.md unchanged (no new documented command; the test runs under the existing `cargo test --release --workspace`).
- **Risk:** none to product behavior — test-only, no `src/` change. The guarded invariant was already structurally correct; this is a regression guard, not a fix.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# If #103 PR merged, remove this worktree + branch:
#   git worktree remove .worktrees/sync-toctou-block-writes-103 && git branch -D feature/sync-toctou-block-writes-103
# Stale merged worktrees safe to prune (confirm each PR merged first):
#   git worktree remove .worktrees/secretaryapp-swift6   && git branch -D feature/secretaryapp-swift6     # #317
#   git worktree remove .worktrees/trash-list-memo-172   && git branch -D feature/trash-list-memo-172     # #315
#   git worktree remove .worktrees/parse-trash-dup-uuid  && git branch -D feature/parse-trash-dup-uuid    # #316
git worktree list && git status -s

# Re-verify this session's work (from the worktree if the PR is still open):
cd .worktrees/sync-toctou-block-writes-103
cargo test --release --workspace --test sync_merge_toctou --test sync_merge_crash --test sync_merge
cargo clippy --release --workspace --tests -- -D warnings
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; symlink retargeted in the same commit on the feature branch. New-path handoff → no add/add conflict. Branch cut from `origin/main` (`50f1b330`); at handoff time `origin/main` is an ancestor of `HEAD` (verified via `git merge-base --is-ancestor`), so no history-binding merge was needed.

## Closing inventory
- **State on close:** PR opening on `feature/sync-toctou-block-writes-103` (`a11748d8` test + handoff). Worktree `.worktrees/sync-toctou-block-writes-103`.
- **Acceptance:** full workspace `cargo test --release` green (0 failed); clippy `-D warnings` clean; fmt clean. New test mutation-verified non-vacuous. Diff is test-only (3 files: new `sync_merge_toctou.rs`, `sync_helpers` `live_record` lift, `sync_merge_crash` dedup).
- **README.md / ROADMAP.md / CLAUDE.md:** unchanged (rationale in §3).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-06-27-sync-toctou-block-writes-103-shipped.md`.
