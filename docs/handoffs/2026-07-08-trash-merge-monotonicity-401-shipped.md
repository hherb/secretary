# NEXT_SESSION.md — #401 conflict-copy trash-list reconciliation ✅ SHIPPED (PR opening)

**Session date:** 2026-07-08. Ships **#401** ("Conflict-copy trash-list reconciliation — purged-marker merge monotonicity"), the direct offspring of #399. Branch `feature/trash-merge-monotonicity-401` cut from `main` @ `80dd2e2` (#399 via PR #403). Full design-first flow: brainstorm → spec → plan → subagent-driven execution (8 tasks, fresh implementer + task-reviewer per task, opus whole-branch review at the end). Worked in an isolated worktree `.worktrees/trash-merge-401/`. **Core-only slice — no FFI / bridge / desktop / mobile change.**

## (1) What we shipped this session

The C-layer sync merge now **reconciles trash lists across conflict copies** so a purge marker (or a plain tombstone) survives a concurrent-write merge — closing the durability gap #399 deferred here. Before this, `commit_with_decisions` built `new_manifest = open.manifest.clone()`, dropping every peer `TrashEntry`.

**Design decisions (resolved in brainstorming):**
1. **Reconcile in `prepare_merge`, carry on the draft** — the exact analog of the existing `post_merge_clock` fold (canonical + every copy). `commit_with_decisions` only re-opens the *local* vault, so the peer trash lists must ride on `DraftMerge.merged_trash`.
2. **Dedicated pure module** `core/src/vault/trash_merge.rs` (not bolted onto the 2097-line `conflict.rs`).
3. **Purge is terminal (user chose this over scope-minimal):** when a `block_uuid` is concurrently live on one copy and purged in another, **purge wins** — the block is removed from `blocks`, kept purged-in-trash. A permanent purge beats a concurrent restore/edit. The non-purged collision loses to live (never silently lose data). This *fixes* the un-purge / dangling-ciphertext bite, not just tolerates it.
4. **Latest-tombstone-wins** for the non-purged triple `(tombstoned_at_ms, tombstoned_by, fingerprint)` — a full-tuple total-order max ⇒ commutative + associative; `purged_at_ms` merged independently and monotonically on top.

**Mechanics:**
- `merge_trash_entry` / `merge_trash_lists` (union keyed by `block_uuid`, latest-triple, `purged_at_ms` = `Some`-if-either / max-millis / `None`<`Some` / never un-purges, unknown-map union reusing `conflict::merge_unknown_map`) + `resolve_live_vs_trash` (purge-terminal). All pure.
- `DraftMerge.merged_trash` (`#[zeroize(skip)]` — `TrashEntry` holds no secret), folded in `prepare_merge`, applied in `commit_with_decisions` (write.rs Step 6, *before* signing at Step 7) with purge-terminal block removal.
- Open-time sweep (`repair/sweep.rs::sweep_purged_trash_files`) extended to unlink **both** `trash/` and `blocks/` residue for a purged, not-live entry — completing the purge on the device that had restored the block. The "not live in `manifest.blocks`" gate is preserved (a concurrent restore that won is never touched).
- Normative `docs/crypto-design.md §11.6` + `docs/vault-format.md §7` (and the pre-existing "documented limitation" note flipped to "Resolved (#401)").
- Cross-language: new `core/tests/data/trash_merge_kat.json` (6 vectors incl. the two tie-break cases), Rust replay in `conflict.rs`, Python clean-room `py_merge_trash` + `conformance.py` §4b, 5 proptests, unit tests, **2 mutation-verified integration scenarios**.

### Branch commits (off `main` @ `80dd2e2`, in order)
- `e05f91f` design · `d130581` plan
- `ff73e16`+`423e208` T1 spec §11.6 + §7 (+reconciled the stale limitation note)
- `f0e46ef`+`0ede1f6` T2 pure module (+list-collision-fold test)
- `1f8992b`+`bc48b94` T3 5 proptests (+narrowed uuid domain so the dedup path is exercised)
- `73d1056` T4 `trash_merge_kat.json` + Rust replay · `67f0f3c` (+2 tie-break vectors)
- `d4fc340` T5 `py_merge_trash` + conformance §4b
- `a72da62` T6 `DraftMerge.merged_trash` + `prepare_merge` fold
- `55d6b7b` T8 sweep `blocks/` residue extension (ran before T7)
- `01ddb18`+`6038663` T7 commit apply + purge-terminal (+ the mutation-verified roles-swapped integration test)
- `f5c1d1b` rustdoc fix (unlink private `merge_unknown_map`) · `f089096` conformance cosmetic cleanup
- `62507df` README + ROADMAP
- → then this docs/handoff commit.

### Acceptance (all verified green this session, from the worktree)
```bash
cargo test --release --workspace                                  # full suite, NO FAILURES
cargo test --release --workspace --features differential-replay   # cross-language replay green
cargo clippy --release --workspace --tests -- -D warnings         # clean
cargo fmt --all --check                                           # clean
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace        # clean
uv run core/tests/python/conformance.py                           # exit 0; §4b 6/6 PASS
```

**Final opus whole-branch review: Ready to merge = Yes, 0 Critical / 0 Important / 1 Minor (fixed).** It independently traced the security-relevant paths: signing covers the reconciled `blocks`/`trash` (reconcile at Step 6, sign at Step 7 — no unsigned trash state); the sweep's not-live gate never unlinks a live block's file; `purged_at_ms` is never lowered/cleared; the equal-clock invariant is untouched (purge-terminal only *removes* a block entry, never rewrites a block clock or plaintext); spec §11.6 is an independent contract both Rust and Python honor (not circular); format-freeze intact (`manifest.rs` has zero diff).

**Notable review catch:** the task-reviewer *empirically* proved the first integration test was vacuous (deleting the entire commit-wiring block still passed 6/6, because the purger was canonical so its folder already carried the purged state). Fix = a roles-swapped scenario (restorer canonical, purger conflict-copy) that forces `blocks_to_remove` non-empty; the mutation check confirms it **fails without the wiring, passes with it**. This is the load-bearing proof that `commit_with_decisions`'s purge-terminal wiring is reachable.

## (2) What's next

Menu (updated — #401 shipped; #402 is its sibling):

1. **#402 — retention auto-purge (§7 step 5).** Design-heavy → **brainstorm first** (auto-deletes trash older than a window without user action: when it runs, consent model, interaction with the open-time sweeps). Builds directly on `purge_block` ("purge every `TrashEntry` older than the window"). The natural next follow-up.
2. **Optional purge UI (platform, deferred from #399):** desktop/iOS/Android "Delete forever" / "Empty Trash" over the shipped FFI surface — each a separate slice. Desktop already has a typed `AppError::BlockPurged` + user message (from #399's exhaustive-match plumbing) but no purge command/button.
3. **Manual GUI smoke of the #374 consent flow** (human-only, still carried): `pnpm tauri dev` against a **temp copy** ([[feedback_smoke_test_temp_copy_golden_vault]]) of a vault with staged crashed-share residue (`core/tests/crash_recovery.rs::stage_crashed_share`). Unlock → "Repair now?" → consent dialog renders added recipient + grouped fingerprint → Cancel leaves vault untouched → Grant adopts the widened set.
4. **Housekeeping:** #290 (`spec_test_name_freshness.py` 3 D.4 design-concept false-positives — Python, your strong area), #387 (`:kit` NewApi lint on `StrongBoxUnavailableException`, min SDK 26 / API 28), #383 (drop RUSTSEC-2026-0194/0195 from `.cargo/audit.toml` **only** when `cargo tree -i quick-xml --target all` shows a single quick-xml ≥0.41).
5. **Carried mobile (on-device / human-only):** iOS Face ID spot-check; Android #338 on-device biometric cloud-open, #331 SAF custom-ROM, #334 native cloud-provider epic (ADR + threat-model first).

## (3) Open decisions and risks

- **Purge-terminal cost (accepted, by design):** a permanent purge on one device discards concurrent *edits/restore* to that block on another device — the honest meaning of "permanent delete." Documented in §11.6.
- **Block-list reconciliation beyond the disjointness guard is untouched.** Copy-only block adoption and general live-vs-trash resurrection remain pre-existing merge limitations (orthogonal to #401). The purge-terminal guard is the *only* block-list mutation, and only to preserve disjointness + purge monotonicity.
- **No crypto / KEM / signature-site / equal-clock change; no `manifest_version` bump; no FFI variant; `#![forbid(unsafe_code)]` intact.** `manifest.rs` has zero diff (`TrashEntry.purged_at_ms` already existed from #399).
- **1 Minor from the final review — already fixed** (`conformance.py::_normalise_trash_entry` redundant guards simplified, `f089096`). No open findings.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After this PR merges, drop the branch + its worktree (squash-merge leaves it "not fully merged"):
#   git worktree remove .worktrees/trash-merge-401 && git branch -D feature/trash-merge-monotonicity-401
git worktree list && git status -s
# Re-run the trash-merge suite any time:
cargo test --release -p secretary-core trash_merge \
  && cargo test --release --workspace --test conflict trash_merge_kat \
  && cargo test --release --workspace --test sync_trash_merge \
  && cargo clippy --release --workspace --tests -- -D warnings
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; the symlink retargeted in the same commit on the feature branch (new path → no add/add conflict; `main` updates cleanly on merge). Per the baton convention the handoff rides inside the PR — do **not** sync to `main` during the pause window.

## Closing inventory
- **State on close:** PR opening on `feature/trash-merge-monotonicity-401` (worktree `.worktrees/trash-merge-401`). 19 branch commits (design + plan + 8 tasks with per-task review fixes + 2 gate fixes + README/ROADMAP + this handoff). #401 closes on merge.
- **Acceptance:** full workspace green; clippy `-D warnings`, `cargo fmt --all --check`, rustdoc `-D warnings` clean; differential-replay green; `conformance.py` exit 0 with §4b 6/6. Final opus whole-branch review: Ready to merge = Yes (0 Critical / 0 Important; the 1 Minor fixed).
- **Follow-up still open:** [#402](https://github.com/hherb/secretary/issues/402) (retention auto-purge — brainstorm first).
- **README / ROADMAP:** updated (flipped the #399 "conflict-copy trash-merge-monotonicity deferred" clause to "shipped in #401").
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-07-08-trash-merge-monotonicity-401-shipped.md`.
