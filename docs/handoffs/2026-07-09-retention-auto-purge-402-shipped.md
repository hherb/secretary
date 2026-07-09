# NEXT_SESSION.md — #402 retention auto-purge ✅ SHIPPED (PR opening)

**Session date:** 2026-07-09. Ships **#402** ("Retention auto-purge — §7 step 5: auto-delete trash past the window"), the design-heavy sibling of #399 (purge/empty-trash) and #401 (conflict-copy trash-merge). Branch `feature/retention-auto-purge-402` cut from `main` @ `f4cecac` (#401 via PR #404). Full design-first flow: brainstorm → spec → plan → subagent-driven execution (8 tasks, fresh implementer + task-reviewer per task, opus whole-branch review at the end, one fix wave). Worked in isolated worktree `.worktrees/retention-402/`. **Core-only slice — no FFI / bridge / desktop / mobile change; `manifest.rs` zero diff.**

## (1) What we shipped this session

`docs/vault-format.md` §7 step 5 (retention window) had a one-line spec and **no code**. #402 implements it as an **explicit, caller-invoked** core operation — `open_vault` stays read-only; the platform decides when to run it.

**Design decisions (resolved in brainstorming):**
1. **Explicit core fn, platform-invoked — NOT automatic on open.** Making `open_vault` a signer would break its read-only nature and the fast sync-poll distinction. Platform owns the *when* + UX.
2. **Caller supplies `window_ms`; core exposes `DEFAULT_RETENTION_WINDOW_MS` (90 days).** Not persisted in `vault.toml`/`manifest` (frozen format). Divergent per-device windows are safe — purge is monotonic and merges via the existing sweep (#401).
3. **Pure preview + commit.** `expired_trash_entries` (pure, no I/O) lists eligible entries so a platform can show "N items will be permanently deleted" before committing; `auto_purge_expired` commits.
4. **Dedicated pure module `core/src/vault/retention.rs`** (mirrors #401's `trash_merge.rs`), reusing a `purge_batch_commit` helper extracted from `empty_trash` so both share one audited commit path.

**Mechanics:**
- Eligibility (pure, exact rule): `purged_at_ms.is_none()` ∧ `block_uuid` not live in `manifest.blocks` ∧ `now_ms.saturating_sub(tombstoned_at_ms) > window_ms` (strict/exclusive; future-dated tombstone → age 0 → never eligible, so skew never causes an *early* purge).
- `auto_purge_expired` = `empty_trash` restricted by the age predicate: selects eligible indices → classifies (best-effort, reporting-only, before the write) → `purge_batch_commit` (stage `purged_at_ms` on N entries → tick clock once → re-sign once → atomic-write once = commit point → swap → best-effort file removal) → `RetentionPurgeReport { purged/shared/owner_only/unknown_count, files_removed/failed, window_ms }`. Empty target set → zero-count report, **no manifest write**.
- **Wall-clock is cleanup-*timing* only, never a merge-freshness signal.** Same `purged_at_ms` transition as `empty_trash` — no re-encrypt, no re-key, no block-clock tick, equal-clock invariant untouched. Documented normatively (§7 step 5) as an accepted **durability** risk, explicitly contrasted with the #350-forbidden `last_mod_ms`-as-freshness use.
- Normative `docs/vault-format.md §7 step 5` (expanded from one line) + `docs/crypto-design.md` tombstone-GC cross-ref (ciphertext removed at retention window; tombstone persists for GC — two lifetimes).
- Cross-language: new `core/tests/data/retention_kat.json` (7 vectors incl. boundary-equal-window + future-dated-saturating), Rust replay + Python clean-room `py_expired_trash_entries` + `conformance.py §4c`. 5 unit + 1 proptest + 4 integration tests (one **mutation-verified**).

### Branch commits (off `main` @ `f4cecac`, in order)
- `2678e20` design · `98aa308` plan
- `5d6308e` T1 spec §7 step 5 + crypto-design cross-ref
- `b36c811` T2 pure selector + `DEFAULT_RETENTION_WINDOW_MS`
- `e1ecbc1` T3 extract `purge_batch_commit`
- `fd5e7d0` T4 `auto_purge_expired` + mutation-verified integration test
- `aa72879` T5 idempotence + subset-of-`empty_trash` tests
- `296ed7d` T6 `retention_kat.json` + Rust replay
- `b23d1a9` T7 Python clean-room `§4c`
- `c8893a6` rustdoc-link fix (removed stray `[[…]]` marker + private-item link) · `967dfa6` T8 README + ROADMAP
- Final-review fixes: `8687dc0` §4c error handling mirrors §4b · `e693ab5` per-caller error context in `purge_batch_commit` · `974fbb3` design `Default`-note correction · `9caa429` vault-format prose parallelism · `4324edd` `build_manifest_from_kat` tolerant of absent `"blocks"` key
- → then this docs/handoff commit.

### Acceptance (all verified green this session, from the worktree)
```bash
cargo test --release --workspace                                  # full suite, NO FAILURES
cargo test --release --workspace --features differential-replay   # cross-language replay clean
cargo clippy --release --workspace --tests -- -D warnings         # clean
cargo fmt --all --check                                           # clean
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace        # clean
uv run core/tests/python/conformance.py                           # exit 0; §4c 7/7 PASS
```

**Final opus whole-branch review: Ready to merge = Yes, 0 Critical / 0 Important / 3 Minor (all fixed).** It independently verified all 9 security-relevant properties: signing covers the mutated `purged_at_ms` state (re-sign is the commit point; nothing after it fails the call); empty-target path performs no manifest write (asserted byte-equal); the not-live gate is byte-identical to `empty_trash`/the sweeps; wall-clock is genuinely cleanup-timing-only (same transition as `empty_trash`, no freshness-signal surface, #350 prohibition intact); the `purge_batch_commit` extraction is behaviour-preserving; saturating/exclusive boundary correct; the Python clean-room is import-free (non-circular) and the KAT encodes the correct rule; no secret widened; format freeze intact (`manifest.rs` zero diff, `#![forbid(unsafe_code)]`).

**Notable:** the mutation-verified integration test (`auto_purge_expired_purges_old_keeps_fresh`) was proven load-bearing — defeating the age clause makes the FRESH block also purge (`purged_count` 2≠1), so the test fails without the filter and passes with it.

## (2) What's next

1. **#402 platform surface (natural follow-ups, file as slices):** FFI projection of `auto_purge_expired` + `expired_trash_entries` (bridge → uniffi + pyo3), then desktop/iOS/Android "run retention now" / scheduled-purge UX over the preview→commit pair. Each a separate slice. **Acceptance for the FFI slice:** typed error surface, wrong-length uuid/secret validated at the binding wrapper (per [[project_secretary_input_validation_at_binding_wrapper]]), Swift+Kotlin conformance run (`run_conformance.sh` — cargo/clippy can't see those, per [[project_secretary_ffivaulterror_workspace_match]]), `:kit`+`:app` build (per [[project_secretary_conformance_scripts_dont_compile_kit]]).
2. **Optional purge UI (platform, still deferred from #399):** desktop/iOS/Android "Delete forever" / "Empty Trash" over the shipped FFI surface. Desktop already has typed `AppError::BlockPurged` + user message but no purge command/button.
3. **Manual GUI smoke of the #374 consent flow** (human-only, carried): `pnpm tauri dev` against a **temp copy** ([[feedback_smoke_test_temp_copy_golden_vault]]) of a vault with staged crashed-share residue (`core/tests/crash_recovery.rs::stage_crashed_share`). Unlock → "Repair now?" → consent dialog → Cancel leaves untouched → Grant adopts widened set.
4. **Housekeeping:** #290 (`spec_test_name_freshness.py` D.4 false-positives — Python; **note** the script also flags 3 pre-existing `docs/threat-model.md` citations `origin_binding`/`registrable_domain`/`exact_origin` at L234, untouched by this branch — fold into #290 or verify tracked), #387 (`:kit` NewApi lint), #383 (drop RUSTSEC-2026-0194/0195 from `.cargo/audit.toml` only when `cargo tree -i quick-xml --target all` shows a single quick-xml ≥0.41).
5. **Carried mobile (on-device / human-only):** iOS Face ID spot-check; Android #338 on-device biometric cloud-open, #331 SAF custom-ROM, #334 native cloud-provider epic (ADR + threat-model first).

## (3) Open decisions and risks

- **Retention-timing wall-clock use (accepted, by design):** `tombstoned_at_ms` gates *when* ciphertext is discarded, never a merge decision. A badly-fast clock could purge an owner-only block slightly early — a **durability** risk, bounded by the 90-day window, blocked in the early direction by `saturating_sub`, opt-in policy, previewable via `expired_trash_entries`. Documented normatively in §7 step 5; distinct from the #350-forbidden freshness-signal use.
- **Tombstone GC is out of scope.** `auto_purge_expired` removes only *ciphertext* (sets `purged_at_ms`); it never removes a `TrashEntry` from `manifest.trash`. Removing the tombstone itself (crypto-design §11 GC, after every device has observed the deletion) remains unshipped.
- **Deferred Minors on record (reviewer-endorsed, not defects):** the Rust proptest oracle in `retention.rs` mirrors the SUT predicate — the independent oracle is the cross-language KAT + Python clean-room; `core/tests/retention.rs` is ~500 lines (cohesive integration-test file; split if it grows). Design §3.2 step 2 still says `RetentionPurgeReport::default()` in prose (the shipped type is intentionally not `Default`) — harmless planning-doc wording, normative docs are correct.
- **No crypto / KEM / signature-site / equal-clock change; no `manifest_version` bump; no FFI variant; `#![forbid(unsafe_code)]` intact.**

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After this PR merges, drop the branch + its worktree (squash-merge leaves it "not fully merged"):
#   git worktree remove .worktrees/retention-402 && git branch -D feature/retention-auto-purge-402
git worktree list && git status -s
# Re-run the retention suite any time:
cargo test --release -p secretary-core retention \
  && cargo test --release --workspace --test retention \
  && cargo test --release --workspace --test purge \
  && cargo clippy --release --workspace --tests -- -D warnings \
  && uv run core/tests/python/conformance.py
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; the symlink retargeted in the same commit on the feature branch (new path → no add/add conflict; `main` updates cleanly on merge). Per the baton convention the handoff rides inside the PR — do **not** sync to `main` during the pause window.

## Closing inventory
- **State on close:** PR opening on `feature/retention-auto-purge-402` (worktree `.worktrees/retention-402`). 17 branch commits (design + plan + 8 tasks with per-task review + 1 rustdoc gate fix + README/ROADMAP + 5 final-review fixes + this handoff). #402 closes on merge.
- **Acceptance:** full workspace green; clippy `-D warnings`, `cargo fmt --all --check`, rustdoc `-D warnings` clean; differential-replay clean; `conformance.py` exit 0 with §4c 7/7. Final opus whole-branch review: Ready to merge = Yes (0 Critical / 0 Important; all 3 Minor fixed).
- **Follow-up still open:** #402 FFI projection + platform retention/purge UX (file as slices).
- **README / ROADMAP:** updated (retention auto-purge shipped; core-only, FFI + platform UX deferred).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-07-09-retention-auto-purge-402-shipped.md`.
