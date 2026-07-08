# NEXT_SESSION.md — #399 purge / empty-trash ✅ SHIPPED (PR opening)

**Session date:** 2026-07-08. Ships **#399** ("Design a purge / empty-trash operation"). Branch `feature/purge-empty-trash-399` cut from `main` @ `ca01b3a` (which carries #376 via PR #400). Full design-first flow: brainstorm → spec → plan → subagent-driven execution (11 tasks, fresh implementer + task-reviewer per task, opus whole-branch review at the end). Worked in an isolated worktree `.worktrees/purge-399/`.

## (1) What we shipped this session

**A permanent purge lifecycle completing the trash story** — `purge_block` + `empty_trash`, across the Rust core + the FFI bridge (pyo3 + uniffi), with normative spec + clean-room + cross-language conformance. Platform purge UIs are **deferred** (this slice = Core + FFI bridge, per the approved design).

**Design decisions (the 5 forks resolved in brainstorming):**
1. **One erasure mechanism + honest classification.** Purge deletes the local `trash/` ciphertext (`fs::remove_file`, no overwrite); owner-only-vs-shared is classified from the §6.2 recipient table for *reporting only*. The wrapped Block Content Key lives only inside the block file, so for an owner-only block the unlink **is** the crypto-shred — there is no separate key to destroy.
2. **Keep the tombstone, mark it purged.** New additive-optional `TrashEntry.purged_at_ms` (same `unknown`-map forward-compat as `fingerprint`; **no `manifest_version` bump**). The tombstone stays as the resurrection guard.
3. **Unlink only, no overwrite theater** (FS secure-erase is unachievable on SSD/CoW/snapshots; the bytes are already ciphertext).
4. **Two explicit verbs** `purge_block` + `empty_trash`; retention auto-purge deferred (→ #402).
5. **Dedicated `FfiVaultError::BlockPurged`** so restore of a purged block is honestly typed (fails fast before any trash scan; marker in the signed manifest ⇒ unforgeable).

**Cross-device:** an open-time purge-cleanup sweep (`repair/sweep.rs::sweep_purged_trash_files`, gated on "not live in `manifest.blocks`" so a concurrent restore wins) propagates a purge across the owner's devices via manifest file sync. Conflict-copy trash-list merge-monotonicity is a **pre-existing durability-only gap** deferred to **#401** (the sync merge is `open.manifest.clone()` — it never reconciles trash lists, purged or not).

### Branch commits (off `main` @ `ca01b3a`, in order)
- `d113c3b` design · `7a8bd02` scope-refine (merge-monotonicity → follow-up) · `639e9e9` plan
- `641d646` T1 `purged_at_ms` field · `8c86582`+`6f04d58` T2 `BlockPurged`+restore guard (+fail-fast fix)
- `bb76dab` T3 `purge_block`+`PurgeReport` · `f508a77` T4 purge-cleanup sweep · `a9c684e` T5 `empty_trash`
- `3a2eb4e`+`5fb693e` T6 vault-format §7.2 (+wording fix) · `34b2577` T7 `conformance.py` §P
- `6516918`+`717fdbb` T8 `FfiVaultError::BlockPurged` threaded (+quote fix) · `bf2d0ef` T9 bridge `purge_block` · `df29e04` T10 bridge `empty_trash`+list-skip
- `c61df12` T11a vectors+Rust replay+pyo3 · `c9ad821`+`c642a40` T11b swift/kotlin runners (+parity fix)
- `e88ad73` README + ROADMAP
- → then this docs/handoff commit.

### Acceptance (all verified green this session, from the worktree)
```bash
cargo test --release --workspace                                  # full suite green
cargo test --release --workspace --features differential-replay   # cross-language replay green
cargo clippy --release --workspace --tests -- -D warnings         # clean
cargo fmt --all --check                                           # clean
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace        # clean
uv run core/tests/python/conformance.py                           # §P purge scenario passes
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh      # 38/38
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh     # 38/38
cd android && ./gradlew :kit:assemble :app:assembleDebug          # BUILD SUCCESSFUL
# pyo3: cd ffi/secretary-ffi-py && uv run --with pytest pytest     # 118/118
```
Desktop: `cd desktop && pnpm run check` (svelte-check 0/0) + `pnpm test` (606/606) — the desktop error plumbing gained a typed `AppError::BlockPurged` (see risks §3).

**Final opus whole-branch review: Ready to merge = Yes, 0 Critical / 0 Important.** It independently strengthened the safety argument: beyond the by-construction invariant, **directory separation** (`trash/<uuid>.cbor.enc.*` vs `blocks/<uuid>.cbor.enc`) makes deleting a *live* block's ciphertext unreachable even under a corrupt both-live-and-trashed manifest, and the sweep runs *after* manifest authentication so a forged marker can't drive a delete.

## (2) What's next

Menu (updated — #399 shipped; #401/#402 are its offspring):

1. **#401 (NEW) — conflict-copy trash-list reconciliation / purged-marker merge monotonicity.** The natural #399 sequel. C-layer sync work in `core/src/sync/commit/write.rs`. **Acceptance:** the merge unions `TrashEntry` records from both conflict copies; purged is monotone (purged-if-either-side; max millis; `None` loses to `Some`; never un-purges); a purged-tombstone merge KAT added to `conflict_kat.json` + `conformance.py`. Durability-only (no security exposure), but closes the "purge didn't stick across a conflict merge" gap.
2. **#402 (NEW) — retention auto-purge (§7 step 5).** Design-heavy → **brainstorm first** (auto-deletes without user action; when does it run, consent model, interaction with the open-time sweeps). Builds on `purge_block` ("purge every `TrashEntry` older than the window").
3. **Manual GUI smoke of the #374 consent flow** (human-only, still carried): `pnpm tauri dev` against a **temp copy** ([[feedback_smoke_test_temp_copy_golden_vault]]) of a vault with staged crashed-share residue (`core/tests/crash_recovery.rs::stage_crashed_share`). Unlock → "Repair now?" → consent dialog renders added recipient + grouped fingerprint → Cancel leaves vault untouched → Grant adopts the widened set.
4. **Housekeeping:** #387 (`:kit` NewApi lint on `StrongBoxUnavailableException`, min SDK 26 / API 28), #290 (`spec_test_name_freshness.py` 3 D.4 design-concept false-positives — Python, your strong area), #383 (drop RUSTSEC-2026-0194/0195 from `.cargo/audit.toml` **only** when `cargo tree -i quick-xml --target all` shows a single quick-xml ≥0.41).
5. **Carried mobile (on-device / human-only):** iOS Face ID spot-check; Android #338 on-device biometric cloud-open, #331 SAF custom-ROM, #334 native cloud-provider epic (ADR + threat-model first).
6. **Optional purge UI (platform, deferred from #399):** desktop/iOS/Android "Delete forever" / "Empty Trash" over the shipped FFI surface — each a separate slice. The desktop already has a typed `AppError::BlockPurged` + user message (from the T8 exhaustive-match plumbing), but no purge *command/button* was wired.

## (3) Open decisions and risks

- **Desktop scope touch (disclosed).** T8 added `FfiVaultError::BlockPurged`, whose workspace-wide exhaustive-match obligation reached `desktop/src-tauri` (a wildcard-free `map_ffi_error` that would break `cargo build --workspace`) — **compile-forced**, minimally scoped. The matching `desktop/src/lib/errors.ts` typed `block_purged` user-message was **not** compile-forced but kept for UX coherence (a typed `AppError::BlockPurged` rendering as a generic "Unknown error" would be a half-wired inconsistency). No purge command/UI was added. The final opus review judged this **sound** (`BlockPurged` is already reachable today via the existing restore command once a purge syncs from another device). If you'd rather the TS half were reserved for a UI slice, it's a clean revert.
- **4 per-task Minors, all triaged LEAVE by the final review** (documented, not silent): T3 test hardcodes `".cbor.enc"` (consistent with production `restore_block`/`list.rs` — fixing would *create* inconsistency); T5 no `files_failed>0` test (needs a platform-flaky permission fault; field is wired from real fs errors); T10 `live_uuids` name-cache memo not pruned for purged entries (bounded, in-memory, cleared on `wipe`); T11a ~50-line KAT match-boilerplate dup (matches the file's existing inlined pattern). None block merge.
- **#401 durability gap** is real but **not a security hole** — a dropped purged marker across a conflict merge means the purge didn't stick for one device pairing; nothing is exposed that a recipient/device didn't already hold. The common single-writer propagation works today via the sweep.
- **No crypto / KEM / signature-site / equal-clock change**; no `manifest_version` bump; `#![forbid(unsafe_code)]` intact.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After this PR merges, drop the branch + its worktree (squash-merge leaves it "not fully merged"):
#   git worktree remove .worktrees/purge-399 && git branch -D feature/purge-empty-trash-399
git worktree list && git status -s
# Re-run the core purge suite any time:
cargo test --release -p secretary-core purge && cargo clippy --release --workspace --tests -- -D warnings
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; the symlink retargeted in the same commit on the feature branch (new path → no add/add conflict; `main` updates cleanly on merge). Per the baton convention the handoff rides inside the PR — do **not** sync to `main` during the pause window.

## Closing inventory
- **State on close:** PR opening on `feature/purge-empty-trash-399` (worktree `.worktrees/purge-399`). 21 branch commits (3 design/plan + 16 task/fix + 1 README/ROADMAP + this handoff). #399 closes on merge (comment recording the deliberate deferrals → #401 merge-monotonicity, #402 retention auto-purge; overwrite = decision-3 non-action).
- **Acceptance:** full workspace green; clippy `-D warnings`, `cargo fmt --all --check`, rustdoc `-D warnings` clean; `conformance.py` §P + differential-replay green; Swift 38/38 · Kotlin 38/38 · pyo3 118/118; `:kit`/`:app` assemble clean; desktop svelte-check 0/0 + pnpm test 606/606. Final opus whole-branch review: Ready to merge = Yes.
- **Follow-ups filed:** [#401](https://github.com/hherb/secretary/issues/401) (conflict-copy merge-monotonicity), [#402](https://github.com/hherb/secretary/issues/402) (retention auto-purge).
- **README / ROADMAP:** updated (unlike #376 — purge is a new FFI lifecycle tier, sibling to the B.5 trash/restore row).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-07-08-purge-empty-trash-399-shipped.md`.
