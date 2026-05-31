# NEXT_SESSION.md — D.1.5 ✅ delete/trash (record tombstone/resurrect + block trash/restore)

**Session date:** 2026-05-31 (D.1.5 — the fifth Sub-project D feature slice, built on D.1.1–D.1.4). Authored spec + plan via brainstorming → writing-plans, then executed all 7 implementation tasks via subagent-driven development (one implementer per task + spec review + quality review after each + final whole-branch review).
**Status:** D.1.5 ✅ complete on branch `feature/d15-delete`; **PR open** against `main` (final whole-branch review: Ready to merge / security CLEAN on all invariants). A follow-up code review was run on the PR and its findings applied (errors.rs bridge-contract comment; RecordList/TrashView loader race guards; #172 filed). All automated gates green. The one human gate left is the **manual GUI smoke** (§(3)) — it cannot run headless; it is the pre-merge gate.

## (1) What we shipped this session

A user with an **unlocked vault** can now **delete and restore** data from the desktop app, at two levels:
- **Delete (tombstone) a record** → confirm dialog → the record leaves the list (it survives in the block file for CRDT merge).
- **Show deleted + resurrect** → a "Show deleted" toggle reveals tombstoned records (greyed); each offers Restore (resurrect at a newer clock, fields intact).
- **Trash a block** → confirm dialog → the whole block moves to `trash/` and leaves the blocks list.
- **Trash view + restore** → a "🗑 Trash" entry lists trashed blocks **by name** (each decrypted just enough for its name); each offers Restore.

**Scope decision (made this session):** the original baton bundled "share" into D.1.5. Sharing needs a net-new **desktop contacts subsystem** (enumerate/load contact cards + a recipient picker) that delete/trash don't, so share was **split out into its own D.1.6 slice** with its own spec → plan cycle. D.1.5 = delete/tombstone + trash/restore only.

Key properties (verified by the final whole-branch review — **security CLEAN**):
- **Rust is the gatekeeper for tombstoned-record visibility.** The block-detail read takes `include_deleted: bool` (default `false`). The "Show deleted" toggle **re-reads with `include_deleted=true`** rather than the client filtering withheld data — a tombstoned record's existence never crosses the IPC seam unless explicitly requested, and even then carries **no field values**. The single-field reveal path still **refuses** tombstoned records (only `resurrect_record` reads one, inside the bridge).
- **`unknown` preserved across tombstone AND resurrect** at block/record/field level — the keystone test (`edit/tombstone.rs`) pins three-level survival across both ops, with fields NOT cleared on tombstone and `tombstoned_at_ms` preserved on resurrect.
- **Whole-block plaintext confined to the bridge.** `list_trashed_blocks` decrypts each trashed file via the extracted `decrypt_block_file_bytes` (shared with `decrypt_block_plaintext`; the secret-key `drop()` wipe timing is byte-for-byte preserved) and returns **only** names + metadata; record plaintext drops per iteration, never reaches JS.
- **`TrashedBlockDto` Debug redacts the block name.**
- **Bridge `trash_block`/`restore_block` already existed (B-phase)** — D.1.5 only wired them; the net-new bridge primitives were `tombstone_record`, `resurrect_record`, and `list_trashed_blocks`.

All commits are on `feature/d15-delete` (branched from `main` @ `cbdb746`):

| Commit | What it landed |
|---|---|
| `bef91f7` | D.1.5 design spec (`docs/superpowers/specs/2026-05-30-d15-delete-trash-design.md`, 16 sections; Rust-gatekeeper revision after review). |
| `00bddb1` | D.1.5 implementation plan (`docs/superpowers/plans/2026-05-30-d15-delete-trash.md`, 8 tasks). |
| `a449f5a` | **Task 1** — `tombstone_record`/`resurrect_record` bridge primitives (native-BlockPlaintext, flip-one-flag, fields kept) + `unknown` keystone. |
| `b83409e` | **Task 1 review fix** — dedupe test consts via `super::super::`, symmetric resurrect error test, monotonic-clock doc. |
| `a89207d` | **Task 2** — `list_trashed_blocks` + extracted `decrypt_block_file_bytes` (shared decrypt tail, wipe timing preserved). |
| `8d9daf4` | **Task 2 review fix** — canonical-decimal `<ts>` guard matching core `restore_block`, reuse `handle_wiped()`, newest-ts-wins test + `tombstoned_by`. |
| `6191ee6` | **Task 3** — typed `AppError::BlockRestoreConflict` + `TrashEntryNotFound` + `map_ffi_error` routing of the bridge `BlockUuidAlreadyLive`/`BlockNotInTrash` variants. |
| `08cbd55` | **Task 4** — `TrashedBlockDto` (redacted Debug) + `RecordDto.tombstoned` + `include_deleted` gate on `read_block`/`project_block_detail` (Rust gatekeeper; `locate_record` still refuses tombstoned). |
| `13b721f` | **Task 4 review fix** — list all `dtos` submodules in the `mod.rs` header. |
| `51ff6e2` | **Task 5** — `commands/delete.rs` (5 IPC commands + `*_impl`) + register in `main.rs` + L3 tests; shared `block_summary_for` (also adopted by `create_block_impl`). |
| `b646744` | **Task 6** — frontend `lib/trash.ts` (`sortTrashed`/`formatTrashedWhen`), 5 ipc wrappers + `readBlock(includeDeleted)` + `RecordDto.tombstoned` + `TrashedBlockDto`, two error codes, browse `trash` level + `openTrash`. |
| `2a6ae11` | **Task 7** — `ConfirmDialog`/`TrashView`/`TrashedBlockRow` + RecordList "Show deleted" toggle/delete/restore + RecordRow/BlockCard actions + Vault trash pane/entry + `theme.css`. |
| `09fea52` | **Task 7 review fix** — restore the RecordList in-flight fetch cancel guard (stale-write race the `load()` extraction dropped), tokenize the danger-button text, add a delete-confirm→`tombstone_record` test. |
| _(ship)_ | README/ROADMAP D.1.5 ✅ + this handoff + symlink retarget. |

**Process note:** one worktree (`.worktrees/d15-delete`), one reviewed commit per task + inline review-fix commits. Every per-task spec+quality review finding was fixed before proceeding; the final whole-branch review found zero issues.

### Automated gauntlet (run on `feature/d15-delete`)

```
Rust:        PASSED 1121 FAILED 0 IGNORED 10   (+19 over the D.1.4 baseline of 1102)
cargo clippy --release --workspace --tests -- -D warnings   → clean
cargo fmt --all -- --check                                  → clean
uv run core/tests/python/conformance.py                     → PASS
uv run core/tests/python/spec_test_name_freshness.py        → PASS  (no KAT change: tombstone/resurrect use existing wire fields)
Swift conformance:   22/22 PASS   (no binding-contract change — new primitives are bridge-only)
Kotlin conformance:  22/22 PASS

Frontend:    Vitest 331 / 0   (new over D.1.4: trash, ipcTrash, browseTrash, ConfirmDialog,
             TrashView, RecordListDelete + errors/ipc/RecordList updates)
pnpm typecheck      → clean
pnpm svelte-check   → 0 errors, 3 warnings (the 3 pre-existing D.1.4 state_referenced_locally;
                      no NEW warnings from D.1.5)
pnpm lint           → clean
```

## (3) ⚠️ Manual GUI smoke — the user's pre-merge gate (NOT run this session; headless-impossible)

> **⚠️ Smoke against a TEMP vault copy, never the git-tracked golden fixture.** See [[feedback_smoke_test_temp_copy_golden_vault]]. D.1.5 writes INTO the vault (tombstone + trash mutate it), so mutating the tracked fixture breaks KATs.

```bash
cd /Users/hherb/src/secretary/.worktrees/d15-delete/desktop
pnpm install && pnpm tauri build --debug
# Create a fresh vault via the D.1.3 wizard (or cp -R an existing test vault to a tempdir), then unlock into it.
./src-tauri/target/debug/secretary-desktop
```

Walk (spec §15): unlock → add a couple of records to a block → **Delete** one (confirm) → it disappears → toggle **Show deleted** → it appears greyed → **Restore** it → back in the live list → **Trash** the block (confirm) → it leaves the blocks list → open **🗑 Trash** → it appears **by name** → **Restore** it → back in the blocks list → re-open the vault → confirm all states persisted. If any step fails it's a D.1.5 regression; don't merge until fixed.

## (2) What's next — D.1.6 (share a block + the contacts subsystem)

D.1.5 deferred sharing because `core::share_block` needs the author card + secret keys + **all** existing recipient cards + the new recipient card, and there is **no desktop contacts surface yet**. D.1.6 builds that surface, then wires share.

**Acceptance criteria:**
- **Contacts subsystem (the new part):** bridge primitives to enumerate the vault's `contacts/*.card` files and load a contact card by id (NB: `core` contact-card structs + `share_block` exist; the bridge enumerate/load is net-new — confirm what's already there before planning). Desktop IPC commands + ipc wrappers + a contact-picker UI.
- **Share flow:** from a block's detail or card, pick a loaded contact → wrap the bridge's existing `share_block` primitive (already re-exported in `ffi/secretary-ffi-bridge/src/lib.rs`). IPC command `share_block`. Surfaces `NotAuthor`/`RecipientAlreadyPresent`/`MissingRecipientCard` as typed `AppError`s (they currently fold to `Internal` in `map_ffi_error` — D.1.6 routes them, mirroring how D.1.5 routed the trash/restore variants).
- Gauntlet: Rust +N (bridge + IPC tests, ephemeral-tempdir vaults, runtime-random crypto); Vitest +N (picker + share UI); typecheck/svelte-check/lint clean; manual smoke against a temp vault copy (needs two identities/contact cards).
- Author the D.1.6 plan via `superpowers:brainstorming` → `superpowers:writing-plans` before touching code; mirror the D.1.5 spec/plan structure.

## (3b) Open decisions and risks

- **Manual GUI smoke is the pre-merge gate** (§(3)). Until #161's L4 e2e lands, every D.1.x ship leans on a human walk-through.
- **Deferred-FFI tracking issue #167** — now also covers the D.1.5 primitives: `tombstone_record`/`resurrect_record`/`list_trashed_blocks` are NOT mirrored on uniffi (Swift/Kotlin) or pyo3 (no mobile/Python consumer yet). Wire them when D.3 (mobile) or a Python consumer needs record delete/trash. Not a D.1.6 blocker.
- **New issue filed this session: #170** — hoist the `state.lock()` session-lock boilerplate into `commands::shared` (`lock_session`, already extracted in `delete.rs`) and adopt it in `edit.rs`. Pure mechanical tidy-up; not a blocker.
- **Restore-conflict path note:** restoring a *live* block hits core's live-collision check first (`BlockUuidAlreadyLive` → `BlockRestoreConflict`); only a never-live-never-trashed uuid reaches `TrashEntryNotFound`. The `BlockRestoreConflict` mapping is unit-tested at the desktop layer (Task 3); the full live+trashed collision is exercised by core/bridge tests (it's not constructable at the desktop L3 since uuids are random).
- **Carry-forwards, all still live:**
  - **#153** — component styles in `theme.css` (Vite 6 `preprocessCSS` blocked); D.1.5 adds `.confirm-dialog*`/`.trash-view*`/`.trashed-row*`/`.record-row--deleted` rules there.
  - **#154** — emoji/glyphs → inline SVG (D.1.5 adds the "🗑" Trash glyph).
  - **#161** — L4 e2e harness deferred (no tauri-driver on macOS WKWebView).
  - **#162** — PathPicker e2e hook.
  - **#164** — Esc-to-pop from D.1.2.

### Verified non-issues (don't re-investigate)
- **RecordList fetch race:** the in-flight cancel guard was restored in `09fea52` — a superseded `readBlock` (block switch / toggle) can no longer write stale records.
- **`map_ffi_error` `BlockNotFound → Internal` for trash/restore:** intentional. Record ops (tombstone/resurrect) need `BlockNotFound` typed (record-deleted-under-editor), so they use `map_record_delete_error`; block ops fold an unknown-block to `Internal` (a frontend bug, since you only trash blocks you can see). Reviewed and accepted.
- **`TrashedBlock` (bridge) derives `Debug` exposing the name:** acceptable — it never crosses IPC and is not logged; the redacting `Debug` is on the `TrashedBlockDto` at the actual boundary.

## (4) Exact commands to resume (D.1.6)

```bash
# Merge the D.1.5 PR first (feature/d15-delete) after the manual smoke, then:
cd /Users/hherb/src/secretary
git fetch --prune origin
git checkout main
git pull --ff-only origin main
git log -5 --oneline           # confirm the D.1.5 ship PR landed

# Re-baseline the automated gauntlet on fresh main:
cargo test --release --workspace --no-fail-fast 2>&1 | grep "^test result:" | awk '$3=="ok." {p+=$4; f+=$6; i+=$8} END {printf "Rust totals → PASSED %d FAILED %d IGNORED %d\n", p, f, i}'
# Expect: PASSED 1121 FAILED 0 IGNORED 10 (D.1.5 baseline)
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh 2>&1 | tail -3
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh 2>&1 | tail -3
cd desktop && pnpm install && pnpm test && pnpm typecheck && pnpm svelte-check 2>&1 | tail -3 && pnpm lint && cd ..
# Expect: Vitest 331 passing

# Author the D.1.6 plan:
#   superpowers:brainstorming  → scope the contacts subsystem + share flow
#   superpowers:writing-plans  → mirror docs/superpowers/plans/2026-05-30-d15-delete-trash.md

# Then the first implementation worktree:
git worktree add .worktrees/d16-share -b feature/d16-share main
cd .worktrees/d16-share/desktop && pnpm install
```

### Housekeeping (after the D.1.5 PR merges)
```bash
cd /Users/hherb/src/secretary
git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/d15-delete 2>/dev/null && git branch -D feature/d15-delete 2>/dev/null
git worktree prune && git worktree list
```

## (5) Handoff file model

`NEXT_SESSION.md` at the repo root is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Author the handoff once; the symlink is a pointer. To open the next slice: author `docs/handoffs/<date>-d16-*.md` and `ln -snf docs/handoffs/<new>.md NEXT_SESSION.md`, committing both on the feature branch (per [[feedback_next_session_in_pr]]).

## Closing inventory

- **Branch on close:** `main` @ `cbdb746`. `feature/d15-delete` carries the spec + plan + 7 task commits + 4 review-fix commits + the ship commit (this handoff + symlink + README/ROADMAP). Squash-merge collapses to one commit on `main`.
- **Automated gauntlet:** Rust **1121 / 0 / 10**; clippy clean; fmt clean; conformance PASS; spec-freshness PASS; Swift 22/22; Kotlin 22/22; Vitest **331 / 0**; typecheck clean; svelte-check 0 errors / 3 pre-existing warnings; lint clean.
- **Final whole-branch review:** ✅ **Ready to merge** — zero Critical/Important/Minor issues. Security verdict **CLEAN** on all five invariants (Rust-gated tombstone visibility; reveal still refuses tombstoned; whole-block plaintext confined to the bridge; secret-key `drop()` timing preserved through the `decrypt_block_file_bytes` extraction; `TrashedBlockDto` Debug redaction). Frozen `core/` untouched (zero `core/` changes).
- **PR:** opened against `main` (`feature/d15-delete`). Merge is gated on the user's manual GUI smoke (§(3)).
- **README.md / ROADMAP.md:** D.1.5 marked ✅; D.1.6 next.
- **CLAUDE.md / `docs/adr/`:** unchanged (no format/architecture change).
- **Issues filed this session:** #170 (hoist `lock_session` into `commands::shared`).
- **NEXT_SESSION.md:** symlink retargeted to this file.
- **This file:** the live D.1.5 ship baton. The next slice opens with `docs/handoffs/<date>-d16-*.md`.
