# NEXT_SESSION.md — #196 ✅ honest resurrect for no-content tombstones

**Session date:** 2026-06-08 (follow-on to D.1.15; closes the data-loss-UX bug the D.1.15 GUI smoke surfaced). Brainstormed via `superpowers:brainstorming` → spec via `superpowers:writing-plans` → executed via `superpowers:subagent-driven-development` (fresh implementer per task + spec-compliance + code-quality review after each + a final whole-branch review).
**Status:** ✅ code-complete on branch `feature/honest-resurrect`. **PR: see §4.** Full **desktop gauntlet green** (478 tests / typecheck / svelte-check / lint). Final whole-branch review: **APPROVE TO MERGE**, zero Critical/Important.
**⚠️ One outstanding gate — the manual GUI smoke** (this slice ships UI). Not automatable here (macOS Tauri e2e blocked — [#161](https://github.com/hherb/secretary/issues/161)). Needs a real merge-tombstone (the #195 `stage_smoke_vault` helper produces one). Run on a **`cp -R` temp copy** before merging — see §3/§4.

## (1) What we shipped this session

Issue **[#196](https://github.com/hherb/secretary/issues/196)**: resurrecting a record that was tombstoned by a sync merge ("Accept delete") silently brought back an **empty** record (the §11.3 merge-tombstone path drops a record's fields), whereas resurrecting a *locally*-deleted record restores its content — same "Restore" button, different outcome, no signal. Reads as data loss / a broken undelete.

**Key reframe (why this is desktop-only):** the issue feared we'd have to *distinguish merge- vs local-tombstone provenance*, which would mean a new flag on the **frozen** on-disk format + CRDT-proptest risk. Not needed. The user-facing fact is *"will resurrect give back anything?"* — answerable directly from data the desktop **already has on the wire**: `RecordDto` carries `tombstoned` and `fieldCount`, and a merge-tombstoned record arrives with `fieldCount === 0`. So the signal is just **`tombstoned === true && fieldCount === 0`**. No `core`, no FFI, no on-disk-format change, no CRDT-proptest risk → **no cross-language conformance run required.**

**Three UI layers** (all `desktop/`):
- **`src/lib/records.ts`** (new) — pure predicate `isContentlessTombstone(record)`.
- **`src/components/RecordRow.svelte`** — a muted italic "· no recoverable contents" hint on contentless-tombstone rows, folded into the row button's `aria-label` (pre-empts the surprise before the click). Style lives in `theme.css` (the component has no scoped styles).
- **`src/components/RecordList.svelte`** — a `ConfirmDialog` gate: resurrecting a contentless tombstone confirms first ("Resurrect an empty record?"); a still-filled tombstone resurrects one-click (lossless undelete, **unchanged**). Mirrors the existing `pendingDelete`/`confirmDelete` pattern (`pendingRestore`/`confirmRestore`/`doRestore`).

Copy is **content-based, not provenance-asserting** ("This record has no stored contents to recover — … Contents are discarded when a record's deletion is merged from another device."): honest even for the degenerate case of a locally-deleted genuinely-empty record (which also matches the predicate and would equally yield an empty shell).

Commits on `feature/honest-resurrect` (branched from `main` @ `273c79a`):

| Commit | What it landed |
|---|---|
| `4a14b13` | design spec |
| `76a9ba3` | 4-task TDD plan |
| `5a578c6` | Task 1 — `isContentlessTombstone` predicate + 5 tests |
| `2449300` / `92e5efa` | Task 2 — RecordRow hint + aria-label (+ DRY ariaLabel review nit) |
| `862155b` / `81ff69c` | Task 3 — RecordList confirm gate (+ **fix**: a stray editor smart-quote pass had swapped the ASCII `"` ConfirmDialog attribute delimiters for U+201D on **both** dialog blocks, breaking svelte-check — restored ASCII) |
| `7f5b5d7` | Task 4 — muted italic hint style in `theme.css` |
| `0d6cc9e` | final-review nit — drop needless `async` on `RecordList.onDelete` (symmetry with the new sync `onRestore`) |
| _(ship)_ | this handoff + symlink retarget |

**Process note (worth carrying forward):** the editor/disk-desync gremlin in these worktrees struck again — a Task-3 edit silently converted straight `"`/`'` into curly Unicode quotes and broke `svelte-check` (it mis-parsed words inside the attribute strings as unknown component props). Caught by the code-quality reviewer running `svelte-check` (lint alone did NOT catch it — eslint doesn't type-check templates). **Always run `svelte-check`, not just lint, after editing `.svelte` attribute strings**; grep for U+2018/2019/201C/201D delimiters if a parse error names a word-inside-a-string as a bad prop.

### Desktop gauntlet (re-run clean on the branch @ HEAD)
```
cd desktop
pnpm test         → 62 files, 478 tests, 0 failed
pnpm typecheck    → clean
pnpm svelte-check → 311 files, 0 errors, 0 warnings
pnpm lint         → clean
```
Rust workspace untouched (no `core`/FFI change) → still green; cross-language conformance **not required** (no FFI-surface change).

## (2) What's next

No slice is pre-committed. Honest next-deferred (pick one → brainstorm → plan → execute):

- **Background auto-sync** — the `notify`-driven daemon loop (C.2 `secretary-sync run`) surfaced in-app so sync happens without a manual click; the pill reflects live status. Acceptance: a vault syncs on file-change with a debounce; the pill updates; must coordinate with `SyncInProgress` (lockfile) so a daemon + a manual click (or an open resolution/resurrect modal) don't fight. Interacts with the D.1.15 resolution flow — a background pass that hits a veto must surface it without stomping an open modal.
- **[#187](https://github.com/hherb/secretary/issues/187)** — project `sync_vault`/`sync_status`/`sync_commit_decisions` + the conflict DTOs onto uniffi+pyo3 (mobile/Python; pairs with #167). Pure FFI-surface slice; **triggers the full workspace gauntlet + Swift/Kotlin conformance** ([[project_secretary_ffivaulterror_workspace_match]]).
- **Reveal-to-decide** — let the user inspect the actual winner/loser field values (reveal-gated) to decide a veto/collision. `FieldCollision` already preserves both values; separate reveal-gated feature (out of D.1.15 scope).

**Acceptance criteria for whichever is chosen:** author via `superpowers:brainstorming` → `superpowers:writing-plans`. If it touches `core`/`ffi`/`FfiVaultError`/UDL, the full workspace gauntlet **and** the Swift+Kotlin conformance runs are mandatory; a pure-desktop slice does not need them. Any mutation path needs the confirm + strict typed-error-surfacing care, and a manual GUI smoke on a **`cp -R` temp copy** of the golden vault ([[feedback_smoke_test_temp_copy_golden_vault]]).

**Open follow-up issues:** **#192** (collision-population test), **#193** (pipeline.rs refactor/real-race/orphaned-pass), plus carried **#186/#189/#190/#161/#162/#167/#187**.

## (3) Open decisions and risks

- **⚠️ Outstanding gate: the manual GUI smoke (do before merge).** Build a real merge-tombstone on a temp golden copy via the #195 `stage_smoke_vault` helper; verify: deleted-list row shows the "no recoverable contents" badge → Restore opens the confirm with the empty-record copy → Confirm brings back the empty record (expected now, explained) and the badge is gone → on a fresh run, Cancel/Esc closes without writing. See §4.
- **Predicate matches a degenerate local case too.** A genuinely-empty *locally*-deleted record (fieldCount 0) also trips the hint+confirm. Accepted: resurrect *would* yield an empty shell, so the warning is honest; the body's first sentence ("no stored contents to recover") is the operative truth, the "merged from another device" sentence is the common-cause explanation. Near-zero-probability workflow; the tradeoff buys "no provenance flag on the frozen format". Documented in the `isContentlessTombstone` JSDoc.
- **No core/format/CRDT change** — the §11.3 field-drop on merge-tombstone is correct and unchanged; this slice is purely how the *desktop* presents the consequence.

### Verified non-issues (don't re-investigate)
- **Delete-confirm flow intact:** `pendingDelete`/`confirmDelete`/the delete dialog are byte-identical to `main` after the encoding fix; reviewer confirmed.
- **Accessibility:** `aria-label` overrides the button's inner text for the accessible name, so the visible hint span does **not** double-announce; the "Restore record" label is on the separate action button.
- **Encoding:** ConfirmDialog attribute delimiters are ASCII `"` on both blocks (`grep -nP '=[\x{201C}\x{201D}]' desktop/src/components/RecordList.svelte` → empty). The em-dash and the pre-existing curly "Show deleted" are content, not delimiters.

## (4) Exact commands to resume

```bash
# 0) Manual GUI smoke BEFORE merging (the one outstanding gate). Build a real merge-tombstone:
cd /Users/hherb/src/secretary/.worktrees/honest-resurrect
SMOKE_OUT=/tmp/veto_smoke cargo test --release -p secretary-cli --test sync_pass_integration -- --ignored stage_smoke_vault --nocapture
cd desktop && pnpm tauri dev
#   open /tmp/veto_smoke → Sync now → Accept delete (merge-tombstones the record)
#   → Show deleted → row shows "no recoverable contents" badge
#   → Restore → confirm dialog with the empty-record copy
#   → Confirm → empty record returns (expected, explained); badge gone
#   → (fresh run) Cancel/Esc → no change, dialog closes. Record in the PR.

# 1) PR (created this session — confirm / review):
cd /Users/hherb/src/secretary && gh pr list --head feature/honest-resurrect

# 2) Merge once the smoke passes (squash), then housekeeping:
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/honest-resurrect && git branch -D feature/honest-resurrect
git worktree prune && git worktree list

# 3) Next slice: brainstorm → plan → execute (see §2). First worktree:
git worktree add .worktrees/<slug> -b feature/<slug> main
```

## (5) Handoff file model

`NEXT_SESSION.md` at the repo root is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Author the handoff once; the symlink is a pointer. To open the next slice: author `docs/handoffs/<date>-<slug>-shipped.md` and `ln -snf docs/handoffs/<new>.md NEXT_SESSION.md`, committing both on the feature branch (per [[feedback_next_session_in_pr]]). main did NOT move during this session (branch point == origin/main == `273c79a`), so the symlink retarget merges cleanly.

## Closing inventory

- **Branch on close:** `main` @ `273c79a`; `feature/honest-resurrect` carries spec + plan + 6 task/review/style commits + this ship commit. Squash-merge collapses to one commit on `main`.
- **Desktop gauntlet:** green — 478 tests / typecheck / svelte-check (0/0) / lint. Rust untouched; no conformance run needed.
- **Final whole-branch review:** **APPROVE TO MERGE** — zero Critical/Important; one Minor (`onDelete` async nit) fixed in `0d6cc9e`.
- **Outstanding gate:** the manual GUI smoke (§3/§4) — this slice ships UI; needs a real merge-tombstone fixture.
- **README.md / ROADMAP.md:** unchanged — neither tracks individual bug-fix PR numbers, and both already cover D.1.15; nothing became inaccurate. (Deliberate no-op, not an oversight.)
- **CLAUDE.md / `docs/adr/`:** unchanged (no new on-disk-format/crypto decision).
- **Issues:** #196 fixed by this branch (close on merge). #192/#193 + #186/#189/#190/#161/#162/#167/#187 remain open.
- **NEXT_SESSION.md:** symlink retargeted to this file.
- **This file:** the live #196 ship baton. The next slice opens with `docs/handoffs/<date>-<slug>-shipped.md`.
