# NEXT_SESSION.md — D.1.14 ✅ desktop sync UI (TopBar "sync pill" + Sync-now password modal)

**Session date:** 2026-06-07 (D.1.14 — the desktop *verb* over the D.1.13 bridge sync primitives; mirrors D.1.10 primitive → D.1.11 UI). Brainstormed scope via `superpowers:brainstorming` (with the visual companion for the indicator/modal layout) → authored spec + 10-task TDD plan via `superpowers:writing-plans` → executed via `superpowers:subagent-driven-development` (fresh implementer per task + a spec-compliance review + a code-quality review after each + a final whole-branch review).
**Status:** D.1.14 ✅ code-complete on branch `feature/d114-desktop-sync-ui`; **PR open, not yet merged**. Full automated gauntlet **green**. Final whole-branch review: **APPROVE TO MERGE**, zero Critical/Important.
**⚠️ One outstanding gate — the manual GUI smoke.** Unlike D.1.13 (headless), this slice ships UI, so it carries a visual smoke gate that was **not** run automatically (macOS Tauri e2e is blocked — [#161](https://github.com/hherb/secretary/issues/161)). Run it (steps in §3) on a **`cp -R` temp copy** of the golden vault before merging.

## (1) What we shipped this session

The desktop sync UI, decomposed (mirrors **D.1.10** revoke-primitive → **D.1.11** revoke-UI): D.1.13 = the bridge primitive; **D.1.14 = the desktop UI** consuming it.

- **Combined "sync pill"** ([SyncPill.svelte](../../desktop/src/components/SyncPill.svelte)) in the TopBar — shows `lastSyncedLabel` ("Synced 2m ago" / "Never synced") and **is** the "Sync now" trigger. Reads `sync_status` on mount + after each sync; renders the outcome as an inline `role="status"`/`"alert"` notice (auto-dismiss after 5 s, matching `Toast`); calls the global `refreshManifest()` **only** on a data-changing outcome (the in-memory manifest goes stale when sync applies peer changes). Uses a new vendored `icons/Sync.svelte` (Lucide `refresh-cw`).
- **Centered password re-prompt modal** ([SyncPasswordDialog.svelte](../../desktop/src/components/SyncPasswordDialog.svelte)) — native `<dialog>` mirroring `ConfirmDialog` (callback props, `showModal()` on mount via `$effect`, Esc→`onCancel`). `sync_vault` re-opens an identity from the password (the frozen bridge surface takes a password, not the session identity), so the re-prompt is inherent. **Strict**: a failure renders the typed `AppError` inline (`role="alert"`) and keeps the dialog open to retry; the master password lives only in component state and is cleared on success **and** cancel/Esc.
- **Two Tauri commands** ([commands/sync.rs](../../desktop/src-tauri/src/commands/sync.rs)) — `sync_status` (read; projects the bridge status for the unlocked vault's uuid) + `sync_now` (mutation; `sync_vault(&vault_folder, SecretBytes::from(password.expose()), now_ms())`). Same `#[tauri::command]`+`_impl`+`lock_session`+`with_unlocked`+`map_ffi_error` shape as the other command modules.
- **Desktop DTOs** ([dtos/sync.rs](../../desktop/src-tauri/src/dtos/sync.rs)) — `SyncStatusDto` (drops the bridge's `device_clocks` — not surfaced in v1) + serde-tagged `SyncOutcomeDto` (`rename_all_fields` so `veto_count`→`vetoCount`). DTO serde wire-format pinned by unit tests.
- **`UnlockedSession.vault_folder: PathBuf`** ([session.rs](../../desktop/src-tauri/src/session.rs)) — retained at unlock so `sync_now` passes the folder to the bridge (the path stays server-side, not handed back from the renderer). Non-secret; Drop zeroize order unaffected.
- **The 5 D.1.13 sync `AppError` codes threaded into the TS layer** ([errors.ts](../../desktop/src/lib/errors.ts)) — `sync_in_progress` / `sync_evidence_stale` / `sync_state_vault_mismatch` / `sync_state_corrupt` / `sync_failed`, each with a real `userMessageFor` title+hint (the `SyncFailed` placeholder copy from D.1.13 now has a proper user-facing string here).
- **Pure helpers** ([lib/sync.ts](../../desktop/src/lib/sync.ts) + `formatRelativeTime` in [lib/format.ts](../../desktop/src/lib/format.ts)) — `syncOutcomeMessage` (the three applied/merged arms collapse to one "Synced — your vault is up to date"; `conflictsPending`→"N conflict(s) … coming soon"; `rollbackRejected`→error), `syncChangedData` (exhaustive switch), `lastSyncedLabel`. All pure, table-tested.

**Architecture: pure D-phase desktop slice.** No `core` / `ffi` / `FfiVaultError` / UDL / **bridge** change (the final reviewer confirmed the diff is confined to `desktop/`, `README.md`, `ROADMAP.md`, `docs/superpowers/`), so **no cross-language conformance run** was needed ([[project_secretary_ffivaulterror_workspace_match]]). Desktop tests are **seam-only-hermetic** (NotUnlocked path + DTO wire-format); the end-to-end sync path stays covered by D.1.13's bridge `TempDir` tests + the manual GUI smoke (decision recorded in spec §7 — the bridge's public `sync_status`/`sync_vault` use the default OS state dir and the `_in` variants are `pub(crate)`, so a hermetic E2E desktop test isn't possible without a bridge change, which we declined).

Commits on `feature/d114-desktop-sync-ui` (branched from `main` @ `5933527`):

| Commit | What it landed |
|---|---|
| `0c1b4b2` | D.1.14 design spec. |
| `c30b76f` | spec §7 scope-correction (seam-only hermetic desktop tests; no bridge change). |
| `0f53090` | 10-task TDD plan. |
| `081f502` | Task 1 — `UnlockedSession.vault_folder`. |
| `d57c483` | Task 2 — desktop sync DTOs + wire-format tests. |
| `7c28264` | Task 3 — `sync_status`/`sync_now` Tauri commands + registration. |
| `6834c6b` | Task 4 — TS `AppError` sync variants + real `sync_failed` copy. |
| `c57df6c` | Task 5 — pure sync helpers (`syncOutcomeMessage`/`syncChangedData`/`lastSyncedLabel`/`formatRelativeTime`). |
| `e7bb1a9` | Task 6 — `syncStatus`/`syncNow` IPC wrappers. |
| `94cbb79` | Task 7 — `SyncPasswordDialog`. |
| `c28a429` | Task 8 — `SyncPill` (+ auto-dismiss, `icons/Sync.svelte`). |
| `a994c55` | Task 9 — mount `SyncPill` in the TopBar. |
| `31f1229` | `cargo fmt` the desktop sync code (whitespace only — caught by the final gauntlet). |
| `34246d1` | README + ROADMAP D.1.14 ✅. |
| _(ship)_ | this handoff + symlink retarget. |

**Process notes (plan-improvements for next time):**
- The per-task **Rust** steps ran `cargo build` + clippy but **not `cargo fmt --check`**, so a non-sorted import + a few long signatures slipped through to the final gauntlet (fixed in `31f1229`). Add `cargo fmt --all --check` to each Rust task's verify step in future plans.
- Two tasks (6 & 7) hit a **Vitest v4 quirk**: the persistent `mockRejectedValue` on a hoisted mock registers a spurious unhandled rejection that fails the test even when the promise is caught. Use `mockRejectedValueOnce` (+ a one-line comment) for rejection-path tests. The Task 7 implementer agent died mid-run on an infra API error; recovery confirmed the files were written but uncommitted, and a fresh implementer diagnosed the same quirk and got 4/4 green.

### Automated gauntlet (re-run clean on `feature/d114-desktop-sync-ui` @ HEAD)

```
# Frontend (desktop/)
pnpm test            → 59 files, 452 tests, 0 failed
pnpm typecheck       → clean
pnpm svelte-check    → 0 errors, 0 warnings (306 files)
pnpm lint            → clean
# Rust (desktop/src-tauri/)
cargo fmt --all --check                  → clean
cargo clippy --tests -- -D warnings      → clean
cargo test                               → 178 passed (113 lib + 48 ipc_integration + 17 session_integration), 0 failed
# (no core-workspace conformance run — pure desktop slice, no core/ffi/FfiVaultError/UDL/bridge change)
```

## (2) What's next

No slice is *pre-committed* after D.1.14. The honest next-deferred items (pick one and brainstorm → plan → execute):

- **Interactive conflict resolution** — the veto-resolution UX over `DraftMerge`. D.1.14 surfaces `ConflictsPending { veto_count }` as "N conflicts need resolution — **coming soon**"; this is the UI that makes it real. Acceptance: a user can review each tombstone veto and choose keep/delete, driving a `commit_with_decisions`-style bridge call. **Likely needs a new bridge primitive** (the draft-merge surface), so probably NOT a pure-desktop slice — scope it carefully.
- **Background auto-sync** — the `notify`-driven daemon loop (the C.2 `secretary-sync run` behavior) surfaced in-app, so sync happens without a manual click. Acceptance: a vault syncs on file-change with a debounce; the pill reflects live status (this is the "live polling" D.1.14 deliberately deferred). Interacts with `SyncInProgress` (the lockfile) — the UI must handle a daemon + manual click gracefully.
- **[#187](https://github.com/hherb/secretary/issues/187)** — project `sync_vault`/`sync_status` + DTOs onto uniffi+pyo3 (mobile/Python; pairs with #167). Pure FFI-surface slice; would trigger the cross-language conformance run.

**Acceptance criteria for whichever is chosen:** author via `superpowers:brainstorming` → `superpowers:writing-plans`. If it touches `core`/`ffi`/`FfiVaultError`/UDL, the full workspace gauntlet **and** the Swift+Kotlin conformance runs are mandatory ([[project_secretary_ffivaulterror_workspace_match]]); a pure-desktop slice does not need them. Any mutation path needs the confirm + strict typed-error-surfacing care D.1.11/D.1.14 used, and a manual GUI smoke on a **`cp -R` temp copy** of the golden vault ([[feedback_smoke_test_temp_copy_golden_vault]]).

**Other deferred / parallel:** **#186** (dedup `copy_dir_recursive` + golden-staging test helpers into a shared bridge `#[cfg(test)]` module); **#189** (lean-binding CI guard — no notify/clap in mobile bindings); **#190** (bridge `MergedClean`-under-lock test); **#161**/#162 (macOS Tauri e2e / PathPicker e2e hook).

## (3) Open decisions and risks

- **⚠️ Outstanding gate: the manual GUI smoke (do before merge).** This is the visual gate the headless automated suite can't cover. See §3-commands below.
- **In-session password re-prompt is inherent, not a wart.** `sync_vault` takes a `password` and opens its own identity (the frozen bridge surface), so the modal re-prompt is required — D.1.14 makes it explicit rather than a surprise. If a future slice wants to reuse the session identity, that's a bridge change (out of this slice's scope).
- **`SyncInProgress` vs a running daemon.** If a user ever runs the headless `secretary-sync` daemon AND clicks "Sync now", the lockfile makes one return `SyncInProgress` → surfaced as "Another sync is in progress — wait, then try again." Correct; the background-auto-sync slice should design for this.
- **`now_ms` for the merge timestamp.** `sync_now`'s `#[command]` wrapper supplies wall-clock; it only affects the merge timestamp on the committing arms (`MergedClean`/`SilentMerge`). No correctness impact on the common arms.

### Verified non-issues (don't re-investigate)
- **Wire format Rust↔TS:** the final reviewer traced it end-to-end — `hasState`/`lastStateWriteMs` (camelCase, `None`→explicit `null`), the tagged `{kind, vetoCount}` outcome — all line up and are unit-pinned.
- **Secret hygiene:** password is component-local `$state`, cleared on success AND cancel/Esc, rides zeroize `Password`/`SecretBytes` on the Rust side, dropped at `_impl` end, never logged/stashed.
- **No silent failure:** `map_ffi_error` covers all 5 sync variants exhaustively; the mutation path maps every error; the ONLY swallow is `SyncPill.loadStatus` (informational status read).
- **Scope:** diff confined to `desktop/` + `README`/`ROADMAP` + `docs/superpowers/`; no core/ffi/FfiVaultError/UDL/bridge change.

## (4) Exact commands to resume

```bash
# 0) Run the manual GUI smoke BEFORE merging the D.1.14 PR (the one outstanding gate).
cd /Users/hherb/src/secretary/.worktrees/d114-desktop-sync-ui
SMOKE_DIR="$(mktemp -d)/golden_smoke"
cp -R core/tests/data/golden_vault_001 "$SMOKE_DIR"
echo "Smoke vault: $SMOKE_DIR  (password: 'correct horse battery staple')"
cd desktop && pnpm tauri dev
#   Verify: TopBar pill shows "Never synced"/"Synced …"; click → centered modal (app dims, focus in field);
#   wrong password → inline role=alert error, dialog stays open; Esc + Cancel close without syncing;
#   correct password (single device, no remote) → modal closes, pill shows "Already up to date" notice
#   (auto-dismisses ~5 s); records view still renders. Record the result in the PR.

# 1) Merge the D.1.14 PR once the smoke passes.
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git log -3 --oneline    # confirm the D.1.14 PR landed

# 2) Housekeeping (after merge):
git worktree remove .worktrees/d114-desktop-sync-ui 2>/dev/null && git branch -D feature/d114-desktop-sync-ui 2>/dev/null
git worktree prune && git worktree list

# 3) Next slice: brainstorm → plan → execute (see §2). First worktree:
git worktree add .worktrees/d115-<slug> -b feature/d115-<slug> main
```

## (5) Handoff file model

`NEXT_SESSION.md` at the repo root is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Author the handoff once; the symlink is a pointer. To open the next slice: author `docs/handoffs/<date>-<slug>-shipped.md` and `ln -snf docs/handoffs/<new>.md NEXT_SESSION.md`, committing both on the feature branch (per [[feedback_next_session_in_pr]]). main hasn't moved during this session (branch point == origin/main == `5933527`), so the symlink retarget merges cleanly.

## Closing inventory

- **Branch on close:** `main` @ `5933527`. `feature/d114-desktop-sync-ui` carries the spec + spec-fix + plan + 9 task commits + the fmt fix + the docs commit + the ship commit (this handoff + symlink). Squash-merge collapses to one commit on `main`.
- **Automated gauntlet:** green — frontend (452 tests, typecheck, svelte-check, lint) + Rust (178 tests, fmt, clippy `-D warnings`).
- **Final whole-branch review:** **APPROVE TO MERGE** — zero Critical/Important; one Minor (a dead-defensive `{code:'internal'}` branch in the dialog catch, already covered by `call`'s normalization) left as belt-and-suspenders.
- **PR:** open (link in the session output). **Outstanding gate: the manual GUI smoke** (§3/§4) — this slice has UI.
- **README.md / ROADMAP.md:** D.1.14 ✅ shipped 2026-06-07.
- **CLAUDE.md / `docs/adr/`:** unchanged (no new architecture decision; no on-disk-format/crypto/bridge change).
- **Issues:** #187 (uniffi/pyo3 sync projection), #186 (bridge test-helper dedup), #189/#190, #161/#162 stay open. No new issues filed.
- **NEXT_SESSION.md:** symlink retargeted to this file.
- **This file:** the live D.1.14 ship baton. The next slice opens with `docs/handoffs/<date>-<slug>-shipped.md`.
