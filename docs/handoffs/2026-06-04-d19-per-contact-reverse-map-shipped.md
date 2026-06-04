# NEXT_SESSION.md — D.1.9 ✅ per-contact reverse map (expand a contact → its blocks → open)

**Session date:** 2026-06-04 (D.1.9 — the ninth Sub-project D feature slice, built on D.1.1–D.1.8). Authored spec + plan via `superpowers:brainstorming` → `superpowers:writing-plans`, then executed all 6 implementation tasks via `superpowers:subagent-driven-development` (fresh implementer per task + a spec-compliance review + a code-quality review after each + a final whole-branch security review).
**Status:** D.1.9 ✅ complete on branch `feature/d19-reverse-map`; **PR opened, not yet merged.** Final whole-branch security review: **CLEAN on all 7 invariants**, zero issues at any severity. All automated gates green. The one human gate left is the **manual GUI smoke** (§(3)) — headless-impossible; it is the pre-merge gate.

## (1) What we shipped this session

The per-contact **inverse** of D.1.8: a user with an **unlocked vault** can now open the Contacts pane, **expand a contact to see which blocks that contact receives**, and **click a block to open it**:
- **Inline reverse map** → each `ContactRow` is now a toggle. Collapsed it shows the existing `receives N blocks` count; expanded it **lazily fetches** (fetch-on-first-expand, then cached) and lists the blocks that contact receives, sorted by name. Clicking a listed block calls `openBlock` and navigates to that block's records view.
- **delete ≠ revoke stays honest** → the reverse map scans the **same** `manifest.blocks[].recipients` set that powers `shared_block_count`, so `contact_blocks(uuid).len()` **==** that contact's `shared_block_count` by construction. (A deleted contact still listed as a recipient is the #177 story; this slice doesn't change it.)

**Architecture (held from D.1.6–D.1.8): bridge-thick, read-only, `core` frozen.** All `contacts/`+manifest knowledge stays in the bridge; the desktop never learns the on-disk layout. `core/src/` untouched (0 lines). **Read-only** — only in-memory manifest scans; no write/delete/rename/re-key. Revoke stays deferred to **[#177](https://github.com/hherb/secretary/issues/177)**.

**Lighter than D.1.7's shared-enum thread, like D.1.8:** **no new `FfiVaultError` variant** (a uuid matching nothing is an empty list, not an error; a wiped handle reuses `CorruptVault`), so **no UDL / Swift / Kotlin / pyo3 change** and no workspace-wide exhaustive-match obligation. Per [#167](https://github.com/hherb/secretary/issues/167) the contacts/recipients *functions* (incl. the new `contact_blocks`) remain bridge+desktop only. **No new TS DTO** — the existing `BlockSummaryDto` is exactly what `openBlock` consumes.

Key properties (verified by the final whole-branch review — **CLEAN on all 7 invariants**, with file:line evidence):
- **Read-only / no mutation.** `contact_blocks` is a pure in-memory filter→map; `list_contact_blocks_impl` reads under `with_unlocked`; `ContactRow` calls only `listContactBlocks` (read) + `openBlock` (a pure `store.set`). Revoke correctly NOT implemented.
- **`core/` frozen** — `git diff main..HEAD -- core/` empty. No KAT / conformance / spec-freshness impact.
- **No new secret surface.** Only `BlockSummaryDto` (block uuid/name/timestamps — already plaintext in the manifest and already exposed by the blocks-list path) crosses the seam. No card bytes/keys.
- **No new `FfiVaultError` variant; bindings untouched** (uniffi/pyo3/UDL diff empty).
- **Count-vs-list integrity.** `contact_blocks` scans `manifest.blocks` (NOT `manifest.trash`), the identical predicate to `enumerate_contact_cards`' `shared_block_count`; a trashed block (moved to `manifest.trash`) drops from both. Pinned by `block_count_matches_shared_block_count_invariant` + `trashing_a_shared_block_drops_it_from_the_list`.
- **No `unsafe`, no panics on edge input** — unknown uuid → empty Vec; `parse_uuid_16` guards malformed hex at the desktop edge; wiped handle → `CorruptVault`.
- **No silent error-swallow.** A fetch fault renders a visible `role="alert"` (not a silent empty list) and resets the lazy-once guard so it is retryable; bridge/command propagate via `map_ffi_error`.

All commits are on `feature/d19-reverse-map` (branched from `main` @ `60d9d1a`):

| Commit | What it landed |
|---|---|
| `60ead3a` | D.1.9 design spec (`docs/superpowers/specs/2026-06-04-d19-per-contact-reverse-map-design.md`; bridge-thick; read-only; revoke deferred to #177). |
| `fa7d95a` | D.1.9 implementation plan (`docs/superpowers/plans/2026-06-04-d19-per-contact-reverse-map.md`, 6 tasks, TDD). |
| `616a1af` | **Task 1** — bridge `contact_blocks` primitive + `block_entry_to_summary` `pub(super)`→`pub(crate)` + re-exports + 5 integration tests (empty / shared / count-invariant / trash-excluded / unknown-uuid). |
| `44b6974` | Task 1 review fix — promote the duplicated `place_card` test helper into `share_block_helpers` (DRY). |
| `349136f` | **Task 2** — `list_contact_blocks` Tauri command + `*_impl` + handler registration + locked-session unit test + happy-path ipc_integration test. |
| `f50a040` | Task 2 review fix — refresh the stale `contacts.rs` module doc header (D.1.6–D.1.9); assert `block_name` in the reverse-map integration test. |
| `1f8b5f4` | **Task 3** — `listContactBlocks` ipc wrapper (mirrors `listBlockRecipients`; reuses `BlockSummaryDto`) + wrapper test. |
| `4a4b0c2` | **Task 4** — pure `sortBlocks` (name case-insensitive, `blockUuidHex` tiebreak) + 3 tests. |
| `5a181b4` | **Task 5** — `ContactRow` inline expand + lazy-fetch-once + `openBlock` wiring + `theme.css` styles + 6 component tests. (Deviations: used `--color-primary` since `--color-accent` doesn't exist; moved the chevron to an `aria-hidden` span to keep ContactsPane's exact-text test green.) |
| `cb882f0` | Task 5 review fix — retry-after-error test (7th ContactRow test); document the one-instance-per-uuid caching assumption; full-width block buttons + wrapper-class comment. |
| `4003a9c` | docs — README/ROADMAP marked D.1.9 ✅, "next" pointer advanced to D.1.10. |
| _(ship)_ | this handoff + symlink retarget. |

**Process note:** one worktree (`.worktrees/d19-reverse-map`), one reviewed commit per task + inline review-fix commits. Four review-fix commits (DRY `place_card`; module-header + name-assert; ContactRow retry-test + a11y/CSS polish). Per-task gate ran **both** `cargo fmt --all -- --check` and clippy (the D.1.8 retro fix) — no fmt-vs-clippy gap this slice. Every per-task spec + quality finding was fixed before proceeding. The final whole-branch security review found zero issues.

**Issue filed this session:** [#180](https://github.com/hherb/secretary/issues/180) — a11y enhancement: pair `aria-expanded` with `aria-controls` on the disclosure buttons (`BlockRecipients` + `ContactRow`); pre-existing project-wide gap surfaced in the D.1.9 quality review, filed rather than held (functional today).

### Automated gauntlet (independently re-run on `feature/d19-reverse-map`)

```
Rust:        PASSED 1172 FAILED 0 IGNORED 10   (+7 over the D.1.8 baseline of 1165:
             5 bridge contact_blocks + 1 command locked-session + 1 command integration)
cargo clippy --release --workspace --tests -- -D warnings   → clean
cargo fmt --all -- --check                                  → clean
uv run core/tests/python/conformance.py                     → PASS  (core untouched)
uv run core/tests/python/spec_test_name_freshness.py        → PASS  (no KAT change)
Swift conformance:   22/22 PASS   (no UDL change)
Kotlin conformance:  22/22 PASS

Frontend:    Vitest 393 / 0   (52 files; new: blocks + ContactRow + ipcContacts case)
pnpm typecheck      → clean
pnpm svelte-check   → 286 files, 0 errors, 0 warnings
pnpm lint           → clean
```

## (3) ⚠️ Manual GUI smoke — the user's pre-merge gate (NOT run this session; headless-impossible)

> **⚠️ Smoke against a TEMP vault copy, never a git-tracked fixture.** See [[feedback_smoke_test_temp_copy_golden_vault]]. D.1.9 is read-only (no writes), so the risk is lower — but still `cp -R` to a tempdir to keep the frozen fixture pristine.

```bash
cd /Users/hherb/src/secretary/.worktrees/d19-reverse-map/desktop
pnpm install && pnpm tauri build --debug
# Unlock a TEMP copy of a vault that has at least one block shared with a contact
# (use the D.1.6 ShareDialog 🔗 to share a block to an imported contact first if needed).
./src-tauri/target/debug/secretary-desktop
```

Walk (spec §10): unlock vault → open the **👤 Contacts** pane → a contact with shared blocks shows `receives N blocks`. **Click the contact** → the row expands to list those N blocks by name (sorted). **Click a listed block** → its records view opens. **Back** returns to the blocks list (accepted single-level nav, spec §8 — not back to Contacts). Reopen Contacts, **expand a contact with 0 shares** → **No shared blocks**. Collapse/re-expand a contact → it does not refetch (and does not flicker). If any step fails it's a D.1.9 regression; don't merge until fixed.

## (2) What's next — D.1.10 (brainstorm to confirm/trim)

D.1.9 delivered the per-contact *view*. Candidate scope for D.1.10 (from the D.1.8/D.1.9 backlog):
- **Revoke / unshare** — **blocked on [#177](https://github.com/hherb/secretary/issues/177)** (a frozen-`core` revoke primitive that does not exist: re-key + drop a recipient + re-sign + atomic write, with spec/KAT/conformance impact). If the user wants *real* revoke next, the next slice is **#177 in `core`/bridge**, NOT a D-phase UI. Both the D.1.8 banner (per-block) and the D.1.9 ContactRow (per-contact) are natural surfaces a future revoke action hangs off (an ✕ per non-owner recipient / per block row), so the revoke UI is cheap once #177 lands. **NB (carried from the D.1.9 review): the revoke *mutation* path must NOT reuse the read-only display's error-leniency** — a transient I/O fault folding to "no blocks" is fine for a display, fatal for a mutation.
- **Contact rename / nickname** — `display_name` is part of the *self-signed* card, so this needs a separate per-vault **local alias** layer (a nickname map), not an edit of `contacts/*.card`. Confirm the data model before scoping.
- **Contact fingerprint-confirmation UX** — TOFU hardening: show/confirm a contact's fingerprint at import (flagged since D.1.6). Security-facing.
- **a11y pass [#180](https://github.com/hherb/secretary/issues/180)** — small, self-contained: `aria-controls` on the `BlockRecipients` + `ContactRow` disclosure buttons. A reasonable "smallest high-value" slice if a feature is blocked.

**Acceptance criteria (if revoke/#177 is chosen):** a frozen-`core` revoke primitive (re-key BCK, drop a recipient from `recipients[]`, re-sign the manifest, atomic write) with spec + KAT + conformance updates; a bridge orchestrator; a typed `FfiVaultError` for the failure modes; threaded through uniffi/pyo3 if a binding consumer needs it. Author the plan via `superpowers:brainstorming` → `superpowers:writing-plans` first; this is a Sub-project A/B change, treat it with full crypto-review rigor.

## (3b) Open decisions and risks

- **Manual GUI smoke is the pre-merge gate** (§(3)). Until #161's L4 e2e lands, every D.1.x ship leans on a human walk-through.
- **#177 (core revoke primitive) still open** — blocks the revoke verb; a frozen-`core` change (Sub-project A/B), not a D-phase UI task. Both D.1.8 and D.1.9 surfaces are revoke-ready.
- **Accepted single-level nav (spec §8):** opening a block from the Contacts pane lands **Back** on the blocks list, not back on Contacts — consistent with `browseNav`'s single-level discriminated union. A return-target mini-stack was explicitly out of scope; revisit only if users find it jarring.
- **Deferred-FFI tracking issue [#167](https://github.com/hherb/secretary/issues/167)** — the contacts/recipients *functions* (incl. `contact_blocks`) are NOT exposed via uniffi (Swift/Kotlin) or pyo3. No shared *error enum* change this slice. Wire the functions when D.3 (mobile) or a Python consumer needs them.
- **#180 (a11y aria-controls)** — newly filed; small, not a blocker.
- **#170 (`lock_session` hoist into `commands::shared`)** still open — `commands/contacts.rs`'s local `lock_session` is now used by 7 commands (D.1.9 added `list_contact_blocks_impl`). Pure mechanical tidy-up; not a blocker.
- **Carry-forwards, all still live:**
  - **#153** — component styles in `theme.css` (Vite 6 `preprocessCSS` blocked); D.1.9 adds `.contact-card-row__toggle` + `.contact-blocks__*`.
  - **#154** — emoji/glyphs → inline SVG (D.1.9 adds no new emoji; the toggle uses `▾`/`▴` text glyphs, `aria-hidden`).
  - **#161** — L4 e2e harness deferred (no tauri-driver on macOS WKWebView).
  - **#162** — PathPicker e2e hook.
  - **#164** — Esc-to-pop from D.1.2.

### Verified non-issues (don't re-investigate)
- **Count-vs-list can never diverge:** `contact_blocks` and `shared_block_count` filter the same `manifest.blocks` with the same predicate; the trash test proves trashed blocks (in `manifest.trash`) appear in neither. The final review judged this CLEAN.
- **Lazy-fetch-once + error-retry state machine:** the `fetched` guard makes a re-expand reuse the cache (no refetch); a fetch error resets the guard so the next expand retries. Pinned by `fetches once across collapse/re-expand` + `retries the fetch after an error on next expand`.
- **`--color-primary` (not `--color-accent`) on block buttons:** `--color-accent` does not exist in `theme.css`; `--color-primary` is the established interactive/link token. Intentional substitution, not a typo.

## (4) Exact commands to resume (D.1.10)

```bash
# Merge the D.1.9 PR first (feature/d19-reverse-map) after the manual smoke, then:
cd /Users/hherb/src/secretary
git fetch --prune origin
git checkout main
git pull --ff-only origin main
git log -5 --oneline           # confirm the D.1.9 ship PR landed

# Re-baseline the automated gauntlet on fresh main:
cargo test --release --workspace --no-fail-fast 2>&1 | grep "^test result:" | awk '$3=="ok." {p+=$4; f+=$6; i+=$8} END {printf "Rust totals → PASSED %d FAILED %d IGNORED %d\n", p, f, i}'
# Expect: PASSED 1172 FAILED 0 IGNORED 10 (D.1.9 baseline)
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh 2>&1 | tail -3
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh 2>&1 | tail -3
cd desktop && pnpm install && pnpm test && pnpm typecheck && pnpm svelte-check 2>&1 | tail -3 && pnpm lint && cd ..
# Expect: Vitest 393 passing

# Author the D.1.10 plan:
#   superpowers:brainstorming  → scope the next slice (real revoke = #177 in core first; or a smaller D-slice)
#   superpowers:writing-plans  → mirror docs/superpowers/plans/2026-06-04-d19-per-contact-reverse-map.md

# Then the first implementation worktree:
git worktree add .worktrees/d110-<slug> -b feature/d110-<slug> main
cd .worktrees/d110-<slug>/desktop && pnpm install
```

### Housekeeping (after the D.1.9 PR merges)
```bash
cd /Users/hherb/src/secretary
git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/d19-reverse-map 2>/dev/null && git branch -D feature/d19-reverse-map 2>/dev/null
git worktree prune && git worktree list
```

## (5) Handoff file model

`NEXT_SESSION.md` at the repo root is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Author the handoff once; the symlink is a pointer. To open the next slice: author `docs/handoffs/<date>-d110-*.md` and `ln -snf docs/handoffs/<new>.md NEXT_SESSION.md`, committing both on the feature branch (per [[feedback_next_session_in_pr]]).

## Closing inventory

- **Branch on close:** `main` @ `60d9d1a`. `feature/d19-reverse-map` carries the spec + plan + 6 task commits + 4 task-review-fix commits + 1 docs commit + the ship commit (this handoff + symlink). Squash-merge collapses to one commit on `main`.
- **Automated gauntlet:** Rust **1172 / 0 / 10**; clippy clean; fmt clean; conformance PASS; spec-freshness PASS; Swift 22/22; Kotlin 22/22; Vitest **393 / 0**; typecheck clean; svelte-check 0 errors / 0 warnings; lint clean.
- **Final whole-branch review:** security verdict **CLEAN** on all 7 invariants (read-only/no mutation; core frozen; no new secret surface; no new error variant / bindings untouched; count-vs-list integrity; no unsafe/no panics on edge input; no silent error-swallow). Zero Critical/Important/Minor issues.
- **PR:** opened against `main` (`feature/d19-reverse-map`). Merge gated on the user's manual GUI smoke (§(3)).
- **README.md / ROADMAP.md:** D.1.9 marked ✅; D.1.10 next.
- **CLAUDE.md / `docs/adr/`:** unchanged (no format/architecture change; `core/` frozen).
- **Issues filed this session:** [#180](https://github.com/hherb/secretary/issues/180) (a11y aria-controls). Revoke stays #177; FFI exposure stays #167.
- **NEXT_SESSION.md:** symlink retargeted to this file.
- **This file:** the live D.1.9 ship baton. The next slice opens with `docs/handoffs/<date>-d110-*.md`.
