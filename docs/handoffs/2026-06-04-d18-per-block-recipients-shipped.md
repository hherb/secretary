# NEXT_SESSION.md — D.1.8 ✅ per-block recipients ("Shared with")

**Session date:** 2026-06-04 (D.1.8 — the eighth Sub-project D feature slice, built on D.1.1–D.1.7). Authored spec + plan via `superpowers:brainstorming` → `superpowers:writing-plans`, then executed all 7 implementation tasks via `superpowers:subagent-driven-development` (fresh implementer per task + a spec-compliance review + a code-quality review after each + a final whole-branch security review).
**Status:** D.1.8 ✅ complete on branch `feature/d18-recipients`; **PR not yet opened** (branch is local). Final whole-branch review: **security CLEAN on all 7 invariants**, zero issues at any severity. All automated gates green. The one human gate left is the **manual GUI smoke** (§(3)) — headless-impossible; it is the pre-merge gate.

## (1) What we shipped this session

A user with an **unlocked vault** can now **see who a block is shared with**, the inverse of D.1.6/D.1.7's "import + share + manage contacts":
- **"Shared with" banner** → the records view for a block (`RecordList`) now opens with a collapsible **Shared with: You, Alice, +1 unknown ▾** banner. Collapsed it names the resolved recipients and folds unknowns into a count; expanded it lists every recipient.
- **Name resolution** → each uuid in the block's `recipients[]` is resolved against `contacts/`: the owner shows as **"You"** (listed first), a peer with a verified card shows its **display name**, and any uuid with no usable card shows as **"Unknown contact (uuid…)"**.
- **delete ≠ revoke made visible** → because D.1.7's delete-contact deliberately leaves a recipient uuid with no card on disk (the former recipient still holds the content key), that residual keyholder now renders as **Unknown contact (8-hex prefix…)** — the standing access you can no longer name stays visible.

**Architecture (held from D.1.6/D.1.7): bridge-thick.** All `contacts/` I/O stays in the bridge; the desktop never learns the on-disk vault layout. `core/` was **frozen and untouched** (0 lines under `core/src/`). **Read-only** — this slice never mutates a recipient set; revoke stays deferred to **[#177](https://github.com/hherb/secretary/issues/177)**.

**Much lighter than D.1.7's shared-enum thread:** **no new `FfiVaultError` variant** (reuses `BlockNotFound` + `CorruptVault`), so **no UDL / Swift / Kotlin / pyo3 change** and no workspace-wide exhaustive-match obligation. Per [#167](https://github.com/hherb/secretary/issues/167) the contacts/recipients *functions* remain bridge+desktop only.

Key properties (verified by the final whole-branch review — **CLEAN on all 7 invariants**, with file:line evidence):
- **No unverified name is ever surfaced.** Every `contacts/<uuid>.card` read on the new path goes through the both-halves `verify_self()` gate (Ed25519 ∧ ML-DSA-65, via the existing `read_verified_card`) before its `display_name` is trusted. A missing, unreadable, **or tampered/forged** card folds to `Unknown` — never a `Contact` with an attacker-controlled name. The name is also bounded (frozen-core 4096-byte cap). Pinned by `tampered_card_is_unknown_not_forged_name`.
- **Seam discipline.** Only `{ uuidHex, kind, displayName? }` crosses the IPC seam — uuid (public), kind, public display name; never card bytes/keys. `RecipientDto`'s hand-written `Debug` redacts `display_name` unconditionally (aligned to `ContactSummaryDto` after a review fix).
- **Owner-first classification.** The owner uuid is classified `Owner` **before** the `contacts/` lookup, so the owner self-card (which also lives in `contacts/`) can't be mislabeled and the owner is never dropped or shown as a peer.
- **Read-only.** The new path performs only `std::fs::read`; no write/delete/rename/re-key anywhere (proven by grep + review). Revoke correctly NOT implemented.
- **No `unsafe`, no panics on attacker input** — corrupt/oversized/empty cards, zero/many recipients, and a sub-8-hex uuid (`slice(0,8)` returns fewer chars, never throws) all handled.
- **Manifest-order in the bridge; presentation order on the client.** `block_recipients` returns recipients in manifest order; the pure `sortRecipients` orders owner-first → contacts alpha (case-insensitive) → unknowns last.
- **`shared`-style fold is clean.** A genuine transient I/O fault is indistinguishable from "deleted contact" (both → Unknown) — acceptable for a read-only *display* surface that makes no security decision; the uuid prefix is always surfaced. (Note for #177: the revoke *mutation* path must NOT reuse this leniency.)

All commits are on `feature/d18-recipients` (branched from `main` @ `4e6c6f3`):

| Commit | What it landed |
|---|---|
| `3c40991` | D.1.8 design spec (`docs/superpowers/specs/2026-06-04-d18-per-block-recipients-design.md`; bridge-thick; read-only; revoke deferred to #177). |
| `926756c` | D.1.8 implementation plan (`docs/superpowers/plans/2026-06-04-d18-per-block-recipients.md`, 7 tasks, TDD). |
| `5f11091` | **Task 1** — bridge `block_recipients` primitive + `RecipientSummary`/`RecipientKind` (Owner/Contact/Unknown; owner-first; verify-fail → Unknown) + 4 integration tests. |
| `5080608` | **Task 2** — `RecipientDto` seam DTO (camelCase, snake_case kind tag, redacting `Debug`, `From<&RecipientSummary>`). |
| `d5fdc41` | Task 2 review fix — `Debug` always emits `<redacted>` (match `ContactSummaryDto`); drop unused `PartialEq/Eq`; redaction test extended to the Owner (None) case. |
| `91631fe` | **Task 3** — `block_recipients` Tauri IPC command + `*_impl` + handler registration + locked-session test. |
| `36724e1` | **Task 4** — `listBlockRecipients` ipc wrapper + `RecipientDto`/`RecipientKind` TS types. |
| `ade0756` | **Task 5** — pure `sortRecipients` + `recipientLabel` (owner→"You"; contact→name; unknown→"Unknown contact (8hex…)"; named prefix constant). |
| `acc01bd` | **Task 6** — `BlockRecipients.svelte` collapsible banner (loadSeq guard keyed by blockUuidHex; summary via `$derived.by`; expand list; loading/error). |
| `083ad77` | Task 6 review fix — `load()` resets `expanded=false` so a new block always greets the user collapsed; block-switch regression test pins it. |
| `31df634` | **Task 7** — mount `<BlockRecipients {block} />` in the `RecordList` header + `.block-recipients*` styles in `theme.css` (unknown rows tinted); existing RecordList tests converted to `mockImplementation` answering both `read_block` + `block_recipients`. |
| `353593a` | fixall — `cargo fmt` (rustfmt import-wrap + call-arg layout; Task 1/3 landed clippy-clean but not fmt-clean). |
| _(ship)_ | README/ROADMAP D.1.8 ✅ + this handoff + symlink retarget. |

**Process note:** one worktree (`.worktrees/d18-recipients`), one reviewed commit per task + inline review-fix commits. Three review-fix commits (the DTO `Debug` alignment, the banner collapse-on-switch, and the whole-branch `cargo fmt` sweep — the last caught only by the controller's full-gauntlet run, not by the per-task implementers who ran clippy but not `fmt --check`). Every per-task spec + quality finding was fixed before proceeding. The final whole-branch security review found zero issues.

### Automated gauntlet (independently re-run on `feature/d18-recipients`)

```
Rust:        PASSED 1165 FAILED 0 IGNORED 10   (+9 over the D.1.7 baseline of 1156:
             4 bridge recipients + 4 DTO recipient + 1 command locked-session)
cargo clippy --release --workspace --tests -- -D warnings   → clean
cargo fmt --all -- --check                                  → clean (after 353593a)
uv run core/tests/python/conformance.py                     → PASS  (core untouched)
uv run core/tests/python/spec_test_name_freshness.py        → PASS  (no KAT change)
Swift conformance:   22/22 PASS   (no UDL change)
Kotlin conformance:  22/22 PASS

Frontend:    Vitest 377 / 0   (new over D.1.6/D.1.7: ipcRecipients + recipients +
             BlockRecipients + a RecordList banner-mount case; 50 files)
pnpm typecheck      → clean
pnpm svelte-check   → 0 errors, 0 warnings
pnpm lint           → clean
```

## (3) ⚠️ Manual GUI smoke — the user's pre-merge gate (NOT run this session; headless-impossible)

> **⚠️ Smoke against a TEMP vault copy, never a git-tracked fixture.** See [[feedback_smoke_test_temp_copy_golden_vault]]. D.1.8 is read-only (no writes), so the risk is lower than D.1.7 — but still `cp -R` to a tempdir to keep the frozen fixture pristine, especially if you also exercise D.1.6 share to seed a recipient.

```bash
cd /Users/hherb/src/secretary/.worktrees/d18-recipients/desktop
pnpm install && pnpm tauri build --debug
# Unlock a TEMP copy of a vault that has at least one block shared with a contact
# (use the D.1.6 ShareDialog 🔗 to share a block to an imported contact first if needed).
./src-tauri/target/debug/secretary-desktop
```

Walk (spec §9): unlock vault → open a block you own → the records view shows a **Shared with:** banner. For an unshared block it reads **Shared with: You**. Share the block to a contact (D.1.6), reopen → the banner now lists **You, <contact>**; expand it (▾) → each recipient on its own row. Now **delete that contact** from the 👤 Contacts pane (D.1.7) → reopen the block → that recipient renders as **Unknown contact (uuid…)** (delete ≠ revoke made visible). Switch to a different block → the banner starts collapsed (not stuck open). If any step fails it's a D.1.8 regression; don't merge until fixed.

## (2) What's next — D.1.9 (brainstorm to confirm/trim)

D.1.8 delivered the per-block recipient *view*. Candidate scope for D.1.9:
- **Revoke / unshare** — **blocked on [#177](https://github.com/hherb/secretary/issues/177)** (a frozen-`core` revoke primitive that does not exist: re-key + drop a recipient + re-sign + atomic write, with spec/KAT/conformance impact). If the user wants *real* revoke next, the next slice is **#177 in `core`/bridge**, NOT a D-phase UI. The D.1.8 banner is the natural surface a future revoke action would hang off (an ✕ per non-owner recipient row), so revoke UI becomes cheap once #177 lands.
- **Per-contact reverse map** — from the Contacts pane, click a contact → list the blocks they receive (the inverse of this slice; reuses the `shared_block_count` data path). Small, self-contained, no core change. A reasonable next "smallest high-value" slice if revoke stays blocked.
- **Contact rename / nickname** — NB `display_name` is part of the *self-signed* card, so this needs a separate per-vault **local alias** layer (a nickname map), not an edit of `contacts/*.card`. Confirm the data model before scoping.
- **Contact fingerprint-confirmation UX** — TOFU hardening: show/confirm a contact's fingerprint at import (flagged since D.1.6). Security-facing.

**Acceptance criteria (per-contact-reverse-map slice, if chosen):** a bridge primitive projecting a contact uuid → the list of blocks that list it as a recipient (names from the manifest; no decryption); an IPC command + ipc wrapper; a view reachable from a ContactRow. Gauntlet green; manual smoke. Author the plan via `superpowers:brainstorming` → `superpowers:writing-plans` first; mirror the D.1.8 spec/plan structure.

## (3b) Open decisions and risks

- **Manual GUI smoke is the pre-merge gate** (§(3)). Until #161's L4 e2e lands, every D.1.x ship leans on a human walk-through.
- **#177 (core revoke primitive) still open** — blocks the revoke verb; a frozen-`core` change (Sub-project A/B), not a D-phase UI task. D.1.8's banner is revoke-ready as a surface.
- **fmt-vs-clippy gap (process):** the per-task implementers ran `cargo clippy` but not `cargo fmt --check`; two tasks landed clippy-clean but fmt-dirty, caught only by the controller's full-gauntlet sweep (`353593a`). For D.1.9, tell Rust implementers to run `cargo fmt --all -- --check` as part of their per-task gate, not just clippy.
- **Deferred-FFI tracking issue [#167](https://github.com/hherb/secretary/issues/167)** — the contacts/recipients *functions* (incl. the new `block_recipients`) are NOT exposed via uniffi (Swift/Kotlin) or pyo3 (no mobile/Python consumer). No shared *error enum* change this slice (none was needed). Wire the functions when D.3 (mobile) or a Python consumer needs them.
- **#170 (`lock_session` hoist into `commands::shared`)** still open — `commands/contacts.rs`'s local `lock_session` is now used by 6 commands (D.1.8 added `block_recipients_impl`). Pure mechanical tidy-up; not a blocker.
- **Carry-forwards, all still live:**
  - **#153** — component styles in `theme.css` (Vite 6 `preprocessCSS` blocked); D.1.8 adds `.block-recipients*`.
  - **#154** — emoji/glyphs → inline SVG (D.1.8 adds no new emoji; the banner uses `▾`/`▴` text glyphs).
  - **#161** — L4 e2e harness deferred (no tauri-driver on macOS WKWebView).
  - **#162** — PathPicker e2e hook.
  - **#164** — Esc-to-pop from D.1.2.

### Verified non-issues (don't re-investigate)
- **Unknown vs genuine I/O fault both render "Unknown contact":** intentional for a read-only display surface (no security decision is made here); the uuid prefix is always shown. The final review judged this clean. The revoke mutation path (#177) must not reuse this fold.
- **Unknown-command → `null` in the RecordList test mock:** matches the pre-existing repo convention (`RecordListDelete.test.ts` does the same with a documented Svelte-5-lifecycle rationale) — not a weakened assertion; the per-command `toHaveBeenCalledWith` checks still pin the commands that matter.
- **`recipientLabel` contact-with-null-name fallback (`?? 'Unknown contact'`) is untested:** the bridge `From` impl always sets `Some(name)` for `Contact`, so this branch is unreachable in practice; the fallback is cheap defensive code, not worth a test for an impossible input.

## (4) Exact commands to resume (D.1.9)

```bash
# Merge the D.1.8 PR first (feature/d18-recipients) after the manual smoke, then:
cd /Users/hherb/src/secretary
git fetch --prune origin
git checkout main
git pull --ff-only origin main
git log -5 --oneline           # confirm the D.1.8 ship PR landed

# Re-baseline the automated gauntlet on fresh main:
cargo test --release --workspace --no-fail-fast 2>&1 | grep "^test result:" | awk '$3=="ok." {p+=$4; f+=$6; i+=$8} END {printf "Rust totals → PASSED %d FAILED %d IGNORED %d\n", p, f, i}'
# Expect: PASSED 1165 FAILED 0 IGNORED 10 (D.1.8 baseline)
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh 2>&1 | tail -3
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh 2>&1 | tail -3
cd desktop && pnpm install && pnpm test && pnpm typecheck && pnpm svelte-check 2>&1 | tail -3 && pnpm lint && cd ..
# Expect: Vitest 377 passing

# Author the D.1.9 plan:
#   superpowers:brainstorming  → scope per-contact-reverse-map (or, for real revoke, scope #177 in core first)
#   superpowers:writing-plans  → mirror docs/superpowers/plans/2026-06-04-d18-per-block-recipients.md

# Then the first implementation worktree:
git worktree add .worktrees/d19-<slug> -b feature/d19-<slug> main
cd .worktrees/d19-<slug>/desktop && pnpm install
```

### Housekeeping (after the D.1.8 PR merges)
```bash
cd /Users/hherb/src/secretary
git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/d18-recipients 2>/dev/null && git branch -D feature/d18-recipients 2>/dev/null
git worktree prune && git worktree list
```

## (5) Handoff file model

`NEXT_SESSION.md` at the repo root is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Author the handoff once; the symlink is a pointer. To open the next slice: author `docs/handoffs/<date>-d19-*.md` and `ln -snf docs/handoffs/<new>.md NEXT_SESSION.md`, committing both on the feature branch (per [[feedback_next_session_in_pr]]).

## Closing inventory

- **Branch on close:** `main` @ `4e6c6f3`. `feature/d18-recipients` carries the spec + plan + 7 task commits + 2 task-review-fix commits + 1 fmt fixall + the ship commit (this handoff + symlink + README/ROADMAP). Squash-merge collapses to one commit on `main`.
- **Automated gauntlet:** Rust **1165 / 0 / 10**; clippy clean; fmt clean; conformance PASS; spec-freshness PASS; Swift 22/22; Kotlin 22/22; Vitest **377 / 0**; typecheck clean; svelte-check 0 errors / 0 warnings; lint clean.
- **Final whole-branch review:** security verdict **CLEAN** on all 7 invariants (no unverified name surfaced + both-halves verify gate; seam discipline + redacting Debug; read-only/no mutation; owner-first classification; core untouched + no new error variant; no unsafe/no panics on attacker input; full spec §9 coverage). Zero Critical/Important/Minor issues.
- **PR:** not yet opened against `main` (`feature/d18-recipients`). Open it, then merge is gated on the user's manual GUI smoke (§(3)).
- **README.md / ROADMAP.md:** D.1.8 marked ✅; D.1.9 next.
- **CLAUDE.md / `docs/adr/`:** unchanged (no format/architecture change; `core/` frozen).
- **Issues filed this session:** none new (revoke stays #177; FFI exposure stays #167).
- **NEXT_SESSION.md:** symlink retargeted to this file.
- **This file:** the live D.1.8 ship baton. The next slice opens with `docs/handoffs/<date>-d19-*.md`.
