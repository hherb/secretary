# NEXT_SESSION.md — D.1.7 ✅ contacts management (export-my-card + a contacts pane)

**Session date:** 2026-06-03 (D.1.7 — the seventh Sub-project D feature slice, built on D.1.1–D.1.6). Authored spec + plan via `superpowers:brainstorming` → `superpowers:writing-plans`, then executed all 8 implementation tasks via `superpowers:subagent-driven-development` (one implementer per task + a spec-compliance review + a code-quality review after each + a final whole-branch security review).
**Status:** D.1.7 ✅ complete on branch `feature/d17-contacts`; **PR not yet opened** (branch is local + pushed-on-open). Final whole-branch review: **security CLEAN on all 8 invariants**. All automated gates green. The one human gate left is the **manual GUI smoke** (§(3)) — headless-impossible; it is the pre-merge gate.

## (1) What we shipped this session

A user with an **unlocked vault** can now **manage contacts** from the desktop app, beyond D.1.6's "import + pick + share":
- **Export my card** → a 👤 Contacts pane offers **Export my card** → the existing folder PathPicker → the owner's own public `.card` is written into the chosen folder (so a peer can import *you*; closes the share loop with D.1.6 import).
- **Contacts pane** → a Vault entry (**👤 Contacts**, mirroring the D.1.5 🗑 Trash entry) lists every imported contact by display name, each labeled **"receives N blocks"** (how many of your blocks list them as a recipient).
- **Delete a contact (warn-but-allow)** → each row offers Delete; if the contact still receives blocks, a confirm dialog warns *"…receives N of your blocks. Deleting their card won't revoke access they already have, but you won't be able to re-share those blocks to anyone."* On confirm the `contacts/<uuid>.card` file is removed.

**Architecture decision (held from D.1.6):** **bridge-thick.** All `contacts/` I/O stays in the bridge; the desktop never learns the on-disk vault layout. `core/` was **frozen and untouched** (0 lines under `core/src/`).

**Scope decision (made this session):** **revoke/unshare was deferred** — `core` has only an append-only `share_block` and no revoke primitive, and `core` is frozen for v1. Removing a recipient needs a new frozen-core orchestrator (re-key + drop a recipient + re-sign + atomic write) with its own spec/KAT/conformance impact. Filed as **[#177](https://github.com/hherb/secretary/issues/177)** (core/B-phase prerequisite). **Deleting a contact's card is NOT revoke** — the former recipient still holds the content key for blocks already shared with them; the pane states this and a test pins it.

Key properties (verified by the final whole-branch review — **security CLEAN on all 8 invariants**):
- **Owner self-card is undeletable.** `delete_contact_card` checks `contact_uuid == owner_uuid` and returns the typed `CannotDeleteOwnerContact` **before any filesystem op** (defense in depth — the pane already omits the owner, but the primitive refuses it regardless). A bridge test asserts the owner card survives on disk after a refused delete.
- **Export is PUBLIC-only.** `owner_card_export` serializes only the public `ContactCard` (public keys + display name + uuid) via a single `owner_card()` lock + `to_canonical_cbor()`; no `Sensitive`/`SecretBytes` touched, no new secret residence. A round-trip test parses the bytes back + `verify_self()` (both halves), proving valid-public-card not secret material.
- **Delete ≠ revoke, stated + pinned.** The pane copy makes the boundary explicit and an invariant test confirms a deleted contact can still decrypt a previously-shared block.
- **Seam discipline preserved.** Only `{ contactUuidHex, displayName, sharedBlockCount }` + a user-chosen export `path` cross the IPC seam — never card bytes/keys. `ContactSummaryDto`'s hand-written `Debug` still redacts `display_name`.
- **No new exhaustive-match catchall.** The new `FfiVaultError::CannotDeleteOwnerContact` got an **explicit** arm at every binding/mapper (uniffi UDL + Rust + Swift/Kotlin conformance, pyo3, the core KAT helper, desktop `map_ffi_error`) — verified by a `--workspace` build (the D.1.6 lesson: per-crate `-p` builds mask shared-enum breaks).
- **No new capability grant.** Export reuses the already-granted `dialog:allow-open` folder picker; the write is native Rust `std::fs::write` — no `dialog:allow-save`, no JS fs capability. (`desktop/src-tauri/capabilities/` untouched.)
- **Export write is outside the session lock** (collected under the lock, written after the guard drops — mirrors `import_contact_impl`).
- **`shared_block_count` is an in-memory scan** of `manifest_body().blocks[].recipients` — no decryption, no I/O.

All commits are on `feature/d17-contacts` (branched from `main` @ `6224532`):

| Commit | What it landed |
|---|---|
| `a2dcd74` | D.1.7 design spec (`docs/superpowers/specs/2026-06-03-d17-contacts-management-design.md`; bridge-thick; revoke deferred to #177). |
| `730d5e6` | D.1.7 implementation plan (`docs/superpowers/plans/2026-06-03-d17-contacts-management.md`, 8 tasks, TDD). |
| `435d868` | **Task 1** — `enumerate_contact_cards` widened with per-contact `shared_block_count` (in-memory recipient scan; `import.rs` literal set to 0). |
| `7fdbd5f` | **Task 2** — `owner_card_export` (canonical filename + bytes; single-lock; public material). |
| `9143d57` | **Task 3** — thread `CannotDeleteOwnerContact` through uniffi (UDL + Rust + Swift/Kotlin) + pyo3 + the core KAT helper + desktop `AppError`/`map_ffi_error`, with mapping tests. Workspace-clean first build. |
| `ee01d76` | **Task 4** — `delete_contact_card` (owner-guard before any I/O; `ContactNotFound` for absent; warn-but-allow). |
| `d80bbc7` | **Task 5** — `ContactSummaryDto.sharedBlockCount` (Debug still redacts the name) + `ExportedCardDto`. |
| `dc991a6` | **Task 6** — `export_contact_card` + `delete_contact_card` IPC commands + registration + L3 tests. |
| `6eb79b5` | Task 6 review fix — release the session lock before the external export write (external I/O outside the lock, per `import_contact_impl`). |
| `86ea015` | **Task 7** — frontend `exportContactCard`/`deleteContactCard` ipc wrappers + `ContactSummaryDto.sharedBlockCount`/`ExportedCardDto` types + browse `'contacts'` level + `openContacts()` + the `cannot_delete_owner_contact` error code/message. |
| `5f9899c` | Task 7 review fix — `back()` pops the Contacts pane to blocks (mirror the trash nav arm; without it Back stranded the user once the pane rendered). |
| `a4ed0c7` | **Task 8** — `ContactsPane` (export PathPicker + list + warn-but-allow delete via the reused `ConfirmDialog`) + `ContactRow` + Vault 👤 entry/branch + `theme.css`. |
| `ea46c57` | Task 8 review fix — give `ContactRow` a distinct `.contact-card-row*` class (the `<div>` was inheriting ShareDialog's pre-existing `.contact-row` button styling) + clear the export notice on delete. |
| _(ship)_ | README/ROADMAP D.1.7 ✅ + this handoff + symlink retarget. |
| _(post-review)_ | `/review` follow-up: ContactsPane self-heals a stale row on a `contact_not_found` delete (reload + benign "already removed" notice instead of a lingering error) + a pinning test; `ContactsPane.test.ts` export fixture `.vcf` → `<uuid>.card`; `delete.rs` documents the benign owner_card()/vault_folder() wipe-gap. Frontend Vitest now **367 / 0**. |

**Process note:** one worktree (`.worktrees/d17-contacts`), one reviewed commit per task + inline review-fix commits. Every per-task spec + quality review finding was fixed before proceeding (three review-fix commits: the lock-scoping, the `back()` arm, the CSS collision). The final whole-branch review found the security posture clean and zero new issues.

### Automated gauntlet (independently re-run on `feature/d17-contacts`)

```
Rust:        PASSED 1156 FAILED 0 IGNORED 10   (+11 over the D.1.6 baseline of 1145)
cargo clippy --release --workspace --tests -- -D warnings   → clean
cargo fmt --all -- --check                                  → clean
uv run core/tests/python/conformance.py                     → PASS
uv run core/tests/python/spec_test_name_freshness.py        → PASS  (no KAT change — a new error arm only)
Swift conformance:   22/22 PASS   (UDL gained 1 error case; vectors unchanged)
Kotlin conformance:  22/22 PASS

Frontend:    Vitest 366 / 0   (new over D.1.6: ContactsPane + contacts ipc/browse/errors updates;
             vitest itself bumped 3.2.4 → 4.1.0 by dependabot #176 — clean)
pnpm typecheck      → clean
pnpm svelte-check   → 0 errors, 0 warnings
pnpm lint           → clean
```

## (3) ⚠️ Manual GUI smoke — the user's pre-merge gate (NOT run this session; headless-impossible)

> **⚠️ Smoke against a TEMP vault copy, never a git-tracked fixture.** See [[feedback_smoke_test_temp_copy_golden_vault]]. D.1.7 writes an exported `.card` and unlinks `contacts/` entries.

```bash
cd /Users/hherb/src/secretary/.worktrees/d17-contacts/desktop
pnpm install && pnpm tauri build --debug
# Unlock a TEMP copy of a vault that already has at least one imported contact
# (import via the D.1.6 ShareDialog first if needed).
./src-tauri/target/debug/secretary-desktop
```

Walk (spec §15): unlock vault A → open **👤 Contacts** → **Export my card** → pick a temp folder → confirm a `<uuid>.card` was written there. With ≥1 imported contact: the pane lists it with "receives N blocks"; share it into a block, reopen Contacts → its count increments. **Delete** that contact → because N>0, the warn dialog appears → confirm → it leaves the list. Re-open the vault → the deletion persisted; the previously-shared block is still present for the owner. (Optionally import vault A's exported card into a second vault B to confirm the round-trip.) If any step fails it's a D.1.7 regression; don't merge until fixed.

## (2) What's next — D.1.8 (brainstorm to confirm/trim)

D.1.7 deliberately deferred everything beyond export + view + delete-contact. Candidate scope for D.1.8:
- **Per-block recipient list** — show who a block is currently shared with (read the block's `recipients` + resolve each uuid to a contact display name). Self-contained, no core change; the natural next contacts-surface step. **Likely smallest high-value slice.**
- **Revoke / unshare** — **blocked on [#177](https://github.com/hherb/secretary/issues/177)** (a frozen-`core` revoke primitive that does not exist). A D-phase UI cannot deliver real revoke until #177 lands; #177 itself is a Sub-project A/B prerequisite (spec + KAT + conformance). If the user wants real revoke next, the next slice is **#177 in `core`/bridge**, not a D-phase UI.
- **Contact rename / nickname** — NB non-trivial: `display_name` is part of the *self-signed* contact card, so you can't rename the peer's card. This would need a separate **local alias** layer (a per-vault nickname map), not an edit of `contacts/*.card`. Confirm the data model before scoping.
- **Contact fingerprint-confirmation UX** — TOFU hardening: show/confirm a contact's fingerprint at import. Separate concern flagged in D.1.6.

**Acceptance criteria (per-block-recipients-first slice):** a bridge primitive to project a block's recipient uuids → resolved contact summaries (names from `contacts/`, owner labeled as "you"); an IPC command + ipc wrapper; a recipients view reachable from a block (and/or surfaced in the Contacts pane). Gauntlet green; manual smoke. Author the plan via `superpowers:brainstorming` → `superpowers:writing-plans` first; mirror the D.1.7 spec/plan structure.

## (3b) Open decisions and risks

- **Manual GUI smoke is the pre-merge gate** (§(3)). Until #161's L4 e2e lands, every D.1.x ship leans on a human walk-through.
- **#177 (core revoke primitive) filed this session** — blocks the revoke verb. It is a frozen-`core` change (Sub-project A/B), not a D-phase UI task. Forward-secrecy caveat noted in the issue: revocation only protects *future* block-versions.
- **Deferred-FFI tracking issue [#167](https://github.com/hherb/secretary/issues/167)** — the contacts *functions* (`enumerate_contact_cards`/`import_contact_card`/`share_block_to`/`owner_card_export`/`delete_contact_card`) are NOT exposed via uniffi (Swift/Kotlin) or pyo3 (no mobile/Python consumer). The shared *error enum* IS fully threaded (the new `CannotDeleteOwnerContact` is matched in both bindings). Wire the functions when D.3 (mobile) or a Python consumer needs contacts.
- **#170 (`lock_session` hoist into `commands::shared`)** still open — `commands/contacts.rs` carries the local copy, now used by 5 commands. Pure mechanical tidy-up; not a blocker.
- **Carry-forwards, all still live:**
  - **#153** — component styles in `theme.css` (Vite 6 `preprocessCSS` blocked); D.1.7 adds `.contacts-pane*` / `.contact-card-row*` / `.vault__contacts-entry`.
  - **#154** — emoji/glyphs → inline SVG (D.1.7 adds the "👤" Contacts glyph).
  - **#161** — L4 e2e harness deferred (no tauri-driver on macOS WKWebView).
  - **#162** — PathPicker e2e hook.
  - **#164** — Esc-to-pop from D.1.2.

### Verified non-issues (don't re-investigate)
- **`.contact-row` vs `.contact-card-row`:** resolved in `ea46c57` — ContactRow uses the distinct `.contact-card-row*` classes; ShareDialog's pre-existing `.contact-row`/`.contact-row--selected` rules are byte-for-byte unchanged.
- **`ContactsPane.test.ts` export mock returns a `.vcf` path string:** cosmetic test-fixture string only; the component just displays `dto.path`. Real exports are `<uuid>.card`. The `/review` follow-up aligned the fixture to the real `<uuid>.card` shape so it no longer implies a vCard path (post-review commit).
- **Export write outside the lock:** intentional (`6eb79b5`) — mirrors `import_contact_impl`; the card bytes are public so there is no zeroize/lifetime concern.
- **`delete_contact_card` does not scan share membership:** intentional — warn-but-allow; the recipient count is computed by `enumerate` and the warning is a UI gate (the primitive only guards the owner + unlinks).

## (4) Exact commands to resume (D.1.8)

```bash
# Merge the D.1.7 PR first (feature/d17-contacts) after the manual smoke, then:
cd /Users/hherb/src/secretary
git fetch --prune origin
git checkout main
git pull --ff-only origin main
git log -5 --oneline           # confirm the D.1.7 ship PR landed

# Re-baseline the automated gauntlet on fresh main:
cargo test --release --workspace --no-fail-fast 2>&1 | grep "^test result:" | awk '$3=="ok." {p+=$4; f+=$6; i+=$8} END {printf "Rust totals → PASSED %d FAILED %d IGNORED %d\n", p, f, i}'
# Expect: PASSED 1156 FAILED 0 IGNORED 10 (D.1.7 baseline)
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh 2>&1 | tail -3
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh 2>&1 | tail -3
cd desktop && pnpm install && pnpm test && pnpm typecheck && pnpm svelte-check 2>&1 | tail -3 && pnpm lint && cd ..
# Expect: Vitest 366 passing

# Author the D.1.8 plan:
#   superpowers:brainstorming  → scope per-block-recipients (or, for real revoke, scope #177 in core first)
#   superpowers:writing-plans  → mirror docs/superpowers/plans/2026-06-03-d17-contacts-management.md

# Then the first implementation worktree:
git worktree add .worktrees/d18-recipients -b feature/d18-recipients main
cd .worktrees/d18-recipients/desktop && pnpm install
```

### Housekeeping (after the D.1.7 PR merges)
```bash
cd /Users/hherb/src/secretary
git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/d17-contacts 2>/dev/null && git branch -D feature/d17-contacts 2>/dev/null
git worktree prune && git worktree list
```

## (5) Handoff file model

`NEXT_SESSION.md` at the repo root is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Author the handoff once; the symlink is a pointer. To open the next slice: author `docs/handoffs/<date>-d18-*.md` and `ln -snf docs/handoffs/<new>.md NEXT_SESSION.md`, committing both on the feature branch (per [[feedback_next_session_in_pr]]).

## Closing inventory

- **Branch on close:** `main` @ `6224532`. `feature/d17-contacts` carries the spec + plan + 8 task commits + 3 review-fix commits + the ship commit (this handoff + symlink + README/ROADMAP). Squash-merge collapses to one commit on `main`.
- **Automated gauntlet:** Rust **1156 / 0 / 10**; clippy clean; fmt clean; conformance PASS; spec-freshness PASS; Swift 22/22; Kotlin 22/22; Vitest **366 / 0** (on vitest 4.1.0); typecheck clean; svelte-check 0 errors / 0 warnings; lint clean.
- **Final whole-branch review:** security verdict **CLEAN** on all 8 invariants (owner self-card undeletable + guard-before-I/O; delete ≠ revoke stated + pinned; export public-only; seam discipline + redacting Debug; no new exhaustive-match catchall; no new capability grant; export write outside the lock; no `unsafe`, `core/` untouched). Zero Critical/Important/Minor issues.
- **PR:** not yet opened against `main` (`feature/d17-contacts`). Open it, then merge is gated on the user's manual GUI smoke (§(3)).
- **README.md / ROADMAP.md:** D.1.7 marked ✅; D.1.8 next.
- **CLAUDE.md / `docs/adr/`:** unchanged (no format/architecture change; `core/` frozen).
- **Issues filed this session:** **#177** (core revoke/unshare prerequisite).
- **NEXT_SESSION.md:** symlink retargeted to this file.
- **This file:** the live D.1.7 ship baton. The next slice opens with `docs/handoffs/<date>-d18-*.md`.
