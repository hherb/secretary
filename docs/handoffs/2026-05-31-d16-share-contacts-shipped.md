# NEXT_SESSION.md — D.1.6 ✅ share a block + desktop contacts subsystem

**Session date:** 2026-05-31 (D.1.6 — the sixth Sub-project D feature slice, built on D.1.1–D.1.5). Authored spec + plan via `superpowers:brainstorming` → `superpowers:writing-plans`, then executed all 9 implementation tasks via `superpowers:subagent-driven-development` (one implementer per task + spec review + quality review after each + a final whole-branch security review).
**Status:** D.1.6 ✅ complete on branch `feature/d16-share`; **PR ready to open** against `main`. Final whole-branch review: **security CLEAN on all 9 invariants**; it also caught one workspace-build break (the new error variants weren't threaded through the uniffi/pyo3 bindings — fixed in `3daf54a`). All automated gates green. The one human gate left is the **manual GUI smoke** (§(3)) — headless-impossible; it is the pre-merge gate.

## (1) What we shipped this session

A user with an **unlocked vault** can now **share a block** they authored with a **contact**, after **importing** that contact's card, all from the desktop app:
- **Import a contact** → a 🔗 Share action on a block opens a dialog; when no contacts exist it offers **"Import a contact…"** → a native file picker for a `.card` file → the card is validated (both signature halves) and copied into the vault's `contacts/`.
- **Pick a contact** → the dialog lists imported contacts by display name (the owner's own card is excluded server-side); selecting one enables **Share**.
- **Share** → the block is re-keyed and the contact is appended to its recipient set (`core::share_block`); the block stays in the owner's list and the recipient can now decrypt it.

**Architecture decision (made this session):** **bridge-thick.** Three new bridge primitives own ALL `contacts/` I/O so the desktop never learns the on-disk vault layout (mirrors D.1.5's `list_trashed_blocks`). `core/` was **frozen and untouched** (0 lines changed under `core/`).

Key properties (verified by the final whole-branch review — **security CLEAN**):
- **Parse-then-`verify_self` is the both-halves gate.** `ContactCard::from_canonical_cbor` only PARSES; the Ed25519 ∧ ML-DSA-65 check is the **separate** `verify_self()`. Both `import_contact_card` and `enumerate_contact_cards` call it and reject/skip a card that fails EITHER half — mirroring `core::vault::restore_block`'s scan. (The spec was corrected mid-brainstorm after this was verified against core; the original draft wrongly claimed `from_canonical_cbor` self-verifies.)
- **TOFU + dedup-reject.** Import refuses to overwrite a trusted card: a duplicate `contact_uuid` → typed `ContactAlreadyExists`, never a silent overwrite.
- **Gatekeeper: card bytes + public keys never cross the IPC seam.** Only `{ contactUuidHex, displayName }` reach JS (`ContactSummaryDto`, redacting `Debug`); the share command takes a `recipientUuidHex`, never card bytes; the Rust side loads `contacts/<uuid>.card` itself. No card bytes in the DOM/logs.
- **Atomic write.** `import_contact_card` writes `contacts/<format_uuid_hyphenated(uuid)>.card` via a `NamedTempFile::persist`/`fsync_dir` replica of core's `write_atomic` (core's is `pub(crate)`, and core is frozen). `tempfile` promoted to a bridge runtime dep at the exact pin `=3.27.0`.
- **Zeroize discipline preserved by delegation.** `share_block_to` introduces no new secret-bearing locals — it assembles the recipient-card byte set from `contacts/` and delegates to the existing `share::share_block` wrapper, which owns the snapshot/per-key-zeroize/drop ordering unchanged.
- **No silent failures.** `enumerate_contact_cards` returns an `unreadableCount` (surfaced as a dialog warning); the five share/contact errors route to typed `AppError`s; `NotAuthor`'s bridge fingerprints are **dropped** at the seam (a test asserts their absence).
- **Filename vs error encoding never conflated:** file names use `format_uuid_hyphenated` (8-4-4-4-12); error `uuid_hex` fields use `hex::encode` (32 hex).

All commits are on `feature/d16-share` (branched from `main` @ `9b6b923`):

| Commit | What it landed |
|---|---|
| `8cb59d7` | D.1.6 design spec (`docs/superpowers/specs/2026-05-31-d16-share-contacts-design.md`; bridge-thick; the `verify_self` security correction). |
| `84f7a94` | D.1.6 implementation plan (`docs/superpowers/plans/2026-05-31-d16-share-contacts.md`, 10 tasks). |
| `0bb7f91` | **Task 1** — `enumerate_contact_cards` (+ `ContactSummary`, `read_verified_card` = parse+`verify_self`; omit owner; count unreadable). |
| `9d0eb8c` | Task 1 review fix — drop stale `allow(dead_code)` on `owner_card` (now a live caller). |
| `bd5b678` | **Task 2** — `import_contact_card` (TOFU `verify_self` + dedup-reject + atomic write; `ContactAlreadyExists`; `tempfile` exact-pin promotion). |
| `3411dd9` | Task 2 review fix — drop stale `allow(dead_code)` on `vault_folder`. |
| `8e61591` | Task 2 review fix — share one `handle_wiped` across contacts; correct the `vault_folder` doc. |
| `f5ebe30` | **Task 3** — `share_block_to` (assemble recipient cards from `contacts/`, delegate to `share_block`; `ContactNotFound`; `manifest_body` annotation refresh). |
| `57fe72b` | **Task 4** — typed `AppError` share/contact variants + `map_ffi_error` routing (replaces the Internal-fold). |
| `5292b24` | Task 4 review fix — correct two stale `map_ffi_error` doc blocks. |
| `9d51228` | Task 4 review fix — assert `NotAuthor` drops fingerprints at the seam (explicit absence). |
| `083032f` | **Task 5** — `ContactSummaryDto` (redacting `Debug`) + `ListContactsDto`. |
| `aa8e0b2` | **Task 6** — `list_contacts`/`import_contact`/`share_block` IPC commands + registration. |
| `658a5f4` | Task 6 review fix — drop redundant test-module imports. |
| `6500c1b` | **Task 7** — L3 integration (list/import/share over an ephemeral golden copy + a created peer card). |
| `af7d92e` | **Task 8** — frontend `lib/contacts.ts` + 3 ipc wrappers + 5 error codes (+ lockstep `errors.test.ts`). |
| `484e590` | **Task 9** — `ShareDialog` (picker + inline import) + `BlockCard` 🔗 + Vault hosting + file-capable `PathPicker` + `theme.css`. |
| `246c1a5` | Task 9 review fix — pin PathPicker file-mode + ShareDialog import/error paths. |
| `3daf54a` | **Whole-branch review fix (C1)** — thread `ContactAlreadyExists`/`ContactNotFound` through uniffi + pyo3 + the core KAT helper (+ Swift/Kotlin conformance runners). |
| _(ship)_ | README/ROADMAP D.1.6 ✅ + this handoff + symlink retarget. |

**Process note:** one worktree (`.worktrees/d16-share`), one reviewed commit per task + inline review-fix commits. Every per-task spec+quality review finding was fixed before proceeding; the final whole-branch review found the security posture clean and one cross-crate build break (C1), which was fixed and re-verified.

### Automated gauntlet (independently re-run on `feature/d16-share`)

```
Rust:        PASSED 1144 FAILED 0 IGNORED 10   (+23 over the D.1.5 baseline of 1121)
cargo clippy --release --workspace --tests -- -D warnings   → clean
cargo fmt --all -- --check                                  → clean
uv run core/tests/python/conformance.py                     → PASS
uv run core/tests/python/spec_test_name_freshness.py        → PASS  (no KAT change — contacts errors aren't in the FFI KAT surface)
Swift conformance:   22/22 PASS   (UDL gained 2 error cases; vectors unchanged)
Kotlin conformance:  22/22 PASS

Frontend:    Vitest 353 / 0   (new over D.1.5: contacts, ipcContacts, ShareDialog,
             PathPicker file-mode + errors/ShareDialog updates)
pnpm typecheck      → clean
pnpm svelte-check   → 0 errors, 0 warnings
pnpm lint           → clean
```

## (3) ⚠️ Manual GUI smoke — the user's pre-merge gate (NOT run this session; headless-impossible)

> **⚠️ Smoke against TEMP vault copies, never a git-tracked fixture.** See [[feedback_smoke_test_temp_copy_golden_vault]]. D.1.6 writes INTO `contacts/` and re-keys blocks.

Two identities are needed. Create **vault B** via the D.1.3 wizard (its `contacts/<ownerB>.card` is the import source), then build + run vault A's app:
```bash
cd /Users/hherb/src/secretary/.worktrees/d16-share/desktop
pnpm install && pnpm tauri build --debug
./src-tauri/target/debug/secretary-desktop
```

Walk (spec §15): unlock vault A → create a block with a record → **🔗 Share** → picker shows no importable contacts → **Import a contact…** → pick vault B's `contacts/<ownerB>.card` → B appears → select B → **Share** → success → re-open vault A → block still listed. Then: Share again with B → **RecipientAlreadyPresent**; Import B again → **ContactAlreadyExists**. If any step fails it's a D.1.6 regression; don't merge until fixed.

## (2) What's next — D.1.7 (contacts management: export-my-card, a contacts pane, revoke)

D.1.6 deliberately deferred everything beyond "import + pick + share." D.1.7 fills the contacts surface out.

**Candidate scope (brainstorm to confirm/trim):**
- **Export-my-card** — write the owner's own `contacts/<owner>.card` to an external file (the symmetric counterpart to import, so a peer can import *you*). Smallest, highest-value add; bridge already has `owner_card_bytes()`.
- **Standalone Contacts pane** — a Vault entry (like the D.1.5 Trash entry) listing imported contacts; view + delete a contact; show a block's current recipients.
- **Revoke / unshare** — remove a recipient from a block. NB: revoke needs a core/bridge primitive that does NOT exist yet (share is append-only in v1) — confirm what core offers before planning; this may itself be a core/B-phase prerequisite and could be deferred again.

**Acceptance criteria (export-first slice):** bridge `export_contact_card` (or reuse `owner_card_bytes`) + an IPC command writing to a user-chosen path; a frontend "Export my card" affordance; gauntlet green; manual smoke. Author the plan via `superpowers:brainstorming` → `superpowers:writing-plans` first; mirror the D.1.6 spec/plan structure.

## (3b) Open decisions and risks

- **Manual GUI smoke is the pre-merge gate** (§(3)). Until #161's L4 e2e lands, every D.1.x ship leans on a human walk-through.
- **Deferred-FFI tracking issue #167** — the contacts *functions* (`enumerate_contact_cards`/`import_contact_card`/`share_block_to`) are NOT exposed via uniffi (Swift/Kotlin) or pyo3 (no mobile/Python consumer). **NOTE:** the two new *error variants* (`ContactAlreadyExists`/`ContactNotFound`) ARE now threaded through both bindings (the shared `FfiVaultError` enum is exhaustively matched there) — only the functions are deferred. Wire the functions when D.3 (mobile) or a Python consumer needs contacts/share.
- **Lesson learned (process):** per-task scoped builds (`-p secretary-ffi-bridge`/`-p secretary-desktop`) MASKED a workspace break — adding a shared-enum variant breaks exhaustive matches in the uniffi/pyo3/KAT crates. **Run `cargo clippy --release --workspace --tests` (not `-p`) whenever you touch `FfiVaultError`.** Caught here only by the final whole-branch review.
- **TOFU is the trust model** — there is no PKI; import asserts the binding (the both-halves self-verify is the only cryptographic floor). A future contact-fingerprint-confirmation UX is a separate concern.
- **Carry-forwards, all still live:**
  - **#153** — component styles in `theme.css` (Vite 6 `preprocessCSS` blocked); D.1.6 adds `.share-dialog*`/`.contact-row*`/`.block-card__share`.
  - **#154** — emoji/glyphs → inline SVG (D.1.6 adds the "🔗" Share glyph).
  - **#161** — L4 e2e harness deferred (no tauri-driver on macOS WKWebView).
  - **#162** — PathPicker e2e hook (PathPicker gained a file mode this slice).
  - **#164** — Esc-to-pop from D.1.2.
  - **#170** — hoist the `lock_session` session-lock boilerplate into `commands::shared`; `commands/contacts.rs` adds a third local copy. Pure mechanical tidy-up; not a blocker.

### Verified non-issues (don't re-investigate)
- **`ContactSummary` / `TrashedBlock` (bridge) derive `Debug` exposing the display name:** acceptable — they never cross IPC and aren't logged; the redacting `Debug` is on the `*Dto` at the actual boundary (D.1.5 precedent).
- **Import `path.exists()` → write TOCTOU:** benign — the desktop session `Mutex` serializes all IPC commands; the dedup guarantee holds in practice.
- **`from_canonical_cbor` does NOT self-verify:** by design (core API); import/enumerate call `verify_self()` explicitly. Don't "simplify" by dropping the explicit call.

## (4) Exact commands to resume (D.1.7)

```bash
# Merge the D.1.6 PR first (feature/d16-share) after the manual smoke, then:
cd /Users/hherb/src/secretary
git fetch --prune origin
git checkout main
git pull --ff-only origin main
git log -5 --oneline           # confirm the D.1.6 ship PR landed

# Re-baseline the automated gauntlet on fresh main:
cargo test --release --workspace --no-fail-fast 2>&1 | grep "^test result:" | awk '$3=="ok." {p+=$4; f+=$6; i+=$8} END {printf "Rust totals → PASSED %d FAILED %d IGNORED %d\n", p, f, i}'
# Expect: PASSED 1144 FAILED 0 IGNORED 10 (D.1.6 baseline)
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh 2>&1 | tail -3
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh 2>&1 | tail -3
cd desktop && pnpm install && pnpm test && pnpm typecheck && pnpm svelte-check 2>&1 | tail -3 && pnpm lint && cd ..
# Expect: Vitest 353 passing

# Author the D.1.7 plan:
#   superpowers:brainstorming  → scope contacts management (export-first; pane; revoke needs a core primitive — confirm)
#   superpowers:writing-plans  → mirror docs/superpowers/plans/2026-05-31-d16-share-contacts.md

# Then the first implementation worktree:
git worktree add .worktrees/d17-contacts -b feature/d17-contacts main
cd .worktrees/d17-contacts/desktop && pnpm install
```

### Housekeeping (after the D.1.6 PR merges)
```bash
cd /Users/hherb/src/secretary
git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/d16-share 2>/dev/null && git branch -D feature/d16-share 2>/dev/null
git worktree prune && git worktree list
# Also still-stale local C-phase branches with [gone] upstreams may be swept with /clean_gone.
```

## (5) Handoff file model

`NEXT_SESSION.md` at the repo root is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Author the handoff once; the symlink is a pointer. To open the next slice: author `docs/handoffs/<date>-d17-*.md` and `ln -snf docs/handoffs/<new>.md NEXT_SESSION.md`, committing both on the feature branch (per [[feedback_next_session_in_pr]]).

## Closing inventory

- **Branch on close:** `main` @ `9b6b923`. `feature/d16-share` carries the spec + plan + 9 task commits + review-fix commits + the C1 binding fix + the ship commit (this handoff + symlink + README/ROADMAP). Squash-merge collapses to one commit on `main`. 38 files, +3526/−60.
- **Automated gauntlet:** Rust **1144 / 0 / 10**; clippy clean; fmt clean; conformance PASS; spec-freshness PASS; Swift 22/22; Kotlin 22/22; Vitest **353 / 0**; typecheck clean; svelte-check 0 errors / 0 warnings; lint clean.
- **Final whole-branch review:** security verdict **CLEAN** on all 9 invariants (parse-then-`verify_self` both-halves gate; TOFU dedup-reject; gatekeeper DTOs; atomic write + exact pin; zeroize preserved by delegation; encoding split; no silent failures; `core/` untouched; no `unsafe`). One Critical build break (C1) found + fixed + re-verified.
- **PR:** ready to open against `main` (`feature/d16-share`). Merge is gated on the user's manual GUI smoke (§(3)).
- **README.md / ROADMAP.md:** D.1.6 marked ✅; D.1.7 next.
- **CLAUDE.md / `docs/adr/`:** unchanged (no format/architecture change; `core/` frozen).
- **NEXT_SESSION.md:** symlink retargeted to this file.
- **This file:** the live D.1.6 ship baton. The next slice opens with `docs/handoffs/<date>-d17-*.md`.
