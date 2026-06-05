# NEXT_SESSION.md — D.1.11 ✅ desktop revoke UI (Revoke ✕ on the D.1.8 banner + D.1.9 reverse map)

**Session date:** 2026-06-05 (D.1.11 — the revoke *verb* on top of the D.1.10 primitive). Authored spec + plan via `superpowers:brainstorming` → `superpowers:writing-plans`, executed all 7 tasks via `superpowers:subagent-driven-development` (fresh implementer per task + a spec-compliance review + a code-quality review after each + a final whole-branch review).
**Status:** D.1.11 ✅ code-complete on branch `feature/d111-revoke-ui`; **PR opened, not yet merged.** Full automated gauntlet **green**. Final whole-branch review: **Approve to merge**, zero Critical/Important issues. This is a **pure D-phase UI slice** (no `core`/bridge/`FfiVaultError` change — the bridge `revoke_block_from` + the two typed errors shipped in D.1.10).
**⚠️ ONE OUTSTANDING PRE-MERGE GATE: the manual GUI smoke (this slice mutates).** It could not be run in the automated session (needs an interactive GUI). **Run it against a temp copy of a vault before merging** — see §(2b).

## (1) What we shipped this session

A **Revoke** action on the two existing share-display surfaces, both calling the bridge `revoke_block_from(block_uuid, recipient_uuid)` through one new IPC command:
- **The D.1.8 "Shared with" banner** ([BlockRecipients.svelte](../../desktop/src/components/BlockRecipients.svelte)) — an always-visible ✕ on every **non-owner** recipient row (the "You" owner row gets none).
- **The D.1.9 per-contact reverse map** ([ContactRow.svelte](../../desktop/src/components/contacts/ContactRow.svelte)) — an always-visible ✕ on each block a contact receives.
- **Confirm-on-destructive** via the existing `ConfirmDialog`, with copy from a pure `revokeConfirmCopy` helper that states the **forward-secrecy boundary explicitly** (the former recipient keeps anything they already saw; revoke only protects future versions).
- **Strict mutation path**: every failure surfaces a **typed** `AppError` via `userMessageFor` — no read-path leniency (a transient fault is fatal for a revoke, never folded to "no recipients"/"no blocks"). The owner is never offered a control; `CannotRevokeOwner` is the backstop.
- **Surface-local refresh** (the design's mid-flight correction): no `refreshManifest()`. BlockRecipients reloads its own recipient list (and now stays expanded after a revoke, matching ContactRow); ContactRow reloads its own block list **and** calls a new required `onRevoked()` prop so **ContactsPane re-runs `listContacts()`** and the contact's `sharedBlockCount` badge drops — mirroring the existing `onDelete`→`confirmDelete`→`load()` flow (the badge is `list_contacts`-derived ContactsPane state, **not** manifest state).

**Architecture: pure D-phase UI slice.** `core/` and `ffi/` are untouched (0 lines — verified). The bridge `revoke_block_from` and the Rust `AppError` variants `RecipientNotPresent`/`CannotRevokeOwner` already shipped in D.1.10; this slice only added the desktop Tauri command wrapping the bridge, the missing TS error variants, the IPC wrapper, the copy helper, and the two UI surfaces.

Key commits on `feature/d111-revoke-ui` (branched from `main` @ `9be7b19`):

| Commit | What it landed |
|---|---|
| `2abfe38` | D.1.11 design spec. |
| `a9d7868` | **spec correction** — surface-local refresh; drop `refreshManifest` (the badge is `list_contacts`-derived, not manifest state). |
| `cbd528d` | 7-task TDD implementation plan. |
| `7f36c62` | **T1** — `revoke_block_from` Tauri IPC command (+ `_impl`), a verbatim inverse of `share_block_impl`; integration test (happy / `RecipientNotPresent` / `CannotRevokeOwner`). |
| `a93a458` | **T2** — TS `recipient_not_present` / `cannot_revoke_owner` variants threaded into `AppError` union + `APP_ERROR_CODES` + `userMessageFor` (+ the lockstep `errors.test.ts` sweep). |
| `e53ef3b` | **T3** — `revokeBlockFrom` TS IPC wrapper (mirrors `shareBlock`). |
| `47bbcf6` | **T4** — pure `revokeConfirmCopy` helper (single source of the forward-secrecy caveat copy). |
| `e790852` | **T5** — Revoke ✕ on the BlockRecipients banner (non-owner rows; ConfirmDialog; reload; typed-error + owner-gating + error-path tests). |
| `a870a87` | **T6** — Revoke ✕ on ContactRow + new required `onRevoked` prop wired from ContactsPane; reload + badge refresh; full test coverage incl. error path. |
| `d2938c8` | **T7** — revoke-control styles in `theme.css` (the repo's convention, not component-local) + README/ROADMAP marked D.1.11 ✅. |
| `18f3ef2` | final-review fix — keep the banner expanded after a revoke (cross-surface consistency with ContactRow). |
| _(ship)_ | this handoff + symlink retarget. |

**Process note:** one worktree (`.worktrees/d111-revoke-ui`), one reviewed commit per task + inline review-fix amends. Every per-task spec + quality finding was fixed before proceeding (the only deviations: T2 also updated the pre-existing lockstep `errors.test.ts` sweep — necessary; T7 put styles in `theme.css` not component-local `<style>` — the actual repo convention). The plan's plan-file is [docs/superpowers/plans/2026-06-05-d111-revoke-ui.md](../superpowers/plans/2026-06-05-d111-revoke-ui.md); the spec is [docs/superpowers/specs/2026-06-05-d111-revoke-ui-design.md](../superpowers/specs/2026-06-05-d111-revoke-ui-design.md).

### Automated gauntlet (re-run clean on `feature/d111-revoke-ui` @ HEAD)

```
Frontend:    pnpm test → 407 passed (54 files)
             pnpm typecheck → clean
             pnpm svelte-check → 289 files, 0 errors, 0 warnings
             pnpm lint → clean
Rust (desktop/src-tauri):
             cargo fmt --check → clean
             cargo clippy --tests -- -D warnings → clean
             cargo test → lib 107 / ipc_integration 46 (+1 new revoke test) / session 16 — all pass
```
(No core-workspace `cargo test --workspace`, no Swift/Kotlin/conformance run needed — this slice adds **no `core`/bridge/`FfiVaultError`/UDL change**, so the cross-language harnesses are untouched.)

## (2) What's next — D.1.12 (open; brainstorm to confirm scope)

**The share/revoke track (D.1.6 → D.1.11) is now complete**: import a contact → share a block → see who a block is shared with → see what a contact receives → revoke from either surface. There is no pre-committed D.1.12 — **the next session should brainstorm what the next desktop slice is.** Candidates (no decision made):
- **Carry-forward polish/issues** (all still live): #153 (component styles → `theme.css` — note D.1.11 already added its revoke styles to `theme.css`, consistent with the destination of #153), #154 (emoji → inline SVG), #161 (L4 e2e — blocked on no tauri-driver for macOS WKWebView), #162 (PathPicker e2e hook), #164 (Esc-to-pop), #170 (`lock_session` hoist into `commands::shared` — still pending; D.1.11 added another local `lock_session` user implicitly via the shared one in contacts.rs), #180 (a11y `aria-controls`).
- **A larger feature slice** (e.g. surfacing sync state in the desktop — the C-phase `secretary-sync` exists headlessly; or contact rename / fingerprint-confirmation UX deferred since D.1.7).

**Acceptance criteria:** author the D.1.12 plan via `superpowers:brainstorming` → `superpowers:writing-plans`. If it stays a pure D-phase UI slice (no `core`/bridge change), it carries no crypto-review rigor; if it is a mutation, treat the confirm + error-surfacing with care (as D.1.11 did).

## (2b) ⚠️ Manual GUI smoke — the outstanding D.1.11 pre-merge gate

Per [[feedback_smoke_test_temp_copy_golden_vault]] this slice **mutates**, so the temp-copy rule is mandatory — NEVER open the tracked golden vault (the app writes settings into it, mutating a frozen KAT). Run before merging the PR:

```bash
SMOKE_PARENT=$(mktemp -d) && cp -R /Users/hherb/src/secretary/core/tests/data/golden_vault_001 "$SMOKE_PARENT/vault"
echo "Smoke vault copy: $SMOKE_PARENT/vault"
cd /Users/hherb/src/secretary/.worktrees/d111-revoke-ui/desktop && pnpm tauri dev
# (unlock the temp copy with the golden vault test password used by unlocked_ephemeral)
```
Verify by hand, then `rm -rf "$SMOKE_PARENT"`:
- Open a shared block → "Shared with" → expand → every non-owner row has a ✕, the **"You" row does NOT**.
- Click ✕ → the confirm dialog shows the **forward-secrecy caveat** copy → Revoke → the recipient disappears and the banner **stays expanded**.
- Contacts pane → expand a contact → each block has a ✕ → revoke → the block leaves the list and the contact's "receives N blocks" count **drops**.
- Confirm a failure surfaces a typed message (nothing silently swallowed) and the ✕ glyphs are laid out correctly (the styles went into `theme.css`, untested by the GUI until now).

Record the result in the PR before merging.

## (3) Open decisions and risks

- **Manual GUI smoke is the one outstanding gate** (see §2b). Everything automated is green; the layout of the new ✕ controls (theme.css flex rules) has only been validated by `svelte-check` (no unused selectors), not visually.
- **Deferred-FFI [#167](https://github.com/hherb/secretary/issues/167) still open** — the revoke *functions* (`revoke_block` / `revoke_block_from`) remain bridge-only, NOT exposed via uniffi/pyo3. The *error variants* are already on the shared `FfiVaultError`/UDL (from D.1.10). Wire the functions when D.3 (mobile) or a Python consumer needs revoke.
- **No `FfiVaultError` churn this slice**, so the Swift/Kotlin conformance-harness tail (`cargo` can't see it) was NOT a risk here — but it remains a standing trap for any future error-enum change (run the Swift + Kotlin conformance scripts then).
- **Carry-forwards, all still live:** #153, #154, #161, #162, #164, #170, #180 (see §2).

### Verified non-issues (don't re-investigate)
- **Owner can't be revoked from the UI:** BlockRecipients renders the ✕ only for `r.kind !== 'owner'`; ContactRow only ever lists contacts. `CannotRevokeOwner` is the fail-fast backstop (pinned by the Rust `revoke_block_from_happy_and_typed_errors` test revoking `owner_user_uuid_hex`).
- **Right recipient on each surface:** BlockRecipients passes the row's `uuidHex`; ContactRow passes `contact.contactUuidHex` with the clicked block — both pinned by component tests asserting the exact `{ blockUuidHex, recipientUuidHex }` invoke payload.
- **No silent swallow on the mutation path:** both surfaces set a typed `AppError` on failure (pinned by an explicit revoke-error test on each); the Rust impl maps every bridge error with `map_ffi_error` (no catchall).
- **Badge refresh is correct:** `onRevoked={load}` re-runs `listContacts` (the badge is `list_contacts` state, not manifest) — the error-path test confirms `onRevoked` is NOT called on failure.

## (4) Exact commands to resume (D.1.12)

```bash
# Run the manual GUI smoke (§2b) and merge the D.1.11 PR first, then:
cd /Users/hherb/src/secretary
git fetch --prune origin
git checkout main
git pull --ff-only origin main
git log -5 --oneline           # confirm the D.1.11 ship PR landed

# Re-baseline the automated gauntlet on fresh main:
cd desktop && pnpm install && pnpm test && pnpm typecheck && pnpm svelte-check && pnpm lint && cd ..
cd desktop/src-tauri && cargo fmt --check && cargo clippy --tests -- -D warnings && cargo test 2>&1 | grep "^test result:" && cd ../..
# (full core-workspace gauntlet only needed if the next slice touches core/ffi:)
# cargo test --release --workspace ; cargo clippy --release --workspace --tests -- -D warnings
# uv run core/tests/python/conformance.py ; bash ffi/secretary-ffi-uniffi/tests/{swift,kotlin}/run_conformance.sh

# Author the D.1.12 plan:
#   superpowers:brainstorming  → confirm the next slice's scope (see §2 candidates)
#   superpowers:writing-plans  → mirror docs/superpowers/plans/2026-06-05-d111-revoke-ui.md

# Then the first implementation worktree:
git worktree add .worktrees/d112-<slug> -b feature/d112-<slug> main
cd .worktrees/d112-<slug>/desktop && pnpm install
```

### Housekeeping (after the D.1.11 PR merges)
```bash
cd /Users/hherb/src/secretary
git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/d111-revoke-ui 2>/dev/null && git branch -D feature/d111-revoke-ui 2>/dev/null
git worktree prune && git worktree list
```

## (5) Handoff file model

`NEXT_SESSION.md` at the repo root is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Author the handoff once; the symlink is a pointer. To open D.1.12: author `docs/handoffs/<date>-d112-*.md` and `ln -snf docs/handoffs/<new>.md NEXT_SESSION.md`, committing both on the feature branch (per [[feedback_next_session_in_pr]]).

## Closing inventory

- **Branch on close:** `main` @ `9be7b19`. `feature/d111-revoke-ui` carries the spec + spec-fix + plan + 7 task commits + the final-review consistency fix + the ship commit (this handoff + symlink). Squash-merge collapses to one commit on `main`.
- **Automated gauntlet:** frontend 407 / 0; typecheck clean; svelte-check 0/0; lint clean; Rust (desktop) 107 + 46 + 16, fmt + clippy clean.
- **Final whole-branch review:** **Approve to merge** — no Critical/Important; full spec-coverage checklist ✔; adversarial pass found no brick/leak/wrong-recipient/silent-swallow/integration gap.
- **PR:** opened against `main` (`feature/d111-revoke-ui`). **Outstanding pre-merge gate: manual GUI smoke (§2b).**
- **README.md / ROADMAP.md:** D.1.11 ✅ shipped 2026-06-05; "next" advanced to D.1.12.
- **CLAUDE.md / `docs/adr/`:** unchanged (no new architecture decision; no on-disk-format or crypto change).
- **Issues:** no new issues filed; #167 stays open; carry-forwards unchanged.
- **NEXT_SESSION.md:** symlink retargeted to this file.
- **This file:** the live D.1.11 ship baton. The next slice opens with `docs/handoffs/<date>-d112-*.md`.
