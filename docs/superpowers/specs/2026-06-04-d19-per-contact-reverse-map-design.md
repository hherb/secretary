# D.1.9 — Per-contact reverse map (which blocks a contact receives)

**Date:** 2026-06-04
**Sub-project:** D (desktop UI), ninth feature slice — built on D.1.1–D.1.8.
**Status:** design approved; ready for implementation plan.

## 1. Problem

D.1.7 (contacts management) gives the Contacts pane a per-contact `shared_block_count` — *how
many* blocks each contact receives. D.1.8 (per-block recipients) gives the inverse for a single
block: open a block, see *who* it is shared with. The remaining gap is the per-contact inverse:
given a **contact**, the user can see the count but cannot see **which** blocks that contact
receives, nor jump to one of them.

## 2. Goal

In the Contacts pane, let a user with an unlocked vault expand any contact to list exactly the
blocks that contact receives, and click a block to open it. This is the symmetric inverse of
D.1.8's "Shared with" banner — read-only, name-from-manifest, no decryption.

## 3. Scope

**In scope**
- A bridge primitive that projects a contact uuid → the list of blocks whose `recipients[]`
  contains that uuid, reusing the exact scan that computes `shared_block_count`.
- A read-only IPC command + frontend wrapper (no new TS DTO — `BlockSummaryDto` already exists).
- An inline, lazily-fetched, collapsible block list on each `ContactRow`; clicking a listed
  block opens that block's records view.

**Out of scope (deferred)**
- **Revoke / unshare** — still blocked on [#177](https://github.com/hherb/secretary/issues/177)
  (a frozen-`core` revoke primitive that does not exist). This slice only *displays*; it never
  mutates a recipient set.
- Exposing the contacts/recipients functions via uniffi (Swift/Kotlin) or pyo3 — tracked by
  [#167](https://github.com/hherb/secretary/issues/167); desktop-only via the bridge crate.
- **Return-to-contacts navigation.** `browseNav` is a single-level discriminated union, not a
  stack; after opening a block (from anywhere, including this list), **Back** returns to the
  blocks list. A return-to-contacts mini-stack is out of scope — see §8.
- Contact rename/nickname, fingerprint-confirmation UX (separate future slices).

## 4. Architecture (bridge-thick; `core/` frozen and untouched)

Held from D.1.6–D.1.8: **all `contacts/` and manifest knowledge stays in the bridge**; the
desktop never learns the on-disk vault layout. `core/src/` is untouched (0 lines). **No new
`FfiVaultError` variant** (reuses existing errors), so **no UDL / Swift / Kotlin / pyo3 change**
and no workspace-wide exhaustive-match obligation.

### 4.1 Bridge primitive — `contact_blocks`

New function in the `contacts/` module (new file `contacts/contact_blocks.rs`, kept under the
500-line rule):

```rust
pub fn contact_blocks(
    manifest: &OpenVaultManifest,
    contact_uuid: [u8; 16],
) -> Result<Vec<BlockSummary>, FfiVaultError>
```

Behavior:
- Get `manifest_body()` (→ `handle_wiped()` / `CorruptVault` if the handle was wiped, mirroring
  `block_recipients` and `enumerate_contact_cards`).
- Iterate `body.blocks[]` — the **same list** `enumerate_contact_cards` scans for
  `shared_block_count`. **`manifest.blocks` holds only live blocks; trashed blocks live in a
  separate `manifest.trash` list**, so there is no "wiped block" to filter out — membership in
  `blocks` already means live.
- Keep each block whose `recipients[]` contains `contact_uuid`, mapping it to the **existing**
  `BlockSummary` (`block_uuid`, `block_name`, `created_at_ms`, `last_modified_ms`,
  `recipient_uuids`) via the existing `block_entry_to_summary` helper (its visibility is bumped
  `pub(super)` → `pub(crate)` so the `contacts` module can reuse it — no new mapping code).
- Return blocks in **manifest order** (ascending `block_uuid`, matching `block_summaries()`).
  Presentation sort happens on the client (§4.4).
- A `contact_uuid` matching no block is **not an error** — it returns an empty `Vec`. (We scan
  recipients, not contact cards; "contact not found" is not a concept here.)

### 4.2 Count-vs-list invariant (testable)

`contact_blocks(uuid).len()` **==** that contact's `shared_block_count`, by construction — both
filter the same live `body.blocks[]` by `recipients.contains(uuid)`. A bridge test pins this for
zero / one / many shares and after a block is trashed (which removes it from `blocks`, dropping
it from both the list and the count). If the two ever diverge, that is a bug in one of the two
scans, not an acceptable state.

### 4.3 Tauri command + IPC wrapper

Follows the `block_recipients` pattern exactly:

```rust
#[tauri::command]
pub async fn list_contact_blocks(
    state: State<'_, Mutex<VaultSession>>,
    contact_uuid_hex: String,
) -> Result<Vec<BlockSummaryDto>, AppError>;

pub fn list_contact_blocks_impl(
    state: &Mutex<VaultSession>,
    contact_uuid_hex: &str,
) -> Result<Vec<BlockSummaryDto>, AppError>;
```

`list_contact_blocks_impl`: `parse_uuid_16` → `lock_session` → `with_unlocked` → bridge
`contact_blocks` (mapped via the existing `map_ffi_error`) → `.iter().map(BlockSummaryDto::from)`.
Registered in `main.rs`'s `invoke_handler`. (It reuses the file-local `lock_session` already
shared by 6 commands — #170's hoist stays deferred.)

IPC wrapper in `lib/ipc.ts`:

```ts
export function listContactBlocks(contactUuidHex: string): Promise<BlockSummaryDto[]>;
```

No new TS DTO: `BlockSummaryDto` already exists and is exactly what `openBlock` consumes.

### 4.4 Frontend — self-contained `ContactRow` (Approach A)

`ContactRow.svelte` gains:
- An `expanded: boolean` (`$state`), collapsed by default.
- A lazy fetch: on **first** expand, call `listContactBlocks(contact.contactUuidHex)` once and
  cache the result; collapse/re-expand reuses the cached list. A fetch guard (keyed by
  `contactUuidHex`, mirroring `BlockRecipients`' `loadSeq`) prevents rendering stale blocks if
  the contact prop changes.
- Loading / error / empty states mirroring `BlockRecipients.svelte`: a loading indicator while
  fetching, an inline error string on failure, and a **"No shared blocks"** empty state when the
  list is empty (the collapsed row already shows `receives 0 blocks`).
- Clicking the row body toggles `expanded`. Each listed block row, on click, calls
  `openBlock(block)` from `browse.ts` directly (the seam already exists; `BlockSummaryDto` is
  exactly what `openBlock` takes — no mapping). The delete button keeps its own click handling
  (stop propagation so deleting doesn't toggle expand).

New pure helper `lib/blocks.ts`:

```ts
export function sortBlocks(blocks: BlockSummaryDto[]): BlockSummaryDto[];
```

Orders by `blockName` **case-insensitive**, tie-broken by `blockUuidHex` for determinism. Pure,
no side effects, unit-tested in isolation (mirrors `lib/recipients.ts::sortRecipients`).
`ContactsPane` stays essentially untouched (Approach A: state + fetch live in the row).

## 5. Data flow

```
ContactRow (expand click)
  └─ listContactBlocks(contactUuidHex)            // ipc.ts
       └─ invoke('list_contact_blocks', { contactUuidHex })
            └─ list_contact_blocks_impl            // commands/contacts.rs
                 └─ contact_blocks(manifest, uuid) // bridge: scan blocks[].recipients
                      → Vec<BlockSummary> (manifest order)
       → BlockSummaryDto[]  →  sortBlocks()         // lib/blocks.ts (presentation order)
         → rendered rows; click → openBlock(block)  // browse.ts → records view
```

## 6. Error handling

- Bridge: a malformed manifest surfaces `CorruptVault` (existing). A uuid matching no block is
  an empty list, **not** an error.
- Command: existing `map_ffi_error`; locked session → the existing locked-session error.
- Frontend: a fetch rejection renders an inline error string on the expanded row (the row stays
  usable; collapse still works). No silent swallow.

## 7. Safety / invariants

- **Read-only.** The new path performs only in-memory manifest scans + the existing block-name
  read; **no write/delete/rename/re-key** anywhere. Revoke remains #177.
- **No new secret surface.** Block names and timestamps are already plaintext in the manifest
  (same data D.1.2's blocks list and D.1.8 already expose); no card bytes/keys cross the seam.
- **No `unsafe`, no panics on odd input** — a uuid matching nothing → empty list; a contact with
  zero shares → empty state; trashed blocks (in `manifest.trash`, not `blocks`) never appear.
- **`core/` frozen** — 0 lines under `core/src/`. No KAT / conformance / spec-freshness impact.

## 8. Accepted UX note

`browseNav` is a single-level discriminated union, not a navigation stack. Opening a block from
this list sets the level to `records`; **Back** then returns to the **blocks list**, identical to
opening a block any other way — not to the Contacts pane. This is consistent with the existing
model and accepted for this slice; a return-target mini-stack is explicitly out of scope.

## 9. Testing (TDD)

**Bridge** (`tests/contact_blocks.rs`, reusing the `share_block_helpers` harness):
- contact with zero shares → empty list;
- contact with one / many shares → exactly those blocks, names from manifest;
- **count-vs-list invariant**: `contact_blocks(uuid).len() == shared_block_count` for the same
  contact (cross-checked against `enumerate_contact_cards`);
- trashing a shared block drops it from both the list and the count (it moves to `manifest.trash`);
- a uuid matching nothing → empty list (no panic, no error).

**Command** (`tests/ipc_integration.rs`): `list_contact_blocks_impl` against the golden vault +
an imported peer with a shared block returns the expected `BlockSummaryDto`; locked-session →
error.

**Vitest:**
- pure `sortBlocks` — name alpha, case-insensitive, `blockUuidHex` tiebreak, stable on ties;
- `listContactBlocks` ipc wrapper — invokes `list_contact_blocks` with `{ contactUuidHex }`;
- `ContactRow` — expand/collapse toggle; lazy-fetch-**once** (no refetch on re-expand); guard on
  changed contact prop; click-a-block calls `openBlock` with that block; empty-state and
  error-state rendering; delete button does not toggle expand.

## 10. Manual GUI smoke (pre-merge gate; headless-impossible)

Against a **temp copy** of a vault (never the tracked fixture — D.1.9 is read-only but copy
anyway): unlock → open the Contacts pane → a contact with shared blocks shows `receives N blocks`
→ click the contact → it expands to list N blocks by name → click a listed block → its records
view opens → Back returns to the blocks list (accepted, §8) → reopen Contacts, expand a contact
with 0 shares → "No shared blocks". Delete a contact that still receives a block (D.1.7) does not
crash the pane. Any failure is a D.1.9 regression; do not merge until fixed.

## 11. Commits / process

One worktree (`.worktrees/d19-reverse-map`), TDD, one reviewed commit per task (mirror the
D.1.8 task sequence: bridge primitive + tests → command/IPC → ipc wrapper + types → pure
`sortBlocks` → `ContactRow` expand/fetch → wire-up + styles → fixall). **Per-task gate must run
`cargo fmt --all -- --check` in addition to clippy** (the D.1.8 retro: implementers ran clippy
but not fmt, so two tasks landed fmt-dirty — see the D.1.8 handoff §3b). Spec-compliance +
code-quality review per task; final whole-branch security review before the PR.
