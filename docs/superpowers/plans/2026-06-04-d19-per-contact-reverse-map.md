# D.1.9 — Per-contact reverse map Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** From the Contacts pane, expand a contact to list the blocks it receives (the inverse of D.1.8's per-block "Shared with" banner) and click a block to open it.

**Architecture:** Bridge-thick and read-only, mirroring D.1.6–D.1.8. A new bridge primitive `contact_blocks` scans the manifest's live block list for a contact uuid; a thin Tauri command + ipc wrapper expose it; a self-contained `ContactRow` lazily fetches and renders its block list on first expand and calls `openBlock` to navigate. `core/` is frozen and untouched; no new `FfiVaultError` variant, so no UDL/Swift/Kotlin/pyo3 change.

**Tech Stack:** Rust (bridge crate `secretary-ffi-bridge`, Tauri commands), TypeScript + Svelte 5 (desktop), Vitest + `@testing-library/svelte`.

**Spec:** `docs/superpowers/specs/2026-06-04-d19-per-contact-reverse-map-design.md`

**Per-task gate (every task):** `cargo fmt --all -- --check` AND `cargo clippy --release --workspace --tests -- -D warnings` must both pass before committing — the D.1.8 retro found two tasks landed clippy-clean but fmt-dirty because implementers ran clippy only. Run **both**.

**Working directory:** `/Users/hherb/src/secretary/.worktrees/d19-reverse-map` on branch `feature/d19-reverse-map`. Verify with `pwd && git branch --show-current` before path-sensitive commands. Use absolute paths or chain `cd` in one call (shell state does not persist between Bash calls).

---

## Key existing references (read before starting)

- Bridge sibling primitive: `ffi/secretary-ffi-bridge/src/contacts/recipients.rs` (`block_recipients`).
- The `shared_block_count` scan being inverted: `ffi/secretary-ffi-bridge/src/contacts/enumerate.rs:54-58`.
- `BlockSummary` struct: `ffi/secretary-ffi-bridge/src/vault/inner.rs:14-26` (re-exported at `secretary_ffi_bridge::vault::BlockSummary` and crate root).
- `block_entry_to_summary` helper: `ffi/secretary-ffi-bridge/src/vault/manifest.rs:427` (currently `pub(super)`).
- Command sibling: `desktop/src-tauri/src/commands/contacts.rs:161-179` (`block_recipients` / `block_recipients_impl`) + local `lock_session` at `:30-36`.
- DTO already exists: `desktop/src-tauri/src/dtos/manifest.rs:16-32` (`BlockSummaryDto` + `From<&BlockSummary>`).
- ipc wrapper sibling: `desktop/src/lib/ipc.ts:260-262` (`listBlockRecipients`).
- Pure-helper sibling: `desktop/src/lib/recipients.ts` + test `desktop/tests/recipients.test.ts`.
- Component sibling: `desktop/src/components/BlockRecipients.svelte` + test `desktop/tests/BlockRecipients.test.ts`.
- Navigation seam: `desktop/src/lib/browse.ts:26-28` (`openBlock(block: BlockSummaryDto)`).
- Component to modify: `desktop/src/components/contacts/ContactRow.svelte`; mounted by `desktop/src/components/contacts/ContactsPane.svelte:126-128` (keyed by `contactUuidHex`).
- Bridge test harness: `ffi/secretary-ffi-bridge/tests/share_block_helpers/mod.rs` (`fresh_writable_vault`, `mint_external_card`, `save_one_record_block`, `NEW_BLOCK_UUID`, `NEW_RECORD_UUID`, `DEVICE_UUID`, `NOW_MS_BASE`).
- Command test fixtures: `desktop/src-tauri/tests/ipc_integration.rs` (`unlocked_ephemeral`, `peer_card_file`, `GOLDEN_BLOCK_UUID_HEX = "112233445566778899aabbccddeeff00"`).

---

## Task 1: Bridge primitive `contact_blocks` + tests

**Files:**
- Create: `ffi/secretary-ffi-bridge/src/contacts/contact_blocks.rs`
- Modify: `ffi/secretary-ffi-bridge/src/contacts/mod.rs` (add `mod` + re-export)
- Modify: `ffi/secretary-ffi-bridge/src/lib.rs:122-124` (add `contact_blocks` to the `pub use contacts::{...}`)
- Modify: `ffi/secretary-ffi-bridge/src/vault/manifest.rs:427` (`pub(super)` → `pub(crate)` on `block_entry_to_summary`)
- Create (test): `ffi/secretary-ffi-bridge/tests/contact_blocks.rs`

- [ ] **Step 1: Write the failing integration test file**

Create `ffi/secretary-ffi-bridge/tests/contact_blocks.rs`:

```rust
//! Integration tests for D.1.9 `contact_blocks` — the per-contact inverse of
//! `block_recipients`. Reuse the share test harness (writable golden copy +
//! runtime-minted external cards). Read-only: no writes beyond the harness's
//! own save/share/trash setup.

#[allow(dead_code)]
mod share_block_helpers;

use secretary_core::identity::card::ContactCard;
use secretary_core::vault::format_uuid_hyphenated;
use secretary_ffi_bridge::{
    contact_blocks, enumerate_contact_cards, share_block_to, trash_block, OpenVaultManifest,
};
use share_block_helpers::{
    fresh_writable_vault, mint_external_card, save_one_record_block, DEVICE_UUID, NEW_BLOCK_UUID,
    NEW_RECORD_UUID, NOW_MS_BASE,
};
use std::fs;
use std::path::Path;

/// Write raw card bytes into the vault's `contacts/` dir under the canonical
/// hyphenated filename. Returns the card's `contact_uuid`. (Local copy of the
/// `recipients.rs` helper — the shared harness mod doesn't expose it.)
fn place_card(folder: &Path, card_bytes: &[u8]) -> [u8; 16] {
    let card = ContactCard::from_canonical_cbor(card_bytes).expect("valid card");
    let path = folder.join("contacts").join(format!(
        "{}.card",
        format_uuid_hyphenated(&card.contact_uuid)
    ));
    fs::write(&path, card_bytes).expect("write card");
    card.contact_uuid
}

/// Shared setup: a writable golden copy with one owner-authored block saved
/// and a minted "Alice" peer card placed in contacts/ (NOT yet a recipient).
/// Returns (tempdir guard, identity, manifest, alice_uuid).
fn vault_with_block_and_alice(
) -> (tempfile::TempDir, secretary_ffi_bridge::UnlockedIdentity, OpenVaultManifest, [u8; 16]) {
    let (tmp, identity, manifest) = fresh_writable_vault();
    save_one_record_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        NEW_RECORD_UUID,
        "user",
        "alice",
        NOW_MS_BASE,
    );
    let (_alice_bundle, alice_card) = mint_external_card(0x42, "Alice");
    let alice_uuid = place_card(tmp.path(), &alice_card);
    (tmp, identity, manifest, alice_uuid)
}

#[test]
fn contact_with_no_shares_has_empty_block_list() {
    let (_tmp, _identity, manifest, alice_uuid) = vault_with_block_and_alice();
    // Alice has a card on disk but was never made a recipient of any block.
    let blocks = contact_blocks(&manifest, alice_uuid).expect("contact_blocks ok");
    assert!(blocks.is_empty(), "an un-shared contact receives no blocks");
}

#[test]
fn contact_blocks_lists_the_shared_block() {
    let (_tmp, identity, manifest, alice_uuid) = vault_with_block_and_alice();
    share_block_to(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        alice_uuid,
        DEVICE_UUID,
        NOW_MS_BASE + 1,
    )
    .expect("share to alice");

    let blocks = contact_blocks(&manifest, alice_uuid).expect("contact_blocks ok");
    assert_eq!(blocks.len(), 1, "alice now receives exactly one block");
    assert_eq!(blocks[0].block_uuid, NEW_BLOCK_UUID);
    assert_eq!(blocks[0].block_name, "shared");
}

#[test]
fn block_count_matches_shared_block_count_invariant() {
    let (_tmp, identity, manifest, alice_uuid) = vault_with_block_and_alice();
    share_block_to(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        alice_uuid,
        DEVICE_UUID,
        NOW_MS_BASE + 1,
    )
    .expect("share to alice");

    let list_len = contact_blocks(&manifest, alice_uuid)
        .expect("contact_blocks ok")
        .len();
    let (summaries, _unreadable) =
        enumerate_contact_cards(&manifest).expect("enumerate ok");
    let alice = summaries
        .iter()
        .find(|c| c.contact_uuid == alice_uuid)
        .expect("alice is an enumerated contact");
    assert_eq!(
        list_len, alice.shared_block_count as usize,
        "contact_blocks length must equal shared_block_count"
    );
}

#[test]
fn trashing_a_shared_block_drops_it_from_the_list() {
    let (_tmp, identity, manifest, alice_uuid) = vault_with_block_and_alice();
    share_block_to(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        alice_uuid,
        DEVICE_UUID,
        NOW_MS_BASE + 1,
    )
    .expect("share to alice");
    assert_eq!(
        contact_blocks(&manifest, alice_uuid).expect("ok").len(),
        1,
        "precondition: alice receives the block before trash"
    );

    trash_block(&identity, &manifest, NEW_BLOCK_UUID, DEVICE_UUID, NOW_MS_BASE + 2)
        .expect("trash the block");

    let blocks = contact_blocks(&manifest, alice_uuid).expect("contact_blocks ok");
    assert!(
        blocks.is_empty(),
        "a trashed block (moved to manifest.trash) must not appear in the reverse map"
    );
}

#[test]
fn unknown_uuid_matches_nothing_without_error() {
    let (_tmp, _identity, manifest, _alice_uuid) = vault_with_block_and_alice();
    let stranger = [0x99u8; 16]; // valid 16 bytes, no card, no recipiency
    let blocks = contact_blocks(&manifest, stranger).expect("contact_blocks ok");
    assert!(blocks.is_empty(), "a uuid matching nothing yields an empty list");
}
```

- [ ] **Step 2: Run the test to verify it fails to compile**

Run: `cd /Users/hherb/src/secretary/.worktrees/d19-reverse-map && cargo test --release -p secretary-ffi-bridge --test contact_blocks 2>&1 | tail -20`
Expected: FAIL — `cannot find function contact_blocks in crate secretary_ffi_bridge` (the primitive does not exist yet).

- [ ] **Step 3: Bump `block_entry_to_summary` visibility**

In `ffi/secretary-ffi-bridge/src/vault/manifest.rs:427`, change:

```rust
pub(super) fn block_entry_to_summary(b: &secretary_core::vault::BlockEntry) -> BlockSummary {
```

to:

```rust
pub(crate) fn block_entry_to_summary(b: &secretary_core::vault::BlockEntry) -> BlockSummary {
```

(So the sibling `contacts` module can reuse the existing mapping rather than duplicate it.)

- [ ] **Step 4: Create the primitive**

Create `ffi/secretary-ffi-bridge/src/contacts/contact_blocks.rs`:

```rust
//! `contact_blocks`: project a contact uuid → the live blocks that list it as
//! a recipient (spec D.1.9). The per-contact inverse of D.1.8's
//! `block_recipients`. Read-only — an in-memory scan of the manifest's live
//! block list. `manifest.blocks` holds only live blocks (trashed blocks live
//! in `manifest.trash`), so they never appear here. No decryption, no I/O, no
//! mutation; revoke stays deferred to #177.

use crate::contacts::handle_wiped;
use crate::error::FfiVaultError;
use crate::vault::manifest::block_entry_to_summary;
use crate::vault::{BlockSummary, OpenVaultManifest};

/// Return the live blocks that list `contact_uuid` as a recipient, in manifest
/// order (ascending `block_uuid`; the client owns presentation ordering).
///
/// This scans the SAME `manifest.blocks` list that `enumerate_contact_cards`
/// counts for `shared_block_count`, so `contact_blocks(uuid).len()` equals that
/// contact's `shared_block_count` by construction. A `contact_uuid` matching no
/// block returns an empty `Vec` (not an error): we scan recipients, not contact
/// cards, so "contact not found" is not a concept here.
///
/// # Errors
/// - [`FfiVaultError::CorruptVault`] — the manifest handle was wiped (locked).
pub fn contact_blocks(
    manifest: &OpenVaultManifest,
    contact_uuid: [u8; 16],
) -> Result<Vec<BlockSummary>, FfiVaultError> {
    let body = manifest.manifest_body().ok_or_else(handle_wiped)?;
    Ok(body
        .blocks
        .iter()
        .filter(|b| b.recipients.contains(&contact_uuid))
        .map(block_entry_to_summary)
        .collect())
}
```

- [ ] **Step 5: Wire the module + re-exports**

In `ffi/secretary-ffi-bridge/src/contacts/mod.rs`, after the `recipients` module block (around line 22-23), add:

```rust
mod contact_blocks;
pub use contact_blocks::contact_blocks;
```

In `ffi/secretary-ffi-bridge/src/lib.rs:122-124`, add `contact_blocks` to the existing `pub use contacts::{...}` list (alphabetical, before `delete_contact_card`):

```rust
pub use contacts::{
    block_recipients, contact_blocks, delete_contact_card, enumerate_contact_cards,
    import_contact_card, owner_card_export, share_block_to, ContactSummary, RecipientKind,
    RecipientSummary,
};
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `cd /Users/hherb/src/secretary/.worktrees/d19-reverse-map && cargo test --release -p secretary-ffi-bridge --test contact_blocks 2>&1 | tail -20`
Expected: PASS — 5 tests pass.

- [ ] **Step 7: Per-task gate (fmt + clippy)**

Run: `cd /Users/hherb/src/secretary/.worktrees/d19-reverse-map && cargo fmt --all -- --check && cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -5`
Expected: both clean (no diff, no warnings). If fmt reports a diff, run `cargo fmt --all` and re-check.

- [ ] **Step 8: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/d19-reverse-map
git add ffi/secretary-ffi-bridge/src/contacts/contact_blocks.rs \
        ffi/secretary-ffi-bridge/src/contacts/mod.rs \
        ffi/secretary-ffi-bridge/src/lib.rs \
        ffi/secretary-ffi-bridge/src/vault/manifest.rs \
        ffi/secretary-ffi-bridge/tests/contact_blocks.rs
git commit -m "feat(d19): bridge contact_blocks primitive (per-contact reverse map)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Tauri command `list_contact_blocks` + tests

**Files:**
- Modify: `desktop/src-tauri/src/commands/contacts.rs` (add command + impl + import; add locked-session unit test)
- Modify: `desktop/src-tauri/src/main.rs` (register the handler)
- Modify: `desktop/src-tauri/tests/ipc_integration.rs` (add a happy-path integration test)

- [ ] **Step 1: Write the failing locked-session unit test**

In `desktop/src-tauri/src/commands/contacts.rs`, inside the existing `#[cfg(test)] mod tests` block (after `block_recipients_locked_session_is_not_unlocked`, around line 208), add:

```rust
    #[test]
    fn list_contact_blocks_locked_session_is_not_unlocked() {
        let state = Mutex::new(VaultSession::new(std::env::temp_dir()));
        // 16-byte hex UUID so parse_uuid_16 succeeds and we reach the lock path.
        let uuid_hex = "00112233445566778899aabbccddeeff";
        let err = list_contact_blocks_impl(&state, uuid_hex).expect_err("locked");
        assert!(matches!(err, AppError::NotUnlocked));
    }
```

- [ ] **Step 2: Run the test to verify it fails to compile**

Run: `cd /Users/hherb/src/secretary/.worktrees/d19-reverse-map && cargo test --release -p secretary-desktop --lib commands::contacts 2>&1 | tail -15`
Expected: FAIL — `cannot find function list_contact_blocks_impl`.

(Note: the desktop crate name is `secretary-desktop`; if `-p secretary-desktop` errors with "package not found", use `cargo test --release --manifest-path desktop/src-tauri/Cargo.toml --lib commands::contacts`.)

- [ ] **Step 3: Add the command + impl**

In `desktop/src-tauri/src/commands/contacts.rs`:

In the bridge import block (lines 15-19), add `contact_blocks as bridge_contact_blocks` (alphabetical, before `block_recipients`... keep it readable):

```rust
use secretary_ffi_bridge::{
    block_recipients as bridge_block_recipients, contact_blocks as bridge_contact_blocks,
    delete_contact_card as bridge_delete, enumerate_contact_cards as bridge_enumerate,
    import_contact_card as bridge_import, owner_card_export as bridge_owner_card_export,
    share_block_to as bridge_share_block_to,
};
```

In the DTO import (line 23), add `BlockSummaryDto`:

```rust
use crate::dtos::{
    BlockSummaryDto, ContactSummaryDto, ExportedCardDto, ListContactsDto, RecipientDto,
};
```

After `block_recipients_impl` (line 179), add:

```rust
#[tauri::command]
pub async fn list_contact_blocks(
    state: State<'_, Mutex<VaultSession>>,
    contact_uuid_hex: String,
) -> Result<Vec<BlockSummaryDto>, AppError> {
    list_contact_blocks_impl(state.inner(), &contact_uuid_hex)
}

pub fn list_contact_blocks_impl(
    state: &Mutex<VaultSession>,
    contact_uuid_hex: &str,
) -> Result<Vec<BlockSummaryDto>, AppError> {
    let contact_uuid = parse_uuid_16(contact_uuid_hex)?;
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        let blocks = bridge_contact_blocks(&u.manifest, contact_uuid).map_err(map_ffi_error)?;
        Ok(blocks.iter().map(BlockSummaryDto::from).collect())
    })
}
```

- [ ] **Step 4: Register the handler**

In `desktop/src-tauri/src/main.rs`, in the `tauri::generate_handler![...]` list, add `contacts::list_contact_blocks,` next to the existing `contacts::block_recipients,` entry (around line 101).

- [ ] **Step 5: Run the unit test to verify it passes**

Run: `cd /Users/hherb/src/secretary/.worktrees/d19-reverse-map && cargo test --release -p secretary-desktop --lib commands::contacts 2>&1 | tail -15`
Expected: PASS — including `list_contact_blocks_locked_session_is_not_unlocked`.

- [ ] **Step 6: Write the failing integration test**

In `desktop/src-tauri/tests/ipc_integration.rs`, in the contacts test module (after `share_block_happy_and_typed_errors`, around line 1239), add:

```rust
    #[test]
    fn list_contact_blocks_lists_shared_block_for_peer() {
        let (state, _vault_dir, _device_dir) = unlocked_ephemeral();

        // Import a fresh peer and share an owner-authored golden block to it.
        let (_peer_dir, card) = peer_card_file();
        let peer = contacts::import_contact_impl(&state, card.to_str().expect("utf8 path"))
            .expect("import peer");
        contacts::share_block_impl(&state, GOLDEN_BLOCK_UUID_HEX, &peer.contact_uuid_hex)
            .expect("share golden block to peer");

        // The peer's reverse map now contains exactly that block.
        let blocks = contacts::list_contact_blocks_impl(&state, &peer.contact_uuid_hex)
            .expect("list_contact_blocks ok");
        assert_eq!(blocks.len(), 1, "peer receives exactly the one shared block");
        assert_eq!(blocks[0].block_uuid_hex, GOLDEN_BLOCK_UUID_HEX);

        // A peer with no shares (use a random valid uuid) gets an empty list.
        let empty = contacts::list_contact_blocks_impl(
            &state,
            "99999999999999999999999999999999",
        )
        .expect("list_contact_blocks ok for unknown uuid");
        assert!(empty.is_empty(), "an unshared/unknown uuid receives no blocks");
    }
```

- [ ] **Step 7: Run the integration test to verify it passes**

Run: `cd /Users/hherb/src/secretary/.worktrees/d19-reverse-map && cargo test --release -p secretary-desktop --test ipc_integration list_contact_blocks 2>&1 | tail -15`
Expected: PASS.

- [ ] **Step 8: Per-task gate (fmt + clippy)**

Run: `cd /Users/hherb/src/secretary/.worktrees/d19-reverse-map && cargo fmt --all -- --check && cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -5`
Expected: both clean.

- [ ] **Step 9: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/d19-reverse-map
git add desktop/src-tauri/src/commands/contacts.rs desktop/src-tauri/src/main.rs \
        desktop/src-tauri/tests/ipc_integration.rs
git commit -m "feat(d19): list_contact_blocks Tauri command

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: `listContactBlocks` ipc wrapper + test

**Files:**
- Modify: `desktop/src/lib/ipc.ts` (add the wrapper next to `listBlockRecipients`)
- Modify: `desktop/tests/ipcContacts.test.ts` (add a wrapper test)

- [ ] **Step 1: Write the failing test**

In `desktop/tests/ipcContacts.test.ts`, add `listContactBlocks` to the import (line 4):

```ts
import { listContacts, importContact, shareBlock, exportContactCard, deleteContactCard, listContactBlocks } from '../src/lib/ipc';
```

And add a test inside the `describe('contacts IPC wrappers', ...)` block:

```ts
  it('listContactBlocks forwards contactUuidHex', async () => {
    invokeMock.mockResolvedValueOnce([
      { blockUuidHex: 'b1', blockName: 'Logins', createdAtMs: 0, lastModifiedMs: 0 }
    ]);
    const out = await listContactBlocks('abcd');
    expect(invokeMock).toHaveBeenCalledWith('list_contact_blocks', { contactUuidHex: 'abcd' });
    expect(out).toEqual([
      { blockUuidHex: 'b1', blockName: 'Logins', createdAtMs: 0, lastModifiedMs: 0 }
    ]);
  });
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /Users/hherb/src/secretary/.worktrees/d19-reverse-map/desktop && pnpm test -- ipcContacts 2>&1 | tail -15`
Expected: FAIL — `listContactBlocks is not exported` / `is not a function`.

- [ ] **Step 3: Add the wrapper**

In `desktop/src/lib/ipc.ts`, immediately after `listBlockRecipients` (line 262), add:

```ts
export async function listContactBlocks(contactUuidHex: string): Promise<BlockSummaryDto[]> {
  return call<BlockSummaryDto[]>('list_contact_blocks', { contactUuidHex });
}
```

(`BlockSummaryDto` is already declared at the top of the file; no new type needed.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd /Users/hherb/src/secretary/.worktrees/d19-reverse-map/desktop && pnpm test -- ipcContacts 2>&1 | tail -15`
Expected: PASS.

- [ ] **Step 5: Typecheck**

Run: `cd /Users/hherb/src/secretary/.worktrees/d19-reverse-map/desktop && pnpm typecheck 2>&1 | tail -5`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/d19-reverse-map
git add desktop/src/lib/ipc.ts desktop/tests/ipcContacts.test.ts
git commit -m "feat(d19): listContactBlocks ipc wrapper

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Pure `sortBlocks` helper + test

**Files:**
- Create: `desktop/src/lib/blocks.ts`
- Create (test): `desktop/tests/blocks.test.ts`

- [ ] **Step 1: Write the failing test**

Create `desktop/tests/blocks.test.ts`:

```ts
// D.1.9 — pure block-list ordering helper for the per-contact reverse map.
import { describe, it, expect } from 'vitest';
import { sortBlocks } from '../src/lib/blocks';
import type { BlockSummaryDto } from '../src/lib/ipc';

const blk = (name: string, uuid: string): BlockSummaryDto => ({
  blockUuidHex: uuid,
  blockName: name,
  createdAtMs: 0,
  lastModifiedMs: 0
});

describe('sortBlocks', () => {
  it('orders by block name case-insensitively', () => {
    const out = sortBlocks([blk('charlie', '03'), blk('Alpha', '01'), blk('bravo', '02')]);
    expect(out.map((b) => b.blockName)).toEqual(['Alpha', 'bravo', 'charlie']);
  });

  it('breaks name ties deterministically by blockUuidHex', () => {
    const out = sortBlocks([blk('Dup', 'ff'), blk('Dup', '0a'), blk('Dup', '7c')]);
    expect(out.map((b) => b.blockUuidHex)).toEqual(['0a', '7c', 'ff']);
  });

  it('is pure (does not mutate the input array)', () => {
    const a = blk('b', '02');
    const input = [a, blk('a', '01')];
    sortBlocks(input);
    expect(input[0]).toBe(a);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /Users/hherb/src/secretary/.worktrees/d19-reverse-map/desktop && pnpm test -- blocks 2>&1 | tail -15`
Expected: FAIL — cannot resolve `../src/lib/blocks`.

- [ ] **Step 3: Create the helper**

Create `desktop/src/lib/blocks.ts`:

```ts
// Pure block-list helpers (D.1.9). No IPC / DOM — the IPC wrapper lives in
// ipc.ts. Mirrors the lib/recipients.ts pure-helper discipline.
import type { BlockSummaryDto } from './ipc';

/**
 * Order blocks for display: by block name, case-insensitive, with ties broken
 * deterministically by `blockUuidHex` so the list is stable across reloads.
 * Pure (returns a new array; does not mutate the input).
 */
export function sortBlocks(blocks: BlockSummaryDto[]): BlockSummaryDto[] {
  return [...blocks].sort((a, b) => {
    const byName = a.blockName.localeCompare(b.blockName, undefined, { sensitivity: 'base' });
    if (byName !== 0) return byName;
    return a.blockUuidHex.localeCompare(b.blockUuidHex);
  });
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd /Users/hherb/src/secretary/.worktrees/d19-reverse-map/desktop && pnpm test -- blocks 2>&1 | tail -15`
Expected: PASS — 3 tests.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/d19-reverse-map
git add desktop/src/lib/blocks.ts desktop/tests/blocks.test.ts
git commit -m "feat(d19): pure sortBlocks helper

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: `ContactRow` inline expand + lazy fetch + open block

**Files:**
- Modify: `desktop/src/components/contacts/ContactRow.svelte`
- Modify: `desktop/src/theme.css` (add `.contact-card-row__toggle` + expanded-list styles)
- Create (test): `desktop/tests/ContactRow.test.ts`

- [ ] **Step 1: Write the failing component test**

Create `desktop/tests/ContactRow.test.ts`:

```ts
// D.1.9 — ContactRow inline reverse map: lazy-fetch the contact's blocks on
// first expand, render them sorted, click a block to open it. Mocks ipc invoke
// and the browse store's openBlock seam.
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));

const { openBlockMock } = vi.hoisted(() => ({ openBlockMock: vi.fn() }));
vi.mock('../src/lib/browse', () => ({ openBlock: openBlockMock }));

import ContactRow from '../src/components/contacts/ContactRow.svelte';

const contact = { contactUuidHex: 'abcd', displayName: 'Alice', sharedBlockCount: 2 };
const noDelete = () => {};

describe('ContactRow reverse map', () => {
  beforeEach(() => {
    invokeMock.mockReset();
    openBlockMock.mockReset();
  });

  it('lazily fetches and lists blocks (sorted) on first expand', async () => {
    invokeMock.mockResolvedValueOnce([
      { blockUuidHex: 'b2', blockName: 'Logins', createdAtMs: 0, lastModifiedMs: 0 },
      { blockUuidHex: 'b1', blockName: 'Cards', createdAtMs: 0, lastModifiedMs: 0 }
    ]);
    const { getByRole, getByText, queryByText } = render(ContactRow, { contact, onDelete: noDelete });

    // Not fetched until expanded.
    expect(invokeMock).not.toHaveBeenCalled();
    expect(queryByText('Logins')).toBeNull();

    await fireEvent.click(getByRole('button', { name: /Alice/ }));

    await waitFor(() => expect(getByText('Cards')).toBeTruthy());
    expect(invokeMock).toHaveBeenCalledWith('list_contact_blocks', { contactUuidHex: 'abcd' });
    // Sorted: Cards before Logins.
    const items = getByRole('list').textContent ?? '';
    expect(items.indexOf('Cards')).toBeLessThan(items.indexOf('Logins'));
  });

  it('fetches once across collapse/re-expand', async () => {
    invokeMock.mockResolvedValueOnce([
      { blockUuidHex: 'b1', blockName: 'Cards', createdAtMs: 0, lastModifiedMs: 0 }
    ]);
    const { getByRole, getByText } = render(ContactRow, { contact, onDelete: noDelete });
    const toggle = getByRole('button', { name: /Alice/ });

    await fireEvent.click(toggle); // expand → fetch
    await waitFor(() => expect(getByText('Cards')).toBeTruthy());
    await fireEvent.click(toggle); // collapse
    await fireEvent.click(toggle); // re-expand → no refetch

    expect(invokeMock).toHaveBeenCalledTimes(1);
  });

  it('clicking a block calls openBlock with that block', async () => {
    const block = { blockUuidHex: 'b1', blockName: 'Cards', createdAtMs: 0, lastModifiedMs: 0 };
    invokeMock.mockResolvedValueOnce([block]);
    const { getByRole, getByText } = render(ContactRow, { contact, onDelete: noDelete });

    await fireEvent.click(getByRole('button', { name: /Alice/ }));
    await waitFor(() => expect(getByText('Cards')).toBeTruthy());
    await fireEvent.click(getByText('Cards'));

    expect(openBlockMock).toHaveBeenCalledWith(block);
  });

  it('shows an empty state when the contact receives no blocks', async () => {
    invokeMock.mockResolvedValueOnce([]);
    const { getByRole, getByText } = render(ContactRow, {
      contact: { contactUuidHex: 'ee', displayName: 'Eve', sharedBlockCount: 0 },
      onDelete: noDelete
    });
    await fireEvent.click(getByRole('button', { name: /Eve/ }));
    await waitFor(() => expect(getByText(/No shared blocks/i)).toBeTruthy());
  });

  it('surfaces an error when the fetch rejects', async () => {
    invokeMock.mockRejectedValueOnce({ code: 'internal' });
    const { getByRole, findByRole } = render(ContactRow, { contact, onDelete: noDelete });
    await fireEvent.click(getByRole('button', { name: /Alice/ }));
    const alert = await findByRole('alert');
    expect(alert.textContent).toMatch(/internal error/i);
  });

  it('the delete button does not toggle expand', async () => {
    const onDelete = vi.fn();
    const { getByRole, queryByRole } = render(ContactRow, { contact, onDelete });
    await fireEvent.click(getByRole('button', { name: /^Delete$/ }));
    expect(onDelete).toHaveBeenCalledWith(contact);
    expect(invokeMock).not.toHaveBeenCalled(); // expand did not trigger a fetch
    expect(queryByRole('list')).toBeNull();
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /Users/hherb/src/secretary/.worktrees/d19-reverse-map/desktop && pnpm test -- ContactRow 2>&1 | tail -20`
Expected: FAIL — ContactRow has no toggle button / no list / openBlock never called.

- [ ] **Step 3: Rewrite `ContactRow.svelte`**

Replace the contents of `desktop/src/components/contacts/ContactRow.svelte` with:

```svelte
<script lang="ts">
  // One imported contact: display name + how many of the owner's blocks it
  // receives + a Delete action. D.1.9 adds an inline, lazily-fetched reverse
  // map: click the row to expand the list of blocks this contact receives;
  // click a block to open it. Mirrors BlockRecipients' load/error/empty shape,
  // but fetches on first expand (not on mount) and caches the result.
  import { listContactBlocks, isAppError, type BlockSummaryDto, type ContactSummaryDto } from '../../lib/ipc';
  import { sortBlocks } from '../../lib/blocks';
  import { openBlock } from '../../lib/browse';
  import { userMessageFor, type AppError } from '../../lib/errors';

  type Props = {
    contact: ContactSummaryDto;
    onDelete: (c: ContactSummaryDto) => void;
  };
  let { contact, onDelete }: Props = $props();

  const blocksLabel = $derived(
    contact.sharedBlockCount === 1
      ? 'receives 1 block'
      : `receives ${contact.sharedBlockCount} blocks`
  );

  let expanded = $state(false);
  let blocks = $state<BlockSummaryDto[] | null>(null);
  let loading = $state(false);
  let error = $state<AppError | null>(null);
  let fetched = false; // lazy-fetch-once guard

  async function ensureLoaded() {
    if (fetched) return;
    fetched = true;
    loading = true;
    error = null;
    try {
      const rows = await listContactBlocks(contact.contactUuidHex);
      blocks = sortBlocks(rows);
    } catch (e) {
      error = isAppError(e) ? e : { code: 'internal' };
      fetched = false; // allow a retry on the next expand after an error
    } finally {
      loading = false;
    }
  }

  function toggle() {
    expanded = !expanded;
    if (expanded) void ensureLoaded();
  }
</script>

<div class="contact-card">
  <div class="contact-card-row">
    <button
      type="button"
      class="contact-card-row__toggle"
      aria-expanded={expanded}
      onclick={toggle}
    >
      <span class="contact-card-row__name">{contact.displayName}</span>
      <span class="contact-card-row__count">{blocksLabel} {expanded ? '▴' : '▾'}</span>
    </button>
    <button type="button" class="contact-card-row__delete" onclick={() => onDelete(contact)}>
      Delete
    </button>
  </div>

  {#if expanded}
    {#if error}
      {@const msg = userMessageFor(error)}
      <p class="contact-blocks__error" role="alert">
        {msg.title}{msg.actionHint ? ` — ${msg.actionHint}` : ''}
      </p>
    {:else if loading || blocks === null}
      <p class="contact-blocks__loading">Loading blocks…</p>
    {:else if blocks.length === 0}
      <p class="contact-blocks__empty">No shared blocks.</p>
    {:else}
      <ul class="contact-blocks__list">
        {#each blocks as b (b.blockUuidHex)}
          <li>
            <button type="button" class="contact-blocks__item" onclick={() => openBlock(b)}>
              {b.blockName}
            </button>
          </li>
        {/each}
      </ul>
    {/if}
  {/if}
</div>
```

- [ ] **Step 4: Run the component test to verify it passes**

Run: `cd /Users/hherb/src/secretary/.worktrees/d19-reverse-map/desktop && pnpm test -- ContactRow 2>&1 | tail -20`
Expected: PASS — 6 tests.

- [ ] **Step 5: Add styles**

In `desktop/src/theme.css`, after the `.contact-card-row__delete:hover` rule (line 945), add (per [[#153]] component styles live in `theme.css` until Vite 6 `preprocessCSS` is unblocked):

```css
.contact-card-row__toggle {
  display: flex;
  flex: 1;
  align-items: baseline;
  gap: var(--space-2);
  padding: 0;
  border: none;
  background: transparent;
  cursor: pointer;
  text-align: left;
}
.contact-blocks__list {
  list-style: none;
  margin: 0;
  padding: var(--space-1) 0 var(--space-2) var(--space-4);
}
.contact-blocks__item {
  padding: var(--space-1) 0;
  border: none;
  background: transparent;
  color: var(--color-accent);
  cursor: pointer;
  font-size: var(--font-size-sm);
}
.contact-blocks__item:hover {
  text-decoration: underline;
}
.contact-blocks__loading,
.contact-blocks__empty,
.contact-blocks__error {
  padding: var(--space-1) 0 var(--space-2) var(--space-4);
  font-size: var(--font-size-xs);
  color: var(--color-text-muted);
}
.contact-blocks__error {
  color: var(--color-danger);
}
```

- [ ] **Step 6: Frontend gate (typecheck + svelte-check + lint + full test)**

Run: `cd /Users/hherb/src/secretary/.worktrees/d19-reverse-map/desktop && pnpm typecheck && pnpm svelte-check 2>&1 | tail -3 && pnpm lint && pnpm test 2>&1 | tail -8`
Expected: typecheck clean; svelte-check 0 errors / 0 warnings; lint clean; all Vitest files passing.

- [ ] **Step 7: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/d19-reverse-map
git add desktop/src/components/contacts/ContactRow.svelte desktop/src/theme.css \
        desktop/tests/ContactRow.test.ts
git commit -m "feat(d19): ContactRow inline reverse map (expand → blocks → open)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Whole-branch gauntlet + docs

**Files:**
- Modify: `README.md` (mark D.1.9 ✅ if the D-phase feature list tracks slices)
- Modify: `ROADMAP.md` (mark D.1.9 done; note D.1.10 / revoke-still-#177 as next)

- [ ] **Step 1: Run the full automated gauntlet on the branch**

```bash
cd /Users/hherb/src/secretary/.worktrees/d19-reverse-map
cargo test --release --workspace --no-fail-fast 2>&1 | grep "^test result:" | awk '$3=="ok." {p+=$4; f+=$6; i+=$8} END {printf "Rust totals → PASSED %d FAILED %d IGNORED %d\n", p, f, i}'
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh 2>&1 | tail -3
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh 2>&1 | tail -3
cd desktop && pnpm install && pnpm test 2>&1 | tail -5 && pnpm typecheck && pnpm svelte-check 2>&1 | tail -3 && pnpm lint && cd ..
```

Expected: Rust **PASSED 1175 FAILED 0 IGNORED 10** (1165 baseline + 5 bridge `contact_blocks` + 1 command unit + 1 command integration = +7 Rust; the exact total may differ if the harness counts differ — the invariant is **FAILED 0** and a positive delta over 1165). clippy/fmt clean; conformance + spec-freshness PASS (core untouched); Swift 22/22; Kotlin 22/22; Vitest passing (+ ipcContacts, blocks, ContactRow cases); typecheck/svelte-check/lint clean.

- [ ] **Step 2: Update README.md / ROADMAP.md**

Read each file first; mirror the D.1.8 entry style (brief dot points per [[feedback_readme_style]]). Mark D.1.9 done (per-contact reverse map: expand a contact → its blocks → open). Confirm whether README even enumerates D-slices before editing — if it only tracks sub-projects coarsely, a README edit may be unnecessary (skip rather than invent). ROADMAP: mark D.1.9 ✅; next candidate is the per-contact view's natural follow-ups or revoke (still blocked on #177).

- [ ] **Step 3: Commit docs**

```bash
cd /Users/hherb/src/secretary/.worktrees/d19-reverse-map
git add README.md ROADMAP.md
git commit -m "docs(d19): mark per-contact reverse map shipped

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Out-of-plan ship steps (done by the controller, not a task)

After all tasks pass and the gauntlet is green:
1. Per-task spec-compliance + code-quality review (subagent-driven-development); fix findings before proceeding ([[feedback_fix_all_review_issues]], [[feedback_fix_before_quality_review]]).
2. Final whole-branch security review (read-only / no-mutation / no-new-secret-surface / count-vs-list invariant / no-unsafe).
3. Author `docs/handoffs/2026-06-04-d19-per-contact-reverse-map-shipped.md`, retarget `NEXT_SESSION.md` symlink, commit on the branch BEFORE opening the PR ([[feedback_next_session_in_pr]]).
4. Open the PR against `main`; merge gated on the manual GUI smoke (spec §10) — against a TEMP vault copy ([[feedback_smoke_test_temp_copy_golden_vault]]).

## Self-review notes (author check)

- **Spec coverage:** §4.1 bridge primitive → Task 1; §4.2 invariant → Task 1 Step 1 test 3 + Task 2 integration test; §4.3 command/wrapper → Tasks 2-3; §4.4 sortBlocks + ContactRow → Tasks 4-5; §6 error handling → command (map_ffi_error) + ContactRow error state (Task 5 test 5); §7 read-only/no-unsafe → Task 1 (no writes) + workspace clippy/`#![forbid(unsafe_code)]`; §8 Back behavior → unchanged (no nav code touched); §9 tests → all tasks; §10 manual smoke → ship step.
- **Type consistency:** `contact_blocks` returns `Vec<BlockSummary>` (Task 1) → `BlockSummaryDto::from` (Task 2, existing impl) → `BlockSummaryDto[]` (Task 3 wrapper) → `sortBlocks` + `openBlock(BlockSummaryDto)` (Tasks 4-5). `list_contact_blocks` command name is identical in main.rs registration, the `_impl`, the ipc wrapper invoke string, and all tests.
- **No placeholders:** every code step shows complete code; every run step shows the command + expected outcome.
