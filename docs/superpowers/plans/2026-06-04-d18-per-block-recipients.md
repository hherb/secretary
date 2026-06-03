# Per-block Recipients ("Shared with") Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show, in the desktop app, who a block is currently shared with — resolving each recipient uuid to a name (owner = "You", peers by name, deleted-contact orphans as "Unknown contact").

**Architecture:** Bridge-thick (held from D.1.6/D.1.7): a new read-only bridge primitive `block_recipients` projects `BlockEntry.recipients[]` into classified, name-resolved summaries by reading each referenced `contacts/<uuid>.card` and verifying it. A seam DTO + one read-only IPC command carry the result; a collapsible "Shared with" banner mounted at the top of the records view renders it. `core/` is frozen and untouched. No new `FfiVaultError` variant, no UDL / Swift / Kotlin / pyo3 change.

**Tech Stack:** Rust (`secretary-ffi-bridge`, Tauri commands), TypeScript, Svelte 5 runes, Vitest, `@testing-library/svelte`.

**Spec:** [docs/superpowers/specs/2026-06-04-d18-per-block-recipients-design.md](../specs/2026-06-04-d18-per-block-recipients-design.md)

**Working directory:** worktree `.worktrees/d18-recipients`, branch `feature/d18-recipients`. Verify before every path-sensitive command: `pwd && git branch --show-current`.

---

## File structure

| File | Responsibility | Task |
|---|---|---|
| `ffi/secretary-ffi-bridge/src/contacts/recipients.rs` | **Create.** `block_recipients` + `RecipientSummary` / `RecipientKind`; classify each recipient uuid. | 1 |
| `ffi/secretary-ffi-bridge/src/contacts/mod.rs` | **Modify.** Re-export the new primitive + types. | 1 |
| `ffi/secretary-ffi-bridge/src/lib.rs` | **Modify.** Crate-level re-export. | 1 |
| `ffi/secretary-ffi-bridge/tests/recipients.rs` | **Create.** Integration tests (owner / contact / unknown / tampered / block-not-found). | 1 |
| `desktop/src-tauri/src/dtos/recipient.rs` | **Create.** `RecipientDto` + `RecipientKindDto` + redacting `Debug` + `From`. | 2 |
| `desktop/src-tauri/src/dtos/mod.rs` | **Modify.** Re-export the DTO. | 2 |
| `desktop/src-tauri/src/commands/contacts.rs` | **Modify.** Add the `block_recipients` command + `*_impl`. | 3 |
| `desktop/src-tauri/src/main.rs` | **Modify.** Register the command. | 3 |
| `desktop/src/lib/ipc.ts` | **Modify.** `RecipientDto` / `RecipientKind` types + `listBlockRecipients` wrapper. | 4 |
| `desktop/tests/ipcRecipients.test.ts` | **Create.** Wrapper passes camelCase args. | 4 |
| `desktop/src/lib/recipients.ts` | **Create.** Pure `sortRecipients` + `recipientLabel`. | 5 |
| `desktop/tests/recipients.test.ts` | **Create.** Pure-function tests. | 5 |
| `desktop/src/components/BlockRecipients.svelte` | **Create.** Collapsible "Shared with" banner. | 6 |
| `desktop/tests/BlockRecipients.test.ts` | **Create.** Component tests. | 6 |
| `desktop/src/components/RecordList.svelte` | **Modify.** Mount the banner. | 7 |
| `desktop/src/theme.css` | **Modify.** `.block-recipients*` styles. | 7 |
| `desktop/tests/RecordList.test.ts` | **Modify.** Assert the banner mounts. | 7 |

---

## Task 1: Bridge primitive `block_recipients`

**Files:**
- Create: `ffi/secretary-ffi-bridge/src/contacts/recipients.rs`
- Modify: `ffi/secretary-ffi-bridge/src/contacts/mod.rs:9-22`
- Modify: `ffi/secretary-ffi-bridge/src/lib.rs:122-125`
- Test: `ffi/secretary-ffi-bridge/tests/recipients.rs`

- [ ] **Step 1: Write the failing integration test**

Create `ffi/secretary-ffi-bridge/tests/recipients.rs`:

```rust
//! Integration tests for D.1.8 `block_recipients`. Reuse the share test
//! harness (writable golden copy + runtime-minted external cards).

#[allow(dead_code)]
mod share_block_helpers;

use secretary_core::identity::card::ContactCard;
use secretary_core::vault::format_uuid_hyphenated;
use secretary_ffi_bridge::{
    block_recipients, share_block_to, FfiVaultError, OpenVaultManifest, RecipientKind,
};
use share_block_helpers::{
    fresh_writable_vault, mint_external_card, save_one_record_block, DEVICE_UUID, NEW_BLOCK_UUID,
    NEW_RECORD_UUID, NOW_MS_BASE,
};
use std::fs;
use std::path::Path;

/// Write raw card bytes into the vault's `contacts/` dir under the canonical
/// hyphenated filename. Returns the card's `contact_uuid`.
fn place_card(folder: &Path, card_bytes: &[u8]) -> [u8; 16] {
    let card = ContactCard::from_canonical_cbor(card_bytes).expect("valid card");
    let path = folder.join("contacts").join(format!(
        "{}.card",
        format_uuid_hyphenated(&card.contact_uuid)
    ));
    fs::write(&path, card_bytes).expect("write card");
    card.contact_uuid
}

/// Resolve the owner's `contact_uuid` from the live manifest.
fn owner_uuid(manifest: &OpenVaultManifest) -> [u8; 16] {
    let bytes = manifest
        .owner_card_bytes()
        .expect("owner_card_bytes ok")
        .expect("vault has owner card");
    ContactCard::from_canonical_cbor(&bytes)
        .expect("owner card parses")
        .contact_uuid
}

#[test]
fn owner_only_block_has_single_owner_recipient() {
    let (_tmp, identity, manifest) = fresh_writable_vault();
    // Bridge save seeds recipients = [owner_card].
    save_one_record_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        NEW_RECORD_UUID,
        "user",
        "alice",
        NOW_MS_BASE,
    );
    let rs = block_recipients(&manifest, NEW_BLOCK_UUID).expect("recipients");
    assert_eq!(rs.len(), 1);
    assert_eq!(rs[0].recipient_uuid, owner_uuid(&manifest));
    assert!(matches!(rs[0].kind, RecipientKind::Owner));
}

#[test]
fn shared_peer_resolves_to_contact_then_unknown_after_card_delete() {
    let (tmp, identity, manifest) = fresh_writable_vault();
    let folder = tmp.path().to_path_buf();
    save_one_record_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        NEW_RECORD_UUID,
        "user",
        "alice",
        NOW_MS_BASE,
    );

    // Share to a minted Alice → recipients = [owner, alice]; Alice resolves.
    let (_bundle, alice_bytes) = mint_external_card(0x51, "Alice");
    let alice = place_card(&folder, &alice_bytes);
    share_block_to(&identity, &manifest, NEW_BLOCK_UUID, alice, DEVICE_UUID, NOW_MS_BASE + 1)
        .expect("share");

    let rs = block_recipients(&manifest, NEW_BLOCK_UUID).expect("recipients");
    assert_eq!(rs.len(), 2);
    assert!(matches!(rs[0].kind, RecipientKind::Owner));
    let alice_row = rs.iter().find(|r| r.recipient_uuid == alice).expect("alice row");
    match &alice_row.kind {
        RecipientKind::Contact { display_name } => assert_eq!(display_name, "Alice"),
        other => panic!("expected Contact, got {other:?}"),
    }

    // Delete Alice's card (D.1.7 delete != revoke): she stays in recipients[]
    // (residual keyholder) but no longer resolves to a name.
    fs::remove_file(
        folder
            .join("contacts")
            .join(format!("{}.card", format_uuid_hyphenated(&alice))),
    )
    .expect("rm card");
    let rs = block_recipients(&manifest, NEW_BLOCK_UUID).expect("recipients");
    assert_eq!(rs.len(), 2);
    let alice_row = rs.iter().find(|r| r.recipient_uuid == alice).expect("alice row");
    assert!(matches!(alice_row.kind, RecipientKind::Unknown));
}

#[test]
fn tampered_card_is_unknown_not_forged_name() {
    let (tmp, identity, manifest) = fresh_writable_vault();
    let folder = tmp.path().to_path_buf();
    save_one_record_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        NEW_RECORD_UUID,
        "user",
        "alice",
        NOW_MS_BASE,
    );
    let (_bundle, alice_bytes) = mint_external_card(0x51, "Alice");
    let alice = place_card(&folder, &alice_bytes);
    share_block_to(&identity, &manifest, NEW_BLOCK_UUID, alice, DEVICE_UUID, NOW_MS_BASE + 1)
        .expect("share");

    // Corrupt Alice's card on disk so parse / verify_self() fails.
    let path = folder
        .join("contacts")
        .join(format!("{}.card", format_uuid_hyphenated(&alice)));
    let mut bytes = fs::read(&path).expect("read card");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    fs::write(&path, &bytes).expect("write tampered card");

    let rs = block_recipients(&manifest, NEW_BLOCK_UUID).expect("recipients");
    let alice_row = rs.iter().find(|r| r.recipient_uuid == alice).expect("alice row");
    assert!(
        matches!(alice_row.kind, RecipientKind::Unknown),
        "a tampered card must classify Unknown, never a trusted name"
    );
}

#[test]
fn unknown_block_is_block_not_found() {
    let (_tmp, _identity, manifest) = fresh_writable_vault();
    let err = block_recipients(&manifest, [0xEE; 16]).expect_err("missing block");
    assert!(matches!(err, FfiVaultError::BlockNotFound { .. }));
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd ffi/secretary-ffi-bridge && cargo test --release --test recipients 2>&1 | tail -20`
Expected: FAIL — `block_recipients`, `RecipientKind` unresolved (not yet exported).

- [ ] **Step 3: Write the bridge primitive**

Create `ffi/secretary-ffi-bridge/src/contacts/recipients.rs`:

```rust
//! `block_recipients`: project a block's manifest recipient set into
//! name-resolved, classified summaries (spec D.1.8). The inverse of
//! `enumerate_contact_cards`'s per-contact `shared_block_count`. Read-only —
//! no decryption, no write; revoke stays deferred to #177.

use secretary_core::vault::format_uuid_hyphenated;

use crate::contacts::{handle_wiped, read_verified_card};
use crate::error::FfiVaultError;
use crate::vault::OpenVaultManifest;

/// One recipient of a block, classified and (where possible) name-resolved.
///
/// Public, secret-free: the uuid is public material and `display_name` (carried
/// inside [`RecipientKind::Contact`]) is the non-secret card label. Card bytes
/// and public keys never appear here. `Debug` is safe to derive.
#[derive(Debug)]
pub struct RecipientSummary {
    /// 16-byte recipient identity — one uuid from `BlockEntry.recipients`.
    pub recipient_uuid: [u8; 16],
    /// Classification + resolved label.
    pub kind: RecipientKind,
}

/// How a recipient uuid resolved against `contacts/` and the owner card.
#[derive(Debug)]
pub enum RecipientKind {
    /// The vault owner (uuid equals the owner card's `contact_uuid`). Checked
    /// FIRST: the owner self-card also lives in `contacts/`, so without the
    /// owner-first check it would otherwise resolve to `Contact`.
    Owner,
    /// A peer with a present, both-halves-verified card in `contacts/`.
    Contact { display_name: String },
    /// The uuid has no usable card: file missing (the D.1.7 delete != revoke
    /// residual keyholder), unreadable, or failing `verify_self()`. An
    /// unverified `display_name` is never surfaced — only the uuid is trusted.
    Unknown,
}

/// Project block `block_uuid`'s `recipients[]` into classified summaries, in
/// manifest recipient order (the client owns presentation ordering). No
/// decryption; the only I/O is reading each referenced `contacts/<uuid>.card`.
///
/// # Errors
/// - [`FfiVaultError::BlockNotFound`] — `block_uuid` absent from the manifest.
/// - [`FfiVaultError::CorruptVault`] — the manifest handle was wiped (locked).
pub fn block_recipients(
    manifest: &OpenVaultManifest,
    block_uuid: [u8; 16],
) -> Result<Vec<RecipientSummary>, FfiVaultError> {
    let folder = manifest.vault_folder().ok_or_else(handle_wiped)?;
    let owner_uuid = manifest.owner_card().ok_or_else(handle_wiped)?.contact_uuid;
    let body = manifest.manifest_body().ok_or_else(handle_wiped)?;
    let contacts_dir = folder.join("contacts");

    let entry = body
        .blocks
        .iter()
        .find(|b| b.block_uuid == block_uuid)
        .ok_or_else(|| FfiVaultError::BlockNotFound {
            uuid_hex: hex::encode(block_uuid),
        })?;

    let summaries = entry
        .recipients
        .iter()
        .map(|uuid| RecipientSummary {
            recipient_uuid: *uuid,
            kind: classify_recipient(&contacts_dir, uuid, &owner_uuid),
        })
        .collect();
    Ok(summaries)
}

/// Classify one recipient uuid: `Owner` (uuid == owner) → `Contact` (a present,
/// both-halves-verified card) → `Unknown` (missing / unreadable / unverifiable).
/// Verification failure folds into `Unknown` so a tampered card's name is never
/// trusted (mirrors the verify gate in `share.rs::load_card_bytes`).
fn classify_recipient(
    contacts_dir: &std::path::Path,
    uuid: &[u8; 16],
    owner_uuid: &[u8; 16],
) -> RecipientKind {
    if uuid == owner_uuid {
        return RecipientKind::Owner;
    }
    let path = contacts_dir.join(format!("{}.card", format_uuid_hyphenated(uuid)));
    match std::fs::read(&path) {
        Ok(bytes) => match read_verified_card(&bytes) {
            Ok(card) => RecipientKind::Contact {
                display_name: card.display_name,
            },
            Err(_) => RecipientKind::Unknown,
        },
        Err(_) => RecipientKind::Unknown,
    }
}
```

- [ ] **Step 4: Wire the module + re-exports**

In `ffi/secretary-ffi-bridge/src/contacts/mod.rs`, after the existing `mod export; pub use export::owner_card_export;` (line ~18-19) add:

```rust
mod recipients;
pub use recipients::{block_recipients, RecipientKind, RecipientSummary};
```

In `ffi/secretary-ffi-bridge/src/lib.rs`, extend the existing contacts re-export block (lines 122-125) to:

```rust
pub use contacts::{
    block_recipients, delete_contact_card, enumerate_contact_cards, import_contact_card,
    owner_card_export, share_block_to, ContactSummary, RecipientKind, RecipientSummary,
};
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd ffi/secretary-ffi-bridge && cargo test --release --test recipients 2>&1 | tail -20`
Expected: PASS — 4 tests (`owner_only_block_has_single_owner_recipient`, `shared_peer_resolves_to_contact_then_unknown_after_card_delete`, `tampered_card_is_unknown_not_forged_name`, `unknown_block_is_block_not_found`).

- [ ] **Step 6: Lint**

Run: `cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -5`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/d18-recipients
git add ffi/secretary-ffi-bridge/src/contacts/recipients.rs ffi/secretary-ffi-bridge/src/contacts/mod.rs ffi/secretary-ffi-bridge/src/lib.rs ffi/secretary-ffi-bridge/tests/recipients.rs
git commit -m "$(printf 'D.1.8 Task 1 — bridge block_recipients primitive\n\nProject a block'"'"'s recipients[] into classified summaries: Owner (uuid\n== owner, checked first), Contact (verified card), Unknown (missing /\nunreadable / unverifiable card — the D.1.7 delete != revoke residual\nkeyholder, and tampered cards, both folded to Unknown so an unverified\nname is never trusted). Read-only; reuses BlockNotFound + CorruptVault\n(no new error variant). core/ untouched.\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

## Task 2: Seam DTO `RecipientDto`

**Files:**
- Create: `desktop/src-tauri/src/dtos/recipient.rs`
- Modify: `desktop/src-tauri/src/dtos/mod.rs:21-37`
- Test: inline `#[cfg(test)]` in `recipient.rs`

- [ ] **Step 1: Write the failing test**

Create `desktop/src-tauri/src/dtos/recipient.rs` with the test module first (the types come in Step 3, so it won't compile yet — that is the failing state):

```rust
//! D.1.8 per-block recipient DTO. `RecipientDto` carries a recipient's public
//! uuid + classification + (for a resolved contact) its display name — a
//! secret-boundary value, so `Debug` redacts it. Card bytes / public keys
//! never appear (spec §3; D.1.8 §4.4).

use secretary_ffi_bridge::{RecipientKind, RecipientSummary};

/// One recipient of a block surfaced to the "Shared with" banner.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecipientDto {
    pub uuid_hex: String,
    pub kind: RecipientKindDto,
    /// `Some(name)` only for a resolved `Contact`; `None` for owner / unknown.
    pub display_name: Option<String>,
}

/// Wire tag for the recipient classification. Serialized lower-case so the
/// frontend switches on `"owner" | "contact" | "unknown"`.
#[derive(Debug, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecipientKindDto {
    Owner,
    Contact,
    Unknown,
}

impl std::fmt::Debug for RecipientDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecipientDto")
            .field("uuid_hex", &self.uuid_hex)
            .field("kind", &self.kind)
            .field("display_name", &self.display_name.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl From<&RecipientSummary> for RecipientDto {
    fn from(s: &RecipientSummary) -> Self {
        let (kind, display_name) = match &s.kind {
            RecipientKind::Owner => (RecipientKindDto::Owner, None),
            RecipientKind::Contact { display_name } => {
                (RecipientKindDto::Contact, Some(display_name.clone()))
            }
            RecipientKind::Unknown => (RecipientKindDto::Unknown, None),
        };
        RecipientDto {
            uuid_hex: hex::encode(s.recipient_uuid),
            kind,
            display_name,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn to_json<T: serde::Serialize>(v: &T) -> Value {
        serde_json::from_str(&serde_json::to_string(v).expect("ser")).expect("parse")
    }

    #[test]
    fn recipient_dto_camel_case_and_kind_tag() {
        let dto = RecipientDto {
            uuid_hex: "00112233445566778899aabbccddeeff".into(),
            kind: RecipientKindDto::Contact,
            display_name: Some("Alice".into()),
        };
        let v = to_json(&dto);
        assert_eq!(v["uuidHex"], "00112233445566778899aabbccddeeff");
        assert_eq!(v["kind"], "contact");
        assert_eq!(v["displayName"], "Alice");
        assert!(v.get("uuid_hex").is_none());
    }

    #[test]
    fn owner_serializes_as_owner_with_null_name() {
        let dto = RecipientDto {
            uuid_hex: "ab".into(),
            kind: RecipientKindDto::Owner,
            display_name: None,
        };
        let v = to_json(&dto);
        assert_eq!(v["kind"], "owner");
        assert!(v["displayName"].is_null());
    }

    #[test]
    fn unknown_serializes_as_unknown() {
        let v = to_json(&RecipientDto {
            uuid_hex: "ab".into(),
            kind: RecipientKindDto::Unknown,
            display_name: None,
        });
        assert_eq!(v["kind"], "unknown");
    }

    #[test]
    fn debug_redacts_display_name() {
        let dto = RecipientDto {
            uuid_hex: "ab".into(),
            kind: RecipientKindDto::Contact,
            display_name: Some("SecretName".into()),
        };
        let dbg = format!("{dto:?}");
        assert!(!dbg.contains("SecretName"));
        assert!(dbg.contains("redacted"));
    }
}
```

- [ ] **Step 2: Wire the module**

In `desktop/src-tauri/src/dtos/mod.rs`, add `mod recipient;` alongside the other `mod` lines and extend the re-exports:

```rust
pub use recipient::{RecipientDto, RecipientKindDto};
```

- [ ] **Step 3: Run the test to verify it passes**

Run: `cd desktop/src-tauri && cargo test --release --lib dtos::recipient 2>&1 | tail -15`
Expected: PASS — 4 tests.

> Note: Steps 1+2 already contain the full implementation (DTO types + `From`), so the "failing → passing" boundary here is module wiring rather than a stubbed impl. This DTO is pure data with no logic branch worth a separate red step.

- [ ] **Step 4: Lint**

Run: `cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -5`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add desktop/src-tauri/src/dtos/recipient.rs desktop/src-tauri/src/dtos/mod.rs
git commit -m "$(printf 'D.1.8 Task 2 — RecipientDto seam DTO\n\nuuidHex + kind (owner|contact|unknown) + optional displayName. Only\npublic material crosses the seam; Debug redacts displayName (mirrors\nContactSummaryDto). From<&RecipientSummary> maps each kind.\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

## Task 3: IPC command `block_recipients`

**Files:**
- Modify: `desktop/src-tauri/src/commands/contacts.rs:15-23` (imports) and append the command
- Modify: `desktop/src-tauri/src/main.rs:96-100` (handler registration)
- Test: inline `#[cfg(test)]` in `contacts.rs`

- [ ] **Step 1: Write the failing test**

In `desktop/src-tauri/src/commands/contacts.rs`, add to the existing `#[cfg(test)] mod tests` block:

```rust
    #[test]
    fn block_recipients_locked_session_is_not_unlocked() {
        let state = Mutex::new(VaultSession::new(std::env::temp_dir()));
        let uuid_hex = "00112233445566778899aabbccddeeff";
        let err = block_recipients_impl(&state, uuid_hex).expect_err("locked");
        assert!(matches!(err, AppError::NotUnlocked));
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd desktop/src-tauri && cargo test --release --lib commands::contacts 2>&1 | tail -15`
Expected: FAIL — `block_recipients_impl` not found.

- [ ] **Step 3: Write the command**

In `desktop/src-tauri/src/commands/contacts.rs`, extend the bridge import (lines 15-19) to include `block_recipients as bridge_block_recipients`:

```rust
use secretary_ffi_bridge::{
    block_recipients as bridge_block_recipients, delete_contact_card as bridge_delete,
    enumerate_contact_cards as bridge_enumerate, import_contact_card as bridge_import,
    owner_card_export as bridge_owner_card_export, share_block_to as bridge_share_block_to,
};
```

Extend the dtos import (line 23) to include `RecipientDto`:

```rust
use crate::dtos::{ContactSummaryDto, ExportedCardDto, ListContactsDto, RecipientDto};
```

Append the command (after `delete_contact_card_impl`, before the `#[cfg(test)]` module):

```rust
#[tauri::command]
pub async fn block_recipients(
    state: State<'_, Mutex<VaultSession>>,
    block_uuid_hex: String,
) -> Result<Vec<RecipientDto>, AppError> {
    block_recipients_impl(state.inner(), &block_uuid_hex)
}

pub fn block_recipients_impl(
    state: &Mutex<VaultSession>,
    block_uuid_hex: &str,
) -> Result<Vec<RecipientDto>, AppError> {
    let block_uuid = parse_uuid_16(block_uuid_hex)?;
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        let rs = bridge_block_recipients(&u.manifest, block_uuid).map_err(map_ffi_error)?;
        Ok(rs.iter().map(RecipientDto::from).collect())
    })
}
```

- [ ] **Step 4: Register the command**

In `desktop/src-tauri/src/main.rs`, add to the `generate_handler!` list (after `contacts::delete_contact_card,` at line ~100):

```rust
            contacts::block_recipients,
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd desktop/src-tauri && cargo test --release --lib commands::contacts 2>&1 | tail -15`
Expected: PASS.

- [ ] **Step 6: Lint**

Run: `cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -5`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add desktop/src-tauri/src/commands/contacts.rs desktop/src-tauri/src/main.rs
git commit -m "$(printf 'D.1.8 Task 3 — block_recipients IPC command\n\nRead-only command: parse block uuid, lock session, call bridge\nblock_recipients, map summaries to RecipientDto. Registered in the\nTauri handler list. BlockNotFound maps via the existing map_ffi_error\n(folds to Internal — a stale block uuid is a frontend race).\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

## Task 4: Frontend ipc wrapper + types

**Files:**
- Modify: `desktop/src/lib/ipc.ts` (types near other DTOs; wrapper near `listContacts`)
- Test: `desktop/tests/ipcRecipients.test.ts`

- [ ] **Step 1: Write the failing test**

Create `desktop/tests/ipcRecipients.test.ts`:

```ts
// D.1.8 — listBlockRecipients passes the block uuid as a camelCase arg and
// returns the recipient DTO array verbatim.
import { describe, it, expect, vi, beforeEach } from 'vitest';

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));

import { listBlockRecipients, type RecipientDto } from '../src/lib/ipc';

describe('listBlockRecipients', () => {
  beforeEach(() => invokeMock.mockReset());

  it('invokes block_recipients with a camelCase blockUuidHex arg', async () => {
    const rows: RecipientDto[] = [
      { uuidHex: 'aa', kind: 'owner', displayName: null },
      { uuidHex: 'bb', kind: 'contact', displayName: 'Alice' }
    ];
    invokeMock.mockResolvedValueOnce(rows);
    const res = await listBlockRecipients('deadbeef');
    expect(invokeMock).toHaveBeenCalledWith('block_recipients', { blockUuidHex: 'deadbeef' });
    expect(res).toEqual(rows);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd desktop && pnpm test -- ipcRecipients 2>&1 | tail -15`
Expected: FAIL — `listBlockRecipients` / `RecipientDto` not exported.

- [ ] **Step 3: Add the types + wrapper**

In `desktop/src/lib/ipc.ts`, add the types near the other DTO interfaces (e.g. after `ListContactsDto`, around line 86):

```ts
export type RecipientKind = 'owner' | 'contact' | 'unknown';

export interface RecipientDto {
  uuidHex: string;
  kind: RecipientKind;
  displayName: string | null;
}
```

Add the wrapper near `listContacts` (around line 250):

```ts
export async function listBlockRecipients(blockUuidHex: string): Promise<RecipientDto[]> {
  return call<RecipientDto[]>('block_recipients', { blockUuidHex });
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd desktop && pnpm test -- ipcRecipients 2>&1 | tail -15`
Expected: PASS.

- [ ] **Step 5: Typecheck + commit**

Run: `cd desktop && pnpm typecheck 2>&1 | tail -5`
Expected: clean.

```bash
git add desktop/src/lib/ipc.ts desktop/tests/ipcRecipients.test.ts
git commit -m "$(printf 'D.1.8 Task 4 — listBlockRecipients ipc wrapper + RecipientDto type\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

## Task 5: Pure lib `recipients.ts`

**Files:**
- Create: `desktop/src/lib/recipients.ts`
- Test: `desktop/tests/recipients.test.ts`

- [ ] **Step 1: Write the failing test**

Create `desktop/tests/recipients.test.ts`:

```ts
// D.1.8 — pure recipient helpers: display ordering + label resolution.
import { describe, it, expect } from 'vitest';
import { sortRecipients, recipientLabel } from '../src/lib/recipients';
import type { RecipientDto } from '../src/lib/ipc';

const owner: RecipientDto = { uuidHex: '00', kind: 'owner', displayName: null };
const alice: RecipientDto = { uuidHex: 'a1', kind: 'contact', displayName: 'Alice' };
const bob: RecipientDto = { uuidHex: 'b2', kind: 'contact', displayName: 'bob' };
const unknown: RecipientDto = {
  uuidHex: 'a1b2c3d4e5f60718',
  kind: 'unknown',
  displayName: null
};

describe('sortRecipients', () => {
  it('orders owner first, then contacts alpha (case-insensitive), then unknowns', () => {
    const out = sortRecipients([unknown, bob, alice, owner]);
    expect(out.map((r) => r.kind)).toEqual(['owner', 'contact', 'contact', 'unknown']);
    expect(out[1].displayName).toBe('Alice');
    expect(out[2].displayName).toBe('bob');
  });

  it('is pure (does not mutate the input array)', () => {
    const input = [bob, alice];
    sortRecipients(input);
    expect(input[0]).toBe(bob);
  });
});

describe('recipientLabel', () => {
  it('labels the owner "You"', () => {
    expect(recipientLabel(owner)).toBe('You');
  });

  it('labels a contact by its display name', () => {
    expect(recipientLabel(alice)).toBe('Alice');
  });

  it('labels an unknown with an 8-hex uuid prefix', () => {
    expect(recipientLabel(unknown)).toBe('Unknown contact (a1b2c3d4…)');
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd desktop && pnpm test -- recipients.test 2>&1 | tail -15`
Expected: FAIL — module `../src/lib/recipients` not found.

- [ ] **Step 3: Write the pure module**

Create `desktop/src/lib/recipients.ts`:

```ts
// Pure per-block recipient helpers (D.1.8). No IPC / DOM — the IPC wrapper
// lives in ipc.ts. Mirrors the lib/contacts.ts pure-helper discipline.
import type { RecipientDto } from './ipc';

/** Number of leading hex chars shown for an unresolved recipient uuid. */
const UNKNOWN_UUID_PREFIX_LEN = 8;

/** Display rank: owner first, contacts middle, unknowns last. */
function rank(r: RecipientDto): number {
  return r.kind === 'owner' ? 0 : r.kind === 'contact' ? 1 : 2;
}

/**
 * Order recipients for display: owner first → contacts sorted case-insensitively
 * by displayName → unknowns last. Pure (returns a new array).
 */
export function sortRecipients(rs: RecipientDto[]): RecipientDto[] {
  return [...rs].sort((a, b) => {
    const dr = rank(a) - rank(b);
    if (dr !== 0) return dr;
    if (a.kind === 'contact' && b.kind === 'contact') {
      return (a.displayName ?? '').localeCompare(b.displayName ?? '', undefined, {
        sensitivity: 'base'
      });
    }
    return 0;
  });
}

/**
 * Human label for one recipient. Owner → "You"; contact → its display name;
 * unknown → "Unknown contact (<8 hex>…)", surfacing the residual-keyholder uuid
 * so a deleted contact's lingering access stays visible (delete ≠ revoke).
 */
export function recipientLabel(r: RecipientDto): string {
  if (r.kind === 'owner') return 'You';
  if (r.kind === 'contact') return r.displayName ?? 'Unknown contact';
  return `Unknown contact (${r.uuidHex.slice(0, UNKNOWN_UUID_PREFIX_LEN)}…)`;
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd desktop && pnpm test -- recipients.test 2>&1 | tail -15`
Expected: PASS — 5 tests.

- [ ] **Step 5: Lint + typecheck + commit**

Run: `cd desktop && pnpm typecheck 2>&1 | tail -3 && pnpm lint 2>&1 | tail -3`
Expected: clean.

```bash
git add desktop/src/lib/recipients.ts desktop/tests/recipients.test.ts
git commit -m "$(printf 'D.1.8 Task 5 — pure sortRecipients + recipientLabel helpers\n\nOwner-first / contacts-alpha / unknowns-last ordering; labels owner as\nYou, contact by name, unknown as Unknown contact (8hex…).\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

## Task 6: `BlockRecipients.svelte` banner

**Files:**
- Create: `desktop/src/components/BlockRecipients.svelte`
- Test: `desktop/tests/BlockRecipients.test.ts`

- [ ] **Step 1: Write the failing test**

Create `desktop/tests/BlockRecipients.test.ts`:

```ts
// D.1.8 — BlockRecipients banner: loads block_recipients on mount, renders a
// collapsed summary, expands to a per-recipient list, surfaces errors.
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));

import BlockRecipients from '../src/components/BlockRecipients.svelte';

const block = { blockUuidHex: 'deadbeef', blockName: 'Logins', lastModifiedMs: 0 };

describe('BlockRecipients', () => {
  beforeEach(() => invokeMock.mockReset());

  it('shows a collapsed summary then expands to the full list', async () => {
    invokeMock.mockResolvedValueOnce([
      { uuidHex: '00', kind: 'owner', displayName: null },
      { uuidHex: 'a1', kind: 'contact', displayName: 'Alice' },
      { uuidHex: 'a1b2c3d4e5f6', kind: 'unknown', displayName: null }
    ]);
    const { getByRole, getByText, queryByText } = render(BlockRecipients, { block });

    // Collapsed: summary names owner + contact + unknown count.
    await waitFor(() => expect(getByText(/Shared with:/)).toBeTruthy());
    expect(getByText(/You, Alice, \+1 unknown/)).toBeTruthy();
    // List rows not shown until expanded.
    expect(queryByText('Unknown contact (a1b2c3d4…)')).toBeNull();

    await fireEvent.click(getByRole('button', { name: /shared with/i }));
    expect(getByText('Unknown contact (a1b2c3d4…)')).toBeTruthy();
    expect(invokeMock).toHaveBeenCalledWith('block_recipients', { blockUuidHex: 'deadbeef' });
  });

  it('surfaces a typed error when the call rejects', async () => {
    invokeMock.mockRejectedValueOnce({ code: 'internal' });
    const { findByRole } = render(BlockRecipients, { block });
    const alert = await findByRole('alert');
    expect(alert.textContent).toMatch(/something went wrong|unexpected/i);
  });
});
```

> The error-copy assertion matches whatever `userMessageFor({ code: 'internal' })` returns in `desktop/src/lib/errors.ts`; if that wording differs, align the regex to it (do not change the error copy).

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd desktop && pnpm test -- BlockRecipients 2>&1 | tail -15`
Expected: FAIL — component not found.

- [ ] **Step 3: Write the component**

Create `desktop/src/components/BlockRecipients.svelte`:

```svelte
<script lang="ts">
  // D.1.8 "Shared with" banner — mounted at the top of the records view.
  // Loads block_recipients for the current block, shows a collapsed one-line
  // summary, and expands to a per-recipient list. Self-contained load/loadSeq
  // guard keyed by block.blockUuidHex (mirrors RecordList's own pattern).
  import { listBlockRecipients, isAppError, type BlockSummaryDto, type RecipientDto } from '../lib/ipc';
  import { sortRecipients, recipientLabel } from '../lib/recipients';
  import { userMessageFor, type AppError } from '../lib/errors';

  type Props = { block: BlockSummaryDto };
  let { block }: Props = $props();

  let recipients = $state<RecipientDto[] | null>(null);
  let error = $state<AppError | null>(null);
  let expanded = $state(false);

  let loadSeq = 0;
  async function load() {
    const seq = ++loadSeq;
    const blockUuidHex = block.blockUuidHex;
    recipients = null;
    error = null;
    try {
      const rows = await listBlockRecipients(blockUuidHex);
      if (seq === loadSeq) recipients = sortRecipients(rows);
    } catch (e) {
      if (seq === loadSeq) error = isAppError(e) ? e : { code: 'internal' };
    }
  }

  $effect(() => {
    void block.blockUuidHex;
    void load();
  });

  // Collapsed summary: name resolved recipients, fold unknowns into a count.
  const summary = $derived.by(() => {
    if (!recipients) return '';
    const named = recipients.filter((r) => r.kind !== 'unknown').map(recipientLabel);
    const unknownCount = recipients.filter((r) => r.kind === 'unknown').length;
    const parts = [...named];
    if (unknownCount > 0) parts.push(`+${unknownCount} unknown`);
    return parts.join(', ');
  });
</script>

<div class="block-recipients">
  {#if error}
    {@const msg = userMessageFor(error)}
    <p class="block-recipients__error" role="alert">
      {msg.title}{msg.actionHint ? ` — ${msg.actionHint}` : ''}
    </p>
  {:else if recipients === null}
    <p class="block-recipients__loading">Loading recipients…</p>
  {:else}
    <button
      type="button"
      class="block-recipients__toggle"
      aria-expanded={expanded}
      onclick={() => (expanded = !expanded)}
    >
      Shared with: {summary} {expanded ? '▴' : '▾'}
    </button>
    {#if expanded}
      <ul class="block-recipients__list">
        {#each recipients as r (r.uuidHex)}
          <li class="block-recipients__row" class:block-recipients__row--unknown={r.kind === 'unknown'}>
            {recipientLabel(r)}
          </li>
        {/each}
      </ul>
    {/if}
  {/if}
</div>
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd desktop && pnpm test -- BlockRecipients 2>&1 | tail -15`
Expected: PASS — 2 tests.

- [ ] **Step 5: Typecheck + svelte-check + commit**

Run: `cd desktop && pnpm typecheck 2>&1 | tail -3 && pnpm svelte-check 2>&1 | tail -3`
Expected: clean (0 errors / 0 warnings).

```bash
git add desktop/src/components/BlockRecipients.svelte desktop/tests/BlockRecipients.test.ts
git commit -m "$(printf 'D.1.8 Task 6 — BlockRecipients collapsible banner\n\nLoads block_recipients on mount (loadSeq guard keyed by blockUuidHex),\ncollapsed summary (You, Alice, +1 unknown), expands to a per-recipient\nlist via recipientLabel. Error + loading states.\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

## Task 7: Mount in RecordList + styles

**Files:**
- Modify: `desktop/src/components/RecordList.svelte:12` (import) and `:86-88` (mount)
- Modify: `desktop/src/theme.css` (append `.block-recipients*` rules)
- Test: `desktop/tests/RecordList.test.ts`

- [ ] **Step 1: Write the failing test**

Add to `desktop/tests/RecordList.test.ts` (it already mocks `@tauri-apps/api/core` invoke; reuse that mock). Add a case asserting the banner mounts and calls `block_recipients`:

```ts
  it('mounts the Shared-with banner for the block', async () => {
    // readBlock (records) + block_recipients (banner) both fire on mount.
    invokeMock.mockImplementation((cmd: string) => {
      if (cmd === 'read_block') return Promise.resolve({ records: [] });
      if (cmd === 'block_recipients')
        return Promise.resolve([{ uuidHex: '00', kind: 'owner', displayName: null }]);
      return Promise.reject(new Error(`unexpected cmd ${cmd}`));
    });
    const { getByText } = render(RecordList, {
      block: { blockUuidHex: 'deadbeef', blockName: 'Logins', lastModifiedMs: 0 }
    });
    await waitFor(() => expect(getByText(/Shared with:/)).toBeTruthy());
    expect(invokeMock).toHaveBeenCalledWith('block_recipients', { blockUuidHex: 'deadbeef' });
  });
```

> If `RecordList.test.ts` uses `mockResolvedValueOnce` per case, switch this case to the `mockImplementation` form above so both the `read_block` and `block_recipients` calls are answered regardless of order. Confirm the existing imports (`render`, `waitFor`, `getByText`) are present at the top of the file; add any missing ones.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd desktop && pnpm test -- RecordList 2>&1 | tail -15`
Expected: FAIL — no "Shared with:" text (banner not mounted).

- [ ] **Step 3: Mount the banner**

In `desktop/src/components/RecordList.svelte`, add the import after the `RecordRow` import (line 12):

```ts
  import BlockRecipients from './BlockRecipients.svelte';
```

Mount it in the header, right after the back button (line 87) and before the "+ Add record" button:

```svelte
  <button type="button" class="record-list__back" onclick={() => back()}>← {block.blockName}</button>
  <BlockRecipients {block} />
  <button type="button" class="record-list__add" onclick={() => openNewRecord(block)}>+ Add record</button>
```

- [ ] **Step 4: Add styles**

Append to `desktop/src/theme.css` (the component-styles location per carry-forward #153):

```css
/* D.1.8 per-block recipients ("Shared with") banner */
.block-recipients {
  margin: 0.25rem 0 0.5rem;
}
.block-recipients__toggle {
  background: none;
  border: none;
  padding: 0.15rem 0;
  color: var(--color-text-muted, #aaa);
  font-size: 0.85rem;
  cursor: pointer;
  text-align: left;
}
.block-recipients__list {
  list-style: none;
  margin: 0.25rem 0 0;
  padding: 0 0 0 0.75rem;
}
.block-recipients__row {
  font-size: 0.85rem;
  line-height: 1.5;
}
.block-recipients__row--unknown {
  color: var(--color-warn, #d08a3a);
}
.block-recipients__loading,
.block-recipients__error {
  font-size: 0.85rem;
  color: var(--color-text-muted, #aaa);
}
.block-recipients__error {
  color: var(--color-error, #d05a5a);
}
```

> Match the actual CSS variable names already used in `theme.css` (e.g. existing `--color-*` tokens). The fallbacks above keep it rendering even if a token is absent; replace them with the project's real tokens where they exist.

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd desktop && pnpm test -- RecordList 2>&1 | tail -15`
Expected: PASS.

- [ ] **Step 6: Full frontend gate**

Run: `cd desktop && pnpm test 2>&1 | tail -6 && pnpm typecheck 2>&1 | tail -3 && pnpm svelte-check 2>&1 | tail -3 && pnpm lint 2>&1 | tail -3`
Expected: all Vitest pass; typecheck/svelte-check/lint clean.

- [ ] **Step 7: Commit**

```bash
git add desktop/src/components/RecordList.svelte desktop/src/theme.css desktop/tests/RecordList.test.ts
git commit -m "$(printf 'D.1.8 Task 7 — mount Shared-with banner in the records view\n\nBlockRecipients mounted at the top of RecordList; .block-recipients*\nstyles in theme.css (unknown rows tinted to flag residual keyholders).\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

## Final verification (after Task 7)

Run the full automated gauntlet from the worktree root:

```bash
cd /Users/hherb/src/secretary/.worktrees/d18-recipients
pwd && git branch --show-current   # confirm feature/d18-recipients

cargo test --release --workspace --no-fail-fast 2>&1 | grep "^test result:" | awk '$3=="ok." {p+=$4; f+=$6; i+=$8} END {printf "Rust totals → PASSED %d FAILED %d IGNORED %d\n", p, f, i}'
# Expect: PASSED ≥ 1160 (1156 baseline + 4 new bridge + 4 new DTO + 1 command), FAILED 0, IGNORED 10

cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
uv run core/tests/python/conformance.py            # PASS (core untouched)
uv run core/tests/python/spec_test_name_freshness.py  # PASS (no KAT change)
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh 2>&1 | tail -2    # 22/22 (no UDL change)
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh 2>&1 | tail -2   # 22/22
cd desktop && pnpm test && pnpm typecheck && pnpm svelte-check && pnpm lint && cd ..
# Expect: Vitest ≥ 375 (367 baseline + new ipc/pure/component/recordlist tests)
```

Then request a whole-branch review (spec-compliance + code-quality + security per [[feedback_fix_all_review_issues]]), fix every finding before proceeding, update README/ROADMAP for D.1.8 ✅, and author the ship handoff per the `/nextsession` symlink workflow.

---

## Self-review notes (author)

- **Spec coverage:** §4.1 (filename read) → Task 1 `classify_recipient`; §4.2 (owner-first / verify-fail→Unknown) → Task 1 + tests; §4.3 (primitive + BlockNotFound, no new variant) → Task 1; §4.4 (DTO, redacting Debug) → Task 2; §4.5 (command) → Task 3; §4.6 (ipc wrapper, pure helpers, banner in RecordList, theme.css) → Tasks 4–7; §7 (all tests) → spread across tasks; §8 invariants → no new variant / no UDL / core untouched, verified in Final gauntlet. No gaps.
- **Type consistency:** `RecipientKind` (bridge) / `RecipientKindDto` (Rust DTO) / `RecipientKind` string union (TS) are distinct by layer and named consistently; `block_recipients` / `block_recipients_impl` / `listBlockRecipients` consistent across tasks; `RecipientDto` field names (`uuidHex`, `kind`, `displayName`) match between Rust serde output and the TS interface.
- **No placeholders:** every code step carries full code; commands carry expected output.
