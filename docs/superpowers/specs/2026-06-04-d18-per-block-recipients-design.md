# D.1.8 — Per-block recipients ("Shared with")

**Date:** 2026-06-04
**Sub-project:** D (desktop UI), eighth feature slice — built on D.1.1–D.1.7.
**Status:** design approved; ready for implementation plan.

## 1. Problem

After D.1.6 (share a block) and D.1.7 (contacts management: import / export-my-card /
delete-contact), a user can share a block with a contact and see, per contact, *how many*
blocks that contact receives (`shared_block_count`). The inverse direction is missing: given
a **block**, the user cannot see **who it is currently shared with**.

D.1.7 also deliberately allows deleting a contact's card while that contact still receives
blocks (delete ≠ revoke — the former recipient still holds the content key for blocks already
shared). This leaves a block's `recipients[]` carrying a uuid with **no resolvable card on
disk**. There is currently no surface that makes this residual-keyholder state visible.

## 2. Goal

Show, in the desktop UI, the recipient list of a block: who currently holds keys to it. Resolve
each recipient uuid to a human label, label the owner as "You", and render any uuid that no
longer resolves to a card as an explicit "Unknown contact" so the delete ≠ revoke consequence
is visible and honest.

## 3. Scope

**In scope**
- A bridge primitive that projects a block's `recipients[]` into classified, name-resolved
  recipient summaries.
- A read-only IPC command + frontend wrapper.
- A collapsible "Shared with" banner at the top of the records view for a block.

**Out of scope (deferred)**
- **Revoke / unshare** — blocked on [#177](https://github.com/hherb/secretary/issues/177)
  (a frozen-`core` revoke primitive that does not exist). This slice only *displays*
  recipients; it never mutates a recipient set.
- Exposing the contacts/recipients functions via uniffi (Swift/Kotlin) or pyo3 — tracked by
  [#167](https://github.com/hherb/secretary/issues/167); wire when a mobile / Python consumer
  needs them. This slice is desktop-only via the bridge crate directly.
- Per-recipient "shared since" timestamps or share history (the manifest carries no such data).

## 4. Architecture (bridge-thick; `core/` frozen and untouched)

Held from D.1.6 / D.1.7: **all `contacts/` I/O stays in the bridge**; the desktop never learns
the on-disk vault layout. `core/src/` is untouched (0 lines).

### 4.1 Name resolution: per-recipient filename read (chosen approach)

For each uuid in `block.recipients[]`, read `contacts/<hyphenated-uuid>.card` directly and run
`verify_self()` (both Ed25519 ∧ ML-DSA-65 halves) before trusting its `display_name`. This
mirrors `share.rs::load_card_bytes` and reuses `contacts/mod.rs::read_verified_card`. It reads
exactly the cards a block references — O(recipients) targeted reads, no full-directory scan.

Rejected alternatives:
- *Full-directory scan → uuid→name map* — reads cards the block doesn't reference.
- *Invert `enumerate_contact_cards` output* — wrong direction; recomputes `shared_block_count`
  for nothing.

### 4.2 Classification

Each recipient uuid is classified into exactly one kind:

| Kind | Condition | Client label |
|---|---|---|
| `Owner` | `uuid == owner_uuid` (checked **first**) | `You` |
| `Contact` | card resolves AND `verify_self()` passes | `display_name` |
| `Unknown` | card missing, unreadable, or fails verification | `Unknown contact (<8-hex prefix>…)` |

The owner check is first because the owner self-card also lives in `contacts/` (share loads it
from there) and would otherwise resolve to a `Contact` with the owner's name. Verification
failure folds into `Unknown` deliberately: an unverified card's `display_name` cannot be
trusted, so we surface the uuid rather than a possibly-forged name. There is no separate
"untrusted" state — the user-facing distinction is only "named contact" vs "can't name".

### 4.3 Bridge primitive

New file `ffi/secretary-ffi-bridge/src/contacts/recipients.rs` (one concept per file):

```rust
/// Public, secret-free projection of one block recipient.
#[derive(Debug)]
pub struct RecipientSummary {
    pub recipient_uuid: [u8; 16],
    pub kind: RecipientKind,
}

#[derive(Debug)]
pub enum RecipientKind {
    Owner,
    Contact { display_name: String },
    Unknown,
}

/// Project a block's `recipients[]` into classified, name-resolved summaries,
/// in manifest recipient order (the client re-sorts). No decryption, no write.
pub fn block_recipients(
    manifest: &OpenVaultManifest,
    block_uuid: [u8; 16],
) -> Result<Vec<RecipientSummary>, FfiVaultError>;
```

- `BlockNotFound { uuid_hex }` if the block is absent from the manifest.
- `handle_wiped()` → `CorruptVault` if the manifest handle was wiped (zeroized on lock).
- Returns summaries in `entry.recipients` order; the client owns presentation ordering.
- **No new `FfiVaultError` variant** — reuses `BlockNotFound` + `CorruptVault`, so there is no
  workspace-wide exhaustive-match obligation (unlike D.1.7's `CannotDeleteOwnerContact`).

Wire `pub use recipients::block_recipients;` into `contacts/mod.rs`.

### 4.4 Seam DTO

New file `desktop/src-tauri/src/dtos/recipient.rs`:

```rust
#[serde(rename_all = "camelCase")]
pub struct RecipientDto {
    pub uuid_hex: String,
    pub kind: RecipientKindDto,   // "owner" | "contact" | "unknown" (serde tag)
    pub display_name: Option<String>, // Some(name) only for Contact
}
```

- Only public material crosses the seam: uuid (public), kind, and the public `display_name`.
  Never card bytes or keys.
- Hand-written `Debug` redacts `display_name` (mirrors `ContactSummaryDto`'s redacting `Debug`).

### 4.5 IPC command

Add to `desktop/src-tauri/src/commands/contacts.rs` (180 lines; room for one more command),
registered in `commands/mod.rs`:

```rust
#[tauri::command]
pub fn block_recipients(state, block_uuid_hex: String) -> Result<Vec<RecipientDto>, AppError>;
```

Read-only; takes the session lock to access the manifest, maps `FfiVaultError → AppError` via
the existing `map_ffi_error`. No new error code needed (`BlockNotFound` already maps).

### 4.6 Frontend

- `desktop/src/lib/ipc.ts`: `RecipientDto` type + `listBlockRecipients(blockUuidHex)` wrapper.
- New pure-function lib module `desktop/src/lib/recipients.ts` (testable in isolation):
  - `sortRecipients(rs: RecipientDto[]): RecipientDto[]` — **owner first → contacts sorted by
    `displayName` (locale-aware) → unknowns last**.
  - `recipientLabel(r: RecipientDto): string` — `You` / `displayName` /
    `Unknown contact (<first 8 hex of uuidHex>…)`.
- New component `desktop/src/components/BlockRecipients.svelte`:
  - Collapsible banner: collapsed shows a one-line summary
    (`Shared with: You, Alice, +1 unknown ▾`); expanded lists each recipient via
    `recipientLabel`.
  - Self-contained `load()` / `loadSeq` generation guard keyed by `block.blockUuidHex`
    (mirrors `RecordList.svelte`'s own pattern), with loading / error / empty states.
  - Mounted at the top of `RecordList.svelte`'s header (after the back button), keeping
    RecordList focused and under the 500-line guideline.
- Styles for `.block-recipients*` go in `theme.css` (carry-forward #153: Vite 6
  `preprocessCSS` blocked).

## 5. Data flow

```
RecordList (block) ──mounts──▶ BlockRecipients(block.blockUuidHex)
                                   │ listBlockRecipients(blockUuidHex)
                                   ▼
                        commands::block_recipients
                                   │ session lock → bridge::block_recipients(manifest, uuid)
                                   ▼
              manifest_body().blocks[uuid].recipients[]  (in-memory)
                  per uuid → contacts/<hyphenated>.card → verify_self()
                                   │ classify Owner / Contact / Unknown
                                   ▼  Vec<RecipientSummary> → Vec<RecipientDto>
                        sortRecipients → recipientLabel → banner
```

No decryption, no write, no `core/` call beyond the read-only manifest accessors + card verify.

## 6. Error handling

| Condition | Bridge | Client |
|---|---|---|
| Block absent | `BlockNotFound` | error banner via `userMessageFor` |
| Handle wiped (locked) | `CorruptVault` | error banner |
| Recipient card missing / unreadable / unverifiable | classified `Unknown` (not an error) | `Unknown contact (…)` row |
| `contacts/` dir absent but block has non-owner recipients | each non-owner → `Unknown` | unknown rows |

A single unresolvable recipient never fails the whole call — it degrades to an `Unknown` row.

## 7. Testing (TDD)

**Bridge (`recipients.rs` unit / bridge integration):**
- owner uuid classified `Owner` even though an owner self-card exists in `contacts/`.
- a shared peer with a valid card → `Contact { display_name }`.
- a recipient uuid with no card file → `Unknown` (delete ≠ revoke residual keyholder).
- a recipient whose card fails `verify_self()` (tampered) → `Unknown`, NOT the forged name.
- absent block → `BlockNotFound`.
- recipient order preserved as manifest order (client sorts).

**Frontend (vitest):**
- `sortRecipients`: owner first; contacts alpha; unknowns last; stable within group.
- `recipientLabel`: `You` for owner; name for contact; `Unknown contact (8hex…)` truncation.
- `BlockRecipients`: loading → list; empty (owner-only) collapsed summary; error banner;
  collapse/expand toggle.

## 8. Invariants preserved
- **Bridge-thick**: desktop never learns the `contacts/` layout.
- **`core/` frozen**: 0 lines under `core/src/`.
- **Seam discipline**: only uuid + kind + public name cross; DTO `Debug` redacts the name.
- **Both-halves verify** gate reused for every card read before its name is trusted.
- **Read-only**: no mutation of any recipient set (revoke stays deferred to #177).
- **No new capability grant; no new error variant; no UDL / Swift / Kotlin / pyo3 change.**

## 9. Acceptance criteria
- A bridge primitive projecting a block's recipient uuids → resolved summaries
  (owner = "You", peers by name, orphans as Unknown), with the tests in §7 green.
- A read-only IPC command + ipc wrapper.
- A "Shared with" banner reachable from a block's records view, listing recipients.
- Full automated gauntlet green (Rust / clippy / fmt / conformance / spec-freshness / Swift /
  Kotlin / Vitest / typecheck / svelte-check / lint).
- Manual GUI smoke: open a block shared with ≥1 contact → banner lists "You" + each contact;
  delete one of those contacts (D.1.7) → reopen the block → that recipient now shows as
  "Unknown contact (…)".
