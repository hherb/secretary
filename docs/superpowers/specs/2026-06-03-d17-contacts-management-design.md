# D.1.7 — Contacts management: export-my-card + a contacts pane (design spec)

**Status:** approved design, pre-plan. Follows D.1.6 (`2026-05-31-d16-share-contacts-design.md`), which shipped the first multi-party flow — import a peer's card + share a block. D.1.6 deliberately confined contacts to "import + pick + share" inside the ShareDialog; D.1.7 fills out the contacts surface: hand your own card to a peer (**export-my-card**) and a standalone **Contacts pane** to view and remove imported contacts.

This spec mirrors the D.1.1–D.1.6 section structure so the seven read as a series. Where a prior section has no D.1.7 analogue it is omitted rather than padded.

## 1. What this slice ships

D.1.6 made sharing demonstrable but one-directional and dialog-bound: you could import a peer's card and share to them, but you had no way to give a peer *your* card (other than digging the file out of the vault folder by hand), and no place to see or manage the contacts you'd imported. D.1.7 adds two user-visible capabilities:

- **Export my card** — write the vault owner's own public contact card (`contacts/<owner>.card`) to an external folder the user chooses, so a peer can import *you*. This closes the share loop: D.1.6 import + D.1.7 export means two vaults can exchange cards without manual file-spelunking.
- **Contacts pane** — a standalone Vault entry (**👤 Contacts**, mirroring D.1.5's 🗑 Trash entry) that lists every imported contact by display name, shows **how many of the owner's blocks each contact receives**, and offers **Delete** per contact. Delete is **warn-but-allow**: removing a contact who still receives blocks is permitted, but the UI warns first (see §3) because share re-keying re-reads every recipient's card.

The non-obvious core is again **not** new cryptography — the owner card already exists in the open manifest and `ContactCard::to_canonical_cbor` already serializes it; `contacts/` enumeration already exists from D.1.6. The work is (a) two small bridge primitives (export-bytes, delete-file) plus a widening of the existing enumerate to report per-contact recipient usage, and (b) wiring them through IPC → a new pane with the same secret-handling discipline (only `{ uuidHex, displayName, sharedBlockCount }` crosses the seam; the owner card is public; the bridge owns all `contacts/` I/O).

Out of scope (see §13): **revoke / unshare** (needs a core primitive that does not exist — §3); editing a contact's display name; per-block recipient lists in the pane; multi-select delete; any change to `core`.

## 2. Why this ordering (management after share)

Sharing had to exist before managing contacts was worth building — there was nothing to manage until import populated `contacts/`. Export-my-card is the smallest, highest-value next step: it is the symmetric counterpart to D.1.6 import and the only missing half of a peer-to-peer card exchange. The contacts pane is the natural home for the management verbs that D.1.6 deferred out of the ShareDialog (YAGNI then; needed now that more than one contact can accumulate). **Revoke** — the obvious third verb — is deliberately *not* in this slice because it requires a frozen-`core` change (§3, §13); pulling it forward would block a UI slice on a cryptographic-core decision.

## 3. Architecture approach

Core is **frozen and unchanged**. Every primitive D.1.7 needs already exists in core, or is a thin file/serialize operation in the bridge:

- **Owner card access + serialization:** the open manifest already holds the owner's `ContactCard` (`OpenVaultManifest::owner_card()`); `ContactCard::to_canonical_cbor()` produces the canonical bytes (`core/src/identity/card.rs`). The owner card is **public key material** (it is *meant* to be handed out) — no secret handling, no zeroize concern. The canonical file name a peer's import expects is `<format_uuid_hyphenated(owner_uuid)>.card` (the same convention D.1.6 import re-derives from the card's own uuid).
- **Contacts enumeration:** `enumerate_contact_cards` (D.1.6) already parses + `verify_self()`-checks every `contacts/*.card`, omits the owner, and counts unreadable files (`ffi/secretary-ffi-bridge/src/contacts/enumerate.rs`).
- **Recipient membership** (for the delete warning) is **already in memory**: `manifest.manifest_body().blocks[].recipients` lists each block's recipient UUID set. Counting how many blocks a contact receives is an in-memory scan — **no decryption, no I/O**.

**Why revoke is deferred (not a choice — a constraint):** core exposes `share_block` (append a recipient) but **no** `revoke_block_recipient` / `unshare` primitive — sharing is append-only in v1, and `core` is frozen for v1 (vaults written today must stay readable for decades). Removing a recipient would require a new core orchestrator (re-key the block, drop one recipient from the wire recipient table + manifest `BlockEntry.recipients`, re-sign, atomic write) — a Sub-project A / B-phase change with its own spec, KAT, and conformance impact. D.1.7 files this as a **core prerequisite issue** and scopes itself to add-only management (export + view + delete-contact-card). Note the important distinction: **deleting a contact's card does NOT revoke their access** to blocks already shared with them — they still hold the content keys from the prior `share_block`. Delete only removes the card from `contacts/` (and thus from the picker and from future re-key assembly). The pane states this.

**Architecture decision — bridge owns all `contacts/` I/O (bridge-thick), consistent with D.1.5/D.1.6.** Three sub-decisions:

| Decision | Choice | Rationale |
|---|---|---|
| Export destination mechanism | **Reuse the granted folder picker; bridge yields bytes, desktop writes to the external folder** | The existing PathPicker folder mode + the already-granted `dialog:allow-open` capability pick a destination *folder*; the bridge returns `(file_name, bytes)` and the desktop writes `dest/<file_name>` (native Rust `fs::write`, no JS fs capability, no new `dialog:allow-save` grant). Symmetric with D.1.6 import ("desktop handles the external path, bridge handles bytes"). A fixed `<uuid>.card` name is exactly what import re-derives anyway, so a save-as dialog (the rejected alternative) would add a capability for no functional gain. |
| Delete-contact semantics | **Warn-but-allow; the warning is a UI gate fed by enumerate's `shared_block_count`** | Share re-keying (`share_block_to`) re-reads **every** existing recipient card from `contacts/` to re-wrap the rotated key; deleting a contact who is an active recipient therefore breaks any *future* re-share of that block (`ContactNotFound`). Rather than silently footgun (unconditional delete) or hard-block legitimate cleanup (gated delete, with no escape hatch until revoke exists), the pane shows the recipient count inline and a confirm dialog warns when count > 0. The **bridge** primitive does not enforce usage — it only removes the file — keeping it simple and idempotent; the warning lives where the user decides. |
| Owner-card delete guard | **Bridge refuses to delete the owner's own self-card (typed `CannotDeleteOwnerContact`)** | Enumerate already omits the owner, so the pane never lists it — but the delete primitive takes a raw uuid, and actually removing `contacts/<owner>.card` would corrupt the vault's self-card. Defense in depth: a dedicated typed refusal, not reliance on UI omission. |
| Usage count home | **Widen the existing `enumerate_contact_cards` (one contacts-listing path)** | `ContactSummary`/`ContactSummaryDto` gain `shared_block_count`; the share picker (ShareDialog) simply ignores it. The scan is in-memory and cheap; a second "managed list" command would duplicate the listing path for no benefit. |

## 4. Project layout (additions)

```
ffi/secretary-ffi-bridge/src/
  contacts/
    mod.rs               MODIFIED — ContactSummary gains shared_block_count: u32
    enumerate.rs         MODIFIED — count manifest_body().blocks[].recipients per contact
    export.rs            NEW — owner_card_export(manifest) -> (file_name, bytes)
    delete.rs            NEW — delete_contact_card(manifest, contact_uuid)
  error/vault/mod.rs     MODIFIED — add CannotDeleteOwnerContact (no fields)
  lib.rs                 MODIFIED — re-export owner_card_export / delete_contact_card
  # NOTE: the contacts FUNCTIONS remain unmirrored on uniffi/pyo3 (#167);
  # the new ERROR variant IS threaded through both bindings + the KAT helper
  # (the shared FfiVaultError enum is exhaustively matched there — D.1.6 lesson).
ffi/secretary-ffi-uniffi/  MODIFIED — exhaustive FfiVaultError match gains CannotDeleteOwnerContact
ffi/secretary-ffi-py/      MODIFIED — same exhaustive match
core/tests/ (KAT helper)   MODIFIED — same exhaustive match (no vector/wire change)
desktop/src-tauri/src/
  commands/
    contacts.rs          MODIFIED — add export_contact_card / delete_contact_card (+ *_impl)
    mod.rs / main.rs     MODIFIED — register the two new commands
  dtos/
    contact.rs           MODIFIED — ContactSummaryDto gains sharedBlockCount; NEW ExportedCardDto { path }
  errors.rs              MODIFIED — AppError::CannotDeleteOwnerContact + map_ffi_error routing
desktop/src/
  lib/
    contacts.ts          MODIFIED — ContactSummaryDto type gains sharedBlockCount (sort unchanged)
    ipc.ts               MODIFIED — exportContactCard(destDir) / deleteContactCard(uuidHex)
                                    + ExportedCardDto type + one error code
    browse.ts            MODIFIED — BrowseNav gains { level: 'contacts' }; openContacts()
  components/
    ContactsPane.svelte  NEW — "Export my card" affordance + contact list
    ContactRow.svelte    NEW — one contact (name + "receives N blocks") + Delete
    Vault.svelte         MODIFIED — 👤 Contacts entry + pane hosting (mirrors the 🗑 Trash entry)
    (ConfirmDialog.svelte — REUSED from D.1.5 for the delete-warn confirm)
  theme.css              MODIFIED — .contacts-pane* / .contact-row* (per the #153 carry-forward)
```

## 5. Bridge surface (signatures + semantics)

```rust
/// Light, secret-free projection of one contact card — the only contact data
/// that crosses the IPC seam. D.1.7 adds `shared_block_count`.
pub struct ContactSummary {
    pub contact_uuid: [u8; 16],
    pub display_name: String,
    /// How many of the owner's blocks list this contact as a recipient
    /// (in-memory scan of manifest_body().blocks[].recipients; no decryption).
    pub shared_block_count: u32,
}

/// Enumerate every OTHER party's verified contact card (D.1.6 semantics:
/// from_canonical_cbor THEN verify_self; omit owner; count unreadable),
/// now also populating `shared_block_count` for each returned summary.
pub fn enumerate_contact_cards(
    manifest: &OpenVaultManifest,
) -> Result<(Vec<ContactSummary>, usize), FfiVaultError>;   // MODIFIED

/// Serialize the vault owner's own PUBLIC contact card for export. Returns the
/// canonical file name (`<hyphenated-owner-uuid>.card` — the name a peer's
/// import re-derives) and the canonical-CBOR bytes. No secret material.
///   - manifest wiped / owner card absent → CorruptVault (via handle_wiped)
///   - to_canonical_cbor failure (should not occur for a valid card) → CorruptVault
pub fn owner_card_export(
    manifest: &OpenVaultManifest,
) -> Result<(String, Vec<u8>), FfiVaultError>;   // NEW

/// Remove one contact's card from `contacts/`.
///   1. contact_uuid == owner uuid → CannotDeleteOwnerContact (never removes
///      the vault's own self-card).
///   2. `contacts/<format_uuid_hyphenated(uuid)>.card` absent → ContactNotFound.
///   3. Otherwise remove the file.
/// Does NOT check recipient membership — the "still receives N blocks" warning
/// is a UI gate fed by enumerate's `shared_block_count` (warn-but-allow, §3).
/// NB: this does NOT revoke access to blocks already shared with the contact.
pub fn delete_contact_card(
    manifest: &OpenVaultManifest,
    contact_uuid: [u8; 16],
) -> Result<(), FfiVaultError>;   // NEW
```

One new `FfiVaultError` variant — `CannotDeleteOwnerContact` (no fields) — joins the enum. Per the FfiVaultError-is-workspace-wide-exhaustive-match discipline, it is threaded through the uniffi + pyo3 bindings and the core KAT helper in the **same** task that adds it, and verified with a **`--workspace`** clippy run (not `-p`), per the D.1.6 lesson that per-crate builds masked exactly this kind of break. No `_ =>` catchall (issue #40 discipline).

## 6. Desktop surface (IPC + DTOs + error mapping)

Two new commands in `commands/contacts.rs`, each a thin shell over a testable `*_impl` (the established `parse_uuid_16` → `lock_session` → `with_unlocked` shape):

| Command | Args (camelCase) | Returns | Notes |
|---|---|---|---|
| `export_contact_card` | `destDir: string` | `ExportedCardDto { path }` | bridge `owner_card_export` → write `destDir/<file_name>` (native Rust); returns the written path for the success toast. Overwrite of a prior same-name export is allowed (idempotent self-card). |
| `delete_contact_card` | `contactUuidHex: string` | `()` | bridge `delete_contact_card`. |

`list_contacts` (D.1.6) is unchanged in shape but now returns `ContactSummaryDto` with a `sharedBlockCount` field. `ContactSummaryDto`'s **redacting `Debug`** is preserved (display name still not logged; the count is non-sensitive). `ExportedCardDto { path }` carries the external path the user already chose — non-sensitive — and is **not** redacted. New typed `AppError::CannotDeleteOwnerContact` is added with a serde round-trip test (errors.rs pattern); `map_ffi_error` routes the corresponding `FfiVaultError` variant to it instead of the `Internal` fold.

## 7. Frontend surface

- `lib/contacts.ts` — `sortContacts` unchanged (still case-insensitive by `displayName`); the `ContactSummaryDto` type gains `sharedBlockCount: number`. No new I/O.
- `ipc.ts` — `exportContactCard(destDir)`, `deleteContactCard(contactUuidHex)`; `ExportedCardDto` type; the `CannotDeleteOwnerContact` error code added to the discriminated error union.
- `browse.ts` — `BrowseNav` gains `{ level: 'contacts' }`; `openContacts()` setter (mirrors `openTrash()`).
- `ContactsPane.svelte` — opened from a Vault **👤 Contacts** entry:
  - On open, `listContacts()`; render the sorted list. If `unreadableCount > 0`, show the existing warning line.
  - Top affordance **Export my card** → PathPicker (folder mode) → `exportContactCard(destDir)` → success toast naming the written path.
  - Each `ContactRow` shows the display name and **"receives N blocks"** (N = `sharedBlockCount`); a **Delete** action. If `N > 0`, Delete opens the reused `ConfirmDialog` warning *"<name> receives N of your blocks. Deleting their card won't revoke access they already have, but you won't be able to re-share those blocks to anyone. Delete anyway?"*; if `N == 0`, a lighter confirm. On confirm → `deleteContactCard` → refresh the list. `CannotDeleteOwnerContact` (defense-in-depth; not reachable via UI) renders as a friendly inline message.
- Reuses the dialog / PathPicker / ConfirmDialog / theme.css patterns from D.1.3–D.1.6; the **👤** glyph joins the inline-SVG carry-forward (#154); styles go in `theme.css` (#153).

## 8. Data flow (export + delete, end to end)

```
Vault "👤 Contacts" → openContacts()
  → ContactsPane → listContacts() ──IPC──▶ list_contacts_impl
                                            → bridge enumerate_contact_cards (+ shared_block_count)
                                            ◀── [{uuidHex, displayName, sharedBlockCount}], unreadableCount

Export my card → PathPicker(folder) → destDir
  → exportContactCard(destDir) ──IPC──▶ export_contact_card_impl
                                            → bridge owner_card_export → (file_name, bytes)
                                            → fs::write(destDir/file_name, bytes)
                                            ◀── { path }              → success toast

Delete (row, N>0) → ConfirmDialog warn → confirm
  → deleteContactCard(uuidHex) ──IPC──▶ delete_contact_card_impl
                                            → bridge delete_contact_card
                                                (owner-guard → exists? → remove file)
                                            ◀── Ok | CannotDeleteOwnerContact | ContactNotFound
  → refresh list
```

## 9. Behavioral invariants (what the tests pin)

1. **Owner card export is public + byte-faithful** — `owner_card_export` returns bytes that `ContactCard::from_canonical_cbor` + `verify_self()` round-trip back to the owner's card; no secret/private-key bytes appear in the output.
2. **Export file name = the import convention** — `file_name == "<format_uuid_hyphenated(owner_uuid)>.card"`, so a peer dropping it into their `contacts/` and importing succeeds (cross-checked by a bridge-level import-of-exported-bytes test).
3. **`shared_block_count` is exact** — a contact who is a recipient of K of the owner's blocks reports `shared_block_count == K`; a contact who receives none reports 0 (built by sharing the same peer into K blocks at runtime).
4. **Delete removes exactly the one card** — `delete_contact_card` removes `contacts/<uuid>.card` and nothing else; enumerate afterward omits it; a second delete of the same uuid → `ContactNotFound`.
5. **Owner self-card is undeletable** — `delete_contact_card(owner_uuid)` → `CannotDeleteOwnerContact`, and `contacts/<owner>.card` still exists on disk afterward.
6. **Delete does not revoke** — after deleting a contact who received a block, the prior recipient can STILL decrypt that block (the card removal is local; access is not rekeyed). This is asserted to document the boundary, not as a defect.
7. **No new secret residence** — export handles only public card bytes; delete is a file unlink; neither introduces a `Sensitive` local or widens a secret lifetime.

## 10. Testing (TDD; ephemeral tempdir vaults; runtime-random crypto)

Per [[feedback_test_crypto_random_not_hardcoded]] all keys/cards are generated at test runtime; per [[feedback_smoke_test_temp_copy_golden_vault]] no test mutates a tracked fixture.

- **Bridge (`contacts/`):**
  - `owner_card_export` — returns the canonical name + bytes; the bytes import cleanly into a *second* runtime vault (round-trip through `import_contact_card`); no private-key material present.
  - `enumerate` widening — owner-only vault → empty; a peer shared into K blocks → that summary's `shared_block_count == K`; an unshared imported peer → 0; `unreadableCount` behavior from D.1.6 still holds.
  - `delete_contact_card` — happy path removes the file + enumerate omits it; owner uuid → `CannotDeleteOwnerContact` (file still present); unknown uuid → `ContactNotFound`; deleting a recipient leaves the block decryptable by the (now card-less) peer in a bridge decrypt-as-peer check.
- **Desktop L3:** `export_contact_card_impl` writes to a tempdir and the file imports back; `delete_contact_card_impl` over a real `VaultSession` (happy + owner-guard + not-found); serde round-trip for the new `AppError` variant.
- **Frontend Vitest:** `contacts` lib (sort stable with the new field); the two new ipc wrappers (mock `invoke`, incl. error-code mapping); `ContactsPane` (list render with counts; export wiring calls `exportContactCard` with the picked dir; delete with N>0 routes through `ConfirmDialog` warn then `deleteContactCard`; delete with N==0 lighter confirm; `unreadableCount` warning line); `ContactRow` ("receives N blocks" label); `Vault` 👤 entry opens the pane.
- **Full gauntlet green:** Rust `cargo test` / **`--workspace`** clippy / fmt; `conformance.py`; `spec_test_name_freshness.py`; Swift + Kotlin conformance (the UDL gains one error case; vectors unchanged); Vitest; typecheck; svelte-check (no new warnings); lint.

## 11. Security considerations

- **Export is public by construction** — the owner contact card contains only public keys + display name + uuid; it is the artifact the protocol is *designed* to distribute. The test pins the absence of any private-key bytes in the exported output so a future card-shape change can't silently leak secret material through this path.
- **Delete ≠ revoke, stated in the UI and pinned by a test** — removing a card does not rescind a recipient's existing access; conflating the two would be a dangerous false sense of security. The pane copy and invariant #6 make the boundary explicit.
- **Owner self-card protected** — the bridge refuses owner deletion typed, not by UI omission alone (invariant #5).
- **Seam discipline preserved** — only `{ uuidHex, displayName, sharedBlockCount }` and a user-chosen export `path` cross IPC; card bytes and public keys stay in the bridge; `ContactSummaryDto`'s redacting `Debug` is retained.
- **No new capability grant** — export reuses the already-granted `dialog:allow-open` folder picker; no `dialog:allow-save`, no JS fs capability (the Rust command does the write).

## 12. Conformance / KAT impact

**None to the wire format or vectors.** D.1.7 introduces no new on-disk format and no merge-semantics change — it serializes the existing `ContactCard` and unlinks a file. `conformance.py`, `conflict_kat.json`, and `conformance_kat.json` are unchanged. The **one** cross-binding touch is the new `FfiVaultError::CannotDeleteOwnerContact` variant, which appears in the bindings' / KAT helper's exhaustive `match` arms (no new vector — just a new arm). `spec_test_name_freshness.py` stays green. (Verified at implementation time, not assumed.)

## 13. Deferred / out of scope

- **Revoke / unshare** — removing a recipient from a block. **Blocked on a new `core` primitive** (`share_block` is append-only; core is frozen) → filed as **#177** (core/B-phase prerequisite). A D-phase UI cannot deliver real revoke until core does. (Deleting a contact's card is *not* revoke; §3.)
- **Edit a contact** (rename display name), **per-block recipient lists in the pane**, **multi-select delete**, **re-export/share from the pane** — YAGNI for this slice.
- **uniffi / pyo3 mirroring of the contacts FUNCTIONS** — still deferred under #167 (no mobile/Python consumer); only the shared error *enum* is threaded.
- **Carry-forwards (all still live):** #153 (component styles in `theme.css`), #154 (emoji → inline SVG — D.1.7 adds 👤), #161 (L4 e2e harness), #162 (PathPicker e2e hook), #164 (Esc-to-pop), #167 (deferred-FFI function mirroring), #170 (`lock_session` hoist into `commands::shared` — `commands/contacts.rs` already carries a copy).

## 14. Acceptance criteria

- A user with an unlocked vault can: open **👤 Contacts** → see imported contacts each labeled with how many blocks they receive → **Export my card** to a chosen folder (the written file imports cleanly into a second vault) → **Delete** a contact (with a warning when that contact still receives blocks) → the contact disappears from the list and the picker.
- Deleting the owner's own card is impossible (typed refusal); deleting an unknown uuid is a typed not-found.
- Only `{ uuidHex, displayName, sharedBlockCount }` + the export path appear in IPC payloads; no card bytes / public keys.
- Full automated gauntlet green (incl. `--workspace` clippy); `core/` untouched; no conformance-vector change; the new error variant threaded through both bindings.
- Manual GUI smoke (§15) passes against a **temp copy** of a vault.

## 15. Manual GUI smoke (the pre-merge gate; headless-impossible)

> ⚠️ Smoke against TEMP vault copies, never a git-tracked fixture (D.1.7 writes an exported `.card` and unlinks `contacts/` entries). See [[feedback_smoke_test_temp_copy_golden_vault]].

Two identities help. In **vault A** (unlocked): open **👤 Contacts** → **Export my card** → pick a temp folder → confirm a `<uuid>.card` was written there. Then with at least one imported contact (import via the D.1.6 ShareDialog if needed): the pane lists it with "receives N blocks"; share it into a block, reopen Contacts → its count increments. **Delete** that contact → because N > 0, the warn dialog appears → confirm → it leaves the list. Re-open the vault → the deletion persisted; the previously-shared block is still present for the owner. (Optionally import vault A's exported card into **vault B** to confirm the round-trip.) If any step fails it is a D.1.7 regression; do not merge until fixed.

---

*Design approved via brainstorming on 2026-06-03. Next: `superpowers:writing-plans` → `docs/superpowers/plans/2026-06-03-d17-contacts-management.md`.*
