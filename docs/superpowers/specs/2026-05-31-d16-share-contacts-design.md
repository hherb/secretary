# D.1.6 — Share a block + desktop contacts subsystem (design spec)

**Status:** approved design, pre-plan. Follows D.1.5 (`2026-05-30-d15-delete-trash-design.md`), which shipped record delete/resurrect + block trash/restore. D.1.6 is the next slice in Sub-project D's feature breadth (browse → create → edit → delete/trash → **share**; see ADR 0007). It is the **first multi-party flow**: it lets the vault owner add a second recipient to a block they authored, which requires a desktop **contacts subsystem** that does not exist yet.

This spec mirrors the D.1.1–D.1.5 section structure so the six read as a series. Where a prior section has no D.1.6 analogue it is omitted rather than padded.

## 1. What this slice ships

D.1.5 completed the single-owner CRUD loop (create → read → update → delete). D.1.6 opens the vault to a **second party**: the owner can **share a block** they authored with a **contact**, after **importing** that contact's card. Three user-visible capabilities:

- **Import a contact** — pick a peer's `.card` file; it is validated (self-signature, both halves) and copied into the vault's `contacts/` directory. Trust-on-first-import (TOFU); a second card claiming an already-known `contact_uuid` is **rejected**, never silently overwritten.
- **Pick a contact** — a share dialog lists the vault's imported contacts by display name (excluding the owner's own card); when the list is empty it prominently offers **Import a contact…**.
- **Share a block** — select a contact → the chosen block is re-keyed and the contact is appended to its recipient set (`core::share_block`). The block stays in the owner's list; the recipient can now decrypt it.

The non-obvious core of this slice is **not** new cryptography — core already implements `share_block` and the `ContactCard` lifecycle, and the bridge already wraps `share_block`. The work is (a) a small **contacts I/O surface in the bridge** (enumerate / import / assemble-and-share), and (b) wiring it through **IPC → UI** with the same secret-handling discipline D.1.5 established (card bytes + public keys never cross the IPC seam; opaque DTOs; typed errors).

Out of scope (see §13): **export-my-card**; a standalone contacts-management pane (view/delete/re-share/list-recipients); multi-recipient share in one action; revoke/unshare; any change to `core`.

## 2. Why this ordering (share after delete)

The everyday single-owner loop (create/read/update/delete) had to exist before a multi-party flow was worth building — there is nothing to share until you can create and edit blocks, and nothing to recover from a mis-share until you can delete. Sharing is also the **first slice that needs a new subsystem rather than just wiring an existing core primitive**: every prior D.1.x slice consumed core primitives that operate on the owner's own data, but `share_block` needs *other people's* contact cards present in the vault, and nothing in the desktop puts them there. D.1.6 therefore builds the minimum contacts surface (import + enumerate) and then wires share on top — the smallest increment that makes sharing demonstrable end-to-end.

## 3. Architecture approach

Core is **frozen and unchanged**. Every primitive D.1.6 needs already exists in core:

- Contact card lifecycle: `core::identity::card::ContactCard` with `from_canonical_cbor` (parse + reject non-canonical input — **parses only, does NOT verify the self-signature**), the **separate** `verify_self()` (returns `Ok(())` only if **both** Ed25519 ∧ ML-DSA-65 self-signatures verify against the card's embedded public keys), `to_canonical_cbor`, `contact_uuid` (16-byte identity), `display_name` — `core/src/identity/card.rs`. The filename convention is `contacts/<format_uuid_hyphenated(contact_uuid)>.card` (lowercase 8-4-4-4-12 hyphenated; `format_uuid_hyphenated` is re-exported at `secretary_core::vault::format_uuid_hyphenated`). `core::vault::restore_block` already establishes the canonical read pattern: `from_canonical_cbor` **then** `verify_self()`, skipping any card that fails either.
- Share: `core::vault::share_block(folder, &mut OpenVault, block_uuid, author_card, author_sk_ed, author_sk_pq, existing_recipient_cards, new_recipient, device_uuid, now_ms, &mut rng)` — rotates the block content key, re-encrypts the body, appends the new recipient to the wire-level recipient table + the manifest `BlockEntry.recipients`, ticks the manifest clock, re-signs, writes atomically (block then manifest), and persists the new recipient card to `contacts/<uuid>.card` — `core/src/vault/orchestrators.rs`. It deliberately **does not read `contacts/` itself**: the caller must supply the author card + **every** existing recipient card + the new recipient card.
- Path convention: `contacts/<contact_uuid_hyphenated>.card` (`CONTACTS_SUBDIR`, `format_uuid_hyphenated`) — `core/src/vault/orchestrators.rs`.

The bridge already wraps `share_block` (`ffi/secretary-ffi-bridge/src/share/orchestration.rs`), taking caller-supplied **CBOR-bytes** cards and the session's `UnlockedIdentity` + `OpenVaultManifest`, and reusing `snapshot_for_save_block()` (which yields the `owner_card` + `vault_folder`) plus the signing-key zeroize/drop machinery. D.1.6's new work sits at the **bridge** layer (Sub-project B, not frozen) and above.

**Architecture decision — bridge owns all `contacts/` I/O (bridge-thick).** Three options were weighed:

| Option | Where contacts I/O + recipient-set assembly live | Verdict |
|---|---|---|
| **Bridge-thick (chosen)** | Bridge gains `enumerate_contact_cards`, `import_contact_card`, and a higher-level `share_block_to(block_uuid, new_recipient_uuid)` that reads the block's recipient UUIDs from the manifest, loads every existing card + the new card from `contacts/`, and calls `core::share_block`. Desktop stays a thin shim. | **Chosen** — keeps vault-layout knowledge (the `contacts/` path, the UUID filename format) inside core/bridge, mirrors D.1.5's `list_trashed_blocks` (which decrypts in the bridge and returns only projections), and keeps the desktop layer free of raw directory reads. |
| Hybrid | Bridge gains enumerate/load/import, but desktop assembles the existing-recipient set (calling a bridge `load_contact_card` per recipient UUID) and calls the existing bridge `share_block` unchanged. | Rejected — more orchestration logic (and the recipient-set invariant) leaks into desktop for no benefit; reuses the existing wrapper but spreads the assembly contract across two layers. |
| Desktop-thick | Bridge exposes only a decode helper; desktop does the directory reads, assembly, validation, and file copy. | Rejected — duplicates the `contacts/` path + UUID-filename conventions outside core and puts vault-layout knowledge in the UI layer. |

| Decision | Choice | Rationale |
|---|---|---|
| Contacts I/O home | **Bridge** (new `contacts/` module) | See table above. Desktop calls through the session, exactly as edit/delete do. |
| Import trust model | **TOFU + dedup-reject** | No PKI exists; import **parses (`from_canonical_cbor`) then cryptographically self-verifies (`verify_self()` — both Ed25519 ∧ ML-DSA-65 halves)** before writing, and the user asserts the binding by importing. A second card for a known `contact_uuid` is **rejected** (typed `ContactAlreadyExists`) rather than overwriting a trusted card — silent overwrite would be a downgrade/substitution vector. |
| Import input | **Desktop reads the external `.card` file bytes; the bridge takes bytes** | Reading a user-chosen file *outside* the vault is a desktop-edge concern (PathPicker yields the path). The bridge deals only in bytes → unit-testable without external-path knowledge, and never learns about the host filesystem layout outside the vault. |
| Share target input | **`new_recipient_uuid` (16 bytes), not card bytes** | The frontend never holds card bytes; it picks a `contactUuidHex`. The bridge loads `contacts/<uuid>.card` itself. |
| What crosses IPC | **Only `{ contactUuidHex, displayName }`** | Card bytes + the four public keys stay server-side, mirroring D.1.5's rule that the server decides what crosses the seam. |
| Malformed `contacts/` entries | **Enumerate returns valid summaries + an `unreadableCount`** | No silent failure: a tampered/corrupt `.card` is surfaced as a count the UI can warn on, not dropped. |
| Picker contents | **All contacts except the owner's own card**; "already a recipient" handled by the typed `RecipientAlreadyPresent` error, not pre-filtered per block | Excluding self is unambiguous and cheap (owner UUID is known). Pre-filtering existing recipients per block would need the block's recipient set in the picker for no security benefit (the owner/author already knows the recipients). |
| Share-button gating | **Always shown; `NotAuthor` surfaces as a typed error** | Defense in depth — the UI does not rely on hiding the action; core/bridge enforce author-only and the desktop routes the typed error. |
| Recipients revoke / re-share / multi-add | **Out of scope** | v1 single-author append-one; revoke is a separate, later concern. |

## 4. Project layout (additions)

```
ffi/secretary-ffi-bridge/src/
  contacts/                NEW dir — contact enumerate/import + share-by-uuid
    mod.rs                   ContactSummary; re-exports
    enumerate.rs             enumerate_contact_cards(manifest) -> (Vec<ContactSummary>, usize)
    import.rs                import_contact_card(manifest, card_bytes) -> ContactSummary
    share.rs                 share_block_to(identity, manifest, block_uuid,
                                             new_recipient_uuid, device_uuid, now_ms)
                             — assembles existing-recipient cards from contacts/,
                               loads the new card, calls the existing share wrapper / core
  error/vault/mod.rs       MODIFIED — add ContactAlreadyExists { uuid_hex },
                                       ContactNotFound { uuid_hex }
  lib.rs                   MODIFIED — re-export the contacts module primitives
  # NOTE: the new primitives are NOT mirrored on uniffi/pyo3 in D.1.6
  # (no mobile/Python consumer yet) — tracked under #167; see §13.
desktop/src-tauri/src/
  commands/
    contacts.rs            NEW — list_contacts / import_contact / share_block (+ *_impl)
    mod.rs                 MODIFIED — register the contacts module
  dtos/
    contact.rs             NEW — ContactSummaryDto (redacting Debug) + ListContactsDto
    mod.rs                 MODIFIED — list the new dtos submodule
  errors.rs               MODIFIED — typed AppError::{NotAuthor, RecipientAlreadyPresent,
                                     MissingRecipientCard, ContactAlreadyExists, ContactNotFound}
                                     + map_ffi_error routing (currently fold to Internal)
  main.rs                 MODIFIED — register the three contacts commands
desktop/src/
  lib/
    contacts.ts            NEW — sortContacts / formatContact (pure)
    ipc.ts                 MODIFIED — listContacts / importContact / shareBlock wrappers
                                     + ContactSummaryDto type + two error codes
  components/
    ShareDialog.svelte     NEW — contact picker + "Import a contact…" + Share action
    BlockCard.svelte       MODIFIED — a "🔗 Share" action that opens ShareDialog
  styles/theme.css         MODIFIED — .share-dialog* rules (per the #153 carry-forward)
```

## 5. Bridge surface (signatures + semantics)

```rust
/// Light, secret-free projection of one contact card — the only contact
/// data that ever crosses the IPC seam.
pub struct ContactSummary {
    pub contact_uuid: [u8; 16],
    pub display_name: String,
}

/// Parse every `contacts/*.card` in the vault folder (`from_canonical_cbor`
/// THEN `verify_self()`, mirroring `restore_block`). Returns the valid,
/// self-verified summaries plus the count of files that failed to parse OR
/// failed self-verification. Malformed/unverifiable entries are counted,
/// never silently dropped (§3).
pub fn enumerate_contact_cards(
    manifest: &OpenVaultManifest,
) -> Result<(Vec<ContactSummary>, usize), FfiVaultError>;

/// TOFU import from raw canonical-CBOR bytes:
///   1. `ContactCard::from_canonical_cbor` (parse + canonical-encoding
///      check) THEN `card.verify_self()` (BOTH Ed25519 ∧ ML-DSA-65 self-
///      signature halves) → on either failure `CardDecodeFailure`.
///   2. If `contacts/<format_uuid_hyphenated(uuid)>.card` already exists →
///      `ContactAlreadyExists`.
///   3. Write `contacts/<format_uuid_hyphenated(uuid)>.card` via
///      `core::vault::io::write_atomic`.
/// Returns the imported card's summary.
pub fn import_contact_card(
    manifest: &OpenVaultManifest,
    card_bytes: &[u8],
) -> Result<ContactSummary, FfiVaultError>;

/// Append one new recipient (by uuid) to a block the owner authored.
///   1. Locate the block's `BlockEntry` in the manifest → recipient UUID set
///      (`BlockNotFound` if absent).
///   2. Load each existing recipient card from `contacts/<uuid>.card`
///      (the owner card is among them for a freshly-saved block) →
///      `ContactNotFound { uuid_hex }` if any referenced card is missing.
///   3. Load the new recipient card from `contacts/<new_recipient_uuid>.card`
///      → `ContactNotFound` if absent.
///   4. Call `core::vault::share_block` (re-key, re-encrypt, append, re-sign,
///      atomic write) via the existing bridge wrapper's snapshot/zeroize path.
/// Surfaces core's `NotAuthor` / `RecipientAlreadyPresent` /
/// `MissingRecipientCard` typed variants unchanged.
pub fn share_block_to(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: [u8; 16],
    new_recipient_uuid: [u8; 16],
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<(), FfiVaultError>;
```

Two new `FfiVaultError` variants — `ContactAlreadyExists { uuid_hex }`, `ContactNotFound { uuid_hex }` — join the existing `NotAuthor` / `RecipientAlreadyPresent` / `MissingRecipientCard` / `CardDecodeFailure`. The share-error mapper (`map_core_vault_error_share`) is unchanged; the new variants are bridge-internal (raised before/around the core call), added to the per-variant `From`/match surfaces with no `_ =>` catchall (per issue #40 discipline).

## 6. Desktop surface (IPC + DTOs + error mapping)

Three commands in `commands/contacts.rs`, each a thin shell over a testable `*_impl` (mirroring `delete.rs`: `parse_uuid_16` → `lock_session` → `with_unlocked`):

| Command | Args (camelCase) | Returns | Notes |
|---|---|---|---|
| `list_contacts` | — | `ListContactsDto { contacts: ContactSummaryDto[], unreadableCount }` | enumerate; sorted client-side. |
| `import_contact` | `cardBytes: number[]` (or base64) | `ContactSummaryDto` | desktop reads the external `.card` file → bytes → bridge. |
| `share_block` | `blockUuidHex`, `newRecipientUuidHex` | `()` | bridge `share_block_to`. |

`ContactSummaryDto { contactUuidHex, displayName }` with a **redacting `Debug`** (display name not logged), mirroring `TrashedBlockDto`. New typed `AppError` variants — `NotAuthor`, `RecipientAlreadyPresent`, `MissingRecipientCard`, `ContactAlreadyExists`, `ContactNotFound` — are added with serde round-trip tests (errors.rs pattern), and `map_ffi_error` routes the corresponding `FfiVaultError` variants to them instead of the current `Internal` fold.

## 7. Frontend surface

- `lib/contacts.ts` — pure helpers: `sortContacts(contacts)` (case-insensitive by `displayName`, stable), `formatContact` (display label). No I/O.
- `ipc.ts` — `listContacts()`, `importContact(cardBytes)`, `shareBlock(blockUuidHex, recipientUuidHex)`; `ContactSummaryDto` type; the two new error codes added to the discriminated error union.
- `ShareDialog.svelte` — opened from `BlockCard`'s **🔗 Share** action for a given block:
  - On open, `listContacts()`; render the picker (sorted, **owner card excluded**). If `unreadableCount > 0`, show a small warning line.
  - **Empty state** (no importable contacts): prominent **Import a contact…** → PathPicker → read file → `importContact` → refresh the list (the imported contact is selectable immediately).
  - Selecting a contact enables **Share** → `shareBlock` → success toast + close. `RecipientAlreadyPresent` / `NotAuthor` / `ContactNotFound` / `ContactAlreadyExists` render as friendly inline messages.
- Reuses the existing dialog/PathPicker/theme.css patterns from D.1.3–D.1.5; the **🔗** glyph joins the inline-SVG carry-forward (#154), its styles go in `theme.css` (#153).

## 8. Data flow (share, end to end)

```
BlockCard "🔗 Share"
  → ShareDialog opens → listContacts() ──IPC──▶ list_contacts_impl
                                                  → bridge enumerate_contact_cards
                                                  ◀── [{uuidHex, displayName}], unreadableCount
  → (empty) "Import a contact…" → PathPicker → read <peer>.card bytes
                                → importContact(bytes) ──IPC──▶ import_contact_impl
                                                  → bridge import_contact_card
                                                      (validate self-sig → dedup → write contacts/<uuid>.card)
                                                  ◀── {uuidHex, displayName}
  → select contact → Share → shareBlock(blockHex, recipHex) ──IPC──▶ share_block_impl
                                → bridge share_block_to
                                    → read BlockEntry.recipients (manifest)
                                    → load contacts/<each>.card (existing set, incl. owner)
                                    → load contacts/<recipHex>.card (new)
                                    → core::share_block (re-key, re-encrypt, append, re-sign, atomic write)
                                ◀── Ok | NotAuthor | RecipientAlreadyPresent | ContactNotFound | BlockNotFound
```

## 9. Behavioral invariants (what the tests pin)

1. **Card bytes + public keys never cross IPC** — only `{ contactUuidHex, displayName }` do; the share command takes a uuid, never card bytes.
2. **Import cryptographically self-verifies both signature halves** — import calls `from_canonical_cbor` **then** `verify_self()`; a card with a tampered Ed25519 *or* ML-DSA signature is rejected (`CardDecodeFailure`); a structurally-valid, self-verified duplicate uuid is rejected (`ContactAlreadyExists`); neither overwrites an existing card. (`from_canonical_cbor` alone only parses — the explicit `verify_self()` is the both-halves gate.)
3. **`share_block_to` assembles the complete existing-recipient set** — for a freshly-saved block that is exactly the owner card; the recipient table on disk and the manifest `BlockEntry.recipients` both gain the new uuid; `MissingRecipientCard` is impossible by construction (the assembler loads every uuid the manifest lists, surfacing `ContactNotFound` if a referenced card is missing from disk).
4. **Secret-key drop timing is preserved** — `share_block_to` routes through the existing share wrapper's snapshot/zeroize machinery byte-for-byte; no new secret residence.
5. **No silent failure on enumerate** — a malformed `.card` increments `unreadableCount`.
6. **Owner excluded from the picker; non-author share fails typed** — selecting the owner is impossible; sharing a block you did not author returns `NotAuthor`.

## 10. Testing (TDD; ephemeral tempdir vaults; runtime-random crypto)

Per [[feedback_test_crypto_random_not_hardcoded]] all keys/cards are generated at test runtime; per [[feedback_smoke_test_temp_copy_golden_vault]] no test mutates a tracked fixture.

- **Bridge (`contacts/`):**
  - `enumerate` — empty vault returns owner-only; N valid cards return N summaries; a corrupt `.card` yields `unreadableCount == 1` and is excluded.
  - `import` — success writes `contacts/<uuid>.card` + returns the summary; duplicate uuid → `ContactAlreadyExists`; tampered signature → `CardDecodeFailure`; write is atomic.
  - `share_block_to` — happy path (owner shares an owner-authored block with a freshly-imported peer): recipient table + `BlockEntry.recipients` both grow; peer can decrypt afterwards. Errors: `ContactNotFound` (unknown new uuid), `BlockNotFound`, `RecipientAlreadyPresent` (re-share same peer), `NotAuthor` (share a block authored by a different identity). Two identities generated at runtime (owner + peer).
- **Desktop L3:** the three `*_impl` over a real `VaultSession` on a temp vault (import a runtime-generated peer card, share, assert success / typed errors); serde round-trip tests for the five new `AppError` variants.
- **Frontend Vitest:** `contacts` lib (sort/format); the three ipc wrappers (mock `invoke`, incl. error-code mapping); `ShareDialog` (empty → import → populated → share; warning line when `unreadableCount > 0`; typed-error rendering); `BlockCard` share action opens the dialog.
- **Full gauntlet green:** Rust `cargo test`/clippy/fmt; `conformance.py`; `spec_test_name_freshness.py`; Swift + Kotlin conformance (unchanged — no wire-format / KAT change); Vitest; typecheck; svelte-check (no new warnings); lint.

## 11. Security considerations

- **TOFU is the trust model and is stated explicitly** — there is no PKI; import asserts the binding. The cryptographic floor is enforced by an **explicit `verify_self()`** after `from_canonical_cbor` (both Ed25519 ∧ ML-DSA-65 halves — `from_canonical_cbor` only parses, it does not verify), and dedup-reject prevents a malicious second card from shadowing a trusted `contact_uuid`. This mirrors the parse-then-`verify_self()` discipline already in `core::vault::restore_block`. (A future contact-fingerprint-confirmation UX is a separate concern.)
- **Plaintext / key material confinement** — card bytes and the four public keys stay in the bridge; the desktop and frontend see only uuid + display name. `share_block_to` reuses the existing wrapper's zeroize/drop ordering verbatim (no new `Sensitive` residence, no widened lifetimes).
- **Author-only enforcement is server-side** — `NotAuthor` is enforced by core and surfaced typed; the UI's button visibility is not a security boundary.
- **No silent failures** on the contacts read path (`unreadableCount`) or the import path (typed rejects).

## 12. Conformance / KAT impact

**None.** D.1.6 introduces no new on-disk wire format and no new merge semantics — it consumes the existing `ContactCard` and `share_block` wire surfaces. `conformance.py`, `conflict_kat.json`, and `conformance_kat.json` are unchanged; `spec_test_name_freshness.py` stays green. (Verified at implementation time, not assumed.)

## 13. Deferred / out of scope

- **Export-my-card** — the symmetric counterpart to import (write the owner's own `contacts/<owner>.card` to an external file for a peer to import). A tiny later add; not needed to test D.1.6, since a second vault's `contacts/<owner>.card` (written by the D.1.3 create wizard) is a ready-made import source.
- **Standalone contacts-management pane** — view all contacts, delete a contact, list a block's current recipients, re-share. Import lives inside `ShareDialog` for this slice (YAGNI).
- **Multi-recipient share in one action; revoke / unshare** — v1 is single-author append-one.
- **uniffi / pyo3 mirroring** of the new primitives — tracked under #167; wire when a mobile/Python consumer needs contacts/share.
- **Carry-forwards (all still live):** #153 (component styles in `theme.css`), #154 (emoji → inline SVG — D.1.6 adds 🔗), #161 (L4 e2e harness), #162 (PathPicker e2e hook), #164 (Esc-to-pop), #167 (deferred-FFI mirroring), #170 (`lock_session` hoist into `commands::shared`).

## 14. Acceptance criteria

- A user with an unlocked vault can: open Share on an owner-authored block → import a peer's `.card` → see the peer in the picker → share → the peer is appended to the block's recipients (verified by reopening / by a bridge-level decrypt-as-peer test).
- Importing a duplicate uuid or a tampered card is rejected with a typed, user-legible error; sharing with an already-present recipient or as a non-author is rejected typed.
- Card bytes / public keys never appear in any IPC payload (only `{ uuidHex, displayName }`).
- Full automated gauntlet green; `core/` untouched; no conformance-KAT change.
- Manual GUI smoke (§15) passes against a **temp copy** of a vault.

## 15. Manual GUI smoke (the pre-merge gate; headless-impossible)

> ⚠️ Smoke against TEMP vault copies, never a git-tracked fixture (D.1.6 writes into `contacts/` and re-keys blocks). See [[feedback_smoke_test_temp_copy_golden_vault]].

Two identities are needed. Create **vault B** via the D.1.3 wizard (its `contacts/<ownerB>.card` is the import source), then in **vault A**: unlock → create a block with a record → **🔗 Share** → picker empty → **Import a contact…** → pick vault B's `contacts/<ownerB>.card` → B appears → select B → **Share** → success. Re-open vault A → block still listed. Then: Share again with B → **RecipientAlreadyPresent**; Import B again → **ContactAlreadyExists**. If any step fails it is a D.1.6 regression; do not merge until fixed.

---

*Design approved via brainstorming on 2026-05-31. Next: `superpowers:writing-plans` → `docs/superpowers/plans/2026-05-31-d16-share-contacts.md`.*
