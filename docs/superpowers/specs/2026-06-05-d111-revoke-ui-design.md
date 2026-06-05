# D.1.11 — Desktop revoke UI (the revoke *verb* on the D.1.8 / D.1.9 surfaces)

**Date:** 2026-06-05
**Sub-project:** D (desktop UI), eleventh feature slice — built on D.1.6–D.1.10.
**Status:** design approved; ready for implementation plan.

## 1. Problem

D.1.10 shipped the frozen-`core` revoke *primitive* (`revoke_block_recipient`) and its bridge
wrappers (`revoke_block`, `revoke_block_from`), closing [#177](https://github.com/hherb/secretary/issues/177).
Every prior share slice (D.1.6–D.1.9) noted "revoke deferred — needs a core primitive that does
not exist." That primitive now exists, but there is **no way to invoke it from the desktop**: no
Tauri command, no TS wrapper, no UI. The user can *see* who a block is shared with (D.1.8) and
*which* blocks a contact receives (D.1.9), but cannot remove a recipient.

## 2. Goal

Give a user with an unlocked vault a **Revoke** action on the two existing share-display surfaces:
- The **D.1.8 "Shared with" banner** ([BlockRecipients.svelte](../../../desktop/src/components/BlockRecipients.svelte)) — revoke a recipient from *this block*.
- The **D.1.9 per-contact reverse map** ([ContactRow.svelte](../../../desktop/src/components/contacts/ContactRow.svelte)) — stop sharing *this block* with *this contact*.

Both call the same bridge function `revoke_block_from(block_uuid, recipient_uuid)` through one new
IPC command. A revoke is a real content-key rotation (re-key + re-sign + atomic write); the UI
must treat it as a destructive mutation with an honest confirm step and strict (non-lenient)
typed error surfacing.

## 3. Scope

**In scope**
- A new Tauri IPC command `revoke_block_from` + testable `revoke_block_from_impl` in
  [commands/contacts.rs](../../../desktop/src-tauri/src/commands/contacts.rs), the near-verbatim
  inverse of `share_block_impl`, registered in [main.rs](../../../desktop/src-tauri/src/main.rs).
- The two missing TS error variants (`recipient_not_present`, `cannot_revoke_owner`) wired into
  [errors.ts](../../../desktop/src/lib/errors.ts) (the Rust `AppError` side already landed in D.1.10).
- A TS IPC wrapper `revokeBlockFrom(...)` in [ipc.ts](../../../desktop/src/lib/ipc.ts).
- A pure `revokeConfirmCopy(...)` helper (new `src/lib/revoke.ts`) — the single source of the
  confirm-dialog copy, including the explicit forward-secrecy caveat.
- An always-visible per-row **Revoke** control on each non-owner recipient row (BlockRecipients)
  and each block row (ContactRow), gated behind the existing
  [ConfirmDialog](../../../desktop/src/components/delete/ConfirmDialog.svelte).
- Cross-surface consistency after a successful revoke via `refreshManifest()` plus a local reload.
- Tests at every layer (pure helper, IPC wrapper, Rust command, both components).

**Out of scope (deferred)**
- **`core/` and bridge changes.** The bridge `revoke_block_from` is complete (D.1.10);
  `core/src/` and `ffi/` are untouched (0 lines). This is a pure D-phase UI slice — **no
  crypto-review rigor, no UDL/Swift/Kotlin/pyo3 change, no `FfiVaultError` variant churn.**
- **Exposing revoke functions via uniffi/pyo3** — still tracked by
  [#167](https://github.com/hherb/secretary/issues/167). The *error variants* are already on the
  shared `FfiVaultError`/UDL (from D.1.10); only the *functions* stay bridge-only until D.3
  (mobile) or a Python consumer needs them.
- **Contact-card deletion on revoke.** Revoke drops the uuid from a block's recipient set; it does
  **not** delete the contact's `.card` (a contact may receive other blocks). Card deletion is the
  separate D.1.7 concern.
- **A shared `<RevokeButton>` component or store-level revoke action.** Considered (approaches B/C)
  and rejected: each surface owns its own reload semantics, so inlining the ✕ + confirm wiring per
  surface (sharing only the IPC wrapper, ConfirmDialog, and copy helper) matches the existing
  convention and adds no premature abstraction.

## 4. Architecture (bridge-thick; `core/` and bridge frozen and untouched)

Held from D.1.6–D.1.10: all `contacts/` and manifest knowledge stays in the bridge; the desktop
never learns the on-disk vault layout. The new Tauri command is the only Rust added, and it is a
thin delegate to the existing bridge `revoke_block_from`.

### 4.1 Rust IPC command — `revoke_block_from`

New command in `commands/contacts.rs`, a near-verbatim inverse of `share_block_impl`:

```rust
#[tauri::command]
pub async fn revoke_block_from(
    state: State<'_, Mutex<VaultSession>>,
    block_uuid_hex: String,
    recipient_uuid_hex: String,
) -> Result<(), AppError> {
    revoke_block_from_impl(state.inner(), &block_uuid_hex, &recipient_uuid_hex)
}

pub fn revoke_block_from_impl(
    state: &Mutex<VaultSession>,
    block_uuid_hex: &str,
    recipient_uuid_hex: &str,
) -> Result<(), AppError> {
    let block_uuid = parse_uuid_16(block_uuid_hex)?;
    let recipient_uuid = parse_uuid_16(recipient_uuid_hex)?;
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        bridge_revoke_block_from(
            &u.identity,
            &u.manifest,
            block_uuid,
            recipient_uuid,
            u.device_uuid,
            now_ms(),
        )
        .map_err(map_ffi_error)?;
        Ok(())
    })
}
```

Imports `revoke_block_from as bridge_revoke_block_from` from `secretary_ffi_bridge`, alongside the
existing `share_block_to as bridge_share_block_to`. Registered in `main.rs` next to
`contacts::share_block`. The bridge signature is argument-for-argument identical to
`share_block_to`, so this is a structural mirror — the only difference is the bridge function name.

### 4.2 TS error variants — `errors.ts`

D.1.10 added `RecipientNotPresent` and `CannotRevokeOwner` to the Rust `AppError` and
`map_ffi_error`, but left the **TS** side unthreaded (D.1.10 had no desktop UI). Add to
[errors.ts](../../../desktop/src/lib/errors.ts):
- `'recipient_not_present'` and `'cannot_revoke_owner'` to `APP_ERROR_CODES`.
- `| { code: 'recipient_not_present' }` and `| { code: 'cannot_revoke_owner' }` to the `AppError`
  union.
- `userMessageFor` cases:
  - `recipient_not_present` → "That contact is no longer a recipient of this block — your view may
    have been out of date. Refresh and try again." (a stale-view race, not a user error).
  - `cannot_revoke_owner` → "You can't remove yourself as the owner of this block." (backstop copy;
    the UI never offers the owner's control, so this should be unreachable in practice).

### 4.3 TS IPC wrapper — `ipc.ts`

One line mirroring `shareBlock`:

```ts
export async function revokeBlockFrom(
  blockUuidHex: string,
  recipientUuidHex: string,
): Promise<void> {
  return call<void>('revoke_block_from', { blockUuidHex, recipientUuidHex });
}
```

### 4.4 Pure copy helper — `src/lib/revoke.ts`

The confirm copy lives in one pure, unit-tested function so both surfaces (and their tests) share
exactly one source of truth, including the **explicit forward-secrecy caveat**:

```ts
export type RevokeConfirmCopy = { title: string; body: string; confirmLabel: string };

/** Build the confirm-dialog copy for revoking `recipientLabel`'s access to `blockName`. */
export function revokeConfirmCopy(blockName: string, recipientLabel: string): RevokeConfirmCopy;
```

Returned copy (final wording tuned at implementation, but the *shape* is fixed here):
- **title**: `Stop sharing “${blockName}” with ${recipientLabel}?`
- **body**: two sentences — (1) the recipient can no longer open the block after revoke, because it
  is re-encrypted so future changes stay private; (2) the **caveat**: they keep any copy they have
  already seen — revoking cannot reach data they already opened.
- **confirmLabel**: `Revoke`.

Pure (no I/O, no Svelte) → lives in `src/lib/`, tested in isolation. `recipientLabel` is supplied
by the caller (the existing `recipientLabel(r)` for BlockRecipients; the contact display name for
ContactRow), so the helper is framing-agnostic.

## 5. UI surfaces

### 5.1 BlockRecipients.svelte (per-block "Shared with" banner)

- Each recipient row renders an **always-visible** Revoke control **except** the owner row
  (`r.kind !== 'owner'`). Always-visible (not hover-revealed) for discoverability and keyboard
  accessibility; each control carries an `aria-label` of the form
  `Revoke ${recipientLabel(r)}’s access to “${block.blockName}”`.
- Click → `pendingRevoke = { recipientUuidHex, label }` → mount `ConfirmDialog` with
  `revokeConfirmCopy(block.blockName, label)`.
- **Confirm** → `revokeBlockFrom(block.blockUuidHex, recipientUuidHex)` → on success: reload the
  banner's own recipient list (existing `load()`) **and** `refreshManifest()`; on failure: set the
  typed `AppError` and render it via `userMessageFor` — **no read-path leniency** (a transient I/O
  fault is fatal for a mutation, not folded to an empty list).
- The unknown-recipient rows (`r.kind === 'unknown'`) are revocable like any non-owner recipient
  (a uuid with no local card is still a recipient that can be removed).

### 5.2 ContactRow.svelte (per-contact reverse map)

- Each block in the expanded block list renders an always-visible Revoke control (the contact is
  never the owner, so every listed block is revocable). `aria-label`:
  `Stop sharing “${block.blockName}” with ${contact.displayName}`.
- Click → `pendingRevoke = { blockUuidHex, blockName }` → `ConfirmDialog` with
  `revokeConfirmCopy(block.blockName, contact.displayName)`.
- **Confirm** → `revokeBlockFrom(block.blockUuidHex, contact.contactUuidHex)` → on success:
  re-fetch this row's block list (drop the `fetched` cache) **and** `refreshManifest()` so the
  contact's `sharedBlockCount` badge drops; on failure: typed `AppError`, strict surfacing.
- Revoking a contact's **last** block leaves the contact in the list with a zero count (a contact
  with no shared blocks is still a valid contact — D.1.7 owns contact deletion).

### 5.3 Refresh / consistency

A revoke drops the uuid from `manifest.BlockEntry.recipients`, so `sharedBlockCount` falls and the
block's recipient set shrinks. After every successful revoke, the surface does **both**: a local
reload for immediate feedback, and `refreshManifest()` so cross-surface counts (the ContactsPane
badges, any open banner) stay consistent. This is the same post-mutation convention `Vault.svelte`
already uses after create/save/trash — not a new store-level abstraction.

## 6. Error handling

- All revoke failures surface as **typed** `AppError` rendered through `userMessageFor`. The
  mutation path does **not** inherit the read-only display's leniency (which folds transient faults
  to "no recipients"/"no blocks").
- `cannot_revoke_owner` is a backstop: the owner's control is never rendered, so the UI cannot
  produce it; if it ever arrives (e.g. a future caller), the typed message is shown rather than a
  silent success.
- `recipient_not_present` indicates a stale view (the recipient was already removed, e.g. by a
  concurrent session) — the copy tells the user to refresh, and the post-failure state is left
  intact for them to retry.

## 7. Testing (TDD, red-first per unit)

- **`revokeConfirmCopy`** (pure): asserts title/body/confirmLabel, that the body contains the
  forward-secrecy caveat, and that `blockName` / `recipientLabel` are interpolated.
- **`revokeBlockFrom`** (IPC wrapper): mocks `invoke`, asserts `invoke('revoke_block_from', {
  blockUuidHex, recipientUuidHex })` and typed-error re-throw.
- **`revoke_block_from_impl`** (Rust `ipc_integration.rs`): happy path (revoke a present
  recipient), `RecipientNotPresent` (revoke a non-recipient), `CannotRevokeOwner` (revoke the
  owner uuid). Mirrors the existing `share_block_happy_and_typed_errors` test harness.
- **BlockRecipients.svelte**: Revoke control visible for non-owner rows, **absent on the owner
  row**; click → confirm → `revokeBlockFrom` invoked → list reloads; typed-error render path.
- **ContactRow.svelte**: Revoke control on each block row; click → confirm → invoke → block list
  re-fetched and count reflects the drop; typed-error render path.
- **Manual GUI smoke** against a **temp copy** of a vault (per `feedback_smoke_test_temp_copy_golden_vault`)
  — this slice mutates, so the temp-copy rule is mandatory. Verify: revoke from each surface,
  confirm-dialog caveat copy, owner has no control, count/banner refresh after revoke.

## 8. Risks & open items

- **Stale-view race**: two sessions revoking the same recipient — the second gets
  `RecipientNotPresent`, surfaced as a "refresh and retry" message. Acceptable; no locking added.
- **Carry-forwards (unchanged by this slice):** #153 (component styles in `theme.css`),
  #154 (emoji→inline SVG), #161 (L4 e2e — no tauri-driver on macOS WKWebView), #162 (PathPicker
  e2e hook), #164 (Esc-to-pop), #170 (`lock_session` hoist into `commands::shared`), #180
  (a11y `aria-controls`). The new Revoke controls should follow whatever labeling convention
  #180 lands, but do not block on it — ship with explicit `aria-label`s now.
