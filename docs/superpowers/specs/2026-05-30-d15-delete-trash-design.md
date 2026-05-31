# D.1.5 — Delete: record delete/resurrect + block trash/restore (design spec)

**Status:** approved design, pre-plan. Follows D.1.4 (`2026-05-30-d14-vault-edit-design.md`), which shipped the lossless record write path (add/edit). D.1.5 is the next slice in Sub-project D's feature breadth (browse → create → edit → **delete/trash** → share; see ADR 0007). It is the **first destructive-but-recoverable flow**: it tombstones records and trashes whole blocks, both reversible from the UI.

This spec mirrors the D.1.1–D.1.4 section structure so the five read as a series. Where a prior section has no D.1.5 analogue it is omitted rather than padded.

## 1. What this slice ships

D.1.4 lets a user add and edit records. D.1.5 lets a user **remove** them — softly and recoverably — at two levels:

- **Delete (tombstone) a record** — a confirm dialog sets the record's `tombstone` flag + death-clock; the record vanishes from the record list and field viewer by default but survives in the block file for CRDT merge.
- **Show deleted + resurrect a record** — a "Show deleted" toggle on the record list reveals tombstoned records (greyed); each offers a **Restore** action that resurrects it (clears `tombstone` via a live edit at a newer clock).
- **Trash a block** — a confirm dialog moves a whole block to `trash/` (atomic rename + manifest `TrashEntry`); it leaves the blocks list.
- **Trash view + restore a block** — a "🗑 Trash" entry on the blocks pane lists trashed blocks **by name** (each decrypted just enough to show its name + when trashed); each offers a **Restore** that moves it back into the live manifest.

The non-obvious core of this slice is **not** new cryptography — core already implements every primitive (record tombstone semantics in `record.rs`; `trash_block`/`restore_block` orchestrators). The work is wiring those through the **bridge → IPC → UI** with the same secret-handling discipline D.1.4 established (whole-block plaintext confined to the bridge; opaque DTOs across the seam; typed errors), plus one **read-projection change** that lets the UI see tombstoned records when the user asks.

Out of scope: block **sharing** + the contacts subsystem it requires (→ D.1.6); permanent/hard delete (purge from disk); bulk delete; trash auto-expiry. (See §13.)

## 2. Why this ordering (delete after edit)

Edit (D.1.4) introduced the lossless write path that mutates an existing block while preserving siblings + `unknown` maps. Delete is the natural next increment: record tombstone **reuses that exact lossless path** (it is a one-field mutation — set `tombstone` — on the same native `BlockPlaintext` round-trip), so it builds directly on D.1.4's keystone rather than opening new write machinery. Block trash/restore is a different shape (whole-block file move, not a content rewrite) but its core orchestrators already exist and are unit-tested in core; D.1.5 only wraps them. Shipping delete also completes the everyday CRUD loop a password manager needs (create → read → update → **delete**) before the heavier sharing slice.

## 3. Architecture approach

Core is **frozen and unchanged**. Every primitive D.1.5 needs already exists in core:

- Record tombstone/resurrect: `core::Record { tombstone: bool, tombstoned_at_ms: u64 }` with documented resurrection semantics (a live edit at `T > tombstoned_at_ms` clears `tombstone`, bumps `last_mod_ms`, preserves `tombstoned_at_ms`) — `core/src/vault/record.rs`.
- Block trash: `core::vault::trash_block(folder, &mut OpenVault, block_uuid, device_uuid, now_ms, &mut rng)` — atomic rename `blocks/<uuid>.cbor.enc` → `trash/<uuid>.cbor.enc.<now_ms>`, drop the `BlockEntry`, append a `TrashEntry`, tick the vault clock, re-sign the manifest — `core/src/vault/orchestrators.rs`.
- Block restore: `core::vault::restore_block(...)` — live-collision check, scan `trash/` for matches, pick newest, purge older duplicates, verify, re-insert into the manifest, tick + re-sign — `core/src/vault/orchestrators.rs`.

The work is at the **bridge** layer (Sub-project B, not frozen) and above. The desktop's unlocked session already holds the bridge `UnlockedIdentity` + manifest handle (D.1.2–D.1.4 call bridge primitives through it), so the new primitives belong in the **bridge** and the desktop calls them through the session — exactly as edit does.

| Decision | Choice | Rationale |
|---|---|---|
| Delete semantics | **Soft delete (tombstone), never hard delete** | The record must survive in the block for CRDT merge (a peer that hasn't seen the delete must still converge). Hard delete/purge is a separate, later concern. |
| Record tombstone path | **Reuse the D.1.4 lossless native-`BlockPlaintext` round-trip**; a dedicated `tombstone_record` primitive sets `tombstone = true` + `tombstoned_at_ms = now`, preserving siblings + all three `unknown` levels | One-field mutation on the proven path; the keystone (sibling + `unknown` survival) is identical to D.1.4 and re-pinned here. |
| Record resurrect path | **A dedicated `resurrect_record` primitive** that clears `tombstone` and bumps `last_mod_ms = now` (`now` > `tombstoned_at_ms`), preserving `tombstoned_at_ms` + siblings + `unknown` | Resurrection is a defined core semantic; D.1.4's `edit_record` deliberately *preserves* `tombstone` (it locates only **live** records), so resurrect is its own small primitive rather than an `edit_record` flag — one concept per function. |
| Block trash/restore path | **Thin bridge wrappers** over `core::vault::trash_block`/`restore_block` | Core does the whole job; the bridge only adapts session handles → core args and core errors → bridge errors. |
| Tombstoned-record visibility | **Rust stays the gatekeeper via an `include_deleted` read parameter** | The block-detail read takes `include_deleted: bool` (default `false` → live only, the current behaviour). The "Show deleted" toggle re-reads with `include_deleted = true`, which additionally emits tombstoned records carrying a `tombstoned: bool` render flag. The client never sees a tombstoned record's existence unless it explicitly asks; one IPC round-trip per toggle. This is the stricter boundary for a secrets manager — the server decides what crosses the seam. |
| Trash view identity | **Decrypt each trashed block for its name** (plaintext confined to the bridge) | The `TrashEntry` carries only `block_uuid`/`tombstoned_at_ms`/`tombstoned_by` — not the name (it's inside the encrypted block). A `list_trashed_blocks` bridge primitive decrypts each trashed file just enough to project its name, never lowering record plaintext to JS. |
| Confirm dialogs | **Delete record and trash block both confirm**, phrased as recoverable | Both are reversible (resurrect / restore), but both remove something from view; an explicit confirm prevents accidents. Resurrect and restore are *additive*, so they need no confirm. |
| Recipients | **Unchanged (owner-only)** | D.1.5 touches no recipient set; sharing is D.1.6. |

## 4. Project layout (additions)

```
ffi/secretary-ffi-bridge/src/
  edit/                    MODIFIED dir — record tombstone/resurrect join the D.1.4 write primitives
    tombstone.rs             NEW — tombstone_record / resurrect_record (native-BlockPlaintext round-trip)
    mod.rs                   MODIFIED — re-export tombstone_record / resurrect_record
  trash/                   NEW dir — block-level trash lifecycle wrappers
    mod.rs                   trash_block / restore_block / list_trashed_blocks over the session handle
  lib.rs                   MODIFIED — re-export the trash module's primitives
  # NOTE: the new primitives are NOT mirrored on uniffi/pyo3 in D.1.5
  # (the desktop consumes the bridge directly; no mobile/Python UI exists yet) — see §13.
desktop/src-tauri/src/
  commands/
    delete.rs              NEW — tombstone_record / resurrect_record / trash_block / restore_block /
                                 list_trashed_blocks (+ *_impl)
  dtos/
    trash.rs               NEW — TrashedBlockDto { block_uuid_hex, name, tombstoned_at_ms, tombstoned_by_hex }
    browse.rs              MODIFIED — RecordDto gains `tombstoned: bool`
    mod.rs                 MODIFIED — re-export TrashedBlockDto
  reveal.rs                MODIFIED — block-detail projection gains `include_deleted: bool` (default off);
                                      emits tombstoned records (flagged) ONLY when set — Rust gates visibility
  errors.rs                MODIFIED — BlockRestoreConflict, TrashEntryNotFound (+ reuse RecordSaveFailed)
  main.rs                  MODIFIED — register the five new commands
desktop/src/
  lib/
    trash.ts               NEW — pure helpers: TrashedBlockDto sort/format (no record filtering — Rust gates that)
    ipc.ts                 MODIFIED — tombstoneRecord, resurrectRecord, trashBlock, restoreBlock,
                                      listTrashedBlocks + DTO interfaces; block-detail read gains an
                                      `includeDeleted` arg; RecordDto gains tombstoned
    errors.ts              MODIFIED — new codes + messages
    browse.ts              MODIFIED — BrowseNav gains { level: 'trash' } + openTrash() transition
  components/
    delete/                NEW dir — one concept per file (< 500 LOC each)
      ConfirmDialog.svelte     reusable confirm (title + body + confirm/cancel); used by delete + trash
      TrashView.svelte         lists TrashedBlockDto rows, each with Restore
      TrashedBlockRow.svelte   one trashed-block row: name + when + Restore
    RecordList.svelte        MODIFIED — per-row Delete action; "Show deleted" toggle; greyed tombstoned
                                        rows with Restore (resurrect)
    BlockList/BlockCard      MODIFIED — per-block Trash action; "🗑 Trash" entry → openTrash()
  routes/
    Vault.svelte           MODIFIED — route the browse stack to the Trash pane; wire confirm dialogs
```

The `delete/` dir keeps each concept a small, single-purpose file; `ConfirmDialog` is shared by both destructive flows.

## 5. Module decomposition + responsibilities

### Bridge (`ffi/secretary-ffi-bridge/src/`)

| Module | Responsibility | Pure? |
|---|---|---|
| `edit/tombstone.rs` | `tombstone_record(session, block_uuid, record_uuid, now_ms)` and `resurrect_record(session, block_uuid, record_uuid, now_ms)`. Each decrypts the target block to a native `core::BlockPlaintext` (the same path `edit_record` uses), locates the record by `record_uuid`, flips exactly one flag (`tombstone = true, tombstoned_at_ms = now_ms` for delete; `tombstone = false, last_mod_ms = now_ms` for resurrect — `tombstoned_at_ms` preserved), leaves siblings + all `unknown` maps native, and calls `core::vault::save_block`. `tombstone_record` targets a **live** record (missing/already-tombstoned → error); `resurrect_record` targets a **tombstoned** record (missing/live → error). | No (decrypt + core call) |
| `trash/mod.rs` | `trash_block(session, block_uuid, now_ms)` and `restore_block(session, block_uuid, now_ms)` adapt session handles → `core::vault::{trash_block,restore_block}` args (device uuid + rng from the session) and map core errors → bridge errors. `list_trashed_blocks(session) -> Vec<TrashedBlock>` reads the manifest's trash table, decrypts each trashed file just enough to project `{ block_uuid, name, tombstoned_at_ms, tombstoned_by }` (record plaintext is **not** projected), and returns the list sorted newest-first. | No (core calls / decrypt) |

`unknown` preservation (the keystone — §10): tombstone/resurrect carry forward block-, record-, and field-level `unknown` byte-faithfully, identically to `edit_record`. A tombstone/resurrect must not be a data-loss event for a future client's forward-compat keys.

### Backend (`desktop/src-tauri/src/`)

| Module | Responsibility | Pure? |
|---|---|---|
| `commands/delete.rs` | Thin `#[tauri::command]` wrappers + `*_impl` for the five primitives. Each `*_impl` resolves uuids from hex (bad hex → typed error), calls the bridge primitive through the session, maps bridge errors to typed `AppError`. `tombstone_record`/`resurrect_record` return a `RecordRefDto` (reused from D.1.4); `trash_block` returns `()`; `restore_block` returns the restored block's `BlockSummaryDto`; `list_trashed_blocks` returns `Vec<TrashedBlockDto>`. | No (bridge/session call) |
| `dtos/trash.rs` | `Serialize` `TrashedBlockDto { block_uuid_hex, name, tombstoned_at_ms, tombstoned_by_hex }` (`#[serde(rename_all = "camelCase")]`). `name` is a block name (category label), not a secret field value — but `Debug` is redacted anyway, for parity with the secret-boundary discipline. | Data only |
| `dtos/browse.rs` (mod) | `RecordDto` gains `tombstoned: bool` (`#[serde(rename_all = "camelCase")]`, already set) — a render flag, only ever `true` when the caller passed `include_deleted`. | Data only |
| `reveal.rs` (mod) | The block-detail projection gains an `include_deleted: bool` parameter: when `false` (default) it filters tombstoned records out (current behaviour); when `true` it additionally emits them with `tombstoned` set. **Rust is the gatekeeper** — the client learns a tombstoned record exists only when it passes the flag. The single-field **reveal** path still refuses a tombstoned record (you can't reveal a deleted record's secrets) — except via the `resurrect_record` write path, which reads it internally in the bridge. | No (decrypt) |
| `errors.rs` (mod) | Add `BlockRestoreConflict { block_uuid_hex }` (a live block with that uuid already exists) and `TrashEntryNotFound { block_uuid_hex }` (the restore target vanished). Reuse `RecordSaveFailed`/`BlockNotFound`/`RecordNotFound` for the tombstone/resurrect write path. | Pure |

### Frontend (`src/`)

| Module | Responsibility | Pure? |
|---|---|---|
| `lib/trash.ts` | Pure helpers, no IPC/DOM: `sortTrashed(dtos)` (newest-first); `formatTrashedWhen(ms)` (relative/absolute label). Live/tombstoned partitioning is **not** a client concern — Rust gates inclusion via `include_deleted`, so the toggle re-reads rather than filtering locally. | Yes |
| `lib/ipc.ts` (mod) | `tombstoneRecord(blockUuidHex, recordUuidHex)`, `resurrectRecord(blockUuidHex, recordUuidHex)`, `trashBlock(blockUuidHex)`, `restoreBlock(blockUuidHex)`, `listTrashedBlocks()` + DTO interfaces; the block-detail read wrapper gains an `includeDeleted` arg (default `false`); `RecordDto` interface gains `tombstoned`. | Wrapper |
| `lib/errors.ts` (mod) | Add `block_restore_conflict`, `trash_entry_not_found` to the exhaustive union + `APP_ERROR_CODES` + user messages. | Pure |
| `lib/browse.ts` (mod) | Extend `BrowseNav` with `{ level: 'trash' }`; add `openTrash()`; `back()` pops it. | Yes |
| `components/delete/*` | Render + dispatch only. `ConfirmDialog` is presentational (props in, events out). `TrashView` fetches `listTrashedBlocks` on mount; `TrashedBlockRow` dispatches restore. | No |
| `components/RecordList.svelte` (mod) | Per-row **Delete** → `ConfirmDialog` → `tombstoneRecord` → refetch. A **"Show deleted"** toggle (local `$state`) **re-reads the block with `includeDeleted = true`** (and back to `false` when off). Tombstoned rows (flagged by Rust) render greyed with a **Restore** → `resurrectRecord` → refetch. | No |
| block list/card (mod) | Per-block **Trash** → `ConfirmDialog` → `trashBlock` → `refreshManifest`. A **"🗑 Trash"** entry → `openTrash()`. | No |
| `routes/Vault.svelte` (mod) | Route the browse stack to the `TrashView` pane; host the shared confirm dialogs; after `trashBlock`/`restoreBlock` call `refreshManifest()` (mirrors D.1.4's post-write refresh). | No |

### IPC boundary discipline

No primitive lowers a sibling record's plaintext to JS. `tombstone_record`/`resurrect_record` return only a `RecordRefDto` (two hex ids). `list_trashed_blocks` returns block **names + metadata** only — never a trashed block's record contents. The block-detail read includes tombstoned records **only when the caller passes `include_deleted`** (Rust gates it); even then it emits the same metadata-only `RecordDto` shape as live records (no field values; secrets still require an explicit per-field reveal, which remains refused for tombstoned records). By default no tombstoned record crosses the seam.

## 6. Delete/trash path lifecycle

### 6.1 `tombstone_record(blockUuidHex, recordUuidHex) -> RecordRefDto`

1. `*_impl` resolves both uuids from hex (bad hex → `BlockNotFound`/`RecordNotFound`).
2. Bridge `tombstone_record`: decrypt block → native `BlockPlaintext`; locate the **live** record by `record_uuid` (missing/already-tombstoned → `RecordNotFound`); set `tombstone = true`, `tombstoned_at_ms = now_ms`; siblings + `unknown` untouched (native) → `core::vault::save_block`.
3. Return `RecordRefDto { block_uuid_hex, record_uuid_hex }`. UI refetches the block detail; the row drops out of the default (live-only) view.

### 6.2 `resurrect_record(blockUuidHex, recordUuidHex) -> RecordRefDto`

1. As 6.1 step 1.
2. Bridge `resurrect_record`: decrypt block → native `BlockPlaintext`; locate the **tombstoned** record by `record_uuid` (missing/live → `RecordNotFound`); set `tombstone = false`, `last_mod_ms = now_ms` (`now_ms` > `tombstoned_at_ms`), **preserve** `tombstoned_at_ms`, `record_uuid`, `created_at_ms`, `unknown`; siblings untouched → `core::vault::save_block`.
3. Return `RecordRefDto`. UI refetches; the row returns to the live view.

### 6.3 `trash_block(blockUuidHex) -> ()`

1. `*_impl` resolves the uuid (bad hex / not in manifest → `BlockNotFound`).
2. Bridge `trash_block` → `core::vault::trash_block` (atomic rename → `trash/<uuid>.cbor.enc.<now_ms>`, drop `BlockEntry`, append `TrashEntry`, tick + re-sign).
3. Return `()`. UI calls `refreshManifest()`; the block leaves the blocks list.

### 6.4 `restore_block(blockUuidHex) -> BlockSummaryDto`

1. `*_impl` resolves the uuid.
2. Bridge `restore_block` → `core::vault::restore_block` (live-collision check → `BlockRestoreConflict`; no trash match → `TrashEntryNotFound`; else re-insert into manifest, tick + re-sign).
3. Return the restored block's `BlockSummaryDto`. UI calls `refreshManifest()` and pops the trash pane (or refetches the trash list).

### 6.5 `list_trashed_blocks() -> TrashedBlockDto[]`

1. Bridge reads the manifest's trash table; for each `TrashEntry`, decrypts the matching `trash/<uuid>.cbor.enc.<ts>` file just enough to read the block **name** (record plaintext is not decoded into handles / not projected).
2. Project `{ block_uuid_hex, name, tombstoned_at_ms, tombstoned_by_hex }`; the decrypted material drops (zeroized) per entry.
3. Return the list (frontend sorts newest-first via `sortTrashed`). A trash file that fails to decrypt/verify is surfaced as an error for that entry rather than silently dropped (typed; logged) — the user should know a trashed block is unreadable, not see it vanish.

## 7. Page routes & navigation

The unlocked browse view navigates a stack via `browseNav` (`blocks → records → fields`, plus D.1.4's `newBlock`/`newRecord`/`editRecord`). D.1.5 adds one new top-level state and two in-pane actions (no new navigation level for delete/resurrect — they act in place on the records pane):

```
blocks ──"🗑 Trash"──▶ trash ──restoreBlock()──▶ (refresh; stay or pop) blocks
   │  └─ per block: "Trash" ──confirm──▶ trashBlock() ──▶ (refresh) blocks
   │
records (of a block)
   ├─ per row: "Delete" ──confirm──▶ tombstoneRecord() ──▶ (refetch) records
   └─ "Show deleted" toggle ──re-read(includeDeleted=true)──▶ greyed tombstoned rows
        └─ per tombstoned row: "Restore" ──▶ resurrectRecord() ──▶ (refetch) records
```

Back button + breadcrumb work uniformly; `back()` pops the trash pane. Confirm dialogs are modal over the current pane; resurrect/restore are immediate (additive, no confirm).

## 8. Delete behaviour & secret handling

| Behaviour | Rule |
|---|---|
| Delete confirm | "Delete this record? It's removed from view but can be restored from 'Show deleted'." Confirm → `tombstoneRecord`. |
| Default visibility | The block-detail read defaults to `include_deleted = false` — Rust filters tombstoned records out; the list shows only live records. |
| Show deleted | A toggle re-reads the block with `include_deleted = true`; tombstoned records come back flagged and render greyed, each with **Restore**. One IPC round-trip per toggle; Rust gates inclusion (no client-side filtering of withheld data). |
| Resurrect | Immediate (no confirm); resurrected row returns to the live view on refetch. |
| Trash confirm | "Move this block to Trash? You can restore it from the Trash view." Confirm → `trashBlock`. |
| Restore block | Immediate (no confirm). Live-uuid collision → typed `BlockRestoreConflict` message; vanished target → `TrashEntryNotFound`. |
| Reveal of tombstoned | The per-field reveal path refuses a tombstoned record (you can't read a deleted record's secrets); only `resurrect_record` reads it, inside the bridge. |
| Backend wipe | Bridge decrypted `BlockPlaintext` (tombstone/resurrect, list-trash name read) drops (zeroize) when the call returns; no plaintext crosses the IPC seam. |
| Trash-name exposure | `list_trashed_blocks` exposes block **names** (category labels) only — never record field values. |

## 9. Error model

New `AppError` variants (`#[serde(tag = "code", rename_all = "snake_case")]`, mirroring D.1.1–D.1.4):

| Variant | Wire `code` | When | Frontend message |
|---|---|---|---|
| `BlockRestoreConflict { block_uuid_hex }` | `block_restore_conflict` | restore target's uuid is already live | "A block with this id already exists. It may have been restored elsewhere." |
| `TrashEntryNotFound { block_uuid_hex }` | `trash_entry_not_found` | restore/list target has no trash file | "That trashed block is no longer available." |

Reused: `BlockNotFound` (trash/restore/tombstone of a missing block), `RecordNotFound` (tombstone of a non-live or resurrect of a non-tombstoned record), `RecordSaveFailed` (bridge/core `save_block` error on the tombstone/resurrect path). Typed errors, not silent `None`s; `detail` fields stay `#[serde(skip_serializing)]` (logged via `tracing`, no secret bytes). `frontend/errors.ts` adds the two new codes to its exhaustive union + `APP_ERROR_CODES`.

## 10. Testing strategy

| Layer | Tool | D.1.5 coverage |
|---|---|---|
| L1 Rust unit (bridge) | `cargo test` | `tombstone.rs` flag transitions in isolation (live→tombstoned sets clock; tombstoned→live clears flag, bumps `last_mod`, preserves `tombstoned_at_ms`); error arms (tombstone of already-tombstoned, resurrect of live). |
| L1 Rust unit (desktop) | `cargo test` | `dtos/trash.rs` serde round-trip (camelCase); `RecordDto.tombstoned` serde; the `include_deleted` projection gate (false → tombstoned omitted; true → emitted with `tombstoned: true`); new error wire codes; hex-resolution boundary → typed errors. |
| L2 TS unit | Vitest | `lib/trash.ts` (`sortTrashed`, `formatTrashedWhen`); `lib/browse.ts` `openTrash`/`back`; `RecordList` (delete confirm; the show-deleted toggle **re-reads with `includeDeleted=true`**, asserted against the IPC mock; resurrect); block trash action, `TrashView`/`TrashedBlockRow`/`ConfirmDialog` interaction; `errors.ts` new codes; `ipc.ts` mocks. |
| L3 Rust integration | `cargo test` | Over **ephemeral tempdirs** with **runtime-random** crypto: tombstone a record → block-detail read with `include_deleted=false` omits it, with `include_deleted=true` flags it; resurrect → it returns live. **Keystones** — (a) tombstoning record A in a block with B & C leaves B/C **byte-faithful**; (b) a record/field carrying synthetic `unknown` keys retains them across a tombstone **and** a resurrect at all three levels. Block: `trash_block` then `list_trashed_blocks` shows it **by name**; `restore_block` returns it to the manifest and `read_block` reads it again; restore into a live-uuid collision → `BlockRestoreConflict`; restore of a purged target → `TrashEntryNotFound`. |
| Cross-language conformance | swift/kotlin scripts | No binding-contract change: the new primitives are **bridge-only** (not mirrored on uniffi/pyo3 — §13), and the projection/`tombstoned`-flag change is desktop-side. The conformance KAT is **not** expected to change (tombstone/resurrect use existing `Record` fields with existing wire encoding); the plan carries an explicit checkpoint to regenerate **only if** a diff appears, scoped + human-reviewed. |
| L4 e2e | (deferred) | No new e2e; rides on the deferred macOS WebDriver decision (#161). |

Any new test that needs crypto material generates it at runtime (`OsRng`); no hardcoded keys/passwords (CodeQL). Writes round-trip through freshly-created tempdir vaults, never the golden fixture.

### Expanded gauntlet at D.1.5 close

Same commands as D.1.4's close (`cargo test --release --workspace`, clippy `-D warnings`, fmt, `conformance.py`, `spec_test_name_freshness.py`, the swift/kotlin conformance scripts, `pnpm test / typecheck / svelte-check / lint`). Rust count rises by the new bridge + desktop unit + integration tests; Vitest by the new trash/delete logic + component tests. Counts recorded in the ship handoff.

## 11. Dependencies (additions)

No new Cargo or npm dependencies are anticipated:

- `zeroize` / `secretary-core` types back the decrypt+save path and the trash-name read (all already deps).
- Block trash/restore call existing core orchestrators; no new crate.
- `list_trashed_blocks` reuses the existing block-decrypt path used by browse — name projection only.

## 12. UX details

- **Blocks pane:** a "🗑 Trash" entry (button) → `TrashView`; each block gets a "Trash" action (confirm → `trashBlock`).
- **Records pane:** each row gets a "Delete" action (confirm → `tombstoneRecord`); a "Show deleted" toggle reveals greyed tombstoned rows, each with "Restore" (`resurrectRecord`).
- **Trash view:** a list of trashed blocks by name + when trashed (+ by-device), each with "Restore". Empty state: "Trash is empty."
- **Confirm dialog:** a shared `ConfirmDialog` (title, body, Confirm/Cancel); destructive confirm styled distinctly; Esc/Cancel closes without acting (Esc-to-pop carry-forward #164 applies to the pane, not the dialog).
- **Styling:** new classes (`.confirm-dialog`, `.trash-view`, `.trashed-row`, `.record-row--deleted`, …) in `theme.css` (Vite 6 `preprocessCSS` workaround, #153), reusing existing tokens; dark mode inherits. The "🗑" glyph follows the emoji→SVG carry-forward (#154).

## 13. Out of scope for D.1.5

| Deferred | To | Why |
|---|---|---|
| Share a block + contacts subsystem (enumerate/load contact cards, recipient picker) | **D.1.6** | `core::share_block` needs the author card + secret keys + **all** existing recipient cards + the new recipient card, and there is **no desktop contacts surface yet** (no bridge enumerate/load, no picker UI). That's a self-contained subsystem deserving its own spec. |
| Permanent / hard delete (purge tombstoned records or trash files from disk) | later | Soft delete satisfies CRDT convergence; purge has its own retention/merge-safety semantics. |
| Bulk delete / multi-select | later | Out of the minimal per-item delete vertical. |
| Trash auto-expiry / retention policy | later | A policy concern, not a write-path primitive. |
| uniffi/pyo3 wrappers for the new primitives | tracking issue (#167 covers the D.1.4 primitives; extend or file a sibling at ship) | The desktop consumes the bridge directly (path dep); no mobile/Python UI consumes these yet. Mirroring (+ Swift/Kotlin/Python conformance) is deferred to when such a consumer exists. |

### Verified facts (recorded; the design depends on them)

- `core::Record` carries `tombstone: bool` + `tombstoned_at_ms: u64` with resurrection semantics (live edit at `T > tombstoned_at_ms` clears the flag, bumps `last_mod_ms`, preserves the death-clock) — `core/src/vault/record.rs`.
- `core::vault::trash_block` / `restore_block` are implemented and unit-tested in core (atomic rename to `trash/`, manifest `TrashEntry`, live-collision check, newest-wins restore + older-duplicate purge) — `core/src/vault/orchestrators.rs`; `TrashEntry { block_uuid, tombstoned_at_ms, tombstoned_by, unknown }` — `core/src/vault/manifest.rs`.
- The bridge record handle exposes `.tombstone()` (`ffi/secretary-ffi-bridge/src/record/handle.rs`); the current desktop block-detail projection **filters tombstoned records out** (`desktop/src-tauri/src/dtos/browse.rs`, `reveal.rs`) — D.1.5 keeps that filter in **Rust**, gated by a new `include_deleted` parameter (default off), rather than moving it client-side.
- D.1.4's `edit_record` locates only **live** records (`!r.tombstone`) and **preserves** `tombstone`/`tombstoned_at_ms` (`ffi/secretary-ffi-bridge/src/edit/mod.rs`); hence tombstone/resurrect are separate primitives, not `edit_record` flags.
- `core::vault::save_block` re-encrypts the **whole** block from supplied plaintext (`orchestrators.rs`), which is why tombstone/resurrect must carry untouched siblings + `unknown` natively (the D.1.4 keystone, re-pinned here).

## 14. Broader project implications

- **README.md:** the D-row note advances from "D.1.4 (edit) shipped" to "D.1.5 (delete/trash) shipped; D.1.6 (share) next" at ship (brief, per the README style).
- **ROADMAP.md:** mark D.1.5 ✅ at ship; D.1.6 ⏳ next (note the scope split — share moved out of D.1.5 into its own slice).
- **Security review surface:** the tombstone/resurrect `unknown`-preservation keystone; **Rust gating tombstoned-record visibility behind `include_deleted` (default off)** — the client cannot observe a deleted record's existence without asking, and even then gets **no field values**; the reveal path's continued refusal of tombstoned records; `list_trashed_blocks` exposing names only; whole-block plaintext confined to the bridge.
- **No spec/format change:** D.1.5 consumes the frozen vault format + existing core orchestrators unchanged. `crypto-design.md` / `vault-format.md` / `conformance.py` are untouched; the conformance KAT is regenerated only if a diff appears (not expected — §10).
- **Bridge surface grows:** five new public bridge primitives (`tombstone_record`, `resurrect_record`, `trash_block`, `restore_block`, `list_trashed_blocks`), additive alongside the D.1.4 write primitives. Read/create/edit surfaces are unchanged.
- **Scope note:** D.1.5 deliberately drops "share" from the original baton bundle (it needs a contacts subsystem); share becomes D.1.6 with its own spec → plan cycle.
- **NEXT_SESSION handoff:** authored on the feature branch per the handoff-symlink workflow.

## 15. Acceptance criteria

Mirrors D.1.1–D.1.4's five categories.

1. **Manual smoke (user, pre-merge gate)** — against a **tempdir copy** (never the tracked golden fixture): unlock → delete a record (confirm) → it disappears from the list → toggle "Show deleted" → it appears greyed → Restore it → it returns to the live list → trash a block (confirm) → it leaves the blocks list → open "🗑 Trash" → it appears **by name** → Restore it → it returns to the blocks list → re-open the vault and confirm all states persisted. A restore into a live-uuid collision shows the typed conflict message.
2. **Automated gauntlet** — all green: `cargo test --release --workspace`, clippy `-D warnings`, fmt, `conformance.py`, `spec_test_name_freshness.py`, the swift/kotlin conformance scripts, `pnpm test / typecheck / svelte-check / lint`.
3. **L4 e2e** — none added (deferred, #161).
4. **Docs** — README + ROADMAP updated; this spec + the implementation plan committed.
5. **Process** — files < 500 LOC (split where heading over), pure functions in `lib/trash.ts` + bridge/desktop helpers, no magic numbers, random crypto in any new tests, the tombstone/resurrect `unknown`-preservation keystone tests present and passing, handoff baton rides inside the ship PR.

## 16. References

- D.1.4 spec — `docs/superpowers/specs/2026-05-30-d14-vault-edit-design.md`
- D.1.3 spec — `docs/superpowers/specs/2026-05-29-d13-create-vault-design.md`
- D.1.2 spec — `docs/superpowers/specs/2026-05-29-d12-browse-design.md`
- D.1.1 spec — `docs/superpowers/specs/2026-05-27-d11-tauri-walking-skeleton-design.md`
- ADR 0007 — `docs/adr/0007-d-row-tauri.md` (Sub-project D → Tauri 2)
- Core record tombstone semantics — `core/src/vault/record.rs`; trash/restore orchestrators — `core/src/vault/orchestrators.rs`; `TrashEntry` — `core/src/vault/manifest.rs`
- Bridge edit primitives (D.1.4, reused) — `ffi/secretary-ffi-bridge/src/edit/`; record handle `.tombstone()` — `ffi/secretary-ffi-bridge/src/record/handle.rs`
- Desktop block-detail projection (current tombstone filter) — `desktop/src-tauri/src/dtos/browse.rs`, `desktop/src-tauri/src/reveal.rs`
- D.1.1–D.1.4 IPC/DTO/error/secret-boundary patterns — `desktop/src-tauri/src/{commands,dtos,errors.rs}`, `desktop/src/lib/{ipc,errors,browse,editor}.ts`
- Deferred-FFI tracking — issue #167
