# D.1.2 — Browse: read-only block detail + field reveal (design spec)

**Status:** approved design, pre-plan. Follows D.1.1 (`2026-05-27-d11-tauri-walking-skeleton-design.md`), which shipped the walking skeleton (unlock → block-list scaffold → auto-lock → lock). D.1.2 is the next slice in Sub-project D's feature breadth (browse → create → edit → share/trash; see ADR 0007).

This spec mirrors the D.1.1 section structure so the two read as a series. Where a D.1.1 section has no D.1.2 analogue (e.g. project initialization), it is omitted rather than padded.

## 1. What this slice ships

D.1.1 gives the user a **list of blocks**. D.1.2 makes that list drillable and lets the user read a secret:

- Click a block card → a **record list** for that block (records labelled by non-secret metadata).
- Click a record → a **field viewer** showing each field's name + type, values **masked by default**.
- Per-field **reveal / re-mask** toggle. Revealing a field calls the FFI `expose_text()` / `expose_bytes()` boundary on demand; revealed values **auto-hide** after a fixed window and clear on navigate / lock.
- Per-field **copy** to the system clipboard, with a fixed **auto-clear** timeout.
- Binary (`bytes`) fields are revealed and copied as **base64**.

Still strictly **read-only**: no create (D.1.3), no edit/save (D.1.4), no share/trash/restore (D.1.5).

## 2. Why this ordering (browse before create/edit)

Browse is the smallest slice that exercises the full read path end-to-end (decrypt a block → project records → reveal a field's plaintext through the zeroize boundary → surface it in the WebView). It validates the IPC read surface and the secret-widening discipline *before* any write path exists, so the riskier create/edit slices build on a proven read foundation. It is also the slice with the highest standalone user value: an unlock-and-read vault is already useful.

## 3. Architecture approach

The bridge read surface (`secretary_ffi_bridge::read_block` → `BlockReadOutput` → `Record` → `FieldHandle`, with `expose_text()` / `expose_bytes()`) was delivered in B.4b and is unchanged by D.1.2. These are **Rust-only opaque handles** that cannot cross IPC. D.1.2 therefore adds two IPC commands over that surface and a stacked-page frontend:

| Decision | Choice | Rationale |
|---|---|---|
| Navigation model | **Stacked pages** (block list → record list → field viewer; back/breadcrumb pops a level) | Reuses D.1.1's manual state-machine routing (lowest risk, fastest); mobile-ready for D.3. A two-pane master/detail is deferred until edit/create make side-by-side worthwhile. |
| Secret reveal | **Stateless re-decrypt per reveal** | Each `reveal_field` call re-decrypts the block, exposes one field, then wipes the handle. Decrypted secrets live in Rust for one call only; **no secret-bearing session state** to clear on lock. Re-decrypt cost is negligible at human click cadence. (Rejected: caching the decrypted `BlockReadOutput` in the session — keeps the whole block decrypted while browsing and multiplies the wipe edges.) |
| The widening point | The revealed `String` serialized over IPC into the WebView JS heap | JS strings can't be zeroized. This is the *single* widening point under stateless reveal; the frontend rule is **request on explicit click, hold briefly, drop on re-mask / navigate / lock, never persist or cache**. |
| Record label | Non-secret metadata (`record_type` · tags · field-count · last-modified) | Field *values* are all secret; only names/type/tags/timestamps are plaintext. A dedicated non-secret "title" field is a vault data-model change, out of scope. |
| Binary fields | Reveal + copy as **base64** | Handles `bytes` fields (keys, TOTP seeds) without a hex-dump UI. No byte-length shown pre-reveal (avoids a bridge change + a minor length side-channel). |
| Clipboard | `tauri-plugin-clipboard-manager`, **write permission only**; unconditional best-effort clear after a timeout | Write-only minimizes the capability surface (no clipboard *read*, a sensitive capability for a secrets app). Unconditional clear may clobber newer clipboard content the user copied meanwhile — an accepted, documented tradeoff vs. requesting read to compare. |

## 4. Project layout (additions)

```
desktop/src-tauri/src/
  commands/
    browse.rs            NEW — read_block + reveal_field command impls
  dtos/                  NEW module (split from the 260-line dtos.rs)
    mod.rs               re-exports; existing ManifestDto/BlockSummaryDto/Settings* move here
    manifest.rs          existing manifest/summary/settings DTOs (moved verbatim)
    browse.rs            NEW — BlockDetailDto, RecordDto, FieldMetaDto, RevealedFieldDto
  reveal.rs              NEW — pure projection + base64 + locate-by-uuid/name helpers
desktop/src/
  lib/
    browse.ts            NEW — pure browse-nav store + transition helpers
    reveal.ts            NEW — pure reveal/clipboard timing logic (injectable setTimeout)
  components/
    RecordList.svelte    NEW
    RecordRow.svelte     NEW
    FieldViewer.svelte   NEW
    FieldRow.svelte      NEW
    BlockCard.svelte     MODIFIED — disabled → clickable
  routes/Vault.svelte    MODIFIED — switch on browse-nav level
```

The `dtos.rs` → `dtos/` split is proactive (the file is 260 lines and the browse DTOs are a distinct concept from the manifest/settings DTOs). The move of the existing DTOs is verbatim — no behaviour change — and the wire-format round-trip tests move with them.

## 5. Module decomposition + responsibilities

### Backend (`src-tauri/src/`)

| Module | Responsibility | Pure? |
|---|---|---|
| `commands/browse.rs` | Thin `#[tauri::command]` wrappers + `*_impl(state, …)` for `read_block` and `reveal_field`. Lock the session mutex, borrow via `with_unlocked`, call the bridge, project/zeroize, return DTO. | No (holds the I/O + bridge calls) |
| `dtos/browse.rs` | `Serialize`-only DTOs crossing the IPC boundary. `#[serde(rename_all = "camelCase")]`. No secrets in `read_block`'s DTOs. | Data only |
| `reveal.rs` | Pure helpers: `BlockReadOutput → BlockDetailDto` projection (tombstone-filtered); locate a record by uuid + field by name; base64-encode revealed bytes (zeroizing the intermediate `Vec<u8>`). | Yes |

### Frontend (`src/`)

| Module | Responsibility | Pure? |
|---|---|---|
| `lib/browse.ts` | Browse-nav store: `{level:'blocks'} \| {level:'records',block} \| {level:'fields',block,record}` + `openBlock / openRecord / back / resetBrowse`. No IPC, no DOM. | Yes (state machine) |
| `lib/reveal.ts` | Reveal lifecycle timing: schedule auto-hide, schedule clipboard-clear, cancel on supersede. `setTimeout`/`clearTimeout` injected for tests; no direct DOM/clipboard calls. | Yes (logic) |
| `lib/ipc.ts` (mod) | Add `readBlock(blockUuidHex)` and `revealField(blockUuidHex, recordUuidHex, fieldName)` + DTO interfaces. | Wrapper |
| `lib/errors.ts` (mod) | Add `block_not_found`, `record_not_found`, `field_not_found` to the code union + user messages. | Pure |
| `lib/constants.ts` (mod) | Add `REVEAL_AUTO_HIDE_MS`, `CLIPBOARD_CLEAR_MS` (frontend-only timers; no backend mirror). | Const |
| `components/*` | Render + dispatch only. Clipboard/DOM I/O lives at the component edge, calling `lib/reveal.ts` for timing. | No |

### IPC boundary discipline

`read_block` returns **metadata only** — `RecordDto`/`FieldMetaDto` carry no secret payload. The only path a plaintext crosses IPC is `reveal_field`'s `RevealedFieldDto.value`, produced lazily on an explicit user click and wiped bridge-side immediately after.

## 6. Read path lifecycle

### `read_block(blockUuidHex) -> BlockDetailDto`

1. Parse `blockUuidHex` → `[u8;16]` (`hex`); bad hex → `AppError::Internal` (frontend only ever passes hex it got from the manifest).
2. `with_unlocked(|u| …)` → `secretary_ffi_bridge::read_block(&u.identity, &u.manifest, &uuid)`.
3. Map `FfiVaultError::BlockNotFound` → `AppError::BlockNotFound { blockUuidHex }` (now user-reachable; D.1.1 mapped it to `Internal`).
4. Project to `BlockDetailDto`, **skipping tombstoned records** (`Record::tombstone() == true`; trash/restore is D.1.5).
5. `output.wipe()` before returning (the DTO holds no secrets, but the handle's `FieldHandle`s do).

### `reveal_field(blockUuidHex, recordUuidHex, fieldName) -> RevealedFieldDto`

1. Parse both uuids.
2. `with_unlocked` → re-run `read_block` (stateless; no cached handle).
3. Locate the record by uuid (iterate `record_at(0..record_count())`); not found → `AppError::RecordNotFound`. Locate the field by name (`Record::field_by_name`); not found → `AppError::FieldNotFound`.
4. `is_text()` → `expose_text()` → `RevealedFieldDto { isText: true, value }`. `is_bytes()` → `expose_bytes()` → base64-encode (zeroize the intermediate `Vec<u8>`) → `RevealedFieldDto { isText: false, value }`.
5. `output.wipe()` before returning. The returned `value` String is the documented widening point.

### Backend data shape

```rust
// dtos/browse.rs  (Serialize-only, camelCase wire)
struct BlockDetailDto { block_uuid_hex: String, block_name: String, records: Vec<RecordDto> }
struct RecordDto {
    record_uuid_hex: String, record_type: String, tags: Vec<String>,
    created_at_ms: u64, last_mod_ms: u64, field_count: u64, fields: Vec<FieldMetaDto>,
}
struct FieldMetaDto { name: String, last_mod_ms: u64, is_text: bool, is_bytes: bool }
struct RevealedFieldDto { is_text: bool, value: String } // value = plaintext | base64
```

No `byteLen` on `FieldMetaDto`: the bridge `FieldHandle` exposes no length accessor, and reading one would either need a B-side change or a decrypt-to-measure (defeating the mask). Length is implied post-reveal by the base64.

## 7. Page routes & navigation

`Vault.svelte` switches on the browse-nav store within the existing `unlocked` state — no change to the top-level `App.svelte` session state machine.

```
browse-nav level:  blocks ──openBlock──▶ records ──openRecord──▶ fields
                      ◀──────back───────    ◀──────back───────
```

- `blocks` → existing block-card list (cards now clickable).
- `records` → `RecordList` (fetches `readBlock` on mount; renders `RecordRow`s + breadcrumb/back).
- `fields` → `FieldViewer` (renders `FieldRow`s + breadcrumb/back).
- The `vault-locked` event (idle, manual, or keep-alive failure) resets the nav to `blocks` and clears all reveal/clipboard state + timers — revealed secrets must not survive a lock.

### Store shape (`lib/browse.ts`)

A writable discriminated union with transition helpers (mirroring `stores.ts` discipline — no direct `.set()` from components):

```ts
type BrowseNav =
  | { level: 'blocks' }
  | { level: 'records'; block: BlockSummaryDto }
  | { level: 'fields'; block: BlockSummaryDto; record: RecordDto };
// openBlock(block) · openRecord(record) · back() · resetBrowse()
```

## 8. Reveal & clipboard behaviour

| Behaviour | Rule |
|---|---|
| Default state | Every field masked. |
| Reveal | Explicit click → `revealField` IPC → value held in component state. |
| Auto-hide | Revealed value re-masks after `REVEAL_AUTO_HIDE_MS`; user can re-mask early. Timer cancelled/reset per field. |
| Copy | Click → write `value` to clipboard via the plugin → toast "Copied". |
| Clipboard auto-clear | After `CLIPBOARD_CLEAR_MS`, unconditionally write empty string (best-effort; may clobber newer content — documented tradeoff). |
| Navigate away | `back()` / `openRecord` clears reveal state + pending timers for the leaving view. |
| Lock | `vault-locked` clears all reveal/clipboard state + timers and resets nav. |

`lib/reveal.ts` owns the timer bookkeeping as pure logic (inject `setTimeout`/`clearTimeout`); components call it and perform the actual clipboard/DOM writes.

## 9. Error model

New `AppError` variants (`#[serde(tag = "code", rename_all = "snake_case")]`, mirroring D.1.1):

| Variant | Wire `code` | When | Frontend message |
|---|---|---|---|
| `BlockNotFound { block_uuid_hex }` | `block_not_found` | `read_block` for a uuid absent from the manifest (stale click / concurrent removal) | "Block not found — it may have been removed." |
| `RecordNotFound { record_uuid_hex }` | `record_not_found` | `reveal_field` can't locate the record | "Record not found." |
| `FieldNotFound { field_name }` | `field_not_found` | `reveal_field` can't locate the field | "Field not found." |

These are typed errors, not silent `None`s — consistent with the project's no-silent-failure discipline. `detail`-bearing internal errors stay `#[serde(skip_serializing)]` as in D.1.1. `frontend/errors.ts` adds the three codes to its exhaustive union + the `isAppError` guard's `APP_ERROR_CODES`.

## 10. Testing strategy

| Layer | Tool | D.1.2 coverage |
|---|---|---|
| L1 Rust unit | `cargo test` | `dtos/browse.rs` serde round-trips (camelCase, hex, no secret leakage); `reveal.rs` projection (tombstone filter, field/record locate, base64 + intermediate zeroize); new error wire codes. |
| L2 TS unit | Vitest | `RecordList`/`RecordRow`/`FieldViewer`/`FieldRow` render + interaction (reveal toggles, copy → clipboard mock, auto-hide via fake timers); `browse.ts` nav transitions; `reveal.ts` timing (injected timers); `errors.ts` new codes; `ipc.ts` mocks for `readBlock`/`revealField`. |
| L3 Rust integration | `cargo test` (`tests/ipc_integration.rs`) | Against `golden_vault_001` (known plaintext via `conformance.py`): `read_block_impl` projects records/fields with **no secrets in the DTO** + tombstone filtering; `reveal_field_impl` returns the correct plaintext (text) and base64 (bytes); typed errors for missing block/record/field. |
| L4 e2e | (deferred) | No new e2e; rides on the deferred macOS WebDriver decision (#161). |

Any new test that needs crypto material generates it at runtime (`OsRng`); no hardcoded keys/nonces (CodeQL). Known-plaintext assertions come from the `golden_vault_001` fixture, not inline literals.

### Expanded gauntlet at D.1.2 close

Same commands as D.1.1's close (`cargo test --release --workspace`, clippy `-D warnings`, fmt, `conformance.py`, `spec_test_name_freshness.py`, `pnpm test/typecheck/svelte-check/lint`). Rust count rises by the new unit + integration tests; Vitest by the new component/store/logic tests. Counts recorded in the ship handoff.

## 11. Dependencies (additions)

| Dependency | Where | Pin | Note |
|---|---|---|---|
| `base64` | `desktop/src-tauri/Cargo.toml` | `"0.22"` (matches `core/`) | Already a vetted workspace dep; encodes already-revealed bytes (not on the crypto path). |
| `tauri-plugin-clipboard-manager` | `desktop/src-tauri` + `@tauri-apps/plugin-clipboard-manager` (npm) | latest 2.x | **New capability.** Add **write permission only** in the Tauri capabilities file; no clipboard-read. This is a deliberate capability expansion of a security-sensitive app — call it out in the ship PR for review. |

`hex` (already present) is reused for uuid parsing. No other new deps.

## 12. UX details

- **Record list:** each row = `record_type` (bold) · tag chips · "N fields · modified `DATE`" · chevron. Empty block → "No records." Tombstoned records absent.
- **Field viewer:** each row = field `name` · masked value (`••••••••`) · reveal (👁) / re-mask (🙈) toggle · copy (⧉). Revealed text shows inline; revealed bytes show base64 with a "binary" tag. A revealed row shows a subtle "auto-hides" affordance.
- **Breadcrumb/back:** every nested page shows where you are (`← Banking` / `← login`) and pops one level. `Esc` also pops a level.
- **Toasts:** reuse the D.1.1 `Toast` surface for "Copied" (and copy/clear failures, if any).
- **Styling:** new classes (`.record-list`, `.record-row`, `.field-viewer`, `.field-row`) in `theme.css` (Vite 6 `preprocessCSS` workaround, #153), reusing existing tokens; dark mode inherits.

## 13. Out of scope for D.1.2

| Deferred | To | Why |
|---|---|---|
| Vault create wizard | D.1.3 | No write path yet; the D.1.1 "Not a vault" picker hint becomes actionable here. |
| Add/edit records, `save_block` write path | D.1.4 | Bridge `RecordInput.record_type` gap (#141) matters here, not for read. |
| Share / trash / restore (incl. *showing* tombstones) | D.1.5 | Needs ContactCard + lifecycle semantics. |
| Search / filter, sort | later | UX convenience, not core to read. |
| Non-secret "title" field | (data-model change) | Would change the vault format; deliberately not done. |
| Configurable reveal/clipboard timeouts | later | D.1.2 ships fixed constants; promote to settings if users ask. |
| Byte-length pre-reveal, hex viewer | later / B-side | Needs a bridge accessor or a decrypt-to-measure. |
| Two-pane master/detail layout | post-edit | Revisit once side-by-side earns its keep. |

## 14. Broader project implications

- **README.md:** D-row note advances from "D.1.1 shipped" to "D.1.2 (browse) shipped; D.1.3 (create) next" at ship (brief, per the README style).
- **ROADMAP.md:** mark D.1.2 ✅ at ship; D.1.3 ⏳ next.
- **Capability review:** the clipboard plugin addition is the one item warranting explicit security attention in the ship PR (§11).
- **No spec/format change:** D.1.2 consumes the frozen vault format and the existing B.4b read surface unchanged. `crypto-design.md` / `vault-format.md` / `conformance.py` are untouched.
- **NEXT_SESSION handoff:** authored on the feature branch per the handoff-symlink workflow.

## 15. Acceptance criteria

Mirrors D.1.1's five categories.

1. **Manual smoke (user, pre-merge gate)** — against a **temp copy** of `golden_vault_001` (never the tracked fixture): unlock → click a block → see records → click a record → see masked fields → reveal a text field (correct plaintext) → re-mask / auto-hide → copy → paste elsewhere (matches) → clipboard clears after the timeout → reveal a bytes field (base64) → back navigation works at each level → lock mid-browse clears the revealed value and returns to Unlock.
2. **Automated gauntlet** — all green: `cargo test --release --workspace`, clippy `-D warnings`, fmt, `conformance.py`, `spec_test_name_freshness.py`, `pnpm test / typecheck / svelte-check / lint`.
3. **L4 e2e** — none added (deferred, #161).
4. **Docs** — README + ROADMAP updated; this spec + the implementation plan committed.
5. **Process** — files < 500 LOC (split where heading over), pure functions in `lib/` + `reveal.rs`, no magic numbers (constants), random crypto in any new tests, handoff baton rides inside the ship PR.

## 16. References

- D.1.1 spec — `docs/superpowers/specs/2026-05-27-d11-tauri-walking-skeleton-design.md`
- B.4b read-block spec — `docs/superpowers/specs/2026-05-09-ffi-b4b-read-block-design.md`
- ADR 0007 — `docs/adr/0007-d-row-tauri.md` (Sub-project D → Tauri 2)
- Bridge read surface — `ffi/secretary-ffi-bridge/src/record/{orchestration,output,handle,field}.rs`
- D.1.1 IPC/DTO/error patterns — `desktop/src-tauri/src/{commands,dtos.rs,errors.rs,session.rs}`
- Tauri clipboard plugin — https://v2.tauri.app/plugin/clipboard/
