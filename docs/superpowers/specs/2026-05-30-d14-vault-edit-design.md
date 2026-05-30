# D.1.4 — Edit: desktop vault edit (add / edit records via a lossless write path) (design spec)

**Status:** approved design, pre-plan. Follows D.1.3 (`2026-05-29-d13-create-vault-design.md`), which shipped the first write path (vault create). D.1.4 is the next slice in Sub-project D's feature breadth (browse → create → **edit** → share/trash; see ADR 0007) and the **first write path that mutates an existing vault** — it writes blocks and re-signs the manifest.

This spec mirrors the D.1.1 / D.1.2 / D.1.3 section structure so the four read as a series. Where a prior section has no D.1.4 analogue it is omitted rather than padded.

## 1. What this slice ships

D.1.3 creates an empty vault; D.1.2 reads existing ones. D.1.4 lets a user with an **unlocked** vault put data into it and change it:

- **Create a block** (a named category) — the entry point that makes a freshly-created (empty) vault usable at all.
- **Add a record** into a block — `record_type` (optional), tags, and a dynamic list of **text** and **bytes (base64-entered)** fields.
- **Edit an existing record** — the same editor, prefilled from the record's current values (secret fields revealed on demand, one record's worth), re-saved.
- The browse view (D.1.2) reflects every change.
- **Closes #141** — `RecordInput` gains `record_type` + `tags`, threaded through `into_core_record`; the settings-write workaround is reverted. (Separate from, and in addition to, the new lossless primitives — see §3.)

The non-obvious core of this slice is **not** the UI — it is a new **lossless** bridge write path. Core's `save_block` re-encrypts the *entire* block from supplied plaintext, and the current bridge write/read surface (B.4c) is **lossy**: it drops forward-compat `unknown` maps at block, record, and field level and hardcodes `record_type`/`tags` empty (issue #141). Writing through that surface would silently destroy a future client's data on every save. D.1.4 introduces bridge primitives that operate on the **native decrypted `BlockPlaintext`** so untouched records — and all `unknown` maps — survive byte-faithfully, while the desktop only ever sends the one record being edited.

Out of scope: tombstone/delete a record (D.1.5), share/trash/restore (D.1.5), bytes-field affordances beyond base64, field reordering, rich field types.

## 2. Why this ordering (edit after create)

Create (D.1.3) produced a fresh vault with no manifest mutation and no block writes — it exercised the atomic-write contract in isolation. Edit is the next increment of risk: it **mutates an existing manifest and writes blocks**, and it is where the whole-block-rewrite semantics of `save_block` first bite. Browse (read) and create (fresh write) are both prerequisites: edit reuses the browse projection to show the result, and only a created (or opened) vault can be edited. Shipping edit also closes the loop that D.1.3 opened — a created empty vault was un-fillable until now.

## 3. Architecture approach

Core already exposes the complete write entry point: `secretary_core::vault::save_block(folder, &mut OpenVault, BlockPlaintext, recipients, device_uuid, now_ms, &mut rng)` — insert-or-update by `block_uuid`, atomic block write + manifest re-sign, owner-as-recipient. **Core is frozen and unchanged.** The work is at the **bridge** layer (Sub-project B, not frozen) and above.

The desktop's unlocked session already holds the bridge `UnlockedIdentity` + manifest handle (D.1.2 browse calls bridge `read_block` through them), so the new write primitives belong in the **bridge** and the desktop calls them through the session — exactly as browse does.

| Decision | Choice | Rationale |
|---|---|---|
| Block ↔ UI model | **Blocks = named categories holding many records** (matches the D.1.2 browse hierarchy) | The natural password-manager UX (folders of entries). The exposure cost of multi-record blocks is contained by the next decision. |
| Whole-block plaintext exposure | **Confined to the bridge (Rust); the JS side only ever holds the one record being edited** | `save_block` rewrites the whole block, but the untouched plaintext never crosses the IPC seam into JS. Preserves D.1.2's "reveal one secret at a time" discipline at the boundary. |
| Forward-compat `unknown` | **Preserved via native in-bridge edit** — untouched records stay `core::Record`, never lowered through the lossy `RecordInput` | The current bridge drops `unknown` at all three levels (verified: `record/orchestration.rs:165` read side, `save/input.rs:92` write side). Routing edits around the lossy types is the only structurally-correct fix; relying on "no second client exists yet" is exactly the assumption this project refuses to make. |
| #141 (`RecordInput` lacks `record_type`/`tags`) | **Closed in D.1.4** — add `record_type` + `tags` to `RecordInput`, thread through `into_core_record`, mirror on the uniffi/pyo3 wrappers, revert the settings workaround | The editor itself uses the new `RecordContent` primitives, but we also bring the raw `save_block(BlockInput)`/`RecordInput` path to type/tags parity so no latent debt remains. `unknown` is **not** added to `RecordInput`: that path constructs records from scratch (its sole user, the settings single-record block, has no siblings and no pre-existing unknowns — empty `unknown` is correct there). Sibling-`unknown` preservation is the job of the native primitives, not this path. |
| Write API shape | **Three native bridge primitives** (`create_block`, `append_record`, `edit_record`) taking a `RecordContent` delta | Reusable by every platform UI (iOS/Android/Python), not duplicated per client. The desktop command layer becomes a thin pass-through. |
| Edit prefill | **One-record reveal** (`reveal_record`) exposing only the target record's fields to JS | Siblings are never exposed to JS; the edited record's own fields cross the seam only on an explicit edit, mirroring D.1.2 field reveal. |
| Recipients | **Owner-only, auto-derived by the bridge** (unchanged) | v1 single-author; `snapshot_for_save_block` already yields the owner card. The desktop supplies no recipients. Multi-recipient is B.4d. |

## 4. Project layout (additions)

```
ffi/secretary-ffi-bridge/src/
  edit/                    NEW dir — native-BlockPlaintext write primitives
    mod.rs                   create_block / append_record / edit_record orchestration
    content.rs               RecordContent / FieldContent input types (zeroize-typed values)
    mod.rs                   create_block / append_record / edit_record — re-exported from lib.rs
  save/input.rs            MODIFIED — #141: RecordInput gains record_type + tags; into_core_record threads both
ffi/secretary-ffi-uniffi/src/
  secretary.udl + wrappers/save.rs   MODIFIED — #141: RecordInput wrapper gains record_type + tags (Swift/Kotlin contract)
ffi/secretary-ffi-py/src/
  save.rs                  MODIFIED — #141: RecordInput wrapper gains record_type + tags (Python contract)
  # NOTE: the three NEW edit primitives are NOT mirrored on uniffi/pyo3 in D.1.4
  # (the desktop consumes the bridge directly; no mobile/Python UI exists yet).
  # Deferred to a tracking issue — see §13.
desktop/src-tauri/src/
  commands/
    edit.rs                NEW — create_block / save_record / save_record_edit / reveal_record (+ *_impl)
  dtos/
    edit.rs                NEW — RecordInputDto, FieldInputDto, FieldValueDto, RecordRefDto, RecordRevealDto
    mod.rs                 MODIFIED — re-export edit DTOs
  errors.rs                MODIFIED — BlockNotFound, RecordNotFound, InvalidFieldValue, RecordSaveFailed
  settings/io.rs           MODIFIED — #141: revert the empty-record_type HACK now that RecordInput carries it
  main.rs                  MODIFIED — register the four new commands
desktop/src/
  lib/
    editor.ts              NEW — pure record-draft model: validation + transforms + DTO mapping
    ipc.ts                 MODIFIED — createBlock, saveRecord, saveRecordEdit, revealRecord + DTO interfaces
    errors.ts              MODIFIED — new codes + messages
    browse.ts              MODIFIED — BrowseNav gains newBlock / newRecord / editRecord states
  components/
    edit/                  NEW dir — one concept per file (< 500 LOC each)
      RecordEditor.svelte      host: draft $state, type/tags/fields, Save/Cancel, save dispatch
      FieldRowEditor.svelte    one field row: name + text/bytes toggle + value + remove
      TagsEditor.svelte        add/remove tag chips
      NewBlock.svelte          block-name form → createBlock
  routes/
    Vault.svelte           MODIFIED — route browse stack to editor panes; add entry buttons
```

The `edit/` dirs (bridge + components) keep each concept a small, single-purpose file; hosts only route/dispatch.

## 5. Module decomposition + responsibilities

### Bridge (`ffi/secretary-ffi-bridge/src/edit/`)

| Module | Responsibility | Pure? |
|---|---|---|
| `edit/mod.rs` | Three free functions over the session's `UnlockedIdentity` + manifest handle. Each (for append/edit) decrypts the target block to a **native `core::BlockPlaintext`** (via the same core decrypt path browse uses, but **kept native** — not lowered to `Record` handles), mutates only the target, and calls `core::vault::save_block`. Untouched `core::Record`s — and their `unknown`/timestamps/tombstone state — are passed straight back. | No (decrypt + core call) |
| `edit/content.rs` | `RecordContent { record_type: String, tags: Vec<String>, fields: Vec<FieldContent> }`; `FieldContent { name: String, value: FieldInputValue }` where `FieldInputValue = Text(SecretString) \| Bytes(SecretBytes)` (zeroize-typed, reused from `save/input.rs`). The desktop-authored editable delta only. | Data (zeroizing) |
| `save/input.rs` (mod, **#141**) | Add `record_type: String` + `tags: Vec<String>` to `RecordInput`; `into_core_record` threads both (drops the two hardcodes). Mirrored on the uniffi/pyo3 `RecordInput` wrappers. Independent of the editor (which uses `RecordContent`); closes the latent debt. | Data |

`unknown` preservation rules (the correctness keystone — §6.4):
- **block-level** `unknown` → carried forward verbatim (the native `BlockPlaintext.unknown` is never rebuilt).
- **record-level** `Record.unknown` → on edit, the target record's map is carried forward; siblings keep theirs natively; a new record gets an empty map.
- **field-level** `RecordField.unknown` → on edit, fields are **name-matched**: an edited/kept field carries forward its own `unknown` sub-keys; a field absent from the delta is dropped *with* its unknowns (the user deleted it — correct); a new field gets an empty map.

### Backend (`desktop/src-tauri/src/`)

| Module | Responsibility | Pure? |
|---|---|---|
| `commands/edit.rs` | Thin `#[tauri::command]` wrappers + `*_impl` for `create_block`, `save_record`, `save_record_edit`, `reveal_record`. Each `*_impl` validates input (base64 decode → typed error), maps the DTO to `RecordContent`, calls the bridge primitive through the session, maps bridge errors to typed `AppError`. `reveal_record_impl` decrypts the target block, locates the one record, exposes its fields, returns a `RecordRevealDto` (siblings untouched). | No (bridge/session call) |
| `dtos/edit.rs` | `Deserialize` `RecordInputDto`/`FieldInputDto`/`FieldValueDto` (inbound, secret-bearing — **`Debug` redacted**); `Serialize` `RecordRefDto { block_uuid_hex, record_uuid_hex }` and `RecordRevealDto { fields: Vec<RevealedFieldDto> }`. All `#[serde(rename_all = "camelCase")]`; `FieldValueDto` is `#[serde(tag = "kind", rename_all = "camelCase")]`. | Data only |
| `errors.rs` (mod) | Add `BlockNotFound { block_uuid_hex }`, `RecordNotFound { record_uuid_hex }`, `InvalidFieldValue { field_name }`, `RecordSaveFailed { detail #[serde skip] }`. | Pure |

### Frontend (`src/`)

| Module | Responsibility | Pure? |
|---|---|---|
| `lib/editor.ts` | The record-draft model. `emptyDraft()`, `recordToDraft(reveal)` (prefill from `RecordRevealDto`), field/tag transforms (`addField`/`removeField`/`setFieldKind`/`addTag`/`removeTag`), `validateRecordDraft(draft) -> ValidationResult` (field name required + unique, base64 well-formed), `draftToRecordInputDto(draft)`, `isValidBase64(s)`. No IPC, no DOM. | Yes |
| `lib/ipc.ts` (mod) | `createBlock(blockName)`, `saveRecord(blockUuidHex, recordInput)`, `saveRecordEdit(blockUuidHex, recordUuidHex, recordInput)`, `revealRecord(blockUuidHex, recordUuidHex)` + DTO interfaces. | Wrapper |
| `lib/errors.ts` (mod) | Add the four codes to the exhaustive union + `APP_ERROR_CODES` + user messages. | Pure |
| `lib/browse.ts` (mod) | Extend `BrowseNav` with `{level:'newBlock'}`, `{level:'newRecord',block}`, `{level:'editRecord',block,record}` + transition helpers (`openNewBlock`, `openNewRecord`, `openEditRecord`) and the existing `back()`. | Yes |
| `components/edit/*` | Render + dispatch only. The draft's secret values live in `RecordEditor` local `$state`, cleared right after a successful save (mirrors D.1.3 `CredentialsStep`). | No |
| `routes/Vault.svelte` (mod) | Route the browse stack to `NewBlock`/`RecordEditor` panes; add "New block" / "Add record" / "Edit" entry buttons to the existing panes. | No |

### IPC boundary discipline

`create_block` returns a metadata-only `BlockSummaryDto` (reuses D.1.2's type; no secrets). `save_record`/`save_record_edit` take one `RecordInputDto` (the only secret-bearing inbound payload, redacted `Debug`) and return a `RecordRefDto` (two hex ids, no secrets). `reveal_record` returns only the **one** target record's field values — never a sibling's. No primitive ever lowers a sibling record's plaintext to JS.

## 6. Edit path lifecycle

### 6.1 `create_block(blockName) -> BlockSummaryDto`

1. Fresh random `block_uuid` (`OsRng`).
2. Bridge `create_block` builds a native `BlockPlaintext { block_uuid, block_name, records: vec![], unknown: empty, .. }` → `core::vault::save_block` (insert path; owner-only recipient).
3. Return the new block's `BlockSummaryDto` so the blocks list refreshes. Empty blocks are valid (format permits `records: []`).

### 6.2 `save_record(blockUuidHex, recordInput) -> RecordRefDto` (add)

1. `*_impl` decodes/validates `recordInput` (base64 fields → `SecretBytes`; bad base64 → `InvalidFieldValue`), maps to `RecordContent`.
2. Bridge `append_record`: decrypt block → native `BlockPlaintext`; **append** a new `core::Record` (fresh `record_uuid`, `created_at = last_mod = now_ms`, empty `unknown`) built from `RecordContent`; siblings untouched (native) → `core::vault::save_block`.
3. Return `RecordRefDto { block_uuid_hex, record_uuid_hex }`. Block missing → `BlockNotFound`.

### 6.3 `save_record_edit(blockUuidHex, recordUuidHex, recordInput) -> RecordRefDto` (edit)

1. As 6.2 step 1.
2. Bridge `edit_record`: decrypt block → native `BlockPlaintext`; locate the record by `record_uuid` (missing/tombstoned → `RecordNotFound`); **replace** its `record_type`/`tags`/`fields` from `RecordContent` while **preserving** `record_uuid`, `created_at_ms`, record-level `unknown`, and (name-matched) per-field `unknown`; bump `last_mod_ms = now_ms`; siblings untouched → `core::vault::save_block`.
3. Return `RecordRefDto`.

### 6.4 `reveal_record(blockUuidHex, recordUuidHex) -> RecordRevealDto` (edit prefill)

1. Decrypt the block, locate the one live record.
2. For each field, expose `is_text` + value (text plaintext, or base64 for bytes) into `RecordRevealDto`. **Only this record's fields** are exposed; siblings are not.
3. The decrypted material drops (zeroized) when `*_impl` returns; the frontend holds it in `RecordEditor` `$state` until save, then clears it.

### Backend data shape

```rust
// dtos/edit.rs  (camelCase wire)
// inbound, secret-bearing — Debug redacted
struct RecordInputDto { record_type: String, tags: Vec<String>, fields: Vec<FieldInputDto> }
struct FieldInputDto  { name: String, value: FieldValueDto }
enum   FieldValueDto  { Text { text: String }, Bytes { base64: String } }  // #[serde(tag="kind")]
// outbound, no secrets
struct RecordRefDto    { block_uuid_hex: String, record_uuid_hex: String }
struct RecordRevealDto { fields: Vec<RevealedFieldDto> }  // RevealedFieldDto: { name, is_text, value } (D.1.2 shape + name)
```

## 7. Page routes & navigation

The unlocked browse view already navigates a stack via the `browseNav` store (`blocks → records → fields`). The editor slots in as **new states on that same stack** — not a modal, not a pre-unlock `appRoute` (the vault is open):

```
blocks ──"New block"──▶ newBlock ──createBlock()──▶ (back to) blocks
   │
records (of a block) ──"Add record"──▶ newRecord ──saveRecord()──▶ (back to) records
   │
fields (of a record) ──"Edit"──▶ editRecord ──revealRecord()→prefill→saveRecordEdit()──▶ (back to) fields
```

Back button + breadcrumb work uniformly. On a successful save the stack pops to the parent pane, which re-fetches so the change shows. Cancel pops without writing.

## 8. Record editor & secret-handling behaviour

| Behaviour | Rule |
|---|---|
| Field-value types | Editor creates/edits **text** (`Text(SecretString)`) and **bytes** (`Bytes(SecretBytes)`, entered/edited as validated base64). |
| `record_type` | Optional free-text (empty allowed; browse renders typeless records). No enforced vocabulary in v1. |
| Tags | List of trimmed-non-empty strings; duplicates collapsed; add/remove chips. |
| Field names | Required and **unique within the record** — enforced at the UI (the bridge collapses dup names last-write-wins; we prevent it so the user isn't surprised by silent loss). |
| Edit prefill | `reveal_record` exposes the **one** target record's fields; text prefills plaintext, bytes prefills base64. Source of truth for *untouched siblings* is the native bridge round-trip, never JS state. |
| Draft secrets | Held only in `RecordEditor` local `$state`; cleared right after a successful save. Never placed in any store, logged, or cached. |
| Backend wipe | The bridge's decrypted `BlockPlaintext` and the command's `RecordContent` (zeroize-typed values) drop (zeroize) when the call returns. |
| Whole-block exposure | Exists only transiently inside the bridge per save; never crosses the IPC seam into JS. |

## 9. Error model

New `AppError` variants (`#[serde(tag = "code", rename_all = "snake_case")]`, mirroring D.1.1–D.1.3):

| Variant | Wire `code` | When | Frontend message |
|---|---|---|---|
| `BlockNotFound { block_uuid_hex }` | `block_not_found` | save/edit/reveal targets a missing block | "That block no longer exists. Refresh and try again." |
| `RecordNotFound { record_uuid_hex }` | `record_not_found` | edit/reveal targets a missing or tombstoned record | "That record no longer exists. Refresh and try again." |
| `InvalidFieldValue { field_name }` | `invalid_field_value` | a bytes field's value isn't valid base64 (or an empty/dup name slips through) | "The value for '<field>' isn't valid." |
| `RecordSaveFailed { detail (skip) }` | `record_save_failed` | bridge/core `save_block` returned an error | "Couldn't save your changes. Please try again." |

Typed errors, not silent `None`s. `detail` stays `#[serde(skip_serializing)]` (logged via `tracing` on a structural `VaultError` Display — no secret bytes). `frontend/errors.ts` adds the four codes to its exhaustive union + `APP_ERROR_CODES`.

## 10. Testing strategy

| Layer | Tool | D.1.4 coverage |
|---|---|---|
| L1 Rust unit (bridge) | `cargo test` | `RecordContent`/`FieldContent` zeroize-on-drop; `edit/mod.rs` mutation helpers in isolation (name-matched field-`unknown` carry-forward; record-level `unknown` carry-forward; new-record empty `unknown`). |
| L1 Rust unit (desktop) | `cargo test` | `dtos/edit.rs` serde round-trips (camelCase, `kind`-tag); `RecordInputDto` `Debug` redaction (`record_input_debug_is_redacted`); base64 decode boundary → `InvalidFieldValue`; new error wire codes. |
| L2 TS unit | Vitest | `lib/editor.ts` validation (dup/empty names, bad base64), draft transforms, `draftToRecordInputDto`, `recordToDraft` prefill; `lib/browse.ts` new transitions; `RecordEditor`/`FieldRowEditor`/`TagsEditor`/`NewBlock` interaction (save/cancel, disabled-while-invalid, type toggle, add/remove); `errors.ts` new codes; `ipc.ts` mocks. |
| L3 Rust integration | `cargo test` | Over **ephemeral tempdirs** with **runtime-random** crypto: `create_block` then `append_record` then `read_block` reflects it; `edit_record` replaces by uuid and re-opens; **the correctness keystones** — (a) editing record A in a block with B & C leaves B/C **byte-faithful**; (b) a block/record/field carrying synthetic `unknown` keys retains them across an edit at **all three levels** (build a native `BlockPlaintext` with unknowns, save it, edit one record via the primitive, assert unknowns survive); `BlockNotFound`/`RecordNotFound`/base64-`InvalidFieldValue` fire as typed errors. |
| Cross-language conformance | swift/kotlin scripts | The only binding-contract change in D.1.4 is the #141 `RecordInput` fields (`save.rs` wrappers + the UDL `RecordInput` dictionary). The new edit primitives are **bridge-only** (not mirrored on uniffi/pyo3 — §13), so they add no binding surface; they're covered by Rust unit + integration tests. The conformance KAT **is** regenerated: the `generate_conformance_kat` test builds a `RecordInput` for `save_block_insert_happy`, so adding `record_type` flows into `read_block_happy.expected.records[*].record_type` (`""` → the supplied type). The diff is scoped to `read_block_happy.expected.records` and human-reviewed before commit; the swift/kotlin scripts then replay it green. |
| L4 e2e | (deferred) | No new e2e; rides on the deferred macOS WebDriver decision (#161). |

Any new test that needs crypto material generates it at runtime (`OsRng`); no hardcoded keys/passwords (CodeQL). No reliance on the golden fixture for writes (assertions round-trip through a freshly-created tempdir vault).

### Expanded gauntlet at D.1.4 close

Same commands as D.1.3's close (`cargo test --release --workspace`, clippy `-D warnings`, fmt, `conformance.py`, `spec_test_name_freshness.py`, the swift/kotlin conformance scripts, `pnpm test / typecheck / svelte-check / lint`). Rust count rises by the new bridge + desktop unit + integration tests; Vitest by the new editor logic/component tests. Counts recorded in the ship handoff.

## 11. Dependencies (additions)

No new Cargo or npm dependencies are anticipated:

- `zeroize` / `secretary-core` types back `RecordContent`/`FieldContent` and the decrypt+save path (all already deps).
- A base64 codec is already in the workspace (the D.1.2 reveal path base64-encodes bytes); the same crate decodes here. If the exact decode helper isn't already exposed, it's a workspace-vetted call-out in the plan, not a new dependency.
- uniffi/pyo3 wrapper additions reuse the existing binding crates (no new dep; codegen regenerates — watch for uniffi's codegen-driven renames, a known wrinkle).

## 12. UX details

- **Blocks pane:** a "New block" button → `NewBlock` pane (name field → `createBlock`).
- **Records pane:** an "Add record" button → `RecordEditor` (empty draft).
- **Fields pane:** an "Edit" button → `RecordEditor` prefilled via `revealRecord`.
- **Record editor:** `record_type` input; `TagsEditor` chips; a list of `FieldRowEditor` rows (name + text/bytes toggle + value; bytes shows a base64 hint and inline "not valid base64" state); "Add field" / per-row remove; Save disabled while invalid; Cancel pops without writing.
- **Styling:** new classes (`.editor`, `.field-row`, `.tags-editor`, …) in `theme.css` (Vite 6 `preprocessCSS` workaround, #153), reusing existing tokens; dark mode inherits. Any new glyph follows the emoji→SVG carry-forward (#154).

## 13. Out of scope for D.1.4

| Deferred | To | Why |
|---|---|---|
| Tombstone / delete a record | D.1.5 | A distinct destructive flow with its own confirm UX; `save_block` already carries tombstone semantics, so it's a clean follow-on. |
| Share / trash / restore | D.1.5 | Needs ContactCard exchange + lifecycle semantics. |
| Bytes-field affordances beyond base64 (file picker, TOTP-seed import) | later | base64 entry covers authoring in v1; richer input is a UX add-on. |
| Field reordering, rich field types (date/number), per-field metadata editing | later | Out of the minimal add/edit vertical. |
| Multi-recipient blocks | B.4d | Bridge is owner-only by design; not a desktop concern yet. |
| uniffi/pyo3 wrappers for the 3 new edit primitives | tracking issue (filed at ship) | The desktop consumes the bridge directly (path dep), so the primitives need only land in the bridge for D.1.4; no mobile/Python UI consumes them yet. Mirroring (+ Swift/Kotlin/Python conformance) is deferred to when such a consumer exists. #141's `RecordInput` mirroring is **not** deferred — it's on the shared `save_block` surface that conformance replay exercises. |
| `unknown` round-trip on the raw `RecordInput` path | (declined) | #141 closure adds `record_type`/`tags` to `RecordInput`, not `unknown`. The raw path builds records from scratch (sole user: the settings single-record block, no siblings/unknowns), so empty `unknown` is correct there; sibling-`unknown` preservation is the native primitives' job. |

### Verified facts (recorded; the design depends on them)

- Core preserves `unknown` at block (`BlockPlaintext.unknown`), record (`Record.unknown`), and field (`RecordField.unknown`) level (§6.3.2; `core/src/vault/{block,record}.rs`).
- The current bridge **drops** `unknown` on read (`record/orchestration.rs:165` — "unknown / tombstoned_at_ms intentionally not surfaced") and **hardcodes it empty** on write (`save/input.rs:92`, `:104`, `:117`, `:151`). This is why the editor uses native in-bridge primitives rather than the existing handle/`RecordInput` round-trip.
- `core::vault::save_block` re-encrypts the **whole** block, preserving only the existing manifest entry's `created_at_ms` + vector-clock summary; everything else comes from the supplied `BlockPlaintext` (`orchestrators.rs:907-918`). This is the reason untouched records must be carried natively.
- The bridge derives the recipient set as `[owner_card]` from `snapshot_for_save_block` (`save/orchestration.rs`); the desktop supplies no recipients.

## 14. Broader project implications

- **README.md:** D-row note advances from "D.1.3 (create) shipped" to "D.1.4 (edit) shipped; D.1.5 (delete/share) next" at ship (brief, per the README style).
- **ROADMAP.md:** mark D.1.4 ✅ at ship; D.1.5 ⏳ next.
- **Security review surface:** the new write path's secret-handling story — whole-block plaintext confined to the bridge, the one-record reveal seam, the `RecordInputDto` redaction, and the `unknown`-preservation correctness — are the items warranting explicit attention in the ship PR.
- **No spec/format change:** D.1.4 consumes the frozen vault format and the existing core `save_block` orchestrator unchanged. `crypto-design.md` / `vault-format.md` / `conformance.py` are untouched; the conformance KAT is regenerated only if the #141 write-then-read scenario emits non-empty `record_type`/`tags` (scoped, human-reviewed — §10).
- **#141 closed:** `RecordInput` gains `record_type` + `tags` across the bridge + uniffi + pyo3 contracts; the settings-write `HACK`/`NOTE(#141)` workaround in `desktop/src-tauri/src/settings/io.rs` is reverted.
- **Bridge surface grows:** the three new primitives are new public bridge API (and uniffi/pyo3 contract), additive alongside the #141-extended `RecordInput`. Existing read/create surfaces are unchanged.
- **NEXT_SESSION handoff:** authored on the feature branch per the handoff-symlink workflow.

## 15. Acceptance criteria

Mirrors D.1.1–D.1.3's five categories.

1. **Manual smoke (user, pre-merge gate)** — against a **tempdir copy** (never the tracked golden fixture): unlock → create a block → add a record (text field + bytes-as-base64 field + a tag + a type) → browse reflects it → reveal the fields and confirm they match → edit a field value and re-save → confirm the change shows and any sibling records in the block are intact → re-open the vault and confirm persistence. A bad base64 bytes value shows the typed "isn't valid" message; a name collision is prevented in the editor.
2. **Automated gauntlet** — all green: `cargo test --release --workspace`, clippy `-D warnings`, fmt, `conformance.py`, `spec_test_name_freshness.py`, the swift/kotlin conformance scripts, `pnpm test / typecheck / svelte-check / lint`.
3. **L4 e2e** — none added (deferred, #161).
4. **Docs** — README + ROADMAP updated; this spec + the implementation plan committed.
5. **Process** — files < 500 LOC (split where heading over), pure functions in `lib/editor.ts` + bridge/desktop helpers, no magic numbers, random crypto in any new tests, the `unknown`-preservation keystone tests present and passing, handoff baton rides inside the ship PR.

## 16. References

- D.1.3 spec — `docs/superpowers/specs/2026-05-29-d13-create-vault-design.md`
- D.1.2 spec — `docs/superpowers/specs/2026-05-29-d12-browse-design.md`
- D.1.1 spec — `docs/superpowers/specs/2026-05-27-d11-tauri-walking-skeleton-design.md`
- ADR 0007 — `docs/adr/0007-d-row-tauri.md` (Sub-project D → Tauri 2)
- Core save path — `core/src/vault/orchestrators.rs::save_block`; block encrypt/decrypt + `unknown` handling — `core/src/vault/block.rs`; record/field `unknown` — `core/src/vault/record.rs`
- Bridge write surface (existing, lossy) — `ffi/secretary-ffi-bridge/src/save/{orchestration,input}.rs`
- Bridge read surface (drops `unknown`) — `ffi/secretary-ffi-bridge/src/record/{orchestration,handle,field}.rs`
- Issue #141 — bridge `RecordInput` lacks `record_type`; settings workaround in `desktop/src-tauri/src/settings/io.rs`
- D.1.1/D.1.2/D.1.3 IPC/DTO/error/secret-boundary patterns — `desktop/src-tauri/src/{commands,dtos,errors.rs,secret_arg.rs}`, `desktop/src/lib/{ipc,errors,browse,create}.ts`
