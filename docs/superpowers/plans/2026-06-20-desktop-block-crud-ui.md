# Desktop block-CRUD UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the existing `rename_block` and `move_record` FFI-bridge ops into the desktop (Tauri) UI, completing the block-CRUD tier on the third platform with parity to Android/iOS.

**Architecture:** Two new `#[tauri::command]` shells + testable `*_impl` helpers in `commands/edit.rs` call the already-depended-on `secretary-ffi-bridge` primitives, enforcing typed guards (`AppError::InvalidArgument`). A new desktop-scoped `AppError::InvalidArgument` variant is added on both the Rust and TS sides. Thin `ipc.ts` wrappers expose them. The frontend re-uses a generalized `BlockNameDialog` (create + rename) page and a new `MoveTargetPicker` modal, with pure-function pre-checks in `lib/blockCrud.ts` (defense in depth — the Rust command is authoritative).

**Tech Stack:** Rust (Tauri 2, `secretary-ffi-bridge`), Svelte 5 (runes), TypeScript, vitest + `@testing-library/svelte`, pnpm.

## Global Constraints

- **Desktop-UI-only slice.** No changes to `core/`, the crypto/vault spec, any `*.udl`, the uniffi/pyo3 projections, Android, or iOS. (Guardrail greps in the final task must come back empty for `core/ | crypto-design | vault-format | \.udl | secretary-ffi-py | android/ | ios/`.)
- **Desktop bypasses the uniffi wrapper** — it calls `secretary-ffi-bridge` directly. The bridge trusts its caller (no same-block / UUID-length guard). Desktop must enforce the same-block-move guard and blank-name rejection itself.
- **`AppError::InvalidArgument` is desktop-scoped** — it is *not* `FfiVaultError`; the Swift/Kotlin conformance harnesses and pyo3/uniffi are untouched.
- **`detail` fields are `#[serde(skip_serializing)]`** on the Rust `AppError` (developer-facing only). So the wire form of the new variant is `{"code":"invalid_argument"}` with NO detail — the TS union member is `{ code: 'invalid_argument' }` (no `detail`), exactly like `record_save_failed`.
- **Tests use a fresh ephemeral vault** via the existing `unlocked_session_over_new_vault()` harness (never mutate the tracked golden fixture; the fresh-vault harness is the established write-path pattern in `ipc_integration.rs`).
- **pnpm, not npm**, for the desktop frontend (`cd desktop && pnpm test`). After editing any `.svelte` attribute, also run `pnpm svelte-check` (smart-quote regressions escape eslint).
- **Run `cargo fmt --all` + `cargo clippy --release --workspace --tests -- -D warnings`** before each Rust commit; clippy must stay clean.
- **Blank-name rejection is a UI policy** applied uniformly (create + rename) in `BlockNameDialog` — this intentionally tightens the previously-permissive create dialog to match Android/iOS + improve UX. The FFI/spec still permit empty names; we do not change the `create_block` command.

---

### Task 1: `AppError::InvalidArgument` typed error (Rust + TS surfaces)

**Files:**
- Modify: `desktop/src-tauri/src/errors.rs` (add enum variant)
- Test: `desktop/src-tauri/src/errors.rs` (inline `#[cfg(test)]` — serialization)
- Modify: `desktop/src/lib/errors.ts` (`APP_ERROR_CODES` + `AppError` union + `userMessageFor` case)
- Test: `desktop/tests/errorsInvalidArgument.test.ts` (new)

**Interfaces:**
- Produces (Rust): `AppError::InvalidArgument { detail: String }` — serializes to `{"code":"invalid_argument"}` (detail stripped).
- Produces (TS): union member `{ code: 'invalid_argument' }`; `'invalid_argument'` in `APP_ERROR_CODES`; a `userMessageFor` arm.

- [ ] **Step 1: Write the failing Rust serialization test**

Add to the existing `#[cfg(test)] mod tests` in `desktop/src-tauri/src/errors.rs` (mirror an existing detail-strip test):

```rust
#[test]
fn invalid_argument_serializes_without_detail() {
    let err = AppError::InvalidArgument {
        detail: "source_block_uuid and target_block_uuid must differ".into(),
    };
    let v = serde_json::to_value(&err).expect("serialize");
    assert_eq!(v, serde_json::json!({ "code": "invalid_argument" }));
}
```

- [ ] **Step 2: Run it; verify it fails to compile (variant missing)**

Run: `cd desktop/src-tauri && cargo test --test '' invalid_argument_serializes 2>&1 | tail -5` (or `cargo test -p secretary-desktop invalid_argument`)
Expected: compile error `no variant named InvalidArgument`.

- [ ] **Step 3: Add the variant**

In `desktop/src-tauri/src/errors.rs`, inside `pub enum AppError`, add (next to `InvalidFieldValue` / `RecordSaveFailed`):

```rust
    /// A frontend-supplied argument was semantically invalid (blank block
    /// name on rename; same-block move). The bridge trusts its caller, so
    /// desktop enforces these guards here. `detail` is developer-facing only.
    #[error("Invalid request")]
    InvalidArgument {
        #[serde(skip_serializing)]
        detail: String,
    },
```

- [ ] **Step 4: Run the Rust test; verify it passes**

Run: `cd desktop/src-tauri && cargo test -p secretary-desktop invalid_argument`
Expected: PASS.

- [ ] **Step 5: Write the failing TS test**

Create `desktop/tests/errorsInvalidArgument.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { APP_ERROR_CODES, userMessageFor } from '../src/lib/errors';

describe('invalid_argument AppError', () => {
  it('is a known error code', () => {
    expect(APP_ERROR_CODES).toContain('invalid_argument');
  });
  it('maps to a user message', () => {
    const msg = userMessageFor({ code: 'invalid_argument' });
    expect(msg.title).toBeTruthy();
  });
});
```

- [ ] **Step 6: Run it; verify it fails**

Run: `cd desktop && pnpm vitest run tests/errorsInvalidArgument.test.ts`
Expected: FAIL (`invalid_argument` not in `APP_ERROR_CODES`; tsc/runtime).

- [ ] **Step 7: Extend the TS error surface**

In `desktop/src/lib/errors.ts`:
1. Add `'invalid_argument',` to the `APP_ERROR_CODES` array (before `'internal'`).
2. Add to the `AppError` union (near `invalid_field_value`): `| { code: 'invalid_argument' }`.
3. Add a `userMessageFor` case (near `invalid_field_value`):

```ts
    case 'invalid_argument':
      return {
        title: 'Invalid request',
        actionHint: 'Check the value and try again.'
      };
```

- [ ] **Step 8: Run the TS test; verify it passes**

Run: `cd desktop && pnpm vitest run tests/errorsInvalidArgument.test.ts`
Expected: PASS.

- [ ] **Step 9: Format, lint, commit**

```bash
cd desktop/src-tauri && cargo fmt --all && cargo clippy --release --workspace --tests -- -D warnings
cd /Users/hherb/src/secretary/.worktrees/desktop-block-crud-ui
git add desktop/src-tauri/src/errors.rs desktop/src/lib/errors.ts desktop/tests/errorsInvalidArgument.test.ts
git commit -m "feat(desktop): add desktop-scoped AppError::InvalidArgument"
```

---

### Task 2: `rename_block` Tauri command + impl (Rust)

**Files:**
- Modify: `desktop/src-tauri/src/commands/edit.rs` (add command + impl; add bridge import)
- Modify: `desktop/src-tauri/src/main.rs:87` (register `edit::rename_block`)
- Test: `desktop/src-tauri/tests/ipc_integration.rs` (in the `mod` containing `create_block_then_add_record_then_read_reflects_it`, ~line 761)

**Interfaces:**
- Consumes: `secretary_ffi_bridge::rename_block(identity, manifest, block_uuid: [u8;16], new_block_name: String, device_uuid: [u8;16], now_ms: u64) -> Result<(), FfiVaultError>`; `AppError::InvalidArgument` (Task 1); existing `map_save_error`, `parse_uuid_16`, `lock_session`, `now_ms`, `block_summary_for`, `new_uuid_16`.
- Produces: `rename_block_impl(state: &Mutex<VaultSession>, block_uuid_hex: &str, new_name: &str) -> Result<BlockSummaryDto, AppError>` and the `#[tauri::command] rename_block` shell.

- [ ] **Step 1: Write the failing integration tests**

Add to `desktop/src-tauri/tests/ipc_integration.rs`, in the same `mod` as `create_block_then_add_record_then_read_reflects_it`:

```rust
#[test]
fn rename_block_changes_name() {
    let (state, _dir, _pw) = unlocked_session_over_new_vault();
    let block = edit::create_block_impl(&state, "Before").expect("create_block");
    let renamed = edit::rename_block_impl(&state, &block.block_uuid_hex, "After")
        .expect("rename_block");
    assert_eq!(renamed.block_name, "After");
    // Manifest reflects it on a fresh read.
    let summary = secretary_desktop::commands::vault::list_blocks_impl(&state)
        .expect("list_blocks")
        .into_iter()
        .find(|b| b.block_uuid_hex == block.block_uuid_hex)
        .expect("block present");
    assert_eq!(summary.block_name, "After");
}

#[test]
fn rename_block_blank_name_is_invalid_argument() {
    let (state, _dir, _pw) = unlocked_session_over_new_vault();
    let block = edit::create_block_impl(&state, "Keep").unwrap();
    let err = edit::rename_block_impl(&state, &block.block_uuid_hex, "   ")
        .expect_err("blank name must be rejected");
    assert!(matches!(err, AppError::InvalidArgument { .. }), "got {err:?}");
}
```

> Note: confirm the `list_blocks` impl name by grepping `commands/vault.rs` for `pub fn list_blocks_impl`; if it differs, use `browse::read_block_impl` on the block and assert the returned `block_name`, or project via the existing helper used by `create_block_impl` (`block_summary_for`). Pick whichever exists; do not invent a name.

- [ ] **Step 2: Run; verify it fails**

Run: `cd desktop/src-tauri && cargo test -p secretary-desktop --test ipc_integration rename_block`
Expected: FAIL (`rename_block_impl` not found).

- [ ] **Step 3: Add the bridge import + command + impl**

In `desktop/src-tauri/src/commands/edit.rs`, extend the bridge `use` to include `rename_block as bridge_rename_block`, then add after `create_block_impl`:

```rust
#[tauri::command]
pub async fn rename_block(
    state: State<'_, Mutex<VaultSession>>,
    block_uuid_hex: String,
    new_name: String,
) -> Result<BlockSummaryDto, AppError> {
    rename_block_impl(state.inner(), &block_uuid_hex, &new_name)
}

/// Rename a block to `new_name`, preserving every record. Blank/whitespace
/// `new_name` is rejected here as `InvalidArgument` (a desktop UI policy;
/// the bridge/spec permit empty names). Returns the updated summary so the
/// block list can refresh with the new name.
pub fn rename_block_impl(
    state: &Mutex<VaultSession>,
    block_uuid_hex: &str,
    new_name: &str,
) -> Result<BlockSummaryDto, AppError> {
    let new_name = new_name.trim();
    if new_name.is_empty() {
        return Err(AppError::InvalidArgument {
            detail: "block name must not be blank".to_string(),
        });
    }
    let block_uuid = parse_uuid_16(block_uuid_hex)?;
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        bridge_rename_block(
            &u.identity,
            &u.manifest,
            block_uuid,
            new_name.to_string(),
            u.device_uuid,
            now_ms(),
        )
        .map_err(map_save_error)?;
        let summary = crate::commands::vault::block_summary_for(&u.manifest, block_uuid)
            .ok_or_else(|| AppError::Internal {
                detail: "renamed block missing from manifest".into(),
            })?;
        Ok(summary)
    })
}
```

- [ ] **Step 4: Register the command**

In `desktop/src-tauri/src/main.rs`, add `edit::rename_block,` to the `generate_handler!` list (next to `edit::create_block,`).

- [ ] **Step 5: Run; verify it passes**

Run: `cd desktop/src-tauri && cargo test -p secretary-desktop --test ipc_integration rename_block`
Expected: PASS (both tests).

- [ ] **Step 6: Format, lint, commit**

```bash
cd desktop/src-tauri && cargo fmt --all && cargo clippy --release --workspace --tests -- -D warnings
cd /Users/hherb/src/secretary/.worktrees/desktop-block-crud-ui
git add desktop/src-tauri/src/commands/edit.rs desktop/src-tauri/src/main.rs desktop/src-tauri/tests/ipc_integration.rs
git commit -m "feat(desktop): rename_block command + blank-name guard"
```

---

### Task 3: `move_record` Tauri command + impl (Rust)

**Files:**
- Modify: `desktop/src-tauri/src/commands/edit.rs` (add command + impl; extend bridge import)
- Modify: `desktop/src-tauri/src/main.rs` (register `edit::move_record`)
- Test: `desktop/src-tauri/tests/ipc_integration.rs` (same `mod` as Task 2)

**Interfaces:**
- Consumes: `secretary_ffi_bridge::move_record(identity, manifest, source_block_uuid, target_block_uuid, source_record_uuid, new_record_uuid, device_uuid, now_ms) -> Result<(), FfiVaultError>`; `new_uuid_16`, `parse_uuid_16`, `map_save_error`, `RecordRefDto`.
- Produces: `move_record_impl(state, source_block_uuid_hex: &str, target_block_uuid_hex: &str, source_record_uuid_hex: &str) -> Result<RecordRefDto, AppError>` + `#[tauri::command] move_record` shell. `RecordRefDto { block_uuid_hex (=target), record_uuid_hex (=new uuid) }`.

- [ ] **Step 1: Write the failing integration tests**

Add to `desktop/src-tauri/tests/ipc_integration.rs` (same `mod`):

```rust
#[test]
fn move_record_copies_to_target_and_tombstones_source() {
    let (state, _dir, _pw) = unlocked_session_over_new_vault();
    let src = edit::create_block_impl(&state, "Source").unwrap();
    let dst = edit::create_block_impl(&state, "Target").unwrap();
    let rec = edit::save_record_impl(
        &state,
        &src.block_uuid_hex,
        RecordInputDto {
            record_type: "login".into(),
            tags: vec![],
            fields: vec![text_field("user", "alice")],
        },
    )
    .unwrap();

    let moved = edit::move_record_impl(
        &state,
        &src.block_uuid_hex,
        &dst.block_uuid_hex,
        &rec.record_uuid_hex,
    )
    .expect("move_record");
    assert_eq!(moved.block_uuid_hex, dst.block_uuid_hex);
    assert_ne!(moved.record_uuid_hex, rec.record_uuid_hex, "fresh uuid in target");

    // Source live view no longer shows it; include_deleted shows the tombstone.
    let src_live = browse::read_block_impl(&state, &src.block_uuid_hex, false).unwrap();
    assert_eq!(src_live.records.len(), 0, "source record tombstoned");
    let src_all = browse::read_block_impl(&state, &src.block_uuid_hex, true).unwrap();
    assert_eq!(src_all.records.len(), 1);
    assert_eq!(src_all.records[0].tombstoned, Some(true));

    // Target has the live copy.
    let dst_all = browse::read_block_impl(&state, &dst.block_uuid_hex, false).unwrap();
    assert_eq!(dst_all.records.len(), 1);
    assert_eq!(dst_all.records[0].record_uuid_hex, moved.record_uuid_hex);
}

#[test]
fn move_record_same_block_is_invalid_argument() {
    let (state, _dir, _pw) = unlocked_session_over_new_vault();
    let b = edit::create_block_impl(&state, "B").unwrap();
    let rec = edit::save_record_impl(
        &state,
        &b.block_uuid_hex,
        RecordInputDto { record_type: "login".into(), tags: vec![], fields: vec![text_field("user", "x")] },
    )
    .unwrap();
    let err = edit::move_record_impl(&state, &b.block_uuid_hex, &b.block_uuid_hex, &rec.record_uuid_hex)
        .expect_err("same-block move must be rejected");
    assert!(matches!(err, AppError::InvalidArgument { .. }), "got {err:?}");
}
```

> Confirm `RecordDto.tombstoned` is `Option<bool>` (matches the TS `tombstoned?: boolean`); if the Rust DTO field is a plain `bool`, assert `== true` instead of `Some(true)`.

- [ ] **Step 2: Run; verify it fails**

Run: `cd desktop/src-tauri && cargo test -p secretary-desktop --test ipc_integration move_record`
Expected: FAIL (`move_record_impl` not found).

- [ ] **Step 3: Add the bridge import + command + impl**

Extend the bridge `use` in `edit.rs` to include `move_record as bridge_move_record`, then add:

```rust
#[tauri::command]
pub async fn move_record(
    state: State<'_, Mutex<VaultSession>>,
    source_block_uuid_hex: String,
    target_block_uuid_hex: String,
    source_record_uuid_hex: String,
) -> Result<RecordRefDto, AppError> {
    move_record_impl(
        state.inner(),
        &source_block_uuid_hex,
        &target_block_uuid_hex,
        &source_record_uuid_hex,
    )
}

/// Move a live record from `source` to `target` under a fresh UUID
/// (copy-before-delete). Same-block moves are rejected here as
/// `InvalidArgument` (the bridge trusts its caller and does not check).
/// Returns the target block uuid + the record's fresh uuid.
pub fn move_record_impl(
    state: &Mutex<VaultSession>,
    source_block_uuid_hex: &str,
    target_block_uuid_hex: &str,
    source_record_uuid_hex: &str,
) -> Result<RecordRefDto, AppError> {
    if source_block_uuid_hex == target_block_uuid_hex {
        return Err(AppError::InvalidArgument {
            detail: "source and target block must differ".to_string(),
        });
    }
    let source_block_uuid = parse_uuid_16(source_block_uuid_hex)?;
    let target_block_uuid = parse_uuid_16(target_block_uuid_hex)?;
    let source_record_uuid = parse_uuid_16(source_record_uuid_hex)?;
    let new_record_uuid = new_uuid_16();
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        bridge_move_record(
            &u.identity,
            &u.manifest,
            source_block_uuid,
            target_block_uuid,
            source_record_uuid,
            new_record_uuid,
            u.device_uuid,
            now_ms(),
        )
        .map_err(map_save_error)?;
        Ok(RecordRefDto {
            block_uuid_hex: target_block_uuid_hex.to_string(),
            record_uuid_hex: hex::encode(new_record_uuid),
        })
    })
}
```

> The same-block guard compares hex strings up front so a same-block move never decodes/locks. Compare BEFORE parsing (a malformed-but-equal pair is still "same block"); the parse then validates length/hex.

- [ ] **Step 4: Register the command**

Add `edit::move_record,` to the `generate_handler!` list in `main.rs`.

- [ ] **Step 5: Run; verify it passes**

Run: `cd desktop/src-tauri && cargo test -p secretary-desktop --test ipc_integration move_record`
Expected: PASS (both tests).

- [ ] **Step 6: Format, lint, commit**

```bash
cd desktop/src-tauri && cargo fmt --all && cargo clippy --release --workspace --tests -- -D warnings
cd /Users/hherb/src/secretary/.worktrees/desktop-block-crud-ui
git add desktop/src-tauri/src/commands/edit.rs desktop/src-tauri/src/main.rs desktop/src-tauri/tests/ipc_integration.rs
git commit -m "feat(desktop): move_record command + same-block guard"
```

---

### Task 4: `ipc.ts` wrappers (`renameBlock`, `moveRecord`)

**Files:**
- Modify: `desktop/src/lib/ipc.ts` (two wrappers)
- Test: `desktop/tests/blockCrudIpc.test.ts` (new)

**Interfaces:**
- Consumes: existing `call<T>(cmd, args)` helper; `BlockSummaryDto`, `RecordRefDto` types; Tauri commands `rename_block` / `move_record` (Tasks 2–3).
- Produces: `renameBlock(blockUuidHex: string, newName: string): Promise<BlockSummaryDto>`; `moveRecord(sourceBlockUuidHex, targetBlockUuidHex, sourceRecordUuidHex): Promise<RecordRefDto>`.

- [ ] **Step 1: Write the failing test**

Create `desktop/tests/blockCrudIpc.test.ts`:

```ts
import { describe, it, expect, vi, beforeEach } from 'vitest';
const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));
import { renameBlock, moveRecord } from '../src/lib/ipc';

describe('block-CRUD ipc wrappers', () => {
  beforeEach(() => invokeMock.mockReset());

  it('renameBlock invokes rename_block with camelCase args', async () => {
    invokeMock.mockResolvedValueOnce({ blockUuidHex: 'ab', blockName: 'After', createdAtMs: 1, lastModifiedMs: 2 });
    await renameBlock('ab', 'After');
    expect(invokeMock).toHaveBeenCalledWith('rename_block', { blockUuidHex: 'ab', newName: 'After' });
  });

  it('moveRecord invokes move_record with camelCase args', async () => {
    invokeMock.mockResolvedValueOnce({ blockUuidHex: 'cd', recordUuidHex: 'ef' });
    const ref = await moveRecord('ab', 'cd', 'rr');
    expect(invokeMock).toHaveBeenCalledWith('move_record', {
      sourceBlockUuidHex: 'ab', targetBlockUuidHex: 'cd', sourceRecordUuidHex: 'rr'
    });
    expect(ref.recordUuidHex).toBe('ef');
  });
});
```

- [ ] **Step 2: Run; verify it fails**

Run: `cd desktop && pnpm vitest run tests/blockCrudIpc.test.ts`
Expected: FAIL (`renameBlock` / `moveRecord` not exported).

- [ ] **Step 3: Add the wrappers**

In `desktop/src/lib/ipc.ts`, after `createBlock`:

```ts
export async function renameBlock(blockUuidHex: string, newName: string): Promise<BlockSummaryDto> {
  return call<BlockSummaryDto>('rename_block', { blockUuidHex, newName });
}

export async function moveRecord(
  sourceBlockUuidHex: string,
  targetBlockUuidHex: string,
  sourceRecordUuidHex: string
): Promise<RecordRefDto> {
  return call<RecordRefDto>('move_record', { sourceBlockUuidHex, targetBlockUuidHex, sourceRecordUuidHex });
}
```

- [ ] **Step 4: Run; verify it passes**

Run: `cd desktop && pnpm vitest run tests/blockCrudIpc.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/desktop-block-crud-ui
git add desktop/src/lib/ipc.ts desktop/tests/blockCrudIpc.test.ts
git commit -m "feat(desktop): ipc wrappers for renameBlock + moveRecord"
```

---

### Task 5: `lib/blockCrud.ts` pure validation module

**Files:**
- Create: `desktop/src/lib/blockCrud.ts`
- Test: `desktop/tests/blockCrud.test.ts` (new)

**Interfaces:**
- Produces: `isBlankName(name: string): boolean`; `isSameBlock(a: string, b: string): boolean`. Pure, no I/O.

- [ ] **Step 1: Write the failing test**

Create `desktop/tests/blockCrud.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { isBlankName, isSameBlock } from '../src/lib/blockCrud';

describe('blockCrud pure guards', () => {
  it('isBlankName: empty / whitespace are blank', () => {
    expect(isBlankName('')).toBe(true);
    expect(isBlankName('   ')).toBe(true);
    expect(isBlankName('\t\n')).toBe(true);
  });
  it('isBlankName: non-blank is not blank', () => {
    expect(isBlankName('Logins')).toBe(false);
    expect(isBlankName('  x  ')).toBe(false);
  });
  it('isSameBlock: equal uuids match', () => {
    expect(isSameBlock('ab', 'ab')).toBe(true);
    expect(isSameBlock('ab', 'cd')).toBe(false);
  });
});
```

- [ ] **Step 2: Run; verify it fails**

Run: `cd desktop && pnpm vitest run tests/blockCrud.test.ts`
Expected: FAIL (module not found).

- [ ] **Step 3: Implement**

Create `desktop/src/lib/blockCrud.ts`:

```ts
// Pure pre-check guards for the block-CRUD UI. The Rust commands enforce the
// same rules authoritatively (defense in depth); these let the dialog/picker
// reject bad input WITHOUT an IPC round-trip and stay open. Keep them pure.

/** True when a block name is empty or whitespace-only (a UI policy: the
 *  FFI/spec permit empty names, but the desktop UI rejects them for parity
 *  with Android/iOS and usability). */
export function isBlankName(name: string): boolean {
  return name.trim().length === 0;
}

/** True when source and target block UUIDs are identical (a same-block move
 *  is a no-op the bridge does not guard against). */
export function isSameBlock(sourceBlockUuidHex: string, targetBlockUuidHex: string): boolean {
  return sourceBlockUuidHex === targetBlockUuidHex;
}
```

- [ ] **Step 4: Run; verify it passes**

Run: `cd desktop && pnpm vitest run tests/blockCrud.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/desktop-block-crud-ui
git add desktop/src/lib/blockCrud.ts desktop/tests/blockCrud.test.ts
git commit -m "feat(desktop): pure block-CRUD validation guards"
```

---

### Task 6: Generalize `NewBlock` → `BlockNameDialog` (create + rename)

**Files:**
- Create: `desktop/src/components/edit/BlockNameDialog.svelte`
- Delete: `desktop/src/components/edit/NewBlock.svelte`
- Modify: `desktop/src/routes/Vault.svelte` (swap `<NewBlock>` → `<BlockNameDialog mode={...}>`)
- Modify/rename test: `desktop/tests/NewBlock.test.ts` → `desktop/tests/BlockNameDialog.test.ts`

**Interfaces:**
- Consumes: `createBlock`, `renameBlock` (ipc); `isBlankName` (Task 5); `BlockSummaryDto`; `userMessageFor`.
- Produces: `BlockNameDialog` with props `{ mode: { kind: 'create' } | { kind: 'rename', block: BlockSummaryDto }, onDone: (block: BlockSummaryDto) => void, onCancel: () => void }`. Rename mode pre-fills `block.blockName`. Blank name → inline error, no IPC call, stays open.

- [ ] **Step 1: Write the failing test (migrate + extend)**

Create `desktop/tests/BlockNameDialog.test.ts` (and delete the old `NewBlock.test.ts` in Step 6):

```ts
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));
import BlockNameDialog from '../src/components/edit/BlockNameDialog.svelte';

const block = { blockUuidHex: 'ab', blockName: 'Before', createdAtMs: 1, lastModifiedMs: 1 };

describe('BlockNameDialog', () => {
  beforeEach(() => invokeMock.mockReset());

  it('create mode: empty field, invokes create_block, calls onDone', async () => {
    invokeMock.mockResolvedValueOnce({ blockUuidHex: 'ab', blockName: 'Logins', createdAtMs: 1, lastModifiedMs: 1 });
    const onDone = vi.fn();
    const { getByLabelText, getByRole } = render(BlockNameDialog, {
      props: { mode: { kind: 'create' }, onDone, onCancel: vi.fn() }
    });
    expect((getByLabelText(/block name/i) as HTMLInputElement).value).toBe('');
    await fireEvent.input(getByLabelText(/block name/i), { target: { value: 'Logins' } });
    await fireEvent.click(getByRole('button', { name: /create block/i }));
    await waitFor(() => expect(invokeMock).toHaveBeenCalledWith('create_block', { blockName: 'Logins' }));
    await waitFor(() => expect(onDone).toHaveBeenCalled());
  });

  it('rename mode: pre-fills name, invokes rename_block', async () => {
    invokeMock.mockResolvedValueOnce({ blockUuidHex: 'ab', blockName: 'After', createdAtMs: 1, lastModifiedMs: 2 });
    const onDone = vi.fn();
    const { getByLabelText, getByRole } = render(BlockNameDialog, {
      props: { mode: { kind: 'rename', block }, onDone, onCancel: vi.fn() }
    });
    expect((getByLabelText(/block name/i) as HTMLInputElement).value).toBe('Before');
    await fireEvent.input(getByLabelText(/block name/i), { target: { value: 'After' } });
    await fireEvent.click(getByRole('button', { name: /rename block/i }));
    await waitFor(() => expect(invokeMock).toHaveBeenCalledWith('rename_block', { blockUuidHex: 'ab', newName: 'After' }));
    await waitFor(() => expect(onDone).toHaveBeenCalled());
  });

  it('blank name: no IPC call, shows error, stays open', async () => {
    const onDone = vi.fn();
    const { getByLabelText, getByRole } = render(BlockNameDialog, {
      props: { mode: { kind: 'create' }, onDone, onCancel: vi.fn() }
    });
    await fireEvent.input(getByLabelText(/block name/i), { target: { value: '   ' } });
    await fireEvent.click(getByRole('button', { name: /create block/i }));
    expect(invokeMock).not.toHaveBeenCalled();
    expect(onDone).not.toHaveBeenCalled();
    await waitFor(() => expect(getByRole('alert')).toBeTruthy());
  });
});
```

- [ ] **Step 2: Run; verify it fails**

Run: `cd desktop && pnpm vitest run tests/BlockNameDialog.test.ts`
Expected: FAIL (component does not exist).

- [ ] **Step 3: Create `BlockNameDialog.svelte`**

Create `desktop/src/components/edit/BlockNameDialog.svelte`:

```svelte
<script lang="ts">
  import { createBlock, renameBlock, type BlockSummaryDto } from '../../lib/ipc';
  import { userMessageFor, type AppError } from '../../lib/errors';
  import { isBlankName } from '../../lib/blockCrud';

  type Mode = { kind: 'create' } | { kind: 'rename'; block: BlockSummaryDto };
  let { mode, onDone, onCancel }: {
    mode: Mode;
    onDone: (block: BlockSummaryDto) => void;
    onCancel: () => void;
  } = $props();

  let name = $state(mode.kind === 'rename' ? mode.block.blockName : '');
  let submitting = $state(false);
  let errMsg = $state<ReturnType<typeof userMessageFor> | null>(null);

  const isRename = $derived(mode.kind === 'rename');
  const heading = $derived(isRename ? 'Rename block' : 'New block');
  const idleLabel = $derived(isRename ? 'Rename block' : 'Create block');
  const busyLabel = $derived(isRename ? 'Renaming…' : 'Creating…');

  async function submit(): Promise<void> {
    if (submitting) return;
    const trimmed = name.trim();
    // UI policy: reject blank names (create + rename) without an IPC round-trip.
    if (isBlankName(trimmed)) {
      errMsg = { title: 'Block name is required' };
      return;
    }
    submitting = true; errMsg = null;
    try {
      const block = mode.kind === 'rename'
        ? await renameBlock(mode.block.blockUuidHex, trimmed)
        : await createBlock(trimmed);
      onDone(block);
    } catch (err) {
      errMsg = userMessageFor(err as AppError);
    } finally {
      submitting = false;
    }
  }
</script>

<section class="editor">
  <button type="button" class="editor__back" onclick={onCancel}>← Cancel</button>
  <h2 class="editor__title">{heading}</h2>
  {#if errMsg}<div class="editor__error" role="alert">{errMsg.title}</div>{/if}
  <label class="editor__field" for="block-name"><span>Block name</span>
    <input id="block-name" type="text" aria-label="block name" bind:value={name} placeholder="e.g. Work logins" disabled={submitting} />
  </label>
  <div class="editor__actions">
    <button type="button" disabled={submitting} onclick={submit}>{submitting ? busyLabel : idleLabel}</button>
  </div>
</section>
```

- [ ] **Step 4: Swap usage in `Vault.svelte` and delete `NewBlock.svelte`**

In `desktop/src/routes/Vault.svelte`: replace the import `import NewBlock from '../components/edit/NewBlock.svelte';` with `import BlockNameDialog from '../components/edit/BlockNameDialog.svelte';`, and replace the `{:else if $browseNav.level === 'newBlock'}` block body:

```svelte
    {:else if $browseNav.level === 'newBlock'}
      <BlockNameDialog
        mode={{ kind: 'create' }}
        onDone={async () => { try { await refreshManifest(); } finally { back(); } }}
        onCancel={() => back()}
      />
```

Then delete the old component and its old test:

```bash
git rm desktop/src/components/edit/NewBlock.svelte desktop/tests/NewBlock.test.ts
```

- [ ] **Step 5: Run dialog tests + svelte-check; verify pass**

Run: `cd desktop && pnpm vitest run tests/BlockNameDialog.test.ts && pnpm svelte-check`
Expected: PASS; svelte-check clean.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/desktop-block-crud-ui
git add desktop/src/components/edit/BlockNameDialog.svelte desktop/src/routes/Vault.svelte desktop/tests/BlockNameDialog.test.ts
git commit -m "refactor(desktop): generalize NewBlock into BlockNameDialog (create+rename)"
```

---

### Task 7: Rename wiring — browse level + `BlockCard` Rename button

**Files:**
- Modify: `desktop/src/lib/browse.ts` (add `renameBlock` level + `openRenameBlock` + `back` case)
- Modify: `desktop/src/routes/Vault.svelte` (render `BlockNameDialog` in rename mode; pass `onRename` to `BlockCard`)
- Modify: `desktop/src/components/BlockCard.svelte` (optional `onRename` → Rename button)
- Test: `desktop/tests/BlockCardRename.test.ts` (new); extend `desktop/tests/browse.test.ts` if it exists (else add cases in the new file)

**Interfaces:**
- Consumes: `BlockSummaryDto`; `BlockNameDialog` (Task 6).
- Produces: `browse.ts` `openRenameBlock(block)`; `BrowseNav` member `{ level: 'renameBlock'; block: BlockSummaryDto }`; `BlockCard` prop `onRename?: (block: BlockSummaryDto) => void`.

- [ ] **Step 1: Write the failing BlockCard test**

Create `desktop/tests/BlockCardRename.test.ts`:

```ts
import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import BlockCard from '../src/components/BlockCard.svelte';

const block = { blockUuidHex: 'ab', blockName: 'Logins', createdAtMs: 1, lastModifiedMs: 1 };

describe('BlockCard rename action', () => {
  it('renders a Rename button when onRename supplied and fires it', async () => {
    const onRename = vi.fn();
    const { getByRole } = render(BlockCard, { props: { block, onClick: vi.fn(), onRename } });
    await fireEvent.click(getByRole('button', { name: /rename block/i }));
    expect(onRename).toHaveBeenCalledWith(block);
  });

  it('omits the Rename button when onRename absent', () => {
    const { queryByRole } = render(BlockCard, { props: { block, onClick: vi.fn() } });
    expect(queryByRole('button', { name: /rename block/i })).toBeNull();
  });
});
```

- [ ] **Step 2: Run; verify it fails**

Run: `cd desktop && pnpm vitest run tests/BlockCardRename.test.ts`
Expected: FAIL (no Rename button).

- [ ] **Step 3: Add the Rename button to `BlockCard.svelte`**

In `desktop/src/components/BlockCard.svelte`, add `onRename?: (block: BlockSummaryDto) => void;` to `Props`, destructure it, and add a button (before `onShare`):

```svelte
  {#if onRename}
    <button
      type="button"
      class="block-card__rename"
      aria-label="Rename block"
      onclick={() => onRename(block)}
    >
      Rename
    </button>
  {/if}
```

- [ ] **Step 4: Add the browse level + helper**

In `desktop/src/lib/browse.ts`:
1. Add to the `BrowseNav` union: `| { level: 'renameBlock'; block: BlockSummaryDto }`.
2. Add the helper:

```ts
export function openRenameBlock(block: BlockSummaryDto): void {
  store.set({ level: 'renameBlock', block });
}
```

3. In `back()`, add (next to the `newBlock` case): `if (s.level === 'renameBlock') return { level: 'blocks' };`

- [ ] **Step 5: Wire `Vault.svelte`**

In `desktop/src/routes/Vault.svelte`:
1. Import `openRenameBlock` from `../lib/browse`.
2. Pass `onRename={openRenameBlock}` to the `<BlockCard ... />` in the blocks list.
3. Add a render branch after the `newBlock` branch:

```svelte
    {:else if $browseNav.level === 'renameBlock'}
      <BlockNameDialog
        mode={{ kind: 'rename', block: $browseNav.block }}
        onDone={async () => { try { await refreshManifest(); } finally { back(); } }}
        onCancel={() => back()}
      />
```

- [ ] **Step 6: Run tests + svelte-check; verify pass**

Run: `cd desktop && pnpm vitest run tests/BlockCardRename.test.ts && pnpm svelte-check`
Expected: PASS; svelte-check clean.

- [ ] **Step 7: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/desktop-block-crud-ui
git add desktop/src/lib/browse.ts desktop/src/routes/Vault.svelte desktop/src/components/BlockCard.svelte desktop/tests/BlockCardRename.test.ts
git commit -m "feat(desktop): rename-block affordance (BlockCard button + browse level)"
```

---

### Task 8: Move UI — `RecordRow` Move button + `MoveTargetPicker` modal + `RecordList` wiring

**Files:**
- Modify: `desktop/src/components/RecordRow.svelte` (optional `onMove` → Move button on live rows)
- Create: `desktop/src/components/edit/MoveTargetPicker.svelte`
- Modify: `desktop/src/components/RecordList.svelte` (pendingMove state, render picker, confirmMove → reload)
- Test: `desktop/tests/RecordRowMove.test.ts`, `desktop/tests/MoveTargetPicker.test.ts` (new)

**Interfaces:**
- Consumes: `listBlocks`, `moveRecord` (ipc); `isSameBlock` (Task 5); `BlockSummaryDto`, `RecordDto`; `userMessageFor`.
- Produces: `RecordRow` prop `onMove?: (record: RecordDto) => void` (live rows only); `MoveTargetPicker` props `{ sourceBlockUuidHex: string, onSelect: (target: BlockSummaryDto) => void, onCancel: () => void }` which loads `listBlocks()`, excludes the source, and renders one button per candidate.

- [ ] **Step 1: Write the failing RecordRow test**

Create `desktop/tests/RecordRowMove.test.ts`:

```ts
import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import RecordRow from '../src/components/RecordRow.svelte';

const live = { recordUuidHex: 'r1', recordType: 'login', tags: [], createdAtMs: 1, lastModMs: 1, fieldCount: 1, fields: [], tombstoned: false };
const dead = { ...live, recordUuidHex: 'r2', tombstoned: true };

describe('RecordRow move action', () => {
  it('shows Move on a live row and fires onMove', async () => {
    const onMove = vi.fn();
    const { getByRole } = render(RecordRow, { props: { record: live, onClick: vi.fn(), onMove } });
    await fireEvent.click(getByRole('button', { name: /move record/i }));
    expect(onMove).toHaveBeenCalledWith(live);
  });

  it('omits Move on a tombstoned row', () => {
    const { queryByRole } = render(RecordRow, { props: { record: dead, onClick: vi.fn(), onMove: vi.fn() } });
    expect(queryByRole('button', { name: /move record/i })).toBeNull();
  });
});
```

- [ ] **Step 2: Run; verify it fails**

Run: `cd desktop && pnpm vitest run tests/RecordRowMove.test.ts`
Expected: FAIL (no Move button).

- [ ] **Step 3: Add `onMove` to `RecordRow.svelte`**

Add `onMove?: (record: RecordDto) => void;` to `Props`, destructure it. In the action area, add a Move button shown only on live rows (alongside Delete). Change the existing live branch so both Delete and Move can render:

```svelte
  {#if deleted && onRestore}
    <button type="button" class="record-row__restore" aria-label="Restore record" onclick={() => onRestore(record)}>Restore</button>
  {:else if !deleted}
    {#if onMove}
      <button type="button" class="record-row__move" aria-label="Move record" onclick={() => onMove(record)}>Move</button>
    {/if}
    {#if onDelete}
      <button type="button" class="record-row__delete" aria-label="Delete record" onclick={() => onDelete(record)}>Delete</button>
    {/if}
  {/if}
```

- [ ] **Step 4: Run; verify the RecordRow test passes**

Run: `cd desktop && pnpm vitest run tests/RecordRowMove.test.ts && pnpm svelte-check`
Expected: PASS; svelte-check clean.

- [ ] **Step 5: Write the failing MoveTargetPicker test**

Create `desktop/tests/MoveTargetPicker.test.ts`:

```ts
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));
import MoveTargetPicker from '../src/components/edit/MoveTargetPicker.svelte';

const blocks = [
  { blockUuidHex: 'src', blockName: 'Source', createdAtMs: 1, lastModifiedMs: 1 },
  { blockUuidHex: 'dst', blockName: 'Target', createdAtMs: 1, lastModifiedMs: 1 }
];

describe('MoveTargetPicker', () => {
  beforeEach(() => invokeMock.mockReset());

  it('lists candidate blocks excluding the source and fires onSelect', async () => {
    invokeMock.mockResolvedValueOnce(blocks); // list_blocks
    const onSelect = vi.fn();
    const { getByRole, queryByRole } = render(MoveTargetPicker, {
      props: { sourceBlockUuidHex: 'src', onSelect, onCancel: vi.fn() }
    });
    await waitFor(() => expect(getByRole('button', { name: /Target/ })).toBeTruthy());
    expect(queryByRole('button', { name: /^Source$/ })).toBeNull();
    await fireEvent.click(getByRole('button', { name: /Target/ }));
    expect(onSelect).toHaveBeenCalledWith(blocks[1]);
  });
});
```

- [ ] **Step 6: Run; verify it fails**

Run: `cd desktop && pnpm vitest run tests/MoveTargetPicker.test.ts`
Expected: FAIL (component not found).

- [ ] **Step 7: Create `MoveTargetPicker.svelte`**

Create `desktop/src/components/edit/MoveTargetPicker.svelte`:

```svelte
<script lang="ts">
  import { listBlocks, isAppError, type BlockSummaryDto } from '../../lib/ipc';
  import { isSameBlock } from '../../lib/blockCrud';
  import { userMessageFor, type AppError } from '../../lib/errors';

  let { sourceBlockUuidHex, onSelect, onCancel }: {
    sourceBlockUuidHex: string;
    onSelect: (target: BlockSummaryDto) => void;
    onCancel: () => void;
  } = $props();

  let candidates = $state<BlockSummaryDto[] | null>(null);
  let error = $state<AppError | null>(null);

  // Load the block list once; exclude the source (a same-block move is a no-op
  // the bridge does not guard, so it must never be offered).
  $effect(() => {
    (async () => {
      try {
        const all = await listBlocks();
        candidates = all.filter((b) => !isSameBlock(b.blockUuidHex, sourceBlockUuidHex));
      } catch (e) {
        error = isAppError(e) ? e : { code: 'internal' };
      }
    })();
  });
</script>

<dialog class="move-picker" open>
  <h3 class="move-picker__title">Move to which block?</h3>
  {#if error}
    {@const msg = userMessageFor(error)}
    <p class="move-picker__error" role="alert">{msg.title}</p>
  {:else if candidates === null}
    <p class="move-picker__loading">Loading…</p>
  {:else if candidates.length === 0}
    <p class="move-picker__empty">No other blocks to move into.</p>
  {:else}
    <div class="move-picker__list">
      {#each candidates as block (block.blockUuidHex)}
        <button type="button" class="move-picker__target" onclick={() => onSelect(block)}>{block.blockName}</button>
      {/each}
    </div>
  {/if}
  <button type="button" class="move-picker__cancel" onclick={onCancel}>Cancel</button>
</dialog>
```

- [ ] **Step 8: Run; verify the picker test passes**

Run: `cd desktop && pnpm vitest run tests/MoveTargetPicker.test.ts && pnpm svelte-check`
Expected: PASS; svelte-check clean.

- [ ] **Step 9: Wire the move flow into `RecordList.svelte`**

In `desktop/src/components/RecordList.svelte`:
1. Add imports: `moveRecord` from `../lib/ipc`; `MoveTargetPicker` from `./edit/MoveTargetPicker.svelte`.
2. Add state: `let pendingMove = $state<RecordDto | null>(null);`
3. Add handlers:

```ts
  function onMove(record: RecordDto) {
    pendingMove = record;
  }

  async function confirmMove(target: BlockSummaryDto) {
    const record = pendingMove;
    if (!record) return;
    pendingMove = null;
    error = null;
    try {
      await moveRecord(block.blockUuidHex, target.blockUuidHex, record.recordUuidHex);
      await load(); // re-read the SOURCE block: the moved record now shows tombstoned
    } catch (e) {
      error = isAppError(e) ? e : { code: 'internal' };
    }
  }
```

4. Pass `{onMove}` to `<RecordRow ... />`.
5. Render the picker after the existing dialogs:

```svelte
{#if pendingMove}
  <MoveTargetPicker
    sourceBlockUuidHex={block.blockUuidHex}
    onSelect={confirmMove}
    onCancel={() => (pendingMove = null)}
  />
{/if}
```

- [ ] **Step 10: Write the RecordList move-flow test**

Create `desktop/tests/RecordListMove.test.ts`:

```ts
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));
import RecordList from '../src/components/RecordList.svelte';

const block = { blockUuidHex: 'src', blockName: 'Source', createdAtMs: 1, lastModifiedMs: 1 };
const rec = { recordUuidHex: 'r1', recordType: 'login', tags: [], createdAtMs: 1, lastModMs: 1, fieldCount: 1, fields: [], tombstoned: false };
const targets = [block, { blockUuidHex: 'dst', blockName: 'Target', createdAtMs: 1, lastModifiedMs: 1 }];

describe('RecordList move flow', () => {
  beforeEach(() => invokeMock.mockReset());

  it('moves a record into the chosen target then reloads the source', async () => {
    invokeMock.mockImplementation((cmd: string) => {
      if (cmd === 'read_block') return Promise.resolve({ blockUuidHex: 'src', blockName: 'Source', records: [rec] });
      if (cmd === 'list_blocks') return Promise.resolve(targets);
      if (cmd === 'move_record') return Promise.resolve({ blockUuidHex: 'dst', recordUuidHex: 'r2' });
      return Promise.resolve(null);
    });
    const { getByRole, findByRole } = render(RecordList, { props: { block } });
    await waitFor(() => getByRole('button', { name: /move record/i }));
    await fireEvent.click(getByRole('button', { name: /move record/i }));
    const target = await findByRole('button', { name: /Target/ });
    await fireEvent.click(target);
    await waitFor(() => expect(invokeMock).toHaveBeenCalledWith('move_record', {
      sourceBlockUuidHex: 'src', targetBlockUuidHex: 'dst', sourceRecordUuidHex: 'r1'
    }));
  });
});
```

- [ ] **Step 11: Run the full desktop suite + svelte-check; verify pass**

Run: `cd desktop && pnpm test && pnpm svelte-check`
Expected: PASS (all vitest tests incl. the new ones); svelte-check clean.

- [ ] **Step 12: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/desktop-block-crud-ui
git add desktop/src/components/RecordRow.svelte desktop/src/components/edit/MoveTargetPicker.svelte desktop/src/components/RecordList.svelte desktop/tests/RecordRowMove.test.ts desktop/tests/MoveTargetPicker.test.ts desktop/tests/RecordListMove.test.ts
git commit -m "feat(desktop): move-record affordance (RecordRow button + target picker)"
```

---

### Task 9: Docs — README + ROADMAP rows

**Files:**
- Modify: `README.md` (block-CRUD platform-status row)
- Modify: `ROADMAP.md` (entry matching the Android/iOS siblings)

**Interfaces:** none (docs only).

- [ ] **Step 1: Inspect the sibling rows**

Run: `grep -niE "block-crud|block crud|create/rename|move record" README.md ROADMAP.md`
Expected: find the Android + iOS block-CRUD rows to mirror. (Keep README terse per the README-style preference — dot points, no test-count walls.)

- [ ] **Step 2: Add the desktop row to README**

Add/extend the block-CRUD status line so desktop joins Android + iOS (mirror the exact wording/format of the sibling row found in Step 1; desktop = Tauri create/rename block + move record).

- [ ] **Step 3: Add the desktop entry to ROADMAP**

Mirror the Android/iOS block-CRUD ROADMAP entry, marking the desktop affordance done (create already shipped; rename + move added this slice → tier now complete on all three platforms).

- [ ] **Step 4: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/desktop-block-crud-ui
git add README.md ROADMAP.md
git commit -m "docs: desktop block-CRUD UI rows in README + ROADMAP"
```

---

### Task 10: Final verification + guardrails

**Files:** none (verification only).

- [ ] **Step 1: Full Rust test + clippy**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/desktop-block-crud-ui/desktop/src-tauri
cargo fmt --all -- --check
cargo test -p secretary-desktop
cargo clippy --release --workspace --tests -- -D warnings
```
Expected: all green; clippy clean; fmt clean.

- [ ] **Step 2: Full desktop frontend suite + svelte-check**

Run: `cd /Users/hherb/src/secretary/.worktrees/desktop-block-crud-ui/desktop && pnpm test && pnpm svelte-check`
Expected: all vitest green; svelte-check clean.

- [ ] **Step 3: Guardrails (must be EMPTY)**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/desktop-block-crud-ui
git diff main...HEAD --name-only | grep -E 'core/|crypto-design|vault-format|\.udl|secretary-ffi-py|android/|ios/'   # expect empty
```
Expected: no output (the slice touched none of these).

- [ ] **Step 4: Confirm no spurious package-lock.json**

Run: `cd /Users/hherb/src/secretary/.worktrees/desktop-block-crud-ui && git status --porcelain | grep package-lock || echo OK`
Expected: `OK` (pnpm only — a stray npm `package-lock.json` must not be committed).

---

## Self-Review

**Spec coverage:**
- Rust commands `rename_block` / `move_record` with authoritative guards → Tasks 2, 3. ✓
- `AppError::InvalidArgument` (Rust + TS) → Task 1. ✓
- `ipc.ts` wrappers → Task 4. ✓
- Pure `blockCrud.ts` (frontend pre-check half of defense-in-depth) → Task 5. ✓
- Generalize `NewBlock` → `BlockNameDialog` (create+rename, pre-fill, blank pre-check, regression of create) → Task 6. ✓
- Rename button + browse level → Task 7. ✓
- Move button + target picker (excludes source) + re-read source after move → Task 8. ✓
- Validation rules (blank→invalid, same-block→invalid, write-failure-stays-open, success-reload) → enforced in Tasks 1–3 (authoritative) + 6, 8 (UI). ✓
- Tests: vitest (dialog/picker/row/pure-fn/ipc) + Rust integration (rename/move happy + guard) → Tasks 1–8. ✓
- No e2e (tauri-driver macOS limitation) → honored (not added). ✓
- README + ROADMAP → Task 9. ✓
- Guardrails empty → Task 10. ✓

**Placeholder scan:** No "TBD/TODO". Two `> Note:` blocks (list_blocks impl name; `RecordDto.tombstoned` shape) instruct the implementer to grep-confirm the exact existing symbol rather than invent one — these are verification directives, not unfilled placeholders, and each gives a concrete fallback.

**Type consistency:** `BlockNameDialog` prop is `onDone` everywhere (Tasks 6–7). `mode` discriminant `{ kind: 'create' } | { kind: 'rename'; block }` consistent. `moveRecord(source, target, record)` arg order identical in ipc wrapper (Task 4), Rust impl (Task 3), and RecordList call (Task 8). `RecordRefDto { blockUuidHex, recordUuidHex }` used consistently. `onMove` / `onRename` optional-prop naming matches the existing `onDelete`/`onTrash` convention.

**Deviation from spec (justified):** spec said "temp copy of golden_vault_001" for the Rust integration tests; the plan uses the established `unlocked_session_over_new_vault()` fresh-vault harness instead — it equally satisfies "never mutate the tracked fixture" and is the existing write-path pattern in `ipc_integration.rs` (writing-plans: follow existing patterns). Also: the TS `invalid_argument` union member carries NO `detail` (the Rust `detail` is `#[serde(skip_serializing)]`), correcting the spec's `{ detail: string }` to match how every other detail-carrying `AppError` projects to the wire.
