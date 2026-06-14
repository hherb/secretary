# iOS `include_deleted` Rust gate — unify tombstone visibility in the shared bridge

**Date:** 2026-06-14
**Status:** Approved (brainstorming → design)
**Scope:** Move record-level tombstone (soft-delete) visibility filtering off the iOS Swift client and into the shared Rust FFI bridge `read_block`, as a first-class `include_deleted` parameter. Consolidate desktop onto the same gate so the Rust core is the single source of truth for tombstone visibility across all platforms.

## Problem

Today the iOS browse screen receives **every** record from the FFI bridge — live and tombstoned — and hides the deleted ones purely in Swift:

```swift
// ios/SecretaryVaultAccess/.../VaultBrowseViewModel.swift
public var visibleRecords: [RecordView] {
    let all = records ?? []
    return showDeleted ? all : all.filter { !$0.tombstone }
}
```

The secret field material of tombstoned records crosses the FFI seam regardless of the toggle. The shared bridge `read_block(identity, manifest, block_uuid)` is a pass-through that returns all records; the only Rust on the iOS path is that bridge (iOS calls uniffi directly — there is no per-platform Rust policy layer like desktop's Tauri command layer).

Desktop already gates correctly, but in its **own** Rust layer (`desktop/src-tauri/src/reveal.rs::project_block_detail`), not in the shared bridge. So the bridge `read_block` is a "returns everything including tombstoned secrets" function that any client can call — a footgun, and a duplication of the filtering concern.

## Goal / acceptance

- The bridge read path **withholds** tombstoned records unless `include_deleted` is set; a withheld record's `FieldHandle`s are never constructed, so its secret field values never cross the FFI seam.
- The iOS "Show deleted" toggle **re-reads** the block through the gate (desktop parity); the client never holds withheld data.
- Tombstone visibility is gated **once**, in the shared Rust bridge, for all platforms (iOS + desktop + Python). The desktop's duplicate filter is removed.
- No on-disk format change, no crypto change, no CRDT change.

## Non-goals

- Caching both filtered/unfiltered result sets on the client (rejected — would retain withheld data in client memory, defeating the goal).
- Block-level trash (`manifest.trash`) — unaffected; this is record-level tombstone visibility only.
- Changing how tombstones are *created* (delete/restore primitives) — only how they are *read/projected*.

## Approach (chosen: A — unify in shared `read_block`)

The alternative (a separate `read_block_visible` function leaving `read_block` untouched) was rejected: it duplicates decode+filter logic and leaves the `read_block` footgun on the FFI surface. Unifying is more churn (cross-language call-site updates) but yields a single Rust source of truth and removes the footgun — consistent with the project's "enforcement over assumptions" and "single source of truth" principles.

## Design

### 1. Rust bridge — the gate

`ffi/secretary-ffi-bridge/src/record/orchestration.rs`:

- New signature:
  ```rust
  pub fn read_block(
      identity: &UnlockedIdentity,
      manifest: &OpenVaultManifest,
      block_uuid: &[u8; 16],
      include_deleted: bool,
  ) -> Result<BlockReadOutput, FfiVaultError>
  ```
- A pure, unit-tested free function expresses the policy (per the project's pure-functions-in-reusable-modules preference):
  ```rust
  /// A record is visible to a foreign reader unless it is tombstoned and the
  /// caller did not ask for deleted records. Pure; the single decision point
  /// for record-level tombstone visibility across all platforms.
  fn record_is_visible(tombstone: bool, include_deleted: bool) -> bool {
      include_deleted || !tombstone
  }
  ```
- In the `BlockPlaintext` → `BlockReadOutput` lowering loop, `continue` past any record where `!record_is_visible(tombstone, include_deleted)` **before** building any `FieldHandle`. Withheld records contribute nothing to the output — neither metadata nor secret field handles.
- `decrypt_block_plaintext` and `decrypt_block_file_bytes` are **unchanged**: they still return the full native `BlockPlaintext` (the edit primitives in `crate::edit` rely on the complete record set for byte-faithful round-trips). The gate lives only in the foreign-projection lowering.
- Doc comment updated to state the withholding contract.

### 2. FFI surface

- `ffi/secretary-ffi-uniffi/src/secretary.udl`: `read_block` gains `boolean include_deleted`.
- uniffi scaffolding wrapper (the `[u8;16]`-coercing wrapper that calls the bridge): thread `include_deleted` through.
- pyo3 wrapper (`ffi/secretary-ffi-py/src/...`): add `include_deleted` (positional, mirroring desktop's TS default of `false` at the call sites; pyo3 has no default-arg sugar, so callers pass it explicitly).

### 3. Desktop consolidation

- `desktop/src-tauri/src/commands/browse.rs`: pass `include_deleted` into the bridge `read_block` call (it already receives the flag over IPC).
- `desktop/src-tauri/src/reveal.rs::project_block_detail`: **remove** the now-duplicate `if record.tombstone() && !include_deleted { continue; }` and drop the `include_deleted` parameter from this projection function (it projects whatever records the bridge returned). Update its call site and any unit tests of `project_block_detail` accordingly.
- Desktop observable behavior is unchanged — it already re-reads on toggle; `desktop/tests/RecordListDelete.test.ts` stays green.

### 4. iOS

- `VaultSession` protocol (`SecretaryVaultAccess`): `readBlock(blockUuid:includeDeleted:) throws -> [RecordView]`.
- `UniffiVaultSession.readBlock(blockUuid:includeDeleted:)` (`SecretaryKit`): pass through to the uniffi `read_block`.
- `FakeVaultSession`: honor `includeDeleted` so host tests can drive both branches (and spy on the flag).
- `VaultBrowseViewModel`:
  - Remove the `visibleRecords` client-side filter. `records` now holds exactly what the gate exposed.
  - `showDeleted`'s mutation triggers a re-read: a setter (`didSet` or an explicit `setShowDeleted`) calls `reload(blockUuid: selectedBlockUuid, includeDeleted: showDeleted)` when a block is selected; if none selected, it just stores the flag.
  - `reload(blockUuid:)` passes `includeDeleted: showDeleted` to `session.readBlock`.
  - All existing reload paths (`selectBlock`, `refresh`, `commitThenReload`) pass the current `showDeleted` so delete/restore re-reads stay consistent with the toggle.
- `VaultBrowseScreen.swift`: iterate `viewModel.records ?? []` (or a thin `visibleRecords` accessor that now just returns `records ?? []`). The `Toggle` binding to `showDeleted` is unchanged; the setter does the re-read.

### 5. Cross-language harnesses (the risk surface)

Every `read_block` / `readBlock` call site gains the argument:

- KAT dispatch `core/tests/conformance_kat_helpers/dispatch/read.rs` and the lifecycle round-trip in `.../dispatch/lifecycle.rs`.
- pyo3 tests: `test_record_edit.py`, `test_trash_restore.py`, `test_smoke.py`.
- Kotlin: `SmokeSaveBlock.kt`, `SmokeReadBlock.kt`, `SmokeTrashRestore.kt`, `Conformance.kt`.
- Swift conformance/smoke equivalents.

Rule: pass `true` where the test inspects tombstoned records (e.g. trash/restore round-trips that assert a record is present-and-tombstoned), `false` (the app default) otherwise.

**Conformance value parity:** the cross-language conformance replay (`dispatch/read.rs` + Swift/Kotlin `Conformance.*`) must pass the **same** `include_deleted` value in all three languages. Use `true` there — conformance verifies that the full decoded record set agrees across languages, so it should not have records filtered out. Since no existing `read_block` KAT vector carries a tombstone (verified by grep), `true` and `false` produce identical output and **no KAT regeneration is required**; `true` is chosen for semantic faithfulness ("all decoded records agree").

Because cargo/clippy cannot see the Swift/Kotlin harnesses, the gauntlet explicitly runs `ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh` and `.../kotlin/run_conformance.sh`, plus the pyo3 pytest suite and desktop vitest — not just `cargo test`.

### 6. Docs

- README iOS status row + ROADMAP: note that record-level tombstone visibility is now gated in the Rust core (`include_deleted`), client no longer filters.

## Data flow (iOS)

```
Toggle showDeleted
  → setter: reload(selectedBlockUuid, includeDeleted: showDeleted)
    → session.readBlock(blockUuid:, includeDeleted:)
      → uniffi read_block(identity, manifest, block_uuid, include_deleted)
        → bridge: record_is_visible gate; withheld records build no FieldHandle
          → only visible records cross the FFI seam
            → records replaced → view renders
```

## Error handling

No change to the error surface. `read_block`'s typed `FfiVaultError` variants (`BlockNotFound` / `CorruptVault` / `FolderInvalid`) are unchanged; the gate is applied only after a successful decrypt+decode, on the already-validated plaintext.

## Testing

- **Rust unit:** `record_is_visible` truth table (4 cases). Bridge integration test: build a vault, save a record, tombstone it; assert `read_block(..., false)` withholds it (record count excludes it, no field handles) and `read_block(..., true)` includes it. Fixture generated in-test (no static KAT).
- **iOS host (`SecretaryVaultAccess` swift test):** toggling `showDeleted` re-reads with the correct `includeDeleted` flag (spied via `FakeVaultSession`); withheld records are absent from `records`; the old client-side-filter tests are rewritten to assert re-read semantics.
- **iOS sim (`SecretaryKit`):** create → tombstone → read round-trip asserts the gate end-to-end through the real uniffi binding.
- **Desktop:** `RecordListDelete.test.ts` (vitest) + any `project_block_detail` Rust unit test stay green with the consolidated gate.
- **Conformance:** Swift + Kotlin `run_conformance.sh` green; pyo3 pytest green.

## Risks

- **Cross-language signature change invisible to cargo.** The Swift/Kotlin harnesses are only exercised by `run_conformance.sh` and the iOS scripts — mitigated by running those suites in the acceptance gauntlet, not just `cargo test`/`clippy`.
- **Desktop double-edit.** Removing the `project_block_detail` filter while adding the bridge gate must be a single coherent change so desktop neither double-filters nor stops filtering. Covered by the existing desktop tests.
- **KAT regeneration** is **not** expected (no tombstone in read vectors). If a vector unexpectedly carries one, that is surfaced by a conformance diff and resolved explicitly per the spec-is-normative rule — never by silently editing one side.

## Acceptance commands (gauntlet)

```bash
cd /Users/hherb/src/secretary/.worktrees/ios-include-deleted-rust-gate

# Rust core + bridge + KAT replay
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings

# pyo3 binding
# (maturin develop in the secretary-ffi-py venv, then) uv run pytest ffi/secretary-ffi-py/tests

# Swift/Kotlin conformance (cargo cannot see these)
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh

# Desktop
# (cd desktop && npm test)   # RecordListDelete.test.ts

# iOS
( cd ios/SecretaryVaultAccess && swift test )
bash ios/scripts/run-ios-tests.sh

# Confirm no on-disk-format / crypto change
git diff main...HEAD --name-only | grep -E 'crypto-design|vault-format' || echo "no format change (expected)"
```
