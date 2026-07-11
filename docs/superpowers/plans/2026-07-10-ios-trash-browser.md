# iOS Trash Browser Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a native SwiftUI Trash browser on iOS — list trashed blocks, restore / delete-forever per block, empty-trash, and run-retention-now (preview→commit against the 90-day default) — all behind the existing Face ID re-auth gate, enabled by projecting the bridge-only `list_trashed_blocks` onto uniffi + pyo3.

**Architecture:** Bottom-up. The `secretary-ffi-bridge` `list_trashed_blocks` + `TrashedBlock` already exist and are re-exported; we project them onto uniffi (for iOS) and pyo3 (parity), regenerate the Swift bindings, then build the iOS layers: a pure `TrashPort` + value types + `TrashViewModel` (host-tested in the FFI-free `SecretaryVaultAccess` package), a `UniffiVaultSession: TrashPort` adapter in `SecretaryKit`, and SwiftUI screens in `SecretaryApp`. The shipped `GraceWindowReauthGate` is reused unchanged.

**Tech Stack:** Rust (uniffi 0.31, pyo3 0.28), Swift 6 (SwiftUI, XCTest), `uv` for Python, `xcodebuild` for the iOS xcframework.

## Global Constraints

- **No `core` / crypto / on-disk-format / KEM / signature-site / equal-clock change; no `manifest_version` bump. `#![forbid(unsafe_code)]` intact.** This slice only projects an existing bridge fn and builds UI on top.
- **No new `FfiVaultError` variant.** `list_trashed_blocks` raises only `CorruptVault` / `FolderInvalid`, both already existing → no Swift/Kotlin `ConformanceErrors.{swift,kt}` harness churn, no workspace-wide exhaustive-match obligation.
- **uniffi `[u8;16]` bridge fields project as `Vec<u8>`** (UDL `bytes`) via `.to_vec()`; **pyo3 exposes them as `Vec<u8>`** under `#[pyclass(frozen, get_all)]` (Python sees `list[int]`, tests wrap with `bytes(...)`).
- **Pure package `SecretaryVaultAccess` stays FFI-free** (no `import SecretaryKit`, no generated types); the FFI DTOs are mapped to pure Swift value types in the `SecretaryKit` adapter.
- **Reuse the shipped `GraceWindowReauthGate` instance** — grace-window parity with desktop (30 s). No new gate code.
- **Copy user-facing strings verbatim from desktop** (`desktop/src/lib/trash.ts`, `RetentionDialog.svelte`, `TrashView.svelte`).
- **Python: `uv` only** — never `pip`.
- **Rust gates each Rust task must pass:** `cargo fmt --all -- --check`, `cargo clippy --release --workspace --tests -- -D warnings`, `cargo test --release --workspace`, `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace`, `bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh`.
- **Work in the worktree** `/Users/hherb/src/secretary/.worktrees/ios-trash-browser` on branch `feature/ios-trash-browser`. Spell out full worktree paths in Edit/Write.

## File structure

| File | Responsibility | Task |
|---|---|---|
| `ffi/secretary-ffi-py/src/trash.rs` | + `TrashedBlock` pyclass + `list_trashed_blocks` pyfn | 1 |
| `ffi/secretary-ffi-py/src/lib.rs` | register the pyclass + pyfn | 1 |
| `ffi/secretary-ffi-py/tests/test_trash_restore.py` | pytest for `list_trashed_blocks` | 1 |
| `ffi/secretary-ffi-uniffi/src/wrappers/trash.rs` (new) | uniffi `TrashedBlock` value type | 2 |
| `ffi/secretary-ffi-uniffi/src/wrappers/mod.rs` | `pub mod trash;` | 2 |
| `ffi/secretary-ffi-uniffi/src/secretary.udl` | `TrashedBlock` dict + `list_trashed_blocks` decl | 2 |
| `ffi/secretary-ffi-uniffi/src/namespace/mod.rs` | `list_trashed_blocks` projection fn | 2 |
| `ffi/secretary-ffi-uniffi/src/lib.rs` | re-export fn + type | 2 |
| `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/TrashModels.swift` (new) | pure value types + `TrashPort` protocol | 3 |
| `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/TrashFormatting.swift` (new) | pure copy/format/sort helpers | 3 |
| `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/TrashFormattingTests.swift` (new) | helper tests | 3 |
| `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeTrashPort.swift` (new) | test double | 4 |
| `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/TrashViewModel.swift` (new) | host-tested VM | 4 |
| `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/TrashViewModelTests.swift` (new) | VM tests | 4 |
| `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSession+Trash.swift` (new) | `TrashPort` adapter | 5 |
| `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/VaultErrorMapping.swift` | + `BlockNotInTrash`/`BlockPurged` arms | 5 |
| `ios/SecretaryApp/Sources/TrashScreen.swift` (new) | SwiftUI screen + row + dialogs | 6 |
| `ios/SecretaryApp/Sources/VaultBrowseScreen.swift` | Trash entry-point toolbar item | 6 |
| `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultBrowseViewModel.swift` | `makeTrashViewModel()` factory + `trashPort` dep | 6 |
| `README.md`, `ROADMAP.md` | status updates | 7 |

---

### Task 1: pyo3 projection of `list_trashed_blocks` (+ pytest)

The bridge is already done (`ffi/secretary-ffi-bridge/src/trash/list.rs` + re-exports at `trash/mod.rs:11` and `lib.rs:169`). This task projects it onto pyo3 with a real red→green pytest.

**Files:**
- Modify: `ffi/secretary-ffi-py/src/trash.rs`
- Modify: `ffi/secretary-ffi-py/src/lib.rs:106` (import), `~:239-242` (registration, the B.5 block)
- Test: `ffi/secretary-ffi-py/tests/test_trash_restore.py`

**Interfaces:**
- Consumes: `secretary_ffi_bridge::{list_trashed_blocks, TrashedBlock}` (already re-exported).
- Produces (Python): `secretary_ffi_py.list_trashed_blocks(identity, manifest) -> list[TrashedBlock]`; `TrashedBlock` with attrs `block_uuid: bytes-like`, `block_name: str`, `tombstoned_at_ms: int`, `tombstoned_by: bytes-like`.

- [ ] **Step 1: Write the failing pytest**

Add to `ffi/secretary-ffi-py/tests/test_trash_restore.py` (reuse the file's existing `_fresh_writable_vault` / `_save_one_record_block` / `VAULT_001_PASSWORD` / `DEVICE_UUID` / `NOW_MS_BASE` fixtures — check the exact `_save_one_record_block` signature in THIS file and match it):

```python
def test_list_trashed_blocks_projects_name_and_tombstone(tmp_path):
    out, _dst = _fresh_writable_vault(tmp_path)
    block_uuid = bytes([0xB7] * 16)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            _save_one_record_block(identity, manifest, block_uuid)
            trashed_at = NOW_MS_BASE + 5_000
            secretary_ffi_py.trash_block(
                identity, manifest, block_uuid, DEVICE_UUID, trashed_at
            )

            listed = secretary_ffi_py.list_trashed_blocks(identity, manifest)

            assert len(listed) == 1
            assert bytes(listed[0].block_uuid) == block_uuid
            assert listed[0].block_name == "Notes"
            assert listed[0].tombstoned_at_ms == trashed_at
            assert bytes(listed[0].tombstoned_by) == DEVICE_UUID
```

(If this file's `_save_one_record_block` names the block something other than "Notes", use that name in the assertion. If it takes a `record_uuid` arg, pass one.)

- [ ] **Step 2: Run to verify it fails**

Run: `cd ffi/secretary-ffi-py && uv run maturin develop && uv run pytest tests/test_trash_restore.py::test_list_trashed_blocks_projects_name_and_tombstone -v`
Expected: FAIL — `AttributeError: module 'secretary_ffi_py' has no attribute 'list_trashed_blocks'`.
(If pytest sees a stale `.so`, nuke the venv + uv cache per the maturin/uv cache note, then re-`maturin develop`.)

- [ ] **Step 3: Add the pyclass + pyfunction**

In `ffi/secretary-ffi-py/src/trash.rs`, add after the existing `trash_block` fn (it already imports `ffi_vault_error_to_pyerr`, `UnlockedIdentity`, `OpenVaultManifest`):

```rust
/// One trashed block, projected by name for a Trash view. Output-only;
/// never constructed from Python. Carries only the block name (already
/// plaintext in manifest summaries) + tombstone metadata — no record
/// material (the bridge decrypts-then-zeroizes internally).
#[pyclass(frozen, get_all)]
pub struct TrashedBlock {
    /// 16-byte UUID of the trashed block.
    pub block_uuid: Vec<u8>,
    /// Human-readable block name, recovered from the newest trashed file.
    pub block_name: String,
    /// Unix-millis the block was moved to trash.
    pub tombstoned_at_ms: u64,
    /// 16-byte UUID of the device that trashed the block.
    pub tombstoned_by: Vec<u8>,
}

impl From<secretary_ffi_bridge::TrashedBlock> for TrashedBlock {
    fn from(b: secretary_ffi_bridge::TrashedBlock) -> Self {
        Self {
            block_uuid: b.block_uuid.to_vec(),
            block_name: b.block_name,
            tombstoned_at_ms: b.tombstoned_at_ms,
            tombstoned_by: b.tombstoned_by.to_vec(),
        }
    }
}

/// List every not-yet-purged trashed block, projected by name (#402
/// follow-up). Raises `CorruptVault` (wiped handle / missing not-yet-purged
/// file / decrypt failure) or `FolderInvalid` (unreadable file).
#[pyfunction]
pub(crate) fn list_trashed_blocks(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
) -> PyResult<Vec<TrashedBlock>> {
    secretary_ffi_bridge::list_trashed_blocks(&identity.0, &manifest.0)
        .map(|v| v.into_iter().map(TrashedBlock::from).collect())
        .map_err(ffi_vault_error_to_pyerr)
}
```

- [ ] **Step 4: Register in `lib.rs`**

In `ffi/secretary-ffi-py/src/lib.rs`, change the trash import (`:106`) from `use trash::trash_block;` to:

```rust
use trash::{list_trashed_blocks, trash_block, TrashedBlock};
```

Then in the B.5 registration block (`~:239-242`), after the `restore_block` line, add:

```rust
    m.add_class::<TrashedBlock>()?;
    m.add_function(wrap_pyfunction!(list_trashed_blocks, m)?)?;
```

- [ ] **Step 5: Run to verify it passes**

Run: `cd ffi/secretary-ffi-py && uv run maturin develop && uv run pytest tests/test_trash_restore.py -v`
Expected: PASS (all tests in the file, incl. the new one).

- [ ] **Step 6: Rust gates**

Run: `cargo fmt --all -- --check && cargo clippy --release --workspace --tests -- -D warnings`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add ffi/secretary-ffi-py/src/trash.rs ffi/secretary-ffi-py/src/lib.rs ffi/secretary-ffi-py/tests/test_trash_restore.py
git commit -m "feat(ffi-py): project list_trashed_blocks + TrashedBlock onto pyo3"
```

---

### Task 2: uniffi projection of `list_trashed_blocks`

**Files:**
- Create: `ffi/secretary-ffi-uniffi/src/wrappers/trash.rs`
- Modify: `ffi/secretary-ffi-uniffi/src/wrappers/mod.rs:27` (add `pub mod trash;`)
- Modify: `ffi/secretary-ffi-uniffi/src/secretary.udl` (dict near `ExpiredEntry` ~:727; decl near the trash cluster ~:132-224)
- Modify: `ffi/secretary-ffi-uniffi/src/namespace/mod.rs` (fn + import at ~:14)
- Modify: `ffi/secretary-ffi-uniffi/src/lib.rs:68` (fn re-export), `:85` (type re-export)

**Interfaces:**
- Consumes: `secretary_ffi_bridge::{list_trashed_blocks, TrashedBlock}`.
- Produces (Swift, after Task 5 regen): `SecretaryKit.listTrashedBlocks(identity:manifest:) throws -> [TrashedBlock]`; generated Swift `struct TrashedBlock { blockUuid: Data; blockName: String; tombstonedAtMs: UInt64; tombstonedBy: Data }`.

- [ ] **Step 1: Create the wrapper value type**

Create `ffi/secretary-ffi-uniffi/src/wrappers/trash.rs`:

```rust
//! uniffi-side value type mirroring the bridge `TrashedBlock` DTO
//! (`secretary_ffi_bridge::TrashedBlock`). Pure data; the namespace fn
//! converts from the bridge type. Field names/shapes match
//! `secretary.udl`'s `TrashedBlock` dictionary exactly.

/// One trashed block, projected by name for a Trash view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrashedBlock {
    /// 16-byte UUID of the trashed block.
    pub block_uuid: Vec<u8>,
    /// Human-readable block name, recovered from the newest trashed file.
    pub block_name: String,
    /// Unix-millis the block was moved to trash.
    pub tombstoned_at_ms: u64,
    /// 16-byte UUID of the device that trashed the block.
    pub tombstoned_by: Vec<u8>,
}
```

- [ ] **Step 2: Declare the module**

In `ffi/secretary-ffi-uniffi/src/wrappers/mod.rs`, add `pub mod trash;` alphabetically in the `pub mod` list (after `pub mod sync;` / near `pub mod save;`). Do NOT add a `pub use` line here (retention has none — it's re-exported from `lib.rs`).

- [ ] **Step 3: Add the UDL dictionary + function**

In `ffi/secretary-ffi-uniffi/src/secretary.udl`, add the dictionary near `ExpiredEntry` (~:727):

```
/// One trashed block projected by name for a Trash view. Carries only the
/// block name (already plaintext in manifest summaries) + tombstone
/// metadata — no record material.
dictionary TrashedBlock {
    /// 16-byte UUID of the trashed block.
    bytes block_uuid;
    /// Human-readable block name.
    string block_name;
    /// Unix-millis the block was moved to trash.
    u64 tombstoned_at_ms;
    /// 16-byte UUID of the device that trashed the block.
    bytes tombstoned_by;
};
```

And the function declaration in the trash/restore/purge cluster (near `restore_block` ~:159 / `purge_block` ~:177):

```
    /// List every not-yet-purged trashed block, projected by name. See
    /// `ffi/secretary-ffi-bridge/src/trash/list.rs`. Raises `CorruptVault`
    /// / `FolderInvalid`.
    [Throws=VaultError]
    sequence<TrashedBlock> list_trashed_blocks(
        UnlockedIdentity identity,
        OpenVaultManifest manifest
    );
```

- [ ] **Step 4: Add the namespace projection fn**

In `ffi/secretary-ffi-uniffi/src/namespace/mod.rs`, add the wrapper import at the top imports block (near `use crate::wrappers::retention::{...}` ~:14):

```rust
use crate::wrappers::trash::TrashedBlock;
```

Then add the fn (near the other trash/purge fns, e.g. after `purge_block` ~:479):

```rust
pub fn list_trashed_blocks(
    identity: std::sync::Arc<UnlockedIdentity>,
    manifest: std::sync::Arc<OpenVaultManifest>,
) -> Result<Vec<TrashedBlock>, VaultError> {
    secretary_ffi_bridge::list_trashed_blocks(&identity.0, &manifest.0)
        .map(|v| {
            v.into_iter()
                .map(|b| TrashedBlock {
                    block_uuid: b.block_uuid.to_vec(),
                    block_name: b.block_name,
                    tombstoned_at_ms: b.tombstoned_at_ms,
                    tombstoned_by: b.tombstoned_by.to_vec(),
                })
                .collect()
        })
        .map_err(VaultError::from)
}
```

- [ ] **Step 5: Re-export from `lib.rs`**

In `ffi/secretary-ffi-uniffi/src/lib.rs`, add `list_trashed_blocks` to the `pub use namespace::{...}` list (~:68, alphabetical — before `move_record`), and add the type re-export near the retention one (~:85):

```rust
pub use wrappers::trash::TrashedBlock;
```

- [ ] **Step 6: Build + lint + UDL-scaffolding check**

Run: `cargo build --release -p secretary-ffi-uniffi && cargo clippy --release -p secretary-ffi-uniffi --tests -- -D warnings`
Expected: clean. (A missing crate-root re-export of either `list_trashed_blocks` or `TrashedBlock` fails here with an unresolved-path error from the generated scaffolding.)

- [ ] **Step 7: Full workspace gates + conformance runners**

Run:
```bash
cargo test --release --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
```
Expected: all pass. (The Swift/Kotlin conformance runners recompile the generated binding harness — they confirm the new `list_trashed_blocks` / `TrashedBlock` binding compiles on both. No `ConformanceErrors` change is needed because no new error variant was added.)

- [ ] **Step 8: Commit**

```bash
git add ffi/secretary-ffi-uniffi/
git commit -m "feat(ffi-uniffi): project list_trashed_blocks + TrashedBlock onto uniffi"
```

---

### Task 3: iOS pure value types, `TrashPort`, and formatting helpers

Pure, FFI-free, host-testable. TDD on the helpers.

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/TrashModels.swift`
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/TrashFormatting.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/TrashFormattingTests.swift`

**Interfaces:**
- Produces: value types `TrashedBlockInfo`, `ExpiredEntryInfo`, `RetentionReportInfo`, `PurgeResultInfo`, `EmptyTrashReportInfo`; protocol `TrashPort`; free functions `sortTrashed(_:) -> [TrashedBlockInfo]`, `emptyTrashConfirmBody(count:) -> String`, `retentionSummary(entries:windowMs:) -> String`, `msToDays(_:) -> UInt64`, `formatTrashedWhen(_:) -> String`.

- [ ] **Step 1: Write the failing helper tests**

Create `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/TrashFormattingTests.swift`:

```swift
import XCTest
@testable import SecretaryVaultAccess

final class TrashFormattingTests: XCTestCase {
    private func tb(_ b: UInt8, at ms: UInt64) -> TrashedBlockInfo {
        TrashedBlockInfo(blockUuid: [b], blockName: "n\(b)",
                         tombstonedAtMs: ms, tombstonedBy: [0])
    }

    func testSortTrashedNewestFirst() {
        let sorted = sortTrashed([tb(1, at: 100), tb(2, at: 300), tb(3, at: 200)])
        XCTAssertEqual(sorted.map { $0.tombstonedAtMs }, [300, 200, 100])
    }

    func testEmptyTrashConfirmBodySingular() {
        XCTAssertEqual(emptyTrashConfirmBody(count: 1),
            "The 1 item in trash will be permanently deleted. This cannot be undone.")
    }

    func testEmptyTrashConfirmBodyPlural() {
        XCTAssertEqual(emptyTrashConfirmBody(count: 4),
            "All 4 items in trash will be permanently deleted. This cannot be undone.")
    }

    func testRetentionSummaryEmpty() {
        // 90 days in ms
        let ninetyDays: UInt64 = 90 * 86_400_000
        XCTAssertEqual(retentionSummary(entries: [], windowMs: ninetyDays),
            "No trashed items are older than 90 days.")
    }

    func testRetentionSummaryNonEmpty() {
        let ninetyDays: UInt64 = 90 * 86_400_000
        let e = [ExpiredEntryInfo(blockUuid: [1], tombstonedAtMs: 0,
                                  ageMs: 100 * 86_400_000)]
        XCTAssertEqual(retentionSummary(entries: e, windowMs: ninetyDays),
            "1 item trashed more than 90 days ago will be permanently deleted (oldest: 100 days).")
    }

    func testMsToDays() {
        XCTAssertEqual(msToDays(90 * 86_400_000), 90)
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter TrashFormattingTests`
Expected: FAIL — build error, `TrashedBlockInfo` / `sortTrashed` etc. undefined.

- [ ] **Step 3: Write the value types + `TrashPort`**

Create `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/TrashModels.swift`:

```swift
import Foundation

/// Read-only metadata for one trashed block. No secret material — the block
/// name is plaintext in the manifest; record content never leaves the core.
public struct TrashedBlockInfo: Equatable {
    public let blockUuid: [UInt8]
    public let blockName: String
    public let tombstonedAtMs: UInt64
    public let tombstonedBy: [UInt8]

    public init(blockUuid: [UInt8], blockName: String,
                tombstonedAtMs: UInt64, tombstonedBy: [UInt8]) {
        self.blockUuid = blockUuid
        self.blockName = blockName
        self.tombstonedAtMs = tombstonedAtMs
        self.tombstonedBy = tombstonedBy
    }

    /// Lowercase hex, no dashes — stable SwiftUI list identity.
    public var uuidHex: String { blockUuid.map { String(format: "%02x", $0) }.joined() }
}

/// One trash entry eligible for retention auto-purge (preview only).
public struct ExpiredEntryInfo: Equatable {
    public let blockUuid: [UInt8]
    public let tombstonedAtMs: UInt64
    public let ageMs: UInt64

    public init(blockUuid: [UInt8], tombstonedAtMs: UInt64, ageMs: UInt64) {
        self.blockUuid = blockUuid
        self.tombstonedAtMs = tombstonedAtMs
        self.ageMs = ageMs
    }
}

/// Aggregate outcome of a retention auto-purge commit. Counts only.
public struct RetentionReportInfo: Equatable {
    public let purgedCount: UInt32
    public let sharedCount: UInt32
    public let ownerOnlyCount: UInt32
    public let unknownCount: UInt32
    public let filesRemoved: UInt32
    public let filesFailed: UInt32
    public let windowMs: UInt64

    public init(purgedCount: UInt32, sharedCount: UInt32, ownerOnlyCount: UInt32,
                unknownCount: UInt32, filesRemoved: UInt32, filesFailed: UInt32,
                windowMs: UInt64) {
        self.purgedCount = purgedCount
        self.sharedCount = sharedCount
        self.ownerOnlyCount = ownerOnlyCount
        self.unknownCount = unknownCount
        self.filesRemoved = filesRemoved
        self.filesFailed = filesFailed
        self.windowMs = windowMs
    }
}

/// Outcome of a single-block purge.
public struct PurgeResultInfo: Equatable {
    public let blockUuid: [UInt8]
    public let wasShared: Bool?
    public let recipientCount: UInt16?
    public let filesRemoved: UInt32

    public init(blockUuid: [UInt8], wasShared: Bool?,
                recipientCount: UInt16?, filesRemoved: UInt32) {
        self.blockUuid = blockUuid
        self.wasShared = wasShared
        self.recipientCount = recipientCount
        self.filesRemoved = filesRemoved
    }
}

/// Aggregate outcome of an empty-trash batch. Counts only.
public struct EmptyTrashReportInfo: Equatable {
    public let purgedCount: UInt32
    public let sharedCount: UInt32
    public let ownerOnlyCount: UInt32
    public let unknownCount: UInt32
    public let filesRemoved: UInt32
    public let filesFailed: UInt32

    public init(purgedCount: UInt32, sharedCount: UInt32, ownerOnlyCount: UInt32,
                unknownCount: UInt32, filesRemoved: UInt32, filesFailed: UInt32) {
        self.purgedCount = purgedCount
        self.sharedCount = sharedCount
        self.ownerOnlyCount = ownerOnlyCount
        self.unknownCount = unknownCount
        self.filesRemoved = filesRemoved
        self.filesFailed = filesFailed
    }
}

/// The vault-trash operations a Trash browser needs. Conformed by the
/// `SecretaryKit` adapter (`UniffiVaultSession`) and by `FakeTrashPort` in
/// tests. `AnyObject, Sendable` mirrors `VaultSession` (reference identity
/// for handle ownership; crosses the gate's async boundary).
public protocol TrashPort: AnyObject, Sendable {
    /// All not-yet-purged trashed blocks, projected by name.
    func listTrashedBlocks() throws -> [TrashedBlockInfo]
    /// Retention preview for `windowMs` (adapter supplies `now`). Non-throwing.
    func expiredTrashEntries(windowMs: UInt64) -> [ExpiredEntryInfo]
    /// The frozen default retention window (90 days).
    func defaultRetentionWindowMs() -> UInt64
    /// Restore the newest trashed copy of a block.
    func restoreBlock(uuid: [UInt8]) throws
    /// Permanently purge one trashed block.
    func purgeBlock(uuid: [UInt8]) throws -> PurgeResultInfo
    /// Permanently purge every currently-trashed block.
    func emptyTrash() throws -> EmptyTrashReportInfo
    /// Permanently purge every trashed block older than `windowMs`.
    func autoPurgeExpired(windowMs: UInt64) throws -> RetentionReportInfo
}
```

- [ ] **Step 4: Write the formatting helpers**

Create `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/TrashFormatting.swift`:

```swift
import Foundation

/// Milliseconds per day — the days↔ms conversion base.
public let msPerDay: UInt64 = 86_400_000

/// Whole days in `ms` (floor).
public func msToDays(_ ms: UInt64) -> UInt64 { ms / msPerDay }

/// Trashed blocks newest-first by tombstone time (parity: desktop `sortTrashed`).
public func sortTrashed(_ entries: [TrashedBlockInfo]) -> [TrashedBlockInfo] {
    entries.sorted { $0.tombstonedAtMs > $1.tombstonedAtMs }
}

/// Absolute yyyy-MM-dd (POSIX, locale-independent) of a tombstone timestamp.
public func formatTrashedWhen(_ ms: UInt64) -> String {
    let f = DateFormatter()
    f.locale = Locale(identifier: "en_US_POSIX")
    f.timeZone = TimeZone(identifier: "UTC")
    f.dateFormat = "yyyy-MM-dd"
    return f.string(from: Date(timeIntervalSince1970: Double(ms) / 1000.0))
}

/// Empty-trash confirm body (parity: desktop `emptyTrashConfirmBody`).
public func emptyTrashConfirmBody(count: Int) -> String {
    let lead = count == 1 ? "The 1 item" : "All \(count) items"
    return "\(lead) in trash will be permanently deleted. This cannot be undone."
}

/// Retention summary (parity: desktop `retentionSummary`).
public func retentionSummary(entries: [ExpiredEntryInfo], windowMs: UInt64) -> String {
    let days = msToDays(windowMs)
    if entries.isEmpty {
        return "No trashed items are older than \(days) days."
    }
    let n = entries.count
    let oldestDays = msToDays(entries.map { $0.ageMs }.max() ?? 0)
    let noun = n == 1 ? "item" : "items"
    return "\(n) \(noun) trashed more than \(days) days ago will be permanently deleted (oldest: \(oldestDays) days)."
}
```

- [ ] **Step 5: Run to verify it passes**

Run: `cd ios/SecretaryVaultAccess && swift test --filter TrashFormattingTests`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/TrashModels.swift ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/TrashFormatting.swift ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/TrashFormattingTests.swift
git commit -m "feat(ios): pure Trash value types, TrashPort, and formatting helpers"
```

---

### Task 4: `FakeTrashPort` + `TrashViewModel` (host-tested)

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeTrashPort.swift`
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/TrashViewModel.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/TrashViewModelTests.swift`

**Interfaces:**
- Consumes: `TrashPort`, `WriteReauthGate`, `FakeWriteReauthGate`, the value types + helpers (Task 3).
- Produces: `@MainActor final class TrashViewModel: ObservableObject` with `init(port: TrashPort, gate: WriteReauthGate)`; `@Published private(set) var entries: [TrashedBlockInfo]`, `error: VaultAccessError?`, `isWriting: Bool`, `preview: [ExpiredEntryInfo]?`; methods `load()`, `restore(uuid:) async`, `purge(uuid:) async`, `emptyTrash() async`, `previewRetention()`, `runRetention() async`.

- [ ] **Step 1: Write the FakeTrashPort**

Create `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeTrashPort.swift`:

```swift
import SecretaryVaultAccess

/// In-memory `TrashPort` double with spies + write-failure injection,
/// modeled on `FakeVaultSession`.
public final class FakeTrashPort: TrashPort, @unchecked Sendable {
    public var trashedBlocks: [TrashedBlockInfo]
    public var expiredEntries: [ExpiredEntryInfo]
    public var defaultWindowMs: UInt64
    public var failNextWrite: VaultAccessError?

    public private(set) var listCount = 0
    public private(set) var previewCount = 0
    public private(set) var restoredUuids: [[UInt8]] = []
    public private(set) var purgedUuids: [[UInt8]] = []
    public private(set) var emptyTrashCount = 0
    public private(set) var autoPurgeWindows: [UInt64] = []

    public init(trashedBlocks: [TrashedBlockInfo] = [],
                expiredEntries: [ExpiredEntryInfo] = [],
                defaultWindowMs: UInt64 = 90 * 86_400_000) {
        self.trashedBlocks = trashedBlocks
        self.expiredEntries = expiredEntries
        self.defaultWindowMs = defaultWindowMs
    }

    private func throwIfInjected() throws {
        if let e = failNextWrite { failNextWrite = nil; throw e }
    }

    public func listTrashedBlocks() throws -> [TrashedBlockInfo] {
        listCount += 1
        return trashedBlocks
    }

    public func expiredTrashEntries(windowMs: UInt64) -> [ExpiredEntryInfo] {
        previewCount += 1
        return expiredEntries
    }

    public func defaultRetentionWindowMs() -> UInt64 { defaultWindowMs }

    public func restoreBlock(uuid: [UInt8]) throws {
        try throwIfInjected()
        restoredUuids.append(uuid)
        trashedBlocks.removeAll { $0.blockUuid == uuid }
    }

    public func purgeBlock(uuid: [UInt8]) throws -> PurgeResultInfo {
        try throwIfInjected()
        purgedUuids.append(uuid)
        trashedBlocks.removeAll { $0.blockUuid == uuid }
        return PurgeResultInfo(blockUuid: uuid, wasShared: false,
                               recipientCount: 0, filesRemoved: 1)
    }

    public func emptyTrash() throws -> EmptyTrashReportInfo {
        try throwIfInjected()
        emptyTrashCount += 1
        let n = UInt32(trashedBlocks.count)
        trashedBlocks.removeAll()
        return EmptyTrashReportInfo(purgedCount: n, sharedCount: 0, ownerOnlyCount: n,
                                    unknownCount: 0, filesRemoved: n, filesFailed: 0)
    }

    public func autoPurgeExpired(windowMs: UInt64) throws -> RetentionReportInfo {
        try throwIfInjected()
        autoPurgeWindows.append(windowMs)
        let n = UInt32(expiredEntries.count)
        return RetentionReportInfo(purgedCount: n, sharedCount: 0, ownerOnlyCount: n,
                                   unknownCount: 0, filesRemoved: n, filesFailed: 0,
                                   windowMs: windowMs)
    }
}
```

- [ ] **Step 2: Write the failing VM tests**

Create `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/TrashViewModelTests.swift`:

```swift
import XCTest
@testable import SecretaryVaultAccessUI
import SecretaryVaultAccess
import SecretaryVaultAccessTesting

@MainActor
final class TrashViewModelTests: XCTestCase {
    private func tb(_ b: UInt8, at ms: UInt64) -> TrashedBlockInfo {
        TrashedBlockInfo(blockUuid: [b], blockName: "n\(b)",
                         tombstonedAtMs: ms, tombstonedBy: [0])
    }

    func testLoadSortsNewestFirst() {
        let port = FakeTrashPort(trashedBlocks: [tb(1, at: 100), tb(2, at: 300)])
        let vm = TrashViewModel(port: port, gate: FakeWriteReauthGate())
        vm.load()
        XCTAssertEqual(vm.entries.map { $0.tombstonedAtMs }, [300, 100])
    }

    func testPurgeGatesThenRemoves() async {
        let port = FakeTrashPort(trashedBlocks: [tb(1, at: 100)])
        let gate = FakeWriteReauthGate()
        let vm = TrashViewModel(port: port, gate: gate)
        vm.load()
        await vm.purge(uuid: [1])
        XCTAssertEqual(gate.authorizeCount, 1)
        XCTAssertEqual(port.purgedUuids, [[1]])
        XCTAssertTrue(vm.entries.isEmpty)
        XCTAssertNil(vm.error)
    }

    func testPurgeBlockedByReauthDoesNotWrite() async {
        let port = FakeTrashPort(trashedBlocks: [tb(1, at: 100)])
        let gate = FakeWriteReauthGate()
        gate.failNext = .reauthFailed("cancelled")
        let vm = TrashViewModel(port: port, gate: gate)
        vm.load()
        await vm.purge(uuid: [1])
        XCTAssertEqual(vm.error, .reauthFailed("cancelled"))
        XCTAssertEqual(port.purgedUuids, [], "no purge on refused re-auth")
        XCTAssertEqual(vm.entries.count, 1, "entry stays listed")
        XCTAssertEqual(gate.authorizeCount, 1)
    }

    func testEmptyTrashGatesReloadsAndDiscardsReport() async {
        let port = FakeTrashPort(trashedBlocks: [tb(1, at: 100), tb(2, at: 200)])
        let gate = FakeWriteReauthGate()
        let vm = TrashViewModel(port: port, gate: gate)
        vm.load()
        await vm.emptyTrash()
        XCTAssertEqual(gate.authorizeCount, 1)
        XCTAssertEqual(port.emptyTrashCount, 1)
        XCTAssertTrue(vm.entries.isEmpty)
    }

    func testPreviewRetentionIsUngated() {
        let port = FakeTrashPort(
            expiredEntries: [ExpiredEntryInfo(blockUuid: [1], tombstonedAtMs: 0,
                                              ageMs: 100 * 86_400_000)])
        let gate = FakeWriteReauthGate()
        let vm = TrashViewModel(port: port, gate: gate)
        vm.previewRetention()
        XCTAssertEqual(port.previewCount, 1)
        XCTAssertEqual(gate.authorizeCount, 0, "preview is a read; no re-auth")
        XCTAssertEqual(vm.preview?.count, 1)
    }

    func testRunRetentionUsesDefaultWindowAndGates() async {
        let port = FakeTrashPort(
            expiredEntries: [ExpiredEntryInfo(blockUuid: [1], tombstonedAtMs: 0, ageMs: 1)],
            defaultWindowMs: 90 * 86_400_000)
        let gate = FakeWriteReauthGate()
        let vm = TrashViewModel(port: port, gate: gate)
        await vm.runRetention()
        XCTAssertEqual(gate.authorizeCount, 1)
        XCTAssertEqual(port.autoPurgeWindows, [90 * 86_400_000])
    }
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter TrashViewModelTests`
Expected: FAIL — `TrashViewModel` undefined.

- [ ] **Step 4: Write the view model**

Create `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/TrashViewModel.swift`:

```swift
import Combine
import SecretaryVaultAccess

/// Host-testable Trash browser view model. Mirrors
/// `VaultBrowseViewModel.reauthedWrite`: the `isWriting` guard is set BEFORE
/// the gate await; a refused re-auth aborts silently (error surfaced, list
/// untouched). Destructive-op reports are discarded — the reloaded (empty)
/// list is the success signal, parity with desktop.
@MainActor
public final class TrashViewModel: ObservableObject {
    @Published public private(set) var entries: [TrashedBlockInfo] = []
    @Published public private(set) var error: VaultAccessError?
    @Published public private(set) var isWriting = false
    /// Populated by `previewRetention()`; drives the retention sheet summary.
    @Published public private(set) var preview: [ExpiredEntryInfo]?

    private let port: TrashPort
    private let gate: WriteReauthGate

    public init(port: TrashPort, gate: WriteReauthGate) {
        self.port = port
        self.gate = gate
    }

    /// The frozen 90-day default retention window (no per-vault setting yet).
    public var retentionWindowMs: UInt64 { port.defaultRetentionWindowMs() }

    public func load() {
        error = nil
        do {
            entries = sortTrashed(try port.listTrashedBlocks())
        } catch let e as VaultAccessError {
            error = e
        } catch {
            self.error = .other(String(describing: error))
        }
    }

    public func previewRetention() {
        preview = port.expiredTrashEntries(windowMs: port.defaultRetentionWindowMs())
    }

    public func restore(uuid: [UInt8]) async {
        _ = await reauthedWrite(reason: "Confirm restoring this block") {
            try self.port.restoreBlock(uuid: uuid)
        }
    }

    public func purge(uuid: [UInt8]) async {
        _ = await reauthedWrite(reason: "Confirm permanently deleting this block") {
            _ = try self.port.purgeBlock(uuid: uuid)
        }
    }

    public func emptyTrash() async {
        _ = await reauthedWrite(reason: "Confirm permanently deleting all trashed blocks") {
            _ = try self.port.emptyTrash()
        }
    }

    public func runRetention() async {
        let window = port.defaultRetentionWindowMs()
        _ = await reauthedWrite(reason: "Confirm permanently deleting expired trash") {
            _ = try self.port.autoPurgeExpired(windowMs: window)
        }
    }

    /// Re-auth, run a guarded write, then reload. `isWriting` set before the
    /// gate await so a second action during the biometric prompt is rejected.
    private func reauthedWrite(reason: String, op: () throws -> Void) async -> Bool {
        guard !isWriting else { return false }
        isWriting = true
        defer { isWriting = false }
        do {
            try await gate.authorizeWrite(reason: reason)
        } catch let e as VaultAccessError {
            error = e
            return false
        } catch {
            self.error = .reauthFailed(String(describing: error))
            return false
        }
        do {
            try op()
        } catch let e as VaultAccessError {
            error = e
            return false
        } catch {
            self.error = .other(String(describing: error))
            return false
        }
        load()
        return true
    }
}
```

- [ ] **Step 5: Run to verify it passes**

Run: `cd ios/SecretaryVaultAccess && swift test --filter TrashViewModelTests`
Expected: PASS.

- [ ] **Step 6: Run the whole pure package suite (no regression)**

Run: `cd ios/SecretaryVaultAccess && swift test`
Expected: PASS (all targets).

- [ ] **Step 7: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeTrashPort.swift ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/TrashViewModel.swift ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/TrashViewModelTests.swift
git commit -m "feat(ios): TrashViewModel + FakeTrashPort, host-tested (gate parity, report discarded)"
```

---

### Task 5: `UniffiVaultSession: TrashPort` adapter (+ regen bindings)

Wires the pure `TrashPort` to the uniffi free functions. Requires the regenerated xcframework (Tasks 1–2 must be committed first). Verified by `xcodebuild test -scheme SecretaryKit` compiling + linking the adapter.

**Files:**
- Create: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSession+Trash.swift`
- Modify: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/VaultErrorMapping.swift`

**Interfaces:**
- Consumes: generated `SecretaryKit.{listTrashedBlocks, expiredTrashEntries, defaultRetentionWindowMs, restoreBlock, purgeBlock, emptyTrash, autoPurgeExpired}` + generated structs `TrashedBlock`/`ExpiredEntry`/`PurgeReport`/`EmptyTrashReport`/`RetentionPurgeReport`; the private `write`/`lock`/`deviceUuid`/`nowMs`/`mapVaultAccessError` helpers on `UniffiVaultSession`.
- Produces: `UniffiVaultSession: TrashPort` conformance.

- [ ] **Step 1: Regenerate the Swift bindings + xcframework**

Run (backgrounded + log-polled — this is the multi-minute silent build; do NOT block a watchdog on it):
`bash ios/scripts/build-xcframework.sh`
Expected: exits 0; regenerates `ios/SecretaryKit/Sources/SecretaryKit/secretary.swift` (gitignored artifact) now containing `func listTrashedBlocks`, `func purgeBlock`, `func emptyTrash`, `func expiredTrashEntries`, `func autoPurgeExpired`, `func defaultRetentionWindowMs`, and `struct TrashedBlock`.

Verify: `grep -c "func listTrashedBlocks\|func purgeBlock\|func emptyTrash" ios/SecretaryKit/Sources/SecretaryKit/secretary.swift` → ≥ 3.

- [ ] **Step 2: Add the error-mapping arms**

`purge_block` / `restore_block` can raise `BlockNotInTrash` / `BlockPurged`, which currently fall through `mapVaultAccessError`'s `default` to `.other(...)`. Map them to the existing `.blockNotFound` case (no new `VaultAccessError` case needed). In `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/VaultErrorMapping.swift`, add before `default:` in the `switch`:

```swift
    case .BlockNotInTrash(let detail):      return .blockNotFound(detail)
    case .BlockPurged(let detail):          return .blockNotFound(detail)
```

(If the generated `VaultError` enum names these cases differently, match the generated spelling — check `grep -n "BlockNotInTrash\|BlockPurged" ios/SecretaryKit/Sources/SecretaryKit/secretary.swift`.)

- [ ] **Step 3: Write the adapter extension**

Create `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSession+Trash.swift`:

```swift
import Foundation
import SecretaryVaultAccess

/// `TrashPort` conformance for `UniffiVaultSession`. Reuses the private
/// `write`/`lock`/`deviceUuid`/`nowMs`/`mapVaultAccessError` helpers so trash
/// writes get the same device-uuid/now resolution, wiped-guard, and error
/// mapping as every other write. Only block names + counts cross this
/// boundary — no record plaintext (guaranteed by the bridge).
extension UniffiVaultSession: TrashPort {
    public func listTrashedBlocks() throws -> [TrashedBlockInfo] {
        try readTrash {
            try SecretaryKit.listTrashedBlocks(identity: identity, manifest: manifest)
                .map { b in
                    TrashedBlockInfo(blockUuid: [UInt8](b.blockUuid),
                                     blockName: b.blockName,
                                     tombstonedAtMs: b.tombstonedAtMs,
                                     tombstonedBy: [UInt8](b.tombstonedBy))
                }
        }
    }

    public func expiredTrashEntries(windowMs: UInt64) -> [ExpiredEntryInfo] {
        readTrashInfallible {
            SecretaryKit.expiredTrashEntries(
                manifest: manifest, windowMs: windowMs, nowMs: Self.nowMsPublic())
                .map { e in
                    ExpiredEntryInfo(blockUuid: [UInt8](e.blockUuid),
                                     tombstonedAtMs: e.tombstonedAtMs, ageMs: e.ageMs)
                }
        }
    }

    public func defaultRetentionWindowMs() -> UInt64 {
        SecretaryKit.defaultRetentionWindowMs()
    }

    public func restoreBlock(uuid: [UInt8]) throws {
        try writeTrash { dev, now in
            try SecretaryKit.restoreBlock(
                identity: identity, manifest: manifest, blockUuid: Data(uuid),
                deviceUuid: Data(dev), nowMs: now)
        }
    }

    public func purgeBlock(uuid: [UInt8]) throws -> PurgeResultInfo {
        try writeTrashReturning { dev, now in
            let r = try SecretaryKit.purgeBlock(
                identity: identity, manifest: manifest, blockUuid: Data(uuid),
                deviceUuid: Data(dev), nowMs: now)
            return PurgeResultInfo(blockUuid: [UInt8](r.blockUuid), wasShared: r.wasShared,
                                   recipientCount: r.recipientCount, filesRemoved: r.filesRemoved)
        }
    }

    public func emptyTrash() throws -> EmptyTrashReportInfo {
        try writeTrashReturning { dev, now in
            let r = try SecretaryKit.emptyTrash(
                identity: identity, manifest: manifest, deviceUuid: Data(dev), nowMs: now)
            return EmptyTrashReportInfo(
                purgedCount: r.purgedCount, sharedCount: r.sharedCount,
                ownerOnlyCount: r.ownerOnlyCount, unknownCount: r.unknownCount,
                filesRemoved: r.filesRemoved, filesFailed: r.filesFailed)
        }
    }

    public func autoPurgeExpired(windowMs: UInt64) throws -> RetentionReportInfo {
        try writeTrashReturning { dev, now in
            let r = try SecretaryKit.autoPurgeExpired(
                identity: identity, manifest: manifest, windowMs: windowMs,
                nowMs: now, deviceUuid: Data(dev))
            return RetentionReportInfo(
                purgedCount: r.purgedCount, sharedCount: r.sharedCount,
                ownerOnlyCount: r.ownerOnlyCount, unknownCount: r.unknownCount,
                filesRemoved: r.filesRemoved, filesFailed: r.filesFailed, windowMs: r.windowMs)
        }
    }
}
```

This references four small helpers on `UniffiVaultSession` that generalize the existing private `write`. Add them to `UniffiVaultSession.swift` (next to the private `write`), OR — simpler — make the existing private members accessible to this same-module extension by giving them `internal` visibility and reusing `write`/`lock`/`deviceUuid`/`mapVaultAccessError`/`nowMs` directly. **Chosen approach:** add these `internal` helpers to `UniffiVaultSession.swift` mirroring the existing `write`:

```swift
    /// Read under the lock with the wiped-guard, returning a value or throwing.
    internal func readTrash<T>(_ body: () throws -> T) throws -> T {
        try lock.withLock {
            if wiped { throw VaultAccessError.other("read on a wiped session") }
            do { return try body() }
            catch let e as VaultError { throw mapVaultAccessError(e) }
        }
    }

    /// Infallible read under the lock; returns an empty projection when wiped.
    internal func readTrashInfallible<T>(_ body: () -> [T]) -> [T] {
        lock.withLock { wiped ? [] : body() }
    }

    /// Like `write`, but the body returns a value.
    internal func writeTrashReturning<T>(
        _ body: (_ deviceUuid: [UInt8], _ nowMs: UInt64) throws -> T) throws -> T {
        try lock.withLock {
            if wiped { throw VaultAccessError.other("write on a wiped session") }
            let dev = try deviceUuid()
            do { return try body(dev, Self.nowMs()) }
            catch let e as VaultError { throw mapVaultAccessError(e) }
        }
    }

    /// Alias for the existing `write` (kept for symmetry in the trash extension).
    internal func writeTrash(
        _ body: (_ deviceUuid: [UInt8], _ nowMs: UInt64) throws -> Void) throws {
        try write(body)
    }

    /// `nowMs()` exposed for the infallible-read preview path.
    internal static func nowMsPublic() -> UInt64 { nowMs() }
```

(If `write`, `lock`, `wiped`, `deviceUuid`, `nowMs`, `mapVaultAccessError` are `private`, widen exactly those to `internal` — they stay module-internal, not `public`.)

- [ ] **Step 4: Build + test the SecretaryKit scheme**

Run (backgrounded + log-polled): `bash ios/scripts/run-ios-tests.sh`
Expected: the pure package tests pass (Step 1 of the script), the xcframework rebuilds, and `xcodebuild test -scheme SecretaryKit` compiles the adapter + passes. Also confirm the app target builds (`build-app.sh`, invoked by the script).

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSession+Trash.swift ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSession.swift ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/VaultErrorMapping.swift
git commit -m "feat(ios): UniffiVaultSession TrashPort adapter over the uniffi trash fns"
```

---

### Task 6: SwiftUI Trash screen + entry point

**Files:**
- Create: `ios/SecretaryApp/Sources/TrashScreen.swift`
- Modify: `ios/SecretaryApp/Sources/VaultBrowseScreen.swift` (toolbar entry point)
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultBrowseViewModel.swift` (`trashPort` dep + `makeTrashViewModel()`)

**Interfaces:**
- Consumes: `TrashViewModel`, `TrashPort`, the pure helpers, `VaultBrowseViewModel`.
- Produces: `TrashScreen` view; `VaultBrowseViewModel.makeTrashViewModel() -> TrashViewModel?`.

- [ ] **Step 1: Add the `trashPort` dep + factory on `VaultBrowseViewModel`**

The browse VM already spawns child VMs (`makeEditViewModel`). Give it an optional `trashPort` (same object as `session` at composition; nil in existing tests so their 2-arg init still compiles) and a factory. In `VaultBrowseViewModel.swift`, change the init + stored deps:

```swift
    private let session: VaultSession
    private let gate: WriteReauthGate
    private let trashPort: TrashPort?
    public init(session: VaultSession, gate: WriteReauthGate, trashPort: TrashPort? = nil) {
        self.session = session
        self.gate = gate
        self.trashPort = trashPort
    }
```

Add the factory near `makeEditViewModel`:

```swift
    /// Build the Trash browser VM sharing this session's re-auth gate.
    /// Returns nil when no trash port was injected (e.g. in browse-only tests).
    public func makeTrashViewModel() -> TrashViewModel? {
        guard let trashPort else { return nil }
        return TrashViewModel(port: trashPort, gate: gate)
    }
```

- [ ] **Step 2: Run the existing browse VM tests (no regression)**

Run: `cd ios/SecretaryVaultAccess && swift test`
Expected: PASS — the defaulted `trashPort: nil` keeps every existing `VaultBrowseViewModel(session:gate:)` call compiling.

- [ ] **Step 3: Write the Trash screen**

Create `ios/SecretaryApp/Sources/TrashScreen.swift`:

```swift
import SwiftUI
import SecretaryVaultAccess
import SecretaryVaultAccessUI

struct TrashScreen: View {
    @StateObject private var viewModel: TrashViewModel
    @State private var pendingPurge: TrashedBlockInfo?
    @State private var pendingEmpty = false
    @State private var showRetention = false

    init(viewModel: TrashViewModel) {
        self._viewModel = StateObject(wrappedValue: viewModel)
    }

    var body: some View {
        List {
            if viewModel.entries.isEmpty {
                Text("Trash is empty.").foregroundStyle(.secondary)
            }
            ForEach(viewModel.entries, id: \.uuidHex) { block in
                VStack(alignment: .leading, spacing: 2) {
                    Text(block.blockName.isEmpty ? "block" : block.blockName)
                        .font(.headline)
                    Text("trashed \(formatTrashedWhen(block.tombstonedAtMs))")
                        .font(.caption).foregroundStyle(.secondary)
                }
                .swipeActions(edge: .trailing) {
                    Button(role: .destructive) { pendingPurge = block } label: {
                        Label("Delete forever", systemImage: "trash")
                    }
                    .disabled(viewModel.isWriting)
                    Button {
                        Task { await viewModel.restore(uuid: block.blockUuid) }
                    } label: { Label("Restore", systemImage: "arrow.uturn.backward") }
                    .tint(.blue)
                    .disabled(viewModel.isWriting)
                }
            }
        }
        .navigationTitle("Trash")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button { showRetention = true } label: {
                    Label("Run retention now", systemImage: "clock.arrow.circlepath")
                }
                .disabled(viewModel.isWriting)
            }
            if !viewModel.entries.isEmpty {
                ToolbarItem(placement: .bottomBar) {
                    Button(role: .destructive) { pendingEmpty = true } label: {
                        Text("Empty trash")
                    }
                    .disabled(viewModel.isWriting)
                    .accessibilityIdentifier("empty-trash")
                }
            }
        }
        .onAppear { viewModel.load() }
        .confirmationDialog("Delete forever?",
            isPresented: Binding(get: { pendingPurge != nil },
                                 set: { if !$0 { pendingPurge = nil } }),
            titleVisibility: .visible) {
            if let block = pendingPurge {
                Button("Delete forever", role: .destructive) {
                    Task { await viewModel.purge(uuid: block.blockUuid) }
                    pendingPurge = nil
                }.disabled(viewModel.isWriting)
            }
            Button("Cancel", role: .cancel) { pendingPurge = nil }
        } message: {
            if let block = pendingPurge {
                Text("\"\(block.blockName)\" will be permanently deleted. This cannot be undone.")
            }
        }
        .confirmationDialog("Empty trash?",
            isPresented: $pendingEmpty, titleVisibility: .visible) {
            Button("Empty trash", role: .destructive) {
                Task { await viewModel.emptyTrash() }
                pendingEmpty = false
            }.disabled(viewModel.isWriting)
            Button("Cancel", role: .cancel) { pendingEmpty = false }
        } message: {
            Text(emptyTrashConfirmBody(count: viewModel.entries.count))
        }
        .sheet(isPresented: $showRetention) {
            RetentionSheet(viewModel: viewModel, isPresented: $showRetention)
        }
    }
}

private struct RetentionSheet: View {
    @ObservedObject var viewModel: TrashViewModel
    @Binding var isPresented: Bool

    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                if let preview = viewModel.preview {
                    Text(retentionSummary(entries: preview,
                                          windowMs: viewModel.retentionWindowMs))
                        .multilineTextAlignment(.center)
                    if !preview.isEmpty {
                        Button(role: .destructive) {
                            Task { await viewModel.runRetention(); isPresented = false }
                        } label: { Text("Purge \(preview.count) items") }
                        .disabled(viewModel.isWriting)
                    }
                } else {
                    ProgressView("Checking trash…")
                }
                Spacer()
            }
            .padding()
            .navigationTitle("Run retention")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") { isPresented = false }
                }
            }
            .onAppear { viewModel.previewRetention() }
        }
    }
}
```

- [ ] **Step 4: Wire the entry point in `VaultBrowseScreen`**

In `VaultBrowseScreen.swift`, add a toolbar item inside the existing `.toolbar { ... }` (mirroring the "New block" button), pushing the Trash screen:

```swift
                ToolbarItem(placement: .primaryAction) {
                    if let trashVM = viewModel.makeTrashViewModel() {
                        NavigationLink {
                            TrashScreen(viewModel: trashVM)
                        } label: {
                            Label("Trash", systemImage: "trash")
                        }
                        .disabled(viewModel.isWriting)
                        .accessibilityIdentifier("open-trash")
                    }
                }
```

- [ ] **Step 5: Pass the trash port at composition**

In `ios/SecretaryApp/Sources/SecretaryApp.swift`, at BOTH `route = .browse(VaultBrowseViewModel(session: session, gate: gate), ...)` sites (~:195 password path, ~:283 device path), pass the same session object as the trash port:

```swift
            route = .browse(VaultBrowseViewModel(session: session, gate: gate, trashPort: session),
                            syncVM, monitor, scoped)
```

(This requires `session` to be a `UniffiVaultSession`, which now conforms to `TrashPort`. If `session` is typed as `VaultSession` at these sites, cast: `trashPort: session as? TrashPort`.)

- [ ] **Step 6: Build the app + full iOS suite**

Run (backgrounded + log-polled): `bash ios/scripts/run-ios-tests.sh`
Expected: pure tests pass, `SecretaryKit` scheme tests pass, the app target builds cleanly (SwiftUI compiles).

- [ ] **Step 7: Commit**

```bash
git add ios/SecretaryApp/Sources/TrashScreen.swift ios/SecretaryApp/Sources/VaultBrowseScreen.swift ios/SecretaryApp/Sources/SecretaryApp.swift ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultBrowseViewModel.swift
git commit -m "feat(ios): Trash screen (list/restore/delete-forever/empty/retention) + browse entry point"
```

---

### Task 7: Docs — README + ROADMAP

**Files:**
- Modify: `README.md`
- Modify: `ROADMAP.md`

- [ ] **Step 1: Update README project-status**

In `README.md`, find the iOS/platform status bullets and add the shipped iOS trash-browser line (brief, dot-point style — no test-count walls). Note the deferred retention-window *setting* + Android mirror. Example bullet:
`- iOS: … + Trash browser (list / restore / delete-forever / empty-trash / run-retention against the 90-day default), behind the Face ID re-auth gate. Retention-window *setting* + Android mirror deferred.`

- [ ] **Step 2: Update ROADMAP**

In `ROADMAP.md`, mark the iOS trash/retention/purge slice's per-platform state: iOS trash-browser shipped (this slice); note the deferred retention-window setting and the Android mirror as the next mobile slices. Keep it consistent with how #409/#410 desktop entries are phrased.

- [ ] **Step 3: Verify links/format**

Run: `grep -n "Trash" README.md ROADMAP.md`
Expected: the new lines present, consistent with surrounding style.

- [ ] **Step 4: Commit**

```bash
git add README.md ROADMAP.md
git commit -m "docs: iOS Trash browser shipped; retention-window setting + Android deferred"
```

---

## Self-review

**Spec coverage:**
- §2 uniffi projection → Task 2. §2 pyo3 projection → Task 1. §2 Swift regen → Task 5 Step 1. §2 pure package (port/VM/helpers) → Tasks 3–4. §2 adapter → Task 5. §2 SecretaryApp UI → Task 6.
- §3 no-new-error-variant → Global Constraints + Tasks 1/2 (only `CorruptVault`/`FolderInvalid`). §3 no plaintext widening → value types carry only name+counts (Task 3).
- §4 dedicated `TrashPort` conformed by the same adapter → Tasks 3 + 5. §5 VM reauth envelope + discarded reports → Task 4. §6 SwiftUI push entry + verbatim copy → Task 6. §7 reuse shipped gate → Task 6 Step 5 (same instance). §8 tests → each Rust/Swift task + Task 2 Step 7 conformance runners + `run-ios-tests.sh`. §10 deferred items → Task 7.
- Fork ⓐ (no KAT change) → honored (no conformance.py/KAT edit; pyo3 pytest instead). Fork ⓑ (dedicated port, same adapter) → Tasks 3/5. Fork ⓒ (push nav) → Task 6 Step 4.

**Placeholder scan:** none — every code step carries full code; every command has expected output.

**Type consistency:** `TrashPort` method names (`listTrashedBlocks`, `expiredTrashEntries`, `defaultRetentionWindowMs`, `restoreBlock`, `purgeBlock`, `emptyTrash`, `autoPurgeExpired`) are identical in Task 3 (protocol), Task 4 (FakeTrashPort + VM callers), and Task 5 (adapter). Value-type field names (`blockUuid`, `blockName`, `tombstonedAtMs`, `tombstonedBy`, `ageMs`, the six report counts, `windowMs`, `wasShared`, `recipientCount`, `filesRemoved`) are consistent across Tasks 3–5. Rust `TrashedBlock` fields match the bridge struct (`block_uuid`, `block_name`, `tombstoned_at_ms`, `tombstoned_by`) in Tasks 1–2. VM method names (`load`, `previewRetention`, `restore`, `purge`, `emptyTrash`, `runRetention`) match between Task 4 (definition) and Task 6 (SwiftUI callers).
