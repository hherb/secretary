# iOS `include_deleted` Rust gate — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move record-level tombstone (soft-delete) visibility off the iOS Swift client into the shared Rust FFI bridge `read_block` as a first-class `include_deleted` parameter, making the Rust core the single source of truth for tombstone visibility across iOS, desktop, and Python.

**Architecture:** The bridge `read_block` gains `include_deleted: bool` and skips tombstoned records (building no `FieldHandle`) when it is `false`, so withheld secrets never cross the FFI seam. Because `core`, `cli`, `desktop/src-tauri`, and the three `ffi/*` crates share one cargo workspace, the signature change must compile workspace-wide in one task (Task 2). The Swift/Kotlin/Python test harnesses live outside the workspace and are updated in their own tasks. iOS switches from a client-side computed filter to a re-read on toggle.

**Tech Stack:** Rust (stable; `cargo test --release --workspace`), uniffi 0.31 UDL, PyO3, Swift (SwiftUI + `swift test` + uniffi harness scripts), Kotlin (uniffi harness scripts), Tauri (desktop, Rust + vitest).

**Spec:** [docs/superpowers/specs/2026-06-14-ios-include-deleted-rust-gate-design.md](../specs/2026-06-14-ios-include-deleted-rust-gate-design.md)

**Working directory for ALL tasks:** `/Users/hherb/src/secretary/.worktrees/ios-include-deleted-rust-gate` (branch `feature/ios-include-deleted-rust-gate`). Verify with `pwd && git branch --show-current` before any `cargo`/`git` command.

**Convention recap (from CLAUDE.md):**
- `#![forbid(unsafe_code)]`; clippy must stay clean with `-D warnings`.
- Pure free functions in reusable modules; doc comments + unit tests mandatory.
- No magic numbers.
- The cross-language conformance replay (Rust `dispatch/read.rs`, Swift `conformance.swift`, Kotlin `Conformance.kt`) must pass the **same** `include_deleted` value — this plan uses `true` there so no record is filtered out of the agreement check (no KAT regeneration; verified no `read_block` vector carries a tombstone).

---

## Task 1: Pure `record_is_visible` helper

The single decision point for record-level tombstone visibility. Pure, independently compilable (adds a new fn, changes no signature), TDD-clean.

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/record/orchestration.rs` (add fn + tests near the existing `#[cfg(test)] mod tests`)

- [ ] **Step 1: Write the failing tests**

Add to the `#[cfg(test)] mod tests` block at the bottom of `ffi/secretary-ffi-bridge/src/record/orchestration.rs` (after `handle_wiped_returns_corrupt_vault_with_wiped_detail`):

```rust
    #[test]
    fn record_is_visible_truth_table() {
        // Live records are always visible.
        assert!(record_is_visible(false, false));
        assert!(record_is_visible(false, true));
        // Tombstoned records are visible only when the caller asks for deleted.
        assert!(!record_is_visible(true, false));
        assert!(record_is_visible(true, true));
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /Users/hherb/src/secretary/.worktrees/ios-include-deleted-rust-gate && cargo test --release -p secretary-ffi-bridge record_is_visible_truth_table 2>&1 | tail -20`
Expected: FAIL — `cannot find function record_is_visible in this scope`.

- [ ] **Step 3: Add the pure helper**

Add near the top of `ffi/secretary-ffi-bridge/src/record/orchestration.rs` (just above `pub fn read_block`):

```rust
/// Whether a record is visible to a foreign reader.
///
/// A record is visible unless it is tombstoned and the caller did not ask
/// for deleted records. This is the single decision point for record-level
/// tombstone visibility across all platforms (iOS, desktop, Python) — the
/// per-platform clients no longer filter tombstoned records themselves.
fn record_is_visible(tombstone: bool, include_deleted: bool) -> bool {
    include_deleted || !tombstone
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test --release -p secretary-ffi-bridge record_is_visible_truth_table 2>&1 | tail -10`
Expected: PASS (`test result: ok. 1 passed`).

- [ ] **Step 5: Commit**

```bash
git add ffi/secretary-ffi-bridge/src/record/orchestration.rs
git commit -m "feat(ffi): pure record_is_visible tombstone-visibility helper"
```

---

## Task 2: Workspace-atomic `read_block` gate

Add `include_deleted: bool` to the bridge `read_block`, apply the gate, update the UDL, and update **every** Rust call site in the workspace so `cargo test --release --workspace` compiles. The existing bridge test `tombstone_record_hides_from_read_block` becomes the behavior driver (asserting both branches).

**Why atomic:** the workspace shares one `Cargo.toml`; changing the signature breaks the bridge lib, uniffi namespace + scaffolding (UDL arity must match), pyo3 crate, desktop, and the KAT helpers simultaneously. They must all be fixed in one task.

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/record/orchestration.rs` (signature + gate)
- Modify: `ffi/secretary-ffi-uniffi/src/secretary.udl` (UDL arity)
- Modify: `ffi/secretary-ffi-uniffi/src/namespace/mod.rs` (wrapper + in-crate test)
- Modify: `ffi/secretary-ffi-py/src/record.rs` (pyo3 wrapper)
- Modify (desktop callers): `desktop/src-tauri/src/commands/browse.rs`, `desktop/src-tauri/src/commands/edit.rs`, `desktop/src-tauri/src/settings/io.rs`
- Modify (bridge tests): `ffi/secretary-ffi-bridge/tests/read_block.rs`, `ffi/secretary-ffi-bridge/tests/save_block.rs`, `ffi/secretary-ffi-bridge/tests/edit.rs`
- Modify (KAT helpers): `core/tests/conformance_kat_helpers/dispatch/read.rs`, `core/tests/conformance_kat_helpers/dispatch/lifecycle.rs`, `core/tests/conformance_kat.rs`

**Call-site rule:** pass `false` (the app default — live-only) everywhere the assertion inspects only live records; pass `true` only where the test inspects tombstoned records or in the conformance replay. Special `true` sites are called out explicitly below; all other Rust call sites get `, false`.

- [ ] **Step 1: Write the failing behavior test (the RED driver)**

Replace the body of `tombstone_record_hides_from_read_block` in `ffi/secretary-ffi-bridge/tests/edit.rs` (currently lines ~258-283) with a both-branches assertion:

```rust
#[test]
fn tombstone_record_hides_from_read_block() {
    let opened = open_writable_golden_001();
    let block_uuid = [0x81u8; 16];
    let record_uuid = [0x82u8; 16];
    block_with_alice(&opened, block_uuid, record_uuid);

    tombstone_record(
        &opened.identity,
        &opened.manifest,
        block_uuid,
        record_uuid,
        DEVICE_UUID,
        3_000,
    )
    .expect("tombstone_record");

    // include_deleted = false: the tombstoned record is WITHHELD — it never
    // crosses the FFI projection, so its field handles are never built.
    let live_only = read_block(&opened.identity, &opened.manifest, &block_uuid, false).expect("read");
    assert!(
        find_record(&live_only, record_uuid).is_none(),
        "tombstoned record must be withheld when include_deleted=false"
    );
    live_only.wipe();

    // include_deleted = true: the record is present (soft-delete) and reports
    // tombstone() == true for the restore UI.
    let with_deleted = read_block(&opened.identity, &opened.manifest, &block_uuid, true).expect("read");
    let found = find_record(&with_deleted, record_uuid).expect("tombstoned record present when include_deleted=true");
    assert!(found.tombstone(), "tombstoned record must report tombstone()");
    with_deleted.wipe();
}
```

- [ ] **Step 2: Run to verify it fails to compile**

Run: `cargo test --release -p secretary-ffi-bridge --test edit tombstone_record_hides_from_read_block 2>&1 | tail -20`
Expected: FAIL — `this function takes 3 arguments but 4 arguments were supplied` (signature not yet changed).

- [ ] **Step 3: Change the bridge signature + apply the gate**

In `ffi/secretary-ffi-bridge/src/record/orchestration.rs`, update `read_block`:

```rust
pub fn read_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: &[u8; 16],
    include_deleted: bool,
) -> Result<BlockReadOutput, FfiVaultError> {
    let plaintext = decrypt_block_plaintext(identity, manifest, block_uuid)?;

    let mut records: Vec<Record> = Vec::with_capacity(plaintext.records.len());
    for r in plaintext.records {
        let CoreRecord {
            record_uuid,
            record_type,
            fields,
            tags,
            created_at_ms,
            last_mod_ms,
            tombstone,
            // unknown / tombstoned_at_ms intentionally not surfaced.
            ..
        } = r;

        // Tombstone visibility gate: withhold deleted records (and therefore
        // never build their FieldHandles, so no secret field bytes cross the
        // FFI seam) unless the caller asked for them.
        if !record_is_visible(tombstone, include_deleted) {
            continue;
        }

        let mut field_handles: Vec<FieldHandle> = Vec::with_capacity(fields.len());
        for (name, field) in fields {
            field_handles.push(FieldHandle::new(
                name,
                field.value,
                field.last_mod,
                field.device_uuid,
            ));
        }
        records.push(Record::new(
            record_uuid,
            record_type,
            tags,
            created_at_ms,
            last_mod_ms,
            tombstone,
            field_handles,
        ));
    }

    Ok(BlockReadOutput::new(
        plaintext.block_uuid,
        plaintext.block_name,
        records,
    ))
}
```

Also update the doc comment above `read_block` (the line `/// Decrypt and return all records in one block of an open vault.`) to:

```rust
/// Decrypt and return the visible records in one block of an open vault.
///
/// When `include_deleted` is `false`, tombstoned (soft-deleted) records are
/// withheld — their `FieldHandle`s are never constructed, so their secret
/// field bytes never cross the FFI seam. When `true`, tombstoned records are
/// returned carrying `tombstone() == true` (for a restore UI). This is the
/// single source of truth for tombstone visibility across all platforms.
```

- [ ] **Step 4: Update the UDL**

In `ffi/secretary-ffi-uniffi/src/secretary.udl`, change the `read_block` declaration to add the boolean (keep the existing `[Throws=VaultError]` and doc comment):

```
[Throws=VaultError]
BlockReadOutput read_block(
    UnlockedIdentity identity,
    OpenVaultManifest manifest,
    bytes block_uuid,
    boolean include_deleted
);
```

- [ ] **Step 5: Update the uniffi namespace wrapper + its in-crate test**

In `ffi/secretary-ffi-uniffi/src/namespace/mod.rs`, update `read_block` (around line 271) to accept and forward the flag:

```rust
pub fn read_block(
    identity: std::sync::Arc<UnlockedIdentity>,
    manifest: std::sync::Arc<OpenVaultManifest>,
    block_uuid: Vec<u8>,
    include_deleted: bool,
) -> Result<std::sync::Arc<BlockReadOutput>, VaultError> {
    if block_uuid.len() != 16 {
        return Err(VaultError::InvalidArgument {
            detail: format!("block_uuid must be 16 bytes, got {}", block_uuid.len()),
        });
    }
    let mut uuid_array = [0u8; 16];
    uuid_array.copy_from_slice(&block_uuid);
    secretary_ffi_bridge::read_block(&identity.0, &manifest.0, &uuid_array, include_deleted)
        .map(|b| std::sync::Arc::new(BlockReadOutput(b)))
        .map_err(VaultError::from)
}
```

And the in-crate wrong-length test call (around line 691) — add `, false`:

```rust
        match read_block(out.identity, out.manifest, vec![0u8; 15], false) {
```

- [ ] **Step 6: Update the pyo3 wrapper**

In `ffi/secretary-ffi-py/src/record.rs` (around line 204), add the param and a `#[pyo3(signature = ...)]` so Python callers can pass it positionally; forward to the bridge. Update the `# Raises` doc to keep listing the same variants (unchanged).

```rust
#[pyfunction]
#[pyo3(signature = (identity, manifest, block_uuid, include_deleted))]
#[allow(clippy::needless_pass_by_value)] // owned Vec<u8> required for bytes ∪ bytearray accept
pub(crate) fn read_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: Vec<u8>,
    include_deleted: bool,
) -> PyResult<BlockReadOutput> {
    if block_uuid.len() != 16 {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "block_uuid must be 16 bytes, got {}",
            block_uuid.len()
        )));
    }
    let mut uuid_array = [0u8; 16];
    uuid_array.copy_from_slice(&block_uuid);
    secretary_ffi_bridge::read_block(&identity.0, &manifest.0, &uuid_array, include_deleted)
        .map(BlockReadOutput)
        .map_err(ffi_vault_error_to_pyerr)
}
```

- [ ] **Step 7: Update desktop Rust call sites (minimal, to compile)**

- `desktop/src-tauri/src/commands/browse.rs:39` (`read_block_impl`): pass the command's own flag — change the call to `bridge_read_block(&u.identity, &u.manifest, &uuid, include_deleted)`.
- `desktop/src-tauri/src/commands/browse.rs:82` (`reveal_field_impl`): reveal targets live records only — change to `bridge_read_block(&u.identity, &u.manifest, &uuid, false)`.
- `desktop/src-tauri/src/commands/edit.rs:229`: edit reads live records — change to `bridge_read_block(&u.identity, &u.manifest, &block_uuid, false)`.
- `desktop/src-tauri/src/settings/io.rs:63`: settings block read is live — change to `read_block(identity, manifest, &block_uuid, false)`.

Leave `project_block_detail`'s own filter in place for now (it filters redundantly with the same flag — idempotent, correct). Task 3 removes the redundancy.

- [ ] **Step 8: Update bridge integration test call sites**

Add `, false` to every `read_block(...)` call in these files **except** the `tombstone_record_hides_from_read_block` test (already done in Step 1). All read live records:
- `ffi/secretary-ffi-bridge/tests/read_block.rs` — lines ~53, 66, 80, 92, 114, 128, 141, 224, 239, 255, 278.
- `ffi/secretary-ffi-bridge/tests/save_block.rs` — lines ~104, 209, 359, 464, 579.
- `ffi/secretary-ffi-bridge/tests/edit.rs` — lines ~95, 160, and 312 (the `resurrect_record_clears_tombstone_and_keeps_fields` read at 312 reads a *resurrected*, i.e. live, record → `false`).

- [ ] **Step 9: Update KAT helper call sites (conformance replay → `true`)**

- `core/tests/conformance_kat_helpers/dispatch/read.rs:31` — change to `secretary_ffi_bridge::record::read_block(&cached.identity, &cached.manifest, &uuid, true)` and add a one-line comment: `// include_deleted=true: conformance verifies the FULL decoded record set agrees across languages; no read_block vector carries a tombstone, so this is observationally identical to false.`
- `core/tests/conformance_kat_helpers/dispatch/lifecycle.rs:225` — the post-save round-trip read: change to `read_block(&cached.identity, &cached.manifest, &uuid, true)` (same parity rationale).
- `core/tests/conformance_kat.rs:273` (golden_vault_001 happy read) — `, true`.
- `core/tests/conformance_kat.rs:365` (wiped-handle read) — `, true`.

- [ ] **Step 10: Build + verify the whole workspace compiles and tests pass**

Run: `cargo test --release --workspace 2>&1 | tail -30`
Expected: PASS — including `tombstone_record_hides_from_read_block` (both branches) and all conformance KAT replay tests. No KAT regeneration prompt (conformance output unchanged).

**Safety net:** if the compile flags any `read_block` call site NOT listed in Steps 7–9 (e.g. an `#[ignore]`d generator or a helper the grep missed), add the appropriate argument — `false` for a live-only read, `true` for a conformance/tombstone read — and re-run. Do not leave any site on the old 3-arg signature.

Run: `cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -15`
Expected: clean (no warnings).

- [ ] **Step 11: Confirm no KAT data drift**

Run: `git status --short core/tests/data/`
Expected: empty (no `conformance_kat.json` change). If non-empty, STOP — investigate per the spec-is-normative rule; do not silently regenerate.

- [ ] **Step 12: Commit**

```bash
cargo fmt --all
git add -A
git commit -m "feat: gate tombstone visibility in bridge read_block(include_deleted)

Single source of truth across iOS/desktop/Python: withheld records build no
FieldHandle, so secret field bytes never cross the FFI seam. UDL + uniffi +
pyo3 + desktop callers + KAT helpers threaded; conformance replay passes
include_deleted=true (no vector carries a tombstone -> no KAT change)."
```

---

## Task 3: Desktop consolidation — remove the redundant filter

`project_block_detail` now filters redundantly with the bridge gate. Remove its tombstone-skip and its `include_deleted` parameter so desktop has a single gate (the bridge). Behavior is unchanged — desktop already re-reads on toggle.

**Files:**
- Modify: `desktop/src-tauri/src/reveal.rs` (`project_block_detail` signature + body)
- Modify: `desktop/src-tauri/src/commands/browse.rs` (the `project_block_detail` call)
- Modify: any `project_block_detail` unit tests in `desktop/src-tauri/src/reveal.rs`

- [ ] **Step 1: Find the project_block_detail unit tests**

Run: `grep -rn "project_block_detail\|include_deleted" desktop/src-tauri/src/reveal.rs`
Expected: the fn def (~line 20), the call in `browse.rs:48`, and any `#[cfg(test)]` cases passing a bool. Note their line numbers for the edits below.

- [ ] **Step 2: Update the test(s) first (RED)**

For each `project_block_detail(...)` call in `reveal.rs`'s `#[cfg(test)] mod tests`, drop the trailing bool argument. A test that previously asserted "tombstoned record skipped when `false`" no longer applies at this layer (the bridge owns that) — repurpose it to assert that `project_block_detail` projects **whatever records the output contains** (it no longer filters). Concretely, a test like:

```rust
// BEFORE: let dto = project_block_detail("ab".into(), &output, false);
// AFTER:
let dto = project_block_detail("ab".into(), &output);
// project_block_detail now projects every record the bridge returned; the
// tombstone gate is exercised at the bridge layer (see
// secretary-ffi-bridge tombstone_record_hides_from_read_block).
```

(If a test fed a `BlockReadOutput` containing a tombstoned record and asserted it was dropped, change it to assert the record IS present with `tombstoned: true` — that is the post-consolidation contract: project everything you're given.)

- [ ] **Step 3: Run to verify it fails to compile**

Run: `cargo test --release -p secretary-desktop reveal 2>&1 | tail -20`
Expected: FAIL — `this function takes 2 arguments but 3 were supplied` (def not yet changed).

- [ ] **Step 4: Remove the param + skip from project_block_detail**

In `desktop/src-tauri/src/reveal.rs`:

```rust
/// Project a decrypted [`BlockReadOutput`] into a [`BlockDetailDto`].
///
/// Projects every record the bridge returned — tombstone visibility is gated
/// upstream in `secretary_ffi_bridge::read_block(include_deleted)`, so this
/// layer no longer filters. Each projected record carries `tombstoned` so the
/// restore UI can style soft-deleted rows. Carries only plaintext metadata —
/// never calls `expose_text`/`expose_bytes`.
pub fn project_block_detail(block_uuid_hex: String, output: &BlockReadOutput) -> BlockDetailDto {
    let mut records = Vec::with_capacity(output.record_count());
    for i in 0..output.record_count() {
        let Some(record) = output.record_at(i) else {
            continue;
        };
        records.push(project_record(&record));
    }
    BlockDetailDto {
        block_uuid_hex,
        block_name: output.block_name(),
        records,
    }
}
```

- [ ] **Step 5: Update the call site in browse.rs**

In `desktop/src-tauri/src/commands/browse.rs:48`, drop the bool argument (the flag is now consumed by the bridge call at line 39):

```rust
        let dto = project_block_detail(block_uuid_hex.to_string(), &output);
```

- [ ] **Step 6: Run desktop Rust tests + clippy**

Run: `cargo test --release -p secretary-desktop 2>&1 | tail -20`
Expected: PASS.
Run: `cargo clippy --release -p secretary-desktop --tests -- -D warnings 2>&1 | tail -10`
Expected: clean.

- [ ] **Step 7: Run the desktop frontend test (unchanged behavior)**

Run: `cd desktop && npm test 2>&1 | tail -20; cd ..`
Expected: PASS, including `RecordListDelete.test.ts` (it mocks IPC; the re-read-on-toggle contract is unchanged).

- [ ] **Step 8: Commit**

```bash
cargo fmt --all
git add -A
git commit -m "refactor(desktop): drop redundant tombstone filter; bridge is sole gate"
```

---

## Task 4: Swift uniffi harnesses

Update every Swift `readBlock(...)` call (smoke + conformance) to pass `includeDeleted`. These compile outside the cargo workspace via `run.sh` / `run_conformance.sh`.

**Files:**
- Modify: `ffi/secretary-ffi-uniffi/tests/swift/SmokeReadBlock.swift` (4 calls), `SmokeSaveBlock.swift` (2), `SmokeRecordEdit.swift` (4), `SmokeTrashRestore.swift` (1)
- Modify: `ffi/secretary-ffi-uniffi/tests/swift/ConformanceAssertions.swift` (1, → `true`), `conformance.swift` (1, → `true`)

**Rule:** pass `includeDeleted: true` in the conformance files (parity with Rust dispatch) and in any smoke assertion that inspects a tombstoned record; `includeDeleted: false` for live-only smoke reads.

- [ ] **Step 1: Update conformance calls to `true`**

`ConformanceAssertions.swift:114`:
```swift
            let output = try readBlock(identity: identity, manifest: manifest, blockUuid: uuid, includeDeleted: true)
```
`conformance.swift:175`:
```swift
                    let out = try readBlock(identity: cached.identity, manifest: cached.manifest, blockUuid: raw, includeDeleted: true)
```

- [ ] **Step 2: Update smoke calls**

For each `readBlock(...)` in `SmokeReadBlock.swift` (lines ~18, 41, 65, 90) and `SmokeSaveBlock.swift` (lines ~43, 179) add `, includeDeleted: false` (all read live records).

In `SmokeRecordEdit.swift`: lines ~48, 79 (live) → `false`; line ~108 (`afterTombstone` — inspects the tombstoned record's flag) → `true`; line ~116 (`afterResurrect` — live) → `false`.

In `SmokeTrashRestore.swift:58` (`restored` — the record is live again after restore) → `false`.

- [ ] **Step 3: Run the Swift smoke + conformance harnesses**

Run: `bash ffi/secretary-ffi-uniffi/tests/swift/run.sh 2>&1 | tail -25`
Expected: all smoke asserts PASS.
Run: `bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh 2>&1 | tail -25`
Expected: conformance PASS (Swift output agrees with the Rust replay).

- [ ] **Step 4: Commit**

```bash
git add ffi/secretary-ffi-uniffi/tests/swift/
git commit -m "test(swift): thread includeDeleted through uniffi read_block harnesses"
```

---

## Task 5: Kotlin uniffi harnesses

Mirror Task 4 for Kotlin.

**Files:**
- Modify: `ffi/secretary-ffi-uniffi/tests/kotlin/SmokeReadBlock.kt` (4), `SmokeSaveBlock.kt` (2), `SmokeRecordEdit.kt` (4), `SmokeTrashRestore.kt` (1), `ConformanceAssertions.kt` (1 → `true`), `Conformance.kt` (1 → `true`)

**Rule:** same as Swift — `true` in conformance + tombstone-inspecting smoke; `false` for live-only.

- [ ] **Step 1: Update conformance calls to `true`**

`Conformance.kt:196`:
```kotlin
                    val block = readBlock(cached.identity, cached.manifest, rawBytes, true)
```
`ConformanceAssertions.kt:135`:
```kotlin
            val output = readBlock(identity, manifest, uuid, true)
```

- [ ] **Step 2: Update smoke calls**

`SmokeReadBlock.kt` (lines ~20, 41, 64, 89): live → append `, false` (e.g. `readBlock(id, mf, VAULT_001_BLOCK_UUID, false)`).
`SmokeSaveBlock.kt` (lines ~52, 186): live → `, false`.
`SmokeTrashRestore.kt:52`: live → `, false`.
`SmokeRecordEdit.kt`: lines ~68, 104 (live) → `, false`; line ~140 (`deadFlag` — inspects tombstoned record) → `, true`; line ~148 (`liveFlag` — live) → `, false`.

- [ ] **Step 3: Run the Kotlin smoke + conformance harnesses**

Run: `bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh 2>&1 | tail -25`
Expected: smoke PASS.
Run: `bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh 2>&1 | tail -25`
Expected: conformance PASS.

- [ ] **Step 4: Commit**

```bash
git add ffi/secretary-ffi-uniffi/tests/kotlin/
git commit -m "test(kotlin): thread includeDeleted through uniffi read_block harnesses"
```

---

## Task 6: Python pyo3 tests

Update every `secretary_ffi_py.read_block(...)` call to pass `include_deleted`. Runs outside the workspace via pytest after `maturin develop`.

**Files:**
- Modify: `ffi/secretary-ffi-py/tests/test_smoke.py` (many), `test_record_edit.py` (4), `test_trash_restore.py` (1)

**Rule:** `include_deleted=False` for live-only reads; `True` where the test inspects a tombstoned record (e.g. trash/restore round-trips that assert a tombstoned record is present).

- [ ] **Step 1: Rebuild the extension**

Per [[project_secretary_maturin_uv_cache]], stale `.so` caching can bite. Build into the test venv:
Run: `cd ffi/secretary-ffi-py && uv run --with maturin maturin develop --release 2>&1 | tail -8; cd ../..`
Expected: `🛠 Installed secretary_ffi_py`.

- [ ] **Step 2: Update call sites**

In `test_smoke.py` add `, include_deleted=False` to the live reads at lines ~541, 556, 572, 586, 599, 643, 658, 674, and the error-path reads at 619 (unknown uuid) and 632 (15-byte) — `False` is fine; the read raises before the flag matters. For lines ~748 and 836 inspect the surrounding assertions: if the block under test contains a tombstoned record being verified, pass `True`, else `False`.

In `test_record_edit.py` (lines ~72, 93, 108, 114): pass `False` unless the specific read asserts a tombstoned record's presence — for an edit-then-read of a *live* record use `False`; for a read that asserts the tombstone flag after `tombstone_record`, use `True`.

In `test_trash_restore.py:175`: the read verifies round-trip readability after restore (live) → `False`.

- [ ] **Step 3: Run the pyo3 test suite**

Run: `cd ffi/secretary-ffi-py && uv run --with pytest pytest tests/ -q 2>&1 | tail -25; cd ../..`
Expected: all PASS. If any test that reads after `tombstone_record` now finds the record absent, flip that call to `include_deleted=True` (it was asserting the tombstoned record's presence).

- [ ] **Step 4: Commit**

```bash
git add ffi/secretary-ffi-py/tests/
git commit -m "test(pyo3): thread include_deleted through read_block tests"
```

---

## Task 7: iOS app layer — re-read on toggle

Thread `includeDeleted` through the Swift `VaultSession` port + adapters, switch `VaultBrowseViewModel` from a client-side computed filter to a re-read on toggle, and prove the gate end-to-end through the real uniffi binding (SecretaryKit sim test).

**Files:**
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultSession.swift` (protocol)
- Modify: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSession.swift` (real adapter)
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeVaultSession.swift` (fake + spy)
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultBrowseViewModel.swift` (re-read on toggle)
- Modify: `ios/SecretaryApp/Sources/VaultBrowseScreen.swift` (view, minimal)
- Modify: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultBrowseViewModelDeletedTests.swift` (rewrite to re-read semantics)
- Modify: SecretaryKit simulator test (the existing read round-trip test — add a gate assertion). Find it first (Step 7).

- [ ] **Step 1: Update the protocol**

In `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultSession.swift`, change the `readBlock` requirement:

```swift
    /// Decrypt one block and return its VISIBLE records (tombstoned records are
    /// withheld by the Rust gate unless `includeDeleted`). Returns records with
    /// on-demand-reveal fields.
    func readBlock(blockUuid: [UInt8], includeDeleted: Bool) throws -> [RecordView]
```

- [ ] **Step 2: Update the real adapter**

In `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSession.swift:47`, change the signature and the uniffi call:

```swift
    public func readBlock(blockUuid: [UInt8], includeDeleted: Bool) throws -> [RecordView] {
        let out: BlockReadOutput
        do {
            out = try SecretaryKit.readBlock(
                identity: identity, manifest: manifest, blockUuid: Data(blockUuid),
                includeDeleted: includeDeleted)
        } catch let e as VaultError {
            throw mapVaultAccessError(e)
        }
        // ... rest unchanged ...
```

- [ ] **Step 3: Update the fake to honor + spy the flag (write the failing host test first)**

First, add to `VaultBrowseViewModelDeletedTests.swift` a test that drives the new fake/VM behavior. Replace the whole file with a re-read-semantics version:

```swift
// ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultBrowseViewModelDeletedTests.swift
import XCTest
@testable import SecretaryVaultAccessUI
import SecretaryVaultAccess
import SecretaryVaultAccessTesting

@MainActor
final class VaultBrowseViewModelDeletedTests: XCTestCase {
    private let block: [UInt8] = [0xB1]

    private func session(_ records: [RecordView]) -> FakeVaultSession {
        FakeVaultSession(
            vaultUuidHex: "feed",
            blocks: [BlockSummary(uuid: block, name: "Logins", createdAtMs: 0, lastModMs: 0)],
            recordsByBlock: [block: records])
    }

    private func record(_ b: UInt8, tombstone: Bool) -> RecordView {
        RecordView(uuid: [b], type: "login", tags: [], fields: [], tombstone: tombstone)
    }

    func testRecordsHideTombstonedByDefault() {
        let vm = VaultBrowseViewModel(session: session([record(1, tombstone: false),
                                                        record(2, tombstone: true)]))
        vm.loadBlocks(); vm.selectBlock(vm.blocks[0])
        // The gate (modeled by the fake) withheld the tombstoned record.
        XCTAssertEqual(vm.visibleRecords.map(\.uuid), [[1]])
    }

    func testTogglingShowDeletedRereadsWithFlag() {
        let s = session([record(1, tombstone: false), record(2, tombstone: true)])
        let vm = VaultBrowseViewModel(session: s)
        vm.loadBlocks(); vm.selectBlock(vm.blocks[0])
        XCTAssertEqual(s.lastIncludeDeleted, false)   // initial read was live-only
        let readsBefore = s.readCount
        vm.showDeleted = true
        XCTAssertGreaterThan(s.readCount, readsBefore) // toggling re-read
        XCTAssertEqual(s.lastIncludeDeleted, true)     // with the new flag
        XCTAssertEqual(vm.visibleRecords.map(\.uuid), [[1], [2]])
    }

    func testDeleteThenRestoreUpdatesVisibility() {
        let vm = VaultBrowseViewModel(session: session([record(1, tombstone: false)]))
        vm.loadBlocks(); vm.selectBlock(vm.blocks[0])
        vm.delete(record: vm.visibleRecords[0])
        XCTAssertTrue(vm.visibleRecords.isEmpty)       // gone from live list
        vm.showDeleted = true
        XCTAssertEqual(vm.visibleRecords.count, 1)     // re-read shows it
        vm.restore(record: vm.visibleRecords[0])
        vm.showDeleted = false
        XCTAssertEqual(vm.visibleRecords.count, 1)     // back in live list
    }

    func testMakeEditViewModelNilBeforeSelectThenNonNilAfter() {
        let vm = VaultBrowseViewModel(session: session([record(1, tombstone: false)]))
        XCTAssertNil(vm.makeEditViewModel(mode: .add))
        vm.loadBlocks(); vm.selectBlock(vm.blocks[0])
        XCTAssertNotNil(vm.makeEditViewModel(mode: .add))
    }

    func testRefreshRereadsSelectedBlock() throws {
        let s = session([record(1, tombstone: false)])
        let vm = VaultBrowseViewModel(session: s)
        vm.loadBlocks(); vm.selectBlock(vm.blocks[0])
        try s.appendRecord(blockUuid: vm.blocks[0].uuid,
            content: RecordContentInput(recordType: "note", tags: [], fields: []))
        XCTAssertEqual(vm.visibleRecords.count, 1)  // not yet refreshed
        vm.refresh()
        XCTAssertEqual(vm.visibleRecords.count, 2)  // refresh picked up the append
    }

    func testRefreshNoOpWhenNoBlockSelected() {
        let vm = VaultBrowseViewModel(session: session([record(1, tombstone: false)]))
        vm.refresh()
        XCTAssertNil(vm.error)
    }
}
```

Then update `FakeVaultSession.swift` to model the gate + spy. Change `readBlock` and add the spy field:

```swift
    public private(set) var readCount = 0
    public private(set) var wipeCount = 0
    /// Spy: the includeDeleted value passed to the most recent readBlock.
    public private(set) var lastIncludeDeleted = false

    public func readBlock(blockUuid: [UInt8], includeDeleted: Bool) throws -> [RecordView] {
        readCount += 1
        lastIncludeDeleted = includeDeleted
        guard let records = recordsByBlock[blockUuid] else {
            throw VaultAccessError.blockNotFound(hex(blockUuid))
        }
        // Model the Rust gate: withhold tombstoned records unless asked.
        return includeDeleted ? records : records.filter { !$0.tombstone }
    }
```

- [ ] **Step 4: Update the view-model to re-read on toggle**

In `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultBrowseViewModel.swift`:

Replace the `showDeleted` declaration (lines ~17-19) with a `didSet` that re-reads:

```swift
    /// When false (default) the browse list shows only live records. The Rust
    /// gate withholds tombstoned records; toggling RE-READS the selected block
    /// with the new flag (the client never holds withheld data).
    @Published public var showDeleted = false {
        didSet {
            guard showDeleted != oldValue, let blockUuid = selectedBlockUuid else { return }
            reload(blockUuid: blockUuid)
        }
    }
```

Change `reload` to pass the flag (line ~44):

```swift
            records = try session.readBlock(blockUuid: blockUuid, includeDeleted: showDeleted)
```

Replace `visibleRecords` (lines ~54-58) — the Rust gate already filtered, so this is now a thin accessor:

```swift
    /// Records to display. The Rust gate already withheld tombstoned records
    /// (unless `showDeleted`), so no client-side filtering happens here.
    public var visibleRecords: [RecordView] { records ?? [] }
```

(`delete` / `restore` / `refresh` / `commitThenReload` already funnel through `reload`, which now passes `showDeleted` — no other change needed.)

- [ ] **Step 5: Run the host tests**

Run: `cd ios/SecretaryVaultAccess && swift test 2>&1 | tail -25; cd ../..`
Expected: PASS (including the rewritten deleted-tests + all other suites). Note: any OTHER host test or fake-consumer that called `readBlock(blockUuid:)` must be updated to `readBlock(blockUuid:includeDeleted:)` — the compiler will flag them; fix each (live reads → `includeDeleted: false`). Check `FakeVaultSessionWriteTests.swift` (lines ~20, 35, 48-51) and `VaultBrowseViewModelTests.swift`.

- [ ] **Step 6: Update the view (minimal)**

`ios/SecretaryApp/Sources/VaultBrowseScreen.swift` already iterates `viewModel.visibleRecords` (now a thin accessor) and binds `$viewModel.showDeleted` (now re-reads via `didSet`). No change required — but verify it still builds in Step 8. If any direct `readBlock(blockUuid:)` call exists in the app target, add `includeDeleted:`.

- [ ] **Step 7: Add the SecretaryKit simulator gate assertion**

Find the existing SecretaryKit read round-trip test:
Run: `grep -rln "readBlock(blockUuid" ios/SecretaryKit/Tests/ 2>/dev/null; grep -rln "tombstone\|readBlock" ios/SecretaryKit/Tests/`
Add (or extend the nearest create→read test with) an assertion: after `tombstoneRecord`, `readBlock(blockUuid:, includeDeleted: false)` omits the record and `readBlock(blockUuid:, includeDeleted: true)` includes it with `tombstone == true`. Use the existing test's tempdir/vault setup helpers (do NOT mutate a tracked fixture — per [[feedback_smoke_test_temp_copy_golden_vault]], copy to a tempdir if a fixture is involved).

- [ ] **Step 8: Run the full iOS gauntlet**

Run: `bash ios/scripts/run-ios-tests.sh 2>&1 | tail -30`
Expected: host packages green; SecretaryKit sim green (incl. the new gate assertion); app BUILD SUCCEEDED.

- [ ] **Step 9: Commit**

```bash
git add ios/
git commit -m "feat(ios): re-read on Show-deleted toggle via Rust include_deleted gate

VaultSession.readBlock gains includeDeleted; VaultBrowseViewModel re-reads the
block on toggle instead of filtering cached records client-side, so the client
never holds withheld tombstoned data."
```

---

## Task 8: Docs + handoff

- [ ] **Step 1: Update README**

In `README.md`, find the iOS status section (the row/bullet describing browse/record-CRUD) and note that record-level tombstone visibility is now gated in the Rust core (`include_deleted`); the client no longer filters. Keep it brief (per [[feedback_readme_style]] — dot points, no test-count walls).

Run: `grep -n "Show deleted\|tombstone\|deleted\|iOS" README.md | head` to locate the right spot.

- [ ] **Step 2: Update ROADMAP**

In `ROADMAP.md`, add/refresh the entry for the iOS `include_deleted` gate (mirror of desktop D.1.5) under the iOS track. Update any progress indicator consistent with prior entries.

- [ ] **Step 3: Write the handoff + retarget the symlink**

Author `docs/handoffs/2026-06-14-ios-include-deleted-rust-gate-shipped.md` capturing: (1) what shipped + commit SHAs, (2) what's next with acceptance criteria, (3) open decisions/risks, (4) exact resume commands. Then:

```bash
ln -snf docs/handoffs/2026-06-14-ios-include-deleted-rust-gate-shipped.md NEXT_SESSION.md
ls -la NEXT_SESSION.md   # shows -> target
head -3 NEXT_SESSION.md  # reads handoff content transparently
```

- [ ] **Step 4: Commit docs + handoff + symlink together**

```bash
git add README.md ROADMAP.md docs/handoffs/2026-06-14-ios-include-deleted-rust-gate-shipped.md NEXT_SESSION.md
git commit -m "docs: README + ROADMAP + handoff for iOS include_deleted Rust gate"
```

---

## Final acceptance gauntlet (run before opening the PR)

```bash
cd /Users/hherb/src/secretary/.worktrees/ios-include-deleted-rust-gate
pwd && git branch --show-current

cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
git status --short core/tests/data/                       # expect empty (no KAT drift)

bash ffi/secretary-ffi-uniffi/tests/swift/run.sh
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh

( cd ffi/secretary-ffi-py && uv run --with maturin maturin develop --release && uv run --with pytest pytest tests/ -q )

( cd desktop && npm test )

( cd ios/SecretaryVaultAccess && swift test )
bash ios/scripts/run-ios-tests.sh

git diff main...HEAD --name-only | grep -E 'crypto-design|vault-format' || echo "no on-disk-format change (expected)"
```

All green + no format-doc change ⇒ ready to push + open PR.
