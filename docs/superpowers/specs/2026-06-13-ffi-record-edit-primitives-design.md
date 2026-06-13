# FFI projection of record-edit primitives (Slice 1 of iOS record CRUD)

**Date:** 2026-06-13
**Status:** Approved design — ready for implementation plan
**Branch:** `feature/ffi-record-edit-primitives`

## Context

"iOS record editing" is a two-slice effort:

- **Slice 1 (this spec):** project the Rust bridge's granular record-edit primitives onto the **uniffi (Swift)** and **pyo3 (Python)** bindings, with tests. No UI.
- **Slice 2 (separate spec):** the iOS Swift record-CRUD UI built on the finished FFI surface.

### Why this slice exists (the handoff was imprecise)

The prior handoff claimed "the FFI already exposes `save_block`/`append_record`/`edit_record`/`tombstone_record`." Investigation found:

- The Rust **bridge** (`ffi/secretary-ffi-bridge/src/edit/`) has CRDT-correct granular primitives: `append_record`, `edit_record`, `tombstone_record`, `resurrect_record`.
- The **uniffi/pyo3 bindings expose only block-level ops** (`save_block`, `share_block`, `trash_block`, `restore_block`) — **no record-level edit primitives**.
- `save_block` is **replace-semantics**: its `RecordInput`/`FieldInput` carry only `record_uuid`/`record_type`/`tags`/`fields(name,value)` — **no per-field `last_mod` clocks, no `device_uuid`, no `created_at_ms`, no `unknown` maps**. Round-tripping an edit through `save_block` would re-stamp every field's clock to `now_ms` and **drop forward-compat `unknown` data** — the exact CRDT-merge corruption that `edit_record` was written to avoid.

The desktop (Tauri) edits records by calling the bridge primitives directly (Rust→Rust). iOS goes through uniffi, which lacks them. This slice closes that gap, for both bindings, to keep the FFI surface symmetric.

## Goal

Swift and Python callers can perform CRDT-correct record CRUD through their respective bindings:

- **add** a new record to a block (`append_record`),
- **edit** an existing live record's type/tags/fields (`edit_record`),
- **soft-delete** a record (`tombstone_record`),
- **restore** a tombstoned record (`resurrect_record`).

Non-goal: any Swift/iOS UI (Slice 2). Non-goal: any change to the on-disk vault format or the Rust core.

## Surface

Four functions, projected 1:1 from the bridge onto each binding, mirroring the existing `trash_block`/`restore_block`/`save_block` projections exactly.

| Function | Args (after binding-side length validation) | Returns | Bridge errors surfaced |
|---|---|---|---|
| `append_record` | `identity, manifest, block_uuid:[u8;16], record_uuid:[u8;16], content: RecordContent, device_uuid:[u8;16], now_ms:u64` | `()` | `BlockNotFound`, `CorruptVault`, `InvalidArgument`(wrong-length) |
| `edit_record` | same shape as `append_record` | `()` | `RecordNotFound`, `BlockNotFound`, `CorruptVault`, `InvalidArgument` |
| `tombstone_record` | `identity, manifest, block_uuid:[u8;16], record_uuid:[u8;16], device_uuid:[u8;16], now_ms:u64` | `()` | `RecordNotFound`, `BlockNotFound`, `CorruptVault`, `InvalidArgument` |
| `resurrect_record` | same shape as `tombstone_record` | `()` | `RecordNotFound`, `BlockNotFound`, `CorruptVault`, `InvalidArgument` |

### New value type: `RecordContent`

Mirrors the bridge's `secretary_ffi_bridge::RecordContent`:

```
RecordContent {
    record_type: String,
    tags: [String],
    fields: [FieldInput],   // REUSES the existing save_block FieldInput / FieldInputValue
}
```

- **uniffi:** a UDL `dictionary` declared in `secretary.udl`, with a matching crate-root Rust struct re-exported from `lib.rs` (UDL scaffolding names it at crate scope, same as `BlockInput`/`RecordInput`).
- **pyo3:** a `#[pyclass]` constructed from Python, mirroring the existing `RecordInput` pyclass.
- `FieldInput`/`FieldInputValue` are **reused unchanged** from the `save_block` projection — they already wrap text in `SecretString` and bytes in `SecretBytes` (zeroize-on-drop) at the bridge boundary. `record_uuid`/`created_at_ms`/`unknown` are deliberately **not** in `RecordContent`; the bridge owns those (preserve-on-edit / mint-on-add).

## CRDT-correctness contract (the reason for this slice)

The projected functions route to the bridge's `edit_record`/`append_record`/`tombstone_record`/`resurrect_record`, which guarantee:

- `edit_record` preserves `created_at_ms`, `record_uuid`, record- and field-level `unknown`; bumps a field's `last_mod`/`device_uuid` **only** when its value actually changed; mints `now_ms` for genuinely new fields.
- `tombstone_record` sets `tombstone=true`, `tombstoned_at_ms=now_ms`, `last_mod_ms=now_ms`; preserves all field data and `unknown`.
- `resurrect_record` clears `tombstone`, bumps `last_mod_ms`, but **freezes** `tombstoned_at_ms` (the merge death-clock invariant).

The projection layer adds **no** record-semantics of its own. Its only responsibilities are: (1) length-validate the three uuid arguments binding-side, (2) convert the flat `RecordContent` into the bridge type (wrapping secrets in the zeroize carriers), (3) map `FfiVaultError` to the binding's error type. Secret material in `RecordContent` is never stashed past the call (the bridge consumes/zeroizes it; foreign-side `String`/`Vec<u8>` remain caller-owned, same contract as `save_block`).

## Error semantics — no new variants

`BlockNotFound` and `RecordNotFound` already exist in the uniffi `VaultError` enum (`secretary.udl`) and the pyo3 error map (`errors.rs`). Wrong-length uuids surface as `InvalidArgument` (uniffi) / `ValueError` (pyo3), exactly as `save_block`/`trash_block` already do.

**Consequence:** no `FfiVaultError` variant is added, so the Swift/Kotlin conformance-error harnesses (`ConformanceErrors.{swift,kt}`) are untouched **by construction**. Both `run_conformance.sh` scripts will still be run to prove it — they are the only check that catches binding/harness drift that `cargo`/`clippy` cannot see.

## File organization (respect the <500-line guideline)

`ffi/secretary-ffi-uniffi/src/namespace/mod.rs` is already **637 lines** (over the 500 guideline). New code goes in its own files rather than extending it:

- **uniffi:**
  - new `ffi/secretary-ffi-uniffi/src/namespace/record_edit.rs` — the 4 namespace fns + a `convert_record_content` helper. Re-exported from `namespace/mod.rs` via `mod record_edit; pub use record_edit::*;` so the UDL scaffolding still resolves them at namespace scope. *(Resolution to be verified during implementation — re-export at namespace scope is the expected uniffi 0.31 pattern.)*
  - `RecordContent` struct added alongside the existing save-input types (`wrappers/save.rs`) and re-exported from `lib.rs`.
  - UDL declarations added to `secretary.udl` (4 fns + the `RecordContent` dictionary), each with a doc comment matching the house style.
- **pyo3:**
  - new `ffi/secretary-ffi-py/src/record_edit.rs` — the 4 `#[pyfunction]`s + the `RecordContent` `#[pyclass]`, mirroring `trash.rs`/`save.rs` style. Registered in `lib.rs`.

## Testing (TDD)

The bridge primitives are already unit-tested, so these tests assert the **projection layer** (length validation, error mapping, type conversion, zeroize contract), not record semantics. Exercising the projected fns needs a real opened-vault handle, so (matching the established convention for `save_block`/`trash_block`) the binding-level coverage lives in the **Swift + Kotlin smoke runners** and **pyo3 pytest** — not in uniffi-crate Rust `#[test]`s (those only cover handle-free path-validation):

- **Swift + Kotlin smoke** (`SmokeRecordEdit.{swift,kt}`, run by `tests/{swift,kotlin}/run.sh`, against a temp-copied golden vault):
  - `append_record` then `read_block` shows the new record with matching field payloads.
  - `edit_record` then `read_block` shows the changed value, AND an untouched sibling field keeps its prior `device_uuid` (asserted via `FieldHandle.device_uuid()`) — a direct binding-level proof of the per-field-clock-preservation CRDT property.
  - `tombstone_record` then `read_block` omits the record from the live set; `resurrect_record` brings it back.
  - wrong-length `record_uuid`/`block_uuid`/`device_uuid` → `VaultError.InvalidArgument`; unknown record/block uuid → `RecordNotFound`/`BlockNotFound`.
- **pyo3 tests** (`tests/test_record_edit.py`, pytest via `uv`, mirroring `test_trash_restore.py`): construct `RecordContent` from Python, exercise the 4 fns against a temp-copied golden vault, assert `ValueError` on wrong-length uuids, `VaultRecordNotFound`/`VaultBlockNotFound` on unknown uuids, and read-back on the happy paths.
- **Gauntlet (all green before PR):**
  - `cargo test --release --workspace`
  - `cargo clippy --release --workspace --tests -- -D warnings`
  - `cargo fmt --all`
  - both `ffi/secretary-ffi-uniffi/tests/{swift,kotlin}/run_conformance.sh`
  - pyo3 build + pytest

Per house rules: tests generate any crypto values at runtime (no hardcoded keys/nonces); KATs only via JSON fixtures; any vault fixture is exercised against a `cp -R` temp copy, never the tracked frozen golden vault in place.

## Out of scope (→ Slice 2)

All Swift/iOS code: the `VaultSession` write extension / a new write port, the `UniffiVaultSession` adapter methods, edit/add/delete view models, the edit screen, `RootView` routing into edit, simulator XCTest, and the on-device smoke. Slice 1 terminates at: "Swift and Python can call the 4 record-edit primitives through their bindings, with the projection layer fully tested and the full gauntlet green."

## Risks / open items

- **uniffi namespace re-export resolution:** moving the new fns into `namespace/record_edit.rs` and re-exporting must satisfy uniffi 0.31's UDL scaffolding lookup. **This is a confirmed, already-in-use pattern** — `namespace/sync.rs` holds `sync_status`/`sync_vault`/`sync_commit_decisions` (all UDL-declared) and is re-exported via `mod sync; pub use sync::{...}` from `namespace/mod.rs`. `record_edit.rs` follows it 1:1. (If a future uniffi quirk bites, the fallback is declaring the fns in `mod.rs` while keeping the conversion helper + `RecordContent` in a separate file.)
- **pyo3 editable-install cache stickiness:** `maturin develop` + `uv`'s editable cache can leave pytest seeing a stale `.so` even after a rebuild; if a pyo3 test fails inexplicably, nuke the venv + uv cache before trusting the failure.
- No on-disk-format / frozen-spec / `FfiVaultError`-variant change — verified by construction; conformance scripts prove it.
