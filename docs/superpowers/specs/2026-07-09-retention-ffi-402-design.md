# Design: #402 FFI projection — retention auto-purge

**Date:** 2026-07-09
**Issue:** #402 follow-up (FFI slice)
**Branch:** `feature/retention-ffi-402` (cut from `main` @ `6070e6ec`, which merged #402 via PR #405)
**Scope:** core-consuming FFI projection only — bridge → uniffi (Swift/Kotlin) + pyo3 (Python). No core change, no crypto, no new `FfiVaultError` variant, no `manifest_version` bump, `#![forbid(unsafe_code)]` intact.

## 1. Purpose

The core retention API shipped in #402 (`core/src/vault/retention.rs`) has **no binding surface**, so no platform can invoke retention. This slice projects the three public core symbols through the FFI stack so downstream platform UX (desktop/iOS/Android "run retention now" / scheduled purge) has an API to call:

1. `expired_trash_entries(&Manifest, window_ms, now_ms) -> Vec<ExpiredEntry>` — pure, I/O-free preview.
2. `auto_purge_expired(folder, &mut OpenVault, window_ms, now_ms, device_uuid, rng) -> Result<RetentionPurgeReport, VaultError>` — the commit.
3. `DEFAULT_RETENTION_WINDOW_MS: u64` — the 90-day default window.

**Non-goals (explicitly deferred to later slices):** desktop/iOS/Android retention UX; any scheduled-purge policy engine; tombstone GC. This slice ends at a callable, tested FFI surface.

## 2. Established template

This is a mechanical projection following the **exact** pattern the #399 purge/empty-trash FFI projection already set:

| Core symbol | Projection template already in tree |
|---|---|
| `auto_purge_expired` (commit, needs identity + I/O) | `ffi/secretary-ffi-bridge/src/purge/orchestration.rs::empty_trash` |
| `RetentionPurgeReport` (usize→u32 counts) | `EmptyTrashReport` (same file) |
| `expired_trash_entries` (pure manifest read) | `block_summaries()` accessor / `list_trashed_blocks` free fn |
| binding-layer uuid validation | `uuid_from_vec` (uniffi) / `uuid_array_or_value_error` (pyo3) |

`auto_purge_expired`'s core signature is `empty_trash`'s plus two scalar args (`window_ms`, `now_ms` — `empty_trash` already carries `now_ms`), and its report is `EmptyTrashReport` plus one pass-through field (`window_ms`). The error surface is identical (retention takes no `block_uuid`, so `BlockNotInTrash` cannot fire).

## 3. Architecture

### 3.1 Bridge — new self-contained `retention/` module

`ffi/secretary-ffi-bridge/src/retention/` (mirrors `purge/` and core's `retention.rs`):

- `mod.rs` — module + re-exports (mirrors `purge/mod.rs`).
- `orchestration.rs` — all four symbols colocated:

**(a) `ExpiredEntry` DTO** — the preview record:
```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiredEntry {
    pub block_uuid: [u8; 16],   // raw array (bridge convention; binding → bytes/Vec<u8>)
    pub tombstoned_at_ms: u64,
    pub age_ms: u64,
}
impl From<secretary_core::vault::ExpiredEntry> for ExpiredEntry { /* field-for-field */ }
```

**(b) `expired_trash_entries` free fn** — pure preview:
```rust
pub fn expired_trash_entries(
    manifest: &OpenVaultManifest,
    window_ms: u64,
    now_ms: u64,
) -> Vec<ExpiredEntry>
```
Reads `manifest.manifest_body()` (the existing `pub(crate) fn -> Option<Manifest>` accessor). On a wiped handle (`None`) returns an **empty vec** — the safe-default convention ([[project_secretary_bridge_wiped_handle_defaults]]), consistent with `block_summaries()`. No identity, no I/O, infallible (no `Result`). Delegates to `secretary_core::vault::expired_trash_entries` and maps each core `ExpiredEntry` → bridge `ExpiredEntry`.

**(c) `RetentionPurgeReport` DTO** — commit outcome:
```rust
#[derive(Debug, Clone)]   // NOT Default: window_ms is meaningful even at purged_count==0
pub struct RetentionPurgeReport {
    pub purged_count: u32,
    pub shared_count: u32,
    pub owner_only_count: u32,
    pub unknown_count: u32,
    pub files_removed: u32,
    pub files_failed: u32,
    pub window_ms: u64,       // pass-through, echoes the caller's window
}
impl From<secretary_core::vault::RetentionPurgeReport> for RetentionPurgeReport { /* counts as u32, window_ms passthrough */ }
```
Every count narrows `usize`→`u32` for uniffi/pyo3 portability (mirrors `EmptyTrashReport`); `window_ms` passes through unchanged.

**(d) `auto_purge_expired` free fn** — commit:
```rust
pub fn auto_purge_expired(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    window_ms: u64,
    now_ms: u64,
    device_uuid: [u8; 16],
) -> Result<RetentionPurgeReport, FfiVaultError>
```
Byte-for-byte the `empty_trash` orchestration: snapshot the manifest 5-tuple (`snapshot_for_save_block`) under one lock → snapshot the identity bundle (`clone_inner_bundle`) → build a temporary `core::vault::OpenVault` → call `secretary_core::vault::auto_purge_expired(&folder, &mut open, window_ms, now_ms, device_uuid, &mut OsRng)` → on `Ok` write back via `replace_manifest_and_file` and map the report; on `Err` map via `map_core_vault_error_retention`. Failure invariant: bridge in-memory state byte-identical to pre-call on `Err` (the `OpenVault` clone owns the only mutated state and drops).

**(e) `map_core_vault_error_retention`** — exhaustive `match` on `&VaultError`, **no `_` catchall** (issue #40), identical arm set to `map_core_vault_error_empty_trash`: `Io` → `FolderInvalid`; every other arm (including `BlockNotInTrash`, which cannot fire — no `block_uuid` input) → `SaveCryptoFailure` umbrella. Adding a future core variant is a compile error here.

### 3.2 The 90-day constant

`DEFAULT_RETENTION_WINDOW_MS` reaches each language idiomatically from a **single** core const (no drift):

- **Bridge:** re-export `pub use secretary_core::vault::DEFAULT_RETENTION_WINDOW_MS;` — the single source of the value; both bindings read it.
- **uniffi:** namespace fn `u64 default_retention_window_ms();` (UDL has no `const` in 0.31) returning the bridge const.
- **pyo3:** module attribute `secretary_ffi.DEFAULT_RETENTION_WINDOW_MS` via `m.add("DEFAULT_RETENTION_WINDOW_MS", secretary_ffi_bridge::DEFAULT_RETENTION_WINDOW_MS)?` — the Pythonic shape.

Both bindings read the same bridge-re-exported core const, so the value cannot diverge across languages.

### 3.3 uniffi binding (`secretary-ffi-uniffi`)

- `src/wrappers/retention.rs` — value types `ExpiredEntry` + `RetentionPurgeReport` (pure data; `block_uuid: Vec<u8>`), matching the UDL dictionaries exactly (mirrors `wrappers/purge.rs`).
- `src/namespace/mod.rs` — three namespace fns:
  - `expired_trash_entries(manifest: Arc<OpenVaultManifest>, window_ms, now_ms) -> Vec<ExpiredEntry>` (infallible; maps bridge → uniffi value type).
  - `auto_purge_expired(identity, manifest, window_ms, now_ms, device_uuid: Vec<u8>) -> Result<RetentionPurgeReport, VaultError>`. `device_uuid` wrong length → `VaultError::InvalidArgument` via `uuid_from_vec` (binding-wrapper validation, [[project_secretary_input_validation_at_binding_wrapper]]).
  - `default_retention_window_ms() -> u64`.
- `src/secretary.udl` — 2 dictionaries (`ExpiredEntry`, `RetentionPurgeReport`) + 3 namespace function declarations. `block_uuid` projects as `bytes`.
- `src/lib.rs` — `pub use` the two wrapper value types.

### 3.4 pyo3 binding (`secretary-ffi-py`)

- `src/retention.rs` — `#[pyclass(frozen, get_all)]` `ExpiredEntry` + `RetentionPurgeReport` (output-only, `block_uuid: Vec<u8>`, top-level return types so no `Clone`/`skip_from_py_object` needed — [[project_secretary_pyo3_028_fromtopyobject_deprecation]]) + `From<bridge::*>` impls; `expired_trash_entries` + `auto_purge_expired` pyfunctions. `device_uuid` validated via `uuid_array_or_value_error` → `ValueError`.
- `src/lib.rs` — register both classes, both pyfunctions, and the module const.

## 4. Error handling

No new `FfiVaultError` variant. Surface for `auto_purge_expired`:
- `CorruptVault` — a handle was wiped, or `replace_manifest_and_file` failed.
- `FolderInvalid` — I/O failure (atomic-write, cross-fs rename).
- `SaveCryptoFailure` — crypto/encoding failure on already-validated inputs (umbrella).

Because no `FfiVaultError` variant is added, the Swift/Kotlin `ConformanceErrors.{swift,kt}` harnesses are **untouched** ([[project_secretary_ffivaulterror_workspace_match]]). `expired_trash_entries` is infallible (empty vec on wipe), so it has no error surface. Binding-layer input validation (`device_uuid` length) lives in the uniffi/pyo3 wrappers, not the bridge ([[project_secretary_input_validation_at_binding_wrapper]]).

## 5. Testing

**Bridge unit tests** (`retention/orchestration.rs`, mirroring the purge tests):
- `RetentionPurgeReport::from` narrows every count `usize`→`u32` and passes `window_ms` through.
- `map_core_vault_error_retention`: `Io` → `FolderInvalid`; `ClockOverflow`/`BlockPurged`/`BlockNotInTrash` → `SaveCryptoFailure`.
- `auto_purge_expired` on an empty target set returns a zero-count report carrying the real `window_ms` (no manifest write).
- `expired_trash_entries` on a wiped handle returns an empty vec.
- `expired_trash_entries` end-to-end over a staged manifest returns exactly the eligible entries (preview matches core rule).

**pyo3 pytest** (`ffi/secretary-ffi-py/tests/…`): open a **temp copy** of the golden vault ([[feedback_smoke_test_temp_copy_golden_vault]]); `expired_trash_entries` with a huge window → empty; with a tiny window over staged trash → preview; `auto_purge_expired` commit → `RetentionPurgeReport` with expected counts + `window_ms`; wrong-length `device_uuid` → `ValueError`; module const equals `90*24*60*60*1000`.

**uniffi Swift + Kotlin smoke**: exercise `default_retention_window_ms()`, a preview call, and a commit call so the generated bindings are proven to compile and run (`run_conformance.sh` builds/compiles the generated harness — the gate that cargo/clippy cannot see, [[project_secretary_ffivaulterror_workspace_match]]).

## 6. Acceptance gates

Run from the worktree:
```bash
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all --check
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
# :kit + :app Gradle build — a uniffi return-shape change can pass conformance yet break :kit
#   (project_secretary_conformance_scripts_dont_compile_kit)
# Python: maturin develop + pytest (project_secretary_maturin_uv_cache if stale .so)
```

**Resolved design decisions:**
- Preview shape: **free function** (colocates all retention code in one bridge module; matches purge/empty-trash/list free-fn convention). (Approved.)
- Constant exposure: **uniffi namespace fn + pyo3 module const**, both reading one bridge-re-exported core const. (Approved.)

## 7. Risks

- **`:kit`/`:app` build drift** — a uniffi signature change compiles the Swift/Kotlin conformance harness fine yet breaks the `:kit` Gradle module ([[project_secretary_conformance_scripts_dont_compile_kit]]). Mitigation: build `:kit` + `:app` in the same task as the uniffi change, not later.
- **maturin/uv stale `.so`** — pytest can see a stale `.so` after a maturin rebuild ([[project_secretary_maturin_uv_cache]]). Mitigation: nuke venv + uv cache if a signature change doesn't surface.
- **Lean-binding boundary** — `notify`/`clap` must not leak into the binding crates (#189). Mitigation: the `check-lean-binding.sh` gate is in the acceptance list; the new code imports only `secretary_ffi_bridge` + `pyo3`/uniffi scaffolding.
