# Design — Project the sync API onto uniffi + pyo3 (#187)

**Date:** 2026-06-09
**Issue:** [#187](https://github.com/hherb/secretary/issues/187) (widened past its pre-D.1.15 text)
**Slice type:** FFI-surface projection (touches `core`-adjacent bridge + both bindings + conformance → full gauntlet mandatory)

## Problem

D.1.13–D.1.15 shipped the full sync surface (`sync_status`, `sync_vault`,
`sync_commit_decisions` + the interactive conflict-resolution DTOs) as **bridge
Rust functions** consumed directly by the desktop `src-tauri` crate. The
uniffi (Swift/Kotlin) and pyo3 (Python) bindings cannot sync at all: the
**function/DTO surface is 100% greenfield on both bindings**. The sync
`FfiVaultError` variants are already threaded through both bindings (D.1.13);
this slice adds the **functions + DTOs**.

Binding consumers, per [ADR 0007](../../adr/0007-d-row-tauri.md): Sub-project D's
first-party UI is now a single **Tauri** universal client (Rust core consumed
directly, *not* via uniffi), so the bindings serve **third-party / alternate
consumers** — Python automation (pyo3) and Swift/Kotlin host integrations
(Shortcuts, AutoFill, scripts) — plus they keep the binding surface at parity
with the bridge and exercise the sync + conflict DTOs cross-language (the
clean-room differential value). This slice does **not** assume native SwiftUI /
Compose UI apps; if that ever changes it only strengthens the case for this
surface.

Projecting only `sync_vault`/`sync_status` (issue #187's original text) would
recreate the `ConflictsPending` dead-end on those consumers that D.1.13–14 had
on desktop before D.1.15, and would leave the conflict DTOs (`VetoDto` etc.)
never exercised cross-language. So the slice projects **all three** functions
and the **full DTO set**.

## Architecture decision: explicit `state_dir` parameter

The public bridge sync functions hardcode `default_state_dir()` =
`dirs::data_dir()/secretary/sync` — a **desktop** path, with no parameter and no
env override. That path is wrong for the slice's actual consumers:

- **Sandboxed / non-desktop consumers**: `dirs::data_dir()` is
  wrong/unavailable inside an iOS/Android sandbox (or any host that controls its
  own data location) — sync state must live at a path only the caller knows.
- **Tests** (Python/Swift/Kotlin): the param-free functions would read/write the
  developer's *real* `~/Library/Application Support/secretary/sync/` —
  non-hermetic and collision-prone.

The bridge already has the right seam: `sync_status_in` / `sync_vault_in` /
`sync_commit_decisions_in` each take an explicit `state_dir: &Path` and are
currently `pub(crate)`.

**Decision:** promote those three `_in` seams to `pub` and project **those** onto
the bindings, so the uniffi/pyo3 functions take an explicit `state_dir` argument.
The param-free `sync_*` wrappers stay unchanged for desktop (they still call
`default_state_dir()` internally). This is the minimal bridge diff (a 3×
visibility change + doc comments), is the honest API for a sandboxed mobile
caller, and makes every cross-language test hermetic for free. No cli change.

Rejected alternatives:
- **Env-var override** (`SECRETARY_SYNC_STATE_DIR` honored by `default_state_dir`,
  param-free signatures): implicit, awkward on mobile, couples location to
  process env rather than an explicit argument.
- **1:1 param-free projection** (defer dir control): knowingly ships a
  mobile-broken surface and forces tests to pollute the real data dir — conflicts
  with the project's no-deferred-debt ethos.

## Surface

Three functions on **both** bindings, each taking `state_dir`:

| Function | Params | Returns |
|---|---|---|
| `sync_status` | `state_dir`, `vault_uuid: [u8;16]` | `SyncStatusDto` |
| `sync_vault` | `state_dir`, `vault_folder`, `password`, `now_ms` | `SyncOutcomeDto` |
| `sync_commit_decisions` | `state_dir`, `vault_folder`, `password`, `decisions: Vec<VetoDecisionDto>`, `manifest_hash`, `now_ms` | `SyncOutcomeDto` |

DTOs projected (shapes already defined in `secretary-ffi-bridge/src/sync/dto.rs`
and `.../sync/status.rs` — bindings mirror them):

- `SyncStatusDto { has_state: bool, device_clocks: Vec<DeviceClockDto>, last_state_write_ms: Option<u64> }`
- `DeviceClockDto { device_uuid_hex: String, counter: u64 }`
- `SyncOutcomeDto` — tagged enum: `NothingToDo` | `AppliedAutomatically` |
  `SilentMerge` | `MergedClean` | `ConflictsPending { vetoes: Vec<VetoDto>, collisions: Vec<CollisionDto>, manifest_hash: Vec<u8> }` | `RollbackRejected`
- `VetoDto { record_uuid_hex, record_type, tags, field_names, local_last_mod_ms, peer_tombstoned_at_ms, peer_device_hex }` — **metadata only, no secret values**
- `CollisionDto { record_uuid_hex, field_names }` — **metadata only**
- `VetoDecisionDto { record_uuid_hex: String, keep_local: bool }` — the one *input* DTO

The error surface (`FfiVaultError` sync variants:
`SyncStateVaultMismatch`/`SyncStateCorrupt`/`SyncEvidenceStale`/`SyncInProgress`/
`SyncFailed`/`SyncDecisionsIncomplete`) is **already wired** on both bindings — no
change.

## Component design

### Bridge (`secretary-ffi-bridge`)

- Promote `sync_status_in`, `sync_vault_in`, `sync_commit_decisions_in` from
  `pub(crate)` to `pub`. Add/extend doc comments to state they are the
  explicit-state-dir public API consumed by the bindings (and tests); the
  param-free `sync_*` are the desktop-default-dir convenience wrappers.
- No behavioural change; no new tests required at the bridge (existing `_in`
  unit tests already cover them).

### uniffi (`secretary-ffi-uniffi`) — Swift/Kotlin

- `src/secretary.udl`: add the three namespace functions, dictionaries
  (`SyncStatusDto`, `DeviceClockDto`, `VetoDto`, `CollisionDto`,
  `VetoDecisionDto`), and `[Enum] interface SyncOutcomeDto` with a data-carrying
  `ConflictsPending(sequence<VetoDto>, sequence<CollisionDto>, bytes)` variant —
  mirroring the existing `[Enum] interface FieldInputValue` pattern.
- `src/wrappers/sync.rs` (**new**): uniffi-side value types mirroring the bridge
  DTOs (pure data, no logic).
- `src/namespace.rs`: three wrapper functions. Each:
  1. Length-validates byte params (`vault_uuid` → 16 bytes; `manifest_hash` →
     32 bytes) via the existing `uuid_from_vec`-style helper → `InvalidArgument`.
  2. Wraps `password: bytes` into `SecretBytes` immediately, mirroring
     `open_with_password`'s zeroize discipline.
  3. Converts `state_dir: string` → `&Path`, converts DTOs, calls the bridge
     `_in` function, `.map_err(VaultError::from)`.
- `src/lib.rs`: `pub use wrappers::sync::{…}` + the namespace re-exports.

### pyo3 (`secretary-ffi-py`) — Python

- `src/sync.rs` (**new**):
  - Output DTOs (`SyncStatusDto`, `DeviceClockDto`, `VetoDto`, `CollisionDto`) as
    `#[pyclass(frozen)]` with read-only getters.
  - `SyncOutcomeDto` as a `#[pyclass]` exposing a **`kind: str` discriminant** +
    payload getters (`vetoes`/`collisions`/`manifest_hash`) populated only for the
    `ConflictsPending` arm (empty/`None` otherwise). This matches the TS
    tagged-union shape already used on the desktop side and is cleaner for Python
    consumers than a pyo3 complex-enum.
  - `VetoDecisionDto` as `#[pyclass]` with a `#[new]` constructor.
- Three `#[pyfunction]`s (`state_dir: PathBuf`, `vault_folder: PathBuf`,
  `password: Vec<u8>` → `SecretBytes`, …), `.map_err(ffi_vault_error_to_pyerr)`.
- `src/lib.rs`: register the classes + functions in the `#[pymodule]`.

## Secret hygiene

- `password` enters each binding as raw bytes and is wrapped in `SecretBytes`
  immediately (mirrors `open_with_password`); the bridge zeroizes on drop. The
  inbound `Vec<u8>`/`bytes` from the host language is non-zeroizable (Swift/Kotlin
  `String`/`ByteArray`, Python `bytes`) — an inherent FFI-boundary limitation, the
  same one the desktop already accepts for the JS webview.
- No secret VALUE crosses any sync DTO — `VetoDto`/`CollisionDto` carry field
  **names** (`.keys()`) and metadata only, never field values. This preserves the
  browse-path secret-hygiene model.

## Tests / conformance (Option 1: Python deep, Swift/Kotlin parity-smoke)

### Python pytest (deep — exercises the conflict DTO population path cross-language)
- `sync_status` on an empty tempdir state_dir → `has_state == False`.
- `sync_vault` on a staged (`cp -R`) golden copy with a tempdir state_dir →
  `AppliedAutomatically`.
- **Full round-trip:** `sync_vault` against the divergence fixture (below) →
  `ConflictsPending` with the expected veto metadata → `sync_commit_decisions`
  with one `VetoDecisionDto` per veto → `MergedClean`.
- Error paths: bad-length `manifest_hash`/decision-hex → `VaultSyncFailed`;
  decisions not covering the veto set → `VaultSyncDecisionsIncomplete`; stale token
  → `VaultSyncEvidenceStale`.

### Swift/Kotlin `SmokeSync.{swift,kt}` (parity-smoke)
- `sync_status` (empty state_dir → `has_state == false`).
- One clean `sync_vault` pass on a staged golden copy → `AppliedAutomatically`.
- Construct a `VetoDecisionDto` and round-trip the DTO field shapes.
- No two-device veto staged in Swift/Kotlin (the conflict *logic* is the same Rust
  under every binding; uniffi generates Swift+Kotlin from one definition, so the
  conflict-DTO marshalling is proven once in Python + DTO-shape parity here).
- Wired into `run_conformance.sh` for both languages.

### Divergence fixture (design call — generated, not hand-built in Python)
The Python conflict round-trip needs a two-device divergence: a conflict-copy that
tombstones a record the canonical side still has live, plus a seeded concurrent
`SyncState` keyed by the vault UUID. The cli already has the 89-line Rust builder
`stage_concurrent_veto_vault`.

**Decision:** produce a committed fixture under
`core/tests/data/sync_conflict_fixture/` via an `--ignored` generator test
(mirroring the existing `generate_conformance_kat` pattern), human-reviewed on
change. Test code (`cp -R` to a tempdir) loads it. Rationale: reimplementing the
89-line staging in Python would be fragile and duplicative; a generated fixture is
reusable by any language binding and keeps the staging logic in one reviewed Rust
place.

Rejected: building the divergence in Python via the pyo3 surface (save + tombstone
+ hand-placing the conflict-copy files) — no new Rust fixture but brittle and
couples the test to internal sync-copy file layout.

## File inventory

**Bridge (visibility only):**
- `ffi/secretary-ffi-bridge/src/sync/status.rs` — `pub` on `sync_status_in`
- `ffi/secretary-ffi-bridge/src/sync/orchestration.rs` — `pub` on `sync_vault_in`, `sync_commit_decisions_in`

**uniffi:**
- `ffi/secretary-ffi-uniffi/src/secretary.udl` (edit)
- `ffi/secretary-ffi-uniffi/src/wrappers/sync.rs` (new)
- `ffi/secretary-ffi-uniffi/src/wrappers/mod.rs` (edit — `pub mod sync`)
- `ffi/secretary-ffi-uniffi/src/namespace.rs` (edit)
- `ffi/secretary-ffi-uniffi/src/lib.rs` (edit — re-exports)
- `ffi/secretary-ffi-uniffi/tests/swift/SmokeSync.swift` (new) + `run_conformance.sh` (edit)
- `ffi/secretary-ffi-uniffi/tests/kotlin/SmokeSync.kt` (new) + `run_conformance.sh` (edit)

**pyo3:**
- `ffi/secretary-ffi-py/src/sync.rs` (new)
- `ffi/secretary-ffi-py/src/lib.rs` (edit — register)
- `ffi/secretary-ffi-py/tests/…` (new pytest module)

**Fixture:**
- `core/tests/data/sync_conflict_fixture/` (new, generated) + the `--ignored`
  generator test living in the cli test crate alongside
  `stage_concurrent_veto_vault` (reuses that builder; writes the fixture into
  `core/tests/data/`).

**Docs:**
- `README.md` / `ROADMAP.md` (#187 ✅)

New files (`wrappers/sync.rs`, pyo3 `sync.rs`) kept focused; split if either nears
500 lines.

## Gauntlet (mandatory — FFI surface changes)

```
cargo fmt --all --check
cargo clippy --release --workspace --tests -- -D warnings
cargo test --release --workspace
uv run core/tests/python/conformance.py
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
# Python binding pytest via maturin (nuke venv + uv cache if a stale .so appears —
# see project memory on maturin/uv editable cache stickiness)
```

## Out of scope

- **Reveal-to-decide** (inspecting actual field values to decide a veto) — separate
  reveal-gated feature.
- Any **merge-semantics** change — the four CRDT proptests stay untouched.
- Desktop changes — desktop consumes the bridge directly and is unaffected.
- New `FfiVaultError` variants — the sync error surface is already wired.
