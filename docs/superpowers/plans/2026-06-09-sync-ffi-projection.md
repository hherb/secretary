# Sync API → uniffi + pyo3 Projection Implementation Plan (#187)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Project the three bridge sync functions (`sync_status`, `sync_vault`, `sync_commit_decisions`) and their full DTO set — including the conflict-resolution DTOs — onto both the uniffi (Swift/Kotlin) and pyo3 (Python) bindings, each taking an explicit `state_dir` so mobile passes its sandbox path and tests are hermetic.

**Architecture:** The bridge already has `pub(crate)` explicit-`state_dir` seams (`sync_status_in` / `sync_vault_in` / `sync_commit_decisions_in`). Promote them to `pub` and project *those*. The param-free `sync_*` desktop wrappers stay unchanged. Bindings are thin: validate byte-length args, wrap `password` bytes in `SecretBytes`, convert DTOs, call the bridge `_in`, translate errors (the sync `FfiVaultError` variants are already wired on both bindings). Tests: deep Python round-trip (incl. a generated two-device divergence fixture) + Swift/Kotlin parity-smokes.

**Tech Stack:** Rust (secretary-ffi-bridge, secretary-ffi-uniffi, secretary-ffi-py), uniffi 0.31 UDL, PyO3 + maturin, uv/pytest, swiftc/kotlinc conformance harnesses.

**Working directory:** `/Users/hherb/src/secretary/.worktrees/sync-ffi-projection` (branch `feature/sync-ffi-projection`). Verify before every cargo/git command: `pwd && git branch --show-current`.

---

## File Structure

| File | Responsibility | Action |
|---|---|---|
| `ffi/secretary-ffi-bridge/src/sync/status.rs` | `sync_status_in` visibility | Modify (pub) |
| `ffi/secretary-ffi-bridge/src/sync/orchestration.rs` | `sync_vault_in`, `sync_commit_decisions_in` visibility | Modify (pub) |
| `ffi/secretary-ffi-bridge/src/sync/mod.rs` | re-export the `_in` seams | Modify |
| `ffi/secretary-ffi-bridge/src/lib.rs` | crate-root re-export | Modify |
| `ffi/secretary-ffi-bridge/tests/sync_public_api.rs` | prove `_in` reachable as `pub` | Create |
| `ffi/secretary-ffi-uniffi/src/wrappers/sync.rs` | uniffi-side sync DTO value types | Create |
| `ffi/secretary-ffi-uniffi/src/wrappers/mod.rs` | `pub mod sync` | Modify |
| `ffi/secretary-ffi-uniffi/src/secretary.udl` | UDL fns + dictionaries + enum | Modify |
| `ffi/secretary-ffi-uniffi/src/namespace.rs` | 3 namespace wrapper fns | Modify |
| `ffi/secretary-ffi-uniffi/src/lib.rs` | crate-root re-exports | Modify |
| `ffi/secretary-ffi-py/src/sync.rs` | pyo3 DTO pyclasses + 3 pyfunctions | Create |
| `ffi/secretary-ffi-py/src/lib.rs` | register classes + functions | Modify |
| `ffi/secretary-ffi-py/tests/test_sync.py` | Python status + sync + conflict round-trip | Create |
| `cli/tests/generate_sync_conflict_fixture.rs` | `--ignored` fixture generator | Create |
| `core/tests/data/sync_conflict_fixture/` | committed two-device divergence fixture | Create (generated) |
| `ffi/secretary-ffi-uniffi/tests/swift/SmokeSync.swift` + `run.sh` + `main.swift` | Swift parity-smoke | Create/Modify |
| `ffi/secretary-ffi-uniffi/tests/kotlin/SmokeSync.kt` + `run.sh` + `Main.kt` | Kotlin parity-smoke | Create/Modify |
| `README.md`, `ROADMAP.md` | #187 ✅ | Modify |

---

## Task 1: Bridge — promote the explicit-`state_dir` seams to `pub`

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/sync/status.rs:48`
- Modify: `ffi/secretary-ffi-bridge/src/sync/orchestration.rs:46`, `:157`
- Modify: `ffi/secretary-ffi-bridge/src/sync/mod.rs:10-12`
- Modify: `ffi/secretary-ffi-bridge/src/lib.rs:140-143`
- Create: `ffi/secretary-ffi-bridge/tests/sync_public_api.rs`

- [ ] **Step 1: Write the failing integration test**

Create `ffi/secretary-ffi-bridge/tests/sync_public_api.rs`. An integration test (separate crate) can only see `pub` items, so it fails to compile until the seams are promoted:

```rust
//! Proves the explicit-`state_dir` sync seams are part of the crate's
//! PUBLIC API (the surface the uniffi/pyo3 bindings project). An
//! integration test compiles as a downstream crate, so referencing a
//! `pub(crate)` item here fails to compile — which is exactly the gate
//! we want on these three functions' visibility.

use secretary_ffi_bridge::{sync_commit_decisions_in, sync_status_in, sync_vault_in};
use tempfile::TempDir;

#[test]
fn sync_status_in_is_public_and_reports_no_state_on_empty_dir() {
    let dir = TempDir::new().unwrap();
    let status = sync_status_in(dir.path(), [3u8; 16]).expect("status");
    assert!(!status.has_state);
}

#[test]
fn sync_vault_in_and_commit_decisions_in_are_public_symbols() {
    // Compile-time reachability is the assertion; take fn pointers so the
    // names must resolve as `pub` without staging a full vault here
    // (behaviour is covered by the in-module unit tests + the Python suite).
    let _v: fn(&std::path::Path, &std::path::Path, secretary_core::crypto::secret::SecretBytes, u64)
        -> Result<secretary_ffi_bridge::SyncOutcomeDto, secretary_ffi_bridge::FfiVaultError> =
        sync_vault_in;
    let _c: fn(
        &std::path::Path,
        &std::path::Path,
        secretary_core::crypto::secret::SecretBytes,
        Vec<secretary_ffi_bridge::VetoDecisionDto>,
        Vec<u8>,
        u64,
    ) -> Result<secretary_ffi_bridge::SyncOutcomeDto, secretary_ffi_bridge::FfiVaultError> =
        sync_commit_decisions_in;
}
```

- [ ] **Step 2: Run the test to verify it fails (compile error: private items)**

Run: `cargo test --release -p secretary-ffi-bridge --test sync_public_api`
Expected: FAIL to compile — `function \`sync_status_in\` is private` (and the other two).

- [ ] **Step 3: Promote the three seams to `pub`**

In `ffi/secretary-ffi-bridge/src/sync/status.rs`, change the `sync_status_in` signature line and its doc:

```rust
/// Public explicit-`state_dir` seam — the API the uniffi/pyo3 bindings
/// project (mobile passes its sandbox path; tests pass a tempdir). The
/// param-free [`sync_status`] is the desktop default-dir convenience
/// wrapper. Also used by the in-crate unit tests.
pub fn sync_status_in(
    state_dir: &Path,
    vault_uuid: [u8; 16],
) -> Result<SyncStatusDto, FfiVaultError> {
```

In `ffi/secretary-ffi-bridge/src/sync/orchestration.rs`, change both `sync_vault_in` (`:46`) and `sync_commit_decisions_in` (`:157`) from `pub(crate) fn` to `pub fn`, and extend each doc comment's first line to read:

```rust
/// Public explicit-`state_dir` seam — the API the uniffi/pyo3 bindings
/// project; the param-free wrapper is the desktop default-dir convenience.
/// Also used by the in-crate unit tests.
```

- [ ] **Step 4: Re-export the seams at the module + crate root**

In `ffi/secretary-ffi-bridge/src/sync/mod.rs`, extend the two `pub use` lines:

```rust
pub use orchestration::{
    sync_commit_decisions, sync_commit_decisions_in, sync_vault, sync_vault_in,
};
pub use status::{sync_status, sync_status_in, DeviceClockDto, SyncStatusDto};
```

In `ffi/secretary-ffi-bridge/src/lib.rs`, extend the `pub use sync::{...}` block (line 140) to add the three `_in` names alongside the existing exports:

```rust
pub use sync::{
    sync_commit_decisions, sync_commit_decisions_in, sync_status, sync_status_in, sync_vault,
    sync_vault_in, CollisionDto, DeviceClockDto, SyncOutcomeDto, VetoDecisionDto, VetoDto,
};
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test --release -p secretary-ffi-bridge --test sync_public_api`
Expected: PASS (2 tests).

- [ ] **Step 6: Clippy + commit**

Run: `cargo clippy --release -p secretary-ffi-bridge --tests -- -D warnings`
Expected: clean.

```bash
git add ffi/secretary-ffi-bridge/src/sync ffi/secretary-ffi-bridge/src/lib.rs ffi/secretary-ffi-bridge/tests/sync_public_api.rs
git commit -m "feat(bridge): promote sync_*_in explicit-state_dir seams to pub (#187)

The uniffi/pyo3 projection needs an explicit state_dir so mobile passes
its sandbox path and tests are hermetic. Promote the existing pub(crate)
sync_status_in / sync_vault_in / sync_commit_decisions_in seams to pub and
re-export at crate root; the param-free wrappers stay for desktop.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: uniffi — project the three functions + DTOs (Swift/Kotlin)

**Files:**
- Create: `ffi/secretary-ffi-uniffi/src/wrappers/sync.rs`
- Modify: `ffi/secretary-ffi-uniffi/src/wrappers/mod.rs:18`
- Modify: `ffi/secretary-ffi-uniffi/src/secretary.udl`
- Modify: `ffi/secretary-ffi-uniffi/src/namespace.rs`
- Modify: `ffi/secretary-ffi-uniffi/src/lib.rs:71-77`

uniffi compiles UDL ↔ Rust as one unit (the scaffolding fails if they diverge), so this is one atomic task. Unit tests cover the hermetic, fixture-free paths; the deep round-trip is Python's job (Task 6).

- [ ] **Step 1: Write the failing unit tests**

Add to the bottom of `ffi/secretary-ffi-uniffi/src/namespace.rs` (inside the existing `#[cfg(test)] mod tests`):

```rust
    #[test]
    fn sync_status_empty_dir_reports_no_state() {
        let dir = tempfile::tempdir().unwrap();
        let status = super::sync_status(
            dir.path().to_str().unwrap().to_string(),
            vec![9u8; 16],
        )
        .expect("status");
        assert!(!status.has_state);
        assert!(status.device_clocks.is_empty());
    }

    #[test]
    fn sync_status_wrong_length_vault_uuid_is_invalid_argument() {
        let dir = tempfile::tempdir().unwrap();
        match super::sync_status(dir.path().to_str().unwrap().to_string(), vec![0u8; 15]) {
            Err(VaultError::InvalidArgument { detail }) => {
                assert!(detail.contains("16 bytes") && detail.contains("got 15"));
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn sync_commit_decisions_bad_manifest_hash_len_is_sync_failed() {
        let dir = tempfile::tempdir().unwrap();
        let folder = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../core/tests/data/golden_vault_001");
        match super::sync_commit_decisions(
            dir.path().to_str().unwrap().to_string(),
            folder.to_str().unwrap().to_string(),
            b"correct horse battery staple".to_vec(),
            vec![],
            vec![0u8; 5], // ≠ 32 → reject before vault open
            0,
        ) {
            Err(VaultError::SyncFailed { detail }) => {
                assert!(detail.contains("manifest_hash must be 32 bytes"));
            }
            other => panic!("expected SyncFailed, got {other:?}"),
        }
    }
```

Add `tempfile` to `ffi/secretary-ffi-uniffi/Cargo.toml` `[dev-dependencies]` if absent (check first: `grep tempfile ffi/secretary-ffi-uniffi/Cargo.toml`). Use the workspace version: `tempfile = "=3.27.0"` — **match the exact pin already in `core/Cargo.toml`** (do not introduce a caret range on this security-relevant crate).

- [ ] **Step 2: Run to verify it fails (function not found)**

Run: `cargo test --release -p secretary-ffi-uniffi sync_ -- --list 2>&1 | head` then `cargo build --release -p secretary-ffi-uniffi`
Expected: FAIL — `cannot find function \`sync_status\` in module \`super\`` (and the UDL scaffolding references nothing yet).

- [ ] **Step 3: Create the uniffi DTO value types**

Create `ffi/secretary-ffi-uniffi/src/wrappers/sync.rs`:

```rust
//! uniffi-side value types mirroring the bridge sync DTOs
//! (`secretary_ffi_bridge::sync::{status,dto}`). Pure data — no logic;
//! the namespace fns convert these to/from the bridge types. Field names
//! and shapes match `secretary.udl` exactly (uniffi 0.31 scaffolding maps
//! `crate::TypeName` from the UDL).

/// One device's vector-clock entry — public metadata, never secret.
pub struct DeviceClockDto {
    pub device_uuid_hex: String,
    pub counter: u64,
}

/// Read-only sync status for a vault.
pub struct SyncStatusDto {
    pub has_state: bool,
    pub device_clocks: Vec<DeviceClockDto>,
    pub last_state_write_ms: Option<u64>,
}

/// Metadata-only tombstone-dispute projection (NO secret values — field
/// *names* only).
pub struct VetoDto {
    pub record_uuid_hex: String,
    pub record_type: String,
    pub tags: Vec<String>,
    pub field_names: Vec<String>,
    pub local_last_mod_ms: u64,
    pub peer_tombstoned_at_ms: u64,
    pub peer_device_hex: String,
}

/// Metadata-only field-collision summary for the "auto-merged" notice.
pub struct CollisionDto {
    pub record_uuid_hex: String,
    pub field_names: Vec<String>,
}

/// Caller's per-record decision. `keep_local = true` → reject the peer
/// tombstone; `false` → accept the delete.
pub struct VetoDecisionDto {
    pub record_uuid_hex: String,
    pub keep_local: bool,
}

/// Result of one sync pass. Mirrors `secretary_ffi_bridge::SyncOutcomeDto`.
pub enum SyncOutcomeDto {
    NothingToDo,
    AppliedAutomatically,
    SilentMerge,
    MergedClean,
    ConflictsPending {
        vetoes: Vec<VetoDto>,
        collisions: Vec<CollisionDto>,
        manifest_hash: Vec<u8>,
    },
    RollbackRejected,
}
```

- [ ] **Step 4: Register the module + crate-root re-exports**

In `ffi/secretary-ffi-uniffi/src/wrappers/mod.rs`, add after `pub mod save;`:

```rust
pub mod sync;
```

In `ffi/secretary-ffi-uniffi/src/lib.rs`, after the `pub use wrappers::save::{...}` line add:

```rust
pub use wrappers::sync::{
    CollisionDto, DeviceClockDto, SyncOutcomeDto, SyncStatusDto, VetoDecisionDto, VetoDto,
};
```

and extend the `pub use namespace::{...}` block to include `sync_commit_decisions, sync_status, sync_vault`.

- [ ] **Step 5: Add the UDL declarations**

In `ffi/secretary-ffi-uniffi/src/secretary.udl`, inside the `namespace secretary { ... }` block add (alongside the other `[Throws=VaultError]` fns):

```
    /// Read-only sync status for a vault. (#187)
    [Throws=VaultError]
    SyncStatusDto sync_status(string state_dir, bytes vault_uuid);

    /// Run one manual sync pass. (#187)
    [Throws=VaultError]
    SyncOutcomeDto sync_vault(
        string state_dir,
        string vault_folder,
        bytes password,
        u64 now_ms
    );

    /// Commit tombstone-veto decisions for a paused sync pass. (#187)
    [Throws=VaultError]
    SyncOutcomeDto sync_commit_decisions(
        string state_dir,
        string vault_folder,
        bytes password,
        sequence<VetoDecisionDto> decisions,
        bytes manifest_hash,
        u64 now_ms
    );
```

and after the existing dictionaries/enums add:

```
dictionary DeviceClockDto {
    string device_uuid_hex;
    u64 counter;
};

dictionary SyncStatusDto {
    boolean has_state;
    sequence<DeviceClockDto> device_clocks;
    u64? last_state_write_ms;
};

dictionary VetoDto {
    string record_uuid_hex;
    string record_type;
    sequence<string> tags;
    sequence<string> field_names;
    u64 local_last_mod_ms;
    u64 peer_tombstoned_at_ms;
    string peer_device_hex;
};

dictionary CollisionDto {
    string record_uuid_hex;
    sequence<string> field_names;
};

dictionary VetoDecisionDto {
    string record_uuid_hex;
    boolean keep_local;
};

[Enum]
interface SyncOutcomeDto {
    NothingToDo();
    AppliedAutomatically();
    SilentMerge();
    MergedClean();
    ConflictsPending(sequence<VetoDto> vetoes, sequence<CollisionDto> collisions, bytes manifest_hash);
    RollbackRejected();
};
```

- [ ] **Step 6: Implement the three namespace wrapper functions**

In `ffi/secretary-ffi-uniffi/src/namespace.rs`, add a `use` for the sync DTOs at the top:

```rust
use crate::wrappers::sync::{
    CollisionDto, DeviceClockDto, SyncOutcomeDto, SyncStatusDto, VetoDecisionDto, VetoDto,
};
```

Add the three functions + two private bridge→uniffi converters (place converters near `uuid_from_vec`):

```rust
/// Read-only sync status for a vault. uniffi-projected (#187).
///
/// `state_dir` is the caller's sync-state directory (mobile sandbox path;
/// tests pass a tempdir). `vault_uuid` must be exactly 16 bytes.
///
/// # Errors
/// - [`VaultError::InvalidArgument`] — wrong-length `vault_uuid`.
/// - [`VaultError::SyncStateVaultMismatch`] / [`VaultError::SyncStateCorrupt`] /
///   [`VaultError::SyncFailed`] — see the bridge `sync_status_in` docs.
pub fn sync_status(state_dir: String, vault_uuid: Vec<u8>) -> Result<SyncStatusDto, VaultError> {
    let vault_uuid = uuid_from_vec(&vault_uuid, "vault_uuid")?;
    secretary_ffi_bridge::sync_status_in(std::path::Path::new(&state_dir), vault_uuid)
        .map(sync_status_from_bridge)
        .map_err(VaultError::from)
}

/// Run one manual sync pass. uniffi-projected (#187).
///
/// Wraps `password` in `SecretBytes` immediately (mirrors
/// `open_with_password` zeroize discipline). `now_ms` is the caller's
/// wall-clock used as the merge timestamp on a clean concurrent merge.
///
/// # Errors
/// See the bridge `sync_vault_in` docs (`SyncInProgress`,
/// `WrongPasswordOrCorrupt`, `SyncEvidenceStale`, `SyncFailed`, ...).
pub fn sync_vault(
    state_dir: String,
    vault_folder: String,
    password: Vec<u8>,
    now_ms: u64,
) -> Result<SyncOutcomeDto, VaultError> {
    use secretary_core::crypto::secret::SecretBytes;
    secretary_ffi_bridge::sync_vault_in(
        std::path::Path::new(&state_dir),
        std::path::Path::new(&vault_folder),
        SecretBytes::new(password),
        now_ms,
    )
    .map(sync_outcome_from_bridge)
    .map_err(VaultError::from)
}

/// Commit tombstone-veto decisions for a paused sync pass. uniffi-projected (#187).
///
/// `manifest_hash` is the opaque 32-byte freshness token from a prior
/// `sync_vault` `ConflictsPending` result.
///
/// # Errors
/// See the bridge `sync_commit_decisions_in` docs
/// (`SyncDecisionsIncomplete`, `SyncEvidenceStale`, `SyncFailed`, ...).
pub fn sync_commit_decisions(
    state_dir: String,
    vault_folder: String,
    password: Vec<u8>,
    decisions: Vec<VetoDecisionDto>,
    manifest_hash: Vec<u8>,
    now_ms: u64,
) -> Result<SyncOutcomeDto, VaultError> {
    use secretary_core::crypto::secret::SecretBytes;
    let bridge_decisions = decisions
        .into_iter()
        .map(|d| secretary_ffi_bridge::VetoDecisionDto {
            record_uuid_hex: d.record_uuid_hex,
            keep_local: d.keep_local,
        })
        .collect();
    secretary_ffi_bridge::sync_commit_decisions_in(
        std::path::Path::new(&state_dir),
        std::path::Path::new(&vault_folder),
        SecretBytes::new(password),
        bridge_decisions,
        manifest_hash,
        now_ms,
    )
    .map(sync_outcome_from_bridge)
    .map_err(VaultError::from)
}

/// Convert the bridge `SyncStatusDto` to the uniffi value type.
fn sync_status_from_bridge(s: secretary_ffi_bridge::SyncStatusDto) -> SyncStatusDto {
    SyncStatusDto {
        has_state: s.has_state,
        device_clocks: s
            .device_clocks
            .into_iter()
            .map(|c| DeviceClockDto {
                device_uuid_hex: c.device_uuid_hex,
                counter: c.counter,
            })
            .collect(),
        last_state_write_ms: s.last_state_write_ms,
    }
}

/// Convert the bridge `SyncOutcomeDto` to the uniffi value type.
fn sync_outcome_from_bridge(o: secretary_ffi_bridge::SyncOutcomeDto) -> SyncOutcomeDto {
    use secretary_ffi_bridge::SyncOutcomeDto as B;
    match o {
        B::NothingToDo => SyncOutcomeDto::NothingToDo,
        B::AppliedAutomatically => SyncOutcomeDto::AppliedAutomatically,
        B::SilentMerge => SyncOutcomeDto::SilentMerge,
        B::MergedClean => SyncOutcomeDto::MergedClean,
        B::RollbackRejected => SyncOutcomeDto::RollbackRejected,
        B::ConflictsPending {
            vetoes,
            collisions,
            manifest_hash,
        } => SyncOutcomeDto::ConflictsPending {
            vetoes: vetoes
                .into_iter()
                .map(|v| VetoDto {
                    record_uuid_hex: v.record_uuid_hex,
                    record_type: v.record_type,
                    tags: v.tags,
                    field_names: v.field_names,
                    local_last_mod_ms: v.local_last_mod_ms,
                    peer_tombstoned_at_ms: v.peer_tombstoned_at_ms,
                    peer_device_hex: v.peer_device_hex,
                })
                .collect(),
            collisions: collisions
                .into_iter()
                .map(|c| CollisionDto {
                    record_uuid_hex: c.record_uuid_hex,
                    field_names: c.field_names,
                })
                .collect(),
            manifest_hash,
        },
    }
}
```

NOTE: the bridge `VetoDto`/`CollisionDto` fields are `pub` (confirmed in `sync/dto.rs`); the bridge `SyncStatusDto`/`DeviceClockDto` likewise (`sync/status.rs`). If any field is private, add a `pub` getter on the bridge side in this task (it is metadata-only, no secret).

- [ ] **Step 7: Run the unit tests + clippy**

Run: `cargo test --release -p secretary-ffi-uniffi`
Expected: PASS incl. the 3 new `sync_*` tests.
Run: `cargo clippy --release -p secretary-ffi-uniffi --tests -- -D warnings`
Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add ffi/secretary-ffi-uniffi/src ffi/secretary-ffi-uniffi/Cargo.toml
git commit -m "feat(uniffi): project sync_status/sync_vault/sync_commit_decisions + DTOs (#187)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: pyo3 — project the three functions + DTOs (Python)

**Files:**
- Create: `ffi/secretary-ffi-py/src/sync.rs`
- Modify: `ffi/secretary-ffi-py/src/lib.rs:50-83` (module decl + imports) and `:115-262` (registration)

pyclasses can only be behaviourally exercised from Python, so the Rust-side gate here is "compiles + `maturin develop` succeeds"; behaviour is pinned by pytest (Tasks 4 + 6).

- [ ] **Step 1: Create the pyo3 DTO pyclasses + the three pyfunctions**

Create `ffi/secretary-ffi-py/src/sync.rs`:

```rust
//! PyO3 sync surface (#187): the three sync functions + their DTOs,
//! mirroring `secretary_ffi_bridge::sync`. Output DTOs are frozen read-only
//! pyclasses; `SyncOutcomeDto` exposes a `kind` discriminant + payload
//! getters (populated only for the ConflictsPending arm) — matching the
//! TS tagged-union shape. `VetoDecisionDto` is the one input pyclass.
//!
//! Every function takes an explicit `state_dir` (mobile sandbox path /
//! hermetic tests). `password` is wrapped in `SecretBytes` immediately.

use std::path::PathBuf;

use pyo3::prelude::*;
use secretary_core::crypto::secret::SecretBytes;

use crate::errors::{ffi_vault_error_to_pyerr, uuid_array_or_value_error};

#[pyclass(frozen, get_all)]
#[derive(Clone)]
pub struct DeviceClockDto {
    pub device_uuid_hex: String,
    pub counter: u64,
}

#[pyclass(frozen, get_all)]
#[derive(Clone)]
pub struct SyncStatusDto {
    pub has_state: bool,
    pub device_clocks: Vec<DeviceClockDto>,
    pub last_state_write_ms: Option<u64>,
}

#[pyclass(frozen, get_all)]
#[derive(Clone)]
pub struct VetoDto {
    pub record_uuid_hex: String,
    pub record_type: String,
    pub tags: Vec<String>,
    pub field_names: Vec<String>,
    pub local_last_mod_ms: u64,
    pub peer_tombstoned_at_ms: u64,
    pub peer_device_hex: String,
}

#[pyclass(frozen, get_all)]
#[derive(Clone)]
pub struct CollisionDto {
    pub record_uuid_hex: String,
    pub field_names: Vec<String>,
}

/// Result of one sync pass. `kind` is one of `"NothingToDo"`,
/// `"AppliedAutomatically"`, `"SilentMerge"`, `"MergedClean"`,
/// `"ConflictsPending"`, `"RollbackRejected"`. `vetoes` / `collisions` /
/// `manifest_hash` are populated only when `kind == "ConflictsPending"`
/// (empty / `None` otherwise).
#[pyclass(frozen, get_all)]
#[derive(Clone)]
pub struct SyncOutcomeDto {
    pub kind: String,
    pub vetoes: Vec<VetoDto>,
    pub collisions: Vec<CollisionDto>,
    pub manifest_hash: Option<Vec<u8>>,
}

#[pyclass]
#[derive(Clone)]
pub struct VetoDecisionDto {
    pub record_uuid_hex: String,
    pub keep_local: bool,
}

#[pymethods]
impl VetoDecisionDto {
    #[new]
    fn new(record_uuid_hex: String, keep_local: bool) -> Self {
        Self {
            record_uuid_hex,
            keep_local,
        }
    }
}

fn outcome_from_bridge(o: secretary_ffi_bridge::SyncOutcomeDto) -> SyncOutcomeDto {
    use secretary_ffi_bridge::SyncOutcomeDto as B;
    let kind = match &o {
        B::NothingToDo => "NothingToDo",
        B::AppliedAutomatically => "AppliedAutomatically",
        B::SilentMerge => "SilentMerge",
        B::MergedClean => "MergedClean",
        B::ConflictsPending { .. } => "ConflictsPending",
        B::RollbackRejected => "RollbackRejected",
    }
    .to_string();
    match o {
        B::ConflictsPending {
            vetoes,
            collisions,
            manifest_hash,
        } => SyncOutcomeDto {
            kind,
            vetoes: vetoes
                .into_iter()
                .map(|v| VetoDto {
                    record_uuid_hex: v.record_uuid_hex,
                    record_type: v.record_type,
                    tags: v.tags,
                    field_names: v.field_names,
                    local_last_mod_ms: v.local_last_mod_ms,
                    peer_tombstoned_at_ms: v.peer_tombstoned_at_ms,
                    peer_device_hex: v.peer_device_hex,
                })
                .collect(),
            collisions: collisions
                .into_iter()
                .map(|c| CollisionDto {
                    record_uuid_hex: c.record_uuid_hex,
                    field_names: c.field_names,
                })
                .collect(),
            manifest_hash: Some(manifest_hash),
        },
        _ => SyncOutcomeDto {
            kind,
            vetoes: Vec::new(),
            collisions: Vec::new(),
            manifest_hash: None,
        },
    }
}

#[pyfunction]
pub(crate) fn sync_status(state_dir: PathBuf, vault_uuid: Vec<u8>) -> PyResult<SyncStatusDto> {
    let vault_uuid = uuid_array_or_value_error(&vault_uuid, "vault_uuid")?;
    let s = secretary_ffi_bridge::sync_status_in(&state_dir, vault_uuid)
        .map_err(ffi_vault_error_to_pyerr)?;
    Ok(SyncStatusDto {
        has_state: s.has_state,
        device_clocks: s
            .device_clocks
            .into_iter()
            .map(|c| DeviceClockDto {
                device_uuid_hex: c.device_uuid_hex,
                counter: c.counter,
            })
            .collect(),
        last_state_write_ms: s.last_state_write_ms,
    })
}

#[pyfunction]
pub(crate) fn sync_vault(
    state_dir: PathBuf,
    vault_folder: PathBuf,
    password: Vec<u8>,
    now_ms: u64,
) -> PyResult<SyncOutcomeDto> {
    secretary_ffi_bridge::sync_vault_in(&state_dir, &vault_folder, SecretBytes::new(password), now_ms)
        .map(outcome_from_bridge)
        .map_err(ffi_vault_error_to_pyerr)
}

#[pyfunction]
pub(crate) fn sync_commit_decisions(
    state_dir: PathBuf,
    vault_folder: PathBuf,
    password: Vec<u8>,
    decisions: Vec<VetoDecisionDto>,
    manifest_hash: Vec<u8>,
    now_ms: u64,
) -> PyResult<SyncOutcomeDto> {
    let bridge_decisions = decisions
        .into_iter()
        .map(|d| secretary_ffi_bridge::VetoDecisionDto {
            record_uuid_hex: d.record_uuid_hex,
            keep_local: d.keep_local,
        })
        .collect();
    secretary_ffi_bridge::sync_commit_decisions_in(
        &state_dir,
        &vault_folder,
        SecretBytes::new(password),
        bridge_decisions,
        manifest_hash,
        now_ms,
    )
    .map(outcome_from_bridge)
    .map_err(ffi_vault_error_to_pyerr)
}
```

NOTE: `pyfunction(Vec<VetoDecisionDto>)` requires `VetoDecisionDto: FromPyObject`. A `#[pyclass] + #[derive(Clone)]` with a `#[new]` yields a class instances of which extract by-ref; PyO3 0.22+ accepts `Vec<T>` of pyclass instances via the `Clone` bound. If extraction fails to compile, add `#[derive(FromPyObject)]` is NOT valid on pyclass — instead change the param to `Vec<Py<VetoDecisionDto>>` and `.borrow(py)` each. Prefer the `Vec<VetoDecisionDto>` form first; fall back only if the compiler rejects it.

- [ ] **Step 2: Register the module, classes, and functions**

In `ffi/secretary-ffi-py/src/lib.rs`, add `mod sync;` to the module list (after `mod share;`), and add a `use`:

```rust
use sync::{
    sync_commit_decisions, sync_status, sync_vault, CollisionDto, DeviceClockDto, SyncOutcomeDto,
    SyncStatusDto, VetoDecisionDto, VetoDto,
};
```

In the `#[pymodule] fn secretary_ffi_py`, before the final `Ok(())`, add:

```rust
    // #187 sync surface — 3 functions + 6 DTO classes (error classes
    // already registered in the D.1.13 block above).
    m.add_class::<DeviceClockDto>()?;
    m.add_class::<SyncStatusDto>()?;
    m.add_class::<VetoDto>()?;
    m.add_class::<CollisionDto>()?;
    m.add_class::<SyncOutcomeDto>()?;
    m.add_class::<VetoDecisionDto>()?;
    m.add_function(wrap_pyfunction!(sync_status, m)?)?;
    m.add_function(wrap_pyfunction!(sync_vault, m)?)?;
    m.add_function(wrap_pyfunction!(sync_commit_decisions, m)?)?;
```

- [ ] **Step 3: Build to verify it compiles**

Run: `cargo build --release -p secretary-ffi-py`
Expected: PASS (no Python yet — pure Rust compile gate).
Run: `cargo clippy --release -p secretary-ffi-py --tests -- -D warnings`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add ffi/secretary-ffi-py/src
git commit -m "feat(pyo3): project sync functions + DTOs onto the Python binding (#187)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: Python pytest — status + clean sync + fixture-free error paths

**Files:**
- Create: `ffi/secretary-ffi-py/tests/test_sync.py`

- [ ] **Step 1: Write the test module (no divergence fixture needed yet)**

Create `ffi/secretary-ffi-py/tests/test_sync.py`:

```python
"""#187 pytest suite — sync_status / sync_vault / sync_commit_decisions.

Each test uses its own tempdir state_dir + a writable copy of
golden_vault_001 so the read-only on-disk fixtures are never touched.
The ConflictsPending round-trip (test_conflict_round_trip) is added in a
later step once the divergence fixture exists.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

import secretary_ffi_py
from secretary_ffi_py import (
    VaultSyncFailed,
    sync_commit_decisions,
    sync_status,
    sync_vault,
)

VAULT_001_PASSWORD = b"correct horse battery staple"
NOW_MS = 1_715_000_000_000


def _golden_vault_path(n: int) -> Path:
    return (
        Path(__file__).resolve().parents[3]
        / "core"
        / "tests"
        / "data"
        / f"golden_vault_{n:03d}"
    )


def _fresh_writable_vault(tmp_path: Path) -> Path:
    dst = tmp_path / "vault001"
    shutil.copytree(_golden_vault_path(1), dst)
    return dst


def test_sync_status_empty_state_dir_reports_no_state(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    status = sync_status(str(state_dir), bytes([9] * 16))
    assert status.has_state is False
    assert status.device_clocks == []
    assert status.last_state_write_ms is None


def test_sync_status_wrong_length_vault_uuid_raises_value_error(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    with pytest.raises(ValueError):
        sync_status(str(state_dir), bytes([0] * 15))


def test_sync_vault_fresh_state_applies_automatically(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    vault = _fresh_writable_vault(tmp_path)
    outcome = sync_vault(str(state_dir), str(vault), VAULT_001_PASSWORD, NOW_MS)
    assert outcome.kind == "AppliedAutomatically"
    # state was persisted → status now reports has_state
    # (vault_uuid is unknown to Python, so just assert via a second sync:
    #  a second pass over the now-current vault is NothingToDo)
    again = sync_vault(str(state_dir), str(vault), VAULT_001_PASSWORD, NOW_MS)
    assert again.kind == "NothingToDo"


def test_sync_commit_decisions_bad_manifest_hash_raises_sync_failed(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    vault = _fresh_writable_vault(tmp_path)
    with pytest.raises(VaultSyncFailed):
        sync_commit_decisions(
            str(state_dir), str(vault), VAULT_001_PASSWORD, [], bytes(5), NOW_MS
        )
```

- [ ] **Step 2: Rebuild the wheel + run the tests**

Run:
```bash
uv run --directory ffi/secretary-ffi-py maturin develop --release
uv run --directory ffi/secretary-ffi-py pytest tests/test_sync.py -v
```
Expected: PASS (4 tests). If pytest sees a stale `.so` (old surface, ImportError on the new symbols), nuke + rebuild per the project memory: `rm -rf ffi/secretary-ffi-py/.venv && uv cache clean && uv run --directory ffi/secretary-ffi-py maturin develop --release`.

- [ ] **Step 3: Commit**

```bash
git add ffi/secretary-ffi-py/tests/test_sync.py
git commit -m "test(pyo3): sync_status + clean sync_vault + error-path pytest (#187)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: Generate the committed two-device divergence fixture

The Python `ConflictsPending` round-trip needs a vault whose canonical + sibling manifests diverge AND a seeded concurrent `SyncState` (the veto only fires when the caller's clock is `Concurrent` with the disk manifests — confirmed in `cli/tests/sync_pass_integration.rs::inspect_returns_veto_detail_and_leaves_disk_untouched`). Reuse the cli's `stage_concurrent_veto_vault` builder; persist the result under `core/tests/data/sync_conflict_fixture/`.

**Files:**
- Create: `cli/tests/generate_sync_conflict_fixture.rs`
- Create (generated): `core/tests/data/sync_conflict_fixture/vault/...` + `core/tests/data/sync_conflict_fixture/state/<uuid>.state.cbor` + `core/tests/data/sync_conflict_fixture/README.md`

- [ ] **Step 1: Read the existing fixture builder + helpers**

Read `cli/tests/sync_pass_integration.rs` fully — note `stage_concurrent_veto_vault` (returns `(TempDir, vault_dir, identity, password, vault_uuid, block_uuid)`), the `LOCAL_DEVICE_UUID` / `VectorClockEntry` constants, `sync_pass_inspect`, and `secretary_cli::state::save`. The generator reuses these. Because the helpers are `fn`-private to that test binary, the generator must live in the **same** test binary OR copy the needed helpers. Decision: add the generator as an additional `#[ignore]` test **inside `cli/tests/sync_pass_integration.rs`** (so it reuses every helper in-place) rather than a separate file. (Update the File Structure note accordingly — no new `.rs` file.)

- [ ] **Step 2: Add the `--ignored` generator test**

Append to `cli/tests/sync_pass_integration.rs` (inside the same module, after the inspect tests):

```rust
/// Generator (run on demand, human-reviewed diff) for the committed
/// two-device divergence fixture consumed by the Python #187 round-trip
/// test. Reuses `stage_concurrent_veto_vault` + a seeded Concurrent
/// `SyncState`, self-validates that the pair yields `ConflictsPending`,
/// then copies the vault folder + the serialized state into
/// `core/tests/data/sync_conflict_fixture/`.
///
/// Run:
///   cargo test --release -p secretary-cli --test sync_pass_integration -- \
///       --ignored generate_sync_conflict_fixture --nocapture
///
/// Diff is human-reviewed before commit; expected diff is scoped to
/// `core/tests/data/sync_conflict_fixture/` and nothing else.
#[test]
#[ignore]
fn generate_sync_conflict_fixture() {
    let (_tmp, vault_dir, identity, password, vault_uuid, _block_uuid) =
        stage_concurrent_veto_vault();

    // Seeded local clock: a device absent from both disk manifests → the
    // disk state classifies as Concurrent and the merge raises a veto.
    let local_clock = vec![VectorClockEntry {
        device_uuid: LOCAL_DEVICE_UUID,
        counter: 1,
    }];
    let mut state = SyncState::new(vault_uuid, local_clock).expect("SyncState::new");

    // Self-validate: the fixture must actually pause on a veto, else it is
    // not a valid ConflictsPending fixture. Inspect writes nothing.
    let mut probe = state.clone();
    match sync_pass_inspect(&vault_dir, &identity, &password, &mut probe, 0)
        .expect("inspect must return Ok")
    {
        InspectOutcome::ConflictsPending { vetoes, .. } => {
            assert!(!vetoes.is_empty(), "fixture must yield ≥1 veto");
        }
        other => panic!("fixture did not pause on a veto: {other:?}"),
    }

    // Destination tree under core/tests/data/.
    let dest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../core/tests/data/sync_conflict_fixture");
    let _ = fs::remove_dir_all(&dest);
    let vault_dest = dest.join("vault");
    let state_dest = dest.join("state");
    fs::create_dir_all(&state_dest).expect("create_dir_all state/");
    copy_dir_recursive_test(&vault_dir, &vault_dest);

    // Persist the seeded concurrent SyncState into state/ (the exact bytes
    // the Python test will load as its state_dir).
    secretary_cli::state::save(&state_dest, &state).expect("save SyncState");

    // A short README so the committed fixture is self-explanatory.
    fs::write(
        dest.join("README.md"),
        "# sync_conflict_fixture (#187, generated)\n\n\
         Two-device divergence: `vault/` holds a canonical manifest + a sibling\n\
         conflict-copy manifest that tombstones a record the canonical side\n\
         still has live; `state/<uuid>.state.cbor` is a seeded SyncState whose\n\
         clock is Concurrent with both manifests. Loading `vault/` with password\n\
         \"correct horse battery staple\" and `state/` as the state dir makes\n\
         `sync_vault` return ConflictsPending (vetoes non-empty, collisions\n\
         empty — the tombstone merge yields no field collision; see #192).\n\n\
         Regenerate via: cargo test --release -p secretary-cli --test \
         sync_pass_integration -- --ignored generate_sync_conflict_fixture \
         --nocapture\n",
    )
    .expect("write fixture README");

    eprintln!("wrote sync_conflict_fixture to {}", dest.display());
}

/// Local recursive dir copy for the generator (the test binary has no
/// `copy_dir_recursive` in scope; small + test-only).
fn copy_dir_recursive_test(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir_recursive_test(&from, &to);
        } else {
            fs::copy(&from, &to).unwrap();
        }
    }
}
```

If `LOCAL_DEVICE_UUID`, `SyncState`, `InspectOutcome`, `sync_pass_inspect`, `VectorClockEntry`, `fs`, `Path`, `PathBuf` are not already imported in the file, they are (per the reads in Step 1) — confirm with `cargo test` compile; add `use` lines only if the compiler complains.

- [ ] **Step 3: Run the generator + verify the fixture**

Run:
```bash
cargo test --release -p secretary-cli --test sync_pass_integration -- --ignored generate_sync_conflict_fixture --nocapture
ls -R core/tests/data/sync_conflict_fixture
```
Expected: prints the write path; the tree contains `vault/` (manifest + sibling manifest + `blocks/`) `state/<32hex>.state.cbor`, `README.md`.

- [ ] **Step 4: Confirm the rest of the suite still compiles/passes**

Run: `cargo test --release -p secretary-cli --test sync_pass_integration`
Expected: PASS (the `#[ignore]` generator is skipped in the normal run).

- [ ] **Step 5: Commit the generator + the generated fixture**

```bash
git add cli/tests/sync_pass_integration.rs core/tests/data/sync_conflict_fixture
git commit -m "test(fixtures): generated two-device divergence fixture for #187 round-trip

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: Python pytest — full ConflictsPending → commit_decisions → MergedClean round-trip

**Files:**
- Modify: `ffi/secretary-ffi-py/tests/test_sync.py`

- [ ] **Step 1: Add the round-trip + error-path tests**

Append to `ffi/secretary-ffi-py/tests/test_sync.py`:

```python
from secretary_ffi_py import VaultSyncDecisionsIncomplete, VetoDecisionDto


def _fixture_root() -> Path:
    return (
        Path(__file__).resolve().parents[3]
        / "core"
        / "tests"
        / "data"
        / "sync_conflict_fixture"
    )


def _stage_conflict(tmp_path: Path) -> tuple[Path, Path]:
    """Copy the committed divergence fixture into writable tempdirs.

    Returns (state_dir, vault_folder) ready for sync_vault.
    """
    root = _fixture_root()
    state_dir = tmp_path / "state"
    vault = tmp_path / "vault"
    shutil.copytree(root / "state", state_dir)
    shutil.copytree(root / "vault", vault)
    return state_dir, vault


def test_conflict_round_trip_keep_local(tmp_path: Path) -> None:
    state_dir, vault = _stage_conflict(tmp_path)

    pending = sync_vault(str(state_dir), str(vault), VAULT_001_PASSWORD, NOW_MS)
    assert pending.kind == "ConflictsPending"
    assert len(pending.vetoes) >= 1
    # Tombstone divergence yields no field collision (see #192).
    assert pending.collisions == []
    assert pending.manifest_hash is not None and len(pending.manifest_hash) == 32

    decisions = [VetoDecisionDto(v.record_uuid_hex, True) for v in pending.vetoes]
    committed = sync_commit_decisions(
        str(state_dir),
        str(vault),
        VAULT_001_PASSWORD,
        decisions,
        bytes(pending.manifest_hash),
        NOW_MS,
    )
    assert committed.kind == "MergedClean"


def test_commit_decisions_incomplete_raises(tmp_path: Path) -> None:
    state_dir, vault = _stage_conflict(tmp_path)
    pending = sync_vault(str(state_dir), str(vault), VAULT_001_PASSWORD, NOW_MS)
    assert pending.kind == "ConflictsPending"
    # Empty decisions cannot cover a non-empty veto set → typed error.
    with pytest.raises(VaultSyncDecisionsIncomplete):
        sync_commit_decisions(
            str(state_dir),
            str(vault),
            VAULT_001_PASSWORD,
            [],
            bytes(pending.manifest_hash),
            NOW_MS,
        )
```

- [ ] **Step 2: Run the full sync pytest module**

Run: `uv run --directory ffi/secretary-ffi-py pytest tests/test_sync.py -v`
Expected: PASS (6 tests). (`maturin develop` not needed unless the Rust changed since Task 4; if ImportError on `VetoDecisionDto`, rebuild as in Task 4 Step 2.)

- [ ] **Step 3: Commit**

```bash
git add ffi/secretary-ffi-py/tests/test_sync.py
git commit -m "test(pyo3): full ConflictsPending → commit_decisions → MergedClean round-trip (#187)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 7: Swift parity-smoke (`SmokeSync.swift`)

**Files:**
- Create: `ffi/secretary-ffi-uniffi/tests/swift/SmokeSync.swift`
- Modify: `ffi/secretary-ffi-uniffi/tests/swift/run.sh` (add the file to the `swiftc` list)
- Modify: `ffi/secretary-ffi-uniffi/tests/swift/main.swift` (call `runSyncAsserts(env:)`)

- [ ] **Step 1: Read the smoke harness conventions**

Read `tests/swift/SmokeTrashRestore.swift` (writable-copy pattern), `SmokeHelpers.swift` (the `SmokeEnv`, `assertEqual`/`recordFailure` helpers, the writable-copy + golden-dir accessors), and `main.swift`. `SmokeSync` mirrors their shape exactly.

- [ ] **Step 2: Write `SmokeSync.swift`**

Create `ffi/secretary-ffi-uniffi/tests/swift/SmokeSync.swift`:

```swift
// Sync parity-smoke (#187): exercises sync_status (empty state dir) and one
// clean sync_vault pass over a writable golden copy, plus a VetoDecisionDto
// round-trip. The two-device conflict round-trip is proven in the Python
// suite (the conflict logic is shared Rust; uniffi generates Swift+Kotlin
// from one definition, so DTO-shape parity here suffices).

import Foundation

func runSyncAsserts(env: SmokeEnv) {
    // 1. Empty state dir → has_state == false.
    let stateDir = makeTempDir()   // SmokeHelpers temp-dir accessor
    defer { try? FileManager.default.removeItem(atPath: stateDir) }
    do {
        let status = try syncStatus(stateDir: stateDir, vaultUuid: Data(repeating: 9, count: 16))
        assertEqual(status.hasState, false, "sync_status empty → has_state false")
        assertEqual(status.deviceClocks.isEmpty, true, "sync_status empty → no clocks")
    } catch {
        recordFailure("sync_status threw: \(error)")
    }

    // 2. Clean sync_vault pass over a fresh writable golden copy.
    let vaultDir = copyGoldenVaultToTemp(env: env)   // SmokeHelpers writable-copy accessor
    defer { try? FileManager.default.removeItem(atPath: vaultDir) }
    do {
        let outcome = try syncVault(
            stateDir: stateDir,
            vaultFolder: vaultDir,
            password: env.password001,
            nowMs: 1_715_000_000_000
        )
        if case .appliedAutomatically = outcome {
            // ok
        } else {
            recordFailure("sync_vault fresh state expected AppliedAutomatically, got \(outcome)")
        }
    } catch {
        recordFailure("sync_vault threw: \(error)")
    }

    // 3. VetoDecisionDto value round-trip (constructs the input DTO).
    let d = VetoDecisionDto(recordUuidHex: String(repeating: "ab", count: 16), keepLocal: true)
    assertEqual(d.keepLocal, true, "VetoDecisionDto field round-trip")
}
```

NOTE: the exact helper names (`makeTempDir`, `copyGoldenVaultToTemp`, `assertEqual`, `recordFailure`, `env.password001`) must match what `SmokeHelpers.swift` actually exports — use the real ones discovered in Step 1; the names above are the expected shapes. uniffi lowerCamelCases the UDL names (`sync_status` → `syncStatus`, `has_state` → `hasState`, `AppliedAutomatically` → `.appliedAutomatically`).

- [ ] **Step 3: Wire into the runner + entrypoint**

In `tests/swift/run.sh`, add `"$SCRIPT_DIR/SmokeSync.swift" \` to the `swiftc` source list (before `main.swift`). In `tests/swift/main.swift`, add `runSyncAsserts(env: env)` after `runTrashRestoreAsserts(env: env)`.

- [ ] **Step 4: Run the Swift smoke runner**

Run: `bash ffi/secretary-ffi-uniffi/tests/swift/run.sh`
Expected: `OK: secretary uniffi Swift smoke runner — all assertions passed.` (If `swiftc` is unavailable on the host, record that the smoke could not run locally and must run in CI / on a macOS host — do not silently skip.)

- [ ] **Step 5: Commit**

```bash
git add ffi/secretary-ffi-uniffi/tests/swift
git commit -m "test(swift): SmokeSync parity-smoke for the projected sync surface (#187)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 8: Kotlin parity-smoke (`SmokeSync.kt`)

**Files:**
- Create: `ffi/secretary-ffi-uniffi/tests/kotlin/SmokeSync.kt`
- Modify: `ffi/secretary-ffi-uniffi/tests/kotlin/run.sh` (add to `kotlinc` list)
- Modify: `ffi/secretary-ffi-uniffi/tests/kotlin/Main.kt` (call `runSyncAsserts(env)`)

- [ ] **Step 1: Read the Kotlin smoke conventions**

Read `tests/kotlin/SmokeTrashRestore.kt`, `SmokeHelpers.kt`, `Main.kt`, and `tests/kotlin/run.sh` (the smoke runner — confirm it lists `Smoke*.kt` sources like the Swift `run.sh`). Mirror their shape.

- [ ] **Step 2: Write `SmokeSync.kt`**

Create `ffi/secretary-ffi-uniffi/tests/kotlin/SmokeSync.kt`:

```kotlin
// Sync parity-smoke (#187) — Kotlin mirror of SmokeSync.swift.

import uniffi.secretary.*

fun runSyncAsserts(env: SmokeEnv) {
    val stateDir = makeTempDir()            // SmokeHelpers temp-dir accessor
    try {
        val status = syncStatus(stateDir, ByteArray(16) { 9 })
        assertEqual(status.hasState, false, "sync_status empty → has_state false")
        assertEqual(status.deviceClocks.isEmpty(), true, "sync_status empty → no clocks")

        val vaultDir = copyGoldenVaultToTemp(env)  // SmokeHelpers writable-copy accessor
        try {
            val outcome = syncVault(stateDir, vaultDir, env.password001, 1_715_000_000_000uL)
            if (outcome !is SyncOutcomeDto.AppliedAutomatically) {
                recordFailure("sync_vault fresh state expected AppliedAutomatically, got $outcome")
            }
        } finally {
            deleteRecursively(vaultDir)
        }

        val d = VetoDecisionDto(recordUuidHex = "ab".repeat(16), keepLocal = true)
        assertEqual(d.keepLocal, true, "VetoDecisionDto field round-trip")
    } finally {
        deleteRecursively(stateDir)
    }
}
```

NOTE: match the real `SmokeHelpers.kt` accessor/assert names from Step 1. uniffi Kotlin lowerCamelCases UDL names and emits the enum as a sealed `SyncOutcomeDto.AppliedAutomatically` object; `u64` args take the `uL` suffix.

- [ ] **Step 3: Wire into the runner + entrypoint**

In `tests/kotlin/run.sh`, add `"$SCRIPT_DIR/SmokeSync.kt" \` to the `kotlinc` source list. In `tests/kotlin/Main.kt`, add `runSyncAsserts(env)` after `runTrashRestoreAsserts(env)`.

- [ ] **Step 4: Run the Kotlin smoke runner**

Run: `bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh`
Expected: `OK: secretary uniffi Kotlin smoke runner — all assertions passed.` (If `kotlinc` is unavailable locally, record that it must run in CI / on a JVM host — do not silently skip.)

- [ ] **Step 5: Commit**

```bash
git add ffi/secretary-ffi-uniffi/tests/kotlin
git commit -m "test(kotlin): SmokeSync parity-smoke for the projected sync surface (#187)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 9: Docs — README + ROADMAP

**Files:**
- Modify: `README.md`
- Modify: `ROADMAP.md`

- [ ] **Step 1: Update README + ROADMAP**

In `ROADMAP.md`, mark #187 done (mirror the existing `D.1.x ✅` line style). In `README.md`, if there is a bindings/status section listing what the uniffi/pyo3 surfaces expose, add sync to it (brief — dot point, per the README-style memory). Do **not** add a test-count wall.

- [ ] **Step 2: Commit**

```bash
git add README.md ROADMAP.md
git commit -m "docs: #187 sync projected onto uniffi + pyo3

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 10: Full gauntlet (mandatory — FFI surface changed)

- [ ] **Step 1: Rust workspace**

```bash
cargo fmt --all --check
cargo clippy --release --workspace --tests -- -D warnings
cargo test --release --workspace
```
Expected: clean / 0 failed.

- [ ] **Step 2: Cross-language conformance + Python**

```bash
uv run core/tests/python/conformance.py
uv run --directory ffi/secretary-ffi-py maturin develop --release
uv run --directory ffi/secretary-ffi-py pytest
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
```
Expected: conformance.py PASS; pytest all green; swift/kotlin smoke + conformance OK. (`run_conformance.sh` is unchanged by this slice but must still pass — the KAT was not touched.) Record any harness that cannot run on the local host (missing swiftc/kotlinc) so it is run in CI, rather than marking it green.

- [ ] **Step 2b (if any toolchain missing locally): note it explicitly** in the final summary; do not claim a smoke passed that did not run.

---

## Self-Review (completed during planning)

- **Spec coverage:** §Surface → Tasks 2/3; §Bridge change → Task 1; §uniffi → Task 2; §pyo3 → Task 3; §Tests Python → Tasks 4/6; §Tests Swift/Kotlin → Tasks 7/8; §Divergence fixture → Task 5; §File inventory → File Structure table; §Gauntlet → Task 10; §Docs → Task 9. All covered.
- **Type consistency:** `SyncOutcomeDto`/`VetoDto`/`CollisionDto`/`VetoDecisionDto`/`SyncStatusDto`/`DeviceClockDto` names + field names are identical across bridge, uniffi value types, pyo3 pyclasses, UDL dictionaries, and the Python/Swift/Kotlin call sites. `keep_local`↔`keepLocal`, `manifest_hash`↔`manifestHash` (`bytes`↔`ByteArray`/`bytes`), `kind` discriminant strings match the bridge enum arm names.
- **Known open detail flagged inline:** the pyo3 `Vec<VetoDecisionDto>` extraction (Task 3 Step 1 NOTE) and the exact Swift/Kotlin `SmokeHelpers` accessor names (Tasks 7/8 NOTEs) are the only places the executor must reconcile against real code; both have a stated fallback.
