# #402 Retention Auto-Purge FFI Projection — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Project the core retention API (`expired_trash_entries`, `auto_purge_expired`, `DEFAULT_RETENTION_WINDOW_MS`) through `secretary-ffi-bridge` → uniffi (Swift/Kotlin) + pyo3 (Python) so platforms can preview and commit retention auto-purge.

**Architecture:** A new self-contained `retention/` bridge module (mirrors core's `retention.rs` and the `purge/` bridge module) carrying an `ExpiredEntry` DTO, a `RetentionPurgeReport` DTO, the pure `expired_trash_entries` preview free-fn, the `empty_trash`-shaped `auto_purge_expired` commit free-fn, and an exhaustive core-error mapper. Both binding crates project these unchanged. No core change, no new `FfiVaultError` variant.

**Tech Stack:** Rust (stable), pyo3 0.28, uniffi 0.31, `uv`/maturin (Python), Gradle/kotlin-jvm (Android `:kit`/`:app`).

## Global Constraints

- `#![forbid(unsafe_code)]` workspace-wide — do not introduce `unsafe`.
- Clippy must stay clean with `-D warnings` (lib + tests).
- `cargo fmt --all --check` clean; `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace` clean.
- No new `FfiVaultError` variant (retention reuses `CorruptVault`/`FolderInvalid`/`SaveCryptoFailure`).
- Input validation (wrong-length `device_uuid`) lives in the **binding wrapper** (uniffi `uuid_from_vec` → `VaultError::InvalidArgument`; pyo3 `uuid_array_or_value_error` → `ValueError`), NOT the bridge — the bridge takes `[u8; 16]` and trusts its caller.
- Core-error mappers are exhaustive `match` with **no `_` catchall** (issue #40).
- `DEFAULT_RETENTION_WINDOW_MS = 90 * 24 * 60 * 60 * 1000` — never a magic number; reached from one bridge-re-exported core const.
- Lean-binding boundary (#189): `notify`/`clap` must not leak into the binding crates — new code imports only `secretary_ffi_bridge` + `pyo3`/uniffi scaffolding.
- All Python via `uv` — never `pip`.
- Tests that open the golden vault must open a **temp copy** (`shutil.copytree` into `tmp_path`), never the tracked fixture.

**Reference templates** (read before implementing — the new code mirrors them):
- Commit fn + report DTO + error mapper: `ffi/secretary-ffi-bridge/src/purge/orchestration.rs` (`empty_trash` / `EmptyTrashReport` / `map_core_vault_error_empty_trash`).
- Pure manifest read: `ffi/secretary-ffi-bridge/src/vault/manifest.rs::block_summaries` + the `manifest_body()` accessor.
- pyo3 projection: `ffi/secretary-ffi-py/src/purge.rs` + registration in `ffi/secretary-ffi-py/src/lib.rs`.
- pyo3 pytest: `ffi/secretary-ffi-py/tests/test_purge.py`.
- uniffi projection: `ffi/secretary-ffi-uniffi/src/wrappers/purge.rs` + `namespace/mod.rs` (`purge_block`/`empty_trash`) + `secretary.udl` (dictionaries + namespace fns).

**Working directory:** all commands run from `.worktrees/retention-ffi-402/` (branch `feature/retention-ffi-402`). Verify with `pwd && git branch --show-current` before any `cargo`/`git`.

---

## Task 1: Bridge `retention/` module — DTOs, `From` impls, const re-export, scaffolding

**Files:**
- Create: `ffi/secretary-ffi-bridge/src/retention/mod.rs`
- Create: `ffi/secretary-ffi-bridge/src/retention/orchestration.rs`
- Modify: `ffi/secretary-ffi-bridge/src/lib.rs` (add `pub mod retention;` + re-exports)

**Interfaces:**
- Consumes: `secretary_core::vault::{ExpiredEntry as CoreExpiredEntry, RetentionPurgeReport as CoreRetentionPurgeReport, DEFAULT_RETENTION_WINDOW_MS}`.
- Produces: `secretary_ffi_bridge::{ExpiredEntry, RetentionPurgeReport, DEFAULT_RETENTION_WINDOW_MS}`; `ExpiredEntry { block_uuid: [u8;16], tombstoned_at_ms: u64, age_ms: u64 }`; `RetentionPurgeReport { purged_count: u32, shared_count: u32, owner_only_count: u32, unknown_count: u32, files_removed: u32, files_failed: u32, window_ms: u64 }`.

- [ ] **Step 1: Write the failing tests**

Add to `ffi/secretary-ffi-bridge/src/retention/orchestration.rs` (create the file with just the DTOs + `From` impls + this test module for now; the fns land in Task 2):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_entry_from_core_projects_all_fields() {
        let core = secretary_core::vault::ExpiredEntry {
            block_uuid: [0xAB; 16],
            tombstoned_at_ms: 1_000,
            age_ms: 4_000,
        };
        let bridge = ExpiredEntry::from(core);
        assert_eq!(bridge.block_uuid, [0xAB; 16]);
        assert_eq!(bridge.tombstoned_at_ms, 1_000);
        assert_eq!(bridge.age_ms, 4_000);
    }

    #[test]
    fn retention_report_from_core_narrows_usize_and_passes_window() {
        let core = secretary_core::vault::RetentionPurgeReport {
            purged_count: 3,
            shared_count: 1,
            owner_only_count: 2,
            unknown_count: 0,
            files_removed: 3,
            files_failed: 0,
            window_ms: 7_776_000_000,
        };
        let bridge = RetentionPurgeReport::from(core);
        assert_eq!(bridge.purged_count, 3);
        assert_eq!(bridge.shared_count, 1);
        assert_eq!(bridge.owner_only_count, 2);
        assert_eq!(bridge.unknown_count, 0);
        assert_eq!(bridge.files_removed, 3);
        assert_eq!(bridge.files_failed, 0);
        assert_eq!(bridge.window_ms, 7_776_000_000);
    }

    #[test]
    fn default_window_re_export_matches_core() {
        assert_eq!(
            crate::DEFAULT_RETENTION_WINDOW_MS,
            secretary_core::vault::DEFAULT_RETENTION_WINDOW_MS
        );
    }
}
```

- [ ] **Step 2: Run to verify it fails (does not compile — types/module absent)**

Run: `cargo test --release -p secretary-ffi-bridge retention 2>&1 | tail -20`
Expected: FAIL — `retention` module / `ExpiredEntry` / `RetentionPurgeReport` unresolved.

- [ ] **Step 3: Write the DTOs, `From` impls, and module doc**

Prepend to `ffi/secretary-ffi-bridge/src/retention/orchestration.rs` (above the test module):

```rust
//! Retention auto-purge FFI projection (#402): the pure `expired_trash_entries`
//! preview, the `auto_purge_expired` commit, their bridge-side DTOs, and an
//! exhaustive core-error mapper. Sibling of [`crate::purge`]; the commit is
//! byte-for-byte `empty_trash`'s orchestration plus two scalar args
//! (`window_ms`, `now_ms`) and one pass-through report field (`window_ms`).
//! `docs/vault-format.md` §7 step 5.

use rand_core::OsRng;
use secretary_core::vault::{OpenVault, VaultError};

use crate::error::FfiVaultError;
use crate::identity::UnlockedIdentity;
use crate::vault::OpenVaultManifest;

/// One trash entry eligible for retention auto-purge — the pure preview
/// record a platform shows before committing. Bridge projection of
/// [`secretary_core::vault::ExpiredEntry`], field-for-field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiredEntry {
    /// The trashed block's UUID.
    pub block_uuid: [u8; 16],
    /// The signed death-clock the age was computed from.
    pub tombstoned_at_ms: u64,
    /// `now_ms.saturating_sub(tombstoned_at_ms)` — how far past trashing
    /// this entry is (always `> window_ms` for an eligible entry).
    pub age_ms: u64,
}

impl From<secretary_core::vault::ExpiredEntry> for ExpiredEntry {
    fn from(e: secretary_core::vault::ExpiredEntry) -> Self {
        ExpiredEntry {
            block_uuid: e.block_uuid,
            tombstoned_at_ms: e.tombstoned_at_ms,
            age_ms: e.age_ms,
        }
    }
}

/// Aggregate outcome of an [`auto_purge_expired`] call. Bridge projection
/// of [`secretary_core::vault::RetentionPurgeReport`]: every count narrowed
/// `usize`→`u32` for uniffi/pyo3 portability (a vault with more than 2^32
/// trashed blocks is not a realistic state); `window_ms` passes through.
///
/// Not `Default`: the empty-target return still carries the caller's real
/// `window_ms`, so a zero-count report is self-describing.
#[derive(Debug, Clone)]
pub struct RetentionPurgeReport {
    /// Entries newly marked purged by this call.
    pub purged_count: u32,
    /// Of `purged_count`, classified shared (≥1 non-owner recipient).
    pub shared_count: u32,
    /// Of `purged_count`, classified owner-only.
    pub owner_only_count: u32,
    /// Of `purged_count`, unclassifiable (trash file unreadable — honest
    /// "unknown", never fabricated).
    pub unknown_count: u32,
    /// On-disk `trash/` files removed across every purged entry.
    pub files_removed: u32,
    /// `trash/` removals that errored (benign orphans; never fatal).
    pub files_failed: u32,
    /// The retention window this call applied (echoes the caller).
    pub window_ms: u64,
}

impl From<secretary_core::vault::RetentionPurgeReport> for RetentionPurgeReport {
    fn from(r: secretary_core::vault::RetentionPurgeReport) -> Self {
        RetentionPurgeReport {
            purged_count: r.purged_count as u32,
            shared_count: r.shared_count as u32,
            owner_only_count: r.owner_only_count as u32,
            unknown_count: r.unknown_count as u32,
            files_removed: r.files_removed as u32,
            files_failed: r.files_failed as u32,
            window_ms: r.window_ms,
        }
    }
}
```

Create `ffi/secretary-ffi-bridge/src/retention/mod.rs`:

```rust
//! `expired_trash_entries` / `auto_purge_expired` orchestrators — the #402
//! retention-window counterpart to [`crate::purge`]. Minimal
//! `orchestration.rs` carrying the free-function entry points, the
//! bridge-side [`ExpiredEntry`] / [`RetentionPurgeReport`] projections, and
//! the core-error mapper.

pub mod orchestration;

pub use orchestration::{
    auto_purge_expired, expired_trash_entries, ExpiredEntry, RetentionPurgeReport,
};
```

In `ffi/secretary-ffi-bridge/src/lib.rs`, add the module declaration (keep alphabetical order — after `record`, before `repair`... actually after `purge`):

```rust
pub mod retention;
```

and the re-exports (after the `pub use purge::{...}` line):

```rust
pub use retention::{
    auto_purge_expired, expired_trash_entries, ExpiredEntry, RetentionPurgeReport,
};
/// The v1 default retention window (90 days, ms). Re-exported unchanged
/// from `secretary-core` — the single source of the value for both
/// binding crates. `docs/vault-format.md` §7 step 5.
pub use secretary_core::vault::DEFAULT_RETENTION_WINDOW_MS;
```

> NOTE: `auto_purge_expired` / `expired_trash_entries` re-exports will not compile until Task 2 defines them. To keep Task 1 independently green, in THIS task re-export only the two DTOs + the const; add the two fn names to both re-export sites in Task 2. Adjust `mod.rs` likewise (DTOs only in Task 1).

Task-1 `mod.rs` re-export line:

```rust
pub use orchestration::{ExpiredEntry, RetentionPurgeReport};
```

Task-1 `lib.rs` re-export:

```rust
pub use retention::{ExpiredEntry, RetentionPurgeReport};
pub use secretary_core::vault::DEFAULT_RETENTION_WINDOW_MS;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --release -p secretary-ffi-bridge retention 2>&1 | tail -20`
Expected: PASS (3 tests). Then `cargo clippy --release -p secretary-ffi-bridge --tests -- -D warnings` clean.

- [ ] **Step 5: Commit**

```bash
git add ffi/secretary-ffi-bridge/src/retention/ ffi/secretary-ffi-bridge/src/lib.rs
git commit -m "feat(ffi-bridge): retention DTOs + 90d const re-export (#402)"
```

---

## Task 2: Bridge `expired_trash_entries` preview + `auto_purge_expired` commit + error mapper

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/retention/orchestration.rs` (add two fns + mapper + mapper tests)
- Modify: `ffi/secretary-ffi-bridge/src/retention/mod.rs` (add fn re-exports)
- Modify: `ffi/secretary-ffi-bridge/src/lib.rs` (add fn re-exports)

**Interfaces:**
- Consumes: `OpenVaultManifest::{manifest_body, snapshot_for_save_block, replace_manifest_and_file}`, `UnlockedIdentity::clone_inner_bundle`, `secretary_core::vault::{expired_trash_entries, auto_purge_expired}`.
- Produces: `pub fn expired_trash_entries(manifest: &OpenVaultManifest, window_ms: u64, now_ms: u64) -> Vec<ExpiredEntry>`; `pub fn auto_purge_expired(identity: &UnlockedIdentity, manifest: &OpenVaultManifest, window_ms: u64, now_ms: u64, device_uuid: [u8;16]) -> Result<RetentionPurgeReport, FfiVaultError>`.

- [ ] **Step 1: Write the failing mapper tests**

Add to the `tests` module in `orchestration.rs`:

```rust
    #[test]
    fn map_core_io_routes_to_folder_invalid() {
        let core_err = VaultError::Io {
            context: "test",
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "missing"),
        };
        assert!(matches!(
            map_core_vault_error_retention(core_err),
            FfiVaultError::FolderInvalid { .. }
        ));
    }

    #[test]
    fn map_core_clock_overflow_folds_to_save_crypto_failure() {
        let core_err = VaultError::ClockOverflow {
            device_uuid: [0xff; 16],
        };
        assert!(matches!(
            map_core_vault_error_retention(core_err),
            FfiVaultError::SaveCryptoFailure { .. }
        ));
    }

    #[test]
    fn map_core_block_not_in_trash_folds_to_save_crypto_failure() {
        // retention takes no block_uuid, so BlockNotInTrash cannot fire;
        // folds to the umbrella (mirrors empty_trash's mapper).
        let core_err = VaultError::BlockNotInTrash {
            block_uuid: [0xbb; 16],
        };
        assert!(matches!(
            map_core_vault_error_retention(core_err),
            FfiVaultError::SaveCryptoFailure { .. }
        ));
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --release -p secretary-ffi-bridge retention 2>&1 | tail -20`
Expected: FAIL — `map_core_vault_error_retention` not found.

- [ ] **Step 3: Write the two fns + mapper**

Insert into `orchestration.rs` (above the `#[cfg(test)] mod tests`):

```rust
/// Pure, side-effect-free preview of the entries retention auto-purge would
/// permanently remove for `(window_ms, now_ms)`. Reads only the manifest; no
/// identity, no I/O. Returns an empty vec on a wiped handle (safe-default
/// convention, matching `block_summaries`). `docs/vault-format.md` §7 step 5.
pub fn expired_trash_entries(
    manifest: &OpenVaultManifest,
    window_ms: u64,
    now_ms: u64,
) -> Vec<ExpiredEntry> {
    match manifest.manifest_body() {
        Some(body) => secretary_core::vault::expired_trash_entries(&body, window_ms, now_ms)
            .into_iter()
            .map(ExpiredEntry::from)
            .collect(),
        None => Vec::new(),
    }
}

/// Permanently purge every trashed block older than `window_ms` — the
/// retention auto-purge commit. See
/// [`secretary_core::vault::auto_purge_expired`] for the normative sequence
/// (single manifest commit; empty target set → zero-count report carrying
/// the real `window_ms`, no manifest write). Same handle-snapshot shape as
/// [`crate::empty_trash`], with `window_ms` threaded to the core call.
///
/// # Errors
///
/// - [`FfiVaultError::CorruptVault`] — either handle has been wiped, or
///   `replace_manifest_and_file` failed.
/// - [`FfiVaultError::FolderInvalid`] — I/O failure (atomic-write, cross-fs
///   rename).
/// - [`FfiVaultError::SaveCryptoFailure`] — crypto / encoding failure on
///   already-validated inputs.
pub fn auto_purge_expired(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    window_ms: u64,
    now_ms: u64,
    device_uuid: [u8; 16],
) -> Result<RetentionPurgeReport, FfiVaultError> {
    // Step 1: snapshot manifest (5-tuple) under one lock acquisition.
    let (manifest_body, manifest_file, owner_card, ibk, vault_folder) = manifest
        .snapshot_for_save_block()
        .ok_or_else(|| FfiVaultError::CorruptVault {
            detail: "vault manifest handle has been closed".into(),
        })?;

    // Step 2: snapshot identity (re-sign needs the secret keys).
    let identity_clone =
        identity
            .clone_inner_bundle()
            .ok_or_else(|| FfiVaultError::CorruptVault {
                detail: "identity handle has been closed".into(),
            })?;

    // Step 3: build a temporary OpenVault from the snapshots.
    let mut open_vault = OpenVault {
        identity_block_key: ibk,
        identity: identity_clone,
        owner_card,
        manifest: manifest_body,
        manifest_file,
    };

    // Step 4: call core.
    let result = secretary_core::vault::auto_purge_expired(
        &vault_folder,
        &mut open_vault,
        window_ms,
        now_ms,
        device_uuid,
        &mut OsRng,
    );

    // Step 5: on Ok, write back; on Err, the bridge handle is untouched
    // (the OpenVault clone owned the only mutated state and drops).
    match result {
        Ok(report) => manifest
            .replace_manifest_and_file(open_vault.manifest, open_vault.manifest_file)
            .map(|()| RetentionPurgeReport::from(report))
            .map_err(|e| FfiVaultError::CorruptVault {
                detail: e.to_string(),
            }),
        Err(e) => Err(map_core_vault_error_retention(e)),
    }
}

/// Map `core::VaultError` → `FfiVaultError` for the retention path.
///
/// Exhaustive (no `_ =>` catchall) per issue #40. Identical arm set to
/// `map_core_vault_error_empty_trash`: retention takes no `block_uuid`, so
/// `BlockNotInTrash` cannot fire and folds to the crypto/encoding umbrella.
/// Adding a new `core::VaultError` variant becomes a compile error here.
fn map_core_vault_error_retention(e: VaultError) -> FfiVaultError {
    match &e {
        VaultError::Io { context, source } => FfiVaultError::FolderInvalid {
            detail: format!("{context}: {source}"),
        },
        VaultError::BlockNotInTrash { .. }
        | VaultError::Record(_)
        | VaultError::Block(_)
        | VaultError::Manifest(_)
        | VaultError::Conflict(_)
        | VaultError::Rollback { .. }
        | VaultError::Unlock(_)
        | VaultError::Card(_)
        | VaultError::Sig(_)
        | VaultError::OwnerUuidMismatch { .. }
        | VaultError::ManifestAuthorMismatch
        | VaultError::ManifestVaultUuidMismatch { .. }
        | VaultError::KdfParamsMismatch
        | VaultError::ClockOverflow { .. }
        | VaultError::ContactCardUuidMismatch { .. }
        | VaultError::NotAuthor { .. }
        | VaultError::BlockNotFound { .. }
        | VaultError::RecipientAlreadyPresent
        | VaultError::RecipientNotPresent
        | VaultError::CannotRevokeOwner
        | VaultError::MissingRecipientCard { .. }
        | VaultError::BlockUuidAlreadyLive { .. }
        | VaultError::RestoreVerificationFailed { .. }
        | VaultError::RestoreTargetMissing { .. }
        | VaultError::BlockPurged { .. }
        | VaultError::BlockFingerprintMismatch { .. }
        | VaultError::BlockFileMissing { .. }
        | VaultError::RepairRejected { .. }
        | VaultError::DeviceSlotNotFound => FfiVaultError::SaveCryptoFailure {
            detail: format!("{e}"),
        },
    }
}
```

> IMPORTANT: the arm list above is copied from `map_core_vault_error_empty_trash` as it exists at plan time. If `cargo build` reports a non-exhaustive match (a `VaultError` variant was added since), add the missing arm to the umbrella group — do NOT add a `_` catchall.

Update `retention/mod.rs` re-export to include the fns:

```rust
pub use orchestration::{
    auto_purge_expired, expired_trash_entries, ExpiredEntry, RetentionPurgeReport,
};
```

Update `lib.rs` re-export to include the fns:

```rust
pub use retention::{
    auto_purge_expired, expired_trash_entries, ExpiredEntry, RetentionPurgeReport,
};
pub use secretary_core::vault::DEFAULT_RETENTION_WINDOW_MS;
```

- [ ] **Step 4: Run tests + clippy + doc**

Run: `cargo test --release -p secretary-ffi-bridge retention 2>&1 | tail -20`
Expected: PASS (6 tests). Then:
```bash
cargo clippy --release -p secretary-ffi-bridge --tests -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps -p secretary-ffi-bridge
```
Expected: both clean.

- [ ] **Step 5: Commit**

```bash
git add ffi/secretary-ffi-bridge/src/retention/ ffi/secretary-ffi-bridge/src/lib.rs
git commit -m "feat(ffi-bridge): auto_purge_expired + expired_trash_entries (#402)"
```

---

## Task 3: pyo3 projection — `retention.rs` + registration + module const

**Files:**
- Create: `ffi/secretary-ffi-py/src/retention.rs`
- Modify: `ffi/secretary-ffi-py/src/lib.rs` (add `mod retention;`, `use`, class/fn/const registration)

**Interfaces:**
- Consumes: `secretary_ffi_bridge::{expired_trash_entries, auto_purge_expired, ExpiredEntry, RetentionPurgeReport, DEFAULT_RETENTION_WINDOW_MS}`, `crate::errors::{ffi_vault_error_to_pyerr, uuid_array_or_value_error}`, `crate::identity::UnlockedIdentity`, `crate::vault::OpenVaultManifest`.
- Produces: Python `secretary_ffi_py.{ExpiredEntry, RetentionPurgeReport, expired_trash_entries, auto_purge_expired, DEFAULT_RETENTION_WINDOW_MS}`.

- [ ] **Step 1: Write `retention.rs`**

Create `ffi/secretary-ffi-py/src/retention.rs`:

```rust
//! Retention auto-purge entry points (#402). Preview (`expired_trash_entries`,
//! pure/infallible) + commit (`auto_purge_expired`). Output DTOs mirror
//! `purge.rs`'s `EmptyTrashReport` shape (top-level return types, raw-bytes
//! `block_uuid`, so no `Clone` / `skip_from_py_object` needed — see
//! [[project_secretary_pyo3_028_fromtopyobject_deprecation]]).

use pyo3::prelude::*;

use crate::errors::{ffi_vault_error_to_pyerr, uuid_array_or_value_error};
use crate::identity::UnlockedIdentity;
use crate::vault::OpenVaultManifest;

/// One trash entry eligible for retention auto-purge. Output-only; never
/// constructed from Python.
#[pyclass(frozen, get_all)]
pub struct ExpiredEntry {
    /// 16-byte UUID of the trashed block.
    pub block_uuid: Vec<u8>,
    /// Signed death-clock (unix-millis) the age was computed from.
    pub tombstoned_at_ms: u64,
    /// `now_ms - tombstoned_at_ms` — how far past trashing this entry is.
    pub age_ms: u64,
}

impl From<secretary_ffi_bridge::ExpiredEntry> for ExpiredEntry {
    fn from(e: secretary_ffi_bridge::ExpiredEntry) -> Self {
        Self {
            block_uuid: e.block_uuid.to_vec(),
            tombstoned_at_ms: e.tombstoned_at_ms,
            age_ms: e.age_ms,
        }
    }
}

/// Aggregate outcome of an `auto_purge_expired` call. Output-only; never
/// constructed from Python.
#[pyclass(frozen, get_all)]
pub struct RetentionPurgeReport {
    /// Entries newly marked purged by this call.
    pub purged_count: u32,
    /// Of `purged_count`, classified shared (>=1 non-owner recipient).
    pub shared_count: u32,
    /// Of `purged_count`, classified owner-only.
    pub owner_only_count: u32,
    /// Of `purged_count`, unclassifiable (trash file unreadable).
    pub unknown_count: u32,
    /// On-disk trash files removed across every purged entry.
    pub files_removed: u32,
    /// Trash-file removals that errored (benign orphans; never fatal).
    pub files_failed: u32,
    /// The retention window this call applied (echoes the caller).
    pub window_ms: u64,
}

impl From<secretary_ffi_bridge::RetentionPurgeReport> for RetentionPurgeReport {
    fn from(r: secretary_ffi_bridge::RetentionPurgeReport) -> Self {
        Self {
            purged_count: r.purged_count,
            shared_count: r.shared_count,
            owner_only_count: r.owner_only_count,
            unknown_count: r.unknown_count,
            files_removed: r.files_removed,
            files_failed: r.files_failed,
            window_ms: r.window_ms,
        }
    }
}

/// Pure preview of the entries retention auto-purge would remove for
/// `(window_ms, now_ms)`. No I/O; returns `[]` on a wiped handle. See
/// `docs/vault-format.md` §7 step 5.
#[pyfunction]
pub(crate) fn expired_trash_entries(
    manifest: &OpenVaultManifest,
    window_ms: u64,
    now_ms: u64,
) -> Vec<ExpiredEntry> {
    secretary_ffi_bridge::expired_trash_entries(&manifest.0, window_ms, now_ms)
        .into_iter()
        .map(ExpiredEntry::from)
        .collect()
}

/// Permanently purge every trashed block older than `window_ms`. See
/// `docs/vault-format.md` §7 step 5 (#402) for the normative sequence.
///
/// `device_uuid` must be exactly 16 bytes; otherwise raises `ValueError`.
/// On failure the bridge handle is byte-identical to its pre-call state.
///
/// # Raises
///
/// - `ValueError` — `device_uuid` length != 16.
/// - `VaultFolderInvalid` — I/O failure (atomic-write on the manifest).
/// - `VaultSaveCryptoFailure` — crypto / encoding failure on
///   already-validated inputs.
/// - `CorruptVault` — either handle has been wiped.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)] // owned Vec<u8> for bytes ∪ bytearray accept
pub(crate) fn auto_purge_expired(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    window_ms: u64,
    now_ms: u64,
    device_uuid: Vec<u8>,
) -> PyResult<RetentionPurgeReport> {
    let device_uuid = uuid_array_or_value_error(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::auto_purge_expired(
        &identity.0,
        &manifest.0,
        window_ms,
        now_ms,
        device_uuid,
    )
    .map(RetentionPurgeReport::from)
    .map_err(ffi_vault_error_to_pyerr)
}
```

- [ ] **Step 2: Register in `lib.rs`**

Add `mod retention;` near `mod purge;`; add the `use`:

```rust
use retention::{auto_purge_expired, expired_trash_entries, ExpiredEntry, RetentionPurgeReport};
```

In the module-init fn, after the `empty_trash` registration block, add:

```rust
    // #402: retention auto-purge — preview + commit + 90-day default window.
    // No new typed exception classes (reuses empty_trash's error surface).
    m.add_class::<ExpiredEntry>()?;
    m.add_class::<RetentionPurgeReport>()?;
    m.add_function(wrap_pyfunction!(expired_trash_entries, m)?)?;
    m.add_function(wrap_pyfunction!(auto_purge_expired, m)?)?;
    m.add("DEFAULT_RETENTION_WINDOW_MS", secretary_ffi_bridge::DEFAULT_RETENTION_WINDOW_MS)?;
```

- [ ] **Step 3: Build the extension**

Run: `cargo build --release -p secretary-ffi-py 2>&1 | tail -20`
Expected: compiles clean. Then `cargo clippy --release -p secretary-ffi-py -- -D warnings` clean.

- [ ] **Step 4: Commit**

```bash
git add ffi/secretary-ffi-py/src/retention.rs ffi/secretary-ffi-py/src/lib.rs
git commit -m "feat(ffi-py): pyo3 retention projection + module const (#402)"
```

---

## Task 4: pyo3 pytest — `test_retention.py` (preview + commit runtime proof)

**Files:**
- Create: `ffi/secretary-ffi-py/tests/test_retention.py`

**Interfaces:**
- Consumes: `secretary_ffi_py.{open_vault_with_password, expired_trash_entries, auto_purge_expired, DEFAULT_RETENTION_WINDOW_MS}`.

> The golden vault has no trash entries by default. Rather than stage trash on
> disk (fragile), this suite proves the projection end-to-end at the API
> boundary: a huge window yields an empty preview + zero-count commit that
> still echoes `window_ms`; `device_uuid` validation raises `ValueError`; the
> const equals 90 days. Selection-rule correctness is already proven in core
> (`core/tests/retention.rs` + `retention_kat.json`); this task proves the
> bridge/pyo3 wiring, not the rule.

- [ ] **Step 1: Write the test**

Create `ffi/secretary-ffi-py/tests/test_retention.py`:

```python
"""#402 pytest suite — retention preview + commit end-to-end via pyo3.

Each test opens its own writable copy of golden_vault_001 in pytest's
``tmp_path`` so the read-only fixture is never touched
(feedback_smoke_test_temp_copy_golden_vault).
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

import secretary_ffi_py
from secretary_ffi_py import (
    DEFAULT_RETENTION_WINDOW_MS,
    auto_purge_expired,
    expired_trash_entries,
)

VAULT_001_PASSWORD = b"correct horse battery staple"
DEVICE_UUID = bytes([0x07] * 16)
NOW_MS = 1_715_000_000_000
HUGE_WINDOW = 10 ** 15  # far larger than any age → nothing eligible


def _golden_vault_path(n: int) -> Path:
    return (
        Path(__file__).resolve().parents[3]
        / "core" / "tests" / "data" / f"golden_vault_{n:03d}"
    )


def _fresh_writable_vault(tmp_path: Path):
    dst = tmp_path / "vault001"
    shutil.copytree(_golden_vault_path(1), dst)
    return secretary_ffi_py.open_vault_with_password(str(dst), VAULT_001_PASSWORD)


def test_default_window_is_ninety_days():
    assert DEFAULT_RETENTION_WINDOW_MS == 90 * 24 * 60 * 60 * 1000


def test_preview_empty_when_no_eligible_entries(tmp_path):
    with _fresh_writable_vault(tmp_path) as vault:
        entries = expired_trash_entries(vault.manifest, DEFAULT_RETENTION_WINDOW_MS, NOW_MS)
        assert entries == []


def test_commit_zero_count_echoes_window_and_no_write(tmp_path):
    with _fresh_writable_vault(tmp_path) as vault:
        report = auto_purge_expired(
            vault.identity, vault.manifest, HUGE_WINDOW, NOW_MS, DEVICE_UUID
        )
        assert report.purged_count == 0
        assert report.shared_count == 0
        assert report.owner_only_count == 0
        assert report.unknown_count == 0
        assert report.files_removed == 0
        assert report.files_failed == 0
        assert report.window_ms == HUGE_WINDOW


def test_commit_rejects_wrong_length_device_uuid(tmp_path):
    with _fresh_writable_vault(tmp_path) as vault:
        with pytest.raises(ValueError):
            auto_purge_expired(
                vault.identity, vault.manifest, HUGE_WINDOW, NOW_MS, bytes([0x07] * 15)
            )
```

> VERIFY at execution: the `OpenVaultOutput` context-manager field names are
> `vault.identity` / `vault.manifest` — confirm against `test_purge.py`'s usage
> (it uses the same `with out as vault:` pattern) and adjust if the accessors
> differ.

- [ ] **Step 2: Build + install the extension, run the test (expect fail first if run before Task 3 install)**

Rebuild so pytest sees the new symbols (avoid the stale-`.so` trap —
[[project_secretary_maturin_uv_cache]]):

```bash
cd ffi/secretary-ffi-py
uv run --with maturin maturin develop --release
uv run --with pytest pytest tests/test_retention.py -v
```
Expected: 4 PASS. If `ImportError` on the new symbols despite a successful build, nuke the venv + uv cache and re-run (stale-`.so` trap).

- [ ] **Step 3: Commit**

```bash
cd ../..
git add ffi/secretary-ffi-py/tests/test_retention.py
git commit -m "test(ffi-py): retention preview + commit pytest (#402)"
```

---

## Task 5: uniffi projection — wrappers + namespace fns + UDL + Swift/Kotlin conformance

**Files:**
- Create: `ffi/secretary-ffi-uniffi/src/wrappers/retention.rs`
- Modify: `ffi/secretary-ffi-uniffi/src/wrappers/mod.rs` (module doc + re-export)
- Modify: `ffi/secretary-ffi-uniffi/src/namespace/mod.rs` (imports + 3 fns)
- Modify: `ffi/secretary-ffi-uniffi/src/lib.rs` (re-export value types + namespace fns)
- Modify: `ffi/secretary-ffi-uniffi/src/secretary.udl` (2 dictionaries + 3 namespace fn decls)

**Interfaces:**
- Consumes: `secretary_ffi_bridge::{expired_trash_entries, auto_purge_expired, DEFAULT_RETENTION_WINDOW_MS}`, `uuid_from_vec`, `VaultError`, `UnlockedIdentity`, `OpenVaultManifest`.
- Produces: uniffi `ExpiredEntry` / `RetentionPurgeReport` dictionaries; namespace fns `expired_trash_entries`, `auto_purge_expired`, `default_retention_window_ms`.

- [ ] **Step 1: Write the wrapper value types**

Create `ffi/secretary-ffi-uniffi/src/wrappers/retention.rs`:

```rust
//! uniffi-side value types mirroring the bridge `ExpiredEntry` /
//! `RetentionPurgeReport` DTOs (`secretary_ffi_bridge::retention`). Pure data;
//! the namespace fns convert to/from the bridge types. Field names/shapes
//! match `secretary.udl`'s `ExpiredEntry` / `RetentionPurgeReport`
//! dictionaries exactly.

/// One trash entry eligible for retention auto-purge (#402).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiredEntry {
    pub block_uuid: Vec<u8>,
    pub tombstoned_at_ms: u64,
    pub age_ms: u64,
}

/// Aggregate outcome of an `auto_purge_expired` call (#402).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionPurgeReport {
    pub purged_count: u32,
    pub shared_count: u32,
    pub owner_only_count: u32,
    pub unknown_count: u32,
    pub files_removed: u32,
    pub files_failed: u32,
    pub window_ms: u64,
}
```

- [ ] **Step 2: Wire the module + re-exports**

In `wrappers/mod.rs`, add a module doc bullet (near the `purge` one) and:

```rust
pub mod retention;
```

In `namespace/mod.rs` imports (near `use crate::wrappers::purge::{...}`):

```rust
use crate::wrappers::retention::{ExpiredEntry, RetentionPurgeReport};
```

Append the three namespace fns to `namespace/mod.rs`:

```rust
/// Pure preview of the entries retention auto-purge would remove — uniffi
/// projection of [`secretary_ffi_bridge::expired_trash_entries`]. No I/O;
/// returns an empty sequence on a wiped handle. `docs/vault-format.md`
/// §7 step 5 (#402).
pub fn expired_trash_entries(
    manifest: std::sync::Arc<OpenVaultManifest>,
    window_ms: u64,
    now_ms: u64,
) -> Vec<ExpiredEntry> {
    secretary_ffi_bridge::expired_trash_entries(&manifest.0, window_ms, now_ms)
        .into_iter()
        .map(|e| ExpiredEntry {
            block_uuid: e.block_uuid.to_vec(),
            tombstoned_at_ms: e.tombstoned_at_ms,
            age_ms: e.age_ms,
        })
        .collect()
}

/// Permanently purge every trashed block older than `window_ms` — uniffi
/// projection of [`secretary_ffi_bridge::auto_purge_expired`].
/// `docs/vault-format.md` §7 step 5 (#402).
///
/// # Errors
///
/// - [`VaultError::InvalidArgument`] — wrong-length `device_uuid`.
/// - [`VaultError::CorruptVault`] — either handle has been wiped.
/// - [`VaultError::FolderInvalid`] — IO failure during the manifest write.
/// - [`VaultError::SaveCryptoFailure`] — crypto / encoding failure on
///   already-validated inputs.
pub fn auto_purge_expired(
    identity: std::sync::Arc<UnlockedIdentity>,
    manifest: std::sync::Arc<OpenVaultManifest>,
    window_ms: u64,
    now_ms: u64,
    device_uuid: Vec<u8>,
) -> Result<RetentionPurgeReport, VaultError> {
    let device_uuid = uuid_from_vec(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::auto_purge_expired(
        &identity.0,
        &manifest.0,
        window_ms,
        now_ms,
        device_uuid,
    )
    .map(|r| RetentionPurgeReport {
        purged_count: r.purged_count,
        shared_count: r.shared_count,
        owner_only_count: r.owner_only_count,
        unknown_count: r.unknown_count,
        files_removed: r.files_removed,
        files_failed: r.files_failed,
        window_ms: r.window_ms,
    })
    .map_err(VaultError::from)
}

/// The v1 default retention window (90 days, in ms). uniffi has no UDL
/// `const`, so the value is exposed as a namespace fn reading the single
/// bridge-re-exported core const. `docs/vault-format.md` §7 step 5 (#402).
pub fn default_retention_window_ms() -> u64 {
    secretary_ffi_bridge::DEFAULT_RETENTION_WINDOW_MS
}
```

In `lib.rs`: add the namespace fns to the `pub use namespace::{...}` list (`auto_purge_expired`, `default_retention_window_ms`, `expired_trash_entries`) and add:

```rust
pub use wrappers::retention::{ExpiredEntry, RetentionPurgeReport};
```

- [ ] **Step 3: Add the UDL declarations**

In `secretary.udl`, inside `namespace secretary { ... }` (after the `empty_trash` declaration):

```
    /// Pure preview of the trash entries retention auto-purge would
    /// permanently remove for (window_ms, now_ms) (#402). No I/O; returns
    /// an empty sequence on a wiped handle. See `docs/vault-format.md`
    /// §7 step 5.
    sequence<ExpiredEntry> expired_trash_entries(
        OpenVaultManifest manifest,
        u64 window_ms,
        u64 now_ms
    );

    /// Permanently purge every trashed block strictly older than
    /// `window_ms` (#402). Single manifest commit; an empty target set
    /// returns an all-zero RetentionPurgeReport (still carrying
    /// `window_ms`) without touching the manifest. See
    /// `docs/vault-format.md` §7 step 5.
    [Throws=VaultError]
    RetentionPurgeReport auto_purge_expired(
        UnlockedIdentity identity,
        OpenVaultManifest manifest,
        u64 window_ms,
        u64 now_ms,
        bytes device_uuid
    );

    /// The v1 default retention window (90 days, in milliseconds) (#402).
    u64 default_retention_window_ms();
```

And the two dictionaries (near `EmptyTrashReport`):

```
/// One trash entry eligible for retention auto-purge (#402).
dictionary ExpiredEntry {
    /// 16-byte UUID of the trashed block.
    bytes block_uuid;
    /// Signed death-clock (unix-millis) the age was computed from.
    u64 tombstoned_at_ms;
    /// `now_ms - tombstoned_at_ms` — how far past trashing this entry is.
    u64 age_ms;
};

/// Aggregate outcome of an `auto_purge_expired` call (#402).
dictionary RetentionPurgeReport {
    /// Entries newly marked purged by this call.
    u32 purged_count;
    /// Of `purged_count`, classified shared (>=1 non-owner recipient).
    u32 shared_count;
    /// Of `purged_count`, classified owner-only.
    u32 owner_only_count;
    /// Of `purged_count`, unclassifiable (trash file unreadable).
    u32 unknown_count;
    /// On-disk trash files removed across every purged entry.
    u32 files_removed;
    /// Trash-file removals that errored (benign orphans; never fatal).
    u32 files_failed;
    /// The retention window this call applied (echoes the caller).
    u64 window_ms;
};
```

- [ ] **Step 4: Build + clippy + doc**

```bash
cargo build --release -p secretary-ffi-uniffi 2>&1 | tail -20
cargo clippy --release -p secretary-ffi-uniffi --tests -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps -p secretary-ffi-uniffi
```
Expected: all clean. A UDL/Rust signature mismatch surfaces here as a uniffi scaffolding error — reconcile the UDL decl with the Rust fn signature (arg order, types, `[Throws]`).

- [ ] **Step 5: Run Swift + Kotlin conformance (proves the generated bindings compile)**

```bash
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
```
Expected: both exit 0. These compile the full generated binding (including the new fns/dictionaries), catching UDL-vs-Rust drift that cargo cannot see ([[project_secretary_ffivaulterror_workspace_match]]). No `ConformanceErrors.{swift,kt}` edit is needed — no new `FfiVaultError` variant.

- [ ] **Step 6: Commit**

```bash
git add ffi/secretary-ffi-uniffi/src/
git commit -m "feat(ffi-uniffi): uniffi retention projection + UDL (#402)"
```

---

## Task 6: Android `:kit` + `:app` Gradle build (return-shape drift gate)

**Files:** none (verification; any fix lands as a follow-up commit here).

> A uniffi return-shape change can pass Swift/Kotlin conformance yet break the
> `:kit` Gradle module ([[project_secretary_conformance_scripts_dont_compile_kit]]).
> `:kit` is host-testable kotlin-jvm (no emulator). Build `:kit` + `:app` in
> THIS task, not later. Use absolute paths for any Android SDK tools
> ([[project_secretary_android_toolchain]]).

- [ ] **Step 1: Build `:kit` and `:app`**

```bash
cd android
./gradlew :kit:build :app:assembleDebug 2>&1 | tail -30
```
Expected: BUILD SUCCESSFUL. The generated Kotlin bindings now include the retention fns/dictionaries; `:kit` compiles against them. If `:kit` references a changed shape and fails to compile, fix the `:kit` usage (or the projection) and re-run.

- [ ] **Step 2: Commit (only if a fix was needed)**

```bash
cd ..
# git add android/... && git commit -m "fix(android): reconcile :kit with retention bindings (#402)"
```
If BUILD SUCCESSFUL with no changes, skip the commit and note it in the task report.

---

## Task 7: README / ROADMAP + full acceptance sweep

**Files:**
- Modify: `README.md` (if the project-status section tracks the retention FFI surface)
- Modify: `ROADMAP.md` (mark the #402 FFI projection shipped; platform UX still deferred)

**Interfaces:** none.

- [ ] **Step 1: Update ROADMAP + README**

Read `ROADMAP.md` and `README.md`; locate the retention / #402 entry (the #402 core slice noted "FFI + platform UX deferred"). Update to reflect the FFI projection now shipped (bridge + uniffi + pyo3), with platform retention/purge **UX** still the remaining follow-up. Keep the README status section brief (dot points) per [[feedback_readme_style]]. If neither doc references the retention FFI surface at the granularity that would change, note that and make no edit.

- [ ] **Step 2: Full acceptance gate sweep**

```bash
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all --check
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh
uv run core/tests/python/conformance.py
```
Expected: all green; `conformance.py` exit 0. (Swift/Kotlin conformance + pyo3 pytest + `:kit`/`:app` already run in Tasks 4–6.)

- [ ] **Step 3: Commit**

```bash
git add README.md ROADMAP.md
git commit -m "docs: retention FFI projection shipped; platform UX deferred (#402)"
```

---

## Self-Review

**Spec coverage:**
- §3.1 bridge module (DTOs, preview, commit, mapper, const) → Tasks 1–2. ✓
- §3.2 constant (bridge re-export + uniffi fn + pyo3 const) → Tasks 1 (const), 3 (pyo3), 5 (uniffi fn). ✓
- §3.3 uniffi binding → Task 5. ✓
- §3.4 pyo3 binding → Tasks 3–4. ✓
- §4 error handling (no new variant, binding-layer validation) → Tasks 2/3/5. ✓
- §5 testing (bridge unit, pyo3 pytest, Swift/Kotlin conformance) → Tasks 1–2 (unit), 4 (pytest), 5 (conformance). ✓
- §6 acceptance gates → Tasks 5 (conformance), 6 (:kit/:app), 7 (full sweep). ✓
- §7 risks (:kit drift, maturin stale, lean-binding) → Tasks 6, 4, 7. ✓

**Placeholder scan:** No "TBD"/"add error handling"/"similar to Task N" — every code step has complete code. Two flagged VERIFY notes (mapper arm exhaustiveness in Task 2; `OpenVaultOutput` field names in Task 4) are deliberate execution-time checks against the live tree, each with an explicit resolution instruction, not placeholders.

**Type consistency:** `ExpiredEntry`/`RetentionPurgeReport` field names identical across core, bridge, pyo3, uniffi, and UDL (`purged_count`, `shared_count`, `owner_only_count`, `unknown_count`, `files_removed`, `files_failed`, `window_ms`; `block_uuid`, `tombstoned_at_ms`, `age_ms`). `auto_purge_expired` arg order `(identity, manifest, window_ms, now_ms, device_uuid)` identical in bridge/pyo3/uniffi and matches the UDL decl. `expired_trash_entries` arg order `(manifest, window_ms, now_ms)` identical everywhere.
