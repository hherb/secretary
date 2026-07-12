//! Python bindings for secretary-core via PyO3.
//!
//! The crate-level `#![allow(unsafe_code)]` is the minimal escape hatch
//! for PyO3's #[pymodule] / #[pyfunction] macros, which expand to unsafe
//! blocks (the CPython C-API bridge is inherently unsafe). The crate-local
//! lint relaxation (workspace `forbid` → crate-local `deny`) is required
//! because `forbid` is non-overridable by inner `#[allow]`; see Cargo.toml.
//!
//! The `#[allow]` is **crate-level** rather than item-level because the
//! function-style `#[pymodule]` macro generates code at crate scope (an
//! `extern "C"` PyInit symbol alongside the entry-point function); a
//! narrower item-level `#[allow]` doesn't cover that expansion. The
//! tradeoff: a future contributor who adds a hand-rolled `unsafe` block
//! anywhere in this crate gets silence rather than a `deny` error. The
//! crate is intentionally tiny and reviewed; new `unsafe` blocks should
//! be challenged in code review.
//!
//! # Module layout
//!
//! - `errors` — `create_exception!` macros + `FfiUnlockError` /
//!   `FfiVaultError` → `PyErr` translators + the `uuid_array_or_value_error`
//!   length-validation helper.
//! - `identity` — `UnlockedIdentity` pyclass (shared by every entry
//!   point that produces or consumes a live identity).
//! - `unlock` — bytes-in unlock + create entry points (B.2 / B.3a /
//!   B.3b): `open_with_password`, `open_with_recovery`, `create_vault`,
//!   `MnemonicOutput`, `CreateVaultOutput`.
//! - `vault` — folder-in vault open entry points (B.4a):
//!   `open_vault_with_password`, `open_vault_with_recovery`, plus the
//!   `OpenVaultManifest` / `OpenVaultOutput` / `BlockSummary` pyclasses.
//! - `record` — block-read entry point (B.4b): `read_block`, plus the
//!   `FieldHandle` / `Record` / `BlockReadOutput` pyclasses.
//! - `save` — block-save entry point (B.4c): `save_block`, plus the
//!   `BlockInput` / `RecordInput` / `FieldInput` / `FieldInputValue`
//!   input pyclasses.
//! - `share` — block-share entry point (B.4d): `share_block`.
//!
//! # Rationale documents
//!
//! - B.1 (boilerplate): docs/superpowers/specs/2026-05-03-ffi-b1-py-bindings-boilerplate-design.md
//! - B.2 (open_with_password): docs/superpowers/specs/2026-05-04-ffi-b2-vault-unlock-design.md
//! - B.3a (open_with_recovery): docs/superpowers/specs/2026-05-04-ffi-b3a-recovery-unlock-design.md
//! - B.3b (create_vault): docs/superpowers/specs/2026-05-05-ffi-b3b-create-vault-design.md
//! - B.4a (open_vault_with_*): docs/superpowers/specs/2026-05-06-ffi-b4a-open-vault-design.md

#![allow(unsafe_code)]

use pyo3::prelude::*;

mod block_crud;
mod contacts;
mod device;
mod errors;
mod identity;
mod purge;
mod record;
mod record_edit;
mod repair;
mod repair_preview;
mod restore;
mod retention;
mod save;
mod settings;
mod share;
mod sync;
mod trash;
mod unlock;
mod vault;

use block_crud::{create_block, move_record, rename_block};
use contacts::{import_contact_card, share_block_to, ContactSummary};
use device::{
    add_device_slot, open_with_device_secret, remove_device_slot, DeviceEnrollOutput,
    DeviceSecretOutput,
};
use errors::{
    CorruptVault, InvalidMnemonic, VaultBlockNotFound, VaultBlockNotInTrash, VaultBlockPurged,
    VaultBlockUuidAlreadyLive, VaultCannotDeleteOwnerContact, VaultCannotRevokeOwner,
    VaultCardDecodeFailure, VaultContactAlreadyExists, VaultContactNotFound, VaultCorruptVault,
    VaultDeviceSlotNotFound, VaultDeviceUuidMismatch, VaultFolderInvalid, VaultFolderNotEmpty,
    VaultInvalidMnemonic, VaultMismatch, VaultMismatchFolder, VaultMissingRecipientCard,
    VaultNeedsRepair, VaultNotAuthor, VaultRecipientAlreadyPresent, VaultRecipientNotPresent,
    VaultRecordNotFound, VaultRepairRejected, VaultSaveCryptoFailure, VaultSyncDecisionsIncomplete,
    VaultSyncEvidenceStale, VaultSyncFailed, VaultSyncInProgress, VaultSyncStateCorrupt,
    VaultSyncStateVaultMismatch, VaultWrongDeviceSecretOrCorrupt, VaultWrongMnemonicOrCorrupt,
    VaultWrongPasswordOrCorrupt, WrongMnemonicOrCorrupt, WrongPasswordOrCorrupt,
};
use identity::UnlockedIdentity;
use purge::{empty_trash, purge_block, EmptyTrashReport, PurgeReport};
use record::{read_block, BlockReadOutput, FieldHandle, Record};
use record_edit::{append_record, edit_record, resurrect_record, tombstone_record, RecordContent};
use repair::{
    repair_with_device_secret, repair_with_password, repair_with_recovery, ApprovedWidening,
};
use repair_preview::{
    preview_repair_with_device_secret, preview_repair_with_password, preview_repair_with_recovery,
    AddedRecipient, RepairPreview, WideningReport,
};
use restore::restore_block;
use retention::{auto_purge_expired, expired_trash_entries, ExpiredEntry, RetentionPurgeReport};
use save::{save_block, BlockInput, FieldInput, FieldInputValue, RecordInput};
use settings::{read_settings, write_settings, Settings};
use share::share_block;
use sync::{
    sync_commit_decisions, sync_status, sync_vault, CollisionDto, DeviceClockDto, SyncOutcomeDto,
    SyncStatusDto, VetoDecisionDto, VetoDto,
};
use trash::{list_trashed_blocks, trash_block, TrashedBlock};
use unlock::{
    create_vault, create_vault_in_folder, open_with_password, open_with_recovery,
    CreateVaultOutput, MnemonicOutput,
};
use vault::{
    open_vault_with_password, open_vault_with_recovery, BlockSummary, OpenVaultManifest,
    OpenVaultOutput,
};

/// Returns the vault format version exposed by the core crate.
///
/// Kept as a free function so Rust callers (and the Rust unit tests below)
/// can use it without going through PyO3 / a Python interpreter.
pub fn version() -> u16 {
    secretary_core::version::FORMAT_VERSION
}

/// Python-exposed addition. B.1 round-trip target. Uses `wrapping_add`
/// to make the overflow contract explicit (matches default Rust `+`
/// semantics in release builds, which silently wrap); B.2 will reconsider
/// when fallible crypto operations make `PyResult` first-class.
#[pyfunction]
fn add(a: u32, b: u32) -> u32 {
    a.wrapping_add(b)
}

/// Python-exposed wrapper around `version()`. Renamed at the PyO3 layer
/// from the Rust ident `version_py` to the Python name `version` so the
/// Python-side surface stays clean.
#[pyfunction]
#[pyo3(name = "version")]
fn version_py() -> u32 {
    u32::from(version())
}

/// `#[pymodule]` entrypoint. The function name (`secretary_ffi_py`) is the
/// Python module name that `import` looks up; it must match the wheel name
/// declared in `pyproject.toml` (`[tool.maturin] module-name`).
#[pymodule]
fn secretary_ffi_py(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Existing B.1 surface:
    m.add_function(wrap_pyfunction!(add, m)?)?;
    m.add_function(wrap_pyfunction!(version_py, m)?)?;

    // B.2 surface:
    m.add_class::<UnlockedIdentity>()?;
    m.add_function(wrap_pyfunction!(open_with_password, m)?)?;
    m.add(
        "WrongPasswordOrCorrupt",
        py.get_type::<WrongPasswordOrCorrupt>(),
    )?;
    m.add("VaultMismatch", py.get_type::<VaultMismatch>())?;
    m.add("CorruptVault", py.get_type::<CorruptVault>())?;

    // B.3a surface:
    m.add_function(wrap_pyfunction!(open_with_recovery, m)?)?;
    m.add(
        "WrongMnemonicOrCorrupt",
        py.get_type::<WrongMnemonicOrCorrupt>(),
    )?;
    m.add("InvalidMnemonic", py.get_type::<InvalidMnemonic>())?;

    // B.3b surface:
    m.add_class::<CreateVaultOutput>()?;
    m.add_class::<MnemonicOutput>()?;
    m.add_function(wrap_pyfunction!(create_vault, m)?)?;
    m.add_function(wrap_pyfunction!(create_vault_in_folder, m)?)?;

    // B.4a surface:
    m.add_class::<BlockSummary>()?;
    m.add_class::<OpenVaultManifest>()?;
    m.add_class::<OpenVaultOutput>()?;
    m.add_function(wrap_pyfunction!(open_vault_with_password, m)?)?;
    m.add_function(wrap_pyfunction!(open_vault_with_recovery, m)?)?;
    m.add(
        "VaultWrongPasswordOrCorrupt",
        py.get_type::<VaultWrongPasswordOrCorrupt>(),
    )?;
    m.add(
        "VaultWrongMnemonicOrCorrupt",
        py.get_type::<VaultWrongMnemonicOrCorrupt>(),
    )?;
    m.add(
        "VaultInvalidMnemonic",
        py.get_type::<VaultInvalidMnemonic>(),
    )?;
    m.add("VaultMismatchFolder", py.get_type::<VaultMismatchFolder>())?;
    m.add("VaultCorruptVault", py.get_type::<VaultCorruptVault>())?;
    m.add("VaultFolderInvalid", py.get_type::<VaultFolderInvalid>())?;
    m.add("VaultFolderNotEmpty", py.get_type::<VaultFolderNotEmpty>())?;

    // B.4b surface:
    m.add_class::<FieldHandle>()?;
    m.add_class::<Record>()?;
    m.add_class::<BlockReadOutput>()?;
    m.add_function(wrap_pyfunction!(read_block, m)?)?;
    m.add("VaultBlockNotFound", py.get_type::<VaultBlockNotFound>())?;
    m.add("VaultRecordNotFound", py.get_type::<VaultRecordNotFound>())?;

    // B.4c surface:
    m.add(
        "VaultSaveCryptoFailure",
        py.get_type::<VaultSaveCryptoFailure>(),
    )?;
    m.add_class::<FieldInputValue>()?;
    m.add_class::<FieldInput>()?;
    m.add_class::<RecordInput>()?;
    m.add_class::<BlockInput>()?;
    m.add_function(wrap_pyfunction!(save_block, m)?)?;

    // Record-edit surface — 4 primitives (append / edit / tombstone / resurrect)
    // + RecordContent input pyclass. Error surface reuses VaultBlockNotFound /
    // VaultRecordNotFound / VaultCorruptVault already registered above.
    m.add_class::<RecordContent>()?;
    m.add_function(wrap_pyfunction!(append_record, m)?)?;
    m.add_function(wrap_pyfunction!(edit_record, m)?)?;
    m.add_function(wrap_pyfunction!(tombstone_record, m)?)?;
    m.add_function(wrap_pyfunction!(resurrect_record, m)?)?;

    // Block-CRUD surface — 3 primitives (create_block / rename_block /
    // move_record). Error surface reuses VaultBlockNotFound /
    // VaultRecordNotFound / VaultCorruptVault / the save-tail classes already
    // registered above; the same-block + uuid-length guards raise ValueError.
    m.add_function(wrap_pyfunction!(create_block, m)?)?;
    m.add_function(wrap_pyfunction!(rename_block, m)?)?;
    m.add_function(wrap_pyfunction!(move_record, m)?)?;

    // B.4d surface — share_block pyfunction + 4 typed exception classes.
    // raw `share_block` is discouraged for FFI consumers; prefer
    // `share_block_to` + `import_contact_card` (#206).
    m.add_function(wrap_pyfunction!(share_block, m)?)?;

    // B.5 surface — trash_block + restore_block pyfunctions + 2 typed
    // exception classes (registered below in the existing block).
    m.add_function(wrap_pyfunction!(trash_block, m)?)?;
    m.add_function(wrap_pyfunction!(restore_block, m)?)?;
    m.add_class::<TrashedBlock>()?;
    m.add_function(wrap_pyfunction!(list_trashed_blocks, m)?)?;
    m.add("VaultNotAuthor", py.get_type::<VaultNotAuthor>())?;
    m.add(
        "VaultRecipientAlreadyPresent",
        py.get_type::<VaultRecipientAlreadyPresent>(),
    )?;
    m.add(
        "VaultRecipientNotPresent",
        py.get_type::<VaultRecipientNotPresent>(),
    )?;
    m.add(
        "VaultCannotRevokeOwner",
        py.get_type::<VaultCannotRevokeOwner>(),
    )?;
    m.add(
        "VaultMissingRecipientCard",
        py.get_type::<VaultMissingRecipientCard>(),
    )?;
    m.add(
        "VaultCardDecodeFailure",
        py.get_type::<VaultCardDecodeFailure>(),
    )?;

    // B.5 trash_block / restore_block error surface — 2 typed exception
    // classes mirroring the bridge's FfiVaultError variants.
    m.add(
        "VaultBlockUuidAlreadyLive",
        py.get_type::<VaultBlockUuidAlreadyLive>(),
    )?;
    m.add(
        "VaultBlockNotInTrash",
        py.get_type::<VaultBlockNotInTrash>(),
    )?;
    // #399 Task 8: restore_block against a purged block.
    m.add("VaultBlockPurged", py.get_type::<VaultBlockPurged>())?;

    // #399 Task 9: purge_block pyfunction + PurgeReport DTO. No new
    // typed exception classes — purge_block's error surface
    // (VaultBlockNotInTrash, VaultFolderInvalid, VaultSaveCryptoFailure,
    // CorruptVault) is already registered above.
    m.add_class::<PurgeReport>()?;
    m.add_function(wrap_pyfunction!(purge_block, m)?)?;

    // #399 Task 10: empty_trash pyfunction + EmptyTrashReport DTO. Same
    // error surface as purge_block minus VaultBlockNotInTrash (empty_trash
    // takes no block_uuid, so it can never fire) — no new typed exception
    // classes needed.
    m.add_class::<EmptyTrashReport>()?;
    m.add_function(wrap_pyfunction!(empty_trash, m)?)?;

    // #402: retention auto-purge — preview + commit + 90-day default window.
    // No new typed exception classes (reuses empty_trash's error surface).
    m.add_class::<ExpiredEntry>()?;
    m.add_class::<RetentionPurgeReport>()?;
    m.add_function(wrap_pyfunction!(expired_trash_entries, m)?)?;
    m.add_function(wrap_pyfunction!(auto_purge_expired, m)?)?;
    m.add(
        "DEFAULT_RETENTION_WINDOW_MS",
        secretary_ffi_bridge::DEFAULT_RETENTION_WINDOW_MS,
    )?;

    // D.1.6 share-contacts error surface — 2 typed exception classes
    // mirroring the bridge's FfiVaultError variants.
    m.add(
        "VaultContactAlreadyExists",
        py.get_type::<VaultContactAlreadyExists>(),
    )?;
    m.add(
        "VaultContactNotFound",
        py.get_type::<VaultContactNotFound>(),
    )?;

    // D.1.7 delete-contact error surface — owner self-card deletion guard.
    m.add(
        "VaultCannotDeleteOwnerContact",
        py.get_type::<VaultCannotDeleteOwnerContact>(),
    )?;

    // D.1.6 contacts surface (#206) — verified share path. The
    // ContactAlreadyExists / ContactNotFound exception classes are already
    // registered above.
    m.add_class::<ContactSummary>()?;
    m.add_function(wrap_pyfunction!(import_contact_card, m)?)?;
    m.add_function(wrap_pyfunction!(share_block_to, m)?)?;

    // Sync error surface — 6 typed exception classes mirroring the bridge's
    // FfiVaultError sync variants: the five from D.1.13 (StateVaultMismatch /
    // StateCorrupt / EvidenceStale / InProgress / Failed) plus
    // SyncDecisionsIncomplete from D.1.15.
    m.add(
        "VaultSyncStateVaultMismatch",
        py.get_type::<VaultSyncStateVaultMismatch>(),
    )?;
    m.add(
        "VaultSyncStateCorrupt",
        py.get_type::<VaultSyncStateCorrupt>(),
    )?;
    m.add(
        "VaultSyncEvidenceStale",
        py.get_type::<VaultSyncEvidenceStale>(),
    )?;
    m.add("VaultSyncInProgress", py.get_type::<VaultSyncInProgress>())?;
    m.add("VaultSyncFailed", py.get_type::<VaultSyncFailed>())?;
    m.add(
        "VaultSyncDecisionsIncomplete",
        py.get_type::<VaultSyncDecisionsIncomplete>(),
    )?;

    // ADR 0009 (B.2) device-slot error surface — 3 typed exception classes
    // mirroring the bridge's FfiVaultError device variants.
    m.add(
        "VaultDeviceSlotNotFound",
        py.get_type::<VaultDeviceSlotNotFound>(),
    )?;
    m.add(
        "VaultWrongDeviceSecretOrCorrupt",
        py.get_type::<VaultWrongDeviceSecretOrCorrupt>(),
    )?;
    m.add(
        "VaultDeviceUuidMismatch",
        py.get_type::<VaultDeviceUuidMismatch>(),
    )?;

    // ADR 0009 (B.2) device-slot ops — 2 pyclasses + 3 pyfunctions.
    // The 3 exception classes (DeviceSlotNotFound / WrongDeviceSecretOrCorrupt /
    // DeviceUuidMismatch) are registered in the error surface block above.
    m.add_class::<DeviceSecretOutput>()?;
    m.add_class::<DeviceEnrollOutput>()?;
    m.add_function(wrap_pyfunction!(add_device_slot, m)?)?;
    m.add_function(wrap_pyfunction!(open_with_device_secret, m)?)?;
    m.add_function(wrap_pyfunction!(remove_device_slot, m)?)?;

    // #187 sync surface — 3 functions + 6 DTO classes (the sync error
    // classes are already registered in the block above).
    m.add_class::<DeviceClockDto>()?;
    m.add_class::<SyncStatusDto>()?;
    m.add_class::<VetoDto>()?;
    m.add_class::<CollisionDto>()?;
    m.add_class::<SyncOutcomeDto>()?;
    m.add_class::<VetoDecisionDto>()?;
    m.add_function(wrap_pyfunction!(sync_status, m)?)?;
    m.add_function(wrap_pyfunction!(sync_vault, m)?)?;
    m.add_function(wrap_pyfunction!(sync_commit_decisions, m)?)?;

    // #374 repair_vault error surface — 2 typed exception classes mirroring
    // the bridge's new FfiVaultError variants (crash-residue "offer Repair"
    // signal and the repair-refused outcome).
    m.add("VaultNeedsRepair", py.get_type::<VaultNeedsRepair>())?;
    m.add("VaultRepairRejected", py.get_type::<VaultRepairRejected>())?;

    // #374 repair_vault projection — 3 pyfunctions mirroring the bridge's
    // repair_vault_with_* trio. Error surface reuses the classes registered
    // above plus the open-path classes already registered elsewhere.
    m.add_function(wrap_pyfunction!(repair_with_password, m)?)?;
    m.add_function(wrap_pyfunction!(repair_with_recovery, m)?)?;
    m.add_function(wrap_pyfunction!(repair_with_device_secret, m)?)?;

    // #374 Task 8 — informed-consent surface: ApprovedWidening (input) +
    // preview_repair_with_* trio + RepairPreview / WideningReport /
    // AddedRecipient (output). Error surface unchanged: a preview that
    // finds nothing to repair raises the same classes as the plain
    // repair_with_* / open_* calls.
    m.add_class::<ApprovedWidening>()?;
    m.add_class::<RepairPreview>()?;
    m.add_class::<WideningReport>()?;
    m.add_class::<AddedRecipient>()?;
    m.add_function(wrap_pyfunction!(preview_repair_with_password, m)?)?;
    m.add_function(wrap_pyfunction!(preview_repair_with_recovery, m)?)?;
    m.add_function(wrap_pyfunction!(preview_repair_with_device_secret, m)?)?;

    // Vault-settings surface — Settings pyclass (input + output) +
    // read_settings / write_settings. No new typed exception classes: both
    // reuse ffi_vault_error_to_pyerr's existing FfiVaultError match, and
    // out-of-range values on write raise a plain ValueError.
    m.add_class::<Settings>()?;
    m.add_function(wrap_pyfunction!(read_settings, m)?)?;
    m.add_function(wrap_pyfunction!(write_settings, m)?)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_returns_format_version() {
        assert_eq!(version(), secretary_core::version::FORMAT_VERSION);
    }

    #[test]
    fn add_returns_arithmetic_sum() {
        assert_eq!(add(2, 3), 5);
    }

    #[test]
    fn add_wraps_on_overflow() {
        // Pin the wrapping contract: u32::MAX + 1 wraps to 0. A future
        // change to checked_add / saturating_add (or a switch to PyResult
        // ergonomics in B.2) is a deliberate test failure rather than a
        // silent contract change.
        assert_eq!(add(u32::MAX, 1), 0);
    }
}
