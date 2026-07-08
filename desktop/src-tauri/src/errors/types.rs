//! `AppError` + `AppWarning` enum definitions crossing the Tauri IPC boundary.
//!
//! These are pure type declarations — the `FfiVaultError` → `AppError`
//! mapping lives in the sibling [`super::mapping`] module. Wire-format
//! discipline (see the crate-level [`super`] doc):
//!
//! - Every variant `#[serde(tag = "code", rename_all = "snake_case")]` so
//!   the wire format is `{ "code": "wrong_password", ... }`.
//! - Developer-facing `detail` fields are `#[serde(skip_serializing)]` — they're
//!   logged via `tracing` on the Rust side but NEVER cross the IPC seam.

// `AppError` variants `VaultPathNotFound` / `VaultPathNotAVault` /
// `VaultPathLocked` / `AlreadyUnlocked` / `NotUnlocked` are constructed by
// the Task 4 command handlers (which have access to the user-picked path
// and the session-state mutex) rather than by the `From<FfiVaultError>`
// impl. They appear in the wire-format schema from day one so the
// frontend's TS discriminated union (Task 6) mirrors the full surface,
// but the Rust producers land in Task 4.
//
// `AppWarning::SettingsCorrupt` is constructed by the Task 3 vault-load
// path when the settings record decodes but its field shapes don't match
// the schema (vs `SettingsClamped` which fires on out-of-range numeric
// values, already produced by `settings::parse_settings_field`).
#[allow(dead_code)]
#[derive(thiserror::Error, Debug, serde::Serialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum AppError {
    #[error("Vault folder does not exist or is not readable")]
    VaultPathNotFound { path: String },

    #[error("Folder exists but doesn't contain a vault")]
    VaultPathNotAVault { path: String },

    /// #353: a path argument was not chosen from a backend-invoked dialog.
    /// Produced only at the desktop IPC boundary; carries the offending path
    /// so the UI can prompt the user to re-pick.
    #[error("That path wasn't chosen from a dialog")]
    PathNotApproved { path: String },

    #[error("Vault is currently locked by another process")]
    VaultPathLocked { path: String },

    #[error("Wrong password")]
    WrongPassword,

    #[error("Vault uses KDF parameters below the minimum")]
    KdfTooWeak {
        current_memory_kib: u32,
        min_memory_kib: u32,
    },

    #[error("Vault is corrupted; consider restoring from a backup")]
    VaultCorrupt {
        #[serde(skip_serializing)]
        detail: String,
    },

    #[error("Vault already unlocked")]
    AlreadyUnlocked,

    #[error("No vault currently unlocked")]
    NotUnlocked,

    #[error("Block not found — it may have been removed")]
    BlockNotFound { block_uuid_hex: String },

    #[error("Record not found")]
    RecordNotFound { record_uuid_hex: String },

    #[error("Field value is invalid")]
    InvalidFieldValue { field_name: String },

    #[error("Could not save the record")]
    RecordSaveFailed {
        #[serde(skip_serializing)]
        detail: String,
    },

    /// A frontend-supplied argument was semantically invalid (blank block
    /// name on rename; same-block move). The bridge trusts its caller, so
    /// desktop enforces these guards here. `detail` is developer-facing only.
    #[error("Invalid request")]
    InvalidArgument {
        #[serde(skip_serializing)]
        detail: String,
    },

    #[error("Cannot restore: a block with this id is already live")]
    BlockRestoreConflict { block_uuid_hex: String },

    #[error("That trashed block is no longer available")]
    TrashEntryNotFound { block_uuid_hex: String },

    /// #399 Task 8: restore was requested on a block whose `TrashEntry`
    /// is marked purged — the ciphertext has been permanently deleted
    /// and cannot be restored. Distinct from `TrashEntryNotFound` (no
    /// tombstone at all) so the UI can render "permanently deleted"
    /// rather than "already restored".
    #[error("That block was permanently deleted and can't be restored")]
    BlockPurged { block_uuid_hex: String },

    #[error("Only the block's author can share it")]
    NotAuthor,

    #[error("This block is already shared with that contact")]
    RecipientAlreadyPresent,

    #[error("That contact is not currently a recipient of this block")]
    RecipientNotPresent,

    #[error("You cannot remove yourself as the owner of this block")]
    CannotRevokeOwner,

    #[error("A recipient's contact card is missing")]
    MissingRecipientCard,

    #[error("That contact is already in your vault")]
    ContactAlreadyExists { contact_uuid_hex: String },

    #[error("That contact is not in your vault")]
    ContactNotFound { contact_uuid_hex: String },

    #[error("Your own contact card can't be deleted")]
    CannotDeleteOwnerContact,

    #[error("Field not found")]
    FieldNotFound { field_name: String },

    #[error("Vault folder is not empty")]
    VaultFolderNotEmpty { path: String },

    #[error("Could not create the vault")]
    VaultCreateFailed {
        #[serde(skip_serializing)]
        detail: String,
    },

    #[error("Settings record is malformed; using defaults")]
    SettingsCorrupt {
        #[serde(skip_serializing)]
        detail: String,
    },

    #[error("Settings record uses an unknown schema version")]
    SettingsUnknownVersion { version: String },

    #[error("Auto-lock timeout must be between {min} and {max} ms")]
    SettingsOutOfRange { min: u64, max: u64 },

    #[error("Filesystem error")]
    Io {
        #[serde(skip_serializing)]
        detail: String,
    },

    #[error("Internal error — this is a bug")]
    Internal {
        #[serde(skip_serializing)]
        detail: String,
    },

    #[error("Sync state file belongs to a different vault")]
    SyncStateVaultMismatch,

    #[error("Sync state cache is corrupt")]
    SyncStateCorrupt {
        #[serde(skip_serializing)]
        detail: String,
    },

    #[error("Vault changed on disk during sync; retry")]
    SyncEvidenceStale,

    #[error("Another sync is already in progress for this vault")]
    SyncInProgress,

    #[error("Some conflicts weren't resolved")]
    SyncDecisionsIncomplete,

    #[error("Sync failed")]
    SyncFailed {
        #[serde(skip_serializing)]
        detail: String,
    },

    /// ADR 0009 (B.2): the requested device slot does not exist in the vault.
    /// Benign caller condition ("this device hasn't been registered yet").
    #[error("Device slot not found")]
    DeviceSlotNotFound,

    /// ADR 0009 (B.2): wrong device secret or wrap-file corruption —
    /// conflated anti-oracle (parallel to `WrongPassword`).
    #[error("Wrong device secret")]
    WrongDeviceSecret,

    /// The opened vault has crash residue repair may adopt. Frontend offers "Repair now?".
    #[error("This vault has crash residue that may be repairable")]
    VaultNeedsRepair { block_uuid_hex: String },

    /// repair_vault refused; `detail` names the reason (recipient delta for
    /// equal-clock). Unlike most `detail` fields in this enum, this one is
    /// user-facing (not developer-only): the bridge's `RepairRejected` doc
    /// contract is "the app should surface `detail`; there is no automatic
    /// fix" — so it crosses the IPC seam rather than being
    /// `#[serde(skip_serializing)]`.
    #[error("Repair was refused for a block")]
    RepairRejected {
        block_uuid_hex: String,
        detail: String,
    },
}

// All three variants are part of the IPC wire-format schema; renaming to
// drop the `Settings` prefix would change the on-wire `code` discriminator
// strings (e.g. `"settings_clamped"` → `"clamped"`) which would be a
// frontend-visible contract break. The shared prefix is intentional —
// these are the settings-domain warnings, and future non-settings
// warnings would NOT share the prefix.
// `Clone` is derived so `VaultSession::pending_warnings()` can hand owned
// copies to IPC commands without coupling the caller's borrow lifetime to
// the session mutex — every variant is a small fixed-size payload, so
// the clone is cheap.
#[allow(clippy::enum_variant_names)]
#[allow(dead_code)]
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum AppWarning {
    SettingsCorrupt {
        #[serde(skip_serializing)]
        detail: String,
    },
    SettingsClamped {
        original_ms: u64,
        clamped_ms: u64,
    },
    SettingsUnknownVersion {
        version: String,
    },
}
