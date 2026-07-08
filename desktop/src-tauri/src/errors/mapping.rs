//! `FfiVaultError` → [`AppError`] mapping across the Tauri IPC boundary.
//!
//! Split into a pure [`map_ffi_error`] function (no side effects, exhaustive
//! match) and an `impl From` that logs at `warn` before delegating, so the
//! side effect is visible at the call site rather than buried inside the
//! `From` body. See spec §9 for the full mapping rules and the crate-level
//! [`super`] doc for the wire-format disciplines.

use super::types::AppError;
use secretary_ffi_bridge::error::FfiVaultError;

/// Pure mapping from `FfiVaultError` to `AppError`. No side effects — the
/// `tracing::warn!` that records the developer-facing detail before it's
/// stripped at the IPC seam lives in `impl From<FfiVaultError> for AppError`
/// so the side effect is visible at the call site.
///
/// Exposed as a function (not just an `impl From` body) so callers that
/// want the mapping without the log line — e.g. unit tests checking variant
/// routing, or future call sites that have already logged the source error
/// at a different level — can use it directly.
///
/// Adding a new `FfiVaultError` variant in the bridge crate will surface
/// here as a compile error (the match must be exhaustive), forcing a
/// deliberate UI-mapping choice.
///
/// The bridge's `WrongPasswordOrCorrupt` / `WrongMnemonicOrCorrupt`
/// variants are deliberately conflated per `docs/threat-model.md` §13's
/// anti-oracle property; both fold to `WrongPassword` here (the user's
/// affordance is "retry credential" in both cases). Block-share
/// authorisation + contacts variants (`NotAuthor`,
/// `RecipientAlreadyPresent`, `RecipientNotPresent`, `CannotRevokeOwner`,
/// `MissingRecipientCard`, `ContactAlreadyExists`, `ContactNotFound`) and
/// the trash/restore
/// preconditions route to typed `AppError`s. The few variants that
/// should never reach a live UI path (e.g. recovery-phrase
/// pre-validation, an unknown block UUID into `read_block`) fold to
/// `Internal { detail }` so a regression that lets them fire surfaces
/// as a clear bug-report path.
///
/// `FolderInvalid` folds to `Io { detail }` here because the bridge
/// surfaces the underlying IO context but not the caller's chosen path.
/// Task 4's command handlers, which DO know the user-picked path, will
/// construct `VaultPathNotFound` / `VaultPathNotAVault` directly at the
/// boundary so the UI can render the path-specific affordance.
pub fn map_ffi_error(e: FfiVaultError) -> AppError {
    match e {
        // Decryption-failure-shaped → WrongPassword (info-leak prevention).
        // Both bridge variants conflate "wrong credential" and "corruption"
        // per the anti-oracle property; we preserve the conflation at the
        // UI boundary too.
        FfiVaultError::WrongPasswordOrCorrupt | FfiVaultError::WrongMnemonicOrCorrupt => {
            AppError::WrongPassword
        }

        // Genuine cryptographic / integrity failures → VaultCorrupt.
        FfiVaultError::CorruptVault { detail }
        | FfiVaultError::SaveCryptoFailure { detail }
        | FfiVaultError::CardDecodeFailure { detail } => AppError::VaultCorrupt { detail },

        // vault.toml ↔ identity.bundle.enc mismatch is a corruption-class
        // failure from the user's perspective: the on-disk state is
        // inconsistent and they need to re-pair from backups. We synthesise
        // a detail string (this variant carries no payload).
        FfiVaultError::VaultMismatch => AppError::VaultCorrupt {
            detail: "vault.toml and identity.bundle.enc reference different vaults".to_string(),
        },

        // Pre-decryption mnemonic validation failure. Unreachable from
        // D.1.1's password-only unlock path; if it ever fires here, it's
        // a bug — surface as Internal with detail for the bug report.
        FfiVaultError::InvalidMnemonic { detail } => AppError::Internal {
            detail: format!("invalid mnemonic on password-only unlock path: {detail}"),
        },

        // Pre-unlock filesystem failure. Task 4's command handlers replace
        // this with the path-aware VaultPathNotFound / VaultPathNotAVault
        // construction at the boundary; here we fold to the generic Io
        // bucket so any pre-Task-4 code path surfaces something coherent.
        FfiVaultError::FolderInvalid { detail } => AppError::Io { detail },

        // Block-lookup miss. Reachable in D.1.1 if a caller passes a
        // stale block UUID to read_block (e.g. between a settings-block
        // creation and the subsequent manifest refresh). Surface as
        // Internal — D.1.1's settings flow never asks for an unknown
        // UUID, so this firing means a bug.
        FfiVaultError::BlockNotFound { uuid_hex } => AppError::Internal {
            detail: format!("block not found in manifest: {uuid_hex}"),
        },

        // Record-lookup miss from the D.1.4 `edit_record` primitive: the
        // user (or a stale frontend) asked to edit a record that is absent
        // or tombstoned. Surface the dedicated typed variant so the editor
        // can react (e.g. the record was deleted under it). The uuid hex is
        // non-secret (a caller-minted UUID) and crosses the seam.
        FfiVaultError::RecordNotFound { uuid_hex } => AppError::RecordNotFound {
            record_uuid_hex: uuid_hex,
        },

        // Restore precondition: the UUID has both a live and a trashed entry.
        // Typed variant so the UI can tell the user to trash the live copy first.
        //
        // Contract: the bridge constructs both restore-precondition variants
        // with `detail = hex::encode(block_uuid)` (see
        // `trash::orchestration` restore-error mapping), so moving `detail`
        // into `block_uuid_hex` is exact — NOT a prose message mislabeled as a
        // UUID. If that bridge mapping ever changes, this relabel breaks.
        FfiVaultError::BlockUuidAlreadyLive { detail } => AppError::BlockRestoreConflict {
            block_uuid_hex: detail,
        },

        // Restore precondition: no TrashEntry or file exists for this UUID.
        // Typed variant so the UI can distinguish "already restored" from
        // corruption. Same bridge contract as above: `detail` is the bare hex.
        FfiVaultError::BlockNotInTrash { detail } => AppError::TrashEntryNotFound {
            block_uuid_hex: detail,
        },

        // #399 Task 8: restore precondition — the TrashEntry is marked
        // purged. Typed variant (distinct from TrashEntryNotFound) so the
        // UI can tell "permanently deleted" apart from "already restored".
        // Same bridge contract as above: `detail` is the bare hex.
        FfiVaultError::BlockPurged { detail } => AppError::BlockPurged {
            block_uuid_hex: detail,
        },

        // Block-share authorization failures and recipient table mismatches,
        // plus contact-table preconditions: now typed (D.1.6 share UI). The
        // recipient fingerprints in `NotAuthor` are dropped at the seam — the
        // user's affordance ("you aren't the author") needs no payload; the
        // contact UUID hex (caller-minted, non-secret) crosses for the others.
        FfiVaultError::NotAuthor { .. } => AppError::NotAuthor,
        FfiVaultError::RecipientAlreadyPresent => AppError::RecipientAlreadyPresent,
        FfiVaultError::RecipientNotPresent => AppError::RecipientNotPresent,
        FfiVaultError::CannotRevokeOwner => AppError::CannotRevokeOwner,
        FfiVaultError::MissingRecipientCard { .. } => AppError::MissingRecipientCard,
        FfiVaultError::ContactAlreadyExists { uuid_hex } => AppError::ContactAlreadyExists {
            contact_uuid_hex: uuid_hex,
        },
        FfiVaultError::ContactNotFound { uuid_hex } => AppError::ContactNotFound {
            contact_uuid_hex: uuid_hex,
        },
        FfiVaultError::CannotDeleteOwnerContact => AppError::CannotDeleteOwnerContact,
        FfiVaultError::SyncStateVaultMismatch => AppError::SyncStateVaultMismatch,
        FfiVaultError::SyncStateCorrupt { detail } => AppError::SyncStateCorrupt { detail },
        FfiVaultError::SyncEvidenceStale => AppError::SyncEvidenceStale,
        FfiVaultError::SyncInProgress => AppError::SyncInProgress,
        FfiVaultError::SyncFailed { detail } => AppError::SyncFailed { detail },
        // The committed decisions did not cover the recomputed veto set (UI bug
        // or a race against a concurrent change). Typed variant so the UI can
        // distinguish "couldn't apply your choices, retry" from a generic sync
        // failure and re-open the conflict resolver.
        FfiVaultError::SyncDecisionsIncomplete => AppError::SyncDecisionsIncomplete,

        // ADR 0009 (B.2) device-slot errors: promoted to typed AppError variants
        // so the desktop UI can render the appropriate affordance when B.2's
        // open_with_device_secret / remove_device_slot surfaces are wired in.
        FfiVaultError::DeviceSlotNotFound => AppError::DeviceSlotNotFound,
        FfiVaultError::WrongDeviceSecretOrCorrupt => AppError::WrongDeviceSecret,
        FfiVaultError::DeviceUuidMismatch { detail } => AppError::VaultCorrupt { detail },

        // Folder-create precondition (iOS create/import Slice 1). The bridge
        // variant is path-less, exactly like `FolderInvalid` above. Desktop's
        // own create command runs its emptiness pre-check and constructs the
        // path-aware `AppError::VaultFolderNotEmpty { path }` directly at the
        // boundary, so this `map_ffi_error` arm is the fallback for any
        // path-less bridge surfacing — fold to the generic `Io` bucket with a
        // descriptive detail, mirroring the `FolderInvalid` → `Io` precedent.
        FfiVaultError::VaultFolderNotEmpty => AppError::Io {
            detail: "vault folder is not empty".to_string(),
        },

        // #374: crash residue `repair_vault` may be able to adopt. Typed
        // variant so the frontend can offer "Repair now?" instead of a
        // generic corruption message.
        FfiVaultError::VaultNeedsRepair { block_uuid_hex } => {
            AppError::VaultNeedsRepair { block_uuid_hex }
        }

        // #374: repair_vault was attempted and refused to adopt a block
        // (fail-closed). `detail` names the reason and is user-facing —
        // there is no automatic fix.
        FfiVaultError::RepairRejected {
            block_uuid_hex,
            detail,
        } => AppError::RepairRejected {
            block_uuid_hex,
            detail,
        },
    }
}

impl From<FfiVaultError> for AppError {
    /// Logs the source error at `warn` level (developer-facing detail goes
    /// to stderr / log sink before being stripped at the IPC seam), then
    /// delegates to the pure mapping in [`map_ffi_error`].
    fn from(e: FfiVaultError) -> Self {
        tracing::warn!(?e, "FfiVaultError surfacing to AppError");
        map_ffi_error(e)
    }
}
