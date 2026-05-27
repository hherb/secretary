//! `AppError` + `AppWarning` types crossing the Tauri IPC boundary.
//!
//! See spec §9 for the full mapping rules. Key disciplines:
//!
//! - Every variant `#[serde(tag = "code", rename_all = "snake_case")]` so
//!   the wire format is `{ "code": "wrong_password", ... }`.
//! - Developer-facing `detail` fields are `#[serde(skip_serializing)]` — they're
//!   logged via `tracing` on the Rust side but NEVER cross the IPC seam.
//! - `From<FfiVaultError>` is an explicit `match` so we choose the user-facing
//!   variant per case; no fall-through wrap-in-`Internal`.
//! - `WrongPassword` collapse rule: anything decryption-failure-shaped becomes
//!   `WrongPassword` (info-leak prevention per `docs/threat-model.md` §13).
//!
//! # Variant coverage versus FfiVaultError
//!
//! D.1.1 only exercises the password-unlock + read-block + save-block paths
//! (no recovery-phrase unlock, no block-share, no trash/restore). The
//! `From<FfiVaultError>` match is nonetheless exhaustive because new bridge
//! variants must force a deliberate UI-mapping choice rather than silently
//! folding to `Internal`. Variants that cannot fire in D.1.1's code paths
//! fold to `Internal { detail }` so a regression surfaces as a clear
//! "this is a bug" rather than a silent miscategorisation.
//!
//! Note: the bridge already collapses `WeakKdfParams` into `CorruptVault`
//! (post-unlock detail string). `AppError::KdfTooWeak` therefore has no
//! producer in this `From` impl — it survives as a typed variant for the
//! future where the bridge exposes the parameter pair structurally, and
//! its serialization shape is pinned by `kdf_too_weak_carries_payload`.

use secretary_ffi_bridge::error::FfiVaultError;

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
}

// All three variants are part of the IPC wire-format schema; renaming to
// drop the `Settings` prefix would change the on-wire `code` discriminator
// strings (e.g. `"settings_clamped"` → `"clamped"`) which would be a
// frontend-visible contract break. The shared prefix is intentional —
// these are the settings-domain warnings, and future non-settings
// warnings would NOT share the prefix.
#[allow(clippy::enum_variant_names)]
#[allow(dead_code)]
#[derive(Debug, serde::Serialize)]
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

impl From<FfiVaultError> for AppError {
    /// Explicit per-variant mapping. Adding a new `FfiVaultError` variant
    /// in the bridge crate will surface here as a compile error (the match
    /// must be exhaustive), forcing a deliberate UI-mapping choice.
    ///
    /// The bridge's `WrongPasswordOrCorrupt` / `WrongMnemonicOrCorrupt`
    /// variants are deliberately conflated per `docs/threat-model.md` §13's
    /// anti-oracle property; both fold to `WrongPassword` here (the user's
    /// affordance is "retry credential" in both cases). Bridge variants
    /// that cannot reach D.1.1's code paths (block-share authorisation,
    /// trash/restore preconditions, recovery-phrase pre-validation) fold
    /// to `Internal { detail }` so a regression that lets them fire
    /// surfaces as a clear bug-report path.
    ///
    /// `FolderInvalid` folds to `Io { detail }` here because the bridge
    /// surfaces the underlying IO context but not the caller's chosen path.
    /// Task 4's command handlers, which DO know the user-picked path, will
    /// construct `VaultPathNotFound` / `VaultPathNotAVault` directly at the
    /// boundary so the UI can render the path-specific affordance.
    fn from(e: FfiVaultError) -> Self {
        // Log developer-facing detail before stripping. tracing::warn so
        // it appears in stderr in dev mode and in any production log sink
        // without requiring DEBUG verbosity.
        tracing::warn!(?e, "FfiVaultError surfacing to AppError");

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

            // Block-share authorization failures, recipient table mismatches,
            // and trash/restore preconditions: unreachable in D.1.1 (no
            // share / no trash UI). Map to Internal so an accidental
            // wiring of a share/trash command surfaces clearly.
            other @ (FfiVaultError::NotAuthor { .. }
            | FfiVaultError::RecipientAlreadyPresent
            | FfiVaultError::MissingRecipientCard { .. }
            | FfiVaultError::BlockUuidAlreadyLive { .. }
            | FfiVaultError::BlockNotInTrash { .. }) => AppError::Internal {
                detail: format!("{other:?}"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn round_trip(err: &AppError) -> Value {
        serde_json::from_str(&serde_json::to_string(err).expect("serialize")).expect("parse")
    }

    #[test]
    fn wrong_password_has_code_only() {
        let v = round_trip(&AppError::WrongPassword);
        assert_eq!(v["code"], "wrong_password");
        assert_eq!(v.as_object().expect("object").len(), 1);
    }

    #[test]
    fn kdf_too_weak_carries_payload() {
        let v = round_trip(&AppError::KdfTooWeak {
            current_memory_kib: 32_768,
            min_memory_kib: 65_536,
        });
        assert_eq!(v["code"], "kdf_too_weak");
        assert_eq!(v["current_memory_kib"], 32_768);
        assert_eq!(v["min_memory_kib"], 65_536);
    }

    #[test]
    fn vault_corrupt_detail_is_stripped() {
        let v = round_trip(&AppError::VaultCorrupt {
            detail: "sensitive dev info".to_string(),
        });
        assert_eq!(v["code"], "vault_corrupt");
        assert!(v.get("detail").is_none(), "detail must NOT cross IPC");
    }

    #[test]
    fn settings_out_of_range_carries_bounds() {
        let v = round_trip(&AppError::SettingsOutOfRange {
            min: 60_000,
            max: 86_400_000,
        });
        assert_eq!(v["code"], "settings_out_of_range");
        assert_eq!(v["min"], 60_000);
        assert_eq!(v["max"], 86_400_000);
    }

    #[test]
    fn settings_clamped_warning_carries_both_values() {
        let w = AppWarning::SettingsClamped {
            original_ms: 30_000,
            clamped_ms: 60_000,
        };
        let v: Value =
            serde_json::from_str(&serde_json::to_string(&w).expect("ser")).expect("parse");
        assert_eq!(v["code"], "settings_clamped");
        assert_eq!(v["original_ms"], 30_000);
        assert_eq!(v["clamped_ms"], 60_000);
    }

    #[test]
    fn unknown_version_warning_carries_version_string() {
        let w = AppWarning::SettingsUnknownVersion {
            version: "secretary.settings.v99".to_string(),
        };
        let v: Value =
            serde_json::from_str(&serde_json::to_string(&w).expect("ser")).expect("parse");
        assert_eq!(v["code"], "settings_unknown_version");
        assert_eq!(v["version"], "secretary.settings.v99");
    }

    // Two additional From<FfiVaultError> spot-checks pin the anti-oracle
    // collapse + the detail-stripping path at the bridge seam itself.
    // These complement the variant-shape tests above by exercising the
    // mapping logic, not just the serde shape.

    #[test]
    fn ffi_wrong_password_or_corrupt_collapses_to_wrong_password() {
        let mapped: AppError = FfiVaultError::WrongPasswordOrCorrupt.into();
        let v = round_trip(&mapped);
        assert_eq!(
            v["code"], "wrong_password",
            "anti-oracle: WrongPasswordOrCorrupt must collapse to WrongPassword"
        );
    }

    #[test]
    fn ffi_corrupt_vault_detail_is_logged_but_stripped_on_serialize() {
        let mapped: AppError = FfiVaultError::CorruptVault {
            detail: "dev-facing crypto failure context".to_string(),
        }
        .into();
        let v = round_trip(&mapped);
        assert_eq!(v["code"], "vault_corrupt");
        assert!(
            v.get("detail").is_none(),
            "FfiVaultError::CorruptVault.detail must NOT cross IPC"
        );
    }
}
