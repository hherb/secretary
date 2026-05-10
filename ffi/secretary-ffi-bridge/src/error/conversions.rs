//! Cross-type translation between [`FfiUnlockError`] and [`FfiVaultError`],
//! plus the byte-identical-mirror tripwire that pins the two enums' shared
//! Display strings.
//!
//! [`FfiVaultError`]'s 5 unlock-class variants share **byte-identical**
//! Display strings with their [`FfiUnlockError`] counterparts. The
//! tripwire test in this module asserts the equality so a future rename
//! on either side cannot drift unnoticed.

use super::{FfiUnlockError, FfiVaultError};

/// Bridge-internal translation of an unlock-class error into the vault-
/// class error surface. Private free function so the bridge crate has a
/// single place to evolve the mapping; the `pub` `From` impl below is a
/// thin delegator.
///
/// The translation is one-to-one because every unlock-class variant maps
/// to a name-identical vault-class variant (the vault-class enum is a
/// strict superset of the unlock-class enum). Future variant additions
/// belong here, not in the `From` impl body.
fn unlock_err_to_vault_err(e: FfiUnlockError) -> FfiVaultError {
    match e {
        FfiUnlockError::WrongPasswordOrCorrupt => FfiVaultError::WrongPasswordOrCorrupt,
        FfiUnlockError::WrongMnemonicOrCorrupt => FfiVaultError::WrongMnemonicOrCorrupt,
        FfiUnlockError::InvalidMnemonic { detail } => FfiVaultError::InvalidMnemonic { detail },
        FfiUnlockError::VaultMismatch => FfiVaultError::VaultMismatch,
        FfiUnlockError::CorruptVault { detail } => FfiVaultError::CorruptVault { detail },
    }
}

/// Bridge-internal conversion. This impl is necessarily `pub` (it
/// implements the standard `From` trait, whose visibility cannot be
/// restricted), but it is **not part of the stable FFI surface**. Do not
/// use this arm directly from foreign-projection code — it would couple
/// the binding-flavor crates (`secretary-ffi-py`, `secretary-ffi-uniffi`)
/// to a private translation step. Foreign code goes through
/// `From<core::vault::VaultError>`, which delegates to
/// `unlock_err_to_vault_err` internally for the unlock-class variants.
impl From<FfiUnlockError> for FfiVaultError {
    fn from(e: FfiUnlockError) -> Self {
        unlock_err_to_vault_err(e)
    }
}

#[cfg(test)]
mod tests {
    use super::{FfiUnlockError, FfiVaultError};

    #[test]
    fn vault_error_display_strings_mirror_unlock_error_byte_identical() {
        // Tripwire: the 5 overlapping variants MUST produce byte-identical
        // Display strings between FfiUnlockError and FfiVaultError. A future
        // rename on either side that breaks the mirror property would fail
        // here, forcing a deliberate decision rather than silent drift.
        assert_eq!(
            FfiUnlockError::WrongPasswordOrCorrupt.to_string(),
            FfiVaultError::WrongPasswordOrCorrupt.to_string(),
        );
        assert_eq!(
            FfiUnlockError::WrongMnemonicOrCorrupt.to_string(),
            FfiVaultError::WrongMnemonicOrCorrupt.to_string(),
        );
        assert_eq!(
            FfiUnlockError::InvalidMnemonic {
                detail: "test".to_string()
            }
            .to_string(),
            FfiVaultError::InvalidMnemonic {
                detail: "test".to_string()
            }
            .to_string(),
        );
        assert_eq!(
            FfiUnlockError::VaultMismatch.to_string(),
            FfiVaultError::VaultMismatch.to_string(),
        );
        assert_eq!(
            FfiUnlockError::CorruptVault {
                detail: "test".to_string()
            }
            .to_string(),
            FfiVaultError::CorruptVault {
                detail: "test".to_string()
            }
            .to_string(),
        );
    }

    #[test]
    fn from_ffi_unlock_error_translates_each_variant_one_to_one() {
        // The private bridge-internal From<FfiUnlockError> arm. This is
        // reachable from FfiVaultError::from(VaultError::Unlock(...)) but
        // worth pinning directly so any rename / variant addition fails here
        // first.
        assert!(matches!(
            FfiVaultError::from(FfiUnlockError::WrongPasswordOrCorrupt),
            FfiVaultError::WrongPasswordOrCorrupt,
        ));
        assert!(matches!(
            FfiVaultError::from(FfiUnlockError::WrongMnemonicOrCorrupt),
            FfiVaultError::WrongMnemonicOrCorrupt,
        ));
        let inv = FfiVaultError::from(FfiUnlockError::InvalidMnemonic {
            detail: "bad".to_string(),
        });
        let FfiVaultError::InvalidMnemonic { detail } = inv else {
            panic!("expected InvalidMnemonic, got {inv:?}");
        };
        assert_eq!(detail, "bad");
        assert!(matches!(
            FfiVaultError::from(FfiUnlockError::VaultMismatch),
            FfiVaultError::VaultMismatch,
        ));
        let corrupt = FfiVaultError::from(FfiUnlockError::CorruptVault {
            detail: "x".to_string(),
        });
        let FfiVaultError::CorruptVault { detail } = corrupt else {
            panic!("expected CorruptVault, got {corrupt:?}");
        };
        assert_eq!(detail, "x");
    }
}
