//! Typed errors surfaced by `sync_once` and `SyncState` codec.

use thiserror::Error;

use crate::vault::VaultError;

#[derive(Debug, Error)]
pub enum SyncError {
    #[error(
        "vault_uuid in SyncState ({state_vault_uuid:?}) does not match \
         vault manifest ({folder_vault_uuid:?})"
    )]
    VaultUuidMismatch {
        state_vault_uuid: [u8; 16],
        folder_vault_uuid: [u8; 16],
    },

    #[error("SyncState CBOR decode failed: {detail}")]
    StateDecodeFailed { detail: String },

    #[error("SyncState CBOR encode failed: {detail}")]
    StateEncodeFailed { detail: String },

    #[error(transparent)]
    Vault(#[from] VaultError),

    #[error("invalid argument: {detail}")]
    InvalidArgument { detail: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_uuid_mismatch_display_is_stable() {
        let err = SyncError::VaultUuidMismatch {
            state_vault_uuid: [1u8; 16],
            folder_vault_uuid: [2u8; 16],
        };
        let s = format!("{err}");
        assert!(s.contains("vault_uuid in SyncState"));
        assert!(s.contains("does not match vault manifest"));
    }

    #[test]
    fn state_decode_failed_display_is_stable() {
        let err = SyncError::StateDecodeFailed {
            detail: "trailing bytes".into(),
        };
        assert_eq!(
            format!("{err}"),
            "SyncState CBOR decode failed: trailing bytes"
        );
    }

    #[test]
    fn state_encode_failed_display_is_stable() {
        let err = SyncError::StateEncodeFailed {
            detail: "encoder primitive error".into(),
        };
        assert_eq!(
            format!("{err}"),
            "SyncState CBOR encode failed: encoder primitive error"
        );
    }

    #[test]
    fn invalid_argument_display_is_stable() {
        let err = SyncError::InvalidArgument {
            detail: "duplicate device_uuid".into(),
        };
        assert_eq!(format!("{err}"), "invalid argument: duplicate device_uuid");
    }

    #[test]
    fn vault_error_forwards_via_from() {
        // VaultError variants are tested in core::vault; here we only
        // certify the From impl exists and folds into the Vault arm.
        // Pick a small variant that doesn't need fixture setup —
        // OwnerUuidMismatch is a plain two-field struct variant.
        let inner: VaultError = VaultError::OwnerUuidMismatch {
            vault: [0u8; 16],
            found: [1u8; 16],
        };
        let outer: SyncError = inner.into();
        assert!(matches!(outer, SyncError::Vault(_)));
    }
}
