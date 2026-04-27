//! Master-password and recovery-key unlock paths.
//! See `docs/crypto-design.md` §3 (Master KEK), §4 (Recovery KEK), §5 (Identity Bundle wrap)
//! and `docs/vault-format.md` §2 (vault.toml), §3 (identity.bundle.enc).

pub mod bundle;
pub mod bundle_file;
pub mod mnemonic;
pub mod vault_toml;

use crate::crypto::aead::AeadError;
use crate::crypto::kdf::KdfError;

#[derive(Debug, thiserror::Error)]
pub enum UnlockError {
    #[error("wrong password or vault corruption")]
    WrongPasswordOrCorrupt,
    #[error("wrong recovery mnemonic or vault corruption")]
    WrongMnemonicOrCorrupt,
    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(#[from] mnemonic::MnemonicError),
    #[error("vault data integrity failure")]
    CorruptVault,
    #[error("vault.toml and identity.bundle.enc reference different vaults")]
    VaultMismatch,

    #[error("malformed vault.toml: {0}")]
    MalformedVaultToml(#[from] vault_toml::VaultTomlError),
    #[error("malformed identity.bundle.enc: {0}")]
    MalformedBundleFile(#[from] bundle_file::BundleFileError),
    #[error("malformed identity bundle plaintext: {0}")]
    MalformedBundle(#[from] bundle::BundleError),

    #[error("KDF failure: {0}")]
    KdfFailure(#[from] KdfError),
    #[error("AEAD primitive failure")]
    AeadFailure,
}

impl From<AeadError> for UnlockError {
    fn from(_: AeadError) -> Self {
        // AEAD primitive errors collapse to AeadFailure — see spec §Error model.
        // Position-specific user-facing variants (WrongPasswordOrCorrupt etc.)
        // are produced explicitly at call sites, not via From.
        UnlockError::AeadFailure
    }
}
