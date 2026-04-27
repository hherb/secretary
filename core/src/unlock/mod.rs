//! Master-password and recovery-key unlock paths.
//! See `docs/crypto-design.md` §3 (Master KEK), §4 (Recovery KEK), §5 (Identity Bundle wrap)
//! and `docs/vault-format.md` §2 (vault.toml), §3 (identity.bundle.enc).

pub mod bundle;
pub mod mnemonic;
