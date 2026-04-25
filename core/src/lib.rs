#![forbid(unsafe_code)]
#![doc = "Secretary core: cryptographic primitives, identity handling, vault format,\n         and unlock paths. See `docs/crypto-design.md` and `docs/vault-format.md`\n         for the normative specifications this crate implements."]

pub mod crypto;
pub mod error;
pub mod identity;
pub mod unlock;
pub mod vault;
pub mod version;

pub use error::Error;
