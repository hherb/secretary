//! `repair_vault` FFI projection (#374). See [`repair_vault_with_password`],
//! [`repair_vault_with_recovery`], [`repair_vault_with_device_secret`].

mod orchestration;
pub use orchestration::{
    repair_vault_with_device_secret, repair_vault_with_password, repair_vault_with_recovery,
};

mod types;
pub use types::FfiApprovedWidening;

#[cfg(test)]
mod tests;
