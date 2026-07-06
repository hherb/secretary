//! `repair_vault` FFI projection (#374). See [`repair_vault_with_password`],
//! [`repair_vault_with_recovery`], [`repair_vault_with_device_secret`] for
//! the mutating repair arms, and [`preview_repair_with_password`],
//! [`preview_repair_with_recovery`], [`preview_repair_with_device_secret`]
//! for the read-only preview arms that surface an informed-consent prompt
//! before a caller builds a [`FfiApprovedWidening`] set.

mod orchestration;
pub use orchestration::{
    repair_vault_with_device_secret, repair_vault_with_password, repair_vault_with_recovery,
};

mod types;
pub use types::FfiApprovedWidening;

mod preview;
pub use preview::{
    preview_repair_with_device_secret, preview_repair_with_password, preview_repair_with_recovery,
    FfiAddedRecipient, FfiRepairPreview, FfiWideningReport,
};

#[cfg(test)]
mod tests;
