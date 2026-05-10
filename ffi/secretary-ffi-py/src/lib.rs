//! Python bindings for secretary-core via PyO3.
//!
//! The crate-level `#![allow(unsafe_code)]` is the minimal escape hatch
//! for PyO3's #[pymodule] / #[pyfunction] macros, which expand to unsafe
//! blocks (the CPython C-API bridge is inherently unsafe). The crate-local
//! lint relaxation (workspace `forbid` → crate-local `deny`) is required
//! because `forbid` is non-overridable by inner #[allow]; see Cargo.toml.
//!
//! The `#[allow]` is **crate-level** rather than item-level because the
//! function-style `#[pymodule]` macro generates code at crate scope (an
//! `extern "C"` PyInit symbol alongside the entry-point function); a
//! narrower item-level `#[allow]` doesn't cover that expansion. The
//! tradeoff: a future contributor who adds a hand-rolled `unsafe` block
//! anywhere in this crate gets silence rather than a `deny` error. The
//! crate is intentionally tiny and reviewed; new `unsafe` blocks should
//! be challenged in code review.
//!
//! # Module layout
//!
//! - [`errors`] — `create_exception!` macros + `FfiUnlockError` /
//!   `FfiVaultError` → `PyErr` translators + the `uuid_array_or_value_error`
//!   length-validation helper.
//! - [`identity`] — `UnlockedIdentity` pyclass (shared by every entry
//!   point that produces or consumes a live identity).
//! - [`unlock`] — bytes-in unlock + create entry points (B.2 / B.3a /
//!   B.3b): `open_with_password`, `open_with_recovery`, `create_vault`,
//!   `MnemonicOutput`, `CreateVaultOutput`.
//! - [`vault`] — folder-in vault open entry points (B.4a):
//!   `open_vault_with_password`, `open_vault_with_recovery`, plus the
//!   `OpenVaultManifest` / `OpenVaultOutput` / `BlockSummary` pyclasses.
//! - [`record`] — block-read entry point (B.4b): `read_block`, plus the
//!   `FieldHandle` / `Record` / `BlockReadOutput` pyclasses.
//! - [`save`] — block-save entry point (B.4c): `save_block`, plus the
//!   `BlockInput` / `RecordInput` / `FieldInput` / `FieldInputValue`
//!   input pyclasses.
//! - [`share`] — block-share entry point (B.4d): `share_block`.
//!
//! # Rationale documents
//!
//! - B.1 (boilerplate): docs/superpowers/specs/2026-05-03-ffi-b1-py-bindings-boilerplate-design.md
//! - B.2 (open_with_password): docs/superpowers/specs/2026-05-04-ffi-b2-vault-unlock-design.md
//! - B.3a (open_with_recovery): docs/superpowers/specs/2026-05-04-ffi-b3a-recovery-unlock-design.md
//! - B.3b (create_vault): docs/superpowers/specs/2026-05-05-ffi-b3b-create-vault-design.md
//! - B.4a (open_vault_with_*): docs/superpowers/specs/2026-05-06-ffi-b4a-open-vault-design.md

#![allow(unsafe_code)]

use pyo3::prelude::*;

mod errors;
mod identity;
mod record;
mod save;
mod share;
mod unlock;
mod vault;

use errors::{
    CorruptVault, InvalidMnemonic, VaultBlockNotFound, VaultCardDecodeFailure, VaultCorruptVault,
    VaultFolderInvalid, VaultInvalidMnemonic, VaultMismatch, VaultMismatchFolder,
    VaultMissingRecipientCard, VaultNotAuthor, VaultRecipientAlreadyPresent,
    VaultSaveCryptoFailure, VaultWrongMnemonicOrCorrupt, VaultWrongPasswordOrCorrupt,
    WrongMnemonicOrCorrupt, WrongPasswordOrCorrupt,
};
use identity::UnlockedIdentity;
use record::{read_block, BlockReadOutput, FieldHandle, Record};
use save::{save_block, BlockInput, FieldInput, FieldInputValue, RecordInput};
use share::share_block;
use unlock::{
    create_vault, open_with_password, open_with_recovery, CreateVaultOutput, MnemonicOutput,
};
use vault::{
    open_vault_with_password, open_vault_with_recovery, BlockSummary, OpenVaultManifest,
    OpenVaultOutput,
};

/// Returns the vault format version exposed by the core crate.
///
/// Kept as a free function so Rust callers (and the Rust unit tests below)
/// can use it without going through PyO3 / a Python interpreter.
pub fn version() -> u16 {
    secretary_core::version::FORMAT_VERSION
}

/// Python-exposed addition. B.1 round-trip target. Uses `wrapping_add`
/// to make the overflow contract explicit (matches default Rust `+`
/// semantics in release builds, which silently wrap); B.2 will reconsider
/// when fallible crypto operations make `PyResult` first-class.
#[pyfunction]
fn add(a: u32, b: u32) -> u32 {
    a.wrapping_add(b)
}

/// Python-exposed wrapper around `version()`. Renamed at the PyO3 layer
/// from the Rust ident `version_py` to the Python name `version` so the
/// Python-side surface stays clean.
#[pyfunction]
#[pyo3(name = "version")]
fn version_py() -> u32 {
    u32::from(version())
}

/// `#[pymodule]` entrypoint. The function name (`secretary_ffi_py`) is the
/// Python module name that `import` looks up; it must match the wheel name
/// declared in `pyproject.toml` (`[tool.maturin] module-name`).
#[pymodule]
fn secretary_ffi_py(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Existing B.1 surface:
    m.add_function(wrap_pyfunction!(add, m)?)?;
    m.add_function(wrap_pyfunction!(version_py, m)?)?;

    // B.2 surface:
    m.add_class::<UnlockedIdentity>()?;
    m.add_function(wrap_pyfunction!(open_with_password, m)?)?;
    m.add(
        "WrongPasswordOrCorrupt",
        py.get_type::<WrongPasswordOrCorrupt>(),
    )?;
    m.add("VaultMismatch", py.get_type::<VaultMismatch>())?;
    m.add("CorruptVault", py.get_type::<CorruptVault>())?;

    // B.3a surface:
    m.add_function(wrap_pyfunction!(open_with_recovery, m)?)?;
    m.add(
        "WrongMnemonicOrCorrupt",
        py.get_type::<WrongMnemonicOrCorrupt>(),
    )?;
    m.add("InvalidMnemonic", py.get_type::<InvalidMnemonic>())?;

    // B.3b surface:
    m.add_class::<CreateVaultOutput>()?;
    m.add_class::<MnemonicOutput>()?;
    m.add_function(wrap_pyfunction!(create_vault, m)?)?;

    // B.4a surface:
    m.add_class::<BlockSummary>()?;
    m.add_class::<OpenVaultManifest>()?;
    m.add_class::<OpenVaultOutput>()?;
    m.add_function(wrap_pyfunction!(open_vault_with_password, m)?)?;
    m.add_function(wrap_pyfunction!(open_vault_with_recovery, m)?)?;
    m.add(
        "VaultWrongPasswordOrCorrupt",
        py.get_type::<VaultWrongPasswordOrCorrupt>(),
    )?;
    m.add(
        "VaultWrongMnemonicOrCorrupt",
        py.get_type::<VaultWrongMnemonicOrCorrupt>(),
    )?;
    m.add(
        "VaultInvalidMnemonic",
        py.get_type::<VaultInvalidMnemonic>(),
    )?;
    m.add("VaultMismatchFolder", py.get_type::<VaultMismatchFolder>())?;
    m.add("VaultCorruptVault", py.get_type::<VaultCorruptVault>())?;
    m.add("VaultFolderInvalid", py.get_type::<VaultFolderInvalid>())?;

    // B.4b surface:
    m.add_class::<FieldHandle>()?;
    m.add_class::<Record>()?;
    m.add_class::<BlockReadOutput>()?;
    m.add_function(wrap_pyfunction!(read_block, m)?)?;
    m.add("VaultBlockNotFound", py.get_type::<VaultBlockNotFound>())?;

    // B.4c surface:
    m.add(
        "VaultSaveCryptoFailure",
        py.get_type::<VaultSaveCryptoFailure>(),
    )?;
    m.add_class::<FieldInputValue>()?;
    m.add_class::<FieldInput>()?;
    m.add_class::<RecordInput>()?;
    m.add_class::<BlockInput>()?;
    m.add_function(wrap_pyfunction!(save_block, m)?)?;

    // B.4d surface — share_block pyfunction + 4 typed exception classes.
    m.add_function(wrap_pyfunction!(share_block, m)?)?;
    m.add("VaultNotAuthor", py.get_type::<VaultNotAuthor>())?;
    m.add(
        "VaultRecipientAlreadyPresent",
        py.get_type::<VaultRecipientAlreadyPresent>(),
    )?;
    m.add(
        "VaultMissingRecipientCard",
        py.get_type::<VaultMissingRecipientCard>(),
    )?;
    m.add(
        "VaultCardDecodeFailure",
        py.get_type::<VaultCardDecodeFailure>(),
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_returns_format_version() {
        assert_eq!(version(), secretary_core::version::FORMAT_VERSION);
    }

    #[test]
    fn add_returns_arithmetic_sum() {
        assert_eq!(add(2, 3), 5);
    }

    #[test]
    fn add_wraps_on_overflow() {
        // Pin the wrapping contract: u32::MAX + 1 wraps to 0. A future
        // change to checked_add / saturating_add (or a switch to PyResult
        // ergonomics in B.2) is a deliberate test failure rather than a
        // silent contract change.
        assert_eq!(add(u32::MAX, 1), 0);
    }
}
