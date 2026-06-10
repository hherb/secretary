//! Open-vault dispatch helpers: password / recovery / writable-copy
//! plus the shared `assert_open_ok` shape check.

use super::super::fixtures::{
    copy_vault_to_tempdir, resolve_mnemonic, resolve_password, resolve_vault_dir,
};
use super::super::types::OkPayload;

pub fn run_open_password(
    inputs: &serde_json::Value,
) -> Result<secretary_ffi_bridge::vault::OpenVaultOutput, secretary_ffi_bridge::error::FfiVaultError>
{
    let vault_dir = resolve_vault_dir(inputs);
    let password = resolve_password(inputs);
    secretary_ffi_bridge::vault::open_vault_with_password(&vault_dir, &password)
}

pub fn run_open_recovery(
    inputs: &serde_json::Value,
) -> Result<secretary_ffi_bridge::vault::OpenVaultOutput, secretary_ffi_bridge::error::FfiVaultError>
{
    let vault_dir = resolve_vault_dir(inputs);
    let mnemonic = resolve_mnemonic(inputs);
    secretary_ffi_bridge::vault::open_vault_with_recovery(&vault_dir, &mnemonic)
}

/// Replays the device-slot open path (ADR 0009 / B.2) through
/// `bridge::device::open_with_device_secret`. The `vault_dir` is resolved
/// fixture-relative; the uuid + secret are resolved (and length-checked)
/// by the dispatch arm before this is reached.
pub fn run_open_device_secret(
    inputs: &serde_json::Value,
    device_uuid: &[u8; 16],
    device_secret: &[u8; 32],
) -> Result<secretary_ffi_bridge::vault::OpenVaultOutput, secretary_ffi_bridge::error::FfiVaultError>
{
    let vault_dir = resolve_vault_dir(inputs);
    secretary_ffi_bridge::device::open_with_device_secret(&vault_dir, device_uuid, device_secret)
}

/// Copies the named fixture vault to a fresh tempdir, opens the copy
/// with the resolved password, and returns the open output paired with
/// the TempDir handle. The caller is responsible for holding the TempDir
/// alongside the cached OpenVaultOutput so the dir survives until replay
/// completes.
pub fn run_open_writable(
    inputs: &serde_json::Value,
) -> Result<
    (
        secretary_ffi_bridge::vault::OpenVaultOutput,
        tempfile::TempDir,
    ),
    secretary_ffi_bridge::error::FfiVaultError,
> {
    let vault_name = inputs
        .get("vault_dir")
        .and_then(|v| v.as_str())
        .expect("open_vault_with_password_writable needs vault_dir (fixture-relative)");
    let tmp = copy_vault_to_tempdir(vault_name);
    let password = resolve_password(inputs);
    let out = secretary_ffi_bridge::vault::open_vault_with_password(tmp.path(), &password)?;
    Ok((out, tmp))
}

pub fn assert_open_ok(
    label: &str,
    output: &secretary_ffi_bridge::vault::OpenVaultOutput,
    expected: &OkPayload,
) {
    if let Some(name) = &expected.display_name {
        assert_eq!(
            &output.identity.display_name(),
            name,
            "{label}: display_name mismatch"
        );
    }
    if let Some(count) = expected.block_count {
        assert_eq!(
            output.manifest.block_count(),
            count,
            "{label}: block_count mismatch"
        );
    }
    if let Some(hex_str) = &expected.block_uuid_hex {
        hex::decode(hex_str).expect("block_uuid_hex must be valid hex");
        let summaries = output.manifest.block_summaries();
        assert!(
            !summaries.is_empty(),
            "{label}: manifest has no blocks but block_uuid_hex was pinned"
        );
        let actual_hex = hex::encode(summaries[0].block_uuid);
        assert_eq!(
            actual_hex,
            hex_str.to_lowercase(),
            "{label}: block_uuid mismatch"
        );
    }
}
