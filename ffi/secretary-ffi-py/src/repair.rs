//! Crash-recovery `repair_vault` entry points (#374): [`repair_with_password`],
//! [`repair_with_recovery`], [`repair_with_device_secret`], plus the
//! informed-consent input type [`ApprovedWidening`]. The read-only
//! `preview_repair_with_*` trio (+ output types) lives in
//! [`crate::repair_preview`].
//!
//! Each mutating arm mirrors its `open_*` / `open_with_device_secret`
//! counterpart in [`crate::vault`] / [`crate::device`] one-for-one — same
//! folder-path UTF-8 validation, same credential-length checks, same
//! zeroize discipline, same `OpenVaultOutput` return shape — but calls
//! `secretary_ffi_bridge::repair_vault_with_*` instead of the plain open
//! path. Repair is never a weaker open: the bridge fn runs the same
//! rollback-resistance check as a normal open before returning a handle
//! (`core/src/vault/repair.rs`, vault-format.md §10).
//!
//! `device_uuid` / `now_ms` follow the `save_block` convention (caller-
//! supplied; the manifest-clock tick on adoption keys on `device_uuid`).
//! On the `WrongPasswordOrCorrupt` / crash-residue split: a genuine crash
//! residue surfaces as `VaultNeedsRepair` from the plain `open_*` calls
//! (see `errors.rs`); `repair_with_*` is the follow-up call once the
//! caller has decided to attempt adoption. `VaultRepairRejected` means one
//! of the fail-closed adoption gates (hybrid verify, header binding, clock
//! freshness, or the recipient-widening guard) refused the on-disk residue
//! — no change was written.
//!
//! ## Informed consent (#374 Task 8)
//!
//! `approvals` licenses consent-eligible recipient-widening crash residue
//! (the crashed-`share_block` shape). `None` (the default — existing
//! Python callers that never pass `approvals` keep working unchanged) and
//! `Some(vec![])` both map to the documented safe zero-value: fail-closed
//! on any widening, exactly as before this task. A caller builds an
//! approval by calling one of `crate::repair_preview`'s
//! `preview_repair_with_*` first (nothing is written), reading the
//! returned `WideningReport`'s `block_uuid_hex` / `file_fingerprint_hex`
//! and each `AddedRecipient`'s `uuid_hex`, hex-decoding them back to
//! bytes, and constructing an [`ApprovedWidening`] that binds exactly
//! those values — a file swapped between preview and repair fails that
//! bind as stale consent (`VaultRepairRejected`).

use pyo3::prelude::*;
use secretary_core::crypto::secret::{SecretBytes, Sensitive};

use crate::errors::{
    array32_into_or_value_error, ffi_vault_error_to_pyerr, indexed_uuid_array_or_value_error,
    uuid_array_or_value_error,
};
use crate::identity::UnlockedIdentity;
use crate::vault::{OpenVaultManifest, OpenVaultOutput};

/// One user-approved crash-repair recipient widening (informed-consent
/// input). Constructor length-validates all four byte fields —
/// `block_uuid` (16), `file_fingerprint` (32), `committed_fingerprint`
/// (32), each entry of `added_recipients` (16) — raising `ValueError`
/// naming the field and the length actually received. Mirrors the
/// input-record length-validation discipline in `save.rs`'s
/// `BlockInput`/`RecordInput` constructors, and projects
/// `secretary_ffi_bridge::FfiApprovedWidening` the same way the uniffi
/// binding's `convert_approvals` helper does
/// (`secretary-ffi-uniffi/src/namespace/repair.rs`) — except here
/// validation happens once, at construction, rather than per-call.
///
/// Mint fresh from a `preview_repair_with_*` run; never persist. An
/// approval is scoped to the immediately-following repair invocation
/// (vault-format.md §6.5), and as of #391 that scoping is structural:
/// `committed_fingerprint` binds the approval to the committed manifest
/// entry the preview diffed against, so a persisted approval replayed
/// after any committed write to the block (e.g. an intervening revocation
/// of the same recipient followed by a re-plant of the previously-
/// approved file) is refused as stale consent.
#[pyclass(from_py_object)]
#[derive(Clone)]
pub struct ApprovedWidening {
    block_uuid: [u8; 16],
    file_fingerprint: [u8; 32],
    committed_fingerprint: [u8; 32],
    added_recipients: Vec<[u8; 16]>,
}

#[pymethods]
impl ApprovedWidening {
    /// Construct a new approved widening. Every byte field is
    /// length-validated; `ValueError` on any mismatch.
    #[new]
    #[allow(clippy::needless_pass_by_value)] // owned Vec<u8> for bytes ∪ bytearray accept
    fn new(
        block_uuid: Vec<u8>,
        file_fingerprint: Vec<u8>,
        committed_fingerprint: Vec<u8>,
        added_recipients: Vec<Vec<u8>>,
    ) -> PyResult<Self> {
        let block_uuid = uuid_array_or_value_error(&block_uuid, "block_uuid")?;
        let mut file_fingerprint_arr = [0u8; 32];
        array32_into_or_value_error(
            &file_fingerprint,
            &mut file_fingerprint_arr,
            "file_fingerprint",
        )?;
        let mut committed_fingerprint_arr = [0u8; 32];
        array32_into_or_value_error(
            &committed_fingerprint,
            &mut committed_fingerprint_arr,
            "committed_fingerprint",
        )?;
        let added_recipients = added_recipients
            .iter()
            .enumerate()
            .map(|(idx, r)| indexed_uuid_array_or_value_error(r, "added_recipients", idx))
            .collect::<PyResult<Vec<_>>>()?;
        Ok(Self {
            block_uuid,
            file_fingerprint: file_fingerprint_arr,
            committed_fingerprint: committed_fingerprint_arr,
            added_recipients,
        })
    }
}

impl ApprovedWidening {
    /// Project into the bridge-side `FfiApprovedWidening`. All fields are
    /// already length-validated (the `#[new]` constructor is the only way
    /// to build one), so this is a pure field copy — no fallibility left.
    fn to_bridge(&self) -> secretary_ffi_bridge::FfiApprovedWidening {
        secretary_ffi_bridge::FfiApprovedWidening {
            block_uuid: self.block_uuid,
            file_fingerprint: self.file_fingerprint,
            committed_fingerprint: self.committed_fingerprint,
            added_recipients: self.added_recipients.clone(),
        }
    }
}

/// Convert a caller-supplied `Option<Vec<ApprovedWidening>>` into the
/// bridge-side `Vec<FfiApprovedWidening>`. `None` and `Some(vec![])` both
/// produce an empty `Vec` — the documented safe zero-value the bridge maps
/// to `RepairPolicy::FailClosed`.
fn bridge_approvals(
    approvals: Option<Vec<ApprovedWidening>>,
) -> Vec<secretary_ffi_bridge::FfiApprovedWidening> {
    approvals
        .unwrap_or_default()
        .iter()
        .map(ApprovedWidening::to_bridge)
        .collect()
}

/// Repair a crash-residue vault using its master password.
///
/// # Inputs
///
/// - `folder_path` — UTF-8 path to the vault directory as raw bytes.
/// - `password` — master password as raw bytes (owned; wrapped in a
///   `SecretBytes` at function entry so it is wiped on every exit path,
///   panic included — #513).
/// - `device_uuid` — 16-byte device UUID; keys the manifest-clock tick on
///   adoption. `ValueError` if not exactly 16 bytes.
/// - `now_ms` — caller-supplied wall-clock milliseconds for the repair's
///   freshness gate.
/// - `approvals` — optional list of [`ApprovedWidening`] licensing
///   consent-eligible recipient-widening residue. Defaults to `None`
///   (fail-closed on any widening); see the module docs' "Informed
///   consent" section.
///
/// # Raises
///
/// - `VaultRepairRejected` — the on-disk residue failed a fail-closed
///   adoption gate (including a widening with no matching, or a stale,
///   approval); no change was written.
/// - `VaultWrongPasswordOrCorrupt`, `VaultMismatchFolder`,
///   `VaultCorruptVault`, `VaultFolderInvalid` — same semantics as
///   `open_vault_with_password`.
/// - `ValueError` — `folder_path` not valid UTF-8, or `device_uuid` wrong
///   length.
#[pyfunction]
#[pyo3(signature = (folder_path, password, device_uuid, now_ms, approvals=None))]
#[allow(clippy::needless_pass_by_value)] // owned Vec<u8> required to move into SecretBytes
pub(crate) fn repair_with_password(
    folder_path: &[u8],
    password: Vec<u8>,
    device_uuid: &[u8],
    now_ms: u64,
    approvals: Option<Vec<ApprovedWidening>>,
) -> PyResult<OpenVaultOutput> {
    // Wrapped immediately so `Drop` covers the wipe on every exit path,
    // including an unwinding panic inside the bridge call (#513).
    let password = SecretBytes::new(password);

    if device_uuid.len() != 16 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            crate::detail::arg_len("device_uuid", 16, device_uuid.len()),
        ));
    }

    let folder_str = std::str::from_utf8(folder_path)
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("folder_path must be valid UTF-8"))?;
    let folder = std::path::Path::new(folder_str);

    // SAFETY: length checked above; unwrap cannot panic here.
    let uuid_arr: [u8; 16] = device_uuid.try_into().expect("length checked above");
    let approvals = bridge_approvals(approvals);

    let bridge_out = secretary_ffi_bridge::repair_vault_with_password(
        folder,
        password.expose(),
        &uuid_arr,
        now_ms,
        &approvals,
    )
    .map_err(ffi_vault_error_to_pyerr)?;
    let secretary_ffi_bridge::OpenVaultOutput { identity, manifest } = bridge_out;
    Ok(OpenVaultOutput::from_bridge(
        UnlockedIdentity(identity),
        OpenVaultManifest(manifest),
    ))
}

/// Repair a crash-residue vault using its 24-word BIP-39 recovery phrase.
///
/// # Inputs
///
/// - `folder_path` — UTF-8 path to the vault directory as raw bytes.
/// - `mnemonic` — UTF-8-encoded recovery phrase as raw bytes (owned;
///   wrapped in a `SecretBytes` at function entry so it is wiped on every
///   exit path, panic included — #513).
/// - `device_uuid` — 16-byte device UUID. `ValueError` if not exactly 16
///   bytes.
/// - `now_ms` — caller-supplied wall-clock milliseconds for the repair's
///   freshness gate.
/// - `approvals` — see [`repair_with_password`].
///
/// # Raises
///
/// - `VaultRepairRejected` — see [`repair_with_password`].
/// - `VaultWrongMnemonicOrCorrupt`, `VaultInvalidMnemonic`,
///   `VaultMismatchFolder`, `VaultCorruptVault`, `VaultFolderInvalid` —
///   same semantics as `open_vault_with_recovery`.
/// - `ValueError` — `folder_path` not valid UTF-8, or `device_uuid` wrong
///   length.
#[pyfunction]
#[pyo3(signature = (folder_path, mnemonic, device_uuid, now_ms, approvals=None))]
#[allow(clippy::needless_pass_by_value)] // owned Vec<u8> required to move into SecretBytes
pub(crate) fn repair_with_recovery(
    folder_path: &[u8],
    mnemonic: Vec<u8>,
    device_uuid: &[u8],
    now_ms: u64,
    approvals: Option<Vec<ApprovedWidening>>,
) -> PyResult<OpenVaultOutput> {
    // Wrapped immediately so `Drop` covers the wipe on every exit path,
    // including an unwinding panic inside the bridge call (#513).
    let mnemonic = SecretBytes::new(mnemonic);

    if device_uuid.len() != 16 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            crate::detail::arg_len("device_uuid", 16, device_uuid.len()),
        ));
    }

    let folder_str = std::str::from_utf8(folder_path)
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("folder_path must be valid UTF-8"))?;
    let folder = std::path::Path::new(folder_str);

    // SAFETY: length checked above; unwrap cannot panic here.
    let uuid_arr: [u8; 16] = device_uuid.try_into().expect("length checked above");
    let approvals = bridge_approvals(approvals);

    let bridge_out = secretary_ffi_bridge::repair_vault_with_recovery(
        folder,
        mnemonic.expose(),
        &uuid_arr,
        now_ms,
        &approvals,
    )
    .map_err(ffi_vault_error_to_pyerr)?;
    let secretary_ffi_bridge::OpenVaultOutput { identity, manifest } = bridge_out;
    Ok(OpenVaultOutput::from_bridge(
        UnlockedIdentity(identity),
        OpenVaultManifest(manifest),
    ))
}

/// Repair a crash-residue vault using a per-device wrap secret (ADR 0009).
///
/// # Inputs
///
/// - `folder_path` — UTF-8 path to the vault directory as raw bytes.
/// - `device_uuid` — the 16-byte device UUID (also selects the
///   `devices/<uuid>.wrap` slot). `ValueError` if not exactly 16 bytes.
/// - `device_secret` — the 32-byte device secret (owned). `ValueError` if
///   not exactly 32 bytes.
/// - `now_ms` — caller-supplied wall-clock milliseconds for the repair's
///   freshness gate.
/// - `approvals` — see [`repair_with_password`].
///
/// # Caller zeroize
///
/// `device_secret` is wrapped in a `SecretBytes` at function entry, and
/// the 32-byte array built from it is a `Sensitive<[u8; 32]>` via
/// [`array32_into_or_value_error`](crate::errors::array32_into_or_value_error).
/// `Drop` covers the wipe of both on every exit path — normal return, an
/// early `ValueError`, or an unwinding panic inside the bridge call
/// (#513) — with no manual `.zeroize()` call anywhere in this function.
///
/// # Raises
///
/// - `VaultRepairRejected` — see [`repair_with_password`].
/// - `VaultDeviceSlotNotFound`, `VaultWrongDeviceSecretOrCorrupt`,
///   `VaultDeviceUuidMismatch`, `VaultFolderInvalid` — same semantics as
///   `open_with_device_secret`.
/// - `ValueError` — `folder_path` not valid UTF-8, or `device_uuid` /
///   `device_secret` wrong length.
#[pyfunction]
#[pyo3(signature = (folder_path, device_uuid, device_secret, now_ms, approvals=None))]
#[allow(clippy::needless_pass_by_value)] // owned Vec<u8> required to move into SecretBytes
pub(crate) fn repair_with_device_secret(
    folder_path: &[u8],
    device_uuid: &[u8],
    device_secret: Vec<u8>,
    now_ms: u64,
    approvals: Option<Vec<ApprovedWidening>>,
) -> PyResult<OpenVaultOutput> {
    // Wrapped immediately, before any validation, so `Drop` covers the
    // wipe on every exit path (mirrors `device::open_with_device_secret`,
    // including retiring the same len()-after-wipe bug class).
    let device_secret = SecretBytes::new(device_secret);

    if device_uuid.len() != 16 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            crate::detail::arg_len("device_uuid", 16, device_uuid.len()),
        ));
    }

    // Same relative position as the original manual length check: after
    // device_uuid, before the folder_path UTF-8 check.
    let secret_arr = Sensitive::try_build([0u8; 32], |slot| {
        array32_into_or_value_error(device_secret.expose(), slot, "device_secret")
    })?;

    let folder_str = std::str::from_utf8(folder_path)
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("folder_path must be valid UTF-8"))?;
    let folder = std::path::Path::new(folder_str);

    // SAFETY: length checked above; unwrap cannot panic here.
    let uuid_arr: [u8; 16] = device_uuid.try_into().expect("length checked above");
    let approvals = bridge_approvals(approvals);

    let bridge_out = secretary_ffi_bridge::repair_vault_with_device_secret(
        folder,
        &uuid_arr,
        secret_arr.expose(),
        now_ms,
        &approvals,
    )
    .map_err(ffi_vault_error_to_pyerr)?;
    let secretary_ffi_bridge::OpenVaultOutput { identity, manifest } = bridge_out;
    Ok(OpenVaultOutput::from_bridge(
        UnlockedIdentity(identity),
        OpenVaultManifest(manifest),
    ))
}
