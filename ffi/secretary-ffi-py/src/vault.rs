//! Folder-in vault open entry points (B.4a) plus the manifest pyclass +
//! its `BlockSummary` projection.
//!
//! [`OpenVaultOutput`] returned by both folder-in pyfunctions carries
//! take-once handles to a live `UnlockedIdentity` and a read-only
//! [`OpenVaultManifest`]. The handles are accessed via destructive
//! `#[getter]` properties — first read MOVES the handle out, every
//! subsequent read raises `RuntimeError`.

use pyo3::prelude::*;
use pyo3::types::PyType;
use secretary_ffi_bridge::{
    BlockSummary as BridgeBlockSummary, OpenVaultManifest as BridgeOpenVaultManifest,
};
use zeroize::Zeroize;

use crate::errors::ffi_vault_error_to_pyerr;
use crate::identity::UnlockedIdentity;

/// Read-only metadata projection of one block in the vault manifest.
/// All five fields are plaintext in the manifest already — no secret
/// material crosses through `BlockSummary`. Frozen because foreign-side
/// mutation would have no effect on the underlying Rust state.
#[pyclass(frozen)]
pub struct BlockSummary {
    /// 16-byte block UUID identifying the block file on disk.
    #[pyo3(get)]
    pub block_uuid: Vec<u8>,
    /// User-visible block name. Plaintext within the encrypted manifest.
    #[pyo3(get)]
    pub block_name: String,
    /// Wall-clock millisecond timestamp at block creation.
    #[pyo3(get)]
    pub created_at_ms: u64,
    /// Wall-clock millisecond timestamp at last modification.
    #[pyo3(get)]
    pub last_modified_ms: u64,
    /// List of 16-byte recipient UUIDs (always includes owner). Plaintext.
    #[pyo3(get)]
    pub recipient_uuids: Vec<Vec<u8>>,
}

impl From<BridgeBlockSummary> for BlockSummary {
    fn from(b: BridgeBlockSummary) -> Self {
        Self {
            block_uuid: b.block_uuid.to_vec(),
            block_name: b.block_name,
            created_at_ms: b.created_at_ms,
            last_modified_ms: b.last_modified_ms,
            recipient_uuids: b.recipient_uuids.into_iter().map(|u| u.to_vec()).collect(),
        }
    }
}

/// Opaque handle to a successfully-opened vault's manifest. Provides
/// read-only block-list accessors. Use as a context manager so `wipe()`
/// is called automatically on exit — the IBK is zeroized at that point.
///
/// RAII is the safety net if the foreign caller forgets to use `with`.
#[pyclass]
pub struct OpenVaultManifest(pub(crate) BridgeOpenVaultManifest);

#[pymethods]
impl OpenVaultManifest {
    /// 16-byte vault UUID. Returns 16 zero bytes if wiped.
    pub fn vault_uuid(&self) -> Vec<u8> {
        self.0.vault_uuid()
    }

    /// 16-byte owner user UUID. Returns 16 zero bytes if wiped.
    pub fn owner_user_uuid(&self) -> Vec<u8> {
        self.0.owner_user_uuid()
    }

    /// Number of blocks in the manifest. Returns 0 if wiped.
    pub fn block_count(&self) -> u64 {
        self.0.block_count()
    }

    /// All block summaries in ascending-by-block_uuid order. Returns an
    /// empty list if wiped.
    pub fn block_summaries(&self) -> Vec<BlockSummary> {
        self.0
            .block_summaries()
            .into_iter()
            .map(BlockSummary::from)
            .collect()
    }

    /// Locate one block by its 16-byte UUID. Returns `None` if wiped or
    /// no matching block exists.
    ///
    /// `block_uuid` is `Vec<u8>` rather than `&[u8]` so PyO3 accepts both
    /// `bytes` and `bytearray` inputs — `&[u8]` would restrict to
    /// immutable `bytes` only. The 16-byte heap copy is negligible; the
    /// foreign-friendly accept-both ergonomics + parity with uniffi's
    /// UDL `bytes` → `Vec<u8>` projection are worth it.
    pub fn find_block(&self, block_uuid: Vec<u8>) -> Option<BlockSummary> {
        self.0.find_block(&block_uuid).map(BlockSummary::from)
    }

    /// Canonical-CBOR bytes of the vault's owner contact card. Suitable
    /// as the only element of `existing_recipient_cards` when calling
    /// `share_block` on a v1 owner-only block, or as the first element
    /// when sharing with multiple recipients. Returns `None` if wiped.
    ///
    /// Encodes on demand: encode failure (practically unreachable on the
    /// v1 invariant; see the bridge accessor's docstring) raises
    /// `VaultCorruptVault`. The widening from `Option[bytes]` to
    /// `bytes | None | raise` lands as part of issue #41 — replaces a
    /// `.expect()` panic-across-FFI with a recoverable typed exception.
    /// New in B.4d.
    pub fn owner_card_bytes(&self) -> PyResult<Option<Vec<u8>>> {
        self.0.owner_card_bytes().map_err(ffi_vault_error_to_pyerr)
    }

    /// Drop the wrapped manifest now, zeroizing the IBK at exactly this
    /// moment. Idempotent.
    pub fn wipe(&self) {
        self.0.wipe();
    }

    /// Context-manager `__enter__`. Returns `self` so `with manifest as m`
    /// binds the handle.
    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    /// Context-manager `__exit__`. Calls `wipe()` and returns `False` so
    /// any exception raised inside the `with`-block propagates after wipe
    /// runs.
    fn __exit__(
        &self,
        _exc_type: Option<&Bound<'_, PyType>>,
        _exc_value: Option<&Bound<'_, PyAny>>,
        _traceback: Option<&Bound<'_, PyAny>>,
    ) -> bool {
        self.0.wipe();
        false
    }
}

/// Output of `open_vault_with_password` / `open_vault_with_recovery`.
/// Holds two opaque take-once handles: `identity` (live
/// `UnlockedIdentity`) and `manifest` (read-only `OpenVaultManifest`).
///
/// The handles are accessed through take-once getter properties. The
/// first access MOVES the handle out of the parent struct; subsequent
/// accesses raise `RuntimeError`. The pattern mirrors B.3b's
/// `CreateVaultOutput.identity` and `.mnemonic` getters exactly.
///
/// Use as a context manager so both inner handles have the opportunity
/// to wipe themselves on exit even if the caller forgot to enter them:
///
/// ```python
/// with open_vault_with_password(folder, pw) as out:
///     with out.identity as id, out.manifest as m:
///         print(id.display_name())
/// ```
#[pyclass]
pub struct OpenVaultOutput {
    /// Live opaque handle, taken once. Wrapped in `Option` so the getter
    /// can move it out exactly once via `Option::take()`.
    identity: Option<UnlockedIdentity>,
    /// Read-only manifest handle, taken once. Same take-once pattern.
    manifest: Option<OpenVaultManifest>,
}

#[pymethods]
impl OpenVaultOutput {
    /// Take ownership of the live `UnlockedIdentity` handle. ONE-SHOT —
    /// the first read MOVES the handle out of the parent struct; every
    /// subsequent read raises `RuntimeError`. Mirrors the shape of
    /// `CreateVaultOutput.identity`.
    #[getter]
    fn identity(&mut self) -> PyResult<UnlockedIdentity> {
        self.identity.take().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(
                "OpenVaultOutput.identity already taken (one-shot)",
            )
        })
    }

    /// Take ownership of the `OpenVaultManifest` handle. ONE-SHOT —
    /// same destructive take-once semantics as `identity`.
    #[getter]
    fn manifest(&mut self) -> PyResult<OpenVaultManifest> {
        self.manifest.take().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(
                "OpenVaultOutput.manifest already taken (one-shot)",
            )
        })
    }

    /// Context-manager `__enter__`. Returns `self` so `with out as o`
    /// binds the output handle.
    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    /// Context-manager `__exit__`. Drops both inner handles if still
    /// resident (which runs their own zeroize-on-drop chains). Returns
    /// `False` so any exception propagates.
    fn __exit__(
        &mut self,
        _exc_type: Option<&Bound<'_, PyType>>,
        _exc_value: Option<&Bound<'_, PyAny>>,
        _traceback: Option<&Bound<'_, PyAny>>,
    ) -> bool {
        // Drop identity: close() zeroizes the IBK + secret keys via the
        // bridge's wipe() forwarder.
        if let Some(id) = self.identity.take() {
            id.close();
        }
        // Drop manifest: wipe() zeroizes the IBK.
        if let Some(m) = self.manifest.take() {
            m.wipe();
        }
        false
    }
}

/// Open a vault folder using its master password (B.4a).
///
/// Reads `vault.toml`, `identity.bundle.enc`, `manifest.cbor.enc`, and
/// the owner contact card from `folder` via `core::vault::open_vault`.
/// Returns an `OpenVaultOutput` with two take-once handles: `identity`
/// (live `UnlockedIdentity`) and `manifest` (read-only `OpenVaultManifest`).
///
/// # Caller zeroize
///
/// `password` is owned bytes (`Vec<u8>`); the bridge wraps it in
/// `SecretBytes` (zeroize-on-drop). The wrapper here additionally zeroizes
/// the wrapper-side `Vec<u8>` after the bridge call returns. The foreign
/// caller's input buffer (e.g. a Python `bytearray`) is the foreign side's
/// responsibility — wipe it after the call returns.
///
/// # Raises
///
/// - `VaultWrongPasswordOrCorrupt` — password is wrong, or vault data
///   integrity failure (anti-oracle conflation).
/// - `VaultMismatchFolder` — `vault.toml` and `identity.bundle.enc`
///   reference different vaults.
/// - `VaultCorruptVault` — manifest decode / verification / cross-check
///   failed post-unlock.
/// - `VaultFolderInvalid` — folder doesn't exist, isn't readable, or is
///   missing one of the four required files.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)] // owned Vec<u8> required for zeroize discipline
pub(crate) fn open_vault_with_password(
    folder: std::path::PathBuf,
    mut password: Vec<u8>,
) -> PyResult<OpenVaultOutput> {
    let result = secretary_ffi_bridge::open_vault_with_password(&folder, &password)
        .map_err(ffi_vault_error_to_pyerr);
    password.zeroize();
    let bridge_out = result?;
    let secretary_ffi_bridge::OpenVaultOutput { identity, manifest } = bridge_out;
    Ok(OpenVaultOutput {
        identity: Some(UnlockedIdentity(identity)),
        manifest: Some(OpenVaultManifest(manifest)),
    })
}

/// Open a vault folder using its 24-word BIP-39 recovery phrase (B.4a).
///
/// Reads the same set of files as `open_vault_with_password`. The
/// `mnemonic` input is UTF-8-encoded bytes; the bridge surfaces
/// malformed-UTF-8 as `VaultInvalidMnemonic` with `detail` =
/// `"phrase contained invalid UTF-8"` — parallel to B.3a's
/// `open_with_recovery`.
///
/// # Caller zeroize
///
/// `mnemonic` is owned bytes; the wrapper zeroizes them after the
/// bridge call returns. The foreign caller's input buffer is the foreign
/// side's responsibility.
///
/// # Raises
///
/// - `VaultWrongMnemonicOrCorrupt` — phrase is wrong, or vault data
///   integrity failure (anti-oracle conflation).
/// - `VaultInvalidMnemonic` — phrase failed BIP-39 validation BEFORE any
///   decryption was attempted (wrong word count, unknown word, bad
///   checksum, or invalid UTF-8 input).
/// - `VaultMismatchFolder` — `vault.toml` and `identity.bundle.enc`
///   reference different vaults.
/// - `VaultCorruptVault` — manifest decode / verification / cross-check
///   failed post-unlock.
/// - `VaultFolderInvalid` — folder doesn't exist, isn't readable, or is
///   missing one of the four required files.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)] // owned Vec<u8> required for zeroize discipline
pub(crate) fn open_vault_with_recovery(
    folder: std::path::PathBuf,
    mut mnemonic: Vec<u8>,
) -> PyResult<OpenVaultOutput> {
    let result = secretary_ffi_bridge::open_vault_with_recovery(&folder, &mnemonic)
        .map_err(ffi_vault_error_to_pyerr);
    mnemonic.zeroize();
    let bridge_out = result?;
    let secretary_ffi_bridge::OpenVaultOutput { identity, manifest } = bridge_out;
    Ok(OpenVaultOutput {
        identity: Some(UnlockedIdentity(identity)),
        manifest: Some(OpenVaultManifest(manifest)),
    })
}
