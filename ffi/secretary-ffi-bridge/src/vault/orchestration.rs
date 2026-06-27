//! Folder-in vault open orchestrators ([`open_vault_with_password`] /
//! [`open_vault_with_recovery`]) plus the [`OpenVaultOutput`] return shape
//! and the bridge-internal `split_core_open_vault` helper that lifts a
//! `core::vault::OpenVault` into the two FFI handles.

use std::path::Path;

use secretary_core::crypto::secret::{SecretBytes, Sensitive};
use secretary_core::vault::Unlocker;
use zeroize::Zeroize as _;

use crate::error::FfiVaultError;
use crate::identity::UnlockedIdentity;

use super::inner::OpenVaultManifestInner;
use super::manifest::OpenVaultManifest;

/// Output of [`open_vault_with_password`] / [`open_vault_with_recovery`].
/// Holds two opaque handles — the live identity and the read-only manifest.
///
/// # Drop discipline
///
/// Fields drop in source order. Both handles zeroize their own inner state
/// on drop; the order is observable but not load-bearing.
///
/// Debug output is redacted via the fields' own Debug impls — no secret
/// material leaks through `{:?}`.
#[derive(Debug)]
pub struct OpenVaultOutput {
    /// Live opaque handle to the unlocked identity. Re-used unchanged from
    /// B.2 / B.3a / B.3b. Same `display_name()` / `user_uuid()` / `wipe()`
    /// accessors.
    pub identity: UnlockedIdentity,
    /// Opaque handle to the decrypted manifest. Holds the IBK, manifest
    /// body, manifest envelope, and verified owner card internally; B.4a
    /// exposes only read-only block-list accessors.
    pub manifest: OpenVaultManifest,
}

/// Open a vault folder using its master password. Reads `vault.toml`,
/// `identity.bundle.enc`, `manifest.cbor.enc`, and the owner contact card
/// from `folder`; performs full unlock + manifest decode + signature
/// verification. Returns two opaque handles: the live `UnlockedIdentity`
/// and the read-only `OpenVaultManifest`.
///
/// # Errors
///
/// Returns [`FfiVaultError`]; six possible variants. See module-level docs
/// on `crate::error` for the full surface.
pub fn open_vault_with_password(
    folder: &Path,
    password: &[u8],
) -> Result<OpenVaultOutput, FfiVaultError> {
    let pw = SecretBytes::new(password.to_vec());
    let core_out = secretary_core::vault::open_vault(folder, Unlocker::Password(&pw), None)?;
    Ok(split_core_open_vault(core_out, folder.to_path_buf()))
    // pw drops here → SecretBytes ZeroizeOnDrop wipes our local copy.
    // The caller's foreign-side password buffer is THEIR concern.
}

/// Open a vault folder using its 24-word BIP-39 recovery phrase. Reads the
/// same set of files as [`open_vault_with_password`]. The mnemonic input is
/// UTF-8 bytes; the bridge runs `std::str::from_utf8` and surfaces
/// malformed-UTF-8 input as [`FfiVaultError::InvalidMnemonic`] with
/// `detail: "phrase contained invalid UTF-8"` — same shape as B.3a's
/// [`crate::open_with_recovery`].
///
/// # Errors
///
/// Returns [`FfiVaultError`]; six possible variants.
pub fn open_vault_with_recovery(
    folder: &Path,
    mnemonic_bytes: &[u8],
) -> Result<OpenVaultOutput, FfiVaultError> {
    let phrase =
        std::str::from_utf8(mnemonic_bytes).map_err(|_| FfiVaultError::InvalidMnemonic {
            detail: "phrase contained invalid UTF-8".to_string(),
        })?;
    let core_out = secretary_core::vault::open_vault(folder, Unlocker::Recovery(phrase), None)?;
    Ok(split_core_open_vault(core_out, folder.to_path_buf()))
}

/// Split a `core::vault::OpenVault` into the two FFI handles.
///
/// `Sensitive<[u8; 32]>` does not implement `Clone`, so we copy the 32 raw
/// bytes out via `expose()` and mint a second `Sensitive` for the manifest
/// handle.  Both copies carry `ZeroizeOnDrop`; the intermediate stack array
/// is explicitly zeroized per `CLAUDE.md`'s stack-residue discipline.
pub(crate) fn split_core_open_vault(
    core_out: secretary_core::vault::OpenVault,
    vault_folder: std::path::PathBuf,
) -> OpenVaultOutput {
    let secretary_core::vault::OpenVault {
        identity_block_key,
        identity,
        owner_card,
        manifest,
        manifest_file,
    } = core_out;

    // Mint a second Sensitive copy for OpenVaultManifestInner.
    // identity_block_key.expose() returns &[u8; 32]; dereference copies the
    // 32-byte array onto the stack.  Sensitive::new moves that stack copy in,
    // but [u8; 32]: Copy so the stack slot is not cleared by the move.
    // Explicit zeroize per CLAUDE.md memory-hygiene-audit-internal §stack-residue.
    let mut ibk_bytes: [u8; 32] = *identity_block_key.expose();
    let ibk_for_manifest = Sensitive::new(ibk_bytes);
    ibk_bytes.zeroize();

    // UnlockedIdentity wraps the core unlock type (IBK + IdentityBundle).
    let unlocked_for_handle = secretary_core::unlock::UnlockedIdentity {
        identity_block_key,
        identity,
    };

    OpenVaultOutput {
        identity: UnlockedIdentity::new(unlocked_for_handle),
        manifest: OpenVaultManifest::new(OpenVaultManifestInner {
            identity_block_key: ibk_for_manifest,
            manifest,
            manifest_file,
            owner_card,
            vault_folder,
        }),
    }
}
