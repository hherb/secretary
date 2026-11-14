//! Session-vs-disk state checks for a long-lived [`OpenVault`] handle (#101).
//!
//! [`OpenVault`]: crate::vault::OpenVault

use std::path::Path;

use crate::vault::manifest::{self, ManifestFile};
use crate::vault::orchestrators::MANIFEST_FILENAME;
use crate::vault::VaultError;

/// Refuse a manifest write whose base is stale (design spec §5.2).
///
/// Reads `manifest.cbor.enc` and requires it to be byte-identical to the
/// encoding of `expected`, the envelope the session last loaded or wrote.
/// A mismatch means another open or the cloud client wrote a newer
/// manifest, and writing now would silently revert it, so this returns
/// [`VaultError::ManifestChangedOnDisk`]. Every writer that takes an
/// `OpenVault` calls this before its FIRST file write — not inside
/// `resign_and_write_manifest`, since `save_block` writes its block file
/// before that. Byte comparison is sound because the envelope encoding
/// round-trips exactly (`manifest_envelope_round_trips_byte_identically`).
///
/// Accepted residual: the check is not atomic with the write. A manifest
/// that lands between this read and the writer's rename is still
/// overwritten (check-then-write TOCTOU). Closing that needs a filesystem
/// compare-and-swap that cloud-synced folders do not offer.
pub(crate) fn ensure_manifest_unchanged_on_disk(
    folder: &Path,
    expected: &ManifestFile,
) -> Result<(), VaultError> {
    let on_disk = std::fs::read(folder.join(MANIFEST_FILENAME)).map_err(|e| VaultError::Io {
        context: "failed to read manifest.cbor.enc for the stale-session check",
        source: e,
    })?;
    if on_disk != manifest::encode_manifest_file(expected)? {
        return Err(VaultError::ManifestChangedOnDisk);
    }
    Ok(())
}
