//! Session-vs-disk state checks for a long-lived [`OpenVault`] handle (#101).
//!
//! [`OpenVault`]: crate::vault::OpenVault

use std::collections::BTreeSet;
use std::path::Path;

use crate::identity::card::ContactCard;
use crate::unlock::UnlockedIdentity;
use crate::vault::manifest::{self, Manifest, ManifestFile};
use crate::vault::orchestrators::{
    read_and_verify_manifest, verify_block_fingerprints, MANIFEST_FILENAME, VAULT_TOML_FILENAME,
};
use crate::vault::{repair, VaultError, VectorClockEntry};

/// The public half of an opened vault: what [`verify_vault_state`] proves
/// about the folder on disk, without any identity secret.
#[derive(Debug)]
pub struct VerifiedVaultState {
    /// Owner contact card, self-verified and key-bound to the identity.
    pub owner_card: ContactCard,
    /// Decrypted, authenticated manifest body (§4.2).
    pub manifest: Manifest,
    /// The on-disk manifest envelope (§4.1) the body was read from.
    pub manifest_file: ManifestFile,
}

/// Re-verify a vault folder with an already-unlocked identity (design spec
/// §5.1): everything [`open_vault`] does after the identity unlock, in the
/// same order, so open, the merge commit and a session refresh cannot drift.
///
/// Reads `vault.toml`, then runs `verify_vault_state_with_toml`. The re-read
/// serves only the §4.3 step 6 cross-check of `vault.toml [kdf]` against the
/// signed manifest body (`VaultError::KdfParamsMismatch`); this function
/// compares no `vault.toml` field other than `[kdf]` (its `vault_uuid` check
/// is the manifest header against the body). The identity's binding to this
/// folder is NOT established here: it comes from the unlock that produced
/// `identity` plus the manifest's AEAD under that identity's IBK, which
/// fails for any other vault's manifest.
///
/// [`open_vault`]: crate::vault::open_vault
pub fn verify_vault_state(
    folder: &Path,
    identity: &UnlockedIdentity,
    local_highest_clock: Option<&[VectorClockEntry]>,
) -> Result<VerifiedVaultState, VaultError> {
    let vault_toml_bytes =
        std::fs::read(folder.join(VAULT_TOML_FILENAME)).map_err(|e| VaultError::Io {
            context: "failed to read vault.toml",
            source: e,
        })?;
    verify_vault_state_with_toml(
        folder,
        &vault_toml_bytes,
        identity,
        local_highest_clock,
        &BTreeSet::new(),
    )
}

/// [`verify_vault_state`] for a merge commit that removes the blocks in
/// `trashed_by_merge` from `blocks` (crypto-design §11.6): their files are
/// not fingerprint-checked. The commit reads and writes none of them, and the
/// device that trashed one has moved its file to `trash/`.
pub(crate) fn verify_vault_state_for_merge(
    folder: &Path,
    identity: &UnlockedIdentity,
    trashed_by_merge: &BTreeSet<[u8; 16]>,
) -> Result<VerifiedVaultState, VaultError> {
    let vault_toml_bytes =
        std::fs::read(folder.join(VAULT_TOML_FILENAME)).map_err(|e| VaultError::Io {
            context: "failed to read vault.toml",
            source: e,
        })?;
    verify_vault_state_with_toml(folder, &vault_toml_bytes, identity, None, trashed_by_merge)
}

/// [`verify_vault_state`] over `vault.toml` bytes the caller already holds,
/// so `open_vault` does not read the file twice.
pub(crate) fn verify_vault_state_with_toml(
    folder: &Path,
    vault_toml_bytes: &[u8],
    identity: &UnlockedIdentity,
    local_highest_clock: Option<&[VectorClockEntry]>,
    skip_block_files: &BTreeSet<[u8; 16]>,
) -> Result<VerifiedVaultState, VaultError> {
    // Steps 3-8: read manifest envelope, load + verify owner card,
    // verify + decrypt manifest, sanity-check body↔envelope and
    // body↔vault.toml, optional rollback check. Shared with
    // `read_vault_manifest` so a caller that already holds an
    // UnlockedIdentity does not re-run Argon2 just to inspect the
    // manifest body.
    //
    // `_manifest_envelope_bytes` (raw on-disk bytes of `manifest.cbor.enc`)
    // is discarded here — `open_vault` doesn't need them. The C.1.1a
    // sync_once Concurrent path uses them via `read_vault_manifest_full`
    // to compute the freshness `ManifestHash` without re-reading the file
    // (see #80).
    let (owner_card, manifest_body, manifest_file, _manifest_envelope_bytes) =
        read_and_verify_manifest(folder, vault_toml_bytes, identity, local_highest_clock)?;

    // C.1.1b D6: verify each on-disk block file's BLAKE3 fingerprint
    // matches `BlockEntry.fingerprint` in the (now-authenticated)
    // manifest. Closes the partial-commit window where a
    // `commit_with_decisions` crash between block writes and the
    // manifest write would leave a mismatched on-disk state. The
    // mismatch surfaces as `VaultError::BlockFingerprintMismatch` —
    // recovery is to re-run `sync_once → prepare_merge →
    // commit_with_decisions`, which is convergent under CRDT
    // idempotence.
    if skip_block_files.is_empty() {
        verify_block_fingerprints(folder, &manifest_body)?;
    } else {
        let mut checked = manifest_body.clone();
        checked
            .blocks
            .retain(|b| !skip_block_files.contains(&b.block_uuid));
        verify_block_fingerprints(folder, &checked)?;
    }

    // #350: best-effort completion of trash renames interrupted between
    // trash_block's manifest commit and its physical move. Rename-only
    // and gated on the signed TrashEntry.fingerprint — see
    // repair::complete_pending_trash_renames.
    repair::complete_pending_trash_renames(folder, &manifest_body);

    // #399: best-effort removal of local trash/ files for entries the
    // signed manifest already marks purged — this is what propagates a
    // purge across the owner's devices via manifest file sync. Gated on
    // "not live in manifest.blocks" so a concurrent restore always wins.
    repair::sweep_purged_trash_files(folder, &manifest_body);

    Ok(VerifiedVaultState {
        owner_card,
        manifest: manifest_body,
        manifest_file,
    })
}

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
