//! `revoke_block` orchestration: decode caller-supplied ContactCard bytes,
//! snapshot the bridge handles, build a temporary `core::vault::OpenVault`,
//! call `core::vault::revoke_block_recipient`, write back the mutated
//! manifest + manifest_file on Ok, map errors per the spec §6 table.
//!
//! The near-exact inverse of [`crate::share::share_block`]: instead of
//! appending a recipient it removes one and re-keys for the remainder.
//! Step-for-step it mirrors share's orchestration wrapper (decode cards,
//! snapshot manifest, clone+extract+zeroize signing keys, build temp
//! `OpenVault`, call core, write manifest back). The only shape difference:
//! revoke takes `revoked_recipient_uuid: [u8; 16]` in place of share's
//! `new_recipient: &[u8]` and has no "card to persist" — revoke grants no
//! new access.
//!
//! Failure invariant: bridge in-memory state is byte-identical to pre-call
//! on Err. On-disk state may have a partial write (block file rewritten
//! but manifest re-sign failed): the manifest still points at the OLD
//! block fingerprint while the file holds the new bytes, so the next
//! `open_vault` read surfaces this as a `BlockFingerprintMismatch` and
//! the owner recovers it via the `vault-format.md` §6.5 re-fingerprint
//! path — identical to the `share_block` partial-write story. No silent
//! corruption: the inconsistency is detected, not swallowed. (The revoked
//! recipient is already gone from the re-keyed block on disk regardless.)

use rand_core::OsRng;
use secretary_core::crypto::secret::Sensitive;
use secretary_core::crypto::sig::{Ed25519Secret, MlDsa65Secret};
use secretary_core::identity::card::ContactCard;
use secretary_core::vault::{BlockUuid, DeviceUuid, OpenVault, RecipientUuid, VaultError};
use zeroize::Zeroize as _;

use crate::error::FfiVaultError;
use crate::identity::UnlockedIdentity;
use crate::vault::OpenVaultManifest;

/// Remove one recipient from an existing block and re-key for the remainder.
/// v1 single-author: only the vault's owner can revoke from blocks they
/// authored.
///
/// # Arguments
///
/// - `existing_recipient_cards`: canonical-CBOR bytes for EVERY recipient
///   currently in the block's wire-level recipient table, INCLUDING the
///   revoke target (core needs the full set to resolve the §6.2 wire table).
/// - `revoked_recipient_uuid`: the 16-byte `contact_uuid` of the recipient
///   to remove. Must currently be a recipient (else `RecipientNotPresent`)
///   and must not be the owner (else `CannotRevokeOwner`).
///
/// See spec §4 for the full argument contract; §6 for error mapping; §9
/// for the behavioral invariants this function pins.
///
/// # Errors
///
/// - [`FfiVaultError::CardDecodeFailure`] — any card byte slice fails
///   `ContactCard::from_canonical_cbor`.
/// - [`FfiVaultError::CorruptVault`] — either handle has been wiped;
///   manifest re-sign failure on already-validated inputs.
/// - [`FfiVaultError::FolderInvalid`] — IO failure during atomic write.
/// - [`FfiVaultError::BlockNotFound`] — `block_uuid` not in `manifest.blocks`.
/// - [`FfiVaultError::NotAuthor`] — calling identity is not the block's author.
/// - [`FfiVaultError::CannotRevokeOwner`] — `revoked_recipient_uuid` is the
///   owner; the owner must always remain a recipient.
/// - [`FfiVaultError::RecipientNotPresent`] — `revoked_recipient_uuid`'s
///   fingerprint does not appear in the wire-level recipient table.
/// - [`FfiVaultError::MissingRecipientCard`] — caller's
///   `existing_recipient_cards` did not cover every recipient on disk.
/// - [`FfiVaultError::SaveCryptoFailure`] — crypto / encoding failure on
///   already-validated inputs.
#[allow(clippy::too_many_arguments)]
pub fn revoke_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: [u8; 16],
    existing_recipient_cards: &[Vec<u8>],
    revoked_recipient_uuid: [u8; 16],
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<(), FfiVaultError> {
    // Step 0: decode every input card into core::ContactCard. Bytes-in is
    // the canonical wire shape (per spec §2 design decision). Any decode
    // failure surfaces as CardDecodeFailure — bridge-internal, never
    // reachable through From<core::VaultError>. Mirrors share's Step 0
    // (revoke has no second "new recipient" card to decode).
    let existing_decoded: Vec<ContactCard> = existing_recipient_cards
        .iter()
        .map(|b| ContactCard::from_canonical_cbor(b))
        .collect::<Result<_, _>>()
        .map_err(|e| FfiVaultError::CardDecodeFailure {
            detail: e.to_string(),
        })?;

    // Step 1: snapshot manifest under one lock acquisition. Re-uses save's
    // snapshot fn unchanged — revoke_block needs the same 5-tuple as share.
    let (manifest_body, manifest_file, owner_card, ibk, vault_folder) = manifest
        .snapshot_for_save_block()
        .ok_or_else(|| FfiVaultError::CorruptVault {
            detail: "vault manifest handle has been closed".into(),
        })?;

    // Step 2: snapshot identity. core::revoke_block_recipient takes the
    // signing keys as separate &Ed25519Secret + &MlDsa65Secret arguments
    // (exactly as core::share_block). We clone the bundle once for OpenVault
    // construction, derive the typed signing-key wrappers from that clone,
    // then zeroize the clone's signing-key fields in place so only one
    // zeroize-on-drop copy of each signing key is live for the rest of the
    // function (issue #42). The Ed25519 secret is materialized via a
    // named-and-zeroized stack buffer so no unnamed transient `[u8; 32]`
    // from the `*expose()` deref lingers — identical to share's wrapper.
    let mut identity_clone =
        identity
            .clone_inner_bundle()
            .ok_or_else(|| FfiVaultError::CorruptVault {
                detail: "identity handle has been closed".into(),
            })?;
    let mut sk_ed_bytes: [u8; 32] = *identity_clone.ed25519_sk.expose();
    let sk_ed: Ed25519Secret = Sensitive::new(sk_ed_bytes);
    sk_ed_bytes.zeroize();
    let sk_pq = MlDsa65Secret::from_bytes(identity_clone.ml_dsa_65_sk.expose()).map_err(|e| {
        FfiVaultError::CorruptVault {
            detail: format!("identity ML-DSA-65 secret parse failed: {e:?}"),
        }
    })?;
    identity_clone.ed25519_sk.zeroize();
    identity_clone.ml_dsa_65_sk.zeroize();

    // Step 3: build temporary OpenVault. owner_card serves as both the
    // OpenVault.owner_card field AND (cloned) the author_card argument
    // to core::revoke_block_recipient — for v1 single-author, owner ==
    // author.
    let author_card = owner_card.clone();
    let mut open_vault = OpenVault {
        identity_block_key: ibk,
        identity: identity_clone,
        owner_card,
        manifest: manifest_body,
        manifest_file,
    };

    // Step 4: call core. Single-recipient-remove (the inverse of share's
    // single-recipient-append).
    let result = secretary_core::vault::revoke_block_recipient(
        &vault_folder,
        &mut open_vault,
        BlockUuid::new(block_uuid),
        &author_card,
        &sk_ed,
        &sk_pq,
        &existing_decoded,
        RecipientUuid::new(revoked_recipient_uuid),
        DeviceUuid::new(device_uuid),
        now_ms,
        &mut OsRng,
    );

    // Step 5: on Ok, write back via the existing replace_manifest_and_file
    // helper. Failure-invariant matches share verbatim — bridge in-memory
    // state stays byte-identical to pre-call on Err.
    match result {
        Ok(()) => manifest
            .replace_manifest_and_file(open_vault.manifest, open_vault.manifest_file)
            .map_err(|e| FfiVaultError::CorruptVault {
                detail: e.to_string(),
            }),
        Err(e) => Err(map_core_vault_error_revoke(e)),
    }
}

/// Map [`secretary_core::vault::VaultError`] to [`FfiVaultError`] per the
/// spec §6 error table for revoke_block.
///
/// Identical in shape to share's `map_core_vault_error_share`: IO failures
/// fold to `FolderInvalid`; on-disk block-decode failures fold to
/// `CorruptVault`; the typed validation variants delegate to the existing
/// `From<core::VaultError>` impl; everything else (typed crypto / encoder
/// failures on already-validated inputs) folds to `SaveCryptoFailure`.
///
/// Per-variant arms (no `_ =>` catchall) per issue #40: adding a new
/// `core::VaultError` variant becomes a *compile* error here rather than
/// silently folding to `SaveCryptoFailure`, forcing a deliberate routing
/// decision at the revoke-mapper boundary.
fn map_core_vault_error_revoke(e: VaultError) -> FfiVaultError {
    match &e {
        VaultError::Io { context, source } => FfiVaultError::FolderInvalid {
            detail: format!("{context}: {source}"),
        },
        VaultError::Block(_) => FfiVaultError::CorruptVault {
            detail: format!("{e}"),
        },
        // Typed revoke-validation variants delegate to the From impl.
        // RecipientNotPresent / CannotRevokeOwner are the revoke-path
        // primaries; RecipientAlreadyPresent is share's sibling — all
        // delegate so the typed variant surfaces rather than folding to
        // SaveCryptoFailure.
        VaultError::NotAuthor { .. }
        | VaultError::RecipientAlreadyPresent
        | VaultError::RecipientNotPresent
        | VaultError::CannotRevokeOwner
        | VaultError::MissingRecipientCard { .. }
        | VaultError::BlockNotFound { .. } => e.into(),
        // Crypto / encoding / structural failures on already-validated
        // inputs. Listed explicitly so a new core variant cannot land
        // here without a compile-time choice.
        VaultError::Record(_)
        | VaultError::Manifest(_)
        | VaultError::Conflict(_)
        | VaultError::Rollback { .. }
        | VaultError::Unlock(_)
        | VaultError::Card(_)
        | VaultError::Sig(_)
        | VaultError::OwnerUuidMismatch { .. }
        | VaultError::ManifestAuthorMismatch
        | VaultError::ManifestVaultUuidMismatch { .. }
        | VaultError::KdfParamsMismatch
        | VaultError::ClockOverflow { .. }
        | VaultError::BlockUuidAlreadyLive { .. }
        | VaultError::BlockNotInTrash { .. }
        | VaultError::RestoreVerificationFailed { .. }
        // #205: restore-only; unreachable from revoke_block, listed for
        // exhaustiveness per issue #40.
        | VaultError::RestoreTargetMissing { .. }
        // Unreachable from revoke_block (open_vault always precedes
        // and would have surfaced this earlier), but listed for
        // exhaustiveness per issue #40. The generic `From<VaultError>`
        // impl routes this to `CorruptVault` on the read path.
        | VaultError::BlockFingerprintMismatch { .. }
        // ADR 0009 (B.1): unreachable from revoke_block; listed for
        // exhaustiveness per issue #40.
        | VaultError::DeviceSlotNotFound => FfiVaultError::SaveCryptoFailure {
            detail: format!("{e}"),
        },
    }
}
