//! `share_block` orchestration: decode caller-supplied ContactCard bytes,
//! snapshot the bridge handles, build a temporary `core::vault::OpenVault`,
//! call `core::vault::share_block`, write back the mutated manifest +
//! manifest_file on Ok, map errors per the spec §6 table.
//!
//! Failure invariant: bridge in-memory state is byte-identical to pre-call
//! on Err. On-disk state may have a partial write (block file rewritten
//! but manifest re-sign failed) — harmless because `open_vault` reads
//! only entries listed in the manifest.
//!
//! Rationale: docs/superpowers/specs/2026-05-10-ffi-b4d-share-block-design.md.

use rand_core::OsRng;
use secretary_core::crypto::secret::Sensitive;
use secretary_core::crypto::sig::{Ed25519Secret, MlDsa65Secret};
use secretary_core::identity::card::ContactCard;
use secretary_core::vault::{OpenVault, VaultError};
use zeroize::Zeroize as _;

use crate::error::FfiVaultError;
use crate::identity::UnlockedIdentity;
use crate::vault::OpenVaultManifest;

/// Append one new recipient to an existing block. v1 single-author: only
/// the vault's owner can share blocks they authored.
///
/// # Arguments
///
/// - `existing_recipient_cards`: canonical-CBOR bytes for EVERY recipient
///   currently in the block's wire-level recipient table, including the
///   author if the author is also a recipient. For a freshly-saved v1
///   block this is `[manifest.owner_card_bytes()??]` (outer `?` for the
///   `Result`; inner `?` for the `Option`).
/// - `new_recipient`: canonical-CBOR bytes of the contact card being
///   added. Must NOT already appear in the existing list (per fingerprint).
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
/// - [`FfiVaultError::RecipientAlreadyPresent`] — `new_recipient`'s
///   fingerprint already appears in the wire-level recipient table.
/// - [`FfiVaultError::MissingRecipientCard`] — caller's
///   `existing_recipient_cards` did not cover every recipient on disk.
/// - [`FfiVaultError::SaveCryptoFailure`] — crypto / encoding failure on
///   already-validated inputs.
#[allow(clippy::too_many_arguments)]
pub fn share_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: [u8; 16],
    existing_recipient_cards: &[Vec<u8>],
    new_recipient: &[u8],
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<(), FfiVaultError> {
    // Step 0: decode every input card into core::ContactCard. Bytes-in is
    // the canonical wire shape (per spec §2 design decision). Any decode
    // failure surfaces as CardDecodeFailure — bridge-internal, never
    // reachable through From<core::VaultError>.
    let existing_decoded: Vec<ContactCard> = existing_recipient_cards
        .iter()
        .map(|b| ContactCard::from_canonical_cbor(b))
        .collect::<Result<_, _>>()
        .map_err(|e| FfiVaultError::CardDecodeFailure {
            detail: e.to_string(),
        })?;
    let new_decoded = ContactCard::from_canonical_cbor(new_recipient).map_err(|e| {
        FfiVaultError::CardDecodeFailure {
            detail: e.to_string(),
        }
    })?;

    // Step 1: snapshot manifest under one lock acquisition. Re-uses save's
    // snapshot fn unchanged — share_block needs the same 5-tuple.
    let (manifest_body, manifest_file, owner_card, ibk, vault_folder) = manifest
        .snapshot_for_save_block()
        .ok_or_else(|| FfiVaultError::CorruptVault {
            detail: "vault manifest handle has been closed".into(),
        })?;

    // Step 2: snapshot identity. core::share_block takes the signing keys
    // as separate &Ed25519Secret + &MlDsa65Secret arguments (unlike
    // save_block, which derives them from open_vault.identity). We clone
    // the bundle once for OpenVault construction, derive the typed
    // signing-key wrappers from that clone, then zeroize the clone's
    // signing-key fields in place so only one zeroize-on-drop copy of
    // each signing key is live for the rest of the function (issue #42).
    //
    // core::share_block reads only the *reader* fields
    // (`x25519_sk` / `ml_kem_768_sk`) off `open.identity` — for the §7
    // decrypt path. The signer fields on the bundle are not consumed by
    // core::share_block; zero'ing them is a memory-hygiene refinement,
    // not a functional change. The author signature is produced from
    // `&sk_ed` / `&sk_pq` passed separately.
    //
    // The Ed25519 secret is materialized via a named-and-zeroized stack
    // buffer so that no unnamed transient `[u8; 32]` from the `*expose()`
    // deref lingers in a stack slot the rest of the function can't reach.
    // After the explicit `zeroize()` on `sk_ed_bytes`, the only live
    // Ed25519 secret in scope is the `Sensitive`-wrapped one inside
    // `sk_ed` (zeroize-on-drop). For ML-DSA-65, `from_bytes` reads the
    // bytes through a borrowed slice and copies internally — no
    // intermediate stack buffer to clean up on the bridge side.
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
    // to core::share_block — for v1 single-author, owner == author.
    let author_card = owner_card.clone();
    let mut open_vault = OpenVault {
        identity_block_key: ibk,
        identity: identity_clone,
        owner_card,
        manifest: manifest_body,
        manifest_file,
    };

    // Step 4: call core. Single-recipient-append.
    let result = secretary_core::vault::share_block(
        &vault_folder,
        &mut open_vault,
        block_uuid,
        &author_card,
        &sk_ed,
        &sk_pq,
        &existing_decoded,
        &new_decoded,
        device_uuid,
        now_ms,
        &mut OsRng,
    );

    // Step 5: on Ok, write back via the existing replace_manifest_and_file
    // helper. Failure-invariant matches B.4c verbatim — bridge in-memory
    // state stays byte-identical to pre-call on Err.
    match result {
        Ok(()) => manifest
            .replace_manifest_and_file(open_vault.manifest, open_vault.manifest_file)
            .map_err(|e| FfiVaultError::CorruptVault {
                detail: e.to_string(),
            }),
        Err(e) => Err(map_core_vault_error_share(e)),
    }
}

/// Map [`secretary_core::vault::VaultError`] to [`FfiVaultError`] per the
/// spec §6 error table for share_block.
///
/// IO failures fold to `FolderInvalid`. On-disk block-decode failures
/// (Step 2 of core::share_block reads the block file) fold to
/// `CorruptVault`. NotAuthor / RecipientAlreadyPresent /
/// MissingRecipientCard / BlockNotFound delegate to the existing
/// `From<core::VaultError>` impl in [`crate::error`], which maps them to
/// the matching typed FFI variants. Everything else (typed crypto /
/// encoder failures on already-validated inputs) folds to
/// `SaveCryptoFailure`.
///
/// Per-variant arms (no `_ =>` catchall) per issue #40: adding a new
/// `core::VaultError` variant becomes a *compile* error here rather than
/// silently folding to `SaveCryptoFailure`, forcing a deliberate routing
/// decision at the share-mapper boundary.
fn map_core_vault_error_share(e: VaultError) -> FfiVaultError {
    match &e {
        VaultError::Io { context, source } => FfiVaultError::FolderInvalid {
            detail: format!("{context}: {source}"),
        },
        VaultError::Block(_) => FfiVaultError::CorruptVault {
            detail: format!("{e}"),
        },
        // Typed share-validation variants delegate to the From impl.
        VaultError::NotAuthor { .. }
        | VaultError::RecipientAlreadyPresent
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
        // Unreachable from share_block (open_vault always precedes
        // and would have surfaced this earlier), but listed for
        // exhaustiveness per issue #40. The generic `From<VaultError>`
        // impl routes this to `CorruptVault` on the read path.
        | VaultError::BlockFingerprintMismatch { .. } => FfiVaultError::SaveCryptoFailure {
            detail: format!("{e}"),
        },
    }
}
