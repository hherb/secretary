//! `commit_with_decisions` — disk-mutation half of the C.1.1b merge
//! commit path. Re-opens the vault, re-checks the manifest envelope
//! hash for TOCTOU freshness, applies decisions via
//! [`super::apply_decisions`], re-encrypts every diverging block with a
//! fresh AEAD nonce, builds + signs a new manifest, and atomically
//! writes block-first manifest-last per design doc §D6 / option (d).
//!
//! Per-file atomicity is delivered by [`crate::vault::io::write_atomic`]
//! (rename-on-`persist` via `tempfile`). Multi-file atomicity is NOT a
//! filesystem primitive — the manifest write is the commit point; pre-
//! manifest crashes are detected on the next `open_vault` and recovered
//! via re-running `sync_once → prepare_merge → commit_with_decisions`.
//! CRDT idempotence guarantees the retried convergence reaches the same
//! final state.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use rand_core::OsRng;
use zeroize::Zeroize;

use crate::crypto::aead;
use crate::crypto::hash::hash as blake3_hash;
use crate::crypto::kem::MlKem768Public;
use crate::crypto::secret::{SecretBytes, Sensitive};
use crate::crypto::sig::{Ed25519Secret, MlDsa65Secret};
use crate::identity::fingerprint::fingerprint;
use crate::sync::bundle::compute_manifest_hash;
use crate::sync::commit::apply_decisions;
use crate::sync::draft::{DraftMerge, RecordId, VetoDecision};
use crate::sync::error::SyncError;
use crate::sync::state::SyncState;
use crate::vault::block::VectorClockEntry;
use crate::vault::io::write_atomic;
use crate::vault::orchestrators::{
    format_uuid_hyphenated, open_vault, BLOCKS_SUBDIR, BLOCK_FILE_EXTENSION, MANIFEST_FILENAME,
};
use crate::vault::record::Record;
use crate::vault::{
    encode_block_file, encode_manifest_file, encrypt_block, sign_manifest, BlockHeader,
    BlockPlaintext, ManifestHeader, RecipientPublicKeys, Unlocker, FILE_KIND_BLOCK,
};

/// Block plaintext `block_version` for v1 (§6.3). v1 is the only value
/// v1 clients write.
const BLOCK_VERSION_V1: u32 = 1;

/// Block plaintext `schema_version` for v1 (§6.3). v1 is the only value
/// v1 clients write.
const SCHEMA_VERSION_V1: u32 = 1;

/// Atomic commit of a merged + decided vault state.
///
/// Re-opens the vault (verifies the manifest hybrid signature and runs
/// `verify_block_fingerprints` per design §D6), re-hashes the on-disk
/// manifest envelope for TOCTOU freshness against `draft.manifest_hash`,
/// applies the caller's [`VetoDecision`] slice via `apply_decisions`,
/// re-encrypts every diverging block with a fresh AEAD nonce and BLAKE3-
/// fingerprints the new bytes, builds a new manifest body (updated
/// `BlockEntry.fingerprint` / `vector_clock_summary` / `last_mod_ms`
/// plus the manifest-level `vector_clock`), hybrid-signs the manifest,
/// and atomically writes block-first then manifest-last.
///
/// On success, returns the new [`SyncState`] the caller persists into
/// the OS keystore.
///
/// # Errors
///
/// - [`SyncError::EvidenceStale`] — the on-disk manifest changed
///   between [`crate::sync::prepare_merge`] and this call. The disk is
///   untouched; caller retries from [`crate::sync::sync_once`].
/// - [`SyncError::MissingVetoDecision`] / [`SyncError::UnknownVetoDecision`]
///   — propagated from `apply_decisions` when `decisions` does not
///   form a bijection with `draft.vetoes`.
/// - [`SyncError::InvalidArgument`] — structural mismatch between
///   `draft` and the on-disk manifest (a `block_uuid` in
///   `draft.plan.diverging_blocks` missing from `draft.per_block_clocks`
///   / `draft.per_block_records` or from the cached `open.manifest`).
/// - [`SyncError::Vault`] — wraps any `open_vault`, AEAD encrypt,
///   encoding, signing, or `write_atomic` failure.
///
/// # Crash recovery (design §D6 / option (d))
///
/// If interrupted between a block write and the manifest write, the
/// next `open_vault` will fire
/// [`crate::vault::VaultError::BlockFingerprintMismatch`]. The caller
/// surfaces this and re-runs
/// `sync_once → prepare_merge → commit_with_decisions`. CRDT
/// idempotence guarantees the retried convergence reaches the same
/// final state.
pub fn commit_with_decisions(
    vault_folder: &Path,
    password: &SecretBytes,
    draft: DraftMerge,
    decisions: Vec<VetoDecision>,
    now_ms: u64,
) -> Result<SyncState, SyncError> {
    // Step 1: re-open the vault. open_vault re-verifies the manifest
    // signature AND runs verify_block_fingerprints (D6 gate) so a
    // commit-in-progress crash from a prior call surfaces as
    // VaultError::BlockFingerprintMismatch here rather than producing a
    // silently inconsistent state.
    let open =
        open_vault(vault_folder, Unlocker::Password(password), None).map_err(SyncError::Vault)?;

    // Step 2: TOCTOU freshness re-check. Read the manifest envelope
    // bytes off disk, BLAKE3-hash them, compare with the hash captured
    // by prepare_merge. open_vault already authenticated the on-disk
    // bytes; this raw re-read can race a concurrent writer between
    // step 1's open and this call, but either way we hash whatever the
    // current bytes are and compare.
    let manifest_path = vault_folder.join(MANIFEST_FILENAME);
    let envelope_bytes = std::fs::read(&manifest_path).map_err(|e| {
        SyncError::Vault(crate::vault::VaultError::Io {
            context: "failed to read manifest envelope for freshness re-check",
            source: e,
        })
    })?;
    if compute_manifest_hash(&envelope_bytes) != draft.manifest_hash {
        return Err(SyncError::EvidenceStale);
    }

    // Step 3: apply caller decisions. Bijection check + per-decision
    // KeepLocal restore. Errors surface as Missing/Unknown VetoDecision
    // before any disk writes happen.
    let post_decision_records = apply_decisions(&draft, &decisions)?;

    // Step 4: derive owner sender + recipient keys once. The golden
    // single-owner v1 model means author == recipient; the recipient
    // list contains exactly the owner, mirroring save_block / share_block.
    let bag = OwnerKeyBag::derive(&open)?;

    // Step 5: per-affected-block re-encrypt + atomic write. Block-first
    // ordering — the manifest write is the commit point (D6).
    let mut rng = OsRng;
    let mut new_block_entries: BTreeMap<[u8; 16], NewBlockEntry> = BTreeMap::new();
    for block_uuid in &draft.plan.diverging_blocks {
        let new_entry = rewrite_one_block(
            vault_folder,
            &mut rng,
            &open,
            &bag,
            *block_uuid,
            &draft,
            &post_decision_records,
            now_ms,
        )?;
        new_block_entries.insert(*block_uuid, new_entry);
    }

    // Step 6: build the new manifest body. Copy the cached manifest,
    // replace top-level vector_clock, update each affected block's
    // BlockEntry with the new fingerprint + per-block clock + last_mod_ms.
    let mut new_manifest = open.manifest.clone();
    new_manifest.vector_clock = draft.post_merge_clock.clone();
    for entry in new_manifest.blocks.iter_mut() {
        if let Some(new) = new_block_entries.get(&entry.block_uuid) {
            entry.fingerprint = new.fingerprint;
            entry.last_mod_ms = now_ms;
            entry.vector_clock_summary = new.vector_clock.clone();
        }
    }

    // #401: apply the reconciled trash list and resolve any live-vs-trash
    // collision so the signed manifest stays well-formed (disjoint
    // blocks/trash). Purge is terminal — a purged trash entry whose block
    // is (concurrently) live wins: the block is dropped, the entry kept.
    // A non-purged collision loses to the live block. commit never deletes
    // block *files*; the open-time sweep destroys purged ciphertext.
    let live_uuids: BTreeSet<[u8; 16]> = new_manifest.blocks.iter().map(|b| b.block_uuid).collect();
    let (blocks_to_remove, reconciled_trash) =
        crate::vault::resolve_live_vs_trash(&live_uuids, draft.merged_trash.clone());
    if !blocks_to_remove.is_empty() {
        new_manifest
            .blocks
            .retain(|b| !blocks_to_remove.contains(&b.block_uuid));
    }
    new_manifest.trash = reconciled_trash;

    // Step 7: sign + encode + atomic-write the manifest. The manifest
    // header preserves vault_uuid + created_at_ms from the prior
    // envelope; only last_mod_ms advances.
    let new_header = ManifestHeader {
        vault_uuid: open.manifest_file.header.vault_uuid,
        created_at_ms: open.manifest_file.header.created_at_ms,
        last_mod_ms: now_ms,
    };
    let aead_nonce = aead::random_nonce(&mut rng);
    let new_manifest_file = sign_manifest(
        new_header,
        &new_manifest,
        &open.identity_block_key,
        &aead_nonce,
        bag.owner_fp,
        &bag.owner_ed_sk,
        &bag.owner_pq_sk,
    )
    .map_err(crate::vault::VaultError::from)?;
    let manifest_bytes =
        encode_manifest_file(&new_manifest_file).map_err(crate::vault::VaultError::from)?;
    write_atomic(&manifest_path, &manifest_bytes).map_err(|e| {
        SyncError::Vault(crate::vault::VaultError::Io {
            context: "failed to write manifest during commit",
            source: e,
        })
    })?;

    let post_merge_clock = draft.post_merge_clock.clone();
    let vault_uuid = draft.vault_uuid;
    // Drop `draft` and `bag` explicitly so secret-bearing fields wipe
    // on drop in source order. `draft` holds plaintext `Record`s with
    // `SecretString`/`SecretBytes` field values that wipe via their own
    // `ZeroizeOnDrop`; `bag` holds Ed25519 + ML-DSA-65 secrets that
    // wipe via `Sensitive` / `MlDsa65Secret`.
    drop(draft);
    drop(bag);

    SyncState::new(vault_uuid, post_merge_clock)
}

/// Stash of owner sender + recipient keys derived once per
/// [`commit_with_decisions`] call. Holds the typed-wrapped Ed25519 and
/// ML-DSA-65 secret keys (both zeroize on drop via [`Sensitive`] /
/// [`MlDsa65Secret`]), the owner's public key bundle bytes, and the
/// owner contact fingerprint. Pre-parsed ML-KEM-768 public key is kept
/// alongside so the per-block recipient list can borrow it without
/// re-parsing per iteration.
struct OwnerKeyBag {
    owner_fp: [u8; 16],
    owner_pk_bundle: Vec<u8>,
    owner_ed_sk: Ed25519Secret,
    owner_pq_sk: MlDsa65Secret,
    owner_ml_kem_pk: MlKem768Public,
    x25519_pk: [u8; 32],
}

impl OwnerKeyBag {
    /// Derive the owner sender + recipient keys from an already-opened
    /// vault handle. Mirrors `save_block`'s step-4 owner-key setup. The
    /// stack copy of the Ed25519 SK is zeroized immediately after
    /// wrapping in [`Sensitive`] (`[u8; 32]: Copy` move-residue pattern,
    /// per CLAUDE.md memory hygiene).
    fn derive(open: &crate::vault::OpenVault) -> Result<Self, SyncError> {
        let owner_card_bytes = open
            .owner_card
            .to_canonical_cbor()
            .map_err(crate::vault::VaultError::from)?;
        let owner_fp = fingerprint(&owner_card_bytes);
        let owner_pk_bundle = open
            .owner_card
            .pk_bundle_bytes()
            .map_err(crate::vault::VaultError::from)?;
        let mut ed_sk_bytes = *open.identity.ed25519_sk.expose();
        let owner_ed_sk: Ed25519Secret = Sensitive::new(ed_sk_bytes);
        ed_sk_bytes.zeroize();
        let owner_pq_sk = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose())
            .map_err(crate::vault::VaultError::from)?;
        // KemError → BlockError → VaultError per the existing
        // conversion chain (BlockError::Kem `#[from] KemError`).
        let owner_ml_kem_pk = MlKem768Public::from_bytes(&open.owner_card.ml_kem_768_pk)
            .map_err(|e| crate::vault::VaultError::from(crate::vault::BlockError::from(e)))?;
        Ok(Self {
            owner_fp,
            owner_pk_bundle,
            owner_ed_sk,
            owner_pq_sk,
            owner_ml_kem_pk,
            x25519_pk: open.owner_card.x25519_pk,
        })
    }

    /// Recipient list view referencing the bag's owned keys. Single-
    /// owner v1 vault → exactly one recipient, the owner.
    fn recipient_keys(&self) -> Vec<RecipientPublicKeys<'_>> {
        vec![RecipientPublicKeys {
            fingerprint: self.owner_fp,
            pk_bundle: &self.owner_pk_bundle,
            x25519_pk: &self.x25519_pk,
            ml_kem_768_pk: &self.owner_ml_kem_pk,
        }]
    }
}

/// What [`rewrite_one_block`] returns to drive the manifest body update.
struct NewBlockEntry {
    fingerprint: [u8; 32],
    vector_clock: Vec<VectorClockEntry>,
}

/// Re-encrypt a single diverging block: filter `post_decision_records`
/// by the per-block record assignment in the draft, build the
/// [`BlockHeader`] + [`BlockPlaintext`], encrypt + sign, atomic-write
/// the new bytes to `blocks/<uuid>.cbor.enc`. Returns the new
/// BLAKE3-256 fingerprint and the per-block vector clock for the
/// manifest body update.
#[allow(clippy::too_many_arguments)]
fn rewrite_one_block(
    vault_folder: &Path,
    rng: &mut OsRng,
    open: &crate::vault::OpenVault,
    bag: &OwnerKeyBag,
    block_uuid: [u8; 16],
    draft: &DraftMerge,
    post_decision_records: &[Record],
    now_ms: u64,
) -> Result<NewBlockEntry, SyncError> {
    let block_clock = draft
        .per_block_clocks
        .get(&block_uuid)
        .cloned()
        .ok_or_else(|| SyncError::InvalidArgument {
            detail: format!("draft.per_block_clocks missing block {block_uuid:02x?}"),
        })?;
    let record_uuids =
        draft
            .per_block_records
            .get(&block_uuid)
            .ok_or_else(|| SyncError::InvalidArgument {
                detail: format!("draft.per_block_records missing block {block_uuid:02x?}"),
            })?;
    let record_id_set: BTreeSet<RecordId> = record_uuids.iter().copied().collect();
    let records_for_block: Vec<Record> = post_decision_records
        .iter()
        .filter(|r| record_id_set.contains(&r.record_uuid))
        .cloned()
        .collect();

    let existing_entry = open
        .manifest
        .blocks
        .iter()
        .find(|b| b.block_uuid == block_uuid)
        .ok_or_else(|| SyncError::InvalidArgument {
            detail: format!("manifest missing block {block_uuid:02x?} after merge"),
        })?;

    let header = BlockHeader {
        magic: crate::version::MAGIC,
        format_version: crate::version::FORMAT_VERSION,
        suite_id: crate::version::SUITE_ID,
        file_kind: FILE_KIND_BLOCK,
        vault_uuid: open.manifest.vault_uuid,
        block_uuid,
        created_at_ms: existing_entry.created_at_ms,
        last_mod_ms: now_ms,
        vector_clock: block_clock.clone(),
    };
    let plaintext = BlockPlaintext {
        block_version: BLOCK_VERSION_V1,
        block_uuid,
        block_name: existing_entry.block_name.clone(),
        schema_version: SCHEMA_VERSION_V1,
        records: records_for_block,
        unknown: BTreeMap::new(),
    };

    let recipients = bag.recipient_keys();
    let block_file = encrypt_block(
        rng,
        &header,
        &plaintext,
        &bag.owner_fp,
        &bag.owner_pk_bundle,
        &bag.owner_ed_sk,
        &bag.owner_pq_sk,
        &recipients,
    )
    .map_err(crate::vault::VaultError::from)?;
    let bytes = encode_block_file(&block_file).map_err(crate::vault::VaultError::from)?;
    let fingerprint = *blake3_hash(&bytes).as_bytes();

    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    let path = vault_folder
        .join(BLOCKS_SUBDIR)
        .join(format!("{uuid_hex}{BLOCK_FILE_EXTENSION}"));
    // Ensure blocks/ exists. The golden vault always has it, but
    // rewriting into a sparser fixture (or a future test that fresh-
    // creates a vault) is supported by mkdir_p semantics here.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            SyncError::Vault(crate::vault::VaultError::Io {
                context: "failed to create blocks/ subdirectory during commit",
                source: e,
            })
        })?;
    }
    write_atomic(&path, &bytes).map_err(|e| {
        SyncError::Vault(crate::vault::VaultError::Io {
            context: "failed to write block during commit",
            source: e,
        })
    })?;

    Ok(NewBlockEntry {
        fingerprint,
        vector_clock: block_clock,
    })
}
