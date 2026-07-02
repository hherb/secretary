//! #350 crash-recovery: the open-time trash-completion sweep (this
//! task) and the explicit [`repair_vault`] orchestrator (added on top).
//!
//! Split out of `orchestrators.rs` (already ~2.8k lines) — one concept
//! per file: everything here exists to converge a crash-interrupted
//! vault back to the §6.5/§7 on-disk shape without weakening the
//! manifest-as-integrity-commitment.

use std::collections::BTreeSet;
use std::path::Path;

use rand_core::{CryptoRng, RngCore};

use zeroize::Zeroize as _;

use crate::crypto::aead;
use crate::crypto::hash::hash as blake3_hash;
use crate::crypto::kem::{self, MlKem768Secret};
use crate::crypto::secret::Sensitive;
use crate::crypto::sig::{Ed25519Secret, MlDsa65Public, MlDsa65Secret};
use crate::identity::fingerprint::fingerprint;

use super::conflict::{clock_relation, ClockRelation};
use super::manifest::{self, BlockEntry, Manifest, ManifestHeader};
use super::orchestrators::{
    format_uuid_hyphenated, read_and_verify_manifest, resolve_recipient_uuids, tick_clock,
    unlock_vault_identity, OpenVault, Unlocker, BLOCKS_SUBDIR, BLOCK_FILE_EXTENSION,
    MANIFEST_FILENAME, TRASH_SUBDIR,
};
use super::{block, io};
use super::{VaultError, VectorClockEntry};

/// Best-effort completion of trash renames interrupted between
/// `trash_block`'s manifest commit and its physical move (#350).
///
/// For every signed `TrashEntry` whose §7 trash file is absent: if the
/// UUID is not live in `manifest.blocks` and `blocks/<uuid>.cbor.enc`
/// exists with bytes hashing to the entry's signed `fingerprint`, the
/// file is renamed to `trash/<uuid>.cbor.enc.<tombstoned_at_ms>`.
///
/// Rename-only: no manifest mutation, no signing, no trust-state
/// change — the gate is the *signed* content commitment, so an attacker
/// who plants an arbitrary `blocks/` file cannot steer the sweep.
/// Idempotent; every I/O failure is swallowed (a vault that cannot
/// complete the move, e.g. cross-filesystem trash/, stays in the benign
/// orphan state that `restore_block` resumes from).
pub(crate) fn complete_pending_trash_renames(folder: &Path, manifest: &Manifest) {
    let trash_dir = folder.join(TRASH_SUBDIR);
    let blocks_dir = folder.join(BLOCKS_SUBDIR);
    for entry in &manifest.trash {
        // Legacy pre-#293 entry: no signed commitment → no safe gate.
        let Some(committed_fp) = entry.fingerprint else {
            continue;
        };
        // Live-and-trashed (trash → re-save same uuid): never touch the
        // live file, regardless of hashes.
        if manifest
            .blocks
            .iter()
            .any(|b| b.block_uuid == entry.block_uuid)
        {
            continue;
        }
        let uuid_hex = format_uuid_hyphenated(&entry.block_uuid);
        let trash_path = trash_dir.join(format!(
            "{uuid_hex}{BLOCK_FILE_EXTENSION}.{}",
            entry.tombstoned_at_ms
        ));
        if trash_path.exists() {
            continue; // move already completed
        }
        let blocks_path = blocks_dir.join(format!("{uuid_hex}{BLOCK_FILE_EXTENSION}"));
        let Ok(bytes) = std::fs::read(&blocks_path) else {
            continue; // no orphan (or unreadable — best-effort)
        };
        if *blake3_hash(&bytes).as_bytes() != committed_fp {
            continue; // not the committed bytes — planted or clobbered
        }
        let _ = std::fs::create_dir_all(&trash_dir)
            .and_then(|()| std::fs::rename(&blocks_path, &trash_path));
    }
}

/// Explicit crash-recovery orchestrator (#350): adopt on-disk block
/// residue that `open_vault` refuses to open.
///
/// A crash between a block-file write and the manifest write (inside
/// `save_block`, `share_block`, `revoke_block_recipient`, or any future
/// re-key path) leaves `blocks/<uuid>.cbor.enc` holding bytes newer than
/// the manifest's committed `BlockEntry.fingerprint` — `open_vault`
/// correctly refuses this as [`VaultError::BlockFingerprintMismatch`]
/// rather than silently picking a side. `repair_vault` is the explicit,
/// opt-in recovery path a caller invokes after that refusal.
///
/// For every mismatched block, adoption is gated on **three** checks, all
/// of which must pass:
/// 1. **Authenticity** — the on-disk file must decode, AEAD-decrypt, and
///    hybrid-verify (Ed25519 ∧ ML-DSA-65, both halves) under the vault
///    owner's card, plus its `block_uuid` / `vault_uuid` header fields
///    must match the manifest entry and this vault.
/// 2. **Freshness** — the on-disk file must be verifiably newer than the
///    manifest's committed entry, judged ONLY on signed, attacker-
///    unforgeable structure (authenticity is not currency: an
///    owner-signed *older* copy verifies fine, and `last_mod_ms` is
///    caller wall-clock with no monotonicity guarantee, so timestamps
///    are deliberately NOT part of this gate). Two-tier rule:
///    - [`ClockRelation::IncomingDominates`] against
///      `vector_clock_summary` — an interrupted `save_block` (content
///      changed, so the block's own clock ticked). Adopted.
///    - [`ClockRelation::Equal`] — the residue of a content-preserving
///      re-key (`share_block` / `revoke_block_recipient` via
///      `rewrite_block_with_recipients`, which deliberately preserves
///      the block clock). Adopted ONLY IF the file's resolved recipient
///      set is a **strict subset** of the committed
///      `BlockEntry.recipients` (subset AND not equal). Soundness rests
///      on an invariant verified at `rewrite_block_with_recipients`
///      step 9/10 (see the guard comment there): within an equal-clock
///      class every legitimate writer re-encrypts the *identical
///      plaintext* — only the recipient set can differ — so a strict
///      subset can only NARROW access. Fail-closed: the worst outcome
///      an attacker replaying retained owner-signed re-key bytes can
///      force is an un-share, recoverable by re-sharing; re-GRANTING
///      access (the superset direction, e.g. resurrecting a revoked
///      recipient) is always refused. Equal sets with different bytes
///      are also refused — no legitimate crashed operation has that
///      shape (stale-replay / forgery). Consequence: the residue of a
///      crashed `share_block` (a genuine superset) is NOT auto-adopted
///      — a documented limitation until an informed-consent adoption
///      path ships with the FFI projection; the rejection `detail`
///      names the recipients that would be added.
///    - Everything else (`IncomingDominated` = rollback plant,
///      `Concurrent` = torn multi-device state this function must not
///      guess about) is refused.
/// 3. **Recipient resolution** — every wrap's `recipient_fingerprint`
///    must resolve to a known `contacts/*.card` UUID via
///    `resolve_recipient_uuids`, so the rebuilt entry's recipient list
///    reflects the on-disk §6.2 table (the *reduced* set after a
///    crashed revocation re-key), not the stale manifest one.
///
/// **All-or-nothing.** Pass 1 is read-only classification over every
/// manifest block; the first gate failure returns
/// [`VaultError::RepairRejected`] (or [`VaultError::BlockFileMissing`]
/// for an absent file — not repairable, repair cannot invent bytes)
/// before anything is staged or written. Only once every mismatched
/// block has cleared all three gates does this function re-sign and
/// atomically write a single updated manifest. A healthy vault (no
/// mismatches) degrades to a plain open — **idempotent**, safe to call
/// speculatively.
///
/// Goes through the same `unlock_vault_identity` +
/// `read_and_verify_manifest` §1 verify-before-decrypt sequence as
/// `open_vault` — the repair path is never a weaker open than a normal
/// one; it only widens what happens *after* the manifest is
/// authenticated.
///
/// The same open-time sweep this module runs for `open_vault`
/// (`complete_pending_trash_renames`) also runs here. That sweep
/// additionally relocates the residue of a *crashed `restore_block`*
/// (the #351 shape: the manifest still holds the signed `TrashEntry`
/// while the file has already been renamed into `blocks/`) back to
/// `trash/`. That relocation is harmless even though it is not a
/// `repair_vault`-gated adoption: a subsequent `restore_block` simply
/// proceeds via its normal trash-file path instead of its `#351` resume
/// path.
pub fn repair_vault(
    folder: &Path,
    unlocker: Unlocker<'_>,
    local_highest_clock: Option<&[VectorClockEntry]>,
    device_uuid: [u8; 16],
    now_ms: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<OpenVault, VaultError> {
    // Same unlock + §10-checked manifest verify as open_vault.
    let (vault_toml_bytes, unlocked) = unlock_vault_identity(folder, unlocker)?;
    let (owner_card, mut manifest, manifest_file, _envelope_bytes) =
        read_and_verify_manifest(folder, &vault_toml_bytes, &unlocked, local_highest_clock)?;

    // Owner verify/decrypt keys — mirrors restore_block's key prep,
    // hoisted once outside the per-block loop. Zeroize the stack copy.
    let owner_pk_bundle = owner_card.pk_bundle_bytes()?;
    let owner_fp = fingerprint(&owner_card.to_canonical_cbor()?);
    let owner_pq_pk = MlDsa65Public::from_bytes(&owner_card.ml_dsa_65_pk)?;
    let mut x_sk_bytes = *unlocked.identity.x25519_sk.expose();
    let owner_x_sk: kem::X25519Secret = Sensitive::new(x_sk_bytes);
    x_sk_bytes.zeroize();
    let owner_pq_sk_reader = MlKem768Secret::from_bytes(unlocked.identity.ml_kem_768_sk.expose())
        .map_err(block::BlockError::from)?;

    // Pass 1 — read-only classification. All-or-nothing: any gate
    // failure returns before anything is staged or written.
    let blocks_dir = folder.join(BLOCKS_SUBDIR);
    let mut adoptions: Vec<(usize, BlockEntry)> = Vec::new();
    for (idx, entry) in manifest.blocks.iter().enumerate() {
        let uuid_hex = format_uuid_hyphenated(&entry.block_uuid);
        let path = blocks_dir.join(format!("{uuid_hex}{BLOCK_FILE_EXTENSION}"));
        let bytes = std::fs::read(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                VaultError::BlockFileMissing {
                    block_uuid: entry.block_uuid,
                }
            } else {
                VaultError::Io {
                    context: "repair_vault: failed to read block file",
                    source: e,
                }
            }
        })?;
        let got = *blake3_hash(&bytes).as_bytes();
        if got == entry.fingerprint {
            continue; // healthy
        }
        // Gate 1 — authenticity: decode + AEAD-decrypt + hybrid verify
        // (Ed25519 ∧ ML-DSA-65, both halves) under the owner card.
        let block_file =
            block::decode_block_file(&bytes).map_err(|e| VaultError::RepairRejected {
                block_uuid: entry.block_uuid,
                detail: format!("decode: {e}"),
            })?;
        // Gate 2 — binding: the file must BE this block of this vault.
        if block_file.header.block_uuid != entry.block_uuid {
            return Err(VaultError::RepairRejected {
                block_uuid: entry.block_uuid,
                detail: "file header block_uuid does not match the manifest entry".to_string(),
            });
        }
        if block_file.header.vault_uuid != manifest.vault_uuid {
            return Err(VaultError::RepairRejected {
                block_uuid: entry.block_uuid,
                detail: "file header vault_uuid does not match this vault".to_string(),
            });
        }
        // Gate 3a — clock sanity. Authenticity is not currency (an
        // owner-signed OLDER copy verifies fine), and last_mod_ms is
        // caller wall-clock with no monotonicity guard, so timestamps
        // decide NOTHING here. Only two relations can be legitimate
        // crash residue:
        //   - IncomingDominates: an interrupted save_block ticked the
        //     block's own vector clock (content changed). Adopt.
        //   - Equal: a content-preserving re-key (share/revoke via
        //     rewrite_block_with_recipients, which deliberately
        //     preserves the block clock). Conditionally adoptable —
        //     the subset-only rule at Gate 3b below decides, after the
        //     recipient set has been decrypt-verified and resolved.
        // Dominated (rollback plant) or concurrent (torn multi-device
        // state we must not guess about) are always refused.
        let relation = clock_relation(&entry.vector_clock_summary, &block_file.header.vector_clock);
        if !matches!(
            relation,
            ClockRelation::IncomingDominates | ClockRelation::Equal
        ) {
            return Err(VaultError::RepairRejected {
                block_uuid: entry.block_uuid,
                detail: format!(
                    "clock relation {relation:?}: on-disk block is not a legitimate \
                     crash-residue shape (dominated = rollback plant, concurrent = \
                     torn multi-device state)"
                ),
            });
        }
        let plaintext = block::decrypt_block(
            &block_file,
            &owner_fp,
            &owner_pk_bundle,
            &owner_card.ed25519_pk,
            &owner_pq_pk,
            &owner_fp,
            &owner_pk_bundle,
            &owner_x_sk,
            &owner_pq_sk_reader,
        )
        .map_err(|e| VaultError::RepairRejected {
            block_uuid: entry.block_uuid,
            detail: format!("decrypt/verify: {e}"),
        })?;
        // The rebuilt entry's recipients come from the on-disk §6.2
        // table (so a crashed revocation adopts the REDUCED set).
        let recipients = resolve_recipient_uuids(folder, &owner_card, &block_file.recipients)?;
        // Gate 3b — Equal-clock subset-only rule. Within an equal-clock
        // class every legitimate writer re-encrypted the IDENTICAL
        // plaintext (invariant guarded at rewrite_block_with_recipients
        // step 9/10), so adoption can only change the recipient set —
        // and only a strict NARROWING is fail-closed: the worst outcome
        // an attacker replaying retained owner-signed re-key bytes can
        // force is an un-share (recoverable by re-sharing). A superset
        // would re-GRANT access (e.g. resurrect a revoked recipient —
        // the 2026-07 review exploit: retained share-bytes stamped with
        // a later wall-clock than a backward-clock revoke), and an
        // equal set with different bytes matches no legitimate crashed
        // operation (stale-replay / forgery shape). Both are refused.
        if matches!(relation, ClockRelation::Equal) {
            let on_disk: BTreeSet<[u8; 16]> = recipients.iter().copied().collect();
            let committed: BTreeSet<[u8; 16]> = entry.recipients.iter().copied().collect();
            let added: Vec<String> = on_disk
                .difference(&committed)
                .map(format_uuid_hyphenated)
                .collect();
            if !added.is_empty() {
                return Err(VaultError::RepairRejected {
                    block_uuid: entry.block_uuid,
                    detail: format!(
                        "equal-clock re-key residue would ADD recipients {{{}}}: refusing \
                         automatic adoption; explicit consent path not yet implemented",
                        added.join(", ")
                    ),
                });
            }
            if on_disk == committed {
                return Err(VaultError::RepairRejected {
                    block_uuid: entry.block_uuid,
                    detail: "equal-clock residue leaves the recipient set unchanged while \
                             the bytes differ: no legitimate crashed re-key has this shape \
                             (stale-replay or forgery)"
                        .to_string(),
                });
            }
            // Strict subset: a crashed revocation's narrowed set. Adopt.
        }
        adoptions.push((
            idx,
            BlockEntry {
                block_uuid: entry.block_uuid,
                block_name: plaintext.block_name.clone(),
                fingerprint: got,
                recipients,
                vector_clock_summary: block_file.header.vector_clock.clone(),
                suite_id: block_file.header.suite_id,
                created_at_ms: block_file.header.created_at_ms,
                // The original write's own stamp — repair is not a
                // content change (mirrors clock-verbatim above).
                last_mod_ms: block_file.header.last_mod_ms,
                // Preserve the committed entry's unknown map: repair
                // replaces the *content commitment*, not v2 metadata.
                unknown: entry.unknown.clone(),
            },
        ));
    }

    if adoptions.is_empty() {
        // Healthy vault: repair degrades to a plain open (idempotent).
        complete_pending_trash_renames(folder, &manifest);
        return Ok(OpenVault {
            identity_block_key: unlocked.identity_block_key,
            identity: unlocked.identity,
            owner_card,
            manifest,
            manifest_file,
        });
    }
    for (idx, new_entry) in adoptions {
        manifest.blocks[idx] = new_entry;
    }
    tick_clock(&mut manifest.vector_clock, &device_uuid)?;

    // Re-sign + atomic-write — same key-rewrap shape as trash_block
    // step 7 (zeroize the ed25519 stack copy).
    let new_header = ManifestHeader {
        vault_uuid: manifest_file.header.vault_uuid,
        created_at_ms: manifest_file.header.created_at_ms,
        last_mod_ms: now_ms,
    };
    let mut ed_sk_bytes = *unlocked.identity.ed25519_sk.expose();
    let owner_ed_sk: Ed25519Secret = Sensitive::new(ed_sk_bytes);
    ed_sk_bytes.zeroize();
    let owner_pq_sk = MlDsa65Secret::from_bytes(unlocked.identity.ml_dsa_65_sk.expose())?;
    let aead_nonce = aead::random_nonce(rng);
    let new_manifest_file = manifest::sign_manifest(
        new_header,
        &manifest,
        &unlocked.identity_block_key,
        &aead_nonce,
        manifest_file.author_fingerprint,
        &owner_ed_sk,
        &owner_pq_sk,
    )?;
    let manifest_bytes = manifest::encode_manifest_file(&new_manifest_file)?;
    let manifest_path = folder.join(MANIFEST_FILENAME);
    io::write_atomic(&manifest_path, &manifest_bytes).map_err(|e| VaultError::Io {
        context: "repair_vault: failed to write manifest.cbor.enc",
        source: e,
    })?;

    complete_pending_trash_renames(folder, &manifest);
    Ok(OpenVault {
        identity_block_key: unlocked.identity_block_key,
        identity: unlocked.identity,
        owner_card,
        manifest,
        manifest_file: new_manifest_file,
    })
}
