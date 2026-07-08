use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use rand_core::{CryptoRng, RngCore};

use zeroize::Zeroize as _;

use crate::crypto::kem::{self, MlKem768Secret};
use crate::crypto::secret::Sensitive;
use crate::crypto::sig::MlDsa65Public;
use crate::identity::fingerprint::fingerprint;

use crate::vault::block;
use crate::vault::manifest::BlockEntry;
use crate::vault::orchestrators::{
    ensure_not_rollback, format_uuid_hyphenated, read_and_verify_manifest,
    resign_and_write_manifest, scan_verified_contact_cards, tick_clock, unlock_vault_identity,
    OpenVault, Unlocker, BLOCKS_SUBDIR,
};
use crate::vault::{VaultError, VectorClockEntry};

use super::classify::{
    classify_block, AddedRecipient, BlockClassification, OwnerVerifyCtx, RepairPreview,
    WideningReport,
};
use super::policy::RepairPolicy;
use super::sweep::{complete_pending_trash_renames, sweep_purged_trash_files};

/// One `ConsentEligibleWidening` collected during `preview_repair`'s
/// classification pass, before the added-recipient uuids have been
/// resolved to display names / card fingerprints. Kept as a named
/// struct (rather than a tuple) purely to stay under clippy's
/// `type_complexity` threshold.
struct RawWidening {
    block_uuid: [u8; 16],
    block_name: String,
    file_fingerprint: [u8; 32],
    /// uuid -> the §6.2 wrap `recipient_fingerprint` that resolved to it
    /// (see [`AddedRecipient::card_fingerprint`] doc comment for why the
    /// fingerprint, not the uuid, must drive the identity lookup below).
    added: std::collections::BTreeMap<[u8; 16], [u8; 16]>,
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
///    are deliberately NOT part of this gate). Two-tier rule, with a
///    **cross-cutting recipient-widening refusal** layered on top — no
///    clock relation ever licenses ADDING a recipient (re-granting
///    access is never automatic):
///    - [`crate::vault::conflict::ClockRelation::IncomingDominates`] against
///      `vector_clock_summary` — an interrupted `save_block` (content
///      changed, so the block's own clock ticked). Adopted, but only if
///      it does not widen the recipient set: `save_block` re-encrypts to
///      the *existing* recipients, so a legitimate residue's recipient
///      set equals the committed one. A dominating file that widens is a
///      planted owner-signed copy carrying a pre-revocation recipient set
///      (a revoke is clock-invisible, so it can dominate a committed
///      post-revoke entry) and is refused.
///    - [`crate::vault::conflict::ClockRelation::Equal`] — the residue of a content-preserving
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
///      recipient) is always refused — on either tier. Equal sets with
///      different bytes are also refused — no legitimate crashed
///      operation has that shape (stale-replay / forgery). Consequence:
///      the residue of a crashed `share_block` (a genuine superset) is
///      NOT auto-adopted by default; it is adoptable ONLY via
///      [`RepairPolicy::AdoptApproved`] with a preview-bound
///      [`super::ApprovedWidening`] (exact on-disk fingerprint AND exact
///      added-recipient set — never subset/superset) — the rejection
///      `detail` names the recipients that would be added.
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
/// speculatively *given a usable §10 baseline store*: the pre-write §10
/// gate below runs unconditionally (before mismatch classification), so
/// a `load_baseline` error or a rollback-flagged committed clock refuses
/// even a would-be no-op repair where `open_vault` (read-only skip
/// posture) still succeeds.
///
/// Goes through the same `unlock_vault_identity` +
/// `read_and_verify_manifest` §1 verify-before-decrypt sequence as
/// `open_vault`, then evaluates the §10 rollback check itself — keyed by
/// the **verified** `manifest.vault_uuid` handed to `load_baseline`, on
/// the committed (pre-tick) clock, strictly before any write; a
/// `load_baseline` error refuses the repair fail-closed (#384). Caution
/// for new callers: the fail-closed posture required by crypto-design
/// §10 lives in the *provider* — passing `|_| Ok(None)` silently opts
/// out of rollback resistance (acceptable only in tests). Production
/// callers must use (or mirror) the bridge's `baseline_provider`, which
/// fails closed on an existing-but-unreadable baseline store. The repair
/// path is never a weaker open than a normal one; it only widens what
/// happens *after* the manifest is authenticated.
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
    load_baseline: impl FnOnce(&[u8; 16]) -> Result<Option<Vec<VectorClockEntry>>, VaultError>,
    device_uuid: [u8; 16],
    now_ms: u64,
    rng: &mut (impl RngCore + CryptoRng),
    policy: RepairPolicy,
) -> Result<OpenVault, VaultError> {
    // Same unlock + §1 verify-before-decrypt manifest sequence as
    // open_vault. §10 runs explicitly below (not inside
    // read_and_verify_manifest) — see the gate comment.
    let (vault_toml_bytes, unlocked) = unlock_vault_identity(folder, unlocker)?;
    let (owner_card, mut manifest, manifest_file, _envelope_bytes) =
        read_and_verify_manifest(folder, &vault_toml_bytes, &unlocked, None)?;

    // §10 pre-write gate (#384): keyed by the VERIFIED manifest
    // `vault_uuid` — available only now, after hybrid-verify + AEAD
    // decrypt — never by the plaintext `vault.toml` value. It must run
    // HERE, before Pass 1 stages anything and before the adopt/tick/
    // manifest rewrite below: a post-write check would evaluate the
    // post-tick clock, where the local tick flips a strictly-dominated
    // (rollback) committed clock into an unflagged "concurrent" one,
    // masking the rollback permanently. A provider error propagates
    // fail-closed — nothing has been staged or written yet.
    let baseline = load_baseline(&manifest.vault_uuid)?;
    ensure_not_rollback(baseline.as_deref(), &manifest.vector_clock)?;

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
    let ctx = OwnerVerifyCtx {
        owner_card: &owner_card,
        owner_fp,
        owner_pk_bundle,
        owner_pq_pk,
        owner_x_sk,
        owner_pq_sk_reader,
    };

    // Pass 1 — read-only classification via the single-source
    // classifier (#374 Task 4). All-or-nothing: any gate failure
    // returns before anything is staged or written. The classifier
    // decides HOW a block's on-disk residue relates to the committed
    // entry; only the policy decision for a consent-eligible widening
    // (does an approval match?) is decided here.
    let blocks_dir = folder.join(BLOCKS_SUBDIR);
    let mut adoptions: Vec<(usize, BlockEntry)> = Vec::new();
    for (idx, entry) in manifest.blocks.iter().enumerate() {
        match classify_block(folder, &blocks_dir, manifest.vault_uuid, entry, &ctx)? {
            BlockClassification::Healthy => continue,
            BlockClassification::Adopt(new_entry) => adoptions.push((idx, new_entry)),
            BlockClassification::ConsentEligibleWidening {
                staged,
                added,
                file_fingerprint,
                block_name: _,
            } => {
                // Consent-eligible = the crashed-share residue shape and
                // ONLY that shape (classify_block already refused every
                // non-eligible widening). The approval lookup happens
                // here, not in the classifier, because a preview has no
                // policy to consult — only `repair_vault` compares
                // against `RepairPolicy`.
                let approval = match &policy {
                    RepairPolicy::AdoptApproved(approvals) => {
                        approvals.iter().find(|a| a.block_uuid == entry.block_uuid)
                    }
                    RepairPolicy::FailClosed => None,
                };
                // `ApprovedWidening.added_recipients` is a uuid set (what
                // the user approved from the preview); `added` is now a
                // uuid -> wrap-fingerprint map (classify.rs, #374 final
                // review — the fingerprint is what lets `preview_repair`
                // content-address identity rendering). The exact-set
                // comparison below is derived from this map's KEYS, so
                // it is byte-for-byte the same uuid-set comparison as
                // before this change.
                let added_uuids: BTreeSet<[u8; 16]> = added.keys().copied().collect();
                match approval {
                    // Exact bind: the previewed bytes AND the previewed delta.
                    Some(a)
                        if a.file_fingerprint == file_fingerprint
                            && a.added_recipients == added_uuids =>
                    {
                        adoptions.push((idx, staged));
                    }
                    Some(_) => {
                        let added_hex: Vec<String> =
                            added_uuids.iter().map(format_uuid_hyphenated).collect();
                        return Err(VaultError::RepairRejected {
                            block_uuid: entry.block_uuid,
                            detail: format!(
                                "approval does not match the on-disk residue (stale \
                                 consent — the block file or recipient delta changed \
                                 after preview; re-run the preview): residue would ADD \
                                 recipients {{{}}}",
                                added_hex.join(", ")
                            ),
                        });
                    }
                    None => {
                        let added_hex: Vec<String> =
                            added_uuids.iter().map(format_uuid_hyphenated).collect();
                        return Err(VaultError::RepairRejected {
                            block_uuid: entry.block_uuid,
                            detail: format!(
                                "re-key residue would ADD recipients {{{}}}: refusing \
                                 automatic adoption; adopting requires explicit consent \
                                 (preview_repair + RepairPolicy::AdoptApproved)",
                                added_hex.join(", ")
                            ),
                        });
                    }
                }
            }
        }
    }

    if adoptions.is_empty() {
        // Healthy vault: repair degrades to a plain open (idempotent).
        complete_pending_trash_renames(folder, &manifest);
        sweep_purged_trash_files(folder, &manifest);
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

    // Re-sign + atomic-write — the shared re-sign tail (#377): re-wrap the
    // owner Ed25519 secret + zeroize the stack copy, fresh AEAD nonce,
    // hybrid-sign, atomic-write. Same manifest verify-before-decrypt open
    // guarantees the rewritten envelope.
    let new_manifest_file = resign_and_write_manifest(
        folder,
        &manifest,
        &unlocked.identity,
        &unlocked.identity_block_key,
        &manifest_file.header,
        now_ms,
        manifest_file.author_fingerprint,
        rng,
        "repair_vault: failed to write manifest.cbor.enc",
    )?;

    complete_pending_trash_renames(folder, &manifest);
    sweep_purged_trash_files(folder, &manifest);
    Ok(OpenVault {
        identity_block_key: unlocked.identity_block_key,
        identity: unlocked.identity,
        owner_card,
        manifest,
        manifest_file: new_manifest_file,
    })
}

/// Read-only preview of what [`repair_vault`] would find (#374 Task 4):
/// every consent-eligible recipient widening in the vault's crash
/// residue, with the recipients' verified display names and identity
/// fingerprints so a caller can present an informed consent prompt
/// before choosing a [`RepairPolicy::AdoptApproved`]. Writes nothing —
/// no manifest rewrite, no re-sign, no clock tick.
///
/// Goes through the SAME unlock + §1 verify-before-decrypt manifest
/// sequence, and the SAME §10 pre-gate (#384) as `repair_vault` — see
/// that function's doc comment for the full rationale. It must run here
/// too, before classification: crypto-design §10's fail-closed rollback
/// posture applies to any code path that reads a vault's crash residue
/// and reports on it, not only to the path that writes a repaired
/// manifest — a caller must not be shown a "safe to adopt" preview for
/// a vault whose committed clock is itself a rollback. A `load_baseline`
/// error therefore propagates fail-closed here exactly as it does in
/// `repair_vault`.
///
/// Every block is classified with the same `classify_block` this
/// module's `repair_vault` uses — a hard rejection (e.g. a rollback
/// plant, or a non-eligible widening shape) propagates as the same
/// [`VaultError::RepairRejected`] `repair_vault` would return: there is
/// nothing to consent to on a vault `repair_vault` cannot repair at all.
/// Only `ConsentEligibleWidening` outcomes are collected into the
/// returned [`RepairPreview`]; `Healthy` and `Adopt` outcomes need no
/// consent and are silently skipped (an interrupted save or a
/// narrowing re-key is exactly what `repair_vault` already adopts
/// unconditionally).
pub fn preview_repair(
    folder: &Path,
    unlocker: Unlocker<'_>,
    load_baseline: impl FnOnce(&[u8; 16]) -> Result<Option<Vec<VectorClockEntry>>, VaultError>,
) -> Result<RepairPreview, VaultError> {
    let (vault_toml_bytes, unlocked) = unlock_vault_identity(folder, unlocker)?;
    let (owner_card, manifest, _manifest_file, _envelope_bytes) =
        read_and_verify_manifest(folder, &vault_toml_bytes, &unlocked, None)?;

    // §10 pre-gate (#384) — see repair_vault's doc comment for the full
    // rationale; the same posture applies to a read-only preview.
    let baseline = load_baseline(&manifest.vault_uuid)?;
    ensure_not_rollback(baseline.as_deref(), &manifest.vector_clock)?;

    let owner_pk_bundle = owner_card.pk_bundle_bytes()?;
    let owner_fp = fingerprint(&owner_card.to_canonical_cbor()?);
    let owner_pq_pk = MlDsa65Public::from_bytes(&owner_card.ml_dsa_65_pk)?;
    let mut x_sk_bytes = *unlocked.identity.x25519_sk.expose();
    let owner_x_sk: kem::X25519Secret = Sensitive::new(x_sk_bytes);
    x_sk_bytes.zeroize();
    let owner_pq_sk_reader = MlKem768Secret::from_bytes(unlocked.identity.ml_kem_768_sk.expose())
        .map_err(block::BlockError::from)?;
    let ctx = OwnerVerifyCtx {
        owner_card: &owner_card,
        owner_fp,
        owner_pk_bundle,
        owner_pq_pk,
        owner_x_sk,
        owner_pq_sk_reader,
    };

    let blocks_dir = folder.join(BLOCKS_SUBDIR);
    let mut raw_widenings: Vec<RawWidening> = Vec::new();
    for entry in &manifest.blocks {
        if let BlockClassification::ConsentEligibleWidening {
            added,
            file_fingerprint,
            block_name,
            staged: _,
        } = classify_block(folder, &blocks_dir, manifest.vault_uuid, entry, &ctx)?
        {
            raw_widenings.push(RawWidening {
                block_uuid: entry.block_uuid,
                block_name,
                file_fingerprint,
                added,
            });
        }
    }

    if raw_widenings.is_empty() {
        return Ok(RepairPreview {
            widenings: Vec::new(),
        });
    }

    // Name lookup for the added recipients: scan contacts/ once (shared
    // scanner, #374 Task 4) rather than once per widening. Keyed by the
    // CARD's own identity fingerprint (§6.1: BLAKE3 over the card's
    // canonical CBOR, which covers its embedded public keys) — never by
    // `contact_uuid`. `verify_self` only proves a card is internally
    // self-consistent; it does NOT prove `contact_uuid` is unique across
    // `contacts/`. An attacker with vault-folder write access could plant
    // a second self-signed card carrying a legitimate recipient's uuid
    // but a different key, and a uuid-keyed lookup would render THAT
    // decoy's display name for a grant that in reality goes to the real
    // key (2026-07 final review of #374). Keying by card fingerprint
    // instead means each added recipient's identity is looked up by the
    // EXACT fingerprint the §6.2 wrap resolved to — the same content-
    // addressing the wrap/grant resolution itself already relies on — so
    // a same-uuid decoy simply never matches.
    let mut lookup: HashMap<[u8; 16], String> = HashMap::new();
    for card in scan_verified_contact_cards(folder)? {
        let card_fp = fingerprint(&card.to_canonical_cbor()?);
        lookup.insert(card_fp, card.display_name.clone());
    }

    let mut widenings = Vec::with_capacity(raw_widenings.len());
    for raw in raw_widenings {
        let (block_uuid, block_name, file_fingerprint, added) = (
            raw.block_uuid,
            raw.block_name,
            raw.file_fingerprint,
            raw.added,
        );
        let mut added_recipients = Vec::with_capacity(added.len());
        for (uuid, wrap_fingerprint) in added {
            // Defensive: Gate 3 resolution in classify_block already
            // proved every wrap resolves to a verified contact card at
            // exactly this fingerprint, so a lookup miss here should not
            // happen in practice. Refuse rather than silently drop the
            // recipient from the preview or fall back to a uuid-keyed
            // lookup (which would reopen the decoy-card issue above).
            let display_name = lookup.get(&wrap_fingerprint).cloned().ok_or_else(|| {
                VaultError::RepairRejected {
                    block_uuid,
                    detail: "preview: an added recipient's wrap fingerprint did not \
                             resolve to a verified contact card"
                        .to_string(),
                }
            })?;
            added_recipients.push(AddedRecipient {
                uuid,
                display_name,
                card_fingerprint: wrap_fingerprint,
            });
        }
        widenings.push(WideningReport {
            block_uuid,
            block_name,
            file_fingerprint,
            added: added_recipients,
        });
    }

    Ok(RepairPreview { widenings })
}
