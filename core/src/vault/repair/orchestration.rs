use std::collections::BTreeSet;
use std::path::Path;

use rand_core::{CryptoRng, RngCore};

use zeroize::Zeroize as _;

use crate::crypto::hash::hash as blake3_hash;
use crate::crypto::kem::{self, MlKem768Secret};
use crate::crypto::secret::Sensitive;
use crate::crypto::sig::MlDsa65Public;
use crate::identity::fingerprint::fingerprint;

use crate::vault::block;
use crate::vault::conflict::{clock_relation, ClockRelation};
use crate::vault::manifest::BlockEntry;
use crate::vault::orchestrators::{
    ensure_not_rollback, format_uuid_hyphenated, read_and_verify_manifest,
    resign_and_write_manifest, resolve_recipient_uuids, tick_clock, unlock_vault_identity,
    OpenVault, Unlocker, BLOCKS_SUBDIR, BLOCK_FILE_EXTENSION,
};
use crate::vault::{VaultError, VectorClockEntry};

use super::policy::RepairPolicy;
use super::sweep::complete_pending_trash_renames;

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
///    - [`ClockRelation::IncomingDominates`] against
///      `vector_clock_summary` — an interrupted `save_block` (content
///      changed, so the block's own clock ticked). Adopted, but only if
///      it does not widen the recipient set: `save_block` re-encrypts to
///      the *existing* recipients, so a legitimate residue's recipient
///      set equals the committed one. A dominating file that widens is a
///      planted owner-signed copy carrying a pre-revocation recipient set
///      (a revoke is clock-invisible, so it can dominate a committed
///      post-revoke entry) and is refused.
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
        //     block's own vector clock (content changed). Still subject
        //     to the recipient-widening refusal at Gate 3b — a crashed
        //     save re-encrypts to the *existing* recipient set, so a
        //     legitimate residue never adds a recipient here.
        //   - Equal: a content-preserving re-key (share/revoke via
        //     rewrite_block_with_recipients, which deliberately
        //     preserves the block clock). Conditionally adoptable —
        //     Gate 3b below decides, after the recipient set has been
        //     decrypt-verified and resolved.
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
        // table (so a crashed revocation adopts the REDUCED set). A
        // missing/unverifiable recipient card is a *gate* failure (the
        // repair contract promises RepairRejected), not the bare
        // MissingRecipientCard the shared resolver returns; remap it so
        // the outcome set stays {RepairRejected, BlockFileMissing}.
        // Environmental Io (contacts/ unreadable) stays Io — it is not a
        // gate rejection.
        let recipients = resolve_recipient_uuids(folder, &owner_card, &block_file.recipients)
            .map_err(|e| match e {
                VaultError::MissingRecipientCard { .. } => VaultError::RepairRejected {
                    block_uuid: entry.block_uuid,
                    detail: format!("recipient resolution: {e}"),
                },
                other => other,
            })?;
        // Gate 3b — recipient-widening is refused REGARDLESS of clock
        // relation. No legitimate crashed operation can ADD a recipient
        // here: save_block ticks the block clock but re-encrypts to the
        // *existing* recipient set (so a genuine IncomingDominates
        // residue has on-disk recipients == committed), and re-keys
        // preserve the clock (Equal) so their residue can only NARROW
        // (revoke). The one widening operation, share_block, also
        // preserves the clock — its crashed superset residue is landed
        // here too but is deliberately NOT auto-adopted — adoptable only
        // via the `RepairPolicy::AdoptApproved` consent arm below (#374).
        // So any added recipient is either that crashed
        // share or an attacker replaying retained owner-signed bytes to
        // re-GRANT access (e.g. resurrect a revoked recipient — the
        // 2026-07 review exploit). Fail closed: the worst an attacker can
        // force through the adopted direction is an un-share, recoverable
        // by re-sharing; re-granting is NEVER automatic on any clock
        // relation. (Earlier this guard was Equal-only, which left the
        // IncomingDominates arm able to adopt a widened set — a planted
        // owner-signed content-save whose block clock dominated a
        // clock-invisible revoke could re-grant the revoked recipient.)
        let on_disk: BTreeSet<[u8; 16]> = recipients.iter().copied().collect();
        let committed: BTreeSet<[u8; 16]> = entry.recipients.iter().copied().collect();
        let added: BTreeSet<[u8; 16]> = on_disk.difference(&committed).copied().collect();
        if !added.is_empty() {
            let added_hex: Vec<String> = added.iter().map(format_uuid_hyphenated).collect();
            // Consent-eligible = the crashed-share residue shape and ONLY
            // that shape: Equal clock ∧ pure adds (strict superset). A
            // dominating widening is the planted-content-save re-grant
            // exploit; a mixed add+remove delta is no single crashed op.
            // Neither is EVER licensed by an approval — the shape check
            // deliberately precedes the approval lookup (spec §3.3).
            let removed_any = committed.difference(&on_disk).next().is_some();
            let consent_eligible = matches!(relation, ClockRelation::Equal) && !removed_any;
            let approval = match (&policy, consent_eligible) {
                (RepairPolicy::AdoptApproved(approvals), true) => {
                    approvals.iter().find(|a| a.block_uuid == entry.block_uuid)
                }
                _ => None,
            };
            match approval {
                // Exact bind: the previewed bytes AND the previewed delta.
                Some(a) if a.file_fingerprint == got && a.added_recipients == added => {
                    // consented crashed-share adoption — fall through
                }
                Some(_) => {
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
                    return Err(VaultError::RepairRejected {
                        block_uuid: entry.block_uuid,
                        detail: format!(
                            "re-key residue would ADD recipients {{{}}}: refusing \
                             automatic adoption; adopting requires explicit consent \
                             (preview_repair + RepairPolicy::AdoptApproved){}",
                            added_hex.join(", "),
                            if consent_eligible {
                                ""
                            } else {
                                " — and this residue is not the crashed-share shape, \
                                 so it is never adoptable"
                            }
                        ),
                    });
                }
            }
        }
        // Equal-clock only: an *unchanged* recipient set with differing
        // bytes is not a legitimate crashed re-key (a re-key changes the
        // set; a content save ticks the clock into IncomingDominates), so
        // it is a stale-replay / forgery shape and is refused. Under
        // IncomingDominates an unchanged recipient set with differing
        // bytes IS the legitimate crashed-save shape and is adopted.
        if matches!(relation, ClockRelation::Equal) && on_disk == committed {
            return Err(VaultError::RepairRejected {
                block_uuid: entry.block_uuid,
                detail: "equal-clock residue leaves the recipient set unchanged while \
                         the bytes differ: no legitimate crashed re-key has this shape \
                         (stale-replay or forgery)"
                    .to_string(),
            });
        }
        // Reaching here: recipients are a subset of committed (narrowing
        // — crashed revocation under Equal, or an owner-signed
        // content-save under IncomingDominates). Adopt.
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
                // Preserve the committed entry's unknown map. Repair
                // replaces the content commitment (fingerprint + clock)
                // from the on-disk block, but BlockEntry-level v2 metadata
                // lives in the manifest, not the block file — so any v2
                // fields the interrupted (and now lost) manifest write
                // would have carried are unrecoverable here regardless.
                // Carrying the committed map forward is the only option
                // that preserves the v2 fields we still have; a future
                // v2-aware repair path cannot do better without a second
                // manifest copy on disk.
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
    Ok(OpenVault {
        identity_block_key: unlocked.identity_block_key,
        identity: unlocked.identity,
        owner_card,
        manifest,
        manifest_file: new_manifest_file,
    })
}
