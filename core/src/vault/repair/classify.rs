//! Single-source per-block crash-residue classification (#374 Task 4).
//!
//! [`classify_block`] is the ONLY place the repair gate logic lives —
//! both [`super::orchestration::repair_vault`] and
//! [`super::orchestration::preview_repair`] call it for every mismatched
//! block. It performs Gate 1 (authenticity), Gate 2 (header binding),
//! Gate 3a (clock sanity), decrypt + recipient resolution, and Gate 3b
//! (recipient-widening shape), returning a [`BlockClassification`] that
//! carries everything needed to either adopt or preview a widening. The
//! ONE thing it deliberately does NOT decide is the policy question —
//! whether a consent-eligible widening is actually approved — since a
//! preview has no policy to consult and `repair_vault` needs the
//! `RepairPolicy` comparison to happen with its own wording (see the
//! module doc on `repair_vault` for the full gate rationale; this module
//! is a pure code-motion of that logic, not a redesign of it).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::crypto::hash::hash as blake3_hash;
use crate::crypto::kem::{self, MlKem768Secret};
use crate::crypto::sig::MlDsa65Public;
use crate::identity::card::ContactCard;

use crate::vault::block;
use crate::vault::conflict::{clock_relation, ClockRelation};
use crate::vault::manifest::BlockEntry;
use crate::vault::orchestrators::{
    format_uuid_hyphenated, resolve_recipient_uuids, BLOCK_FILE_EXTENSION,
};
use crate::vault::VaultError;

/// Owner verify/decrypt key material, built once per `repair_vault` /
/// `preview_repair` run and passed by reference into [`classify_block`]
/// for every mismatched block. Holds the same `Sensitive`-typed secrets
/// the pre-Task-4 inline loop held — moved here verbatim, never cloned
/// out, so the zeroize-on-drop discipline is unchanged.
pub(crate) struct OwnerVerifyCtx<'a> {
    pub owner_card: &'a ContactCard,
    pub owner_fp: [u8; 16],
    pub owner_pk_bundle: Vec<u8>,
    pub owner_pq_pk: MlDsa65Public,
    pub owner_x_sk: kem::X25519Secret,
    pub owner_pq_sk_reader: MlKem768Secret,
}

/// The outcome of classifying one manifest [`BlockEntry`] against its
/// on-disk `blocks/<uuid>.cbor.enc` file.
pub(crate) enum BlockClassification {
    /// On-disk fingerprint matches the committed entry: nothing to do.
    Healthy,
    /// Adoptable without consent: an interrupted `save_block` (content
    /// change, no widening) or a narrowing re-key (crashed revoke).
    Adopt(BlockEntry),
    /// The crashed-`share_block` shape: `Equal` clock ∧ a strict
    /// recipient superset (pure adds, no removes). Never auto-adopted —
    /// adoptable only via a matching `RepairPolicy::AdoptApproved` entry.
    ConsentEligibleWidening {
        /// The fully-built adopted-shape entry (recipients = on-disk
        /// set) a caller stages once consent is confirmed.
        staged: BlockEntry,
        /// The recipient UUIDs the widening would add, each paired with
        /// the §6.2 wrap `recipient_fingerprint` that actually resolved
        /// to it. A preview MUST render identity by this fingerprint,
        /// not by the uuid alone (2026-07 final review): `verify_self`
        /// proves a `contacts/*.card` is internally self-consistent, NOT
        /// that its `contact_uuid` is unique — an attacker with
        /// vault-folder write access could otherwise plant a decoy card
        /// sharing a legitimate recipient's uuid to steer a uuid-keyed
        /// preview lookup onto the wrong display name / fingerprint.
        /// Callers that only need the uuid *set* (e.g. `repair_vault`'s
        /// exact-match against `RepairPolicy::AdoptApproved`) derive it
        /// from this map's keys — that comparison's semantics are
        /// unchanged by this type.
        added: BTreeMap<[u8; 16], [u8; 16]>,
        /// BLAKE3-256 of the on-disk block file bytes classified here —
        /// the fingerprint a consent approval / preview binds to.
        file_fingerprint: [u8; 32],
        /// The on-disk block's plaintext name, for preview display.
        block_name: String,
    },
}

/// Classify one manifest block against its on-disk file. Pure move of
/// the pre-Task-4 `repair_vault` loop body: every hard rejection, every
/// detail string, and the gate order (authenticity → binding → clock
/// sanity → decrypt → recipient resolution → widening shape →
/// equal-set-different-bytes) are preserved verbatim. The one thing
/// this function does NOT do is decide whether a consent-eligible
/// widening is approved — that policy decision belongs to the caller
/// (`repair_vault` compares against `RepairPolicy`; `preview_repair`
/// just reports it).
pub(crate) fn classify_block(
    folder: &Path,
    blocks_dir: &Path,
    vault_uuid: [u8; 16],
    entry: &BlockEntry,
    ctx: &OwnerVerifyCtx<'_>,
) -> Result<BlockClassification, VaultError> {
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
        return Ok(BlockClassification::Healthy);
    }
    // Gate 1 — authenticity: decode + AEAD-decrypt + hybrid verify
    // (Ed25519 ∧ ML-DSA-65, both halves) under the owner card.
    let block_file = block::decode_block_file(&bytes).map_err(|e| VaultError::RepairRejected {
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
    if block_file.header.vault_uuid != vault_uuid {
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
        &ctx.owner_fp,
        &ctx.owner_pk_bundle,
        &ctx.owner_card.ed25519_pk,
        &ctx.owner_pq_pk,
        &ctx.owner_fp,
        &ctx.owner_pk_bundle,
        &ctx.owner_x_sk,
        &ctx.owner_pq_sk_reader,
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
    let recipients = resolve_recipient_uuids(folder, ctx.owner_card, &block_file.recipients)
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
    // via the caller's `RepairPolicy::AdoptApproved` consent arm
    // (#374). So any added recipient is either that crashed share or
    // an attacker replaying retained owner-signed bytes to re-GRANT
    // access (e.g. resurrect a revoked recipient — the 2026-07 review
    // exploit). Fail closed: the worst an attacker can force through
    // the adopted direction is an un-share, recoverable by re-sharing;
    // re-granting is NEVER automatic on any clock relation. (Earlier
    // this guard was Equal-only, which left the IncomingDominates arm
    // able to adopt a widened set — a planted owner-signed
    // content-save whose block clock dominated a clock-invisible
    // revoke could re-grant the revoked recipient.)
    let on_disk: BTreeSet<[u8; 16]> = recipients.iter().copied().collect();
    let committed: BTreeSet<[u8; 16]> = entry.recipients.iter().copied().collect();
    let added: BTreeSet<[u8; 16]> = on_disk.difference(&committed).copied().collect();
    // `recipients[i]` is the uuid `resolve_recipient_uuids` resolved from
    // `block_file.recipients[i]`'s wrap — same index, same order (the
    // resolver preserves wrap order). Zip them into a uuid -> wrap
    // fingerprint map so a consent-eligible widening's preview can
    // content-address each added recipient's identity by the fingerprint
    // that ACTUALLY resolved it, not by the (attacker-plantable) uuid.
    let uuid_to_wrap_fp: BTreeMap<[u8; 16], [u8; 16]> = recipients
        .iter()
        .zip(block_file.recipients.iter())
        .map(|(uuid, wrap)| (*uuid, wrap.recipient_fingerprint))
        .collect();
    if !added.is_empty() {
        // Consent-eligible = the crashed-share residue shape and ONLY
        // that shape: Equal clock ∧ pure adds (strict superset). A
        // dominating widening is the planted-content-save re-grant
        // exploit; a mixed add+remove delta is no single crashed op.
        // Neither is EVER licensed by an approval — the shape check
        // deliberately precedes any approval lookup (spec §3.3), and
        // since neither shape is ever adoptable, classify_block itself
        // is the right place to reject them (there is no policy
        // decision left to defer to the caller).
        let removed_any = committed.difference(&on_disk).next().is_some();
        let consent_eligible = matches!(relation, ClockRelation::Equal) && !removed_any;
        if !consent_eligible {
            let added_hex: Vec<String> = added.iter().map(format_uuid_hyphenated).collect();
            return Err(VaultError::RepairRejected {
                block_uuid: entry.block_uuid,
                detail: format!(
                    "re-key residue would ADD recipients {{{}}}: refusing \
                     automatic adoption; adopting requires explicit consent \
                     (preview_repair + RepairPolicy::AdoptApproved) — and this \
                     residue is not the crashed-share shape, so it is never \
                     adoptable",
                    added_hex.join(", ")
                ),
            });
        }
        let staged = BlockEntry {
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
        };
        let added_with_fp: BTreeMap<[u8; 16], [u8; 16]> = added
            .iter()
            .map(|uuid| (*uuid, uuid_to_wrap_fp[uuid]))
            .collect();
        return Ok(BlockClassification::ConsentEligibleWidening {
            staged,
            added: added_with_fp,
            file_fingerprint: got,
            block_name: plaintext.block_name.clone(),
        });
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
    Ok(BlockClassification::Adopt(BlockEntry {
        block_uuid: entry.block_uuid,
        block_name: plaintext.block_name.clone(),
        fingerprint: got,
        recipients,
        vector_clock_summary: block_file.header.vector_clock.clone(),
        suite_id: block_file.header.suite_id,
        created_at_ms: block_file.header.created_at_ms,
        last_mod_ms: block_file.header.last_mod_ms,
        unknown: entry.unknown.clone(),
    }))
}

/// One recipient a consent-eligible widening would add: the manifest
/// UUID plus the verified display name and identity fingerprint from
/// their `contacts/*.card`.
///
/// `card_fingerprint` is 16 bytes — the identity
/// [`crate::identity::fingerprint::fingerprint`] output, the same value
/// §6.2 wraps use as `recipient_fingerprint` — NOT the 32-byte block
/// content fingerprint. It is the fingerprint of the card whose key
/// ACTUALLY gains access (the §6.2 wrap's `recipient_fingerprint`), not
/// merely a card that happens to carry `uuid` — `contact_uuid` is a
/// self-declared field a `contacts/*.card` file does not prove unique
/// (2026-07 final review of #374): `display_name` and `card_fingerprint`
/// are always looked up by this fingerprint, never by `uuid` alone. In
/// the honest, non-attacked case this is the same value it always was —
/// no behavior change for legitimate data.
#[derive(Debug, Clone)]
pub struct AddedRecipient {
    pub uuid: [u8; 16],
    pub display_name: String,
    pub card_fingerprint: [u8; 16],
}

/// One block whose crash residue is a consent-eligible recipient
/// widening (the crashed-`share_block` shape), as reported by
/// [`super::orchestration::preview_repair`].
#[derive(Debug, Clone)]
pub struct WideningReport {
    pub block_uuid: [u8; 16],
    pub block_name: String,
    /// BLAKE3-256 of the on-disk block file bytes previewed here — bind
    /// a subsequent `RepairPolicy::AdoptApproved` approval to exactly
    /// these bytes (a file swapped between preview and repair fails
    /// the bind as stale consent).
    pub file_fingerprint: [u8; 32],
    pub added: Vec<AddedRecipient>,
}

/// The read-only result of [`super::orchestration::preview_repair`]:
/// every consent-eligible recipient widening found in the vault's
/// crash residue, with nothing written to disk.
#[derive(Debug, Clone)]
pub struct RepairPreview {
    pub widenings: Vec<WideningReport>,
}
