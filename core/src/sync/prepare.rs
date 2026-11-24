//! `prepare_merge` — turn the C.1.1a [`crate::sync::VaultBundle`] into a
//! [`crate::sync::DraftMerge`] by decrypting each diverging block on
//! demand and composing the existing `merge_block` primitive into an
//! N-way pairwise fold.
//!
//! See `docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md`
//! §"prepare_merge". The module exposes [`prepare_merge`] (the
//! orchestrator entry point, re-exported via [`crate::sync`]) and
//! `tombstone_veto_set` (pure-function veto detector, `pub(crate)` —
//! kept internal and consumed by `prepare_merge` per record).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use zeroize::Zeroize;

use crate::crypto::hash::hash as blake3_hash;
use crate::crypto::kem::{MlKem768Secret, X25519Secret};
use crate::crypto::secret::Sensitive;
use crate::crypto::sig::MlDsa65Public;
use crate::identity::fingerprint::fingerprint;
use crate::sync::bundle::{compute_manifest_hash, ManifestSnapshot, VaultBundle};
use crate::sync::draft::{
    BlockId, DraftMerge, MergedBlockMeta, RecordCollisionSummary, RecordId, RecordTombstoneVeto,
};
use crate::sync::error::SyncError;
use crate::sync::outcome::DiffPlan;
use crate::unlock::UnlockedIdentity;
use crate::vault::block::{decode_block_file, decrypt_block, BlockPlaintext, VectorClockEntry};
use crate::vault::conflict::{
    clock_relation, conflict_to_vault_error, merge_block, merge_vector_clocks, tick_for_device,
    ClockRelation, ConflictError,
};
use crate::vault::orchestrators::read_vault_manifest_full;
use crate::vault::record::Record;

/// Pure-function veto check: given the local (canonical) record and
/// the per-copy peer records that share its `record_uuid`, return a
/// [`RecordTombstoneVeto`] iff any peer copy would tombstone the
/// record at a timestamp strictly later than the local `last_mod_ms`,
/// AND the local copy is still live (`!local.tombstone`).
///
/// **Why "strictly later":** equality is the C.1.1a §11.3
/// staleness-filter boundary — a tombstone observed AT the same
/// instant as the local edit applies under LWW without needing user
/// veto. Strict-later is the "peer saw my live edit, then deleted,
/// while I made a newer edit they haven't seen yet" case the user
/// must adjudicate.
///
/// When multiple peers tombstone after the local edit, the returned
/// veto carries the *latest* peer's `tombstoned_at_ms` and the
/// best-effort device uuid attached to it. On tied `tombstoned_at_ms`
/// the lexicographically smallest `device_uuid` wins — the tie-break
/// is intrinsic so the result is independent of the iteration order
/// the caller passes peers in. Tests assert there's at most one
/// canonical peer for the same `record_uuid` in a well-formed bundle
/// (each copy must be signed by the canonical owner identity — an
/// attacker forging multiple copies cannot bypass the design).
///
/// **Pure:** borrows all inputs, allocates only the returned
/// [`RecordTombstoneVeto`] (which `clone()`s `local` so the caller
/// retains ownership).
///
/// # Caller-side invariants (not enforced here)
///
/// - All peers in `remote_per_copy` are expected to share
///   `local.record_uuid`. Peers with a different `record_uuid` are
///   compared timestamps-only and would still trigger a veto, but
///   that would be a [`prepare_merge`]-side correctness bug rather
///   than this helper's concern.
/// - `block_id` is forwarded into the returned veto unchanged.
#[must_use]
pub(crate) fn tombstone_veto_set(
    local: &Record,
    block_id: BlockId,
    remote_per_copy: &[&Record],
) -> Option<RecordTombstoneVeto> {
    if local.tombstone {
        return None;
    }
    let mut latest: Option<(u64, [u8; 16])> = None;
    for peer in remote_per_copy {
        if peer.tombstone && peer.tombstoned_at_ms > local.last_mod_ms {
            let cand = (
                peer.tombstoned_at_ms,
                last_modifier_device(peer).unwrap_or([0u8; 16]),
            );
            // Strict-greater timestamp wins; on ties the lexicographically
            // smaller device_uuid wins. Order-independent.
            latest = Some(match latest {
                Some(prev) if prev.0 > cand.0 => prev,
                Some(prev) if prev.0 == cand.0 && prev.1 <= cand.1 => prev,
                _ => cand,
            });
        }
    }
    latest.map(|(at_ms, device)| RecordTombstoneVeto {
        record_id: local.record_uuid,
        block_id,
        local_state: local.clone(),
        disk_tombstone_at_ms: at_ms,
        disk_tombstoner_device: device,
    })
}

/// Best-effort recovery of the device uuid that performed the last
/// modification on a record. Records don't carry a record-level
/// `device_uuid`; the per-field `device_uuid` of the field with the
/// highest `last_mod` is the closest available signal. Tombstoned
/// records with empty `fields` return `None`; callers fall back to a
/// sentinel (the all-zero uuid).
fn last_modifier_device(record: &Record) -> Option<[u8; 16]> {
    record
        .fields
        .values()
        .max_by_key(|f| f.last_mod)
        .map(|f| f.device_uuid)
}

/// Per-block decryption material derived once per `prepare_merge`
/// call. Holds the owner card's public-key bytes / fingerprints plus
/// the reader's secret keys parsed into their typed wrappers. The
/// `Sensitive` / `MlKem768Secret` fields are zeroized when this struct
/// drops, so callers shouldn't stash it past the function scope.
///
/// All fields are owned (no borrows from `UnlockedIdentity`) so the
/// owner's `pk_bundle_bytes` survives across the per-block loop without
/// re-encoding the card each iteration.
struct BlockReaderKeys {
    owner_fp: [u8; 16],
    owner_ed_pk: crate::crypto::sig::Ed25519Public,
    owner_pq_pk: MlDsa65Public,
    owner_pk_bundle: Vec<u8>,
    reader_x_sk: X25519Secret,
    reader_pq_sk: MlKem768Secret,
}

/// Derive the owner public-key material + reader secret keys once for
/// the lifetime of a `prepare_merge` call. The owner card is re-read
/// from disk (Path B in the C.1.1b plan — VaultBundle does not cache
/// the owner card today; adding a cache touches the 1a ingest layer,
/// which is out of scope for Task 8). Returns a [`BlockReaderKeys`]
/// that holds every input the per-block `decrypt_block` call needs.
///
/// Stack-residue discipline: the X25519 secret is copied into a local
/// `[u8; 32]` so it can be wrapped in [`X25519Secret`] (== `Sensitive<
/// [u8; 32]>`), then the local stack copy is zeroized before the
/// function returns — matching the documented `Sensitive::new`
/// pattern from `crypto::kem::derive_wrap_key`. The ML-KEM-768 secret
/// is parsed directly from the `Sensitive<Vec<u8>>` exposed bytes; no
/// intermediate stack copy is made.
fn derive_block_reader_keys(
    vault_folder: &Path,
    identity: &UnlockedIdentity,
) -> Result<BlockReaderKeys, SyncError> {
    // Re-load the owner card. Costs one manifest verify-and-decrypt
    // pass; the IBK is already cached on `identity`, so no Argon2id
    // re-derivation. The bundle could cache the owner card to skip
    // this read (plan Path A) — deferred per "out of scope for Task 8".
    let (owner_card, _manifest, _envelope_bytes) =
        read_vault_manifest_full(vault_folder, identity, None)?;

    let owner_card_bytes = owner_card
        .to_canonical_cbor()
        .map_err(crate::vault::VaultError::from)?;
    let owner_fp = fingerprint(&owner_card_bytes);
    let owner_ed_pk = owner_card.ed25519_pk;
    let owner_pq_pk = MlDsa65Public::from_bytes(&owner_card.ml_dsa_65_pk)
        .map_err(|e| SyncError::Vault(crate::vault::VaultError::from(e)))?;
    let owner_pk_bundle = owner_card
        .pk_bundle_bytes()
        .map_err(crate::vault::VaultError::from)?;

    let mut x_sk_bytes = *identity.identity.x25519_sk.expose();
    let reader_x_sk: X25519Secret = Sensitive::new(x_sk_bytes);
    x_sk_bytes.zeroize();
    let reader_pq_sk = MlKem768Secret::from_bytes(identity.identity.ml_kem_768_sk.expose())
        .map_err(|e| {
            SyncError::Vault(crate::vault::VaultError::from(
                crate::vault::block::BlockError::from(e),
            ))
        })?;

    Ok(BlockReaderKeys {
        owner_fp,
        owner_ed_pk,
        owner_pq_pk,
        owner_pk_bundle,
        reader_x_sk,
        reader_pq_sk,
    })
}

/// Decode and AEAD-decrypt one block envelope using the owner's keys
/// (single-owner v1: author == reader). Pure function over the
/// pre-derived [`BlockReaderKeys`]; errors are surfaced as
/// `SyncError::Vault`.
fn decrypt_block_envelope(
    envelope_bytes: &[u8],
    keys: &BlockReaderKeys,
) -> Result<BlockPlaintext, SyncError> {
    let block_file = decode_block_file(envelope_bytes)
        .map_err(|e| SyncError::Vault(crate::vault::VaultError::from(e)))?;
    let plaintext = decrypt_block(
        &block_file,
        &keys.owner_fp,
        &keys.owner_pk_bundle,
        &keys.owner_ed_pk,
        &keys.owner_pq_pk,
        &keys.owner_fp,
        &keys.owner_pk_bundle,
        &keys.reader_x_sk,
        &keys.reader_pq_sk,
    )
    .map_err(|e| SyncError::Vault(crate::vault::VaultError::from(e)))?;
    Ok(plaintext)
}

/// Look up a block's `vector_clock_summary` on a manifest by block_uuid.
/// Returns [`SyncError::InvalidArgument`] if the manifest doesn't carry
/// an entry for `block_uuid` — that would mean the bundle's
/// `diverging_blocks` map references a block that doesn't exist on the
/// referenced manifest, which is a structural bundle bug (1a ingestion
/// only inserts block_uuids present on both sides).
///
/// Linear scan over `manifest.blocks` (O(N) per lookup); acceptable at
/// v1 scale (handful of blocks per manifest). If Task 15's property
/// tests show this in a hot path, consider a `BTreeMap` keyed lookup
/// or memoising on the snapshot.
fn block_clock_on_manifest(
    manifest: &crate::vault::Manifest,
    block_uuid: &[u8; 16],
    context: &str,
) -> Result<Vec<VectorClockEntry>, SyncError> {
    manifest
        .blocks
        .iter()
        .find(|b| b.block_uuid == *block_uuid)
        .map(|b| b.vector_clock_summary.clone())
        .ok_or_else(|| SyncError::InvalidArgument {
            detail: format!("{context} manifest missing block {block_uuid:02x?}"),
        })
}

/// Pair a copy block envelope with its parent manifest's
/// `vector_clock_summary` by matching the envelope's BLAKE3-256
/// fingerprint against `BlockEntry::fingerprint` on each copy manifest.
///
/// **Why fingerprint matching rather than positional index:** the 1a
/// ingestion layer populates `bundle.copies` (via
/// [`crate::sync::ingest::ingest_manifest_copies`]) and
/// `divergence.copy_envelopes` (via
/// [`crate::sync::ingest::ingest_block_divergence`]) from two
/// independent filesystem scans — sibling manifest files in the vault
/// root vs. sibling block files in `blocks/`. The two slices have no
/// enforced 1:1 positional alignment: a manifest sibling may not have
/// rewritten this particular block; a block sibling may be an orphan
/// left by a sync tool whose matching manifest sibling was cleaned up.
/// Pairing by positional index would silently fold the wrong vector
/// clock into `merge_block`, producing a structurally wrong merge
/// without any signal.
///
/// `BlockEntry::fingerprint` is the BLAKE3-256 of the complete block
/// file bytes (the same value `verify_block_fingerprints` checks at
/// `open_vault` time), so a fingerprint match uniquely identifies the
/// manifest that authored this envelope.
///
/// # Errors
///
/// - [`SyncError::InvalidArgument`] if no manifest in `copies` has a
///   `BlockEntry` for `block_uuid` whose `fingerprint` equals the
///   envelope's. This is an "orphan block sibling" condition:
///   structurally, the envelope authenticated through 1a (signed by the
///   canonical owner) but no authenticated copy manifest references it.
///   Surfacing the error rather than silently skipping or guessing a
///   clock keeps the merge result trustworthy — the user can clean
///   stale block siblings or report a 1a-ingest bug.
///
/// # Cost
///
/// One BLAKE3-256 of `envelope_bytes` (already verified by 1a on
/// ingest; redoing it here costs O(envelope size)) plus a linear scan
/// over `copies × blocks_per_manifest`. Acceptable at v1 scale.
fn parent_block_clock(
    envelope_bytes: &[u8],
    block_uuid: &[u8; 16],
    copies: &[ManifestSnapshot],
) -> Result<Vec<VectorClockEntry>, SyncError> {
    let envelope_fp = *blake3_hash(envelope_bytes).as_bytes();
    for copy in copies {
        for entry in &copy.manifest.blocks {
            if entry.block_uuid == *block_uuid && entry.fingerprint == envelope_fp {
                return Ok(entry.vector_clock_summary.clone());
            }
        }
    }
    Err(SyncError::InvalidArgument {
        detail: format!(
            "orphan block sibling for block_uuid {block_uuid:02x?}: no copy manifest \
             in bundle.copies has a BlockEntry whose fingerprint matches the supplied \
             envelope; either a stale block file on disk or a 1a-ingest data shape bug",
        ),
    })
}

/// Lift a merge-layer error: a clock overflow keeps its typed
/// `VaultError::ClockOverflow`, anything else is a structural bundle error.
fn merge_error(e: ConflictError) -> SyncError {
    match e {
        ConflictError::ClockOverflow { .. } => SyncError::Vault(conflict_to_vault_error(e)),
        e => SyncError::InvalidArgument {
            detail: format!("merge_block: {e}"),
        },
    }
}

/// Turn the C.1.1a [`VaultBundle`] into a [`DraftMerge`]. AEAD-decrypts
/// each diverging block envelope on demand, composes pairwise merges
/// via the existing [`merge_block`] primitive, and surfaces
/// record-level tombstone vetoes via `tombstone_veto_set`.
///
/// # Inputs
///
/// - `vault_folder`: on-disk folder, used only to re-load the owner
///   contact card (Path B per the C.1.1b plan; the bundle does not
///   cache the owner card today).
/// - `identity`: caller's `UnlockedIdentity`, providing the X25519 +
///   ML-KEM-768 secret keys for block decryption.
/// - `bundle`: the C.1.1a ingestion product (authenticated canonical
///   manifest + authenticated conflict-copy manifests + per-block
///   envelopes for blocks whose `vector_clock_summary` diverges).
/// - `plan`: the [`DiffPlan`] produced alongside `bundle` by
///   [`crate::sync::sync_once`]; its `diverging_blocks` field drives
///   the per-block iteration order.
/// - `merging_device`: this device's per-vault device UUID (the one its
///   block writes tick). A diverging block whose merged clock is no
///   single copy's clock gets `+1` for it once, however many copies
///   were folded (crypto-design §11.2 "N-way merge", #751), and it
///   rides on the draft so `commit_with_decisions` ticks the manifest
///   clock for it too (§10, #744).
///
/// # Algorithm
///
/// 1. Derive the owner public-key material + reader secret keys once
///    (see `derive_block_reader_keys`).
/// 2. For each `block_uuid` in `plan.diverging_blocks`, AEAD-decrypt the
///    canonical envelope and every copy envelope, then iteratively merge
///    via [`merge_block`]; the accumulator's records advance per fold
///    step, and its block clock is the unticked running max of the copies'
///    clocks, ticked once for `merging_device` after the fold iff that
///    max equals no folded copy's clock. Run `tombstone_veto_set` across
///    the merged record set vs the per-copy plaintexts for the same
///    `record_uuid` and collect any vetoes. Extend the running
///    `merged_records` map (keyed by `record_uuid` — `merge_block`
///    already dedupes per block; this outer map dedupes across blocks).
/// 3. Fold the manifest-level vector clocks: `post_merge_clock =
///    merge_vector_clocks(canonical, copy_0, ..., copy_N)`. Unticked: the
///    commit adds the merging device's `+1` last, after any caller fold.
/// 4. Construct the `DraftMerge`.
///
/// # Per-copy block-clock pairing
///
/// The per-copy block clock is looked up by matching each envelope's
/// BLAKE3-256 fingerprint against [`crate::vault::manifest::BlockEntry`]
/// `::fingerprint` on every copy manifest in `bundle.copies` (see
/// `parent_block_clock`). The 1a ingestion layer does NOT guarantee
/// positional alignment between `bundle.copies[i]` and
/// `divergence.copy_envelopes[i]` — the two slices come from
/// independent filesystem scans (`enumerate_manifest_siblings` vs.
/// `enumerate_block_siblings`) and may diverge whenever a manifest
/// sibling didn't rewrite the block, or a block sibling has no
/// matching manifest sibling. Fingerprint matching is the unambiguous
/// pairing: it returns the manifest that authored the envelope.
///
/// # Errors
///
/// - `SyncError::Vault` wraps any AEAD-decrypt / block-decode failure.
///   A bundle that authenticated through 1a is structurally sound; a
///   decrypt failure here is either a programmer error (wrong
///   identity) or an attacker-supplied corrupted ciphertext.
/// - `SyncError::InvalidArgument` fires when the plan references a
///   `block_uuid` not present in `bundle.diverging_blocks` (structural
///   bundle/plan disagreement), when the canonical manifest is missing
///   a `BlockEntry` for a divergent block_uuid, or when a copy block
///   envelope's fingerprint matches no copy manifest's `BlockEntry`
///   (orphan sibling — see `parent_block_clock`).
///
/// # Purity & cost
///
/// One disk read for the owner card; the rest is in-memory. The
/// returned `DraftMerge` clones every merged record (Records aren't
/// zeroize-typed yet; the `DraftMerge` derives `Zeroize` so the
/// cloned records are wiped on drop via the outer struct).
pub fn prepare_merge(
    vault_folder: &Path,
    identity: &UnlockedIdentity,
    bundle: &VaultBundle,
    plan: &DiffPlan,
    merging_device: [u8; 16],
) -> Result<DraftMerge, SyncError> {
    let keys = derive_block_reader_keys(vault_folder, identity)?;

    let mut merged_records: BTreeMap<[u8; 16], Record> = BTreeMap::new();
    let mut vetoes: Vec<RecordTombstoneVeto> = Vec::new();
    let mut per_block_clocks: BTreeMap<[u8; 16], Vec<VectorClockEntry>> = BTreeMap::new();
    let mut per_block_records: BTreeMap<[u8; 16], Vec<RecordId>> = BTreeMap::new();
    let mut per_block_meta: BTreeMap<[u8; 16], MergedBlockMeta> = BTreeMap::new();
    // Metadata-only field-collision accumulator: record_uuid → sorted,
    // deduped set of colliding field names across the per-copy fold.
    // Projected into `DraftMerge.collisions` at the end — carries no
    // secret values (the `merge_block` step keeps `winner`/`loser`).
    let mut collisions: BTreeMap<[u8; 16], BTreeSet<String>> = BTreeMap::new();

    for block_uuid in &plan.diverging_blocks {
        let divergence =
            bundle
                .diverging_blocks
                .get(block_uuid)
                .ok_or_else(|| SyncError::InvalidArgument {
                    detail: format!(
                    "plan references block_uuid {block_uuid:02x?} not in bundle.diverging_blocks"
                ),
                })?;

        let canonical_block_clock =
            block_clock_on_manifest(&bundle.canonical.manifest, block_uuid, "canonical")?;
        let canonical_pt = decrypt_block_envelope(&divergence.canonical_envelope.bytes, &keys)?;

        let mut acc_records: BTreeMap<[u8; 16], Record> = canonical_pt
            .records
            .iter()
            .cloned()
            .map(|r| (r.record_uuid, r))
            .collect();
        // The running max of the copies folded so far, never ticked inside
        // the loop: an N-way fold is one merge event and gets one tick, after
        // the loop (crypto-design §11.2 "N-way merge", #751). Each step's
        // relation is taken against this unticked max, since no copy has
        // observed the tick. `folded_clocks` decides that tick from the SET
        // of copies, so it cannot depend on fold order.
        let mut folded_clocks = vec![canonical_block_clock.clone()];
        let mut acc_clock = canonical_block_clock;
        let mut acc_unknown = canonical_pt.unknown.clone();
        let mut acc_block_name = canonical_pt.block_name.clone();
        let mut acc_block_version = canonical_pt.block_version;
        let mut acc_schema_version = canonical_pt.schema_version;

        // Per-copy plaintexts retained across the iterative fold so the
        // veto pass at the bottom of the loop can compare the merged
        // accumulator against every copy's original record state.
        let mut copy_plaintexts: Vec<BlockPlaintext> =
            Vec::with_capacity(divergence.copy_envelopes.len());
        // This block's collisions, kept only if the fold merged (see below).
        let mut block_collisions: BTreeMap<[u8; 16], BTreeSet<String>> = BTreeMap::new();

        for copy_env in &divergence.copy_envelopes {
            // Pair the envelope with its parent manifest's
            // vector_clock_summary via BLAKE3-256 fingerprint match;
            // positional alignment between `copy_envelopes` and
            // `bundle.copies` is NOT guaranteed by 1a.
            let copy_block_clock = parent_block_clock(&copy_env.bytes, block_uuid, &bundle.copies)?;
            let copy_pt = decrypt_block_envelope(&copy_env.bytes, &keys)?;

            let acc_pt = BlockPlaintext {
                block_version: acc_block_version,
                block_uuid: *block_uuid,
                block_name: acc_block_name.clone(),
                schema_version: acc_schema_version,
                records: acc_records.values().cloned().collect(),
                unknown: acc_unknown.clone(),
            };
            let merged = merge_block(
                &acc_pt,
                &acc_clock,
                &copy_pt,
                &copy_block_clock,
                merging_device,
            )
            .map_err(merge_error)?;

            // Capture metadata-only field collisions BEFORE `merged` is
            // moved into `acc_records`. Projects already-computed LWW
            // collision metadata into the accumulator; touches no merge
            // logic and copies only field-name strings, never values.
            for rc in &merged.collisions {
                let entry = block_collisions.entry(rc.record_uuid).or_default();
                for fc in &rc.field_collisions {
                    entry.insert(fc.field_name.clone());
                }
            }

            acc_records = merged
                .merged
                .records
                .into_iter()
                .map(|r| (r.record_uuid, r))
                .collect();
            // `merged.vector_clock` is ticked on a concurrent step; the
            // accumulator takes the unticked max instead (see above).
            acc_clock = merge_vector_clocks(&acc_clock, &copy_block_clock);
            acc_unknown = merged.merged.unknown;
            acc_block_name = merged.merged.block_name;
            acc_block_version = merged.merged.block_version;
            acc_schema_version = merged.merged.schema_version;
            folded_clocks.push(copy_block_clock);
            copy_plaintexts.push(copy_pt);
        }

        // A max equal to one folded copy's clock means that copy dominates
        // every other and the fold adopted it whole, so its clock stands
        // untouched; otherwise some step was concurrent and the merge ticks
        // once. Compared by relation, not `Vec` equality, so a zero-counter
        // entry cannot make two equal clocks look different.
        // shortcut: `merge_block` still ticks (and discards) on a concurrent
        // step, so a merging-device counter at u64::MAX can fail closed with
        // ClockOverflow in one fold order and not another; untick merge_block
        // if counters that high ever become reachable.
        //
        // An adopting fold takes that copy's plaintext whole, not the
        // accumulator: an `Equal` step keeps the accumulator, which after a
        // concurrent step holds merged content, and writing that under the
        // copy's own clock would pair one clock with two plaintexts
        // (vault-format §6.5.1, #764). Its collisions are dropped for the same
        // reason: they came from steps whose result was not kept, and only
        // some fold orders take such steps.
        let adopted = folded_clocks
            .iter()
            .position(|c| clock_relation(c, &acc_clock) == ClockRelation::Equal);
        let adopted_one_copy = adopted.is_some();
        match adopted {
            // `folded_clocks[0]` is the canonical clock; copy `i` is at `i + 1`.
            Some(i) => {
                let pt = match i {
                    0 => &canonical_pt,
                    _ => &copy_plaintexts[i - 1],
                };
                acc_records = pt
                    .records
                    .iter()
                    .cloned()
                    .map(|r| (r.record_uuid, r))
                    .collect();
                acc_unknown = pt.unknown.clone();
                acc_block_name = pt.block_name.clone();
                acc_block_version = pt.block_version;
                acc_schema_version = pt.schema_version;
            }
            None => {
                acc_clock = tick_for_device(acc_clock, merging_device).map_err(merge_error)?;
                for (record_uuid, names) in block_collisions {
                    collisions.entry(record_uuid).or_default().extend(names);
                }
            }
        }

        // Per-record veto pass. Walk the CANONICAL (pre-merge) records
        // here, NOT `acc_records` (the post-merge accumulator). The
        // veto's `local_state` is the canonical record — what
        // [`crate::sync::commit::apply_decisions::KeepLocal`] will
        // restore on top of `merged_records` when the user rejects the
        // peer's tombstone.
        //
        // Why pre-merge and not post-merge: when a peer's tombstone is
        // strictly later than the canonical record's `last_mod_ms`,
        // [`merge_block`]'s §11.3 tombstone-wins-by-clock rule writes
        // a tombstoned record into `acc_records`. Iterating
        // `acc_records` here would see `local_rec.tombstone == true`
        // and `continue` past the very case the veto is meant to
        // surface — making the integration veto branch unreachable
        // under well-formed inputs (proved by the test corpus from
        // C.1.1b Task 13.1; the pre-fix behavior produced
        // `vetoes.is_empty()` on a per-block-divergent fixture where
        // the design says exactly one veto must fire).
        //
        // Linear scan: O(canonical_records · copies · records_per_copy).
        // Acceptable at v1 scale (a handful of copies × tens of records);
        // a per-copy `BTreeMap<record_uuid, &Record>` index would be the
        // tighter shape if Task 15's proptests show this in a hot path.
        for canonical_rec in canonical_pt.records.iter() {
            if canonical_rec.tombstone {
                continue;
            }
            let peers: Vec<&Record> = copy_plaintexts
                .iter()
                .flat_map(|cpt| cpt.records.iter())
                .filter(|r| r.record_uuid == canonical_rec.record_uuid)
                .collect();
            if let Some(v) = tombstone_veto_set(canonical_rec, *block_uuid, &peers) {
                vetoes.push(v);
            }
        }

        // Snapshot the per-block fold output so `commit_with_decisions`
        // can re-encrypt this block without re-running the merge.
        // `acc_records` is keyed by `record_uuid` and BTreeMap iteration
        // yields the sorted ascending order required for canonical
        // re-encrypt; collecting the keys preserves that order.
        per_block_clocks.insert(*block_uuid, acc_clock.clone());
        per_block_records.insert(*block_uuid, acc_records.keys().copied().collect());
        per_block_meta.insert(
            *block_uuid,
            MergedBlockMeta {
                block_name: acc_block_name,
                unknown: acc_unknown,
                block_version: acc_block_version,
                schema_version: acc_schema_version,
                adopted_copy_clock: adopted_one_copy,
            },
        );

        merged_records.extend(acc_records);
    }

    let mut post_merge_clock = bundle.canonical.manifest.vector_clock.clone();
    for copy in &bundle.copies {
        post_merge_clock = merge_vector_clocks(&post_merge_clock, &copy.manifest.vector_clock);
    }

    // #401: reconcile trash lists across canonical + every conflict copy,
    // the exact analog of the post_merge_clock fold above. Carried on the
    // draft; commit_with_decisions applies it (with purge-terminal
    // live-vs-trash resolution).
    let trash_lists: Vec<&[crate::vault::manifest::TrashEntry]> =
        std::iter::once(bundle.canonical.manifest.trash.as_slice())
            .chain(bundle.copies.iter().map(|c| c.manifest.trash.as_slice()))
            .collect();
    let merged_trash = crate::vault::trash_merge::merge_trash_lists(&trash_lists);

    let collisions: Vec<RecordCollisionSummary> = collisions
        .into_iter()
        .map(|(record_id, names)| RecordCollisionSummary {
            record_id,
            field_names: names.into_iter().collect(),
        })
        .collect();

    Ok(DraftMerge {
        vault_uuid: bundle.canonical.manifest.vault_uuid,
        plan: plan.clone(),
        manifest_hash: compute_manifest_hash(&bundle.canonical.raw_envelope_bytes),
        merged_records: merged_records.into_values().collect(),
        vetoes,
        collisions,
        post_merge_clock,
        merging_device,
        per_block_clocks,
        per_block_records,
        per_block_meta,
        merged_trash,
    })
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod parent_block_clock_tests;
