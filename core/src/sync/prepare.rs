//! `prepare_merge` — turn the C.1.1a [`crate::sync::VaultBundle`] into a
//! [`crate::sync::DraftMerge`] by decrypting each diverging block on
//! demand and composing the existing `merge_block` primitive into an
//! N-way pairwise fold.
//!
//! See `docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md`
//! §"prepare_merge". The module exposes [`prepare_merge`] (the
//! orchestrator entry point, re-exported via [`crate::sync`]) and
//! [`tombstone_veto_set`] (pure-function veto detector, `pub(crate)` —
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
    BlockId, DraftMerge, RecordCollisionSummary, RecordId, RecordTombstoneVeto,
};
use crate::sync::error::SyncError;
use crate::sync::outcome::DiffPlan;
use crate::unlock::UnlockedIdentity;
use crate::vault::block::{decode_block_file, decrypt_block, BlockPlaintext, VectorClockEntry};
use crate::vault::conflict::{merge_block, merge_vector_clocks};
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

/// Turn the C.1.1a [`VaultBundle`] into a [`DraftMerge`]. AEAD-decrypts
/// each diverging block envelope on demand, composes pairwise merges
/// via the existing [`merge_block`] primitive, and surfaces
/// record-level tombstone vetoes via [`tombstone_veto_set`].
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
///
/// # Algorithm
///
/// 1. Derive the owner public-key material + reader secret keys once
///    (see [`derive_block_reader_keys`]).
/// 2. For each `block_uuid` in `plan.diverging_blocks`, AEAD-decrypt the
///    canonical envelope and every copy envelope, then iteratively merge
///    via [`merge_block`]; the accumulator's records + per-block vector
///    clock advance per fold step. Run [`tombstone_veto_set`] across
///    the merged record set vs the per-copy plaintexts for the same
///    `record_uuid` and collect any vetoes. Extend the running
///    `merged_records` map (keyed by `record_uuid` — `merge_block`
///    already dedupes per block; this outer map dedupes across blocks).
/// 3. Fold the manifest-level vector clocks: `post_merge_clock =
///    merge_vector_clocks(canonical, copy_0, ..., copy_N)`.
/// 4. Construct the `DraftMerge`.
///
/// # Per-copy block-clock pairing
///
/// The per-copy block clock is looked up by matching each envelope's
/// BLAKE3-256 fingerprint against [`crate::vault::manifest::BlockEntry`]
/// `::fingerprint` on every copy manifest in `bundle.copies` (see
/// [`parent_block_clock`]). The 1a ingestion layer does NOT guarantee
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
///   (orphan sibling — see [`parent_block_clock`]).
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
) -> Result<DraftMerge, SyncError> {
    let keys = derive_block_reader_keys(vault_folder, identity)?;

    let mut merged_records: BTreeMap<[u8; 16], Record> = BTreeMap::new();
    let mut vetoes: Vec<RecordTombstoneVeto> = Vec::new();
    let mut per_block_clocks: BTreeMap<[u8; 16], Vec<VectorClockEntry>> = BTreeMap::new();
    let mut per_block_records: BTreeMap<[u8; 16], Vec<RecordId>> = BTreeMap::new();
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
        let mut acc_clock = canonical_block_clock;
        let mut acc_unknown = canonical_pt.unknown.clone();
        let acc_block_name = canonical_pt.block_name.clone();
        let acc_block_version = canonical_pt.block_version;
        let acc_schema_version = canonical_pt.schema_version;

        // Per-copy plaintexts retained across the iterative fold so the
        // veto pass at the bottom of the loop can compare the merged
        // accumulator against every copy's original record state.
        let mut copy_plaintexts: Vec<BlockPlaintext> =
            Vec::with_capacity(divergence.copy_envelopes.len());

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
            // Multi-device note: `user_uuid` is the single-owner v1
            // stand-in for the merging device. When multi-device support
            // lands, this becomes a real `device_uuid` on
            // `UnlockedIdentity` (or threaded from caller config).
            let merged = merge_block(
                &acc_pt,
                &acc_clock,
                &copy_pt,
                &copy_block_clock,
                identity.identity.user_uuid,
            )
            .map_err(|e| SyncError::InvalidArgument {
                detail: format!("merge_block: {e}"),
            })?;

            // Capture metadata-only field collisions BEFORE `merged` is
            // moved into `acc_records`. Projects already-computed LWW
            // collision metadata into the accumulator; touches no merge
            // logic and copies only field-name strings, never values.
            for rc in &merged.collisions {
                let entry = collisions.entry(rc.record_uuid).or_default();
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
            acc_clock = merged.vector_clock;
            acc_unknown = merged.merged.unknown;
            copy_plaintexts.push(copy_pt);
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

        merged_records.extend(acc_records);
    }

    let mut post_merge_clock = bundle.canonical.manifest.vector_clock.clone();
    for copy in &bundle.copies {
        post_merge_clock = merge_vector_clocks(&post_merge_clock, &copy.manifest.vector_clock);
    }

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
        per_block_clocks,
        per_block_records,
    })
}

#[cfg(test)]
mod tests {
    use super::tombstone_veto_set;
    use crate::crypto::secret::SecretString;
    use crate::sync::draft::BlockId;
    use crate::vault::record::{Record, RecordField, RecordFieldValue};
    use std::collections::BTreeMap;

    /// Construct a test [`Record`] with explicit tombstone state. All
    /// other fields take placeholder defaults — `tombstone_veto_set`
    /// only inspects `record_uuid`, `last_mod_ms`, `tombstone`,
    /// `tombstoned_at_ms`, and (via `last_modifier_device`) `fields`.
    fn rec(uuid: u8, last_mod_ms: u64, tombstone: bool, tombstoned_at_ms: u64) -> Record {
        Record {
            record_uuid: [uuid; 16],
            record_type: "kv".into(),
            fields: BTreeMap::new(),
            tags: Vec::new(),
            created_at_ms: 0,
            last_mod_ms,
            tombstone,
            tombstoned_at_ms,
            unknown: BTreeMap::new(),
        }
    }

    /// Construct a tombstoned peer [`Record`] carrying a single
    /// placeholder field with the supplied `field_device` as its
    /// `device_uuid`. Used to exercise the `last_modifier_device`
    /// happy path (`max_by_key(|f| f.last_mod)` returns `Some`).
    fn peer_with_field(
        uuid: u8,
        last_mod_ms: u64,
        tombstoned_at_ms: u64,
        field_device: [u8; 16],
    ) -> Record {
        let mut fields = BTreeMap::new();
        fields.insert(
            "username".to_string(),
            RecordField {
                value: RecordFieldValue::Text(SecretString::new(String::new())),
                last_mod: last_mod_ms,
                device_uuid: field_device,
                unknown: BTreeMap::new(),
            },
        );
        Record {
            record_uuid: [uuid; 16],
            record_type: "kv".into(),
            fields,
            tags: Vec::new(),
            created_at_ms: 0,
            last_mod_ms,
            tombstone: true,
            tombstoned_at_ms,
            unknown: BTreeMap::new(),
        }
    }

    /// Block-uuid placeholder used by every veto-set assertion. The
    /// value is opaque — `tombstone_veto_set` only forwards it into
    /// the returned `RecordTombstoneVeto.block_id`.
    const TEST_BLOCK_UUID: BlockId = [0xBB; 16];

    #[test]
    fn no_peers_no_veto() {
        let local = rec(1, 100, false, 0);
        assert!(tombstone_veto_set(&local, TEST_BLOCK_UUID, &[]).is_none());
    }

    #[test]
    fn peer_live_no_veto() {
        let local = rec(1, 100, false, 0);
        let peer = rec(1, 200, false, 0);
        assert!(tombstone_veto_set(&local, TEST_BLOCK_UUID, &[&peer]).is_none());
    }

    #[test]
    fn peer_tombstoned_before_local_edit_no_veto() {
        // local edited at t=100; peer tombstoned at t=50. Local
        // last_mod_ms (100) > peer.tombstoned_at_ms (50). LWW already
        // wins; no veto needed.
        let local = rec(1, 100, false, 0);
        let peer = rec(1, 50, true, 50);
        assert!(tombstone_veto_set(&local, TEST_BLOCK_UUID, &[&peer]).is_none());
    }

    #[test]
    fn peer_tombstoned_at_same_instant_as_local_edit_no_veto() {
        // Boundary: strict-later predicate. Equality goes silent.
        let local = rec(1, 100, false, 0);
        let peer = rec(1, 100, true, 100);
        assert!(tombstone_veto_set(&local, TEST_BLOCK_UUID, &[&peer]).is_none());
    }

    #[test]
    fn peer_tombstoned_after_local_edit_vetoes() {
        let local = rec(1, 100, false, 0);
        let peer = rec(1, 200, true, 200);
        let veto = tombstone_veto_set(&local, TEST_BLOCK_UUID, &[&peer]).expect("expected veto");
        assert_eq!(veto.record_id, [1; 16]);
        assert_eq!(veto.block_id, TEST_BLOCK_UUID);
        assert_eq!(veto.disk_tombstone_at_ms, 200);
    }

    #[test]
    fn local_tombstoned_no_veto_regardless_of_peer() {
        let local = rec(1, 100, true, 100);
        let peer = rec(1, 200, true, 200);
        assert!(tombstone_veto_set(&local, TEST_BLOCK_UUID, &[&peer]).is_none());
    }

    #[test]
    fn multiple_peers_latest_wins() {
        let local = rec(1, 100, false, 0);
        let peer_a = rec(1, 200, true, 200);
        let peer_b = rec(1, 300, true, 300);
        let veto = tombstone_veto_set(&local, TEST_BLOCK_UUID, &[&peer_a, &peer_b])
            .expect("expected veto");
        assert_eq!(veto.disk_tombstone_at_ms, 300);
    }

    /// `last_modifier_device` returns the `device_uuid` of the field
    /// with the maximum `last_mod`. When the peer record has a single
    /// field, that field's `device_uuid` is propagated unchanged into
    /// the returned veto's `disk_tombstoner_device`. Closes the gap
    /// that the empty-fields tests leave (they always exercise the
    /// `None` branch and the all-zero sentinel).
    #[test]
    fn veto_propagates_peer_field_device() {
        let local = rec(1, 100, false, 0);
        let peer = peer_with_field(1, 200, 200, [0x42; 16]);
        let veto = tombstone_veto_set(&local, TEST_BLOCK_UUID, &[&peer]).expect("expected veto");
        assert_eq!(veto.disk_tombstone_at_ms, 200);
        assert_eq!(veto.disk_tombstoner_device, [0x42; 16]);
    }

    /// On tied `tombstoned_at_ms` across peers, the veto carries the
    /// lexicographically smallest `device_uuid`. The result is
    /// independent of slice iteration order — running the helper on
    /// both peer orderings yields the same veto.
    #[test]
    fn tied_timestamps_smallest_device_wins() {
        let local = rec(1, 100, false, 0);
        let peer_high = peer_with_field(1, 200, 200, [0xFF; 16]);
        let peer_low = peer_with_field(1, 200, 200, [0x01; 16]);

        let v1 = tombstone_veto_set(&local, TEST_BLOCK_UUID, &[&peer_high, &peer_low])
            .expect("expected veto");
        let v2 = tombstone_veto_set(&local, TEST_BLOCK_UUID, &[&peer_low, &peer_high])
            .expect("expected veto");

        assert_eq!(v1.disk_tombstone_at_ms, 200);
        assert_eq!(v1.disk_tombstoner_device, [0x01; 16]);
        assert_eq!(v2.disk_tombstone_at_ms, 200);
        assert_eq!(v2.disk_tombstoner_device, [0x01; 16]);
    }
}

#[cfg(test)]
mod parent_block_clock_tests {
    //! Unit tests for [`parent_block_clock`] — proves the
    //! fingerprint-matching pairing is sound across the cases that
    //! positional-index pairing got wrong: copies missing this block,
    //! copies referencing a different envelope for the same block_uuid,
    //! and the orphan-envelope structural error.

    use super::parent_block_clock;
    use crate::crypto::hash::hash as blake3_hash;
    use crate::sync::bundle::ManifestSnapshot;
    use crate::vault::block::VectorClockEntry;
    use crate::vault::{BlockEntry, KdfParamsRef, Manifest};
    use std::path::PathBuf;

    /// Empty-on-everything Manifest; tests populate `blocks` per case.
    fn empty_manifest() -> Manifest {
        Manifest {
            manifest_version: 1,
            vault_uuid: [0u8; 16],
            format_version: 1,
            suite_id: 1,
            owner_user_uuid: [0u8; 16],
            vector_clock: vec![],
            blocks: vec![],
            trash: vec![],
            kdf_params: KdfParamsRef {
                memory_kib: 262_144,
                iterations: 3,
                parallelism: 1,
                salt: [0u8; 32],
            },
            unknown: std::collections::BTreeMap::new(),
        }
    }

    /// Wrap a manifest in a ManifestSnapshot with placeholder envelope
    /// bytes and source_path — `parent_block_clock` only inspects
    /// `manifest.blocks`.
    fn snapshot(manifest: Manifest) -> ManifestSnapshot {
        ManifestSnapshot {
            manifest,
            raw_envelope_bytes: vec![],
            source_path: PathBuf::from("/dev/null"),
        }
    }

    fn block_entry(block_uuid: [u8; 16], fp: [u8; 32], clock: Vec<VectorClockEntry>) -> BlockEntry {
        BlockEntry {
            block_uuid,
            block_name: String::new(),
            fingerprint: fp,
            recipients: vec![],
            vector_clock_summary: clock,
            suite_id: 1,
            created_at_ms: 0,
            last_mod_ms: 0,
            unknown: std::collections::BTreeMap::new(),
        }
    }

    const UUID_A: [u8; 16] = [0xAA; 16];
    const UUID_B: [u8; 16] = [0xBB; 16];

    #[test]
    fn returns_matching_manifests_clock_when_single_copy_matches() {
        let envelope = b"envelope-bytes-for-uuid-a".to_vec();
        let fp = *blake3_hash(&envelope).as_bytes();
        let clock = vec![VectorClockEntry {
            device_uuid: [0x11; 16],
            counter: 7,
        }];

        let mut m = empty_manifest();
        m.blocks.push(block_entry(UUID_A, fp, clock.clone()));

        let copies = vec![snapshot(m)];
        let got = parent_block_clock(&envelope, &UUID_A, &copies).expect("expected clock");
        assert_eq!(got, clock);
    }

    #[test]
    fn returns_first_match_when_multiple_copies_share_fingerprint() {
        // Two manifest siblings both reference the same unchanged block
        // (same fingerprint, same clock summary). Either is a valid
        // parent; the helper returns the first match.
        let envelope = b"envelope-bytes-shared".to_vec();
        let fp = *blake3_hash(&envelope).as_bytes();
        let clock = vec![VectorClockEntry {
            device_uuid: [0x22; 16],
            counter: 3,
        }];

        let mut m1 = empty_manifest();
        m1.blocks.push(block_entry(UUID_A, fp, clock.clone()));
        let mut m2 = empty_manifest();
        m2.blocks.push(block_entry(UUID_A, fp, clock.clone()));

        let copies = vec![snapshot(m1), snapshot(m2)];
        let got = parent_block_clock(&envelope, &UUID_A, &copies).expect("expected clock");
        assert_eq!(got, clock);
    }

    #[test]
    fn skips_copies_without_block_uuid_entry() {
        // copy[0] doesn't reference UUID_A at all; copy[1] does.
        // Positional-index pairing would have returned copy[0] (and
        // erroneously failed). Fingerprint pairing correctly finds
        // copy[1].
        let envelope = b"envelope-bytes-uuid-a".to_vec();
        let fp = *blake3_hash(&envelope).as_bytes();
        let clock_a = vec![VectorClockEntry {
            device_uuid: [0x33; 16],
            counter: 5,
        }];
        let other_fp = *blake3_hash(b"other-envelope").as_bytes();

        let mut m_other = empty_manifest();
        m_other.blocks.push(block_entry(
            UUID_B,
            other_fp,
            vec![VectorClockEntry {
                device_uuid: [0x44; 16],
                counter: 1,
            }],
        ));
        let mut m_target = empty_manifest();
        m_target
            .blocks
            .push(block_entry(UUID_A, fp, clock_a.clone()));

        let copies = vec![snapshot(m_other), snapshot(m_target)];
        let got = parent_block_clock(&envelope, &UUID_A, &copies).expect("expected clock");
        assert_eq!(got, clock_a);
    }

    #[test]
    fn skips_copies_with_different_fingerprint_for_same_uuid() {
        // copy[0] references UUID_A but with a different envelope
        // fingerprint (e.g. an older block version); copy[1] is the
        // actual parent. Positional pairing would have grabbed copy[0]'s
        // (wrong) clock summary.
        let envelope = b"envelope-bytes-new".to_vec();
        let fp_new = *blake3_hash(&envelope).as_bytes();
        let fp_old = *blake3_hash(b"envelope-bytes-old").as_bytes();
        let clock_new = vec![VectorClockEntry {
            device_uuid: [0x55; 16],
            counter: 9,
        }];
        let clock_old = vec![VectorClockEntry {
            device_uuid: [0x66; 16],
            counter: 4,
        }];

        let mut m_old = empty_manifest();
        m_old.blocks.push(block_entry(UUID_A, fp_old, clock_old));
        let mut m_new = empty_manifest();
        m_new
            .blocks
            .push(block_entry(UUID_A, fp_new, clock_new.clone()));

        let copies = vec![snapshot(m_old), snapshot(m_new)];
        let got = parent_block_clock(&envelope, &UUID_A, &copies).expect("expected clock");
        assert_eq!(got, clock_new);
    }

    #[test]
    fn errors_on_orphan_envelope_with_no_matching_manifest() {
        // The envelope authenticated (caller upstream) but no copy
        // manifest references it. Structural bundle error —
        // `parent_block_clock` returns InvalidArgument so the caller
        // can surface the issue rather than guess a clock.
        let envelope = b"orphan-envelope".to_vec();
        let fp_other = *blake3_hash(b"some-other-envelope").as_bytes();

        let mut m = empty_manifest();
        m.blocks.push(block_entry(
            UUID_A,
            fp_other,
            vec![VectorClockEntry {
                device_uuid: [0x77; 16],
                counter: 1,
            }],
        ));

        let copies = vec![snapshot(m)];
        let err = parent_block_clock(&envelope, &UUID_A, &copies).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("orphan block sibling"),
            "expected 'orphan block sibling' in error, got: {msg}"
        );
    }

    #[test]
    fn errors_on_empty_copies() {
        let envelope = b"envelope".to_vec();
        let copies: Vec<ManifestSnapshot> = vec![];
        let err = parent_block_clock(&envelope, &UUID_A, &copies).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("orphan block sibling"),
            "expected 'orphan block sibling' in error, got: {msg}"
        );
    }
}
