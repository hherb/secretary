//! Draft-merge types produced by [`crate::sync::prepare_merge`] and
//! consumed by [`crate::sync::commit_with_decisions`].
//!
//! See `docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md`
//! §"DraftMerge, RecordTombstoneVeto, VetoDecision".
//!
//! These are the public-API surface that connects the two halves of
//! C.1.1b's merge layer. [`prepare_merge`] returns a [`DraftMerge`]
//! summarising the CRDT merge of every diverging block (canonical +
//! conflict-copies) plus the set of record-level veto candidates the
//! caller must adjudicate. The caller pairs each veto with a
//! [`VetoDecision`] and feeds the pair back into
//! [`commit_with_decisions`], which atomically re-encrypts and
//! persists the result.
//!
//! Zeroize discipline: the types hold plaintext `Record`s after AEAD
//! decryption of peer blocks, so the wrappers derive
//! `Zeroize + ZeroizeOnDrop` per CLAUDE.md's memory-hygiene contract.
//! Non-secret framing fields (`vault_uuid`, plan, manifest hash,
//! vector-clock entries) carry `#[zeroize(skip)]`; the secret-bearing
//! `Record` payloads also carry `#[zeroize(skip)]` because [`Record`]
//! does not itself derive `Zeroize` (its
//! `RecordFieldValue::{Text(SecretString), Bytes(SecretBytes)}`
//! variants wipe via their own `ZeroizeOnDrop` impls on drop — the
//! drop-time wipe is the real contract, explicit `.zeroize()` on the
//! outer struct is defense-in-depth only).
//!
//! [`prepare_merge`]: crate::sync::prepare_merge
//! [`commit_with_decisions`]: crate::sync::commit_with_decisions
//! [`Record`]: crate::vault::record::Record

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::sync::bundle::ManifestHash;
use crate::sync::outcome::DiffPlan;
use crate::vault::block::VectorClockEntry;
use crate::vault::record::Record;

/// 16-byte record identifier alias. Records carry `record_uuid:
/// [u8; 16]` inline; this alias makes the API surface read self-
/// documenting without introducing a newtype boundary.
pub type RecordId = [u8; 16];

/// 16-byte block identifier alias. Mirrors [`RecordId`].
pub type BlockId = [u8; 16];

/// Output of [`crate::sync::prepare_merge`]. Carries the merged
/// records, the veto set (records the disk would tombstone but local
/// has live), and the freshness anchors needed for atomic commit.
///
/// **Zeroize discipline.** Holds plaintext peer-side data after AEAD
/// decryption — derives `Zeroize` + `ZeroizeOnDrop` per CLAUDE.md's
/// memory-hygiene contract. `merged_records` and `vetoes` hold
/// `Record`s with sealed-typed `SecretString` / `SecretBytes` fields;
/// drop-time zeroization wipes them through the inner field types'
/// own `ZeroizeOnDrop` impls. The [`DiffPlan`] and [`ManifestHash`]
/// are not secret material — annotated `#[zeroize(skip)]`. The
/// vector clock is a `Vec<VectorClockEntry>` of `(device_uuid,
/// counter)` pairs — not secret material; skipped.
///
/// `PartialEq` (not `Eq`) for the same reason as [`Record`]: forward-
/// compat unknown-key payloads (`UnknownValue`) wrap `ciborium::Value`
/// which is not `Eq`. No call site requires `Eq`.
#[derive(Debug, Clone, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct DraftMerge {
    /// Vault UUID; mirrors `bundle.canonical.manifest.vault_uuid`. The
    /// commit returns a `SyncState` built from this + `post_merge_clock`.
    #[zeroize(skip)]
    pub vault_uuid: [u8; 16],
    /// Forwarded from `SyncOutcome::ConcurrentDetected`.
    #[zeroize(skip)]
    pub plan: DiffPlan,
    /// Freshness anchor: the BLAKE3-256 of the manifest envelope bytes
    /// at the moment `sync_once` saw the disk. The commit re-hashes
    /// the on-disk manifest and aborts with `SyncError::EvidenceStale`
    /// if they differ.
    #[zeroize(skip)]
    pub manifest_hash: ManifestHash,
    /// CRDT merge output: one entry per record that exists in any
    /// diverging block (canonical or copy) post-merge. Tombstoned
    /// records remain in this list — the commit needs them to write
    /// the death clock to disk.
    #[zeroize(skip)]
    pub merged_records: Vec<Record>,
    /// Records the merge would tombstone if accepted as-is, but where
    /// the local (canonical) side has the record live. Caller must
    /// supply one [`VetoDecision`] per entry. Empty vec = silent merge.
    #[zeroize(skip)]
    pub vetoes: Vec<RecordTombstoneVeto>,
    /// Component-wise max of canonical + every copy's manifest-level
    /// vector clock. Becomes the manifest's `vector_clock` post-commit
    /// (caller's local `SyncState.highest_vector_clock_seen` advances
    /// to match).
    #[zeroize(skip)]
    pub post_merge_clock: Vec<VectorClockEntry>,
}

/// One record that the merge would tombstone if accepted as-is, but
/// where the local side has it still live. The user picks per-record
/// ([`VetoDecision::KeepLocal`] vs [`VetoDecision::AcceptTombstone`]).
/// D2 + D3 — record-level only.
///
/// **Zeroize discipline.** Holds the local plaintext `Record` after
/// AEAD decryption of the canonical block. Derives
/// `Zeroize + ZeroizeOnDrop`; the `local_state: Record` field is
/// `#[zeroize(skip)]` because [`Record`] does not derive `Zeroize` —
/// its secret-bearing `RecordFieldValue` variants
/// (`Text(SecretString)` and `Bytes(SecretBytes)`) wipe themselves on
/// drop. The `disk_tombstoner_device` and `disk_tombstone_at_ms`
/// fields are wiped explicitly on zeroize as defense-in-depth.
#[derive(Debug, Clone, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct RecordTombstoneVeto {
    /// 16-byte UUID of the disputed record.
    #[zeroize(skip)]
    pub record_id: RecordId,
    /// 16-byte UUID of the block that owns this record.
    #[zeroize(skip)]
    pub block_id: BlockId,
    /// What the local (canonical) side has live. Held in plaintext
    /// after `prepare_merge` AEAD-decrypts the canonical block — the
    /// outer struct's `ZeroizeOnDrop` derive plus the [`Record`]'s
    /// own sealed-typed field discipline handle the wipe on drop.
    #[zeroize(skip)]
    pub local_state: Record,
    /// The peer's `tombstoned_at_ms` — the timestamp at which the
    /// remote side observed the tombstone.
    pub disk_tombstone_at_ms: u64,
    /// 16-byte UUID of the device that recorded the tombstone.
    pub disk_tombstoner_device: [u8; 16],
}

/// Caller's decision on a single tombstone veto.
///
/// `commit_with_decisions` enforces `decisions.len() == vetoes.len()`
/// AND `{decision.record_id} == {veto.record_id}` (bijection), failing
/// with [`crate::sync::SyncError::MissingVetoDecision`] /
/// [`crate::sync::SyncError::UnknownVetoDecision`] on violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VetoDecision {
    /// Reject the peer's tombstone. The record stays alive on disk;
    /// the local state survives.
    KeepLocal {
        /// Record UUID this decision applies to.
        record_id: RecordId,
    },
    /// Honour the peer's tombstone. The record is tombstoned at the
    /// peer's `tombstoned_at_ms` after commit.
    AcceptTombstone {
        /// Record UUID this decision applies to.
        record_id: RecordId,
    },
}

impl VetoDecision {
    /// The `record_id` this decision applies to. Used by the
    /// bijection-check pass in `commit_with_decisions`.
    #[must_use]
    pub fn record_id(&self) -> RecordId {
        match self {
            VetoDecision::KeepLocal { record_id } | VetoDecision::AcceptTombstone { record_id } => {
                *record_id
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Construct a minimal-but-valid [`Record`] for tests. The
    /// `last_mod_ms` parameter doubles as the synthetic clock anchor;
    /// `created_at_ms` is set 1000 ms earlier (well-formed under the
    /// `tombstoned_at_ms ≤ last_mod_ms` invariant — see
    /// `core/src/vault/record.rs` §"Invariants on well-formed records").
    fn dummy_record(uuid: u8, last_mod_ms: u64) -> Record {
        Record {
            record_uuid: [uuid; 16],
            record_type: "kv".into(),
            fields: BTreeMap::new(),
            tags: Vec::new(),
            created_at_ms: last_mod_ms.saturating_sub(1_000),
            last_mod_ms,
            tombstone: false,
            tombstoned_at_ms: 0,
            unknown: BTreeMap::new(),
        }
    }

    /// Calling [`RecordTombstoneVeto::zeroize`] wipes the explicitly-
    /// zeroized fields (`disk_tombstone_at_ms`, `disk_tombstoner_device`)
    /// and compiles cleanly despite `local_state: Record` carrying
    /// `#[zeroize(skip)]`. The drop-time wipe of the contained
    /// `Record`'s `SecretString` / `SecretBytes` field values is
    /// covered by the inner types' own `ZeroizeOnDrop` impls — this
    /// test asserts the wrapper's discipline holds, not that the
    /// `Record` was wiped.
    ///
    /// Also pins the `#[zeroize(skip)]` semantics on the framing
    /// fields (`record_id`, `block_id`, `local_state`): if a future
    /// edit drops the skip annotation, these post-zeroize equality
    /// checks fail, catching the regression at test time.
    #[test]
    fn record_tombstone_veto_zeroize_preserves_local_state() {
        let r = dummy_record(0xAA, 1_000);
        let mut veto = RecordTombstoneVeto {
            record_id: [0xAA; 16],
            block_id: [0xBB; 16],
            local_state: r,
            disk_tombstone_at_ms: 2_000,
            disk_tombstoner_device: [0xCC; 16],
        };
        assert_eq!(veto.local_state.record_type, "kv");
        veto.zeroize();
        assert_eq!(veto.disk_tombstone_at_ms, 0);
        assert_eq!(veto.disk_tombstoner_device, [0u8; 16]);
        // Skip-annotated framing fields must survive zeroize().
        assert_eq!(veto.record_id, [0xAA; 16]);
        assert_eq!(veto.block_id, [0xBB; 16]);
        assert_eq!(veto.local_state.record_type, "kv");
    }

    /// [`VetoDecision`] equality is structural over the variant
    /// discriminant and the embedded `record_id`. Two `KeepLocal`s on
    /// the same record_id compare equal; a `KeepLocal` and an
    /// `AcceptTombstone` on the same record_id do not; two `KeepLocal`s
    /// on different record_ids do not.
    #[test]
    fn veto_decision_eq_is_structural() {
        let a = VetoDecision::KeepLocal { record_id: [1; 16] };
        let b = VetoDecision::KeepLocal { record_id: [1; 16] };
        let c = VetoDecision::AcceptTombstone { record_id: [1; 16] };
        let d = VetoDecision::KeepLocal { record_id: [2; 16] };
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    /// [`VetoDecision::record_id`] returns the same UUID for both
    /// variants — required because `commit_with_decisions`'s bijection
    /// check uses this accessor uniformly.
    #[test]
    fn veto_decision_record_id_accessor() {
        let keep = VetoDecision::KeepLocal {
            record_id: [0x11; 16],
        };
        let accept = VetoDecision::AcceptTombstone {
            record_id: [0x22; 16],
        };
        assert_eq!(keep.record_id(), [0x11; 16]);
        assert_eq!(accept.record_id(), [0x22; 16]);
    }

    /// [`DraftMerge`] holds the six required fields (vault UUID, plan,
    /// manifest hash, merged records, vetoes, post-merge clock) in
    /// shapes the downstream `commit_with_decisions` consumes.
    #[test]
    fn draft_merge_holds_required_fields() {
        let d = DraftMerge {
            vault_uuid: [9; 16],
            plan: DiffPlan {
                diverging_blocks: vec![[0; 16]],
            },
            manifest_hash: ManifestHash([0; 32]),
            merged_records: Vec::new(),
            vetoes: Vec::new(),
            post_merge_clock: Vec::new(),
        };
        assert_eq!(d.vault_uuid, [9; 16]);
        assert_eq!(d.plan.diverging_blocks.len(), 1);
        assert!(d.vetoes.is_empty());
        assert!(d.merged_records.is_empty());
        assert!(d.post_merge_clock.is_empty());
        assert_eq!(d.manifest_hash, ManifestHash([0; 32]));
    }
}
