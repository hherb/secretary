# C.1.1b — Sync orchestration: automatic merge + veto-on-tombstone

**Date:** 2026-05-18
**Phase:** Sub-project C, phase C.1.1b (third slice — merge + commit layer)
**Status:** Design approved (D1–D5 + atomicity option (d) settled in conversation 2026-05-18); waiting on C.1.1a to land before implementation begins
**Predecessor:** [`docs/superpowers/specs/2026-05-18-c1-1a-conflict-copy-ingestion-design.md`](2026-05-18-c1-1a-conflict-copy-ingestion-design.md) — the conflict-copy ingestion layer whose `VaultBundle` this design's `prepare_merge` consumes
**Root predecessor:** [`docs/superpowers/specs/2026-05-17-c1-sync-detection-design.md`](2026-05-17-c1-sync-detection-design.md)

---

## Reorganisation note (2026-05-18)

The original C.1.1 brainstorm settled D1–D5 + atomicity option (d) for the merge layer (this document), then surfaced a fundamental gap during spec self-review: **the merge layer needs a second source**. `merge_block` and `merge_record` both take `(local, remote)` two-side inputs, and Secretary's cloud-folder sync model provides the "remote" side via conflict-copy files (Dropbox `(conflicted copy <date>)`, iCloud `… 2.cbor.enc`, etc.) that no current code path ingests.

C.1.1 was therefore split into two sequential slices per the user's brick-by-brick preference:

- **C.1.1a** — conflict-copy ingestion (`VaultBundle` type + sibling-manifest authentication + vault_uuid agreement check). Lands first; design at the C.1.1a spec linked above.
- **C.1.1b** — this document. The merge + veto + commit layer, consuming the `VaultBundle` from 1a. Lands after 1a is merged to `main`.

The design below remains correct in shape. The one signature change relative to what was approved in conversation is that `prepare_merge` gains a `bundle: &VaultBundle` parameter so it can read the conflict-copy "remote" side. Function order becomes `sync_once → prepare_merge(folder, identity, plan, bundle) → commit_with_decisions`.

---

## Context

C.1 phase 1 (PR #74) shipped detection-only sync orchestration: `sync_once` classifies disk state into `NothingToDo` / `AppliedAutomatically` / `ForkDetected` / `RollbackRejected`. The `ForkDetected` branch is **terminal** in phase 1 — concurrent vector clocks are reported but not merged.

C.1.1 takes over the concurrent branch. It adds:

1. **Automatic CRDT merge** for any concurrent state — composed from the existing `core::vault::conflict::merge_record` and `merge_block` primitives (which already pass commutativity / associativity / idempotence / well-formedness proptests).
2. **Veto-on-tombstone workflow** — when the disk's authoritative record state would tombstone a record the local side still has live, the user is asked to decide before the merge commits. Field-level LWW conflicts are resolved silently by the existing CRDT.
3. **A new on-disk-format-verification gap fix in `open_vault`** — adding per-block fingerprint verification that the C.1 phase 1 spec already claimed was in place but actually wasn't. This is the lowest-risk crash-safety story for multi-block atomic commit, and pays a latent debt across `save_block` / `share_block` / `trash_block` / `restore_block` at the same time.

## Goals

C.1.1 delivers a three-step Rust API surface that turns one concurrent state into a committed merge:

| Step | Function | Reads disk? | Writes disk? | Returns |
|---|---|---|---|---|
| 1 | `sync_once` (extended) | manifest only | no | `SyncOutcome::ConcurrentDetected { plan, manifest_hash, ... }` |
| 2 | `prepare_merge` (new) | divergence blocks | no | `DraftMerge { merged_records, vetoes, post_merge_clock, ... }` |
| 3 | `commit_with_decisions` (new) | re-reads manifest for freshness check | yes (atomic) | `SyncState` |

Caller may abort between any two steps without on-disk consequences.

## Non-goals

- **No FFI surface change.** C.1.1 is core-only. B-side projection follows in C.3.
- **No Python clean-room replay of the new KAT vectors.** Scoped into [issue #76](https://github.com/hherb/secretary/issues/76) (C.4 work).
- **No "backup-restore override" for `RollbackRejected`.** Per C.1 phase 1 §non-goals; deferred to C.1.x or the C.2 CLI layer.
- **No conflict-copy file ingestion** (`VaultBundle` with `.conflict-copy.*` variants). Orthogonal to the three-step merge flow; future C.x phase.
- **No background sync / daemonisation.** Foreground-only mental model frozen in C.1 phase 1 D1.
- **No record-resurrection workflow beyond `KeepLocal`.** Undoing an `AcceptTombstone` later is an unrelated UX surface.
- **No multi-vault batching.** One vault per `sync_once → prepare_merge → commit_with_decisions` chain.
- **No on-disk pending-merge state.** Per D2 (single-call atomicity); crashes during the user dialog cause re-detection on relaunch, not resumption.
- **No new fuzz targets.** The new types are not deserialised from untrusted bytes; the existing six fuzz targets cover the on-disk format surfaces.

## Design decisions and the rationale chain

Five substantive decisions shape this design, on top of the four C.1 phase 1 decisions (foreground-only sync, peer-originated-tombstone-only veto scope, free-function API style, detect-then-merge phasing).

### D1 — `SyncOutcome` variant shape: layered

`ForkDetected` is **deleted**. `AppliedAutomatically` generalises to cover both clean dominance and silent merges with no vetoes. `ConcurrentDetected` is added for any concurrent state — vetoes are not yet known at sync_once time (see D4/D5).

```rust
pub enum SyncOutcome {
    NothingToDo,
    AppliedAutomatically { new_state: SyncState },   // dominance only post-C.1.1; merges go via three-step API
    ConcurrentDetected {
        plan: DiffPlan,
        manifest_hash: ManifestHash,
        disk_vector_clock: Vec<VectorClockEntry>,
        local_highest_seen: Vec<VectorClockEntry>,
    },
    RollbackRejected(RollbackEvidence),
}
```

Rationale: every concurrent state is mergeable via the existing CRDT (closure property). Defensive "what if merge fails" is unreachable in practice — YAGNI per `feedback_security_no_assumptions.md`'s "pick enforcement over plausibility" principle. Three observable terminal states post-detection (NothingToDo / AppliedAutomatically / RollbackRejected) plus one follow-up state (ConcurrentDetected) keeps the match exhaustive and the meaning of each variant single-purpose.

### D2 — `commit_with_decisions` atomicity: single-call

`commit_with_decisions` is one atomic entry point. No on-disk pending-merge state; no two-phase prepare/finalise; no sidecar files.

Rationale: app crash between sync_once and commit is recoverable by re-detection — sync_once is idempotent on unchanged disk state. The two-phase complexity (sidecar schema, lifecycle, cleanup, recovery) would solve a UX-resilience problem that hasn't materialised. Per `feedback_security_no_assumptions.md`: don't pre-engineer for non-security UX flows.

### D3 — Veto granularity: record-level only (closed in C.1 phase 1)

The C.1 phase 1 design doc settled this at section D2 line 60–66: "When automatic merge ships (C.1.1), the only merge outcome that surfaces a user-veto prompt is a peer-originated record tombstone that would delete a locally-live record. Field-level LWW overwrites, block disappearances from the cloud folder, and all other merge outcomes apply silently per the existing §11 spec."

Re-stated here for completeness; not re-opened in C.1.1.

### D4 — Disk-block readout: lazy, with manifest-hash freshness guard

`sync_once` still reads only the manifest. When concurrent state is detected, it returns a `DiffPlan` (which records to pull) and a `ManifestHash` (anchor for freshness verification at commit time). A follow-up `prepare_merge(folder, identity, plan)` reads only the diverging blocks.

Rationale:
- Cost is **O(divergence_size)**, not O(vault_size). Polls on quiet vaults stay cheap.
- Secrets stay sealed in encrypted form on disk until the user actually opens the veto dialog. The decryption surface widens only on-demand.
- Aligns with `Sensitive<T>` discipline per CLAUDE.md memory-hygiene: minimise the window during which plaintext sits in memory.

### D5 — Detect / merge / commit split: three-step API

D1 + D4 together force one more decision: at `sync_once` time we don't yet know if a concurrent state will need vetoes (records have not been read). Two options exist; the design picks **three-step API**:

```rust
sync_once(folder, identity, state, _now_ms) -> SyncOutcome
    // returns ConcurrentDetected { plan, manifest_hash, ... } for ANY concurrent state

prepare_merge(folder, identity, plan) -> DraftMerge
    // reads divergence blocks, runs merge_record, computes vetoes
    // DraftMerge.vetoes may be empty (silent merge case)

commit_with_decisions(folder, identity, draft, decisions, now_ms) -> SyncState
    // verifies manifest_hash still matches, applies decisions, atomic disk write
```

Rationale for three-step over a two-step "sync_once reads divergence blocks too" alternative:
- Preserves the secrets-stay-sealed-until-dialog property of D4.
- Caller decides whether to invoke `prepare_merge` at all (e.g., a polling status check can skip it).
- `DraftMerge.vetoes.is_empty()` is the caller's silent-vs-dialog branch — clean and explicit.

### D6 — Crash-safety story for multi-block commit: option (d) — block-first manifest-last + read-time fingerprint verification

`commit_with_decisions` rewrites N affected blocks followed by the manifest, using per-file `write_atomic` (same as existing `save_block`). The crash window between block writes and manifest write would, today, leave the vault in a state where some on-disk block bytes don't match the manifest's `BlockEntry.fingerprint`. The current `open_vault` doesn't verify these fingerprints (grep-confirmed, despite the C.1 phase 1 spec line 253 asserting it does), so a partial commit would silently corrupt the user's merge result — appearing to "lose" K records' updates.

C.1.1 fixes this by adding `verify_block_fingerprints(folder, manifest) -> Result<(), VaultError>` and calling it inside `open_vault` after the manifest signature is verified. Partial commits are then **detected** (typed `VaultError::BlockFingerprintMismatch`), and the caller can re-run sync_once + prepare_merge + commit_with_decisions to converge — CRDT idempotence guarantees the retry produces the same final state.

Alternatives considered:

| Option | Why rejected |
|---|---|
| (a) Inherit save_block's silent-partial-write window | Silent corruption is the highest-risk failure mode. Hides the bug from the user. |
| (b) `manifest.prev` backup for undo | Doesn't actually recover the K already-written blocks — same mismatch window as (a), just deliberately re-entered. |
| (c) Stage-rename via `.new` suffix and atomic flip | Either requires spec change (filenames in manifest body — v1 freeze violation) or new `open_vault` fallback path + new failure modes; ~300 LOC. |

Option (d) is **lowest-risk** because: (i) it detects rather than masks partial commits; (ii) it doesn't expand attack surface — only adds a BLAKE3 equality check against an already-signed value; (iii) it closes the existing gap that C.1 phase 1's spec already claimed was closed; (iv) recovery is provably correct via CRDT idempotence rather than a new recovery state machine. Cost: ~175 LOC, almost entirely in `core/src/vault/orchestrators.rs`.

## Public API

### `SyncOutcome` (modified — `core/src/sync/outcome.rs`)

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncOutcome {
    /// Disk has nothing new since the last sync. No state mutation.
    NothingToDo,

    /// Disk strictly dominates local highest_seen. The disk state is
    /// the new canonical truth. Caller persists `new_state` to OS
    /// keystore before next sync. Pre-C.1.1 also covered concurrent
    /// states that produced silent merges; post-C.1.1 those go via
    /// the three-step API (sync_once returns ConcurrentDetected first).
    AppliedAutomatically { new_state: SyncState },

    /// Disk and local highest_seen are concurrent (incomparable).
    /// Caller invokes `prepare_merge` with the carried `plan` to
    /// read divergence blocks and compute the draft + vetoes.
    /// `manifest_hash` is the freshness anchor consulted by
    /// `commit_with_decisions` to detect disk changes between
    /// prepare and commit.
    ConcurrentDetected {
        plan: DiffPlan,
        manifest_hash: ManifestHash,
        disk_vector_clock: Vec<VectorClockEntry>,
        local_highest_seen: Vec<VectorClockEntry>,
    },

    /// Disk vector clock is strictly dominated by local highest_seen.
    /// Per `crypto-design.md` §10 — rollback rejected. Caller's UX
    /// may offer an "I am restoring from backup, accept anyway"
    /// override (deferred to C.1.x or the C.2 CLI layer).
    RollbackRejected(RollbackEvidence),
}
```

`ForkDetected` is **removed**. (Source compatibility break with C.1 phase 1 — there are no external callers yet; in-tree call sites are limited to test code and are updated as part of C.1.1.)

### `DiffPlan` and `ManifestHash` (defined in `core/src/sync/diff.rs`; producer is C.1.1a)

```rust
/// Blocks whose state diverges between the canonical manifest and at
/// least one conflict-copy manifest. Computed by C.1.1a's
/// `compute_diff_plan` from the assembled `VaultBundle`; consumed by
/// this slice's `prepare_merge` to drive the per-block merge loop.
///
/// **Shape note (2026-05-18 reorganisation):** the original C.1.1
/// brainstorm sketched this as `Vec<(BlockId, RecordId)>`, which was
/// the wrong granularity — the merge primitive `merge_block` operates
/// per-block and produces merged records as output, not as input.
/// The correct shape is `Vec<[u8; 16]>` of diverging block_uuids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffPlan {
    pub diverging_blocks: Vec<[u8; 16]>,   // sorted ascending; deduped
}

/// BLAKE3-256 of the full on-disk manifest envelope bytes (header + body + sig).
///
/// Used by `commit_with_decisions` as a TOCTOU freshness check: if the
/// manifest on disk has changed between `prepare_merge` and `commit`,
/// the commit aborts with `SyncError::EvidenceStale` and the caller
/// retries from `sync_once`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestHash(pub [u8; 32]);
```

### `DraftMerge`, `RecordTombstoneVeto`, `VetoDecision` (new — `core/src/sync/draft.rs`)

```rust
/// Output of `prepare_merge`. Carries the merged records, the veto set
/// (records where the disk would tombstone something local has live),
/// and the freshness anchors needed for atomic commit.
///
/// Holds plaintext secrets after decryption — derives Zeroize +
/// ZeroizeOnDrop per CLAUDE.md memory-hygiene contract.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct DraftMerge {
    pub vault_uuid: [u8; 16],                        // = bundle.canonical.manifest.vault_uuid; needed for the returned SyncState
    pub plan: DiffPlan,                              // forwarded from ConcurrentDetected
    pub manifest_hash: ManifestHash,                 // forwarded from ConcurrentDetected
    pub merged_records: Vec<MergedRecord>,           // CRDT merge output
    pub vetoes: Vec<RecordTombstoneVeto>,            // record-level only (D3)
    pub post_merge_clock: Vec<VectorClockEntry>,     // = merge_vector_clocks folded across canonical + all copies
}

/// One record that the merge would tombstone if accepted as-is, but
/// where the local side has it still live. The user picks per-record.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecordTombstoneVeto {
    pub record_id: RecordId,
    pub block_id: BlockId,
    pub local_state: RecordSnapshot,                 // what the local side has live (sealed-typed fields)
    pub disk_tombstone_at_ms: u64,
    pub disk_tombstoner_device: [u8; 16],
}

/// Caller's decision on a single tombstone veto.
///
/// `decisions.len() == vetoes.len()` AND each decision's record_id ∈
/// vetoes.record_ids — bijection enforced by `commit_with_decisions`,
/// which returns `MissingVetoDecision` or `UnknownVetoDecision` on
/// violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VetoDecision {
    KeepLocal { record_id: RecordId },               // reject the peer's tombstone; record stays alive
    AcceptTombstone { record_id: RecordId },         // honour the peer's delete
}
```

`MergedRecord` and `RecordSnapshot` are thin wrappers around `Record` with the same sealed-typed field discipline (`SecretString` / `SecretBytes` per CLAUDE.md). They reuse the existing `Record` machinery rather than duplicating it.

### `sync_once` (extended — `core/src/sync/once.rs`)

Signature unchanged from C.1 phase 1. Dispatch changes:

| `ClockRelation` | Pre-C.1.1 `SyncOutcome` | Post-C.1.1 `SyncOutcome` |
|---|---|---|
| `Equal` | `NothingToDo` | `NothingToDo` (unchanged) |
| `IncomingDominates` | `AppliedAutomatically { new_state }` | `AppliedAutomatically { new_state }` (unchanged) |
| `IncomingDominated` | `RollbackRejected(...)` | `RollbackRejected(...)` (unchanged) |
| `Concurrent` | `ForkDetected { ... }` | `ConcurrentDetected { plan, manifest_hash, ... }` |

For the `Concurrent` arm, `sync_once` additionally computes:

- `manifest_hash`: BLAKE3-256 of the on-disk manifest envelope bytes (already read at step 1).
- `plan`: derived by walking the manifest's per-block `vector_clock_summary` against `state.highest_vector_clock_seen`. Only blocks whose summary is not dominated by local-seen are included. Pure helper, lives in `core/src/sync/once.rs` alongside `sync_once`.

`sync_once` does NOT read any block files in C.1.1 (lazy per D4).

### `prepare_merge` (new — `core/src/sync/prepare.rs`)

```rust
pub fn prepare_merge(
    vault_folder: &Path,
    identity: &UnlockedIdentity,
    bundle: &VaultBundle,           // produced by C.1.1a's sync_once on the Concurrent path
    plan: &DiffPlan,                // also produced by 1a; carried in SyncOutcome::ConcurrentDetected
) -> Result<DraftMerge, SyncError>;
```

Algorithm:

1. For each `block_uuid` in `plan.diverging_blocks`:
   1. Find `bundle.diverging_blocks[&block_uuid]` → `BlockDivergence { canonical_envelope, copy_envelopes }`.
   2. AEAD-decrypt `canonical_envelope.bytes` using `identity` → `canonical_plaintext: BlockPlaintext`.
   3. For each envelope in `copy_envelopes`, AEAD-decrypt → `Vec<BlockPlaintext>`.
   4. Iteratively merge per 1a-D2 (N-way iterative pairwise):
      ```
      acc = canonical_plaintext
      acc_clock = canonical_block_entry.vector_clock_summary
      for (copy_pt, copy_clock) in zip(copy_plaintexts, copy_block_entries):
          merged_block = merge_block(acc, acc_clock, copy_pt, copy_clock, device_uuid)?;
          acc = merged_block.merged
          acc_clock = merged_block.vector_clock
      ```
   5. The merged records for this block_uuid go into the running `merged_records` collection.
2. After all blocks are processed, walk the merged records. For each `(block_uuid, record_uuid)` pair, run `tombstone_veto_set(local: &Record, remote_per_copy: &[&Record]) -> Option<RecordTombstoneVeto>`:
   - Returns `Some(veto)` if any remote copy has `tombstoned_at_ms > local.last_mod_ms` AND `local.is_alive()`.
   - Pure function, lives in `core/src/sync/prepare.rs`.
3. Assemble `DraftMerge { plan, manifest_hash, merged_records, vetoes, post_merge_clock, vault_uuid }`. `post_merge_clock = merge_vector_clocks` folded across canonical + all copies' manifest clocks. `vault_uuid` comes from `bundle.canonical.manifest.vault_uuid`.

### `commit_with_decisions` (new — `core/src/sync/commit.rs`)

```rust
pub fn commit_with_decisions(
    vault_folder: &Path,
    identity: &UnlockedIdentity,
    draft: DraftMerge,
    decisions: Vec<VetoDecision>,
    now_ms: u64,
) -> Result<SyncState, SyncError>;
```

Algorithm:

1. **Freshness re-check.** Read manifest envelope bytes; compute BLAKE3-256. Compare to `draft.manifest_hash`. Mismatch → `SyncError::EvidenceStale`. (Caller retries from `sync_once`.)
2. **Decision bijection check.** Verify `decisions.len() == draft.vetoes.len()` and the set of `record_id`s match exactly. Mismatch → `SyncError::MissingVetoDecision` or `SyncError::UnknownVetoDecision`.
3. **Apply decisions to `draft.merged_records`.** For each `KeepLocal { id }`: clear the disk tombstone, restore local record state. For each `AcceptTombstone { id }`: leave the record tombstoned at disk's `tombstoned_at_ms`.
4. **Re-derive affected block bytes.** For each affected block, encrypt + sign (per existing `save_block` step 1-6). Compute BLAKE3 fingerprint of each new block file.
5. **Build new manifest body.** Update `BlockEntry.fingerprint` for each affected block. Set `vector_clock = draft.post_merge_clock`. Set `last_mod_ms = now_ms`. Re-sign hybrid (Ed25519 ∧ ML-DSA).
6. **Write to disk (atomic per file; block-first then manifest):**
   - For each affected block: `io::write_atomic(blocks/<uuid>.cbor.enc, new_bytes)`.
   - `io::write_atomic(manifest.cbor.enc, new_manifest_bytes)` **LAST** — commit point.
7. **Return** `SyncState { vault_uuid: draft.vault_uuid, highest_vector_clock_seen: draft.post_merge_clock }`.

**Crash recovery.** Per D6 / option (d): if interrupted between step 6's block writes and the manifest write, on the next `sync_once` the new `open_vault` fingerprint verification detects the mismatch and returns `VaultError::BlockFingerprintMismatch`. The caller surfaces this to the user as "incomplete previous sync; retrying" and re-runs `sync_once → prepare_merge → commit_with_decisions`. CRDT idempotence guarantees the retried convergence reaches the same final state.

### `verify_block_fingerprints` (new — `core/src/vault/orchestrators.rs`)

```rust
pub(crate) fn verify_block_fingerprints(
    folder: &Path,
    manifest: &ManifestBody,
) -> Result<(), VaultError>;
```

Walks `manifest.blocks`. For each `BlockEntry`, reads the on-disk file at `folder/blocks/<uuid>.cbor.enc`, computes BLAKE3-256, compares to `entry.fingerprint`. Returns the first mismatch as `VaultError::BlockFingerprintMismatch { block_uuid, expected, got }`. Called inside `open_vault` after the manifest hybrid signature has been verified — verification order is "manifest is authentic, THEN check it matches disk".

### `SyncError` extensions (`core/src/sync/error.rs`)

```rust
#[error("manifest changed on disk between prepare_merge and commit_with_decisions")]
EvidenceStale,

#[error("decision references unknown veto record_id: {record_id:?}")]
UnknownVetoDecision { record_id: RecordId },

#[error("decision missing for tombstone veto record_id: {record_id:?}")]
MissingVetoDecision { record_id: RecordId },

#[error("merge produced no draft records but vetoes are non-empty (internal invariant)")]
EmptyDraftWithVetoes,   // defensive — should be unreachable
```

### `VaultError` extension (`core/src/vault/mod.rs`)

```rust
#[error("block {block_uuid:?} fingerprint mismatch: manifest expected {expected:?}, disk has {got:?}")]
BlockFingerprintMismatch {
    block_uuid: [u8; 16],
    expected: [u8; 32],
    got: [u8; 32],
},
```

## Module file layout

```
core/src/sync/
├── mod.rs            existing — extend pub-use re-exports
├── state.rs          existing ~unchanged — SyncState + CBOR
├── outcome.rs        existing modified — ConcurrentDetected replaces ForkDetected
├── error.rs          existing + 4 new variants
├── once.rs           existing 100 → ~180 LOC (ConcurrentDetected branch + diff-plan helper)
├── diff.rs           NEW ~80 LOC  — DiffPlan + ManifestHash + ctor + canonical-sort
├── draft.rs          NEW ~150 LOC — DraftMerge + RecordTombstoneVeto + VetoDecision + zeroize coverage
├── prepare.rs        NEW ~300 LOC — prepare_merge + tombstone_veto_set helper
└── commit.rs         NEW ~400 LOC — commit_with_decisions + apply_decisions helper
```

All under the 500-LOC threshold per `feedback_split_files_proactively.md`. Each file is one concept. The heaviest unit is `commit.rs` (multi-block atomic write + freshness re-verification + decision-bijection enforcement); the second-heaviest is `prepare.rs` (per-block read + merge composition + veto-set computation).

Outside `core/src/sync/`:

```
core/src/vault/orchestrators.rs   +verify_block_fingerprints (~30 LOC) + call in open_vault (1 line)
core/src/vault/mod.rs             +BlockFingerprintMismatch variant (~5 LOC)
```

## Testing strategy

### Integration tests — `core/tests/sync_merge.rs` (new)

| Test | Asserts |
|---|---|
| `prepare_merge_concurrent_no_vetoes_returns_empty_vetoes` | Concurrent clocks + no tombstone-vs-live → `DraftMerge.vetoes.is_empty()` |
| `prepare_merge_single_tombstone_veto_surfaces_one_decision` | Disk tombstoned a record local has live → exactly one `RecordTombstoneVeto` |
| `prepare_merge_multiple_tombstone_vetoes` | N disk tombstones vs N live local records → N vetoes |
| `prepare_merge_stale_manifest_hash_returns_evidence_stale` | Disk manifest rewritten between sync_once and prepare_merge → `SyncError::EvidenceStale` |
| `prepare_merge_field_level_lww_silent` | Concurrent edits to same field, no tombstone → resolved via existing CRDT, zero vetoes |
| `commit_with_decisions_empty_decisions_no_vetoes_applies_merge` | vetoes=[], decisions=[] → atomic rewrite, returns new SyncState with post-merge clock |
| `commit_with_decisions_keep_local_overrides_tombstone` | Decision KeepLocal{id} → record stays alive on disk, vector clock progresses |
| `commit_with_decisions_accept_tombstone_finalizes_delete` | Decision AcceptTombstone{id} → record tombstoned at disk's timestamp |
| `commit_with_decisions_partial_decisions_returns_missing_veto_decision` | Vetoes carry N, decisions carry N−1 → `SyncError::MissingVetoDecision` |
| `commit_with_decisions_unknown_decision_id_returns_unknown_veto` | Decisions includes id not in vetoes → `SyncError::UnknownVetoDecision` |
| `commit_with_decisions_stale_manifest_hash_aborts` | Disk changed between prepare and commit → `SyncError::EvidenceStale`, NO disk writes |
| `commit_with_decisions_block_fingerprint_mismatch_repaired_by_reconverge` | Simulate partial-crash via mid-test manifest revert → next sync_once+prepare+commit produces consistent state (idempotence proof) |
| `open_vault_detects_block_fingerprint_mismatch` | Manually corrupt one block file → `VaultError::BlockFingerprintMismatch` |

### Property tests — `core/tests/sync_merge_proptest.rs` (new)

- `prop_commit_then_sync_once_yields_nothing_to_do` — closure property: post-commit, persisting returned SyncState and re-running sync_once on unchanged disk returns `NothingToDo`.
- `prop_three_step_idempotent_on_repeated_invocation` — `sync_once → prepare_merge → commit_with_decisions` invoked twice with same inputs (and re-derived hash on the second pass) → bit-identical disk state after each.
- `prop_commit_associative_under_disjoint_vetoes` — two non-overlapping veto sets committed in either order produce the same final state.
- `prop_decision_bijection_enforced` — for any `(vetoes, decisions)` pair where `decision.ids != vetoes.ids`, commit returns `MissingVetoDecision` or `UnknownVetoDecision`.

### KAT vectors — `core/tests/data/sync_kat.json` (9 → 16)

| New vector | Covers |
|---|---|
| `concurrent_disjoint_blocks_no_vetoes_applied` | Different blocks touched by each side → silent merge |
| `concurrent_same_block_field_lww_no_vetoes` | Same block, same record, different fields → CRDT field LWW, no veto |
| `concurrent_one_tombstone_veto_keep_local` | One disk-tombstones-local-live + KeepLocal decision |
| `concurrent_one_tombstone_veto_accept_tombstone` | One disk-tombstones-local-live + AcceptTombstone decision |
| `concurrent_two_tombstone_vetoes_mixed_decisions` | Two vetoes, one Keep + one Accept |
| `prepare_merge_stale_hash_evidence_stale` | Manifest hash mismatch path |
| `commit_block_fingerprint_mismatch_repair_via_reconverge` | Partial-write simulation + idempotent reconvergence |

Rust-side replay only in C.1.1; Python clean-room replay added when issue [#76](https://github.com/hherb/secretary/issues/76) is finally done (C.4 scope).

### Unit tests (inline in each new file)

- `diff.rs` — DiffPlan sort/dedup invariant, ManifestHash round-trip, ctor rejects malformed.
- `draft.rs` — Zeroize-on-drop coverage (using existing assert-zeroized pattern from `crypto::secret` tests), Eq/Debug derives stable, RecordSnapshot wraps Record correctly.
- `prepare.rs` — `tombstone_veto_set(local_records, disk_records)` pure-function table-driven coverage: all-disk-tombstones, no-tombstones, tombstoned-on-both-sides (no veto), local-tombstoned-disk-live (no veto, local wins), local-live-disk-tombstone (veto fires).
- `commit.rs` — `apply_decisions(draft, decisions)` table-driven; freshness-hash mismatch path; bijection enforcement.
- `outcome.rs` — adjusted Eq/Debug tests for the renamed variant.

### Test growth target

~13 integration + ~4 proptest + ~30-40 inline unit + 7 KAT vectors. Workspace cargo total grows from **681 → ~720 ± a few**.

## Atomicity contract (full statement)

Stated in one place for the security review record:

- **Per-file write atomicity** is delivered by `core::vault::io::write_atomic`, which uses `tempfile::NamedTempFile::persist` (pinned to `=3.27.0` per CLAUDE.md). C.1.1 adds no new write primitives — all disk mutations route through `write_atomic`.

- **Multi-file commit atomicity** for `commit_with_decisions` is NOT a filesystem primitive. The contract is:
  1. Each block file write is individually atomic.
  2. The manifest write is the **commit point** — pre-manifest-write crash leaves the vault in a state where `open_vault` will detect block-fingerprint mismatches (new behaviour from C.1.1) and return `VaultError::BlockFingerprintMismatch`.
  3. Crash recovery is caller-driven: surface the typed error, re-run `sync_once → prepare_merge → commit_with_decisions`. CRDT idempotence guarantees convergence.

- **TOCTOU race between prepare and commit** is closed by the `manifest_hash` carried through `ConcurrentDetected → DraftMerge`. If the on-disk manifest envelope hash differs at commit time, `SyncError::EvidenceStale` aborts the commit with zero disk writes.

- **Per-block AEAD nonce** is freshly generated for each rewritten block, per the existing `save_block` step 12 pattern. Never share key+nonce across rewrites.

## Open items for the implementation plan

These are decisions to settle in the plan, not the design:

1. Whether `verify_block_fingerprints` runs eagerly inside `open_vault` for every open, or lazily on first block read. **Lean: eagerly** — open is already O(blocks) work for the manifest signature verification; the BLAKE3 pass is small per-block constant cost.
2. Whether `ManifestHash` covers the full on-disk envelope bytes or only the canonical body. **Lean: full envelope** — exactly what's read off disk, no canonicalisation step needed in the hot freshness-check path.
3. Whether the `DiffPlan` construction in `sync_once` lives in `once.rs` or moves into `diff.rs`. **Lean: helper lives in `diff.rs`**; `sync_once` calls it. Keeps `once.rs` close to its current footprint.
4. Whether `MergedRecord` is a distinct type or a re-export of `Record`. **Lean: re-export** — no new shape, just a named alias for the merge layer's output.
5. The exact AEAD nonce parameterisation for the multi-rewrite-per-test test helper (`fresh_vault_with_clock` in `core/tests/sync_helpers/mod.rs`). Carried risk from the C.1.1 baton — must not share key+nonce across rewrites in the same test.

## Workspace impact

| Component | Change |
|---|---|
| `core/src/sync/outcome.rs` | `ForkDetected` removed, `ConcurrentDetected` added |
| `core/src/sync/error.rs` | +4 variants |
| `core/src/sync/once.rs` | `Concurrent` arm produces `ConcurrentDetected` |
| `core/src/sync/diff.rs` | NEW |
| `core/src/sync/draft.rs` | NEW |
| `core/src/sync/prepare.rs` | NEW |
| `core/src/sync/commit.rs` | NEW |
| `core/src/sync/mod.rs` | Extended re-exports |
| `core/src/vault/orchestrators.rs` | `verify_block_fingerprints` helper + call from `open_vault` |
| `core/src/vault/mod.rs` (VaultError) | +1 variant `BlockFingerprintMismatch` |
| `core/tests/sync_merge.rs` | NEW (integration) |
| `core/tests/sync_merge_proptest.rs` | NEW (properties) |
| `core/tests/sync.rs` | Existing tests renamed (fork → concurrent_detected); minor signature updates |
| `core/tests/sync_kat.rs` | Replay logic extended for new vector shapes |
| `core/tests/data/sync_kat.json` | 9 → 16 vectors |
| `docs/crypto-design.md` §11 | Cross-reference added pointing at C.1.1 implementation of the merge layer (no normative changes — §11 already specifies the merge) |
| `docs/vault-format.md` | No changes (on-disk format unchanged) |
| `docs/superpowers/specs/2026-05-18-c1-1-sync-merge-design.md` | THIS DOCUMENT |
| FFI crates | Unchanged |
| `core/fuzz/` | Unchanged (no new fuzz targets) |
| `core/tests/python/conformance.py` | Unchanged (sync layer is C.4 scope) |
| ROADMAP.md | C.1.1 moved to in-flight, then ✅ on merge |
| README.md | Status table updated when C.1.1 ships |

## Risks

- **`DraftMerge` zeroize discipline**. Any new type holding peer-side `RecordFieldValue` snapshots is a new memory-hygiene surface. Re-read [`docs/manual/contributors/memory-hygiene-audit-internal.md`](../../manual/contributors/memory-hygiene-audit-internal.md) before implementing the type — past commit `6054185` fixed twelve stack-residue gaps following the same pattern.
- **`fresh_vault_with_clock` test helper** uses a deterministic AEAD nonce. C.1.1 needs multi-rewrite-per-test sequences (sync detects, user vetoes, commit, re-sync converges). Adding per-call nonce parameterisation (or `getrandom`) is one of the first plan items. **Must not share key-nonce pair across rewrites in the same test** — would break AEAD's nonce-uniqueness invariant.
- **`write_atomic` dependency pin**. `tempfile` is exact-pinned to `=3.27.0` per CLAUDE.md atomic-write section; do not bump as part of C.1.1.
- **CRDT proptests must not weaken**. If C.1.1 changes anything in `core/src/vault/conflict.rs` (it shouldn't — only call existing `pub fn`s), the four proptest properties (commutativity, associativity, idempotence, well-formedness) must continue to hold. A weakening of those is a design problem; push back.

## Cross-references

- [C.1 phase 1 design](2026-05-17-c1-sync-detection-design.md) — the predecessor design; D1 / D2 / D3 / D4 of that document remain in force, plus D2-veto-scope explicitly carried as this document's D3.
- [`docs/crypto-design.md`](../../crypto-design.md) §10 — manifest signing and rollback resistance.
- [`docs/crypto-design.md`](../../crypto-design.md) §11 — per-record CRDT merge (implemented by this slice's `prepare_merge` composition).
- [`docs/threat-model.md`](../../threat-model.md) §3.1 — cloud-folder host adversary; the per-manifest rollback row.
- [`docs/threat-model.md`](../../threat-model.md) §4 limit 3 — equivocation handling; this design assumes detection-plus-CRDT-merge is sufficient.
- [`docs/adr/0003-cloud-folder-sync.md`](../../adr/0003-cloud-folder-sync.md) — no-server, file-by-file sync model.
- [`docs/adr/0004-block-as-unit.md`](../../adr/0004-block-as-unit.md) — block-as-unit-of-sharing decision.
- [`docs/manual/contributors/memory-hygiene-audit-internal.md`](../../manual/contributors/memory-hygiene-audit-internal.md) — wrapper discipline + drop ordering; mandatory reading before implementing `DraftMerge`.
- [`docs/superpowers/specs/2026-05-09-ffi-b4c-save-block-design.md`](2026-05-09-ffi-b4c-save-block-design.md) — `device_uuid` caller-supplied convention; existing pattern for the atomic-block-rewrite ordering this design inherits.
- [Issue #76](https://github.com/hherb/secretary/issues/76) — Python clean-room replay of `sync_kat.json` (C.4 scope; the new vectors join when #76 is finally done).

---

**Approved decisions:** D1 (layered variants), D2 (single-call commit), D3 (record-level veto — carried from C.1 phase 1), D4 (lazy disk readout with manifest-hash guard), D5 (three-step API), D6 (block-first manifest-last + read-time fingerprint verification — option (d)).
