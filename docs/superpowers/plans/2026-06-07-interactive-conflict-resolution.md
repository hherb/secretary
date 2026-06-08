# Interactive Conflict Resolution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the dead-end `ConflictsPending` outcome actionable — when "Sync now" hits a record-tombstone veto, surface a resolution modal (Keep mine / Accept delete per record + a read-only auto-merge notice), then commit the user's decisions.

**Architecture:** A continuous, two-call **stateless recompute-on-commit** flow. Call 1 (`sync_now`) returns the veto + collision metadata + a `manifest_hash` freshness token, committing nothing. Call 2 (new `sync_commit_decisions`) recomputes the deterministic draft, asserts the token still matches, and commits decisions. The bridge holds no state between calls; the merge engine (`prepare_merge` → `commit_with_decisions`) already exists in `core`.

**Tech Stack:** Rust (`secretary-core`, `secretary-cli`, `secretary-ffi-bridge`, uniffi + pyo3 bindings, Tauri `src-tauri`), TypeScript + Svelte 5 (runes) frontend, Vitest, `cargo test`/`clippy`/`fmt`.

**Spec:** [docs/superpowers/specs/2026-06-07-interactive-conflict-resolution-design.md](../specs/2026-06-07-interactive-conflict-resolution-design.md)

**Working dir:** worktree `.worktrees/conflict-resolution`, branch `feature/interactive-conflict-resolution`. Verify before any path-sensitive command:
```bash
pwd && git branch --show-current && git worktree list
```

**Per-task hygiene (all Rust tasks):** every Rust task's verify step ends with, from the relevant crate dir or repo root:
```bash
cargo fmt --all --check && cargo clippy --release --workspace --tests -- -D warnings
```
(The D.1.14 plan-improvement note: `fmt --check` was missing per-task and a non-sorted import slipped through.)

---

## File Structure

| File | Responsibility | Task |
|---|---|---|
| `core/src/sync/draft.rs` | `RecordCollisionSummary` type + `DraftMerge.collisions` field | 1 |
| `core/src/sync/prepare.rs` | collect collisions from `merge_block` onto the draft | 1 |
| `cli/src/pipeline.rs` | `InspectOutcome` + `sync_pass_inspect` + `sync_pass_commit_decisions` | 2, 3 |
| `cli/tests/sync_pass_integration.rs` | two-device veto fixture + helper tests | 2, 3 |
| `ffi/secretary-ffi-bridge/src/sync/orchestration.rs` | DTOs, enriched outcome, `sync_commit_decisions`, error un-collapse | 4, 5 |
| `ffi/secretary-ffi-bridge/src/error.rs` | new `FfiVaultError` variants | 5 |
| `ffi/secretary-ffi-uniffi/**`, `ffi/secretary-ffi-py/**` | expose new fn + types; conformance KAT regen | 6 |
| `desktop/src-tauri/src/dtos/sync.rs` | enriched outcome + 3 new DTOs + wire tests | 7 |
| `desktop/src-tauri/src/commands/sync.rs` | `sync_commit_decisions` command + `_impl` | 8 |
| `desktop/src-tauri/src/main.rs`, `commands/mod.rs` | register the command | 8 |
| `desktop/src/lib/errors.ts` | `sync_decisions_incomplete` code + message | 9 |
| `desktop/src/lib/sync.ts` | TS DTO types + `collectDecisions`/`decisionsComplete`/`formatVetoSummary` | 10 |
| `desktop/src/lib/ipc.ts` | `syncCommitDecisions` wrapper | 11 |
| `desktop/src/components/ConflictResolutionDialog.svelte` | the resolution modal | 12 |
| `desktop/src/components/SyncPasswordDialog.svelte`, `SyncPill.svelte` | thread conflicts + password into the modal | 13 |
| `README.md`, `ROADMAP.md` | shipped status | 14 |

---

## Task 1: core — surface field collisions on `DraftMerge` (metadata only)

**Files:**
- Modify: `core/src/sync/draft.rs` (add type + field, near `RecordTombstoneVeto` ~line 153 and the `DraftMerge` struct ~line 67)
- Modify: `core/src/sync/prepare.rs` (collect collisions in the merge loop ~line 435-503)
- Test: `core/src/sync/prepare.rs` `#[cfg(test)]` module

- [ ] **Step 1: Write the failing test** — append to the `tests` module in `core/src/sync/prepare.rs`. This needs a concurrent two-copy bundle that produces both a field collision and is otherwise mergeable. Reuse the integration bundle builders if a unit-level one is impractical; if so, move this assertion to `cli/tests` in Task 2 and instead unit-test the projection helper directly:

```rust
    #[test]
    fn record_collision_summary_is_metadata_only() {
        // RecordCollisionSummary must carry record_id + field_names only —
        // no RecordField (which holds secret values). Compile-time proof:
        // the struct has exactly these two fields.
        let s = super::super::draft::RecordCollisionSummary {
            record_id: [7u8; 16],
            field_names: vec!["password".to_string(), "url".to_string()],
        };
        assert_eq!(s.record_id, [7u8; 16]);
        assert_eq!(s.field_names, vec!["password", "url"]);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --release -p secretary-core record_collision_summary_is_metadata_only`
Expected: FAIL — `RecordCollisionSummary` not found.

- [ ] **Step 3: Add the type and field** in `core/src/sync/draft.rs`. After the `RecordTombstoneVeto` struct (after line 153), add:

```rust
/// Metadata-only summary of one record's field-level LWW collisions
/// during a concurrent merge. Surfaced for an informational
/// "auto-merged" notice (spec §4-A). Carries **no values** —
/// [`crate::vault::conflict::FieldCollision`]'s `winner`/`loser`
/// (`RecordField`, secret-bearing) stay inside the merge step. The
/// `field_names` are plaintext metadata (like the browse-path
/// `FieldMetaDto`), so no zeroize obligation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordCollisionSummary {
    /// 16-byte UUID of the record whose fields collided.
    pub record_id: RecordId,
    /// Names of the fields where both sides held differing values and
    /// LWW silently picked a winner. Sorted ascending (inherited from
    /// `FieldCollision` ordering); deduped across the per-copy fold.
    pub field_names: Vec<String>,
}
```

Then add the field to `DraftMerge` (after `vetoes` ~line 96, before `post_merge_clock`):

```rust
    /// Metadata-only field-collision summaries for the informational
    /// "auto-merged silently" notice (spec §4-A). One entry per record
    /// that had ≥1 field LWW collision in this merge. `#[zeroize(skip)]`
    /// — values are plaintext field names, not secret material.
    #[zeroize(skip)]
    pub collisions: Vec<RecordCollisionSummary>,
```

- [ ] **Step 4: Collect collisions in `prepare_merge`** (`core/src/sync/prepare.rs`). Add an accumulator alongside the others (~line 380):

```rust
    let mut collisions: BTreeMap<[u8; 16], std::collections::BTreeSet<String>> = BTreeMap::new();
```

Inside the per-copy fold, after the `let merged = merge_block(...)?;` block and before `acc_records = ...` (~line 446), capture the collisions:

```rust
        for rc in &merged.collisions {
            let entry = collisions.entry(rc.record_id).or_default();
            for fc in &rc.field_collisions {
                entry.insert(fc.field_name.clone());
            }
        }
```

(`merge_block` returns `MergedBlock { merged, vector_clock, collisions: Vec<RecordCollision> }`; `RecordCollision { record_id, field_collisions: Vec<FieldCollision> }`; `FieldCollision { field_name, winner, loser }` — confirm field names against `core/src/vault/conflict.rs:744` / `:199`.)

Then build the summary vec just before the `Ok(DraftMerge { ... })` (~line 510):

```rust
    let collisions: Vec<RecordCollisionSummary> = collisions
        .into_iter()
        .map(|(record_id, names)| RecordCollisionSummary {
            record_id,
            field_names: names.into_iter().collect(),
        })
        .collect();
```

Add `collisions,` to the `DraftMerge { ... }` literal, and import the type: in the `use crate::sync::draft::{...}` line at the top of `prepare.rs`, add `RecordCollisionSummary`.

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test --release -p secretary-core record_collision_summary_is_metadata_only`
Expected: PASS.

- [ ] **Step 6: Verify the existing CRDT proptests + draft tests still pass** (merge semantics unchanged)

Run: `cargo test --release -p secretary-core sync::`
Expected: PASS (the 4 proptests + draft/prepare tests).

- [ ] **Step 7: Lint + commit**

```bash
cargo fmt --all --check && cargo clippy --release --workspace --tests -- -D warnings
git add core/src/sync/draft.rs core/src/sync/prepare.rs
git commit -m "core: surface field-collision summary (metadata only) on DraftMerge"
```

---

## Task 2: cli — `sync_pass_inspect` (the stateless call-1 helper)

**Files:**
- Modify: `cli/src/pipeline.rs` (new `InspectOutcome` enum + `sync_pass_inspect` fn, near `sync_pass_pause_on_conflict` ~line 232)
- Test: `cli/tests/sync_pass_integration.rs`

**Context:** `sync_pass_inspect` is `sync_pass_pause_on_conflict` except the `ConflictsPending` arm returns the draft's `vetoes` + `collisions` + `manifest_hash` instead of just a count, and commits/advances state on the clean arms exactly as before. It does NOT drive `VetoUx` — decisions arrive in Task 3.

- [ ] **Step 1: Write the failing integration test** in `cli/tests/sync_pass_integration.rs`. First locate the existing concurrent/veto fixture builder in this file (or `core/tests/sync_pass_kat.rs`) that produces a non-empty veto — reuse it. The test asserts inspect returns veto + collision detail with the disk byte-unchanged:

```rust
#[test]
fn inspect_returns_veto_detail_and_leaves_disk_untouched() {
    // ARRANGE: stage a two-device divergence where the canonical side has a
    // record live and a copy tombstoned it later (the veto case). Reuse the
    // existing builder that sync_pass_pause_on_conflict's veto test uses.
    let (vault_folder, identity, password, mut state) = stage_two_device_veto_fixture();
    let before = hash_dir(&vault_folder); // helper: BLAKE3 over all files

    // ACT
    let outcome = sync_pass_inspect(&vault_folder, &identity, &password, &mut state, 0)
        .expect("inspect must succeed");

    // ASSERT: a veto came back with metadata, nothing was written, state unmoved.
    match outcome {
        InspectOutcome::ConflictsPending { vetoes, manifest_hash, .. } => {
            assert_eq!(vetoes.len(), 1);
            assert!(!manifest_hash.as_bytes().is_empty());
        }
        other => panic!("expected ConflictsPending, got {other:?}"),
    }
    assert_eq!(hash_dir(&vault_folder), before, "inspect must not write");
}
```

If no `stage_two_device_veto_fixture` / `hash_dir` helper exists, add them to this test file (reuse the bundle-construction code already present in the veto test; `hash_dir` walks the dir and feeds bytes to `blake3::Hasher`).

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --release -p secretary-cli --test sync_pass_integration inspect_returns_veto_detail`
Expected: FAIL — `sync_pass_inspect` / `InspectOutcome` not found.

- [ ] **Step 3: Implement `InspectOutcome` + `sync_pass_inspect`** in `cli/src/pipeline.rs`. Add imports (extend the `secretary_core::sync` use at line 26-28):

```rust
use secretary_core::sync::{
    commit_with_decisions, prepare_merge, sync_once, ManifestHash, RecordCollisionSummary,
    RecordTombstoneVeto, SyncError, SyncOutcome, SyncState,
};
```

(Confirm `ManifestHash` / `RecordCollisionSummary` / `RecordTombstoneVeto` are re-exported from `secretary_core::sync`; if not, import from `secretary_core::sync::draft`.)

Add after `SyncPassOutcome` (~line 110):

```rust
/// Outcome of one [`sync_pass_inspect`] pass — the stateless call-1 of the
/// interactive resolution flow. Identical to [`SyncPassOutcome`] on every arm
/// except `ConflictsPending`, which carries the full draft detail (vetoes +
/// collision summaries + the manifest-hash freshness token) the UI needs to
/// render the resolution modal. Nothing is committed on this arm and `state`
/// is not advanced — the commit happens in [`sync_pass_commit_decisions`].
#[derive(Debug, Clone, PartialEq)]
pub enum InspectOutcome {
    /// Disk clock == local highest-seen. No state mutation, no write.
    NothingToDo,
    /// Disk strictly dominates local. `state` advanced; no vault write.
    AppliedAutomatically,
    /// Concurrent, diverging_blocks empty → silent-merge clock advance.
    SilentMerge,
    /// Concurrent, diverging, zero vetoes → committed. `state` advanced.
    MergedClean,
    /// Concurrent, diverging, non-empty vetoes → nothing committed.
    ConflictsPending {
        /// Tombstone disputes awaiting a human decision.
        vetoes: Vec<RecordTombstoneVeto>,
        /// Metadata-only field-collision summaries (informational).
        collisions: Vec<RecordCollisionSummary>,
        /// Freshness token threaded to `sync_pass_commit_decisions`.
        manifest_hash: ManifestHash,
    },
    /// Rollback. `state` unchanged.
    RollbackRejected,
}

/// Stateless call-1: run a sync pass, auto-applying every safe arm, and on a
/// tombstone veto return the full draft detail (no commit, no state advance).
/// Mirrors [`sync_pass_pause_on_conflict`] but exposes the draft so an
/// out-of-band UI can adjudicate and call [`sync_pass_commit_decisions`].
///
/// # Errors
/// Any [`SyncError`] from `sync_once` / `prepare_merge` / `commit_with_decisions`
/// bubbles up verbatim.
pub fn sync_pass_inspect(
    vault_folder: &Path,
    identity: &UnlockedIdentity,
    password: &SecretBytes,
    state: &mut SyncState,
    now_ms: u64,
) -> Result<InspectOutcome, SyncError> {
    let outcome = sync_once(vault_folder, identity, state, now_ms)?;
    match outcome {
        SyncOutcome::NothingToDo => Ok(InspectOutcome::NothingToDo),
        SyncOutcome::AppliedAutomatically { new_state } => {
            *state = new_state;
            Ok(InspectOutcome::AppliedAutomatically)
        }
        SyncOutcome::RollbackRejected(_evidence) => Ok(InspectOutcome::RollbackRejected),
        SyncOutcome::ConcurrentDetected {
            bundle,
            plan,
            manifest_hash: _,
            disk_vector_clock,
            local_highest_seen: _,
        } => {
            if plan.diverging_blocks.is_empty() {
                let copy_clocks: Vec<&[VectorClockEntry]> = bundle
                    .copies
                    .iter()
                    .map(|c| c.manifest.vector_clock.as_slice())
                    .collect();
                state.highest_vector_clock_seen = silent_merge_clock(
                    &disk_vector_clock,
                    &copy_clocks,
                    &state.highest_vector_clock_seen,
                );
                return Ok(InspectOutcome::SilentMerge);
            }
            let draft = prepare_merge(vault_folder, identity, &bundle, &plan)?;
            if !draft.vetoes.is_empty() {
                return Ok(InspectOutcome::ConflictsPending {
                    vetoes: draft.vetoes.clone(),
                    collisions: draft.collisions.clone(),
                    manifest_hash: draft.manifest_hash,
                });
            }
            let new_state =
                commit_with_decisions(vault_folder, password, draft, Vec::new(), now_ms)?;
            *state = new_state;
            Ok(InspectOutcome::MergedClean)
        }
    }
}
```

(Confirm `silent_merge_clock` and `VectorClockEntry` are already in scope in this file — they are, used by `sync_pass_pause_on_conflict`. `ManifestHash` must be `Copy` or the `draft.manifest_hash` move is fine since `draft` is consumed below only on the no-veto path; on the veto path we `return` before consuming it — adjust to `manifest_hash: draft.manifest_hash` reading the field before the early return, which is valid since the struct is still owned.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --release -p secretary-cli --test sync_pass_integration inspect_returns_veto_detail`
Expected: PASS.

- [ ] **Step 5: Lint + commit**

```bash
cargo fmt --all --check && cargo clippy --release --workspace --tests -- -D warnings
git add cli/src/pipeline.rs cli/tests/sync_pass_integration.rs
git commit -m "cli: sync_pass_inspect — stateless call-1 returning veto+collision detail"
```

---

## Task 3: cli — `sync_pass_commit_decisions` (the stateless call-2 helper)

**Files:**
- Modify: `cli/src/pipeline.rs`
- Test: `cli/tests/sync_pass_integration.rs`

**Context:** Recompute the draft, assert the freshness token from call 1 still matches, then commit decisions. Returns `SyncPassOutcome` (reusing the existing enum — the commit lands as `MergedClean`).

- [ ] **Step 1: Write the failing tests** in `cli/tests/sync_pass_integration.rs`:

```rust
#[test]
fn commit_decisions_keep_local_keeps_record_live() {
    let (vault_folder, identity, password, mut state) = stage_two_device_veto_fixture();
    let InspectOutcome::ConflictsPending { vetoes, manifest_hash, .. } =
        sync_pass_inspect(&vault_folder, &identity, &password, &mut state.clone(), 0).unwrap()
    else { panic!("expected veto") };
    let decisions: Vec<VetoDecision> = vetoes
        .iter()
        .map(|v| VetoDecision::KeepLocal { record_id: v.record_id })
        .collect();

    let outcome = sync_pass_commit_decisions(
        &vault_folder, &identity, &password, &mut state, manifest_hash, decisions, 1,
    )
    .expect("commit must succeed");
    assert_eq!(outcome, SyncPassOutcome::MergedClean);
    // a clean re-sync now finds nothing to merge (state advanced + record live)
    // (assert via a follow-up sync_pass_inspect returning a non-conflict arm)
}

#[test]
fn commit_decisions_stale_token_is_rejected() {
    let (vault_folder, identity, password, mut state) = stage_two_device_veto_fixture();
    let InspectOutcome::ConflictsPending { vetoes, manifest_hash, .. } =
        sync_pass_inspect(&vault_folder, &identity, &password, &mut state.clone(), 0).unwrap()
    else { panic!("expected veto") };
    let decisions: Vec<VetoDecision> = vetoes
        .iter()
        .map(|v| VetoDecision::AcceptTombstone { record_id: v.record_id })
        .collect();
    // Simulate a concurrent writer: mutate the manifest between inspect and commit.
    mutate_manifest_bytes(&vault_folder);
    let before = hash_dir(&vault_folder);

    let err = sync_pass_commit_decisions(
        &vault_folder, &identity, &password, &mut state, manifest_hash, decisions, 1,
    )
    .unwrap_err();
    assert!(matches!(err, SyncError::EvidenceStale), "got {err:?}");
    assert_eq!(hash_dir(&vault_folder), before, "no write on stale");
}
```

(Add `mutate_manifest_bytes` — append a byte to the manifest file or re-stage a different copy; reuse existing fixture helpers.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --release -p secretary-cli --test sync_pass_integration commit_decisions_`
Expected: FAIL — `sync_pass_commit_decisions` not found.

- [ ] **Step 3: Implement `sync_pass_commit_decisions`** in `cli/src/pipeline.rs`. Add `VetoDecision` to the core import, then:

```rust
/// Stateless call-2: recompute the draft, assert the freshness token from
/// [`sync_pass_inspect`] still matches the on-disk manifest, then commit the
/// caller's decisions. `expected_manifest_hash` is the token returned by call 1;
/// a mismatch (a concurrent writer touched the vault while the modal was open)
/// yields [`SyncError::EvidenceStale`] with nothing written, so the UI re-runs
/// inspect against the fresh disk.
///
/// On the non-conflict arms (the disk changed to NothingToDo/Applied/etc. since
/// inspect) returns the corresponding [`SyncPassOutcome`] without applying
/// decisions — the caller treats anything but `MergedClean` as "re-inspect".
///
/// # Errors
/// `EvidenceStale` on a stale token; `MissingVetoDecision`/`UnknownVetoDecision`
/// if `decisions` does not exactly cover the recomputed veto set; otherwise any
/// `SyncError` from the underlying primitives.
pub fn sync_pass_commit_decisions(
    vault_folder: &Path,
    identity: &UnlockedIdentity,
    password: &SecretBytes,
    state: &mut SyncState,
    expected_manifest_hash: ManifestHash,
    decisions: Vec<VetoDecision>,
    now_ms: u64,
) -> Result<SyncPassOutcome, SyncError> {
    let outcome = sync_once(vault_folder, identity, state, now_ms)?;
    match outcome {
        SyncOutcome::NothingToDo => Ok(SyncPassOutcome::NothingToDo),
        SyncOutcome::AppliedAutomatically { new_state } => {
            *state = new_state;
            Ok(SyncPassOutcome::AppliedAutomatically)
        }
        SyncOutcome::RollbackRejected(_evidence) => Ok(SyncPassOutcome::RollbackRejected),
        SyncOutcome::ConcurrentDetected {
            bundle,
            plan,
            manifest_hash,
            disk_vector_clock,
            local_highest_seen: _,
        } => {
            // Freshness gate: the disk manifest must be byte-identical to what
            // inspect saw. Reject before any decision is applied.
            if manifest_hash != expected_manifest_hash {
                return Err(SyncError::EvidenceStale);
            }
            if plan.diverging_blocks.is_empty() {
                let copy_clocks: Vec<&[VectorClockEntry]> = bundle
                    .copies
                    .iter()
                    .map(|c| c.manifest.vector_clock.as_slice())
                    .collect();
                state.highest_vector_clock_seen = silent_merge_clock(
                    &disk_vector_clock,
                    &copy_clocks,
                    &state.highest_vector_clock_seen,
                );
                return Ok(SyncPassOutcome::SilentMerge);
            }
            let draft = prepare_merge(vault_folder, identity, &bundle, &plan)?;
            let new_state =
                commit_with_decisions(vault_folder, password, draft, decisions, now_ms)?;
            *state = new_state;
            Ok(SyncPassOutcome::MergedClean)
        }
    }
}
```

(`SyncOutcome::ConcurrentDetected` exposes `manifest_hash`; confirm the field name + that `ManifestHash: PartialEq`. If the disk-side recompute of `prepare_merge`'s own `manifest_hash` is the authoritative compare, use `draft.manifest_hash != expected_manifest_hash` after `prepare_merge` instead — `commit_with_decisions` also re-checks internally, so this is belt-and-suspenders.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --release -p secretary-cli --test sync_pass_integration commit_decisions_`
Expected: PASS.

- [ ] **Step 5: Lint + commit**

```bash
cargo fmt --all --check && cargo clippy --release --workspace --tests -- -D warnings
git add cli/src/pipeline.rs cli/tests/sync_pass_integration.rs
git commit -m "cli: sync_pass_commit_decisions — stateless call-2 with freshness gate"
```

---

## Task 4: ffi bridge — DTOs + enriched `ConflictsPending`

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/sync/orchestration.rs`
- Test: same file's `#[cfg(test)]` module

- [ ] **Step 1: Write the failing test** (append to the `tests` module):

```rust
    #[test]
    fn veto_decision_dto_round_trips_to_core() {
        let d = VetoDecisionDto { record_uuid_hex: "0a".repeat(16), keep_local: true };
        let core = d.to_core().expect("valid hex");
        assert!(matches!(core, secretary_core::sync::VetoDecision::KeepLocal { .. }));
        let d2 = VetoDecisionDto { record_uuid_hex: "ff".repeat(16), keep_local: false };
        assert!(matches!(
            d2.to_core().unwrap(),
            secretary_core::sync::VetoDecision::AcceptTombstone { .. }
        ));
        // bad hex is a typed error, not a panic
        assert!(VetoDecisionDto { record_uuid_hex: "zz".into(), keep_local: true }.to_core().is_err());
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --release -p secretary-ffi-bridge veto_decision_dto_round_trips`
Expected: FAIL — types not found.

- [ ] **Step 3: Add the DTOs + enrich the outcome** in `orchestration.rs`. Add near `SyncOutcomeDto` (line 20). First the new metadata DTOs:

```rust
/// Metadata-only projection of a [`secretary_core::sync::RecordTombstoneVeto`]
/// for the resolution UI. NO secret values — only the plaintext identifiers a
/// user needs to recognize the disputed record (mirrors the browse-path
/// secret-hygiene model).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VetoDto {
    pub record_uuid_hex: String,
    pub record_type: String,
    pub tags: Vec<String>,
    pub field_names: Vec<String>,
    pub local_last_mod_ms: u64,
    pub peer_tombstoned_at_ms: u64,
    pub peer_device_hex: String,
}

/// Metadata-only field-collision summary for the "auto-merged" notice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollisionDto {
    pub record_uuid_hex: String,
    pub field_names: Vec<String>,
}

/// Caller's per-record decision. `keep_local = true` → reject the peer
/// tombstone; `false` → accept the delete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VetoDecisionDto {
    pub record_uuid_hex: String,
    pub keep_local: bool,
}

impl VetoDecisionDto {
    /// Parse the 32-char hex `record_uuid` into a core [`VetoDecision`].
    pub(crate) fn to_core(&self) -> Result<secretary_core::sync::VetoDecision, FfiVaultError> {
        let bytes = hex_to_16(&self.record_uuid_hex)?;
        Ok(if self.keep_local {
            secretary_core::sync::VetoDecision::KeepLocal { record_id: bytes }
        } else {
            secretary_core::sync::VetoDecision::AcceptTombstone { record_id: bytes }
        })
    }
}

/// Parse exactly 32 hex chars → [u8; 16]; typed error otherwise.
fn hex_to_16(s: &str) -> Result<[u8; 16], FfiVaultError> {
    let v = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2).unwrap_or("zz"), 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| FfiVaultError::SyncFailed { detail: "invalid record_uuid hex".into() })?;
    v.try_into().map_err(|_| FfiVaultError::SyncFailed {
        detail: "record_uuid must be 16 bytes".into(),
    })
}
```

Then change `SyncOutcomeDto::ConflictsPending` (lines 31-34) from `{ veto_count: u32 }` to:

```rust
    /// Concurrent diverging copies produced tombstone vetoes — the pass paused.
    /// Carries the metadata the UI needs + the freshness token for the commit.
    ConflictsPending {
        vetoes: Vec<VetoDto>,
        collisions: Vec<CollisionDto>,
        /// BLAKE3-256 of the manifest envelope at inspect time; opaque token
        /// the caller passes back to `sync_commit_decisions`.
        manifest_hash: Vec<u8>,
    },
```

- [ ] **Step 4: Replace the `From<SyncPassOutcome>` impl** with one over `InspectOutcome` (the bridge now calls inspect). Replace lines 39-52 — import `InspectOutcome` and add a projection helper. The veto/collision projection reads `local_state` (a `Record`) for metadata:

```rust
use secretary_cli::pipeline::{
    sync_pass_commit_decisions, sync_pass_inspect, InspectOutcome, SyncPassOutcome,
};

fn project_veto(v: &secretary_core::sync::RecordTombstoneVeto) -> VetoDto {
    VetoDto {
        record_uuid_hex: hex16(&v.record_id),
        record_type: v.local_state.record_type.clone(),
        tags: v.local_state.tags.clone(),
        field_names: v.local_state.fields.keys().cloned().collect(),
        local_last_mod_ms: v.local_state.last_mod_ms,
        peer_tombstoned_at_ms: v.disk_tombstone_at_ms,
        peer_device_hex: hex16(&v.disk_tombstoner_device),
    }
}

fn hex16(b: &[u8; 16]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl From<InspectOutcome> for SyncOutcomeDto {
    fn from(o: InspectOutcome) -> Self {
        match o {
            InspectOutcome::NothingToDo => SyncOutcomeDto::NothingToDo,
            InspectOutcome::AppliedAutomatically => SyncOutcomeDto::AppliedAutomatically,
            InspectOutcome::SilentMerge => SyncOutcomeDto::SilentMerge,
            InspectOutcome::MergedClean => SyncOutcomeDto::MergedClean,
            InspectOutcome::RollbackRejected => SyncOutcomeDto::RollbackRejected,
            InspectOutcome::ConflictsPending { vetoes, collisions, manifest_hash } => {
                SyncOutcomeDto::ConflictsPending {
                    vetoes: vetoes.iter().map(project_veto).collect(),
                    collisions: collisions
                        .iter()
                        .map(|c| CollisionDto {
                            record_uuid_hex: hex16(&c.record_id),
                            field_names: c.field_names.clone(),
                        })
                        .collect(),
                    manifest_hash: manifest_hash.as_bytes().to_vec(),
                }
            }
        }
    }
}

// SyncPassOutcome still maps for the commit path (Task 5).
impl From<SyncPassOutcome> for SyncOutcomeDto {
    fn from(o: SyncPassOutcome) -> Self {
        match o {
            SyncPassOutcome::NothingToDo => SyncOutcomeDto::NothingToDo,
            SyncPassOutcome::AppliedAutomatically => SyncOutcomeDto::AppliedAutomatically,
            SyncPassOutcome::SilentMerge => SyncOutcomeDto::SilentMerge,
            SyncPassOutcome::MergedClean => SyncOutcomeDto::MergedClean,
            SyncPassOutcome::RollbackRejected => SyncOutcomeDto::RollbackRejected,
            // commit-path SyncPassOutcome never carries ConflictsPending back to
            // the bridge surface (commit either lands MergedClean or re-inspects);
            // map defensively to a SyncFailed-free arm.
            SyncPassOutcome::ConflictsPending { .. } => SyncOutcomeDto::ConflictsPending {
                vetoes: Vec::new(),
                collisions: Vec::new(),
                manifest_hash: Vec::new(),
            },
        }
    }
}
```

(`ManifestHash::as_bytes()` — confirm the accessor name in `core`; it may be `.0` or `.to_vec()`. Adjust.)

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test --release -p secretary-ffi-bridge veto_decision_dto_round_trips`
Expected: PASS.

- [ ] **Step 6: Lint + commit**

```bash
cargo fmt --all --check && cargo clippy --release --workspace --tests -- -D warnings
git add ffi/secretary-ffi-bridge/src/sync/orchestration.rs
git commit -m "ffi(bridge): conflict-detail DTOs + enriched ConflictsPending"
```

---

## Task 5: ffi bridge — `sync_vault` via inspect + `sync_commit_decisions` + error un-collapse

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/sync/orchestration.rs`
- Modify: `ffi/secretary-ffi-bridge/src/error.rs` (new `FfiVaultError` variants)
- Test: orchestration.rs `#[cfg(test)]`

- [ ] **Step 1: Add the new error variants** in `error.rs`. Find the `FfiVaultError` enum and add (matching the existing `#[serde(tag="code", rename_all="snake_case")]` + thiserror pattern used by the other variants):

```rust
    /// `commit_with_decisions` could not match the supplied decisions to the
    /// recomputed veto set (UI bug or a race). Distinct from `SyncFailed` so the
    /// desktop can show "couldn't apply your choices — try again".
    #[error("sync decisions did not cover the pending conflicts")]
    SyncDecisionsIncomplete,
```

(`SyncEvidenceStale` already exists and is reused for the stale-token case — no new variant needed there.)

- [ ] **Step 2: Write the failing test** in orchestration.rs `tests`:

```rust
    #[test]
    fn commit_decisions_in_happy_path_keep_local() {
        // Stage a two-device veto fixture writable copy. (Reuse the cli fixture
        // builder pattern; if the bridge has no veto fixture yet, build one here
        // mirroring stage_golden_writable_and_password but with a divergent copy.)
        let (_tmp, vault_folder, password, _uuid) = stage_two_device_veto_writable();
        let state_dir = TempDir::new().unwrap();
        // call 1: inspect via sync_vault_in
        let out = sync_vault_in(state_dir.path(), &vault_folder, password, 0).unwrap();
        let (decisions, hash) = match out {
            SyncOutcomeDto::ConflictsPending { vetoes, manifest_hash, .. } => (
                vetoes.into_iter()
                    .map(|v| VetoDecisionDto { record_uuid_hex: v.record_uuid_hex, keep_local: true })
                    .collect::<Vec<_>>(),
                manifest_hash,
            ),
            other => panic!("expected ConflictsPending, got {other:?}"),
        };
        // call 2: commit
        let pw2 = SecretBytes::new(VAULT_001_PASSWORD.to_vec());
        let final_out = sync_commit_decisions_in(
            state_dir.path(), &vault_folder, pw2, decisions, hash, 1,
        )
        .unwrap();
        assert_eq!(final_out, SyncOutcomeDto::MergedClean);
    }
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test --release -p secretary-ffi-bridge commit_decisions_in_happy_path`
Expected: FAIL — `sync_commit_decisions_in` not found.

- [ ] **Step 4: Point `sync_vault_in` at inspect.** In `sync_vault_in` (line 115-132), replace the `sync_pass_pause_on_conflict(...)` call with `sync_pass_inspect(...)`, change the local `outcome` type to `InspectOutcome`, and update the persist `match` to the `InspectOutcome` arms (advancing arms = `AppliedAutomatically | SilentMerge | MergedClean`; no-write arms = `NothingToDo | RollbackRejected | ConflictsPending { .. }`). Return `Ok(outcome.into())`.

- [ ] **Step 5: Add `sync_commit_decisions` + `_in`** after `sync_vault_in`:

```rust
/// Commit the user's veto decisions (call-2 of interactive resolution).
/// Re-opens the vault from `password`, recomputes the draft, asserts the
/// `manifest_hash` token from the inspect pass still matches, then writes.
///
/// # Errors
/// - `SyncEvidenceStale` — the vault changed since inspect; UI re-inspects.
/// - `SyncDecisionsIncomplete` — decisions did not cover the veto set.
/// - plus the same open/lock/state errors as [`sync_vault`].
pub fn sync_commit_decisions(
    vault_folder: &Path,
    password: SecretBytes,
    decisions: Vec<VetoDecisionDto>,
    manifest_hash: Vec<u8>,
    now_ms: u64,
) -> Result<SyncOutcomeDto, FfiVaultError> {
    let state_dir = default_state_dir().ok_or_else(|| FfiVaultError::SyncFailed {
        detail: "no platform data directory available for the sync state cache".into(),
    })?;
    sync_commit_decisions_in(&state_dir, vault_folder, password, decisions, manifest_hash, now_ms)
}

pub(crate) fn sync_commit_decisions_in(
    state_dir: &Path,
    vault_folder: &Path,
    password: SecretBytes,
    decisions: Vec<VetoDecisionDto>,
    manifest_hash: Vec<u8>,
    now_ms: u64,
) -> Result<SyncOutcomeDto, FfiVaultError> {
    let expected = ManifestHash::from_bytes(&manifest_hash)
        .ok_or_else(|| FfiVaultError::SyncFailed { detail: "bad manifest_hash token".into() })?;
    let core_decisions = decisions
        .iter()
        .map(VetoDecisionDto::to_core)
        .collect::<Result<Vec<_>, _>>()?;

    let core_out =
        secretary_core::vault::open_vault(vault_folder, Unlocker::Password(&password), None)?;
    let vault_uuid = core_out.manifest.vault_uuid;
    let identity = secretary_core::unlock::UnlockedIdentity {
        identity_block_key: core_out.identity_block_key,
        identity: core_out.identity,
    };
    let _guard = LockfileGuard::acquire(state_dir, vault_uuid).map_err(map_state_error)?;
    let mut state = load(state_dir, vault_uuid).map_err(map_state_error)?;

    let outcome = sync_pass_commit_decisions(
        vault_folder, &identity, &password, &mut state, expected, core_decisions, now_ms,
    )
    .map_err(map_sync_error)?;

    match outcome {
        SyncPassOutcome::AppliedAutomatically
        | SyncPassOutcome::SilentMerge
        | SyncPassOutcome::MergedClean => save(state_dir, &state).map_err(map_state_error)?,
        SyncPassOutcome::NothingToDo
        | SyncPassOutcome::RollbackRejected
        | SyncPassOutcome::ConflictsPending { .. } => {}
    }
    Ok(outcome.into())
}
```

(`ManifestHash::from_bytes` — add a small constructor in `core` if it doesn't exist, or store/compare as `Vec<u8>` end-to-end. Confirm + adjust. Add `ManifestHash` to the bridge's core imports.)

- [ ] **Step 6: Un-collapse the decision errors** in `map_sync_error` (lines 155-161). Move `MissingVetoDecision` / `UnknownVetoDecision` out of the `SyncFailed` group into their own arm:

```rust
        SyncError::MissingVetoDecision { .. } | SyncError::UnknownVetoDecision { .. } => {
            FfiVaultError::SyncDecisionsIncomplete
        }
        SyncError::InvalidArgument { .. }
        | SyncError::ConflictCopyScanIoFailed { .. }
        | SyncError::EmptyDraftWithVetoes => FfiVaultError::SyncFailed { detail: e.to_string() },
```

- [ ] **Step 7: Run test + the existing bridge sync tests**

Run: `cargo test --release -p secretary-ffi-bridge sync`
Expected: PASS (new test + the 3 existing `sync_vault_in_*` tests, now over `InspectOutcome`).

- [ ] **Step 8: Re-export new types** from the bridge crate root (`ffi/secretary-ffi-bridge/src/lib.rs`): add `VetoDto, CollisionDto, VetoDecisionDto, sync_commit_decisions` to the `pub use` list next to `SyncOutcomeDto`/`sync_vault`. Verify the FfiVaultError exhaustive matches elsewhere in the crate still compile (the new variant).

- [ ] **Step 9: Lint + commit**

```bash
cargo fmt --all --check && cargo clippy --release --workspace --tests -- -D warnings
git add ffi/secretary-ffi-bridge/src/
git commit -m "ffi(bridge): sync_commit_decisions + inspect wiring + un-collapsed decision errors"
```

---

## Task 6: ffi uniffi + pyo3 — expose + conformance KAT regen

**Files:**
- Modify: `ffi/secretary-ffi-uniffi/**` (UDL + lib), `ffi/secretary-ffi-py/**` (pyo3)
- Modify: `ffi/secretary-ffi-uniffi/tests/swift/ConformanceErrors.swift`, `tests/kotlin/ConformanceErrors.kt`
- Regenerate: `core/tests/data/conformance_kat.json`

**Per [[project_secretary_ffivaulterror_workspace_match]]: cargo + clippy CANNOT see the Swift/Kotlin harnesses — only `run_conformance.sh` does. Thread every new variant and run both scripts.**

- [ ] **Step 1: Find every FfiVaultError match + binding surface**

Run: `grep -rn "FfiVaultError::" ffi/ && grep -rln "SyncOutcomeDto\|sync_vault" ffi/secretary-ffi-uniffi ffi/secretary-ffi-py`
Expected: a list of exhaustive matches + the uniffi UDL/scaffolding + pyo3 module to extend.

- [ ] **Step 2: Add `SyncDecisionsIncomplete`** to the uniffi error enum (UDL or `#[derive(uniffi::Error)]`) and the pyo3 error mapping. Add the `VetoDto`/`CollisionDto`/`VetoDecisionDto` records + enrich the `ConflictsPending` variant in both bindings. Expose `sync_commit_decisions`.

- [ ] **Step 3: Thread the variant** through `ConformanceErrors.swift` and `ConformanceErrors.kt` (add the case to whatever exhaustive switch/when each harness uses).

- [ ] **Step 4: Build the bindings**

Run: `cargo build --release -p secretary-ffi-uniffi -p secretary-ffi-py`
Expected: clean.

- [ ] **Step 5: Regenerate the conformance KAT** (human-review the diff — expected scope: the conflict-path records only)

Run: `cargo test --release --workspace -- --ignored generate_conformance_kat --nocapture`
Then: `git diff core/tests/data/conformance_kat.json` — confirm the diff is scoped to the new conflict surface, nothing else.

- [ ] **Step 6: Run both cross-language conformance scripts**

```bash
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
```
Expected: both PASS.

- [ ] **Step 7: Run the Python conformance + workspace tests**

```bash
uv run core/tests/python/conformance.py
cargo test --release --workspace
```
Expected: PASS.

- [ ] **Step 8: Lint + commit**

```bash
cargo fmt --all --check && cargo clippy --release --workspace --tests -- -D warnings
git add ffi/ core/tests/data/conformance_kat.json
git commit -m "ffi(uniffi+pyo3): expose sync_commit_decisions + conflict DTOs; regen conformance KAT"
```

---

## Task 7: desktop src-tauri — DTOs (enrich + 3 new) + wire-format tests

**Files:**
- Modify: `desktop/src-tauri/src/dtos/sync.rs`
- Test: same file

- [ ] **Step 1: Write the failing wire-format tests** (append to the `tests` module). Replace `conflicts_pending_serializes_kind_and_camelcase_veto_count` (lines 133-137) since the shape changed:

```rust
    #[test]
    fn conflicts_pending_serializes_detail() {
        let v = serde_json::to_value(SyncOutcomeDto::ConflictsPending {
            vetoes: vec![VetoDto {
                record_uuid_hex: "0a".repeat(16),
                record_type: "login".into(),
                tags: vec!["work".into()],
                field_names: vec!["password".into()],
                local_last_mod_ms: 10,
                peer_tombstoned_at_ms: 20,
                peer_device_hex: "9c".repeat(16),
            }],
            collisions: vec![CollisionDto {
                record_uuid_hex: "0a".repeat(16),
                field_names: vec!["password".into()],
            }],
            manifest_hash: vec![1, 2, 3],
        })
        .unwrap();
        assert_eq!(v["kind"], "conflictsPending");
        assert_eq!(v["vetoes"][0]["recordType"], "login");
        assert_eq!(v["vetoes"][0]["localLastModMs"], 10);
        assert_eq!(v["collisions"][0]["fieldNames"][0], "password");
        assert_eq!(v["manifestHash"], serde_json::json!([1, 2, 3]));
    }

    #[test]
    fn veto_decision_dto_deserializes_camelcase() {
        let d: VetoDecisionDto = serde_json::from_value(
            serde_json::json!({ "recordUuidHex": "0a", "keepLocal": true }),
        )
        .unwrap();
        assert!(d.keep_local);
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd desktop/src-tauri && cargo test conflicts_pending_serializes_detail`
Expected: FAIL.

- [ ] **Step 3: Add the DTOs** in `dtos/sync.rs`. Add `Serialize`-deriving `VetoDto`/`CollisionDto` (camelCase) and a `Deserialize`-deriving `VetoDecisionDto`, import the bridge equivalents, change `ConflictsPending` to the rich shape, and update the `From<BridgeSyncOutcomeDto>` impl:

```rust
use serde::{Deserialize, Serialize};
use secretary_ffi_bridge::{
    CollisionDto as BridgeCollisionDto, SyncOutcomeDto as BridgeSyncOutcomeDto,
    SyncStatusDto as BridgeSyncStatusDto, VetoDto as BridgeVetoDto,
};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VetoDto {
    pub record_uuid_hex: String,
    pub record_type: String,
    pub tags: Vec<String>,
    pub field_names: Vec<String>,
    pub local_last_mod_ms: u64,
    pub peer_tombstoned_at_ms: u64,
    pub peer_device_hex: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CollisionDto {
    pub record_uuid_hex: String,
    pub field_names: Vec<String>,
}

/// Inbound decision from the renderer (deserialized from the command arg).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VetoDecisionDto {
    pub record_uuid_hex: String,
    pub keep_local: bool,
}
```

Change the `ConflictsPending` arm of the desktop `SyncOutcomeDto` enum:

```rust
    ConflictsPending {
        vetoes: Vec<VetoDto>,
        collisions: Vec<CollisionDto>,
        manifest_hash: Vec<u8>,
    },
```

Update the `From<BridgeSyncOutcomeDto>` impl's `ConflictsPending` arm to map each bridge `VetoDto`/`CollisionDto` field-for-field into the desktop DTO and `manifest_hash` straight through. Add a `From<BridgeVetoDto> for VetoDto` + `From<BridgeCollisionDto> for CollisionDto` (or inline `.map`).

- [ ] **Step 4: Export the new types** from `dtos/mod.rs` (add to the `pub use sync::{...}` line: `VetoDto, CollisionDto, VetoDecisionDto`).

- [ ] **Step 5: Run to verify it passes**

Run: `cd desktop/src-tauri && cargo test conflicts_pending_serializes_detail veto_decision_dto_deserializes`
Expected: PASS.

- [ ] **Step 6: Lint + commit**

```bash
cargo fmt --all --check && cargo clippy --release --workspace --tests -- -D warnings
git add desktop/src-tauri/src/dtos/
git commit -m "desktop(tauri): enriched ConflictsPending DTO + veto/collision/decision DTOs"
```

---

## Task 8: desktop src-tauri — `sync_commit_decisions` command

**Files:**
- Modify: `desktop/src-tauri/src/commands/sync.rs`
- Modify: `desktop/src-tauri/src/main.rs` (register), `commands/mod.rs` if it re-exports
- Test: `commands/sync.rs` `#[cfg(test)]` or the `ipc_integration` test target (NotUnlocked seam)

- [ ] **Step 1: Write the failing seam test** (mirror the existing NotUnlocked tests for the sync commands; find one with `grep -n "not_unlocked\|NotUnlocked" desktop/src-tauri/src/commands/sync.rs desktop/src-tauri/tests/*.rs`). Add:

```rust
    #[test]
    fn sync_commit_decisions_impl_requires_unlock() {
        let state = Mutex::new(VaultSession::locked());
        let err = sync_commit_decisions_impl(&state, &Password::from("pw".to_string()), Vec::new(), Vec::new(), 0)
            .unwrap_err();
        assert!(matches!(err, AppError::NotUnlocked));
    }
```

(Match the exact `VaultSession` locked-constructor + `Password` constructor used by the existing `sync_now_impl` seam test.)

- [ ] **Step 2: Run to verify it fails**

Run: `cd desktop/src-tauri && cargo test sync_commit_decisions_impl_requires_unlock`
Expected: FAIL.

- [ ] **Step 3: Implement the command** in `commands/sync.rs`. Add imports (`sync_commit_decisions as bridge_sync_commit_decisions`, `VetoDecisionDto`) and:

```rust
#[tauri::command]
pub async fn sync_commit_decisions(
    state: State<'_, Mutex<VaultSession>>,
    password: Password,
    decisions: Vec<VetoDecisionDto>,
    manifest_hash: Vec<u8>,
) -> Result<SyncOutcomeDto, AppError> {
    sync_commit_decisions_impl(state.inner(), &password, decisions, manifest_hash, now_ms())
}

/// Testable core for `sync_commit_decisions` (call-2 of interactive resolution).
/// Re-opens an identity from `password`, recomputes + commits over the session's
/// retained vault folder. Strict: every bridge error is mapped.
pub fn sync_commit_decisions_impl(
    state: &Mutex<VaultSession>,
    password: &Password,
    decisions: Vec<VetoDecisionDto>,
    manifest_hash: Vec<u8>,
    now_ms: u64,
) -> Result<SyncOutcomeDto, AppError> {
    let bridge_decisions: Vec<secretary_ffi_bridge::VetoDecisionDto> = decisions
        .into_iter()
        .map(|d| secretary_ffi_bridge::VetoDecisionDto {
            record_uuid_hex: d.record_uuid_hex,
            keep_local: d.keep_local,
        })
        .collect();
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        let outcome = bridge_sync_commit_decisions(
            &u.vault_folder,
            SecretBytes::from(password.expose()),
            bridge_decisions,
            manifest_hash,
            now_ms,
        )
        .map_err(map_ffi_error)?;
        Ok(SyncOutcomeDto::from(outcome))
    })
}
```

- [ ] **Step 4: Register** in `main.rs` — add `commands::sync::sync_commit_decisions` to the `tauri::generate_handler![...]` list (next to `sync_now`).

- [ ] **Step 5: Run to verify it passes**

Run: `cd desktop/src-tauri && cargo test sync_commit_decisions_impl_requires_unlock`
Expected: PASS.

- [ ] **Step 6: Lint + commit**

```bash
cargo fmt --all --check && cargo clippy --release --workspace --tests -- -D warnings
git add desktop/src-tauri/src/
git commit -m "desktop(tauri): sync_commit_decisions command + NotUnlocked seam"
```

---

## Task 9: desktop TS — `sync_decisions_incomplete` AppError

**Files:**
- Modify: `desktop/src/lib/errors.ts`
- Test: `desktop/src/lib/errors.test.ts` (or wherever `userMessageFor` is tested — `grep -rln userMessageFor desktop/src`)

- [ ] **Step 1: Write the failing test**:

```ts
it('maps sync_decisions_incomplete to a retry message', () => {
  const msg = userMessageFor({ code: 'sync_decisions_incomplete' });
  expect(msg.title).toMatch(/couldn.t apply/i);
  expect(msg.actionHint).toBeDefined();
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd desktop && pnpm test errors`
Expected: FAIL (tsc: `'sync_decisions_incomplete'` not assignable).

- [ ] **Step 3: Add the code** — three edits in `errors.ts`:
  1. Add `'sync_decisions_incomplete',` to `APP_ERROR_CODES` (after `'sync_failed'`, line 47).
  2. Add `| { code: 'sync_decisions_incomplete' }` to the `AppError` union (after line 93).
  3. Add the case to `userMessageFor` (after the `sync_failed` arm, line 258):

```ts
    case 'sync_decisions_incomplete':
      return {
        title: "Couldn't apply your choices",
        actionHint: 'Some conflicts weren’t resolved — please try syncing again.'
      };
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd desktop && pnpm test errors`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add desktop/src/lib/errors.ts desktop/src/lib/errors.test.ts
git commit -m "desktop(ts): sync_decisions_incomplete AppError + message"
```

---

## Task 10: desktop TS — conflict types + pure helpers

**Files:**
- Modify: `desktop/src/lib/sync.ts`
- Test: `desktop/src/lib/sync.test.ts` (find with `grep -rln "syncOutcomeMessage" desktop/src`)

- [ ] **Step 1: Write the failing tests**:

```ts
import { collectDecisions, decisionsComplete, formatVetoSummary, type VetoDto } from './sync';

const veto = (id: string): VetoDto => ({
  recordUuidHex: id, recordType: 'login', tags: ['work'],
  fieldNames: ['username', 'password'], localLastModMs: 1000, peerTombstonedAtMs: 2000,
  peerDeviceHex: 'ab'.repeat(16)
});

it('collectDecisions maps choices to the DTO array', () => {
  const vetoes = [veto('0a'), veto('0b')];
  const choices = { '0a': true, '0b': false };
  expect(collectDecisions(vetoes, choices)).toEqual([
    { recordUuidHex: '0a', keepLocal: true },
    { recordUuidHex: '0b', keepLocal: false }
  ]);
});

it('decisionsComplete is true only when every veto has a choice', () => {
  const vetoes = [veto('0a'), veto('0b')];
  expect(decisionsComplete(vetoes, { '0a': true })).toBe(false);
  expect(decisionsComplete(vetoes, { '0a': true, '0b': false })).toBe(true);
});

it('formatVetoSummary builds a metadata label', () => {
  expect(formatVetoSummary(veto('0a'))).toContain('login');
  expect(formatVetoSummary(veto('0a'))).toContain('work');
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd desktop && pnpm test sync`
Expected: FAIL — exports not found.

- [ ] **Step 3: Add types + helpers** to `sync.ts`. Add the DTO types and enrich `SyncOutcome`:

```ts
export type VetoDto = {
  recordUuidHex: string;
  recordType: string;
  tags: string[];
  fieldNames: string[];
  localLastModMs: number;
  peerTombstonedAtMs: number;
  peerDeviceHex: string;
};
export type CollisionDto = { recordUuidHex: string; fieldNames: string[] };
export type VetoDecisionDto = { recordUuidHex: string; keepLocal: boolean };

/** keepLocal choice keyed by recordUuidHex. */
export type VetoChoices = Record<string, boolean>;
```

Change the `conflictsPending` arm of `SyncOutcome` (line 18):

```ts
  | { kind: 'conflictsPending'; vetoes: VetoDto[]; collisions: CollisionDto[]; manifestHash: number[] }
```

Then the helpers:

```ts
/** Build the decision array for `sync_commit_decisions`. Order follows `vetoes`. */
export function collectDecisions(vetoes: VetoDto[], choices: VetoChoices): VetoDecisionDto[] {
  return vetoes.map((v) => ({ recordUuidHex: v.recordUuidHex, keepLocal: choices[v.recordUuidHex] }));
}

/** True when every veto has an explicit choice (no undefined). */
export function decisionsComplete(vetoes: VetoDto[], choices: VetoChoices): boolean {
  return vetoes.every((v) => typeof choices[v.recordUuidHex] === 'boolean');
}

/** Human label for a disputed record — metadata only (no secret values). */
export function formatVetoSummary(v: VetoDto): string {
  const tagPart = v.tags.length ? ` · ${v.tags.join(' · ')}` : '';
  return `${v.recordType}${tagPart}`;
}
```

Fix `syncOutcomeMessage`/`syncChangedData` `conflictsPending` arms to use `outcome.vetoes.length` instead of `outcome.vetoCount` (the `coming soon` text is now replaced by the dialog opening — keep a short fallback message for the rare case the dialog can't open, e.g. `${n} conflict(s) to resolve`).

- [ ] **Step 4: Run to verify it passes**

Run: `cd desktop && pnpm test sync && pnpm typecheck`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add desktop/src/lib/sync.ts desktop/src/lib/sync.test.ts
git commit -m "desktop(ts): conflict DTO types + collectDecisions/decisionsComplete/formatVetoSummary"
```

---

## Task 11: desktop TS — `syncCommitDecisions` IPC wrapper

**Files:**
- Modify: `desktop/src/lib/ipc.ts`
- Test: `desktop/src/lib/ipc.test.ts` (find with `grep -n "syncNow" desktop/src/lib/ipc.ts desktop/src/lib/*.test.ts`)

- [ ] **Step 1: Write the failing test** (mirror the existing `syncNow` wrapper test — same `invoke` mock pattern):

```ts
it('syncCommitDecisions invokes the command with decisions + token', async () => {
  invokeMock.mockResolvedValueOnce({ kind: 'mergedClean' });
  const out = await syncCommitDecisions('pw', [{ recordUuidHex: '0a', keepLocal: true }], [1, 2, 3]);
  expect(invokeMock).toHaveBeenCalledWith('sync_commit_decisions', {
    password: 'pw', decisions: [{ recordUuidHex: '0a', keepLocal: true }], manifestHash: [1, 2, 3]
  });
  expect(out).toEqual({ kind: 'mergedClean' });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd desktop && pnpm test ipc`
Expected: FAIL.

- [ ] **Step 3: Add the wrapper** in `ipc.ts` (mirror `syncNow`'s exact shape — the Tauri arg key casing must match the command param names: `password`, `decisions`, `manifestHash`):

```ts
import type { VetoDecisionDto } from './sync';

export async function syncCommitDecisions(
  password: string,
  decisions: VetoDecisionDto[],
  manifestHash: number[]
): Promise<SyncOutcome> {
  return invoke<SyncOutcome>('sync_commit_decisions', { password, decisions, manifestHash });
}
```

(Confirm `SyncOutcome` is already imported in `ipc.ts` from `./sync` — `syncNow` returns it.)

- [ ] **Step 4: Run to verify it passes**

Run: `cd desktop && pnpm test ipc && pnpm typecheck`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add desktop/src/lib/ipc.ts desktop/src/lib/ipc.test.ts
git commit -m "desktop(ts): syncCommitDecisions IPC wrapper"
```

---

## Task 12: desktop — `ConflictResolutionDialog.svelte`

**Files:**
- Create: `desktop/src/components/ConflictResolutionDialog.svelte`
- Test: `desktop/src/components/ConflictResolutionDialog.test.ts`

**Mirrors `SyncPasswordDialog`: native `<dialog>`, `showModal()` via `$effect`, Esc → cancel, strict inline error, busy guard. Receives the vetoes + collisions + manifestHash + password; calls `syncCommitDecisions` on Apply.**

- [ ] **Step 1: Write the failing component tests** (mirror existing component test setup; use `mockRejectedValueOnce` for the error path per [[project_secretary_vitest_mockrejectedvalue_quirk]]):

```ts
import { render, fireEvent } from '@testing-library/svelte';
import { vi } from 'vitest';
import ConflictResolutionDialog from './ConflictResolutionDialog.svelte';

const veto = (id: string) => ({
  recordUuidHex: id, recordType: 'login', tags: ['work'], fieldNames: ['password'],
  localLastModMs: 1, peerTombstonedAtMs: 2, peerDeviceHex: 'ab'.repeat(16)
});

const baseProps = (over = {}) => ({
  vetoes: [veto('0a')], collisions: [], manifestHash: [1, 2, 3], password: 'pw',
  onResolved: vi.fn(), onCancel: vi.fn(), ...over
});

it('renders one card per veto with default keep-mine', async () => {
  const { getByText } = render(ConflictResolutionDialog, baseProps());
  expect(getByText(/login/)).toBeInTheDocument();
});

it('Apply collects decisions and calls syncCommitDecisions', async () => {
  const { syncCommitDecisions } = await import('../lib/ipc');
  vi.mocked(syncCommitDecisions).mockResolvedValueOnce({ kind: 'mergedClean' });
  const onResolved = vi.fn();
  const { getByText } = render(ConflictResolutionDialog, baseProps({ onResolved }));
  await fireEvent.click(getByText(/apply/i));
  expect(syncCommitDecisions).toHaveBeenCalledWith('pw', [{ recordUuidHex: '0a', keepLocal: true }], [1, 2, 3]);
  expect(onResolved).toHaveBeenCalledWith({ kind: 'mergedClean' });
});

it('keeps the dialog open and shows an alert on error', async () => {
  const { syncCommitDecisions } = await import('../lib/ipc');
  vi.mocked(syncCommitDecisions).mockRejectedValueOnce({ code: 'sync_decisions_incomplete' });
  const onResolved = vi.fn();
  const { getByText, findByRole } = render(ConflictResolutionDialog, baseProps({ onResolved }));
  await fireEvent.click(getByText(/apply/i));
  expect(await findByRole('alert')).toBeInTheDocument();
  expect(onResolved).not.toHaveBeenCalled();
});
```

(Add the `vi.mock('../lib/ipc', ...)` hoisted mock at top, mirroring `SyncPasswordDialog.test.ts`.)

- [ ] **Step 2: Run to verify it fails**

Run: `cd desktop && pnpm test ConflictResolutionDialog`
Expected: FAIL — component doesn't exist.

- [ ] **Step 3: Create the component**:

```svelte
<script lang="ts">
  // Centered resolution modal (interactive conflict resolution). Mirrors
  // SyncPasswordDialog: native <dialog>, showModal() via $effect, Esc → cancel.
  // Default per-record choice is Keep mine (no data loss). Strict: a commit
  // failure renders the typed AppError inline and keeps the dialog open
  // (except the stale case, surfaced to the parent to re-inspect). The
  // password is received from SyncPasswordDialog and cleared by the parent.
  import { syncCommitDecisions, isAppError } from '../lib/ipc';
  import { userMessageFor, type AppError } from '../lib/errors';
  import {
    collectDecisions, decisionsComplete, formatVetoSummary,
    type VetoDto, type CollisionDto, type SyncOutcome, type VetoChoices
  } from '../lib/sync';

  type Props = {
    vetoes: VetoDto[];
    collisions: CollisionDto[];
    manifestHash: number[];
    password: string;
    onResolved: (outcome: SyncOutcome) => void;
    onCancel: () => void;
  };
  let { vetoes, collisions, manifestHash, password, onResolved, onCancel }: Props = $props();

  let dialogEl: HTMLDialogElement | undefined = $state();
  // Default every veto to keep-mine (no data loss).
  let choices = $state<VetoChoices>(
    Object.fromEntries(vetoes.map((v) => [v.recordUuidHex, true]))
  );
  let busy = $state(false);
  let error = $state<AppError | null>(null);

  const canApply = $derived(!busy && decisionsComplete(vetoes, choices));

  $effect(() => {
    if (dialogEl && !dialogEl.hasAttribute('open')) dialogEl.showModal();
  });

  function setChoice(id: string, keepLocal: boolean) {
    choices = { ...choices, [id]: keepLocal };
  }

  function onNativeCancel(event: Event) {
    event.preventDefault();
    onCancel();
  }

  async function apply(event: Event) {
    event.preventDefault();
    if (!canApply) return;
    busy = true;
    error = null;
    try {
      const outcome = await syncCommitDecisions(password, collectDecisions(vetoes, choices), manifestHash);
      onResolved(outcome);
    } catch (err) {
      error = isAppError(err) ? err : { code: 'internal' };
    } finally {
      busy = false;
    }
  }
</script>

<dialog bind:this={dialogEl} class="conflict-dialog" oncancel={onNativeCancel}>
  <form class="conflict-dialog__form" onsubmit={apply}>
    <h2 class="conflict-dialog__title">Resolve sync conflicts</h2>
    <p class="conflict-dialog__subtitle">
      These records were deleted on another device but you have them here. Choose what to keep —
      nothing is written until you click Apply.
    </p>

    {#each vetoes as v (v.recordUuidHex)}
      <div class="conflict-dialog__card">
        <div class="conflict-dialog__meta">
          <strong>{formatVetoSummary(v)}</strong>
          <span class="conflict-dialog__fields">fields: {v.fieldNames.join(' · ')}</span>
          <span class="conflict-dialog__when">
            you edited this · peer deleted it on device {v.peerDeviceHex.slice(0, 4)}…
          </span>
        </div>
        <div class="conflict-dialog__choices" role="group" aria-label="Resolution for {formatVetoSummary(v)}">
          <button type="button" aria-pressed={choices[v.recordUuidHex] === true}
            onclick={() => setChoice(v.recordUuidHex, true)} disabled={busy}>Keep mine</button>
          <button type="button" aria-pressed={choices[v.recordUuidHex] === false}
            onclick={() => setChoice(v.recordUuidHex, false)} disabled={busy}>Accept delete</button>
        </div>
      </div>
    {/each}

    {#if collisions.length > 0}
      <details class="conflict-dialog__collisions" open>
        <summary>{collisions.length} field(s) auto-merged (newer edit won) — no action needed</summary>
        <ul>
          {#each collisions as c (c.recordUuidHex)}
            <li>{c.fieldNames.join(', ')}</li>
          {/each}
        </ul>
      </details>
    {/if}

    {#if error}
      {@const msg = userMessageFor(error)}
      <p class="conflict-dialog__error" role="alert">
        {msg.title}{msg.actionHint ? ` — ${msg.actionHint}` : ''}
      </p>
    {/if}

    <div class="conflict-dialog__actions">
      <button type="button" onclick={onCancel} disabled={busy}>Cancel</button>
      <button type="submit" class="conflict-dialog__button--primary" disabled={!canApply}>
        {busy ? 'Applying…' : 'Apply & finish sync'}
      </button>
    </div>
  </form>
</dialog>
```

(Add styles mirroring `sync-dialog` from SyncPasswordDialog — confirm whether styles are co-located or in a global stylesheet, and follow that convention.)

- [ ] **Step 4: Run to verify it passes**

Run: `cd desktop && pnpm test ConflictResolutionDialog && pnpm svelte-check`
Expected: PASS, 0 svelte-check errors.

- [ ] **Step 5: Commit**

```bash
git add desktop/src/components/ConflictResolutionDialog.svelte desktop/src/components/ConflictResolutionDialog.test.ts
git commit -m "desktop(ui): ConflictResolutionDialog — per-record keep/accept + auto-merge notice"
```

---

## Task 13: desktop — wire the flow (password → conflicts → resolution)

**Files:**
- Modify: `desktop/src/components/SyncPasswordDialog.svelte` (yield password + conflicts up instead of dead-ending)
- Modify: `desktop/src/components/SyncPill.svelte` (open ConflictResolutionDialog)
- Test: update `SyncPasswordDialog.test.ts`, `SyncPill.test.ts`

**Hygiene:** the password must survive from the password dialog into the resolution dialog (for call 2), then be cleared on every terminal path. JS can't zeroize; null it out on resolve/cancel/error (matching the `RevealedFieldDto` "cannot be zeroized in JS, drop on terminal" precedent).

- [ ] **Step 1: Write/adjust the failing tests** — `SyncPill.test.ts`: when `syncNow` resolves `conflictsPending`, the pill renders `ConflictResolutionDialog`; on its `onResolved`, the pill shows the synced notice + refreshes. Mock `syncNow` to return a `conflictsPending` outcome and assert the resolution dialog appears:

```ts
it('opens the resolution dialog on conflictsPending and finishes on resolve', async () => {
  const { syncNow } = await import('../lib/ipc');
  vi.mocked(syncNow).mockResolvedValueOnce({
    kind: 'conflictsPending',
    vetoes: [{ recordUuidHex: '0a', recordType: 'login', tags: [], fieldNames: ['p'],
      localLastModMs: 1, peerTombstonedAtMs: 2, peerDeviceHex: 'ab'.repeat(16) }],
    collisions: [], manifestHash: [1]
  });
  // ... open pill → submit password → assert ConflictResolutionDialog text shows
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd desktop && pnpm test SyncPill`
Expected: FAIL.

- [ ] **Step 3: Change `SyncPasswordDialog`** to surface a conflicts outcome + the password instead of closing. Change the `Props` to add `onConflicts`:

```ts
  type Props = {
    onSynced: (outcome: SyncOutcome) => void;
    onConflicts: (outcome: Extract<SyncOutcome, { kind: 'conflictsPending' }>, password: string) => void;
    onCancel: () => void;
  };
  let { onSynced, onConflicts, onCancel }: Props = $props();
```

In `submit`, branch on the outcome — do NOT clear the password for the conflicts arm:

```ts
      const outcome = await syncNow(password);
      if (outcome.kind === 'conflictsPending') {
        onConflicts(outcome, password); // password handed to the resolution dialog
        return; // keep this component's state until parent unmounts it
      }
      password = '';
      onSynced(outcome);
```

- [ ] **Step 4: Change `SyncPill`** to manage the resolution dialog. Add state + handlers:

```svelte
  import ConflictResolutionDialog from './ConflictResolutionDialog.svelte';
  // ...
  let conflicts = $state<Extract<SyncOutcome, { kind: 'conflictsPending' }> | null>(null);
  let conflictPassword = $state<string | null>(null);

  function onConflicts(outcome: Extract<SyncOutcome, { kind: 'conflictsPending' }>, password: string) {
    dialogOpen = false;
    conflicts = outcome;
    conflictPassword = password;
  }

  async function onResolved(outcome: SyncOutcome) {
    conflicts = null;
    conflictPassword = null; // drop the password (cannot zeroize in JS)
    await onSynced(outcome);
  }

  function onResolveCancel() {
    conflicts = null;
    conflictPassword = null;
  }
```

Pass `onConflicts` to `SyncPasswordDialog` and render the resolution dialog:

```svelte
{#if dialogOpen}
  <SyncPasswordDialog {onSynced} {onConflicts} onCancel={() => (dialogOpen = false)} />
{/if}

{#if conflicts && conflictPassword !== null}
  <ConflictResolutionDialog
    vetoes={conflicts.vetoes}
    collisions={conflicts.collisions}
    manifestHash={conflicts.manifestHash}
    password={conflictPassword}
    {onResolved}
    onCancel={onResolveCancel}
  />
{/if}
```

- [ ] **Step 5: Run to verify it passes**

Run: `cd desktop && pnpm test SyncPill SyncPasswordDialog && pnpm typecheck && pnpm svelte-check`
Expected: PASS.

- [ ] **Step 6: Full frontend gauntlet + commit**

```bash
cd desktop && pnpm test && pnpm typecheck && pnpm svelte-check && pnpm lint
git add desktop/src/components/SyncPill.svelte desktop/src/components/SyncPasswordDialog.svelte desktop/src/components/*.test.ts
git commit -m "desktop(ui): wire SyncPill → password → ConflictResolutionDialog flow"
```

---

## Task 14: docs + manual smoke fixture

**Files:**
- Modify: `README.md`, `ROADMAP.md`
- Reference: the two-device veto fixture for the manual smoke

- [ ] **Step 1: Update ROADMAP.md** — mark interactive conflict resolution shipped (find the relevant section: `grep -n "conflict\|coming soon\|D.1.14\|ConflictsPending" ROADMAP.md`). Add a dated line per the existing style.

- [ ] **Step 2: Update README.md** — if README lists desktop sync capabilities, add interactive conflict resolution (brief dot point per [[feedback_readme_style]] — no test-count walls).

- [ ] **Step 3: Document the manual smoke** in the PR description (not a tracked file unless the repo has a smoke doc). The smoke needs a real veto, which the single golden vault can't produce alone. Steps:

```bash
# Build a two-device divergence on a temp copy of the golden vault:
SMOKE_DIR="$(mktemp -d)/golden_smoke"
cp -R core/tests/data/golden_vault_001 "$SMOKE_DIR"
# (Use the test fixture builder / a small script to write a conflict-copy whose
#  manifest tombstones a record the canonical side still has live — i.e. drop a
#  *.copy block alongside, mirroring the cli veto fixture. Document the exact
#  steps the cli fixture uses so the smoke reproduces one veto.)
cd desktop && pnpm tauri dev
#   Verify: Sync now → password modal → resolution modal lists the disputed
#   record (metadata only) + auto-merge notice; Keep mine / Accept delete toggle;
#   wrong/again behaviors; Apply → pill shows Synced; records view refreshes;
#   Esc/Cancel close without writing. Record the result in the PR.
```

- [ ] **Step 4: Commit**

```bash
git add README.md ROADMAP.md
git commit -m "docs: interactive conflict resolution shipped (README + ROADMAP)"
```

---

## Final verification (before PR)

- [ ] **Full workspace gauntlet:**
```bash
cargo fmt --all --check
cargo clippy --release --workspace --tests -- -D warnings
cargo test --release --workspace
uv run core/tests/python/conformance.py
```
- [ ] **Both cross-language conformance scripts:**
```bash
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
```
- [ ] **Desktop frontend gauntlet:**
```bash
cd desktop && pnpm test && pnpm typecheck && pnpm svelte-check && pnpm lint
cd desktop/src-tauri && cargo test
```
- [ ] **Manual GUI smoke** (Task 14 §3) on the two-device fixture — recorded in the PR.
- [ ] **Spec-test-name freshness** (docs cite test names):
```bash
uv run core/tests/python/spec_test_name_freshness.py
```

## Risks / watch-items (from spec §8)

- **Two-device veto fixture** (Tasks 2, 5, 14) is the main unknown. Reuse the existing `cli/tests/sync_pass_integration.rs` veto builder; do NOT hand-roll new crypto values ([[feedback_test_crypto_random_not_hardcoded]]).
- **`ManifestHash` accessor names** (`as_bytes` / `from_bytes`) are assumed — confirm in `core` and adjust; if no `from_bytes`, thread the token as `Vec<u8>` and compare via a core helper.
- **FfiVaultError exhaustive matches** — the new `SyncDecisionsIncomplete` variant breaks every match across uniffi/pyo3/core-KAT AND the Swift/Kotlin `ConformanceErrors` harnesses ([[project_secretary_ffivaulterror_workspace_match]]); cargo/clippy can't see the latter — Task 6 runs both `run_conformance.sh`.
