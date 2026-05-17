# C.1 — Sync orchestration: rollback + fork detection

**Date:** 2026-05-17
**Phase:** Sub-project C, phase C.1 (first slice — detection only)
**Status:** Design approved; ready for implementation plan

---

## Context

Sub-project C is the headless sync-orchestration layer that sits between the Sub-project A core and the platform consumers (the C.2 `secretary sync` CLI, and eventually each D.x UI through the FFI). ROADMAP decomposes C into four phases:

- **C.1** — pure-Rust sync state machine, no OS dependencies.
- **C.2** — `secretary sync` CLI on desktop, wraps C.1 + the `notify` crate.
- **C.3** — mobile sync adapters (iOS `NSFilePresenter`, Android SAF).
- **C.4** — cross-device convergence conformance.

This document specifies **the first slice of C.1: rollback detection and fork detection only**. Automatic merge, conflict-copy ingestion, and the veto-on-tombstone workflow are scoped to a follow-up slice (C.1.1) with its own design doc; the rationale for the split is below.

## Goals

C.1 (this slice) delivers a single Rust function — `sync_once` — that reconciles one local vault folder against persisted "highest vector clock seen" state, classifying the disk's current state into one of four outcomes:

| Outcome | Meaning |
|---|---|
| `NothingToDo` | Local state is at-or-ahead of disk. No-op. |
| `AppliedAutomatically { new_state }` | Disk strictly dominates local state. Caller persists `new_state` and proceeds. |
| `ForkDetected { disk_vector_clock, local_highest_seen }` | Disk and local state are concurrent (incomparable vector clocks). C.1 reports the fork; C.1.1 will extend with automatic merge. |
| `RollbackRejected(RollbackEvidence)` | Disk is strictly dominated by local state — `crypto-design.md` §10 rollback. Caller's UX may offer an override (deferred). |

This is exactly the §10 algorithm from `crypto-design.md`, exposed as a pure function.

## Non-goals (for this slice)

- **Automatic merge of concurrent states.** `ForkDetected` is terminal in C.1; C.1.1 takes it over.
- **Veto-on-tombstone workflow.** Vacuous without automatic merge; deferred to C.1.1.
- **Conflict-copy file ingestion.** No `VaultBundle` parameter; C.1 reads only the canonical filenames inside the vault folder.
- **File-system watching.** `notify` / `NSFilePresenter` / SAF integration is C.2 and C.3.
- **`secretary sync` CLI binary.** C.2.
- **Mobile lifecycle adapters.** C.3.
- **FFI exposure.** C.1 settles as a Rust-only surface before being frozen into PyO3 / uniffi. The reference consumer in C.2 is itself Rust, so no FFI is needed to prove the API.
- **Cross-language conformance.** A `sync_kat.json` slot is allocated; the clean-room Python implementation lands with C.4.
- **Shared-block import (peer → user vault).** One-shot ingest, orthogonal to sync orchestration.
- **`SyncState` persistence machinery.** C.1 defines the CBOR format and provides encode/decode; the caller decides where to store the bytes (OS keystore per §10 recommendation).
- **`device_uuid` lifecycle.** Caller-supplied `[u8; 16]`, same convention as B.4c `save_block`. (Not actually consumed by C.1's detection function; included in the broader Sub-project C scope.)
- **Multi-vault orchestration.** C.1 handles one vault per call.

## Design decisions and the rationale chain

Four substantive decisions shape this design. Each follows from a stated user constraint and forecloses a class of alternatives.

### D1 — Sync UX mental model: foreground-while-unlocked

Sync runs only while the vault is unlocked in a Secretary process — a CLI session, a UI window, or an app in foreground. When the user locks or quits, sync stops. The `UnlockedIdentity` lives in process memory **only during the unlock window**.

Rationale: matches `ADR-0003`'s note that mobile is foreground-only anyway, and matches the threat-model intent of minimising secret residence to the user's actual session. Background sync via a long-running daemon is out: it would split the desktop and mobile behaviour models (mobile can't do it per ADR-0003) and dramatically extend the secret-residence-in-memory window.

Consequence: `sync_once` takes `&UnlockedIdentity` by reference, per call. C.1 never holds the identity across calls.

### D2 — Veto scope: peer-originated record tombstones only

When automatic merge ships (C.1.1), the only merge outcome that surfaces a user-veto prompt is a peer-originated record tombstone that would delete a locally-live record. Field-level LWW overwrites, block disappearances from the cloud folder, and all other merge outcomes apply silently per the existing §11 spec.

Rationale: protects against the most-regrettable silent loss (records the user is actively using disappearing) without training the user to click-through prompts.

Consequence on C.1 (this slice): none — vetoes are vacuous without merge. The decision is recorded so C.1.1's design starts from a settled answer.

### D3 — API shape: free functions, caller-persisted `SyncState`

C.1 exposes free `pub fn`s, not an engine struct. State is a serializable value the caller passes in by reference and persists between calls.

Rationale: matches the established `secretary-core` style (`fn create_vault`, `fn open_vault`, `fn save_block` are all free functions returning typed values) and the user's `feedback_pure_functions` preference. An engine struct would add ceremony for no testing or composition benefit. An event-driven FSM with input/output events would be over-engineered for ~hundreds of lines of actual work and would fight Rust's natural `Result<T, std::io::Error>` shape.

### D4 — Merge scope phasing: detect-only C.1, merge in C.1.1

C.1 ships rollback detection + fork detection only. The veto-on-tombstone feature and conflict-copy ingestion land in a separate C.1.1 PR.

Rationale: per `feedback_stay_in_inner_loop` — brick-by-brick is preferred. The detect-only first slice is ~500-800 LOC and validates the API shape before the merge complexity lands. The full-merge design has more moving parts (`VaultBundle` with conflict-copy variants, `PendingMerge` / `TombstoneDecisions` / `StagedMerge` / `commit_with_decisions`) and deserves its own brainstorm informed by what we learn shipping C.1.

## Module layout

```
core/src/sync/
├── mod.rs       # module doc + pub use re-exports
├── state.rs     # SyncState type + CBOR encode/decode
├── outcome.rs   # SyncOutcome, RollbackEvidence
├── error.rs     # SyncError enum
└── once.rs      # sync_once free function
```

Per `feedback_split_files_proactively`, each file is one concept. `once.rs` is the largest and will land near 200-400 lines, comfortably under the 500-LOC guideline. `state.rs` / `outcome.rs` / `error.rs` are small data-type files.

Tests, mirroring the established `core/tests/` pattern:

```
core/tests/sync.rs            # integration suite (happy + each error path)
core/tests/sync_proptest.rs   # convergence + idempotence properties
core/tests/data/sync_kat.json # vector file slot (Python clean-room replay in C.4)
```

## Public types

### `SyncState` (`state.rs`)

```rust
/// Per-vault sync orchestration state. Persisted by the caller between
/// `sync_once` calls — recommended storage is the OS keystore alongside
/// the vault entry, per `crypto-design.md` §10.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncState {
    pub vault_uuid: [u8; 16],
    pub highest_vector_clock_seen: Vec<VectorClockEntry>,
}

impl SyncState {
    /// Fresh state for a vault we've never synced on this device.
    /// First `sync_once` call will produce `AppliedAutomatically`
    /// for any non-empty disk state.
    pub fn empty(vault_uuid: [u8; 16]) -> Self;

    /// Canonical CBOR encoding (forward-compat via `unknown` opaque
    /// round-trip per the `Record`/`Manifest` pattern, when C.1.x
    /// adds fields).
    pub fn to_canonical_cbor(&self) -> Vec<u8>;
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SyncError>;
}
```

`VectorClockEntry` is re-exported from `core::vault::conflict`. Entries in `highest_vector_clock_seen` are sorted ascending by `device_uuid` (the §6.1 convention); the constructor and decoder canonicalise inputs and reject duplicates.

### `SyncOutcome` (`outcome.rs`)

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncOutcome {
    /// Disk has nothing new since the last sync. No state mutation.
    NothingToDo,

    /// Disk strictly dominates local highest_seen. The disk state is
    /// the new canonical truth. Caller persists `new_state` to OS
    /// keystore before next sync.
    AppliedAutomatically { new_state: SyncState },

    /// Disk and local highest_seen are concurrent (incomparable).
    /// The vault has forked across devices. Per threat-model §4
    /// limit 3 — detection is sufficient at this layer. C.1.1 will
    /// extend this branch with automatic merge + veto-on-tombstone.
    ForkDetected {
        disk_vector_clock: Vec<VectorClockEntry>,
        local_highest_seen: Vec<VectorClockEntry>,
    },

    /// Disk vector clock is strictly dominated by local highest_seen.
    /// Per `crypto-design.md` §10 — rollback rejected. Caller's UX
    /// may offer an "I am restoring from backup, accept anyway"
    /// override (deferred to C.1.1 or C.2 layer).
    RollbackRejected(RollbackEvidence),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackEvidence {
    pub disk_vector_clock: Vec<VectorClockEntry>,
    pub local_highest_seen: Vec<VectorClockEntry>,
}
```

### `SyncError` (`error.rs`)

```rust
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("vault_uuid in SyncState does not match vault.toml ({state_vault_uuid:?} vs {folder_vault_uuid:?})")]
    VaultUuidMismatch {
        state_vault_uuid: [u8; 16],
        folder_vault_uuid: [u8; 16],
    },

    #[error("SyncState CBOR decode failed: {detail}")]
    StateDecodeFailed { detail: String },

    #[error("SyncState CBOR encode failed: {detail}")]
    StateEncodeFailed { detail: String },

    #[error(transparent)]
    Vault(#[from] VaultError),

    #[error("I/O failure: {context}")]
    Io {
        context: &'static str,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid argument: {detail}")]
    InvalidArgument { detail: String },
}
```

**Anti-conflation discipline.** Every variant maps to one observable cause. `Vault(VaultError)` forwards an already-typed error from the layer below; the `VaultError` variants preserve the distinction at the umbrella surface.

## `sync_once` algorithm

```rust
pub fn sync_once(
    vault_folder: &Path,
    identity: &UnlockedIdentity,
    state: &SyncState,
    _now_ms: u64,  // unused in detect-only; forward-compat with C.1.1
) -> Result<SyncOutcome, SyncError>;
```

Steps:

1. **Read `vault.toml`** from `vault_folder` via `std::fs::read_to_string`. Decode via `core::unlock::vault_toml::decode(&s)`. Compare `decoded.vault_uuid` to `state.vault_uuid`; if different, return `VaultUuidMismatch`. (The parse is duplicated when step 2 calls `open_vault` — which parses `vault.toml` again internally. `vault.toml` is tiny (< 500 bytes) and the duplication makes the UUID-mismatch error path testable without triggering a full open / unlock attempt against a mismatched vault.)

2. **Open the vault** via `core::vault::orchestrators::open_vault(vault_folder, Unlocker::Bundle(identity), None)`. Note `local_highest_clock = None` — C.1 IS the bookkeeping layer that consumes `local_highest_clock`; passing it through `open_vault` would double-enforce. Any `VaultError` propagates as `SyncError::Vault(...)`.

3. **Extract `disk_clock`** from the opened manifest's `vector_clock`.

4. **Dispatch on `clock_relation(local: state.highest_vector_clock_seen, incoming: disk_clock)`** (from `core::vault::conflict`):

   | `clock_relation` result | `SyncOutcome` |
   |---|---|
   | `Equal` | `NothingToDo` |
   | `IncomingDominates` (disk strictly newer) | `AppliedAutomatically { new_state: SyncState { vault_uuid: state.vault_uuid, highest_vector_clock_seen: disk_clock } }` |
   | `IncomingDominated` (disk strictly older — rollback) | `RollbackRejected(RollbackEvidence { ... })` |
   | `Concurrent` | `ForkDetected { disk_vector_clock: disk_clock, local_highest_seen: state.highest_vector_clock_seen.clone() }` |

The four branches are disjoint and exhaustive per `ClockRelation`'s definition. No panic paths.

### Subtlety: the `Unlocker::Bundle` extension

`open_vault` currently takes `Unlocker<'a>` with `Password` and `Recovery` variants — both perform the unlock step. C.1 already has an `UnlockedIdentity` (caller-supplied per D1) and must not re-unlock. We extend `core::vault::orchestrators` with one additional variant:

```rust
pub enum Unlocker<'a> {
    Password(&'a Password),
    Recovery(&'a [&'a str]),
    Bundle(&'a UnlockedIdentity),   // NEW in C.1
}
```

`open_vault`'s match on `Unlocker` gains a third arm that short-circuits the Argon2 + bundle-decrypt step and uses the existing `UnlockedIdentity` directly. The arm is small (under 20 lines) and additive. Existing call sites are unaffected.

Alternative considered: have `sync_once` reach for lower-level primitives (`read_vault_toml`, `decrypt_manifest_body`, `verify_owner_card_self`, etc.) and assemble its own open path. Rejected — duplicates the contact-card-verify, vault-toml-cross-check, and TOCTOU-closing work that `open_vault` does, and C.1 should inherit those defenses for free.

### What `sync_once` deliberately does NOT do

- Does not write anything to disk.
- Does not merge concurrent states.
- Does not handle conflict-copy files.
- Does not perform "restoring from backup" override.
- Does not enforce per-block rollback (already enforced by the manifest's per-block fingerprint signature, verified inside `open_vault`).
- Does not consume `_now_ms` (parameter present for forward-compat with C.1.1's merge timestamps).

## State persistence model

C.1 doesn't touch the keystore. `SyncState::to_canonical_cbor()` / `::from_canonical_cbor()` are the surface; the caller stores the bytes wherever it puts other per-vault state. The recommendation in `crypto-design.md` §10 is the **OS keystore alongside the vault entry** (so it shares the device's tamper-resistance and survives app restarts). C.2 will codify a keystore key naming convention.

**Initial state.** When no persisted state exists for a vault (fresh install, vault first opened on this device, keystore entry destroyed), the caller constructs `SyncState::empty(vault_uuid)`. Under the C.1 algorithm:

- `state.highest_vector_clock_seen` is empty (the lattice bottom).
- `clock_relation(empty, disk_clock)` returns `IncomingDominates` for any non-empty `disk_clock`; `Equal` only if `disk_clock` is also empty.
- → `SyncOutcome::AppliedAutomatically { new_state: SyncState { vault_uuid, highest_vector_clock_seen: disk_clock } }` (or `NothingToDo` for a brand-new empty vault).

This matches `crypto-design.md` §10 verbatim: "Destroying it (e.g., re-installing Secretary on the same device) returns the device to a 'no history' state — the next manifest is accepted regardless of its clock, and rollback resistance is reset on that device."

**CBOR format (frozen for v1).** Two-field map, canonical CBOR (via the existing `core::vault::canonical` helpers). Forward-compat via the `unknown` opaque round-trip pattern used by `Record` / `Manifest` — C.1.0 readers ignore unknown keys; C.1.1+ readers consume them.

```cbor
{
  "vault_uuid": h'<16 bytes>',
  "highest_vector_clock_seen": [
    { "device_uuid": h'<16 bytes>', "counter": 5 },
    ...  // sorted ascending by device_uuid per §6.1
  ]
}
```

**Size budget.** A `VectorClockEntry` is 16 + 8 = 24 bytes. A user with 5 devices that have ever written to the vault → 5 entries → ~120 bytes plus CBOR framing. Fits comfortably in any OS keystore entry.

## Testing strategy

**Unit tests** (inline in `core/src/sync/*.rs`):

- `state.rs` — CBOR round-trip identity; rejection of malformed state bytes; rejection of duplicate `device_uuid` in `highest_vector_clock_seen`; rejection of unsorted entries (input canonicalisation invariant).
- `outcome.rs` — `Eq`/`Debug` derives, no real logic.
- `error.rs` — `Display` strings stable per variant.
- `once.rs` — algorithm-pure tests via a `#[doc(hidden)] pub` helper that bypasses `open_vault` and exercises the clock-relation dispatch in isolation (per the [`project_secretary_cfg_test_not_propagated`](memory) pattern — `#[cfg(test)]` items on the lib are invisible to integration tests).

**Integration tests** (`core/tests/sync.rs`):

| Test | Asserts |
|---|---|
| `sync_once_empty_state_accepts_disk` | First run on fresh keystore → `AppliedAutomatically` with disk clock |
| `sync_once_unchanged_disk_nothing_to_do` | Second run on same disk + same state → `NothingToDo` |
| `sync_once_strictly_dominated_disk_rollback_rejected` | Disk clock behind state → `RollbackRejected` with both clocks in evidence |
| `sync_once_concurrent_clocks_fork_detected` | Disk and state are incomparable → `ForkDetected` with both clocks |
| `sync_once_disk_strictly_ahead_applied_automatically` | Disk has new edits → `AppliedAutomatically` with new state |
| `sync_once_wrong_vault_uuid_typed_error` | State belongs to a different vault → `VaultUuidMismatch` |
| `sync_once_corrupted_manifest_propagates_vault_error` | `open_vault` returns `Err` → `Vault(...)` |
| `sync_once_missing_vault_toml_propagates_io_error` | File missing → `Io { context: "..." }` |
| `sync_once_with_unlocker_bundle_skips_re_unlock` | New `Unlocker::Bundle` variant works without re-running Argon2 |

Fixtures: re-use `golden_vault_001/` for happy paths; synthesise per-test vector-clock variations by reading the golden vault's manifest and ticking components in-memory before writing to a per-test temp dir.

**Property tests** (`core/tests/sync_proptest.rs`):

- `prop_sync_once_idempotent_no_disk_change` — calling `sync_once` twice with the same inputs returns the same `SyncOutcome`.
- `prop_sync_once_applied_then_nothing_to_do` — after `AppliedAutomatically`, persisting `new_state` and calling again returns `NothingToDo`.
- `prop_sync_once_branch_disjoint` — for any combination of `state.highest_vector_clock_seen` and synthetic `disk_clock`, exactly one of `{NothingToDo, AppliedAutomatically, ForkDetected, RollbackRejected}` is returned (no panics, no overlap).

**Cross-language conformance (deferred).** `core/tests/data/sync_kat.json` is created with vectors and a Rust-side `replay_sync_kat` test. The Python clean-room implementation lands in C.4 — the same staging pattern used for the FFI conformance KAT in B.6.

**Test counts target.** ~9 integration tests + ~3 proptest properties + ~15-20 inline unit tests + 1 KAT replay. Workspace cargo total grows from 642 → ~670 ± a few.

## Workspace impact

- **New module:** `core/src/sync/` (5 files).
- **Extended type:** `core::vault::orchestrators::Unlocker` gains one variant.
- **New tests:** `core/tests/sync.rs`, `core/tests/sync_proptest.rs`, `core/tests/data/sync_kat.json`.
- **No FFI changes.** Bridge / PyO3 / uniffi crates untouched.
- **No spec doc changes.** `crypto-design.md` §10 already specifies the algorithm; C.1 implements it. The C.1.1 design will revisit §11 for the merge-with-veto layer.
- **ROADMAP update:** one sentence under "Sub-project C", marking C.1 phase 1 as in-flight.
- **No CLAUDE.md changes.**

## Open items for the implementation plan

- Decide whether `SyncState`'s sorted-by-`device_uuid` invariant is enforced in the constructor (`fn new(...)`) or only in the CBOR decoder. Recommendation: enforce in both, plus a `debug_assert!` on every read path.
- Decide whether the `Unlocker::Bundle` extension lives in the same PR as C.1 or in a small pre-PR. Recommendation: same PR — the extension is small and only `sync_once` consumes it; isolating it would create dead code in the interim.
- Decide whether `core/tests/data/sync_kat.json` is populated in C.1 (with Rust-only replay) or empty-allocated until C.4. Recommendation: populated, Rust-only replay; the file shape settles now and the Python clean-room implementation in C.4 has a target to match.

---

## Cross-references

- `crypto-design.md` §10 — manifest signing and rollback resistance (the algorithm this design implements).
- `crypto-design.md` §11 — per-record CRDT merge (consumed by C.1.1, not by C.1).
- `threat-model.md` §3.1 — cloud-folder host adversary; the per-manifest rollback row.
- `threat-model.md` §4 limit 3 — "detection is sufficient" for the equivocation case; the design basis for `ForkDetected` as a terminal outcome in C.1.
- `docs/adr/0003-cloud-folder-sync.md` — the no-server, file-by-file sync model.
- `docs/adr/0004-block-as-unit.md` — block-as-unit-of-sharing decision (informs C.1.1's merge granularity but not C.1's detection).
- ROADMAP §150-168 — C.1-C.4 phase plan.
- B.4c [`docs/superpowers/specs/2026-05-09-ffi-b4c-save-block-design.md`] — `device_uuid` caller-supplied convention.
- B.6 v1 [`docs/superpowers/specs/2026-05-15-ffi-b6-conformance-kat-design.md`] — cross-language conformance KAT pattern that C.4 will follow for sync.
