# C.1.1a — Sync orchestration: conflict-copy ingestion

**Date:** 2026-05-18
**Phase:** Sub-project C, phase C.1.1a (second slice — conflict-copy ingestion + `VaultBundle`)
**Status:** Design approved (1a-D1 / 1a-D2 / 1a-D3 settled in conversation 2026-05-18); ready for implementation plan
**Predecessor:** [`docs/superpowers/specs/2026-05-17-c1-sync-detection-design.md`](2026-05-17-c1-sync-detection-design.md) — C.1 phase 1 detection layer
**Successor:** [`docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md`](2026-05-18-c1-1b-sync-merge-design.md) — the merge + veto + commit layer that consumes the `VaultBundle` this design produces

---

## Context

C.1 phase 1 (PR #74) shipped detection-only sync orchestration: `sync_once` classifies disk state into `NothingToDo` / `AppliedAutomatically` / `ForkDetected` / `RollbackRejected`. The `ForkDetected` branch is terminal in phase 1.

The original C.1.1 brainstorm settled the merge + commit layer (now C.1.1b), then surfaced during spec self-review that **the merge layer needs a second source**. `merge_block(local, local_clock, remote, remote_clock, …)` and `merge_record(local, remote)` both take two-side inputs, and Secretary's cloud-folder sync model (per [ADR-0003](../../adr/0003-cloud-folder-sync.md)) provides the "remote" side through conflict-copy files that the host cloud-sync product (Dropbox / iCloud / OneDrive / Syncthing / …) creates when concurrent writes happen.

No current code path ingests these conflict-copies. The C.1 phase 1 spec at lines 18, 76, and 78 explicitly scoped this work to C.1.1.

C.1.1a delivers exactly this ingestion layer. It is **prerequisite** for C.1.1b — the merge layer cannot operate without the `VaultBundle` this slice produces.

## Goals

C.1.1a delivers four things:

1. **`VaultBundle` type** — bundles the canonical on-disk manifest + records with N ≥ 0 authenticated conflict-copies of the manifest, plus authenticated conflict-copies of any blocks whose state diverges between manifests. Zeroize-typed.
2. **Sibling-file scanner** — scans the vault folder for files matching `*.cbor.enc`, decodes each as a manifest or block file, authenticates against the canonical, silently ignores anything that fails authentication.
3. **Modified `SyncOutcome::ConcurrentDetected`** — gains a `bundle: VaultBundle` field carrying the ingestion product. The `DiffPlan` is computed inside `sync_once` from the ingested manifests' per-block `vector_clock_summary` divergence.
4. **`SyncError` extensions** — new typed variants for the failure modes specific to ingestion (`ConflictCopyAuthenticationFailed`, etc., though most authentication failures are silent per 1a-D3).

## Non-goals

The following land in **C.1.1b**, not 1a:

- **No merge logic.** `merge_record` and `merge_block` are not called by 1a. The bundle is data; merging is 1b.
- **No `prepare_merge` / `commit_with_decisions`.** Those operate on the bundle but live in 1b.
- **No `VetoDecision` / `RecordTombstoneVeto` types.** Veto computation is 1b.
- **No `verify_block_fingerprints` in `open_vault`.** That's a 1b deliverable (the partial-commit detection landing alongside the multi-block write path).

Other ongoing non-goals (carried from C.1 phase 1):

- **No FFI surface change.** Core-only; B-side projection follows in C.3.
- **No Python clean-room of any new KAT vectors.** Scoped into issue [#76](https://github.com/hherb/secretary/issues/76) (C.4).
- **No background sync / daemonisation.** Foreground-only mental model frozen in C.1 phase 1.
- **No new fuzz targets.** The new types are not deserialised from untrusted bytes in a way the existing six fuzz targets don't already cover (manifest_file and block_file fuzz harnesses already exercise the parse path against arbitrary bytes).

## Design decisions and the rationale chain

Three substantive decisions, plus one structural rule that isn't a decision.

### 1a-D1 — Conflict-copy scanning runs inside `sync_once`, lazily

`sync_once` first reads the canonical manifest. **Only** when `clock_relation` returns `Concurrent` does it then scan for sibling conflict-copies. The bundle is returned inside `SyncOutcome::ConcurrentDetected { bundle, plan, manifest_hash, … }`. Quiet vaults pay zero extra I/O.

Rationale: preserves C.1.1b's D4-lazy property (no extra reads on the non-merging path) and keeps the caller's API free of conflict-copy mechanics. The caller's mental model stays simple: "call `sync_once`, look at the outcome."

Consequence: `sync_once` body grows from ~100 LOC to ~200 LOC, but the new code is single-arm and tightly scoped to the Concurrent branch.

### 1a-D2 — N-way conflict-copies are supported via iterative pairwise merge

`VaultBundle.copies` is `Vec<ManifestSnapshot>` — zero or more. C.1.1b's merge will iteratively merge the canonical with each copy in turn:

```
acc = canonical
for c in copies:
    acc = merge_pair(acc, c)   // associative CRDT closure → order-independent
return DraftMerge::from(acc)
```

Rationale: CRDT closure (`merge_record` proptest associativity already passes for arbitrary record domains) guarantees that pairwise merges of N replicas produce the same final state regardless of order. Rejecting 3+ as a typed error would force manual cleanup in the multi-device hot-zone case (family-shared vault with 4 phones, all editing) without any underlying mathematical reason — the CRDT supports N-way natively.

Veto accumulation: each pairwise step contributes its own `RecordTombstoneVeto` set. C.1.1b's `prepare_merge` collects the union, deduping by `record_id`. (Detail lives in the 1b spec; 1a only commits to "bundle carries N copies, order doesn't matter".)

### 1a-D3 — File matching: heuristic decode-then-authenticate, not strict patterns

The scanner enumerates `*.cbor.enc` files in the vault folder (and `blocks/*.cbor.enc` once it's looking at block siblings). For each candidate, it attempts decode + authenticate. If both succeed, the file is accepted as a conflict-copy. If either fails, the file is **silently ignored**.

Authentication is the security boundary, not the filename. New cloud-sync products / version-bumped naming conventions cannot break us; junk files in the vault folder cannot fool us. Authentication is non-negotiable (1a-D4 below).

Rationale: per `feedback_security_no_assumptions.md`, security paths should pick enforcement over plausibility. A pattern-registry approach is a plausibility argument ("our list covers the clouds we know about today"); decode-then-authenticate is enforcement ("only files that prove they came from the same vault's owner are accepted").

Cost: O(N_siblings × per-file-decode-time). Vault folders are small (typically < 1000 files); decode is ~µs per file; this is well below disk-read latency on the same files. Not a hot path.

### 1a-D4 — Authentication rules (structural, not a decision)

Every candidate conflict-copy MUST pass ALL of the following to be accepted into the bundle. Failure of any rule causes silent rejection (logged at `tracing::debug!` for diagnostics, not surfaced as a user-visible error — junk files in cloud-sync folders are routine).

| Rule | What's checked |
|---|---|
| **Decodes as a `ManifestFile` (or `BlockFile`)** | Canonical CBOR + magic + length sanity per the existing format primitives. |
| **Hybrid signature verifies** | Ed25519 ∧ ML-DSA-65 (both halves), using the canonical's `owner_card`'s keys. Reuses the existing `manifest::verify_signature` machinery. |
| **`vault_uuid` matches canonical** | Authenticated via the same hybrid signature. Wrong vault → ignore. |
| **`author_fingerprint` matches canonical** | Same owner contact card on both sides. A peer's manifest in this folder is not a conflict-copy (it'd be a separate vault or a sharing-flow file). |
| **AEAD-decrypts with the unlocked Identity Block Key** | Proves both the conflict-copy was written by an identity that knew the IBK and that the bytes haven't been tampered post-write. |

All five are MUSTs because each plugs a distinct attack class:
- (decode) — malformed bytes can't pivot into authenticated state.
- (signature) — only the owner can produce a valid manifest envelope.
- (vault_uuid) — a misplaced file from a different vault is rejected even if its owner is the same person.
- (author_fingerprint) — a peer's manifest (sharing flow leftover) doesn't masquerade as a conflict-copy of this vault.
- (AEAD) — tamper detection on the inner body.

The "silent ignore" disposition is **only safe because all five MUSTs hold**. Weakening any of them would open a CRDT-merge-poisoning path where an attacker (cloud-folder host) feeds a forged "remote side" to make the merge produce attacker-chosen output.

## Public API

### `VaultBundle` (new — `core/src/sync/bundle.rs`)

```rust
/// Authenticated bundle of the canonical vault manifest plus zero or
/// more conflict-copies (sibling manifest files created by the
/// host cloud-sync product when concurrent writes happen), plus
/// authenticated conflict-copies of any blocks whose state diverges
/// between manifests.
///
/// Produced by `sync_once` only on the Concurrent path. Holds
/// decrypted manifest bodies AND encrypted block-file envelopes —
/// block plaintext is NOT decrypted until C.1.1b's `prepare_merge`
/// is invoked (preserves the secrets-stay-sealed-until-needed
/// property of C.1.1b's D4-lazy strategy).
///
/// Zeroize + ZeroizeOnDrop coverage:
///   - `ManifestSnapshot::manifest` (decrypted body) wraps any
///     potentially-identifying fields per the existing Manifest
///     zeroize discipline.
///   - `BlockEnvelope::bytes` is encrypted ciphertext — no zeroize
///     needed at this layer; C.1.1b's read_block decrypts to a
///     sealed-typed BlockPlaintext.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct VaultBundle {
    pub canonical: ManifestSnapshot,
    pub copies: Vec<ManifestSnapshot>,            // N ≥ 0; sibling manifest conflict-copies
    pub diverging_blocks: BTreeMap<[u8; 16], BlockDivergence>, // keyed by block_uuid
}

/// One side of a manifest — canonical or a single conflict-copy.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct ManifestSnapshot {
    pub manifest: Manifest,            // decrypted + authenticated body
    pub raw_envelope_bytes: Vec<u8>,   // for ManifestHash freshness anchor (C.1.1b)
    #[zeroize(skip)]
    pub source_path: PathBuf,          // diagnostics only; not a secret
}

/// Conflict-copies of one block, scoped to blocks where the
/// canonical-vs-copies manifests carry different per-block
/// `vector_clock_summary` values. Other blocks are not in this map.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct BlockDivergence {
    pub canonical_envelope: BlockEnvelope,
    pub copy_envelopes: Vec<BlockEnvelope>,   // N ≥ 0 conflict-copy versions of this block
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct BlockEnvelope {
    pub bytes: Vec<u8>,                // raw encrypted block file bytes (BlockFile envelope)
    #[zeroize(skip)]
    pub source_path: PathBuf,
}
```

### `SyncOutcome` modification (`core/src/sync/outcome.rs`)

`ForkDetected` is removed (per the merge-replaces-detect promise in C.1 phase 1 §non-goals). `ConcurrentDetected` becomes:

```rust
pub enum SyncOutcome {
    NothingToDo,
    AppliedAutomatically { new_state: SyncState },
    ConcurrentDetected {
        bundle: VaultBundle,                              // NEW from 1a
        plan: DiffPlan,                                   // shape from 1b spec; computed in 1a
        manifest_hash: ManifestHash,                      // BLAKE3-256 of canonical envelope; freshness anchor for 1b
        disk_vector_clock: Vec<VectorClockEntry>,         // canonical's clock — for diagnostics
        local_highest_seen: Vec<VectorClockEntry>,        // for diagnostics
    },
    RollbackRejected(RollbackEvidence),
}
```

`DiffPlan` (defined in 1b's spec; 1a computes it):

```rust
pub struct DiffPlan {
    pub diverging_blocks: Vec<[u8; 16]>,   // block_uuids where canonical + at least one copy disagree
}
```

`ManifestHash`:

```rust
pub struct ManifestHash(pub [u8; 32]);   // BLAKE3-256 of canonical envelope bytes
```

### `sync_once` (extended — `core/src/sync/once.rs`)

Signature unchanged. Algorithm changes on the `Concurrent` arm only:

```
sync_once(folder, identity, state, _now_ms):
    1. canonical = read_vault_manifest(folder, identity, None)
       (existing C.1 phase 1 path)

    2. if state.vault_uuid != canonical.vault_uuid:
           return VaultUuidMismatch

    3. manifest_hash = BLAKE3-256(canonical_envelope_bytes)

    4. match clock_relation(state.highest_vector_clock_seen, canonical.vector_clock):
           Equal             → return NothingToDo
           IncomingDominates → return AppliedAutomatically { ... }
           IncomingDominated → return RollbackRejected(...)
           Concurrent        → fall through to 5

    5. bundle = ingest_conflict_copies(folder, identity, canonical, canonical_envelope_bytes)
       // Authenticated scan per 1a-D3 / 1a-D4. Returns canonical + 0..N copies + per-block divergence.

    6. plan = compute_diff_plan(&bundle)
       // For each block_uuid present in canonical.blocks:
       //   look at every copy's BlockEntry for that uuid
       //   if any copy has a vector_clock_summary that is NOT dominated by canonical's
       //     OR is concurrent with canonical's
       //     → add block_uuid to plan.diverging_blocks
       // Sorted ascending.

    7. return ConcurrentDetected {
           bundle, plan, manifest_hash,
           disk_vector_clock: canonical.vector_clock.clone(),
           local_highest_seen: state.highest_vector_clock_seen.clone(),
       }
```

### `ingest_conflict_copies` (new — `core/src/sync/ingest.rs`)

```rust
pub(crate) fn ingest_conflict_copies(
    folder: &Path,
    identity: &UnlockedIdentity,
    canonical: &Manifest,                  // already-verified canonical body
    canonical_envelope_bytes: &[u8],       // for source-path filter
) -> Result<VaultBundle, SyncError>;
```

Algorithm:

1. **Manifest copies pass.** `std::fs::read_dir(folder)` for entries matching `*.cbor.enc`. For each non-canonical (path ≠ `folder/manifest.cbor.enc`):
   - Read bytes; if empty or > MAX_MANIFEST_SIZE, skip.
   - Attempt `manifest::decode_manifest_file(&bytes)`. On `Err`, skip.
   - Authenticate per 1a-D4. On any failure, skip (`tracing::debug!`).
   - Push to `copies`.
2. **Block divergence detection.** For each `block_uuid` present in canonical's `blocks`, look at every copy. If any copy's `BlockEntry.vector_clock_summary` differs from canonical's per `clock_relation` (returns anything other than `Equal` or `IncomingDominated`), this block needs ingestion.
3. **Block copies pass.** For each diverging `block_uuid`:
   - Read canonical block at `folder/blocks/<uuid>.cbor.enc`. Store `BlockEnvelope`.
   - Enumerate `folder/blocks/` for `<uuid>*.cbor.enc` siblings (any prefix-match other than the canonical name).
   - For each candidate, attempt `block::decode_block_file(&bytes)`. On `Err`, skip.
   - Authenticate: `author_fingerprint` matches canonical owner, hybrid signature verifies. (Block-file AEAD decryption is deferred to 1b.)
   - Push `BlockEnvelope` to `BlockDivergence.copy_envelopes`.
4. Assemble + return `VaultBundle`.

### `SyncError` extensions

```rust
#[error("conflict-copy scan failed: failed to enumerate folder: {source}")]
ConflictCopyScanIoFailed {
    #[source]
    source: std::io::Error,
},

#[error("internal invariant: canonical manifest envelope failed BLAKE3 hash")]
CanonicalHashInternal,   // defensive — should be unreachable
```

(Most authentication failures are silent per 1a-D3 / 1a-D4. The above are for genuine I/O failures during the scan, not file-content-level rejections.)

## Module file layout

```
core/src/sync/
├── mod.rs            existing — extend pub-use re-exports
├── state.rs          existing ~unchanged
├── outcome.rs        modified — ConcurrentDetected gains bundle field; ForkDetected removed
├── error.rs          existing + 2 new variants
├── once.rs           existing 100 → ~200 LOC (new Concurrent-arm body)
├── bundle.rs         NEW ~200 LOC — VaultBundle + ManifestSnapshot + BlockDivergence + BlockEnvelope + zeroize coverage
└── ingest.rs         NEW ~300 LOC — ingest_conflict_copies + compute_diff_plan + authenticate helpers
```

All under the 500-LOC threshold per `feedback_split_files_proactively.md`. Each file = one concept.

Outside `core/src/sync/`: no changes. The existing `core::vault::manifest::decode_manifest_file` / `core::vault::block::decode_block_file` / hybrid-signature verification helpers are all reusable as-is.

## Testing strategy

### Integration tests — `core/tests/sync_ingest.rs` (new)

| Test | Asserts |
|---|---|
| `sync_once_concurrent_no_conflict_copies_returns_bundle_zero_copies` | Canonical-only state with concurrent clock → `bundle.copies.is_empty()`, plan computed from canonical alone (vacuous) |
| `sync_once_concurrent_one_conflict_copy_authenticated` | One sibling manifest present, fully authenticatable → `bundle.copies.len() == 1` |
| `sync_once_concurrent_three_conflict_copies_authenticated` | Three siblings, all valid → `bundle.copies.len() == 3` (N-way support) |
| `sync_once_concurrent_invalid_signature_silently_ignored` | Sibling with corrupted hybrid signature → `bundle.copies.is_empty()` |
| `sync_once_concurrent_wrong_vault_uuid_silently_ignored` | Sibling for different vault dropped accidentally → `bundle.copies.is_empty()` |
| `sync_once_concurrent_wrong_owner_fingerprint_silently_ignored` | Sibling from peer (sharing flow leftover) → `bundle.copies.is_empty()` |
| `sync_once_concurrent_aead_tampered_body_silently_ignored` | Sibling with valid sig but tampered ciphertext → `bundle.copies.is_empty()` |
| `sync_once_concurrent_block_divergence_block_copies_ingested` | Canonical + copy disagree on block X → `bundle.diverging_blocks[X].copy_envelopes.len() >= 1` |
| `sync_once_concurrent_block_agreement_block_copies_skipped` | Canonical + copy agree on block X (only metadata-level concurrent) → block X NOT in `diverging_blocks` |
| `sync_once_concurrent_diff_plan_includes_only_diverging_blocks` | Mixed: blocks X,Y diverge; block Z agrees → `plan.diverging_blocks == [X, Y]` |
| `sync_once_no_concurrent_no_scan_performed` | Disk strictly ahead → AppliedAutomatically without any sibling scan I/O (asserted via tempdir read counter or trace) |
| `sync_once_concurrent_dropbox_naming_convention_accepted` | Sibling named `manifest (conflicted copy 2026-05-15).cbor.enc` → accepted on authentication |
| `sync_once_concurrent_syncthing_naming_convention_accepted` | Sibling named `manifest.sync-conflict-20260515-100000-ABCD1234.cbor.enc` → accepted on authentication |
| `sync_once_concurrent_random_filename_accepted_on_authentication` | Sibling named `random_garbage.cbor.enc` → accepted iff it authenticates (proves heuristic) |
| `sync_once_concurrent_concurrent_after_ingest_returns_concurrent_detected_variant` | End-to-end shape check on the new variant |

### Property tests — `core/tests/sync_ingest_proptest.rs` (new)

- `prop_ingest_idempotent` — calling `ingest_conflict_copies` twice with same folder state returns equal `VaultBundle`s.
- `prop_ingest_silently_rejects_junk` — for any arbitrary bytes written to a `*.cbor.enc` file in the vault folder, ingestion never panics and never falsely accepts.
- `prop_n_way_order_independence` — for any permutation of K conflict-copy filenames produced by the same source-set of `Manifest` values, the resulting `bundle.copies` represents the same set (order may differ, but set equality holds).

### Unit tests (inline in each new file)

- `bundle.rs` — Zeroize-on-drop coverage (using existing `assert_zeroized` pattern), Eq/Debug derives stable, ManifestSnapshot round-trip.
- `ingest.rs` — `authenticate_manifest_copy(candidate, canonical, identity) -> bool` table-driven; `enumerate_sibling_paths(folder, canonical_path) -> Vec<PathBuf>` deterministic ordering test.

### KAT vectors — `core/tests/data/sync_kat.json` (9 → 12)

Three new vectors to fix the cross-language ingestion semantics:

| New vector | Covers |
|---|---|
| `concurrent_zero_copies_bundle_empty` | Concurrent clock detected but no sibling files present → bundle.copies empty |
| `concurrent_one_copy_authenticates` | One sibling with valid hybrid signature → accepted |
| `concurrent_one_copy_wrong_vault_uuid_rejected` | One sibling decoded but rejected → silently absent from bundle |

(The other authentication-rejection scenarios are exercised in integration tests but don't need cross-language KATs — the rule is structural, not subtle.)

### Test growth target

~15 integration + ~3 proptest + ~15 inline unit + 3 KAT vectors. Workspace cargo total grows from **681 → ~715 ± a few**.

## Workspace impact

| Component | Change |
|---|---|
| `core/src/sync/outcome.rs` | `ForkDetected` removed; `ConcurrentDetected` extended with `bundle` field |
| `core/src/sync/error.rs` | +2 variants (`ConflictCopyScanIoFailed`, `CanonicalHashInternal`) |
| `core/src/sync/once.rs` | New Concurrent-arm body (~50 LOC added) |
| `core/src/sync/bundle.rs` | NEW |
| `core/src/sync/ingest.rs` | NEW |
| `core/src/sync/mod.rs` | Extended re-exports |
| `core/tests/sync_ingest.rs` | NEW (integration) |
| `core/tests/sync_ingest_proptest.rs` | NEW (properties) |
| `core/tests/sync.rs` | Existing fork-detected tests renamed; minor shape updates |
| `core/tests/sync_kat.rs` | Replay logic extended for ConcurrentDetected with bundle |
| `core/tests/data/sync_kat.json` | 9 → 12 vectors |
| `docs/crypto-design.md` | No changes (the spec doesn't currently address conflict-copy ingestion; that's a documentation gap to fix in a follow-up but doesn't gate this PR) |
| `docs/vault-format.md` | No changes (on-disk format unchanged) |
| `docs/superpowers/specs/2026-05-18-c1-1a-conflict-copy-ingestion-design.md` | THIS DOCUMENT |
| `docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md` | EXISTS (the merge layer that consumes this slice's bundle) |
| FFI crates | Unchanged |
| `core/fuzz/` | Unchanged |
| `core/tests/python/conformance.py` | Unchanged (sync layer is C.4 scope) |
| ROADMAP.md | C.1.1a → in-flight, then ✅ on merge |
| README.md | Status table updated when C.1.1a ships |

## Open items for the implementation plan

These settle in the plan, not the design:

1. Whether `compute_diff_plan` lives in `ingest.rs` or `once.rs`. **Lean: `ingest.rs`** — it operates on the assembled `VaultBundle`, so it's downstream of ingestion logically.
2. Whether `BlockEnvelope.bytes` is `Vec<u8>` or `Box<[u8]>` for memory layout. **Lean: `Vec<u8>`** — simplest; the bytes are encrypted and not on a hot path.
3. The `MAX_MANIFEST_SIZE` constant for the scan-loop early reject. **Lean: 1 MiB** — current manifests fit in a few KB; 1 MiB is generous slack with a reasonable DoS bound.
4. Whether the `tracing::debug!` logs of silent rejections include the candidate's path. **Lean: yes** — diagnostics value during user support outweighs the very-weak path-leak concern (path is already user-visible in their cloud folder).
5. Test fixtures for the multi-cloud naming-convention tests. **Lean: hand-construct authenticated manifest envelopes with arbitrary filenames** rather than depending on actual cloud-product behaviour.

## Risks

- **Test fixture complexity.** Constructing a valid second-side manifest envelope (signed by the same owner, with a different vector clock) requires reusing the existing `manifest::sign_manifest` helper with controlled inputs. The C.1 phase 1 test helpers (`fresh_vault_with_clock` in `core/tests/sync_helpers/mod.rs`) need extension to support "write a second manifest envelope as a sibling under a custom filename, signed with the same owner identity". Carried risk from C.1.1 baton.
- **AEAD nonce sharing in test helpers.** Per CLAUDE.md atomic-write section, never share key+nonce across rewrites. The fixture extension above must call `getrandom` for each rewritten manifest. Identical risk language to the C.1.1b design.
- **`tracing` dependency.** Silent-reject diagnostics rely on `tracing::debug!`. If `tracing` isn't already a `core` dep, the implementation plan must decide whether to add it (small, ubiquitous, low risk) or use `eprintln!` (works but loses structure).
- **Cloud-folder host adversary** (threat-model §3.1) can write arbitrary `*.cbor.enc` files into the vault folder. 1a-D4's MUST-rules handle this — every candidate must prove ownership + AEAD-integrity before acceptance. The "silently ignore" disposition is **only safe** because all five MUSTs hold; do not weaken any of them.

## Cross-references

- [C.1 phase 1 design](2026-05-17-c1-sync-detection-design.md) — the predecessor; D1 (foreground sync), D2 (veto scope), D3 (free-function API), D4 (detect-then-merge phasing) all remain in force.
- [C.1.1b design](2026-05-18-c1-1b-sync-merge-design.md) — the successor that consumes `VaultBundle`. Reciprocal cross-reference.
- [`docs/adr/0003-cloud-folder-sync.md`](../../adr/0003-cloud-folder-sync.md) — sync model rationale; the "Dropbox file-conflict copies, iCloud silent dedup, Google Drive byte-range race" sentence is the motivation for 1a's existence.
- [`docs/threat-model.md`](../../threat-model.md) §3.1 — cloud-folder host adversary; the threat that 1a-D4 defends against.
- [`docs/crypto-design.md`](../../crypto-design.md) §8 — hybrid signature scheme reused by `authenticate_manifest_copy`.
- [`docs/crypto-design.md`](../../crypto-design.md) §11 — per-record CRDT merge; the future consumer of the bundle 1a produces.
- [`docs/manual/contributors/memory-hygiene-audit-internal.md`](../../manual/contributors/memory-hygiene-audit-internal.md) — wrapper discipline + drop ordering; mandatory reading before implementing `VaultBundle`'s zeroize coverage.

---

**Approved decisions:** 1a-D1 (sync_once-internal lazy scan), 1a-D2 (N-way iterative pairwise), 1a-D3 (heuristic decode-then-authenticate), 1a-D4 (five-rule authentication MUST set).
