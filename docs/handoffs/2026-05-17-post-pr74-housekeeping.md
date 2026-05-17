# NEXT_SESSION.md

**Session date:** 2026-05-17 (post-merge housekeeping after PR #74 — C.1 phase 1 landed on main)
**Status:** `main` at `381c34d` carries the full C.1 phase 1 work (sync detection). Gauntlet green. No new code this session — this was a transition session that cleaned up post-merge state and prepared for C.1.1 brainstorming. **No commits to push yet** beyond what this baton itself adds.

## (1) What we shipped this session

This was a **housekeeping-only session** — no Rust, no docs/spec changes, no test additions. The motivation: yesterday's [PR #74](https://github.com/hherb/secretary/pull/74) landed C.1 phase 1 with a squash merge, leaving four stale local branches and a defunct worktree. Cleaning these up before C.1.1 starts avoids the parallel-session collision risk called out in [CLAUDE.md](CLAUDE.md#working-directory-discipline).

### Cleanup performed

| Action | Detail |
|---|---|
| Removed worktree | `.worktrees/c1-sync-detection` (was at `d25e68b`; branch squash-merged via #74) |
| Deleted local branch | `feature/c1-sync-detection` (was `d25e68b`; squash-merged via #74) |
| Deleted local branch | `chore/b6-pre-v2-cleanup` (was `9161f84`; squash-merged via #64 on 2026-05-16) |
| Deleted local branch | `pr-65-review` (was `8abf584`; content squash-merged via #65 on 2026-05-16) |
| Deleted local branch | `test/issue-35-save-block-mid-call-wipe-race` (was `c6fda32`; squash-merged via #65) |
| Pruned remote ref | `origin/feature/c1-sync-detection` (GitHub had already auto-deleted on merge) |

All four branches were verified merged via `gh pr list --state merged` — their head-ref names appear there. The `git branch --merged main` check returns only `main` itself because squash-merges leave the originating SHAs unreachable from main, but the *content* is in main. The deletions used `-D` (force) because of that — safe by content equivalence, not graph reachability.

### Gauntlet verification on main

| Check | Result |
|---|---|
| `cargo test --release --workspace --no-fail-fast` | **681 passed; 0 failed; 10 ignored** ✅ |
| `cargo clippy --release --workspace --tests -- -D warnings` | clean ✅ |
| `cargo fmt --all -- --check` | OK ✅ |
| `uv run core/tests/python/conformance.py` | PASS ✅ |
| `uv run core/tests/python/spec_test_name_freshness.py` | 96 resolved / 0 unresolved / 2 allowlisted ✅ |

**Discrepancy with previous baton:** the prior `NEXT_SESSION.md` (lines 67 and 212) reported the test count inconsistently — once as 681 and once as 682. The actual close number matches the line-67 figure (681). The 682 in the closing inventory was a transcription slip. Not a real divergence; just noting it.

FFI runners (Swift / Kotlin / Swift-conformance / Kotlin-conformance) were not re-run this session — main has zero Rust changes since PR #74's close-numbers verified all four green yesterday, so re-running would be cycle-burn without information value.

### Commit SHAs from this session

| SHA | Subject |
|---|---|
| (this commit) | `docs: post-merge housekeeping baton — PR #74 closure, branch cleanup, C.1.1 readiness` |

Just one docs commit landing this NEXT_SESSION.md + its frozen handoff snapshot. The cleanup itself is local git state with no commit footprint (branch deletions don't show up in `git log`).

## (2) What's next — C.1.1 brainstorming session

C.1.1 is "**sync_once extension: automatic merge + veto-on-tombstone**". The previous baton (line 99-112) listed proposed acceptance criteria. Before turning those into a spec, the next session should be **interactive brainstorming** — multiple design decisions need user input, not pre-baked assumptions on a security-critical conflict-resolution surface.

### Open design questions for the brainstorm (D1–D4)

These are the questions to put to the user. Each lists my current lean as an option, but the user gets the call.

**D1: `PendingMerge` state shape — flat vs nested vetoes?**

Two shapes for the new variant:

```rust
// Option A: flat — one PendingMerge variant with vetoes inline
SyncOutcome::PendingMerge {
    vetoes: Vec<RecordTombstoneVeto>,
    draft_state: SyncState,
    draft_records: Vec<RecordDraft>,  // merged-but-uncommitted
}

// Option B: layered — keep ForkDetected for veto-free forks, add MergeWithVetoes for the rest
SyncOutcome::ForkDetected { evidence }                              // existing — no merging possible without vetoes
SyncOutcome::MergeWithVetoes { vetoes, draft_state, draft_records } // new — disk merge OK except for tombstone-vs-live conflicts
SyncOutcome::AppliedAutomatically { new_state }                     // existing — generalises to "merged with no vetoes"
```

My lean: **Option B (layered)**. Keeps `ForkDetected` as the "we genuinely cannot reconcile" terminal state (e.g. different vault UUIDs treated as fork, divergence beyond clock-replay window). `MergeWithVetoes` is the more interesting case where automatic merging is possible *modulo* explicit user decisions on resurrected-vs-tombstoned records. Reason: it preserves the single-responsibility property of each variant — a caller can pattern-match exhaustively.

**D2: `commit_with_decisions` atomicity boundary — single call or two-phase?**

```rust
// Option A: single atomic call — caller hands in decisions, we write everything or nothing
fn commit_with_decisions(
    folder: &Path,
    identity: &UnlockedIdentity,
    draft: DraftMerge,           // returned via PendingMerge / MergeWithVetoes
    decisions: Vec<VetoDecision>,
    now_ms: u64,
) -> Result<SyncState, SyncError>;

// Option B: two-phase — prepare-then-commit so an app crash between dialog and write doesn't lose state
fn prepare_commit(...) -> Result<PreparedCommit, SyncError>;       // serializes draft + decisions to a temp file
fn finalize_commit(prepared: PreparedCommit, ...) -> Result<SyncState, SyncError>;
```

My lean: **Option A (single call)** for v1. The §10 atomicity story already covers manifest-then-blocks via `write_atomic`. If app-crash-during-dialog resilience becomes a UX requirement, a third entry point can serialize the `DraftMerge` to a sidecar file later — backwards-compatible. Don't over-engineer for a need that hasn't materialised. (Memory: "feedback_security_no_assumptions.md" — pick enforcement when security matters, but DON'T pre-engineer for non-security UX flows.)

**D3: `RecordTombstoneVeto` semantics — record-level or field-level?**

```rust
// Option A: record-level — one veto per (record_id, tombstoner_vector_clock)
struct RecordTombstoneVeto {
    record_id: RecordId,
    local_state: RecordSnapshot,   // what the local side has live
    disk_tombstone_at_ms: u64,     // when the peer tombstoned
    disk_tombstoner: NodeId,
}

// Option B: field-level — veto on a per-field-change basis (LWW-friendlier)
struct FieldChangeVeto {
    record_id: RecordId,
    field_path: FieldPath,
    local_value: FieldValueSnapshot,
    disk_value: FieldValueSnapshot,
    tie_break_winner: Side,
}
```

My lean: **Option A (record-level)** for v1. The CRDT merge layer (`vault::conflict::merge_record`) already does LWW field-by-field with deterministic tiebreak. The *one* case where automatic merge is unsafe is record-level tombstone-vs-resurrection — peer says "delete this record" while local says "modify this record". Field-level disagreements have a deterministic answer; the user shouldn't be asked. Reason: surface only the genuinely ambiguous decisions to the user. (Memory: "feedback_pure_functions.md" — push complexity to edges; the user-facing API is the highest-cost surface to bloat.)

**D4: Disk-block readout strategy — eager or lazy?**

`sync_once` currently reads only the manifest. C.1.1 needs to surface enough record data to render a veto dialog. Two strategies:

```
// Option A: eager — read all disk blocks during sync_once, return DraftMerge with full record contents
//   pro: caller has everything needed for UI without further IO
//   con: large vaults pay O(vault_size) per poll even when no merge needed
//   con: secrets reside in DraftMerge memory; zeroize discipline must extend to DraftMerge

// Option B: lazy — sync_once still reads only manifest, returns a DiffPlan { records_to_pull: Vec<RecordId> }
//                 caller calls read_records(folder, identity, &plan) on the slow path
//   pro: O(divergence_size), not O(vault_size)
//   pro: secrets stay sealed unless the user actually opens the veto dialog
//   con: split-brain risk if disk changes again between sync_once and read_records
//   mitigation: read_records re-verifies the manifest signature matches the plan's manifest_hash; mismatch ⇒ EvidenceStale, caller retries sync_once
```

My lean: **Option B (lazy with manifest-hash freshness check)**. Both perf and zeroize discipline pull the same direction. The split-brain mitigation is one extra read+verify, which is cheap. This also lets `sync_once`'s O(1)-disk-reads property survive into C.1.1. (Memory: "feedback_pure_functions.md" + the secrets-stay-sealed property is alignment with `Sensitive<T>` discipline from CLAUDE.md.)

### Proposed acceptance criteria (carried from previous baton, refined)

Refining the previous baton's list (lines 108–112) in light of D1–D4. **These should be re-confirmed during brainstorming.**

- [ ] **New variant added per D1**: either `SyncOutcome::PendingMerge` (flat) or `SyncOutcome::MergeWithVetoes` (layered) depending on D1's resolution.
- [ ] **`commit_with_decisions` entry point** (or two-phase prepare/finalize per D2): atomically rewrites blocks + manifest, returns a fresh `SyncState` for caller persistence.
- [ ] **`core::sync::conflict::tombstone_veto_set(local, disk) -> Vec<VetoKind>`** — pure helper. Proptest-pinned: returns only records where the disk tombstone post-dates the local last-edit AND the local record is non-tombstoned. (Granularity follows D3.)
- [ ] **`read_records(folder, identity, plan) -> Result<Vec<Record>, SyncError>`** (per D4 lazy strategy), or eager bundling in `sync_once` (D4 eager). Either way: zeroize discipline for any new secret-bearing types.
- [ ] **`sync_kat.json` grows from 9 → ~15 vectors** covering the new merge-with-vetoes paths. New vectors must include: (a) clean merge no vetoes, (b) merge with one tombstone veto, (c) merge with multiple vetoes, (d) all-vetoes-rejected path, (e) all-vetoes-accepted path, (f) mixed accept/reject path.
- [ ] **No FFI surface change** — C.1.1 is core-only. B-side projection follows in C.3.
- [ ] **Python clean-room replay** — defer to [#76](https://github.com/hherb/secretary/issues/76)'s scope, but the new KAT vectors should be added to that replay's scope at the same time the work is done in C.4.
- [ ] **Zeroize discipline preserved**: any new `Draft*` / `Snapshot*` types holding `RecordFieldValue`-equivalent data must wrap secrets in `SecretBytes` / `SecretString` per [core/src/crypto/secret.rs](core/src/crypto/secret.rs) and derive `Zeroize, ZeroizeOnDrop`.
- [ ] **Tests pass byte-identically before/after** for non-merge code paths (`open_vault`, existing `sync_once` callers).

### Optional pre-brainstorming reading

Before the C.1.1 brainstorming session, it'd be worth re-reading:
- [docs/superpowers/specs/2026-05-17-c1-sync-detection-design.md](docs/superpowers/specs/2026-05-17-c1-sync-detection-design.md) — what we shipped, especially §10 dispatch semantics.
- [docs/crypto-design.md](docs/crypto-design.md) §10 — the spec text about rollback + fork detection.
- [core/src/vault/conflict.rs](core/src/vault/conflict.rs) — the existing merge layer (`merge_record`, `merge_block`, vector-clock + tombstone-clock invariants).

## (3) Open decisions and risks

### Decisions waiting on user input

**D1–D4 above.** Each has my lean stated, but each is a real choice the user should sign off on (security-critical merge semantics; one of the cases — D3's record-vs-field veto granularity — directly determines how much trust we ask the user to extend). Reason for not pre-baking: feedback memories `feedback_security_no_assumptions.md` and `feedback_verify_deferred_items.md` — pre-bake at peril.

### Risks for the C.1.1 work itself (carried + refined)

- **`fresh_vault_with_clock` test helper** (existing, lives in `core/tests/sync_helpers/mod.rs`) uses a deterministic AEAD nonce. C.1.1 likely needs multi-rewrite-per-test sequences (sync detects, user vetoes, commit, re-sync converges). Adding per-call nonce parameterisation (or `getrandom`) is one of the first plan items. **Don't share a key-nonce pair across rewrites in the same test.**
- **`DraftMerge` zeroize.** Any new type holding peer-side `RecordFieldValue` snapshots is a new memory-hygiene surface. Re-read [docs/manual/contributors/memory-hygiene-audit-internal.md](docs/manual/contributors/memory-hygiene-audit-internal.md) before designing the type — past commit `6054185` fixed twelve stack-residue gaps that follow the same pattern.
- **`commit_with_decisions` atomic-rewrite** depends on the existing `write_atomic` contract ([core/src/vault/io.rs](core/src/vault/io.rs)). `tempfile` is exact-pinned to `=3.27.0` per CLAUDE.md's atomic-write section; do not bump.

### Issues still open from prior sessions (unchanged)

- **Issue [#37](https://github.com/hherb/secretary/issues/37)** — Sub-project C design discipline umbrella. C.1 phase 1 partially addresses; stays open for C.1.1 / C.2 / C.3 / C.4.
- **Issue [#38](https://github.com/hherb/secretary/issues/38)** — `save_block` proptest case-count budget; revisit when C.1.1 vault-lifecycle decisions land.
- **Issue [#45](https://github.com/hherb/secretary/issues/45)** — three `pub(crate) #[allow(dead_code)]` accessors on `OpenVaultManifest`; revisit when C-side consumers materialise.
- **Issue [#75](https://github.com/hherb/secretary/issues/75)** — replace `#[doc(hidden)] pub __test_dispatch` with `pub(crate)` + lib-internal tests. **Deliberately not picked up this session** because C.1.1 will heavily edit `core/src/sync/once.rs` and any refactor now would either churn or conflict-merge with that work. Pick up when C.1.1 ships or before B.7.
- **Issue [#76](https://github.com/hherb/secretary/issues/76)** — Python clean-room replay of `sync_kat.json`. Scoped to C.4. The C.1.1 KAT additions should be in scope when #76 is finally done.

### Open PRs at close

None. PR #74 is merged.

## (4) Exact commands to resume

The next session is a C.1.1 brainstorming session. Start from clean main:

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin
git checkout main
git pull --ff-only origin main
git status --short                                   # expect: clean
git branch -a                                        # expect: just main + remotes/origin/{HEAD,main}
git worktree list                                    # expect: just the primary working tree

# Sanity-check the gauntlet is still green:
cargo test --release --workspace --no-fail-fast > /tmp/c11-resume.log 2>&1
grep -E "^test result:" /tmp/c11-resume.log | awk '{
  for (i=1; i<=NF; i++) {
    if ($i == "passed;") p += $(i-1)
    if ($i == "failed;") f += $(i-1)
    if ($i == "ignored;") ig += $(i-1)
  }
}
END { printf("TOTAL: %d passed; %d failed; %d ignored\n", p, f, ig) }'
# Expect: TOTAL: 681 passed; 0 failed; 10 ignored

# When ready to brainstorm + start C.1.1 work, create the feature worktree:
git worktree add .worktrees/c1-1-sync-merge -b feature/c1-1-sync-merge
cd .worktrees/c1-1-sync-merge

# Brainstorm in conversation. Capture D1–D4 decisions + any new questions
# in docs/superpowers/specs/2026-05-18-c1-1-sync-merge-design.md (date as appropriate).
# Then write the implementation plan in docs/superpowers/plans/<date>-c1-1-sync-merge.md.
# Then write a pre-implementation baton commit, then implement TDD-style.
```

## Closing inventory on main

- **Branch state on close:** `main` at `381c34d` (will tick to the SHA of this baton commit after `git commit` lands). No feature branches, no stale worktrees.
- **Workspace tests:** **681 passed + 10 ignored** under `cargo test --release --workspace` — bit-identical to PR #74's close numbers.
- **README.md:** unchanged this session (already reflects C.1 phase 1 ✅ from PR #74).
- **ROADMAP.md:** unchanged this session (already reflects C.1 phase 1 ✅ from PR #74).
- **CLAUDE.md:** unchanged.
- **Open issues:** [#37](https://github.com/hherb/secretary/issues/37) / [#38](https://github.com/hherb/secretary/issues/38) / [#45](https://github.com/hherb/secretary/issues/45) / [#75](https://github.com/hherb/secretary/issues/75) / [#76](https://github.com/hherb/secretary/issues/76).
- **Open PRs:** none.
- **Frozen baton snapshot:** [`docs/handoffs/2026-05-17-post-pr74-housekeeping.md`](docs/handoffs/2026-05-17-post-pr74-housekeeping.md) — exact copy of this file for audit/learning.
