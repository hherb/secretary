# NEXT_SESSION.md

**Session date:** 2026-05-18 (C.1.1a implementation — conflict-copy ingestion shipped end-to-end on `feature/c1-1-sync-merge`)
**Status:** `main` unchanged at `a5689ec`. All work this session landed on `feature/c1-1-sync-merge` inside `.worktrees/c1-1-sync-merge`. Eleven new code commits implement Tasks 1–17 of the C.1.1a plan; branch carries 14 commits total ahead of `main` (3 docs + 11 code). **Branch is NOT yet pushed**; no PR open.

## (1) What we shipped this session

Eleven code commits + ROADMAP/README/NEXT_SESSION updates implementing the full C.1.1a slice:

| SHA | Subject |
|---|---|
| `0f741a9` | `test(sync-ingest): proptest properties (idempotence, junk-rejection)` |
| `b3e7578` | `test(sync-ingest): integration tests for C.1.1a end-to-end (Task 13)` |
| `37b721b` | `feat(sync): wire SyncOutcome::ConcurrentDetected end-to-end (Tasks 11+12)` |
| `bcf951b` | `feat(sync): wire ingest_block_divergence + compute_diff_plan + ingest_conflict_copies` |
| `ffd1502` | `feat(sync): add enumerate_block_siblings + promote uuid/blocks helpers` |
| `d5e8255` | `feat(sync): add authenticate_block_envelope pure helper` |
| `71ff931` | `feat(sync): wire ingest_manifest_copies (scan + authenticate composition)` |
| `2f34b60` | `feat(sync): add enumerate_manifest_siblings directory scan helper` |
| `c6b335d` | `feat(sync): add authenticate_manifest_envelope pure helper` |
| `a4d3748` | `feat(sync): add compute_manifest_hash pure helper` |
| `19a954a` | `feat(sync): add VaultBundle + ManifestSnapshot + BlockDivergence types` |
| `3de6782` | `test(sync-helpers): add multi-manifest fixture helpers for C.1.1a` |
| `3ab631f` | `docs(c1-1a): implementation plan for conflict-copy ingestion` (prior session) |
| `781b16c` | `docs(c1-1): split C.1.1 design into 1a + 1b` (prior session) |

**What landed (architecturally):**

- **`SyncOutcome::ForkDetected` retires; replaced by `ConcurrentDetected { bundle, plan, manifest_hash, disk_vector_clock, local_highest_seen }`**. The Concurrent dispatch arm of `sync_once` now does conflict-copy ingestion before returning.
- **`core::sync::bundle`** (NEW): `VaultBundle`, `ManifestSnapshot`, `BlockEnvelope`, `BlockDivergence`, `ManifestHash`, `compute_manifest_hash`. All composite types `Zeroize + ZeroizeOnDrop`; `Manifest` field is `#[zeroize(skip)]` (precedent: `OpenVault.manifest`). `VaultBundle.diverging_blocks` is `#[zeroize(skip)]` since `BTreeMap` has no blanket Zeroize impl, but its values still zeroize via their own ZeroizeOnDrop on drop.
- **`core::sync::ingest`** (NEW): `authenticate_manifest_envelope` (5 MUSTs per §1a-D4 — decode + hybrid sig + vault_uuid + author_fp + AEAD-decrypt), `enumerate_manifest_siblings` (prefix-match scanner), `ingest_manifest_copies` (compose), `authenticate_block_envelope` (3 MUSTs — block AEAD-decrypt deferred to 1b), `enumerate_block_siblings`, `ingest_block_divergence`, `compute_diff_plan`, `ingest_conflict_copies` (top-level).
- **`core::sync::DiffPlan`** new type: `{ diverging_blocks: Vec<[u8;16]> }`.
- **`core::sync::SyncError`** grows 2 variants: `ConflictCopyScanIoFailed { source }` + `CanonicalHashInternal` (defensive).
- **`core::vault::verify_block_signature(block, ed_pk, pq_pk)`** new public helper: verifies the §8 hybrid signature on a `BlockFile` without recipient decap or body AEAD-decrypt. Re-exported from `core::vault`.
- **`core::vault::orchestrators::read_vault_manifest_full`** new `pub(crate)` helper: returns `(ContactCard, Manifest, ManifestFile)` so `sync_once` can derive owner public keys for the authenticators without re-doing Argon2 or re-loading the owner card.
- **`core::vault::orchestrators::{format_uuid_hyphenated, BLOCKS_SUBDIR, BLOCK_FILE_EXTENSION}`** promoted from private → `pub(crate)`; the orchestrators module visibility went `mod` → `pub(crate) mod`. Keeps the on-disk filename format pinned to one source of truth (the same format `save_block` writes).
- **`core::SyncOutcome`** drops `Eq` (keeps `PartialEq`) because `VaultBundle`'s inner `Manifest` derives `PartialEq` without `Eq`. No call site requires `Eq`. Variant carries `clippy::large_enum_variant` allow — one-per-call return value, not a hot `Vec`.
- **New tests:** 20 lib unit tests across `sync::bundle` (4) + `sync::ingest` (16); 9 integration tests in `core/tests/sync_ingest.rs`; 2 proptest properties in `core/tests/sync_ingest_proptest.rs`.
- **Workspace test count:** 681 → **712** passed, 0 failed, 10 ignored.

**Per-task ACK:**

- [x] Task 1: multi-manifest fixture helpers
- [x] Task 2: bundle.rs types + zeroize
- [x] Task 3: compute_manifest_hash
- [x] Task 4: authenticate_manifest_envelope (5 MUSTs)
- [x] Task 5: enumerate_manifest_siblings
- [x] Task 6: ingest_manifest_copies
- [x] Task 7: authenticate_block_envelope + new `verify_block_signature` public helper in block.rs
- [x] Task 8: enumerate_block_siblings + UUID/blocks helpers promoted to pub(crate)
- [x] Task 9: ingest_block_divergence
- [x] Task 10: compute_diff_plan + top-level ingest_conflict_copies
- [x] Task 11: SyncOutcome::ConcurrentDetected variant + DiffPlan + 2 new SyncError variants
- [x] Task 12: sync_once wires ingest_conflict_copies on Concurrent arm
- [x] Task 13: 9 integration tests in core/tests/sync_ingest.rs
- [⏭] Task 14: KAT vectors expansion — **deferred to follow-up issue**. Reason: the existing `sync_kat.json` schema has no `sibling_fixture` field; extending it to drive sibling-file construction inside `__test_dispatch` requires the schema bump described in plan §Task 14 and a corresponding rewrite of `core/tests/sync_kat.rs`'s replay logic. Two existing fork-detected vectors renamed to `ConcurrentDetected` (their replays already pass through the Option-None Concurrent signal in the clock-only dispatch helper). New ingestion-bearing KAT vectors not added.
- [x] Task 15: 2 proptest properties (idempotence + junk-rejection)
- [x] Task 16: `tracing = "0.1"` added in Task 4's commit (first use site); `spec_test_name_freshness.py` reports 0 unresolved
- [x] Task 17: gauntlet green (712 / 0 / 10); ROADMAP + README updated; this NEXT_SESSION.md authored

**Deliberately deferred to follow-up issues** (per plan's own risk notes):

- wrong-vault_uuid silent rejection integration test — needs `create_vault` to build a second authenticated vault.
- wrong-owner-fingerprint silent rejection integration test — same plus a distinct owner identity.
- block-divergence end-to-end integration test — needs a block re-signing helper to construct a sibling block with a different vector_clock_summary than the canonical.
- N-way order independence proptest — fixture-construction cost outweighs marginal coverage given Task 13 covers N-way explicitly.

The lib-side authentication logic IS covered: pure-input rejection arms (empty/garbage/oversize) live in `core/src/sync/ingest.rs::tests`; signature-tampered + Dropbox/Syncthing naming + lazy-no-scan all covered in `core/tests/sync_ingest.rs`. The deferred items are integration depth, not correctness gaps.

## (2) What's next — open PR for C.1.1a, then start C.1.1b

### (a) **First thing next session: push + open PR**

The branch is local-only. Push and open the PR:

```bash
cd /Users/hherb/src/secretary/.worktrees/c1-1-sync-merge
git status --short       # expect clean
git log --oneline -15    # confirm the 11 code commits land in this order
git push -u origin feature/c1-1-sync-merge
gh pr create --title "feat(c1-1a): conflict-copy ingestion (VaultBundle + sibling auth)" \
  --body "$(cat <<'EOF'
## Summary

- Adds the `VaultBundle` ingestion layer that scans the vault folder for sibling
  `*.cbor.enc` manifest/block files, authenticates each against the canonical
  manifest's owner identity (five MUST rules per spec §1a-D4), and packages
  canonical + N copies + per-block divergence.
- Replaces `SyncOutcome::ForkDetected` (terminal) with
  `SyncOutcome::ConcurrentDetected { bundle, plan, manifest_hash, … }`.
- Lays the groundwork for C.1.1b (merge + veto + commit), which consumes
  this slice's `VaultBundle`.

## Test plan

- [x] `cargo test --release --workspace --no-fail-fast` → 712 passed, 0 failed, 10 ignored
- [x] `cargo clippy --release --workspace --tests -- -D warnings` → clean
- [x] `cargo fmt --all -- --check` → clean
- [x] `uv run core/tests/python/conformance.py` → PASS
- [x] `uv run core/tests/python/spec_test_name_freshness.py` → 0 unresolved

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

### (b) Follow-up issues to file (before/after PR merge)

- **Issue [follow-up]: C.1.1a integration-test gaps** — wrong-vault_uuid + wrong-owner-fingerprint + block-divergence integration tests (need `create_vault` second-vault fixture + block re-signing helper).
- **Issue [follow-up]: sync_kat.json ingestion vectors** — schema extension for `sibling_fixture` + replay extension; superseded by issue #76 if Python clean-room replay is part of the same closure.

### (c) Acceptance criteria for C.1.1b (the merge layer)

Per the 1b design doc at [`docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md`](docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md):

- [ ] `prepare_merge(folder, identity, bundle, plan) -> DraftMerge` decrypts each diverging block envelope on demand, calls `merge_block` from `core::vault::conflict`, and surfaces field-level collisions for veto.
- [ ] `commit_with_decisions(folder, identity, draft, decisions) -> SyncOutcome::CommitApplied` writes the merged result + bumps the local clock + re-checks the canonical `manifest_hash` (TOCTOU close) before persisting.
- [ ] Block-first manifest-last atomic write + a new `verify_block_fingerprints` step in `open_vault` (closes the latent gap the C.1 phase 1 spec line 253 claimed was already closed but isn't).
- [ ] Record-level veto API (per D2).
- [ ] Gauntlet still green; new tests for veto/dominance/silent-merges + commit ordering.

## (3) Open decisions and risks

### Open decisions

**None outstanding from C.1.1a.** All §1a-D1 → §1a-D4 decisions implemented per the design doc.

For C.1.1b: D1–D5 + atomicity option (d) were all settled in the prior session's brainstorm and recorded in the 1b design doc. No new decisions to make.

### Risks (carried into C.1.1b)

- **Test fixture complexity for second-vault scenarios** — the wrong-vault_uuid + wrong-owner-fingerprint integration tests are deferred for this reason. A `create_second_vault_manifest_bytes` helper would close it; ~1-hour effort.
- **AEAD nonce sharing across rewrites in test fixtures** — handled in C.1.1a's `sync_helpers/mod.rs` via four distinct nonce constants. Continue this discipline in C.1.1b: any new helper that writes multiple manifests/blocks in one tempdir must use distinct nonces.
- **CRDT proptests must not weaken.** C.1.1a didn't touch `core/src/vault/conflict.rs`. C.1.1b consumes `merge_record` / `merge_block` — push back on any change that requires the four proptests to weaken.
- **Block envelope payload is held verbatim inside `VaultBundle`.** That's intentional (decryption is C.1.1b's job), but a long-lived `ConcurrentDetected` value carries encrypted record material in memory. Callers should not hold `SyncOutcome::ConcurrentDetected` beyond the immediate prepare/commit cycle. The bundle's `Zeroize + ZeroizeOnDrop` covers eventual cleanup.

### Issues still open from prior sessions

- **Issue [#37](https://github.com/hherb/secretary/issues/37)** — Sub-project C design discipline umbrella. C.1.1a closes partially (bundle + ingest layers).
- **Issue [#38](https://github.com/hherb/secretary/issues/38)** — `save_block` proptest case-count budget; revisit when C.1.1b's vault-lifecycle decisions land.
- **Issue [#45](https://github.com/hherb/secretary/issues/45)** — three `pub(crate) #[allow(dead_code)]` accessors on `OpenVaultManifest`; revisit when C-side consumers materialise (C.1.1b might consume them).
- **Issue [#75](https://github.com/hherb/secretary/issues/75)** — replace `#[doc(hidden)] pub __test_dispatch` with `pub(crate)` + lib-internal tests. **NOTE: __test_dispatch's signature changed in this session** (now returns `Result<Option<SyncOutcome>, _>` to signal Concurrent via None). The doc-hidden pattern is preserved.
- **Issue [#76](https://github.com/hherb/secretary/issues/76)** — Python clean-room replay of `sync_kat.json`. C.1.1a did NOT add new vectors (Task 14 deferred); this issue still has the original 9-vector scope plus the 2 vector renames (ForkDetected → ConcurrentDetected).

### Open PRs at close

None. Branch is local; PR creation is the first item next session.

## (4) Exact commands to resume

The work is in a worktree. Resume in the worktree:

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin
git status --short                                              # expect: clean
git worktree list
# Expected: main + .worktrees/c1-1-sync-merge on feature/c1-1-sync-merge

cd .worktrees/c1-1-sync-merge
pwd                                                             # confirm worktree
git branch --show-current                                       # → feature/c1-1-sync-merge
git log --oneline -15
# Expected first lines (newest first):
#   <doc commit SHA> docs: ROADMAP + README + NEXT_SESSION baton for C.1.1a (this commit)
#   0f741a9 test(sync-ingest): proptest properties (idempotence, junk-rejection)
#   b3e7578 test(sync-ingest): integration tests for C.1.1a end-to-end (Task 13)
#   37b721b feat(sync): wire SyncOutcome::ConcurrentDetected end-to-end (Tasks 11+12)
#   bcf951b feat(sync): wire ingest_block_divergence + compute_diff_plan + ingest_conflict_copies
#   ffd1502 feat(sync): add enumerate_block_siblings + promote uuid/blocks helpers
#   ... etc.

# Resume gauntlet (sanity-check on resume; expected stable at 712 / 0 / 10):
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | head -3
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3

# First action: push + open PR (see section 2.a above).
# Second action: start C.1.1b implementation against the merged 1a base.
```

If the worktree was destroyed:

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin
git worktree add .worktrees/c1-1-sync-merge feature/c1-1-sync-merge
cd .worktrees/c1-1-sync-merge
```

(The branch is local-only this session. If the worktree directory is destroyed before push, the 11 code commits would need to be reconstructed from git reflog or re-authored — **push the branch to remote as the first action next session**, even before opening the PR.)

## Closing inventory

- **Branch state on close:** `main` at `a5689ec` (unchanged). `feature/c1-1-sync-merge` at the doc commit on top of `0f741a9`. No PRs open.
- **Workspace tests on `feature/c1-1-sync-merge`:** 712 passed + 10 ignored. Conformance PASS. Spec-name-freshness 0 unresolved.
- **README.md:** updated — C.1.1a status row, `ForkDetected` → `ConcurrentDetected` callout, 5-MUST authentication summary.
- **ROADMAP.md:** updated — C.1.1a marked ✅ with full description; progress bar bumped from `========` to `==========`.
- **CLAUDE.md:** unchanged.
- **Open issues:** [#37](https://github.com/hherb/secretary/issues/37) / [#38](https://github.com/hherb/secretary/issues/38) / [#45](https://github.com/hherb/secretary/issues/45) / [#75](https://github.com/hherb/secretary/issues/75) / [#76](https://github.com/hherb/secretary/issues/76); two new follow-ups described in §2.b above to be filed alongside or after the PR.
- **Open PRs:** none.
- **Worktrees on disk:** `main` + `.worktrees/c1-1-sync-merge`.
- **Frozen baton snapshot:** [`docs/handoffs/2026-05-18-c1-1a-conflict-copy-ingestion-shipped.md`](docs/handoffs/2026-05-18-c1-1a-conflict-copy-ingestion-shipped.md) — exact copy of this file for audit/learning.
