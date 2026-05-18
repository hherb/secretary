# NEXT_SESSION.md

**Session date:** 2026-05-18 (C.1.1 brainstorming session; split into 1a + 1b and authored 1a implementation plan)
**Status:** `main` unchanged at `a5689ec` (last session's housekeeping baton). All work this session landed on `feature/c1-1-sync-merge` inside `.worktrees/c1-1-sync-merge`. Three commits on the feature branch are the C.1.1a design, C.1.1b design, and the 17-task C.1.1a implementation plan — **no implementation code yet**.

## (1) What we shipped this session

A brainstorm + planning session, no Rust code. Three commits on the feature branch:

| SHA | Subject |
|---|---|
| `3ab631f` | `docs(c1-1a): implementation plan for conflict-copy ingestion` — 17-task TDD plan, 2973 LOC |
| `781b16c` | `docs(c1-1): split C.1.1 design into 1a (conflict-copy ingestion) + 1b (merge)` — both design docs, 913 LOC |
| `a5689ec` | (from main) prior session's housekeeping baton |

The brainstorm walked D1–D5 + atomicity option (d) for the merge layer, then discovered during spec self-review that the merge primitives (`merge_block`, `merge_record`) need a **second source** that no current code path provides — Secretary's cloud-folder sync model emits conflict-copy files (Dropbox `(conflicted copy …)`, iCloud `… 2.cbor.enc`, Syncthing `.sync-conflict-…`, etc.) but nobody has written code to ingest them yet. The C.1 phase 1 spec at lines 18, 76, 78 explicitly scoped this work to C.1.1.

**Decision (committed in `781b16c`):** split C.1.1 into two sequential PRs per the user's brick-by-brick preference:

- **C.1.1a** — conflict-copy ingestion: `VaultBundle` + sibling-manifest authentication + N-way support + heuristic decode-then-authenticate file matching. **This is the next implementation slice.**
- **C.1.1b** — merge + veto + commit + verify_block_fingerprints, consumes 1a's `VaultBundle`. Design preserved; implementation queued until 1a lands.

Approved 1a decisions:
- **1a-D1:** sync_once-internal lazy scan (no extra I/O on quiet vaults)
- **1a-D2:** N-way iterative pairwise merge (CRDT closure supports it natively)
- **1a-D3:** Heuristic decode-then-authenticate (vs. strict pattern registry per cloud)
- **1a-D4:** Five-rule MUST authentication set (decode, hybrid signature, vault_uuid, author_fingerprint, AEAD)

Approved 1b decisions (preserved in [`docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md`](docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md), implementation deferred):
- **D1:** Layered `SyncOutcome` variants — `ForkDetected` retires; `AppliedAutomatically` covers dominance + silent merges; `MergeWithVetoes`/`ConcurrentDetected` for the rest
- **D2:** Single-call `commit_with_decisions` atomicity boundary
- **D3:** Record-level veto (carried from C.1 phase 1 §D2)
- **D4:** Lazy disk-block readout with `manifest_hash` freshness guard
- **D5:** Three-step API (`sync_once → prepare_merge → commit_with_decisions`)
- **Atomicity option (d):** Block-first manifest-last + read-time `verify_block_fingerprints` in `open_vault` (closes a latent gap the C.1 phase 1 spec line 253 claimed was already closed but isn't)

Gauntlet not re-run this session — `main` has zero Rust changes since the prior session's verification (681 passed, 0 failed, 10 ignored).

## (2) What's next — execute C.1.1a Task 1 of the plan

Plan lives at `docs/superpowers/plans/2026-05-18-c1-1a-conflict-copy-ingestion.md` on `feature/c1-1-sync-merge`. **17 tasks, TDD, ~1100 LOC of new code + tests.**

### Acceptance criteria for C.1.1a (the PR that closes this slice)

- [ ] `core/src/sync/bundle.rs` (NEW) defines `VaultBundle`, `ManifestSnapshot`, `BlockDivergence`, `BlockEnvelope`, `ManifestHash` with `Zeroize + ZeroizeOnDrop` derives.
- [ ] `core/src/sync/ingest.rs` (NEW) defines `authenticate_manifest_envelope`, `enumerate_manifest_siblings`, `ingest_manifest_copies`, `authenticate_block_envelope`, `enumerate_block_siblings`, `ingest_block_divergence`, `compute_diff_plan`, `ingest_conflict_copies`. All five MUST authentication rules enforced per spec §1a-D4.
- [ ] `core/src/sync/outcome.rs` modified: `ForkDetected` removed; `ConcurrentDetected { bundle, plan, manifest_hash, disk_vector_clock, local_highest_seen }` added.
- [ ] `core/src/sync/error.rs` adds `ConflictCopyScanIoFailed` + `CanonicalHashInternal`.
- [ ] `core/src/sync/once.rs` Concurrent arm invokes `ingest_conflict_copies` and returns `ConcurrentDetected`.
- [ ] `core/tests/sync_helpers/mod.rs` extended with `fresh_vault_two_concurrent_manifests` + `fresh_vault_four_concurrent_manifests` + four distinct AEAD nonces (no key+nonce reuse across rewrites — CLAUDE.md atomic-write contract).
- [ ] `core/tests/sync_ingest.rs` (NEW) covers ~12 integration tests including: zero/one/three-copies happy paths; signature-tampered silent rejection; wrong-vault_uuid silent rejection; wrong-owner-fingerprint silent rejection; block-divergence ingestion; Dropbox/Syncthing naming convention compatibility; no-scan-on-non-concurrent fast-path.
- [ ] `core/tests/sync_ingest_proptest.rs` (NEW) covers idempotence + junk-rejection properties.
- [ ] `core/tests/data/sync_kat.json` grows from 9 → 12 vectors (3 new ingestion vectors); `core/tests/sync_kat.rs` replay logic extended.
- [ ] Workspace gauntlet green: `cargo test --release --workspace --no-fail-fast` ≈ 715 passed (681 → ~715), 0 failed; `cargo clippy --release --workspace --tests -- -D warnings` clean; `cargo fmt --all -- --check` clean; `uv run core/tests/python/conformance.py` PASS; `uv run core/tests/python/spec_test_name_freshness.py` 0 unresolved.
- [ ] ROADMAP.md updated (C.1.1a → ✅ on merge).
- [ ] NEXT_SESSION.md updated **on the feature branch BEFORE pushing** (per `feedback_next_session_in_pr.md`) pointing at C.1.1b.

### Plumbing research the implementer must do early (called out inline in the plan)

These are 5–10 min grep-and-read items, not TBDs:

- Task 4 / Task 7: find the existing `manifest::verify_then_decrypt` (or equivalent) helper in `core/src/vault/manifest.rs` and the block-envelope signature verifier in `core/src/vault/block.rs`; thread owner public keys through. May involve extracting a `pub(crate)` helper from `read_and_verify_manifest` in `core/src/vault/orchestrators.rs:562-680`.
- Task 8: promote `format_uuid_hyphenated` from `core/src/vault/orchestrators.rs:72` to `pub(crate)` (or move to a shared util module) so the block-sibling scanner can use it instead of re-implementing.
- Task 13 / Step 3: build a `create_second_vault_manifest_bytes` helper for the wrong-vault_uuid + wrong-owner-fingerprint silent-rejection integration tests. If this proves too heavy, defer those two tests to a follow-up issue (and document the gap in the spec).
- Task 16: confirm `tracing` is in `core/Cargo.toml`; add it if missing (caret-range pin acceptable — not on a security-critical path).

## (3) Open decisions and risks

### Open decisions

**None of this session's design questions are still open.** D1–D5 + 1a-D1–1a-D4 all settled in conversation and recorded in the design docs.

### Risks (carried from C.1.1a spec §Risks)

- **Test fixture complexity.** Constructing a second authenticated vault (for wrong-vault_uuid and wrong-owner-fingerprint silent-rejection tests) requires calling `core::vault::create_vault` with controlled inputs. Time-box Task 13's helper extension to ~1 hour; if `create_vault` has many dependencies, file a follow-up issue and skip those two tests in 1a's PR.
- **AEAD nonce sharing in test helpers.** Task 1 explicitly addresses this — four distinct nonce constants. Per CLAUDE.md atomic-write section: never share key+nonce across rewrites. Carries through every fixture that writes multiple manifests in the same tempdir.
- **Cloud-folder host adversary (threat-model §3.1)** can write arbitrary `*.cbor.enc` files into the vault folder. Spec §1a-D4's five MUST rules handle this; **do not weaken any of them** during implementation. The "silently ignore" disposition is only safe because all five MUSTs hold.
- **CRDT proptests must not weaken.** C.1.1a doesn't touch `core/src/vault/conflict.rs`. If the 1a implementation appears to need a change to the merge primitives, that's a design problem — push back; don't relax the property.

### Issues still open from prior sessions (unchanged)

- **Issue [#37](https://github.com/hherb/secretary/issues/37)** — Sub-project C design discipline umbrella. C.1.1a will close it partially.
- **Issue [#38](https://github.com/hherb/secretary/issues/38)** — `save_block` proptest case-count budget; revisit when C.1.1b's vault-lifecycle decisions land.
- **Issue [#45](https://github.com/hherb/secretary/issues/45)** — three `pub(crate) #[allow(dead_code)]` accessors on `OpenVaultManifest`; revisit when C-side consumers materialise (C.1.1a consumes them).
- **Issue [#75](https://github.com/hherb/secretary/issues/75)** — replace `#[doc(hidden)] pub __test_dispatch` with `pub(crate)` + lib-internal tests. Still deferred; C.1.1a's Task 12 may refactor `dispatch` (read the relevant Task 12 note for the recommended approach).
- **Issue [#76](https://github.com/hherb/secretary/issues/76)** — Python clean-room replay of `sync_kat.json`. C.1.1a adds 3 new vectors; they join #76's scope.

### Open PRs at close

None. The feature branch `feature/c1-1-sync-merge` has three docs commits but no PR open.

## (4) Exact commands to resume

The work is in a worktree. Resume in the worktree, **do not start fresh on main**:

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin
git status --short                                              # expect: clean

# Worktree is already created from this session:
git worktree list
# Expected: main + .worktrees/c1-1-sync-merge on feature/c1-1-sync-merge

cd .worktrees/c1-1-sync-merge
pwd                                                             # confirm worktree
git branch --show-current                                       # → feature/c1-1-sync-merge
git log --oneline -5
# Expected first three lines:
#   3ab631f docs(c1-1a): implementation plan for conflict-copy ingestion
#   781b16c docs(c1-1): split C.1.1 design into 1a (conflict-copy ingestion) + 1b (merge)
#   a5689ec docs: post-PR-#74 housekeeping baton + C.1.1 brainstorming readiness

# Sanity-check the gauntlet (one-time before starting Task 1):
cargo test --release --workspace --no-fail-fast > /tmp/c11a-resume.log 2>&1
grep -E "^test result:" /tmp/c11a-resume.log | head -3
# Expected: 681 passed (matches main; no Rust changes yet)

# Read the plan:
cat docs/superpowers/plans/2026-05-18-c1-1a-conflict-copy-ingestion.md | head -100
# OR open in editor

# Begin Task 1: extend test helper for per-nonce + sibling manifest writes.
# Each task in the plan is one logical commit with TDD: write failing
# test → run to confirm fail → implement → run to confirm pass → clippy
# + fmt clean → commit.

# Optional: dispatch the subagent-driven-development skill to drive
# task-by-task subagent execution with review checkpoints between tasks.
```

If the worktree was destroyed accidentally, recreate from main:

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin
git worktree add .worktrees/c1-1-sync-merge feature/c1-1-sync-merge
cd .worktrees/c1-1-sync-merge
# the three docs commits are on the remote branch (if pushed) or local (if not)
```

(The branch wasn't pushed this session — it's local-only on `feature/c1-1-sync-merge`. If the worktree directory is destroyed locally without a remote push, the three docs commits would need to be reconstructed from git reflog or re-authored.)

## Closing inventory

- **Branch state on close:** `main` at `a5689ec` (unchanged from start of session). `feature/c1-1-sync-merge` at `3ab631f`. No PRs open.
- **Workspace tests on main:** 681 passed + 10 ignored (unchanged — no Rust touched).
- **Workspace tests on `feature/c1-1-sync-merge`:** same as main (only docs added).
- **README.md:** unchanged this session. Existing reference to "C.1.1 will add merge + veto" remains accurate (1a + 1b together = merge + veto).
- **ROADMAP.md:** unchanged this session. Will update when 1a code lands per the plan's Task 17.
- **CLAUDE.md:** unchanged.
- **Open issues:** [#37](https://github.com/hherb/secretary/issues/37) / [#38](https://github.com/hherb/secretary/issues/38) / [#45](https://github.com/hherb/secretary/issues/45) / [#75](https://github.com/hherb/secretary/issues/75) / [#76](https://github.com/hherb/secretary/issues/76).
- **Open PRs:** none.
- **Worktrees on disk:** `main` + `.worktrees/c1-1-sync-merge`.
- **Frozen baton snapshot:** [`docs/handoffs/2026-05-18-c1-1-brainstorm-split-1a-1b.md`](docs/handoffs/2026-05-18-c1-1-brainstorm-split-1a-1b.md) — exact copy of this file for audit/learning.
