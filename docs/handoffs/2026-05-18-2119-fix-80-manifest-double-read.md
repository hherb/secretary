# NEXT_SESSION.md

**Session date:** 2026-05-18 (post-merge follow-up — fixed #80 surfaced during PR #77 review)
**Status:** PRs **#77 (C.1.1a)** and **#82 (AEAD nonce centralisation)** both merged to `main` since the previous baton was written. Two follow-up issues surfaced during the PR #77 review — **#80** (manifest double-read TOCTOU window in `sync_once`) and **#81** (`MAX_BLOCK_FILE_SIZE` undocumented vs format-max recipient table). This session fixed **#80** as a small dedicated PR; **#81** is documentation-only and deferred. C.1.1b plan authoring is the next session's first task.

## (1) What we shipped this session

| Action | Result |
|---|---|
| Resume gauntlet on `main` after PRs #77 + #82 merges (cargo test/clippy/fmt + conformance + spec-name-freshness) | 712 / 0 / 10; all green |
| Fixed **#80**: single-read of `manifest.cbor.enc` in `sync_once`'s Concurrent path | `read_and_verify_manifest` now returns the raw envelope bytes alongside the decoded body + envelope + owner card; `read_vault_manifest_full` forwards them; `sync_once` consumes them to compute `ManifestHash` AND to feed `ingest_conflict_copies` — closing the TOCTOU window where a concurrent writer between the two old reads would leave the bundle body authenticated from read 1 but the hash + bundle bytes from read 2. |
| Added regression test `sync_once_concurrent_manifest_hash_matches_bundle_envelope_bytes` in `core/tests/sync.rs` | Asserts the invariant `BLAKE3(bundle.canonical.raw_envelope_bytes) == manifest_hash` AND `bundle.canonical.raw_envelope_bytes == on-disk manifest.cbor.enc`. Passes by construction post-fix (single read); was a coincidence pre-fix. |
| Gauntlet on `fix/80-manifest-double-read` (cargo test/clippy/fmt + conformance + spec-name-freshness) | 713 / 0 / 10 (= 712 + new regression test); clippy clean with `-D warnings`; fmt clean; conformance PASS; spec-name-freshness PASS (96 resolved, 0 unresolved). |
| Pushed branch + opened PR | Branch + PR pending push at the end of this session — see "Open PRs at close" below. |
| This baton update + handoff snapshot | Commit on `fix/80-manifest-double-read`; rides in the PR per `feedback_next_session_in_pr.md`. |

**Files touched:**
- `core/src/vault/orchestrators.rs` — `read_and_verify_manifest` signature now returns a 4-tuple (added `Vec<u8>` for envelope bytes); `read_vault_manifest_full` signature now returns a 3-tuple (added `Vec<u8>`); `open_vault` and `read_vault_manifest` updated to destructure the new field (discarded with `_`).
- `core/src/sync/once.rs` — `sync_once` consumes the new envelope bytes from `read_vault_manifest_full`; `assemble_concurrent_outcome` now takes `canonical_envelope_bytes: &[u8]` parameter and no longer re-reads. The `std::fs::read(&canonical_path)` call is removed; `canonical_path` is still computed to pass to `ingest_conflict_copies` as the source_path.
- `core/tests/sync.rs` — new regression test (described above).

**No design doc changes:** the C.1.1a / C.1.1b design docs don't pin the internal signature of `read_vault_manifest_full`. The fix is an internal tightening; the surface contract (manifest_hash is a freshness anchor) is unchanged.

**No README / ROADMAP changes:** the fix tightens implementation to match what the existing docs already claim. The change is invisible at the user-facing surface (no API break — all 3 callers of `read_and_verify_manifest` continue to compile, just destructure one extra field).

## (2) What's next — author C.1.1b plan, then execute

### (a) First thing next session: review + merge #80 fix PR

```bash
cd /Users/hherb/src/secretary/.worktrees/fix-80-manifest-double-read
gh pr view <PR# from push> --comments     # check for review comments
# Address any feedback on this branch and push, or merge if clean.
gh pr merge <PR#> --squash                # per user preference
```

After merge:

```bash
cd /Users/hherb/src/secretary
git checkout main
git pull origin main
git worktree remove .worktrees/fix-80-manifest-double-read
git branch -d fix/80-manifest-double-read
```

### (b) Then author the C.1.1b implementation plan

The design doc is at [`docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md`](docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md). It is **complete** — D1–D5 + atomicity option (d) are all settled; no new brainstorming required. Five open implementation-level decisions are listed at lines 460–467 with "Lean" recommendations (eager fingerprint verify in `open_vault`; ManifestHash covers full envelope; DiffPlan helper in `diff.rs`; MergedRecord = re-export of Record; nonce parameterisation for test helper) — settle these in the plan.

Suggested first action next session:

```bash
git worktree add .worktrees/c1-1b-sync-merge -b feature/c1-1b-sync-merge main
cd .worktrees/c1-1b-sync-merge
# Use superpowers:writing-plans to author the 1b plan from the design doc.
# Save plan to docs/superpowers/plans/<date>-c1-1b-sync-merge.md.
# Then use superpowers:subagent-driven-development to execute.
```

### (c) Acceptance criteria for C.1.1b (unchanged from prior baton)

- [ ] `prepare_merge(folder, identity, bundle, plan) -> DraftMerge` decrypts each diverging block envelope on demand, calls `merge_block` from `core::vault::conflict`, and surfaces field-level collisions for veto.
- [ ] `commit_with_decisions(folder, identity, draft, decisions) -> SyncOutcome::CommitApplied` writes the merged result + bumps the local clock + re-checks the canonical `manifest_hash` (TOCTOU close — now load-bearing on the #80 fix) before persisting.
- [ ] Block-first manifest-last atomic write + a new `verify_block_fingerprints` step in `open_vault` (closes the latent gap the C.1 phase 1 spec line 253 claimed was already closed but isn't).
- [ ] Record-level veto API (per D2).
- [ ] Gauntlet stays green; new tests for veto/dominance/silent-merges + commit ordering.
- [ ] **New invariant from this session's #80 fix:** the `ManifestHash` freshness check in `commit_with_decisions` SHOULD assert that the re-read disk hash equals `draft.manifest_hash` — the #80 fix makes this assertion meaningful (without it, a concurrent writer between prepare and commit could pass the TOCTOU check by accident if the bytes-used-for-verify and the bytes-used-for-hash differed in `prepare_merge`).

## (3) Open decisions and risks

### Open decisions

**None outstanding for #80.** C.1.1a + the #80 follow-up are both shipped (pending PR merge). C.1.1b decisions are settled in the design doc; five implementation-level "Lean" choices listed at design-doc lines 460–467 are to be settled in the 1b plan, not re-opened.

### Risks (carried into C.1.1b)

- **#80 fix premise validation.** The fix's regression test asserts the invariant in quiet test envs but does not deterministically demonstrate the bug pre-fix (no concurrent-writer injection harness). The architectural change (single read) is what guarantees the invariant under concurrent writers — the test is a contract / regression guard. A future change reintroducing a divergence between bytes-verified and bytes-hashed would still pass the test in CI but fail under any future race-injection harness.
- **`#81` (MAX_BLOCK_FILE_SIZE documentation) remains open.** Pure docs / sizing decision; no security implication; deferred until a real "large recipient list" workload appears or C.3 work surfaces the FFI-side ceiling discussion.
- **Test fixture complexity for second-vault scenarios** — partially deferred to **#78**. Worth closing #78 alongside or before C.1.1b so the same helpers are reusable.
- **AEAD nonce sharing across rewrites in test fixtures** — C.1.1b's tests will likely need multi-block sibling fixtures; continue the discipline of distinct nonce constants per rewrite (CLAUDE.md atomic-write contract). PR #82 centralised live-path nonce generation; test helpers may still need parameterisation.
- **CRDT proptests must not weaken.** C.1.1b consumes `merge_record` / `merge_block` directly. Push back on any change that requires the four proptests to weaken.
- **`SyncOutcome::ConcurrentDetected` is large** — variant carries `clippy::large_enum_variant` allow; one-per-call return so the box-allocation cost isn't worth it. Revisit if call sites multiply.
- **Block envelope payload held verbatim inside `VaultBundle`** — encrypted record material lives in memory until C.1.1b's prepare_merge decap. Callers must not hold `ConcurrentDetected` beyond one prepare/commit cycle. The bundle's `Zeroize + ZeroizeOnDrop` handles eventual cleanup.

### Issues currently open

- **[#37](https://github.com/hherb/secretary/issues/37)** — Sub-project C design discipline umbrella. C.1.1a closes partially (bundle + ingest layers).
- **[#38](https://github.com/hherb/secretary/issues/38)** — `save_block` proptest case-count budget; revisit when C.1.1b's vault-lifecycle decisions land.
- **[#45](https://github.com/hherb/secretary/issues/45)** — three `pub(crate) #[allow(dead_code)]` accessors on `OpenVaultManifest`; revisit when C-side consumers materialise (C.1.1b may consume them).
- **[#75](https://github.com/hherb/secretary/issues/75)** — replace `#[doc(hidden)] pub __test_dispatch` with `pub(crate)` + lib-internal tests.
- **[#76](https://github.com/hherb/secretary/issues/76)** — Python clean-room replay of `sync_kat.json`.
- **[#78](https://github.com/hherb/secretary/issues/78)** — C.1.1a integration-test gaps (second-vault fixtures + block re-signing helper).
- **[#79](https://github.com/hherb/secretary/issues/79)** — sync_kat.json ingestion vectors (Task 14 from the 1a plan).
- **[#81](https://github.com/hherb/secretary/issues/81)** — `MAX_BLOCK_FILE_SIZE = 16 MiB` undocumented vs format-max recipient table (pure docs).
- **#80 will close on PR merge.**

### Open PRs at close

- **fix/80-manifest-double-read** — pushed at the end of this session; PR number assigned on push. Closes #80.

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin
git status --short                                              # expect: clean
git worktree list

# If PR for #80 fix has not yet been merged — resume in the worktree to address review:
cd .worktrees/fix-80-manifest-double-read
pwd                                                             # confirm worktree
git branch --show-current                                       # → fix/80-manifest-double-read
git log --oneline -5
gh pr list --state open                                         # find PR#
gh pr view <PR#> --comments                                     # read review feedback

# Sanity-check gauntlet (expect stable at 713 / 0 / 10):
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:"
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3

# If #80 fix is merged — start C.1.1b on a fresh branch off main:
cd /Users/hherb/src/secretary
git checkout main
git pull origin main
git worktree remove .worktrees/fix-80-manifest-double-read     # cleanup
git worktree add .worktrees/c1-1b-sync-merge -b feature/c1-1b-sync-merge main
cd .worktrees/c1-1b-sync-merge

# Author the 1b implementation plan (use superpowers:writing-plans):
#   Inputs: docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md
#   Output: docs/superpowers/plans/<date>-c1-1b-sync-merge.md
# Then execute the plan with superpowers:subagent-driven-development.
```

## Closing inventory

- **Branch state on close:** `main` at `730505f` (PRs #77 + #82 already on main from prior). `fix/80-manifest-double-read` at the #80 fix commit (SHA assigned on push) + this baton commit.
- **Workspace tests on `fix/80-manifest-double-read`:** 713 passed + 10 ignored (= 712 baseline + 1 new regression test). Clippy clean. Fmt clean. Conformance PASS. Spec-name-freshness 96 resolved / 0 unresolved.
- **README.md:** unchanged this session (the #80 fix tightens implementation to match the existing surface contract).
- **ROADMAP.md:** unchanged this session (small follow-up PR; tracked in PR description, not the roadmap).
- **CLAUDE.md:** unchanged.
- **Open issues:** [#37](https://github.com/hherb/secretary/issues/37) / [#38](https://github.com/hherb/secretary/issues/38) / [#45](https://github.com/hherb/secretary/issues/45) / [#75](https://github.com/hherb/secretary/issues/75) / [#76](https://github.com/hherb/secretary/issues/76) / [#78](https://github.com/hherb/secretary/issues/78) / [#79](https://github.com/hherb/secretary/issues/79) / [#81](https://github.com/hherb/secretary/issues/81). #80 will close on PR merge.
- **Open PRs:** **fix/80-manifest-double-read** (this branch) — PR# assigned on push.
- **Worktrees on disk:** `main` + `.worktrees/fix-80-manifest-double-read`.
- **Frozen baton snapshot:** [`docs/handoffs/2026-05-18-2119-fix-80-manifest-double-read.md`](docs/handoffs/2026-05-18-2119-fix-80-manifest-double-read.md) — exact copy of this file for audit/learning.
