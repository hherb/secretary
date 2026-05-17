# NEXT_SESSION.md

**Session date:** 2026-05-17 (C.1 phase 1 sync detection — implementation landed; PR opening on this branch)
**Status:** `feature/c1-sync-detection` branch carries the full C.1 implementation, ready to open as a PR. The 15-task plan executed cleanly through all five phases; gauntlet matches the plan's acceptance criteria. Pre-implementation baton (PR-less docs commit at `7b8ab6e`) is preserved below; this file overwrites it now that the implementation is on the same branch.

## (1) What we shipped this session

| SHA | Subject |
|---|---|
| `b71cbdc` | docs(readme): record C.1 phase 1 (sync detection) on the status table |
| `7d26da3` | docs(roadmap): record C.1 phase 1 (sync detection) as landed |
| `f41ffca` | chore(c1): cargo fmt sweep for the sync module |
| `88ecf34` | test(c1): sync_kat.json — 9-vector dispatch KAT + Rust replay |
| `3c3a27a` | test(c1): proptest properties — idempotence + applied-then-nothing + disjoint branches |
| `e6420b7` | test(c1): error propagation paths for sync_once |
| `81ce5dc` | test(c1): end-to-end sync_once coverage via fresh_vault_with_clock helper |
| `18f3aee` | test(c1): dispatch branch coverage for all four ClockRelation outcomes |
| `019e34c` | feat(c1): sync_once skeleton with vault.toml UUID cross-check |
| `9b5c110` | feat(c1): refactor open_vault → extract read_and_verify_manifest + add read_vault_manifest |
| `fd934b4` | feat(c1): SyncOutcome and RollbackEvidence types |
| `541e50b` | feat(c1): SyncState canonical CBOR encode/decode |
| `0441b6d` | feat(c1): SyncState type with sorted/deduped clock invariant |
| `9a2eb81` | feat(c1): SyncError enum with 6 typed variants |
| `dc8df18` | feat(c1): scaffold core::sync module skeleton |
| `7b8ab6e` | docs: pre-implementation baton — C.1 spec + plan on feature/c1-sync-detection |
| `8d685f0` | docs(c1): implementation plan — 15 TDD tasks across 5 phases |
| `ff05335` | docs(c1): design spec — sync rollback + fork detection (phase 1) |

### What's new under the hood

- **`core::sync::sync_once(folder, &UnlockedIdentity, &SyncState, now_ms)`** — pure-function reconcile of one vault folder against caller-persisted state. Dispatches `ClockRelation` between the disk manifest's vector clock and the caller's `highest_vector_clock_seen` to one of `SyncOutcome::{NothingToDo, AppliedAutomatically { new_state }, ForkDetected, RollbackRejected}`. No disk writes, no merge — phase 1 is detection only.
- **`core::sync::SyncState`** — caller-persisted `(vault_uuid, highest_vector_clock_seen)` value. Sorted/deduped clock invariant enforced symmetrically by `SyncState::new` and the `from_canonical_cbor` decoder via a shared `validate_clock_canonical` helper. Canonical-CBOR encode/decode uses the same `core::vault::canonical::{encode_canonical_map, canonical_sort_entries}` helpers Manifest/Record/Card use — no parallel CBOR layer.
- **`core::sync::SyncOutcome` + `RollbackEvidence`** — 4-variant typed enum mapping `clock_relation` outputs onto §10 terminal states. `RollbackEvidence` surfaces both the disk and local clocks so a caller's "restoring from backup, accept anyway" UX can render the divergence.
- **`core::sync::SyncError`** — 6 typed variants: `VaultUuidMismatch`, `StateDecodeFailed`, `StateEncodeFailed`, `Vault(#[from] VaultError)`, `Io { context, source }`, `InvalidArgument`. Anti-conflation discipline preserved at the umbrella surface.
- **`core::vault::read_vault_manifest(folder, &UnlockedIdentity, local_highest_clock)`** — new public entry point. Reads/verifies/decrypts the manifest body using a caller-held identity, returns just the `Manifest`. Used by `sync_once` so a poll runs in milliseconds (file read + signature verify + AEAD decrypt), no Argon2. Built by extracting a private `read_and_verify_manifest` helper from `open_vault` — both share the §1 read-order steps 3-8 logic bit-for-bit, so the 642 existing tests pass byte-identically.
- **Pivot from `Unlocker::Bundle(&UnlockedIdentity)`** — the plan's original approach would have required cloning `IdentityBundle`, which deliberately does NOT derive Clone (cloning would silently duplicate secret material per the bundle's struct docstring safety policy). The `read_vault_manifest` parallel-entry-point design respects that policy.

### Test additions: 40 new tests on top of the 642 baseline

| Layer | Count | Files |
|---|---|---|
| `core::sync::error` unit tests | 6 | inline in `core/src/sync/error.rs` |
| `core::sync::state` invariant unit tests | 5 | inline in `core/src/sync/state.rs` |
| `core::sync::state::cbor_tests` | 7 | inline in `core/src/sync/state.rs` |
| `core::sync::outcome` unit tests | 3 | inline in `core/src/sync/outcome.rs` |
| `read_vault_manifest` integration | 2 | `core/tests/read_vault_manifest.rs` |
| `sync_once` UUID-mismatch + 6 dispatch + 4 end-to-end + 2 error propagation | 13 | `core/tests/sync.rs` |
| `sync_proptest` (256 cases each) | 3 | `core/tests/sync_proptest.rs` |
| `sync_kat` replay (9 vectors via one `#[test]`) | 1 | `core/tests/sync_kat.rs` |

### Gauntlet on close

| Check | Result |
|---|---|
| `cargo test --release --workspace --no-fail-fast` | **682 passed; 0 failed; 10 ignored** (642 → 682) |
| `cargo clippy --release --workspace --tests -- -D warnings` | clean |
| `cargo fmt --all -- --check` | OK |
| `uv run core/tests/python/conformance.py` | PASS |
| `uv run core/tests/python/spec_test_name_freshness.py` | 96 resolved / 0 unresolved / 2 allowlisted |
| `bash ffi/secretary-ffi-uniffi/tests/swift/run.sh` | **38/38 PASS** |
| `bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh` | **39/39 PASS** |
| `bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh` | **22/22 PASS** |
| `bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh` | **22/22 PASS** |

All FFI runners unchanged from main — C.1 touches no FFI surface.

### Files created/modified

**New files:**
- `core/src/sync/{mod,error,state,outcome,once}.rs` — the C.1 module (5 files, all under 500 LOC; largest is `state.rs` at ~370 LOC including its 12 unit/CBOR tests).
- `core/tests/fixtures/mod.rs` — shared `golden_vault_001_password()` helper.
- `core/tests/sync_helpers/mod.rs` — `fresh_vault_with_clock` test fixture (recursive_copy + manifest re-sign with caller-supplied vector clock).
- `core/tests/sync.rs` — 13 integration tests covering sync_once end-to-end and via `__test_dispatch`.
- `core/tests/sync_proptest.rs` — 3 proptest properties (256 cases each).
- `core/tests/sync_kat.rs` + `core/tests/data/sync_kat.json` — 9-vector dispatch KAT.
- `core/tests/read_vault_manifest.rs` — 2 integration tests pinning the new entry point matches `open_vault`'s manifest body field-for-field.

**Modified files:**
- `core/src/lib.rs` — `pub mod sync;`
- `core/src/vault/mod.rs` — re-export `read_vault_manifest`.
- `core/src/vault/orchestrators.rs` — refactor `open_vault` to call a new private `read_and_verify_manifest` helper; add public `read_vault_manifest`.
- `README.md` — Sub-project C status line updated to reflect C.1 phase 1 ✅.
- `ROADMAP.md` — added C.1 phase 1 sentence + bumped Sub-project C progress bar from all-dashes to a partial fill.

## (2) What's next

### C.1.1 — sync_once extension: automatic merge + veto-on-tombstone

The `ForkDetected` branch currently returns evidence and stops. C.1.1 will:

1. **Read disk blocks** for the records the disk-side has but local doesn't (and vice versa) — needs a `VaultBundle`-like read that reads ALL blocks, not just the manifest. New entry point `read_vault_bundle(folder, &UnlockedIdentity)` or extension to `read_vault_manifest`.
2. **Apply automatic CRDT merge** — existing `core::vault::conflict::{merge_record, merge_block}` primitives. Detect peer-originated tombstones on records the local side still considers live → surface as `PendingMerge { user_vetoes_needed: Vec<RecordTombstoneVeto> }`.
3. **`commit_with_decisions`** — caller resolves each veto (`Accept` / `Reject` / `Override`) and calls back to commit the merged state, which atomically rewrites blocks + manifest and yields a new `SyncState`.

Acceptance criteria (proposed for C.1.1's plan):
- [ ] New `SyncOutcome::PendingMerge { vetoes, decisions_required, draft_state }` variant; existing `ForkDetected` becomes the no-conflicts subset (where `vetoes.is_empty()`).
- [ ] `commit_with_decisions(folder, &UnlockedIdentity, draft_state, decisions, now_ms) -> Result<SyncState, SyncError>` atomically writes the merged vault and returns the new caller-persistable state.
- [ ] `core::sync::conflict::tombstone_veto_set(local, disk) -> Vec<RecordTombstoneVeto>` — pure helper; proptest-pinned that it returns only records the local side still considers live AND the disk side considers tombstoned.
- [ ] `sync_kat.json` grows from 9 → ~15 vectors covering the new merge-with-vetoes paths.
- [ ] No FFI surface change (still core-only); B-side projection follows in C.3.

### C.2 — Headless `secretary sync` CLI (desktop)

Wraps `sync_once` + the `notify` crate (file watcher) + the OS keystore. Two-instance tests run two CLIs against a shared temp directory and assert convergence. This is shippable software for technical users with NAS deployments.

Risks/decisions for the next planning session:
- Where does `SyncState` live? OS keychain (macOS), libsecret (Linux), Credential Manager (Windows) — likely the `keyring` crate. CLI also accepts `--state-file <path>` for portable installs.
- File-watcher debounce policy: how do we coalesce multi-file mtime bursts from a cloud client without missing genuine changes? Probably a 250 ms quiet-window.

## (3) Open decisions and risks

### Plan revision notes from this session

- **Original Task 6 (`Unlocker::Bundle(&UnlockedIdentity)`) was pivoted** to a parallel-entry-point design (`read_vault_manifest` + private `read_and_verify_manifest` helper). The plan correctly flagged this risk in its "Open decisions and risks" section: "if a non-Clone field is present, the implementer revises the plan." `IdentityBundle`'s no-Clone safety policy is the reason. The pivot:
  - Doesn't violate the no-Clone policy.
  - Doesn't duplicate security-critical code (helper is shared).
  - Doesn't change `open_vault`'s public signature (642 existing tests pass byte-identically).
  - Gives `sync_once` a narrower, purpose-built API.
- **No `Unlocker::Bundle` variant exists.** A future caller that wants both unlock-and-open with a pre-held identity should use `read_vault_manifest` (manifest-only) or — when C.1.1 adds `read_vault_bundle` — that future entry point. The original spec doc says `Unlocker::Bundle` will be added; treat the spec as the wishful-thinking artefact in this one detail. The README + ROADMAP are correct.
- **`SyncState` requires `serde` on the dev-deps**, already present. No new dependencies were added.

### Risks for future C.1.1 work

- **Pre-merge state shape.** C.1.1's `SyncOutcome::PendingMerge` needs to round-trip via CBOR too (for resume-after-app-crash scenarios). The draft_state probably needs to be cap-CBOR-encodable and indexed by veto-decision ID. Worth a brainstorming session before the spec.
- **`fresh_vault_with_clock` test helper** uses a deterministic AEAD nonce constant. Each test gets a unique vault in its own tempdir, so the key-nonce reuse risk is bounded to test code. If C.1.1 tests need multiple-rewrites-per-test (e.g. for a "sync detects, user vetoes, sync converges" sequence), refactor the helper to take a per-call nonce or generate one via `getrandom`.

### Issues still open from prior sessions

- **Issue [#37](https://github.com/hherb/secretary/issues/37)** — design discipline reminder for Sub-project C; C.1 phase 1 partially addresses it but the umbrella stays open for C.1.1 / C.2 / C.3 / C.4.
- **Issue [#38](https://github.com/hherb/secretary/issues/38)** — `save_block` proptest case-count budget; design space depends on C.1.1's vault-lifecycle decisions.
- **Issue [#45](https://github.com/hherb/secretary/issues/45)** — three `pub(crate) #[allow(dead_code)]` accessors on `OpenVaultManifest`; revisit when C-side consumers materialise via the bridge.

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin

# Worktree is still around if this session didn't clean it up:
ls .worktrees/c1-sync-detection 2>/dev/null && cd .worktrees/c1-sync-detection

# Otherwise re-create from origin (the branch will have a PR open after this session):
[ ! -d .worktrees/c1-sync-detection ] && \
  git worktree add .worktrees/c1-sync-detection feature/c1-sync-detection && \
  cd .worktrees/c1-sync-detection

git checkout feature/c1-sync-detection
git pull --ff-only origin feature/c1-sync-detection 2>&1 | tail -3
git status --short                                       # expect: clean
git log --oneline main..HEAD                             # 18 commits ahead — 3 docs + 15 implementation

# Verify the gauntlet still matches close numbers (682 / 0 / 10):
cargo test --release --workspace --no-fail-fast > /tmp/c1-resume.log 2>&1
grep -E "^test result:" /tmp/c1-resume.log | awk '{
  for (i=1; i<=NF; i++) {
    if ($i == "passed;") p += $(i-1)
    if ($i == "failed;") f += $(i-1)
    if ($i == "ignored;") ig += $(i-1)
  }
}
END { printf("TOTAL: %d passed; %d failed; %d ignored\n", p, f, ig) }'

# To begin C.1.1 in a new branch, branch from main (NOT from this branch's HEAD —
# wait for the PR to merge first):
# git checkout main && git pull --ff-only origin main
# git worktree add .worktrees/c1-1-sync-merge feature/c1-1-sync-merge -b feature/c1-1-sync-merge
```

### Optional housekeeping deferred from this session

Three local branches exist that may be orphaned. Next session may want to triage:

```bash
git branch -a
git log --oneline main..chore/b6-pre-v2-cleanup
git log --oneline main..pr-65-review
git log --oneline main..test/issue-35-save-block-mid-call-wipe-race
# If a branch is fully ancestral to main, safe to `git branch -D <name>`.
```

---

## Closing inventory

- **Branch state on close:** `feature/c1-sync-detection` at `b71cbdc` (or this baton commit's SHA after this commit lands), 18 commits ahead of main. PR opens via `gh pr create` after this baton commit.
- **Workspace tests:** **682 passed + 10 ignored** under `cargo test --release --workspace` (642 → 682, +40 across SyncError / SyncState / SyncOutcome / sync_once unit + integration + proptest + KAT).
- **README:** Sub-project C status line updated to reflect C.1 phase 1 ✅.
- **ROADMAP:** C.1 phase 1 sentence added under Sub-project C; progress bar bumped from all-dashes to partial fill.
- **CLAUDE.md:** unchanged.
- **Issues open at session close:** [#37](https://github.com/hherb/secretary/issues/37) / [#38](https://github.com/hherb/secretary/issues/38) / [#45](https://github.com/hherb/secretary/issues/45) (all multi-C-phase; C.1 partially addresses #37).
- **Open PRs:** one new — `feature/c1-sync-detection` to be opened against `main` after this commit lands.
- **Frozen baton snapshot:** [`docs/handoffs/2026-05-17-c1-sync-detection-implementation.md`](docs/handoffs/2026-05-17-c1-sync-detection-implementation.md) — exact copy of this file for audit/learning.
