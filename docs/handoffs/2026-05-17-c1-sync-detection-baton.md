# NEXT_SESSION.md

**Session date:** 2026-05-17 (Option A — Sub-project C kickoff: brainstorm + C.1 spec + plan)
**Status:** Branch `feature/c1-sync-detection` **local-only** (not yet pushed; not yet a PR — implementation hasn't started). Spec at commit `ff05335`, plan at commit `8d685f0`. This baton ships as a third commit on the same branch per [`feedback_next_session_in_pr`](memory). When the implementation lands and the PR opens, the PR will carry all three docs plus the production code. Main is at `3809544` (post-PR-#73 merge); the gauntlet on main was re-verified this session: 642 cargo + 10 ignored / clippy clean / fmt OK / Python conformance PASS / freshness 96/0/2 / Swift smoke **38/38** / Kotlin smoke **39/39** / Swift conformance **22/22** / Kotlin conformance **22/22**.

## (1) What we shipped this session

No production code. Two design artifacts on the new feature branch — a spec and an implementation plan — produced through a full brainstorming session that resolved four substantive C.1 decisions (sync UX model, veto scope, API shape, merge phasing).

| SHA | Subject | Notes |
|---|---|---|
| `ff05335` | `docs(c1): design spec — sync rollback + fork detection (phase 1)` | Spec for the first slice of Sub-project C: pure-Rust `sync_once` free function classifying disk state vs. caller-persisted state into `NothingToDo` / `AppliedAutomatically` / `ForkDetected` / `RollbackRejected`. 345 lines at [`docs/superpowers/specs/2026-05-17-c1-sync-detection-design.md`](docs/superpowers/specs/2026-05-17-c1-sync-detection-design.md). |
| `8d685f0` | `docs(c1): implementation plan — 15 TDD tasks across 5 phases` | Bite-sized TDD plan at [`docs/superpowers/plans/2026-05-17-c1-sync-detection.md`](docs/superpowers/plans/2026-05-17-c1-sync-detection.md). Each task: failing test → minimal impl → run → commit, with exact code blocks and verification commands. |
| _(baton)_ | `docs: pre-implementation baton — C.1 spec + plan on feature/c1-sync-detection` | This file + its frozen handoff snapshot at [`docs/handoffs/2026-05-17-c1-sync-detection-baton.md`](docs/handoffs/2026-05-17-c1-sync-detection-baton.md). |

### Brainstorm decisions captured in the spec (D1-D4)

| # | Decision | Rationale |
|---|---|---|
| D1 | **Sync UX model — foreground-while-unlocked.** `sync_once` takes `&UnlockedIdentity` per call; identity lives in process memory only during the user's unlock window. No daemon, no background sync. | Matches ADR-0003 (mobile is foreground-only anyway) and the threat-model intent of minimising secret residence. |
| D2 | **Veto scope (for C.1.1) — peer-originated record tombstones only.** Field LWW overwrites and other merge outcomes apply silently per §11. Recorded but vacuous in C.1 because no automatic merge. | Protects against the most-regrettable silent loss (records the user is actively using disappearing) without prompt fatigue. |
| D3 | **API shape — free functions + caller-persisted `SyncState`.** No engine struct, no FSM. | Matches the existing free-`fn` style throughout `secretary-core` and the `feedback_pure_functions` preference. |
| D4 | **Merge scope phasing — detect-only C.1; merge + veto in C.1.1.** | Brick-by-brick per `feedback_stay_in_inner_loop`. First slice is ~500-800 LOC and validates the API shape before the merge complexity (VaultBundle / PendingMerge / commit_with_decisions) lands. |

### Open items in the spec — all resolved before the plan was written

| Item | Resolution |
|---|---|
| `SyncState` sorted/dedup invariant — constructor vs. decoder? | **Both.** Shared `validate_clock_canonical` helper used by `SyncState::new` and the CBOR decoder so a malformed input on either path produces `InvalidArgument`. |
| `Unlocker::Bundle` extension — same PR as `sync_once`, or pre-PR? | **Same PR.** The extension is small (one variant + one match arm); isolating it would create dead code in the interim. Plan Task 6. |
| `sync_kat.json` — populate in C.1 or empty-allocate for C.4? | **Populate with Rust-only replay this PR.** The JSON shape settles now; the Python clean-room implementation in C.4 has a frozen target to match. Plan Task 12 (9 vectors). |

### Gauntlet verified on main + worktree

Both at SHA `3809544`. Worktree has only the spec + plan + this baton committed — no Rust code touched.

| Check | Main result |
|---|---|
| `cargo test --release --workspace --no-fail-fast` | **642 passed; 0 failed; 10 ignored** |
| `cargo clippy --release --workspace --tests -- -D warnings` | clean |
| `cargo fmt --all -- --check` | OK |
| `uv run core/tests/python/conformance.py` | PASS |
| `uv run core/tests/python/spec_test_name_freshness.py` | 96 / 0 / 2 PASS |
| `bash ffi/secretary-ffi-uniffi/tests/swift/run.sh` | **38/38 PASS** |
| `bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh` | **39/39 PASS** |
| `bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh` | **22/22 PASS** |
| `bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh` | **22/22 PASS** |

### Housekeeping

The merged worktree for PR #73 was removed and the local branch `refactor/issue-72-split-smoke-runners` deleted. Three other local branches remain that look orphaned and were not triaged this session: `chore/b6-pre-v2-cleanup`, `pr-65-review`, `test/issue-35-save-block-mid-call-wipe-race`. The next session may want to verify they are merged-or-superseded and prune via `git branch -D`.

## (2) What's next

**Execute the C.1 implementation plan** at [`docs/superpowers/plans/2026-05-17-c1-sync-detection.md`](docs/superpowers/plans/2026-05-17-c1-sync-detection.md). 15 tasks across 5 phases, each producing a commit. Estimated 1-3 sessions depending on how cleanly the `Unlocker::Bundle` extension and the `sync_helpers::fresh_vault_with_clock` fixture land.

### Phases at a glance

| Phase | Tasks | What it produces |
|---|---|---|
| A — Foundation | 1-5 | `core/src/sync/` module tree, `SyncError`, `SyncState` with CBOR codec + invariant, `SyncOutcome` |
| B — Unlocker extension | 6 | `Unlocker::Bundle(&UnlockedIdentity)` variant; `open_vault` reuses caller's identity without re-running Argon2 |
| C — sync_once | 7-10 | The function itself, all four `ClockRelation` branches, error propagation |
| D — Properties + KAT | 11-12 | Proptest convergence/idempotence/disjoint-branch, 9-vector `sync_kat.json` + Rust replay |
| E — Polish | 13-15 | Clippy/fmt sweep, ROADMAP sentence, full gauntlet, push branch + open PR |

### Acceptance criteria (the gauntlet to clear before opening the PR)

- [ ] `cargo test --release --workspace` ≈ **672 passed, 0 failed, 10 ignored** (642 → 672, +~30 new tests across `core::sync` unit tests + `core/tests/sync.rs` + `core/tests/sync_proptest.rs` + `core/tests/sync_kat.rs`).
- [ ] `cargo clippy --release --workspace --tests -- -D warnings` — clean.
- [ ] `cargo fmt --all -- --check` — OK.
- [ ] `uv run core/tests/python/conformance.py` — PASS.
- [ ] `uv run core/tests/python/spec_test_name_freshness.py` — PASS (96+ resolved; the new sync test names should resolve cleanly via the docs/superpowers/specs/ citation in commit messages).
- [ ] Swift smoke / Kotlin smoke / Swift conformance / Kotlin conformance — all unchanged from main (38/38, 39/39, 22/22, 22/22). C.1 touches no FFI surface.
- [ ] No file in `core/src/sync/` exceeds 500 LOC (per `feedback_split_files_proactively`); design intentionally splits into 5 files, all small.
- [ ] Spec section "What `sync_once` deliberately does NOT do" still reads true after implementation — no disk writes, no merge, no conflict-copy ingestion.

### Plan corrections already applied during self-review

During the plan's spec-vs-code self-review pass, four code-actual discrepancies were spotted and corrected inline in the plan file:

- `VaultError::FolderInvalid` does not exist → Task 2 uses `OwnerUuidMismatch` to certify the `#[from]` fold.
- `OpenVault.manifest_body()` is not an accessor → it's a public field `manifest: Manifest`; Task 6 and 7 use the field directly.
- `golden_vault_001/password.bytes` does not exist → password is in the sibling `golden_vault_001_inputs.json` file; Task 7's `fixtures/mod.rs` deserialises that.
- `VaultTomlError` does not impl `Into<VaultError>` directly → folds via `UnlockError::MalformedVaultToml(#[from])` then `VaultError::Unlock(#[from])`; Task 7's `sync_once` does the double `into()` in one closure.

The plan's "Self-review checklist" at the bottom captures the spec → tasks mapping.

## (3) Open decisions and risks

### Open items in the plan (intentional implementation-handoff markers)

- **Task 9 Step 1 has two `todo!()` macros** in `core/tests/sync_helpers/mod.rs`: `recursive_copy` and `rewrite_manifest_clock`. Step 3 explicitly says to replace both with concrete implementations. The Swift/Kotlin smoke runners' `_freshWritableVault` helpers are the reference pattern; the Rust port should use `core::vault::orchestrators::save_block` or the manifest re-sign helpers directly. The cheapest path is acceptable — the helper only exists to set up tests, not as production surface.

### Risks

- **`UnlockedIdentity` and `IdentityBundle` `Clone` derives.** Plan Task 6 Step 6 adds `#[derive(Clone)]` to `UnlockedIdentity`. If `IdentityBundle` doesn't already derive `Clone`, that needs to be added too. The custom redacting `Debug` impl on `UnlockedIdentity` is preserved (no semantic change). Risk: if `IdentityBundle` carries a non-`Clone` field, this requires more surgery than the plan implies. **Mitigation:** plan Task 6 Step 6 explicitly says to inspect `core/src/identity/bundle.rs` first; if a non-`Clone` field is present, the implementer revises the plan.
- **`Unlocker::Bundle` arm clones the bundle.** Each `sync_once` call clones the `UnlockedIdentity` (and its `Sensitive<[u8;32]>` IBK + the `IdentityBundle`'s secret keys). The clones are zeroize-on-drop, but the peak memory residence doubles during the call. Acceptable for v1; if profiling shows it matters, refactor `open_vault` to take `&UnlockedIdentity` through the body and avoid the clone. **Not blocking C.1.**
- **`__test_dispatch` is `#[doc(hidden)] pub`.** Per [`project_secretary_cfg_test_not_propagated`](memory), this is the established cross-target test-hook pattern. The hook is excluded from rendered docs but appears in the lib's public ABI. A future audit may want to seal it under a feature flag like `test-internals` if multiple such hooks accumulate; not worth doing for one.

### Issues still open from prior sessions (not actionable yet)

- **Issue [#37](https://github.com/hherb/secretary/issues/37)** — design discipline reminder for Sub-project C; partially addressed by this C.1 spec but the umbrella issue stays open for C.1.1 / C.2 / C.3 / C.4.
- **Issue [#38](https://github.com/hherb/secretary/issues/38)** — `save_block` proptest case-count budget (shared writable-vault fixture); design space depends on C.1.1's vault-lifecycle decisions.
- **Issue [#45](https://github.com/hherb/secretary/issues/45)** — three `pub(crate) #[allow(dead_code)]` accessors on `OpenVaultManifest`; revisit when C-side consumers materialise (some via the bridge, not within C.1 itself).

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary/.worktrees/c1-sync-detection
git checkout feature/c1-sync-detection                   # should already be on this
git status --short                                       # expect: clean
git log --oneline -5                                     # expect: baton, 8d685f0 plan, ff05335 spec, then main HEAD
pwd && git branch --show-current && git worktree list    # working-directory discipline check

# Pre-flight: re-verify the baseline gauntlet matches this session's closing numbers.
cargo test --release --workspace --no-fail-fast > /tmp/c1-baseline.log 2>&1
grep -E "^test result:" /tmp/c1-baseline.log | awk '{
  for (i=1; i<=NF; i++) {
    if ($i == "passed;") p += $(i-1)
    if ($i == "failed;") f += $(i-1)
    if ($i == "ignored;") ig += $(i-1)
  }
}
END { printf("TOTAL: %d passed; %d failed; %d ignored\n", p, f, ig) }'
# Expect: TOTAL: 642 passed; 0 failed; 10 ignored

# Start the implementation plan:
$EDITOR docs/superpowers/plans/2026-05-17-c1-sync-detection.md
# Begin at "Phase A — Module scaffolding and data types" / Task 1.
# Each task: write the failing test, run, implement, run, commit. Don't batch.

# When all 15 tasks land green, push + open PR per Task 15 Step 5.

# If a fresh session needs to verify it's still on the right branch:
git remote -v 2>&1 | head -3                             # confirms origin url
git log --oneline main..HEAD                             # expect: 3 commits ahead (spec, plan, baton)
```

### If the prior `refactor-issue-72-split-smoke-runners` worktree is somehow back

This session removed `.worktrees/refactor-issue-72-split-smoke-runners` and deleted the local branch `refactor/issue-72-split-smoke-runners`. If it re-appears, that's a parallel-session artefact; safe to re-remove since the work landed as squash-merge `3809544`.

```bash
git worktree remove .worktrees/refactor-issue-72-split-smoke-runners 2>/dev/null
git branch -D refactor/issue-72-split-smoke-runners 2>/dev/null
```

### Optional housekeeping deferred from this session

Three other local branches exist that may be orphaned. The next session may want to triage:

```bash
git branch -a                                            # inventory
git log --oneline main..chore/b6-pre-v2-cleanup          # check if already merged
git log --oneline main..pr-65-review                     # check if already merged
git log --oneline main..test/issue-35-save-block-mid-call-wipe-race  # check
# If a branch is fully ancestral to main, safe to `git branch -D <name>`.
```

---

## Closing inventory

- **Branch state on close:** `feature/c1-sync-detection` at the baton commit (third commit on the branch; pushed only after the implementation lands).
- **Workspace tests:** 642 cargo + 10 ignored, unchanged across this session (no Rust touched).
- **README:** unchanged.
- **ROADMAP:** unchanged this session; C.1's "phase 1 landed" sentence is added by Task 14 of the plan once the implementation PR is open.
- **CLAUDE.md:** unchanged.
- **Files created this session:**
  - `docs/superpowers/specs/2026-05-17-c1-sync-detection-design.md` (345 lines, on feature branch)
  - `docs/superpowers/plans/2026-05-17-c1-sync-detection.md` (2341 lines, on feature branch)
  - `NEXT_SESSION.md` (this file, on feature branch — overwriting the prior post-PR-#73 baton)
  - `docs/handoffs/2026-05-17-c1-sync-detection-baton.md` (frozen snapshot of this file)
- **Files modified this session:** none in production code.
- **Issues open at session close:** [#37](https://github.com/hherb/secretary/issues/37), [#38](https://github.com/hherb/secretary/issues/38), [#45](https://github.com/hherb/secretary/issues/45) (all multi-C-phase; C.1 spec addresses #37 partially, the umbrella stays open).
- **Open PRs:** none from this session. The next PR will be the C.1 implementation once the plan is executed.
