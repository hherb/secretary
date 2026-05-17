# NEXT_SESSION.md

**Session date:** 2026-05-17 (Option A — close issue #69)
**Status:** PR [#70](https://github.com/hherb/secretary/pull/70) **open** on branch `test/issue-69-kat-vectors` at commit `6e1414d`. Closes issue [#69](https://github.com/hherb/secretary/issues/69) on merge. Two non-blocking follow-ups remain across the B.6 v2 design arc: [#67](https://github.com/hherb/secretary/issues/67) (split 500-LOC helper files) and the C-blocked items [#37](https://github.com/hherb/secretary/issues/37) / [#38](https://github.com/hherb/secretary/issues/38) / [#45](https://github.com/hherb/secretary/issues/45). Gauntlet on this branch green: 642 cargo + 10 ignored / clippy clean / fmt OK / Python conformance PASS / freshness 96/0/2 / Swift conformance **22/22** / Kotlin conformance **22/22**.

## (1) What we shipped this session

PR [#70](https://github.com/hherb/secretary/pull/70) on branch `test/issue-69-kat-vectors`. One feature commit + this baton commit (added separately so the live baton rides inside the PR per [`feedback_next_session_in_pr`](memory)).

| SHA | Subject | Notes |
|---|---|---|
| `6e1414d` | `test(conformance-kat): add 2 missing error-path vectors (closes #69)` | Adds `restore_block_already_live` + `save_block_invalid_record_uuid` to the conformance KAT (20 → 22 vectors). Updates Swift + Kotlin `blockInputFromInputs` to accept `record_uuid_bytes_hex` so wrong-length record_uuid passes through to uniffi's `convert_record_input`, which surfaces `VaultException.InvalidArgument` symmetrically with the existing `device_uuid_bytes_hex` pattern. ROADMAP §B.6-paragraph counts updated 20 → 22. |
| `<TBD>` | `docs: pre-merge baton — issue #69 KAT vectors (PR #70 open)` | This file + its frozen handoff snapshot at [`docs/handoffs/2026-05-17-issue-69-kat-vectors.md`](docs/handoffs/2026-05-17-issue-69-kat-vectors.md). |

### Vector summary

| Vector | After | Inputs | Expected |
|---|---|---|---|
| `restore_block_already_live` | `restore_block_not_in_trash` | block_uuid `abababab…` (currently live), device_uuid `070707…`, now_ms `1715000007000` | `Err Vault(BlockUuidAlreadyLive)` |
| `save_block_invalid_record_uuid` | `open_writable_happy` | valid block_uuid + device_uuid, records[0].record_uuid_bytes_hex `"cd"` (1 byte) | `Err Vault(InvalidArgument)` |

### Cross-runner symmetry achieved

- **Rust**: dispatch already synthesized `InvalidArgument` for wrong-length `record_uuid` via the post-PR-#66 `uuid_from_inputs` helper in [`core/tests/conformance_kat_helpers/dispatch.rs:255-260`](core/tests/conformance_kat_helpers/dispatch.rs#L255-L260). No change needed.
- **Swift**: [`conformance.swift::blockInputFromInputs`](ffi/secretary-ffi-uniffi/tests/swift/conformance.swift) now falls back from `record_uuid_hex` to `record_uuid_bytes_hex` (force-cast nil on missing key was the trap that surfaced as `BPT 5` during initial replay against the new vector).
- **Kotlin**: same change in [`Conformance.kt::blockInputFromInputs`](ffi/secretary-ffi-uniffi/tests/kotlin/Conformance.kt).
- **uniffi binding layer** (unchanged): [`namespace.rs::convert_record_input`](ffi/secretary-ffi-uniffi/src/namespace.rs#L406) already calls `uuid_from_vec` on each record_uuid; surfaces `VaultError::InvalidArgument` on length mismatch — the surface this vector pins.

### Gauntlet verified on this branch

| Check | Result |
|---|---|
| `cargo test --release --workspace --no-fail-fast` | **642 passed; 0 failed; 10 ignored** (unchanged from `main`; `replay_conformance_kat` iterates all 22 vectors internally) |
| `cargo clippy --release --workspace --tests -- -D warnings` | clean |
| `cargo fmt --all -- --check` | OK |
| `uv run core/tests/python/conformance.py` | PASS |
| `uv run core/tests/python/spec_test_name_freshness.py` | 96 / 0 / 2 PASS |
| `bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh` | **22/22 PASS** |
| `bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh` | **22/22 PASS** |
| `cargo test --release --workspace --test conformance_kat -- --ignored generate_conformance_kat --nocapture` | idempotent (only re-touches `read_block_happy.records` + `save_block_insert_happy.post_state` placeholders — the two new vectors are entirely hand-pinned) |

### Issues opened and closed via PR #70

| Issue | Title | State on close of this session |
|---|---|---|
| [#69](https://github.com/hherb/secretary/issues/69) | Add KAT vectors for `BlockUuidAlreadyLive` + wrong-length `record_uuid` | **CLOSED on merge of PR #70** |

## (2) What's next

Three viable directions, in roughly increasing scope. Pick one to open the next session.

### Option A (small, ~1 session) — Close issue #67: split conformance KAT helper files

Three files past the 500-LOC threshold:
- `core/tests/conformance_kat_helpers/dispatch.rs` (~572 lines, ROADMAP-side unchanged by #69) → split by op family (`open.rs`, `read_block.rs`, `lifecycle.rs`, `assertions.rs`, `inputs.rs`).
- `ffi/secretary-ffi-uniffi/tests/swift/conformance.swift` (now ~774 lines after #69, was 766) → split via Swift file-level extension or per-op file pattern (constrained by the `swiftc` invocation in `run_conformance.sh`).
- `ffi/secretary-ffi-uniffi/tests/kotlin/Conformance.kt` (now ~889 lines after #69, was 880) → split via Kotlin file-per-concept (driver entry, dispatch, assertions, helpers).

**Acceptance criteria:**
- Each resulting file ≤ ~500 lines; one concept per file per [CLAUDE.md](CLAUDE.md) guidance and [`feedback_split_files_proactively`](memory).
- No semantic change: gauntlet stays at 642+10, Swift+Kotlin still 22/22.
- Each binding's host-runner shell script (`run_conformance.sh`) loads the new file list without warnings.
- PR closes #67.

### Option B (large, multi-session) — Sub-project C kickoff: sync orchestration

B.6 design arc is now fully closed (v1 KAT, v2 lifecycle KAT, both error-path follow-ups). Next forward-progress is Sub-project C. **No code yet** — start with `/brainstorm` against the C scope. Open questions to surface before any design doc (carried forward from the prior baton):

- **Conflict-detection trigger.** File watcher (inotify/FSEvents/ReadDirectoryChangesW) vs. poll vs. event-driven via cloud-folder webhooks vs. on-demand?
- **Orchestrator location.** In-process per platform UI, or a separate daemon (per platform OS-conventions)?
- **Conflict-resolution UI surface.** CRDT auto-merge per [`core/src/vault/conflict.rs`](core/src/vault/conflict.rs) handles the vast majority; the C design needs to decide what surfaces to the user for the residual.
- **Sync FSM granularity.** Per-block, per-vault, or per-folder?
- **Authentication boundary.** Does the orchestrator hold an unlocked identity, or does each operation re-unlock?

Per [`feedback_stay_in_inner_loop`](memory) — this is intentionally a brainstorm-first, brick-by-brick path, not an autonomous pipeline.

### Option C (optional B.6 extension, ~½ session) — PyO3 conformance runner

Round out the three-language parity contract to four by adding a Python host runner that loads `conformance_kat.json` and drives the PyO3 binding pipeline. The JSON format is binding-agnostic; the structural work is mirroring `blockInputFromInputs` / dispatch logic in Python. Not currently filed as an issue. Lowest-priority forward direction since the existing three-runner contract already establishes cross-language parity.

**Recommendation:** Option A (closes the last B.6-arc follow-up, ends a complete sub-project chapter, low risk, no new design). Then Option B (Sub-project C) on a fresh head, with the helper files in tidy shape for the new chapter.

## (3) Open decisions and risks

### Open decisions (carried forward, not yet actionable)

- **Sub-project C scope.** No design doc exists. The session that opens C needs to start with brainstorming, not coding. See Option B above.
- **PyO3 conformance runner.** Optional B.6 extension — see Option C above; not blocking.

### Risks (unchanged from prior session, restated for context)

- **Test-state coupling across v2 vectors.** All 9 lifecycle vectors (8 from v2 + the new `restore_block_already_live`) chain via `after:` against ONE writable-vault copy. A failure in `save_block_insert_happy` cascades downstream. Mitigation is in place (per-vector PASS lines + sub-check counts attribute failures clearly); the `find_cache_ancestor_name` walker tolerates missing intermediate cache entries. v3 could split into independent per-op chains if cascade-attribution friction grows.
- **Future `Operation` enum variants need dispatch arms in all three runners.** Rust's exhaustive `match` catches missed Rust arms at compile time. Swift's `switch` with `default:` and Kotlin's `when {}` with `else ->` silently fall to the default branch (marks vector as failed, but doesn't tell the author "you forgot to add a case"). Acceptable at three runners; revisit if more bindings appear.
- **Baton inaccuracy caught during this session.** The post-merge baton claimed `0a5249e` had made `record_uuid` synthesis "symmetric across all three runners" — only the Rust side carried the symmetry; Swift + Kotlin runners had `as! String` / `getString` hard casts on `record_uuid_hex` that would crash on the new vector. This PR closes that gap. No durable risk; flagged here so a future audit doesn't trust the prior baton's symmetry claim retroactively (the symmetry claim is now true, after this PR).

### Issues still open from prior sessions (not actionable this round)

- **Issue [#37](https://github.com/hherb/secretary/issues/37)** — design discipline reminder for Sub-project C; resolves when C design doc lands.
- **Issue [#38](https://github.com/hherb/secretary/issues/38)** — `save_block` proptest case-count budget (shared writable-vault fixture); design space depends on C's vault-lifecycle decisions.
- **Issue [#45](https://github.com/hherb/secretary/issues/45)** — three `pub(crate) #[allow(dead_code)]` accessors on `OpenVaultManifest`; revisit when C consumers materialize.
- **Issue [#67](https://github.com/hherb/secretary/issues/67)** — split conformance KAT helper files (B.6 v2 review follow-up); see Option A.

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin

# If PR #70 has merged:
git checkout main
git pull --ff-only origin main
git worktree remove .worktrees/test-issue-69-kat-vectors 2>/dev/null || true
git branch -D test/issue-69-kat-vectors 2>/dev/null || true

# Otherwise (PR still open) — pick up review feedback on the branch:
cd /Users/hherb/src/secretary/.worktrees/test-issue-69-kat-vectors
git checkout test/issue-69-kat-vectors
git pull --ff-only origin test/issue-69-kat-vectors
git status --short                                     # expect: clean

# Verify the gauntlet still matches this session's closing numbers:
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{
  for (i=1; i<=NF; i++) {
    if ($i == "passed;") p += $(i-1)
    if ($i == "failed;") f += $(i-1)
    if ($i == "ignored;") ig += $(i-1)
  }
}
END { printf("TOTAL: %d passed; %d failed; %d ignored\n", p, f, ig) }'
# Expect: TOTAL: 642 passed; 0 failed; 10 ignored

cargo clippy --release --workspace --tests -- -D warnings    # Expect: clean
cargo fmt --all -- --check                                   # Expect: OK
uv run core/tests/python/conformance.py                      # Expect: PASS
uv run core/tests/python/spec_test_name_freshness.py         # Expect: PASS (96 / 0 / 2)

bash ffi/secretary-ffi-uniffi/tests/swift/run.sh             # Expect: OK; ~37 PASS asserts
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh # Expect: 22/22 PASS
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh            # Expect: OK; ~37 PASS asserts
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh # Expect: 22/22 PASS

# Pick a forward-progress chunk (see §2 above):
#   Option A (small):  /brainstorm "issue #67 — split 500-LOC conformance KAT helper files"
#   Option B (large):  /brainstorm "Sub-project C — sync orchestration scope"
#   Option C (½ sess): /brainstorm "PyO3 conformance runner for B.6 KAT"
# Or scan the open backlog:
gh issue list --state open
```

---

## Closing inventory

- **Branch state on close:** `test/issue-69-kat-vectors` at `6e1414d` + the baton commit (`<TBD>`) pushed to `origin`. PR #70 open. No untracked files outside the worktree.
- **Workspace tests:** **642 cargo + 10 ignored**, unchanged across this PR (the KAT generator + replay are one `#[test]` + one `#[ignore]` regardless of vector count).
- **Per-binding conformance counts:** Swift `22/22 PASS`, Kotlin `22/22 PASS`, Rust `replay_conformance_kat ... ok`.
- **README:** unchanged — no specific KAT counts surfaced there; the high-level B.6 line at §144 still reads true.
- **ROADMAP:** B.6-paragraph counts bumped 20 → 22 + brief description of the two new vectors added in the same paragraph at line 34.
- **CLAUDE.md:** unchanged.
- **Files created this session:** [`NEXT_SESSION.md`](NEXT_SESSION.md) (overwritten); [`docs/handoffs/2026-05-17-issue-69-kat-vectors.md`](docs/handoffs/2026-05-17-issue-69-kat-vectors.md) (frozen snapshot of this file).
- **Files modified this session:** [`core/tests/data/conformance_kat.json`](core/tests/data/conformance_kat.json), [`ffi/secretary-ffi-uniffi/tests/swift/conformance.swift`](ffi/secretary-ffi-uniffi/tests/swift/conformance.swift), [`ffi/secretary-ffi-uniffi/tests/kotlin/Conformance.kt`](ffi/secretary-ffi-uniffi/tests/kotlin/Conformance.kt), [`ROADMAP.md`](ROADMAP.md).
- **Issues open at session close:** [#67](https://github.com/hherb/secretary/issues/67) (next likely target, see §2 Option A); [#37](https://github.com/hherb/secretary/issues/37), [#38](https://github.com/hherb/secretary/issues/38), [#45](https://github.com/hherb/secretary/issues/45) (C-blocked).
- **Open PRs:** [#70](https://github.com/hherb/secretary/pull/70) (this one — awaiting CI + review).
