# NEXT_SESSION.md

**Session date:** 2026-05-17 (Option A — close issue #67)
**Status:** PR open on branch `refactor/issue-67-split-conformance-helpers` at refactor commit `d947371` (this baton commit pushed separately so the live baton rides inside the PR per [`feedback_next_session_in_pr`](memory)). Closes issue [#67](https://github.com/hherb/secretary/issues/67) on merge. Remaining open issues are the three C-blocked items ([#37](https://github.com/hherb/secretary/issues/37) / [#38](https://github.com/hherb/secretary/issues/38) / [#45](https://github.com/hherb/secretary/issues/45)). Gauntlet on this branch green: 642 cargo + 10 ignored / clippy clean / fmt OK / Python conformance PASS / freshness 96/0/2 / Swift conformance **22/22** / Kotlin conformance **22/22**.

## (1) What we shipped this session

PR on branch `refactor/issue-67-split-conformance-helpers`. One refactor commit + this baton commit (added separately so the live baton rides inside the PR per [`feedback_next_session_in_pr`](memory)).

| SHA | Subject | Notes |
|---|---|---|
| `d947371` | `refactor(conformance-kat): split 500-LOC helper files (closes #67)` | Splits the three oversized helper files into directory modules / sibling files per the project's 500-LOC guideline; folds in the two PR #70 stylistic nits recorded as comments on issue #67. |
| _(baton)_ | `docs: pre-merge baton — issue #67 helper-file splits` | This file + its frozen handoff snapshot at [`docs/handoffs/2026-05-17-issue-67-helper-file-splits.md`](docs/handoffs/2026-05-17-issue-67-helper-file-splits.md). |

### Note on issue state at session open

Issue #67 was reported as **CLOSED-COMPLETED** at the moment PR #70 merged (2026-05-17T08:40:58Z) despite `closedByPullRequestsReferences: []`. Likely an inadvertent close — the underlying work was unaddressed and the three files were still oversized. Reopened with a short comment and worked from there.

### Files split

#### Rust: `core/tests/conformance_kat_helpers/dispatch.rs` (572) → `dispatch/`
| File | Lines | Contents |
|---|---|---|
| `dispatch/mod.rs` | 28 | Re-exports `run_*` + `assert_*` from sibling modules so callers' `use conformance_kat_helpers::dispatch::{...}` paths stay unchanged. |
| `dispatch/open.rs` | 84 | `run_open_password` / `run_open_recovery` / `run_open_writable` + `assert_open_ok`. |
| `dispatch/read.rs` | 132 | `run_read_block` + `assert_read_block_ok` + `assert_read_block_records` (public so `lifecycle::assert_post_state` can call it). |
| `dispatch/inputs.rs` | 144 | `uuid_from_inputs` / `block_input_from_inputs` / `now_ms_from_inputs` (kept `pub(super)` — sibling-module only). |
| `dispatch/lifecycle.rs` | 229 | v2 write ops (`run_save_block` / `run_share_block` / `run_trash_block` / `run_restore_block`) + `assert_post_state`. |

#### Swift: `ffi/secretary-ffi-uniffi/tests/swift/conformance.swift` (777) → 5 files
| File | Lines | Contents |
|---|---|---|
| `ConformanceErrors.swift` | 42 | `vaultErrorName` + `vaultErrorDetail` (the exhaustive switches that act as a uniffi-codegen-drift tripwire). |
| `ConformanceHelpers.swift` | 131 | Input resolvers, hex codec, `recursiveCopy`, `readContactCardBytes`, `findWritableDir` / `findCacheAncestorName`. |
| `ConformanceInputs.swift` | 65 | `uuidFromInputs` + `blockInputFromInputs` with the documented `as!` convention. |
| `ConformanceAssertions.swift` | 161 | `handleOpenOk` / `handleVaultError` / `assertPostState`. |
| `conformance.swift` | 420 | `@main struct ConformanceRunner` carrying only `static func main()` + the dispatch switch. |

#### Kotlin: `ffi/secretary-ffi-uniffi/tests/kotlin/Conformance.kt` (892) → 5 files
| File | Lines | Contents |
|---|---|---|
| `ConformanceErrors.kt` | 47 | `vaultExceptionVariantName` + `vaultExceptionDetail`. |
| `ConformanceHelpers.kt` | 161 | Input resolvers, hex codec, `recursiveCopy` / `cleanupTempVault`, `readContactCardBytes`, `findWritableDir` / `findCacheAncestorName`. |
| `ConformanceInputs.kt` | 71 | `uuidFromInputs` + `blockInputFromInputs` with the documented vector-authoring-contract convention. |
| `ConformanceAssertions.kt` | 204 | `handleOpenOk` / `handleVaultError` / `assertPostState`. |
| `Conformance.kt` | 453 | `fun main()` + the dispatch `when` loop. |

#### Build-script updates
- `ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh` — `swiftc` call updated to pass the four new `Conformance*.swift` siblings plus `conformance.swift` (order irrelevant — Swift compiles all source files as a single module).
- `ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh` — `kotlinc` call updated to pass the four new `Conformance*.kt` siblings plus `Conformance.kt`.

### Folded-in PR #70 review nits

Both items were recorded as comments on issue #67 during PR #70 review and naturally folded into the split.

1. **`record_uuid_hex` → `record_uuid_str` rename** in both `blockInputFromInputs` runners. The value may be a wrong-length hex string when the vector exercises the `record_uuid_bytes_hex` length-check path; the new local name reflects that.
2. **`as!` / `getString` "force-cast = vector authoring contract" convention** documented at the top of both `ConformanceInputs.swift` and `ConformanceInputs.kt`. Per #67 comment 1's two options, picked "leave them all alone and explicitly document the convention" — a defensive `guard let … else fatalError(...)` per call site would obscure authoring errors behind a generic "vector failed" message; the loud raw trap with the variable name + line number visible in the stack trace is more useful when a KAT vector is malformed.

### Gauntlet verified on this branch

| Check | Result |
|---|---|
| `cargo test --release --workspace --no-fail-fast` | **642 passed; 0 failed; 10 ignored** (unchanged from `main`) |
| `cargo clippy --release --workspace --tests -- -D warnings` | clean |
| `cargo fmt --all -- --check` | OK |
| `uv run core/tests/python/conformance.py` | PASS |
| `uv run core/tests/python/spec_test_name_freshness.py` | 96 / 0 / 2 PASS |
| `bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh` | **22/22 PASS** |
| `bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh` | **22/22 PASS** |

### Issues closed via this PR

| Issue | Title | State on close of this session |
|---|---|---|
| [#67](https://github.com/hherb/secretary/issues/67) | Split conformance KAT helper files past 500-LOC threshold | Reopened during session (auto-closed at PR #70 merge without an actual fix); **CLOSED on merge of this PR** |

### Not touched in this PR (deliberately out of scope)

- `ffi/secretary-ffi-uniffi/tests/swift/main.swift` (1201 lines) and `ffi/secretary-ffi-uniffi/tests/kotlin/Main.kt` (1229 lines) — these are the **smoke** runners, not the conformance KAT runners. Issue #67 scoped to the conformance files specifically. The smoke runners are a candidate for a separate follow-up issue if the project wants to enforce the 500-LOC guideline uniformly on test-side helpers; flagging here rather than expanding scope mid-PR.

## (2) What's next

Two viable directions. Pick one to open the next session.

### Option A (large, multi-session) — Sub-project C kickoff: sync orchestration

B.6 design arc is now fully closed (v1 KAT, v2 lifecycle KAT, both error-path follow-ups, plus the 500-LOC cleanup). Next forward-progress is Sub-project C. **No code yet** — start with `/brainstorm` against the C scope. Open questions to surface before any design doc (carried forward from prior batons):

- **Conflict-detection trigger.** File watcher (inotify/FSEvents/ReadDirectoryChangesW) vs. poll vs. event-driven via cloud-folder webhooks vs. on-demand?
- **Orchestrator location.** In-process per platform UI, or a separate daemon (per platform OS-conventions)?
- **Conflict-resolution UI surface.** CRDT auto-merge per [`core/src/vault/conflict.rs`](core/src/vault/conflict.rs) handles the vast majority; the C design needs to decide what surfaces to the user for the residual.
- **Sync FSM granularity.** Per-block, per-vault, or per-folder?
- **Authentication boundary.** Does the orchestrator hold an unlocked identity, or does each operation re-unlock?

Per [`feedback_stay_in_inner_loop`](memory) — this is intentionally a brainstorm-first, brick-by-brick path, not an autonomous pipeline.

### Option B (optional B.6 extension, ~½ session) — PyO3 conformance runner

Round out the three-language parity contract to four by adding a Python host runner that loads `conformance_kat.json` and drives the PyO3 binding pipeline. The JSON format is binding-agnostic; the structural work is mirroring `blockInputFromInputs` / dispatch logic in Python. Not currently filed as an issue. Lowest-priority forward direction since the existing three-runner contract already establishes cross-language parity.

### Option C (tiny, ~½ session) — Smoke runners 500-LOC follow-up

`main.swift` (1201) and `Main.kt` (1229) are the smoke runners; same 500-LOC reasoning that motivated #67 applies. Not filed as an issue yet — would need filing first if the user wants this path. Lower priority than C kickoff because smoke runners are a stable interface that won't grow further (the smoke suite is feature-complete through B.4d).

**Recommendation:** Option A (Sub-project C kickoff). The B.6 chapter is now genuinely closed; opening C on a fresh head with the helper-file shape in tidy form is the natural next step.

## (3) Open decisions and risks

### Open decisions (carried forward, not yet actionable)

- **Sub-project C scope.** No design doc exists. The session that opens C needs to start with brainstorming, not coding. See Option A above.
- **PyO3 conformance runner.** Optional B.6 extension — see Option B above; not blocking.
- **Smoke-runner 500-LOC threshold.** Whether the 500-LOC guideline should apply uniformly to all test-side helpers (including the smoke runners). See Option C above.

### Risks

- **Pure refactor — no functional risk surface added.** The change is a code-move with re-exports preserving every call site; the gauntlet was verified before commit. Risks below are carried forward from prior session as context, not added by this PR.
- **Test-state coupling across v2 vectors.** All 9 lifecycle vectors chain via `after:` against ONE writable-vault copy. A failure in `save_block_insert_happy` cascades downstream. Mitigation is in place (per-vector PASS lines + sub-check counts attribute failures clearly); the `find_cache_ancestor_name` walker tolerates missing intermediate cache entries. v3 could split into independent per-op chains if cascade-attribution friction grows.
- **Future `Operation` enum variants need dispatch arms in all three runners.** Rust's exhaustive `match` catches missed Rust arms at compile time. Swift's `switch` with `default:` and Kotlin's `when {}` with `else ->` silently fall to the default branch (marks vector as failed, but doesn't tell the author "you forgot to add a case"). Acceptable at three runners; revisit if more bindings appear.
- **Issue auto-close caveat.** Issue #67 was auto-closed at PR #70 merge despite no PR reference. Worth re-checking on issue close events for any GitHub Actions / GraphQL webhook quirks if it recurs.

### Issues still open from prior sessions (not actionable this round)

- **Issue [#37](https://github.com/hherb/secretary/issues/37)** — design discipline reminder for Sub-project C; resolves when C design doc lands.
- **Issue [#38](https://github.com/hherb/secretary/issues/38)** — `save_block` proptest case-count budget (shared writable-vault fixture); design space depends on C's vault-lifecycle decisions.
- **Issue [#45](https://github.com/hherb/secretary/issues/45)** — three `pub(crate) #[allow(dead_code)]` accessors on `OpenVaultManifest`; revisit when C consumers materialize.

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin

# If the PR has merged:
git checkout main
git pull --ff-only origin main
git worktree remove .worktrees/refactor-issue-67-split-conformance-helpers 2>/dev/null || true
git branch -D refactor/issue-67-split-conformance-helpers 2>/dev/null || true

# Otherwise (PR still open) — pick up review feedback on the branch:
cd /Users/hherb/src/secretary/.worktrees/refactor-issue-67-split-conformance-helpers
git checkout refactor/issue-67-split-conformance-helpers
git pull --ff-only origin refactor/issue-67-split-conformance-helpers
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

bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh # Expect: 22/22 PASS
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh # Expect: 22/22 PASS

# Pick a forward-progress chunk (see §2 above):
#   Option A (large):  /brainstorm "Sub-project C — sync orchestration scope"
#   Option B (½ sess): /brainstorm "PyO3 conformance runner for B.6 KAT"
#   Option C (½ sess): file an issue + split main.swift / Main.kt smoke runners
# Or scan the open backlog:
gh issue list --state open
```

---

## Closing inventory

- **Branch state on close:** `refactor/issue-67-split-conformance-helpers` at `d947371` + the baton commit (pushed separately so it rides inside the PR per [`feedback_next_session_in_pr`](memory)). PR open. No untracked files outside the worktree.
- **Workspace tests:** **642 cargo + 10 ignored**, unchanged across this PR (pure refactor).
- **Per-binding conformance counts:** Swift `22/22 PASS`, Kotlin `22/22 PASS`, Rust `replay_conformance_kat ... ok`.
- **File sizes after the split:**
  - Rust `dispatch/`: max single file = `lifecycle.rs` at 229 lines (was 572 flat).
  - Swift `tests/swift/`: max conformance-side file = `conformance.swift` at 420 lines (was 777 flat). `main.swift` smoke runner at 1201 lines is out of scope — see §1 "Not touched".
  - Kotlin `tests/kotlin/`: max conformance-side file = `Conformance.kt` at 453 lines (was 892 flat). `Main.kt` smoke runner at 1229 lines is out of scope — see §1 "Not touched".
- **README:** unchanged — no file-size or split details surfaced there.
- **ROADMAP:** B.6 paragraph gained a sentence describing the issue-#67 split (line counts, file list, the two folded-in tidy items, pure-refactor disclaimer).
- **CLAUDE.md:** unchanged.
- **Files created this session:** 4 Rust + 4 Swift + 4 Kotlin sibling files (12 total), plus this `NEXT_SESSION.md` (overwritten) and its frozen handoff snapshot at [`docs/handoffs/2026-05-17-issue-67-helper-file-splits.md`](docs/handoffs/2026-05-17-issue-67-helper-file-splits.md).
- **Files deleted this session:** `core/tests/conformance_kat_helpers/dispatch.rs` (replaced by directory module).
- **Files modified this session:** `ffi/secretary-ffi-uniffi/tests/swift/conformance.swift` (shrunk to @main-only), `ffi/secretary-ffi-uniffi/tests/kotlin/Conformance.kt` (shrunk to main+dispatch), both `run_conformance.sh` scripts (updated to pass sibling file lists), `ROADMAP.md` (+1 sentence in the B.6 paragraph).
- **Issues open at session close:** [#37](https://github.com/hherb/secretary/issues/37), [#38](https://github.com/hherb/secretary/issues/38), [#45](https://github.com/hherb/secretary/issues/45) (all C-blocked).
- **Open PRs:** This branch (awaiting CI + review).
