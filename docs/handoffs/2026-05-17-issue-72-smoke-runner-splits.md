# NEXT_SESSION.md

**Session date:** 2026-05-17 (Option C — close issue #72, smoke-runner splits)
**Status:** PR pending on branch `refactor/issue-72-split-smoke-runners` at refactor commit `5990b4e` (this baton commit pushed separately so the live baton rides inside the PR per [`feedback_next_session_in_pr`](memory)). Closes issue [#72](https://github.com/hherb/secretary/issues/72) on merge. Remaining open issues are the three C-blocked items ([#37](https://github.com/hherb/secretary/issues/37) / [#38](https://github.com/hherb/secretary/issues/38) / [#45](https://github.com/hherb/secretary/issues/45)). Gauntlet on this branch green: 642 cargo + 10 ignored / clippy clean / fmt OK / Python conformance PASS / freshness 96/0/2 / Swift smoke **38/38** / Kotlin smoke **39/39** / Swift conformance **22/22** / Kotlin conformance **22/22**.

## (1) What we shipped this session

PR on branch `refactor/issue-72-split-smoke-runners`. One refactor commit + this baton commit (added separately so the live baton rides inside the PR per [`feedback_next_session_in_pr`](memory)).

| SHA | Subject | Notes |
|---|---|---|
| `5990b4e` | `refactor(smoke-runners): split 500-LOC smoke files (closes #72)` | Splits both smoke runners (`main.swift` 1201 → 8 files, `Main.kt` 1229 → 8 files) into op-family sibling files per the project's 500-LOC guideline. Pure refactor — gauntlet unchanged. |
| _(baton)_ | `docs: pre-merge baton — issue #72 smoke-runner splits` | This file + its frozen handoff snapshot at [`docs/handoffs/2026-05-17-issue-72-smoke-runner-splits.md`](docs/handoffs/2026-05-17-issue-72-smoke-runner-splits.md). |

### Files split

#### Swift: `ffi/secretary-ffi-uniffi/tests/swift/main.swift` (1201) → 8 files

| File | Lines | Contents |
|---|---|---|
| `main.swift` | 37 | Top-level entry: `loadSmokeEnv()` → `runXxxAsserts(env:)` calls → final pass/fail summary. |
| `SmokeHelpers.swift` | 253 | Module-level `failures` / `assertsRun`, `check(_:,_:)`, all pinned KAT constants (`EXPECTED_FORMAT_VERSION`, `TRUNCATION_SUFFIX_BYTES`, `expectedDisplayName`, `expectedUserUuid`, `vault001BlockUuid`, plus save/share/B.5 UUIDs), the `SmokeEnv` struct, `loadSmokeEnv()`, and fixture helpers (`_phraseFromInputs`, `_recursiveCopy`, `_freshWritableVault`, `_aliceCardBytes`). |
| `SmokeBytesIn.swift` | 269 | Asserts 1-15: B.0 round-trip (`add`, `version`), B.2 `open_with_password` (success + 3 errors + explicit wipe), B.3a `open_with_recovery` (success + 3 errors), B.3b `create_vault` (shape + 2 round-trips). |
| `SmokeFolderIn.swift` | 122 | Asserts 16-18 (B.4a `open_vault_with_password`) + 35-37 (#30 follow-up: `open_vault_with_recovery`). |
| `SmokeReadBlock.swift` | 104 | Asserts 19-22 (B.4b `read_block`). |
| `SmokeSaveBlock.swift` | 189 | Asserts 23-26 (B.4c `save_block`). |
| `SmokeShareBlock.swift` | 198 | Asserts 27-30 (B.4d `share_block`). |
| `SmokeTrashRestore.swift` | 178 | Asserts 31-34 (B.5 `trash_block` + `restore_block`). |

#### Kotlin: `ffi/secretary-ffi-uniffi/tests/kotlin/Main.kt` (1229) → 8 files

| File | Lines | Contents |
|---|---|---|
| `Main.kt` | 38 | `fun main()` entry: `loadSmokeEnv()` → `runXxxAsserts(env)` calls → final pass/fail summary. |
| `SmokeHelpers.kt` | 316 | File-level `failures` / `assertsRun`, `check(Boolean, String)`, all pinned KAT constants (`EXPECTED_FORMAT_VERSION`, `TRUNCATION_SUFFIX_BYTES`, `BIP39_PHRASE_SHAPE`, `EXPECTED_DISPLAY_NAME`, `EXPECTED_USER_UUID`, `VAULT_001_BLOCK_UUID`, save/share/B.5 UUIDs), the `SmokeEnv` data class, `loadSmokeEnv()`, and fixture helpers (`phraseFromInputs`, `recursiveCopy`, `cleanupTempVault`, `freshWritableVault`, `aliceCardBytes`). |
| `SmokeBytesIn.kt` | 279 | Same scope as `SmokeBytesIn.swift`. |
| `SmokeFolderIn.kt` | 126 | Same scope as `SmokeFolderIn.swift`. |
| `SmokeReadBlock.kt` | 102 | Same scope as `SmokeReadBlock.swift`. |
| `SmokeSaveBlock.kt` | 196 | Same scope as `SmokeSaveBlock.swift`. |
| `SmokeShareBlock.kt` | 167 | Same scope as `SmokeShareBlock.swift`. |
| `SmokeTrashRestore.kt` | 146 | Same scope as `SmokeTrashRestore.swift`. |

#### Build-script updates

- `ffi/secretary-ffi-uniffi/tests/swift/run.sh` — `swiftc` call extended to pass the seven `Smoke*.swift` siblings plus `main.swift`. Order is irrelevant — Swift compiles all source files as a single module.
- `ffi/secretary-ffi-uniffi/tests/kotlin/run.sh` — `kotlinc` call extended to pass the seven `Smoke*.kt` siblings plus `Main.kt`. Order is irrelevant — Kotlin compiles all source files in one invocation as a single module.

### Shared-state model

Both runners now thread shared fixture state through a `SmokeEnv` struct/data class (vault paths, vault.toml / bundle bytes, password bytes, mnemonic phrase bytes), constructed once at startup by `loadSmokeEnv()` and passed to every `runXxxAsserts(env)`. Module-level `var failures` / `var assertsRun` in `SmokeHelpers.{swift,kt}` stay visible to every assertion file:

- **Swift**: top-level `var` in a non-`main.swift` file is a module-level global, visible to every other Swift file in the compilation unit.
- **Kotlin**: top-level `var` compiles as a private-to-jar `static` JVM field via the file's synthetic `SmokeHelpersKt` class — accessible to every other Kotlin file in the same kotlinc invocation.

### Deviation from issue #72's suggested layout

Issue #72 suggested combining save / share / trash / restore into one `SmokeLifecycle.{swift,kt}`, but that would have landed at ~510 lines — over the threshold. Split into three op-family files (`SmokeSaveBlock` / `SmokeShareBlock` / `SmokeTrashRestore`) keeps each well under 300 lines and matches the just-merged PR #71's "one concept per file" spirit.

### Gauntlet verified on this branch

| Check | Result |
|---|---|
| `cargo test --release --workspace --no-fail-fast` | **642 passed; 0 failed; 10 ignored** (unchanged from `main`) |
| `cargo clippy --release --workspace --tests -- -D warnings` | clean |
| `cargo fmt --all -- --check` | OK |
| `uv run core/tests/python/conformance.py` | PASS |
| `uv run core/tests/python/spec_test_name_freshness.py` | 96 / 0 / 2 PASS |
| `bash ffi/secretary-ffi-uniffi/tests/swift/run.sh` | **38/38 PASS** |
| `bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh` | **39/39 PASS** |
| `bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh` | **22/22 PASS** |
| `bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh` | **22/22 PASS** |

### Issues closed via this PR

| Issue | Title | State on close of this session |
|---|---|---|
| [#72](https://github.com/hherb/secretary/issues/72) | Split smoke-runner files past 500-LOC threshold (main.swift / Main.kt) | **CLOSED on merge of this PR** |

## (2) What's next

The B.6 cleanup arc is **now fully closed** — both #67 (conformance helpers) and #72 (smoke runners) are merged / pending merge. Two viable directions remain.

### Option A (large, multi-session) — Sub-project C kickoff: sync orchestration

B.6 design arc is fully closed. Next forward-progress is Sub-project C. **No code yet** — start with `/brainstorm` against the C scope. Open questions to surface before any design doc (carried forward from prior batons):

- **Conflict-detection trigger.** File watcher (inotify/FSEvents/ReadDirectoryChangesW) vs. poll vs. event-driven via cloud-folder webhooks vs. on-demand?
- **Orchestrator location.** In-process per platform UI, or a separate daemon (per platform OS-conventions)?
- **Conflict-resolution UI surface.** CRDT auto-merge per [`core/src/vault/conflict.rs`](core/src/vault/conflict.rs) handles the vast majority; the C design needs to decide what surfaces to the user for the residual.
- **Sync FSM granularity.** Per-block, per-vault, or per-folder?
- **Authentication boundary.** Does the orchestrator hold an unlocked identity, or does each operation re-unlock?

Per [`feedback_stay_in_inner_loop`](memory) — this is intentionally a brainstorm-first, brick-by-brick path, not an autonomous pipeline.

### Option B (optional B.6 extension, ~½ session) — PyO3 conformance runner

Round out the three-language parity contract to four by adding a Python host runner that loads `conformance_kat.json` and drives the PyO3 binding pipeline. The JSON format is binding-agnostic; the structural work is mirroring `blockInputFromInputs` / dispatch logic in Python. Not currently filed as an issue. Lowest-priority forward direction since the existing three-runner contract already establishes cross-language parity.

**Recommendation:** Option A (Sub-project C kickoff). The B.6 chapter is now genuinely closed end-to-end — every test-side file in the FFI tree is under the 500-LOC guideline; no orphan refactor backlog remains. Opening C on a fresh head is the natural next step.

## (3) Open decisions and risks

### Open decisions (carried forward, not yet actionable)

- **Sub-project C scope.** No design doc exists. The session that opens C needs to start with brainstorming, not coding. See Option A above.
- **PyO3 conformance runner.** Optional B.6 extension — see Option B above; not blocking.

### Risks

- **Pure refactor — no functional risk surface added.** The change is a code-move with module-level globals + `SmokeEnv` threading preserving every call site; the gauntlet was verified before commit. No security-critical paths touched.
- **Module-level mutable globals in Smoke files.** `var failures` and `var assertsRun` live in `SmokeHelpers.{swift,kt}` and are mutated from every assertion file. Not thread-safe — but the smoke runners are single-threaded scripts (no async, no goroutines, no concurrency primitives), so this is a non-issue. If a future host runner ever introduces concurrency, these would need to migrate to thread-safe accumulators.
- **Future `Operation` enum variants need dispatch arms in all three runners.** Rust's exhaustive `match` catches missed Rust arms at compile time. Swift's `switch` with `default:` and Kotlin's `when {}` with `else ->` silently fall to the default branch. Acceptable at three runners; revisit if more bindings appear. (Carried forward; not added by this PR.)

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
git worktree remove .worktrees/refactor-issue-72-split-smoke-runners 2>/dev/null || true
git branch -D refactor/issue-72-split-smoke-runners 2>/dev/null || true

# Otherwise (PR still open) — pick up review feedback on the branch:
cd /Users/hherb/src/secretary/.worktrees/refactor-issue-72-split-smoke-runners
git checkout refactor/issue-72-split-smoke-runners
git pull --ff-only origin refactor/issue-72-split-smoke-runners
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

bash ffi/secretary-ffi-uniffi/tests/swift/run.sh             # Expect: 38/38 PASS
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh            # Expect: 39/39 PASS
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh # Expect: 22/22 PASS
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh # Expect: 22/22 PASS

# Pick a forward-progress chunk (see §2 above):
#   Option A (large):  /brainstorm "Sub-project C — sync orchestration scope"
#   Option B (½ sess): /brainstorm "PyO3 conformance runner for B.6 KAT"
# Or scan the open backlog:
gh issue list --state open
```

---

## Closing inventory

- **Branch state on close:** `refactor/issue-72-split-smoke-runners` at `5990b4e` + the baton commit (pushed separately so it rides inside the PR per [`feedback_next_session_in_pr`](memory)). PR open. No untracked files outside the worktree.
- **Workspace tests:** **642 cargo + 10 ignored**, unchanged across this PR (pure refactor).
- **Per-binding smoke counts:** Swift `38/38 PASS`, Kotlin `39/39 PASS`. Conformance unchanged: Swift `22/22 PASS`, Kotlin `22/22 PASS`.
- **File sizes after the split (largest single file per language):**
  - Swift smoke: `SmokeBytesIn.swift` at 269 lines (was 1201 monolithic).
  - Kotlin smoke: `SmokeHelpers.kt` at 316 lines (was 1229 monolithic).
  - Conformance files (untouched by this PR): max `Conformance.kt` at 453 lines.
  - **Every test-side file in the FFI tree is now under the 500-LOC guideline.**
- **README:** unchanged — no file-size or split details surfaced there (the high-level smoke-runner mention at line 164 still reads true).
- **ROADMAP:** B.6 paragraph gained a sentence describing the issue-#72 split parallel to the existing #67 sentence (line 34).
- **CLAUDE.md:** unchanged.
- **Files created this session:** 7 Swift + 7 Kotlin sibling files (14 total), plus this `NEXT_SESSION.md` (overwritten) and its frozen handoff snapshot at [`docs/handoffs/2026-05-17-issue-72-smoke-runner-splits.md`](docs/handoffs/2026-05-17-issue-72-smoke-runner-splits.md).
- **Files modified this session:** `ffi/secretary-ffi-uniffi/tests/swift/main.swift` (shrunk to entry-only), `ffi/secretary-ffi-uniffi/tests/kotlin/Main.kt` (shrunk to entry-only), both `run.sh` scripts (updated to pass sibling file lists), `ROADMAP.md` (+1 sentence in the B.6 paragraph).
- **Issues open at session close:** [#37](https://github.com/hherb/secretary/issues/37), [#38](https://github.com/hherb/secretary/issues/38), [#45](https://github.com/hherb/secretary/issues/45) (all C-blocked).
- **Open PRs:** this one — awaiting CI + review.
