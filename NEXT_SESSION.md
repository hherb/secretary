# NEXT_SESSION.md

**Session date:** 2026-05-16 (single-day session; B.6 v1 pre-v2 cleanup bundle + review follow-ups)
**Status:** Ten commits on `chore/b6-pre-v2-cleanup` (6 original + 4 review follow-ups in this same branch, addressing the PR self-review). All four target issues (#60 #61 #62 #63) closed in-branch. Gauntlet green: 641 cargo + 10 ignored / clippy clean / fmt OK / Python conformance + freshness PASS / Swift smoke 38 / Swift conformance 11/11 / Kotlin smoke 39 / Kotlin conformance 11/11.

## (1) What we shipped this session

The single deliverable: the four B.6 v1 PR-review follow-ups (one structural file split + one KAT vector expansion + one Swift+Kotlin assertion factoring + one Kotlin cache-drain fix) landed in commit order so semantic changes slot into the post-split file structure. Brainstorming → design doc → plan → 4-commit TDD execution via the superpowers skill chain (brainstorming → writing-plans → executing-plans).

| Commit | Type | What landed |
|---|---|---|
| `85163b2` | docs(specs) | Design doc at [docs/superpowers/specs/2026-05-16-b6-pre-v2-cleanup-bundle-design.md](docs/superpowers/specs/2026-05-16-b6-pre-v2-cleanup-bundle-design.md). 8 sections, ~256 lines: §3 per-commit shape with concrete file layouts + helper signatures + cross-language symmetry rules; §4 testing strategy; §5 risks (freshness-count drift, PR #58 gating-fix regression risk in #62, cross-language drift, #60 boundary judgement). |
| `79e74d1` | docs(plans) | Implementation plan at [docs/superpowers/plans/2026-05-16-b6-pre-v2-cleanup-bundle.md](docs/superpowers/plans/2026-05-16-b6-pre-v2-cleanup-bundle.md). 7 tasks (4 implementation + final gauntlet + docs/handoff + push+PR), ~1680 lines with full code blocks + expected-output assertions for every command. Plan included an upfront fallback for #60's `dispatch.rs` helper extraction (the bridge crate types are `Record` not `RecordHandle`; planning anticipated this and authorised an inline alternative). |
| `2f25c5e` | chore(b6) | #60 — split `core/tests/conformance_kat.rs` (594 LOC → 194-LOC entry + 5 helper files under `core/tests/conformance_kat_helpers/`: `mod.rs` 12 / `types.rs` 93 / `fixtures.rs` 70 / `errors.rs` 74 / `dispatch.rs` 177). Pure structural refactor — no semantic change. `assert_record` + `assert_field` kept inline inside `assert_read_block_ok` because the bridge crate names its per-record handle type `Record` (not `RecordHandle` as the plan initially guessed); inlining sidesteps the type-naming uncertainty entirely. All test names + panic messages preserved; cargo count unchanged at 641 + 10 ignored. |
| `7e7afb7` | test(b6) | #61 — add `read_block_oversize_uuid` (17-byte input) + `read_block_zero_length_uuid` (0-byte input) vectors. JSON-only change to `core/tests/data/conformance_kat.json`. No code change in any replay engine — the existing synthesized-`InvalidArgument` path already handles arbitrary `block_uuid_bytes_hex` lengths. Vector count 9 → 11. Rust replay + Swift conformance + Kotlin conformance all now 11/11. |
| `d640292` | refactor(b6) | #62 — factor Swift `handleOpenOk` + `handleOpenError` helpers (file-scope `func`s, 60 LOC) and Kotlin equivalent (`private fun`s, 60 LOC). Two switch/when arms compressed: Swift ~32 LOC each → ~10 LOC each; Kotlin ~41 LOC each → ~10 LOC each. Cross-language symmetric (same names, same parameter order, same assertion order). Negative-test verified: corrupting `open_password_happy.display_name` → both runners emit `FAIL:` and no `PASS:` for the affected vector (PR #58 gated-PASS-after-FAIL fix preserved). Net diff: Swift +13, Kotlin +20 in helpers — but the switch-arm body compression nets out to -108/+121 across both files. Swift/Kotlin smoke runners both still pass. |
| `d2de3a8` | fix(b6) | #63 — Kotlin runner drains `cache.values.forEach { it.destroy() }; cache.clear()` above the summary if/else, so both `exitProcess(0)` and `exitProcess(1)` paths release the cached `OpenVaultOutput` handles deterministically rather than waiting for the JVM `Cleaner` thread. No leak today; matters for B.6 v2 second-pass replays. Cache-lifetime comment updated to reflect explicit drain. Kotlin conformance still 11/11. |

### Review follow-ups (this same branch)

Self-review of the just-pushed PR surfaced four minor issues. Per the `feedback_fix_all_review_issues` rule (no technical debt; fix every review issue before merging), all four landed as separate commits on top of the original bundle, one issue per commit.

| Commit | Type | What landed |
|---|---|---|
| (Fix #1) | fix(b6) | **Symmetric Swift cache drain.** The original `#63` comment claimed "Swift needs no equivalent (ARC reclaims on process exit)" — technically wrong. `exit()` skips Swift scope unwinding; ARC only fires on normal scope exit. Added `cache.removeAll()` before the summary `exit()` in `conformance.swift`, mirroring the Kotlin drain. Forward-compat for B.6 v2 second-pass replays in either language. |
| (Fix #2) | refactor(b6) | **DRY read_block error handling.** `handleOpenError` (Swift) / `handleOpenError` (Kotlin) and the inline `read_block` error arm were doing identical work (variant + detail_contains check). Renamed `handleOpenError` → `handleVaultError` in both languages and reused for every op that throws a vault-error (open_*, read_block). Net: ~20 LOC removed across the two files; the next-version `save_block` / `delete_block` lifecycle arms get the same call shape for free. |
| (Fix #3) | refactor(b6) | **Cache only on full sub-check pass.** Pre-fix: Swift/Kotlin `handleOpenOk` always inserted into the cache even when sub-checks (`display_name`, `block_count`, `block_uuid_hex`) failed — divergent from Rust where `assert_open_ok`'s panic prevented `cache.insert`. Now `handleOpenOk` aggregates `check(…)` return values into a local `allOk` flag and only caches when `allOk` is true. Verified end-to-end: corrupting `display_name` produces 7 FAILs (the failed source vector + 5 chained `read_block_*` "predecessor not cacheable" reports + the recovery vector that shares the source name) and no spurious PASS lines. Closes the cross-language semantic divergence raised in self-review. |
| (Fix #4) | chore(b6) | **Unused Kotlin imports removed.** `uniffi.secretary.BlockReadOutput`, `OpenVaultManifest`, `UnlockedIdentity` were imported but never named-referenced in `Conformance.kt` (they appear only via inferred method-return types, which Kotlin resolves without the import). Three lines deleted; `kotlinc` still happy. |

10 commits total on the feature branch (2 docs + 4 issue-closing + 4 review follow-ups).

### Final gauntlet at session close

| Check | Result |
|---|---|
| `cargo test --release --workspace --no-fail-fast` | **641 passed + 10 ignored** (unchanged from B.6 v1 close at PR #58) |
| `cargo clippy --release --workspace --tests -- -D warnings` | clean |
| `cargo fmt --all -- --check` | OK |
| `uv run core/tests/python/conformance.py` | PASS |
| `uv run core/tests/python/spec_test_name_freshness.py` | PASS (96 / 0 / 2 — unchanged baseline) |
| `bash ffi/secretary-ffi-uniffi/tests/swift/run.sh` | 38 PASS asserts, OK (unchanged smoke surface; prior NEXT_SESSION's "37/37" claim was approximate) |
| `bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh` | **11/11 PASS** (was 9/9 pre-#61) |
| `bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh` | 39 PASS asserts, OK (unchanged smoke surface) |
| `bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh` | **11/11 PASS** (was 9/9 pre-#61) |

### Inline-execution notes (for future sessions)

This bundle ran via `superpowers:executing-plans` (inline) rather than `subagent-driven-development`. Justified by scope: 4 small commits totaling ~570 LOC of net change, no `cargo build` chains longer than ~60s per task, no risk of subagent timeout. Wall-clock for the whole bundle (commits + gauntlets): ~25 min. The B.6 v1 subagent-driven flow would have spent that much time on Task 1 alone. **Calibration:** subagent-driven shines when individual tasks involve long compile/test cycles (B.6 v1 had Rust + Swift + Kotlin builds per task) or when reviews between tasks are load-bearing; this bundle had neither.

The plan's upfront `RecordHandle` type-name fallback (Step 1.7 — "if not nameable, inline") proved correct: bridge types are `Record` + `FieldHandle`. Inlining was the right call; the alternative would have introduced lifetime-parameter fiddling for zero readability gain.

## (2) What's next

### Sub-project B.6 v2 design — lifecycle conformance KAT (issue [#59](https://github.com/hherb/secretary/issues/59))

The bundle that just shipped sets B.6 up for v2: file split + factored Swift/Kotlin helpers + symmetric cross-language shape = v2 lifecycle vectors land as ~4 short switch arms instead of 4 near-duplicate 30-LOC blocks per language. The remaining question is unchanged from prior NEXT_SESSION:

**Blocker design question:** `save_block` uses OS-CSPRNG-driven AEAD nonces, so on-disk block bytes differ between runs. Three options:

1. Add a `#[cfg(test)]` RNG knob to the bridge that seeds the AEAD nonce stream deterministically. Pin full output bytes.
2. Keep nondeterminism. Pin shape-only assertions (block_count delta, manifest signature presence, trash entry exists, etc.) instead of bytes.
3. Refactor `save_block` to take a `dyn RngCore` parameter; production passes `OsRng`, tests pass a seeded generator.

(2) is the lightest touch; (3) is the cleanest if write-path determinism becomes useful elsewhere. Start with `/brainstorm` on this question before writing the v2 design doc — it's a genuine architectural fork, not a mechanical extension.

**Preliminary acceptance criteria** (refine during brainstorming):
- All four lifecycle ops have at least one happy + one error vector in the KAT.
- The three replay engines (Rust + Swift + Kotlin) all execute the new vectors and pass.
- The chosen determinism approach is documented in the v2 design doc with rationale for rejecting the other two.

**Scope estimate:** 1–2 PRs. Swift + Kotlin runners gain ~150 LOC each; Rust replay grows ~200 LOC; generator needs determinism-aware path. 7–10 days of work depending on which determinism option wins. The just-shipped #62 factoring will save real time here.

### Issue [#35](https://github.com/hherb/secretary/issues/35) — mid-call wipe race in `save_block` (carryover)

Unchanged: needs a `#[cfg(test)]` synchronization barrier in `OpenVaultManifest`. Orchestrator at [ffi/secretary-ffi-bridge/src/save/orchestration.rs:114-125](ffi/secretary-ffi-bridge/src/save/orchestration.rs#L114-L125) handles a documented mid-call wipe race correctly but the existing `save_block_on_wiped_manifest_returns_corrupt_vault` test only exercises the pre-call wipe. Defer to a focused session; lower value than B.6 v2 forward progress.

### Issues #37, #38, #45 (blocked on Sub-project C)

Unchanged from prior handoff. Not actionable until C starts.

## (3) Open decisions and risks

### Risks

- **`save_block` determinism design (B.6 v2 blocker).** Real architectural decision; spend a session brainstorming before writing code. Three options documented in (2); preference logged but not committed.
- **Inline-execution wall-clock budget.** This bundle ran in ~25 min. Larger bundles (B.6 v2's lifecycle KAT will probably be 600+ LOC of new code) may stretch context. Subagent-driven becomes more valuable as task size grows.
- **`feedback_split_files_proactively.md` calibration.** Newly-split `dispatch.rs` is 177 LOC — well under 500 — but B.6 v2 will add per-op runners that could push it past 300. Watch threshold during v2 plan.

### Issues still open from prior sessions

- **Issue #35** — mid-call wipe race in `save_block` (carried; not actionable in isolation).
- **Issue #37** — design discipline reminder for Sub-project C; not actionable until C starts.
- **Issue #38** — proptest case budget (shared writable-vault fixture); not actionable until C.
- **Issue #45** — three `pub(crate) #[allow(dead_code)]` accessors on `OpenVaultManifest` (forward-compat for C; revisit when C starts).
- **Issue #59** — B.6 v2 lifecycle conformance KAT. Design + plan + impl. Next session candidate.
- **Issues #60, #61, #62, #63** — closed this session by the PR (when it merges).

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git checkout main
git pull --ff-only origin main                       # after the PR merges
git fetch --prune origin
git status --short                                   # expect: clean
git branch -vv                                       # expect: only main (after local feature/* branch is deleted)
git worktree list                                    # expect: only the primary worktree

# Verify the test gauntlet still matches this session's closing numbers:
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{
  for (i=1; i<=NF; i++) {
    if ($i == "passed;") p += $(i-1)
    if ($i == "failed;") f += $(i-1)
    if ($i == "ignored;") ig += $(i-1)
  }
}
END { printf("TOTAL: %d passed; %d failed; %d ignored\n", p, f, ig) }'
# Expect: TOTAL: 641 passed; 0 failed; 10 ignored

cargo clippy --release --workspace --tests -- -D warnings    # Expect: clean
cargo fmt --all -- --check                                    # Expect: OK
uv run core/tests/python/conformance.py                       # Expect: PASS
uv run core/tests/python/spec_test_name_freshness.py          # Expect: PASS (96 / 0 / 2)

bash ffi/secretary-ffi-uniffi/tests/swift/run.sh              # Expect: OK; ~38 PASS asserts
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh  # Expect: 11/11 PASS
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh             # Expect: OK; ~39 PASS asserts
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh # Expect: 11/11 PASS

# Next forward-progress chunk — B.6 v2 design (recommended):
#   /brainstorm on the save_block determinism question (see (2) above)
# or check the open backlog:
gh issue list --state open
```

---

## Closing inventory

- **Branch state on close:** `chore/b6-pre-v2-cleanup` carries 10 commits on top of `d1595c5` (the B.6 v1 squash-merge that ended PR #58) — 6 original bundle commits + 4 self-review follow-ups. PR #64 already open against main with title `chore(b6): pre-v2 cleanup bundle (#60 #61 #62 #63)`; the follow-up commits attach to that PR.
- **Workspace tests:** **641 cargo + 10 ignored** (unchanged from B.6 v1 close). Conformance KAT vector count 9 → 11. Swift conformance 9/9 → 11/11; Kotlin conformance 9/9 → 11/11. Smoke runners + Python pytest unchanged.
- **README:** unchanged (no specific test counts or B.6 v1 internals mentioned).
- **ROADMAP:** line 34 updated — "9-vector frozen JSON" → "11-vector frozen JSON", "9/9 PASS" → "11/11 PASS", added clause documenting the bundle (file split + helpers + cache drain) and the #60/#61/#62/#63 closures.
- **CLAUDE.md:** unchanged — the existing Commands section already documents the conformance runners; this bundle doesn't add new commands.
- **Files created:** [`docs/superpowers/specs/2026-05-16-b6-pre-v2-cleanup-bundle-design.md`](docs/superpowers/specs/2026-05-16-b6-pre-v2-cleanup-bundle-design.md), [`docs/superpowers/plans/2026-05-16-b6-pre-v2-cleanup-bundle.md`](docs/superpowers/plans/2026-05-16-b6-pre-v2-cleanup-bundle.md), `core/tests/conformance_kat_helpers/mod.rs`, `core/tests/conformance_kat_helpers/types.rs`, `core/tests/conformance_kat_helpers/fixtures.rs`, `core/tests/conformance_kat_helpers/errors.rs`, `core/tests/conformance_kat_helpers/dispatch.rs`, [`NEXT_SESSION.md`](NEXT_SESSION.md) (this file, overwritten), [`docs/handoffs/2026-05-16-b6-pre-v2-cleanup-bundle.md`](docs/handoffs/2026-05-16-b6-pre-v2-cleanup-bundle.md) (frozen archive of this file).
- **Files modified:** [`core/tests/conformance_kat.rs`](core/tests/conformance_kat.rs) (594 → 194 LOC, lifted helpers out), [`core/tests/data/conformance_kat.json`](core/tests/data/conformance_kat.json) (+26 lines for 2 vectors), [`ffi/secretary-ffi-uniffi/tests/swift/conformance.swift`](ffi/secretary-ffi-uniffi/tests/swift/conformance.swift) (factoring + symmetric ARC drain + handleVaultError unification + cache-on-success-only), [`ffi/secretary-ffi-uniffi/tests/kotlin/Conformance.kt`](ffi/secretary-ffi-uniffi/tests/kotlin/Conformance.kt) (factoring + drain + comment update + handleVaultError unification + cache-on-success-only + unused-imports trim), [`ROADMAP.md`](ROADMAP.md) (vector-count + bundle note).
- **Issues filed this session:** none (all four target issues already existed from PR #58 review).
- **PR to open:** `chore(b6): pre-v2 cleanup bundle (#60 #61 #62 #63)` against `main`.
