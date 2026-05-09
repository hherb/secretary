# Handoff: 2026-05-09 — B.4b deferred-cleanup pass

**Session date:** 2026-05-09
**Branch:** `chore/b4b-deferred-cleanup`
**Status:** four B.4b deferred items closed in a single PR; no new feature work.

This is the contemporaneous frozen-in-time handoff. The live equivalent at the time of writing is `NEXT_SESSION.md` on the feature branch; this file is preserved unmodified for historical traceability.

---

## Why this session existed

PR #31 (B.4b read_block) merged 2026-05-09 leaving four deferred items in the post-merge baton (NEXT_SESSION.md):

1. `ffi/secretary-ffi-uniffi/src/lib.rs` was 979 lines past the 500-line policy threshold; reviewer specifically suggested splitting into `errors.rs` + `wrappers/{identity,vault,block}.rs` + `namespace.rs` *before* B.4c started adding `save_block` to that file.
2. Stale `wipe()` UDL docstrings on the older interfaces (UnlockedIdentity, MnemonicOutput, OpenVaultManifest) had simpler text than the B.4b-corrected interfaces (BlockReadOutput, Record, FieldHandle), which carry the "uniffi 0.31 codegen generates BOTH `wipe()` AND `close()`" paragraph from the review-fix `43abd13`.
3. GitHub issue #32 (orphan-rule housekeeping for `From<FfiUnlockError> for FfiVaultError`) — non-blocking but flagged in PR #31 review.
4. `as u64` / `as usize` casts in the uniffi wrapper were lossy on 32-bit targets for `record_at` / `field_at`'s `idx as usize` paths.

User scope decision at session start: include all four. NEXT_SESSION's other deferred items (bridge/error.rs split, bridge/vault.rs split, py/src/lib.rs split, py/test_smoke.py split) were left for after B.4c per the original baton's explicit "B.4c will grow these further; defer until after" note.

## What landed

Four task commits, one per item, in the order listed above:

| # | Commit SHA | Subject |
|---|---|---|
| 1 | `9815167` | refactor(ffi-uniffi): split lib.rs into errors + wrappers + namespace modules |
| 2 | `5e9b123` | refactor(ffi-uniffi): tighten u64 → usize casts in record_at / field_at |
| 3 | `220222a` | docs(ffi-uniffi): align older UDL wipe() docstrings with B.4b codegen reality |
| 4 | `259825d` | refactor(ffi-bridge): move unlock→vault arm into private free function |

Plus one docs commit (this file + README + ROADMAP + NEXT_SESSION).

### Verification at each commit

Per-commit verification (recorded inline in each commit body):

- `9815167`: `cargo test --release --workspace`: 552 passed + 9 ignored, 0 failed; clippy clean; fmt OK; Swift 22/22; Kotlin all PASS.
- `5e9b123`: cargo test 552/0/9; clippy clean. (Behavior change is on 32-bit only; 64-bit test result identical.)
- `220222a`: cargo build clean; Kotlin smoke all PASS.
- `259825d`: cargo test 552/0/9; clippy clean.

Final session-close verification:
- cargo test --release --workspace: 552 passed + 9 ignored, 0 failed
- cargo clippy --release --workspace -- -D warnings: clean
- cargo fmt --all -- --check: OK
- uv run --directory ffi/secretary-ffi-py pytest: 40 passed
- uv run core/tests/python/conformance.py: PASS
- uv run core/tests/python/spec_test_name_freshness.py: PASS
- Swift smoke: 22/22 PASS
- Kotlin smoke: 23 PASS lines

## Significant findings

### The split was a pure relocation, not a behavior change

All 18 uniffi crate tests survived the split unchanged; tests followed the code they exercise (per-module `#[cfg(test)]` blocks). The challenge was visibility: bridge handle inner fields needed `pub(crate)` so namespace functions in `namespace.rs` could still access `identity.0` / `manifest.0`. Tagged the inner fields with `pub(crate)` rather than introducing a new accessor method to keep the diff minimal — accessors would be the right move only if there's >1 reason to own the access pattern.

### The 32-bit cast guard is silent on the test host

`record_at(idx as usize)` and `field_at(idx as usize)` on 64-bit Rust round-trip every `u64` value losslessly, so a unit test for "out-of-range u64 returns None" passes both before and after the fix. The improvement is real on smaller platforms (16-bit and 32-bit usize) where `idx as usize` truncates the high bits. Clippy doesn't warn (`cast_possible_truncation` is not enabled workspace-wide). The defense is a tight inline rationale comment instead of a redundant 64-bit-only test.

### The B.4b-corrected codegen paragraph propagates downward, not upward

uniffi 0.31's Kotlin codegen generates BOTH `wipe()` AND `close()` as separate methods (NOT a rename). This was discovered during PR #31 review; commit `43abd13` corrected the docstrings on the new B.4b interfaces. The same paragraph now lives on the older B.2 / B.3a / B.3b / B.4a interfaces' `wipe()` methods. The interface-level `Same close → wipe rename rationale as ...` wording stays — that captures the design rationale (we *named* it `wipe` instead of `close` to avoid colliding with the auto-generated `AutoCloseable.close()`), which is unrelated to the codegen-generates-BOTH discovery.

### Issue #32's reachability is unchanged

The reviewer's concern with `pub impl From<FfiUnlockError> for FfiVaultError` was that it's necessarily `pub` (orphan rule on the standard `From` trait), but bridge-internal in intent. Refactoring the arm body into a private `unlock_err_to_vault_err` function does NOT change orphan-rule reachability — downstream binding crates can still call `FfiVaultError::from(some_unlock_err)` and bypass the doc warning. The improvement is that future variant additions edit one private function instead of an `impl From` block, reducing the surface that looks like API but isn't. Closes #32.

### Inherited docs drift fixed in passing

README.md and ROADMAP.md "Where we are" paragraphs both said "549 cargo + 9 ignored, 81 bridge, 17 uniffi" — those numbers were the pre-review-fix totals from when PR #31's docs commit landed mid-flight, not the post-merge truth (552 / 83 / 18). Since they were stale from PR #31's merge (not from anything this session changed), the fix rides in this branch's docs commit rather than its own PR.

## What did NOT happen this session

- No B.4c work. NEXT_SESSION's "begin B.4c" instructions are preserved verbatim in the new baton.
- No `save_block` brainstorming, spec, or plan.
- No changes to PyO3 surface — `secretary-ffi-py` was untouched.
- No new tests. The 552 total is unchanged from post-PR-#31; uniffi's 18 are relocated, not added.
- No worktree. Standard branch-in-main-checkout, consistent with B.2 / B.3a / B.3b / B.4a / B.4b.

## Risks carried forward

Same as the pre-cleanup B.4b baton — the cleanup pass did not change the project's design surface, just the file layout and docs. See the "Open decisions and risks" section of `NEXT_SESSION.md` (post-cleanup) for the full carryover list.

## Next session

`NEXT_SESSION.md` post-cleanup. The "(4) Exact commands to resume" section is unchanged from pre-cleanup except that the `cargo test` baseline expectation is now 552 (was 549 in the pre-cleanup NEXT_SESSION).

The next session's first action is the B.4c brainstorming step (NEXT_SESSION post-cleanup, section 4).

---

**Closing inventory:**

- 4 task commits + 1 docs commit on `chore/b4b-deferred-cleanup`.
- File split: `ffi/secretary-ffi-uniffi/src/lib.rs` 979 → 116 lines; new files `errors.rs` (297), `namespace.rs` (303), `wrappers/mod.rs` (15), `wrappers/identity.rs` (131), `wrappers/vault.rs` (89), `wrappers/block.rs` (102).
- Cumulative diff vs. main: ~+1100 / ~−905 lines (refactor + docs).
- Tests: 552 + 9 ignored, 40 pytest, 22 Swift, 23 Kotlin.
- Issues closed: GitHub #32.
- Spec / plan docs: none authored — pure cleanup.
