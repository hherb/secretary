# NEXT_SESSION.md

**Session date:** 2026-05-15 (Code-quality drainage: Issue #29 — uniffi `errors.rs` split into directory module; Issue #25 — clippy `--tests` gate extension + 18 mechanical `sort_by_key` conversions)
**Status:** Two parallel cleanup PRs open against `main`. Test gauntlet clean on both (640 cargo + 9 ignored; clippy / fmt / conformance / spec-freshness PASS; Swift 37/37; Kotlin 37/37). PR #56 (#29) is independent of PR #57 (#25); both touch disjoint files. **Merge order: #56 first, then #57** — the session docs in this file ride inside #57, so #57 carrying the updated `ROADMAP.md` + `NEXT_SESSION.md` is the head of main after both merge.

## (1) What we shipped this session

Two cleanup items from the open backlog that the previous handoff (PR #55, Issue #30) silently dropped. Both are pure code-quality work — no Rust semantic changes — that drain residual technical debt left over from earlier B-phases. Both surfaced during a fresh-eye pass over `gh issue list --state open` at session start.

| Commit | PR | Type | What landed |
|---|---|---|---|
| `b3ece14` | [#56](https://github.com/hherb/secretary/pull/56) | refactor(ffi-uniffi) | **Issue #29** — split the 532-line flat [`ffi/secretary-ffi-uniffi/src/errors.rs`](ffi/secretary-ffi-uniffi/src/errors.rs) into a directory module [`errors/{mod.rs, unlock.rs, vault.rs}`](ffi/secretary-ffi-uniffi/src/errors/) (31 / 145 / 379 lines respectively) mirroring the bridge crate's `error/` pattern that landed in PR #53. Every type, variant, error message, `From` mapping, and pinned test moved verbatim — `git mv`-style rename for `errors.rs → errors/vault.rs` with the unlock half hoisted into its own file. `lib.rs` is unchanged because the existing `pub use errors::{UnlockError, VaultError}` line already feeds the uniffi scaffolding's `crate::TypeName` paths from the new mod regardless of internal layout. Issue #29's original scope (PyO3 + bridge crate splits) was already finished by intermediate PRs #43 (PyO3 lib.rs split during B.4d cleanup) and #53 (bridge `error/vault.rs` directory split, closing #44); this PR closes the uniffi-side gap that those didn't touch. |
| `55bb24d` | [#57](https://github.com/hherb/secretary/pull/57) | fix(clippy) | **Issue #25** — extend the documented clippy gate in CLAUDE.md from `cargo clippy --release --workspace -- -D warnings` to `cargo clippy --release --workspace --tests -- -D warnings`, and fix all 18 `unnecessary_sort_by` lints (introduced in clippy 1.95.0) that the wider gate surfaces in test code: 4 in [`core/tests/proptest.rs`](core/tests/proptest.rs), 12 in [`core/src/vault/manifest.rs`](core/src/vault/manifest.rs) `#[cfg(test)]`, 1 each in [`core/src/vault/conflict.rs`](core/src/vault/conflict.rs) and [`core/src/vault/block.rs`](core/src/vault/block.rs). All 18 are the same mechanical shape — `sort_by(|a, b| a.uuid.cmp(&b.uuid))` → `sort_by_key(|a| a.uuid)` — produced by `cargo clippy --fix --tests`; sort keys are 16-byte UUID arrays (`Copy`), so no `.clone()` is needed. `cargo fmt` re-applied afterwards to collapse the now-shorter chains onto one line. Future regressions will fail locally with the new wider gate documented in CLAUDE.md. |
| _this commit_ | _bundled in_ #57 | docs | ROADMAP.md line 34 (current-state wall) extended with brief notes covering both PRs' work; NEXT_SESSION.md (this file, overwritten); handoff snapshot under `docs/handoffs/2026-05-15-issues-29-25-uniffi-errors-split-and-clippy-tests-gate.md`. Per the standing rule (`feedback_next_session_in_pr.md`), docs ride inside the feature PR, not main directly — they land via #57 (the second-to-merge of this session's two). |

### Why two parallel PRs instead of one squashed branch

One issue per PR is the project's standing rule (`feedback_fix_all_review_issues.md`). Issue #29 (refactor) and issue #25 (lint fixes + gate change) touch disjoint files and have orthogonal review concerns — bundling them would defeat the per-issue-bisectability the rule is there to preserve. The two PRs were authored on separate worktrees under `.worktrees/` (cleaned up at session end).

### Verification at session close (each branch, after `git merge main` no-op)

| Check | PR #56 (Issue #29) | PR #57 (Issue #25) |
|---|---|---|
| `cargo test --release --workspace --no-fail-fast` | **640 passed + 9 ignored** | **640 passed + 9 ignored** |
| `cargo clippy --release --workspace -- -D warnings` | clean | clean |
| `cargo clippy --release --workspace --tests -- -D warnings` | clean (already, no test code touched) | clean (was 18 errors before this PR) |
| `cargo fmt --all -- --check` | OK | OK |
| `uv run core/tests/python/conformance.py` | PASS | PASS |
| `uv run core/tests/python/spec_test_name_freshness.py` | PASS (96 / 0 / 2 unchanged) | PASS (96 / 0 / 2 unchanged) |
| `bash ffi/secretary-ffi-uniffi/tests/swift/run.sh` | **37/37 PASS** (no smoke runner change) | **37/37 PASS** (no smoke runner change) |
| `bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh` | **37/37 PASS** (no smoke runner change) | **37/37 PASS** (no smoke runner change) |

## (2) What's next

### Sub-project B.6 design — Swift + Kotlin conformance smoke runners (recommended, unchanged from prior handoff)

The cleanup queue is now nearly drained. After PR #56 + PR #57 merge, the only remaining open issues blocking on nothing else are:

- **#35** — exercise mid-call wipe race in `save_block`. Needs a `#[cfg(test)]` injection barrier in `OpenVaultManifest` between snapshot and write-back. Probably 1 PR, but pacing this against B.6 forward progress is a judgment call (the bug it would catch is exotic — concurrent wipe-during-save — and a future refactor would be the only realistic way to regress it).

All other open issues (#37, #38, #45) are blocked on Sub-project C and not actionable in isolation.

**B.6 is therefore the right forward-progress chunk to take up.** Preliminary acceptance criteria (refine during brainstorming):

- A new `tests/conformance/` harness on each of [`ffi/secretary-ffi-uniffi/tests/swift/`](ffi/secretary-ffi-uniffi/tests/swift/) and [`ffi/secretary-ffi-uniffi/tests/kotlin/`](ffi/secretary-ffi-uniffi/tests/kotlin/) that loads the same `golden_vault_001` fixture, performs the same sequence of FFI calls (`unlock → read_block → save_block → share_block → trash_block → restore_block`), and pins outputs against a `conformance_kat.json` cross-language KAT.
- Should produce a single PASS/FAIL line per host runner; the existing `run.sh` invocation pattern stays.

**Scope:** Likely 1–2 PRs. Start with a brainstorming pass (the `superpowers:brainstorming` skill) — the design space includes whether the KAT is generated by Rust (golden-truth) and consumed by both bindings, or generated by each binding and compared cross-wise.

### Issue #35 — mid-call wipe race in `save_block` (carried forward from B.4c era)

The orchestrator at [ffi/secretary-ffi-bridge/src/save/orchestration.rs:114-125](ffi/secretary-ffi-bridge/src/save/orchestration.rs#L114-L125) handles a documented race where `manifest.wipe()` lands between `snapshot_for_save_block` and `replace_manifest_and_file`. The behavior is correct (returns `CorruptVault`, but on-disk state is updated and signed). The existing `save_block_on_wiped_manifest_returns_corrupt_vault` test only exercises the pre-call wipe. A mid-call test needs a `#[cfg(test)]` synchronization barrier — adds a noop-in-release `Option<Arc<...>>` field to `OpenVaultManifest`. Defer to a focused session; less valuable than B.6 forward progress unless a refactor near `save_block` is being planned.

### Issue #38 — proptest case budget (B.4c era)

Still waiting on Sub-project C infrastructure (shared writable-vault fixture). Not actionable yet.

### Issue #45 — three `pub(crate) #[allow(dead_code)]` accessors on `OpenVaultManifest`

Forward-compat for Sub-project C. Not actionable in isolation. Revisit when C starts or after B.6 lands.

### Issue #37 — design discipline reminder for Sub-project C

Preserve the manifest-only-read invariant for the sync layer. Not actionable until C starts.

## (3) Open decisions and risks

### Risks

- **PR merge order matters.** Both PRs were authored against `main` at `9732797`. They touch disjoint files (#56 only changes `ffi/secretary-ffi-uniffi/src/errors{.rs,/*}`; #57 only changes `CLAUDE.md` + `core/src/vault/{block,conflict,manifest}.rs` `#[cfg(test)]` blocks + `core/tests/proptest.rs` + the docs ROADMAP/NEXT_SESSION/handoff bundle). Either order is mechanically clean (no merge conflict expected). However, NEXT_SESSION.md lives inside #57's docs commit and references PR #56 as merged — if #57 merged first, post-merge `main` would briefly carry a NEXT_SESSION claiming "PR #56 (#29) has landed" before #56 actually does. The recommended merge order is **#56 → #57** so the docs commit's claims match `main`'s git history at the moment it lands. Either order ends up identical after both are in, so this is a cosmetic concern only.
- **Otherwise no new risks.** Pure cleanup work: zero Rust semantic changes, zero public-API changes, zero changes to any execution path that wasn't already covered by pinned tests.

### Issues still open from prior sessions

- **Issue #35** — mid-call wipe race in `save_block` (forward-compat for B.6 / Sub-project C; not actionable in isolation, no semantic gap).
- **Issue #37** — design discipline reminder for Sub-project C (preserve the manifest-only-read invariant for the sync layer); not actionable until C starts.
- **Issue #38** — proptest case budget (shared writable-vault fixture); not actionable until Sub-project C.
- **Issue #45** — three `pub(crate) #[allow(dead_code)]` accessors on `OpenVaultManifest` (forward-compat for Sub-project C; revisit when C starts).
- **Issue #29** — **CLOSED in this session by PR #56.**
- **Issue #25** — **CLOSED in this session by PR #57.**

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git checkout main
git pull --ff-only origin main                       # after PRs #56 + #57 merge
git fetch --prune origin                             # mark merged branches as [gone]
git status --short                                   # expect: clean
git branch -vv                                       # expect: only main (after deleting [gone] branches)
git worktree list                                    # expect: only the primary worktree

# Verify the test gauntlet still matches this session's closing numbers:
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | python3 -c "
import sys, re
p=f=i=0
for line in sys.stdin:
    m = re.search(r'(\d+) passed.*?(\d+) failed.*?(\d+) ignored', line)
    if m: p+=int(m.group(1)); f+=int(m.group(2)); i+=int(m.group(3))
print(f'TOTAL: {p} passed; {f} failed; {i} ignored')"
# Expect: TOTAL: 640 passed; 0 failed; 9 ignored

# Note the WIDENED clippy gate — covers both lib + test targets after PR #57:
cargo clippy --release --workspace --tests -- -D warnings    # Expect: clean (was 18 errors pre-#57)
cargo fmt --all -- --check                                    # Expect: OK
uv run core/tests/python/conformance.py                       # Expect: PASS
uv run core/tests/python/spec_test_name_freshness.py          # Expect: PASS (96 / 0 / 2)

bash ffi/secretary-ffi-uniffi/tests/swift/run.sh              # Expect: 37/37 PASS
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh             # Expect: 37/37 PASS

# Then pick the next chunk — B.6 design (recommended):
#   Run /brainstorm on Swift+Kotlin conformance smoke runners
#   (cross-language KAT-driven parity testing of the FFI surface)
# or check the still-open backlog:
gh issue list --state open
```

---

## Closing inventory

- **Branch state on close:** two open PRs against `main` (`9732797`). `cleanup/issue-29-uniffi-errors-split` carries 1 code commit (`b3ece14`); `cleanup/issue-25-clippy-tests-gate` carries 1 code commit (`55bb24d`) + this docs commit. Main is untouched until the PRs merge. Both worktrees under `.worktrees/` to be removed by the post-merge `clean_gone` skill invocation.
- **Workspace tests:** **640 cargo + 9 ignored** (unchanged baseline — no Rust semantic changes; the `errors::tests` test module was renamed to `errors::unlock::tests` + `errors::vault::tests` but the test count is identical). 68 pytest unchanged. Swift smoke 37/37 PASS; Kotlin smoke 37/37 PASS.
- **README / ROADMAP:** README unchanged (no test-count references; per `feedback_readme_style.md` README walls were pruned in PR #51). ROADMAP line 34 (current-state summary) extended with brief notes for both PRs — clippy `--tests` extension + 18 sort_by_key conversions (#25), and the `errors/` directory split (#29).
- **CLAUDE.md:** the documented clippy invocation widened from `cargo clippy --release --workspace -- -D warnings` to `cargo clippy --release --workspace --tests -- -D warnings`. No other change.
- **Files modified:** `ffi/secretary-ffi-uniffi/src/errors.rs` (deleted) → `ffi/secretary-ffi-uniffi/src/errors/{mod.rs,unlock.rs,vault.rs}` (created); `core/src/vault/{block.rs,conflict.rs,manifest.rs}` `#[cfg(test)]` blocks (mechanical `sort_by_key` conversion + fmt); `core/tests/proptest.rs` (mechanical `sort_by_key` conversion + fmt); `CLAUDE.md` (extended clippy gate line); `ROADMAP.md` (line 34 wall extended); `NEXT_SESSION.md` (overwritten, this file); `docs/handoffs/2026-05-15-issues-29-25-uniffi-errors-split-and-clippy-tests-gate.md` (created, this file's frozen archive).
- **Issues closed this session:** [#29](https://github.com/hherb/secretary/issues/29) — uniffi-side `errors.rs` split into directory module (closes the last item from #29's original scope; PyO3 + bridge halves were closed by intermediate PRs #43 and #53). [#25](https://github.com/hherb/secretary/issues/25) — clippy gate extended to `--tests` target + 18 `unnecessary_sort_by` lints fixed.
