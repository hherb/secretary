# NEXT_SESSION.md

**Session date:** 2026-05-16 (issue #35 mid-call wipe race test)
**Status:** Branch `test/issue-35-save-block-mid-call-wipe-race` carries five commits on top of `1b4a529` (PR #64 merge). PR open against `main`. Gauntlet green: 642 cargo + 10 ignored / clippy clean / fmt OK / Python conformance + freshness PASS (96 / 0 / 2) / Swift smoke 38 / Swift conformance 11/11 / Kotlin smoke 39 / Kotlin conformance 11/11.

## (1) What we shipped this session

| Commit | Type | What landed |
|---|---|---|
| `aa07c72` | docs(specs) | Design doc at [docs/superpowers/specs/2026-05-16-issue-35-save-block-mid-call-wipe-race-design.md](docs/superpowers/specs/2026-05-16-issue-35-save-block-mid-call-wipe-race-design.md). 8 sections. Self-review pass fixed an inaccurate "cargo test 60s default timeout" claim, a wrong "design holds the inner lock during `core::save_block`" claim (the bridge releases the lock for `core::save_block`'s duration; the "during-core" window is observationally equivalent to the post-core window we DO test), and an awkward "published-as-test-target" phrasing. Updated in `04af895` to reflect the `#[doc(hidden)] pub` outcome of the visibility-blocker decision below. |
| `97c5b91` | docs(plans) | Implementation plan at [docs/superpowers/plans/2026-05-16-issue-35-save-block-mid-call-wipe-race.md](docs/superpowers/plans/2026-05-16-issue-35-save-block-mid-call-wipe-race.md). 8 tasks (3 implementation file edits + verification gauntlet + commit + README/ROADMAP check + handoff + push/PR). Production-side first (manifest + orchestrator) before test, contra the spec's TDD-staged "test first" suggestion — the intermediate state would hang rather than fail cleanly. Updated in `04af895` for the same visibility-blocker decision. |
| `04af895` | test(ffi-bridge) | Issue #35 closure. `mid_call_hook: Mutex<Option<Box<dyn Fn() + Send>>>` field on `OpenVaultManifest` + `pub(crate) fn run_mid_call_hook` caller (one line in the `save_block` orchestrator's `Ok` arm) + `#[doc(hidden)] pub fn install_mid_call_hook` installer. New test `save_block_wipe_during_call_returns_corrupt_vault_but_persists_on_disk` in `tests/save_block.rs` uses a `MidCallRace` helper (two `sync_channel(0)` rendezvous handshakes) to drive a deterministic mid-call wipe, asserting (a) `CorruptVault` with the documented "closed during save" detail and (b) the partial-success-mid-race contract — re-open + `find_block` + `read_block` round-trip on the post-race on-disk state. **5 files changed** because the spec + plan got synced in-commit to reflect the `#[doc(hidden)] pub` outcome below. Cargo test count: 641 + 10 → 642 + 10. |
| `cbc0913` | docs(roadmap) | ROADMAP line 34 cargo-count bump (641 → 642) + one-clause #35 mention. |
| `d7be4ca` | docs(ffi-bridge) | PR #65 self-review followup. Three doc-comment edits, no executable code changes: (a) [ffi/secretary-ffi-bridge/src/save/orchestration.rs](ffi/secretary-ffi-bridge/src/save/orchestration.rs) inline comment fix — replace misleading "Empty body in release builds" with accurate "Always present in all builds — pays one uncontended Mutex lock + Option::is_none check per call". (b) `OpenVaultManifest::wipe` doc gains a paragraph noting `wipe()` does NOT clear `mid_call_hook` (separate Mutex; test-only state). (c) `install_mid_call_hook` doc gains paragraphs on the bundled `MidCallRace` helper's single-shot semantics + closure-panic recovery contract. Gauntlet re-run: 642 + 10 / clippy clean / fmt OK / Python + Swift + Kotlin conformance unchanged. |

### Visibility blocker mid-execution (worth remembering)

The original spec used `#[cfg(test)] pub(crate)` for `install_mid_call_hook`. First test run failed to compile with `method not found for &OpenVaultManifest`. Root cause: **`--cfg test` is NOT propagated to dependencies.** When the integration-test binary at `tests/save_block.rs` compiles, it links against `secretary-ffi-bridge` compiled **without** `cfg(test)`, so `#[cfg(test)]` items in the lib are invisible to integration tests in `tests/*.rs`.

Three workarounds considered: (1) `#[doc(hidden)] pub` always-present, (2) a `test-hooks` Cargo feature with `--features` in CI commands, (3) move the test inline as a unit test. Picked (1) — standard pattern in `tokio` / `hyper` / `tracing` for analogous test hooks. Spec + plan updated in `04af895` to reflect.

Calibration takeaway: when designing test infrastructure that crosses lib ↔ integration-test boundaries, the default assumption should be `#[doc(hidden)] pub`, not `#[cfg(test)] pub(crate)`. The latter only works for **unit** tests inside the lib's own `#[cfg(test)] mod tests`.

### Final gauntlet at session close

| Check | Result |
|---|---|
| `cargo test --release --workspace --no-fail-fast` | **642 passed + 10 ignored** (was 641 + 10) |
| `cargo clippy --release --workspace --tests -- -D warnings` | clean |
| `cargo fmt --all -- --check` | OK |
| `uv run core/tests/python/conformance.py` | PASS |
| `uv run core/tests/python/spec_test_name_freshness.py` | PASS (96 / 0 / 2 — unchanged baseline) |
| `bash ffi/secretary-ffi-uniffi/tests/swift/run.sh` | OK, 38 PASS asserts |
| `bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh` | 11/11 PASS |
| `bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh` | OK, 39 PASS asserts |
| `bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh` | 11/11 PASS |

### Inline-execution notes

Plan estimated 8–15 min wall-clock for inline execution; actual was ~12 min including the visibility-blocker pause + spec/plan re-sync. Subagent-driven would have stretched to ~30–45 min for the same content with minimal review value (each task is small enough to inspect in the diff). Confirms the calibration from the B.6 pre-v2 cleanup bundle: inline execution wins for small bundles; subagent-driven shines when individual tasks have long compile/test cycles or load-bearing reviews between tasks.

## (2) What's next

### Sub-project B.6 v2 design — lifecycle conformance KAT (issue [#59](https://github.com/hherb/secretary/issues/59))

Unchanged from the prior NEXT_SESSION. Top of the forward-progress queue. Three options on the `save_block` AEAD-nonce determinism question (cfg(test) RNG knob / shape-only assertions / dyn RngCore parameter) — start with `/brainstorm` before writing the v2 design doc.

### Optional follow-ups now unblocked by this session

- **Trash / restore mid-call wipe race tests.** Same hook, same `MidCallRace` helper. Each is one additional `manifest.run_mid_call_hook();` line in the respective orchestrator + one test file. Lift `MidCallRace` to `tests/common/mid_call_race.rs` when the second consumer arrives. Not blocking B.6 v2; pick up if a sub-project C audit surfaces the need.

### Issues #37, #38, #45 (blocked on Sub-project C)

Unchanged from prior handoff. Not actionable until C starts.

## (3) Open decisions and risks

### Risks

- **`save_block` determinism design (B.6 v2 blocker).** Real architectural decision; spend a session brainstorming before writing code.
- **Future orchestrators must remember `run_mid_call_hook` to be testable for the same race.** Doc comment on the method names the contract; reviewer catch is the mitigation. No mechanical enforcement (over-engineering for 3-4 call sites).
- **`mid_call_hook` field is always present in production builds.** Costs ~24 bytes per `OpenVaultManifest` + one `Mutex` lock per `save_block` call. Trivial for this domain (few open vaults per process; `save_block` not a hot path); flagged because the field is no longer cfg-gated as the original spec assumed.

### Issues still open from prior sessions

- **Issue #37** — design discipline reminder for Sub-project C; not actionable until C starts.
- **Issue #38** — proptest case budget (shared writable-vault fixture); not actionable until C.
- **Issue #45** — three `pub(crate) #[allow(dead_code)]` accessors on `OpenVaultManifest`; revisit when C starts.
- **Issue #59** — B.6 v2 lifecycle conformance KAT. Design + plan + impl. Next session candidate.
- **Issue #35** — closed this session by the PR (when it merges).

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git checkout main
git pull --ff-only origin main                       # after the PR merges
git fetch --prune origin
git status --short                                   # expect: clean
git branch -vv                                       # expect: only main (after local feature branch is deleted)
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
# Expect: TOTAL: 642 passed; 0 failed; 10 ignored

cargo clippy --release --workspace --tests -- -D warnings    # Expect: clean
cargo fmt --all -- --check                                    # Expect: OK
uv run core/tests/python/conformance.py                       # Expect: PASS
uv run core/tests/python/spec_test_name_freshness.py          # Expect: PASS (96 / 0 / 2)

bash ffi/secretary-ffi-uniffi/tests/swift/run.sh              # Expect: OK; ~38 PASS asserts
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh  # Expect: 11/11 PASS
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh             # Expect: OK; ~39 PASS asserts
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh # Expect: 11/11 PASS

# Next forward-progress chunk — B.6 v2 design (recommended):
#   /brainstorm on the save_block determinism question (issue #59)
# or check the open backlog:
gh issue list --state open
```

---

## Closing inventory

- **Branch state on close:** `test/issue-35-save-block-mid-call-wipe-race` carries 4 commits on top of `1b4a529` — 1 spec + 1 plan + 1 implementation (5 files: 3 code + 2 spec/plan in-commit sync) + 1 ROADMAP touch-up. PR open against main.
- **Workspace tests:** **642 cargo + 10 ignored** (was 641 + 10). Conformance + Swift + Kotlin runners unchanged.
- **README:** unchanged.
- **ROADMAP:** line 34 cargo-count bump 641 → 642 plus a one-clause #35 mention.
- **CLAUDE.md:** unchanged.
- **Files created:** [`docs/superpowers/specs/2026-05-16-issue-35-save-block-mid-call-wipe-race-design.md`](docs/superpowers/specs/2026-05-16-issue-35-save-block-mid-call-wipe-race-design.md), [`docs/superpowers/plans/2026-05-16-issue-35-save-block-mid-call-wipe-race.md`](docs/superpowers/plans/2026-05-16-issue-35-save-block-mid-call-wipe-race.md), [`NEXT_SESSION.md`](NEXT_SESSION.md) (this file, overwritten), [`docs/handoffs/2026-05-16-issue-35-save-block-mid-call-wipe-race.md`](docs/handoffs/2026-05-16-issue-35-save-block-mid-call-wipe-race.md) (frozen archive of this file).
- **Files modified:** [`ffi/secretary-ffi-bridge/src/vault/manifest.rs`](ffi/secretary-ffi-bridge/src/vault/manifest.rs) (+1 field, +2 methods, +~26 LOC of doc), [`ffi/secretary-ffi-bridge/src/save/orchestration.rs`](ffi/secretary-ffi-bridge/src/save/orchestration.rs) (+1 call site, +8 lines of comment), [`ffi/secretary-ffi-bridge/tests/save_block.rs`](ffi/secretary-ffi-bridge/tests/save_block.rs) (+1 import, +~30 LOC helper, +~50 LOC test), [`ROADMAP.md`](ROADMAP.md) (count + one-clause #35 mention).
- **Issues filed this session:** none.
- **PR to open:** `test(ffi-bridge): mid-call wipe race in save_block (closes #35)` against `main`.
