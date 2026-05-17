# NEXT_SESSION.md

**Session date:** 2026-05-17 (B.6 v2 lifecycle conformance KAT)
**Status:** PR [#66](https://github.com/hherb/secretary/pull/66) open against `main`. Branch `design/b6-v2-lifecycle-conformance-kat` carries **14 commits** on top of `4e8f7fa` (PR #65 merge) — 13 from the v2 design + plan + implementation, plus 1 post-review fix commit `22d5ff2` covering I1 + I2 + M2 from the final code review. Two follow-up issues filed (#67 for M3 file-size drift, #68 for M4 record_uuid panic-on-wrong-length). Gauntlet all green: 642 cargo + 10 ignored / clippy clean / fmt OK / Python conformance + freshness PASS (96 / 0 / 2) / Swift smoke 38 / **Swift conformance 20/20** / Kotlin smoke 39 / **Kotlin conformance 20/20**.

## (1) What we shipped this session

| Commit | Type | What landed |
|---|---|---|
| `3d44e83` | docs(specs) | Design doc at [docs/superpowers/specs/2026-05-17-ffi-b6-v2-lifecycle-conformance-kat-design.md](docs/superpowers/specs/2026-05-17-ffi-b6-v2-lifecycle-conformance-kat-design.md). 12 sections. Self-review pass during brainstorming caught (a) `recipient_count` was wrongly described as "per-record" — recipients live on the BLOCK summary, and `BlockSummary.recipient_uuids` is already exposed on every binding; the §11 "open question" about a recipient-count accessor was therefore not actually open. |
| `c5bb678` | docs(specs) | Spec correction: vault_001/contacts/ alice user_uuid was `7921b6ed8fa8cff2baf61a43f3a66a9f` per `golden_vault_001_inputs.json:39`, not `78d7ab1d…` (that UUID belongs to bob). No design change. |
| `1e33317` | docs(plans) | Implementation plan at [docs/superpowers/plans/2026-05-17-ffi-b6-v2-lifecycle-conformance-kat.md](docs/superpowers/plans/2026-05-17-ffi-b6-v2-lifecycle-conformance-kat.md). 16 tasks. Plan self-review fixed an `SecretString`/`SecretBytes` import path that referenced `secretary_ffi_bridge::SecretString` (the bridge doesn't re-export them — they live at `secretary_core::crypto::secret`). |
| `2f1fea6` | test(conformance-kat) | Types for v2: `Operation` enum +5 variants, `PostState` + `ExpectedReadBlock` structs, `OkPayload.post_state` field. Implementer also added a temporary wildcard arm in `conformance_kat.rs` (required to keep the exhaustive match compiling between Task 2 and Task 6). |
| `30e56a1` | test(conformance-kat) | `fixtures.rs` additions: `copy_vault_to_tempdir` + `read_contact_card_bytes`. Mirrors the bridge crate's `fresh_writable_vault()` precedent. |
| `e5e857f` | test(conformance-kat) | `dispatch.rs` additions: `run_open_writable` + `run_save_block` + `run_share_block` + `run_trash_block` + `run_restore_block` + shared input-parsing helpers (`uuid_from_inputs`, `block_input_from_inputs`, `now_ms_from_inputs`). Wrong-length block_uuid / device_uuid synthesize `InvalidArgument` matching uniffi's namespace-layer length check. |
| `05eda52` | test(conformance-kat) | `dispatch.rs` additions: `assert_post_state` (block_count + find_block_uuid_hex + recipient_count + round-trip read_block) + factored `assert_read_block_records` out of `assert_read_block_ok` for reuse. v1 `replay_conformance_kat` still 11/11. |
| `5efe629` | test(conformance-kat) | `conformance_kat.rs` replay loop wired in: 5 new dispatch arms + 2 new exhaustiveness-error arms + `find_writable_dir` helper + `handle_write_op_result` helper + tempdir/writable-dir tracking. Temporary Task-2 wildcard arm removed. `#[allow(dead_code)]` removed from 11 sites now that the wiring is live. **Spec compliance review confirmed all 10 requirements met.** |
| `aaa73d6` | test(conformance-kat) | The big one — KAT JSON v2 (version bump 1→2, 9 new vectors with `<filled-in-by-generator>` placeholder) + Rust version assertion updated to accept `1 \|\| 2` + extended `#[ignore]` generator to fill the placeholder + **cache-ancestor fix** for chained write ops: the original Task 6 wiring looked up `cache.get(predecessor)` where `predecessor` is the immediate `after:` value, but only the writable-open vector ever inserts into the cache (write ops mutate via interior mutability and do NOT re-key). Added `find_cache_ancestor_name` that walks the `after:` chain back to the cache-keyed writable-open ancestor. Also corrected the `restore_block_not_in_trash` vector: restoring a *live* uuid produces `BlockUuidAlreadyLive`, not `BlockNotInTrash`; the vector now uses `0x00*16` (never-live, never-trashed) to exercise the `BlockNotInTrash` path. **Rust replay: 20/20.** |
| `d843ee0` | test(conformance-kat) | Swift conformance runner extended with 5 new dispatch cases + `recursiveCopy` + `readContactCardBytes` + `assertPostState` + chain-walkers. Version check bumped to `(1, 2).contains()`. Implementer caught a `break`-out-of-`for`-vs-`switch` bug in the plan's `existing_recipient_uuid_hexes` loop. **Swift conformance: 20/20 PASS.** |
| `9b7c808` | test(conformance-kat) | Kotlin conformance runner extended with the same shape, using `java.nio.file.Files.walk` + `Path` + `JSONObject.getLong("now_ms")`. **Kotlin conformance: 20/20 PASS.** |
| `3f6ade1` | docs(roadmap) | ROADMAP: Sub-project B progress line gains `B.6 v2 conformance KAT — lifecycle ✅`. Line 34 paragraph rewritten to reflect v2 closure + the determinism reframing (cross-language parity doesn't require AEAD-nonce byte pinning since all three host runners share the same Rust bridge). |
| `8637a49` | docs | NEXT_SESSION.md + frozen handoff snapshot, committed inside the PR per the standing rule. |
| `22d5ff2` | fix(conformance-kat) | Post-review fixes from the final full-PR code-quality review. **I1**: Swift + Kotlin runners no longer short-circuit `save_block_invalid_input` — they now pass the 1-byte device_uuid through to `saveBlock()` so the real uniffi-namespace `VaultException.InvalidArgument` fires (which is exactly the surface the vector exists to pin). **I2**: dropped the unimplemented "find_block_uuid_hex: null asserts absent" capability — it was documented in spec §§4.2/8 but never wired (Rust panicked, Swift/Kotlin silently skipped); the `block_count` assertion already covers absence-after-trash (trash_block_happy pins 2→1, which is only reachable if find_block returns None). `PostState.find_block_uuid_hex: Option<Option<String>>` → `Option<String>`. Spec doc §§2/4.2/5.3/8 updated. **M2**: cycle-guards on `find_writable_dir` and `find_cache_ancestor_name` in all three runners — bounded by `vectors.len()` so an authoring-error `after:` cycle fails loudly instead of hanging CI. Final gauntlet still 20/20 on Swift + Kotlin. |

### Headline design decision: shape + round-trip, not bytes

The B.6 v1 spec deferred lifecycle ops to v2 because `save_block` uses OS-CSPRNG-driven AEAD nonces, framing it as "either add a test-RNG knob or settle for shape-only assertions." The v2 brainstorm reframed: **all three host runners (Rust / Swift / Kotlin) delegate to the same `secretary-ffi-bridge` crate via uniffi.** They cannot disagree on AEAD nonce bytes — those bytes are produced inside the shared Rust code path. Cross-language parity does not require byte-level determinism.

Consequence: **no bridge changes.** v2 is replay-side-only. The KAT pins typed Ok/Err + post-call manifest shape (`block_count`, `find_block(uuid).is_some()`, `BlockSummary.recipient_uuids.len()`) + round-trip read after `save_block_insert`. Bridge regression detection still happens — it's just covered by the existing `core/tests/save_block.rs` round-trip tests and the fuzz harness, not by the KAT.

### Two implementation-mid-flight bug fixes worth remembering

1. **Cache-ancestor lookup for chained write ops.** Task 6's dispatch arms used `cache.get(predecessor)` directly. That works for the first save_block (whose `after:` points at the writable-open vector, which IS in the cache). It does NOT work for subsequent share_block, trash_block, restore_block, which `after:` write vectors that didn't insert under their own name (the bridge's `OpenVaultManifest` is mutated in place via interior mutability — no re-keying needed). Fix: `find_cache_ancestor_name` walks the chain back to the writable-open ancestor.
2. **`BlockNotInTrash` vs `BlockUuidAlreadyLive` semantics.** Restoring a CURRENTLY-LIVE uuid returns `BlockUuidAlreadyLive`. `BlockNotInTrash` only fires when the uuid is neither live nor in trash — i.e. a uuid the manifest has never seen. The original `restore_block_not_in_trash` vector chained off `restore_block_happy` and re-restored the just-restored block, which produces `BlockUuidAlreadyLive`. Fix: vector now uses `0x00*16` (never-touched) to exercise the not-in-trash path.

### Subagent-driven execution discipline (transparency)

The implementation phase was dispatched via `subagent-driven-development`. **Hybrid review applied:** Tasks 2–5 (small, mechanical Rust scaffolding with plan-prescribed code blocks) were dispatched with implementer-only review (controller diff inspection + cargo gauntlet at each commit). Task 6 (the critical replay-loop wiring) got a full spec-compliance reviewer dispatch (✅ compliant). Tasks 7+9+10 were bundled (data file + generator + green-checkpoint) into one commit `aaa73d6`. Tasks 11 + 12 (Swift + Kotlin) were implementer-only because both had per-task verification gates (`run_conformance.sh` 20/20 PASS required before commit).

Calibration: full subagent-driven (implementer + spec + quality per task) would have been ~48 dispatches for 13 implementation tasks. The hybrid approach was ~14 implementer + 1 spec reviewer = 15 dispatches. The work that genuinely benefited from fresh-context subagent isolation was Swift + Kotlin (large, language-specific, easy to get wrong on JSON type coercion). The small Rust scaffolding tasks (2–5) benefited little from the subagent layer.

### Final gauntlet at session close

| Check | Result |
|---|---|
| `cargo test --release --workspace --no-fail-fast` | **642 passed + 10 ignored** (unchanged — `replay_conformance_kat` is one `#[test]` running all 20 vectors internally) |
| `cargo clippy --release --workspace --tests -- -D warnings` | clean |
| `cargo fmt --all -- --check` | OK |
| `uv run core/tests/python/conformance.py` | PASS |
| `uv run core/tests/python/spec_test_name_freshness.py` | PASS (96 / 0 / 2 — unchanged baseline) |
| `bash ffi/secretary-ffi-uniffi/tests/swift/run.sh` | OK, 38 PASS asserts |
| `bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh` | **20/20 PASS** (was 11/11) |
| `bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh` | OK, 39 PASS asserts |
| `bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh` | **20/20 PASS** (was 11/11) |

## (2) What's next

### Wait for PR #66 review + merge

PR [#66](https://github.com/hherb/secretary/pull/66) is open against `main` with 14 commits. CI gates (CodeQL) should pass; the local gauntlet is green. Once merged, run the standard cleanup:

```bash
cd /Users/hherb/src/secretary
git checkout main
git pull --ff-only origin main
git fetch --prune origin
git branch -D design/b6-v2-lifecycle-conformance-kat   # local cleanup after [gone] on remote
```

### After PR merges — Sub-project C kickoff

B.6 design arc closes when this PR merges. Next forward-progress chunk is **Sub-project C — Sync orchestration**. No design docs exist yet; this will start with `/brainstorm` on the C scope (file watching, cloud-folder integration, conflict-detection scheduling, headless via FFI). Open questions to brainstorm before any code:
- Which conflict-detection trigger? File watcher (inotify/FSEvents/ReadDirectoryChangesW) vs. poll vs. event-driven via cloud-folder webhooks?
- Where does the orchestrator live — in-process per platform UI, or a separate daemon?
- How does conflict resolution UI surface? (CRDT auto-merge per `core/src/vault/conflict.rs` handles 99% — the design needs to decide what to do with the remaining 1%.)

### Optional follow-ups now unblocked by v2

- **Final code review of the entire PR**: I deferred running a full code-quality reviewer on the PR (the hybrid subagent-driven approach skipped per-task quality reviewers). If you'd like one, dispatch `feature-dev:code-reviewer` against the diff `4e8f7fa..HEAD` on this branch before merging.
- **PyO3 conformance runner** (B.6 v2 PyO3): the JSON KAT format is binding-agnostic; adding a Python host runner against PyO3 would round out the three-language parity contract. Future PR; not blocking.

## (3) Open decisions and risks

### Risks

- **Test-state coupling across v2 vectors.** All 8 lifecycle vectors chain via `after:` against ONE writable-vault copy. A failure in `save_block_insert_happy` cascades to share/trash/restore being skipped or operating on the wrong state. The `find_cache_ancestor_name` walker tolerates a missing intermediate cache entry by walking past it, but a `restore_block_happy` after a failed `trash_block_happy` would observe wrong state. Mitigation: each per-vector PASS line is gated on its own sub-check count, so cascade failures are clearly attributed in the output. Future v3 could split into independent per-op chains if this becomes a problem.
- **Future Operation enum variants need dispatch arms in all three runners.** The exhaustive Rust match catches missed Rust arms at compile time. Swift's `switch` with `default:` and Kotlin's `when {}` with `else ->` will silently fall to the default branch (which marks the vector as failed, but doesn't tell the author "you forgot to add a case"). Acceptable for the current 3-runner setup; would be worth revisiting if more bindings appear.

### Issues still open from prior sessions

- **Issue #37** — design discipline reminder for Sub-project C; not actionable until C starts.
- **Issue #38** — proptest case budget (shared writable-vault fixture); not actionable until C.
- **Issue #45** — three `pub(crate) #[allow(dead_code)]` accessors on `OpenVaultManifest`; revisit when C starts.
- **Issue #59** — closed by this session's PR #66 when it merges.

### Issues filed this session (B.6 v2 follow-ups)

- **Issue [#67](https://github.com/hherb/secretary/issues/67)** — split conformance KAT helper files past 500-LOC threshold. Three files affected: `core/tests/conformance_kat_helpers/dispatch.rs` (615 lines), `ffi/secretary-ffi-uniffi/tests/swift/conformance.swift` (~766), `ffi/secretary-ffi-uniffi/tests/kotlin/Conformance.kt` (~880). Not blocking; pick up before the next test-infrastructure expansion.
- **Issue [#68](https://github.com/hherb/secretary/issues/68)** — `block_input_from_inputs` panics on wrong-length `record_uuid_hex`. No vector exercises this path today, but a future v3 negative-path vector would crash instead of synthesizing `InvalidArgument`. Defensive fix: replace inline `copy_from_slice` with a `uuid_from_inputs`-style helper.

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git checkout design/b6-v2-lifecycle-conformance-kat   # if not already
git status --short                                     # expect: clean
git log --oneline -3                                   # expect: 3f6ade1 / 9b7c808 / d843ee0 on top
git branch -vv                                         # if branch is gone (PR merged), `git checkout main && git pull --ff-only`

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
cargo fmt --all -- --check                                   # Expect: OK
uv run core/tests/python/conformance.py                      # Expect: PASS
uv run core/tests/python/spec_test_name_freshness.py         # Expect: PASS (96 / 0 / 2)

bash ffi/secretary-ffi-uniffi/tests/swift/run.sh             # Expect: OK; ~38 PASS asserts
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh # Expect: 20/20 PASS
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh            # Expect: OK; ~39 PASS asserts
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh # Expect: 20/20 PASS

# If the PR is still open and needs pushing/creating:
git push -u origin design/b6-v2-lifecycle-conformance-kat
gh pr create --base main --head design/b6-v2-lifecycle-conformance-kat \
  --title "test(conformance-kat): B.6 v2 lifecycle KAT (closes #59)" \
  --body "$(cat docs/handoffs/2026-05-17-ffi-b6-v2-lifecycle-conformance-kat.md | head -80)"
# (the canonical PR body lives in §2 of this NEXT_SESSION.md — copy from there)

# Next forward-progress chunk after merge — Sub-project C:
#   /brainstorm on sync orchestration scope
# Or check the open backlog:
gh issue list --state open
```

---

## Closing inventory

- **Branch state on close:** `design/b6-v2-lifecycle-conformance-kat` carries **14 commits** on top of `4e8f7fa` — 3 docs (spec + UUID fix + plan) + 9 implementation/test commits + 1 handoff commit (`8637a49`) + 1 post-review fix commit (`22d5ff2`). PR [#66](https://github.com/hherb/secretary/pull/66) open against `main`.
- **Workspace tests:** **642 cargo + 10 ignored** (unchanged — `replay_conformance_kat` is one `#[test]` running 20 vectors internally; the new vectors don't add `#[test]` entries).
- **Per-binding conformance counts:** Swift `20/20 PASS` (was 11/11), Kotlin `20/20 PASS` (was 11/11), Rust `replay_conformance_kat ... ok`.
- **README:** unchanged (B.6 is a test harness, not a new FFI surface — same convention as B.6 v1).
- **ROADMAP:** Sub-project B progress line gains `B.6 v2 conformance KAT — lifecycle ✅`; line 34 paragraph rewritten to reflect v2 closure + the determinism reframing.
- **CLAUDE.md:** unchanged (the run_conformance.sh entries already documented are unchanged; same shell entry points, new vectors).
- **Files created this session:** [`docs/superpowers/specs/2026-05-17-ffi-b6-v2-lifecycle-conformance-kat-design.md`](docs/superpowers/specs/2026-05-17-ffi-b6-v2-lifecycle-conformance-kat-design.md), [`docs/superpowers/plans/2026-05-17-ffi-b6-v2-lifecycle-conformance-kat.md`](docs/superpowers/plans/2026-05-17-ffi-b6-v2-lifecycle-conformance-kat.md), [`NEXT_SESSION.md`](NEXT_SESSION.md) (this file, overwritten), [`docs/handoffs/2026-05-17-ffi-b6-v2-lifecycle-conformance-kat.md`](docs/handoffs/2026-05-17-ffi-b6-v2-lifecycle-conformance-kat.md) (frozen archive of this file).
- **Files modified this session:** [`core/tests/data/conformance_kat.json`](core/tests/data/conformance_kat.json) (v1→v2 + 9 vectors), [`core/tests/conformance_kat.rs`](core/tests/conformance_kat.rs) (replay loop + generator + helpers), [`core/tests/conformance_kat_helpers/types.rs`](core/tests/conformance_kat_helpers/types.rs) (Operation+5, PostState, ExpectedReadBlock), [`core/tests/conformance_kat_helpers/dispatch.rs`](core/tests/conformance_kat_helpers/dispatch.rs) (5 run_*, assert_post_state, factored records check), [`core/tests/conformance_kat_helpers/fixtures.rs`](core/tests/conformance_kat_helpers/fixtures.rs) (tempdir copy + contact-card reader), [`ffi/secretary-ffi-uniffi/tests/swift/conformance.swift`](ffi/secretary-ffi-uniffi/tests/swift/conformance.swift) (5 dispatch cases + helpers), [`ffi/secretary-ffi-uniffi/tests/kotlin/Conformance.kt`](ffi/secretary-ffi-uniffi/tests/kotlin/Conformance.kt) (5 dispatch cases + helpers), [`ROADMAP.md`](ROADMAP.md) (B.6 v2 ✅ + paragraph).
- **Issues filed this session:** [#67](https://github.com/hherb/secretary/issues/67) (file-size threshold drift on conformance helper files); [#68](https://github.com/hherb/secretary/issues/68) (`block_input_from_inputs` panic on wrong-length `record_uuid_hex`). Both are non-blocking follow-ups surfaced by the post-implementation code review.
- **PR open:** [#66 `test(conformance-kat): B.6 v2 lifecycle KAT (closes #59)`](https://github.com/hherb/secretary/pull/66) against `main`. 14 commits.
