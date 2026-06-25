# NEXT_SESSION.md — iOS UniffiVaultSession TSan concurrency coverage (#300 follow-up) ✅ SHIPPED (PR opening)

**Session date:** 2026-06-25. Started from a clean baton — PR #304 (`3cba686c`, the #300 readBlock/wipe lock) had already merged to `main`, so the prior handoff's "PR opening" was done; removed the merged worktree/branch (`ios-readblock-wipe-race` / `fix/ios-readblock-wipe-race`). User picked the **#300 TSan follow-up** (the optional, unfiled item the prior handoff flagged: "run the SecretaryKit suite under Swift TSan in CI rather than a flaky stress test"). Executed via full **brainstorm → spec → plan → subagent-driven-development** flow in project-local worktree `.worktrees/ios-tsan-concurrency`.

**Status:** ✅ **SHIPPED — branch `test/ios-tsan-concurrency`, PR opening.** Spec + plan committed; 3 tasks each TDD'd, implemented, and task-reviewed clean; final whole-branch review (opus) = **Ready to merge: Yes** (no Critical/Important); all Minors fixed per [[feedback_fix_all_review_issues]].

## (1) What we shipped this session

iOS **test + CI only** — **no** Rust-core / on-disk-format / spec / `conformance.py` change; **no** `FfiVaultError` variant; **no** `UniffiVaultSession` production-code change (the TDD red step temporarily neutered the lock, then fully reverted). Zero `core/` files touched → Rust `cargo`/`clippy`/CodeQL/conformance/Swift+Kotlin-conformance gates unaffected.

**The gap (#300 follow-up).** PR #304 made `UniffiVaultSession` thread-safe (`NSLock` + `wiped` flag serializing the mutable stored properties `currentBlock` / `wiped` / `cachedDeviceUuid`), but that mutual exclusion was asserted **by construction + doc-comment only** — no test drove it under concurrency, so a future lock regression would pass the suite. This session closes that with a TSan-verified concurrency suite + a CI job that runs it.

**Why a concurrency test is NOT flaky here:** TSan detects races via happens-before tracking (NSLock is TSan-aware), so it flags an unsynchronized stored-property access *regardless of interleaving*. The flakiness the prior handoff feared comes only from asserting a *specific race winner* — which we deliberately never do (assertions are no-crash + count/contents that hold under any valid order).

**Three deliverables:**
1. **`ios/scripts/run-ios-tsan.sh`** (new) — builds the xcframework, runs the **whole** `SecretaryKit` suite under `xcodebuild ... -enableThreadSanitizer YES`. The ~20-line simulator-name→UDID resolver was extracted into a sourceable **`ios/scripts/lib/resolve-simulator.sh`** shared with `run-ios-tests.sh` (pure extraction; only semantic delta `exit 2`→`return 2`, correct for a sourced fn under `set -e` command-substitution).
2. **`SessionConcurrencyIntegrationTests.swift`** (new) — 3 tests over a temp copy of `golden_vault_001` ([[feedback_smoke_test_temp_copy_golden_vault]]), sharing the non-`Sendable` session via an `@unchecked Sendable` box (the deliberate, documented bypass — the lock is what makes it safe; preserves the zero-warning bar): `testConcurrentReadsAreRaceFree` (drives `currentBlock` evict/replace), `testConcurrentReadAndWipeAreRaceFree` (drives `currentBlock`/`wiped`), `testConcurrentWritesAreRaceFree` (drives `write()` + `cachedDeviceUuid`). Counts via named constants (`concurrentWorkers=8`, `wipeRaceSessions=4`). Plus retired the now-stale "not unit-tested … flaky" caveat in `SessionWipeGuardIntegrationTests`'s docstring.
3. **`.github/workflows/ios-tsan.yml`** (new) — path-gated (`ios/**` + the workflow file, on push-to-main + PR) `macos-latest` job running `run-ios-tsan.sh`. A **separate workflow file** (documented deviation from the spec's "in test.yml") because workflow-level `paths:` is the only clean no-third-party-action way to gate one heavy macOS job without gating test.yml's rust/desktop/conformance jobs. `timeout-minutes: 60` + `IOS_SIM` escape-hatch note added per final review.

**Branch commits** (off `main` @ `3cba686c`):
| SHA | What |
|---|---|
| `94a09898` | **docs(spec)**: TSan concurrency coverage design |
| `69840e1e` | **docs(plan)**: implementation plan |
| `6e1db18b` | **test(ios)**: `run-ios-tsan.sh` + extracted shared simulator resolver |
| `57907b0f` | **test(ios)**: concurrency tests under TSan + retired docstring caveat |
| `bcb531d7` | **ci(ios)**: path-gated macOS ThreadSanitizer job |
| `d159ef2d` | **test(ios)**: review polish (docstring wrap + clarifying comment) |
| `6a431ca0` | **ci(ios)**: TSan job `timeout-minutes` + `IOS_SIM` note |
| (+ handoff commit) | this baton + retargeted `NEXT_SESSION.md` symlink |

### Acceptance (verified this session — RED→GREEN, not assumed)
```bash
cd /Users/hherb/src/secretary/.worktrees/ios-tsan-concurrency
bash ios/scripts/run-ios-tsan.sh   # builds xcframework, runs whole suite under TSan
```
- **RED (TDD teeth):** with the `lock.withLock` wrappers temporarily commented out in `UniffiVaultSession.{readBlock,wipe,write}`, `run-ios-tsan.sh` produced **6 `ThreadSanitizer: data race` reports** naming `readBlock` / `wipe()`.
- **GREEN (lock restored):** full `SecretaryKitTests` **35/35 pass, 0 TSan races**; `run-ios-tests.sh` still `** TEST SUCCEEDED **` (32 tests) after the resolver extraction; `actionlint` clean on the workflow.
- Final whole-branch review (opus) verified the tests *would not pass if the lock regressed* (each scenario targets a real unsynchronized site) — i.e. they genuinely guard #300.

## (2) What's next
**#300 follow-up done (PR open). Pick a fresh item.** Strongest carried/new candidates:
- **#299** (`security`, FFI) — uniffi's generated lowering buffer for password/phrase isn't zeroized (residue beyond the adapter-owned `Data` that #229/#298 scrub). Open-ended research: may dead-end in a documented upstream-uniffi limitation in the memory-hygiene memo. #229 follow-up. **NOTE:** a parallel session appears to be working `ios-android-memory-hygiene` (a worktree + a `docs/handoffs/2026-06-25-ios-android-memory-hygiene-shipped.md` exist) — check for collision/overlap before starting #299.
- **#290** — allowlist the 3 D.4 freshness false-positives; **still collision-risky** — `.worktrees/d4-browser-autofill` (`claude/intelligent-davinci-hriple`) was active again this session with post-merge commits.
- **First real CI run of `ios-tsan.yml`:** confirm `macos-latest` actually has an `iPhone 16` simulator and capture observed job duration into the next baton, so the `timeout-minutes: 60` value is grounded in data (final-review recommendation #2 — not yet observable until the PR runs CI).

**Acceptance criteria template for the next pick:** a failing test that reproduces the gap on `main`, the typed-error/enforcement surface *proven* not assumed (security paths, [[feedback_verify_deferred_items]]), the platform's full test gate green, and spec/`conformance.py` updated in lockstep if observable bytes/semantics change.

**Open follow-up issues (carried):** #299 / #290 / #284 / #280 / #277 / #273 / #272 / #269 / #255 / #252 / #247 / #246 / #234 / #232 / #231 / #224 / #218 / #193 / #192 / #190 / #189 / #186 / #183.

## (3) Open decisions and risks
- **Separate CI workflow file over a job in `test.yml`** (documented spec deviation, final-review-endorsed): `test.yml` has no workflow-level `paths:` filter and runs all jobs on every PR, so a `paths:`-gated job can't live there without gating everything; the alternatives (inline `git diff` job-guard, or a third-party paths-filter action) are fragile/greenwash-prone and forbidden by the no-unpinned-action constraint. The separate file is the clean mechanism.
- **Whole suite under TSan, not just the new tests** — defense-in-depth (any future race anywhere is caught); the 3 new tests are the teeth. Existing 32-test suite was already TSan-clean (0 races) → **no suppressions file needed**.
- **`@unchecked Sendable` boxes confined to the test target** — `UncheckedBox` (immutable; the unsafety is the property under test) + `Collector` (its own `NSLock`, genuinely thread-safe). Don't widen them out of the test target.
- **Mutual-exclusion proof is by TSan happens-before, not a deterministic interleave** — there is intentionally NO test asserting a specific race winner (that *would* be flaky). Don't add one.
- **`vaultUuidHex` / read-only metadata stays unguarded in production** (unchanged from #304) — not in scope here.
- **README / ROADMAP unchanged (deliberate).** Test/CI hardening with no new capability or milestone — no ROADMAP item to tick (TSan coverage was never a planned milestone), README's "session wiped on background" stays accurate. Matches the #210/#251/#229/#300 pure-hardening precedent.
- **Risk:** none to product behavior (no production code changed). CI risk: the macOS TSan job is heavy (~5-15× slower Argon2id under TSan); `timeout-minutes: 60` bounds a pathological hang, and `IOS_SIM` overrides the sim if a future runner image drops `iPhone 16`. First real run duration is unobserved until the PR triggers CI.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# If PR merged: branch + worktree .worktrees/ios-tsan-concurrency can be removed:
#   git worktree remove .worktrees/ios-tsan-concurrency && git branch -D test/ios-tsan-concurrency
git worktree list && git status -s

# Re-run this fix's gate (from the worktree if the PR is still open):
cd .worktrees/ios-tsan-concurrency
bash ios/scripts/run-ios-tsan.sh        # 35/35 GREEN, 0 TSan races
# Focused (faster) run of just the new concurrency tests:
SIM_ID="$(bash -c 'source ios/scripts/lib/resolve-simulator.sh; resolve_simulator "iPhone 16"')"
cd ios/SecretaryKit && xcodebuild test -scheme SecretaryKit \
  -destination "platform=iOS Simulator,id=$SIM_ID" \
  -only-testing:SecretaryKitTests/SessionConcurrencyIntegrationTests
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; symlink retargeted in the same commit on the feature branch. New-path handoff → no add/add conflict. Branch was cut from `origin/main` (`3cba686c`) and `origin/main` had **not** advanced at handoff time (verified: `origin/main` == merge-base == `3cba686c`), so no history-binding merge was needed.

## Closing inventory
- **State on close:** PR opening on `test/ios-tsan-concurrency` (spec `94a09898` + plan `69840e1e` + 3 task commits `6e1db18b`/`57907b0f`/`bcb531d7` + review polish `d159ef2d`/`6a431ca0` + handoff). Worktree `.worktrees/ios-tsan-concurrency`.
- **Acceptance:** local GREEN — RED→GREEN proven (6 TSan races with lock removed → 0 with lock); full `SecretaryKitTests` 35/35; `run-ios-tests.sh` 32 tests still green post-refactor; `actionlint` clean. Final whole-branch review (opus): Ready to merge, no Critical/Important; all Minors fixed. Zero `core/` touched → conformance / Swift/Kotlin harnesses unaffected.
- **README.md / ROADMAP.md:** unchanged (rationale in §3 — test/CI hardening, no capability/milestone change).
- **CLAUDE.md:** unchanged.
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-06-25-ios-tsan-concurrency-shipped.md`.
