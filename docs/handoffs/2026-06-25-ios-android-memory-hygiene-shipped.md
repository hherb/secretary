# NEXT_SESSION.md — iOS/Android memory-hygiene hardening (#251 + #229) ✅ SHIPPED (PR opening)

**Session date:** 2026-06-25. Started from a clean baton — PR #297 (#206 FFI share-TOFU) had merged to `main` (`e3f5f370`); removed the prior `.worktrees/ffi-share-tofu-hardening` worktree + deleted branch. Picked the **memory-hygiene pair #251 + #229** (you chose it over #210 / #295). Brainstormed → spec → plan → executed via **subagent-driven development** (fresh sonnet implementer + sonnet spec/quality reviewer per task; final whole-branch review on opus) → applied 2 cosmetic final-review minors → docs decision → opening PR.

**Status:** ✅ **SHIPPED — branch `feature/ios-android-memory-hygiene`, PR opening.** Final whole-branch review (opus): **Ready to merge, 0 Critical / 0 Important.** All per-task reviews: spec ✅ / quality Approved.

## (1) What we shipped this session

Two independent, pre-existing memory-hygiene gaps in the **iOS/Android FFI layer** — no Rust-core / on-disk-format / spec change; `conformance.py` + the Swift/Kotlin conformance harnesses untouched.

**#251 — reveal-residency accumulation (iOS + Android parity).** `UniffiVaultSession.readBlock` appended every decrypted `BlockReadOutput` to an `openBlocks` list and never released it until the session was wiped (lock/background), so browsing A→B→A left every visited block's *entire* decrypted plaintext resident, and re-selecting a block accumulated duplicates. **Fix:** replace the unbounded list with a single `currentBlock: BlockReadOutput?`, wiping the prior block on each **successful** `readBlock` (decrypt-first: a thrown decrypt leaves the on-screen block retained). Making it an optional turns "≤1 block resident" into a **type-level invariant** (accidental accumulation impossible) and dedups re-selection. Android keeps the #250 `sessionLock` + `wiped`-race guard — eviction sits inside the lock, after the `wiped` check.

**#229 — iOS FFI-boundary password copy never scrubbed.** The port adapters copy the master password / recovery phrase into `Data(password)` at the FFI boundary and never overwrite that copy (uniffi copies into Rust where it *is* zeroized; the residue is the Swift `Data`). **Fix:** a pure `zeroize(_ data: inout Data)` + a `withZeroizingData` wrapper that scrubs the boundary `Data` in a `defer` (fires on return **and** throw), applied at all five sites (open password/recovery, create, sync, commitDecisions). Scrubs only the **adapter-owned** `Data` — deliberately NOT the caller's `[UInt8]` (Swift copy-on-write makes that ineffective; documented in the helper, matching the existing `toFfi` text-residue precedent).

**Why the #251 fix is safe (verified against real code by the final review, not assumed):** the VM clears the reveal map before every read (iOS `VaultBrowseViewModel.reload` → `revealed.removeAll()`; Android `VaultBrowseModel.selectBlock` → `_revealed.value = emptyMap()`), so no *live* reveal closure points at the evicted block; and `BlockReadOutput.wipe()` cascades `Record.wipe()` → `FieldHandle.wipe()` via a shared `Arc` (`Option::take`), so an already-captured `FieldHandle` returns `None`/throws after eviction — proven by the existing bridge unit test `arc_clone_shares_wiped_state` and exercised directly by both teeth tests.

**Branch commits** (off `main` @ `e3f5f370`):
| SHA | What |
|---|---|
| `c244f172` | design doc (`docs/superpowers/specs/2026-06-25-ios-android-memory-hygiene-design.md`) |
| `c8a7de65` | implementation plan (`docs/superpowers/plans/2026-06-25-ios-android-memory-hygiene.md`) |
| `8b702215` | **fix(ios)**: bound reveal-residency to the on-screen block (#251, Task 1) |
| `3a82886f` | **fix(android)**: bound reveal-residency to the on-screen block (#251, Task 2) |
| `303cc537` | **fix(ios)**: scrub FFI-boundary password Data copy via `withZeroizingData` (#229, Task 3) |
| `3cc97dff` | docs(test): note dedup is a type-level invariant; wrap long comment (final-review minors) |
| (+ handoff commit) | this baton + retargeted `NEXT_SESSION.md` symlink |

**Tests added (TDD red→green throughout):**
- **#251 iOS** — `RevealResidencyIntegrationTests.swift` (host XCTest, golden_vault_001 temp copy): captures a reveal closure, re-reads the single golden block, asserts the **stale closure throws** after eviction (fails on pre-fix accumulate-forever code).
- **#251 Android** — `RevealResidencyInstrumentedTest.kt` (instrumented, on `emulator-5554`): the same teeth assertion (`assertThrows(VaultBrowseError.CorruptVault)`).
- **#229** — `ZeroizingDataTests.swift` (5 cases): `zeroize` overwrites all bytes + empty-data no-op; `withZeroizingData` exposes bytes / returns body result / propagates throws (the scrub itself proven by composition through the pure `zeroize`, since the local `Data` is unobservable post-call — a Swift value-type/CoW limit).

### Acceptance (verified by the controller this session, not assumed)
```bash
cd /Users/hherb/src/secretary/.worktrees/ios-android-memory-hygiene
bash ios/scripts/run-ios-tests.sh           # 29 tests, 0 failures — RevealResidency ✅ + ZeroizingData(5) ✅
# Android instrumented (emulator-5554 was up):
cd android && ./gradlew :kit:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.browse.RevealResidencyInstrumentedTest
cd android && ./gradlew :kit:testDebugUnitTest :vault-access:test   # host units green
# Rust unchanged but proven no incidental drift:
cargo fmt --all -- --check                   # clean
uv run core/tests/python/conformance.py      # PASS (unchanged)
cargo test --release --workspace             # <SEE PR — running at handoff; CI is the gate>
```
**CI is the real gate once pushed** — `test.yml` (rust ×2 OS + desktop vitest + swift/kotlin conformance + smoke) + `rust-lint.yml` (fmt/clippy) + CodeQL. No new `FfiVaultError`/format surface → conformance KAT + harnesses unaffected.

## (2) What's next
**#251 + #229 done (PR open). Pick a fresh item.** Remaining sync/daemon + tooling backlog:
- **#295** — `once` mode doesn't `log_outcome` (rollback/veto surfaced only via exit code, no forensic clocks). Small, pure-Rust/cli; spinoff of the daemon cluster. Call `daemon::log_outcome` on the `Ok` arm of `dispatch_once_subcommand`.
- **#210** — fuzz monitor dashboard binds `0.0.0.0` with no auth (docs say localhost). Python; small, quick win; carries the `security` label.
- **#290** — allowlist the 3 D.4 freshness false-positives (`origin_binding`/`registrable_domain`/`exact_origin`) once the `d4-browser-autofill` session settles (worktree `.worktrees/d4-browser-autofill` was still active at handoff).
- **Possible #251/#229 follow-ups (not filed):** (a) the VM-owned input `[UInt8]` password array on iOS is still unscrubbed (CoW makes adapter-side scrubbing impossible — would need `inout`/a wrapper type threaded through every port signature + VM; out of scope here, file if wanted). (b) #251's derived-handle note: the per-`Record`/`FieldHandle` uniffi wrappers are now bounded to one block's worth regardless, so the minor "lingering native allocation" sub-concern in #251 is closed by construction.

**Acceptance criteria template for the next pick:** a failing test that reproduces the gap on `main`, the typed-error/enforcement surface *proven* not assumed (security paths), full `cargo test --workspace` + clippy `-D warnings` green, and spec/`conformance.py` updated in lockstep if observable bytes/semantics change.

**Open follow-up issues (carried):** #295 / #290 / #284 / #280 / #277 / #273 / #272 / #269 / #255 / #252 / #247 / #246 / #234 / #232 / #231 / #224 / #218 / #210 / #193 / #192 / #190 / #189 / #186 / #183. (#251 + #229 now closed by this PR; #206 / #207 / #208 / #209 / #205 / #293 closed earlier.)

## (3) Open decisions and risks
- **#251: single-optional, not a bounded list (deliberate).** Bounding `openBlocks` to one element would also work, but `currentBlock: BlockReadOutput?` makes "≤1 block resident" a compile-time invariant — accidental re-accumulation is impossible. The no-growth-on-re-selection property is therefore enforced by the **type**, not a runtime count assertion (both teeth tests carry a comment saying so). Don't "promote" it back to a list.
- **#251: decrypt-first ordering is load-bearing.** Evict the prior block only AFTER the new block decrypts successfully — a thrown decrypt must leave the on-screen block (and its live reveal closures) retained. Structurally enforced on both platforms (the eviction lines are unreachable if the FFI read throws). Don't reorder.
- **#229: scrub the `Data` copy only (fail-honest scope).** The helper cannot scrub the caller's `[UInt8]` (Swift CoW → mutating our binding allocates a throwaway and leaves the caller's buffer intact). This is documented, not a gap to "fix" by mutating the param. Threading `inout`/a `SecretBytes` wrapper through every port signature + VM was explicitly rejected as disproportionate for this PR (see #2 follow-up (a)).
- **#229: `zeroize` is the pure, testable core.** The happy-path/throw-path scrub at the `withZeroizingData` level is not directly observable (the `Data` is local and gone post-call) — proven by composition via `testZeroizeOverwritesAllBytes`. Don't inline `zeroize` into the wrapper; the split is what makes the post-condition assertable.
- **README / ROADMAP unchanged (deliberate).** #251/#229 add **no new capability or projected surface** — pure internal hardening of already-shipped mobile reveal/sync slices (C.3). The README iOS reveal row stays accurate; adding per-fix hardening notes would be the per-binding minutiae the README-style guidance discourages. (Contrast #206, which projected *new* primitives to Python/mobile → warranted a README note.) No milestone moved, so ROADMAP is unchanged.
- **Risk:** none to honest-vault behavior. #251 eviction only drops blocks the user navigated away from (reveal map already cleared); the on-screen block is always retained → reveal-on-tap, write, and sync paths unaffected (full iOS suite + Android host units green; instrumented teeth test green on `emulator-5554`). #229 only overwrites a copy the FFI call has already consumed.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# If PR merged: branch + worktree .worktrees/ios-android-memory-hygiene can be removed:
#   git worktree remove .worktrees/ios-android-memory-hygiene && git branch -D feature/ios-android-memory-hygiene
git worktree list && git status -s

# Run any gate locally (from the worktree if the PR is still open):
bash ios/scripts/run-ios-tests.sh
cd android && ./gradlew :kit:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.browse.RevealResidencyInstrumentedTest   # needs an emulator/device up
cargo test --release --workspace && cargo clippy --release --workspace --tests -- -D warnings
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; symlink retargeted in the same commit on the feature branch. New-path handoff → no add/add conflict. Branch was cut from current `origin/main` (`e3f5f370`) and `origin/main` had **not** advanced at handoff time (verified: `origin/main` == merge-base), so no history-binding merge was needed this session.

## Closing inventory
- **State on close:** PR opening on `feature/ios-android-memory-hygiene` (6 code/doc commits + handoff). Worktree `.worktrees/ios-android-memory-hygiene`.
- **Acceptance:** local GREEN — iOS host suite (29 tests, 0 fail), Android instrumented teeth test + host units, conformance PASS, fmt clean. Full `cargo test --release --workspace` was running at handoff (Rust diff is empty — zero core files touched); CI is the gate on push. Final whole-branch review (opus): Ready to merge, 0 Critical / 0 Important; only cosmetic Minors (2 applied as `3cc97dff`, rest intentional/language-imposed).
- **README.md / ROADMAP.md:** unchanged (rationale in §3 — internal hardening, no capability/milestone change).
- **CLAUDE.md:** unchanged (the zeroize-discipline + "both halves" properties it documents are preserved and now also enforced at the mobile reveal-residency + password-boundary surfaces).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-06-25-ios-android-memory-hygiene-shipped.md`.
