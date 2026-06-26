# NEXT_SESSION.md — #252 UniffiVaultSession read-only wipe-guard (iOS + Android) ✅ SHIPPED (PR opening)

**Session date:** 2026-06-26. Started from a clean baton — PR #308 (the #193 pipeline refactor) had merged to `main` as `24c690dc`; removed the merged worktree/branch (`.worktrees/pipeline-refactor-193` / `refactor/pipeline-submodule-193`). User picked **#252** (cross-platform read-only wipe-guard hardening). Executed in project-local worktree `.worktrees/session-wiped-guard-252`, branch `fix/session-wiped-guard-252`.

**Status:** ✅ **SHIPPED — branch `fix/session-wiped-guard-252`, PR opening.** Pure internal hardening of the FFI session layer on **both** iOS and Android. **No public-interface change** (`VaultSession` protocol/interface untouched), **no Rust/`core`/FFI/on-disk-format/`conformance.py` change.** `Closes #252` rides in the PR body.

## (1) What we shipped this session

**The bug (#252).** `UniffiVaultSession`'s read-only methods could touch the FFI manifest handle *after* `wipe()` zeroized it, unlike the already-guarded `readBlock`/write paths. Investigation found the bridge (`ffi/secretary-ffi-bridge/src/vault/manifest.rs`) is **defensively coded** — a wiped handle returns *safe defaults*, not a panic/throw:
- `vault_uuid()` wiped → `vec![0u8; 16]` → hex `00…00` (a **silently-wrong** all-zero UUID — the genuine defect)
- `block_summaries()` wiped → **empty Vec** (already the desired post-wipe behavior)

So the design (approved with the user) split honestly:
- **`vaultUuidHex` = real correctness fix.** The vault UUID is *immutable* for a session's life, so **snapshot the hex at construction** into an immutable field (`vaultUuidHexValue`). The accessor returns the stored value and never touches the FFI handle again → correct after wipe, no lock, no throw. This *eliminates* the bug class (vs. the originally-considered throw-typed-error, which would have cascaded `throws` through iOS's non-throwing open-time `makeVaultSync`). Also removes an FFI touch from the internal write-path `deviceUuid()` call.
- **`blockSummaries` = defense-in-depth.** Add a `wiped` check inside the existing lock returning empty (mirrors `readBlock`'s lost-race empty return). **No observable change** (bridge already returns empty) — the session now enforces its own contract instead of relying on a cross-crate default, and closes the readBlock/write-vs-summaries asymmetry.

**Branch commits** (off `main` @ `24c690dc`):
| SHA | What |
|---|---|
| `8a307716` | **fix(ios)**: snapshot `vaultUuidHex` + `blockSummaries` wiped guard + 2 tests |
| `03effc7d` | **fix(android)**: Kotlin mirror + instrumented test |
| (+ handoff commit) | this baton + retargeted `NEXT_SESSION.md` symlink |

### Acceptance (verified this session, in the worktree)
```bash
cd /Users/hherb/src/secretary/.worktrees/session-wiped-guard-252
# iOS — built the xcframework once, then ran the SecretaryKit sim suite:
bash ios/scripts/run-ios-tests.sh            # (or scoped xcodebuild test -scheme SecretaryKit)
#   → genuine RED first: testVaultUuidHexSurvivesWipe failed pre-fix
#     ("00000000000000000000000000000000" != "00112233445566778899aabbccddeeff")
#   → GREEN after fix: full SecretaryKit suite 37 tests, 0 failures.
# Android (emulator emulator-5554 was already up):
cd android
./gradlew :kit:connectedDebugAndroidTest --console=plain \
  -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.browse.SessionWipeGuardInstrumentedTest,org.secretary.browse.RevealResidencyInstrumentedTest   # 3 tests green
./gradlew :kit:testDebugUnitTest :vault-access:test          # host unit tests green
```
- **Genuine red→green on BOTH platforms**: iOS red captured on the simulator; Android red confirmed by momentarily pointing the accessor back at the live handle (`vaultUuidHexSurvivesWipe` failed), then restored.
- No Rust change → cargo clippy/test/`conformance.py` and all language conformance gates unaffected (not re-run; nothing they cover changed).
- Focused code-review pass (pr-review-toolkit code-reviewer) on the diff: **no material issues** (init order, write-path reentrancy, lock publication of `wiped`, cross-platform symmetry, doc staleness, silent-failure all checked clean).

## (2) What's next
**#252 done (PR open). Pick a fresh item.** Carried candidates (collision status as of this session):
- **#290** — allowlist the 3 D.4 freshness false-positives (`origin_binding`/`registrable_domain`/`exact_origin` in `threat-model.md`). Trivial (3 allowlist entries, precedent exists), but **collision-risky**: `.worktrees/d4-browser-autofill` (`claude/intelligent-davinci-hriple`) is active — coordinate first.
- **#231** (iOS) — enable `-strict-concurrency=complete` on the SwiftPM targets; natural follow-on to the #300 TSan work. No collision.
- **#92** (docs) — clean up the 28 pre-existing `cargo doc` warnings (14 in `secretary-cli`). Self-contained docs slice; `cargo doc -D warnings` is **not** a CI gate today. No collision.

**Acceptance criteria template:** a failing test reproducing the gap on `main`, the typed-error/enforcement surface *proven* not assumed (security paths, [[feedback_verify_deferred_items]]), the platform's full test gate green, spec/`conformance.py` updated in lockstep if observable bytes/semantics change.

**Open follow-up issues (carried):** #290 / #284 / #280 / #277 / #273 / #269 / #255 / #247 / #246 / #234 / #232 / #231 / #224 / #218 / #192 / #190 / #189 / #186 / #183 / #92. (#252 closing via this PR.)

## (3) Open decisions and risks
- **Design pivot from the issue's premise (resolved with user).** The issue assumed a wiped handle might "panic or return garbage"; the bridge actually returns *defined* safe defaults. So `blockSummaries` had **no observable bug** (already empty) — its guard is belt-and-suspenders. The only real defect was `vaultUuidHex`'s all-zero UUID, fixed by the snapshot. The snapshot approach (a 3rd option) was chosen over the user's earlier "throw typed error" pick *after* discovering it avoids an iOS `throws`-cascade and eliminates the bug class — re-confirmed with the user.
- **README / ROADMAP unchanged (deliberate).** Pure internal session hardening, no public interface / behavior / on-disk-format / milestone change — matches the #210/#251/#229/#300 pure-hardening precedent. Verified no `#252` / "known gaps" reference exists in either doc.
- **Risk:** none to product behavior. `vaultUuidHex` now returns the correct (non-secret) UUID post-wipe instead of all-zero; `blockSummaries` post-wipe behavior is byte-identical to before (empty). Public interface verbatim; the lone iOS consumer (`makeVaultSync`, open-time) and Android `VaultBrowseModel` are unaffected.
- **Verification gate scope:** iOS xcframework build + sim suite and the Android emulator instrumented run were both exercised here (iOS toolchain + a running emulator-5554 were available). CI runs the same gates.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# If PR merged: branch + worktree can be removed:
#   git worktree remove .worktrees/session-wiped-guard-252 && git branch -D fix/session-wiped-guard-252
git worktree list && git status -s

# Re-verify this session's gate (from the worktree if the PR is still open):
cd .worktrees/session-wiped-guard-252
bash ios/scripts/run-ios-tests.sh
cd android && ./gradlew :kit:testDebugUnitTest :vault-access:test
#   instrumented (needs an emulator):
#   ./gradlew :kit:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.browse.SessionWipeGuardInstrumentedTest
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; symlink retargeted in the same commit on the feature branch. New-path handoff → no add/add conflict. Branch cut from `origin/main` (`24c690dc`); `origin/main` had **not** advanced at handoff time (verified `origin/main` == merge-base == `24c690dc`), so no history-binding merge was needed.

## Closing inventory
- **State on close:** PR opening on `fix/session-wiped-guard-252` (`8a307716` iOS + `03effc7d` Android + handoff). Worktree `.worktrees/session-wiped-guard-252`.
- **Acceptance:** iOS full SecretaryKit suite (37) + Android instrumented (wipe-guard + reveal-residency) + `:kit`/`:vault-access` host unit tests all green; genuine red→green proven on both platforms; code-review clean. No `core`/FFI/on-disk-format/`conformance.py` touched → all language gates unaffected. `#252` closes via the PR.
- **README.md / ROADMAP.md:** unchanged (rationale in §3).
- **CLAUDE.md:** unchanged.
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-06-26-session-wiped-guard-252-shipped.md`.
