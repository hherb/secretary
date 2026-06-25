# NEXT_SESSION.md — iOS UniffiVaultSession readBlock/wipe race (#300) ✅ SHIPPED (PR opening)

**Session date:** 2026-06-25. Started from a clean baton — PR #303 (`8681f4e9`, the #295 once-mode RunOutcome forensics) had already merged to `main`, so the prior handoff's "PR opening" item was done. Removed the merged worktree/branch (`once-log-outcome` / `fix/once-mode-log-outcome`). User picked **#300** (`security`, iOS) over **#299** (uniffi lowering-buffer scrub, open-ended) and **#290** (D.4 allowlist — declined: collides with the still-active `.worktrees/d4-browser-autofill`). After investigation the design choice was **mirror Android's lock** (enforcement) over document-only; executed via **TDD** (red→green) in project-local worktree `.worktrees/ios-readblock-wipe-race`.

**Status:** ✅ **SHIPPED — branch `fix/ios-readblock-wipe-race`, PR opening.** Spec commit + code/test commit; targeted tests RED→GREEN proven; full `SecretaryKitTests` 32/32 green; SwiftUI app compiles; reviewed clean by `code-reviewer` (no material issues).

## (1) What we shipped this session

iOS-only thread-safety hardening — **no Rust-core / on-disk-format / spec change**; `conformance.py` + Swift/Kotlin conformance harnesses untouched; no `FfiVaultError` variant; zero `core/` files touched → Rust `cargo`/`clippy`/CodeQL gates unaffected.

**#300 — iOS `UniffiVaultSession.readBlock`/`wipe()` race on `currentBlock`.** PR #298 (#251 reveal-residency bound) added `currentBlock?.wipe()` inside `readBlock` (`ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSession.swift`). Unlike the Android `UniffiVaultSession` (serializes `readBlock` vs `wipe()` under `sessionLock` + a `wiped` flag, #250), the iOS type was a plain `final class` with **no lock**. Both `readBlock` (mutates+wipes `currentBlock`) and `wipe()` (wipes `currentBlock`, then zeroizes `manifest`/`identity`) touch shared FFI state → concurrent calls race.

**Investigation (proved iOS is safe *today*, then chose enforcement anyway):** the only prod caller of `wipe()` is `VaultBrowseViewModel.lock()` (`@MainActor`, incl. the scene-phase `.background` handler); `readBlock` is synchronous on `@MainActor`; and the type is non-`Sendable`, so the compiler already bars it from the one off-actor seam (`runOffMainActor`, which requires `@Sendable`). That's a sound proof — but it's a doc-comment-enforced convention a future off-actor `wipe()` could break. Per [[feedback_security_no_assumptions]] we chose enforcement.

**Why not `@MainActor` on the type/protocol (the "obvious" enforcement):** ruled out — `UniffiVaultSession(output:)` is deliberately constructed **inside** `UniffiVaultOpenPort`'s `runOffMainActor` closure (off the main actor, so Argon2id open doesn't block the UI). Marking it `@MainActor` forces construction onto the main actor, requiring the non-`Sendable` `OpenVaultOutput` FFI handle to cross an actor hop — defeating the off-actor open.

**Fix (mirror Android).** Add `private let lock = NSLock()` + `private var wiped = false`; wrap `blockSummaries()`, `readBlock()`, the private `write()` helper, and `wipe()` in `lock.withLock { … }`. `readBlock`: after the FFI decrypt (decrypt-first ordering, like Android), `if wiped { out.wipe(); return [] }`. `write`: `if wiped { throw .other("write on a wiped session") }` **before** touching handles. `wipe()`: set `wiped = true`, then the existing `currentBlock`→`manifest`→`identity` cascade. `vaultUuidHex` left unguarded (mirrors Android — read-only derived metadata). `NSLock` chosen over `OSAllocatedUnfairLock` because the latter's `withLock` return value carries a `Sendable` constraint `[RecordView]` (escaping reveal closures) can't satisfy.

**Branch commits** (off `main` @ `8681f4e9`):
| SHA | What |
|---|---|
| `240e8744` | **docs(spec)**: iOS readBlock/wipe race serialization design (#300) |
| `36f75c55` | **fix(ios)**: serialize `UniffiVaultSession` FFI-handle access under a lock + `wiped` guard (#300) — impl + 3 integration tests |
| (+ handoff commit) | this baton + retargeted `NEXT_SESSION.md` symlink |

**Tests added (TDD red→green):** `ios/SecretaryKit/Tests/SecretaryKitTests/SessionWipeGuardIntegrationTests.swift` — opens a temp copy of `golden_vault_001` (never mutates the frozen KAT, per [[feedback_smoke_test_temp_copy_golden_vault]]) with a `FixedDeviceUuid` provider:
- `testWriteAfterWipeThrowsWipedSessionError` — **the teeth**: after `wipe()`, `appendRecord` throws `.other("write on a wiped session")`. **RED** pre-fix (the FFI threw `.corruptVault("vault manifest handle has been wiped")` on dead handles — wrong variant), **GREEN** once the flag-guard short-circuits.
- `testWipeIsIdempotent` — `wipe()` twice is a safe no-op; a subsequent write still throws the wiped error. (Also RED pre-fix for the same variant reason.)
- `testReadBlockAfterWipeYieldsNoRecords` — after `wipe()`, `readBlock` must not return records. (Passed pre-fix too — FFI errors on dead handles → caught → no records; regression guard.)

### Acceptance (verified this session, not assumed)
```bash
cd /Users/hherb/src/secretary/.worktrees/ios-readblock-wipe-race
# xcframework already built this session (ios/Secretary.xcframework); rebuild if stale:
#   bash ios/scripts/build-xcframework.sh
SIM_ID="$(xcrun simctl list devices available | grep -E '^[[:space:]]*iPhone 16 \(' | head -1 \
  | grep -oE '[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}')"
cd ios/SecretaryKit
xcodebuild test -scheme SecretaryKit -destination "platform=iOS Simulator,id=$SIM_ID" \
  -only-testing:SecretaryKitTests/SessionWipeGuardIntegrationTests   # 3/3 GREEN (2 were RED pre-fix)
xcodebuild test -scheme SecretaryKit -destination "platform=iOS Simulator,id=$SIM_ID"   # 32/32 GREEN
cd .. && bash ios/scripts/build-app.sh                                # ** BUILD SUCCEEDED **
```
**RED→GREEN proof:** with the lock+seam absent, the two write-guard tests failed asserting the wrong error variant (`.corruptVault` from FFI-on-dead-handle vs the expected `.other("write on a wiped session")`); adding the `wiped`-before-body guard turned them green. Full `SecretaryKitTests` 32/32 and the app compile confirm the lock wrapping of `readBlock`/`blockSummaries`/writes introduced no regression.

## (2) What's next
**#300 done (PR open). Pick a fresh item.** Strongest carried/new candidates:
- **#299** (`security`, FFI) — uniffi's generated lowering buffer for password/phrase isn't zeroized (residue beyond the adapter-owned `Data` that #229/#298 scrub). Open-ended research: may dead-end in a documented upstream-uniffi limitation in the memory-hygiene memo. #229 follow-up.
- **#290** — allowlist the 3 D.4 freshness false-positives (`origin_binding`/`registrable_domain`/`exact_origin`); **check first** — `.worktrees/d4-browser-autofill` (`claude/intelligent-davinci-hriple`) was still active this session with post-merge commits beyond merged PR #242 (likely a parallel session). Collision risk.
- **Concurrency-test depth for #300 (optional follow-up):** the `NSLock` mutual-exclusion under genuine concurrency is by-construction + documented, not unit-tested (a deterministic interleave needs an injected mid-`readBlock` seam; a stress test would be flaky). If wanted, run the SecretaryKit suite under Swift TSan (`-sanitize=thread`) in CI rather than adding a flaky stress test. Not filed as an issue — mention only.

**Acceptance criteria template for the next pick:** a failing test that reproduces the gap on `main`, the typed-error/enforcement surface *proven* not assumed (security paths), the platform's full test gate green, and spec/`conformance.py` updated in lockstep if observable bytes/semantics change.

**Open follow-up issues (carried):** #299 / #290 / #284 / #280 / #277 / #273 / #272 / #269 / #255 / #252 / #247 / #246 / #234 / #232 / #231 / #224 / #218 / #193 / #192 / #190 / #189 / #186 / #183. (#300 now closed by this PR; #295 closed by #303; #210 closed by #302; #251/#229 closed by #298.)

## (3) Open decisions and risks
- **Mirror-Android lock chosen over document-only** ([[feedback_security_no_assumptions]]): enforcement (thread-safe by construction) beats a plausibility comment a future off-actor caller could break. The lock is uncontended today (all callers `@MainActor`) — pure defense-in-depth that also closes the iOS/Android asymmetry the issue is about.
- **Serialization extended to writes** (beyond the issue's literal `readBlock`/`wipe` scope): `wipe()` zeroizes `identity`/`manifest`, so write-vs-`wipe()` is the same race class. Mirroring Android's full serialization avoids fixing one side and leaving the sibling gap open. Don't narrow it back to readBlock-only.
- **`vaultUuidHex` intentionally unguarded** — mirrors Android (read-only derived metadata; the `deviceUuid()` path that needs it already runs inside the `write` lock). Don't "fix" it into the lock without reason; it would diverge from Android.
- **`NSLock` over `OSAllocatedUnfairLock`** — the latter's `withLock` constrains the return type to `Sendable`, which `[RecordView]` (escaping reveal closures, non-`Sendable`) can't satisfy. Don't swap it.
- **README / ROADMAP unchanged (deliberate).** #300 adds **no new capability** — thread-safety hardening of already-shipped iOS browse behavior. README's "session wiped on background" remains accurate (grep-confirmed). Matches the pure-hardening rationale for #210/#251/#229/#295.
- **Risk:** none to behavior. On the single-threaded `@MainActor` path the lock is uncontended and observable behavior is unchanged (existing 32 tests pass); the only new observable is the typed `.other("write on a wiped session")` on a write after lock (previously a `.corruptVault` FFI error) — a strictly clearer error.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# If PR merged: branch + worktree .worktrees/ios-readblock-wipe-race can be removed:
#   git worktree remove .worktrees/ios-readblock-wipe-race && git branch -D fix/ios-readblock-wipe-race
git worktree list && git status -s

# Re-run this fix's gate (from the worktree if the PR is still open; xcframework already built):
cd .worktrees/ios-readblock-wipe-race/ios/SecretaryKit
SIM_ID="$(xcrun simctl list devices available | grep -E '^[[:space:]]*iPhone 16 \(' | head -1 \
  | grep -oE '[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}')"
xcodebuild test -scheme SecretaryKit -destination "platform=iOS Simulator,id=$SIM_ID"   # 32/32
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; symlink retargeted in the same commit on the feature branch. New-path handoff → no add/add conflict. Branch was cut from current `origin/main` (`8681f4e9`) and `origin/main` had **not** advanced at handoff time (verified: `origin/main` == merge-base == `8681f4e9`), so no history-binding merge was needed.

## Closing inventory
- **State on close:** PR opening on `fix/ios-readblock-wipe-race` (spec `240e8744` + code/test `36f75c55` + handoff). Worktree `.worktrees/ios-readblock-wipe-race`.
- **Acceptance:** local GREEN — 3/3 targeted wipe-guard tests (RED→GREEN proven on 2), full `SecretaryKitTests` 32/32, SwiftUI app compiles; reviewed clean by `code-reviewer`. Zero `core/` touched → conformance / Swift/Kotlin harnesses unaffected.
- **README.md / ROADMAP.md:** unchanged (rationale in §3 — thread-safety hardening, no capability/milestone change).
- **CLAUDE.md:** unchanged (the lock rationale lives in the type's doc-comment; no cross-cutting architectural guidance affected).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-06-25-ios-readblock-wipe-race-shipped.md`.
