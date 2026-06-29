# NEXT_SESSION.md — Android SAF eventual-consistency hardening (#330) ✅ SHIPPED (PR opening)

**Session date:** 2026-06-29. Built **`RetryingCloudFolderPort`** — a `CloudFolderPort` decorator that hardens Android cloud-vault flush/materialize against eventually-consistent SAF providers (Google Drive), the #333 follow-up [#330](https://github.com/hherb/secretary/issues/330). Executed subagent-driven (fresh implementer per task → spec+quality review per task → fix loop → whole-branch opus review) in worktree `.worktrees/android-cloud-saf-retry-330`, branch `feature/android-cloud-saf-retry-330` (cut from `main` @ `0cb209e`). **Kotlin/Android only — no core `src/`, no on-disk-format / spec / `conformance.py` / conflict-KAT / observable-byte / FFI-surface change.**

## (1) What we shipped this session

**The feature.** Google Drive's SAF `DocumentsProvider` is eventually-consistent (caches listings, defers writes), so a cloud create/sync failed on the first attempt and routed silently back to Unlock (now a Toast after #333's `4f2bdbc`); a retry worked unchanged. `RetryingCloudFolderPort` (in `:vault-access`, `org.secretary.mirror`) wraps any `CloudFolderPort` and adds:
- **`write`** — **two separate retry loops** (review-fix #335): phase 1 retries `inner.write` on its own throw; phase 2 polls `inner.read` + `contentEquals` and retries **only the read** — it never re-issues the write. Re-writing while the prior write is not yet visible would fork a **duplicate** physical file on an eventually-consistent provider (the not-yet-visible file is invisible to `findOrCreate`'s overwrite `findFile`, so the delete-then-create is skipped) and diverge cloud from working copy; the read-only verify absorbs the same invisible/stale-read modes without that hazard. A persistent mismatch rethrows a typed `CloudFolderException` after `maxAttempts`, and the next flush re-writes from the top. `:kit`'s `findOrCreate` additionally now deletes *every* same-named child (defense-in-depth self-heal).
- **`list` / `read`** — retry on `CloudFolderException` (no verify; they *are* reads).
- **`delete`** — retry on exception, **no read-back verify** (idempotent; a stale-present file is re-deleted next pass, never corrupts the vault; verifying absence would mean treating a "no such file" throw as success).
- **`RetryPolicy(maxAttempts, baseDelayMs, maxDelayMs)`** + pure `backoffDelayMs(attempt, policy)` (exponential, capped, overflow-guarded). `CLOUD_DEFAULT = (5, 250, 2000)` → 250/500/1000/2000/(2000) ms, ~5.75 s worst case. No magic numbers.
- **Host-testable seams:** `sleep: (Long) -> Unit = Thread::sleep`, `onRetry: (String) -> Unit = {}` — no `android.util.Log`, no Android types in the class. Production wires `onRetry = { Log.i(TAG, it) }` from the app layer.

**Production wiring (one line).** `openCloudTarget` ([CloudVaultOpen.kt](../../android/app/src/main/kotlin/org/secretary/app/CloudVaultOpen.kt)) now builds `VaultMirror(RetryingCloudFolderPort(safCloudFolderPort(...), onRetry = { Log.i(TAG, it) }))`. It is the **only** production SAF-mirror construction site; both **flush and materialize** benefit (the wrapped mirror is shared via `cloudCoordinator`). No control-flow change. `VaultMirror`, the SAF factory, and the `CloudFolderPort` interface are untouched.

**Docs.** [android/README.md](../../android/README.md) gained a "Cloud vault storage (SAF providers)" section (supported/tested vs best-effort eventually-consistent; references #330 + #334). Root README status row + ROADMAP C.3/progress-bar clauses updated.

**Verification:** `:vault-access:test` **339 green** (incl. backoff table, 3 fault-injection fake tests, 8 decorator tests, the flush integration test, + final-review completeness adds). Full host gate green at Task 6: `:vault-access:test :kit:testDebugUnitTest :app:testDebugUnitTest :app:compileDebugKotlin :app:compileDebugAndroidTestKotlin` BUILD SUCCESSFUL. Whole-branch review (opus): **Ready to merge: Yes, 0 Critical / 0 Important** — traced all three write failure modes correct, confirmed the non-recursive read-back, the single wiring site, and the delete-no-verify + cause-less-rethrow decisions sound.

**Branch commits** (off `main` @ `0cb209e`):
| SHA | What |
|---|---|
| `5cf57bb` | docs: design |
| `f6b33c3` | docs: implementation plan |
| `fb56303` | Task 1 — `RetryPolicy` + pure `backoffDelayMs` |
| `f1ec7f6` | Task 2 — count-scoped fault injection in `FakeCloudFolderPort` |
| `b2ca298` | Task 3 — `write` retry + read-back verify |
| `a3b11f2` | Task 3 review fix — assert `onRetry` on read-back miss + non-`CloudFolderException` propagates |
| `bc5eb28` | Task 4 — retry `list`/`read`/`delete` (delete no read-back) |
| `ba6ed25` | Task 5 — `VaultMirror.flush` composition integration test |
| `4f54d9a` | Task 6 — wire `openCloudTarget` + android README SAF-providers note |
| `147a15c` | final-review test-completeness (backoff guard/custom-policy, callLog-of-failed-ops, delete end-state, list exhaustion) |
| `970c258` | docs: README + ROADMAP |
| (+ handoff commit) | this baton + retargeted `NEXT_SESSION.md` symlink |

### Acceptance (verified this session)
```bash
cd /Users/hherb/src/secretary/.worktrees/android-cloud-saf-retry-330/android
./gradlew :vault-access:test                                              # 339 green
./gradlew :vault-access:test :kit:testDebugUnitTest :app:testDebugUnitTest \
  :app:compileDebugKotlin :app:compileDebugAndroidTestKotlin              # full host gate green
```

## (2) What's next
Candidate next steps (pick at brainstorm). #330 is complete; remaining cloud follow-ups + the native-provider fork:

1. **Native cloud-provider integration epic ([#334](https://github.com/hherb/secretary/issues/334)).** mSecure-style native Dropbox/Drive OAuth SDK as an *additive* `CloudFolderPort` impl (strongly consistent, no SAF flakiness). **Gated on an ADR + threat-model review FIRST** — a third-party SDK in the secrets process + an embedded OAuth client secret changes the in-process attack surface vs OS-mediated SAF. *Acceptance:* ADR recorded; Dropbox selectable from the vault menu, authorizing via its OAuth popup, read/writing the vault folder through the same seam, no `VaultMirror`/open-flow change.
2. **Picker can't grant local/non-GDrive SAF tree on custom ROMs ([#331](https://github.com/hherb/secretary/issues/331)).** RedMagic's picker shows only Google Drive. *Acceptance:* in-app guidance when no usable provider is granted, and/or an app-managed local vault location not dependent on the system tree picker.
3. **UnlockScreen UX polish ([#332](https://github.com/hherb/secretary/issues/332)).** Progress spinner during the multi-second Argon2id open; typed error on failed demo unlock; title-by-target (not hardcoded "demo vault"). *Acceptance:* loading indicator + disabled button during open; typed error on failed demo unlock; title by target.
4. **Biometric cloud-*open*** (deferred from #333 — cloud open stays password-based). *Acceptance:* an enrolled device opens a cloud vault by biometric (device-secret open through the cloud coordinator + materialize-before-open ordering + unlock-screen biometric button).
5. **Settings-screen enroll/disenroll toggle for cloud vaults** (#333 is opt-in-at-open only; demo's settings flow is untouched).

## (3) Open decisions and risks
- **On-device GDrive retry not re-proven this session.** The decorator is fully host-tested with a flaky fake simulating all three failure modes; an on-device RedMagic-over-real-Google-Drive confirmation that the retry now absorbs the first-attempt failure is a nice-to-have manual check, **not** a merge gate. Worth doing opportunistically when next on the device.
- **Retry-exhaustion rethrow folds `e.message` without a `cause`** — deliberate: `CloudFolderException`/`VaultMirrorException` are single-arg in this layer, and `onRetry` logs every attempt. Threading a cause is a cross-layer convention change (out of scope). Confirmed sound by the opus review.
- **Permanent failures (revoked SAF permission) burn the full retry budget before rethrowing** — accepted: we can't distinguish transient from permanent (both fold to `CloudFolderException`), and the provider is eventually-consistent so most real failures are transient. Bounded (~5.75 s worst case).
- **`:app` Compose-UI instrumented tests fail on the RedMagic** ("No compose hierarchies found") — pre-existing, device/harness-specific (carried from the slice-6 / #333 batons), not this slice. This slice ships zero `:app` instrumented tests; all new tests are host (`:vault-access`).

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After this PR merges, remove the worktree + branch:
#   git worktree remove .worktrees/android-cloud-saf-retry-330 && \
#   git branch -D feature/android-cloud-saf-retry-330
git worktree list && git status -s
# Pick a next item (see §2). Android toolchain on this machine: emulator-5554 +
# a real RedMagic 11 Pro (serial 912607710061); adb/emulator need absolute paths
# (~/Library/Android/sdk/platform-tools/adb); logcat is blocked on the RedMagic.
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; symlink retargeted in the same commit on the feature branch (new path → no add/add conflict; `main` updates cleanly on merge). Per [[feedback_next_session_in_pr]] / [[feedback_next_session_main_authoritative]] the baton rides inside the PR — do **not** sync to `main` during the pause window.

## Closing inventory
- **State on close:** PR opening on `feature/android-cloud-saf-retry-330` (11 commits + handoff). Worktree `.worktrees/android-cloud-saf-retry-330`. Feature complete; #330 resolved; native-provider epic #334 filed with a threat-model gate.
- **Acceptance:** `:vault-access:test` 339 green; full host gate green; whole-branch opus review Ready-to-merge YES (0 Critical / 0 Important); all per-task + final-review Minors fixed except the deliberate cause-less-rethrow convention.
- **README.md / ROADMAP.md:** updated (root README status row + android/README provider note + ROADMAP C.3/progress bars). **CLAUDE.md:** unchanged.
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-06-29-android-saf-eventual-consistency-hardening-shipped.md`.
