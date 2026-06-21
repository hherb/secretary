# NEXT_SESSION.md — Android write re-auth (biometric) ✅ (code-complete; all gates green; PR to open)

**Session date:** 2026-06-21. Flow: `/nextsession` → the prior baton (#278 desktop write-reauth) had **already been squash-merged** to `main` @ `00ea3bd3` by a parallel session; I verified the merge captured everything (two-dot diff `main` vs the merged branch was empty, incl. the review-gap security fixes), then removed its worktree/branch. With that baton discharged, you chose a net-new feature — **Android write re-auth** (bringing the iOS #275 biometric-write-reauth gate to the native Android client). Full brainstorm → spec → plan → subagent-driven execution (per-task spec+quality reviews, final whole-branch review on opus, batched fix wave) → this handoff.

**Status:** ✅ **code-complete; all gates green.** Branch `feature/android-write-reauth` (worktree `.worktrees/android-write-reauth`), branched from `main` @ `00ea3bd3`. **Android-only:** `core/`, the crypto/vault spec, all `*.udl`, `secretary-ffi-py`, `ios/`, and `desktop/` are **untouched** (guardrail verified empty). **PR not yet open** — push + open it (see §4).

## (1) What we shipped this session

**The central idea:** unlike desktop (no Secure-Enclave → password re-entry), Android already ships a biometric primitive (`BiometricPrompt` + the biometric-gated Keystore enclave, from device-unlock #262/#269), so Android mirrors **iOS #275**: every mutating vault write first requires a **biometric presence proof**, throttled by a **30 s grace window**, **active iff a device secret is enrolled** (no-op otherwise — no regression for password-only users). The proof reuses the shipped `DeviceUnlockCoordinator.unlock` → `enclave.release` path; the released 32-byte secret is **zeroized and discarded** — only the *act of releasing it* matters (proves biometry + Keystore-key integrity). **No new crypto, no FFI/UDL/core/on-disk-format change.**

| Layer | What landed |
|---|---|
| **Pure policy** (`:vault-access` `Reauth.kt`) | `needsReauth(lastAuthAtMs, nowMs, windowMs)` (null→true; `>=window`→true, boundary inclusive; else false) + `ReauthWindow.V1_DEFAULT_MS = 30_000L` (named const, no magic number). |
| **Gate** (`:vault-access` `WriteReauthGate.kt`) | `WriteReauthGate { authorizeWrite(reason); seed(nowMs)=no-op; reset()=no-op }`, `BiometricAuthorizer { isEnrolled; authorize(reason) }`, `GraceWindowReauthGate(authorizer, clock, windowMs)` (advances `lastAuthAtMs` **only on success**; single clock snapshot per call), `object NoopReauthGate`. |
| **Real authorizer** (`:vault-access` `CoordinatorBiometricAuthorizer.kt`) | Wraps `DeviceUnlockCoordinator`: `isEnrolled` delegates; `authorize` = `coordinator.unlock(vaultId, reason).secret.fill(0)` — release-as-proof, **same-instance zeroize** (verified end-to-end). Pure → host-tested (placed in `:vault-access`, not `:kit` as the spec first guessed; spec §3.3 corrected). |
| **Typed error** (`:vault-access` `VaultBrowseError.kt`) | New `data class ReauthFailed(detail)` arm. Cross-module `when` audit found **no** exhaustive consumer `when (VaultBrowseError)` in production (`BrowseMapping.kt` maps *from* `VaultException` with `else`), so the arm broke nothing; full multi-module build confirms. |
| **Gated writes — 2 chokepoints, 7 sites** | `VaultBrowseModel.guardedWrite(reason, …)` (covers delete/restore via `commitThenReload`, confirmMove, confirmBlockName create/rename) + `RecordEditModel.commit` (append/edit). Gate runs **after** validation + the re-entrancy guard, **before** the `session.*` write. `UserCancelled` → silent abort (dialog/form stays open, no error); other `DeviceUnlockError` → `_error = ReauthFailed`, no write; `_writing`/`_inFlight` reset in `finally`; `CancellationException` propagates (catches are `DeviceUnlockError`-scoped, with a comment forbidding widening). `lock()` calls `gate.reset()`. Android's 2-chokepoint funnel **structurally avoids** the desktop #280 missed-gate class. |
| **`:app` wiring** | `unlockAndOpen` builds a **fresh per-unlock** `GraceWindowReauthGate(CoordinatorBiometricAuthorizer(coordinator, vaultId), clock = System::currentTimeMillis)`; `openBrowseWithSync(…, gate)` injects it into `VaultBrowseModel` (threaded into `RecordEditModel`) and **seeds** it at open (first post-unlock write is silent); reset on lock. All new gate params **defaulted** to `NoopReauthGate` → ~15 existing call sites/tests compile unchanged. |
| **UI** (`:browse-ui` `BrowseScreen.kt`) | `ErrorBanner` renders `ReauthFailed` write-aware (`"Couldn't authorize the change: <detail>"`); all other arms unchanged. |
| **Tests** | Host-tested in `:vault-access`: `needsReauth`, `GraceWindowReauthGate` (incl. cancel/fail-does-not-advance on the **same** gate, not a fresh one), `CoordinatorBiometricAuthorizer` (incl. **same-instance zeroize** regression + guard-before-prompt), `VaultBrowseModelReauthTest` (7), `RecordEditModelReauthTest` (4). Instrumented `WriteReauthInstrumentedTest` (real Keystore enclave + auto-approving gate; not-enrolled no-op; `try/finally` cleanup) — compiles; on-device run is manual. |
| **Docs** | README status row + ROADMAP (C.3 + D.x + progress bars) — write-reauth now iOS + desktop + Android. Spec + plan under `docs/superpowers/`. |

**Branch commits** (12; squash-merge → one on `main`): `11b80fa6` spec · `4b782d5f` plan · `0d38fe84` T1 needsReauth · `a91ee874` T2 gate · `aff6141d` T2 fix (cancel-path invariant, single clock) · `bf5dfa17` T3 authorizer · `77364db6` T3 tidy · `363ec97d` T4 VaultBrowseModel gate + ReauthFailed · `495c9f42` T5 RecordEditModel gate · `3f844140` T6 app wiring · `bc6f4070` T7 docs · `c3b61b9c` final-review fixes.

### Acceptance (all green this session)
```bash
cd /Users/hherb/src/secretary/.worktrees/android-write-reauth/android
./gradlew :vault-access:test :browse-ui:test :sync-ui:test \
          :app:compileDebugKotlin :kit:compileDebugKotlin :app:compileDebugAndroidTestKotlin   # BUILD SUCCESSFUL
```
Guardrails (from the worktree root):
```bash
cd /Users/hherb/src/secretary/.worktrees/android-write-reauth
git diff main...HEAD --name-only | grep -E 'core/|crypto-design|vault-format|\.udl|secretary-ffi-py|^ios/|^desktop/'   # EMPTY
git diff main...HEAD --name-only | grep -E '^android/'                                                                  # 16 files (expected)
```

### Deliberate design decisions (so a future reader doesn't "fix" them)
- **Biometric, not password re-entry** — Android has a hardware biometric primitive (unlike desktop), so it mirrors iOS. OS-biometric-without-enrollment is out of scope (see deferred).
- **Fixed 30 s window, no settings UI** — matches iOS; smallest scope; gate active implicitly when a device secret is enrolled. Configurable/persisted settings deferred.
- **Gate is active iff device-secret enrolled** — not enrolled → no Keystore key → gate is a no-op → password-only sessions write exactly as before.
- **Release-as-proof, zeroized** — `authorize` releases the device secret via the coordinator and immediately `.fill(0)`s it (verified same-instance through enclave→coordinator→credential→authorizer; no defensive copy). No new key/file/FFI.
- **`CoordinatorBiometricAuthorizer` lives in `:vault-access`** (purer than the spec's first guess — it's interface-only) → host-tested. Spec §3.3 carries an implementation note.
- **2 chokepoints, not N scattered sites** — Android funnels all writes through `guardedWrite` + `commit`, structurally dodging the desktop #280 missed-gate risk **for the current write set** (see risk below).
- **No new `AppError`/UDL/conformance change** — `DeviceUnlockError` already carries the biometric arms; `VaultBrowseError.ReauthFailed` is a `:vault-access`-only arm.

### Review outcome
Per-task spec+quality reviews (all approved; 2 fix rounds: T2 cancel-path invariant test rewritten on the same gate + single clock snapshot; T3 test idiom). **Final whole-branch review (opus): With fixes, NO Critical/Important** — security mechanics verified (same-instance zeroize chain, gate placement, no swallowed cancellation, in-flight resets, grace-window seed/reset/advance, guardrail, cross-module `when`). Batched fix wave `c3b61b9c`: docs `:kit`→`:vault-access`; `ErrorBanner` write-aware `ReauthFailed`; `ReauthTest` refs the named constant; `CancellationException` comments; failed-reauth test asserts `committed==false`; instrumented-test `try/finally`.

## (2) What's next
- **Push + open the PR** (§4), then after merge, housekeeping (remove this worktree + branch).
- **Manual on-device biometric checklist** (not CI-automatable; against a temp copy of the golden vault — settings live in the vault, don't mutate the fixture):
  1. Unlock → immediately edit+save → **no prompt** (within the 30 s seeded window).
  2. Wait > 30 s → save an edit → **biometric prompt**; on success the write commits.
  3. Trigger a write, **cancel** the prompt → record/block/edit dialog **stays open**, nothing written, no error banner.
  4. Trigger a write, **fail** biometry (to lockout) → write refused, `ReauthFailed` banner ("Couldn't authorize the change: …"), dialog stays open.
  5. **No device secret enrolled** (password-only) → writes proceed, **no prompt** (no regression).
  6. Background→re-unlock → first post-unlock write is silent (re-seeded) — confirms per-session gate reset.
- **Deferred follow-ups** (note in a future issue if you want them tracked): configurable/persisted grace-window setting (read the shared `secretary.settings.v1` record for desktop parity); a presence proof for **password-only sessions with no device-secret enrollment** (no Keystore key exists today → deliberate no-op); the `ErrorBanner` `ReauthFailed` branch has **no automated test** (all `:browse-ui` tests are emulator-instrumented) — covered by the manual check.

**Open follow-up issues (carried):** #277 (desktop OS biometric) / #279 (pre-existing ffi fmt drift on main) / #280 (desktop centralized gate-coverage test) / #224 / #234 / #192 / #193 / #190 / #189 / #186 / #161 / #162 / #167 / #251 / #252 / #255.

## (3) Open decisions and risks
- **Presence layer, NOT a hard boundary.** The gate lives in the VM/frontend; the FFI write surface is not itself gated. An attacker with code-exec in an unlocked session already holds the in-memory plaintext, so VM-level gating is the right altitude (same framing as desktop #278). Don't reframe this as a defence against a compromised process.
- **Missed-gate risk for FUTURE writes.** The 2-chokepoint design covers today's 7 write sites with no scattered call sites. But a **new** mutating VM/method added later must remember to route through `guardedWrite`/`commit` (or call the gate) — there is no centralized enforcement test (the Android analogue of desktop #280). If sharing/contacts or other write surfaces land on Android, add the gate + a coverage check.
- **Argon2id is NOT on this path** — the proof is a fast biometric release, not a KDF (that's the desktop cost). The 30 s window is for UX (burst edits), not cost amortization.
- **No cross-language / iOS / desktop run needed** — Android-only; guardrail empty by construction (verified).

## (4) Exact commands to resume
```bash
# 0) Push the branch + open the PR (worktree kept alive for PR iteration):
cd /Users/hherb/src/secretary/.worktrees/android-write-reauth
git push -u origin feature/android-write-reauth
gh pr create --base main --head feature/android-write-reauth --title "Android write re-auth (biometric presence proof, mirror iOS #275)" --body "<summary>"

# Re-run the gates before merge:
cd android && ./gradlew :vault-access:test :browse-ui:test :sync-ui:test :app:compileDebugKotlin :kit:compileDebugKotlin :app:compileDebugAndroidTestKotlin

# Guardrails (must be empty / android-only):
cd /Users/hherb/src/secretary/.worktrees/android-write-reauth
git diff main...HEAD --name-only | grep -E 'core/|crypto-design|vault-format|\.udl|secretary-ffi-py|^ios/|^desktop/'   # empty
git diff main...HEAD --name-only | grep -E '^android/'                                                                  # non-empty

# 1) After the PR merges, housekeeping (from the MAIN checkout, not this worktree):
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/android-write-reauth && git branch -D feature/android-write-reauth
git worktree prune && git worktree list
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Authored once; the symlink is the pointer. Both this handoff + the retargeted symlink are committed on the feature branch ([[feedback_next_session_in_pr]]). If you resume this branch for fixups, first `git fetch origin && git merge origin/main` (branch-version-wins on the handoff path) before editing ([[feedback_next_session_main_authoritative]]). `origin/main` was at `00ea3bd3` (the branch point) at close, so no bind was needed this session.

## Closing inventory
- **Branch on close:** `feature/android-write-reauth` @ `c3b61b9c` + the handoff commit; `main`/`origin/main` @ `00ea3bd3`. PR to open. Squash-merge → one commit on `main`.
- **Acceptance:** green — `:vault-access` + `:browse-ui` + `:sync-ui` host tests; `:app`/`:kit` + instrumented-test compile. Guardrail empty (android-only).
- **Reviews:** per-task spec+quality (approved, 2 fix rounds) + final whole-branch review on opus (With fixes, no Critical/Important; batched fix wave applied).
- **README.md / ROADMAP.md:** updated (write-reauth now iOS + desktop + Android; configurable-settings + password-only-presence-proof pending).
- **NEXT_SESSION.md:** symlink retargeted to this file.
