# Android write re-auth (biometric presence proof) — design

**Date:** 2026-06-21
**Status:** approved (brainstorm) — ready for implementation plan
**Sibling features:** iOS #275 (biometric write re-auth, shipped) · desktop #278 (password write re-auth, shipped)
**Tracking:** the last platform without a write-reauth affordance.

## 1. Purpose & one-line summary

Bring write re-authentication to the Android client: every *mutating* vault write
(record add/edit/delete/restore/move, block create/rename) first requires a
**biometric presence proof**, throttled by a short grace window, so an
unlocked-but-unattended session cannot be silently mutated by someone other than
the enrolled user.

Android already ships the biometric primitive used for device-secret unlock
(`BiometricPrompt` + the biometric-gated Keystore enclave, #262/#269). This
feature **reuses that path verbatim** — there is **no new cryptography**. The
presence proof is the existing `enclave.release(reason)`: releasing the wrapped
32-byte device secret under a `BIOMETRIC_STRONG`-gated Keystore key proves both
*biometry* and *Keystore key integrity*, exactly as iOS uses Secure-Enclave
key-release. The released secret is not needed here — it is immediately
zeroized and discarded; only the *act of releasing it* matters.

This makes Android a faithful mirror of **iOS #275** rather than desktop #278:
desktop has no Secure-Enclave, so it falls back to password re-entry; Android,
like iOS, has a hardware biometric primitive and uses it.

## 2. Decisions (locked during brainstorm)

| Decision | Choice | Rationale |
|---|---|---|
| Presence proof | **Biometric** (mirror iOS) | Reuses shipped Android biometric infra; native idiom; host-testable via fakes. |
| Settings model | **Fixed default, no settings UI** (mirror iOS) | Smallest scope; no vault-settings-record schema work; gate is active implicitly whenever a device secret is enrolled. Configurable/persisted settings can be a later slice. |
| Grace-window default | **30 s** (match iOS `ReauthWindow.v1Default`) | Consistency with the biometric sibling; biometric prompts are fast, so a short window is low-friction. (Desktop's 120 s partly amortized the ~1–2 s Argon2id cost, which does not apply here.) |
| Enablement | **Implicit: active iff a device secret is enrolled** | No opt-in toggle this slice. Not enrolled → no Keystore key → gate is a no-op → no regression for password-only users. |

## 3. Architecture & layering

Built entirely within the existing three-tier Android structure:

- **`:vault-access`** — pure, FFI-free, host-tested Kotlin (policy + gate + VM wiring).
- **`:kit` / `:app`** — real Android adapters (biometric authorizer over the
  shipped enclave) + instrumented tests + the cross-module `when` rebuild.

### 3.1 Pure policy (`:vault-access`)

```kotlin
// Named constant — no magic number.
object ReauthWindow { const val V1_DEFAULT_MS: Long = 30_000 }

/**
 * Does a write need a fresh presence proof?
 *   lastAuthAtMs == null            -> true  (never authed this session)
 *   nowMs - lastAuthAtMs >= window  -> true  (window elapsed; boundary INCLUSIVE)
 *   else                            -> false (within grace window)
 */
fun needsReauth(lastAuthAtMs: Long?, nowMs: Long, windowMs: Long): Boolean
```

### 3.2 Gate interfaces (`:vault-access`)

```kotlin
/** The presence gate the VMs depend on. Throws on cancel/failure. */
interface WriteReauthGate {
    suspend fun authorizeWrite(reason: String)
}

/** The biometric primitive, abstracted for host-test fakes. */
interface BiometricAuthorizer {
    /** True iff a device secret is enrolled (a Keystore key exists to release). */
    val isEnrolled: Boolean
    /** Prove presence; throws DeviceUnlockError on cancel/lockout/failure. */
    suspend fun authorize(reason: String)
}

/** Grace-window gate. Pure; host-tested over a fake authorizer + injected clock. */
class GraceWindowReauthGate(
    private val authorizer: BiometricAuthorizer,
    private val clock: () -> Long,
    private val windowMs: Long = ReauthWindow.V1_DEFAULT_MS,
) : WriteReauthGate {
    private var lastAuthAtMs: Long? = null

    override suspend fun authorizeWrite(reason: String) {
        if (!authorizer.isEnrolled) return                       // no-op: no regression
        if (!needsReauth(lastAuthAtMs, clock(), windowMs)) return // within grace window
        authorizer.authorize(reason)                             // throws on cancel/fail
        lastAuthAtMs = clock()                                   // advance ONLY on success
    }

    /** Seed the window open at session open (mirrors iOS). */
    fun seed(nowMs: Long) { lastAuthAtMs = nowMs }
    /** Reset on lock. */
    fun reset() { lastAuthAtMs = null }
}
```

### 3.3 Real authorizer (`:kit` / `:app`)

A `BiometricAuthorizer` implementation that wraps the already-shipped device-unlock
path: `isEnrolled` delegates to the enrollment metadata/enclave (`devices/<uuid>.wrap`
present), and `authorize(reason)` calls `enclave.release(reason)` through the real
`BiometricPromptGate`, then **zeroizes and discards** the released secret. No new
Keystore key, no new file format, no FFI change.

## 4. Injection points (the chokepoint advantage)

Android's browse VM already funnels **every** write through a single helper, so the
gate needs only **two** injection points — vs desktop's 13 scattered call sites.
This structurally avoids the desktop #280 "missed gate" risk for the current write set.

1. **`VaultBrowseModel.guardedWrite(reason, reload, op)`** — gains a `reason`
   parameter; calls `gate.authorizeWrite(reason)` at the top, *after* the
   `_writing` re-entrancy check and *before* `op()`. This one chokepoint covers:
   - `delete` / `restore` (via `commitThenReload`),
   - `confirmMove`,
   - `confirmBlockName` (create / rename).

   Input validation already runs *before* `guardedWrite` (empty-name guard,
   same-block guard), and each dialog's `… = null` state clear happens *inside*
   `op` — so a gate rejection before `op()` **leaves the dialog/picker open** with
   no additional code.

2. **`RecordEditModel.commit()`** — the only write outside the browse VM
   (a separate VM). The gate call is added after input validation, before
   `appendRecord` / `editRecord`. On rejection the edit form stays open
   (`onEditCommitted` clears it only on success).

### 4.1 Reason strings (per site, mirroring iOS)

| Site | Reason |
|---|---|
| `delete` | "Confirm deleting this entry" |
| `restore` | "Confirm restoring this entry" |
| `confirmMove` | "Confirm moving this entry" |
| `confirmBlockName` (create) | "Confirm creating this block" |
| `confirmBlockName` (rename) | "Confirm renaming this block" |
| `RecordEditModel.commit` (add) | "Confirm saving this entry" |
| `RecordEditModel.commit` (edit) | "Confirm saving this entry" |

### 4.2 Construction & lifetime

The gate is constructed once per unlocked session in `:app` (where the browse model
is created) and injected into `VaultBrowseModel`, which threads it into every
`RecordEditModel` it creates (`startAdd` / `startEdit`). The gate's `lastAuthAtMs`
therefore persists across individual edit-form lifecycles within a session.

## 5. Error handling

The gate throws the **existing `DeviceUnlockError`** (it already carries
`UserCancelled`, `BiometryLockout`, `BiometryUnavailable`, `BiometryNotEnrolled`,
`AuthenticationFailed`, `WrappedSecretCorrupt`, `Enclave`). **No new gate error type.**
The VMs catch it and map:

- **`UserCancelled`** → silent abort: no write, no error surfaced, dialog/form
  stays open.
- **Any other arm** → no write; surface a new **`VaultBrowseError.ReauthFailed(detail)`**
  arm so the UI can explain biometry failure (lockout / unavailable), mirroring
  iOS's `VaultAccessError.reauthFailed(reason:)`.
- **Not enrolled** → the gate is a no-op (handled in `GraceWindowReauthGate`), so
  the write proceeds unchanged — no regression for password-only users.

### 5.1 Cross-module obligation (must-not-defer)

Adding `VaultBrowseError.ReauthFailed` widens a sealed type, which breaks every
no-`else` `when (e: VaultBrowseError)` in `:kit` / `:app` at compile time
(see project memory: *Android sealed-type arm breaks cross-module exhaustive when*).
The implementation plan **builds `:app` in the same task** that adds the arm — not
later — and threads the new arm through every exhaustive `when`.

### 5.2 Clock seeding

`gate.seed(now)` is called when the browse session opens (the just-unlocked grace
window starts open, like iOS), and `gate.reset()` on lock.

## 6. Testing strategy (TDD)

| Layer | Where | What |
|---|---|---|
| Pure policy | `:vault-access` host test | `needsReauth`: null → prompt; `< window` → silent; `== window` → prompt (inclusive); `> window` → prompt. |
| Gate | `:vault-access` host test | `GraceWindowReauthGate` over fake authorizer + injected clock: not-enrolled no-op; null `lastAuthAtMs` prompts; within-window silent; at/after window prompts; success advances clock; cancel throws + does NOT advance; non-cancel failure throws + does NOT advance. |
| VM | `:vault-access` host test | Each of the 7 write calls invokes the gate before the `session.*` write; `UserCancelled` → no write + dialog/form stays open + no error; other failure → no write + `ReauthFailed` surfaced; not-enrolled → write proceeds (regression guard); seed/reset behavior. |
| Instrumented | `:app` `androidTest` | Real `BiometricAuthorizer` over the Keystore enclave with the auto-approving gate seam (no on-device biometric in CI). |
| Manual | on-device checklist | Real fingerprint/face prompt: write after the window prompts; within the window does not; cancel refuses the write and leaves the dialog open; not-enrolled writes proceed. Mirrors iOS's manual SE proof. |

## 7. Scope boundary (frozen for future readers)

**In scope**
- `:vault-access`: `needsReauth`, `ReauthWindow`, `WriteReauthGate` /
  `BiometricAuthorizer` / `GraceWindowReauthGate`, VM wiring (`guardedWrite`
  `reason` param + `RecordEditModel.commit` gate call), `VaultBrowseError.ReauthFailed` arm.
- `:kit` / `:app`: real `BiometricAuthorizer` adapter over the shipped enclave,
  gate construction/injection + seed/reset wiring, the same-task `when` rebuild,
  instrumented test.

**Untouched** (guardrail: `git diff main...HEAD --name-only` matches only `^android/`
+ docs)
- `core/`, the crypto/vault spec (`crypto-design.md`, `vault-format.md`), all
  `*.udl`, `secretary-ffi-py`, `desktop/`, `ios/`.

**Deliberately deferred** (so a future reader does not "fix" the omission)
- Configurable / persisted settings + an Android settings UI (this slice is fixed
  30 s; a later slice can read the shared `secretary.settings.v1` record for
  cross-platform parity with desktop).
- A presence proof for users who unlocked by password and never enrolled a device
  secret (no Keystore key exists; the gate is a deliberate no-op for them).
- Sharing / contacts write-site gates — those write sites do not yet exist in the
  Android `:vault-access` surface.

## 8. Acceptance criteria

- `needsReauth` and `GraceWindowReauthGate` are pure and host-tested with the cases in §6.
- All 7 mutating write sites route through the gate; cancel leaves the originating
  dialog/form open and writes nothing; not-enrolled writes proceed unchanged.
- `VaultBrowseError.ReauthFailed` is threaded through every exhaustive `when` in
  `:vault-access` / `:kit` / `:app`; `:app` compiles in the same task.
- Host tests green; instrumented test (auto-approving gate) green; manual on-device
  checklist documented in the handoff.
- Guardrail empty: no diff outside `^android/` + docs.
- `core/`, `*.udl`, `ios/`, `desktop/`, `secretary-ffi-py` untouched.
