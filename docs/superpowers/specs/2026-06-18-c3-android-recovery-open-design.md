# C.3 Android — recovery-phrase open path (design)

**Date:** 2026-06-18
**Slice:** C.3 Android — add a second unlock credential (the 24-word BIP-39 recovery
phrase) alongside the existing password open, both reaching the unified
`BrowseWithSyncScreen`.
**Status:** design approved; awaiting spec review → implementation plan.

## 1. Goal

Every Android open slice so far is password-only. The Rust core already exposes a
recovery-phrase open (`open_vault_with_recovery`) on the uniffi surface; iOS already
consumes it. This slice brings the same capability to Android: an unlocked user can
open the golden vault with its 24-word recovery phrase and land on the same
`BrowseWithSyncScreen` they reach via password.

**Acceptance:** open `golden_vault_001` on-device via its recovery mnemonic and reach
the block list; the password path is unchanged; both credentials route through the
same browse+sync screen.

## 2. Scope and non-goals

**In scope (Android-only):**
- A recovery branch on the open port (`VaultOpenPort.openWithRecovery`).
- The `:kit` adapter over the generated `openVaultWithRecovery` binding + error mapping.
- A pure `RecoveryPhrase.normalize` helper.
- A credential-aware `:app` unlock flow (sealed `UnlockCredential`) and a
  Password/Recovery toggle on `UnlockScreen`.

**Out of scope (deferred):**
- **Device-secret open** (`add_device_slot` / `open_with_device_secret`) and its
  biometric Keystore/StrongBox storage — a separate, larger effort mirroring the iOS
  B.3 Secure-Enclave stack (#201/#202). Tracked as the next direction after this slice.
- Any `core` / `ffi` / `ios` / on-disk-format / UDL change. `open_vault_with_recovery`
  is already in the Rust UDL and is generated into the Android Kotlin bindings at build
  time (`android/kit` regenerates bindings from the live cdylib — they are never
  committed), so **no FFI work is required**.

## 3. Background: the FFI surface (already present)

Rust UDL (`ffi/secretary-ffi-uniffi/src/secretary.udl`), generated into Kotlin at
build time:

```
[Throws=VaultError]
OpenVaultOutput open_vault_with_recovery(bytes folder_path, bytes mnemonic);
```

- `mnemonic` is the UTF-8 bytes of the (normalized) 24-word phrase.
- Error arms relevant here (`VaultError` → Kotlin `VaultException`):
  - `WrongMnemonicOrCorrupt` — phrase failed verification OR vault corruption
    (**conflated by design**, anti-oracle per crypto threat-model §13).
  - `InvalidMnemonic { detail }` — malformed phrase (bad word / wrong length / invalid
    UTF-8). A **format** error, distinct from the conflated wrong-or-corrupt.

iOS already mirrors exactly this split in `VaultAccessError`
(`wrongMnemonicOrCorrupt`, `invalidMnemonic(String)`); Android will mirror it in
`VaultBrowseError`.

## 4. The password-keyed-sync constraint (key design point)

The Android sync surface is **password-keyed**: `sync_vault(state_dir, vault_folder,
password, now_ms)` and `sync_commit_decisions(... password ...)` both require the
password (they re-open the vault per call and run Argon2id). There is **no
recovery-credential sync**. Therefore a recovery-opened session **cannot auto-run a
sync pass** — it has no password to feed the coordinator.

This is exactly the situation iOS already handles. iOS's `onUnlocked` callback takes an
**optional** password:

```swift
if let password { Task { await syncVM.syncAtUnlock(password: password) } }
else            { Task { await syncVM.refreshStatus() } }   // recovery: status only
route = .browse(...)                                          // BOTH reach the browse screen
```

**Android mirrors this:**
- A recovery open still reaches `BrowseWithSyncScreen` and still builds the sync VM +
  monitor. `makeVaultSync(folder, stateDir, vaultUuid)` needs **no credential and no
  session** (Android passes `vaultUuid` separately via `goldenVaultUuid`), so the sync
  VM is built identically regardless of open method.
- The recovery branch runs `sync.refreshStatus()` (a cheap `status()` disk read → the
  badge shows last-known sync status) **instead of** `launchSyncAtUnlock`. No sync pass,
  no Argon2id.
- **Manual sync still works** for a recovery user: tapping the badge opens the existing
  `SyncScreen` password sheet (`beginInteractiveSync` → `submitPassword`), which
  re-prompts for the password fresh. No phrase is retained, and no new long-lived
  secret buffer is introduced.

## 5. Architecture (Approach A — sealed `UnlockCredential`)

A single sealed type carries *which secret* the user supplied; the `when` over it is the
one place that decides *how to open* and *how to sync*. This makes the recovery branch
impossible to forget (exhaustive match) and keeps the secret-handling decisions
(zeroize both; sync-at-unlock only for password) in one auditable place. Mirrors iOS's
`UnlockViewModel.Mode { password, recovery }`.

```
:app
  UnlockCredential.kt   sealed interface UnlockCredential {
                            data class Password(val bytes: ByteArray) : UnlockCredential
                            data class Recovery(val phraseBytes: ByteArray) : UnlockCredential
                        }
  UnlockScreen.kt       Password/Recovery segmented toggle; emits an UnlockCredential
  BrowseSession.kt      openBrowseWithSync(..., credential: UnlockCredential) dispatches the open
  AppRoot.kt            unlockAndOpen matches credential:
                          Password -> launchSyncAtUnlock(scope, bytes, sync::syncAtUnlock)
                          Recovery -> sync.refreshStatus()           (no sync pass)
                        both: zeroize the credential bytes in finally

:kit
  UniffiVaultOpenPort   + openWithRecovery(vaultFolder, phrase) over openVaultWithRecovery
  BrowseMapping.kt      mapVaultBrowseError gains two explicit arms before `else`

:vault-access
  VaultOpenPort.kt      + suspend fun openWithRecovery(vaultFolder: String, phrase: ByteArray): VaultSession
  RecoveryPhrase.kt     pure normalize(raw: String): String   (mirror of iOS RecoveryPhrase)
  VaultBrowseError.kt   + WrongRecoveryOrCorrupt (object) + InvalidRecoveryPhrase(detail)
```

### 5.1 Pure helper — `RecoveryPhrase.normalize`

Mirror of iOS `RecoveryPhrase.normalize`: lowercase, split on any whitespace run, rejoin
single-spaced. Removes copy/paste and keyboard auto-capitalization noise without
altering the words. Pure, free function in a reusable module; host-tested.

```kotlin
object RecoveryPhrase {
    fun normalize(raw: String): String =
        raw.lowercase().split(Regex("\\s+")).filter { it.isNotEmpty() }.joinToString(" ")
}
```

### 5.2 Port + adapter

`VaultOpenPort` gains one suspend method; `UniffiVaultOpenPort` implements it exactly
like `openWithPassword` (IO dispatcher for Argon2id, UTF-8 folder path, raw phrase bytes
forwarded per call and never retained, `mapErrors`), with an injectable `recoveryFn`
seam defaulting to `::openVaultWithRecovery` (parallels the existing `openFn` seam).

### 5.3 Error mapping

`mapVaultBrowseError` gains two explicit arms **before** the `else` (per the file's
maintainer warning that the `else` silently swallows new arms):

```kotlin
is VaultException.WrongMnemonicOrCorrupt -> VaultBrowseError.WrongRecoveryOrCorrupt
is VaultException.InvalidMnemonic        -> VaultBrowseError.InvalidRecoveryPhrase(e.detail)
```

`WrongRecoveryOrCorrupt` stays conflated (anti-oracle §13) — do NOT split it.
`InvalidRecoveryPhrase(detail)` is a usability signal the UI can surface ("check the
phrase") without leaking whether the vault exists/is-corrupt.

### 5.4 App flow

`openBrowseWithSync` takes `credential: UnlockCredential` instead of `password`, and
dispatches:

```kotlin
val session = when (credential) {
    is UnlockCredential.Password -> openPort.openWithPassword(folder.path, credential.bytes)
    is UnlockCredential.Recovery -> openPort.openWithRecovery(folder.path, credential.phraseBytes)
}
```

It still does NOT zeroize and does NOT launch sync (caller owns both). `unlockAndOpen`
matches the credential to decide the post-open sync action and zeroizes the bytes in its
`finally`:

```kotlin
when (credential) {
    is UnlockCredential.Password -> launchSyncAtUnlock(scope, credential.bytes, session.sync::syncAtUnlock)
    is UnlockCredential.Recovery -> session.sync.refreshStatus()   // no password → status only
}
// finally: (credential payload).fill(0)
```

### 5.5 UI

`UnlockScreen` gains a Password/Recovery segmented toggle (mirrors iOS's segmented
`Mode`). Password mode is unchanged (masked single-line field → `Password(bytes)`).
Recovery mode shows a multi-line, **unmasked** phrase field (24 words are unreadable when
dotted out, and the threat model already assumes a trusted unlock moment under
`FLAG_SECURE`); on submit it normalizes via `RecoveryPhrase.normalize` and emits
`Recovery(normalized.toByteArray(UTF_8))`.

## 6. Secret hygiene

- Both `UnlockCredential` payloads are `ByteArray`; `unlockAndOpen`'s `finally`
  zeroizes whichever was used (same discipline as today's password buffer). The
  `openBrowseWithSync` open awaits before the zeroize, so it cannot race the Argon2id
  that consumes the bytes.
- The recovery branch hands no copy to a background job (no `launchSyncAtUnlock`), so the
  phrase bytes are fully owned by `unlockAndOpen` and zeroized on every exit.
- The normalized `String` lingers until GC — the same accepted demo-skeleton tradeoff
  already documented for the password `String` in `UnlockScreen`. Documented, not fixed
  (consistent with prior slices).
- No phrase is retained for sync; manual sync re-prompts for the password.

## 7. Testing (TDD, written test-first per task)

**Host (`:vault-access`, `:kit`, `:app` unit):**
- `RecoveryPhrase.normalize`: collapses internal runs, trims leading/trailing, lowercases
  mixed case, handles tabs/newlines, drops empty tokens, leaves a clean phrase unchanged.
- `mapVaultBrowseError`: `WrongMnemonicOrCorrupt -> WrongRecoveryOrCorrupt`,
  `InvalidMnemonic(detail) -> InvalidRecoveryPhrase(detail)`.
- `openBrowseWithSync` credential dispatch via a fake `VaultOpenPort`: `Recovery`
  invokes `openWithRecovery` (not `openWithPassword`) with the phrase bytes; `Password`
  unchanged.
- The recovery branch skips sync-at-unlock: assert (via a spy/fake sync VM seam) that
  `Recovery` triggers `refreshStatus()` and never `syncAtUnlock`, and that `Password`
  still triggers the background sync.

**Instrumented (emulator / on-device):**
- A recovery smoke mirroring `OpenBrowseWithSyncSmokeTest`: stage `golden_vault_001`,
  open it via the real `.so` using `openWithRecovery(folder, mnemonic)` with the golden
  recovery phrase, assert the block list is reachable. The phrase is the published KAT
  input `recovery_mnemonic_phrase` in `core/tests/data/golden_vault_001_inputs.json`
  (a KAT, not a real secret — same status as the golden password the existing smokes
  use). The plan includes a step to locate it there and fail loudly if absent.

## 8. Guardrails (verified empty at close)

```
git diff main...HEAD --name-only | grep -E 'core/|ffi/|crypto-design|vault-format'                   # empty
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)' # empty (no ios/)
```

## 9. File-size discipline

All touched `:app` files stay small (`UnlockScreen`, `BrowseSession`, `AppRoot`,
`UnlockCredential`, `SyncAtUnlock` are each well under 500 lines). `RecoveryPhrase.kt`
is a one-function file. No refactor pressure introduced.

## 10. Risks / open items

- **Recovery user cannot silently sync** — by design (sync is password-keyed). Mitigated:
  the badge shows status and manual sync re-prompts. Surfacing a subtle "sync needs your
  password" affordance for recovery sessions is a possible future polish, not this slice.
- **`InvalidMnemonic` vs `WrongMnemonicOrCorrupt` UI copy** — the UI should show a
  distinct "check the phrase" hint for `InvalidRecoveryPhrase` while keeping the
  conflated wrong-or-corrupt generic. Minor UI wording, settled in the plan.
- **The exact uniffi Kotlin variant names** (`VaultException.WrongMnemonicOrCorrupt`,
  `VaultException.InvalidMnemonic` with `.detail`) are confirmed against the Rust UDL but
  must be re-verified against the generated bindings at first build (a one-line fix if
  the codegen renamed them — see the uniffi-codegen-rename memo).
