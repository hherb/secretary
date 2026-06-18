# C.3 Android — real biometric device open (slice 2 of 2)

**Status:** design approved 2026-06-19; awaiting spec review → implementation plan.
**Predecessor:** slice 1 (`#262`, `c923be6a`) shipped the pure `DeviceUnlockCoordinator`,
the three ports (`VaultDeviceSlotPort` / `DeviceSecretEnclave` /
`DeviceEnrollmentMetadataStore`), the `UnlockCredential.DeviceSecret` pipeline
(`openWithCredential` → `openBrowseWithSync` → `dispatchPostOpenSync`, device-secret syncs
like recovery), and the `:kit` FFI adapters — all with **in-memory fakes** for the enclave
and metadata. Slice 2 swaps those fakes for **real Android implementations + UI + an
on-device biometric proof**.

## 1. Goal

An enrolled Android device opens `golden_vault_001` via its per-device wrap slot
(`devices/<uuid>.wrap`), with the 32-byte device secret released only behind a real
`BiometricPrompt`, reaching `BrowseWithSyncScreen`. Proven on the emulator with
`adb emu finger touch`.

**Acceptance (slice 2):**
- Enroll on-device (password + "remember this device") mints the slot, wraps the secret
  under a biometric-gated Keystore key, and persists non-secret metadata.
- After killing the app, "Unlock with biometrics" presents a real `BiometricPrompt`; a
  successful auth releases the secret, opens the vault via the slice-1 credential pipeline
  (same manifest verify-before-decrypt as password/recovery), and reaches
  `BrowseWithSyncScreen`.
- Host suite green (`vault-access` `DeviceUnlockViewModel` state machine over the slice-1
  fakes); instrumented enclave round-trip green on the emulator (auto-approving gate);
  manual `adb emu finger` walking-skeleton proof passes.

## 2. Scope

**In scope (the minimal cohesive end-to-end round-trip):**
- Real `KeystoreDeviceSecretEnclave` (AES-256-GCM Keystore key, `release` gated by
  `BiometricPrompt` via `CryptoObject`).
- Real `FileDeviceEnrollmentMetadataStore` (non-secret `vaultId` + `deviceUuid`).
- Pure, host-tested `DeviceUnlockViewModel` state machine.
- `UnlockScreen` enroll affordance ("Remember this device with biometrics" checkbox) +
  "Unlock with biometrics" affordance.
- `AppRoot` wiring: construct the coordinator (real enclave + gate + metadata), enroll on
  password-unlock-with-remember, biometric-unlock on relaunch.
- `MainActivity` `ComponentActivity` → `FragmentActivity` (+ `androidx.biometric` dep) —
  required by `androidx.biometric.BiometricPrompt`.
- Instrumented `:kit` enclave round-trip test (auto-approving gate, no human fingerprint).

**Out of scope (a later slice):**
- Polished enrollment/settings surface (a Browse toggle, an explicit disenroll button,
  enrollment-status display).
- Disenroll-from-UI (the coordinator's `disenroll` exists from slice 1; no UI yet).
- StrongBox attestation surfacing.
- Any change to `core` / `ffi` / `ios` / on-disk format / UDL. **Android-only.** (Slice 1's
  guardrail re-applies; verified empty at close.)

## 3. Architecture

Three layers, mirroring iOS's `SecretaryDeviceUnlock` (pure) / `SecretaryKit` (real
adapters) / `SecretaryApp` (Activity + UI) split.

### 3.1 `vault-access` (pure, host-tested) — NEW: `DeviceUnlockViewModel`

The state machine the baton calls out. No Android imports; constructed over the three
ports (real in production, the slice-1 in-memory fakes in tests). It does NOT open the
vault — it produces the `UnlockCredential.DeviceSecret` and hands it to a supplied
`onCredential` callback (`AppRoot` opens), exactly as the coordinator's `unlock` already
returns a credential rather than a session.

States (sealed):
- `Unenrolled` — no enrollment; the screen shows password/recovery only (+ the "remember"
  checkbox in password mode).
- `Enrolled` — `coordinator.isEnrolled` true; the screen offers "Unlock with biometrics".
- `Prompting` — a biometric prompt is in flight (button disabled, spinner).
- `Failed(error: DeviceUnlockError)` — `Cancelled` / `Corrupt` / `Mismatch` / `NotEnrolled`
  surfaced for display; recoverable (returns to `Enrolled` or `Unenrolled`).

Operations:
- `refresh()` — recompute `Unenrolled` vs `Enrolled` from `coordinator.isEnrolled` (cheap,
  prompt-free).
- `enroll(folder, vaultId, password)` — delegates to `coordinator.enroll`; on success →
  `Enrolled`. Caller (AppRoot) owns the password bytes and the zeroize.
- `unlockWithBiometrics(folder, vaultId, reason, onCredential)` — `Prompting` →
  `coordinator.unlock` (presents the prompt inside `enclave.release`) → `onCredential(cred)`
  on success → back to `Enrolled`; on `DeviceUnlockError` → `Failed`.

Because the ViewModel is pure and the prompt lives behind the injected enclave, the **full
enroll/unlock/error matrix is host-tested** with the slice-1 fakes (incl. a fake enclave
whose `release` throws `UserCancelled` / `WrappedSecretCorrupt`).

### 3.2 `:kit` (Android lib, real — device-only tested) — NEW

Mirror of iOS's `SecureEnclaveDeviceSecretStore`. Keystore APIs require a device/emulator,
so this is **instrumented-test-only**, like iOS's device-only SE store.

**`KeystoreDeviceSecretEnclave : DeviceSecretEnclave`**
- Key: an AES-256-GCM key in the AndroidKeyStore, alias `org.secretary.deviceSecret.aesKey`,
  generated with:
  - `setBlockModes(GCM)`, `setEncryptionPaddings(NoPadding)`,
  - `setKeySize(256)`,
  - `setUserAuthenticationRequired(true)`,
  - `setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)` (0 = auth
    required for *every* use; no time window),
  - `setInvalidatedByBiometricEnrollment(true)` (enrolling a new fingerprint invalidates the
    key — a defense against an attacker adding their own biometric),
  - StrongBox **best-effort**: `setIsStrongBoxBacked(true)`, retry without it on
    `StrongBoxUnavailableException` (the emulator lacks StrongBox).
- `store(secret: ByteArray)`: encrypt the 32 bytes with a fresh GCM `Cipher` (this op does
  NOT require auth — `store` happens right after a password unlock; only `release` is gated).
  Persist `IV ‖ ciphertext` as one blob under `noBackupFilesDir/devicesecret/blob`. Takes an
  internal copy; the caller may zeroize its array after return (port contract).

  > **Auth-on-encrypt decision:** `setUserAuthenticationRequired(true)` gates *every* use of
  > a symmetric Keystore key — Android cannot scope auth to decryption only. So the
  > enroll-time `store` encryption ALSO routes its `Cipher` through the gate (§3.2.1),
  > producing exactly **one biometric confirmation at enroll**. This is acceptable: enroll is
  > an explicit, deliberate user action, and the iOS enroll flow likewise touches its SE key.
  > `release` prompts again at each unlock. If this single enroll prompt proves awkward
  > on-device, the fallback is a two-key wrap (§3.2.1) — but the primary path is one
  > auth-required key with one enroll prompt.
- `isEnrolled: Boolean`: blob file present (no prompt, never queries the key) — iOS parity.
- `clear()`: delete the key entry + the blob file; attempt BOTH before throwing (revocation
  must make maximal progress — iOS parity).
- `release(reason: String): ByteArray`: load the blob, init a DECRYPT `Cipher` with the
  stored IV + GCM tag length, then `gate(cipher, reason)` → unlocked `Cipher` →
  `cipher.doFinal(ciphertext)` → the 32 bytes (caller-owned, caller zeroizes). AEAD-tag
  failure (corrupt/invalidated key) → `DeviceUnlockError.WrappedSecretCorrupt`.

#### 3.2.1 The `BiometricGate` seam

```kotlin
// in :kit, the contract the enclave depends on
typealias BiometricGate = suspend (cipher: Cipher, reason: String) -> Cipher
```

`KeystoreDeviceSecretEnclave(gate: BiometricGate, ...)`. Both `store` (one enroll-time
prompt, §3.2 note) and `release` route their `Cipher` through `gate`. In production `:app`
supplies the real `BiometricPrompt`-backed gate (§3.3); in the `:kit` instrumented test an
**auto-approving gate** returns the `Cipher` unchanged after a no-op (proves the Keystore
crypto without a human fingerprint). A gate that throws `DeviceUnlockError` (cancel/lockout)
propagates unchanged.

> **Enroll-prompt simplification under review:** if a single biometric confirmation at
> enroll proves awkward in the walking skeleton, the fallback is to wrap with a *second*,
> non-auth-required Keystore key used only for `store`, and keep the auth-required key for
> `release`. The spec's primary path is the single auth-required key (one enroll prompt);
> the implementation plan will validate the enroll prompt on-device and switch to the
> two-key fallback only if the single-key enroll UX is unacceptable. Either way the
> `release` gate and the host-tested ViewModel are unchanged.

**`FileDeviceEnrollmentMetadataStore : DeviceEnrollmentMetadataStore`**
Non-secret `vaultId` (UTF-8) + `deviceUuid` (16 bytes) serialized to a small file under
`noBackupFilesDir/devicesecret/enrollment`. `load` returns `null` if absent/malformed
(matches iOS's `try? metadata.load()` conservative under-report). `save` writes atomically
(temp + rename). `clear` deletes. Non-secret, so not zeroized (vault-format §3a: the uuid is
a loggable filename stem).

### 3.3 `:app` (Activity-bound, real) — NEW + MODIFIED

**`BiometricPromptGate`** (NEW) — the real `BiometricGate`. Given a `FragmentActivity` (or
its `androidx.biometric.BiometricPrompt`), runs
`BiometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))` on the main
thread and bridges the callback into the `suspend` via `suspendCancellableCoroutine`:
- `onAuthenticationSucceeded` → resume with `result.cryptoObject!!.cipher!!`.
- `onAuthenticationError(USER_CANCELED | NEGATIVE_BUTTON | CANCELED)` →
  `DeviceUnlockError.UserCancelled`.
- `onAuthenticationError(LOCKOUT | LOCKOUT_PERMANENT | HW_*)` → a mapped
  `DeviceUnlockError` (new `BiometricUnavailable`/lockout case if the slice-1 taxonomy lacks
  one; otherwise reuse the closest existing case — confirmed during planning).
- `promptInfo`: `BIOMETRIC_STRONG` only (matches the key's `AUTH_BIOMETRIC_STRONG`), title +
  `reason` as subtitle, an explicit negative ("Use password") button.

**`MainActivity`: `ComponentActivity` → `FragmentActivity`** (MODIFIED) — required by
`androidx.biometric`. `FragmentActivity extends ComponentActivity`, so `setContent` /
activity-compose are unaffected. Add `androidx.biometric:biometric` to `:app` deps (explicit
version, matching the repo's explicit-version convention for `activity-compose`).

**`UnlockScreen`** (MODIFIED) — slice-1 has a Password/Recovery segmented toggle. Add:
- In **Password** mode: a "Remember this device with biometrics" checkbox (test tag
  `remember-device`), shown only when not already enrolled.
- When `isEnrolled`: a "Unlock with biometrics" button (test tag `biometric-unlock`) — a
  primary affordance above/beside the toggle. Tapping it calls the VM's
  `unlockWithBiometrics`.
- The screen stays a thin Composable; the enroll/unlock decisions live in
  `DeviceUnlockViewModel` + `AppRoot`. The `onUnlock(UnlockCredential)` contract is
  unchanged for password/recovery; a new `onEnrollChoice(Boolean)` (or a richer callback)
  carries the checkbox state to `AppRoot`.

**`AppRoot`** (MODIFIED) — construct the coordinator ONCE (real
`KeystoreDeviceSecretEnclave(BiometricPromptGate(activity))` + `FileDeviceEnrollmentMetadataStore`
+ the existing `UniffiVaultDeviceSlotPort`). Two new paths:
- **Enroll path** — on a password unlock with "remember" checked: after `openBrowseWithSync`
  succeeds (so we know the password is valid), call `coordinator.enroll(folder, vaultId,
  password)` BEFORE the existing `finally` zeroize. Enroll failure is non-fatal (log; the
  user still reaches Browse via password) — a failed enroll must not block the open.
- **Biometric path** — on relaunch, `coordinator.isEnrolled` true → "Unlock with
  biometrics" → `coordinator.unlock(vaultId, reason)` (presents the prompt) → the resulting
  `DeviceSecret` credential flows through the SAME `unlockAndOpen` → `openBrowseWithSync` →
  `dispatchPostOpenSync` (device-secret syncs like recovery — status-only, slice-1 wired).
  Cancel/error returns to the unlock screen with the failure surfaced.

## 4. Data flow

```
ENROLL (password unlock + remember):
  UnlockScreen → AppRoot.unlockAndOpen(Password, remember=true)
    → openBrowseWithSync(...)                      // validates password, opens vault
    → coordinator.enroll(folder, vaultId, password)
        → slotPort.addDeviceSlot(folder, password) // real .so → mints devices/<uuid>.wrap, returns 32-byte secret
        → enclave.store(secret)                    // wrap under biometric-gated Keystore key (one enroll prompt, §3.2.1)
        → metadata.save(vaultId, uuid)
    → finally { password.fill(0) }                 // existing slice-1 zeroize

UNLOCK (relaunch, enrolled):
  UnlockScreen "Unlock with biometrics" → DeviceUnlockViewModel.unlockWithBiometrics
    → coordinator.unlock(vaultId, reason)
        → metadata.load() guard (NotEnrolled / VaultSlotMismatch BEFORE any prompt)
        → enclave.release(reason)                  // BiometricPrompt(CryptoObject) → doFinal → 32 bytes
        → UnlockCredential.DeviceSecret(uuid, secret)
    → onCredential → AppRoot.unlockAndOpen(DeviceSecret)
        → openBrowseWithSync(...)                  // same manifest verify-before-decrypt
        → dispatchPostOpenSync(DeviceSecret → onRecovery: status-only)
        → finally { secret.fill(0) }
    → BrowseWithSyncScreen
```

## 5. Error handling

- Guards (`NotEnrolled` / `VaultSlotMismatch`) fire in `coordinator.unlock` **before**
  `enclave.release`, so a stale / wrong-vault enrollment never triggers a biometric prompt
  (slice-1 invariant; preserved).
- `BiometricPrompt` callbacks map to `DeviceUnlockError`: cancel/negative →
  `UserCancelled`; AEAD-tag failure on `doFinal` (corrupt blob OR key invalidated by a new
  biometric enrollment) → `WrappedSecretCorrupt`; lockout/hardware → a lockout case
  (reuse or add one — decided in planning, see §7).
- `setInvalidatedByBiometricEnrollment(true)`: enrolling a new fingerprint invalidates the
  key → next `release` fails AEAD → `WrappedSecretCorrupt` → the user falls back to password
  and re-enrolls. This is the intended security behavior, not a bug.
- A failed `enroll` (e.g. Keystore error) is **non-fatal**: logged, the user still reaches
  Browse via the password open. Enroll never blocks the open.
- `:app`'s `dispatchPostOpenSync` already has the `DeviceSecret` arm (slice 1) — no change.

## 6. Testing (TDD)

| Layer | Test | Runs on |
|---|---|---|
| `vault-access` (pure) | `DeviceUnlockViewModel` state-machine matrix over slice-1 fakes: refresh→Unenrolled/Enrolled; enroll success/failure; unlock success; unlock→Cancelled/Corrupt/Mismatch/NotEnrolled; guard-before-release (fake enclave `release` "must not be called" when guard trips) | host (`:vault-access:test`) |
| `:kit` (real) | `KeystoreDeviceSecretEnclaveTest` instrumented: store→release round-trip (secret bytes match) with an auto-approving gate; `isEnrolled` blob-only; `clear` removes key+blob; corrupt-blob → `WrappedSecretCorrupt` | emulator (`:kit:connectedDebugAndroidTest`) |
| `:app` (real) | manual `adb emu finger touch 1` walking-skeleton: enroll → kill → biometric unlock → `BrowseWithSyncScreen` reached | emulator (manual) |

TDD discipline: the `DeviceUnlockViewModel` is written test-first (it's pure). The Keystore
enclave is written against its instrumented round-trip. The on-device proof is the
acceptance gate, not an automated CI test (mirrors iOS #202).

## 7. Open items for the implementation plan

- **Lockout error case**: confirm whether the slice-1 `DeviceUnlockError` taxonomy already
  has a usable lockout/unavailable case; if not, add one (`vault-access`, pure) and thread
  it through `BiometricPromptGate`'s mapping. (`WrongDeviceSecretOrCorrupt` /
  `DeviceSlotNotFound` / `DeviceUuidMismatch` are the `VaultBrowseError` arms; the
  enclave-side taxonomy is `DeviceUnlockError` — `UserCancelled`, `NotEnrolled`,
  `VaultSlotMismatch`, `WrappedSecretCorrupt`, `enclave(...)`.)
- **Enroll-time prompt**: validate the single-auth-required-key enroll UX on-device (one
  biometric confirmation at enroll). Fall back to the two-key wrap (§3.2.1) only if
  unacceptable. The `release` gate + ViewModel are unchanged either way.
- **`device_uuid` provenance**: enroll persists the uuid returned by `addDeviceSlot`; the
  metadata store round-trips it as 16 raw bytes (non-secret).
- **CodeQL**: the instrumented enclave test must randomize its dummy secret (`OsRng`/
  `SecureRandom`), never a literal byte array (repo convention).

## 8. Guardrails (verified empty at close)

```
git diff main...HEAD --name-only | grep -E 'core/|ffi/|crypto-design|vault-format'   # empty
git diff main...HEAD --name-only | grep -vE '^(android/|docs/)'                       # empty (no ios/)
```
