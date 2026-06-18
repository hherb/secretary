# C.3 Android — device-secret open path, slice 1: pure core + FFI adapter (design)

**Date:** 2026-06-19
**Slice:** C.3 Android — add a third unlock credential (a per-device wrap secret) so an
enrolled device can open the vault without the password or recovery phrase. **Slice 1
of 2**: the pure, host-tested orchestration + the real `:kit` FFI adapter, proven
end-to-end against the real `.so` with a **fake in-memory enclave**. The real
biometric Keystore/StrongBox enclave and the `UnlockScreen` toggle are **slice 2**.
**Status:** design approved; awaiting spec review → implementation plan.

## 1. Goal

The Android open paths so far are password and (as of #260) recovery phrase. The Rust
core also exposes a **per-device wrap slot** (ADR 0009): `add_device_slot` mints a
random 32-byte device secret, wraps the Identity Block Key (IBK) under
`device_kek = HKDF-SHA-256(device_secret)`, and writes `devices/<uuid>.wrap`
(`file_kind 0x0004`); `open_with_device_secret` opens the vault with that secret instead
of the password. iOS already consumes this as its B.3 Secure-Enclave/biometric stack
(#201/#202). This direction brings the same capability to Android.

This **first slice** delivers the platform-neutral half — the analogue of iOS's pure,
FFI-free `SecretaryDeviceUnlock` package plus its real `UniffiVaultDeviceSlotPort` —
fully host-tested and proven against the real Rust core, with an **in-memory enclave**
standing in for biometric hardware (exactly how iOS's `DeviceUnlockIntegrationTests`
runs). It deliberately stops short of the real Android Keystore/StrongBox enclave,
`BiometricPrompt`, and the unlock-screen UI, which are slice 2.

**Acceptance (slice 1):** with a fake in-memory enclave, enrol a device slot against
`golden_vault_001` on-device (real `.so`), then `unlock` → open via the resulting
`UnlockCredential.DeviceSecret` and assert the opened `vaultUuidHex` matches golden,
then `disenroll` and assert a subsequent open fails `DeviceSlotNotFound` and
`coordinator.unlock` throws `NotEnrolled`. All pure orchestration is host-tested with
fakes. `core` / `ffi` / `ios` / on-disk-format / UDL all untouched.

## 2. Scope and non-goals

**In scope (Android-only, slice 1):**
- `UnlockCredential.DeviceSecret(deviceUuid, secret)` arm + the exhaustive `when` in
  `openWithCredential` routing it to `VaultOpenPort.openWithDeviceSecret`.
- `VaultOpenPort.openWithDeviceSecret` seam + the `:kit` `UniffiVaultOpenPort`
  implementation over the already-generated `openWithDeviceSecret` binding.
- A new `VaultDeviceSlotPort` (slot management: `addDeviceSlot` / `removeDeviceSlot`)
  + the `:kit` `UniffiVaultDeviceSlotPort` over the generated `addDeviceSlot` /
  `removeDeviceSlot` bindings.
- The pure `DeviceUnlockCoordinator` + its ports (`DeviceSecretEnclave`,
  `DeviceEnrollmentMetadataStore`) + `DeviceUnlockError`, all in `:vault-access`.
- `VaultBrowseError` gains `WrongDeviceSecretOrCorrupt`, `DeviceSlotNotFound`,
  `DeviceUuidMismatch(detail)`.
- In-memory test fakes + host tests + one instrumented round-trip test against the
  real `.so`.

**Out of scope (deferred to slice 2):**
- The **real Android Keystore/StrongBox `DeviceSecretEnclave`** behind `BiometricPrompt`
  (the Android analogue of iOS's non-exportable Secure-Enclave P-256 + biometric
  `SecAccessControl`).
- The `UnlockScreen` toggle / button for biometric unlock and the `AppRoot` wiring.
- The `dispatchPostOpenSync` `DeviceSecret` arm (status-refresh-only, like recovery —
  see §4).
- On-device/emulator **biometric** proof (`adb emu finger`).

**Out of scope (entirely):**
- Any `core` / `ffi` / `ios` / on-disk-format / UDL change. `add_device_slot`,
  `open_with_device_secret`, and `remove_device_slot` are already in the Rust UDL and
  generated into the Android Kotlin bindings at build time (`android/kit` regenerates
  bindings from the live cdylib — they are never committed), so **no FFI work is
  required**.

## 3. Background: the FFI surface (already present)

Rust UDL (`ffi/secretary-ffi-uniffi/src/secretary.udl`), generated into Kotlin at build
time:

```
[Throws=VaultError]
DeviceEnrollOutput add_device_slot(bytes folder_path, bytes password);

[Throws=VaultError]
OpenVaultOutput open_with_device_secret(bytes folder_path, bytes device_uuid, bytes device_secret);

[Throws=VaultError]
void remove_device_slot(bytes folder_path, bytes device_uuid);

interface DeviceSecretOutput { sequence<u8>? take_secret(); void wipe(); };
dictionary DeviceEnrollOutput { bytes device_uuid; DeviceSecretOutput device_secret; };
```

Contract (from `ffi/secretary-ffi-bridge/src/device.rs` and the uniffi wrapper):
- `add_device_slot` password-opens the vault (validates the password **before** writing
  any slot), mints a fresh 16-byte `device_uuid` and a fresh **raw 32-byte CSPRNG**
  `device_secret` (not password-derived — 256 bits of entropy, no Argon2id), wraps the
  IBK, and writes `devices/<uuid>.wrap` atomically. Returns the uuid + a **one-shot**
  `DeviceSecretOutput` handle (`take_secret()` yields the 32 bytes once; then `wipe()`).
- `open_with_device_secret` reads `devices/<uuid>.wrap`, derives `device_kek`,
  AEAD-decrypts the IBK, and proceeds through the **same manifest verify-before-decrypt**
  as the password/recovery paths (it is never a weaker open). `device_uuid` must be 16
  bytes and `device_secret` 32 bytes; the uniffi wrapper validates lengths and returns
  `InvalidArgument` otherwise (and zeroizes the secret on the reject path).
- `remove_device_slot` deletes `devices/<uuid>.wrap` (revocation).

Error arms relevant here (`VaultError` → Kotlin `VaultException`):
- `WrongDeviceSecretOrCorrupt` — secret failed verification OR wrap-file/vault
  corruption (**conflated by design**, anti-oracle per threat-model §13; a payload-free
  condition).
- `DeviceSlotNotFound` — no `devices/<uuid>.wrap` (benign "no such device").
- `DeviceUuidMismatch { detail }` — wrap-file header `device_uuid` ≠ lookup uuid
  (§3a relabel-integrity check).
- `InvalidArgument { detail }` — wrong-length uuid/secret (validated at the binding
  layer; the Android port passes correctly-sized arrays so this is a guard, not an
  expected path).

The exact uniffi Kotlin variant names (`VaultException.WrongDeviceSecretOrCorrupt`,
`VaultException.DeviceSlotNotFound`, `VaultException.DeviceUuidMismatch` with `.detail`)
are taken from the Rust `FfiVaultError` and must be re-verified against the generated
bindings at first build (a one-line fix if codegen renamed any — see the
uniffi-codegen-rename memo).

## 4. Why device-secret sessions sync like recovery, not password (slice 2 note)

Recorded here so slice 2 does not "fix" it: the Android sync surface is **password-keyed**
(`sync_vault` / `sync_commit_decisions` re-open the vault and run Argon2id, requiring the
password). A device-secret open has **no password**, exactly like a recovery open.
Therefore — when slice 2 wires the UI — a device-secret session reaches
`BrowseWithSyncScreen` and runs `sync.refreshStatus()` only (status badge, no auto-sync
pass); manual sync re-prompts for the password via the existing badge sheet. This
mirrors iOS's optional-password `onUnlocked` and the recovery slice. **Slice 1 does no
app wiring**, so this is forward context only.

## 5. Architecture

iOS lumped all three device FFI calls into one `VaultDeviceSlotPort` because iOS has no
separate credential-open abstraction. Android **does** — `VaultOpenPort` already owns
`openWithPassword` / `openWithRecovery`. So the device FFI is split by responsibility:

- **`openWithDeviceSecret`** joins `VaultOpenPort` (it is a credential open, parallel to
  password/recovery), and the coordinator's `unlock` returns an
  `UnlockCredential.DeviceSecret` that flows through the **existing** `openWithCredential`
  pipeline — honoring the sealed-credential design intent and reusing the established
  zeroize-in-`finally` + `dispatchPostOpenSync` machinery (so slice 2's wiring is
  trivial).
- **`addDeviceSlot` / `removeDeviceSlot`** form a new `VaultDeviceSlotPort` (slot
  *management*), used by the coordinator.

```
:vault-access (pure, host-tested)
  UnlockCredential.kt        + DeviceSecret(deviceUuid: ByteArray /*16*/, override val secret: ByteArray /*32*/)
                             + openWithCredential `when` arm -> openPort.openWithDeviceSecret(folder, uuid, secret)
  VaultOpenPort.kt           + suspend fun openWithDeviceSecret(vaultFolder: String, deviceUuid: ByteArray, deviceSecret: ByteArray): VaultSession
  VaultBrowseError.kt        + WrongDeviceSecretOrCorrupt (object) + DeviceSlotNotFound (object) + DeviceUuidMismatch(detail)
  VaultDeviceSlotPort.kt     interface { suspend addDeviceSlot(folder, password): EnrolledSlot; suspend removeDeviceSlot(folder, deviceUuid) }
                             EnrolledSlot(deviceUuid: ByteArray, secret: ByteArray)
  DeviceSecretEnclave.kt     interface { val isEnrolled: Boolean; suspend store(secret); suspend release(reason): ByteArray; suspend clear() }
  DeviceEnrollmentStore.kt   interface DeviceEnrollmentMetadataStore { load(): DeviceEnrollment?; save(e); clear() }
                             DeviceEnrollment(vaultId: String, deviceUuid: ByteArray)
  DeviceUnlockCoordinator.kt enroll / unlock / disenroll / isEnrolled  (pure orchestration)
  DeviceUnlockError.kt       sealed: NotEnrolled, VaultSlotMismatch, BiometryUnavailable,
                             BiometryNotEnrolled, BiometryLockout, UserCancelled,
                             AuthenticationFailed, WrappedSecretCorrupt, Enclave(detail)

:kit (FFI adapter, real .so)
  UniffiVaultOpenPort.kt     + openWithDeviceSecret over generated openWithDeviceSecret (IO dispatcher, injectable deviceSecretFn seam)
  UniffiVaultDeviceSlotPort.kt  addDeviceSlot/removeDeviceSlot over generated addDeviceSlot/removeDeviceSlot;
                             take_secret() once then wipe(); mapErrors
  BrowseMapping.kt           mapVaultBrowseError gains three arms before `else`
```

### 5.1 The credential arm (parallels the recovery slice)

```kotlin
// UnlockCredential.kt — DeviceSecret carries BOTH the uuid (to locate the wrap file)
// and the 32-byte secret. secret stays the `override val` so the shared zeroize works.
class DeviceSecret(
    val deviceUuid: ByteArray,
    override val secret: ByteArray,
) : UnlockCredential

// openWithCredential `when` (exhaustive, no `else`):
is UnlockCredential.DeviceSecret ->
    openPort.openWithDeviceSecret(vaultFolder, credential.deviceUuid, credential.secret)
```

The exhaustive `when` (no `else`) means a future fourth credential becomes a compile
error, not a silent drop — the property the recovery slice established.

### 5.2 The slot-management port + coordinator

`VaultDeviceSlotPort` is the FFI seam for minting/removing slots; the coordinator owns
the transactional enrol/disenroll logic and the biometric-release-to-credential unlock.
It mirrors iOS's `DeviceUnlockCoordinator` exactly, except `unlock` returns a credential
instead of opening directly:

```kotlin
class DeviceUnlockCoordinator(
    private val slotPort: VaultDeviceSlotPort,
    private val enclave: DeviceSecretEnclave,
    private val metadata: DeviceEnrollmentMetadataStore,
) {
    val isEnrolled: Boolean get() = enclave.isEnrolled && metadata.load() != null

    // addDeviceSlot -> enclave.store -> metadata.save; transactional rollback; zeroize in finally.
    suspend fun enroll(folder: String, vaultId: String, password: ByteArray)

    // load metadata (else NotEnrolled) -> vaultId match (else VaultSlotMismatch)
    //   -> enclave.release(reason) -> UnlockCredential.DeviceSecret(uuid, secret).
    // The CALLER opens via openWithCredential and zeroizes the credential in finally.
    suspend fun unlock(folder: String, vaultId: String, reason: String): UnlockCredential.DeviceSecret

    // idempotent: removeDeviceSlot (tolerate DeviceSlotNotFound) + enclave.clear + metadata.clear.
    suspend fun disenroll(folder: String)
}
```

**Enroll transaction (matches iOS rollback semantics):**
1. `slot = slotPort.addDeviceSlot(folder, password)` — writes `devices/<uuid>.wrap`.
2. `enclave.store(slot.secret)` — on failure: `slotPort.removeDeviceSlot(...)` (roll back
   the wrap file), rethrow.
3. `metadata.save(DeviceEnrollment(vaultId, slot.deviceUuid))` — on failure:
   `enclave.clear()` + `slotPort.removeDeviceSlot(...)` (roll back both), rethrow the
   **original** save error.
4. `finally`: zeroize `slot.secret`. **Invariant:** no orphan (wrap file / enclave entry
   / metadata) survives any failure.

**Unlock:** guards first (so a wrong-vault or not-enrolled state never triggers a
biometric prompt in slice 2), then `enclave.release(reason)` yields the 32 bytes, wrapped
into `DeviceSecret(uuid, secret)`. The secret's ownership passes to the credential; the
caller's `finally` zeroizes it (the same discipline password/recovery already use). The
coordinator does **not** open and therefore does not surface open-time errors —
`WrongDeviceSecretOrCorrupt` / `DeviceSlotNotFound` surface as `VaultBrowseError` from
`openWithCredential`, consistent with the password/recovery paths.

**Disenroll** is idempotent and tolerant: a `DeviceSlotNotFound` from `removeDeviceSlot`
is swallowed (already gone is success); `enclave.clear()` and `metadata.clear()` are
best-effort. No orphan survives.

### 5.3 Error mapping

`mapVaultBrowseError` gains three explicit arms **before** the `else` (per the file's
maintainer warning that the `else` silently swallows new arms):

```kotlin
is VaultException.WrongDeviceSecretOrCorrupt -> VaultBrowseError.WrongDeviceSecretOrCorrupt
is VaultException.DeviceSlotNotFound         -> VaultBrowseError.DeviceSlotNotFound
is VaultException.DeviceUuidMismatch         -> VaultBrowseError.DeviceUuidMismatch(e.detail)
```

`WrongDeviceSecretOrCorrupt` stays conflated (anti-oracle §13) — a payload-free
`data object`; do NOT split it. `DeviceUuidMismatch(detail)` is a structural integrity
signal (a relabelled wrap file) safe to surface. (`InvalidArgument` already maps via the
existing arm; the Android port always passes correctly-sized arrays.)

Per [[project_secretary_ffivaulterror_workspace_match]]: adding `VaultBrowseError`
variants is purely an **Android `:vault-access`** concern (a Kotlin sealed class
internal to Android) — it does **not** touch the Rust `FfiVaultError` and therefore does
**not** trigger the workspace-wide / Swift+Kotlin-conformance match obligation. The Rust
`FfiVaultError` device variants already exist (B.2). No conformance harness change.

## 6. Secret hygiene

- The 32-byte device secret is **raw CSPRNG** minted by the core, never password-derived,
  and **never persisted inside the vault** — the enclave (slice 2) is its sole persistent
  store; slice 1's fake holds it in memory only.
- `add_device_slot` returns the secret via a **one-shot** `DeviceSecretOutput`: the `:kit`
  adapter calls `take_secret()` once into a Kotlin `ByteArray`, then `wipe()` on the
  handle in a `finally` (mirrors iOS's `defer { out.deviceSecret.wipe() }`), so the bridge
  side retains nothing.
- The coordinator zeroizes its `EnrolledSlot.secret` copy in `enroll`'s `finally` (after
  `enclave.store` has consumed it). In `unlock`, ownership of the released secret passes
  to the returned `UnlockCredential.DeviceSecret`; the existing `unlockAndOpen`
  `finally` zeroizes `credential.secret` (slice 2). The open awaits before any zeroize,
  so it cannot race the AEAD that consumes the bytes.
- `device_uuid` is **non-secret** (suitable for logging / metadata storage).

## 7. Testing (TDD, written test-first per task)

**Host (`:vault-access`, `:kit` JVM-pure parts):**
- `openWithCredential` device dispatch via a fake `VaultOpenPort`: `DeviceSecret` invokes
  `openWithDeviceSecret` with the uuid + secret (not password/recovery).
- `mapVaultBrowseError`: the three new arms map as specified.
- `DeviceUnlockCoordinator` with all-fake ports
  (`FakeVaultDeviceSlotPort` / `FakeDeviceSecretEnclave` / `FakeEnrollmentMetadataStore`):
  - enroll happy path → slot minted, secret stored, metadata saved, secret zeroized;
  - enroll rollback when `enclave.store` throws → slot removed, metadata not saved;
  - enroll rollback when `metadata.save` throws → enclave cleared + slot removed, original
    error rethrown;
  - unlock guards → `NotEnrolled` (no metadata) and `VaultSlotMismatch` (wrong vaultId)
    **before** any `enclave.release`;
  - unlock happy path → returns `DeviceSecret(uuid, secret)` with the released bytes;
  - disenroll idempotency → tolerates `DeviceSlotNotFound`, clears enclave + metadata;
  - `isEnrolled` requires **both** enclave-enrolled and metadata-present.
- The fakes support error injection (per-call throw) to drive the rollback branches.

**Instrumented (emulator / on-device, real `.so`, FAKE in-memory enclave + metadata):**
- One round-trip test mirroring iOS's `DeviceUnlockIntegrationTests`:
  1. `coordinator.enroll(folder, "golden", goldenPassword)` → real `addDeviceSlot` writes
     `devices/<uuid>.wrap`.
  2. `coordinator.unlock(folder, "golden", reason)` → fake enclave releases the secret →
     `DeviceSecret` credential.
  3. `openWithCredential(realOpenPort, folder, credential)` → real `openWithDeviceSecret`
     → assert `session.vaultUuidHex()` == golden uuid.
  4. `coordinator.disenroll(folder)` → real `removeDeviceSlot` deletes the wrap file.
  5. Assert reopen via the captured uuid now fails `DeviceSlotNotFound`, and
     `coordinator.unlock` now throws `NotEnrolled`.
- The golden password is the published KAT input `password` in
  `core/tests/data/golden_vault_001_inputs.json` (a KAT, not a real secret — same status
  as the recovery phrase the existing smoke uses). `AppVaultProvisioning` gains a
  `goldenPassword(context)` reader mirroring `goldenRecoveryPhrase`, failing loudly if
  absent. (Confirm the JSON key name at implementation time.)

## 8. Guardrails (verified empty at close)

```
git diff main...HEAD --name-only | grep -E 'core/|ffi/|crypto-design|vault-format'                   # empty
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)' # empty (no ios/)
```

## 9. File-size discipline

One concept per file (per the split-files preference): `UnlockCredential.kt` gains one
arm; `VaultOpenPort.kt` one method; `VaultBrowseError.kt` three variants; and each new
type — `VaultDeviceSlotPort`, `DeviceSecretEnclave`, `DeviceEnrollmentMetadataStore`,
`DeviceUnlockCoordinator`, `DeviceUnlockError` — is its own small file. The `:kit`
`UniffiVaultDeviceSlotPort` is its own file; `UniffiVaultOpenPort` gains one method. All
stay well under 500 lines. No refactor pressure introduced.

## 10. Risks / open items

- **Coordinator returns a credential, not a session** — a deliberate divergence from iOS
  (whose coordinator opens directly). The tradeoff: open-time errors surface as
  `VaultBrowseError` from the shared pipeline rather than as `DeviceUnlockError` from the
  coordinator. This is consistent with how password/recovery open errors already surface
  on Android, and keeps the coordinator's responsibility to the secret lifecycle. Settled
  this slice; do not "unify" it back without revisiting the credential-pipeline reuse.
- **`DeviceSecretEnclave.release` is `suspend`** even though slice 1's fake returns
  immediately — required so slice 2's real `BiometricPrompt` (callback → cancellable
  coroutine) bridges in without an interface change.
- **The golden-vault inputs JSON key for the password** must be confirmed at
  implementation time (`password` vs another name); the plan includes a locate-or-fail
  step.
- **Generated uniffi Kotlin variant names** for the three device errors must be verified
  against the build output at first compile (see the uniffi-codegen-rename memo).
- **No host test of the real `:kit` adapters** (`UniffiVaultDeviceSlotPort`,
  `openWithDeviceSecret`) — they depend on the FFI, so they are covered by the
  instrumented round-trip. The genuinely pure logic (coordinator, dispatch, mapping) is
  fully host-tested.
