# Cloud-vault device enrollment + biometric write-reauth (Android)

**Date:** 2026-06-29
**Status:** Approved (brainstorm complete; ready for implementation plan)
**Scope:** Android only. No core `src/`, no on-disk-format / spec / `conformance.py` / conflict-KAT / observable-byte / FFI-surface change. Conformance must stay 27/27 (Kotlin + Swift).

## Problem

Android's cloud-drive vault path (epic #321, complete) opens and writes to a cloud vault through a SAF working-copy shim, but every write is authorized by `NoopReauthGate` — there is **no biometric write-reauth over a cloud vault**, and **no way to enrol a device secret against a cloud vault**. The local/demo vault already has the full machinery (`GraceWindowReauthGate`, `DeviceUnlockCoordinator`, `KeystoreDeviceSecretEnclave`, `UniffiVaultDeviceSlotPort`, `FileDeviceEnrollmentMetadataStore`); the cloud path simply hardcodes the no-op gate ([`CloudVaultOpen.kt:110-121`](../../../android/app/src/main/kotlin/org/secretary/app/CloudVaultOpen.kt)) and hides the enroll UI.

This is the baton's next-step #1 for the Android cloud-drive epic and brings the cloud path to write-reauth parity with iOS.

## Decisions (from brainstorm)

1. **Full scope incl. on-device proof** — code + host tests + instrumented tests (auto-approving gate) + a real on-device biometric verification on the RedMagic 11 Pro.
2. **Per-vault keyed multi-enrollment** — both the metadata store and the Keystore enclave are namespaced by vault identity (`cloudVaultKey(treeUri)`). A device can be enrolled simultaneously against the demo vault and one or more cloud vaults, each with its own SE-wrapped secret.
3. **Mirror-demo opt-in** — a "Remember this device" checkbox on the cloud unlock screen; enrol after a successful password open. Non-fatal on failure.
4. **Write-reauth only** — cloud open stays password-based this session; biometric *open* of a cloud vault is a clean follow-up. Enrollment exists so the gate can prove biometric presence on **writes**.

## Approach (A — per-vault DeviceUnlock factory)

The pure layer is unchanged. The work is **keying + wiring**, concentrated in `:app`, reusing the already-parameterized `:kit` stores. Demo path stays byte-identical (zero migration).

### Module layout

| Module | Change |
|---|---|
| `:vault-access` | **Unchanged.** `DeviceUnlockCoordinator`, `WriteReauthGate`, `GraceWindowReauthGate`, `CoordinatorBiometricAuthorizer`, the three port interfaces already exist. |
| `:kit` | **No new types.** Reuse `KeystoreDeviceSecretEnclave(dir, gate, keyAlias)` and `FileDeviceEnrollmentMetadataStore(dir)` with per-key dirs/aliases. |
| `:app` | **New `CloudDeviceUnlock.kt`** — factory + pure route helper. **New `CloudDeviceEnroll.kt`** — enroll-with-flush orchestration (keeps `CloudVaultOpen.kt`/`AppRoot.kt` under 500 lines). `CloudVaultOpen.kt` — `openCloudBrowse` gains the device coordinator + `enrollThisDevice` flag, replaces the hardcoded `NoopReauthGate`. `AppRoot.kt` — un-hide "Remember this device" on the cloud unlock screen, thread the checkbox. |

### Keying scheme

- **Cloud enrollment:** `noBackupFilesDir/devicesecret/cloud/<cloudVaultKey>/` (enclave blob + metadata file) with `keyAlias = "secretary.devicesecret.cloud.<cloudVaultKey>"`.
- **Demo (unchanged):** `noBackupFilesDir/devicesecret/` + `DEFAULT_ALIAS`. Zero migration; demo behaviour byte-identical.
- `cloudVaultKey(treeUri)` is the existing stable-hash primitive already used for the working dir and pending-flush marker.

## Components

### `cloudDeviceUnlockCoordinator(context, cloudKey): DeviceUnlockCoordinator`
Builds a `DeviceUnlockCoordinator` over:
- `KeystoreDeviceSecretEnclave(dir = devicesecret/cloud/<cloudKey>, gate = biometricPromptGate(activity), keyAlias = "secretary.devicesecret.cloud.<cloudKey>")`
- `FileDeviceEnrollmentMetadataStore(dir = devicesecret/cloud/<cloudKey>)`
- `UniffiVaultDeviceSlotPort()`

### `cloudReauthRoute(enclaveEnrolled, openVaultId, metadataVaultId): GateChoice` (pure, host-tested)
Decides gate vs no-op from enrollment state. The caller performs the I/O (`enclave.isEnrolled`, `metadata.load()?.vaultId`) and passes the resulting values in, so the decision itself is a pure function with no Keystore/file access:

| `enclaveEnrolled` | `metadataVaultId == openVaultId` | result (`GateChoice`) |
|---|---|---|
| false | — | `NoopReauthGate` |
| true | false / null (stale enrollment for a changed vault) | `NoopReauthGate` |
| true | true | `GraceWindowReauthGate` |

The mismatch guard protects against a treeUri whose underlying vault changed since enrollment.

## Data flow

### Enrollment (opt-in, `CloudDeviceEnroll.kt`)
Triggered after a **successful password open** when "Remember this device" is checked:

1. `coordinator.enroll(workingDir, vaultId, password)` — mints `devices/<uuid>.wrap` into the **working copy**, stores the 32-byte secret in the keyed Keystore enclave (one biometric enroll prompt), saves keyed metadata. (Coordinator already rolls back enclave/slot on its internal failures.)
2. **Flush working→cloud** via the working-copy `coordinator.afterCommit()`, so the new wrap file reaches the cloud and survives the next materialize.
3. **Atomic enroll:** if the flush throws, roll back the whole enrollment — `deviceCoordinator.disenroll(workingDir)` (removes slot, clears enclave + metadata) — and surface a typed non-fatal failure. A half-state (Keystore secret present, cloud slot absent) would be silently wrong after the next materialize, so enrollment is all-or-nothing **including** the cloud round-trip. This is the one deliberate deviation from the #327 "set marker, retry later" pattern, justified because a partially-enrolled device is worse than an un-enrolled one.
4. Non-fatal throughout (mirrors demo): biometric-not-enrolled / flush failure → toast; the open still succeeds with `NoopReauthGate`.

`vaultId` = the learned cloud vault UUID hex (same id used for metadata match on later opens).

### Open + gate wiring (`openCloudBrowse`, replacing lines 110-121)
```
deviceCoord = cloudDeviceUnlockCoordinator(context, cloudVaultKey(location.treeUri))
choice = cloudReauthRoute(deviceCoord.enclaveEnrolled, vaultId, deviceCoord.metadataVaultId)
gate = when (choice)
           GraceWindowReauthGate -> GraceWindowReauthGate(
                                        CoordinatorBiometricAuthorizer(deviceCoord, vaultId),
                                        clock = { SystemClock.elapsedRealtime() })
           NoopReauthGate        -> NoopReauthGate
openBrowseWithSync(..., gate = gate, onCommit = { coordinator.afterCommit() })
gate.seed(SystemClock.elapsedRealtime())   // first write after open is silent, 30s window
```
Every write (`guardedWrite` in `VaultBrowseModel`, `authorizeWrite` in `RecordEditModel`) already routes through the gate — **no write-site changes**. 30s monotonic grace window (`elapsedRealtime`, never wall-clock) reused as-is.

## Error handling & edge cases

- **Manifest-less / wrong-clock:** untouched — gate uses monotonic `elapsedRealtime`; #327 flush/marker discipline reused verbatim for the enroll flush.
- **Materialize overwrites the slot:** the enroll flush (step 2) pushes the wrap file *before* any later materialize; the existing materialize guard prevents an empty cloud from clobbering.
- **Disenroll:** cloud disenroll removes the slot from the working copy, flushes the removal to cloud, then clears keyed enclave + metadata.
- **Per-vault isolation:** two cloud vaults → two key dirs → two Keystore aliases → independent secrets, no cross-talk (instrumented-proven).
- **Not enrolled:** identical behaviour to today (`NoopReauthGate`).

## Testing strategy

- **Host (`:vault-access`/`:app`/`:kit` JVM):**
  - `cloudReauthRoute` decision table (enrolled+match → gate; enrolled+mismatch → noop; unenrolled → noop).
  - cloud enroll-with-flush orchestration with fake slot/enclave/metadata/mirror, incl. **flush-failure-rolls-back-fully**.
  - `FileDeviceEnrollmentMetadataStore` per-key isolation.
- **Instrumented (`:kit`/`:app`, emulator authoritative + RedMagic for `:kit`):**
  - keyed `KeystoreDeviceSecretEnclave` two-key isolation (no blob cross-talk).
  - cloud enroll round-trip over **real SAF** (mint → flush → fresh materialize pulls the wrap back).
  - write-reauth over a cloud vault with an auto-approving `BiometricGate` (write inside window silent; past window re-prompts).
- **On-device (manual, user taps):** real biometric prompt on a cloud-vault write past the 30s window on the RedMagic 11 Pro — the full-scope acceptance.
- **Unchanged gates:** Rust fmt + clippy clean (no core/FFI change); Kotlin + Swift conformance stay 27/27.

## Acceptance criteria

1. A device can be enrolled against a cloud working copy via the "Remember this device" checkbox; the `devices/<uuid>.wrap` slot round-trips through real SAF (instrumented-proven).
2. With an enrolled device, a cloud-vault write past the 30s grace window prompts for a real biometric on-device; a write within the window is silent.
3. Enrollment is atomic: a failed cloud flush rolls the enrollment back fully (no orphan Keystore secret).
4. Per-vault isolation: demo + cloud (and two cloud vaults) hold independent secrets with no cross-talk.
5. Demo path unchanged; host gate green; instrumented green on emulator (+ `:kit` on RedMagic); conformance 27/27 both.

## Out of scope (follow-ups)

- Biometric **open** of a cloud vault (open stays password-based).
- A settings-screen enroll/disenroll toggle for cloud vaults (this session is opt-in-at-open only; demo's existing settings flow is untouched).
- Wiring `createdButNotSynced` into a user-facing banner (#329).
