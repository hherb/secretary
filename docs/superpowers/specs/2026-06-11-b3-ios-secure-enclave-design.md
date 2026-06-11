# B.3 — iOS Secure Enclave / biometric release of the device secret

**Date:** 2026-06-11
**Issue:** #202
**Depends on:** B.1 (per-device wrap-slot core), B.2 (FFI projection, #201/#212), D.3 slice 1 (iOS XCFramework, #200)
**ADRs:** 0008 (native mobile via uniffi), 0009 (per-device wrap slot)

## 1. Purpose & scope

Protect the per-device `device_secret` with the iOS Secure Enclave behind a biometric
gate, and drive vault unlock through it. The B.2 FFI already provides everything on the
Rust side; B.3 is the Swift/SecretaryKit layer that:

- at **enroll**: password-opens the vault, mints a device slot, wraps the returned
  32-byte `device_secret` with a non-exportable Secure Enclave P-256 key, and persists
  the ciphertext;
- at **unlock**: passes a biometric gate, has the Secure Enclave release the
  `device_secret`, and feeds it back to `open_with_device_secret` to open the vault;
- at **disenroll**: removes the vault slot and clears the enclave key + metadata.

### Scoped IN (this slice)

- The pure orchestration layer (a coordinator over three injected ports) with full,
  host-runnable unit coverage against in-memory fakes.
- A **real, compiling** Secure Enclave conformer (`SecKey` + `LAContext` + ECIES) — its
  device/biometric behaviour is *not* asserted here (see §7).
- A real uniffi adapter over the three B.2 device-slot functions.
- A real Keychain-backed metadata store for the non-secret `device_uuid`.
- One simulator integration test proving the orchestration drives the **real** B.2 FFI
  end-to-end (real uniffi port + fake enclave + a staged copy of `golden_vault_001`).

### Scoped OUT (deferred follow-ups under #202 / the app track)

- Real on-device Face ID / Touch ID verification of `SecureEnclaveDeviceSecretStore`
  (manual/device proof — un-automatable in CI here).
- The SwiftUI walking-skeleton host app.
- Multi-vault enrollment registry (single vault-keyed enrollment only — §4).
- Any change to the frozen on-disk format or the B.2 FFI surface (none required).

## 2. Background: the B.2 contract this consumes

From `ffi/secretary-ffi-uniffi` (uniffi-generated Swift), already cross-language tested:

```swift
func addDeviceSlot(folderPath: Data, password: Data) throws -> DeviceEnrollOutput
//   DeviceEnrollOutput { deviceUuid: Data /*16B*/, deviceSecret: DeviceSecretOutput }
//   DeviceSecretOutput.takeSecret() -> [UInt8]?   // one-shot; nil on 2nd call
//   DeviceSecretOutput.wipe()                     // idempotent zeroize
func openWithDeviceSecret(folderPath: Data, deviceUuid: Data, deviceSecret: Data) throws -> OpenVaultOutput
func removeDeviceSlot(folderPath: Data, deviceUuid: Data) throws
```

Facts the design relies on (verified against the core/spec):

- `device_secret` is **32 bytes** of OS-CSPRNG entropy, minted by the core at enroll,
  **never stored in the vault**. It is the only secret B.3 must protect.
- `device_uuid` is **16 bytes**, non-secret (it is the `devices/<uuid>.wrap` filename).
- The device open path goes through the **same** manifest verify-before-decrypt
  (Ed25519 ∧ ML-DSA-65) as the password/recovery paths — B.3 inherits that; it is not a
  weaker open.
- Anti-rollback (`local_highest_clock`) is `None` on the device path, at parity with the
  password path (carried from B.2; out of B.3 scope).
- Wrong-length `device_uuid`/`device_secret` are rejected at the binding layer as
  `VaultError.InvalidArgument`; the device errors are `DeviceSlotNotFound`,
  `WrongDeviceSecretOrCorrupt`, `DeviceUuidMismatch`.

The issue (#202) **mandates a non-exportable Secure Enclave P-256 key that wraps the
`device_secret`** — i.e. the SE private key is the gate and never leaves the enclave —
not merely a biometric-ACL Keychain item.

## 3. Module structure

The pure orchestration logic is split into its **own FFI-free Swift package** so it runs
under plain host `swift test` in milliseconds. This split is forced: `SecretaryKit`
depends on `Secretary.xcframework`, an **iOS-only** binary target, so any test target in
that dependency graph can only run on the simulator via `xcodebuild`. Keeping the logic
FFI-free is what buys the fast host loop (and matches "push I/O to the edges").

```
ios/
  SecretaryDeviceUnlock/                    # NEW pure SPM package, zero iOS-binary deps
    Package.swift
    Sources/SecretaryDeviceUnlock/          # protocols + coordinator + error type
      OpenedVault.swift
      VaultDeviceSlotPort.swift
      DeviceSecretEnclave.swift
      DeviceEnrollmentMetadataStore.swift
      DeviceEnrollment.swift
      DeviceUnlockError.swift
      DeviceUnlockCoordinator.swift
      Zeroizing.swift                        # withZeroizing helper
    Sources/SecretaryDeviceUnlockTesting/    # the fakes, as a reusable library product
      InMemoryDeviceSecretEnclave.swift
      FakeVaultDeviceSlotPort.swift
      InMemoryEnrollmentMetadataStore.swift
      FakeOpenedVault.swift
    Tests/SecretaryDeviceUnlockTests/        # host `swift test` — orchestration + every branch
      DeviceUnlockCoordinatorTests.swift
      ZeroizingTests.swift

  SecretaryKit/                             # EXISTING package; adds .package(path: "../SecretaryDeviceUnlock")
    Sources/SecretaryKit/DeviceUnlock/       # the platform adapters (import the XCFramework + Security + LocalAuthentication)
      UniffiVaultDeviceSlotPort.swift
      SecureEnclaveDeviceSecretStore.swift   # the real SE conformer (compiles; device-verification deferred)
      KeychainEnrollmentMetadataStore.swift
    Tests/SecretaryKitTests/
      DeviceUnlockIntegrationTests.swift      # ONE simulator test: real uniffi port + fake enclave + golden-vault copy
```

Each file is one concept and well under the 500-line guideline. The pure package names
no uniffi type — the `OpenedVault` protocol abstracts `OpenVaultOutput`.

## 4. Protocols & types (pure package)

**`OpenedVault`** — boundary type so the coordinator never names `OpenVaultOutput`:

```swift
public protocol OpenedVault {
    var vaultUuid: [UInt8] { get }
}
```

**`VaultDeviceSlotPort`** — thin port over the three B.2 uniffi funcs:

```swift
public struct EnrolledSlot {
    public let deviceUuid: [UInt8]   // 16 bytes
    public let deviceSecret: [UInt8] // 32 bytes
}
public protocol VaultDeviceSlotPort {
    func addDeviceSlot(vaultPath: Data, password: [UInt8]) throws -> EnrolledSlot
    func openWithDeviceSecret(vaultPath: Data, deviceUuid: [UInt8], deviceSecret: [UInt8]) throws -> OpenedVault
    func removeDeviceSlot(vaultPath: Data, deviceUuid: [UInt8]) throws
}
```

The real adapter (`UniffiVaultDeviceSlotPort`) is the **only** place that touches the
one-shot `DeviceSecretOutput`: it `takeSecret()`s once, `wipe()`s the handle, hands the
32 bytes up inside an `EnrolledSlot`, and retains nothing.

**`DeviceSecretEnclave`** — the biometric-gated wrap/store (the SE abstraction):

```swift
public protocol DeviceSecretEnclave {
    var isEnrolled: Bool { get }
    func store(secret: [UInt8]) throws            // generate SE key if needed, wrap, persist blob; replaces existing
    func release(reason: String) async throws -> [UInt8]  // biometric gate, then decrypt; async (LAContext)
    func clear() throws                            // delete SE key + wrapped blob
}
```

**`DeviceEnrollmentMetadataStore`** — persists the *non-secret* `device_uuid` + a vault id:

```swift
public struct DeviceEnrollment: Equatable {
    public let vaultId: String      // caller-supplied opaque id for the vault
    public let deviceUuid: [UInt8]  // 16 bytes
}
public protocol DeviceEnrollmentMetadataStore {
    func load() throws -> DeviceEnrollment?
    func save(_ enrollment: DeviceEnrollment) throws
    func clear() throws
}
```

`vaultId` is an opaque token the app assigns to a vault; it lets unlock detect a stale
enrollment pointed at a different vault. **Single enrollment per device** (YAGNI — a
multi-vault registry is a later wrapper over the same primitives).

### Secret handling

Secret `[UInt8]` buffers are routed through a `withZeroizing { ... }` helper that
`memset_s`-overwrites the buffer on scope exit. Swift value-copy semantics make this
**best-effort** ("as far as the runtime allows", per the issue) — documented honestly,
not claimed as a hard guarantee.

## 5. Coordinator orchestration

```swift
public struct DeviceUnlockCoordinator {
    let slotPort: VaultDeviceSlotPort
    let enclave: DeviceSecretEnclave
    let metadata: DeviceEnrollmentMetadataStore

    public var isEnrolled: Bool { get }  // true iff enclave.isEnrolled AND metadata.load() != nil
    public func enroll(vaultPath: Data, vaultId: String, password: [UInt8]) throws
    public func unlock(vaultPath: Data, vaultId: String, reason: String) async throws -> OpenedVault
    public func disenroll(vaultPath: Data) throws
}
```

**enroll** — transactional, with compensating rollback so no orphan state survives a
mid-flow failure:

1. `slot = slotPort.addDeviceSlot(vaultPath, password)` → 16B uuid + 32B secret.
2. `enclave.store(slot.deviceSecret)`. **On throw:** `slotPort.removeDeviceSlot(slot.deviceUuid)`
   (no orphan wrap file holding a secret nobody can release); re-throw.
3. `metadata.save(DeviceEnrollment(vaultId, slot.deviceUuid))`. **On throw:**
   `enclave.clear()` + `slotPort.removeDeviceSlot(slot.deviceUuid)`; re-throw.
4. The secret is zeroized on every exit path.

**unlock**:

1. `enrollment = metadata.load()`; `nil` ⇒ `.notEnrolled`.
2. Guard `enrollment.vaultId == vaultId`, else `.vaultSlotMismatch`.
3. `secret = await enclave.release(reason)` — biometric gate; enclave errors map to typed cases.
4. `out = slotPort.openWithDeviceSecret(vaultPath, enrollment.deviceUuid, secret)`; zeroize secret; return `out`.
   A `WrongDeviceSecretOrCorrupt` / `DeviceSlotNotFound` here means enclave↔vault desync
   (e.g. the slot was revoked elsewhere) — surfaced honestly, never swallowed.

**disenroll** — idempotent-tolerant:

1. `enrollment = metadata.load()`; if present, `slotPort.removeDeviceSlot(uuid)` tolerating `DeviceSlotNotFound`.
2. `enclave.clear()` then `metadata.clear()` — always, so no orphaned SE key/blob survives.

## 6. Error taxonomy

`DeviceUnlockError` — every case reachable in tests via fake injection:

| Case | Trigger |
|---|---|
| `.biometryUnavailable` | no biometric hardware / disabled (`LAError.biometryNotAvailable`) |
| `.biometryNotEnrolled` | no biometric enrolled (`LAError.biometryNotEnrolled`) |
| `.biometryLockout` | too many failed attempts (`LAError.biometryLockout`) |
| `.userCancelled` | prompt dismissed (`LAError.userCancel` / `.appCancel` / `.systemCancel`) |
| `.authenticationFailed` | biometric mismatch (`LAError.authenticationFailed`) |
| `.notEnrolled` | no enrollment on this device (metadata absent) |
| `.vaultSlotMismatch` | stored `vaultId` ≠ requested, or slot missing in vault (`DeviceSlotNotFound`) |
| `.wrappedSecretCorrupt` | SE/ECIES blob fails to decrypt/authenticate |
| `.wrongDeviceSecretOrCorrupt` | FFI `WrongDeviceSecretOrCorrupt` (enclave↔vault desync) |
| `.vault(VaultError)` | any other passthrough FFI error |
| `.enclave(Error)` | unexpected Security.framework / `OSStatus` error |

The real `SecureEnclaveDeviceSecretStore` owns the `LAError`/`OSStatus` →
`DeviceUnlockError` mapping. The fakes let the coordinator tests reach every branch
without hardware.

## 7. Testing strategy

**Tier 1 — host `swift test` (`SecretaryDeviceUnlock`, no XCFramework, milliseconds), TDD-first.**
Coordinator tests written red→green against all three fakes:

- enroll happy path (asserts the secret is handed to `enclave.store`, metadata saved with
  the returned `deviceUuid`, buffer zeroized).
- enroll rollback: inject `enclave.store` failure ⇒ assert `removeDeviceSlot` ran + error
  re-thrown; inject `metadata.save` failure ⇒ assert both `enclave.clear` and
  `removeDeviceSlot` ran.
- unlock happy path (fake enclave returns the stored secret, fake port returns a canned
  `OpenedVault`; assert `openWithDeviceSecret` got the right uuid+secret and `vaultUuid`
  flows through; buffer zeroized).
- unlock error branches: one test per `DeviceUnlockError` case — `.notEnrolled`,
  `.vaultSlotMismatch` (both wrong-`vaultId` and `DeviceSlotNotFound`), each injected
  biometric error, `.wrongDeviceSecretOrCorrupt`, `.vault(_)` passthrough.
- disenroll: happy; tolerates `DeviceSlotNotFound`; still clears enclave + metadata when
  the slot was already gone.
- `withZeroizing` overwrites the buffer on scope exit.

**Tier 2 — one simulator XCTest (`SecretaryKitTests`, real FFI).**
`DeviceUnlockIntegrationTests`: real `UniffiVaultDeviceSlotPort` + **fake**
`InMemoryDeviceSecretEnclave` + in-memory metadata, against a **staged writable copy of
`golden_vault_001`** (never the frozen fixture). Flow: `enroll(password)` → real minted
secret stored in the fake enclave → `unlock` → `enclave.release` → real
`openWithDeviceSecret` → assert the vault opens and `vaultUuid` matches the fixture. Then
`disenroll` → assert (a) a subsequent `coordinator.unlock` fails `.notEnrolled` (metadata
was cleared), and (b) calling the **real port's** `openWithDeviceSecret` directly with the
now-removed `deviceUuid` throws `DeviceSlotNotFound` — proving the `devices/<uuid>.wrap`
file was actually deleted from disk, not just forgotten. This proves the orchestration
drives the real B.2 FFI end-to-end.

**Explicitly NOT automated:** the real `SecureEnclaveDeviceSecretStore` is compiled by the
simulator build but its biometric `release` is not asserted against — real Face ID /
Touch ID on hardware is the #202 follow-up's manual/device proof. The integration test
uses the fake enclave so it stays deterministic and CI-runnable.

**Runner wiring:** Tier 1 via `swift test` in `ios/SecretaryDeviceUnlock/` (added to the
iOS test script / CI as a fast pre-step); Tier 2 via the existing
`ios/scripts/run-ios-tests.sh` xcodebuild-on-simulator path, alongside `OpenVaultLinkTests`.

## 8. Acceptance criteria (from #202) — how this slice satisfies each

These are design intentions (nothing is implemented yet); the plan turns them into tests.

- **Non-exportable SE P-256 key with biometric access control wraps the `device_secret`;
  SE private key never leaves the enclave** → `SecureEnclaveDeviceSecretStore`
  (`kSecAttrTokenIDSecureEnclave` + `SecAccessControl[.privateKeyUsage, .biometryCurrentSet]`,
  ECIES wrap). Compiles this slice; device-verified in the follow-up.
- **Enroll: password open → `add_device_slot` mints the secret → SE-wrap → persist blob**
  → `DeviceUnlockCoordinator.enroll` (§5).
- **Unlock: biometric success → SE decrypts → `device_secret` → `open_with_device_secret`
  → vault open** → `DeviceUnlockCoordinator.unlock`, proven by the simulator integration
  test with the fake enclave (§7 Tier 2).
- **Clear typed failure modes for biometry unavailable / not enrolled / locked out** →
  `DeviceUnlockError` (§6), each branch covered by Tier-1 tests.
- **Protocol-boundary unit tests cover enroll→release→open against the in-memory fake** →
  §7 Tier 1; the real `LAContext`/Security.framework conformer is device-verified in the
  follow-up.
- **No secret key material persisted in exportable form; `device_secret` zeroized after
  use as far as the runtime allows** → SE key is non-exportable token-backed; secrets
  routed through `withZeroizing` (best-effort, §4).

## 9. Risks & open decisions

- **Best-effort zeroization** — Swift cannot guarantee no secret bytes linger after a
  value copy. We minimise lifetime and `memset_s` on exit; documented as best-effort.
- **The real SE conformer is unverified by an assertion this slice** — chosen
  deliberately (it can only be truly verified on a device with a real biometric). The
  protocol shape is validated by being *implemented* against the real `SecKey`/`LAContext`
  API, not just designed on paper.
- **`vaultId` is an opaque app token**, not the cryptographic `vault_uuid` — sufficient
  for stale-enrollment detection in the single-vault slice; revisit if/when the registry
  (multi-vault) lands.
- **No format / FFI change** — B.3 is additive Swift only; `golden_vault_001` and the
  uniffi surface are untouched.
- **Anti-rollback stays `None`** on the device path, at parity with password (carried
  from B.2). If a future slice wires a real highest-clock for the SE path, do it for all
  paths.
```
