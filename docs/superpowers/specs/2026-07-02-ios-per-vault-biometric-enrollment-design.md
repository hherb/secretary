# iOS per-vault-keyed biometric enrollment (#347) — design

**Date:** 2026-07-02
**Issue:** [#347](https://github.com/hherb/secretary/issues/347) — "Unlock with Face ID" shown vault-agnostically → doomed biometric prompt in multi-vault use
**Scope chosen:** Full per-vault enrollment (Android parity), not the minimal button-scope-only variant.
**Platforms touched:** iOS only (`ios/`). No `core`/`ffi` Rust, no on-disk vault-format / spec / conformance / FFI-surface change. No change to the FFI-free coordinator or enclave protocols.

---

## 1. Problem

Device-unlock enrollment metadata (`KeychainEnrollmentMetadataStore`) and the Secure-Enclave key
(`SecureEnclaveDeviceSecretStore`) are **device-global**: fixed Keychain `service`/`account`/`applicationTag`
constants, one `DeviceEnrollment` per device. The Unlock screen shows **"Unlock with Face ID"** whenever
`coordinator.isEnrolled` is true — which is vault-agnostic. With multiple vaults (vault selection ships),
enrolling the device for vault A makes the button appear when unlocking vault B too.

Tapping it in that state fires a **doomed Face ID prompt**: the vault opens with A's `deviceUuid` against B's
folder and only then fails (`DeviceSlotNotFound` → `wrongDeviceSecretOrCorrupt` → `.failed`). The post-open
`session.vaultUuidHex == cred.enrolledVaultId` check makes it **fail gracefully** — no data loss, no weaker
open. It is a **UX wart**, not a security defect.

Root cause: the vault UUID is unknown until *after* open, and the enrollment is stored under device-global
keys, so the button cannot be scoped to the current vault at render time.

## 2. Approach

Mirror Android's actual per-vault model. On Android the **cloud** path namespaces *both* the Keystore key
alias (`cloudDeviceKeyAlias(cloudKey)`) *and* the metadata/blob directory (`cloudDeviceSecretDir(...)`) by
`cloudKey = SHA-256(treeUri)`, while the Kotlin `DeviceEnrollment` struct stays vault-agnostic — the
per-vault-ness lives entirely in the **storage location**, not the struct.

iOS adopts the same principle:

> **Per-vault-ness lives in the Keychain storage keys, not in the `DeviceEnrollment` struct.** Each vault gets
> its own Secure-Enclave key **and** its own metadata entry, namespaced by a hash of the vault path.

This **diverges from the issue's suggested mechanism** (which proposed adding a `vaultPath` field to
`DeviceEnrollment` and comparing it at render). Storage-key namespacing is cleaner, matches Android exactly,
and makes the button correct-by-construction:

- A vault-B-keyed coordinator queries vault-B's Keychain items → `isEnrolled` returns `false` when only vault A
  is enrolled → the button hides. **No change to `isEnrolled` logic is required.**
- The doomed cross-vault prompt becomes **unreachable** (a vault-B coordinator can never load vault A's
  enrollment), not merely guarded after the fact.
- The existing pre-prompt `vaultId` guard (`DeviceUnlockCoordinator.unlock`) and the post-open UUID check
  (`DeviceUnlockOpen.open`) **remain** as defense-in-depth. No security path is weakened.

### Divergence from Android (intentional)

Android keeps its **local/demo** path device-global and only the **cloud** path per-vault, because Android has a
local-vs-cloud split. iOS has **no such split** — every vault is a security-scoped file path (including the
staged demo vault) — so iOS keys **all** vaults uniformly by path hash. This is cleaner than Android's split
and fixes #347 for every vault.

## 3. Component design

### 3.1 `vaultKey(fromPath:)` — pure derivation

A pure, host-testable free function (the iOS mirror of Android's `cloudVaultKey`):

```swift
/// Stable per-vault namespace token: lowercase SHA-256 hex of the vault path bytes.
/// Pure: same path → same key; different path → (overwhelmingly) different key.
func vaultKey(fromPath vaultPath: Data) -> String
```

- Algorithm: SHA-256 (CryptoKit `SHA256`), lowercase hex, `sha256HexLength = 64` chars (named constant, no
  magic number).
- Home: the **FFI-free `SecretaryDeviceUnlock` package** (pure, no xcframework dependency). This matches the
  repo's own test architecture: `run-ios-tests.sh` **Step 1** runs the pure package via fast host `swift test`
  *before* the multi-minute xcframework build, so a keying-logic regression fails in milliseconds without a
  simulator. The `SecretaryKit` factory (§3.3) imports it. The per-vault *identifier scheme* (the account/tag
  string builders) lives here too, so the whole namespacing decision is pure and host-tested; only the concrete
  Keychain-store construction stays in `SecretaryKit`.

### 3.2 Namespacing scheme

| Item | Today (device-global) | Per-vault |
|---|---|---|
| SE key `applicationTag` (`keyTag`) | `com.secretary.deviceSecret.seKey` | `com.secretary.deviceSecret.seKey.<vaultKey>` |
| Wrapped-blob account (`blobAccount`) | `wrappedDeviceSecret` | `wrappedDeviceSecret.<vaultKey>` |
| Enrollment metadata account (`account`) | `deviceEnrollment` | `deviceEnrollment.<vaultKey>` |

Services (`blobService = "com.secretary.deviceSecret"`, enrollment `service = "com.secretary.enrollment"`) stay
stable — grouping all Secretary items under one service — while the **account / applicationTag** carries the
vault key. Both `SecureEnclaveDeviceSecretStore` and `KeychainEnrollmentMetadataStore` are **already**
constructor-parameterizable on exactly these fields, so no adapter API changes; the factory supplies vault-keyed
values.

No on-disk vault-format change: the `devices/<uuid>.wrap` slot is already keyed by a random per-enrollment
`deviceUuid`.

### 3.3 `makePerVaultDeviceUnlock(vaultPath:)` — composition point

One new factory in `SecretaryKit`, the analog of Android's `cloudDeviceUnlockCoordinator`:

```swift
struct PerVaultDeviceUnlock {
    let coordinator: DeviceUnlockCoordinator
    let enclave: DeviceSecretEnclave   // SAME-keyed enclave, for the reauth gate's authorizer
}

func makePerVaultDeviceUnlock(vaultPath: Data) -> PerVaultDeviceUnlock
```

It derives `vaultKey(fromPath:)` once and builds:
- `SecureEnclaveDeviceSecretStore(keyTag: …seKey.<key>, blobService: <stable>, blobAccount: wrappedDeviceSecret.<key>)`
- `KeychainEnrollmentMetadataStore(service: <stable>, account: deviceEnrollment.<key>)`
- `DeviceUnlockCoordinator(slotPort: UniffiVaultDeviceSlotPort(), enclave:, metadata:)`

Returning the **enclave alongside the coordinator** matters: the write-reauth grace gate builds an
`EnclaveBiometricAuthorizer` over a `DeviceSecretEnclave`, and it must be the *same-keyed* enclave so
`authorizer.isEnrolled` / `authorize()` act on this vault's key.

### 3.4 Call-site rewiring (all six already have the vault path in scope)

`ios/SecretaryApp/Sources/SecretaryApp.swift`:
1. `.select` `onOpen` — `biometricEnrolled = makePerVaultDeviceUnlock(vaultPath: scoped.pathData).coordinator.isEnrolled`
2. `.unlock` — build the coordinator for the unlock screen via the factory with `scoped.pathData`
3. `onUnlocked` enroll block — enroll on the factory's coordinator with `scoped.pathData`
4. `onUnlocked` password-path gate — `EnclaveBiometricAuthorizer(enclave: makePerVaultDeviceUnlock(vaultPath: scoped.pathData).enclave)`
5. `openDemo()` — `biometricEnrolled = makePerVaultDeviceUnlock(vaultPath: scoped.pathData).coordinator.isEnrolled`

`ios/SecretaryApp/Sources/DeviceUnlockOpen.swift`:
6. biometric-path gate — the function already takes `vaultPath: Data`; build the gate's authorizer enclave via
   the factory with that path.

`localCoordinator()` (currently device-global) is replaced by `makePerVaultDeviceUnlock(vaultPath:)`.

## 4. Data flow

Enroll (vault V, "Remember this device" ticked):
`scoped.pathData → vaultKey(V) → per-V enclave.store(secret) + per-V metadata.save({vaultId: V.uuid, deviceUuid})`.

Button visibility (vault V at Unlock entry):
`scoped.pathData → vaultKey(V) → per-V coordinator.isEnrolled` (enclave holds a secret under V's tag AND V's
metadata exists) → show button only if true.

Biometric unlock (vault V):
`per-V coordinator.releaseCredential` loads V's metadata → biometric release of V's SE secret → open V → UUID
matches (guaranteed, since only V's enrollment is reachable) → grace gate seeded with V's same-keyed enclave.

## 5. Behavior changes and risks

- **Write-reauth grace gate becomes per-vault (behavior change, improvement).** Today, if *any* vault is
  enrolled the #284 gate is armed for every vault; after this it is armed only for the enrolled vault. An
  unenrolled vault already has no gate, so this is more correct, not a regression. It is a behavior change on
  the #284 path and must be called out in review.
- **Path-hash stability (accepted limitation).** If a vault file moves (e.g. iCloud relocation), its resolved
  path changes → hash changes → enrollment appears lost → button hides → user re-enrolls. No data loss:
  password unlock always works, and the post-open UUID check remains the authority. Same class of concern as
  Android keying on `treeUri`. The vault UUID would be stabler but is unknown pre-open, so the path is the only
  pre-open key.
- **No migration of old device-global items (YAGNI, pre-release).** The app is unreleased; nobody holds a
  durable enrollment to preserve. Old device-global Keychain items / SE key become orphaned but harmless
  (they are simply never queried again). No cleanup pass.
- **Demo vault included.** Keyed by its staged path like any other vault. If the staged path varies across
  launches the demo enrollment is ephemeral — demo-only, acceptable.

## 6. Testing (TDD)

- **Pure derivation — host unit tests in `SecretaryDeviceUnlockTests`** (fast `swift test`, no simulator, runs
  in `run-ios-tests.sh` Step 1):
  - `vaultKey(fromPath:)` determinism: same path bytes → identical key;
  - distinctness: two different paths → different keys;
  - shape: output is `sha256HexLength` (64) lowercase-hex chars; stable against a pinned known-answer vector
    (SHA-256 of a fixed byte string), matching the existing "KATs via fixtures / random elsewhere" discipline;
  - identifier scheme: distinct vault keys → distinct SE tag / blob account / enrollment account, and each
    carries the documented prefix.
- **Factory `makePerVaultDeviceUnlock` (`SecretaryKit`)** — thin composition; verified by compile + the
  existing on-simulator `DeviceUnlockIntegrationTests` / `EnclaveBiometricAuthorizerTests` staying green (no
  regression). Keychain I/O cannot run in pure host tests, so the keying *logic* is proven by the pure
  identifier tests above and the factory is proven to *wire those identifiers through* by construction + compile.
- **No new tests on the coordinator/enclave protocols** — they are unchanged.

## 7. Out of scope

- Any change to the Rust core, FFI surface, on-disk format, or the CRDT/crypto paths.
- A disenroll/settings UI (iOS has none today; enrollment is opt-in via the "Remember this device" checkbox).
- Android changes — Android is already per-vault on its cloud path; this slice is iOS-only. (A future
  `DeviceEnrollment` data-model change would want an Android review, but this design adds no such field.)
- On-device Face ID acceptance run (manual; tracked separately).

## 8. Affected files

Change / create:
- `ios/SecretaryDeviceUnlock/Sources/SecretaryDeviceUnlock/PerVaultDeviceUnlockIdentifiers.swift` — new: pure
  `vaultKey(fromPath:)` + the per-vault identifier scheme (SE tag / blob account / enrollment account builders)
  + `sha256HexLength` constant.
- `ios/SecretaryKit/Sources/SecretaryKit/DeviceUnlock/PerVaultDeviceUnlock.swift` — new: `PerVaultDeviceUnlock`
  struct + `makePerVaultDeviceUnlock(vaultPath:)` factory (imports the pure derivation).
- `ios/SecretaryApp/Sources/SecretaryApp.swift` — replace `localCoordinator()` and the two gate enclave
  constructions with factory calls (five sites).
- `ios/SecretaryApp/Sources/DeviceUnlockOpen.swift` — build the gate authorizer enclave via the factory.

New tests:
- `ios/SecretaryDeviceUnlock/Tests/SecretaryDeviceUnlockTests/PerVaultDeviceUnlockIdentifiersTests.swift` — pure
  host unit tests for `vaultKey` + the identifier scheme.

Unchanged (verified): `DeviceEnrollment`, `DeviceEnrollmentMetadataStore`, `DeviceSecretEnclave`,
`DeviceUnlockCoordinator`, `KeychainEnrollmentMetadataStore` / `SecureEnclaveDeviceSecretStore` *APIs*
(only their construction arguments change), `EnclaveBiometricAuthorizer`, `GraceWindowReauthGate`.
