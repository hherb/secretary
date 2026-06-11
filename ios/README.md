# ios/

Native iOS client for Secretary (Sub-project D.3), per
[ADR 0008](../docs/adr/0008-native-mobile-via-uniffi.md): a Swift app
consuming `secretary-core` through the `ffi/secretary-ffi-uniffi` bindings.

## Status — D.3 slice 1 ✅ + B.3 (Secure-Enclave device unlock) ✅

The first slice established the iOS build pipeline and proves the core runs
on-device. B.3 adds biometric-gated, Secure-Enclave-backed release of the
per-device secret (the ADR 0009 wrap slot → vault unlock).

- `scripts/build-xcframework.sh` — cross-compiles the uniffi staticlib for the
  three iOS triples, generates the Swift bindings, and assembles
  `Secretary.xcframework` (device + simulator). Also stages `golden_vault_001`
  as an SPM test resource.
- `SecretaryKit/` — a Swift Package: a `binaryTarget` for the XCFramework, a
  `SecretaryKit` library wrapping the generated `secretary.swift`, and an
  XCTest target that opens the golden vault on a simulator.
- `SecretaryDeviceUnlock/` — a pure, FFI-free Swift package: the unlock
  orchestration (`DeviceUnlockCoordinator` over three injected ports:
  `VaultDeviceSlotPort`, `DeviceSecretEnclave`, `DeviceEnrollmentMetadataStore`)
  and a typed `DeviceUnlockError`, fully covered by host `swift test`. A
  `SecretaryDeviceUnlockTesting` product provides in-memory fakes for
  integration tests.
- `SecretaryKit/Sources/SecretaryKit/DeviceUnlock/` — the iOS adapters: the
  real uniffi `UniffiVaultDeviceSlotPort`, the Secure-Enclave conformer
  `SecureEnclaveDeviceSecretStore` (non-exportable P-256 + biometric
  `SecAccessControl` + ECIES wrap), and `KeychainEnrollmentMetadataStore`. The
  SE conformer compiles and is exercised on the simulator with a fake enclave;
  real Face ID / Touch ID verification on a device is the #202 follow-up.
- `SecretaryApp/` — a XcodeGen SwiftUI walking-skeleton app driving the full
  enroll / unlock / disenroll flow through the real `DeviceUnlockCoordinator`.
  Built (and the demo vault staged) via `scripts/build-app.sh`. The
  `SecretaryDeviceUnlockUI` product provides the host-tested `DeviceUnlockViewModel`
  that backs the app's views. The SE store records the raw `domain`+`code`
  diagnostic on each unlock attempt for the [#202](https://github.com/hherb/secretary/issues/202)
  on-device biometric proof.
- `scripts/run-ios-tests.sh` — the acceptance entry point: builds the framework,
  runs the pure package's host `swift test`, runs the XCTest on a simulator,
  then builds the app (`scripts/build-app.sh`). (`IOS_SIM` overrides the device;
  default `iPhone 16`.) Requires macOS + Xcode; the first run fetches the iOS
  Rust std via `rustup target add`.

```bash
bash ios/scripts/run-ios-tests.sh   # host swift test + simulator XCTest + app build
```

The XCFramework, generated `secretary.swift`, and staged fixtures are
build artifacts (gitignored) — rebuild them with the script.
