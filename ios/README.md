# ios/

Native iOS client for Secretary (Sub-project D.3), per
[ADR 0008](../docs/adr/0008-native-mobile-via-uniffi.md): a Swift app
consuming `secretary-core` through the `ffi/secretary-ffi-uniffi` bindings.

## Status — D.3 slice 1: XCFramework + linked-call proof ✅

The first slice establishes the iOS build pipeline and proves the core runs
on-device. There is no app UI yet, and no Keychain/Secure-Enclave key storage
yet (that is the next slice).

- `scripts/build-xcframework.sh` — cross-compiles the uniffi staticlib for the
  three iOS triples, generates the Swift bindings, and assembles
  `Secretary.xcframework` (device + simulator). Also stages `golden_vault_001`
  as an SPM test resource.
- `SecretaryKit/` — a Swift Package: a `binaryTarget` for the XCFramework, a
  `SecretaryKit` library wrapping the generated `secretary.swift`, and an
  XCTest target that opens the golden vault on a simulator.
- `scripts/run-ios-tests.sh` — the acceptance entry point: builds the framework
  then runs the XCTest on a simulator (`IOS_SIM` overrides the device; default
  `iPhone 16`). Requires macOS + Xcode; the first run fetches the iOS Rust std
  via `rustup target add`.

```bash
bash ios/scripts/run-ios-tests.sh        # build + test on the simulator
```

The XCFramework, generated `secretary.swift`, and staged fixtures are
build artifacts (gitignored) — rebuild them with the script.
