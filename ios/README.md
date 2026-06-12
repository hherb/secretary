# ios/

Native iOS client for Secretary (Sub-project D.3), per
[ADR 0008](../docs/adr/0008-native-mobile-via-uniffi.md): a Swift app
consuming `secretary-core` through the `ffi/secretary-ffi-uniffi` bindings.

## Status — D.3 slice 1 ✅ + B.3 (Secure-Enclave device unlock) ✅ + password/recovery unlock + read-only browse ✅ + vault selection ✅

The first slice established the iOS build pipeline and proves the core runs
on-device. B.3 adds biometric-gated, Secure-Enclave-backed release of the
per-device secret (the ADR 0009 wrap slot → vault unlock). A later slice
opens the vault by **password or recovery phrase** and **browses blocks /
records read-only** with reveal-on-demand secret fields. The latest slice adds
**vault selection** — the app opens a user-chosen vault folder (system
`.fileImporter`) and remembers it across launches via a persisted
security-scoped bookmark; the bundled golden vault is now an explicit opt-in
demo (no prefilled password).

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
  real Face ID / Touch ID release was verified on an iPhone 13 Pro Max
  (#202 ✅ — see `SecretaryApp/` below).
- `SecretaryVaultAccess/` — a pure, FFI-free Swift package for unlock + browse +
  selection: ports (`VaultOpenPort`, `VaultSession`, `VaultLocationStore`), pure
  models, typed errors (`VaultAccessError`, whose `…OrCorrupt` cases preserve the
  core's anti-oracle conflation, + `VaultSelectionError`), a single-owner
  `ScopedVaultPath` (holds the security scope for the whole session, idempotent
  release), and the host-tested `UnlockViewModel` / `VaultBrowseViewModel` /
  `VaultSelectionViewModel`. A `SecretaryVaultAccessTesting` product provides
  in-memory fakes (incl. a scope-counting `FakeVaultLocationStore`). Reveal is
  on-demand only; `lock()` drops all revealed plaintext and wipes the session.
- `SecretaryKit/Sources/SecretaryKit/VaultAccess/` — the real adapters:
  `UniffiVaultOpenPort` / `UniffiVaultSession` over the projected
  `open_vault_with_password` / `open_vault_with_recovery` + `read_block`, and
  `BookmarkVaultLocationStore` (security-scoped bookmark persistence in
  `UserDefaults` + scoped access), plus simulator integration tests that open
  golden_vault_001 by password/recovery and through a resolved bookmark.
- `SecretaryApp/` — a XcodeGen SwiftUI app. The current root flow is **select a
  vault (system `.fileImporter` folder pick, remembered across launches via a
  bookmark; or an explicit opt-in demo vault) → unlock (password or 24-word
  recovery) → read-only browse** (blocks → records → tap-to-reveal a field),
  releasing the scope + locking the vault on background. The earlier
  device-unlock walking-skeleton (`DeviceUnlockScreen` over the real
  `DeviceUnlockCoordinator`) remains in the package as a reference but is not
  currently wired into the root flow.
  Built (and the demo vault staged) via `scripts/build-app.sh`. The SE store
  records the raw `domain`+`code` diagnostic on each unlock attempt.
  [#202](https://github.com/hherb/secretary/issues/202) ✅ **proven on an
  iPhone 13 Pro Max** (2026-06-11): real SE + Face ID released the secret and
  opened the vault (uuid matched the pinned fixture); biometric cancel/non-match
  surface in `LAError` (`userCancel`) → `userCancelled`, never as tamper.
- `scripts/run-ios-tests.sh` — the acceptance entry point: builds the framework,
  runs both pure packages' host `swift test` (`SecretaryDeviceUnlock` +
  `SecretaryVaultAccess`), runs the XCTest on a simulator (`IOS_SIM` overrides
  the device; default `iPhone 16`), then builds the app (`scripts/build-app.sh`).
  Requires macOS + Xcode; the first run fetches the iOS Rust std via
  `rustup target add`.

```bash
bash ios/scripts/run-ios-tests.sh   # host swift test + simulator XCTest + app build
```

The XCFramework, generated `secretary.swift`, and staged fixtures are
build artifacts (gitignored) — rebuild them with the script.
