# D.3 slice 1 — iOS XCFramework + linked-call proof

**Date:** 2026-06-09
**Sub-project:** D (platform UIs) — D.3 (native iOS), first sub-slice
**Status:** design approved; implementation pending
**Governing ADR:** [ADR 0008](../../adr/0008-native-mobile-via-uniffi.md) — mobile is built as native apps consuming `secretary-core` via `ffi/secretary-ffi-uniffi`; the uniffi surface is the mobile UI path.

## Purpose

Prove that the audited `secretary-core` actually runs through the existing uniffi bindings **on an iOS simulator**, by establishing a reproducible XCFramework build pipeline and an automated XCTest that opens the golden vault on-device.

This is the thinnest possible D.3 slice: it de-risks the genuinely-novel infrastructure — cross-compiling the Rust core for iOS triples, packaging it as an XCFramework, and linking it from a Swift package — **before** any UI or security-critical key-storage work. It deliberately ships no app and no Keychain/Secure Enclave code.

## Why this scope (decisions taken in brainstorming)

| Decision | Choice | Rationale |
|---|---|---|
| Slice boundary | XCFramework + XCTest linked-call proof, no app UI, no key storage | Isolate and retire the packaging risk first; the SwiftUI app and the hardware-key path are each large enough to be their own slices. |
| Verification | Automated scripted `xcodebuild test` against a simulator | Matches the project's verification-before-completion discipline; reproducible from the CLI, CI-wireable later. |
| Project structure | Swift Package (SPM) — `binaryTarget` + test target | Text-based, git-friendly, zero external tooling; the right container for a no-UI proof. The eventual app's project structure is a separate, later decision. |
| What the test exercises | Real vault open (`open_vault_with_password` on `golden_vault_001`) | Exercises the full on-device path (FFI marshalling → Argon2id → X25519⊕ML-KEM decap → AEAD decrypt → struct return), not just symbol resolution. Mirrors existing `SmokeHelpers.swift`, so low authoring risk. |

## Architecture

```
secretary-ffi-uniffi (Rust)
   │  cargo build --target {aarch64-apple-ios, aarch64-apple-ios-sim, x86_64-apple-ios}  (staticlib)
   │  uniffi-bindgen generate --language swift
   ▼
Secretary.xcframework  (device .a slice + lipo'd simulator .a slice + headers/modulemap)
   +  secretary.swift   (generated high-level Swift API)
   ▼
SPM package (ios/SecretaryKit/)
   binaryTarget(SecretaryFFI → Secretary.xcframework)
   target(SecretaryKit → wraps secretary.swift, depends on SecretaryFFI)
   testTarget(SecretaryKitTests → opens golden_vault_001 on the simulator)
   ▼
xcodebuild test -destination 'platform=iOS Simulator,…'   → pass/fail
```

## File layout (all new, under `ios/`)

```
ios/
  README.md                      (updated: no longer a bare placeholder)
  SecretaryKit/
    Package.swift                (SPM manifest: binaryTarget + lib + testTarget)
    Sources/SecretaryKit/
      secretary.swift            (GENERATED — gitignored, rebuilt by the script)
    Tests/SecretaryKitTests/
      OpenVaultLinkTests.swift   (the linked-call proof XCTest)
      Resources/                 (golden_vault_001 staged here at build time — gitignored)
  scripts/
    build-xcframework.sh         (cross-compile + bindgen + assemble xcframework + stage fixture)
    run-ios-tests.sh             (build-xcframework.sh, then xcodebuild test on a named simulator)
  Secretary.xcframework/         (GENERATED — gitignored)
  .gitignore                     (ignores xcframework, generated swift, staged fixture, build dirs)
```

**Committed:** the two scripts, `Package.swift`, `OpenVaultLinkTests.swift`, README, `.gitignore`.
**Generated / gitignored:** `Secretary.xcframework/`, `Sources/SecretaryKit/secretary.swift`, `Tests/SecretaryKitTests/Resources/`, `.build/`.
**Rationale:** the XCFramework and generated bindings are reproducible binary/codegen artifacts — committing them bloats the repo and risks drift from the Rust source. The scripts make them one-command reproducible instead.

## The one Rust-crate change

`ffi/secretary-ffi-uniffi/Cargo.toml`: add `"staticlib"` to crate-type:

```toml
crate-type = ["cdylib", "rlib", "staticlib"]
```

iOS links the Rust core as a static archive (`.a`) inside the XCFramework — the standard uniffi-iOS recipe. The change is **purely additive**: the existing `cdylib` (desktop Swift/Kotlin smoke) and `rlib` (workspace) consumers are untouched. There is no Rust code change, no UDL change, and no new `FfiVaultError` variant, so this slice **does not re-trigger the cross-language conformance gauntlet** (it adds a build target, not a binding surface). The existing gauntlet must still pass unchanged after the crate-type edit — that is part of acceptance.

## `build-xcframework.sh`

Script-relative paths, `set -euo pipefail`, macOS + Xcode preflight guards (mirroring the existing `tests/swift/run.sh`). Steps:

1. `rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios` (idempotent).
2. `cargo build --release -p secretary-ffi-uniffi --target <each>` → three `libsecretary_ffi_uniffi.a` archives.
3. `lipo -create` the two simulator archives (arm64-sim + x86_64-sim) → one fat simulator `.a` (runs on both Apple-silicon and Intel simulators).
4. `cargo run --release --features cli -p secretary-ffi-uniffi --bin uniffi-bindgen -- generate --library <device .a> --language swift --out-dir <staging>` → emits `secretary.swift` + `secretaryFFI.h` + `secretaryFFI.modulemap`. Copy `secretary.swift` into `Sources/SecretaryKit/`; assemble a headers dir containing the `.h` + a `module.modulemap`.
5. `rm -rf ios/Secretary.xcframework` then `xcodebuild -create-xcframework -library <device.a> -headers <hdrs> -library <simfat.a> -headers <hdrs> -output ios/Secretary.xcframework` (`-create-xcframework` refuses to overwrite, hence the clean-rebuild).
6. Stage the fixture: `cp -R core/tests/data/golden_vault_001` (+ `golden_vault_001_inputs.json`, for the pinned uuid) into `Tests/SecretaryKitTests/Resources/`. Keeps `core/tests/data/` the single source of truth — no committed duplicate — while giving SPM a bundleable resource.

**Toolchain note:** iOS targets use the stable toolchain's std for those triples (pulled by `rustup target add`); the repo's `rust-toolchain.toml` is stable, so no nightly is involved. The script fails fast with a clear message if `xcodebuild` / `lipo` are missing.

## SPM package — `Package.swift`

- `binaryTarget(name: "SecretaryFFI", path: "../Secretary.xcframework")` — the XCFramework.
- `target(name: "SecretaryKit", dependencies: ["SecretaryFFI"])` — wraps the generated `secretary.swift` high-level Swift API.
- `testTarget(name: "SecretaryKitTests", dependencies: ["SecretaryKit"], resources: [.copy("Resources/golden_vault_001"), .copy("Resources/golden_vault_001_inputs.json")])` — bundles the staged fixture so it is reachable inside the simulator sandbox via `Bundle.module`.
- Platform floor: `.iOS(.v17)`. The floor is nearly irrelevant to this test-only slice (XCTest / `Bundle.module` / the generated Swift all work from iOS 13 up); it is set forward-looking. With no legacy users to support, iOS 17 still covers ~5 years of devices (iPhone XS / 2018 and later) while keeping slice 2's richer `LocalAuthentication` / Keychain / Secure-Enclave APIs and modern Swift concurrency defaults in reach without a later bump. Trivially revisitable when the app slice sets a real minimum.

## The XCTest — `OpenVaultLinkTests.swift`

- `setUp`: locate the bundled fixture via `Bundle.module.url(forResource:…)`; `cp -R` it into `FileManager`'s per-test temp dir. Opening a vault may write vault-stored settings, so the read-only fixture is never opened in place — mirrors the desktop smoke and [[feedback_smoke_test_temp_copy_golden_vault]].
- `testOpenGoldenVaultOnDevice`: call `openVaultWithPassword(folder: tmpCopy, password: "correct horse battery staple")`; assert it returns without throwing; assert `out.vaultUuid()` equals the pinned uuid read from the bundled `golden_vault_001_inputs.json`; call `wipe()`.
- `testWrongPasswordSurfacesTypedError`: assert opening with a bad password throws the expected typed `VaultError` — cheaply proves error-marshalling across the FFI.
- `tearDown`: remove the temp copy.

## `run-ios-tests.sh`

Runs `build-xcframework.sh`, then:

```
xcodebuild test -scheme SecretaryKit \
  -destination "platform=iOS Simulator,name=${IOS_SIM:-iPhone 16}"
```

Exits non-zero on failure. The simulator name is overridable via `IOS_SIM`; if the named simulator is absent the script prints the available simulators (`xcrun simctl list devices`) and fails with a clear message.

## TDD shape

The XCTest *is* the spec. Write `OpenVaultLinkTests.swift` first; it fails to compile/link until the XCFramework + `Package.swift` exist, then goes green once the pipeline produces a working framework. Red → green path: script not yet wired → linker/bundle error → passing assertions. Each plan task ends by running `run-ios-tests.sh` and showing its output (verification before completion).

## Acceptance criteria

1. `bash ios/scripts/run-ios-tests.sh` builds the XCFramework from a clean tree and exits 0 with both XCTests passing on the simulator.
2. The existing desktop gauntlet still passes unchanged after the `staticlib` crate-type addition:
   - `cargo clippy --release --workspace --tests -- -D warnings`
   - `cargo test --release --workspace`
   - `bash ffi/secretary-ffi-uniffi/tests/swift/run.sh` and `…/kotlin/run.sh`
3. `README.md` and `ROADMAP.md` updated for D.3 slice 1.

## Explicitly out of scope (boundary is normative)

- **No SwiftUI app, no app target, no UI** — XCTest only.
- **No Keychain / Secure Enclave / LocalAuthentication / biometric key binding** — key material stays in-memory in the test. That is slice 2, with its own threat-model-careful brainstorm.
- **No CI wiring** — the runner is CLI-reproducible but invoked manually this session; CI integration (Xcode-on-CI cost) is a later decision.
- **No Android equivalent, no document-picker / Files-app vault selection, no write/sync flows.**

## Risks & mitigations

- **Simulator flakiness / boot latency in automation.** Mitigated by a fixed, overridable simulator name and a clear error path that lists available devices. The test itself is deterministic (golden vault, pinned password/uuid).
- **`-create-xcframework` overwrite refusal.** Mitigated by the explicit `rm -rf` clean-rebuild in step 5.
- **uniffi-bindgen header/modulemap naming drift between uniffi versions.** The script assembles the headers dir from whatever bindgen emits (globs the `.h` + `.modulemap`) rather than hard-coding names, so a uniffi bump that renames the emitted files surfaces as a build error in this slice's own pipeline, not silently.
- **iOS-target std download requires network on first run.** `rustup target add` is idempotent and only fetches once; noted in the README so a fresh checkout knows the first build pulls toolchain components.
