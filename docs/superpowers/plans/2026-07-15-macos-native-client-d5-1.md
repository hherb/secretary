# D.5.1 — macOS enclave walking skeleton — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove Touch ID / Secure Enclave key release on a real Apple Silicon Mac by opening a staged vault through the same `open_with_device_secret` path the iOS app uses — via a macOS slice of the uniffi XCFramework, a macOS-generalized `SecretaryKit`, and a minimal SwiftUI Mac app.

**Architecture:** Additive UI + build-arch work only; the Rust core, the `.udl`, and `FfiVaultError` are untouched. The two pure Swift packages (`SecretaryDeviceUnlock`, `SecretaryVaultAccess`) are already `.macOS(.v13)` and reused as-is. The XCFramework gains an `aarch64-apple-darwin` slice; `SecretaryKit` gains `.macOS(.v13)` (its adapters already import only cross-platform `Security` + `LocalAuthentication`, no UIKit); a new minimal `SecretaryMac` XcodeGen app reuses `makePerVaultDeviceUnlock` + `DeviceUnlockViewModel`.

**Tech Stack:** Rust (uniffi staticlib), Swift 6 / SwiftUI, SwiftPM, XcodeGen, `xcodebuild`, `cargo`, bash.

## Global Constraints

- **Apple Silicon only.** Target `aarch64-apple-darwin`; macOS deployment target **13.0**. Intel (`x86_64-apple-darwin`) is explicitly deferred — do not add it.
- **Do not touch** `core/`, `ffi/secretary-ffi-uniffi/src/secretary.udl`, the bridge, or `FfiVaultError`. If a step seems to need an FFI-surface change, stop — it is out of scope for D.5.1.
- **`SecretaryKit` keeps `.iOS(.v17)`** and *adds* `.macOS(.v13)`. Guard any platform-divergent code with `#if os(macOS)` / `#if os(iOS)` so the iOS build stays green.
- **iOS must stay green.** After any change under `ios/SecretaryKit/`, run `bash ios/scripts/run-ios-tests.sh` before considering the task done.
- **Swift 6 language mode** (`swift-tools-version: 6.0`, `SWIFT_VERSION: "6.0"`): complete strict-concurrency is a hard compile error, not a warning.
- **Worktree discipline.** All work happens in `/Users/hherb/src/secretary/.worktrees/d5-macos-native` on branch `feature/d5-macos-native-client`. Shell state does NOT persist between Bash calls — chain `cd … && …` in one call or use absolute paths. Verify with `pwd && git branch --show-current` before any `git`/`cargo`/`xcodebuild`.
- **The XCFramework build is multi-minute and silent.** Run `build-xcframework.sh` backgrounded with log polling; never kill a running build assuming it hung.
- **Never mutate the tracked `core/tests/data/golden_vault_001` fixture.** Always operate on a staged copy.
- **Commits:** conventional-commit subject; every commit ends with the trailer
  `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>` (shown as a second `-m` in each task).

## File Structure

**Decision — macOS app location:** the new app lives at **`ios/SecretaryMacApp/`** (sibling of `ios/SecretaryApp/`), so its XcodeGen package refs stay `../SecretaryKit` and it shares `ios/scripts/`. The `ios/` directory already houses the shared Apple-platform packages (`SecretaryDeviceUnlock` is not iOS-specific), so this is the low-friction placement. A future reorg could hoist shared packages to a top-level `apple/` dir; out of scope here. *If you'd prefer a top-level `macos/`, redirect before starting Task 4.*

| Path | Create/Modify | Responsibility |
|---|---|---|
| `ios/scripts/build-xcframework.sh` | Modify | Add the `aarch64-apple-darwin` slice to the XCFramework. |
| `ios/SecretaryKit/Package.swift` | Modify | Add `.macOS(.v13)` to `platforms`. |
| `ios/SecretaryKit/Sources/SecretaryKit/DeviceUnlock/*` | Modify (only if compiler flags it) | `#if os` guards for any macOS-unavailable symbol. |
| `ios/SecretaryMacApp/project.yml` | Create | XcodeGen macOS app target. |
| `ios/SecretaryMacApp/SecretaryMac.entitlements` | Create | `keychain-access-groups` for SE/data-protection Keychain. |
| `ios/SecretaryMacApp/Sources/SecretaryMacApp.swift` | Create | `@main` App + window. |
| `ios/SecretaryMacApp/Sources/MacDeviceUnlockView.swift` | Create | Minimal SwiftUI unlock screen over `DeviceUnlockViewModel`. |
| `ios/SecretaryMacApp/Sources/MacVaultProvisioning.swift` | Create | Stage a writable copy of the bundled golden vault (macOS). |
| `ios/SecretaryMacApp/.gitignore` | Create | Ignore generated `*.xcodeproj` + staged `Fixtures/`. |
| `ios/scripts/build-macos-app.sh` | Create | Stage fixture, `xcodegen generate`, macOS compile proof. |
| `ios/scripts/run-macos-tests.sh` | Create | Layered runner: host packages → XCFramework → Kit host test → app compile. |
| `ios/SecretaryMacApp/MANUAL-PROOF.md` | Create | On-Mac Touch ID acceptance procedure (the D.5.1 milestone). |
| `docs/adr/0011-macos-native-swiftui.md` | Create | Decision record. |
| `ROADMAP.md` | Modify | Add the D.5 row. |

---

## Task 1: Add the macOS slice to the XCFramework

**Files:**
- Modify: `ios/scripts/build-xcframework.sh`

**Interfaces:**
- Produces: `ios/Secretary.xcframework` now contains a `macos-arm64` slice in addition to the iOS device + simulator slices. Consumed by Tasks 2–5.

- [ ] **Step 1: Write the failing verification**

The "test" for this infra task is: the built XCFramework advertises a macОS slice. First confirm it currently does **not**. From the worktree root:

```bash
cd /Users/hherb/src/secretary/.worktrees/d5-macos-native
plutil -p ios/Secretary.xcframework/Info.plist 2>/dev/null | grep -i "macos" || echo "NO_MACOS_SLICE"
```

- [ ] **Step 2: Run it to verify it fails**

Expected output: `NO_MACOS_SLICE` (or a "No such file" if the framework isn't built yet — either way, no macOS slice exists).

- [ ] **Step 3: Edit `build-xcframework.sh` to add the macOS target**

After the existing iOS target declarations (the `DEVICE_TARGET` / `SIM_TARGETS` lines), add the macOS target:

```bash
DEVICE_TARGET="aarch64-apple-ios"
SIM_TARGETS=("aarch64-apple-ios-sim" "x86_64-apple-ios")
# macOS native slice (D.5.1). Apple Silicon only — Intel (x86_64-apple-darwin)
# is deferred. This is the same triple as the host build below, but building it
# explicitly under --target keeps the artifact at a predictable path for the
# XCFramework packaging and future-proofs against a non-arm64 host.
MACOS_TARGET="aarch64-apple-darwin"
```

In **Step 1** (`rustup target add`), add the macOS triple:

```bash
echo "==> rustup target add (iOS + macOS)"
rustup target add "$DEVICE_TARGET" "${SIM_TARGETS[@]}" "$MACOS_TARGET"
```

In **Step 2** (`cargo build staticlib`), also build the macOS slice:

```bash
echo "==> cargo build staticlib (device + simulators + macOS)"
for t in "$DEVICE_TARGET" "${SIM_TARGETS[@]}" "$MACOS_TARGET"; do
    (cd "$REPO_ROOT" && cargo build --release -p "$CRATE" --target "$t")
done
```

After the `DEVICE_LIB=` assignment (Step 3 region), add the macOS lib path:

```bash
DEVICE_LIB="$REPO_ROOT/target/$DEVICE_TARGET/release/$LIB"
MACOS_LIB="$REPO_ROOT/target/$MACOS_TARGET/release/$LIB"
```

In **Step 5** (`xcodebuild -create-xcframework`), add the macOS slice as a third `-library`:

```bash
xcodebuild -create-xcframework \
    -library "$DEVICE_LIB" -headers "$HDRS" \
    -library "$SIM_FAT" -headers "$HDRS" \
    -library "$MACOS_LIB" -headers "$HDRS" \
    -output "$XCFRAMEWORK"
```

Also update the script's header comment (first line) from "for iOS (device + simulator)" to "for iOS (device + simulator) + macOS (Apple Silicon)".

- [ ] **Step 4: Run the build (backgrounded — it is multi-minute and silent)**

```bash
cd /Users/hherb/src/secretary/.worktrees/d5-macos-native
bash ios/scripts/build-xcframework.sh > /tmp/d51-xcframework.log 2>&1 &
```

Poll `/tmp/d51-xcframework.log` until it ends with `==> done:`. Do not kill it.

- [ ] **Step 5: Verify the macOS slice now exists**

```bash
plutil -p ios/Secretary.xcframework/Info.plist | grep -i "macos"
```

Expected: at least one line containing `"macos-arm64"` (as `LibraryIdentifier` / `SupportedPlatform`). If instead you see the iOS slices only, re-check the `-library "$MACOS_LIB"` line.

- [ ] **Step 6: Commit**

```bash
git add ios/scripts/build-xcframework.sh
git commit -m "build(macos): add aarch64-apple-darwin slice to Secretary.xcframework (D.5.1)" \
           -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

*(The `ios/Secretary.xcframework` output is git-ignored — only the script is committed.)*

---

## Task 2: Generalize `SecretaryKit` to macOS (build + host test)

**Files:**
- Modify: `ios/SecretaryKit/Package.swift`
- Modify (only if the compiler flags a symbol): `ios/SecretaryKit/Sources/SecretaryKit/DeviceUnlock/*.swift`
- Test: the package's existing `SecretaryKitTests`, now run on the macOS host.

**Interfaces:**
- Consumes: the `macos-arm64` XCFramework slice from Task 1.
- Produces: `SecretaryKit` builds and host-tests on macOS via `swift test`; `makePerVaultDeviceUnlock(vaultPath: Data) -> PerVaultDeviceUnlock` and its members are available to Task 4.

- [ ] **Step 1: Confirm it currently fails to build for macOS**

`SecretaryKit` is `.iOS(.v17)`-only, so a host build is rejected before Task 1's slice even matters:

```bash
cd /Users/hherb/src/secretary/.worktrees/d5-macos-native/ios/SecretaryKit && swift build 2>&1 | head -20
```

Expected: an error that the package supports only iOS / the platform is unsupported.

- [ ] **Step 2: Add `.macOS(.v13)` to `Package.swift`**

Change the `platforms` line:

```swift
    name: "SecretaryKit",
    platforms: [.macOS(.v13), .iOS(.v17)],
```

- [ ] **Step 3: Build for the macOS host**

```bash
cd /Users/hherb/src/secretary/.worktrees/d5-macos-native/ios/SecretaryKit && swift build 2>&1 | tail -30
```

Expected outcome: **build succeeds.** The adapters import only `Foundation`, `Security`, `LocalAuthentication`, `Combine`, and the pure packages — all macOS-available — so no source change is expected.

**If (and only if) the compiler flags a macOS-unavailable symbol**, wrap the minimal offending region in an availability guard, e.g.:

```swift
#if os(iOS)
        // iOS-only symbol usage stays here
#elseif os(macOS)
        // macOS equivalent (or a typed DeviceUnlockError.enclave("unsupported on macOS"))
#endif
```

Do not broaden a guard beyond the exact symbol the compiler rejected. Re-run `swift build` until clean.

- [ ] **Step 4: Host-test on macOS**

The XCFramework macOS slice from Task 1 must be present (it is, if Task 1 passed). Run:

```bash
cd /Users/hherb/src/secretary/.worktrees/d5-macos-native/ios/SecretaryKit && swift test 2>&1 | tail -40
```

Expected: the suite builds and passes on the host. (The Secure-Enclave conformer has no automated test — real Touch ID needs a device, Task 6 — so nothing here should require enclave hardware.)

**If a specific test references an iOS-only API**, guard that test method or file with `#if os(iOS)` (never weaken an assertion to make it pass), then re-run.

**Note — SE-availability (spec §4 / §9):** no new availability code is needed for D.5.1. The requirement is "fail *typed* on non-SE hardware, never crash or mislabel." `SecureEnclaveDeviceSecretStore.ensureKey()` already routes a non-SE `SecKeyCreateRandomKey` failure through `throw DeviceUnlockError.enclave(cfErrorString(...))` — a typed enclave error, never `.wrappedSecretCorrupt`. Since D.5.1 floors at Apple Silicon (M1+, which always has a Secure Enclave), this path is exercised only on out-of-scope hardware, and the existing typed error is the acceptable "stub." Do **not** add a fallback-UX branch here — that is a later slice. Verify only that you did not remove or weaken this existing typed-error path.

- [ ] **Step 5: Prove iOS is still green**

```bash
cd /Users/hherb/src/secretary/.worktrees/d5-macos-native
bash ios/scripts/run-ios-tests.sh > /tmp/d51-ios.log 2>&1 &
```

Poll `/tmp/d51-ios.log`; expected final state: the iOS simulator XCTest and app build both pass. (Backgrounded — it rebuilds the XCFramework and runs a simulator, multiple minutes.)

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/d5-macos-native
git add ios/SecretaryKit/Package.swift ios/SecretaryKit/Sources/
git commit -m "feat(macos): make SecretaryKit build & host-test on macOS (D.5.1)" \
           -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Minimal SwiftUI macOS app

**Files:**
- Create: `ios/SecretaryMacApp/project.yml`
- Create: `ios/SecretaryMacApp/SecretaryMac.entitlements`
- Create: `ios/SecretaryMacApp/Sources/MacVaultProvisioning.swift`
- Create: `ios/SecretaryMacApp/Sources/MacDeviceUnlockView.swift`
- Create: `ios/SecretaryMacApp/Sources/SecretaryMacApp.swift`
- Create: `ios/SecretaryMacApp/.gitignore`
- Create: `ios/scripts/build-macos-app.sh`

**Interfaces:**
- Consumes: `makePerVaultDeviceUnlock(vaultPath:)` and `DeviceUnlockViewModel(coordinator:vaultPath:vaultId:)` from Tasks 1–2.
- Produces: a `SecretaryMac` scheme that compiles for `platform=macOS`; consumed by Tasks 4–5.

- [ ] **Step 1: Create `.gitignore`**

`ios/SecretaryMacApp/.gitignore`:

```gitignore
# Generated by XcodeGen
*.xcodeproj
# Staged at build time from core/tests/data (never committed)
Fixtures/
```

- [ ] **Step 2: Create `MacVaultProvisioning.swift`**

Reproduces the iOS `AppVaultProvisioning` staging (bundle-read-only → writable Application Support copy; enroll mutates the vault). `applicationSupportDirectory` is macOS-available, so this is a direct port.

`ios/SecretaryMacApp/Sources/MacVaultProvisioning.swift`:

```swift
import Foundation

/// Stages a WRITABLE copy of the bundled read-only golden_vault_001 into
/// Application Support on first launch (the bundle is read-only; enroll/disenroll
/// mutate the vault). Never touches the bundled fixture. Idempotent.
enum MacVaultProvisioning {
    struct ProvisioningError: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    /// Returns the path to the writable staged vault, copying it on first call.
    static func stageGoldenVault() throws -> URL {
        let fm = FileManager.default
        let support = try fm.url(for: .applicationSupportDirectory,
                                 in: .userDomainMask, appropriateFor: nil, create: true)
        let dest = support.appendingPathComponent("golden_vault_001", isDirectory: true)
        if fm.fileExists(atPath: dest.path) { return dest }

        guard let bundled = Bundle.main.url(forResource: "golden_vault_001",
                                            withExtension: nil,
                                            subdirectory: "Fixtures") else {
            throw ProvisioningError(message: "golden_vault_001 not bundled — run ios/scripts/build-macos-app.sh")
        }
        try fm.copyItem(at: bundled, to: dest)
        return dest
    }

    /// The pinned vault_uuid (lowercase hex, no dashes) — used as `vaultId` so the
    /// post-open check (`session.vaultUuidHex == enrolledVaultId`) passes, and as
    /// the on-screen happy-path assertion.
    static func pinnedVaultUuidHex() throws -> String {
        guard let url = Bundle.main.url(forResource: "golden_vault_001_inputs",
                                        withExtension: "json",
                                        subdirectory: "Fixtures") else {
            throw ProvisioningError(message: "golden_vault_001_inputs.json not bundled")
        }
        let json = try JSONSerialization.jsonObject(with: Data(contentsOf: url))
        guard let dict = json as? [String: Any], let dashed = dict["vault_uuid"] as? String else {
            throw ProvisioningError(message: "vault_uuid missing from inputs JSON")
        }
        return dashed.replacingOccurrences(of: "-", with: "").lowercased()
    }
}
```

- [ ] **Step 3: Create `MacDeviceUnlockView.swift`**

Minimal screen over the shared `DeviceUnlockViewModel`. `vaultPath = Data(url.path.utf8)` — the exact encoding the iOS app uses (`SecretaryApp.swift:247`); no security-scoped bookmark because the skeleton is unsandboxed.

`ios/SecretaryMacApp/Sources/MacDeviceUnlockView.swift`:

```swift
import SwiftUI
import SecretaryDeviceUnlock
import SecretaryDeviceUnlockUI
import SecretaryKit

struct MacDeviceUnlockView: View {
    @StateObject private var model: DeviceUnlockViewModel
    @State private var password: String = ""
    private let setupError: String?

    init() {
        // Build the real per-vault device-unlock bundle over a staged vault.
        do {
            let vaultURL = try MacVaultProvisioning.stageGoldenVault()
            let vaultPath = Data(vaultURL.path.utf8)                    // same as SecretaryApp.swift:247
            let vaultId = try MacVaultProvisioning.pinnedVaultUuidHex()
            let bundle = makePerVaultDeviceUnlock(vaultPath: vaultPath)
            _model = StateObject(wrappedValue: DeviceUnlockViewModel(
                coordinator: bundle.coordinator, vaultPath: vaultPath, vaultId: vaultId))
            self.setupError = nil
        } catch {
            // Provisioning failed — show the error; VM is a harmless placeholder.
            let vaultPath = Data("<unprovisioned>".utf8)
            let bundle = makePerVaultDeviceUnlock(vaultPath: vaultPath)
            _model = StateObject(wrappedValue: DeviceUnlockViewModel(
                coordinator: bundle.coordinator, vaultPath: vaultPath, vaultId: "0"))
            self.setupError = error.localizedDescription
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Secretary — macOS device unlock (D.5.1)").font(.headline)
            if let setupError {
                Text("Setup error: \(setupError)").foregroundColor(.red)
            }
            Text("State: \(String(describing: model.state))")
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)

            SecureField("Vault password (to enroll)", text: $password)
                .frame(maxWidth: 320)

            HStack(spacing: 12) {
                Button("Enroll device slot") {
                    Task { await model.enroll(password: Array(password.utf8)); password = "" }
                }.disabled(password.isEmpty)

                Button("Unlock with Touch ID") {
                    Task { await model.unlock(reason: "Unlock your Secretary vault") }
                }
            }

            Button("Refresh status") { model.refreshStatus() }
        }
        .padding(24)
        .frame(minWidth: 440, minHeight: 260)
        .onAppear { model.refreshStatus() }
    }
}
```

- [ ] **Step 4: Create `SecretaryMacApp.swift`**

`ios/SecretaryMacApp/Sources/SecretaryMacApp.swift`:

```swift
import SwiftUI

@main
struct SecretaryMacApp: App {
    var body: some Scene {
        WindowGroup {
            MacDeviceUnlockView()
        }
        .windowResizability(.contentSize)
    }
}
```

- [ ] **Step 5: Create the entitlements file**

The macOS data-protection Keychain + Secure-Enclave key require the app be signed with an application-identifier and a keychain-access-group. (App Sandbox stays OFF — deferred to a later slice.)

`ios/SecretaryMacApp/SecretaryMac.entitlements`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>keychain-access-groups</key>
    <array>
        <string>$(AppIdentifierPrefix)com.secretary.macapp</string>
    </array>
</dict>
</plist>
```

- [ ] **Step 6: Create `project.yml`**

`ios/SecretaryMacApp/project.yml`:

```yaml
name: SecretaryMac
options:
  bundleIdPrefix: com.secretary
  deploymentTarget:
    macOS: "13.0"
  createIntermediateGroups: true
packages:
  SecretaryKit:
    path: ../SecretaryKit
  SecretaryDeviceUnlock:
    path: ../SecretaryDeviceUnlock
  SecretaryVaultAccess:
    path: ../SecretaryVaultAccess
targets:
  SecretaryMac:
    type: application
    platform: macOS
    sources:
      - path: Sources
      - path: Fixtures
        type: folder
        optional: true
    dependencies:
      - package: SecretaryKit
        product: SecretaryKit
      - package: SecretaryDeviceUnlock
        product: SecretaryDeviceUnlock
      - package: SecretaryDeviceUnlock
        product: SecretaryDeviceUnlockUI
    settings:
      base:
        PRODUCT_BUNDLE_IDENTIFIER: com.secretary.macapp
        GENERATE_INFOPLIST_FILE: "YES"
        MARKETING_VERSION: "0.1"
        CURRENT_PROJECT_VERSION: "1"
        # Swift 6 language mode — matches the #231 bar on every package.
        SWIFT_VERSION: "6.0"
        CODE_SIGN_STYLE: Automatic
        DEVELOPMENT_TEAM: "$(DEVELOPMENT_TEAM)"
        CODE_SIGN_ENTITLEMENTS: SecretaryMac.entitlements
        # Hardened runtime OFF for the dev skeleton (notarization is a later slice).
        ENABLE_HARDENED_RUNTIME: "NO"
```

- [ ] **Step 7: Create `build-macos-app.sh`**

Mirrors `build-app.sh`: ensures the XCFramework, stages the fixture under `Fixtures/`, generates the project, and does a signing-free compile proof for CI. (Real Touch ID is Task 6, run from Xcode with a signing team.)

`ios/scripts/build-macos-app.sh`:

```bash
#!/usr/bin/env bash
# Stage the demo vault, generate the Xcode project with XcodeGen, and build the
# SecretaryMac app for macOS (a signing-free compile proof for CI). Real Touch ID
# release is the manual proof in ios/SecretaryMacApp/MANUAL-PROOF.md (D.5.1).
#
# Secretary.xcframework is a prerequisite — build it (with its macOS slice) first.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
APP_DIR="$REPO_ROOT/ios/SecretaryMacApp"
RES_DIR="$APP_DIR/Fixtures"
XCFRAMEWORK="$REPO_ROOT/ios/Secretary.xcframework"

command -v xcodegen >/dev/null || { echo "ERROR: xcodegen not found — 'brew install xcodegen'"; exit 1; }

if [[ ! -d "$XCFRAMEWORK" ]]; then
    echo "==> Secretary.xcframework not found — running build-xcframework.sh first"
    bash "$SCRIPT_DIR/build-xcframework.sh"
fi

echo "==> stage golden_vault_001 fixture into the app bundle (Fixtures/)"
rm -rf "$RES_DIR"; mkdir -p "$RES_DIR"
cp -R "$REPO_ROOT/core/tests/data/golden_vault_001" "$RES_DIR/golden_vault_001"
cp "$REPO_ROOT/core/tests/data/golden_vault_001_inputs.json" "$RES_DIR/golden_vault_001_inputs.json"

echo "==> generate SecretaryMac.xcodeproj"
( cd "$APP_DIR" && xcodegen generate )

echo "==> build for macOS (no signing — compile proof)"
xcodebuild build \
  -project "$APP_DIR/SecretaryMac.xcodeproj" \
  -scheme SecretaryMac \
  -destination 'platform=macOS' \
  CODE_SIGNING_ALLOWED=NO
```

- [ ] **Step 8: Run the compile proof**

```bash
cd /Users/hherb/src/secretary/.worktrees/d5-macos-native
chmod +x ios/scripts/build-macos-app.sh
bash ios/scripts/build-macos-app.sh > /tmp/d51-macapp.log 2>&1 &
```

Poll `/tmp/d51-macapp.log`; expected final line: `** BUILD SUCCEEDED **`. If the compiler rejects a symbol in the app sources, fix it (the app imports only SwiftUI + the shared packages, all macOS-available).

- [ ] **Step 9: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/d5-macos-native
git add ios/SecretaryMacApp/ ios/scripts/build-macos-app.sh
git commit -m "feat(macos): minimal SwiftUI SecretaryMac app + macOS compile proof (D.5.1)" \
           -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: `run-macos-tests.sh` acceptance runner

**Files:**
- Create: `ios/scripts/run-macos-tests.sh`

**Interfaces:**
- Consumes: `build-xcframework.sh` (Task 1), `SecretaryKit` macOS host test (Task 2), `build-macos-app.sh` (Task 3).
- Produces: a single green/red acceptance command for D.5.1's automated portion.

- [ ] **Step 1: Create the runner**

Mirrors `run-ios-tests.sh` layering (fast host tests first, then the slow native build), but the Kit test runs on the **macOS host** via `swift test` — no simulator.

`ios/scripts/run-macos-tests.sh`:

```bash
#!/usr/bin/env bash
# Acceptance entry point for D.5.1: host-test the pure packages, build the
# Secretary.xcframework (incl. the macOS slice), host-test SecretaryKit on macOS,
# and compile-prove the SecretaryMac app. Exits non-zero on any failure.
#
# Real Touch ID / Secure-Enclave release is a manual proof — see
# ios/SecretaryMacApp/MANUAL-PROOF.md. Run from anywhere.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IOS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "ERROR: macOS builds require macOS (got $(uname -s))" >&2; exit 2
fi

# --- Step 1: host-run the pure packages (fast, no framework) ---
echo "==> swift test (pure SecretaryDeviceUnlock — host)"
( cd "$IOS_DIR/SecretaryDeviceUnlock" && swift test )
echo "==> swift test (pure SecretaryVaultAccess — host)"
( cd "$IOS_DIR/SecretaryVaultAccess" && swift test )

# --- Step 2: build the framework (incl. the macOS slice) + stage fixtures ---
echo "==> build-xcframework.sh"
bash "$SCRIPT_DIR/build-xcframework.sh"

# --- Step 3: host-test SecretaryKit on macOS (no simulator — the D.5.1 win) ---
echo "==> swift test (SecretaryKit — macOS host)"
( cd "$IOS_DIR/SecretaryKit" && swift test )

# --- Step 4: compile-prove the SecretaryMac app ---
echo "==> build the SecretaryMac app (XcodeGen + macOS compile proof)"
bash "$SCRIPT_DIR/build-macos-app.sh"

echo "==> D.5.1 automated acceptance: PASS"
```

- [ ] **Step 2: Run it end-to-end (backgrounded)**

```bash
cd /Users/hherb/src/secretary/.worktrees/d5-macos-native
chmod +x ios/scripts/run-macos-tests.sh
bash ios/scripts/run-macos-tests.sh > /tmp/d51-run.log 2>&1 &
```

Poll `/tmp/d51-run.log`; expected final line: `==> D.5.1 automated acceptance: PASS`.

- [ ] **Step 3: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/d5-macos-native
git add ios/scripts/run-macos-tests.sh
git commit -m "test(macos): add run-macos-tests.sh layered acceptance runner (D.5.1)" \
           -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Manual on-Mac Touch ID proof (acceptance milestone)

**Files:**
- Create: `ios/SecretaryMacApp/MANUAL-PROOF.md`

This task's deliverable is the **documented, reproducible on-hardware procedure** plus a recorded PASS. It is manual because real Touch ID / Secure Enclave cannot be exercised in CI (mirrors the iOS #202 proof).

- [ ] **Step 1: Write the procedure doc**

`ios/SecretaryMacApp/MANUAL-PROOF.md`:

````markdown
# D.5.1 manual proof — Touch ID / Secure Enclave on macOS

Proves `open_with_device_secret` on a real Apple Silicon Mac with Touch ID.
Equivalent to the iOS #202 proof.

## Prereqs
- Apple Silicon Mac (M1+) with Touch ID, macOS 13+.
- Xcode signed in to an Apple Developer team.
- `brew install xcodegen`.

## Steps
1. Build the framework + generate the project:
   ```bash
   DEVELOPMENT_TEAM=<YOUR_TEAM_ID> bash ios/scripts/build-macos-app.sh
   ```
2. Open `ios/SecretaryMacApp/SecretaryMac.xcodeproj` in Xcode.
3. Select the `SecretaryMac` scheme, destination **My Mac**. Under
   Signing & Capabilities, confirm your team is selected (Automatic signing).
4. Run (⌘R).
5. In the window, type the **golden_vault_001 test password** (see
   `core/tests/data/golden_vault_001_inputs.json`) and click **Enroll device slot**.
   Expect `State: enrolled`.
6. Quit and relaunch the app (⌘R again) — do NOT re-enroll.
7. Click **Unlock with Touch ID**. Authenticate at the Touch ID prompt.
   Expect `State: unlocked(vaultUuidHex: "<pinned uuid>")`.
8. Re-run, click Unlock, and **cancel** the Touch ID prompt. Expect the state to
   return to a `failed(userCancelled, …)` / silent case — **never**
   `wrappedSecretCorrupt`.

## PASS criteria
- [ ] Enroll → `enrolled`.
- [ ] Relaunch + Touch ID → `unlocked(vaultUuidHex:)` matching the pinned uuid.
- [ ] Cancel maps to the cancel path, not `wrappedSecretCorrupt`.

## Known pitfall — `errSecMissingEntitlement` (-34018)
If enroll fails with OSStatus **-34018**, the app is not signed with an
application-identifier the data-protection Keychain / Secure Enclave accepts.
Fix: ensure Automatic signing with a real team is selected (step 3) and that
`SecretaryMac.entitlements` (keychain-access-groups) is attached to the target.
This is expected on the first unsigned run and is why the manual proof runs from
Xcode with a team, not via the `CODE_SIGNING_ALLOWED=NO` CI compile proof.
````

- [ ] **Step 2: Execute the procedure on hardware and record the result**

Run the steps above on this Apple Silicon Mac. Check the three PASS boxes in the file if they hold. If a step fails, treat it as a real bug (systematic-debugging), not a doc edit.

- [ ] **Step 3: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/d5-macos-native
git add ios/SecretaryMacApp/MANUAL-PROOF.md
git commit -m "docs(macos): D.5.1 manual Touch ID proof procedure + result" \
           -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: ADR 0011 + ROADMAP row

**Files:**
- Create: `docs/adr/0011-macos-native-swiftui.md`
- Modify: `ROADMAP.md`

**Interfaces:**
- Consumes: the approved design (`docs/superpowers/specs/2026-07-15-macos-native-swiftui-client-design.md`).

- [ ] **Step 1: Write ADR 0011**

`docs/adr/0011-macos-native-swiftui.md`:

```markdown
# ADR 0011 — macOS gets a native SwiftUI client; Tauri macOS coexists then cuts over

**Status:** Accepted (2026-07-15)
**Supersedes:** none (extends ADR 0007 / 0008)
**Superseded by:** none

## Context

ADR 0007 made desktop (macOS/Linux/Windows) a Tauri universal client; ADR 0008
reverted *mobile* to native SwiftUI/Compose via uniffi because Tauri had no
first-party hardware-backed key storage and its biometric plugin is a gate, not
a key binding. Modern Macs (Apple Silicon, T2 Intel) have a Secure Enclave and
Touch ID, so the moment enclave-backed, biometric-bound key release is a macOS
requirement, ADR 0008's reasoning transfers from mobile to Mac verbatim.

## Decision

macOS gets a **native SwiftUI client**, branched from the iOS app, consuming
`secretary-core` through a macOS slice of the uniffi XCFramework, using the
Secure Enclave + Touch ID for hardware-backed, biometric-bound key release.

It **coexists** with the shipped Tauri macOS build (which stays on the
password/recovery desktop tier) until the native app reaches feature parity plus
an on-device biometric proof, at which point macOS **cuts over** to native and
Tauri narrows to Linux + Windows.

## Consequences

- The iOS device-unlock work (`SecretaryDeviceUnlock`, the SE conformer) is
  reused on Mac; only the XCFramework arch, `SecretaryKit` platform, and a Mac
  SwiftUI shell are net-new.
- A native Mac UI diverges from the Tauri Linux/Windows UI; mitigated by the
  Rust core remaining the single source of truth.
- Secrets cross the uniffi boundary into Swift on Mac (as on mobile); the
  wrapping key stays hardware-protected in the enclave — which Tauri could not
  match. Accepted at the UI tier.

## Alternatives considered

- **Extend the Tauri app to the Mac App Store.** Rejected for the enclave
  requirement (same alpha-plugin/bespoke-shim problem as ADR 0008); remains the
  right choice for the desktop tier and macOS until cutover.
- **Mac Catalyst.** Not chosen: carries iOS UIKit idioms; a native SwiftUI macOS
  target reusing the shared packages is cleaner with the same enclave access.
```

- [ ] **Step 2: Add the D.5 row to `ROADMAP.md`**

Find the Sub-project D section and add, in the same style as the surrounding rows:

```markdown
- **D.5 — native macOS client (SwiftUI via uniffi).** Touch ID / Secure Enclave
  unlock, coexisting with the Tauri macOS build then cutting over (ADR 0011).
  D.5.1 (enclave walking skeleton) is the current slice.
```

(Match the exact heading/list format already used in that section; do not invent a new one.)

- [ ] **Step 3: Verify doc links stay warning-clean**

The new ADR is Markdown (not rustdoc), but confirm nothing else regressed:

```bash
cd /Users/hherb/src/secretary/.worktrees/d5-macos-native
ls docs/adr/0011-macos-native-swiftui.md && grep -q "D.5" ROADMAP.md && echo "OK"
```

Expected: `OK`.

- [ ] **Step 4: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/d5-macos-native
git add docs/adr/0011-macos-native-swiftui.md ROADMAP.md
git commit -m "docs(adr): ADR 0011 — native macOS SwiftUI client + D.5 roadmap row" \
           -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Done criteria (maps to spec §7)

1. ✅ Task 1 — XCFramework has a macOS slice; iOS slices still build.
2. ✅ Task 2 — `SecretaryKit` is `.macOS(.v13)`, builds for macOS, iOS stays green.
3. ✅ Task 2 — `SecretaryKit` host-builds via `swift test` on macOS.
4. ✅ Task 4 — `run-macos-tests.sh` runs Tasks 1–3 + app compile green.
5. ✅ Task 5 — real Touch-ID enroll → relaunch → `open_with_device_secret`; cancel maps to the typed cancel path.
6. ✅ All tasks — no change to `secretary-core`, `.udl`, or `FfiVaultError`.
7. ✅ Task 6 — ADR 0011 written and cross-links the spec.
```
