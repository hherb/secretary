# iOS app walking-skeleton + on-device #202 biometric proof — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the first runnable iOS app — a minimal SwiftUI walking-skeleton driving the real B.3 device-unlock flow — and use it on a physical iPhone 13 Pro Max to close #202 with an on-device Secure-Enclave / Face ID biometric proof.

**Architecture:** Pure, host-testable `DeviceUnlockViewModel` (a new `SecretaryDeviceUnlockUI` product in the existing FFI-free package) + a thin SwiftUI shell + the real `DeviceUnlockCoordinator` (real SE store + uniffi port + Keychain) wired at the `@main` entry point. The Xcode app target is managed declaratively via XcodeGen (`project.yml` checked in; generated `.xcodeproj` gitignored).

**Tech Stack:** Swift 5.9 / SwiftUI, SwiftPM (local packages), XcodeGen, `xcodebuild`, the existing `Secretary.xcframework` (uniffi). No Rust / on-disk-format / FFI-surface change.

**Spec:** [docs/superpowers/specs/2026-06-11-ios-app-device-unlock-design.md](../specs/2026-06-11-ios-app-device-unlock-design.md)

**Working directory:** worktree `.worktrees/ios-app-device-unlock` on branch `feature/ios-app-device-unlock`. All paths below are repo-relative. Verify with `pwd && git branch --show-current` before path-sensitive commands.

---

## File structure

| File | Responsibility | Task |
|---|---|---|
| `ios/SecretaryDeviceUnlock/Sources/SecretaryDeviceUnlock/DeviceSecretEnclave.swift` | **Modify** — add `lastReleaseDiagnostic` protocol member + default-nil extension | 1 |
| `ios/SecretaryDeviceUnlock/Sources/SecretaryDeviceUnlock/DeviceUnlockCoordinator.swift` | **Modify** — add `lastReleaseDiagnostic` passthrough | 1 |
| `ios/SecretaryDeviceUnlock/Sources/SecretaryDeviceUnlockTesting/InMemoryDeviceSecretEnclave.swift` | **Modify** — injectable `releaseDiagnostic` | 1 |
| `ios/SecretaryDeviceUnlock/Package.swift` | **Modify** — add `SecretaryDeviceUnlockUI` lib + test targets | 2 |
| `ios/SecretaryDeviceUnlock/Sources/SecretaryDeviceUnlockUI/DeviceUnlockState.swift` | Pure UI state enum | 2 |
| `ios/SecretaryDeviceUnlock/Sources/SecretaryDeviceUnlockUI/DeviceUnlockViewModel.swift` | `@MainActor` state machine over the coordinator | 3, 4 |
| `ios/SecretaryDeviceUnlock/Tests/SecretaryDeviceUnlockUITests/DeviceUnlockViewModelTests.swift` | Host tests for the ViewModel | 3, 4 |
| `ios/SecretaryApp/project.yml` | XcodeGen manifest (app target `Secretary`) | 5 |
| `ios/SecretaryApp/.gitignore` | Ignore generated `Secretary.xcodeproj` + staged `Resources/` | 5 |
| `ios/SecretaryApp/Sources/SecretaryApp.swift` | `@main` App — wiring | 5, 7 |
| `ios/SecretaryApp/Sources/DeviceUnlockScreen.swift` | Thin SwiftUI shell | 7 |
| `ios/SecretaryApp/Sources/AppVaultProvisioning.swift` | Stage a writable vault copy | 7 |
| `ios/SecretaryKit/Sources/SecretaryKit/DeviceUnlock/SecureEnclaveDeviceSecretStore.swift` | **Modify** — populate `lastReleaseDiagnostic` (taxonomy capture) | 6 |
| `ios/scripts/build-app.sh` | Stage resources, XcodeGen generate, simulator build | 5 |
| `ios/scripts/run-ios-tests.sh` | **Modify** — also build the app | 8 |
| `ios/README.md`, root `README.md`, `ROADMAP.md` | **Modify** — status + the new app/proof | 8 |
| `docs/handoffs/2026-06-11-ios-app-device-unlock-shipped.md` + `NEXT_SESSION.md` symlink | Handoff baton + the captured taxonomy | 9 |

---

### Task 1: `lastReleaseDiagnostic` plumbing (pure package, host-tested)

**Files:**
- Modify: `ios/SecretaryDeviceUnlock/Sources/SecretaryDeviceUnlock/DeviceSecretEnclave.swift`
- Modify: `ios/SecretaryDeviceUnlock/Sources/SecretaryDeviceUnlock/DeviceUnlockCoordinator.swift`
- Modify: `ios/SecretaryDeviceUnlock/Sources/SecretaryDeviceUnlockTesting/InMemoryDeviceSecretEnclave.swift`
- Test: `ios/SecretaryDeviceUnlock/Tests/SecretaryDeviceUnlockTests/DiagnosticPassthroughTests.swift`

- [ ] **Step 1: Write the failing test**

Create `ios/SecretaryDeviceUnlock/Tests/SecretaryDeviceUnlockTests/DiagnosticPassthroughTests.swift`:

```swift
import XCTest
import SecretaryDeviceUnlock
import SecretaryDeviceUnlockTesting

final class DiagnosticPassthroughTests: XCTestCase {
    private func makeCoordinator(enclave: InMemoryDeviceSecretEnclave)
        -> DeviceUnlockCoordinator {
        DeviceUnlockCoordinator(
            slotPort: FakeVaultDeviceSlotPort(),
            enclave: enclave,
            metadata: InMemoryEnrollmentMetadataStore())
    }

    func testCoordinatorExposesEnclaveReleaseDiagnostic() {
        let enclave = InMemoryDeviceSecretEnclave()
        enclave.releaseDiagnostic = "domain=NSOSStatusErrorDomain code=-128 mappedTo=userCancelled"
        let coord = makeCoordinator(enclave: enclave)
        XCTAssertEqual(coord.lastReleaseDiagnostic,
                       "domain=NSOSStatusErrorDomain code=-128 mappedTo=userCancelled")
    }

    func testDiagnosticDefaultsToNil() {
        XCTAssertNil(makeCoordinator(enclave: InMemoryDeviceSecretEnclave()).lastReleaseDiagnostic)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ios/SecretaryDeviceUnlock && swift test --filter DiagnosticPassthroughTests`
Expected: FAIL — `value of type 'InMemoryDeviceSecretEnclave' has no member 'releaseDiagnostic'` / `'DeviceUnlockCoordinator' has no member 'lastReleaseDiagnostic'`.

- [ ] **Step 3: Add the protocol member + default**

In `DeviceSecretEnclave.swift`, add the member to the protocol (after `var isEnrolled: Bool { get }`) and a default-nil extension at the end of the file:

```swift
public protocol DeviceSecretEnclave {
    var isEnrolled: Bool { get }
    /// Raw diagnostic from the most recent `release` failure ("domain=… code=…
    /// mappedTo=…"), for a UI to surface so the real Security-framework taxonomy
    /// can be observed (#202). nil after a successful release.
    var lastReleaseDiagnostic: String? { get }
    /// Generate the hardware key if needed, wrap `secret`, persist the blob.
    /// Replaces any existing enrollment.
    func store(secret: [UInt8]) throws
    /// Biometric-gate, then release the secret. `async` because the real
    /// conformer drives an `LAContext` evaluation.
    func release(reason: String) async throws -> [UInt8]
    /// Delete the key + wrapped blob.
    func clear() throws
}

public extension DeviceSecretEnclave {
    /// Conformers that capture no diagnostic report none — keeps the member
    /// additive (existing conformers compile unchanged).
    var lastReleaseDiagnostic: String? { nil }
}
```

- [ ] **Step 4: Add the coordinator passthrough**

In `DeviceUnlockCoordinator.swift`, add inside the struct (after the `init`):

```swift
    /// The most recent release diagnostic from the enclave (raw domain+code on a
    /// biometric/decrypt failure), for a UI to surface. Read immediately after a
    /// failed `unlock`; nil after a successful release.
    public var lastReleaseDiagnostic: String? { enclave.lastReleaseDiagnostic }
```

- [ ] **Step 5: Override in the fake with an injectable value**

In `InMemoryDeviceSecretEnclave.swift`, add the stored property (after `public var releaseError: DeviceUnlockError?`) and the override:

```swift
    /// Injected value returned by `lastReleaseDiagnostic` (simulates the real
    /// store's captured domain+code). Default nil.
    public var releaseDiagnostic: String?
    public var lastReleaseDiagnostic: String? { releaseDiagnostic }
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd ios/SecretaryDeviceUnlock && swift test`
Expected: PASS — all existing tests + the 2 new ones (26 total).

- [ ] **Step 7: Commit**

```bash
git add ios/SecretaryDeviceUnlock
git commit -m "feat(app): lastReleaseDiagnostic hook for on-device taxonomy capture (#202)"
```

---

### Task 2: `SecretaryDeviceUnlockUI` target + `DeviceUnlockState`

**Files:**
- Modify: `ios/SecretaryDeviceUnlock/Package.swift`
- Create: `ios/SecretaryDeviceUnlock/Sources/SecretaryDeviceUnlockUI/DeviceUnlockState.swift`
- Test: `ios/SecretaryDeviceUnlock/Tests/SecretaryDeviceUnlockUITests/DeviceUnlockStateTests.swift`

- [ ] **Step 1: Add the targets to Package.swift**

Replace the `products:` and `targets:` arrays in `ios/SecretaryDeviceUnlock/Package.swift`:

```swift
    products: [
        .library(name: "SecretaryDeviceUnlock", targets: ["SecretaryDeviceUnlock"]),
        .library(name: "SecretaryDeviceUnlockUI", targets: ["SecretaryDeviceUnlockUI"]),
        .library(name: "SecretaryDeviceUnlockTesting", targets: ["SecretaryDeviceUnlockTesting"]),
    ],
    targets: [
        .target(name: "SecretaryDeviceUnlock"),
        .target(name: "SecretaryDeviceUnlockUI", dependencies: ["SecretaryDeviceUnlock"]),
        .target(name: "SecretaryDeviceUnlockTesting", dependencies: ["SecretaryDeviceUnlock"]),
        .testTarget(
            name: "SecretaryDeviceUnlockTests",
            dependencies: ["SecretaryDeviceUnlock", "SecretaryDeviceUnlockTesting"]
        ),
        .testTarget(
            name: "SecretaryDeviceUnlockUITests",
            dependencies: ["SecretaryDeviceUnlockUI", "SecretaryDeviceUnlockTesting"]
        ),
    ]
```

- [ ] **Step 2: Write the failing test**

Create `ios/SecretaryDeviceUnlock/Tests/SecretaryDeviceUnlockUITests/DeviceUnlockStateTests.swift`:

```swift
import XCTest
import SecretaryDeviceUnlock
@testable import SecretaryDeviceUnlockUI

final class DeviceUnlockStateTests: XCTestCase {
    func testStatesAreEquatable() {
        XCTAssertEqual(DeviceUnlockState.busy(.unlocking), .busy(.unlocking))
        XCTAssertNotEqual(DeviceUnlockState.busy(.unlocking), .busy(.enrolling))
        XCTAssertEqual(DeviceUnlockState.unlocked(vaultUuidHex: "ab"),
                       .unlocked(vaultUuidHex: "ab"))
        XCTAssertEqual(DeviceUnlockState.failed(.userCancelled, detail: "d"),
                       .failed(.userCancelled, detail: "d"))
        XCTAssertNotEqual(DeviceUnlockState.failed(.userCancelled, detail: "d"),
                          .failed(.userCancelled, detail: nil))
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd ios/SecretaryDeviceUnlock && swift test --filter DeviceUnlockStateTests`
Expected: FAIL — `no such module 'SecretaryDeviceUnlockUI'` / `cannot find 'DeviceUnlockState'`.

- [ ] **Step 4: Create the state enum**

Create `ios/SecretaryDeviceUnlock/Sources/SecretaryDeviceUnlockUI/DeviceUnlockState.swift`:

```swift
import SecretaryDeviceUnlock

/// What the ViewModel is currently doing — drives the spinner + disables buttons.
public enum Activity: Equatable {
    case enrolling, unlocking, disenrolling
}

/// The single observable state of the device-unlock screen. Pure value type so
/// the ViewModel is fully host-testable.
public enum DeviceUnlockState: Equatable {
    /// Before the first status refresh.
    case idle
    case notEnrolled
    /// Enrolled, not yet unlocked this session.
    case enrolled
    case busy(Activity)
    /// Happy path — the opened vault's uuid as lowercase hex.
    case unlocked(vaultUuidHex: String)
    /// Typed failure + the raw domain+code detail (nil when not applicable).
    case failed(DeviceUnlockError, detail: String?)
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd ios/SecretaryDeviceUnlock && swift test --filter DeviceUnlockStateTests`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add ios/SecretaryDeviceUnlock
git commit -m "feat(app): SecretaryDeviceUnlockUI target + DeviceUnlockState enum"
```

---

### Task 3: `DeviceUnlockViewModel` — status + enroll

**Files:**
- Create: `ios/SecretaryDeviceUnlock/Sources/SecretaryDeviceUnlockUI/DeviceUnlockViewModel.swift`
- Test: `ios/SecretaryDeviceUnlock/Tests/SecretaryDeviceUnlockUITests/DeviceUnlockViewModelTests.swift`

- [ ] **Step 1: Write the failing tests**

Create `ios/SecretaryDeviceUnlock/Tests/SecretaryDeviceUnlockUITests/DeviceUnlockViewModelTests.swift`:

```swift
import XCTest
import SecretaryDeviceUnlock
import SecretaryDeviceUnlockTesting
@testable import SecretaryDeviceUnlockUI

@MainActor
final class DeviceUnlockViewModelTests: XCTestCase {
    private let pw: [UInt8] = Array("pw".utf8)

    private func makeVM(
        port: FakeVaultDeviceSlotPort = FakeVaultDeviceSlotPort(),
        enclave: InMemoryDeviceSecretEnclave = InMemoryDeviceSecretEnclave(),
        metadata: InMemoryEnrollmentMetadataStore = InMemoryEnrollmentMetadataStore()
    ) -> DeviceUnlockViewModel {
        let coord = DeviceUnlockCoordinator(slotPort: port, enclave: enclave, metadata: metadata)
        return DeviceUnlockViewModel(coordinator: coord, vaultPath: Data("p".utf8), vaultId: "v")
    }

    func testRefreshStatusNotEnrolled() {
        let vm = makeVM()
        vm.refreshStatus()
        XCTAssertEqual(vm.state, .notEnrolled)
    }

    func testEnrollSuccess() async {
        let vm = makeVM()
        await vm.enroll(password: pw)
        XCTAssertEqual(vm.state, .enrolled)
    }

    func testEnrollFailureSurfacesTypedError() async {
        let port = FakeVaultDeviceSlotPort(addResult: .failure(.invalidArgument("bad")))
        let vm = makeVM(port: port)
        await vm.enroll(password: pw)
        XCTAssertEqual(vm.state, .failed(.vault(.invalidArgument("bad")), detail: nil))
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd ios/SecretaryDeviceUnlock && swift test --filter DeviceUnlockViewModelTests`
Expected: FAIL — `cannot find 'DeviceUnlockViewModel'`.

- [ ] **Step 3: Create the ViewModel (status + enroll only for now)**

Create `ios/SecretaryDeviceUnlock/Sources/SecretaryDeviceUnlockUI/DeviceUnlockViewModel.swift`:

```swift
import Foundation
import Combine
import SecretaryDeviceUnlock

/// Drives the device-unlock screen. Holds only the (injected) coordinator, so it
/// is fully host-testable with the in-memory fakes. `@MainActor` because it
/// publishes UI state; the heavy password KDF at `enroll` briefly blocks the
/// main actor (acceptable for the walking-skeleton — a background-offload
/// refinement is a noted follow-up).
@MainActor
public final class DeviceUnlockViewModel: ObservableObject {
    @Published public private(set) var state: DeviceUnlockState = .idle

    private let coordinator: DeviceUnlockCoordinator
    private let vaultPath: Data
    private let vaultId: String

    public init(coordinator: DeviceUnlockCoordinator, vaultPath: Data, vaultId: String) {
        self.coordinator = coordinator
        self.vaultPath = vaultPath
        self.vaultId = vaultId
    }

    /// Synchronous, prompt-free status check (no biometric).
    public func refreshStatus() {
        state = coordinator.isEnrolled ? .enrolled : .notEnrolled
    }

    public func enroll(password: [UInt8]) async {
        state = .busy(.enrolling)
        do {
            try coordinator.enroll(vaultPath: vaultPath, vaultId: vaultId, password: password)
            state = .enrolled
        } catch {
            state = .failed(asDeviceUnlockError(error), detail: nil)
        }
    }

    /// The coordinator surfaces `DeviceUnlockError` for enclave/slot failures and
    /// rethrows the metadata store's untyped error as-is; wrap the latter so the
    /// UI always has a typed case to render.
    private func asDeviceUnlockError(_ error: Error) -> DeviceUnlockError {
        (error as? DeviceUnlockError) ?? .enclave(String(describing: error))
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd ios/SecretaryDeviceUnlock && swift test --filter DeviceUnlockViewModelTests`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryDeviceUnlock
git commit -m "feat(app): DeviceUnlockViewModel status + enroll"
```

---

### Task 4: `DeviceUnlockViewModel` — unlock + disenroll

**Files:**
- Modify: `ios/SecretaryDeviceUnlock/Sources/SecretaryDeviceUnlockUI/DeviceUnlockViewModel.swift`
- Test: `ios/SecretaryDeviceUnlock/Tests/SecretaryDeviceUnlockUITests/DeviceUnlockViewModelTests.swift`

- [ ] **Step 1: Add the failing tests**

Append inside `DeviceUnlockViewModelTests`:

```swift
    func testUnlockSuccessShowsVaultUuidHex() async {
        // Default fake open returns vaultUuid = 16 × 0xEF. The enclave must hold a
        // secret, else `release` throws .notEnrolled before the open is reached.
        let enclave = InMemoryDeviceSecretEnclave()
        try? enclave.store(secret: Array(repeating: 0xCD, count: 32))
        let metadata = InMemoryEnrollmentMetadataStore(
            enrollment: DeviceEnrollment(vaultId: "v", deviceUuid: Array(repeating: 0xAB, count: 16)))
        let vm = makeVM(enclave: enclave, metadata: metadata)
        await vm.unlock(reason: "Unlock")
        XCTAssertEqual(vm.state, .unlocked(vaultUuidHex: String(repeating: "ef", count: 16)))
    }

    func testUnlockFailureCarriesReleaseDiagnostic() async {
        let enclave = InMemoryDeviceSecretEnclave()
        enclave.releaseError = .userCancelled
        enclave.releaseDiagnostic = "domain=NSOSStatusErrorDomain code=-128 mappedTo=userCancelled"
        let metadata = InMemoryEnrollmentMetadataStore(
            enrollment: DeviceEnrollment(vaultId: "v", deviceUuid: Array(repeating: 0xAB, count: 16)))
        let vm = makeVM(enclave: enclave, metadata: metadata)
        await vm.unlock(reason: "Unlock")
        XCTAssertEqual(
            vm.state,
            .failed(.userCancelled,
                    detail: "domain=NSOSStatusErrorDomain code=-128 mappedTo=userCancelled"))
    }

    func testUnlockNotEnrolled() async {
        let vm = makeVM()  // empty metadata
        await vm.unlock(reason: "Unlock")
        XCTAssertEqual(vm.state, .failed(.notEnrolled, detail: nil))
    }

    func testDisenrollReturnsToNotEnrolled() async {
        let metadata = InMemoryEnrollmentMetadataStore(
            enrollment: DeviceEnrollment(vaultId: "v", deviceUuid: Array(repeating: 0xAB, count: 16)))
        let enclave = InMemoryDeviceSecretEnclave()
        try? enclave.store(secret: Array(repeating: 0xCD, count: 32))
        let vm = makeVM(enclave: enclave, metadata: metadata)
        await vm.disenroll()
        XCTAssertEqual(vm.state, .notEnrolled)
    }
```

Note: `testUnlockNotEnrolled` expects `detail: nil` — the not-enrolled guard trips before any release, so `lastReleaseDiagnostic` is nil on the fresh fake. `testUnlockFailureCarriesReleaseDiagnostic` expects the injected diagnostic because the release path runs and fails.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd ios/SecretaryDeviceUnlock && swift test --filter DeviceUnlockViewModelTests`
Expected: FAIL — `value of type 'DeviceUnlockViewModel' has no member 'unlock'` / `'disenroll'`.

- [ ] **Step 3: Add `unlock` + `disenroll`**

In `DeviceUnlockViewModel.swift`, add after `enroll`:

```swift
    public func unlock(reason: String) async {
        state = .busy(.unlocking)
        do {
            let opened = try await coordinator.unlock(
                vaultPath: vaultPath, vaultId: vaultId, reason: reason)
            let hex = opened.vaultUuid.map { String(format: "%02x", $0) }.joined()
            opened.wipe()  // release the opened vault's secret material immediately
            state = .unlocked(vaultUuidHex: hex)
        } catch {
            // Read the diagnostic right after the failed release (synchronous on
            // the main actor — no interleaving).
            state = .failed(asDeviceUnlockError(error),
                            detail: coordinator.lastReleaseDiagnostic)
        }
    }

    public func disenroll() async {
        state = .busy(.disenrolling)
        do {
            try coordinator.disenroll(vaultPath: vaultPath)
            state = .notEnrolled
        } catch {
            state = .failed(asDeviceUnlockError(error), detail: nil)
        }
    }
```

- [ ] **Step 4: Run the whole pure-package suite**

Run: `cd ios/SecretaryDeviceUnlock && swift test`
Expected: PASS — 26 (Task 1) + state (1) + ViewModel (7) tests all green.

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryDeviceUnlock
git commit -m "feat(app): DeviceUnlockViewModel unlock + disenroll, with release diagnostic"
```

---

### Task 5: XcodeGen app target that builds on the simulator

**Files:**
- Create: `ios/SecretaryApp/project.yml`
- Create: `ios/SecretaryApp/.gitignore`
- Create: `ios/SecretaryApp/Sources/SecretaryApp.swift` (minimal placeholder UI — fleshed out in Task 7)
- Create: `ios/scripts/build-app.sh`

- [ ] **Step 1: Ensure XcodeGen is installed**

Run: `command -v xcodegen || brew install xcodegen`
Expected: a path to `xcodegen` (installs if missing).

- [ ] **Step 2: Write the XcodeGen manifest**

Create `ios/SecretaryApp/project.yml`:

```yaml
name: Secretary
options:
  bundleIdPrefix: com.secretary
  deploymentTarget:
    iOS: "17.0"
  createIntermediateGroups: true
packages:
  SecretaryKit:
    path: ../SecretaryKit
  SecretaryDeviceUnlock:
    path: ../SecretaryDeviceUnlock
targets:
  Secretary:
    type: application
    platform: iOS
    sources:
      - path: Sources
      - path: Resources
        type: folder
        optional: true
    dependencies:
      - package: SecretaryKit
        product: SecretaryKit
      - package: SecretaryDeviceUnlock
        product: SecretaryDeviceUnlockUI
    settings:
      base:
        PRODUCT_BUNDLE_IDENTIFIER: com.secretary.app
        GENERATE_INFOPLIST_FILE: "YES"
        INFOPLIST_KEY_NSFaceIDUsageDescription: "Unlock your Secretary vault with Face ID."
        INFOPLIST_KEY_UILaunchScreen_Generation: "YES"
        TARGETED_DEVICE_FAMILY: "1,2"
        CODE_SIGN_STYLE: Automatic
        DEVELOPMENT_TEAM: "$(DEVELOPMENT_TEAM)"
        SWIFT_VERSION: "5.9"
```

`Resources` is `optional: true` so the project generates before `build-app.sh` stages the fixture; `type: folder` bundles `golden_vault_001/` as a directory (blue folder reference), preserving its structure.

- [ ] **Step 3: Write the .gitignore**

Create `ios/SecretaryApp/.gitignore`:

```gitignore
# Generated by XcodeGen — never committed (worktree/parallel-session hygiene).
Secretary.xcodeproj/
# Staged at build time from core/tests/data (see scripts/build-app.sh).
Resources/
```

- [ ] **Step 4: Write a minimal @main app (placeholder UI; real wiring in Task 7)**

Create `ios/SecretaryApp/Sources/SecretaryApp.swift`:

```swift
import SwiftUI

@main
struct SecretaryApp: App {
    var body: some Scene {
        WindowGroup {
            Text("Secretary — device unlock skeleton")
                .padding()
        }
    }
}
```

- [ ] **Step 5: Write build-app.sh**

Create `ios/scripts/build-app.sh`:

```bash
#!/usr/bin/env bash
# Stage the demo vault, generate the Xcode project with XcodeGen, and build the
# Secretary app for the iOS Simulator (a signing-free compile proof for CI).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
APP_DIR="$REPO_ROOT/ios/SecretaryApp"
RES_DIR="$APP_DIR/Resources"

command -v xcodegen >/dev/null || { echo "ERROR: xcodegen not found — 'brew install xcodegen'"; exit 1; }

echo "==> stage golden_vault_001 fixture into the app bundle resources"
rm -rf "$RES_DIR"
mkdir -p "$RES_DIR"
cp -R "$REPO_ROOT/core/tests/data/golden_vault_001" "$RES_DIR/golden_vault_001"
cp "$REPO_ROOT/core/tests/data/golden_vault_001_inputs.json" "$RES_DIR/golden_vault_001_inputs.json"

echo "==> generate Secretary.xcodeproj"
( cd "$APP_DIR" && xcodegen generate )

echo "==> build for the iOS Simulator (no signing)"
xcodebuild build \
  -project "$APP_DIR/Secretary.xcodeproj" \
  -scheme Secretary \
  -destination 'generic/platform=iOS Simulator' \
  CODE_SIGNING_ALLOWED=NO
```

- [ ] **Step 6: Run build-app.sh to verify it builds**

Run: `chmod +x ios/scripts/build-app.sh && bash ios/scripts/build-app.sh 2>&1 | tail -5`
Expected: `** BUILD SUCCEEDED **`.

- [ ] **Step 7: Commit**

```bash
git add ios/SecretaryApp/project.yml ios/SecretaryApp/.gitignore ios/SecretaryApp/Sources/SecretaryApp.swift ios/scripts/build-app.sh
git commit -m "feat(app): XcodeGen Secretary app target + simulator build script"
```

---

### Task 6: Real SE store populates `lastReleaseDiagnostic` (taxonomy capture)

**Files:**
- Modify: `ios/SecretaryKit/Sources/SecretaryKit/DeviceUnlock/SecureEnclaveDeviceSecretStore.swift`

This conformer is simulator/device-only (no host test); verification is the `xcodebuild build` plus the on-device proof in Task 9. Per the spec, the typed-case *mapping* is unchanged — only the diagnostic string is added.

- [ ] **Step 1: Add the stored diagnostic property**

In `SecureEnclaveDeviceSecretStore.swift`, add after the `algorithm` stored property:

```swift
    /// Raw diagnostic from the most recent `release` failure (domain+code +
    /// mapped case). Surfaced via the `DeviceSecretEnclave` protocol so the UI
    /// can display the real Security-framework taxonomy (#202). nil after success.
    public private(set) var lastReleaseDiagnostic: String?
```

- [ ] **Step 2: Clear it at the start of a release attempt and on success**

In `release(reason:)`, set it nil at entry, before `loadBlob`:

```swift
    public func release(reason: String) async throws -> [UInt8] {
        lastReleaseDiagnostic = nil
        guard let blob = try loadBlob() else { throw DeviceUnlockError.notEnrolled }
```

(The success path leaves it nil; only `mapDecryptError` sets it.)

- [ ] **Step 3: Record the diagnostic in mapDecryptError (all branches)**

Replace `mapDecryptError` so each return first records the raw detail. Change its signature to mutating-capable by recording into `self` before returning:

```swift
    private func mapDecryptError(_ error: Unmanaged<CFError>?) -> DeviceUnlockError {
        guard let cf = error?.takeRetainedValue() else {
            record(domain: "nil", code: 0, mappedTo: "wrappedSecretCorrupt")
            return .wrappedSecretCorrupt
        }
        let nsError = cf as Error as NSError
        let mapped = classify(nsError)
        record(domain: nsError.domain, code: nsError.code, mappedTo: "\(mapped)")
        return mapped
    }

    /// Pure classification (no side effects) — the mapping hardened in #214.
    private func classify(_ nsError: NSError) -> DeviceUnlockError {
        if nsError.domain == LAError.errorDomain {
            guard let code = LAError.Code(rawValue: nsError.code) else {
                return .enclave(nsError.localizedDescription)
            }
            switch code {
            case .biometryNotAvailable:                  return .biometryUnavailable
            case .biometryNotEnrolled:                   return .biometryNotEnrolled
            case .biometryLockout:                       return .biometryLockout
            case .userCancel, .appCancel, .systemCancel: return .userCancelled
            case .authenticationFailed:                  return .authenticationFailed
            default:                                     return .enclave(nsError.localizedDescription)
            }
        }
        if nsError.domain == NSOSStatusErrorDomain {
            switch nsError.code {
            case Int(errSecUserCanceled):                return .userCancelled
            case Int(errSecAuthFailed):                  return .authenticationFailed
            case Int(errSecNotAvailable),
                 Int(errSecInteractionNotAllowed):       return .biometryUnavailable
            default:                                     return .enclave(nsError.localizedDescription)
            }
        }
        return .enclave(nsError.localizedDescription)
    }

    private func record(domain: String, code: Int, mappedTo: String) {
        lastReleaseDiagnostic = "domain=\(domain) code=\(code) mappedTo=\(mappedTo)"
    }
```

This preserves the exact typed mapping from #214 (now in `classify`) and adds only the diagnostic capture.

- [ ] **Step 4: Build to verify it compiles**

Run: `cd ios/SecretaryKit && xcodebuild build -scheme SecretaryKit -destination 'generic/platform=iOS Simulator' 2>&1 | tail -3`
Expected: `** BUILD SUCCEEDED **`.

- [ ] **Step 5: Re-run the SecretaryKit simulator integration test (unchanged behaviour)**

Run: `bash ios/scripts/run-ios-tests.sh 2>&1 | tail -5`
Expected: host 26 + UI tests + simulator 3/3 → `** TEST SUCCEEDED **`. (The integration test uses the fake enclave, so the real store's new field is not exercised here — that is Task 9.)

- [ ] **Step 6: Commit**

```bash
git add ios/SecretaryKit/Sources/SecretaryKit/DeviceUnlock/SecureEnclaveDeviceSecretStore.swift
git commit -m "feat(app): SE store records raw domain+code diagnostic for #202 taxonomy"
```

---

### Task 7: Wire the app — vault provisioning + real coordinator + screen

**Files:**
- Create: `ios/SecretaryApp/Sources/AppVaultProvisioning.swift`
- Create: `ios/SecretaryApp/Sources/DeviceUnlockScreen.swift`
- Modify: `ios/SecretaryApp/Sources/SecretaryApp.swift`

- [ ] **Step 1: Vault provisioning helper**

Create `ios/SecretaryApp/Sources/AppVaultProvisioning.swift`:

```swift
import Foundation

/// Stages a WRITABLE copy of the bundled read-only golden_vault_001 into the app
/// sandbox on first launch (the bundle is read-only; enroll/disenroll mutate the
/// vault). Never touches the bundled fixture. Idempotent.
enum AppVaultProvisioning {
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

        guard let bundled = Bundle.main.url(forResource: "golden_vault_001", withExtension: nil) else {
            throw ProvisioningError(message: "golden_vault_001 not bundled — run ios/scripts/build-app.sh")
        }
        try fm.copyItem(at: bundled, to: dest)
        return dest
    }

    /// The pinned vault_uuid (lowercase hex, no dashes) from the bundled inputs
    /// JSON, for the on-screen happy-path assertion.
    static func pinnedVaultUuidHex() throws -> String {
        guard let url = Bundle.main.url(forResource: "golden_vault_001_inputs", withExtension: "json") else {
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

- [ ] **Step 2: The thin SwiftUI screen**

Create `ios/SecretaryApp/Sources/DeviceUnlockScreen.swift`:

```swift
import SwiftUI
import SecretaryDeviceUnlock
import SecretaryDeviceUnlockUI

/// Thin shell: renders `viewModel.state` and forwards button taps. No logic.
struct DeviceUnlockScreen: View {
    @StateObject var viewModel: DeviceUnlockViewModel
    /// Pinned uuid for the happy-path match readout (nil if unavailable).
    let pinnedVaultUuidHex: String?
    @State private var password: String = "correct horse battery staple"

    private var isBusy: Bool { if case .busy = viewModel.state { return true } else { return false } }

    var body: some View {
        NavigationStack {
            Form {
                Section("Status") { Text(statusText).font(.callout.monospaced()) }

                Section("Demo vault password (enroll)") {
                    SecureField("password", text: $password)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                }

                Section {
                    Button("Enroll") { Task { await viewModel.enroll(password: Array(password.utf8)) } }
                    Button("Unlock (Face ID)") { Task { await viewModel.unlock(reason: "Unlock your Secretary vault") } }
                    Button("Disenroll", role: .destructive) { Task { await viewModel.disenroll() } }
                }
                .disabled(isBusy)

                if let detail = failureDetail {
                    Section("Last error detail (raw domain+code)") {
                        Text(detail).font(.footnote.monospaced()).foregroundStyle(.secondary)
                    }
                }
            }
            .navigationTitle("Secretary")
            .overlay { if isBusy { ProgressView() } }
            .onAppear { viewModel.refreshStatus() }
        }
    }

    private var statusText: String {
        switch viewModel.state {
        case .idle:               return "…"
        case .notEnrolled:        return "not enrolled"
        case .enrolled:           return "enrolled — ready to unlock"
        case .busy(let a):        return "busy: \(a)"
        case .unlocked(let hex):
            let match = pinnedVaultUuidHex.map { $0 == hex ? " ✅ matches pinned" : " ❌ MISMATCH" } ?? ""
            return "unlocked\nvault_uuid=\(hex)\(match)"
        case .failed(let err, _): return "failed: \(err)"
        }
    }

    private var failureDetail: String? {
        if case .failed(_, let detail) = viewModel.state { return detail }
        return nil
    }
}
```

- [ ] **Step 3: Real wiring at @main**

Replace `ios/SecretaryApp/Sources/SecretaryApp.swift`:

```swift
import SwiftUI
import SecretaryKit
import SecretaryDeviceUnlock
import SecretaryDeviceUnlockUI

@main
struct SecretaryApp: App {
    var body: some Scene {
        WindowGroup { RootView() }
    }
}

/// Builds the REAL coordinator (Secure Enclave + uniffi port + Keychain) over a
/// staged writable copy of golden_vault_001, or shows a provisioning error.
private struct RootView: View {
    var body: some View {
        switch Self.build() {
        case .success(let (vm, pinned)):
            DeviceUnlockScreen(viewModel: vm, pinnedVaultUuidHex: pinned)
        case .failure(let error):
            Text("Setup failed: \(error.localizedDescription)").padding()
        }
    }

    private static func build() -> Result<(DeviceUnlockViewModel, String?), Error> {
        do {
            let vaultURL = try AppVaultProvisioning.stageGoldenVault()
            let pinned = try? AppVaultProvisioning.pinnedVaultUuidHex()
            let coordinator = DeviceUnlockCoordinator(
                slotPort: UniffiVaultDeviceSlotPort(),
                enclave: SecureEnclaveDeviceSecretStore(),
                metadata: KeychainEnrollmentMetadataStore())
            let vm = DeviceUnlockViewModel(
                coordinator: coordinator,
                vaultPath: Data(vaultURL.path.utf8),
                vaultId: "golden")
            return .success((vm, pinned))
        } catch {
            return .failure(error)
        }
    }
}
```

Note: `@StateObject` is initialised from the passed instance; building the VM once in `build()` is acceptable for the skeleton (RootView is the app root, constructed once).

- [ ] **Step 4: Rebuild the app**

Run: `bash ios/scripts/build-app.sh 2>&1 | tail -5`
Expected: `** BUILD SUCCEEDED **`.

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryApp/Sources
git commit -m "feat(app): wire real coordinator + DeviceUnlockScreen + vault provisioning"
```

---

### Task 8: CI wiring + docs

**Files:**
- Modify: `ios/scripts/run-ios-tests.sh`
- Modify: `ios/README.md`, root `README.md`, `ROADMAP.md`

- [ ] **Step 1: Add the app build to run-ios-tests.sh**

At the end of `ios/scripts/run-ios-tests.sh` (after the simulator XCTest step), append:

```bash
echo "==> build the Secretary app (XcodeGen + simulator compile proof)"
bash "$(dirname "$0")/build-app.sh"
```

(Verify the surrounding script uses `set -e`; if not, add `|| exit 1`.)

- [ ] **Step 2: Run the full runner**

Run: `bash ios/scripts/run-ios-tests.sh 2>&1 | tail -8`
Expected: host tests + simulator XCTest `** TEST SUCCEEDED **` + app `** BUILD SUCCEEDED **`.

- [ ] **Step 3: Update docs**

In `ios/README.md`, under the status section, add a bullet describing `SecretaryApp/` (the XcodeGen walking-skeleton app driving enroll/unlock/disenroll via the real coordinator) and the `build-app.sh` step. In root `README.md` and `ROADMAP.md`, mark the iOS app walking-skeleton ✅ and note #202's on-device biometric proof as the remaining manual step (closed in Task 9). Keep entries brief (dot points) per the README style.

- [ ] **Step 4: Commit**

```bash
git add ios/scripts/run-ios-tests.sh ios/README.md README.md ROADMAP.md
git commit -m "docs(app): wire app build into the iOS runner; README/ROADMAP updates"
```

---

### Task 9: On-device biometric proof (closes #202) + handoff

**Files:**
- Create: `docs/handoffs/2026-06-11-ios-app-device-unlock-shipped.md`
- Modify: `NEXT_SESSION.md` (retarget symlink)

This task is **manual** and run together with the user (the physical Face ID interaction cannot be automated). It produces the evidence that closes #202.

- [ ] **Step 1: Find the device UDID**

Run: `xcrun xctrace list devices 2>&1 | grep -i iphone`
Expected: the iPhone 13 Pro Max with its UDID. Record it as `DEVICE_UDID`.

- [ ] **Step 2: Generate the project with the signing team and deploy to the device**

Run (substituting the team id; obtain via `security find-identity -v -p codesigning` or Xcode → Settings → Accounts):

```bash
bash ios/scripts/build-app.sh   # stage resources + generate the project
xcodebuild -project ios/SecretaryApp/Secretary.xcodeproj -scheme Secretary \
  -destination "platform=iOS,id=<DEVICE_UDID>" -allowProvisioningUpdates \
  DEVELOPMENT_TEAM=<TEAMID> build
```

(Passing `DEVELOPMENT_TEAM` as a build setting overrides the `$(DEVELOPMENT_TEAM)`
passthrough in `project.yml`, so the device build signs without editing the manifest.)

If automatic signing fails, open `ios/SecretaryApp/Secretary.xcodeproj` in Xcode once, select the team, and run on the device. Record any signing steps needed.

- [ ] **Step 3: Run the proof on the device and record the taxonomy**

Drive the app on the iPhone and fill in this table (paste real values into the handoff):

| Action | Expected state | Observed state | Observed `domain`/`code` |
|---|---|---|---|
| Enroll (correct password) | `enrolled` | | (n/a) |
| Unlock → match Face ID | `unlocked`, uuid ✅ matches pinned | | (n/a) |
| Unlock → cancel the prompt | `failed(userCancelled)` | | |
| Unlock → non-matching face ×N | `failed(authenticationFailed)` | | |
| Unlock → trigger lockout | `failed(biometryLockout)` | | |
| Disenroll | `notEnrolled` | | (n/a) |

- [ ] **Step 4: Reconcile the taxonomy with the #214 mapping**

If any observed `domain`/`code` maps to a *different* typed case than `classify` chose (Task 6), note it. If a tightening is warranted, open a one-line follow-up issue (do not silently change the mapping here). If everything matches, state that `751d542`'s `NSOSStatusErrorDomain` choices are device-confirmed.

- [ ] **Step 5: Author the handoff + retarget the symlink**

Write `docs/handoffs/2026-06-11-ios-app-device-unlock-shipped.md` capturing: what shipped (with commit SHAs), the filled taxonomy table, #202 closure status, what's next with acceptance criteria, open risks, and the exact resume commands. Then:

```bash
ln -snf docs/handoffs/2026-06-11-ios-app-device-unlock-shipped.md NEXT_SESSION.md
ls -la NEXT_SESSION.md   # shows the -> target
git add docs/handoffs/2026-06-11-ios-app-device-unlock-shipped.md NEXT_SESSION.md
git commit -m "docs: handoff — iOS app walking-skeleton + #202 on-device proof"
```

- [ ] **Step 6: Push + open the PR**

```bash
git push -u origin feature/ios-app-device-unlock
gh pr create --title "iOS app walking-skeleton + on-device #202 biometric proof" \
  --body "<summary + the taxonomy table + 'Closes #202' if the on-device proof passed>"
```

---

## Self-review notes

- **Spec coverage:** §3.1 ViewModel → Tasks 3–4; §3.2 screen → Task 7; §3.3 wiring/provisioning → Task 7; §3.4 + `lastReleaseDiagnostic` → Tasks 1 & 6; XcodeGen/app target §3 + §4 → Task 5; §6 automated acceptance → Tasks 4/6/8; §6 manual proof + #202 → Task 9; docs → Task 8.
- **No host test for `SecureEnclaveDeviceSecretStore`** is intentional (simulator/device-only, per spec §1/§7) — verified by build + the Task 9 device proof.
- **Type consistency:** `DeviceUnlockState` / `Activity` / `DeviceUnlockViewModel(coordinator:vaultPath:vaultId:)` / `lastReleaseDiagnostic` used identically across Tasks 1–7. Fake APIs (`addResult`, `releaseError`, `releaseDiagnostic`, default `vaultUuid = 16×0xEF`) match the shipped fakes.
- **Concurrency note:** the `@MainActor` ViewModel awaits the synchronous, CPU-heavy `enroll` directly (brief main-actor block) — documented as an accepted skeleton tradeoff with a background-offload follow-up.
