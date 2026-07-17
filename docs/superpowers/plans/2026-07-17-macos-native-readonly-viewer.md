# D.5.2 — macOS Native Read-Only Vault Viewer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Grow the macOS app from the D.5.1 device-unlock skeleton into a usable read-only vault viewer with the iOS-parity flow select → unlock → browse.

**Architecture:** A fresh macOS `MacRootView` state machine (`.select | .unlock | .browse`) presents macOS-idiomatic SwiftUI views over the *already-built, host-tested* shared view models (`VaultSelectionViewModel`, `UnlockViewModel`, `VaultBrowseViewModel`). Only two pieces are genuinely new: a plain-path `FileVaultLocationStore` (FFI-free, host-tested) and the relocation of the reauth-gate factory into SecretaryKit. The rest is presentation.

**Tech Stack:** Swift 6 (language mode), SwiftUI (macOS 13+), AppKit (`NSOpenPanel`, `NSPasteboard`, `NSApplication` notifications), XcodeGen, SwiftPM packages (`SecretaryVaultAccess`, `SecretaryKit`, `SecretaryDeviceUnlock`), the uniffi `Secretary.xcframework` (macos-arm64 slice).

## Global Constraints

- **Design source of truth:** `docs/superpowers/specs/2026-07-17-macos-native-readonly-viewer-design.md`. Non-goals there are binding (no mutation UI, no Settings, no sync UI/monitor, no App Sandbox/bookmarks, no notarization, no Intel, no auto-lock timeout, no privacy cover).
- **No `core` / `.udl` / `FfiVaultError` / on-disk-format change.** No new FFI surface. If any Rust file is touched (none expected), re-run the full cargo gate set.
- **Swift 6 language mode** on every target (`SWIFT_VERSION: "6.0"`): a non-`Sendable` value crossing a `@MainActor`/actor boundary is a hard compile error. All view models are `@MainActor`.
- **Apple Silicon only** (`aarch64-apple-darwin` / `macos-arm64`); macOS deployment target 13.0.
- **Read-only:** wire NO mutation controls (no delete/restore/move/edit/create-block buttons). `VaultBrowseViewModel.reveal()` never routes through the reauth gate — only writes do — so the read-only viewer never triggers re-auth.
- **Secrets discipline:** the location store persists folder **paths only** — never passwords or key material. Revealed plaintext is dropped on hide / resign-active / lock; `session.wipe()` on lock.
- **Demo vault stays SKELETON-ONLY:** `MacVaultProvisioning` + the `build-macos-app.sh` fixture staging are retained AND retain their existing SKELETON-ONLY guard comments; they must never reach a distributable build (stripped in the later notarization slice).
- **File size:** keep each new view file focused (< ~200 lines); split proactively if one grows past that.
- **Acceptance runners:** `bash ios/scripts/run-macos-tests.sh` (pure host tests + xcframework + SecretaryKit macOS host test + `SecretaryMac.app` compile) and `bash ios/scripts/run-ios-tests.sh` (iOS, because the gate-factory move touches the iOS app). The xcframework build is multi-minute and silent — **run these in the background and poll the log**, do not block on them.
- **Working directory:** worktree `.worktrees/d5-macos-readonly-viewer`, branch `feature/d5-macos-readonly-viewer`. Spell out the worktree path in every edit/read.

---

## File Structure

**New (SecretaryVaultAccess package — FFI-free, host-tested):**
- `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/FileVaultLocationStore.swift` — plain-path `VaultLocationStore`.
- `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/FileVaultLocationStoreTests.swift` — its host tests.

**New (SecretaryKit — hoisted shared factory):**
- `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/RetargetableGateFactory.swift` — `makeRetargetableReauthGate` moved here, made `public`.

**New (macOS app target `ios/SecretaryMacApp/Sources/`):**
- `MacRootView.swift` — the `.select | .unlock | .browse` route state machine.
- `MacVaultSelectionView.swift` — remembered-vault + `NSOpenPanel` + demo.
- `MacUnlockView.swift` — password + Touch ID + "Remember this Mac"; owns gate construction.
- `MacBrowseView.swift` — three-column `NavigationSplitView`; reveal/mask/copy; Lock.
- `MacDeviceUnlockOpen.swift` — ported (copied) `DeviceUnlockOpen` domain flow.

**Modified:**
- `ios/SecretaryApp/Sources/RetargetableGateFactory.swift` — **deleted**; iOS imports the hoisted SecretaryKit factory.
- `ios/SecretaryMacApp/project.yml` — add the `SecretaryVaultAccess` package (products `SecretaryVaultAccess` + `SecretaryVaultAccessUI`).
- `ios/SecretaryMacApp/Sources/SecretaryMacApp.swift` — `WindowGroup { MacRootView() }`.
- `ios/SecretaryMacApp/Sources/MacDeviceUnlockView.swift` — **deleted** (retired as root; the demo path now flows through selection → unlock).
- `README.md`, `ROADMAP.md` — mark D.5.2.

---

## Task 1: `FileVaultLocationStore` (plain-path location store, TDD)

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/FileVaultLocationStore.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/FileVaultLocationStoreTests.swift`

**Interfaces:**
- Consumes: `VaultLocationStore` protocol, `VaultLocation` (`displayName: String`, `bookmark: Data`), `ScopedVaultPath` (`init(pathData:onEnd:)`, `pathData: Data`, `end()`) — all in `SecretaryVaultAccess`.
- Produces: `public final class FileVaultLocationStore: VaultLocationStore` with `init(defaults: UserDefaults, pathKey: String, nameKey: String)` and the four protocol methods. Consumed by `MacRootView` (Task 3).

- [ ] **Step 1: Write the failing tests**

Create `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/FileVaultLocationStoreTests.swift`:

```swift
import XCTest
@testable import SecretaryVaultAccess

final class FileVaultLocationStoreTests: XCTestCase {
    /// Each test gets an isolated UserDefaults suite so nothing touches `.standard`.
    private func makeStore() -> FileVaultLocationStore {
        let suite = "test.filevaultstore.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        return FileVaultLocationStore(defaults: defaults)
    }

    func testLoadReturnsNilWhenEmpty() {
        XCTAssertNil(makeStore().load())
    }

    func testPersistThenLoadRoundTrips() {
        let store = makeStore()
        let loc = VaultLocation(displayName: "Personal", bookmark: Data("/vaults/personal".utf8))
        store.persist(loc)
        let loaded = store.load()
        XCTAssertEqual(loaded?.displayName, "Personal")
        XCTAssertEqual(loaded.map { String(decoding: $0.bookmark, as: UTF8.self) }, "/vaults/personal")
    }

    func testPersistReplacesPriorLocation() {
        let store = makeStore()
        store.persist(VaultLocation(displayName: "A", bookmark: Data("/a".utf8)))
        store.persist(VaultLocation(displayName: "B", bookmark: Data("/b".utf8)))
        XCTAssertEqual(store.load()?.displayName, "B")
        XCTAssertEqual(store.load().map { String(decoding: $0.bookmark, as: UTF8.self) }, "/b")
    }

    func testClearForgetsLocation() {
        let store = makeStore()
        store.persist(VaultLocation(displayName: "A", bookmark: Data("/a".utf8)))
        store.clear()
        XCTAssertNil(store.load())
    }

    func testBeginAccessReturnsNoOpScopedPath() throws {
        let store = makeStore()
        let loc = VaultLocation(displayName: "A", bookmark: Data("/some/vault".utf8))
        let scoped = try store.beginAccess(loc)
        XCTAssertEqual(String(decoding: scoped.pathData, as: UTF8.self), "/some/vault")
        // No-op scope: end() must be safe and idempotent (no crash on double-end).
        scoped.end()
        scoped.end()
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd ios/SecretaryVaultAccess && swift test --filter FileVaultLocationStoreTests`
Expected: FAIL — `cannot find 'FileVaultLocationStore' in scope`.

- [ ] **Step 3: Write the implementation**

Create `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/FileVaultLocationStore.swift`:

```swift
import Foundation

/// macOS `VaultLocationStore`: persists the one remembered vault as a PLAIN folder
/// path (no security-scoped bookmark) in `UserDefaults`, and brokers access with a
/// no-op scope. macOS pre-sandbox has direct filesystem access, so no bookmark is
/// required; the App-Sandbox slice will swap in a bookmark-backed store with no
/// change to `VaultSelectionViewModel`.
///
/// Reuses `VaultLocation.bookmark` to carry the UTF-8 path bytes — that field is
/// documented as a non-secret "path-style token", and a plain path is exactly that,
/// so no protocol or model change is needed. No password or key material ever flows
/// through this type (paths only).
///
/// Single-vault by design (mirrors `BookmarkVaultLocationStore`): `persist` replaces
/// any prior location.
public final class FileVaultLocationStore: VaultLocationStore {
    private let defaults: UserDefaults
    private let pathKey: String
    private let nameKey: String

    public init(defaults: UserDefaults = .standard,
                pathKey: String = "secretary.mac.vault.path",
                nameKey: String = "secretary.mac.vault.displayName") {
        self.defaults = defaults
        self.pathKey = pathKey
        self.nameKey = nameKey
    }

    public func load() -> VaultLocation? {
        guard let path = defaults.string(forKey: pathKey),
              let name = defaults.string(forKey: nameKey) else { return nil }
        return VaultLocation(displayName: name, bookmark: Data(path.utf8))
    }

    public func persist(_ location: VaultLocation) {
        defaults.set(String(decoding: location.bookmark, as: UTF8.self), forKey: pathKey)
        defaults.set(location.displayName, forKey: nameKey)
    }

    public func clear() {
        defaults.removeObject(forKey: pathKey)
        defaults.removeObject(forKey: nameKey)
    }

    /// macOS pre-sandbox: the stored path bytes are directly usable; there is no
    /// security scope to hold, so `onEnd` is a no-op. A folder that has since moved
    /// or been deleted is NOT hard-failed here (mirroring the iOS store's philosophy):
    /// it surfaces loudly downstream as the FFI's typed open error at unlock time.
    public func beginAccess(_ location: VaultLocation) throws -> ScopedVaultPath {
        ScopedVaultPath(pathData: location.bookmark, onEnd: {})
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd ios/SecretaryVaultAccess && swift test --filter FileVaultLocationStoreTests`
Expected: PASS (5 tests).

- [ ] **Step 5: Run the full package suite (no regressions)**

Run: `cd ios/SecretaryVaultAccess && swift test`
Expected: PASS (all existing SecretaryVaultAccess + SecretaryVaultAccessUI tests + the 5 new).

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/d5-macos-readonly-viewer
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/FileVaultLocationStore.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/FileVaultLocationStoreTests.swift
git commit -m "feat(macos): plain-path FileVaultLocationStore (D.5.2)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Hoist `makeRetargetableReauthGate` into SecretaryKit

Behavior-preserving relocation of the reauth-gate factory from the iOS app target into SecretaryKit (public), so both the iOS app and the new macOS app share one copy. Guarded by the iOS host tests + `run-ios-tests.sh`.

**Files:**
- Create: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/RetargetableGateFactory.swift`
- Delete: `ios/SecretaryApp/Sources/RetargetableGateFactory.swift`
- Verify (no change needed): `ios/SecretaryApp/Sources/SecretaryApp.swift` and `DeviceUnlockOpen.swift` call `makeRetargetableReauthGate(...)` — same signature, now resolved from the imported `SecretaryKit` module.

**Interfaces:**
- Produces: `public func makeRetargetableReauthGate(session: VaultSession, vaultPath: Data, biometricUnlock: Bool) -> RetargetableReauthGate` in SecretaryKit. Consumed by iOS `SecretaryApp` + `DeviceUnlockOpen`, and by macOS `MacUnlockView` + `MacDeviceUnlockOpen` (Task 4).

- [ ] **Step 1: Create the hoisted factory in SecretaryKit**

Create `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/RetargetableGateFactory.swift` with the factory made `public` (verbatim body from the old iOS file, `func` → `public func`):

```swift
import Foundation
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Build the shared retargetable re-auth gate for an opened session, seeded with
/// the persisted grace window (or the schema default when the vault has no settings
/// block / on a read error). One instance is shared by every writer (record edit,
/// trash, settings save); a Settings save retargets it live.
///
/// `biometricUnlock` seeds the initial window's last-auth instant — a device unlock
/// counts as presence (first write is free), a password open does not.
///
/// Hoisted from the iOS app target into SecretaryKit (D.5.2) so the iOS app and the
/// macOS app share one factory. It builds only on cross-platform symbols
/// (`makePerVaultDeviceUnlock`, `EnclaveBiometricAuthorizer` — both in SecretaryKit;
/// `RetargetableReauthGate`, `GraceWindowReauthGate`, `SettingsPort`,
/// `MonotonicInstant`, `reauthInitialAuthAt` — in SecretaryVaultAccess/UI). It lives
/// in SecretaryKit (not SecretaryVaultAccessUI) because it depends on
/// `makePerVaultDeviceUnlock`/`EnclaveBiometricAuthorizer`; hoisting it into
/// SecretaryVaultAccessUI would invert the package dependency (a cycle).
@MainActor
public func makeRetargetableReauthGate(session: VaultSession,
                                       vaultPath: Data,
                                       biometricUnlock: Bool) -> RetargetableReauthGate {
    let authorizer = EnclaveBiometricAuthorizer(
        enclave: makePerVaultDeviceUnlock(vaultPath: vaultPath).enclave)
    let graceMs = (try? (session as? SettingsPort)?.readSettings())?.reauthGraceWindowMs
        ?? SecretaryKit.reauthWindowDefaultMs()
    let initialAuthAt = reauthInitialAuthAt(biometricUnlock: biometricUnlock, now: MonotonicInstant.now())
    return RetargetableReauthGate(
        window: .milliseconds(Int(graceMs)),
        initialAuthAt: initialAuthAt,
        clock: MonotonicInstant.now) { window, seed in
            GraceWindowReauthGate(authorizer: authorizer, window: window,
                                  clock: MonotonicInstant.now, initialAuthAt: seed)
        }
}
```

> Note: `reauthWindowDefaultMs()` was referenced as `SecretaryKit.reauthWindowDefaultMs()` from the iOS app; inside SecretaryKit it is the same module, so `SecretaryKit.` is a redundant-but-valid module qualifier — keep it verbatim, or drop the `SecretaryKit.` prefix if the compiler flags the self-qualification. `reauthInitialAuthAt` and `MonotonicInstant` come from SecretaryVaultAccessUI/SecretaryVaultAccess (already imported).

- [ ] **Step 2: Delete the iOS app-target copy**

```bash
cd /Users/hherb/src/secretary/.worktrees/d5-macos-readonly-viewer
git rm ios/SecretaryApp/Sources/RetargetableGateFactory.swift
```

- [ ] **Step 3: Verify no other change is needed**

The iOS call sites (`SecretaryApp.swift`, `DeviceUnlockOpen.swift`) already `import SecretaryKit`, so `makeRetargetableReauthGate(...)` now resolves from SecretaryKit unchanged. Confirm with:

Run: `grep -rn "makeRetargetableReauthGate" ios | grep -v Tests`
Expected: definition now in `ios/SecretaryKit/.../RetargetableGateFactory.swift`; call sites in `SecretaryApp.swift` + `DeviceUnlockOpen.swift` unchanged.

- [ ] **Step 4: Compile-prove + host-test via the iOS runner (background + poll)**

Run in the background (multi-minute xcframework build):
`bash ios/scripts/run-ios-tests.sh > /tmp/d52-ios.log 2>&1 &`
Poll `/tmp/d52-ios.log` until it ends. Expected: the iOS app + SecretaryKit build and the XCTest suite pass — the hoist is behavior-preserving.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/d5-macos-readonly-viewer
git add ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/RetargetableGateFactory.swift
git add -A ios/SecretaryApp/Sources/RetargetableGateFactory.swift
git commit -m "refactor: hoist makeRetargetableReauthGate into SecretaryKit (D.5.2)

Shared by the iOS app and the new macOS app; removes the app-target copy.
Behavior-preserving move.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: macOS package wiring + `MacRootView` + `MacVaultSelectionView` (select route)

Add the shared UI packages to the macOS app, introduce the `Route` state machine, and build the selection screen (remembered vault + `NSOpenPanel` + demo). Routes to a temporary unlock stub so the app compiles end-to-end at this task.

**Files:**
- Modify: `ios/SecretaryMacApp/project.yml`
- Create: `ios/SecretaryMacApp/Sources/MacRootView.swift`
- Create: `ios/SecretaryMacApp/Sources/MacVaultSelectionView.swift`
- Modify: `ios/SecretaryMacApp/Sources/SecretaryMacApp.swift`

**Interfaces:**
- Consumes: `FileVaultLocationStore` (Task 1); `VaultSelectionViewModel(store:probe:)`, `.state` (`.empty`/`.located(displayName:)`/`.unavailable(reason:)`), `loadPersisted()`, `considerImport(url:bookmark:displayName:) -> ImportOutcome`, `chooseDifferent()`, `beginAccess() throws -> ScopedVaultPath`; `FileManagerVaultShapeProbe`; `MacVaultProvisioning.stageGoldenVault()`.
- Produces: `MacRootView` (a `View`); `MacVaultSelectionView(viewModel:onOpen:onOpenDemo:)`.

- [ ] **Step 1: Add the SecretaryVaultAccess package to the macOS app**

Edit `ios/SecretaryMacApp/project.yml` — under `packages:` add:

```yaml
  SecretaryVaultAccess:
    path: ../SecretaryVaultAccess
```

and under the `SecretaryMac` target's `dependencies:` add:

```yaml
      - package: SecretaryVaultAccess
        product: SecretaryVaultAccess
      - package: SecretaryVaultAccess
        product: SecretaryVaultAccessUI
```

- [ ] **Step 2: Add the selection view**

Create `ios/SecretaryMacApp/Sources/MacVaultSelectionView.swift`:

```swift
import SwiftUI
import AppKit
import SecretaryVaultAccess
import SecretaryVaultAccessUI
import SecretaryKit

/// Vault selection (macOS): shows the one remembered vault (if any), an "Open
/// other…" folder picker (`NSOpenPanel`), and the SKELETON-ONLY demo vault. On
/// macOS the "bookmark" handed to `considerImport` is the UTF-8 folder path (see
/// `FileVaultLocationStore`), not a security-scoped bookmark.
@MainActor
struct MacVaultSelectionView: View {
    @ObservedObject var viewModel: VaultSelectionViewModel
    let onOpen: (ScopedVaultPath) -> Void
    let onOpenDemo: () throws -> Void

    @State private var errorText: String?

    var body: some View {
        Form {
            switch viewModel.state {
            case .empty:
                Section("No vault selected") {
                    Button("Open other…") { pickFolder() }
                }
            case .located(let name):
                Section("Vault") {
                    Text(name)
                    Button("Open") { open() }
                    Button("Choose a different vault") { viewModel.chooseDifferent() }
                }
            case .unavailable(let reason):
                Section("Vault unavailable") {
                    Text(reason).foregroundStyle(.secondary)
                    Button("Choose a different vault") { viewModel.chooseDifferent() }
                }
            }

            Section("Demo") {
                Button("Open demo vault") {
                    do { try onOpenDemo() } catch { errorText = error.localizedDescription }
                }
            }

            if let errorText {
                Section("Error") { Text(errorText).foregroundStyle(.red) }
            }
        }
        .formStyle(.grouped)
        .frame(minWidth: 460, minHeight: 320)
        .onAppear { viewModel.loadPersisted() }
    }

    private func open() {
        do { onOpen(try viewModel.beginAccess()) }
        catch { errorText = String(describing: error) }
    }

    /// macOS folder picker. The picked folder's UTF-8 path is the "bookmark".
    private func pickFolder() {
        errorText = nil
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.prompt = "Open Vault"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let outcome = viewModel.considerImport(url: url,
                                               bookmark: Data(url.path.utf8),
                                               displayName: url.lastPathComponent)
        switch outcome {
        case .opened:
            open()
        case .notAVault:
            errorText = "That folder is not a Secretary vault (no vault.toml)."
        case .unavailable(let reason):
            errorText = reason
        }
    }
}
```

> `ImportOutcome` cases are `.opened`, `.notAVault`, `.unavailable(String)` (from `SecretaryVaultAccess/VaultProvisioning.swift`). If a case name differs at build time, read that file and match exactly.

- [ ] **Step 3: Add the root state machine**

Create `ios/SecretaryMacApp/Sources/MacRootView.swift`:

```swift
import SwiftUI
import SecretaryVaultAccess
import SecretaryVaultAccessUI
import SecretaryKit

/// Routes select → unlock → browse for the macOS client. A user-selected vault's
/// (no-op, pre-sandbox) scope is held by the `ScopedVaultPath` for the whole session
/// and released on lock, returning to selection (which still shows the remembered
/// vault — one click re-opens).
@MainActor
struct MacRootView: View {
    private enum Route {
        case select
        case unlock(ScopedVaultPath)
        case browse(VaultBrowseViewModel, ScopedVaultPath)
    }

    private let store: VaultLocationStore
    @StateObject private var selectionVM: VaultSelectionViewModel
    @State private var route: Route = .select
    @State private var biometricEnrolled = false
    @State private var biometricError: String?
    @State private var rememberDevice = false

    init() {
        let store = FileVaultLocationStore()
        self.store = store
        _selectionVM = StateObject(wrappedValue: VaultSelectionViewModel(
            store: store, probe: FileManagerVaultShapeProbe()))
    }

    var body: some View {
        switch route {
        case .select:
            MacVaultSelectionView(
                viewModel: selectionVM,
                onOpen: { enterUnlock($0) },
                onOpenDemo: { try openDemo() })
        case .unlock(let scoped):
            // TEMPORARY stub until Task 4 adds MacUnlockView.
            VStack(spacing: 12) {
                Text("Unlock route (stub) — \(String(decoding: scoped.pathData, as: UTF8.self))")
                Button("Back") { scoped.end(); route = .select }
            }.padding(24).frame(minWidth: 460, minHeight: 200)
        case .browse:
            // TEMPORARY stub until Task 5 adds MacBrowseView.
            Text("Browse route (stub)").padding(24)
        }
    }

    private func enterUnlock(_ scoped: ScopedVaultPath) {
        biometricError = nil
        rememberDevice = false
        biometricEnrolled = makePerVaultDeviceUnlock(vaultPath: scoped.pathData).coordinator.isEnrolled
        route = .unlock(scoped)
    }

    /// Stage + open the bundled golden vault behind an explicit opt-in (SKELETON
    /// ONLY). The demo path is transient — not persisted to the store.
    private func openDemo() throws {
        let url = try MacVaultProvisioning.stageGoldenVault()
        enterUnlock(ScopedVaultPath(pathData: Data(url.path.utf8), onEnd: {}))
    }
}
```

- [ ] **Step 4: Point `@main` at the root view**

Edit `ios/SecretaryMacApp/Sources/SecretaryMacApp.swift`:

```swift
import SwiftUI

@main
struct SecretaryMacApp: App {
    var body: some Scene {
        WindowGroup {
            MacRootView()
        }
        .windowResizability(.contentSize)
    }
}
```

> Leave `MacDeviceUnlockView.swift` in place for now (unused) — it is deleted in Task 5 to keep every task compiling.

- [ ] **Step 5: Compile-prove the macOS app (background + poll)**

Run in the background:
`bash ios/scripts/build-macos-app.sh > /tmp/d52-mac.log 2>&1 &`
Poll `/tmp/d52-mac.log`. Expected: `xcodegen generate` picks up the new deps, `xcodebuild ... BUILD SUCCEEDED`.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/d5-macos-readonly-viewer
git add ios/SecretaryMacApp/project.yml \
        ios/SecretaryMacApp/Sources/MacRootView.swift \
        ios/SecretaryMacApp/Sources/MacVaultSelectionView.swift \
        ios/SecretaryMacApp/Sources/SecretaryMacApp.swift
git commit -m "feat(macos): vault selection screen + route state machine (D.5.2)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: `MacUnlockView` + ported `MacDeviceUnlockOpen` (unlock route)

Password + Touch ID + "Remember this Mac". The view owns gate construction and hands `MacRootView` a fully-opened `(VaultSession, RetargetableReauthGate)`.

**Files:**
- Create: `ios/SecretaryMacApp/Sources/MacDeviceUnlockOpen.swift` (ported from iOS `DeviceUnlockOpen.swift`, which is `internal` to `SecretaryApp` and cannot be imported).
- Create: `ios/SecretaryMacApp/Sources/MacUnlockView.swift`
- Modify: `ios/SecretaryMacApp/Sources/MacRootView.swift` (replace the unlock stub).

**Interfaces:**
- Consumes: `UnlockViewModel(port:vaultPath:)`, `.state` (`.idle`/`.busy`/`.unlocked(VaultSession)`/`.failed(VaultAccessError)`), `.mode`, `unlock(secret:[UInt8]) async`; `UniffiVaultOpenPort()`; `makeRetargetableReauthGate` (SecretaryKit, Task 2); `makePerVaultDeviceUnlock(vaultPath:).coordinator` (`isEnrolled`, `enroll(vaultPath:vaultId:password:) throws`); the ported `MacDeviceUnlockOpen.open(...)`.
- Produces: `MacUnlockView(viewModel:vaultPath:biometricEnrolled:biometricError:rememberDevice:onOpened:)`, where `onOpened: (VaultSession, RetargetableReauthGate) -> Void`.

- [ ] **Step 1: Port the device-unlock flow**

Create `ios/SecretaryMacApp/Sources/MacDeviceUnlockOpen.swift` — copy `ios/SecretaryApp/Sources/DeviceUnlockOpen.swift` verbatim, renaming the enum types to `MacDeviceUnlockOpen` / `MacDeviceUnlockOpenResult` (so there is no confusion with the iOS internal type; the macOS target has no access to the iOS one). Keep every import and every private helper (`vaultAccessFailureMessage`) in the file. Its dependencies resolve on macOS: `makeRetargetableReauthGate` (SecretaryKit, Task 2), `deviceUnlockFailureDisplay` + `zeroize` (from `SecretaryDeviceUnlockUI` / `SecretaryKit`, already macOS deps), `VaultAccessError`, `DeviceUnlockCoordinator`, `VaultOpenPort`.

```swift
import Foundation
import SecretaryDeviceUnlock
import SecretaryDeviceUnlockUI
import SecretaryVaultAccess
import SecretaryVaultAccessUI
import SecretaryKit

enum MacDeviceUnlockOpenResult {
    case opened(VaultSession, gate: RetargetableReauthGate)
    case cancelled
    case failed(String)
}

/// Release the device secret behind a biometric prompt, open the vault with it,
/// verify the opened vault matches enrollment, and build a retargetable re-auth
/// gate seeded at the unlock instant. Ported verbatim from the iOS
/// `DeviceUnlockOpen` (which is module-internal to `SecretaryApp`); pure
/// Foundation/domain logic, no iOS-only UI API.
enum MacDeviceUnlockOpen {
    @MainActor
    static func open(
        coordinator: DeviceUnlockCoordinator,
        openPort: VaultOpenPort,
        vaultPath: Data,
        reason: String
    ) async -> MacDeviceUnlockOpenResult {
        do {
            var cred = try await coordinator.releaseCredential(reason: reason)
            let session: VaultSession
            do {
                session = try await openPort.openWithDeviceSecret(
                    vaultPath: vaultPath, deviceUuid: cred.deviceUuid, deviceSecret: cred.secret)
            } catch {
                zeroize(&cred.secret)
                let display = (error as? VaultAccessError).map(vaultAccessFailureMessage)
                    ?? "Couldn’t open the vault. Unlock with your password."
                return .failed(display)
            }
            zeroize(&cred.secret)

            guard session.vaultUuidHex == cred.enrolledVaultId else {
                session.wipe()
                return .failed("This device’s biometric enrollment is for a different vault.")
            }

            let gate = makeRetargetableReauthGate(
                session: session, vaultPath: vaultPath, biometricUnlock: true)
            return .opened(session, gate: gate)
        } catch let e as DeviceUnlockError {
            switch deviceUnlockFailureDisplay(e) {
            case .silent:            return .cancelled
            case .message(let text): return .failed(text)
            }
        } catch {
            return .failed("Biometric unlock failed. Unlock with your password.")
        }
    }
}

private func vaultAccessFailureMessage(_ e: VaultAccessError) -> String {
    switch e {
    case .wrongDeviceSecretOrCorrupt:
        return "The device key couldn’t open this vault. Unlock with your password."
    case .folderInvalid:
        return "The vault folder is missing or unreadable."
    default:
        return "Couldn’t open the vault. Unlock with your password."
    }
}
```

> If the compiler reports that `zeroize` or `deviceUnlockFailureDisplay` / the `.silent`/`.message` display enum are not visible, `grep -rn "func zeroize\|func deviceUnlockFailureDisplay" ios` to find their module and add the missing `import` (both are used by the iOS `DeviceUnlockOpen`, so they live in already-linked macOS deps). Do not re-implement them.

- [ ] **Step 2: Add the unlock view**

Create `ios/SecretaryMacApp/Sources/MacUnlockView.swift`:

```swift
import SwiftUI
import os
import SecretaryVaultAccess
import SecretaryVaultAccessUI
import SecretaryKit

private let macUnlockLog = Logger(subsystem: "com.secretary.macapp", category: "unlock")

/// Password + Touch ID unlock (macOS). Owns gate construction so `MacRootView`
/// receives a fully-opened `(session, gate)` regardless of which tier was used.
@MainActor
struct MacUnlockView: View {
    @StateObject private var viewModel: UnlockViewModel
    let vaultPath: Data
    let biometricEnrolled: Bool
    @Binding var biometricError: String?
    @Binding var rememberDevice: Bool
    let onOpened: (VaultSession, RetargetableReauthGate) -> Void

    @State private var password: String = ""
    @State private var lastPasswordSecret: [UInt8]?

    init(viewModel: UnlockViewModel, vaultPath: Data, biometricEnrolled: Bool,
         biometricError: Binding<String?>, rememberDevice: Binding<Bool>,
         onOpened: @escaping (VaultSession, RetargetableReauthGate) -> Void) {
        _viewModel = StateObject(wrappedValue: viewModel)
        self.vaultPath = vaultPath
        self.biometricEnrolled = biometricEnrolled
        _biometricError = biometricError
        _rememberDevice = rememberDevice
        self.onOpened = onOpened
    }

    private var isBusy: Bool { if case .busy = viewModel.state { return true } else { return false } }
    private var stateIsUnlocked: Bool { if case .unlocked = viewModel.state { return true } else { return false } }

    var body: some View {
        Form {
            if biometricEnrolled {
                Section("Touch ID") {
                    Button("Unlock with Touch ID") { biometricUnlock() }
                }
            }
            Section("Master password") {
                SecureField("Password", text: $password)
                Toggle("Remember this Mac with Touch ID", isOn: $rememberDevice)
            }
            Section {
                Button("Unlock") { passwordUnlock() }.disabled(isBusy || password.isEmpty)
            }
            if case .failed(let err) = viewModel.state {
                Section("Error") { Text(String(describing: err)).foregroundStyle(.red) }
            }
            if let biometricError {
                Section("Couldn’t unlock") { Text(biometricError).foregroundStyle(.red) }
            }
        }
        .formStyle(.grouped)
        .frame(minWidth: 460, minHeight: 320)
        .overlay { if isBusy { ProgressView() } }
        .onChange(of: stateIsUnlocked) { _, unlocked in
            guard unlocked, case .unlocked(let session) = viewModel.state else { return }
            let password = lastPasswordSecret
            lastPasswordSecret = nil
            let gate = makeRetargetableReauthGate(session: session, vaultPath: vaultPath,
                                                  biometricUnlock: false)
            if rememberDevice, let password { enrollDevice(session: session, password: password) }
            onOpened(session, gate)
        }
    }

    private func passwordUnlock() {
        viewModel.mode = .password
        let secret = Array(password.utf8)
        lastPasswordSecret = secret
        Task { await viewModel.unlock(secret: secret) }
    }

    private func biometricUnlock() {
        biometricError = nil
        let coordinator = makePerVaultDeviceUnlock(vaultPath: vaultPath).coordinator
        Task {
            let result = await MacDeviceUnlockOpen.open(
                coordinator: coordinator, openPort: UniffiVaultOpenPort(),
                vaultPath: vaultPath, reason: "Unlock your Secretary vault")
            switch result {
            case .cancelled: break                              // stay on unlock, quietly
            case .failed(let message): biometricError = message
            case .opened(let session, let gate): onOpened(session, gate)
            }
        }
    }

    /// Best-effort device-slot enrollment on password unlock (mirrors iOS): a second
    /// Argon2id open, hopped onto a background queue so the route transition is never
    /// blocked. Non-fatal — the password open already succeeded.
    private func enrollDevice(session: VaultSession, password: [UInt8]) {
        let coordinator = makePerVaultDeviceUnlock(vaultPath: vaultPath).coordinator
        let vaultPath = self.vaultPath
        let vaultId = session.vaultUuidHex
        Task {
            do {
                try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
                    DispatchQueue.global(qos: .userInitiated).async {
                        do { try coordinator.enroll(vaultPath: vaultPath, vaultId: vaultId, password: password); c.resume() }
                        catch { c.resume(throwing: error) }
                    }
                }
            } catch {
                macUnlockLog.error("device enroll failed: \(error.localizedDescription, privacy: .public)")
                await MainActor.run { biometricError = "Couldn’t enable Touch ID unlock. You can try again later." }
            }
        }
    }
}
```

- [ ] **Step 3: Wire the unlock route in `MacRootView`**

In `ios/SecretaryMacApp/Sources/MacRootView.swift`, replace the `.unlock` stub case with:

```swift
        case .unlock(let scoped):
            MacUnlockView(
                viewModel: UnlockViewModel(port: UniffiVaultOpenPort(), vaultPath: scoped.pathData),
                vaultPath: scoped.pathData,
                biometricEnrolled: biometricEnrolled,
                biometricError: $biometricError,
                rememberDevice: $rememberDevice,
                onOpened: { session, gate in enterBrowse(session, gate: gate, scoped: scoped) })
```

and add the `enterBrowse` helper to `MacRootView`:

```swift
    private func enterBrowse(_ session: VaultSession, gate: RetargetableReauthGate,
                             scoped: ScopedVaultPath) {
        let vm = VaultBrowseViewModel(session: session, gate: gate,
                                      trashPort: session as? TrashPort,
                                      settingsPort: session as? SettingsPort)
        route = .browse(vm, scoped)
    }
```

(The `.browse` stub from Task 3 still renders; it is replaced in Task 5.)

- [ ] **Step 4: Compile-prove the macOS app (background + poll)**

Run in the background: `bash ios/scripts/build-macos-app.sh > /tmp/d52-mac.log 2>&1 &`; poll. Expected: BUILD SUCCEEDED.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/d5-macos-readonly-viewer
git add ios/SecretaryMacApp/Sources/MacDeviceUnlockOpen.swift \
        ios/SecretaryMacApp/Sources/MacUnlockView.swift \
        ios/SecretaryMacApp/Sources/MacRootView.swift
git commit -m "feat(macos): password + Touch ID unlock screen (D.5.2)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: `MacBrowseView` (three-column read-only browse) + retire the skeleton root

The three-column `NavigationSplitView` (blocks | records | field detail) with per-field reveal/mask, copy-with-auto-clear, an explicit Lock button, and drop-reveals-on-resign-active. Deletes the retired `MacDeviceUnlockView`.

**Files:**
- Create: `ios/SecretaryMacApp/Sources/MacBrowseView.swift`
- Modify: `ios/SecretaryMacApp/Sources/MacRootView.swift` (replace the browse stub; add the Lock wiring).
- Delete: `ios/SecretaryMacApp/Sources/MacDeviceUnlockView.swift`

**Interfaces:**
- Consumes: `VaultBrowseViewModel` — `blocks: [BlockSummary]`, `loadBlocks()`, `selectBlock(_:)`, `records: [RecordView]?`, `visibleRecords: [RecordView]`, `error: VaultAccessError?`, `reveal(record:field:)`, `revealedValue(recordUuidHex:fieldName:) -> RevealedValue?`, `hide(recordUuidHex:fieldName:)`, `hideAll()`, `vaultUuidHex: String`; `BlockSummary` (`uuid`, `name`, `uuidHex`), `RecordView` (`uuidHex`, `type`, `tags`, `fields: [FieldView]`), `FieldView` (`name`, `kind`, `reveal`), `RevealedValue` (`.text`/`.bytes`), `RevealPolicy.autoHideSeconds`.
- Produces: `MacBrowseView(viewModel:onLock:)`.

- [ ] **Step 1: Add the browse view**

Create `ios/SecretaryMacApp/Sources/MacBrowseView.swift`:

```swift
import SwiftUI
import AppKit
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Read-only three-column browse (macOS): blocks sidebar | records list | field
/// detail. Reveal is explicit and short-lived — dropped on hide, on resign-active,
/// and on Lock. No mutation controls (read-only slice).
@MainActor
struct MacBrowseView: View {
    @StateObject private var viewModel: VaultBrowseViewModel
    let onLock: () -> Void

    @State private var selectedBlockHex: String?
    @State private var selectedRecordHex: String?
    @State private var isActive = true

    init(viewModel: VaultBrowseViewModel, onLock: @escaping () -> Void) {
        _viewModel = StateObject(wrappedValue: viewModel)
        self.onLock = onLock
    }

    private var selectedRecord: RecordView? {
        viewModel.visibleRecords.first { $0.uuidHex == selectedRecordHex }
    }

    var body: some View {
        NavigationSplitView {
            List(viewModel.blocks, id: \.uuidHex, selection: $selectedBlockHex) { block in
                Text(block.name).tag(block.uuidHex)
            }
            .navigationTitle("Blocks")
        } content: {
            if viewModel.records != nil {
                List(viewModel.visibleRecords, id: \.uuidHex, selection: $selectedRecordHex) { record in
                    VStack(alignment: .leading) {
                        Text(record.type.isEmpty ? "(untyped)" : record.type)
                        if !record.tags.isEmpty {
                            Text(record.tags.joined(separator: ", "))
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }.tag(record.uuidHex)
                }
                .navigationTitle("Records")
            } else {
                Text("Select a block").foregroundStyle(.secondary)
            }
        } detail: {
            if let record = selectedRecord {
                fieldList(record)
            } else {
                Text("Select a record").foregroundStyle(.secondary)
            }
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button("Lock", systemImage: "lock.fill") { onLock() }
            }
        }
        .overlay(alignment: .bottom) {
            if let error = viewModel.error {
                Text(String(describing: error)).foregroundStyle(.red).padding(8)
            }
        }
        .onAppear { viewModel.loadBlocks() }
        .onChange(of: selectedBlockHex) { _, hex in
            selectedRecordHex = nil
            if let block = viewModel.blocks.first(where: { $0.uuidHex == hex }) {
                viewModel.selectBlock(block)
            }
        }
        // macOS analogue of the iOS scenePhase privacy behavior: drop revealed
        // plaintext when the app loses focus, and redact revealed values while
        // inactive. Does not wipe the session (that is Lock / window-close).
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in
            isActive = false
            viewModel.hideAll()
        }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            isActive = true
        }
    }

    @ViewBuilder
    private func fieldList(_ record: RecordView) -> some View {
        List {
            Section("uuid=\(record.uuidHex)") {
                ForEach(record.fields, id: \.name) { field in
                    fieldRow(record: record, field: field)
                }
            }
        }
        .navigationTitle(record.type.isEmpty ? "Record" : record.type)
    }

    @ViewBuilder
    private func fieldRow(record: RecordView, field: FieldView) -> some View {
        let revealed = viewModel.revealedValue(recordUuidHex: record.uuidHex, fieldName: field.name)
        HStack {
            Text(field.name)
            Spacer()
            if let revealed {
                Text(display(revealed))
                    .textSelection(.enabled)
                    .redacted(reason: isActive ? [] : .privacy)
                Button("Copy") { copyToPasteboard(revealed) }
                Button("Hide") { viewModel.hide(recordUuidHex: record.uuidHex, fieldName: field.name) }
                    // Auto-hide after the shared reveal window.
                    .task(id: "\(record.uuidHex)/\(field.name)") {
                        try? await Task.sleep(for: .seconds(RevealPolicy.autoHideSeconds))
                        guard !Task.isCancelled else { return }
                        viewModel.hide(recordUuidHex: record.uuidHex, fieldName: field.name)
                    }
            } else {
                Text("••••••").foregroundStyle(.secondary)
                Button("Reveal") { viewModel.reveal(record: record, field: field) }
            }
        }
    }

    private func display(_ value: RevealedValue) -> String {
        switch value {
        case .text(let s): return s
        case .bytes(let b): return b.map { String(format: "%02x", $0) }.joined()
        }
    }

    /// Copy revealed plaintext to the pasteboard, hinting clipboard managers not to
    /// persist it (macOS `org.nspasteboard.ConcealedType` convention), and clear it
    /// after the reveal window unless a newer copy has since replaced it.
    private func copyToPasteboard(_ value: RevealedValue) {
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.declareTypes([.string, NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")], owner: nil)
        pb.setString(display(value), forType: .string)
        let generation = pb.changeCount
        DispatchQueue.main.asyncAfter(deadline: .now() + Double(RevealPolicy.autoHideSeconds)) {
            if NSPasteboard.general.changeCount == generation { NSPasteboard.general.clearContents() }
        }
    }
}
```

> `RevealPolicy.autoHideSeconds` is used by the iOS screen as `.seconds(RevealPolicy.autoHideSeconds)`; if it is an `Int`, the `Double(...)` cast in `copyToPasteboard` is required and the `.seconds(...)` call takes it directly. If it is already a `Double`/`TimeInterval`, drop the `Double(...)`. Match the declared type in `SecretaryVaultAccess/RevealPolicy.swift`.

- [ ] **Step 2: Wire the browse route + delete the skeleton root**

In `ios/SecretaryMacApp/Sources/MacRootView.swift`, replace the `.browse` stub case with:

```swift
        case .browse(let browseVM, let scoped):
            MacBrowseView(viewModel: browseVM, onLock: {
                browseVM.lock()
                scoped.end()
                route = .select
            })
```

Delete the retired skeleton root:

```bash
cd /Users/hherb/src/secretary/.worktrees/d5-macos-readonly-viewer
git rm ios/SecretaryMacApp/Sources/MacDeviceUnlockView.swift
```

- [ ] **Step 3: Compile-prove the macOS app (background + poll)**

Run in the background: `bash ios/scripts/build-macos-app.sh > /tmp/d52-mac.log 2>&1 &`; poll. Expected: BUILD SUCCEEDED with no reference to the deleted `MacDeviceUnlockView`.

- [ ] **Step 4: Manual smoke (temp copy of the golden vault — never the tracked fixture)**

The app self-stages the golden vault into Application Support (writable copy), so the tracked fixture is never mutated. Launch the built app, "Open demo vault", unlock (password `correct horse battery staple` via `secretary_test_utils::golden_vault_001_password()` — or use the bundled inputs JSON), select a block, reveal/copy/hide a field, and press Lock. Confirm: three columns render; reveal shows plaintext; Hide/auto-hide/resign-active drop it; Lock returns to selection.

> This step is manual (no ViewInspector render-layer test infra — that is the deferred #417 decision). Record the result in the commit / handoff.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/d5-macos-readonly-viewer
git add ios/SecretaryMacApp/Sources/MacBrowseView.swift \
        ios/SecretaryMacApp/Sources/MacRootView.swift
git add -A ios/SecretaryMacApp/Sources/MacDeviceUnlockView.swift
git commit -m "feat(macos): three-column read-only browse + Lock; retire skeleton root (D.5.2)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Full acceptance + docs

**Files:**
- Modify: `README.md`, `ROADMAP.md`

- [ ] **Step 1: Run the full macOS acceptance (background + poll)**

Run in the background: `bash ios/scripts/run-macos-tests.sh > /tmp/d52-macfull.log 2>&1 &`; poll to completion.
Expected: `D.5.1 automated acceptance: PASS` (the runner label is unchanged) — pure host tests (incl. the new `FileVaultLocationStore` tests) + xcframework + SecretaryKit macOS host test + `SecretaryMac.app` compile all green.

- [ ] **Step 2: Confirm iOS still green (background + poll)**

Run in the background: `bash ios/scripts/run-ios-tests.sh > /tmp/d52-iosfull.log 2>&1 &`; poll.
Expected: PASS (the gate-factory hoist is behavior-preserving).

- [ ] **Step 3: Update ROADMAP.md**

Add a `D.5.2 ✅ shipped (2026-07-17)` entry to both the Sub-project D status line and the D.5 phase-plan row, describing: native macOS read-only viewer (select via `NSOpenPanel` + demo → password/Touch ID unlock → three-column browse with reveal/mask/copy + Lock); reuse of the shared host-tested view models; new FFI-free `FileVaultLocationStore`; `makeRetargetableReauthGate` hoisted into SecretaryKit; no core/FFI/on-disk change. Keep the D.5 umbrella in-progress. Match the phrasing style of the existing D.5.1 entry.

- [ ] **Step 4: Update README.md**

If README's project-status section enumerates D.5 slices, add a brief dot-point for D.5.2 (native macOS read-only viewer). Keep it terse (per the README style: brief, audience-aware, no test-count walls). If README does not track per-slice D.5 state, make no change and note that in the commit.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/d5-macos-readonly-viewer
git add README.md ROADMAP.md
git commit -m "docs: mark D.5.2 macOS read-only viewer shipped

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 6: Baton handoff + PR**

Author the next handoff at `docs/handoffs/2026-07-17-d5-macos-readonly-viewer-shipped.md`, retarget the `NEXT_SESSION.md` symlink to it, commit both on the branch, then push and open the PR (per the ship-by-default authorization). Capture: shipped commits + SHAs, next slices (D.5.3 write parity / Settings / sync UI), open risks (gate-factory hoist touches iOS; copy-to-pasteboard residue; no folder-change monitor), and the exact resume commands.

---

## Self-Review

**Spec coverage:**
- Select (remembered + `NSOpenPanel` + demo) → Task 3. ✓
- Unlock (password + Touch ID + Remember this Mac) → Task 4. ✓
- Browse (three-column, reveal/mask/copy) → Task 5. ✓
- Explicit Lock + drop-reveals-on-resign + wipe-on-close → Task 5 (Lock/resign) + `MacRootView` scope.end + `lock()`. ✓ (Window-close wipe: SwiftUI drops the `VaultBrowseViewModel` when the window/scene tears down; `lock()` on the explicit path covers the in-session case. Note in handoff that a dedicated `onDisappear { viewModel.lock() }` can be added if window-close wipe needs to be explicit.)
- `FileVaultLocationStore` in SecretaryVaultAccess (⚑1a) → Task 1. ✓
- `makeRetargetableReauthGate` hoisted to SecretaryKit (⚑2a) → Task 2. ✓
- Non-goals (no mutation UI, Settings, sync, sandbox, notarization, Intel) → honored (no such controls wired). ✓
- Testing: `FileVaultLocationStore` host tests (Task 1); gate hoist guarded by `run-ios-tests.sh` (Task 2); view compile-proofs (Tasks 3–5); full acceptance (Task 6). ✓

**Gap found + closed:** window-close wipe is implicit (scene teardown drops the VM). Added an explicit note in Task 5 self-review + handoff so a follow-up can add `onDisappear { lock() }` if a hard guarantee is wanted. Not blocking for a read-only slice (no unsaved state; reveals already drop on resign).

**Placeholder scan:** no TBD/TODO; every code step shows complete code; the two "verify the symbol/type at build time" notes (`ImportOutcome` case names, `zeroize`/`deviceUnlockFailureDisplay` visibility, `RevealPolicy.autoHideSeconds` numeric type) are explicit build-time resolutions with the exact grep to run, not hand-waves.

**Type consistency:** `onOpened: (VaultSession, RetargetableReauthGate) -> Void` is consistent between `MacUnlockView` (Task 4) and `MacRootView.enterBrowse` (Task 4). `MacDeviceUnlockOpenResult.opened(VaultSession, gate:)` matches its consumer in `biometricUnlock()`. `selectedBlockHex`/`selectedRecordHex` (String uuidHex) are used consistently as `List` selection + lookup keys. `VaultBrowseViewModel(session:gate:trashPort:settingsPort:)` matches the verbatim init.
