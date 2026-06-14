# Argon2id off the main actor — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the CPU-heavy Argon2id open/create off the iOS main actor so the UI stays responsive during vault open and create.

**Architecture:** The two `@MainActor` view-models (`UnlockViewModel`, `VaultProvisioningViewModel`) call **synchronous** port methods inline, so Argon2id (m=256 MiB, t=3 ≈ 0.5–1 s) runs on the main actor and freezes the UI. We make the three port requirements (`VaultOpenPort.openWithPassword/openWithRecovery`, `VaultCreatePort.create`) `async throws`; the real `SecretaryKit` adapters offload the synchronous FFI call through a shared `runOffMainActor` helper (a `withCheckedThrowingContinuation` + `DispatchQueue.global(qos:.userInitiated)` hop); the pure view-models just `await`. No Rust/FFI/on-disk-format/crypto/CRDT change.

**Tech Stack:** Swift 5.9, Swift Concurrency (async/await, `CheckedContinuation`, GCD global queue), XCTest. Packages: `SecretaryVaultAccess` (pure, host-testable), `SecretaryVaultAccessTesting` (fakes), `SecretaryVaultAccessUI` (view-models), `SecretaryKit` (real uniffi adapters, simulator-tested).

**Spec:** `docs/superpowers/specs/2026-06-14-argon2id-off-main-actor-design.md`

---

## Working directory

All paths below are relative to the worktree root:
`/Users/hherb/src/secretary/.worktrees/argon2id-off-main-actor`

Verify before any git/build command:
```bash
pwd && git branch --show-current
# expect: …/.worktrees/argon2id-off-main-actor  and  feature/argon2id-off-main-actor
```

## Test commands

- **Fast host tests** (pure packages — `SecretaryVaultAccess` + UI + Testing):
  ```bash
  cd ios/SecretaryVaultAccess && swift test
  ```
- **Full iOS gauntlet** (host + `SecretaryKit` simulator tests + app build) — slow, run in the final task:
  ```bash
  bash ios/scripts/run-ios-tests.sh
  ```

`SecretaryKit` builds against the iOS/sim uniffi xcframework and is **not** part of `swift test` on the `SecretaryVaultAccess` package. Tasks 1 and 2 therefore change `SecretaryKit` adapter + its tests in the **same commit** as the protocol change (so no commit leaves `SecretaryKit` un-compilable), but those `SecretaryKit` changes are only *executed* by the simulator run in Task 4. Each of Tasks 1–2 is fast-verified by `swift test`; Task 4 is the simulator proof.

## File map

| File | Task | Responsibility / change |
|---|---|---|
| `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/SuspensionGate.swift` | 1 | **NEW** — actor gate letting a test hold a fake port mid-call to prove non-blocking |
| `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultOpenPort.swift` | 1 | protocol → `async throws` |
| `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeVaultOpenPort.swift` | 1 | `async` + optional `gate` |
| `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/UnlockViewModel.swift` | 1 | `await` the port; update stale doc comment |
| `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/RunOffMainActor.swift` | 1 | **NEW** — `runOffMainActor` offload helper |
| `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultOpenPort.swift` | 1 | offload via helper |
| `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/UnlockViewModelTests.swift` | 1 | **NEW** responsiveness test + thread existing |
| `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/FakesTests.swift` | 1 | thread async open calls |
| `ios/SecretaryKit/Tests/SecretaryKitTests/VaultAccessIntegrationTests.swift` | 1 | thread async open calls |
| `ios/SecretaryKit/Tests/SecretaryKitTests/BookmarkVaultLocationStoreTests.swift` | 1 | thread async open call |
| `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultProvisioning.swift` | 2 | `VaultCreatePort.create` → `async throws` |
| `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeVaultCreatePort.swift` | 2 | `async` + optional `gate` |
| `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultProvisioningViewModel.swift` | 2 | `await` the port; update stale doc comment |
| `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultCreatePort.swift` | 2 | offload via helper |
| `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultProvisioningViewModelTests.swift` | 2 | **NEW** responsiveness test |
| `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/FakeProvisioningFakesTests.swift` | 2 | thread async create calls |
| `ios/SecretaryKit/Tests/SecretaryKitTests/UniffiVaultCreatePortTests.swift` | 2 | thread async create calls |
| `README.md`, `ROADMAP.md` | 3 | document the slice |

---

## Task 1: Open path — async `VaultOpenPort`, adapter offload, unlock responsiveness test

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/SuspensionGate.swift`
- Create: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/RunOffMainActor.swift`
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultOpenPort.swift`
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeVaultOpenPort.swift`
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/UnlockViewModel.swift`
- Modify: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultOpenPort.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/UnlockViewModelTests.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/FakesTests.swift`
- Test: `ios/SecretaryKit/Tests/SecretaryKitTests/VaultAccessIntegrationTests.swift`
- Test: `ios/SecretaryKit/Tests/SecretaryKitTests/BookmarkVaultLocationStoreTests.swift`

- [ ] **Step 1: Create the `SuspensionGate` test helper**

Create `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/SuspensionGate.swift`:

```swift
import Foundation

/// A two-sided rendezvous used by responsiveness tests to hold a fake port
/// *mid-call*. The fake calls `enterAndWait()` from its (off-main-actor) port
/// method; the test calls `waitUntilEntered()` to learn the port is in flight,
/// makes its main-actor assertions, then `release()`s to let the fake return.
///
/// Being able to run main-actor assertions *while the port is suspended* is the
/// proof that the open/create call did not block the main actor — against the
/// old synchronous-on-main-actor code the test would deadlock instead.
public actor SuspensionGate {
    private var entered = false
    private var enteredWaiter: CheckedContinuation<Void, Never>?
    private var released = false
    private var releaseWaiter: CheckedContinuation<Void, Never>?

    public init() {}

    /// Fake side: mark entry (waking any `waitUntilEntered`), then suspend until
    /// `release()`. Returns immediately if already released.
    public func enterAndWait() async {
        entered = true
        enteredWaiter?.resume()
        enteredWaiter = nil
        if released { return }
        await withCheckedContinuation { releaseWaiter = $0 }
    }

    /// Test side: suspend until the fake has entered its port method.
    public func waitUntilEntered() async {
        if entered { return }
        await withCheckedContinuation { enteredWaiter = $0 }
    }

    /// Test side: let a suspended fake return.
    public func release() {
        released = true
        releaseWaiter?.resume()
        releaseWaiter = nil
    }
}
```

- [ ] **Step 2: Write the failing responsiveness test (drives the async API)**

In `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/UnlockViewModelTests.swift`, add this test method inside the class (after `testPasswordUnlockSuccessPublishesSession`):

```swift
    func testMainActorIsFreeWhileOpening() async {
        let s = session("cd")
        let gate = SuspensionGate()
        let port = FakeVaultOpenPort(passwordResult: .success(s),
                                     recoveryResult: .failure(.wrongMnemonicOrCorrupt))
        port.gate = gate
        let vm = UnlockViewModel(port: port, vaultPath: Data("p".utf8))
        vm.mode = .password

        let task = Task { await vm.unlock(secret: Array("pw".utf8)) }

        // Suspends THIS (main-actor) test until the fake is mid-call. Reaching the
        // next line proves the unlock did not hold the main actor — otherwise this
        // await could never interleave and the test would hang.
        await gate.waitUntilEntered()
        guard case .busy = vm.state else {
            return XCTFail("expected .busy while the port is in flight")
        }

        await gate.release()
        await task.value
        guard case .unlocked(let opened) = vm.state else {
            return XCTFail("expected unlocked")
        }
        XCTAssertTrue(opened === s)
    }
```

- [ ] **Step 3: Run the test — expect a COMPILE failure (red)**

Run: `cd ios/SecretaryVaultAccess && swift test --filter UnlockViewModelTests`
Expected: FAIL to build — `value of type 'FakeVaultOpenPort' has no member 'gate'` (the async API does not exist yet).

- [ ] **Step 4: Make the open path async + offload — implementation**

(a) `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultOpenPort.swift` — replace the protocol body:

```swift
import Foundation

/// Opens a vault folder by password or recovery phrase, producing a
/// `VaultSession`. Implementations throw `VaultAccessError`.
///
/// `async` because the real open runs Argon2id (CPU-heavy); implementations
/// offload it off the calling actor so a `@MainActor` caller's UI stays
/// responsive (see `SecretaryKit.runOffMainActor`).
public protocol VaultOpenPort {
    func openWithPassword(vaultPath: Data, password: [UInt8]) async throws -> VaultSession
    func openWithRecovery(vaultPath: Data, phrase: [UInt8]) async throws -> VaultSession
}
```

(b) `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeVaultOpenPort.swift` — add the gate and make the methods async (replace the whole file):

```swift
import Foundation
import SecretaryVaultAccess

/// In-memory `VaultOpenPort` returning pre-seeded results.
public final class FakeVaultOpenPort: VaultOpenPort {
    private let passwordResult: Result<VaultSession, VaultAccessError>
    private let recoveryResult: Result<VaultSession, VaultAccessError>
    /// Spies asserted by the UnlockViewModel tests (which credential bytes the
    /// VM forwarded for each mode).
    public private(set) var lastPassword: [UInt8]?
    public private(set) var lastPhrase: [UInt8]?
    /// Optional rendezvous so a responsiveness test can hold the call mid-flight.
    public var gate: SuspensionGate?

    public init(passwordResult: Result<VaultSession, VaultAccessError>,
                recoveryResult: Result<VaultSession, VaultAccessError>) {
        self.passwordResult = passwordResult
        self.recoveryResult = recoveryResult
    }

    public func openWithPassword(vaultPath: Data, password: [UInt8]) async throws -> VaultSession {
        lastPassword = password
        await gate?.enterAndWait()
        return try passwordResult.get()
    }

    public func openWithRecovery(vaultPath: Data, phrase: [UInt8]) async throws -> VaultSession {
        lastPhrase = phrase
        await gate?.enterAndWait()
        return try recoveryResult.get()
    }
}
```

(c) `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/UnlockViewModel.swift` — update the doc comment (lines 5–9) and `await` the two calls (lines 32–35). Replace the class doc comment block:

```swift
/// Drives the unlock screen. Holds only the injected port + vault path, so it is
/// fully host-testable. `@MainActor` because it publishes UI state. The CPU-heavy
/// Argon2id open is offloaded off the main actor by the port implementation, so
/// `unlock` only suspends (it does not block) the main actor while the vault opens.
@MainActor
```

and replace the two `case` lines inside `do`:

```swift
            case .password: session = try await port.openWithPassword(vaultPath: vaultPath, password: secret)
            case .recovery: session = try await port.openWithRecovery(vaultPath: vaultPath, phrase: secret)
```

(d) Create `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/RunOffMainActor.swift`:

```swift
import Foundation

/// Run a synchronous, CPU-bound (Argon2id) throwing closure off the calling
/// actor on a user-initiated global queue, *suspending* the caller rather than
/// blocking it. Used by the real vault open/create adapters so a `@MainActor`
/// caller's UI stays responsive during the KDF.
///
/// Implemented with `withCheckedThrowingContinuation` (not `Task.detached`) on
/// purpose: `Task<Success, _>` constrains `Success: Sendable`, but the open
/// adapter returns `any VaultSession` (a non-`Sendable` `AnyObject`), which would
/// emit a Swift-5.9 Sendable warning. `CheckedContinuation`'s result type is
/// unconstrained, so the freshly-built session transfers back across the
/// suspension cleanly. `work` is `@Sendable` and captures only `Sendable` inputs
/// (`Data` / `[UInt8]` / `URL` / `String`); neither adapter captures `self`.
func runOffMainActor<T>(_ work: @escaping @Sendable () throws -> T) async throws -> T {
    try await withCheckedThrowingContinuation { continuation in
        DispatchQueue.global(qos: .userInitiated).async {
            do { continuation.resume(returning: try work()) }
            catch { continuation.resume(throwing: error) }
        }
    }
}
```

(e) `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultOpenPort.swift` — make both methods async and offload (replace the whole file):

```swift
import Foundation
import SecretaryVaultAccess

/// Real `VaultOpenPort` over the uniffi folder-in open functions. The CPU-heavy
/// Argon2id open runs off the calling actor via `runOffMainActor`, so a
/// `@MainActor` view-model's UI is not blocked during the KDF.
public struct UniffiVaultOpenPort: VaultOpenPort {
    public init() {}

    public func openWithPassword(vaultPath: Data, password: [UInt8]) async throws -> VaultSession {
        try await runOffMainActor {
            do {
                let out = try SecretaryKit.openVaultWithPassword(
                    folderPath: vaultPath, password: Data(password))
                return UniffiVaultSession(output: out)
            } catch let e as VaultError {
                throw mapVaultAccessError(e)
            }
        }
    }

    public func openWithRecovery(vaultPath: Data, phrase: [UInt8]) async throws -> VaultSession {
        try await runOffMainActor {
            do {
                let out = try SecretaryKit.openVaultWithRecovery(
                    folderPath: vaultPath, mnemonic: Data(phrase))
                return UniffiVaultSession(output: out)
            } catch let e as VaultError {
                throw mapVaultAccessError(e)
            }
        }
    }
}
```

- [ ] **Step 5: Thread the existing open-path test call sites**

(a) `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/FakesTests.swift` — `testFakeOpenPortRoutesPasswordAndRecovery` (lines 40–48). Change the signature to `async throws` and thread the calls. Replace the method:

```swift
    func testFakeOpenPortRoutesPasswordAndRecovery() async throws {
        let session = FakeVaultSession(vaultUuidHex: "ab", blocks: [], recordsByBlock: [:])
        let port = FakeVaultOpenPort(passwordResult: .success(session),
                                     recoveryResult: .failure(.wrongMnemonicOrCorrupt))
        let opened = try await port.openWithPassword(vaultPath: Data(), password: [1])
        XCTAssertTrue(opened === session)
        do {
            _ = try await port.openWithRecovery(vaultPath: Data(), phrase: [1])
            XCTFail("expected recovery to throw")
        } catch {
            XCTAssertEqual(error as? VaultAccessError, .wrongMnemonicOrCorrupt)
        }
    }
```

(b) `ios/SecretaryKit/Tests/SecretaryKitTests/VaultAccessIntegrationTests.swift` — make the three tests async:

- `testPasswordOpenBrowseAndRevealOnDemand() throws` → `async throws`, and line 34 `let session = try port.openWithPassword(...)` → `let session = try await port.openWithPassword(...)`.
- `testRecoveryOpensSameVault() throws` → `async throws`, and line 56 `try port.openWithRecovery(...)` → `try await port.openWithRecovery(...)`.
- `testWrongPasswordSurfacesConflatedVariant()` → `async`, and replace the `XCTAssertThrowsError(...)` block (lines 62–69) with:

```swift
    func testWrongPasswordSurfacesConflatedVariant() async {
        let port = UniffiVaultOpenPort()
        do {
            _ = try await port.openWithPassword(
                vaultPath: path, password: [UInt8]("definitely wrong".utf8))
            XCTFail("expected wrong password to throw")
        } catch {
            XCTAssertEqual(error as? VaultAccessError, .wrongPasswordOrCorrupt,
                           "wrong password must be indistinguishable from corruption (anti-oracle)")
        }
    }
```

(c) `ios/SecretaryKit/Tests/SecretaryKitTests/BookmarkVaultLocationStoreTests.swift` — `testBeginAccessResolvesToFolderAndOpensGoldenVault() throws` → `async throws`; change line 64–65 `let session = try port.openWithPassword(...)` to `let session = try await port.openWithPassword(...)`. (The other tests in this file do not touch the port — leave them.)

- [ ] **Step 6: Run the fast host tests — expect green**

Run: `cd ios/SecretaryVaultAccess && swift test`
Expected: PASS, including `testMainActorIsFreeWhileOpening` and the threaded `testFakeOpenPortRoutesPasswordAndRecovery`.

(The `SecretaryKit` test edits in 5(b)/5(c) are compiled+run by the simulator gauntlet in Task 4, not by this host run.)

- [ ] **Step 7: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/argon2id-off-main-actor
git add ios/SecretaryVaultAccess ios/SecretaryKit
git commit -m "feat(ios): offload Argon2id open off the main actor (async VaultOpenPort)

VaultOpenPort.openWith{Password,Recovery} become async throws; the real
UniffiVaultOpenPort offloads the synchronous FFI open through a shared
runOffMainActor (withCheckedThrowingContinuation + global queue) helper, so the
@MainActor UnlockViewModel only suspends — never blocks — during the KDF. Adds a
SuspensionGate test helper + a responsiveness test that would deadlock against
the old synchronous-on-main-actor code.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Create path — async `VaultCreatePort`, adapter offload, create responsiveness test

**Files:**
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultProvisioning.swift`
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeVaultCreatePort.swift`
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultProvisioningViewModel.swift`
- Modify: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultCreatePort.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultProvisioningViewModelTests.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/FakeProvisioningFakesTests.swift`
- Test: `ios/SecretaryKit/Tests/SecretaryKitTests/UniffiVaultCreatePortTests.swift`

- [ ] **Step 1: Write the failing create responsiveness test**

In `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultProvisioningViewModelTests.swift`, add this test inside the class (after `testHappyPathPersistsThenShowsMnemonic`):

```swift
    func testMainActorIsFreeWhileCreating() async {
        let (vm, port, _) = makeVM(createResult: okResult(name: "v1"))
        let gate = SuspensionGate()
        port.gate = gate
        vm.chooseParent(URL(fileURLWithPath: "/p"), vaultName: "v1")

        let task = Task {
            await vm.create(displayName: "Owner",
                            password: Array("pw".utf8), confirm: Array("pw".utf8))
        }

        // Reaching past this await proves create did not hold the main actor:
        // the VM is suspended in the port while we run main-actor assertions.
        await gate.waitUntilEntered()
        XCTAssertEqual(port.lastVaultName, "v1")        // reached the port
        if case .mnemonic = vm.step { XCTFail("must not advance until port returns") }

        await gate.release()
        await task.value
        XCTAssertEqual(vm.step, .mnemonic)
        XCTAssertEqual(vm.mnemonicRows?.count, 24)
    }
```

- [ ] **Step 2: Run the test — expect a COMPILE failure (red)**

Run: `cd ios/SecretaryVaultAccess && swift test --filter VaultProvisioningViewModelTests`
Expected: FAIL to build — `value of type 'FakeVaultCreatePort' has no member 'gate'`.

- [ ] **Step 3: Make the create path async + offload — implementation**

(a) `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultProvisioning.swift` — make the protocol requirement async. Replace the `VaultCreatePort` protocol (lines 47–57):

```swift
/// Create boundary: mkdir a fresh subfolder named `vaultName` inside the
/// security-scoped `parent`, create a complete vault there via the FFI, build a
/// persistable bookmark, and return the location + recovery phrase. Throws
/// `VaultProvisioningError`. Implementations own all filesystem + FFI I/O so the
/// view-model is host-testable against a fake.
///
/// `async` because create runs Argon2id (CPU-heavy); implementations offload it
/// off the calling actor (see `SecretaryKit.runOffMainActor`).
public protocol VaultCreatePort {
    func create(parent: URL,
                vaultName: String,
                password: [UInt8],
                displayName: String) async throws -> CreatedVault
}
```

(b) `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeVaultCreatePort.swift` — add gate + async (replace the whole file):

```swift
import Foundation
import SecretaryVaultAccess

/// In-memory `VaultCreatePort` returning a pre-seeded result and spying on the
/// inputs the view-model forwarded.
public final class FakeVaultCreatePort: VaultCreatePort {
    private let result: Result<CreatedVault, VaultProvisioningError>
    public private(set) var lastParent: URL?
    public private(set) var lastVaultName: String?
    public private(set) var lastPassword: [UInt8]?
    public private(set) var lastDisplayName: String?
    /// Optional rendezvous so a responsiveness test can hold the call mid-flight.
    public var gate: SuspensionGate?

    public init(result: Result<CreatedVault, VaultProvisioningError>) {
        self.result = result
    }

    public func create(parent: URL,
                       vaultName: String,
                       password: [UInt8],
                       displayName: String) async throws -> CreatedVault {
        lastParent = parent
        lastVaultName = vaultName
        lastPassword = password
        lastDisplayName = displayName
        await gate?.enterAndWait()
        return try result.get()
    }
}
```

(c) `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultProvisioningViewModel.swift` — update the class doc comment (lines 5–9) and `await` the create call (line 53). Replace the doc comment block:

```swift
/// Drives the create-vault wizard over a `VaultCreatePort` and persists the new
/// location via a `VaultLocationStore`. Holds only injected ports, so it is fully
/// host-testable. `@MainActor` because it publishes UI state. The CPU-heavy
/// Argon2id create is offloaded off the main actor by the port implementation, so
/// `create` only suspends (it does not block) the main actor while the vault is built.
@MainActor
```

and change line 53 to:

```swift
            let created = try await createPort.create(parent: parent,
```

(d) `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultCreatePort.swift` — make `create` async and wrap the body in `runOffMainActor`. Change the signature line:

```swift
    public func create(parent: URL,
                       vaultName: String,
                       password: [UInt8],
                       displayName: String) async throws -> CreatedVault {
        try await runOffMainActor {
```

then wrap the existing body (the security-scope/mkdir/FFI/bookmark logic, lines 16–67) inside that closure — i.e. add the `try await runOffMainActor {` line right after the signature `{`, and add a matching `}` before the method's closing brace. The body is unchanged; only its execution context moves off the main actor. The `return CreatedVault(...)` becomes the closure's return.

Concretely, the method becomes:

```swift
    public func create(parent: URL,
                       vaultName: String,
                       password: [UInt8],
                       displayName: String) async throws -> CreatedVault {
        try await runOffMainActor {
            // Hold the parent's security scope for the whole create + bookmark window.
            let granted = parent.startAccessingSecurityScopedResource()
            defer { if granted { parent.stopAccessingSecurityScopedResource() } }

            let folder = parent.appendingPathComponent(vaultName, isDirectory: true)

            // mkdir the fresh subfolder. `withIntermediateDirectories: false` so that
            // an existing dir surfaces as a typed error rather than silently reusing it.
            do {
                try FileManager.default.createDirectory(
                    at: folder, withIntermediateDirectories: false)
            } catch let err as NSError
                where err.domain == NSCocoaErrorDomain && err.code == NSFileWriteFileExistsError {
                throw VaultProvisioningError.folderNotEmpty
            } catch {
                throw VaultProvisioningError.folderInvalid(String(describing: error))
            }

            let mnem: MnemonicOutput
            do {
                mnem = try SecretaryKit.createVaultInFolder(
                    folderPath: Data(folder.path.utf8),
                    password: Data(password),
                    displayName: displayName,
                    createdAtMs: UInt64(Date().timeIntervalSince1970 * 1000))
            } catch let e as VaultError {
                throw mapProvisioningError(e)
            }
            defer { mnem.wipe() }

            guard let phrase = mnem.takePhrase() else {
                throw VaultProvisioningError.createFailed("recovery phrase unavailable")
            }

            // Bookmark the NEW subfolder while still inside the parent's scope (the
            // standard pattern for bookmarking a child URL). iOS uses `[]` options.
            //
            // Degraded path: if bookmarking fails here the vault files are already
            // written, so we leave a complete-but-unreferenced vault folder on disk and
            // surface a typed error (never a silent no-op). The orphan is harmless — the
            // user can re-import the folder via "Import existing vault" to recover it.
            // We don't auto-delete it: destroying just-written user data on a transient
            // bookmark failure would be the worse outcome.
            let bookmark: Data
            do {
                bookmark = try folder.bookmarkData()
            } catch {
                throw VaultProvisioningError.folderInvalid(
                    "vault created but bookmark failed: \(String(describing: error))")
            }

            return CreatedVault(
                location: VaultLocation(displayName: vaultName, bookmark: bookmark),
                phrase: phrase)
        }
    }
```

- [ ] **Step 4: Thread the existing create-path test call sites**

(a) `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/FakeProvisioningFakesTests.swift`:

- `testCreatePortReturnsSeededResultAndSpiesInputs() throws` → `async throws`; line 10 `let out = try port.create(...)` → `let out = try await port.create(...)`.
- `testCreatePortThrowsSeededError()` → `async`; replace the `XCTAssertThrowsError(try port.create(...))` block (lines 22–33) with:

```swift
    func testCreatePortThrowsSeededError() async {
        let port = FakeVaultCreatePort(result: .failure(.folderNotEmpty))
        do {
            _ = try await port.create(parent: URL(fileURLWithPath: "/p"),
                                      vaultName: "v",
                                      password: [1],
                                      displayName: "d")
            XCTFail("expected create to throw")
        } catch {
            XCTAssertEqual(error as? VaultProvisioningError, .folderNotEmpty)
        }
        XCTAssertEqual(port.lastVaultName, "v")
        XCTAssertEqual(port.lastPassword, [1])
        XCTAssertEqual(port.lastDisplayName, "d")
    }
```

(b) `ios/SecretaryKit/Tests/SecretaryKitTests/UniffiVaultCreatePortTests.swift`:

- `testCreateThenOpenRoundTrips() throws` → `async throws`; line 17 `var created = try port.create(...)` → `var created = try await port.create(...)`.
- `testCreateIntoExistingNonEmptyNameThrowsFolderNotEmpty() throws` → `async throws`; replace the `XCTAssertThrowsError(try UniffiVaultCreatePort().create(...))` block (lines 46–49) with:

```swift
        do {
            _ = try await UniffiVaultCreatePort().create(
                parent: parent, vaultName: "v1", password: [1, 2, 3], displayName: "X")
            XCTFail("expected folderNotEmpty")
        } catch {
            XCTAssertEqual(error as? VaultProvisioningError, .folderNotEmpty)
        }
```

- `testShapeProbeDetectsVault() throws` → `async throws`; line 64 `_ = try UniffiVaultCreatePort().create(...)` → `_ = try await UniffiVaultCreatePort().create(...)`.

- [ ] **Step 5: Run the fast host tests — expect green**

Run: `cd ios/SecretaryVaultAccess && swift test`
Expected: PASS, including `testMainActorIsFreeWhileCreating` and the threaded `FakeProvisioningFakesTests`.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/argon2id-off-main-actor
git add ios/SecretaryVaultAccess ios/SecretaryKit
git commit -m "feat(ios): offload Argon2id create off the main actor (async VaultCreatePort)

VaultCreatePort.create becomes async throws; UniffiVaultCreatePort runs its whole
security-scope/mkdir/FFI/bookmark body inside runOffMainActor, so the @MainActor
VaultProvisioningViewModel only suspends — never blocks — during the KDF. Adds a
create responsiveness test mirroring the open path.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Docs — README + ROADMAP

**Files:**
- Modify: `README.md`
- Modify: `ROADMAP.md`

- [ ] **Step 1: Inspect the current iOS status sections**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/argon2id-off-main-actor
grep -n "include_deleted\|main actor\|Argon2\|iOS" README.md | head -20
grep -n "include_deleted\|iOS\|main actor\|progress\|2026-06" ROADMAP.md | head -20
```
Expected: locate the iOS status row/table in README and the dated progress line in ROADMAP that the previous slice updated.

- [ ] **Step 2: Add a README line for this slice**

Following the existing iOS status style (brief dot points — see `[[feedback_readme_style]]`), add a row/bullet noting: *Argon2id open/create now run off the main actor (UI stays responsive during the KDF); device unlock unaffected (HKDF, already fast).* Match the surrounding format exactly (table row vs bullet) — do not add a test-count wall.

- [ ] **Step 3: Update ROADMAP**

Update the iOS progress entry/date to reflect the responsiveness slice (2026-06-14). Mirror whatever shape the previous entry used (date + one-line progress note / progress bar). Keep it to one line.

- [ ] **Step 4: Verify no unintended scope in the docs diff**

Run: `git diff --stat README.md ROADMAP.md`
Expected: only README.md and ROADMAP.md changed, a handful of lines each.

- [ ] **Step 5: Commit**

```bash
git add README.md ROADMAP.md
git commit -m "docs: note Argon2id-off-main-actor responsiveness slice (README + ROADMAP)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Full gauntlet verification

**Files:** none (verification only).

- [ ] **Step 1: Fast host tests**

Run: `cd /Users/hherb/src/secretary/.worktrees/argon2id-off-main-actor/ios/SecretaryVaultAccess && swift test`
Expected: PASS — all existing tests plus `testMainActorIsFreeWhileOpening` and `testMainActorIsFreeWhileCreating`.

- [ ] **Step 2: Full iOS simulator gauntlet (compiles + runs SecretaryKit + app)**

Run: `cd /Users/hherb/src/secretary/.worktrees/argon2id-off-main-actor && bash ios/scripts/run-ios-tests.sh`
Expected: host green; SecretaryKit sim tests green (the threaded `UniffiVaultOpenPort`/`UniffiVaultCreatePort` integration tests exercise `runOffMainActor` against the real FFI); app BUILD/TEST SUCCEEDED. **Watch for any new Swift compiler warning** — the `runOffMainActor` design exists specifically to avoid a Sendable warning; if one appears, it is a regression to fix, not to accept (`[[feedback_security_no_assumptions]]`, clean-build discipline).

- [ ] **Step 3: Confirm no Rust/FFI/format/crypto/CRDT change**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/argon2id-off-main-actor
git diff main...HEAD --name-only | grep -vE '^(ios/|docs/|README.md|ROADMAP.md)' || echo "OK: only ios/ + docs touched"
git diff main...HEAD --name-only | grep -E 'crypto-design|vault-format|conflict.rs|core/|ffi/secretary-ffi|core/tests/data' && echo "UNEXPECTED core/ffi change" || echo "OK: no core/ffi/KAT change"
```
Expected: `OK: only ios/ + docs touched` and `OK: no core/ffi/KAT change`.

---

## Self-review notes (already applied)

- **Spec coverage:** every spec component maps to a task — async ports (T1 protocol, T2 protocol), adapter offload + `runOffMainActor` (T1 helper + open adapter, T2 create adapter), fakes async + gate (T1, T2), VM `await` + doc-comment (T1, T2), responsiveness tests (T1, T2), preserved typed errors (mapping kept inside the offloaded closures), threaded existing tests (T1 step 5, T2 step 4), docs (T3), full gauntlet incl. no-core-change check (T4).
- **No new error cases:** error mapping logic is unchanged; only its execution context moves inside `runOffMainActor`.
- **Type consistency:** `SuspensionGate` API (`enterAndWait` / `waitUntilEntered` / `release`) and the `gate` property name are used identically across both fakes and both responsiveness tests; `runOffMainActor` signature is identical at both adapter call sites.
- **Out of scope (unchanged):** device-unlock VM (HKDF, fast), cancellation, progress reporting, any core/FFI change.
