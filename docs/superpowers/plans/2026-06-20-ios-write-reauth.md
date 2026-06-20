# iOS biometric re-auth before a write — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Gate every mutating iOS vault write behind a biometric re-auth, with a grace window keyed off the Secure-Enclave key-release primitive.

**Architecture:** A view-model-level abstract `WriteReauthGate` port is awaited before each mutating write in `VaultBrowseViewModel` / `RecordEditViewModel`. The whole policy is a pure function (`needsReauth`). `GraceWindowReauthGate` (UI) drives an abstract `BiometricAuthorizer` only when enrolled and outside the grace window; the real `EnclaveBiometricAuthorizer` (SecretaryKit) wraps `DeviceSecretEnclave.release` and zeroizes the released secret. Not enrolled ⇒ no gate (writes proceed as today).

**Tech Stack:** Swift 5.9, SwiftPM, XCTest, `@MainActor` view models, LocalAuthentication/Secure Enclave (already wrapped behind `DeviceSecretEnclave`).

## Global Constraints

- **iOS only.** No change to `core/`, `docs/crypto-design.md`, `docs/vault-format.md`, any `*.udl`, `secretary-ffi-py`, or `android/`. Guardrail greps (see Acceptance) MUST be empty.
- **`VaultAccessError` is Swift-only**, distinct from the Rust-bridge `FfiVaultError`. Adding a case does **not** touch `FfiVaultError`/`*.udl`/the Swift+Kotlin conformance harnesses. The "FfiVaultError ⇒ workspace-wide match" rule does NOT apply.
- **No magic numbers.** The grace window is the named constant `ReauthWindow.v1Default = 30` seconds.
- **Not-enrolled = no gate.** The gate predicate is `BiometricAuthorizer.isEnrolled`; a non-enrolled session writes exactly as today (no regression).
- **Failed/cancelled re-auth ⇒ the write is NOT attempted**, `error` is set to `.reauthFailed`, and any open dialog/sheet stays open (mirrors the existing "failed write keeps it open" rule).
- **Concurrency annotations:** mirror the existing async-biometric precedent (`DeviceSecretEnclave.release` is `async` and awaited on `@MainActor` in `DeviceUnlockCoordinator`). Keep the zero-warning bar (`-D`-clean). Test fakes that hold mutable state and are passed to `@MainActor` consumers may use `@unchecked Sendable` with a one-line single-thread justification, as the codebase already does. See memory `project_secretary_ios_value_types_sendable_offload`.
- **Host tests run via `swift test`** in each package (no simulator). The single real-FFI proof runs via `ios/scripts/run-ios-tests.sh` (simulator). On-device Face ID is a manual handoff checklist item (biometry can't be automated in CI).
- **TDD, frequent commits, files < 500 lines.** New files are small and single-purpose.

---

## File structure

| File | Responsibility | Task |
|---|---|---|
| `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/Reauth.swift` (create) | `WriteReauthGate` + `BiometricAuthorizer` protocols, `ReauthWindow.v1Default`, pure `needsReauth` | 1 |
| `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultAccessError.swift` (modify) | add `.reauthFailed(String)` | 1 |
| `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/ReauthTests.swift` (create) | `needsReauth` unit tests | 1 |
| `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeBiometricAuthorizer.swift` (create) | spy authorizer | 2 |
| `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeWriteReauthGate.swift` (create) | pass-through / failing gate | 2 |
| `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/GraceWindowReauthGate.swift` (create) | grace-window gate holder | 3 |
| `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/GraceWindowReauthGateTests.swift` (create) | gate behavior tests | 3 |
| `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/RecordEditViewModel.swift` (modify) | gate `commit()` (async) | 4 |
| `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/RecordEditViewModelTests.swift` (modify) | await + gating tests | 4 |
| `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultBrowseViewModel.swift` (modify) | gate 4 actions (async) + `makeEditViewModel` passes gate | 5 |
| `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultBrowseViewModel{Tests,DeletedTests,BlockCrudTests}.swift` (modify) | await + gating tests | 5 |
| `ios/SecretaryKit/Sources/SecretaryKit/DeviceUnlock/EnclaveBiometricAuthorizer.swift` (create) | real authorizer over `DeviceSecretEnclave` | 6 |
| `ios/SecretaryKit/Tests/SecretaryKitTests/EnclaveBiometricAuthorizerTests.swift` (create) | simulator proof over fake enclave | 6 |
| `ios/SecretaryKit/Tests/SecretaryKitTests/BlockCrudRoundTripIntegrationTests.swift` (modify) | pass not-enrolled real gate + await | 6 |
| `ios/SecretaryApp/Sources/SecretaryApp.swift` (modify) | build real gate, inject into browse VM | 7 |
| `ios/SecretaryApp/Sources/{VaultBrowseScreen,BlockCrudViews,RecordEditScreen}.swift` (modify) | wrap 5 call sites in `Task { await }` | 7 |
| `README.md`, `ROADMAP.md` (modify) | status row; drop "deferred: biometric re-auth" notes | 7 |

---

### Task 1: Re-auth core — protocols, constant, pure policy, error case

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/Reauth.swift`
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultAccessError.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/ReauthTests.swift`

**Interfaces:**
- Produces: `protocol WriteReauthGate { func authorizeWrite(reason: String) async throws }`; `protocol BiometricAuthorizer { var isEnrolled: Bool { get }; func authorize(reason: String) async throws }`; `enum ReauthWindow { static let v1Default: TimeInterval }`; `func needsReauth(lastAuthAt: Date?, now: Date, window: TimeInterval) -> Bool`; `VaultAccessError.reauthFailed(String)`.

- [ ] **Step 1: Write the failing test**

Create `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/ReauthTests.swift`:

```swift
import XCTest
@testable import SecretaryVaultAccess

final class ReauthTests: XCTestCase {
    private let t0 = Date(timeIntervalSince1970: 1_000_000)

    func testNeverAuthedNeedsReauth() {
        XCTAssertTrue(needsReauth(lastAuthAt: nil, now: t0, window: 30))
    }

    func testWithinWindowDoesNotNeedReauth() {
        let last = t0
        let now = t0.addingTimeInterval(29)
        XCTAssertFalse(needsReauth(lastAuthAt: last, now: now, window: 30))
    }

    func testAtExactWindowNeedsReauth() {
        let last = t0
        let now = t0.addingTimeInterval(30)
        XCTAssertTrue(needsReauth(lastAuthAt: last, now: now, window: 30),
                      "boundary is inclusive: exactly `window` ⇒ re-auth")
    }

    func testPastWindowNeedsReauth() {
        XCTAssertTrue(needsReauth(lastAuthAt: t0, now: t0.addingTimeInterval(31), window: 30))
    }

    func testV1DefaultIsThirtySeconds() {
        XCTAssertEqual(ReauthWindow.v1Default, 30)
    }

    func testReauthFailedEquatable() {
        XCTAssertEqual(VaultAccessError.reauthFailed("x"), .reauthFailed("x"))
        XCTAssertNotEqual(VaultAccessError.reauthFailed("x"), .reauthFailed("y"))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter ReauthTests`
Expected: FAIL — `needsReauth`, `ReauthWindow`, and `.reauthFailed` are undefined.

- [ ] **Step 3: Create `Reauth.swift`**

```swift
import Foundation

/// The biometric primitive the re-auth gate drives. The real conformer wraps the
/// Secure-Enclave key-release (the released secret is zeroized + discarded — re-auth
/// only cares that the release succeeded). `isEnrolled` is the prompt-free predicate
/// that decides whether the gate engages at all.
public protocol BiometricAuthorizer {
    var isEnrolled: Bool { get }
    /// Prove presence. Throws `DeviceUnlockError`-class failures on cancel / non-match
    /// / lockout. `async` because the real conformer drives an `LAContext` evaluation.
    func authorize(reason: String) async throws
}

/// A gate the view models `await` before each mutating write. Conformers decide
/// whether a write needs a fresh biometric prompt (grace window) and engage the
/// biometric only when required.
public protocol WriteReauthGate {
    /// Returns normally when the write may proceed (authorized, within the grace
    /// window, or not enrolled); throws when biometry was required and failed.
    func authorizeWrite(reason: String) async throws
}

/// v1 re-auth grace window. Writes inside this window after the last successful auth
/// do not re-prompt. One global value (no per-write-type tuning in v1).
public enum ReauthWindow {
    public static let v1Default: TimeInterval = 30
}

/// Pure policy: does a write need a fresh biometric prompt? `true` when never authed
/// (`lastAuthAt == nil`) or when at least `window` seconds have elapsed since the last
/// auth. Boundary is inclusive: exactly `window` seconds ⇒ re-auth required.
public func needsReauth(lastAuthAt: Date?, now: Date, window: TimeInterval) -> Bool {
    guard let last = lastAuthAt else { return true }
    return now.timeIntervalSince(last) >= window
}
```

- [ ] **Step 4: Add the error case**

In `VaultAccessError.swift`, add before `case other(String)`:

```swift
    /// Biometric re-auth before a write failed or was cancelled. Carries a short
    /// human label derived from the underlying `DeviceUnlockError`. The write was
    /// NOT performed. Local to this Swift enum — NOT a Rust-bridge `FfiVaultError`.
    case reauthFailed(String)
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd ios/SecretaryVaultAccess && swift test --filter ReauthTests`
Expected: PASS (6 tests).

- [ ] **Step 6: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/Reauth.swift \
        ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultAccessError.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/ReauthTests.swift
git commit -m "feat(ios): re-auth core — gate/authorizer ports, needsReauth, reauthFailed"
```

---

### Task 2: Test fakes for the gate + authorizer

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeBiometricAuthorizer.swift`
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeWriteReauthGate.swift`

**Interfaces:**
- Consumes: `BiometricAuthorizer`, `WriteReauthGate`, `VaultAccessError` (Task 1).
- Produces: `FakeBiometricAuthorizer(isEnrolled:)` with `authorizeCount`, `failNextAuthorize: Error?`; `FakeWriteReauthGate()` with `authorizeCount`, `failNext: VaultAccessError?`.

- [ ] **Step 1: Create `FakeBiometricAuthorizer.swift`**

```swift
import Foundation
import SecretaryVaultAccess

/// Spy `BiometricAuthorizer` for host tests. `@unchecked Sendable`: a reference type
/// with mutable counters driven single-threaded by host tests (no real concurrency).
public final class FakeBiometricAuthorizer: BiometricAuthorizer, @unchecked Sendable {
    public var isEnrolled: Bool
    public private(set) var authorizeCount = 0
    /// When set, the NEXT `authorize` throws this once, then clears.
    public var failNextAuthorize: Error?

    public init(isEnrolled: Bool = true) { self.isEnrolled = isEnrolled }

    public func authorize(reason: String) async throws {
        authorizeCount += 1
        if let e = failNextAuthorize { failNextAuthorize = nil; throw e }
    }
}
```

- [ ] **Step 2: Create `FakeWriteReauthGate.swift`**

```swift
import Foundation
import SecretaryVaultAccess

/// Pass-through `WriteReauthGate` for host tests that don't exercise gating.
/// `failNext` makes the NEXT `authorizeWrite` throw it once. `@unchecked Sendable`
/// for the same single-thread reason as `FakeBiometricAuthorizer`.
public final class FakeWriteReauthGate: WriteReauthGate, @unchecked Sendable {
    public private(set) var authorizeCount = 0
    public var failNext: VaultAccessError?

    public init() {}

    public func authorizeWrite(reason: String) async throws {
        authorizeCount += 1
        if let e = failNext { failNext = nil; throw e }
    }
}
```

- [ ] **Step 3: Build to verify the Testing target compiles**

Run: `cd ios/SecretaryVaultAccess && swift build`
Expected: build succeeds (no warnings; if strict-concurrency flags the fakes, the `@unchecked Sendable` above is the sanctioned escape — keep the justification comment).

- [ ] **Step 4: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeBiometricAuthorizer.swift \
        ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeWriteReauthGate.swift
git commit -m "test(ios): fakes for BiometricAuthorizer + WriteReauthGate"
```

---

### Task 3: `GraceWindowReauthGate`

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/GraceWindowReauthGate.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/GraceWindowReauthGateTests.swift`

**Interfaces:**
- Consumes: `WriteReauthGate`, `BiometricAuthorizer`, `ReauthWindow`, `needsReauth` (Task 1); `FakeBiometricAuthorizer` (Task 2).
- Produces: `@MainActor final class GraceWindowReauthGate: WriteReauthGate` with `init(authorizer: BiometricAuthorizer, window: TimeInterval = ReauthWindow.v1Default, clock: @escaping () -> Date = Date.init, initialAuthAt: Date? = nil)`.

- [ ] **Step 1: Write the failing test**

Create `GraceWindowReauthGateTests.swift`:

```swift
import XCTest
@testable import SecretaryVaultAccessUI
import SecretaryVaultAccess
import SecretaryVaultAccessTesting

@MainActor
final class GraceWindowReauthGateTests: XCTestCase {
    private let t0 = Date(timeIntervalSince1970: 2_000_000)

    func testNotEnrolledIsNoOp() async throws {
        let auth = FakeBiometricAuthorizer(isEnrolled: false)
        let gate = GraceWindowReauthGate(authorizer: auth, clock: { self.t0 })
        try await gate.authorizeWrite(reason: "x")
        XCTAssertEqual(auth.authorizeCount, 0, "no SE key ⇒ never prompt")
    }

    func testEnrolledNeverAuthedPromptsOnce() async throws {
        let auth = FakeBiometricAuthorizer(isEnrolled: true)
        let gate = GraceWindowReauthGate(authorizer: auth, clock: { self.t0 })
        try await gate.authorizeWrite(reason: "x")
        XCTAssertEqual(auth.authorizeCount, 1)
    }

    func testWithinGraceDoesNotReprompt() async throws {
        var t = t0
        let auth = FakeBiometricAuthorizer(isEnrolled: true)
        let gate = GraceWindowReauthGate(authorizer: auth, window: 30, clock: { t })
        try await gate.authorizeWrite(reason: "x")     // prompts, lastAuthAt = t0
        t = t0.addingTimeInterval(10)
        try await gate.authorizeWrite(reason: "x")     // within grace
        XCTAssertEqual(auth.authorizeCount, 1)
    }

    func testPastGraceReprompts() async throws {
        var t = t0
        let auth = FakeBiometricAuthorizer(isEnrolled: true)
        let gate = GraceWindowReauthGate(authorizer: auth, window: 30, clock: { t })
        try await gate.authorizeWrite(reason: "x")     // prompt 1
        t = t0.addingTimeInterval(31)
        try await gate.authorizeWrite(reason: "x")     // prompt 2
        XCTAssertEqual(auth.authorizeCount, 2)
    }

    func testFailureLeavesClockUnchanged() async throws {
        var t = t0
        let auth = FakeBiometricAuthorizer(isEnrolled: true)
        auth.failNextAuthorize = VaultAccessError.reauthFailed("cancelled")
        let gate = GraceWindowReauthGate(authorizer: auth, window: 30, clock: { t })
        do { try await gate.authorizeWrite(reason: "x"); XCTFail("should throw") }
        catch {}
        // lastAuthAt was NOT advanced, so the next write still prompts immediately.
        t = t0.addingTimeInterval(1)
        try await gate.authorizeWrite(reason: "x")
        XCTAssertEqual(auth.authorizeCount, 2)
    }

    func testInitialAuthAtSeedsGrace() async throws {
        let auth = FakeBiometricAuthorizer(isEnrolled: true)
        // Seeded as just-authed (e.g. a device-unlock open); first write is free.
        let gate = GraceWindowReauthGate(authorizer: auth, window: 30,
                                         clock: { self.t0 }, initialAuthAt: self.t0)
        try await gate.authorizeWrite(reason: "x")
        XCTAssertEqual(auth.authorizeCount, 0)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter GraceWindowReauthGateTests`
Expected: FAIL — `GraceWindowReauthGate` undefined.

- [ ] **Step 3: Create `GraceWindowReauthGate.swift`**

```swift
import Foundation
import SecretaryVaultAccess

/// Grace-window re-auth gate over a `BiometricAuthorizer`. Engages only when the
/// authorizer is enrolled; within `window` of the last successful auth it is a no-op.
/// `@MainActor` because it holds mutable `lastAuthAt` consumed on the main actor
/// alongside the view models. `initialAuthAt` lets a device-unlock open seed the
/// clock (the unlock biometric counts); the password open path passes `nil`.
@MainActor
public final class GraceWindowReauthGate: WriteReauthGate {
    private let authorizer: BiometricAuthorizer
    private let window: TimeInterval
    private let clock: () -> Date
    private var lastAuthAt: Date?

    public init(authorizer: BiometricAuthorizer,
                window: TimeInterval = ReauthWindow.v1Default,
                clock: @escaping () -> Date = Date.init,
                initialAuthAt: Date? = nil) {
        self.authorizer = authorizer
        self.window = window
        self.clock = clock
        self.lastAuthAt = initialAuthAt
    }

    public func authorizeWrite(reason: String) async throws {
        guard authorizer.isEnrolled else { return }            // no SE key: no gate
        guard needsReauth(lastAuthAt: lastAuthAt, now: clock(), window: window) else { return }
        try await authorizer.authorize(reason: reason)         // biometric prompt
        lastAuthAt = clock()                                   // advance only on success
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ios/SecretaryVaultAccess && swift test --filter GraceWindowReauthGateTests`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/GraceWindowReauthGate.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/GraceWindowReauthGateTests.swift
git commit -m "feat(ios): GraceWindowReauthGate — enrollment-gated, grace-windowed re-auth"
```

---

### Task 4: Gate `RecordEditViewModel.commit()`

**Files:**
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/RecordEditViewModel.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/RecordEditViewModelTests.swift`

**Interfaces:**
- Consumes: `WriteReauthGate` (Task 1), `FakeWriteReauthGate` (Task 2).
- Produces: `RecordEditViewModel.init(session:blockUuid:mode:gate:)`; `func commit() async`.

- [ ] **Step 1: Write the failing tests (append to `RecordEditViewModelTests.swift`)**

Add a helper + two new tests. (The existing tests are updated in Step 4.)

```swift
    func testCommitBlockedByReauthDoesNotWrite() async {
        let s = FakeVaultSession(vaultUuidHex: "00", blocks: [],
                                 recordsByBlock: [block: []])
        let gate = FakeWriteReauthGate()
        gate.failNext = .reauthFailed("cancelled")
        let vm = RecordEditViewModel(session: s, blockUuid: block, mode: .add, gate: gate)
        vm.recordType = "login"
        vm.fields = [EditableField(name: "u", kind: .text, rawText: "v")]
        await vm.commit()
        XCTAssertEqual(vm.error, .reauthFailed("cancelled"))
        XCTAssertFalse(vm.committed, "a refused re-auth must not commit")
        // FakeVaultSession appended nothing: the block is still empty.
        XCTAssertEqual(try s.readBlock(blockUuid: block, includeDeleted: true).count, 0)
    }

    func testCommitProceedsWhenReauthAuthorizes() async {
        let s = FakeVaultSession(vaultUuidHex: "00", blocks: [],
                                 recordsByBlock: [block: []])
        let gate = FakeWriteReauthGate()       // pass-through
        let vm = RecordEditViewModel(session: s, blockUuid: block, mode: .add, gate: gate)
        vm.recordType = "login"
        vm.fields = [EditableField(name: "u", kind: .text, rawText: "v")]
        await vm.commit()
        XCTAssertNil(vm.error)
        XCTAssertTrue(vm.committed)
        XCTAssertEqual(gate.authorizeCount, 1)
    }
```

(`block` is the existing per-test block uuid constant in this file; reuse it. If the file builds the session through a local helper, mirror that helper.)

- [ ] **Step 2: Run to verify failure**

Run: `cd ios/SecretaryVaultAccess && swift test --filter RecordEditViewModelTests`
Expected: FAIL — `commit` is not async / `gate:` param missing.

- [ ] **Step 3: Add the gate to the VM**

In `RecordEditViewModel.swift`, change the stored deps + init:

```swift
    private let session: VaultSession
    private let blockUuid: [UInt8]
    private let gate: WriteReauthGate
    public let mode: Mode

    public init(session: VaultSession, blockUuid: [UInt8], mode: Mode, gate: WriteReauthGate) {
        self.session = session
        self.blockUuid = blockUuid
        self.mode = mode
        self.gate = gate
    }
```

Make `commit()` async and await the gate AFTER validation, BEFORE the write:

```swift
    public func commit() async {
        guard !committed, !isWriting, !loadFailed else { return }
        isWriting = true
        defer { isWriting = false }
        let content: RecordContentInput
        do {
            content = try buildContent()
        } catch let e as VaultAccessError {
            error = e
            return
        } catch {
            self.error = .other(String(describing: error))
            return
        }
        if let v = content.validate() {
            error = Self.mapValidation(v)
            return
        }
        // Re-auth gate: a refused biometric stops the write and surfaces the error,
        // leaving the form intact (committed stays false → screen does not dismiss).
        do {
            try await gate.authorizeWrite(reason: "Confirm saving this entry")
        } catch let e as VaultAccessError {
            error = e
            return
        } catch {
            self.error = .reauthFailed(String(describing: error))
            return
        }
        do {
            switch mode {
            case .add:
                try session.appendRecord(blockUuid: blockUuid, content: content)
            case .edit(let recordUuid):
                try session.editRecord(blockUuid: blockUuid, recordUuid: recordUuid, content: content)
            }
            error = nil
            committed = true
        } catch let e as VaultAccessError {
            error = e
        } catch {
            self.error = .other(String(describing: error))
        }
    }
```

- [ ] **Step 4: Update existing tests in this file**

Every existing `RecordEditViewModel(session: s, blockUuid: block, mode: …)` gains `, gate: FakeWriteReauthGate()`. Every existing `vm.commit()` becomes `await vm.commit()`, and its enclosing `func test…()` becomes `func test…() async`. Add `import SecretaryVaultAccessTesting` if not already present (it is — `FakeVaultSession` lives there).

- [ ] **Step 5: Run to verify pass**

Run: `cd ios/SecretaryVaultAccess && swift test --filter RecordEditViewModelTests`
Expected: PASS (all existing + 2 new).

- [ ] **Step 6: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/RecordEditViewModel.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/RecordEditViewModelTests.swift
git commit -m "feat(ios): re-auth gate before RecordEditViewModel.commit()"
```

---

### Task 5: Gate `VaultBrowseViewModel` (delete / restore / move / block-name)

**Files:**
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultBrowseViewModel.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultBrowseViewModelTests.swift`, `…DeletedTests.swift`, `…BlockCrudTests.swift`

**Interfaces:**
- Consumes: `WriteReauthGate` (Task 1), `FakeWriteReauthGate` (Task 2), `RecordEditViewModel.init(…gate:)` (Task 4).
- Produces: `VaultBrowseViewModel.init(session:gate:)`; `delete`/`restore`/`confirmMove`/`confirmBlockName` become `async`.

- [ ] **Step 1: Write the failing tests (append to `VaultBrowseViewModelBlockCrudTests.swift`)**

```swift
    func testConfirmBlockNameBlockedByReauthDoesNotWrite() async {
        let s = makeSession()                       // mirror the file's existing session helper
        let gate = FakeWriteReauthGate()
        gate.failNext = .reauthFailed("cancelled")
        let vm = VaultBrowseViewModel(session: s, gate: gate)
        vm.loadBlocks()
        let before = vm.blocks.count
        vm.startCreateBlock()
        await vm.confirmBlockName("New")
        XCTAssertEqual(vm.error, .reauthFailed("cancelled"))
        XCTAssertEqual(vm.blocks.count, before, "no block created on refused re-auth")
        XCTAssertNotNil(vm.blockNameDialog, "dialog stays open on a refused write")
    }

    func testNotEnrolledGateWritesAsBefore() async {
        let s = makeSession()
        let vm = VaultBrowseViewModel(session: s, gate: FakeWriteReauthGate())   // pass-through
        vm.loadBlocks()
        let before = vm.blocks.count
        vm.startCreateBlock()
        await vm.confirmBlockName("New")
        XCTAssertNil(vm.error)
        XCTAssertEqual(vm.blocks.count, before + 1)
        XCTAssertNil(vm.blockNameDialog)
    }
```

(Replace `makeSession()` with whatever fixture the file already uses to build a `FakeVaultSession`.)

- [ ] **Step 2: Run to verify failure**

Run: `cd ios/SecretaryVaultAccess && swift test --filter VaultBrowseViewModelBlockCrudTests`
Expected: FAIL — `gate:` param missing / `confirmBlockName` not async.

- [ ] **Step 3: Add the gate + make the four actions async**

In `VaultBrowseViewModel.swift`:

Init:
```swift
    private let session: VaultSession
    private let gate: WriteReauthGate
    public init(session: VaultSession, gate: WriteReauthGate) {
        self.session = session
        self.gate = gate
    }
```

Add one private async helper that runs the gate then the existing sync write, preserving the "failed write keeps dialog open" contract:

```swift
    /// Re-auth, then run a guarded write. Returns false (write not performed) if the
    /// re-auth is refused — surfacing `.reauthFailed` and leaving any open dialog/sheet
    /// untouched, exactly like a failed write. Otherwise delegates to `guardedWrite`.
    private func reauthedWrite(reason: String,
                              onSuccess: () -> Void,
                              op: () throws -> Void) async -> Bool {
        do {
            try await gate.authorizeWrite(reason: reason)
        } catch let e as VaultAccessError {
            error = e
            return false
        } catch {
            self.error = .reauthFailed(String(describing: error))
            return false
        }
        return guardedWrite(onSuccess: onSuccess, op: op)
    }
```

`delete` / `restore` (re-read the selected block on success, mirroring `commitThenReload`):
```swift
    public func delete(record: RecordView) async {
        guard let blockUuid = selectedBlockUuid else { return }
        _ = await reauthedWrite(reason: "Confirm deleting this entry",
                                onSuccess: { self.reload(blockUuid: blockUuid) }) {
            try self.session.tombstoneRecord(blockUuid: blockUuid, recordUuid: record.uuid)
        }
    }

    public func restore(record: RecordView) async {
        guard let blockUuid = selectedBlockUuid else { return }
        _ = await reauthedWrite(reason: "Confirm restoring this entry",
                                onSuccess: { self.reload(blockUuid: blockUuid) }) {
            try self.session.resurrectRecord(blockUuid: blockUuid, recordUuid: record.uuid)
        }
    }
```

(`commitThenReload` is now unused — delete it.)

`confirmMove` (same-block guard stays BEFORE the gate):
```swift
    public func confirmMove(target: BlockSummary) async {
        guard let record = movingRecord else { return }
        guard let source = selectedBlockUuid else { return }
        guard target.uuid != source else {
            error = .invalidArgument("source and target block must differ")
            return
        }
        let ok = await reauthedWrite(reason: "Confirm moving this entry",
                                     onSuccess: { self.refresh() }) {
            try self.session.moveRecord(sourceBlockUuid: source,
                                        targetBlockUuid: target.uuid,
                                        sourceRecordUuid: record.uuid)
        }
        if ok { movingRecord = nil }
    }
```

`confirmBlockName` (blank-name guard stays BEFORE the gate):
```swift
    public func confirmBlockName(_ name: String) async {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            error = .invalidArgument("block name must not be blank")
            return
        }
        guard let dialog = blockNameDialog else { return }
        let ok = await reauthedWrite(reason: "Confirm saving this block",
                                     onSuccess: { self.loadBlocks() }) {
            switch dialog {
            case .create:
                try self.session.createBlock(blockName: trimmed)
            case .rename(let block):
                try self.session.renameBlock(blockUuid: block.uuid, newName: trimmed)
            }
        }
        if ok { blockNameDialog = nil }
    }
```

`makeEditViewModel` passes the gate through:
```swift
    public func makeEditViewModel(mode: RecordEditViewModel.Mode) -> RecordEditViewModel? {
        guard let blockUuid = selectedBlockUuid else { return nil }
        return RecordEditViewModel(session: session, blockUuid: blockUuid, mode: mode, gate: gate)
    }
```

- [ ] **Step 4: Update the existing browse tests (3 files)**

In `VaultBrowseViewModelTests.swift`, `…DeletedTests.swift`, `…BlockCrudTests.swift`: every `VaultBrowseViewModel(session: …)` gains `, gate: FakeWriteReauthGate()`; every `vm.delete(record:)`, `vm.restore(record:)`, `vm.confirmMove(target:)`, `vm.confirmBlockName(…)` becomes `await …`, and the enclosing test func becomes `… async`. Add `import SecretaryVaultAccessTesting` if absent.

- [ ] **Step 5: Run to verify pass**

Run: `cd ios/SecretaryVaultAccess && swift test`
Expected: PASS — full `SecretaryVaultAccess` package suite green (existing + new gating tests).

- [ ] **Step 6: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultBrowseViewModel.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultBrowseViewModelTests.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultBrowseViewModelDeletedTests.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultBrowseViewModelBlockCrudTests.swift
git commit -m "feat(ios): re-auth gate before all VaultBrowseViewModel writes"
```

---

### Task 6: Real `EnclaveBiometricAuthorizer` + integration-test wiring

**Files:**
- Create: `ios/SecretaryKit/Sources/SecretaryKit/DeviceUnlock/EnclaveBiometricAuthorizer.swift`
- Test: `ios/SecretaryKit/Tests/SecretaryKitTests/EnclaveBiometricAuthorizerTests.swift`
- Modify: `ios/SecretaryKit/Tests/SecretaryKitTests/BlockCrudRoundTripIntegrationTests.swift`

**Interfaces:**
- Consumes: `BiometricAuthorizer` (Task 1), `DeviceSecretEnclave` + `DeviceUnlockError` (`SecretaryDeviceUnlock`), `InMemoryDeviceSecretEnclave` (`SecretaryDeviceUnlockTesting`), `GraceWindowReauthGate` (Task 3).
- Produces: `struct EnclaveBiometricAuthorizer: BiometricAuthorizer` over a `DeviceSecretEnclave`.

- [ ] **Step 1: Write the failing test**

Create `EnclaveBiometricAuthorizerTests.swift`:

```swift
import XCTest
@testable import SecretaryKit
import SecretaryVaultAccess
import SecretaryDeviceUnlock
import SecretaryDeviceUnlockTesting

final class EnclaveBiometricAuthorizerTests: XCTestCase {
    func testNotEnrolledReflectsEnclave() {
        let enclave = InMemoryDeviceSecretEnclave()       // nothing stored ⇒ not enrolled
        let auth = EnclaveBiometricAuthorizer(enclave: enclave)
        XCTAssertFalse(auth.isEnrolled)
    }

    func testAuthorizeReleasesAndSucceedsWhenEnrolled() async throws {
        let enclave = InMemoryDeviceSecretEnclave()
        try enclave.store(secret: [UInt8](repeating: 7, count: 32))
        let auth = EnclaveBiometricAuthorizer(enclave: enclave)
        XCTAssertTrue(auth.isEnrolled)
        try await auth.authorize(reason: "Confirm")       // drives release(); secret discarded
    }
}
```

(If `InMemoryDeviceSecretEnclave` always reports `isEnrolled == true` regardless of `store`, assert only the `store → authorize` path and the enrolled flag; adapt to the fake's actual semantics — read it first.)

- [ ] **Step 2: Run to verify failure**

Run: `cd ios/SecretaryKit && swift build` (host build of the test target) — or note it fails at the simulator step. Expected: FAIL — `EnclaveBiometricAuthorizer` undefined.

- [ ] **Step 3: Create `EnclaveBiometricAuthorizer.swift`**

```swift
import Foundation
import SecretaryVaultAccess
import SecretaryDeviceUnlock

/// Real `BiometricAuthorizer`: proves presence by driving the Secure-Enclave
/// key-release (the SAME biometry-bound gate as device unlock). The released device
/// secret is zeroized and discarded — re-auth only needs the release to succeed.
public struct EnclaveBiometricAuthorizer: BiometricAuthorizer {
    private let enclave: DeviceSecretEnclave

    public init(enclave: DeviceSecretEnclave) { self.enclave = enclave }

    public var isEnrolled: Bool { enclave.isEnrolled }

    public func authorize(reason: String) async throws {
        var secret = try await enclave.release(reason: reason)
        // Overwrite the released copy: re-auth discards it (we only needed the gate).
        for i in secret.indices { secret[i] = 0 }
        _ = secret
    }
}
```

(If the codebase has a canonical `[UInt8]` zeroize helper, use it instead of the manual loop — grep `zeroize`/`resetBytes` under `ios/SecretaryKit` and match the existing pattern.)

- [ ] **Step 4: Update `BlockCrudRoundTripIntegrationTests.swift`**

Add imports if missing:
```swift
import SecretaryDeviceUnlockTesting
```
Replace the VM construction (line ~53) so the round-trip drives a real, **not-enrolled** gate (no biometric ⇒ behavior identical to today):
```swift
        let gate = GraceWindowReauthGate(
            authorizer: EnclaveBiometricAuthorizer(enclave: InMemoryDeviceSecretEnclave()))
        let vm = VaultBrowseViewModel(session: session, gate: gate)
```
Make every gated call in the test `await` (`vm.confirmBlockName(…)`, `vm.confirmMove(…)`, and any `delete`/`restore`); the test class is already `@MainActor`, so mark the test method `async` if it isn't.

- [ ] **Step 5: Run the simulator gauntlet**

Run: `cd /Users/hherb/src/secretary/.worktrees/ios-write-reauth && bash ios/scripts/run-ios-tests.sh`
Expected: host `swift test` for both packages green; xcframework builds; `EnclaveBiometricAuthorizerTests` + `BlockCrudRoundTripIntegrationTests` green on the simulator.

- [ ] **Step 6: Commit**

```bash
git add ios/SecretaryKit/Sources/SecretaryKit/DeviceUnlock/EnclaveBiometricAuthorizer.swift \
        ios/SecretaryKit/Tests/SecretaryKitTests/EnclaveBiometricAuthorizerTests.swift \
        ios/SecretaryKit/Tests/SecretaryKitTests/BlockCrudRoundTripIntegrationTests.swift
git commit -m "feat(ios): EnclaveBiometricAuthorizer (SE key-release) + round-trip gate wiring"
```

---

### Task 7: App wiring + SwiftUI call sites + docs

**Files:**
- Modify: `ios/SecretaryApp/Sources/SecretaryApp.swift`
- Modify: `ios/SecretaryApp/Sources/VaultBrowseScreen.swift`, `BlockCrudViews.swift`, `RecordEditScreen.swift`
- Modify: `README.md`, `ROADMAP.md`

- [ ] **Step 1: Build the real gate in the app and inject it**

In `SecretaryApp.swift` at the browse construction (≈ line 106), build the gate from a default `SecureEnclaveDeviceSecretStore` (its `isEnrolled` is a prompt-free blob check; not enrolled ⇒ no gate). The main-app open is via password, so the clock is **not** seeded (`initialAuthAt` defaults to `nil` ⇒ the first mutating write prompts):

```swift
                            let reauthGate = GraceWindowReauthGate(
                                authorizer: EnclaveBiometricAuthorizer(
                                    enclave: SecureEnclaveDeviceSecretStore()))
                            route = .browse(VaultBrowseViewModel(session: session, gate: reauthGate),
                                            syncVM, monitor, scoped)
```

Add `import SecretaryVaultAccessUI` / `SecretaryVaultAccess` if not already imported (they are — `VaultBrowseViewModel` is already used here).

- [ ] **Step 2: Wrap the 5 SwiftUI call sites in `Task { await }`**

The gated VM actions are now `async`; wrap each button/handler:
- `VaultBrowseScreen.swift:148` → `Task { await viewModel.delete(record: record) }`
- `VaultBrowseScreen.swift:164` → `Button("Save") { Task { await viewModel.confirmBlockName(blockNameField) } }`
- `VaultBrowseScreen.swift:219` → `Task { await viewModel.restore(record: record) }`
- `BlockCrudViews.swift:25` → `Button(block.name) { Task { await viewModel.confirmMove(target: block) } }`
- `RecordEditScreen.swift:61` → `Button("Save") { Task { await viewModel.commit() } }`

(Grep `viewModel.delete(`/`viewModel.restore(`/`viewModel.confirmMove(`/`viewModel.confirmBlockName(`/`viewModel.commit(` across `ios/SecretaryApp/Sources/` to catch any site these line numbers missed.)

- [ ] **Step 3: Build the app**

Run: `cd /Users/hherb/src/secretary/.worktrees/ios-write-reauth && bash ios/scripts/build-app.sh`
Expected: `** BUILD SUCCEEDED **`.

- [ ] **Step 4: Update README + ROADMAP**

In `README.md`: add a new status-table row after the existing iOS record-CRUD row (line ~182), mirroring its style, describing the biometric-re-auth-before-write slice (grace window 30s; SE key-release primitive; not-enrolled = no gate; host-tested gate + `needsReauth` + VM tests + simulator `EnclaveBiometricAuthorizer` proof; on-device Face ID proof = manual checklist). In that record-CRUD row, change the trailing "Deferred: biometric re-auth before a write." to note it shipped this slice (or drop the clause).

In `ROADMAP.md`: add an iOS bullet mirroring the existing iOS C.3 entries; in the record-CRUD entry (line ~104) remove "biometric re-auth before a write" from the **Deferred follow-ups** list. Reference the spec + plan paths.

- [ ] **Step 5: Verify guardrails empty**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/ios-write-reauth
git diff main...HEAD --name-only | grep -E 'core/|crypto-design|vault-format|\.udl|secretary-ffi-py|android/'   # expect EMPTY
git diff main...HEAD --name-only | grep -E '\.rs$|Cargo'                                                        # expect EMPTY
```
Expected: both empty.

- [ ] **Step 6: Commit**

```bash
git add ios/SecretaryApp/Sources/SecretaryApp.swift \
        ios/SecretaryApp/Sources/VaultBrowseScreen.swift \
        ios/SecretaryApp/Sources/BlockCrudViews.swift \
        ios/SecretaryApp/Sources/RecordEditScreen.swift \
        README.md ROADMAP.md
git commit -m "feat(ios): wire re-auth gate into the app + async call sites; docs"
```

---

## Acceptance criteria (whole branch)

```bash
cd /Users/hherb/src/secretary/.worktrees/ios-write-reauth

# Host VM + gate + pure-function suite (fast, no simulator):
cd ios/SecretaryVaultAccess && swift test          # all green incl. ReauthTests + GraceWindowReauthGateTests + new VM gating tests
cd ../SecretaryDeviceUnlock && swift test          # unaffected, still green

# Full simulator gauntlet (regenerate bindings, build framework, XCTest):
cd /Users/hherb/src/secretary/.worktrees/ios-write-reauth
bash ios/scripts/run-ios-tests.sh                  # EnclaveBiometricAuthorizerTests + round-trip green
bash ios/scripts/build-app.sh                      # ** BUILD SUCCEEDED **

# Guardrails (both EMPTY):
git diff main...HEAD --name-only | grep -E 'core/|crypto-design|vault-format|\.udl|secretary-ffi-py|android/'
git diff main...HEAD --name-only | grep -E '\.rs$|Cargo'
```

- Enrolled session: a mutating write outside the grace window prompts biometry first; within the window it does not re-prompt.
- Cancelled/failed biometric prevents the write (no session write call), sets `.reauthFailed`, keeps any open dialog/sheet open.
- Non-enrolled session writes exactly as today (no regression).
- On-device Face ID proof: manual handoff checklist item.

## Self-review notes

- **Spec coverage:** grace window (Task 1 `needsReauth`/`ReauthWindow` + Task 3 gate), SE key-release primitive (Task 6), `isEnrolled` predicate (Task 3 guard + Task 6), VM injection (Tasks 4–5), all six write sites (Task 4 commit + Task 5 four actions), error surface `.reauthFailed` (Task 1 + 4 + 5), app wiring + async call sites (Task 7), docs (Task 7). All covered.
- **Type consistency:** `WriteReauthGate.authorizeWrite(reason:)`, `BiometricAuthorizer.authorize(reason:)`/`isEnrolled`, `GraceWindowReauthGate.init(authorizer:window:clock:initialAuthAt:)`, `EnclaveBiometricAuthorizer.init(enclave:)`, `VaultAccessError.reauthFailed(String)`, `RecordEditViewModel.init(session:blockUuid:mode:gate:)`, `VaultBrowseViewModel.init(session:gate:)` — names identical across tasks.
- **Concurrency caveat (flagged, not a placeholder):** if the zero-warning bar surfaces a Sendable requirement when an `@MainActor` VM awaits the existential gate, follow the `DeviceSecretEnclave`/`runOffMainActor` precedent already in the repo (memory `project_secretary_ios_value_types_sendable_offload`); the fakes carry `@unchecked Sendable` for that reason.
