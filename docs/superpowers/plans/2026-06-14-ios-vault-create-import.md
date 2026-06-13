# iOS Vault Create / Import UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a native-iOS create-vault wizard and an import affordance, sitting on the Slice-1 `createVaultInFolder` FFI surface, mirroring desktop D.1.3 parity.

**Architecture:** A pure wizard (validation, password-match, mnemonic grouping, step state machine) and a host-tested `VaultProvisioningViewModel` drive the create flow over two ports — `VaultCreatePort` (mkdir + `createVaultInFolder` + bookmark) and `VaultShapeProbe` (import `vault.toml` detection). Real FFI/filesystem adapters live in `SecretaryKit`; SwiftUI wizard views live in `SecretaryApp`. No `core/src`, FFI, or frozen-format change.

**Tech Stack:** Swift 5.9, SwiftUI, SwiftPM packages (`SecretaryVaultAccess` pure / `SecretaryVaultAccessUI` view-models / `SecretaryVaultAccessTesting` fakes / `SecretaryKit` FFI adapters), XcodeGen app target, uniffi-generated bindings.

---

## File Structure

**`SecretaryVaultAccess` (pure, FFI-free):**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultName.swift` — `validateVaultName(_:)`
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/PasswordMatch.swift` — `passwordsMatch(_:_:)`
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/MnemonicWord.swift` — `MnemonicWord` + `groupMnemonic(_:)`
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultProvisioning.swift` — `VaultProvisioningStep`, `VaultProvisioningError`, `CreatedVault`, `VaultCreatePort`, `VaultShapeProbe`, `ImportOutcome`

**`SecretaryVaultAccessUI` (host-tested):**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultProvisioningViewModel.swift`
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultSelectionViewModel.swift` (add probe + `considerImport`)

**`SecretaryVaultAccessTesting` (shared fakes):**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeVaultCreatePort.swift`
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeVaultShapeProbe.swift`

**Tests (host, `swift test`):**
- Create: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/VaultNameTests.swift`
- Create: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/PasswordMatchTests.swift`
- Create: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/MnemonicWordTests.swift`
- Create: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/FakeProvisioningFakesTests.swift`
- Create: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultProvisioningViewModelTests.swift`
- Modify: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultSelectionViewModelTests.swift` (probe + import outcomes)

**`SecretaryKit` (real adapters + simulator test):**
- Create: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultCreatePort.swift`
- Create: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/FileManagerVaultShapeProbe.swift`
- Create: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/ProvisioningErrorMapping.swift`
- Create: `ios/SecretaryKit/Tests/SecretaryKitTests/UniffiVaultCreatePortTests.swift`

**`SecretaryApp` (SwiftUI):**
- Create: `ios/SecretaryApp/Sources/CreateVaultWizardView.swift`
- Modify: `ios/SecretaryApp/Sources/VaultSelectionScreen.swift` (Create / Import branching)
- Modify: `ios/SecretaryApp/Sources/SecretaryApp.swift` (route to wizard; pass probe to selection VM)

**Docs:**
- Modify: `README.md`, `ROADMAP.md`

---

### Task 1: Pure helper — `validateVaultName`

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultName.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/VaultNameTests.swift`

- [ ] **Step 1: Write the failing test**

```swift
import XCTest
@testable import SecretaryVaultAccess

final class VaultNameTests: XCTestCase {
    func testValidName() {
        XCTAssertEqual(validateVaultName("My Vault"), .valid("My Vault"))
    }

    func testTrimsSurroundingWhitespace() {
        XCTAssertEqual(validateVaultName("  vault  "), .valid("vault"))
    }

    func testEmptyIsRejected() {
        XCTAssertEqual(validateVaultName(""), .invalid(.empty))
        XCTAssertEqual(validateVaultName("   "), .invalid(.empty))
    }

    func testPathSeparatorIsRejected() {
        XCTAssertEqual(validateVaultName("a/b"), .invalid(.containsSeparator))
    }

    func testDotNamesAreRejected() {
        XCTAssertEqual(validateVaultName("."), .invalid(.reservedName))
        XCTAssertEqual(validateVaultName(".."), .invalid(.reservedName))
    }

    func testNullByteIsRejected() {
        XCTAssertEqual(validateVaultName("a\u{0}b"), .invalid(.containsSeparator))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter VaultNameTests`
Expected: FAIL — `validateVaultName` / `ValidatedVaultName` not defined.

- [ ] **Step 3: Write minimal implementation**

```swift
import Foundation

/// Why a vault name is rejected by `validateVaultName`.
public enum VaultNameError: Equatable {
    /// Empty or whitespace-only.
    case empty
    /// Contains a path separator (`/`) or NUL — would escape the chosen parent.
    case containsSeparator
    /// The reserved directory names `.` or `..`.
    case reservedName
}

/// Result of validating a user-typed vault (sub)folder name. The `.valid`
/// payload is the trimmed name actually used for `mkdir`.
public enum ValidatedVaultName: Equatable {
    case valid(String)
    case invalid(VaultNameError)
}

/// Validate a vault folder name the user typed in the create wizard. The name
/// becomes a fresh subfolder inside the picked parent, so it must be a single
/// path component: non-empty, no separators / NUL, and not the reserved `.`/`..`.
/// Mirrors desktop D.1.3's `joinSubfolder` traversal guard.
public func validateVaultName(_ raw: String) -> ValidatedVaultName {
    let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
    if trimmed.isEmpty { return .invalid(.empty) }
    if trimmed.contains("/") || trimmed.contains("\u{0}") { return .invalid(.containsSeparator) }
    if trimmed == "." || trimmed == ".." { return .invalid(.reservedName) }
    return .valid(trimmed)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ios/SecretaryVaultAccess && swift test --filter VaultNameTests`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultName.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/VaultNameTests.swift
git commit -m "feat(ios): validateVaultName pure helper for create wizard"
```

---

### Task 2: Pure helper — `passwordsMatch`

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/PasswordMatch.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/PasswordMatchTests.swift`

- [ ] **Step 1: Write the failing test**

```swift
import XCTest
@testable import SecretaryVaultAccess

final class PasswordMatchTests: XCTestCase {
    func testMatchingNonEmpty() {
        XCTAssertTrue(passwordsMatch(Array("hunter2".utf8), Array("hunter2".utf8)))
    }

    func testEmptyDoesNotMatch() {
        // An empty password is not a valid create credential even if "confirmed".
        XCTAssertFalse(passwordsMatch([], []))
    }

    func testMismatch() {
        XCTAssertFalse(passwordsMatch(Array("a".utf8), Array("b".utf8)))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter PasswordMatchTests`
Expected: FAIL — `passwordsMatch` not defined.

- [ ] **Step 3: Write minimal implementation**

```swift
import Foundation

/// True iff `password` and `confirm` are byte-equal AND non-empty. Gates the
/// create wizard's credentials step (desktop D.1.3 parity: both fields filled
/// and identical; no password-strength rule). This is a UX confirm-match check,
/// NOT a secret comparison against stored material, so constant-time is not
/// required here.
public func passwordsMatch(_ password: [UInt8], _ confirm: [UInt8]) -> Bool {
    !password.isEmpty && password == confirm
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ios/SecretaryVaultAccess && swift test --filter PasswordMatchTests`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/PasswordMatch.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/PasswordMatchTests.swift
git commit -m "feat(ios): passwordsMatch pure helper for create wizard"
```

---

### Task 3: Pure helper — `MnemonicWord` + `groupMnemonic`

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/MnemonicWord.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/MnemonicWordTests.swift`

- [ ] **Step 1: Write the failing test**

```swift
import XCTest
@testable import SecretaryVaultAccess

final class MnemonicWordTests: XCTestCase {
    func testGroupsTwentyFourWordsNumbered() {
        let phrase = (1...24).map { "w\($0)" }.joined(separator: " ")
        let rows = groupMnemonic(phrase)
        XCTAssertEqual(rows.count, 24)
        XCTAssertEqual(rows.first, MnemonicWord(number: 1, word: "w1"))
        XCTAssertEqual(rows.last, MnemonicWord(number: 24, word: "w24"))
    }

    func testCollapsesExtraWhitespace() {
        let rows = groupMnemonic("  alpha   beta \n gamma ")
        XCTAssertEqual(rows, [
            MnemonicWord(number: 1, word: "alpha"),
            MnemonicWord(number: 2, word: "beta"),
            MnemonicWord(number: 3, word: "gamma"),
        ])
    }

    func testEmptyPhraseYieldsNoRows() {
        XCTAssertEqual(groupMnemonic("   "), [])
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter MnemonicWordTests`
Expected: FAIL — `MnemonicWord` / `groupMnemonic` not defined.

- [ ] **Step 3: Write minimal implementation**

```swift
import Foundation

/// One numbered word of a recovery phrase, for display in the mnemonic step.
/// 1-based `number` matches how users transcribe BIP-39 phrases.
public struct MnemonicWord: Equatable {
    public let number: Int
    public let word: String

    public init(number: Int, word: String) {
        self.number = number
        self.word = word
    }
}

/// Split a space-separated recovery phrase into numbered words for display.
/// Whitespace-tolerant (collapses runs, ignores leading/trailing). Pure: does no
/// I/O and holds no secret beyond the returned value, which the caller drops once
/// the mnemonic step is dismissed.
public func groupMnemonic(_ phrase: String) -> [MnemonicWord] {
    phrase
        .split(whereSeparator: { $0.isWhitespace })
        .enumerated()
        .map { MnemonicWord(number: $0.offset + 1, word: String($0.element)) }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ios/SecretaryVaultAccess && swift test --filter MnemonicWordTests`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/MnemonicWord.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/MnemonicWordTests.swift
git commit -m "feat(ios): MnemonicWord + groupMnemonic display helper"
```

---

### Task 4: Provisioning types & ports

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultProvisioning.swift`
- Test: (covered by Task 5's fakes + Task 6's view-model; this task adds the type definitions and a tiny enum sanity test in Task 5's file)

- [ ] **Step 1: Write the implementation (no behaviour to TDD — these are interface/type definitions; their behaviour is exercised by the fakes in Task 5 and the view-model in Task 6)**

```swift
import Foundation

/// Wizard step for creating a brand-new vault. Holds only NON-secret data; the
/// recovery phrase is held privately by `VaultProvisioningViewModel`, never in
/// this (Equatable) value.
public enum VaultProvisioningStep: Equatable {
    /// Pick a parent location + type a vault name.
    case folder
    /// Enter display name + password + confirm. Carries the validated inputs
    /// from the folder step.
    case credentials(parent: URL, vaultName: String)
    /// The vault was created + its location persisted; show the recovery phrase.
    case mnemonic
    /// User acknowledged the phrase; the new vault is ready to open.
    case done(VaultLocation)
}

/// Typed failures surfaced by the create wizard. Maps from the FFI `VaultError`
/// (see SecretaryKit's `mapProvisioningError`) plus the local name-validation gate.
public enum VaultProvisioningError: Error, Equatable {
    /// The typed name failed `validateVaultName`.
    case invalidName(VaultNameError)
    /// Password and confirm did not match (or were empty).
    case passwordMismatch
    /// A folder with that name already exists and is non-empty.
    case folderNotEmpty
    /// The chosen location could not be used (path invalid / unreadable).
    case folderInvalid(String)
    /// Any other create failure, with a diagnostic detail.
    case createFailed(String)
}

/// The product of a successful create: the persisted, openable location plus the
/// one-shot recovery-phrase bytes (UTF-8). The caller (view-model) owns zeroizing
/// `phrase` once the mnemonic step is dismissed.
public struct CreatedVault {
    public let location: VaultLocation
    public var phrase: [UInt8]

    public init(location: VaultLocation, phrase: [UInt8]) {
        self.location = location
        self.phrase = phrase
    }
}

/// Create boundary: mkdir a fresh subfolder named `vaultName` inside the
/// security-scoped `parent`, create a complete vault there via the FFI, build a
/// persistable bookmark, and return the location + recovery phrase. Throws
/// `VaultProvisioningError`. Implementations own all filesystem + FFI I/O so the
/// view-model is host-testable against a fake.
public protocol VaultCreatePort {
    func create(parent: URL,
                vaultName: String,
                password: [UInt8],
                displayName: String) throws -> CreatedVault
}

/// Import boundary: cheap, crypto-free check of whether `folder` looks like a
/// vault (contains `vault.toml`). Throws only on an unreadable folder.
public protocol VaultShapeProbe {
    func looksLikeVault(_ folder: URL) throws -> Bool
}

/// Outcome of considering a picked folder for import.
public enum ImportOutcome: Equatable {
    /// The folder is a vault; it has been persisted and is ready to open.
    case opened
    /// The folder does not contain a vault (no `vault.toml`).
    case notAVault
    /// The folder could not be inspected (unreadable / probe error).
    case unavailable(String)
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd ios/SecretaryVaultAccess && swift build`
Expected: builds clean (no test yet — behaviour is covered in Tasks 5–6).

- [ ] **Step 3: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultProvisioning.swift
git commit -m "feat(ios): provisioning step/error/port types for create+import"
```

---

### Task 5: Test fakes — `FakeVaultCreatePort` + `FakeVaultShapeProbe`

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeVaultCreatePort.swift`
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeVaultShapeProbe.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/FakeProvisioningFakesTests.swift`

- [ ] **Step 1: Write the failing test**

```swift
import XCTest
import SecretaryVaultAccess
import SecretaryVaultAccessTesting

final class FakeProvisioningFakesTests: XCTestCase {
    func testCreatePortReturnsSeededResultAndSpiesInputs() throws {
        let loc = VaultLocation(displayName: "v1", bookmark: Data("bm".utf8))
        let port = FakeVaultCreatePort(result: .success(
            CreatedVault(location: loc, phrase: Array("word1 word2".utf8))))
        let out = try port.create(parent: URL(fileURLWithPath: "/p"),
                                  vaultName: "v1",
                                  password: Array("pw".utf8),
                                  displayName: "Owner")
        XCTAssertEqual(out.location, loc)
        XCTAssertEqual(port.lastVaultName, "v1")
        XCTAssertEqual(port.lastPassword, Array("pw".utf8))
        XCTAssertEqual(port.lastDisplayName, "Owner")
    }

    func testCreatePortThrowsSeededError() {
        let port = FakeVaultCreatePort(result: .failure(.folderNotEmpty))
        XCTAssertThrowsError(try port.create(parent: URL(fileURLWithPath: "/p"),
                                             vaultName: "v",
                                             password: [1],
                                             displayName: "d")) {
            XCTAssertEqual($0 as? VaultProvisioningError, .folderNotEmpty)
        }
    }

    func testShapeProbeReturnsSeededAnswer() throws {
        XCTAssertTrue(try FakeVaultShapeProbe(answer: .success(true))
            .looksLikeVault(URL(fileURLWithPath: "/p")))
        XCTAssertFalse(try FakeVaultShapeProbe(answer: .success(false))
            .looksLikeVault(URL(fileURLWithPath: "/p")))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter FakeProvisioningFakesTests`
Expected: FAIL — fakes not defined.

- [ ] **Step 3: Write minimal implementation**

`FakeVaultCreatePort.swift`:
```swift
import Foundation
import SecretaryVaultAccess

/// In-memory `VaultCreatePort` returning a pre-seeded result and spying on the
/// inputs the view-model forwarded.
public final class FakeVaultCreatePort: VaultCreatePort {
    private let result: Result<CreatedVault, VaultProvisioningError>
    public private(set) var lastVaultName: String?
    public private(set) var lastPassword: [UInt8]?
    public private(set) var lastDisplayName: String?

    public init(result: Result<CreatedVault, VaultProvisioningError>) {
        self.result = result
    }

    public func create(parent: URL,
                       vaultName: String,
                       password: [UInt8],
                       displayName: String) throws -> CreatedVault {
        lastVaultName = vaultName
        lastPassword = password
        lastDisplayName = displayName
        return try result.get()
    }
}
```

`FakeVaultShapeProbe.swift`:
```swift
import Foundation
import SecretaryVaultAccess

/// In-memory `VaultShapeProbe` returning a pre-seeded answer.
public final class FakeVaultShapeProbe: VaultShapeProbe {
    private let answer: Result<Bool, Error>
    public private(set) var lastFolder: URL?

    public init(answer: Result<Bool, Error>) {
        self.answer = answer
    }

    public func looksLikeVault(_ folder: URL) throws -> Bool {
        lastFolder = folder
        return try answer.get()
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ios/SecretaryVaultAccess && swift test --filter FakeProvisioningFakesTests`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeVaultCreatePort.swift \
        ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeVaultShapeProbe.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/FakeProvisioningFakesTests.swift
git commit -m "test(ios): fakes for VaultCreatePort + VaultShapeProbe"
```

---

### Task 6: `VaultProvisioningViewModel`

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultProvisioningViewModel.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultProvisioningViewModelTests.swift`

- [ ] **Step 1: Write the failing test**

```swift
import XCTest
import Combine
import SecretaryVaultAccess
import SecretaryVaultAccessTesting
@testable import SecretaryVaultAccessUI

@MainActor
final class VaultProvisioningViewModelTests: XCTestCase {
    private func makeVM(
        createResult: Result<CreatedVault, VaultProvisioningError>
    ) -> (VaultProvisioningViewModel, FakeVaultCreatePort, FakeVaultLocationStore) {
        let port = FakeVaultCreatePort(result: createResult)
        let store = FakeVaultLocationStore()
        return (VaultProvisioningViewModel(createPort: port, store: store), port, store)
    }

    private func okResult(name: String = "v1") -> Result<CreatedVault, VaultProvisioningError> {
        .success(CreatedVault(
            location: VaultLocation(displayName: name, bookmark: Data("bm".utf8)),
            phrase: Array((1...24).map { "w\($0)" }.joined(separator: " ").utf8)))
    }

    func testFolderStepRejectsInvalidName() {
        let (vm, _, _) = makeVM(createResult: okResult())
        vm.chooseParent(URL(fileURLWithPath: "/p"), vaultName: "a/b")
        XCTAssertEqual(vm.step, .folder)
        XCTAssertEqual(vm.nameError, .containsSeparator)
    }

    func testFolderStepAdvancesOnValidName() {
        let (vm, _, _) = makeVM(createResult: okResult())
        vm.chooseParent(URL(fileURLWithPath: "/p"), vaultName: "  My Vault  ")
        XCTAssertEqual(vm.step, .credentials(parent: URL(fileURLWithPath: "/p"), vaultName: "My Vault"))
        XCTAssertNil(vm.nameError)
    }

    func testPasswordMismatchBlocksCreate() async {
        let (vm, port, _) = makeVM(createResult: okResult())
        vm.chooseParent(URL(fileURLWithPath: "/p"), vaultName: "v1")
        await vm.create(displayName: "Owner",
                        password: Array("a".utf8), confirm: Array("b".utf8))
        XCTAssertEqual(vm.error, .passwordMismatch)
        XCTAssertNil(port.lastPassword)             // never reached the port
        if case .mnemonic = vm.step { XCTFail("must not advance") }
    }

    func testHappyPathPersistsThenShowsMnemonic() async {
        let (vm, port, store) = makeVM(createResult: okResult(name: "v1"))
        vm.chooseParent(URL(fileURLWithPath: "/p"), vaultName: "v1")
        await vm.create(displayName: "Owner",
                        password: Array("pw".utf8), confirm: Array("pw".utf8))
        XCTAssertEqual(port.lastVaultName, "v1")
        XCTAssertEqual(port.lastDisplayName, "Owner")
        XCTAssertEqual(store.stored?.displayName, "v1")   // persisted BEFORE mnemonic
        XCTAssertEqual(vm.step, .mnemonic)
        XCTAssertEqual(vm.mnemonicRows?.count, 24)
    }

    func testFolderNotEmptyErrorSurfaces() async {
        let (vm, _, store) = makeVM(createResult: .failure(.folderNotEmpty))
        vm.chooseParent(URL(fileURLWithPath: "/p"), vaultName: "v1")
        await vm.create(displayName: "Owner",
                        password: Array("pw".utf8), confirm: Array("pw".utf8))
        XCTAssertEqual(vm.error, .folderNotEmpty)
        XCTAssertNil(store.stored)                        // nothing persisted on failure
        XCTAssertEqual(vm.step, .credentials(parent: URL(fileURLWithPath: "/p"), vaultName: "v1"))
    }

    func testAcknowledgeClearsPhraseAndCompletes() async {
        let (vm, _, _) = makeVM(createResult: okResult(name: "v1"))
        vm.chooseParent(URL(fileURLWithPath: "/p"), vaultName: "v1")
        await vm.create(displayName: "Owner",
                        password: Array("pw".utf8), confirm: Array("pw".utf8))
        vm.acknowledgeMnemonic()
        XCTAssertNil(vm.mnemonicRows)                     // display cleared
        guard case .done(let loc) = vm.step else { return XCTFail("expected .done") }
        XCTAssertEqual(loc.displayName, "v1")
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter VaultProvisioningViewModelTests`
Expected: FAIL — `VaultProvisioningViewModel` not defined.

- [ ] **Step 3: Write minimal implementation**

```swift
import Foundation
import Combine
import SecretaryVaultAccess

/// Drives the create-vault wizard over a `VaultCreatePort` and persists the new
/// location via a `VaultLocationStore`. Holds only injected ports, so it is fully
/// host-testable. `@MainActor` because it publishes UI state; like `UnlockViewModel`,
/// the CPU-heavy Argon2id create briefly blocks the main actor on the create path
/// (accepted for this slice; background-offload is a noted follow-up).
@MainActor
public final class VaultProvisioningViewModel: ObservableObject {
    @Published public private(set) var step: VaultProvisioningStep = .folder
    @Published public private(set) var nameError: VaultNameError?
    @Published public private(set) var error: VaultProvisioningError?
    /// Numbered words for the mnemonic step; `nil` outside that step or after ack.
    @Published public private(set) var mnemonicRows: [MnemonicWord]?

    private let createPort: VaultCreatePort
    private let store: VaultLocationStore
    /// The one-shot recovery phrase, held only between create and acknowledge.
    private var phrase: [UInt8]?

    public init(createPort: VaultCreatePort, store: VaultLocationStore) {
        self.createPort = createPort
        self.store = store
    }

    /// Validate the typed name and advance to the credentials step. On an invalid
    /// name, stay on `.folder` and publish `nameError`.
    public func chooseParent(_ parent: URL, vaultName: String) {
        error = nil
        switch validateVaultName(vaultName) {
        case .invalid(let e):
            nameError = e
        case .valid(let name):
            nameError = nil
            step = .credentials(parent: parent, vaultName: name)
        }
    }

    /// Create the vault: confirm-match the password, call the port, persist the
    /// location BEFORE revealing the phrase (so a crash mid-flow leaves an openable
    /// vault), then advance to the mnemonic step. The caller owns clearing its own
    /// Swift-side `password`/`confirm` copies after this returns.
    public func create(displayName: String, password: [UInt8], confirm: [UInt8]) async {
        guard case .credentials(let parent, let vaultName) = step else { return }
        error = nil
        guard passwordsMatch(password, confirm) else {
            error = .passwordMismatch
            return
        }
        do {
            var created = try createPort.create(parent: parent,
                                                vaultName: vaultName,
                                                password: password,
                                                displayName: displayName)
            store.persist(created.location)            // persist BEFORE mnemonic
            phrase = created.phrase
            mnemonicRows = groupMnemonic(String(decoding: created.phrase, as: UTF8.self))
            created.phrase.resetBytes(in: created.phrase.indices)  // wipe the local copy
            step = .mnemonic
        } catch let e as VaultProvisioningError {
            error = e
        } catch {
            self.error = .createFailed(String(describing: error))
        }
    }

    /// User confirmed they wrote down the phrase: wipe the retained phrase + the
    /// display rows, and complete. `.done` carries the persisted location so the
    /// host can route to the unlock screen.
    public func acknowledgeMnemonic() {
        guard case .mnemonic = step else { return }
        if phrase != nil { phrase!.resetBytes(in: phrase!.indices) }
        phrase = nil
        mnemonicRows = nil
        if let loc = store.load() {
            step = .done(loc)
        }
    }
}

private extension Array where Element == UInt8 {
    /// Overwrite the byte range with zeros in place (best-effort scrubbing of a
    /// secret buffer; value-type copies elsewhere are out of scope here).
    mutating func resetBytes(in range: Range<Int>) {
        for i in range { self[i] = 0 }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ios/SecretaryVaultAccess && swift test --filter VaultProvisioningViewModelTests`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultProvisioningViewModel.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultProvisioningViewModelTests.swift
git commit -m "feat(ios): VaultProvisioningViewModel create-wizard state machine"
```

---

### Task 7: Extend `VaultSelectionViewModel` with import probe

**Files:**
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultSelectionViewModel.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultSelectionViewModelTests.swift`

- [ ] **Step 1: Write the failing test (append to the existing test file)**

```swift
    // --- Import-probe behaviour (Slice 2) ---

    func testConsiderImportOpensWhenFolderIsVault() {
        let store = FakeVaultLocationStore()
        let probe = FakeVaultShapeProbe(answer: .success(true))
        let vm = VaultSelectionViewModel(store: store, probe: probe)
        let outcome = vm.considerImport(url: URL(fileURLWithPath: "/v"),
                                        bookmark: Data("bm".utf8),
                                        displayName: "v")
        XCTAssertEqual(outcome, .opened)
        XCTAssertEqual(store.stored?.displayName, "v")     // persisted
        XCTAssertEqual(vm.state, .located(displayName: "v"))
    }

    func testConsiderImportRejectsNonVault() {
        let store = FakeVaultLocationStore()
        let probe = FakeVaultShapeProbe(answer: .success(false))
        let vm = VaultSelectionViewModel(store: store, probe: probe)
        let outcome = vm.considerImport(url: URL(fileURLWithPath: "/x"),
                                        bookmark: Data("bm".utf8),
                                        displayName: "x")
        XCTAssertEqual(outcome, .notAVault)
        XCTAssertNil(store.stored)                          // NOT persisted
    }

    func testConsiderImportProbeErrorIsUnavailable() {
        struct Boom: Error {}
        let store = FakeVaultLocationStore()
        let probe = FakeVaultShapeProbe(answer: .failure(Boom()))
        let vm = VaultSelectionViewModel(store: store, probe: probe)
        let outcome = vm.considerImport(url: URL(fileURLWithPath: "/x"),
                                        bookmark: Data("bm".utf8),
                                        displayName: "x")
        if case .unavailable = outcome {} else { XCTFail("expected .unavailable") }
        XCTAssertNil(store.stored)
    }
```

Also update **every existing** `VaultSelectionViewModel(store:)` construction in this file to `VaultSelectionViewModel(store: store, probe: FakeVaultShapeProbe(answer: .success(true)))`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter VaultSelectionViewModelTests`
Expected: FAIL — `considerImport` / the new `init(store:probe:)` not defined.

- [ ] **Step 3: Write minimal implementation (modify the VM)**

Add the import to the file header (already imports `SecretaryVaultAccess`). Add a stored `probe`, update `init`, add `considerImport`:

```swift
    private let store: VaultLocationStore
    private let probe: VaultShapeProbe

    public init(store: VaultLocationStore, probe: VaultShapeProbe) {
        self.store = store
        self.probe = probe
    }
```

```swift
    /// Consider a folder the user picked via "Import existing vault". Runs the
    /// crypto-free shape probe FIRST: only a folder that contains a vault is
    /// persisted + located. A non-vault folder is rejected without persisting (so
    /// the user is not handed an "Open" button that will just fail at unlock); an
    /// unreadable folder surfaces as `.unavailable`. The caller must hold the
    /// folder's security scope across this call (the probe reads `vault.toml`).
    public func considerImport(url: URL, bookmark: Data, displayName: String) -> ImportOutcome {
        do {
            guard try probe.looksLikeVault(url) else { return .notAVault }
            recordSelection(bookmark: bookmark, displayName: displayName)
            return .opened
        } catch {
            return .unavailable(String(describing: error))
        }
    }
```

- [ ] **Step 4: Run the full package test (the init change touches the whole file)**

Run: `cd ios/SecretaryVaultAccess && swift test`
Expected: PASS — all `SecretaryVaultAccess` + `SecretaryVaultAccessUI` tests green (existing selection tests now construct with a probe).

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultSelectionViewModel.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultSelectionViewModelTests.swift
git commit -m "feat(ios): import vault-shape probe in VaultSelectionViewModel"
```

---

### Task 8: Real adapters in `SecretaryKit`

**Files:**
- Create: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/ProvisioningErrorMapping.swift`
- Create: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultCreatePort.swift`
- Create: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/FileManagerVaultShapeProbe.swift`
- Test: covered by Task 9's simulator test (these touch the xcframework + filesystem, so they are proven on-simulator, not host)

- [ ] **Step 1: Write the error mapping**

`ProvisioningErrorMapping.swift`:
```swift
import Foundation
import SecretaryVaultAccess

/// Map a uniffi `VaultError` from a create call onto the wizard's typed
/// `VaultProvisioningError`. `VaultFolderNotEmpty` is structurally rare (we mkdir
/// a fresh subfolder) but mapped for the name-collides-with-existing-dir case.
func mapProvisioningError(_ e: VaultError) -> VaultProvisioningError {
    switch e {
    case .VaultFolderNotEmpty:
        return .folderNotEmpty
    case .FolderInvalid(let detail):
        return .folderInvalid(detail)
    case .InvalidArgument(let detail):
        // A name that passed Swift validation but the bridge rejected.
        return .createFailed("invalid argument: \(detail)")
    default:
        return .createFailed(String(describing: e))
    }
}
```

- [ ] **Step 2: Write `UniffiVaultCreatePort`**

`UniffiVaultCreatePort.swift`:
```swift
import Foundation
import SecretaryVaultAccess

/// Real `VaultCreatePort` over the uniffi `createVaultInFolder` surface. Owns the
/// iOS filesystem dance: hold the parent's security scope, mkdir a fresh subfolder
/// (guaranteed empty), create the vault, build a persistable bookmark, and return
/// the location + one-shot recovery phrase.
public struct UniffiVaultCreatePort: VaultCreatePort {
    public init() {}

    public func create(parent: URL,
                       vaultName: String,
                       password: [UInt8],
                       displayName: String) throws -> CreatedVault {
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

- [ ] **Step 3: Write `FileManagerVaultShapeProbe`**

`FileManagerVaultShapeProbe.swift`:
```swift
import Foundation
import SecretaryVaultAccess

/// Real `VaultShapeProbe`: a folder looks like a vault iff it directly contains a
/// `vault.toml`. Crypto-free shape detection only — corrupt contents still surface
/// at unlock time via the FFI's typed errors.
public struct FileManagerVaultShapeProbe: VaultShapeProbe {
    public init() {}

    public func looksLikeVault(_ folder: URL) throws -> Bool {
        let marker = folder.appendingPathComponent("vault.toml", isDirectory: false)
        return FileManager.default.fileExists(atPath: marker.path)
    }
}
```

- [ ] **Step 4: Verify SecretaryKit builds**

Run: `cd ios/SecretaryKit && swift build` (or, if the package needs the xcframework, the build is proven in Task 9 via `run-ios-tests.sh`).
Expected: builds clean (uniffi symbols `createVaultInFolder` / `MnemonicOutput` / `VaultError` resolve from the linked framework).

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/ProvisioningErrorMapping.swift \
        ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultCreatePort.swift \
        ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/FileManagerVaultShapeProbe.swift
git commit -m "feat(ios): real UniffiVaultCreatePort + FileManagerVaultShapeProbe"
```

---

### Task 9: Simulator end-to-end test (real FFI)

**Files:**
- Create: `ios/SecretaryKit/Tests/SecretaryKitTests/UniffiVaultCreatePortTests.swift`

- [ ] **Step 1: Write the test (runs on simulator via xcodebuild)**

```swift
import XCTest
import SecretaryVaultAccess
@testable import SecretaryKit

final class UniffiVaultCreatePortTests: XCTestCase {
    /// Create a vault in a fresh tempdir parent, then open it by password and
    /// assert the display name round-trips. NEVER touches the bundled golden
    /// fixture — a unique tempdir, not even a copy.
    func testCreateThenOpenRoundTrips() throws {
        let parent = FileManager.default.temporaryDirectory
            .appendingPathComponent("create-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: parent) }

        let port = UniffiVaultCreatePort()
        let password = Array("create-test-pw".utf8)
        var created = try port.create(parent: parent,
                                      vaultName: "v1",
                                      password: password,
                                      displayName: "Sim-Owner")
        defer { created.phrase.replaceSubrange(created.phrase.indices, with: repeatElement(0, count: created.phrase.count)) }

        // 24-word recovery phrase.
        let words = String(decoding: created.phrase, as: UTF8.self)
            .split(whereSeparator: { $0.isWhitespace })
        XCTAssertEqual(words.count, 24)

        // Re-open the created folder by password → display name round-trips.
        let folder = parent.appendingPathComponent("v1", isDirectory: true)
        let out = try SecretaryKit.openVaultWithPassword(
            folderPath: Data(folder.path.utf8), password: Data(password))
        defer { out.identity.wipe() }
        defer { out.manifest.wipe() }
        XCTAssertEqual(out.identity.displayName(), "Sim-Owner")
    }

    func testCreateIntoExistingNonEmptyNameThrowsFolderNotEmpty() throws {
        let parent = FileManager.default.temporaryDirectory
            .appendingPathComponent("create-collide-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: parent) }
        // Pre-create the subfolder so the port's mkdir hits an existing dir.
        try FileManager.default.createDirectory(
            at: parent.appendingPathComponent("v1", isDirectory: true),
            withIntermediateDirectories: false)

        XCTAssertThrowsError(try UniffiVaultCreatePort().create(
            parent: parent, vaultName: "v1", password: [1, 2, 3], displayName: "X")) {
            XCTAssertEqual($0 as? VaultProvisioningError, .folderNotEmpty)
        }
    }

    func testShapeProbeDetectsVault() throws {
        let parent = FileManager.default.temporaryDirectory
            .appendingPathComponent("probe-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: parent) }

        let probe = FileManagerVaultShapeProbe()
        XCTAssertFalse(try probe.looksLikeVault(parent))             // empty → not a vault
        let folder = parent.appendingPathComponent("v1", isDirectory: true)
        _ = try UniffiVaultCreatePort().create(
            parent: parent, vaultName: "v1", password: Array("pw".utf8), displayName: "O")
        XCTAssertTrue(try probe.looksLikeVault(folder))              // now has vault.toml
    }
}
```

- [ ] **Step 2: Run on the simulator**

Run: `bash ios/scripts/run-ios-tests.sh`
Expected: host packages pass, framework builds, `SecretaryKit` XCTest passes (incl. the 3 new tests), app build step passes.

- [ ] **Step 3: Commit**

```bash
git add ios/SecretaryKit/Tests/SecretaryKitTests/UniffiVaultCreatePortTests.swift
git commit -m "test(ios): simulator create→open round-trip + folder-not-empty + probe"
```

---

### Task 10: SwiftUI wizard views + selection branching + RootView wiring

**Files:**
- Create: `ios/SecretaryApp/Sources/CreateVaultWizardView.swift`
- Modify: `ios/SecretaryApp/Sources/VaultSelectionScreen.swift`
- Modify: `ios/SecretaryApp/Sources/SecretaryApp.swift`

- [ ] **Step 1: Write `CreateVaultWizardView`**

```swift
import SwiftUI
import UniformTypeIdentifiers
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Three-step create wizard (folder → credentials → mnemonic) over a
/// `VaultProvisioningViewModel`. On completion, calls `onCreated` with the
/// persisted `VaultLocation` so the host can route to the unlock screen
/// (re-enter password — desktop D.1.3 parity, no auto-open).
struct CreateVaultWizardView: View {
    @ObservedObject var viewModel: VaultProvisioningViewModel
    let onCreated: (VaultLocation) -> Void
    let onCancel: () -> Void

    @State private var pickingParent = false
    @State private var parentURL: URL?
    @State private var vaultName = ""
    @State private var displayName = ""
    @State private var password = ""
    @State private var confirm = ""

    var body: some View {
        NavigationStack {
            Form {
                switch viewModel.step {
                case .folder:        folderStep
                case .credentials:   credentialsStep
                case .mnemonic:      mnemonicStep
                case .done(let loc): Color.clear.onAppear { onCreated(loc) }
                }
            }
            .navigationTitle("Create vault")
            .toolbar { ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") { onCancel() }
            } }
            .fileImporter(isPresented: $pickingParent,
                          allowedContentTypes: [.folder]) { result in
                if case .success(let url) = result { parentURL = url }
            }
        }
    }

    private var folderStep: some View {
        Section("Location") {
            Button("Choose parent folder…") { pickingParent = true }
            if let parentURL { Text(parentURL.lastPathComponent).font(.footnote.monospaced()) }
            TextField("Vault name", text: $vaultName)
            if let e = viewModel.nameError { Text(message(for: e)).foregroundStyle(.red).font(.footnote) }
            Button("Continue") {
                if let parentURL { viewModel.chooseParent(parentURL, vaultName: vaultName) }
            }
            .disabled(parentURL == nil || vaultName.isEmpty)
        }
    }

    private var credentialsStep: some View {
        Section("Credentials") {
            TextField("Display name", text: $displayName)
            SecureField("Master password", text: $password)
            SecureField("Confirm password", text: $confirm)
            if viewModel.error == .passwordMismatch {
                Text("Passwords do not match").foregroundStyle(.red).font(.footnote)
            } else if let e = viewModel.error {
                Text(message(for: e)).foregroundStyle(.red).font(.footnote)
            }
            Button("Create vault") {
                Task {
                    var pw = Array(password.utf8); var cf = Array(confirm.utf8)
                    await viewModel.create(displayName: displayName, password: pw, confirm: cf)
                    for i in pw.indices { pw[i] = 0 }; for i in cf.indices { cf[i] = 0 }
                    password = ""; confirm = ""
                }
            }
            .disabled(displayName.isEmpty || password.isEmpty || confirm.isEmpty)
        }
    }

    private var mnemonicStep: some View {
        Section("Recovery phrase") {
            Text("Write these 24 words down and keep them safe. This is the only way to recover your vault if you forget the password.")
                .font(.footnote).foregroundStyle(.secondary)
            ForEach(viewModel.mnemonicRows ?? [], id: \.number) { w in
                Text("\(w.number). \(w.word)").font(.body.monospaced())
            }
            Button("I have written down my recovery phrase") {
                viewModel.acknowledgeMnemonic()
            }
        }
    }

    private func message(for e: VaultNameError) -> String {
        switch e {
        case .empty: return "Enter a vault name"
        case .containsSeparator: return "Name can't contain “/”"
        case .reservedName: return "Choose a different name"
        }
    }

    private func message(for e: VaultProvisioningError) -> String {
        switch e {
        case .folderNotEmpty: return "A folder with that name already exists — choose another"
        case .folderInvalid: return "That location can't be used"
        case .invalidName: return "Choose a different name"
        case .passwordMismatch: return "Passwords do not match"
        case .createFailed(let d): return "Couldn't create the vault (\(d))"
        }
    }
}
```

- [ ] **Step 2: Add Create / Import branching to `VaultSelectionScreen`**

In `VaultSelectionScreen.swift`: add `let onCreateNew: () -> Void` to the struct's properties. In `selectSection`, add a "Create new vault" button. Change the import-success path in `handleImport` to route through the probe via the VM's `considerImport` and surface `.notAVault`:

```swift
    let onCreateNew: () -> Void
```

```swift
    private var selectSection: some View {
        Section("Open a vault") {
            Button("Import existing vault…") { importing = true }
            Button("Create new vault…") { onCreateNew() }
        }
    }
```

```swift
    private func handleImport(_ result: Result<URL, Error>) {
        errorText = nil
        switch result {
        case .failure(let error):
            errorText = String(describing: error)
        case .success(let url):
            let didAccess = url.startAccessingSecurityScopedResource()
            defer { if didAccess { url.stopAccessingSecurityScopedResource() } }
            do {
                let bookmark = try url.bookmarkData()
                switch viewModel.considerImport(url: url, bookmark: bookmark,
                                                 displayName: url.lastPathComponent) {
                case .opened:
                    break                                    // VM is now .located
                case .notAVault:
                    errorText = "This folder doesn’t contain a vault."
                case .unavailable(let reason):
                    errorText = reason
                }
            } catch {
                errorText = String(describing: error)
            }
        }
    }
```

- [ ] **Step 3: Wire the wizard route into `RootView` (`SecretaryApp.swift`)**

Add a `.create` route and a `createNew` entry; construct the selection VM with the real probe and pass `UniffiVaultCreatePort` + the shared store into the wizard VM:

```swift
    private enum Route {
        case select
        case create
        case unlock(ScopedVaultPath)
        case browse(VaultBrowseViewModel, ScopedVaultPath)
    }

    private let store = BookmarkVaultLocationStore()
    @StateObject private var selectionVM =
        VaultSelectionViewModel(store: BookmarkVaultLocationStore(),
                                probe: FileManagerVaultShapeProbe())
```

> NOTE: `selectionVM` and the wizard must share ONE store instance so a created vault is visible to `selectionVM.loadPersisted()`. Construct a single `BookmarkVaultLocationStore()` and inject it into both. (Replace the two separate `BookmarkVaultLocationStore()` constructions above with one shared `let store` passed to both `VaultSelectionViewModel(store: store, probe:)` and the wizard's `VaultProvisioningViewModel(createPort:store:)`.)

In `body`, add the cases:
```swift
            case .select:
                VaultSelectionScreen(
                    viewModel: selectionVM,
                    onOpen: { scoped in route = .unlock(scoped) },
                    onOpenDemo: { try openDemo() },
                    onCreateNew: { route = .create })
            case .create:
                CreateVaultWizardView(
                    viewModel: VaultProvisioningViewModel(
                        createPort: UniffiVaultCreatePort(), store: store),
                    onCreated: { _ in
                        selectionVM.loadPersisted()          // pick up the new location
                        route = .select                      // back to select → "Open" → unlock
                    },
                    onCancel: { route = .select })
```

> NOTE: `onCreated` returns to the selection screen (now `.located` with the new vault), where the existing "Open" → `beginAccess` → unlock path applies — re-enter password, desktop parity, no auto-open.

- [ ] **Step 4: Build the app (XcodeGen compile proof)**

Run: `bash ios/scripts/run-ios-tests.sh`
Expected: all host tests + simulator tests pass AND the app build step (`build-app.sh`) compiles the new views.

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryApp/Sources/CreateVaultWizardView.swift \
        ios/SecretaryApp/Sources/VaultSelectionScreen.swift \
        ios/SecretaryApp/Sources/SecretaryApp.swift
git commit -m "feat(ios): create-vault wizard UI + import branching + RootView wiring"
```

---

### Task 11: Docs — README + ROADMAP

**Files:**
- Modify: `README.md`
- Modify: `ROADMAP.md`

- [ ] **Step 1: Update README status**

Add/adjust the iOS status line to note the create/import wizard shipped (brief, dot-point — per the README style preference). Locate the iOS row and add: "create new vault + import existing (folder-shape detection) wizard".

- [ ] **Step 2: Update ROADMAP**

Mark Slice 2 (iOS vault create/import UI) complete under the iOS section, referencing the FFI surface from Slice 1 (#223).

- [ ] **Step 3: Verify the full gauntlet once more**

Run:
```bash
cd ios/SecretaryVaultAccess && swift test
bash ios/scripts/run-ios-tests.sh
```
Expected: all green.

- [ ] **Step 4: Commit**

```bash
git add README.md ROADMAP.md
git commit -m "docs: iOS vault create/import wizard shipped — README + ROADMAP"
```

---

## Self-Review

**Spec coverage:**
- Folder model (pick parent + name → mkdir subfolder) → Task 8 `UniffiVaultCreatePort` (mkdir `withIntermediateDirectories: false`) + Task 10 folder step.
- Post-create re-enter password (no auto-open) → Task 10 `onCreated` routes back to select → existing unlock path.
- Import entry choice + `vault.toml` detection → Task 7 `considerImport` + Task 8 `FileManagerVaultShapeProbe` + Task 10 branching.
- Pure helpers (name/password/mnemonic/step) → Tasks 1–4.
- Host-tested view-model + fakes → Tasks 5–7.
- Persist-before-mnemonic invariant → Task 6 (`store.persist` before `step = .mnemonic`) + asserted in test.
- Bookmark inside parent scope → Task 8 (`bookmarkData()` inside the `start/stop` window).
- Simulator tempdir create→open (never golden fixture) → Task 9.
- Error mapping table → Task 8 `mapProvisioningError` + Task 6/Task 10 surfaces.
- Secret zeroization (best-effort) → Task 6 (`resetBytes`) + Task 10 (clear `pw`/`cf`); noted as best-effort for value-type copies, observable clear asserted in Task 6.
- Docs → Task 11.

**Placeholder scan:** No TBD/TODO. The one illustrative-vs-real divergence (the `mapProvisioningError` `InvalidArgument` arm) is called out with the exact two-line replacement to use.

**Type consistency:** `VaultProvisioningStep`, `VaultProvisioningError`, `CreatedVault`, `VaultCreatePort`, `VaultShapeProbe`, `ImportOutcome`, `ValidatedVaultName`/`VaultNameError`, `MnemonicWord` — defined in Task 1/3/4, used consistently in Tasks 5–10. `VaultProvisioningViewModel(createPort:store:)` and `VaultSelectionViewModel(store:probe:)` signatures match across tasks. The single-shared-store requirement is flagged in Task 10.

**Scope check:** Single subsystem (iOS create/import UI on an existing FFI surface). No decomposition needed.
