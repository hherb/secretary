# iOS password/recovery unlock + read-only browse — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an iOS flow that opens the app-staged demo vault by password or 24-word recovery phrase, then browses its blocks/records read-only with reveal-on-demand for secret fields.

**Architecture:** A new FFI-free SPM package `SecretaryVaultAccess` (ports + pure models + `@MainActor` view models + in-memory fakes) holds all host-testable logic; real uniffi adapters live in `SecretaryKit/VaultAccess/`; SwiftUI screens live in `SecretaryApp`. The slice is 100% Swift — the FFI surface (`openVaultWithPassword`/`openVaultWithRecovery`, `readBlock`, manifest `blockSummaries()`, record/field handles) is already projected by `secretary-ffi-uniffi`.

**Tech Stack:** Swift 5.9, SwiftPM, SwiftUI, XCTest (host `swift test` + simulator `xcodebuild test`), XcodeGen, the existing `Secretary.xcframework`.

**Spec:** `docs/superpowers/specs/2026-06-12-ios-vault-unlock-browse-design.md`

**Working dir:** worktree `.worktrees/ios-vault-unlock-browse`, branch `feature/ios-vault-unlock-browse`. All paths below are relative to the repo root **inside that worktree**. Run every `swift`/`git` command from the worktree.

---

## File structure

New pure package `ios/SecretaryVaultAccess/`:
```
Package.swift
Sources/SecretaryVaultAccess/
    BlockSummary.swift          # value model
    RecordView.swift            # RecordView + FieldView + RevealedValue
    RecoveryPhrase.swift        # pure normalize() helper
    VaultAccessError.swift      # typed error (anti-oracle conflation preserved)
    VaultSession.swift          # VaultSession protocol
    VaultOpenPort.swift         # VaultOpenPort protocol
    RevealPolicy.swift          # named auto-hide constant
Sources/SecretaryVaultAccessUI/
    UnlockState.swift           # UnlockState + Mode
    UnlockViewModel.swift
    VaultBrowseViewModel.swift
Sources/SecretaryVaultAccessTesting/
    FakeVaultSession.swift
    FakeVaultOpenPort.swift
Tests/SecretaryVaultAccessTests/
    ModelsTests.swift
    RecoveryPhraseTests.swift
    VaultAccessErrorTests.swift
    FakesTests.swift
Tests/SecretaryVaultAccessUITests/
    UnlockViewModelTests.swift
    VaultBrowseViewModelTests.swift
```

New adapters in existing `ios/SecretaryKit/`:
```
Sources/SecretaryKit/VaultAccess/
    VaultErrorMapping.swift          # uniffi VaultError -> VaultAccessError (file-private use)
    UniffiVaultOpenPort.swift        # VaultOpenPort over openVaultWith{Password,Recovery}
    UniffiVaultSession.swift         # VaultSession over OpenVaultOutput + readBlock
Tests/SecretaryKitTests/
    VaultAccessIntegrationTests.swift
```

New screens in existing `ios/SecretaryApp/`:
```
Sources/UnlockScreen.swift
Sources/VaultBrowseScreen.swift
Sources/SecretaryApp.swift           # MODIFY: route unlock -> browse + scenePhase lock
```

Modified: `ios/SecretaryKit/Package.swift` (add `SecretaryVaultAccess(Testing)` deps), `ios/SecretaryApp/project.yml` (add package + UI product), `ios/scripts/run-ios-tests.sh` (host-run the new package), `README.md`, `ROADMAP.md`, `ios/README.md`.

**Name-collision caution:** the uniffi binding ALSO defines a type named `BlockSummary` and a type named `Record`. Our pure package defines `BlockSummary` and `RecordView`. In `SecretaryKit/VaultAccess/*` (where both modules are imported) **always module-qualify the pure type** as `SecretaryVaultAccess.BlockSummary`, and refer to the uniffi one unqualified.

---

## Task 1: Scaffold the SecretaryVaultAccess package

**Files:**
- Create: `ios/SecretaryVaultAccess/Package.swift`
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/RevealPolicy.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/ModelsTests.swift` (placeholder assertion this task; grown in Task 2)

- [ ] **Step 1: Write the package manifest**

Create `ios/SecretaryVaultAccess/Package.swift`:

```swift
// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SecretaryVaultAccess",
    platforms: [.macOS(.v13), .iOS(.v17)],
    products: [
        .library(name: "SecretaryVaultAccess", targets: ["SecretaryVaultAccess"]),
        .library(name: "SecretaryVaultAccessUI", targets: ["SecretaryVaultAccessUI"]),
        .library(name: "SecretaryVaultAccessTesting", targets: ["SecretaryVaultAccessTesting"]),
    ],
    targets: [
        .target(name: "SecretaryVaultAccess"),
        .target(name: "SecretaryVaultAccessUI", dependencies: ["SecretaryVaultAccess"]),
        .target(name: "SecretaryVaultAccessTesting", dependencies: ["SecretaryVaultAccess"]),
        .testTarget(
            name: "SecretaryVaultAccessTests",
            dependencies: ["SecretaryVaultAccess", "SecretaryVaultAccessTesting"]
        ),
        .testTarget(
            name: "SecretaryVaultAccessUITests",
            dependencies: ["SecretaryVaultAccessUI", "SecretaryVaultAccessTesting"]
        ),
    ]
)
```

- [ ] **Step 2: Add the one non-test source file so the target compiles**

Create `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/RevealPolicy.swift`:

```swift
import Foundation

/// Policy constants for revealing secret field values. Auto-hide is driven by
/// the SwiftUI layer (a `Task.sleep` over this interval); the view models
/// expose `hide`/`hideAll`, which are the unit-tested seam. The interval is a
/// named constant — never a magic number sprinkled in the view.
public enum RevealPolicy {
    /// How long a revealed value stays visible before the UI auto-hides it.
    public static let autoHideSeconds: TimeInterval = 30
}
```

- [ ] **Step 3: Write a placeholder failing test to prove the test target runs on host**

Create `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/ModelsTests.swift`:

```swift
import XCTest
@testable import SecretaryVaultAccess

final class ModelsTests: XCTestCase {
    func testAutoHideIntervalIsPositive() {
        XCTAssertGreaterThan(RevealPolicy.autoHideSeconds, 0)
    }
}
```

- [ ] **Step 4: Run the host test suite**

Run: `cd ios/SecretaryVaultAccess && swift test`
Expected: PASS (1 test).

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess
git commit -m "feat(ios): scaffold SecretaryVaultAccess package (ports+UI+testing products)"
```

---

## Task 2: Pure value models — BlockSummary, RecordView, FieldView, RevealedValue

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/BlockSummary.swift`
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/RecordView.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/ModelsTests.swift` (extend)

- [ ] **Step 1: Write failing tests for model shape + uuidHex**

Replace `ModelsTests.swift` contents with:

```swift
import XCTest
@testable import SecretaryVaultAccess

final class ModelsTests: XCTestCase {
    func testAutoHideIntervalIsPositive() {
        XCTAssertGreaterThan(RevealPolicy.autoHideSeconds, 0)
    }

    func testBlockSummaryUuidHexIsLowercaseNoDashes() {
        let s = BlockSummary(
            uuid: [0x00, 0x11, 0xab, 0xcd] + Array(repeating: 0xff, count: 12),
            name: "Logins", createdAtMs: 1, lastModMs: 2)
        XCTAssertEqual(s.uuidHex, "0011abcd" + String(repeating: "ff", count: 12))
    }

    func testRecordViewUuidHexAndFieldKinds() throws {
        let field = FieldView(name: "password", kind: .text) { .text("hunter2") }
        let rec = RecordView(
            uuid: Array(repeating: 0x01, count: 16),
            type: "login", tags: ["work"], fields: [field])
        XCTAssertEqual(rec.uuidHex, String(repeating: "01", count: 16))
        XCTAssertEqual(rec.fields.first?.kind, .text)
        XCTAssertEqual(try rec.fields.first?.reveal(), .text("hunter2"))
    }

    func testRevealedValueEquatable() {
        XCTAssertEqual(RevealedValue.bytes([1, 2, 3]), .bytes([1, 2, 3]))
        XCTAssertNotEqual(RevealedValue.text("a"), .text("b"))
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd ios/SecretaryVaultAccess && swift test`
Expected: FAIL — `cannot find 'BlockSummary'/'RecordView'/'FieldView'/'RevealedValue' in scope`.

- [ ] **Step 3: Implement BlockSummary**

Create `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/BlockSummary.swift`:

```swift
import Foundation

/// Read-only metadata for one block in an opened vault's manifest. Carries no
/// secret material — block names + timestamps are plaintext in the manifest.
public struct BlockSummary: Equatable {
    /// 16-byte block UUID (raw, for passing back to `readBlock`).
    public let uuid: [UInt8]
    /// User-visible block name.
    public let name: String
    public let createdAtMs: UInt64
    public let lastModMs: UInt64

    public init(uuid: [UInt8], name: String, createdAtMs: UInt64, lastModMs: UInt64) {
        self.uuid = uuid
        self.name = name
        self.createdAtMs = createdAtMs
        self.lastModMs = lastModMs
    }

    /// Lowercase hex, no dashes — stable key for UI identity + reveal maps.
    public var uuidHex: String { uuid.map { String(format: "%02x", $0) }.joined() }
}
```

- [ ] **Step 4: Implement RecordView + FieldView + RevealedValue**

Create `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/RecordView.swift`:

```swift
import Foundation

/// A revealed (decrypted) field value. Equatable for test assertions; holds
/// plaintext, so callers must drop it promptly (see `VaultBrowseViewModel`).
public enum RevealedValue: Equatable {
    case text(String)
    case bytes([UInt8])
}

/// One field of a record. Metadata (name, kind) is non-secret. `reveal`
/// materializes the plaintext ON DEMAND only — the real adapter wires it to the
/// FFI `expose_text`/`expose_bytes`, so plaintext is never eagerly decrypted.
/// Not `Equatable` (it holds a closure); assert on `name`/`kind`/`reveal()`.
public struct FieldView {
    public enum Kind: Equatable { case text, bytes }
    public let name: String
    public let kind: Kind
    public let reveal: () throws -> RevealedValue

    public init(name: String, kind: Kind, reveal: @escaping () throws -> RevealedValue) {
        self.name = name
        self.kind = kind
        self.reveal = reveal
    }
}

/// One decrypted record. Field metadata is exposed; plaintext stays behind
/// `FieldView.reveal`.
public struct RecordView {
    public let uuid: [UInt8]
    public let type: String
    public let tags: [String]
    public let fields: [FieldView]

    public init(uuid: [UInt8], type: String, tags: [String], fields: [FieldView]) {
        self.uuid = uuid
        self.type = type
        self.tags = tags
        self.fields = fields
    }

    public var uuidHex: String { uuid.map { String(format: "%02x", $0) }.joined() }
}
```

- [ ] **Step 5: Run to verify pass**

Run: `cd ios/SecretaryVaultAccess && swift test`
Expected: PASS (all ModelsTests).

- [ ] **Step 6: Commit**

```bash
git add ios/SecretaryVaultAccess
git commit -m "feat(ios): pure vault-access models (BlockSummary, RecordView, FieldView)"
```

---

## Task 3: Typed VaultAccessError (anti-oracle conflation preserved)

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultAccessError.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/VaultAccessErrorTests.swift`

- [ ] **Step 1: Write failing test**

Create `VaultAccessErrorTests.swift`:

```swift
import XCTest
@testable import SecretaryVaultAccess

final class VaultAccessErrorTests: XCTestCase {
    // The two credential-or-corrupt cases are DISTINCT cases per credential type
    // but neither distinguishes "wrong credential" from "corrupt vault" — that
    // conflation is the anti-oracle property and must NOT be split further.
    func testCredentialOrCorruptCasesAreEquatableAndDistinct() {
        XCTAssertEqual(VaultAccessError.wrongPasswordOrCorrupt, .wrongPasswordOrCorrupt)
        XCTAssertEqual(VaultAccessError.wrongMnemonicOrCorrupt, .wrongMnemonicOrCorrupt)
        XCTAssertNotEqual(VaultAccessError.wrongPasswordOrCorrupt, .wrongMnemonicOrCorrupt)
    }

    func testAssociatedValueCasesCarryDetail() {
        XCTAssertEqual(VaultAccessError.corruptVault("x"), .corruptVault("x"))
        XCTAssertNotEqual(VaultAccessError.blockNotFound("a"), .blockNotFound("b"))
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd ios/SecretaryVaultAccess && swift test --filter VaultAccessErrorTests`
Expected: FAIL — `cannot find 'VaultAccessError' in scope`.

- [ ] **Step 3: Implement**

Create `VaultAccessError.swift`:

```swift
import Foundation

/// Typed failures from opening or browsing a vault. The two "…OrCorrupt" cases
/// deliberately fold "wrong credential" together with "vault corruption": the
/// core (see `docs/.../crypto-design.md` + `error/unlock.rs`) refuses to let a
/// caller distinguish a wrong password from a tampered vault (anti-oracle).
/// Do NOT add a separate "wrong credential" case — that would reintroduce the
/// oracle this conflation exists to prevent.
public enum VaultAccessError: Error, Equatable {
    /// Password open failed: wrong password OR vault corruption (indistinguishable).
    case wrongPasswordOrCorrupt
    /// Recovery open failed: wrong phrase OR vault corruption (indistinguishable).
    case wrongMnemonicOrCorrupt
    /// Recovery phrase was malformed (bad word/length/UTF-8) — a format error,
    /// not a credential check, so it is safe to surface distinctly.
    case invalidMnemonic(String)
    /// The opened vault's UUID did not match the expected one.
    case vaultMismatch
    /// A block file was present but undecryptable/undecodable.
    case corruptVault(String)
    /// Block UUID not found in the manifest's live blocks.
    case blockNotFound(String)
    /// FFI input-shape error (e.g. wrong-length UUID).
    case invalidArgument(String)
    /// Vault folder missing or unreadable.
    case folderInvalid(String)
    /// Any other / unmapped failure, carried as a string (never a raw panic).
    case other(String)
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cd ios/SecretaryVaultAccess && swift test --filter VaultAccessErrorTests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess
git commit -m "feat(ios): VaultAccessError typed enum (preserves anti-oracle conflation)"
```

---

## Task 4: RecoveryPhrase.normalize pure helper

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/RecoveryPhrase.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/RecoveryPhraseTests.swift`

- [ ] **Step 1: Write failing tests**

Create `RecoveryPhraseTests.swift`:

```swift
import XCTest
@testable import SecretaryVaultAccess

final class RecoveryPhraseTests: XCTestCase {
    func testTrimsAndCollapsesInternalWhitespace() {
        XCTAssertEqual(
            RecoveryPhrase.normalize("  wall   annual\tclay\nzebra "),
            "wall annual clay zebra")
    }

    func testLowercases() {
        XCTAssertEqual(RecoveryPhrase.normalize("Wall ANNUAL Clay"), "wall annual clay")
    }

    func testEmptyAndWhitespaceOnly() {
        XCTAssertEqual(RecoveryPhrase.normalize("   \n\t "), "")
        XCTAssertEqual(RecoveryPhrase.normalize(""), "")
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd ios/SecretaryVaultAccess && swift test --filter RecoveryPhraseTests`
Expected: FAIL — `cannot find 'RecoveryPhrase' in scope`.

- [ ] **Step 3: Implement**

Create `RecoveryPhrase.swift`:

```swift
import Foundation

/// Normalizes user-typed BIP-39 recovery phrases before handing them to the
/// FFI: trims, lowercases, and collapses any run of whitespace to one space.
/// The canonical BIP-39 word list is all-lowercase and single-space-joined, so
/// this removes the most common copy/paste and keyboard-autocapitalization
/// noise without altering the words themselves.
public enum RecoveryPhrase {
    public static func normalize(_ raw: String) -> String {
        raw.lowercased()
            .split(whereSeparator: { $0.isWhitespace })
            .joined(separator: " ")
    }
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cd ios/SecretaryVaultAccess && swift test --filter RecoveryPhraseTests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess
git commit -m "feat(ios): RecoveryPhrase.normalize pure helper"
```

---

## Task 5: Ports + in-memory fakes

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultSession.swift`
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultOpenPort.swift`
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeVaultSession.swift`
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeVaultOpenPort.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/FakesTests.swift`

- [ ] **Step 1: Implement the port protocols (no behavior to test yet)**

Create `VaultSession.swift`:

```swift
import Foundation

/// An opened vault. Abstracts the uniffi `OpenVaultOutput` (identity+manifest)
/// + `readBlock`, so the pure package never names an FFI handle type. The real
/// adapter retains the decrypted block handles for `reveal`, and `wipe` releases
/// all of them plus the manifest + identity.
public protocol VaultSession: AnyObject {
    /// Opened vault UUID, lowercase hex, no dashes.
    var vaultUuidHex: String { get }
    /// Block metadata from the manifest (no plaintext).
    func blockSummaries() -> [BlockSummary]
    /// Decrypt one block; returns records with on-demand-reveal fields.
    func readBlock(blockUuid: [UInt8]) throws -> [RecordView]
    /// Release ALL secret material held by this session. Idempotent.
    func wipe()
}
```

Create `VaultOpenPort.swift`:

```swift
import Foundation

/// Opens a vault folder by password or recovery phrase, producing a
/// `VaultSession`. Implementations throw `VaultAccessError`.
public protocol VaultOpenPort {
    func openWithPassword(vaultPath: Data, password: [UInt8]) throws -> VaultSession
    func openWithRecovery(vaultPath: Data, phrase: [UInt8]) throws -> VaultSession
}
```

- [ ] **Step 2: Write failing tests for the fakes' instrumentation**

Create `FakesTests.swift`:

```swift
import XCTest
import SecretaryVaultAccess
import SecretaryVaultAccessTesting

final class FakesTests: XCTestCase {
    func testFakeSessionCountsReadsAndWipesAndDefersReveal() throws {
        var revealCalls = 0
        let field = FieldView(name: "password", kind: .text) {
            revealCalls += 1
            return .text("s3cret")
        }
        let rec = RecordView(uuid: Array(repeating: 1, count: 16),
                             type: "login", tags: [], fields: [field])
        let session = FakeVaultSession(
            vaultUuidHex: "ab",
            blocks: [BlockSummary(uuid: [9], name: "B", createdAtMs: 0, lastModMs: 0)],
            recordsByBlock: [[9]: [rec]])

        XCTAssertEqual(session.blockSummaries().count, 1)
        // Reveal closure must NOT have fired just by reading the block.
        let records = try session.readBlock(blockUuid: [9])
        XCTAssertEqual(session.readCount, 1)
        XCTAssertEqual(revealCalls, 0, "reveal must be on-demand only")
        // Firing reveal explicitly works and is counted by the closure.
        XCTAssertEqual(try records[0].fields[0].reveal(), .text("s3cret"))
        XCTAssertEqual(revealCalls, 1)

        session.wipe()
        session.wipe()
        XCTAssertEqual(session.wipeCount, 2)
    }

    func testFakeSessionReadUnknownBlockThrows() {
        let session = FakeVaultSession(vaultUuidHex: "ab", blocks: [], recordsByBlock: [:])
        XCTAssertThrowsError(try session.readBlock(blockUuid: [0xde])) { err in
            XCTAssertEqual(err as? VaultAccessError, .blockNotFound("de"))
        }
    }

    func testFakeOpenPortRoutesPasswordAndRecovery() throws {
        let session = FakeVaultSession(vaultUuidHex: "ab", blocks: [], recordsByBlock: [:])
        let port = FakeVaultOpenPort(passwordResult: .success(session),
                                     recoveryResult: .failure(.wrongMnemonicOrCorrupt))
        XCTAssertTrue(try port.openWithPassword(vaultPath: Data(), password: [1]) === session)
        XCTAssertThrowsError(try port.openWithRecovery(vaultPath: Data(), phrase: [1])) { err in
            XCTAssertEqual(err as? VaultAccessError, .wrongMnemonicOrCorrupt)
        }
    }
}
```

- [ ] **Step 3: Run to verify failure**

Run: `cd ios/SecretaryVaultAccess && swift test --filter FakesTests`
Expected: FAIL — `cannot find 'FakeVaultSession'/'FakeVaultOpenPort' in scope`.

- [ ] **Step 4: Implement the fakes**

Create `FakeVaultSession.swift`:

```swift
import Foundation
import SecretaryVaultAccess

/// In-memory `VaultSession` for host tests. `recordsByBlock` is keyed by raw
/// block uuid bytes. Records reveal-call deferral via whatever closures the
/// test installs on its `FieldView`s; this fake only counts reads + wipes.
public final class FakeVaultSession: VaultSession {
    public let vaultUuidHex: String
    private let blocks: [BlockSummary]
    private let recordsByBlock: [[UInt8]: [RecordView]]
    public private(set) var readCount = 0
    public private(set) var wipeCount = 0

    public init(vaultUuidHex: String,
                blocks: [BlockSummary],
                recordsByBlock: [[UInt8]: [RecordView]]) {
        self.vaultUuidHex = vaultUuidHex
        self.blocks = blocks
        self.recordsByBlock = recordsByBlock
    }

    public func blockSummaries() -> [BlockSummary] { blocks }

    public func readBlock(blockUuid: [UInt8]) throws -> [RecordView] {
        readCount += 1
        guard let records = recordsByBlock[blockUuid] else {
            let hex = blockUuid.map { String(format: "%02x", $0) }.joined()
            throw VaultAccessError.blockNotFound(hex)
        }
        return records
    }

    public func wipe() { wipeCount += 1 }
}
```

Create `FakeVaultOpenPort.swift`:

```swift
import Foundation
import SecretaryVaultAccess

/// In-memory `VaultOpenPort` returning pre-seeded results.
public final class FakeVaultOpenPort: VaultOpenPort {
    private let passwordResult: Result<VaultSession, VaultAccessError>
    private let recoveryResult: Result<VaultSession, VaultAccessError>
    public private(set) var lastPassword: [UInt8]?
    public private(set) var lastPhrase: [UInt8]?

    public init(passwordResult: Result<VaultSession, VaultAccessError>,
                recoveryResult: Result<VaultSession, VaultAccessError>) {
        self.passwordResult = passwordResult
        self.recoveryResult = recoveryResult
    }

    public func openWithPassword(vaultPath: Data, password: [UInt8]) throws -> VaultSession {
        lastPassword = password
        return try passwordResult.get()
    }

    public func openWithRecovery(vaultPath: Data, phrase: [UInt8]) throws -> VaultSession {
        lastPhrase = phrase
        return try recoveryResult.get()
    }
}
```

- [ ] **Step 5: Run to verify pass**

Run: `cd ios/SecretaryVaultAccess && swift test`
Expected: PASS (all suites).

- [ ] **Step 6: Commit**

```bash
git add ios/SecretaryVaultAccess
git commit -m "feat(ios): VaultSession/VaultOpenPort ports + in-memory fakes"
```

---

## Task 6: UnlockViewModel + UnlockState

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/UnlockState.swift`
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/UnlockViewModel.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/UnlockViewModelTests.swift`

- [ ] **Step 1: Write failing tests**

Create `UnlockViewModelTests.swift`:

```swift
import XCTest
import SecretaryVaultAccess
import SecretaryVaultAccessTesting
@testable import SecretaryVaultAccessUI

@MainActor
final class UnlockViewModelTests: XCTestCase {
    private func session(_ hex: String = "ab") -> FakeVaultSession {
        FakeVaultSession(vaultUuidHex: hex, blocks: [], recordsByBlock: [:])
    }

    func testPasswordUnlockSuccessPublishesSession() async {
        let s = session("cd")
        let port = FakeVaultOpenPort(passwordResult: .success(s),
                                     recoveryResult: .failure(.wrongMnemonicOrCorrupt))
        let vm = UnlockViewModel(port: port, vaultPath: Data("p".utf8))
        vm.mode = .password
        await vm.unlock(secret: Array("pw".utf8))
        guard case .unlocked(let opened) = vm.state else { return XCTFail("expected unlocked") }
        XCTAssertTrue(opened === s)
        XCTAssertEqual(port.lastPassword, Array("pw".utf8))
    }

    func testRecoveryUnlockSuccessUsesRecoveryPath() async {
        let s = session("ef")
        let port = FakeVaultOpenPort(passwordResult: .failure(.wrongPasswordOrCorrupt),
                                     recoveryResult: .success(s))
        let vm = UnlockViewModel(port: port, vaultPath: Data("p".utf8))
        vm.mode = .recovery
        await vm.unlock(secret: Array("phrase".utf8))
        guard case .unlocked(let opened) = vm.state else { return XCTFail("expected unlocked") }
        XCTAssertTrue(opened === s)
        XCTAssertEqual(port.lastPhrase, Array("phrase".utf8))
    }

    func testWrongPasswordSurfacesConflatedVariant() async {
        let port = FakeVaultOpenPort(passwordResult: .failure(.wrongPasswordOrCorrupt),
                                     recoveryResult: .failure(.wrongMnemonicOrCorrupt))
        let vm = UnlockViewModel(port: port, vaultPath: Data("p".utf8))
        vm.mode = .password
        await vm.unlock(secret: Array("bad".utf8))
        guard case .failed(let err) = vm.state else { return XCTFail("expected failed") }
        // Anti-oracle: a wrong password is NOT distinguishable from corruption.
        XCTAssertEqual(err, .wrongPasswordOrCorrupt)
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd ios/SecretaryVaultAccess && swift test --filter UnlockViewModelTests`
Expected: FAIL — `cannot find 'UnlockViewModel'/'UnlockState' in scope`.

- [ ] **Step 3: Implement UnlockState**

Create `UnlockState.swift`:

```swift
import SecretaryVaultAccess

/// The single observable state of the unlock screen. Not `Equatable` — the
/// `.unlocked` case carries a live `VaultSession` (a reference). Tests pattern-
/// match the case.
public enum UnlockState {
    case idle
    case busy
    /// Opened — carries the live session handed to the browse screen.
    case unlocked(VaultSession)
    case failed(VaultAccessError)
}
```

- [ ] **Step 4: Implement UnlockViewModel**

Create `UnlockViewModel.swift`:

```swift
import Foundation
import Combine
import SecretaryVaultAccess

/// Drives the unlock screen. Holds only the injected port + vault path, so it is
/// fully host-testable. `@MainActor` because it publishes UI state; like the
/// device-unlock VM, the synchronous CPU-heavy Argon2id open briefly blocks the
/// main actor on the password path (accepted for this slice; background-offload
/// is a noted follow-up).
@MainActor
public final class UnlockViewModel: ObservableObject {
    public enum Mode { case password, recovery }

    @Published public private(set) var state: UnlockState = .idle
    /// Which credential the next `unlock` uses. Set by the segmented control.
    public var mode: Mode = .password

    private let port: VaultOpenPort
    private let vaultPath: Data

    public init(port: VaultOpenPort, vaultPath: Data) {
        self.port = port
        self.vaultPath = vaultPath
    }

    /// `secret` is the password bytes (`.password`) or normalized phrase bytes
    /// (`.recovery`). The caller owns clearing the Swift-side copy.
    public func unlock(secret: [UInt8]) async {
        state = .busy
        do {
            let session: VaultSession
            switch mode {
            case .password: session = try port.openWithPassword(vaultPath: vaultPath, password: secret)
            case .recovery: session = try port.openWithRecovery(vaultPath: vaultPath, phrase: secret)
            }
            state = .unlocked(session)
        } catch let e as VaultAccessError {
            state = .failed(e)
        } catch {
            state = .failed(.other(String(describing: error)))
        }
    }
}
```

- [ ] **Step 5: Run to verify pass**

Run: `cd ios/SecretaryVaultAccess && swift test --filter UnlockViewModelTests`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add ios/SecretaryVaultAccess
git commit -m "feat(ios): UnlockViewModel + UnlockState (password/recovery open)"
```

---

## Task 7: VaultBrowseViewModel (reveal-on-demand + wipe lifecycle)

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultBrowseViewModel.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultBrowseViewModelTests.swift`

- [ ] **Step 1: Write failing tests**

Create `VaultBrowseViewModelTests.swift`:

```swift
import XCTest
import SecretaryVaultAccess
import SecretaryVaultAccessTesting
@testable import SecretaryVaultAccessUI

@MainActor
final class VaultBrowseViewModelTests: XCTestCase {
    private func makeSession(revealCounter: @escaping () -> Void)
        -> (FakeVaultSession, BlockSummary, RecordView) {
        let block = BlockSummary(uuid: [7], name: "Logins", createdAtMs: 1, lastModMs: 2)
        let field = FieldView(name: "password", kind: .text) {
            revealCounter(); return .text("s3cret")
        }
        let rec = RecordView(uuid: Array(repeating: 2, count: 16),
                             type: "login", tags: [], fields: [field])
        let session = FakeVaultSession(vaultUuidHex: "ab",
                                       blocks: [block],
                                       recordsByBlock: [[7]: [rec]])
        return (session, block, rec)
    }

    func testLoadBlocksThenSelectReadsRecordsWithoutRevealing() throws {
        var reveals = 0
        let (session, block, _) = makeSession { reveals += 1 }
        let vm = VaultBrowseViewModel(session: session)
        vm.loadBlocks()
        XCTAssertEqual(vm.blocks, [block])
        vm.selectBlock(block)
        XCTAssertEqual(vm.records?.count, 1)
        XCTAssertEqual(session.readCount, 1)
        XCTAssertEqual(reveals, 0, "reading a block must not reveal any field")
    }

    func testRevealStoresValueThenHideDropsIt() throws {
        var reveals = 0
        let (session, block, rec) = makeSession { reveals += 1 }
        let vm = VaultBrowseViewModel(session: session)
        vm.loadBlocks(); vm.selectBlock(block)
        let field = try XCTUnwrap(vm.records?.first?.fields.first)

        vm.reveal(record: rec, field: field)
        XCTAssertEqual(reveals, 1)
        XCTAssertEqual(vm.revealedValue(recordUuidHex: rec.uuidHex, fieldName: "password"), .text("s3cret"))

        vm.hide(recordUuidHex: rec.uuidHex, fieldName: "password")
        XCTAssertNil(vm.revealedValue(recordUuidHex: rec.uuidHex, fieldName: "password"))
    }

    func testLockClearsRevealedAndWipesSession() throws {
        let (session, block, rec) = makeSession {}
        let vm = VaultBrowseViewModel(session: session)
        vm.loadBlocks(); vm.selectBlock(block)
        let field = try XCTUnwrap(vm.records?.first?.fields.first)
        vm.reveal(record: rec, field: field)

        vm.lock()
        XCTAssertNil(vm.revealedValue(recordUuidHex: rec.uuidHex, fieldName: "password"))
        XCTAssertEqual(session.wipeCount, 1)
    }

    func testSelectUnknownBlockSurfacesTypedError() {
        let session = FakeVaultSession(vaultUuidHex: "ab", blocks: [], recordsByBlock: [:])
        let vm = VaultBrowseViewModel(session: session)
        vm.selectBlock(BlockSummary(uuid: [0xde], name: "x", createdAtMs: 0, lastModMs: 0))
        XCTAssertEqual(vm.error, .blockNotFound("de"))
        XCTAssertNil(vm.records)
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd ios/SecretaryVaultAccess && swift test --filter VaultBrowseViewModelTests`
Expected: FAIL — `cannot find 'VaultBrowseViewModel' in scope`.

- [ ] **Step 3: Implement**

Create `VaultBrowseViewModel.swift`:

```swift
import Foundation
import Combine
import SecretaryVaultAccess

/// Drives the read-only browse screen. Owns the `VaultSession` and is the single
/// place that decides WHEN secret material is materialized (reveal) and WHEN it
/// is released (hide/lock). Host-testable with `FakeVaultSession`.
@MainActor
public final class VaultBrowseViewModel: ObservableObject {
    @Published public private(set) var blocks: [BlockSummary] = []
    @Published public private(set) var records: [RecordView]?
    @Published public private(set) var error: VaultAccessError?
    /// Currently-revealed plaintext, keyed "<recordUuidHex>/<fieldName>". Kept as
    /// small + short-lived as possible; cleared on hide / lock / background.
    @Published public private(set) var revealed: [String: RevealedValue] = [:]

    private let session: VaultSession
    public init(session: VaultSession) { self.session = session }

    public var vaultUuidHex: String { session.vaultUuidHex }

    public func loadBlocks() { blocks = session.blockSummaries() }

    public func selectBlock(_ block: BlockSummary) {
        error = nil
        revealed.removeAll()  // never carry a reveal across a block switch
        do {
            records = try session.readBlock(blockUuid: block.uuid)
        } catch let e as VaultAccessError {
            records = nil
            error = e
        } catch {
            records = nil
            self.error = .other(String(describing: error))
        }
    }

    private func key(_ recordUuidHex: String, _ fieldName: String) -> String {
        "\(recordUuidHex)/\(fieldName)"
    }

    public func reveal(record: RecordView, field: FieldView) {
        do {
            revealed[key(record.uuidHex, field.name)] = try field.reveal()
        } catch let e as VaultAccessError {
            error = e
        } catch {
            self.error = .other(String(describing: error))
        }
    }

    public func revealedValue(recordUuidHex: String, fieldName: String) -> RevealedValue? {
        revealed[key(recordUuidHex, fieldName)]
    }

    public func hide(recordUuidHex: String, fieldName: String) {
        revealed[key(recordUuidHex, fieldName)] = nil
    }

    /// Drop all revealed plaintext (e.g. on backgrounding) without locking.
    public func hideAll() { revealed.removeAll() }

    /// Lock the vault: drop all plaintext AND release the session's handles.
    /// After `lock`, this VM should be discarded (route back to unlock).
    public func lock() {
        revealed.removeAll()
        session.wipe()
    }
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cd ios/SecretaryVaultAccess && swift test`
Expected: PASS (all suites).

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess
git commit -m "feat(ios): VaultBrowseViewModel — reveal-on-demand + wipe-on-lock"
```

---

## Task 8: Real uniffi adapters in SecretaryKit + simulator integration test

**Files:**
- Modify: `ios/SecretaryKit/Package.swift`
- Create: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/VaultErrorMapping.swift`
- Create: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSession.swift`
- Create: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultOpenPort.swift`
- Create: `ios/SecretaryKit/Tests/SecretaryKitTests/VaultAccessIntegrationTests.swift`

> This task's tests require the simulator (the xcframework). Verify with
> `bash ios/scripts/run-ios-tests.sh` (host `swift test` for SecretaryKit is not
> possible — it links the binary target).

- [ ] **Step 1: Add the package dependency to SecretaryKit**

Modify `ios/SecretaryKit/Package.swift` — add to `dependencies`:

```swift
        .package(path: "../SecretaryDeviceUnlock"),
        .package(path: "../SecretaryVaultAccess"),
```

add to the `SecretaryKit` target `dependencies`:

```swift
                .product(name: "SecretaryDeviceUnlock", package: "SecretaryDeviceUnlock"),
                .product(name: "SecretaryVaultAccess", package: "SecretaryVaultAccess"),
```

and to the `SecretaryKitTests` target `dependencies`:

```swift
                .product(name: "SecretaryDeviceUnlockTesting", package: "SecretaryDeviceUnlock"),
                .product(name: "SecretaryVaultAccessTesting", package: "SecretaryVaultAccess"),
```

- [ ] **Step 2: Implement the error mapping (preserves the conflation)**

Create `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/VaultErrorMapping.swift`:

```swift
import SecretaryVaultAccess

/// Map the uniffi `VaultError` onto the pure `VaultAccessError`. `internal` (not
/// public) so a vault-access mapping is never reused on a non-vault-access path
/// — same discipline as `UniffiVaultDeviceSlotPort.mapVaultError`.
///
/// CRITICAL: `WrongPasswordOrCorrupt` / `WrongMnemonicOrCorrupt` are the core's
/// deliberately-conflated anti-oracle variants. They map 1:1 and must NOT be
/// split into a "wrong credential" vs "corrupt" distinction here.
func mapVaultAccessError(_ e: VaultError) -> VaultAccessError {
    switch e {
    case .WrongPasswordOrCorrupt:           return .wrongPasswordOrCorrupt
    case .WrongMnemonicOrCorrupt:           return .wrongMnemonicOrCorrupt
    case .InvalidMnemonic(let detail):      return .invalidMnemonic(detail)
    case .VaultMismatch:                    return .vaultMismatch
    case .CorruptVault(let detail):         return .corruptVault(detail)
    case .BlockNotFound(let uuidHex):       return .blockNotFound(uuidHex)
    case .InvalidArgument(let detail):      return .invalidArgument(detail)
    case .FolderInvalid(let detail):        return .folderInvalid(detail)
    default:                                return .other(String(describing: e))
    }
}
```

> If the Swift compiler reports a missing/extra `VaultError` case here, reconcile
> against the generated binding — do NOT add a wildcard that swallows a
> credential variant into a non-conflated case.

- [ ] **Step 3: Implement UniffiVaultSession**

Create `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSession.swift`:

```swift
import Foundation
import SecretaryVaultAccess

/// Real `VaultSession` over the uniffi `OpenVaultOutput` (identity + manifest)
/// plus `readBlock`. Retains every `BlockReadOutput` it decodes so the
/// per-field `reveal` closures (which capture an FFI `FieldHandle`) stay valid
/// until `wipe()`. `wipe()` releases blocks, then manifest, then identity.
public final class UniffiVaultSession: VaultSession {
    private let identity: UnlockedIdentity
    private let manifest: OpenVaultManifest
    /// Retained decrypted-block handles, so reveal closures remain valid.
    private var openBlocks: [BlockReadOutput] = []

    public init(output: OpenVaultOutput) {
        self.identity = output.identity
        self.manifest = output.manifest
    }

    public var vaultUuidHex: String {
        [UInt8](manifest.vaultUuid()).map { String(format: "%02x", $0) }.joined()
    }

    public func blockSummaries() -> [SecretaryVaultAccess.BlockSummary] {
        manifest.blockSummaries().map { s in
            SecretaryVaultAccess.BlockSummary(
                uuid: [UInt8](s.blockUuid),
                name: s.blockName,
                createdAtMs: s.createdAtMs,
                lastModMs: s.lastModifiedMs)
        }
    }

    public func readBlock(blockUuid: [UInt8]) throws -> [RecordView] {
        let out: BlockReadOutput
        do {
            out = try SecretaryKit.readBlock(
                identity: identity, manifest: manifest, blockUuid: Data(blockUuid))
        } catch let e as VaultError {
            throw mapVaultAccessError(e)
        }
        openBlocks.append(out)  // keep alive for reveal closures + wipe
        let count = out.recordCount()
        var records: [RecordView] = []
        records.reserveCapacity(Int(count))
        var i: UInt64 = 0
        while i < count {
            guard let rec = out.recordAt(idx: i) else { i += 1; continue }
            records.append(makeRecordView(rec))
            i += 1
        }
        return records
    }

    private func makeRecordView(_ rec: Record) -> RecordView {
        let fieldCount = rec.fieldCount()
        var fields: [FieldView] = []
        fields.reserveCapacity(Int(fieldCount))
        var j: UInt64 = 0
        while j < fieldCount {
            if let handle = rec.fieldAt(idx: j) {
                fields.append(makeFieldView(handle))
            }
            j += 1
        }
        return RecordView(
            uuid: [UInt8](rec.recordUuid()),
            type: rec.recordType(),
            tags: rec.tags(),
            fields: fields)
    }

    private func makeFieldView(_ handle: FieldHandle) -> FieldView {
        let kind: FieldView.Kind = handle.isText() ? .text : .bytes
        // `handle` is captured: calling reveal() invokes expose_* ON DEMAND.
        // The owning BlockReadOutput is retained in `openBlocks` until wipe().
        return FieldView(name: handle.name(), kind: kind) {
            switch kind {
            case .text:
                guard let s = handle.exposeText() else { throw VaultAccessError.corruptVault("text field could not be exposed") }
                return .text(s)
            case .bytes:
                guard let b = handle.exposeBytes() else { throw VaultAccessError.corruptVault("bytes field could not be exposed") }
                return .bytes([UInt8](b))
            }
        }
    }

    public func wipe() {
        for b in openBlocks { b.wipe() }
        openBlocks.removeAll()
        manifest.wipe()
        identity.wipe()
    }
}
```

- [ ] **Step 4: Implement UniffiVaultOpenPort**

Create `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultOpenPort.swift`:

```swift
import Foundation
import SecretaryVaultAccess

/// Real `VaultOpenPort` over the uniffi folder-in open functions.
public struct UniffiVaultOpenPort: VaultOpenPort {
    public init() {}

    public func openWithPassword(vaultPath: Data, password: [UInt8]) throws -> VaultSession {
        do {
            let out = try SecretaryKit.openVaultWithPassword(
                folderPath: vaultPath, password: Data(password))
            return UniffiVaultSession(output: out)
        } catch let e as VaultError {
            throw mapVaultAccessError(e)
        }
    }

    public func openWithRecovery(vaultPath: Data, phrase: [UInt8]) throws -> VaultSession {
        do {
            let out = try SecretaryKit.openVaultWithRecovery(
                folderPath: vaultPath, mnemonic: Data(phrase))
            return UniffiVaultSession(output: out)
        } catch let e as VaultError {
            throw mapVaultAccessError(e)
        }
    }
}
```

> Confirm the exact generated parameter labels (`folderPath:password:` /
> `folderPath:mnemonic:` / `readBlock(identity:manifest:blockUuid:)`) against the
> binding if the compiler complains — uniffi derives them from the Rust arg
> names (`folder_path`, `password`, `mnemonic`, `identity`, `manifest`,
> `block_uuid`), shown in `ffi/secretary-ffi-uniffi/src/namespace/mod.rs`.

- [ ] **Step 5: Write the simulator integration test**

Create `ios/SecretaryKit/Tests/SecretaryKitTests/VaultAccessIntegrationTests.swift`:

```swift
import XCTest
@testable import SecretaryKit
import SecretaryVaultAccess

/// Drives the real folder-in open + read_block FFI on a simulator against a
/// writable copy of golden_vault_001. Asserts the open yields the pinned vault
/// UUID, blocks enumerate, a block reads, a text field reveals non-empty
/// plaintext ONLY when asked, recovery opens the same vault, and a wrong
/// password surfaces the conflated `.wrongPasswordOrCorrupt`.
final class VaultAccessIntegrationTests: XCTestCase {
    private let goldenPassword = "correct horse battery staple"
    private let goldenRecovery = "wall annual clay zebra cost cricket choose light small neck mimic season fix situate love asset dismiss online island disease turkey grab dish that"
    private let pinnedVaultUuidHex = "00112233445566778899aabbccddeeff"
    private var vaultCopy: URL!

    override func setUpWithError() throws {
        let bundled = try XCTUnwrap(
            Bundle.module.url(forResource: "golden_vault_001", withExtension: nil),
            "golden_vault_001 not bundled — run ios/scripts/build-xcframework.sh")
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("gv-va-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        vaultCopy = tmp.appendingPathComponent("golden_vault_001", isDirectory: true)
        try FileManager.default.copyItem(at: bundled, to: vaultCopy)
    }

    override func tearDownWithError() throws {
        if let vaultCopy { try? FileManager.default.removeItem(at: vaultCopy.deletingLastPathComponent()) }
    }

    private var path: Data { Data(vaultCopy.path.utf8) }

    func testPasswordOpenBrowseAndRevealOnDemand() throws {
        let port = UniffiVaultOpenPort()
        let session = try port.openWithPassword(vaultPath: path, password: [UInt8](goldenPassword.utf8))
        defer { session.wipe() }

        XCTAssertEqual(session.vaultUuidHex, pinnedVaultUuidHex)

        let blocks = session.blockSummaries()
        XCTAssertFalse(blocks.isEmpty, "golden vault has at least one block")

        let records = try session.readBlock(blockUuid: blocks[0].uuid)
        XCTAssertFalse(records.isEmpty, "the first block has at least one record")

        // Find a text field and reveal it — must produce non-empty plaintext.
        let textField = try XCTUnwrap(
            records.flatMap(\.fields).first(where: { $0.kind == .text }),
            "expected at least one text field in the login record")
        guard case .text(let plaintext) = try textField.reveal() else {
            return XCTFail("text field did not reveal text")
        }
        XCTAssertFalse(plaintext.isEmpty)
    }

    func testRecoveryOpensSameVault() throws {
        let port = UniffiVaultOpenPort()
        let session = try port.openWithRecovery(vaultPath: path, phrase: [UInt8](goldenRecovery.utf8))
        defer { session.wipe() }
        XCTAssertEqual(session.vaultUuidHex, pinnedVaultUuidHex)
    }

    func testWrongPasswordSurfacesConflatedVariant() {
        let port = UniffiVaultOpenPort()
        XCTAssertThrowsError(
            try port.openWithPassword(vaultPath: path, password: [UInt8]("definitely wrong".utf8))
        ) { err in
            XCTAssertEqual(err as? VaultAccessError, .wrongPasswordOrCorrupt,
                           "wrong password must be indistinguishable from corruption (anti-oracle)")
        }
    }
}
```

- [ ] **Step 6: Build the xcframework + run the simulator suite**

Run: `bash ios/scripts/run-ios-tests.sh`
Expected: host `swift test` (SecretaryDeviceUnlock + SecretaryVaultAccess) PASS; xcframework builds; SecretaryKit XCTest PASS (existing device tests + the 3 new VaultAccess tests); app build SUCCEEDED.

> Note: Task 10 adds the SecretaryVaultAccess host run to this script. Until
> then, also run `cd ios/SecretaryVaultAccess && swift test` explicitly.

- [ ] **Step 7: Commit**

```bash
git add ios/SecretaryKit
git commit -m "feat(ios): UniffiVaultOpenPort + UniffiVaultSession + simulator integration test"
```

---

## Task 9: SwiftUI screens + app routing (unlock → browse, scenePhase lock)

**Files:**
- Modify: `ios/SecretaryApp/project.yml`
- Create: `ios/SecretaryApp/Sources/UnlockScreen.swift`
- Create: `ios/SecretaryApp/Sources/VaultBrowseScreen.swift`
- Modify: `ios/SecretaryApp/Sources/SecretaryApp.swift`

> Screens are verified by the app BUILD (no XCTest target in the app). The
> logic they render is already unit-tested in Tasks 6–7.

- [ ] **Step 1: Wire the new package + UI product into XcodeGen**

Modify `ios/SecretaryApp/project.yml`:

Under `packages:` add:

```yaml
  SecretaryVaultAccess:
    path: ../SecretaryVaultAccess
```

Under the `Secretary` target `dependencies:` add:

```yaml
      - package: SecretaryVaultAccess
        product: SecretaryVaultAccess
      - package: SecretaryVaultAccess
        product: SecretaryVaultAccessUI
```

- [ ] **Step 2: Implement UnlockScreen**

Create `ios/SecretaryApp/Sources/UnlockScreen.swift`:

```swift
import SwiftUI
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Password / recovery-phrase unlock. Thin shell: renders `viewModel.state` and
/// forwards the entered secret. On `.unlocked` it calls `onUnlocked(session)`.
struct UnlockScreen: View {
    @StateObject private var viewModel: UnlockViewModel
    let onUnlocked: (VaultSession) -> Void

    @State private var mode: UnlockViewModel.Mode = .password
    @State private var password: String = "correct horse battery staple"
    @State private var phrase: String = ""

    init(viewModel: UnlockViewModel, onUnlocked: @escaping (VaultSession) -> Void) {
        self._viewModel = StateObject(wrappedValue: viewModel)
        self.onUnlocked = onUnlocked
    }

    private var isBusy: Bool { if case .busy = viewModel.state { return true } else { return false } }

    var body: some View {
        NavigationStack {
            Form {
                Picker("Unlock with", selection: $mode) {
                    Text("Password").tag(UnlockViewModel.Mode.password)
                    Text("Recovery phrase").tag(UnlockViewModel.Mode.recovery)
                }
                .pickerStyle(.segmented)

                switch mode {
                case .password:
                    Section("Master password") {
                        SecureField("password", text: $password)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                    }
                case .recovery:
                    Section("24-word recovery phrase") {
                        TextField("word word word …", text: $phrase, axis: .vertical)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .lineLimit(3...6)
                    }
                }

                Section {
                    Button("Unlock") {
                        viewModel.mode = mode
                        let secret: [UInt8] = mode == .password
                            ? Array(password.utf8)
                            : Array(RecoveryPhrase.normalize(phrase).utf8)
                        Task { await viewModel.unlock(secret: secret) }
                    }
                }
                .disabled(isBusy)

                if case .failed(let err) = viewModel.state {
                    Section("Error") {
                        Text(String(describing: err)).font(.footnote.monospaced()).foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Unlock vault")
            .overlay { if isBusy { ProgressView() } }
            .onChange(of: stateIsUnlocked) { _, unlocked in
                if unlocked, case .unlocked(let session) = viewModel.state { onUnlocked(session) }
            }
        }
    }

    // A Bool projection so `.onChange` fires exactly when we transition to unlocked.
    private var stateIsUnlocked: Bool {
        if case .unlocked = viewModel.state { return true } else { return false }
    }
}
```

- [ ] **Step 3: Implement VaultBrowseScreen**

Create `ios/SecretaryApp/Sources/VaultBrowseScreen.swift`:

```swift
import SwiftUI
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Read-only browse: block list → record list → tap-to-reveal field. Redacts
/// revealed values when the app is not active; the parent (RootView) locks the
/// session on background.
struct VaultBrowseScreen: View {
    @StateObject private var viewModel: VaultBrowseViewModel
    @Environment(\.scenePhase) private var scenePhase

    init(viewModel: VaultBrowseViewModel) {
        self._viewModel = StateObject(wrappedValue: viewModel)
    }

    var body: some View {
        NavigationStack {
            List {
                Section("Vault") {
                    Text("uuid=\(viewModel.vaultUuidHex)").font(.footnote.monospaced())
                }
                Section("Blocks") {
                    ForEach(viewModel.blocks, id: \.uuidHex) { block in
                        Button(block.name) { viewModel.selectBlock(block) }
                    }
                }
                if let records = viewModel.records {
                    Section("Records") {
                        ForEach(records, id: \.uuidHex) { record in
                            recordView(record)
                        }
                    }
                }
                if let error = viewModel.error {
                    Section("Error") {
                        Text(String(describing: error)).font(.footnote.monospaced()).foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Browse")
            .onAppear { viewModel.loadBlocks() }
            // Drop any revealed plaintext the moment we leave the foreground.
            .onChange(of: scenePhase) { _, phase in
                if phase != .active { viewModel.hideAll() }
            }
        }
    }

    @ViewBuilder
    private func recordView(_ record: RecordView) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(record.type.isEmpty ? "record" : record.type).font(.headline)
            ForEach(record.fields, id: \.name) { field in
                fieldRow(record: record, field: field)
            }
        }
    }

    @ViewBuilder
    private func fieldRow(record: RecordView, field: FieldView) -> some View {
        let revealed = viewModel.revealedValue(recordUuidHex: record.uuidHex, fieldName: field.name)
        HStack {
            Text(field.name).font(.subheadline)
            Spacer()
            if let revealed {
                Text(display(revealed))
                    .font(.subheadline.monospaced())
                    .redacted(reason: scenePhase == .active ? [] : .privacy)
                Button("Hide") { viewModel.hide(recordUuidHex: record.uuidHex, fieldName: field.name) }
            } else {
                Button("Reveal") { viewModel.reveal(record: record, field: field) }
            }
        }
    }

    private func display(_ value: RevealedValue) -> String {
        switch value {
        case .text(let s): return s
        case .bytes(let b): return "\(b.count) bytes"
        }
    }
}
```

- [ ] **Step 4: Rewrite SecretaryApp.swift to route unlock → browse and lock on background**

Replace `ios/SecretaryApp/Sources/SecretaryApp.swift` with:

```swift
import SwiftUI
import SecretaryKit
import SecretaryVaultAccess
import SecretaryVaultAccessUI

@main
struct SecretaryApp: App {
    var body: some Scene {
        WindowGroup { RootView() }
    }
}

/// Routes between the unlock screen and the browse screen, and LOCKS (wipes the
/// session) when the app backgrounds — re-unlock is required on return. Builds
/// the real `UniffiVaultOpenPort` over a staged writable copy of golden_vault_001.
private struct RootView: View {
    private enum Route {
        case unlock
        case browse(VaultSession)
    }

    @State private var route: Route = .unlock
    @State private var staged: Result<Data, Error> = RootView.stageVaultPath()
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        Group {
            switch staged {
            case .failure(let error):
                Text("Setup failed: \(error.localizedDescription)").padding()
            case .success(let vaultPath):
                switch route {
                case .unlock:
                    UnlockScreen(
                        viewModel: UnlockViewModel(port: UniffiVaultOpenPort(), vaultPath: vaultPath),
                        onUnlocked: { session in route = .browse(session) })
                case .browse(let session):
                    VaultBrowseScreen(viewModel: VaultBrowseViewModel(session: session))
                }
            }
        }
        // Lock on background: wipe the live session and return to unlock.
        .onChange(of: scenePhase) { _, phase in
            if phase == .background, case .browse(let session) = route {
                session.wipe()
                route = .unlock
            }
        }
    }

    private static func stageVaultPath() -> Result<Data, Error> {
        do {
            let url = try AppVaultProvisioning.stageGoldenVault()
            return .success(Data(url.path.utf8))
        } catch {
            return .failure(error)
        }
    }
}
```

> `AppVaultProvisioning` already exists; `pinnedVaultUuidHex()` is no longer used
> by the app (the browse screen shows the live uuid). Leave `AppVaultProvisioning`
> unchanged.

- [ ] **Step 5: Build the app (compile proof on simulator)**

Run: `bash ios/scripts/build-app.sh`
Expected: BUILD SUCCEEDED.

- [ ] **Step 6: Commit**

```bash
git add ios/SecretaryApp
git commit -m "feat(ios): unlock + browse SwiftUI screens; lock-on-background routing"
```

---

## Task 10: CI wiring + docs

**Files:**
- Modify: `ios/scripts/run-ios-tests.sh`
- Modify: `README.md`
- Modify: `ROADMAP.md`
- Modify: `ios/README.md`

- [ ] **Step 1: Add the SecretaryVaultAccess host run to the test script**

In `ios/scripts/run-ios-tests.sh`, after the existing Step-1 SecretaryDeviceUnlock block, add:

```bash
echo "==> swift test (pure SecretaryVaultAccess — host)"
( cd "$IOS_DIR/SecretaryVaultAccess" && swift test )
```

- [ ] **Step 2: Run the full gauntlet**

Run: `bash ios/scripts/run-ios-tests.sh`
Expected: both pure packages host-PASS; xcframework builds; SecretaryKit XCTest PASS; app BUILD SUCCEEDED.

- [ ] **Step 3: Update README.md and ios/README.md**

In `README.md` (iOS status bullet) and `ios/README.md`, add a brief dot-point noting the iOS app now supports password/recovery unlock + read-only block/record browse with reveal-on-demand (keep it brief per the README style — no test-count walls).

In `ROADMAP.md`, mark the "iOS app — password/recovery unlock + read-only browse" slice as done, with a pointer to the spec/plan.

- [ ] **Step 4: Commit**

```bash
git add ios/scripts/run-ios-tests.sh README.md ROADMAP.md ios/README.md
git commit -m "ci+docs(ios): host-run SecretaryVaultAccess; document unlock+browse slice"
```

---

## Final verification (before PR)

- [ ] `cd ios/SecretaryVaultAccess && swift test` — all green.
- [ ] `bash ios/scripts/run-ios-tests.sh` — host (both packages) + simulator XCTest + app build all succeed.
- [ ] `git diff main..HEAD --name-only | grep -E '\.rs$'` — **empty** (no Rust touched).
- [ ] On-device manual smoke (Face-ID device): unlock the staged vault by **password** AND by **recovery phrase**, list blocks, open a block, reveal a text field, background the app → revealed value redacted + vault re-locks, relaunch → unlock screen.
- [ ] Update the handoff (`docs/handoffs/<date>-ios-vault-unlock-browse-shipped.md`) and retarget the `NEXT_SESSION.md` symlink; commit on the branch before opening the PR.

---

## Self-review notes (author)

- **Spec coverage:** unlock password (T6/T8/T9) ✓; unlock recovery (T6/T8/T9) ✓; block enumerate (T7/T8) ✓; record read (T7/T8) ✓; reveal-on-demand (T7 asserts reveal count, T8 reveals real field) ✓; wipe on teardown/lock (T7) + background (T9) ✓; backgrounding redaction (T9 `.privacy` + `hideAll`) ✓; anti-oracle conflation (T3 type, T6 + T8 assertions, T8 mapping comment) ✓; typed error mapping (T8) ✓; new-package boundary (T1) ✓; CI wiring (T10) ✓; no Rust change (final verification) ✓.
- **Auto-hide timeout:** `RevealPolicy.autoHideSeconds` is defined (T1) as the named constant; the timed auto-hide itself is UI-driven (a `Task.sleep`) and not unit-time-tested to avoid flakiness — the unit-tested seam is `hide`/`hideAll`. (Documented decision; matches spec "open decision".)
- **Type consistency:** `VaultSession`/`VaultOpenPort`/`BlockSummary`/`RecordView`/`FieldView`/`RevealedValue`/`VaultAccessError`/`UnlockState`/`UnlockViewModel`/`VaultBrowseViewModel` names used identically across tasks; `BlockSummary` module-qualified in SecretaryKit (T8) to avoid the uniffi name clash.
- **Placeholder scan:** no TBD/TODO; every code step shows complete code; commands have expected output.
