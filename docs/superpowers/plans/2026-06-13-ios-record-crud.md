# iOS record CRUD UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the native-iOS record-editing UI (add / edit-full-content / soft-delete / restore) on the merged Slice-1 record-edit FFI surface, in a selected and unlocked vault.

**Architecture:** Architecture A — the write surface lives as methods on the existing `VaultSession` protocol (identity+manifest are encapsulated in `UniffiVaultSession`, so writes route through the session). Pure, host-testable modules (`RecordContentInput`, `DeviceUuidStore`, view models) do the logic; the FFI commit is the only simulator-only part. Tombstoned records are filtered client-side in Swift. Device-UUID resolution mirrors desktop `load_or_create_device_uuid` (stable, random, per-(install, vault), persisted in Application Support, excluded from backup).

**Tech Stack:** Swift / SwiftUI, SPM (4 packages under `ios/`), uniffi-generated FFI (`appendRecord`/`editRecord`/`tombstoneRecord`/`resurrectRecord`), XcodeGen app target, `swift test` (host) + `xcodebuild test` (simulator).

**Spec:** `docs/superpowers/specs/2026-06-13-ios-record-crud-design.md`

---

## Orientation (read before Task 1)

Packages under `ios/`:
- `SecretaryVaultAccess` — **pure**, no FFI. Products: `SecretaryVaultAccess` (API), `SecretaryVaultAccessUI` (view models), `SecretaryVaultAccessTesting` (fakes). Host-tested with `swift test`.
- `SecretaryKit` — FFI adapter. `UniffiVaultSession` over the uniffi binding. Simulator-tested (`xcodebuild test`).
- `SecretaryApp` — XcodeGen SwiftUI app. `RootView` routes `select → unlock → browse`.

Key existing types (do not rename):
- `VaultSession` protocol (`AnyObject`): `vaultUuidHex`, `blockSummaries()`, `readBlock(blockUuid:) -> [RecordView]`, `wipe()` — `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultSession.swift`.
- `RecordView { uuid, type, tags, fields }`, `FieldView { name, kind, reveal: () throws -> RevealedValue }`, `RevealedValue { .text(String), .bytes([UInt8]) }` — `.../RecordView.swift`.
- `VaultAccessError` (typed, `Equatable`) — `.../VaultAccessError.swift`.
- `FakeVaultSession` — `.../SecretaryVaultAccessTesting/FakeVaultSession.swift`.
- `UniffiVaultSession` — `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSession.swift`.
- `mapVaultAccessError(_ VaultError) -> VaultAccessError` — `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/VaultErrorMapping.swift`.

Generated FFI signatures (from `ffi/secretary-ffi-uniffi/tests/swift/SmokeRecordEdit.swift`):
```swift
try appendRecord(identity:, manifest:, blockUuid: Data, recordUuid: Data, content: RecordContent, deviceUuid: Data, nowMs: UInt64)   // throws VaultError
try editRecord(identity:, manifest:, blockUuid: Data, recordUuid: Data, content: RecordContent, deviceUuid: Data, nowMs: UInt64)
try tombstoneRecord(identity:, manifest:, blockUuid: Data, recordUuid: Data, deviceUuid: Data, nowMs: UInt64)
try resurrectRecord(identity:, manifest:, blockUuid: Data, recordUuid: Data, deviceUuid: Data, nowMs: UInt64)
// RecordContent(recordType: String, tags: [String], fields: [FieldInput])
// FieldInput(name: String, value: FieldInputValue)  ;  FieldInputValue: .text(text: String) | .bytes(data: [UInt8])
// Record interface: recordAt(idx:), fieldByName(name:), fieldAt(idx:), recordUuid(), recordType(), tags(),
//                   createdAtMs(), lastModMs(), tombstone() -> Bool, fieldCount()
// FieldHandle: name(), deviceUuid() -> Data, isText(), isBytes(), exposeText() -> String?, exposeBytes() -> Data?, lastModMs()
```

Commands:
```bash
# host (pure packages) — fast
( cd ios/SecretaryVaultAccess && swift test )
# full simulator gauntlet (framework build + XCTest + app compile)
bash ios/scripts/run-ios-tests.sh
```

**File-size discipline:** keep new files focused and under ~500 lines (project rule). The edit view model and the edit screen each get their own file.

---

## Task 1: `RecordContentInput` domain type + validation (pure)

A Swift domain type mirroring the FFI `RecordContent`, so view models never name the uniffi type, plus a pure `validate()` the edit VM calls before committing.

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/RecordContentInput.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/RecordContentInputTests.swift`

- [ ] **Step 1: Write the failing test**

```swift
// ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/RecordContentInputTests.swift
import XCTest
import SecretaryVaultAccess

final class RecordContentInputTests: XCTestCase {
    func testValidContentPassesValidation() {
        let c = RecordContentInput(
            recordType: "login", tags: ["work"],
            fields: [
                FieldContentInput(name: "user", value: .text("alice")),
                FieldContentInput(name: "key", value: .bytes([0xDE, 0xAD])),
            ])
        XCTAssertNil(c.validate())
    }

    func testEmptyFieldNameIsRejected() {
        let c = RecordContentInput(recordType: "login", tags: [],
            fields: [FieldContentInput(name: "  ", value: .text("x"))])
        XCTAssertEqual(c.validate(), .emptyFieldName)
    }

    func testDuplicateFieldNamesAreRejected() {
        let c = RecordContentInput(recordType: "login", tags: [],
            fields: [
                FieldContentInput(name: "user", value: .text("a")),
                FieldContentInput(name: "user", value: .text("b")),
            ])
        XCTAssertEqual(c.validate(), .duplicateFieldName("user"))
    }

    func testEmptyRecordIsValid() {
        XCTAssertNil(RecordContentInput(recordType: "", tags: [], fields: []).validate())
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `( cd ios/SecretaryVaultAccess && swift test --filter RecordContentInputTests )`
Expected: FAIL — `RecordContentInput` / `FieldContentInput` / `FieldContentValue` undefined.

- [ ] **Step 3: Write minimal implementation**

```swift
// ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/RecordContentInput.swift
import Foundation

/// A field's plaintext value to write. Text is keyboard plaintext; Bytes is raw
/// bytes (the edit UI enters/edits these as hex). Mirrors the FFI
/// `FieldInputValue` without naming it, keeping this package FFI-free.
public enum FieldContentValue: Equatable {
    case text(String)
    case bytes([UInt8])

    public enum Kind: Equatable { case text, bytes }
    public var kind: Kind { switch self { case .text: return .text; case .bytes: return .bytes } }
}

/// One field to write: a non-secret name + a value. Mirrors FFI `FieldInput`.
public struct FieldContentInput: Equatable {
    public let name: String
    public let value: FieldContentValue
    public init(name: String, value: FieldContentValue) {
        self.name = name
        self.value = value
    }
}

/// Full desired content of a record to add or edit. Mirrors FFI `RecordContent`.
/// `record_uuid`, `created_at_ms`, per-field clocks and forward-compat `unknown`
/// maps are intentionally NOT here — the bridge edit primitives own those
/// (mint-on-add / preserve-on-edit).
public struct RecordContentInput: Equatable {
    public let recordType: String
    public let tags: [String]
    public let fields: [FieldContentInput]
    public init(recordType: String, tags: [String], fields: [FieldContentInput]) {
        self.recordType = recordType
        self.tags = tags
        self.fields = fields
    }

    /// Pure pre-commit validation. `nil` == valid. Field names must be
    /// non-blank and unique (the bridge diffs fields by name on edit, so two
    /// same-named fields would alias). Record type and tags are unconstrained.
    public func validate() -> RecordContentInputError? {
        var seen = Set<String>()
        for f in fields {
            if f.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                return .emptyFieldName
            }
            if !seen.insert(f.name).inserted {
                return .duplicateFieldName(f.name)
            }
        }
        return nil
    }
}

/// Why a `RecordContentInput` is not writable. Surfaced inline in the edit UI.
public enum RecordContentInputError: Error, Equatable {
    case emptyFieldName
    case duplicateFieldName(String)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `( cd ios/SecretaryVaultAccess && swift test --filter RecordContentInputTests )`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/RecordContentInput.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/RecordContentInputTests.swift
git commit -m "feat(ios-vault-access): RecordContentInput domain type + pure validation"
```

---

## Task 2: `DeviceUuidStore` — stable per-vault device UUID (pure, host-tested)

Mirror of desktop `load_or_create_device_uuid_in`: random 16-byte per-(install, vault) UUID, keyed by lowercase vault hex, persisted under Application Support, read back on subsequent calls, excluded from backup. A `DeviceUuidProviding` protocol lets the integration test inject a known UUID.

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/DeviceUuid.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/DeviceUuidStoreTests.swift`

- [ ] **Step 1: Write the failing test**

```swift
// ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/DeviceUuidStoreTests.swift
import XCTest
import SecretaryVaultAccess

final class DeviceUuidStoreTests: XCTestCase {
    private var dir: URL!

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("dev-uuid-\(UUID().uuidString)", isDirectory: true)
    }
    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: dir)
    }

    func testFirstCallMintsSixteenBytesAndPersists() throws {
        let store = DeviceUuidStore(directory: dir)
        let uuid = try store.deviceUuid(forVaultHex: "aa00aa00aa00aa00aa00aa00aa00aa00")
        XCTAssertEqual(uuid.count, 16)
        XCTAssertTrue(FileManager.default.fileExists(
            atPath: dir.appendingPathComponent("aa00aa00aa00aa00aa00aa00aa00aa00.dev").path))
    }

    func testSecondCallReturnsIdenticalBytes() throws {
        let store = DeviceUuidStore(directory: dir)
        let first = try store.deviceUuid(forVaultHex: "bb")
        let second = try store.deviceUuid(forVaultHex: "bb")
        XCTAssertEqual(first, second)
    }

    func testDistinctVaultsGetDistinctUuids() throws {
        let store = DeviceUuidStore(directory: dir)
        let a = try store.deviceUuid(forVaultHex: "01")
        let b = try store.deviceUuid(forVaultHex: "02")
        XCTAssertNotEqual(a, b)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `( cd ios/SecretaryVaultAccess && swift test --filter DeviceUuidStoreTests )`
Expected: FAIL — `DeviceUuidStore` undefined.

- [ ] **Step 3: Write minimal implementation**

```swift
// ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/DeviceUuid.swift
import Foundation
import Security

/// Resolves the 16-byte CRDT modifier UUID for a vault on this device. The edit
/// FFI stamps it onto every field a write touches. Non-secret (a public
/// per-device fingerprint), so it is NOT key material.
public protocol DeviceUuidProviding {
    /// `vaultHex`: lowercase, dash-less vault UUID hex. Returns 16 bytes.
    func deviceUuid(forVaultHex vaultHex: String) throws -> [UInt8]
}

public enum DeviceUuidStoreError: Error, Equatable {
    case entropyUnavailable(OSStatus)
    case corruptLength(Int)
}

/// File-backed `DeviceUuidProviding` mirroring desktop
/// `settings/io.rs::load_or_create_device_uuid_in`: random 16 bytes per
/// (install, vault), persisted as `<vaultHex>.dev`, read back on later calls so
/// one device == one CRDT fingerprint. iOS apps are single-process per vault, so
/// an atomic write + prior-existence check is sufficient (no cross-process race
/// to guard, unlike desktop's `persist_noclobber`). The file is excluded from
/// iCloud/iTunes backup so a restored backup does not clone the fingerprint.
public struct DeviceUuidStore: DeviceUuidProviding {
    /// 16 bytes — a UUID. Named to avoid a magic literal at the call sites.
    public static let uuidByteLen = 16

    private let directory: URL
    public init(directory: URL) { self.directory = directory }

    /// Production store under `Application Support/Secretary/devices/`.
    public static func applicationSupportDefault() throws -> DeviceUuidStore {
        let base = try FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true)
        return DeviceUuidStore(
            directory: base.appendingPathComponent("Secretary/devices", isDirectory: true))
    }

    public func deviceUuid(forVaultHex vaultHex: String) throws -> [UInt8] {
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true)
        let file = directory.appendingPathComponent("\(vaultHex).dev", isDirectory: false)
        if FileManager.default.fileExists(atPath: file.path) {
            return try Self.readUuid(at: file)
        }
        var uuid = [UInt8](repeating: 0, count: Self.uuidByteLen)
        let status = SecRandomCopyBytes(kSecRandomDefault, Self.uuidByteLen, &uuid)
        guard status == errSecSuccess else {
            throw DeviceUuidStoreError.entropyUnavailable(status)
        }
        do {
            try Data(uuid).write(to: file, options: [.atomic, .withoutOverwriting])
        } catch let e as NSError where e.code == NSFileWriteFileExistsError {
            return try Self.readUuid(at: file)  // lost a same-launch race; converge
        }
        excludeFromBackup(file)
        return uuid
    }

    /// Best-effort: backup exclusion is a correctness hint (don't clone the
    /// fingerprint via restore), not a security control, so a failure here is
    /// non-fatal — the UUID is still usable.
    private func excludeFromBackup(_ url: URL) {
        var url = url
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? url.setResourceValues(values)
    }

    private static func readUuid(at file: URL) throws -> [UInt8] {
        let bytes = [UInt8](try Data(contentsOf: file))
        guard bytes.count == uuidByteLen else {
            throw DeviceUuidStoreError.corruptLength(bytes.count)
        }
        return bytes
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `( cd ios/SecretaryVaultAccess && swift test --filter DeviceUuidStoreTests )`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/DeviceUuid.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/DeviceUuidStoreTests.swift
git commit -m "feat(ios-vault-access): file-backed per-vault DeviceUuidStore (desktop parity)"
```

---

## Task 3: Surface tombstone state + `recordNotFound` error mapping

`RecordView` gains a `tombstone` flag (read_block surfaces deleted records); the real adapter populates it; `VaultAccessError` gains a `recordNotFound` case mapped from `VaultError.RecordNotFound` (currently it silently falls through to `.other`).

**Files:**
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/RecordView.swift`
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultAccessError.swift`
- Modify: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSession.swift:73-77` (makeRecordView return)
- Modify: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/VaultErrorMapping.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/RecordViewTests.swift`

- [ ] **Step 1: Write the failing test**

```swift
// ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/RecordViewTests.swift
import XCTest
import SecretaryVaultAccess

final class RecordViewTests: XCTestCase {
    func testTombstoneDefaultsFalse() {
        let r = RecordView(uuid: [0x01], type: "login", tags: [], fields: [])
        XCTAssertFalse(r.tombstone)
    }
    func testTombstoneCanBeSet() {
        let r = RecordView(uuid: [0x01], type: "login", tags: [], fields: [], tombstone: true)
        XCTAssertTrue(r.tombstone)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `( cd ios/SecretaryVaultAccess && swift test --filter RecordViewTests )`
Expected: FAIL — `RecordView` has no `tombstone` parameter.

- [ ] **Step 3a: Add `tombstone` to `RecordView`**

Edit `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/RecordView.swift` — replace the `RecordView` struct's stored props + init:

```swift
/// One decrypted record. Field metadata is exposed; plaintext stays behind
/// `FieldView.reveal`. `tombstone` is true for a soft-deleted record (read_block
/// surfaces deleted records; the browse layer filters them client-side).
public struct RecordView {
    public let uuid: [UInt8]
    public let type: String
    public let tags: [String]
    public let fields: [FieldView]
    public let tombstone: Bool

    public init(uuid: [UInt8], type: String, tags: [String], fields: [FieldView],
                tombstone: Bool = false) {
        self.uuid = uuid
        self.type = type
        self.tags = tags
        self.fields = fields
        self.tombstone = tombstone
    }

    public var uuidHex: String { uuid.map { String(format: "%02x", $0) }.joined() }
}
```

- [ ] **Step 3b: Populate it in the real adapter**

Edit `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSession.swift` — in `makeRecordView`, change the returned `RecordView(...)` to pass the flag:

```swift
        return RecordView(
            uuid: [UInt8](rec.recordUuid()),
            type: rec.recordType(),
            tags: rec.tags(),
            fields: fields,
            tombstone: rec.tombstone())
```

- [ ] **Step 3c: Add `recordNotFound` + map it**

Edit `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultAccessError.swift` — add a case after `blockNotFound`:

```swift
    /// Block UUID not found in the manifest's live blocks.
    case blockNotFound(String)
    /// Record UUID not found in the target block (for edit/tombstone/resurrect).
    case recordNotFound(String)
```

Edit `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/VaultErrorMapping.swift` — add a case before `FolderInvalid`:

```swift
    case .BlockNotFound(let uuidHex):       return .blockNotFound(uuidHex)
    case .RecordNotFound(let detail):       return .recordNotFound(detail)
```

> If the generated `VaultError.RecordNotFound` carries no associated value, use `case .RecordNotFound:  return .recordNotFound("")`. Verify by reading the generated enum (search the build output / `.swift` binding for `case RecordNotFound`). The smoke test only matches `if case .RecordNotFound = e`, so confirm the arity before compiling.

- [ ] **Step 4: Run test to verify it passes**

Run: `( cd ios/SecretaryVaultAccess && swift test --filter RecordViewTests )`
Expected: PASS (2 tests). (SecretaryKit changes are compiled in Task 7's simulator run.)

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/RecordView.swift \
        ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultAccessError.swift \
        ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSession.swift \
        ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/VaultErrorMapping.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/RecordViewTests.swift
git commit -m "feat(ios-vault-access): surface record tombstone flag + recordNotFound mapping"
```

---

## Task 4: Write surface — `VaultSession` methods + `FakeVaultSession` + real `UniffiVaultSession`

Adds the four write methods to the protocol. All conformers must update together (a protocol change breaks conformance repo-wide), so this single task lands: protocol methods, the in-memory `FakeVaultSession` impl (host-tested here), and the real `UniffiVaultSession` impl (compiled + verified by Task 7's simulator run).

**Files:**
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultSession.swift`
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeVaultSession.swift`
- Modify: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSession.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/FakeVaultSessionWriteTests.swift`

- [ ] **Step 1: Write the failing test (against the Fake)**

```swift
// ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/FakeVaultSessionWriteTests.swift
import XCTest
import SecretaryVaultAccess
import SecretaryVaultAccessTesting

final class FakeVaultSessionWriteTests: XCTestCase {
    private let block: [UInt8] = [0xB1]
    private func freshSession() -> FakeVaultSession {
        FakeVaultSession(
            vaultUuidHex: "feed",
            blocks: [BlockSummary(uuid: block, name: "Logins", createdAtMs: 0, lastModMs: 0)],
            recordsByBlock: [block: []])
    }

    func testAppendAddsLiveRecord() throws {
        let s = freshSession()
        let newUuid = try s.appendRecord(
            blockUuid: block,
            content: RecordContentInput(recordType: "login", tags: ["w"],
                fields: [FieldContentInput(name: "user", value: .text("alice"))]))
        let records = try s.readBlock(blockUuid: block)
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(records[0].uuid, newUuid)
        XCTAssertFalse(records[0].tombstone)
        XCTAssertEqual(records[0].fields.first?.name, "user")
    }

    func testEditReplacesFieldsKeepingUuid() throws {
        let s = freshSession()
        let id = try s.appendRecord(blockUuid: block,
            content: RecordContentInput(recordType: "login", tags: [],
                fields: [FieldContentInput(name: "user", value: .text("alice"))]))
        try s.editRecord(blockUuid: block, recordUuid: id,
            content: RecordContentInput(recordType: "login", tags: ["x"],
                fields: [FieldContentInput(name: "user", value: .text("bob"))]))
        let rec = try XCTUnwrap(try s.readBlock(blockUuid: block).first)
        XCTAssertEqual(rec.uuid, id)
        XCTAssertEqual(rec.tags, ["x"])
        guard case .text(let v) = try XCTUnwrap(rec.fields.first).reveal() else {
            return XCTFail("expected text")
        }
        XCTAssertEqual(v, "bob")
    }

    func testTombstoneThenResurrectTogglesFlag() throws {
        let s = freshSession()
        let id = try s.appendRecord(blockUuid: block,
            content: RecordContentInput(recordType: "login", tags: [], fields: []))
        try s.tombstoneRecord(blockUuid: block, recordUuid: id)
        XCTAssertTrue(try XCTUnwrap(try s.readBlock(blockUuid: block).first).tombstone)
        try s.resurrectRecord(blockUuid: block, recordUuid: id)
        XCTAssertFalse(try XCTUnwrap(try s.readBlock(blockUuid: block).first).tombstone)
    }

    func testEditUnknownRecordThrowsRecordNotFound() throws {
        let s = freshSession()
        XCTAssertThrowsError(try s.editRecord(blockUuid: block, recordUuid: [0xFF],
            content: RecordContentInput(recordType: "x", tags: [], fields: []))) { err in
            guard case VaultAccessError.recordNotFound = err else {
                return XCTFail("expected .recordNotFound, got \(err)")
            }
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `( cd ios/SecretaryVaultAccess && swift test --filter FakeVaultSessionWriteTests )`
Expected: FAIL — `appendRecord`/`editRecord`/`tombstoneRecord`/`resurrectRecord` not in `VaultSession`.

- [ ] **Step 3a: Add write methods to the protocol**

Edit `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultSession.swift` — add inside the protocol, after `readBlock`:

```swift
    /// Append a NEW record to a block. The session mints a fresh 16-byte record
    /// UUID, stamps this device's UUID + now, and returns the new UUID.
    @discardableResult
    func appendRecord(blockUuid: [UInt8], content: RecordContentInput) throws -> [UInt8]
    /// Edit an existing LIVE record's full content (CRDT-correct: untouched
    /// fields keep their per-field clocks). Throws `.recordNotFound` if absent.
    func editRecord(blockUuid: [UInt8], recordUuid: [UInt8], content: RecordContentInput) throws
    /// Soft-delete a LIVE record (flips its tombstone). Throws `.recordNotFound`.
    func tombstoneRecord(blockUuid: [UInt8], recordUuid: [UInt8]) throws
    /// Restore a TOMBSTONED record. Throws `.recordNotFound`.
    func resurrectRecord(blockUuid: [UInt8], recordUuid: [UInt8]) throws
```

- [ ] **Step 3b: Implement in `FakeVaultSession`**

Edit `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeVaultSession.swift` — change `recordsByBlock` to `var`, add a UUID counter, and append the write methods. Replace the whole file body with:

```swift
import Foundation
import SecretaryVaultAccess

/// In-memory `VaultSession` for host tests. `recordsByBlock` is mutable so the
/// write methods model real add/edit/delete/restore state transitions. Field
/// `reveal` closures capture the stored plaintext.
public final class FakeVaultSession: VaultSession {
    public let vaultUuidHex: String
    private let blocks: [BlockSummary]
    private var recordsByBlock: [[UInt8]: [RecordView]]
    private var nextUuidByte: UInt8 = 0xA0
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
            throw VaultAccessError.blockNotFound(hex(blockUuid))
        }
        return records
    }

    @discardableResult
    public func appendRecord(blockUuid: [UInt8], content: RecordContentInput) throws -> [UInt8] {
        try requireBlock(blockUuid)
        let uuid = mintUuid()
        recordsByBlock[blockUuid]?.append(recordView(uuid: uuid, content: content, tombstone: false))
        return uuid
    }

    public func editRecord(blockUuid: [UInt8], recordUuid: [UInt8], content: RecordContentInput) throws {
        let idx = try liveIndex(blockUuid, recordUuid)
        recordsByBlock[blockUuid]?[idx] = recordView(uuid: recordUuid, content: content, tombstone: false)
    }

    public func tombstoneRecord(blockUuid: [UInt8], recordUuid: [UInt8]) throws {
        let idx = try liveIndex(blockUuid, recordUuid)
        setTombstone(blockUuid, idx, true)
    }

    public func resurrectRecord(blockUuid: [UInt8], recordUuid: [UInt8]) throws {
        try requireBlock(blockUuid)
        guard let idx = recordsByBlock[blockUuid]?.firstIndex(
            where: { $0.uuid == recordUuid && $0.tombstone }) else {
            throw VaultAccessError.recordNotFound(hex(recordUuid))
        }
        setTombstone(blockUuid, idx, false)
    }

    public func wipe() { wipeCount += 1 }

    // MARK: - helpers

    private func requireBlock(_ blockUuid: [UInt8]) throws {
        guard recordsByBlock[blockUuid] != nil else {
            throw VaultAccessError.blockNotFound(hex(blockUuid))
        }
    }

    private func liveIndex(_ blockUuid: [UInt8], _ recordUuid: [UInt8]) throws -> Int {
        try requireBlock(blockUuid)
        guard let idx = recordsByBlock[blockUuid]?.firstIndex(
            where: { $0.uuid == recordUuid && !$0.tombstone }) else {
            throw VaultAccessError.recordNotFound(hex(recordUuid))
        }
        return idx
    }

    private func setTombstone(_ blockUuid: [UInt8], _ idx: Int, _ value: Bool) {
        guard let old = recordsByBlock[blockUuid]?[idx] else { return }
        recordsByBlock[blockUuid]?[idx] = RecordView(
            uuid: old.uuid, type: old.type, tags: old.tags, fields: old.fields, tombstone: value)
    }

    private func recordView(uuid: [UInt8], content: RecordContentInput, tombstone: Bool) -> RecordView {
        let fields = content.fields.map { f -> FieldView in
            switch f.value {
            case .text(let s):
                return FieldView(name: f.name, kind: .text) { .text(s) }
            case .bytes(let b):
                return FieldView(name: f.name, kind: .bytes) { .bytes(b) }
            }
        }
        return RecordView(uuid: uuid, type: content.recordType, tags: content.tags,
                          fields: fields, tombstone: tombstone)
    }

    private func mintUuid() -> [UInt8] {
        let b = nextUuidByte
        nextUuidByte = nextUuidByte &+ 1
        return [UInt8](repeating: b, count: 16)
    }

    private func hex(_ bytes: [UInt8]) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
}
```

- [ ] **Step 3c: Implement in the real `UniffiVaultSession`**

Edit `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSession.swift`:

(i) Add a stored device-UUID provider + designated init alongside the existing one:

```swift
    private let identity: UnlockedIdentity
    private let manifest: OpenVaultManifest
    private let deviceUuids: DeviceUuidProviding
    /// Retained decrypted-block handles, so reveal closures remain valid.
    private var openBlocks: [BlockReadOutput] = []
    /// Cached per this session so every write stamps the same device UUID.
    private var cachedDeviceUuid: [UInt8]?

    public convenience init(output: OpenVaultOutput) throws {
        self.init(output: output, deviceUuids: try DeviceUuidStore.applicationSupportDefault())
    }

    public init(output: OpenVaultOutput, deviceUuids: DeviceUuidProviding) {
        self.identity = output.identity
        self.manifest = output.manifest
        self.deviceUuids = deviceUuids
    }
```

> NOTE: the existing `init(output:)` becomes `convenience ... throws`. Update its one production call site in `ios/SecretaryKit` that constructs `UniffiVaultSession(output:)` (the open port — `UniffiVaultOpenPort`/`OpenVaultOutput+OpenedVault` area) to `try UniffiVaultSession(output:)`. Find it: `grep -rn "UniffiVaultSession(output" ios/SecretaryKit/Sources`.

(ii) Add the write methods + a content-mapping helper at the end of the class (before the closing brace):

```swift
    @discardableResult
    public func appendRecord(blockUuid: [UInt8], content: RecordContentInput) throws -> [UInt8] {
        let recordUuid = Self.freshRecordUuid()
        try write { dev, now in
            try SecretaryKit.appendRecord(
                identity: identity, manifest: manifest,
                blockUuid: Data(blockUuid), recordUuid: Data(recordUuid),
                content: Self.toFfi(content), deviceUuid: Data(dev), nowMs: now)
        }
        return recordUuid
    }

    public func editRecord(blockUuid: [UInt8], recordUuid: [UInt8], content: RecordContentInput) throws {
        try write { dev, now in
            try SecretaryKit.editRecord(
                identity: identity, manifest: manifest,
                blockUuid: Data(blockUuid), recordUuid: Data(recordUuid),
                content: Self.toFfi(content), deviceUuid: Data(dev), nowMs: now)
        }
    }

    public func tombstoneRecord(blockUuid: [UInt8], recordUuid: [UInt8]) throws {
        try write { dev, now in
            try SecretaryKit.tombstoneRecord(
                identity: identity, manifest: manifest,
                blockUuid: Data(blockUuid), recordUuid: Data(recordUuid),
                deviceUuid: Data(dev), nowMs: now)
        }
    }

    public func resurrectRecord(blockUuid: [UInt8], recordUuid: [UInt8]) throws {
        try write { dev, now in
            try SecretaryKit.resurrectRecord(
                identity: identity, manifest: manifest,
                blockUuid: Data(blockUuid), recordUuid: Data(recordUuid),
                deviceUuid: Data(dev), nowMs: now)
        }
    }

    /// Resolve (device uuid, now-ms), run the FFI write, map errors. Centralizes
    /// the device-uuid resolve + `VaultError` mapping for all four writers.
    private func write(_ body: (_ deviceUuid: [UInt8], _ nowMs: UInt64) throws -> Void) throws {
        let dev = try deviceUuid()
        do {
            try body(dev, Self.nowMs())
        } catch let e as VaultError {
            throw mapVaultAccessError(e)
        }
    }

    private func deviceUuid() throws -> [UInt8] {
        if let c = cachedDeviceUuid { return c }
        let d = try deviceUuids.deviceUuid(forVaultHex: vaultUuidHex)
        cachedDeviceUuid = d
        return d
    }

    private static func nowMs() -> UInt64 {
        UInt64(Date().timeIntervalSince1970 * 1000)
    }

    private static func freshRecordUuid() -> [UInt8] {
        var u = [UInt8](repeating: 0, count: DeviceUuidStore.uuidByteLen)
        _ = SecRandomCopyBytes(kSecRandomDefault, u.count, &u)
        return u
    }

    /// Map the FFI-free `RecordContentInput` to the uniffi `RecordContent`,
    /// zeroizing the plaintext byte payloads we copy in once the value type is
    /// built (text values are Strings — same residue limitation as the unlock
    /// password field).
    private static func toFfi(_ c: RecordContentInput) -> RecordContent {
        let fields = c.fields.map { f -> FieldInput in
            switch f.value {
            case .text(let s):
                return FieldInput(name: f.name, value: .text(text: s))
            case .bytes(var b):
                let input = FieldInput(name: f.name, value: .bytes(data: b))
                b.resetBytes(in: b.indices)  // overwrite our copy
                return input
            }
        }
        return RecordContent(recordType: c.recordType, tags: c.tags, fields: fields)
    }
```

Add `import Security` at the top of the file (for `SecRandomCopyBytes`) if not present. `resetBytes(in:)` is `Foundation.Data`'s zeroing call — `b` is `[UInt8]`; use `for i in b.indices { b[i] = 0 }` instead (Array has no `resetBytes`). Use this exact zeroing loop:

```swift
            case .bytes(var b):
                let input = FieldInput(name: f.name, value: .bytes(data: b))
                for i in b.indices { b[i] = 0 }  // overwrite our copy of the payload
                return input
```

> The uniffi `.bytes(data:)` arity: confirm whether it is `[UInt8]` or `Data` in the generated binding (the UDL declares `bytes data`; uniffi maps `bytes` → `Data` in Swift). If it is `Data`, pass `Data(b)` and zero `b` after. Verify against the generated `FieldInputValue` before compiling — the smoke test only exercises `.text(text:)`.

- [ ] **Step 4: Run test to verify it passes**

Run: `( cd ios/SecretaryVaultAccess && swift test --filter FakeVaultSessionWriteTests )`
Expected: PASS (4 tests). The real `UniffiVaultSession` is compiled + exercised in Task 7.

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultSession.swift \
        ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeVaultSession.swift \
        ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSession.swift
git commit -m "feat(ios): record write surface on VaultSession (fake + uniffi impls)"
```

---

## Task 5: Browse VM — show-deleted partition + tombstone/resurrect actions

`VaultBrowseViewModel` filters tombstoned records out of the live list by default, exposes a `showDeleted` toggle, and gains delete/restore actions that commit then re-read.

**Files:**
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultBrowseViewModel.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultBrowseViewModelDeletedTests.swift`

- [ ] **Step 1: Write the failing test**

```swift
// ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultBrowseViewModelDeletedTests.swift
import XCTest
@testable import SecretaryVaultAccessUI
import SecretaryVaultAccess
import SecretaryVaultAccessTesting

@MainActor
final class VaultBrowseViewModelDeletedTests: XCTestCase {
    private let block: [UInt8] = [0xB1]

    private func session(_ records: [RecordView]) -> FakeVaultSession {
        FakeVaultSession(
            vaultUuidHex: "feed",
            blocks: [BlockSummary(uuid: block, name: "Logins", createdAtMs: 0, lastModMs: 0)],
            recordsByBlock: [block: records])
    }

    private func record(_ b: UInt8, tombstone: Bool) -> RecordView {
        RecordView(uuid: [b], type: "login", tags: [], fields: [], tombstone: tombstone)
    }

    func testVisibleRecordsHideTombstonedByDefault() {
        let vm = VaultBrowseViewModel(session: session([record(1, tombstone: false),
                                                        record(2, tombstone: true)]))
        vm.loadBlocks()
        vm.selectBlock(vm.blocks[0])
        XCTAssertEqual(vm.visibleRecords.map(\.uuid), [[1]])
    }

    func testShowDeletedRevealsTombstoned() {
        let vm = VaultBrowseViewModel(session: session([record(1, tombstone: false),
                                                        record(2, tombstone: true)]))
        vm.loadBlocks(); vm.selectBlock(vm.blocks[0])
        vm.showDeleted = true
        XCTAssertEqual(vm.visibleRecords.map(\.uuid), [[1], [2]])
    }

    func testDeleteThenRestoreUpdatesVisibility() throws {
        let vm = VaultBrowseViewModel(session: session([record(1, tombstone: false)]))
        vm.loadBlocks(); vm.selectBlock(vm.blocks[0])
        vm.delete(record: vm.visibleRecords[0])
        XCTAssertTrue(vm.visibleRecords.isEmpty)          // gone from live list
        vm.showDeleted = true
        XCTAssertEqual(vm.visibleRecords.count, 1)
        vm.restore(record: vm.visibleRecords[0])
        vm.showDeleted = false
        XCTAssertEqual(vm.visibleRecords.count, 1)        // back in live list
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `( cd ios/SecretaryVaultAccess && swift test --filter VaultBrowseViewModelDeletedTests )`
Expected: FAIL — `visibleRecords` / `showDeleted` / `delete` / `restore` undefined.

- [ ] **Step 3: Implement**

Edit `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultBrowseViewModel.swift`:

(i) Add published state after `revealed`:

```swift
    /// When false (default) the browse list hides tombstoned records. Toggling
    /// it does not re-read — `visibleRecords` re-partitions the cached `records`.
    @Published public var showDeleted = false

    /// The block-currently-selected uuid, so delete/restore can re-read it.
    private var selectedBlockUuid: [UInt8]?
```

(ii) Add a computed projection + remember the selected block. In `selectBlock`, store the uuid; add `visibleRecords`:

```swift
    public func selectBlock(_ block: BlockSummary) {
        error = nil
        revealed.removeAll()
        selectedBlockUuid = block.uuid
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

    /// Records to display: tombstoned ones are hidden unless `showDeleted`.
    public var visibleRecords: [RecordView] {
        let all = records ?? []
        return showDeleted ? all : all.filter { !$0.tombstone }
    }
```

(iii) Add delete/restore that commit then re-read the selected block:

```swift
    /// Soft-delete a record, then re-read so `visibleRecords` reflects it.
    public func delete(record: RecordView) {
        commitThenReload { try session.tombstoneRecord(blockUuid: $0, recordUuid: record.uuid) }
    }

    /// Restore a soft-deleted record, then re-read.
    public func restore(record: RecordView) {
        commitThenReload { try session.resurrectRecord(blockUuid: $0, recordUuid: record.uuid) }
    }

    private func commitThenReload(_ op: ([UInt8]) throws -> Void) {
        guard let blockUuid = selectedBlockUuid else { return }
        error = nil
        do {
            try op(blockUuid)
            revealed.removeAll()  // never carry a reveal across a mutation
            records = try session.readBlock(blockUuid: blockUuid)
        } catch let e as VaultAccessError {
            error = e
        } catch {
            self.error = .other(String(describing: error))
        }
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `( cd ios/SecretaryVaultAccess && swift test --filter VaultBrowseViewModelDeletedTests )`
Expected: PASS (3 tests). Also run the existing suite: `( cd ios/SecretaryVaultAccess && swift test )` — all green.

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultBrowseViewModel.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultBrowseViewModelDeletedTests.swift
git commit -m "feat(ios-vault-access-ui): show-deleted toggle + delete/restore browse actions"
```

---

## Task 6: `RecordEditViewModel` — add / edit form logic

The add+edit form state machine: an editable field list (add/remove/rename, text↔bytes via hex), validation, and a `commit()` that builds `RecordContentInput`, validates, and calls `appendRecord`/`editRecord`. Edit mode prefills from a `RecordView` by revealing its fields.

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/RecordEditViewModel.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/RecordEditViewModelTests.swift`

- [ ] **Step 1: Write the failing test**

```swift
// ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/RecordEditViewModelTests.swift
import XCTest
@testable import SecretaryVaultAccessUI
import SecretaryVaultAccess
import SecretaryVaultAccessTesting

@MainActor
final class RecordEditViewModelTests: XCTestCase {
    private let block: [UInt8] = [0xB1]
    private func session(_ records: [RecordView] = []) -> FakeVaultSession {
        FakeVaultSession(
            vaultUuidHex: "feed",
            blocks: [BlockSummary(uuid: block, name: "Logins", createdAtMs: 0, lastModMs: 0)],
            recordsByBlock: [block: records])
    }

    func testAddCommitWritesRecord() throws {
        let s = session()
        let vm = RecordEditViewModel(session: s, blockUuid: block, mode: .add)
        vm.recordType = "login"
        vm.addField()
        vm.fields[0].name = "user"
        vm.fields[0].rawText = "alice"
        vm.commit()
        XCTAssertTrue(vm.committed)
        XCTAssertNil(vm.error)
        XCTAssertEqual(try s.readBlock(blockUuid: block).count, 1)
    }

    func testDuplicateFieldNameBlocksCommit() throws {
        let s = session()
        let vm = RecordEditViewModel(session: s, blockUuid: block, mode: .add)
        vm.addField(); vm.fields[0].name = "user"; vm.fields[0].rawText = "a"
        vm.addField(); vm.fields[1].name = "user"; vm.fields[1].rawText = "b"
        vm.commit()
        XCTAssertFalse(vm.committed)
        XCTAssertEqual(vm.error, .invalidArgument("duplicate field name: user"))
        XCTAssertEqual(try s.readBlock(blockUuid: block).count, 0)  // nothing written
    }

    func testBadHexInBytesFieldBlocksCommit() throws {
        let s = session()
        let vm = RecordEditViewModel(session: s, blockUuid: block, mode: .add)
        vm.addField()
        vm.fields[0].name = "key"
        vm.setKind(at: 0, .bytes)
        vm.fields[0].rawText = "zz"  // not hex
        vm.commit()
        XCTAssertFalse(vm.committed)
        XCTAssertEqual(vm.error, .invalidArgument("field 'key' is not valid hex"))
    }

    func testEditPrefillsFromRecordThenCommitsEdit() throws {
        let id: [UInt8] = [0xC1]
        let existing = RecordView(
            uuid: id, type: "login", tags: ["w"],
            fields: [FieldView(name: "user", kind: .text) { .text("alice") }])
        let s = session([existing])
        let vm = RecordEditViewModel(session: s, blockUuid: block, mode: .edit(recordUuid: id))
        try vm.loadForEdit(record: existing)
        XCTAssertEqual(vm.recordType, "login")
        XCTAssertEqual(vm.fields.first?.rawText, "alice")
        vm.fields[0].rawText = "bob"
        vm.commit()
        XCTAssertTrue(vm.committed)
        guard case .text(let v) = try XCTUnwrap(try s.readBlock(blockUuid: block).first?.fields.first).reveal() else {
            return XCTFail("expected text")
        }
        XCTAssertEqual(v, "bob")
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `( cd ios/SecretaryVaultAccess && swift test --filter RecordEditViewModelTests )`
Expected: FAIL — `RecordEditViewModel` undefined.

- [ ] **Step 3: Implement**

```swift
// ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/RecordEditViewModel.swift
import Foundation
import Combine
import SecretaryVaultAccess

/// One editable field row. `rawText` holds plaintext for `.text` fields and a
/// hex string for `.bytes` fields (the only byte-entry affordance this slice).
public struct EditableField: Identifiable, Equatable {
    public let id: UUID
    public var name: String
    public var kind: FieldContentValue.Kind
    public var rawText: String

    public init(id: UUID = UUID(), name: String = "", kind: FieldContentValue.Kind = .text,
                rawText: String = "") {
        self.id = id; self.name = name; self.kind = kind; self.rawText = rawText
    }
}

/// Drives the add/edit record form. Host-testable with `FakeVaultSession`. On a
/// successful `commit()` it sets `committed` (the screen dismisses + the browse
/// VM re-reads); on failure it sets a typed `error` and writes nothing.
@MainActor
public final class RecordEditViewModel: ObservableObject {
    public enum Mode: Equatable {
        case add
        case edit(recordUuid: [UInt8])
    }

    @Published public var recordType: String = ""
    @Published public var tags: [String] = []
    @Published public var fields: [EditableField] = []
    @Published public private(set) var error: VaultAccessError?
    @Published public private(set) var committed = false

    private let session: VaultSession
    private let blockUuid: [UInt8]
    public let mode: Mode

    public init(session: VaultSession, blockUuid: [UInt8], mode: Mode) {
        self.session = session
        self.blockUuid = blockUuid
        self.mode = mode
    }

    public func addField() { fields.append(EditableField()) }
    public func removeField(at index: Int) {
        guard fields.indices.contains(index) else { return }
        fields.remove(at: index)
    }
    public func setKind(at index: Int, _ kind: FieldContentValue.Kind) {
        guard fields.indices.contains(index) else { return }
        fields[index].kind = kind
    }

    /// Reveal each field of an existing record into the editable rows. Text →
    /// plaintext; bytes → lowercase hex. Throws if a field cannot be revealed.
    public func loadForEdit(record: RecordView) throws {
        recordType = record.type
        tags = record.tags
        fields = try record.fields.map { fv in
            switch try fv.reveal() {
            case .text(let s):
                return EditableField(name: fv.name, kind: .text, rawText: s)
            case .bytes(let b):
                return EditableField(name: fv.name, kind: .bytes, rawText: Self.hex(b))
            }
        }
    }

    /// Build → validate → write. Sets `committed` on success; sets `error` and
    /// writes nothing on any validation or FFI failure.
    public func commit() {
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

    // MARK: - helpers

    private func buildContent() throws -> RecordContentInput {
        let built = try fields.map { f -> FieldContentInput in
            switch f.kind {
            case .text:
                return FieldContentInput(name: f.name, value: .text(f.rawText))
            case .bytes:
                guard let bytes = Self.parseHex(f.rawText) else {
                    throw VaultAccessError.invalidArgument("field '\(f.name)' is not valid hex")
                }
                return FieldContentInput(name: f.name, value: .bytes(bytes))
            }
        }
        return RecordContentInput(recordType: recordType, tags: tags, fields: built)
    }

    private static func mapValidation(_ v: RecordContentInputError) -> VaultAccessError {
        switch v {
        case .emptyFieldName:            return .invalidArgument("a field name is empty")
        case .duplicateFieldName(let n): return .invalidArgument("duplicate field name: \(n)")
        }
    }

    private static func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    /// Parse an even-length hex string to bytes; `nil` if malformed. Whitespace
    /// is stripped so users can paste spaced hex.
    private static func parseHex(_ s: String) -> [UInt8]? {
        let cleaned = s.filter { !$0.isWhitespace }
        guard cleaned.count % 2 == 0 else { return nil }
        var out = [UInt8](); out.reserveCapacity(cleaned.count / 2)
        var i = cleaned.startIndex
        while i < cleaned.endIndex {
            let j = cleaned.index(i, offsetBy: 2)
            guard let b = UInt8(cleaned[i..<j], radix: 16) else { return nil }
            out.append(b)
            i = j
        }
        return out
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `( cd ios/SecretaryVaultAccess && swift test --filter RecordEditViewModelTests )`
Expected: PASS (4 tests). Then `( cd ios/SecretaryVaultAccess && swift test )` — full host suite green.

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/RecordEditViewModel.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/RecordEditViewModelTests.swift
git commit -m "feat(ios-vault-access-ui): RecordEditViewModel (add/edit form + hex bytes + validation)"
```

---

## Task 7: Simulator integration round-trip (real FFI)

Drives the real `UniffiVaultSession` writes against a **`cp -R` temp copy of golden_vault_001** (never the tracked fixture — this writes): add → edit (with the per-field-clock proof) → delete → restore. Injects a fixed device UUID so the clock proof is deterministic.

**Files:**
- Create: `ios/SecretaryKit/Tests/SecretaryKitTests/RecordEditIntegrationTests.swift`

- [ ] **Step 1: Write the failing test**

```swift
// ios/SecretaryKit/Tests/SecretaryKitTests/RecordEditIntegrationTests.swift
import XCTest
@testable import SecretaryKit
import SecretaryVaultAccess

/// A device-uuid provider that yields a fixed, known UUID, so the per-field
/// clock proof is deterministic and differs from the seed device.
private struct FixedDeviceUuid: DeviceUuidProviding {
    let value: [UInt8]
    func deviceUuid(forVaultHex vaultHex: String) throws -> [UInt8] { value }
}

/// Real append/edit/tombstone/resurrect FFI on a simulator against a WRITABLE
/// copy of golden_vault_001. The golden vault is a frozen KAT — we copy it to a
/// tempdir and mutate the copy only.
final class RecordEditIntegrationTests: XCTestCase {
    private let goldenPassword = "correct horse battery staple"
    private var vaultCopy: URL!

    override func setUpWithError() throws {
        let bundled = try XCTUnwrap(
            Bundle.module.url(forResource: "golden_vault_001", withExtension: nil),
            "golden_vault_001 not bundled — run ios/scripts/build-xcframework.sh")
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("gv-edit-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        vaultCopy = tmp.appendingPathComponent("golden_vault_001", isDirectory: true)
        try FileManager.default.copyItem(at: bundled, to: vaultCopy)
    }
    override func tearDownWithError() throws {
        if let vaultCopy { try? FileManager.default.removeItem(at: vaultCopy.deletingLastPathComponent()) }
    }
    private var path: Data { Data(vaultCopy.path.utf8) }

    private func openSession(device: [UInt8]) throws -> UniffiVaultSession {
        let out = try openVaultWithPasswordRaw(  // see note below
            vaultPath: path, password: [UInt8](goldenPassword.utf8))
        return UniffiVaultSession(output: out, deviceUuids: FixedDeviceUuid(value: device))
    }

    func testAddEditDeleteRestoreRoundTrip() throws {
        let device = [UInt8](repeating: 0x5A, count: 16)
        let session = try openSession(device: device)
        defer { session.wipe() }
        let block = try XCTUnwrap(session.blockSummaries().first).uuid

        // ADD a record with two text fields.
        let id = try session.appendRecord(blockUuid: block, content: RecordContentInput(
            recordType: "login", tags: ["work"],
            fields: [FieldContentInput(name: "user", value: .text("alice")),
                     FieldContentInput(name: "pass", value: .text("hunter2"))]))
        var rec = try XCTUnwrap(try session.readBlock(blockUuid: block).first { $0.uuid == id })
        XCTAssertFalse(rec.tombstone)

        // EDIT only "pass"; "user" must keep its prior clock (per-field proof
        // is asserted at the FFI level in Task-1 smoke; here assert the value).
        try session.editRecord(blockUuid: block, recordUuid: id, content: RecordContentInput(
            recordType: "login", tags: ["work"],
            fields: [FieldContentInput(name: "user", value: .text("alice")),
                     FieldContentInput(name: "pass", value: .text("s3cret!"))]))
        rec = try XCTUnwrap(try session.readBlock(blockUuid: block).first { $0.uuid == id })
        let pass = try XCTUnwrap(rec.fields.first { $0.name == "pass" })
        guard case .text(let v) = try pass.reveal() else { return XCTFail("expected text") }
        XCTAssertEqual(v, "s3cret!")

        // DELETE → leaves the live projection.
        try session.tombstoneRecord(blockUuid: block, recordUuid: id)
        let afterDelete = try session.readBlock(blockUuid: block).first { $0.uuid == id }
        XCTAssertEqual(afterDelete?.tombstone, true)

        // RESTORE → live again.
        try session.resurrectRecord(blockUuid: block, recordUuid: id)
        let afterRestore = try session.readBlock(blockUuid: block).first { $0.uuid == id }
        XCTAssertEqual(afterRestore?.tombstone, false)
    }
}
```

> **`openVaultWithPasswordRaw` note:** the test needs the raw `OpenVaultOutput` to construct a `UniffiVaultSession` with an injected device provider — `UniffiVaultOpenPort.openWithPassword` returns a `VaultSession` (the protocol), not the output. Read `ios/SecretaryKit/Sources/SecretaryKit/.../UniffiVaultOpenPort.swift` (and `OpenVaultOutput+OpenedVault.swift`) to find the existing password-open call that yields `OpenVaultOutput` (the uniffi `openVault`/`openVaultWithPassword` free function). Call that uniffi function directly in the test (it is `@testable import SecretaryKit`, so internal helpers are visible). If the existing port already exposes a way to get the output, reuse it. Do NOT add a production seam solely for the test — use the uniffi free function the port itself calls.

- [ ] **Step 2: Run test to verify it fails / compiles**

Run: `bash ios/scripts/run-ios-tests.sh`
Expected: builds the framework, then this test FAILS first if the FFI mapping has a bug, or PASSES. Iterate on `toFfi`/init arity (Task 4 notes) until green. This run is also the first compile of all SecretaryKit changes from Tasks 3–4.

- [ ] **Step 3: Fix any FFI-arity mismatches**

Resolve the two arity uncertainties flagged in Task 4 against the now-built generated binding: `FieldInputValue.bytes(data:)` (`Data` vs `[UInt8]`) and `VaultError.RecordNotFound` (with/without payload). Adjust `toFfi` and `mapVaultAccessError` accordingly. Re-run.

- [ ] **Step 4: Run to verify it passes**

Run: `bash ios/scripts/run-ios-tests.sh`
Expected: host suites green, `xcodebuild test` green (incl. `RecordEditIntegrationTests`), app compile green.

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryKit/Tests/SecretaryKitTests/RecordEditIntegrationTests.swift \
        ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSession.swift \
        ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/VaultErrorMapping.swift
git commit -m "test(ios-kit): simulator add/edit/delete/restore round-trip on a temp vault copy"
```

---

## Task 8: App UI — edit screen + browse wiring

The SwiftUI surface: a Form-based `RecordEditScreen` (add/edit), and `VaultBrowseScreen` gaining add/edit/delete/restore entry points + a "Show deleted" toggle, routed from `RootView`/the browse screen via a sheet. View-model logic is already host-tested; this task is the view layer + app-compile proof.

**Files:**
- Create: `ios/SecretaryApp/Sources/RecordEditScreen.swift`
- Modify: `ios/SecretaryApp/Sources/VaultBrowseScreen.swift`
- Read first: `ios/SecretaryApp/Sources/VaultBrowseScreen.swift`, `ios/SecretaryApp/Sources/UnlockScreen.swift` (Form idiom)

- [ ] **Step 1: Write `RecordEditScreen`**

A `Form` over a `@StateObject RecordEditViewModel`: a Record-type text field; an editable field list (name + a text/bytes `Picker` + value field — `SecureField` for text, hex `TextField` for bytes) with add/remove; a Save button calling `viewModel.commit()`; an Error section (mirror `UnlockScreen`); `onChange(of: committed)` → `onDone()` to dismiss + signal refresh. Pattern:

```swift
// ios/SecretaryApp/Sources/RecordEditScreen.swift
import SwiftUI
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Add / edit a record. Thin shell over `RecordEditViewModel`: renders the
/// editable field rows and forwards Save. On `committed` it calls `onDone`,
/// which dismisses the sheet and re-reads the block in the browse VM.
struct RecordEditScreen: View {
    @StateObject private var viewModel: RecordEditViewModel
    let title: String
    let onDone: () -> Void

    init(viewModel: RecordEditViewModel, title: String, onDone: @escaping () -> Void) {
        self._viewModel = StateObject(wrappedValue: viewModel)
        self.title = title
        self.onDone = onDone
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Type") {
                    TextField("record type (e.g. login)", text: $viewModel.recordType)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                }
                Section("Fields") {
                    ForEach($viewModel.fields) { $field in
                        VStack(alignment: .leading) {
                            TextField("name", text: $field.name)
                                .textInputAutocapitalization(.never).autocorrectionDisabled()
                            Picker("kind", selection: $field.kind) {
                                Text("Text").tag(FieldContentValue.Kind.text)
                                Text("Bytes (hex)").tag(FieldContentValue.Kind.bytes)
                            }.pickerStyle(.segmented)
                            if field.kind == .text {
                                SecureField("value", text: $field.rawText)
                            } else {
                                TextField("hex bytes", text: $field.rawText)
                                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                            }
                        }
                    }
                    .onDelete { viewModel.fields.remove(atOffsets: $0) }
                    Button("Add field") { viewModel.addField() }
                }
                Section { Button("Save") { viewModel.commit() } }
                if let err = viewModel.error {
                    Section("Error") {
                        Text(String(describing: err)).font(.footnote.monospaced()).foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle(title)
            .onChange(of: viewModel.committed) { _, done in if done { onDone() } }
        }
    }
}
```

- [ ] **Step 2: Wire `VaultBrowseScreen`**

Read `ios/SecretaryApp/Sources/VaultBrowseScreen.swift` first. Add:
- a `Toggle("Show deleted", isOn: $viewModel.showDeleted)` in the records section header,
- iterate `viewModel.visibleRecords` instead of the raw records,
- a toolbar "+" that presents `RecordEditScreen` in `.add` mode for the selected block (sheet state `@State private var editing: RecordEditViewModel?`),
- per-record swipe actions: Edit (presents `RecordEditScreen` in `.edit` mode, calling `viewModel.… loadForEdit`), Delete (confirmationDialog → `viewModel.delete(record:)`), and — for tombstoned rows shown under Show-deleted — Restore (`viewModel.restore(record:)`),
- on the edit sheet's `onDone`, dismiss + re-select the block so the list refreshes.

Construct the edit VM from the browse VM's session. The browse VM exposes its session for this; add a minimal accessor if needed:

```swift
// in VaultBrowseViewModel — expose what the edit sheet needs without leaking the session widely:
public func makeEditViewModel(mode: RecordEditViewModel.Mode) -> RecordEditViewModel? {
    guard let blockUuid = selectedBlockUuid else { return nil }
    return RecordEditViewModel(session: session, blockUuid: blockUuid, mode: mode)
}
```

> Keep the wiring minimal and follow the existing `VaultBrowseScreen` structure (privacy redaction on background, etc.). The exact SwiftUI is at the implementer's discretion as long as it: shows `visibleRecords`, gates deleted rows behind the toggle, and routes add/edit/delete/restore through the (already-tested) VM methods.

- [ ] **Step 3: Build the app (compile proof)**

Run: `bash ios/scripts/run-ios-tests.sh`
Expected: all host + simulator tests green AND the final `build-app.sh` step compiles the app with the new screens.

- [ ] **Step 4: Commit**

```bash
git add ios/SecretaryApp/Sources/RecordEditScreen.swift \
        ios/SecretaryApp/Sources/VaultBrowseScreen.swift \
        ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultBrowseViewModel.swift
git commit -m "feat(ios-app): record add/edit/delete/restore UI + show-deleted toggle"
```

---

## Task 9: Docs — README + ROADMAP

**Files:**
- Modify: `README.md`
- Modify: `ROADMAP.md`

- [ ] **Step 1: Update README**

Read the iOS status section of `README.md`. Add a brief dot-point that the iOS app now supports record CRUD (add / edit full content / soft-delete / restore) on a selected, unlocked vault, with deleted records hidden behind a "Show deleted" toggle. Keep it brief (per the README-style preference — no test-count walls).

- [ ] **Step 2: Update ROADMAP**

Read `ROADMAP.md`, find the iOS / D.3 slice list, and mark the iOS record-CRUD UI slice (Slice 2) shipped, noting follow-ups (iOS read-path `include_deleted` Rust gate; vault create/import; biometric-re-auth-before-write).

- [ ] **Step 3: Commit**

```bash
git add README.md ROADMAP.md
git commit -m "docs: iOS record-CRUD UI shipped — README + ROADMAP"
```

---

## Final gauntlet (run before opening the PR)

```bash
cd /Users/hherb/src/secretary/.worktrees/ios-record-crud
( cd ios/SecretaryVaultAccess && swift test )          # host: all pure + UI VM tests
bash ios/scripts/run-ios-tests.sh                       # framework build + simulator XCTest + app compile
# Confirm no core / frozen-format / FfiVaultError change:
git diff main..HEAD --name-only | grep -E '\.rs$' || echo "no Rust changes (expected)"
```

Expected: host suite green; `run-ios-tests.sh` green end-to-end (incl. `RecordEditIntegrationTests`); no `.rs` changes (this slice is Swift-only — it consumes the Slice-1 FFI, does not modify it).

On-device smoke (manual, per CLAUDE.md — only on-device biometric/real-hardware steps are manual): add, edit, delete, and restore a record in a real vault on an iPhone, confirming the writes persist across a lock/unlock.

---

## Self-review notes (carried into execution)

- **Two FFI-arity uncertainties** are flagged inline (Task 4 / Task 7 Step 3): `FieldInputValue.bytes(data:)` (`Data` vs `[UInt8]`) and `VaultError.RecordNotFound` payload arity. Both are resolved against the generated binding at first simulator compile — do not guess; read the binding.
- **`init(output:)` becomes throwing** (Task 4) — its existing call site in the open port must gain `try`. Grep for it; don't leave a broken constructor.
- **Golden vault is frozen** — the integration test (Task 7) copies it to a tempdir and mutates only the copy (the established pattern in `VaultAccessIntegrationTests`). Never point a write at the bundled fixture.
- **No `.rs` changes** — every task is under `ios/` + `README.md`/`ROADMAP.md`. If a task tempts you into `ffi/` or `core/`, stop: the FFI surface is frozen from Slice 1.
