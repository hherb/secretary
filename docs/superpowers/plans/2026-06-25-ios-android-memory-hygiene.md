# iOS/Android memory-hygiene hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bound the reveal-residency window to the on-screen block (#251, iOS + Android) and scrub the FFI-boundary password `Data` copy on iOS (#229), without any Rust-core / on-disk-format / spec change.

**Architecture:** Replace the unbounded `openBlocks: [BlockReadOutput]` accumulator in each platform's `UniffiVaultSession` with a single retained `currentBlock: BlockReadOutput?`, wiping the prior block on each successful `readBlock`. Add a small `withZeroizingData` helper in iOS `SecretaryKit` and apply it at the five password/phrase FFI sites.

**Tech Stack:** Swift (XCTest, Foundation `Data`), Kotlin (AndroidJUnit4 instrumented tests, kotlinx-coroutines), uniffi-generated `BlockReadOutput`/`Record`/`FieldHandle` handles.

## Global Constraints

- No new `FfiVaultError` / `VaultError` variant; no change to observable bytes or merge semantics → `conformance.py`, conformance KATs, and the Swift/Kotlin conformance harnesses must stay untouched and green.
- Preserve the "blocks → manifest → identity" wipe order in `wipe()` on both platforms.
- Preserve Android's existing `sessionLock` serialization + `wiped`-race guard from #250 — the new eviction goes **inside** the lock, after the `wiped` check.
- Decrypt-first ordering is load-bearing: evict the prior block only **after** the new block decrypts successfully (a thrown decrypt must leave the on-screen block retained).
- No magic numbers; doc-comment every new symbol; one concept per file. Reuse the existing golden-vault test harness (`goldenPassword = "correct horse battery staple"`, the published KAT password — not a real secret, so not zeroized).
- The golden vault (`golden_vault_001`) has exactly **one** block, so the #251 teeth test reads that block **twice** — proving eviction and re-selection dedup in one shot.

---

### Task 1: #251 — bound iOS `UniffiVaultSession` to the on-screen block

**Files:**
- Modify: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSession.swift` (field at :14, append at :56, `wipe()` at :116-121)
- Test: `ios/SecretaryKit/Tests/SecretaryKitTests/RevealResidencyIntegrationTests.swift` (create)

**Interfaces:**
- Consumes: `UniffiVaultOpenPort().openWithPassword(vaultPath:password:) async throws -> VaultSession`; `VaultSession.blockSummaries() -> [BlockSummary]` (`.uuid`); `VaultSession.readBlock(blockUuid:includeDeleted:) throws -> [RecordView]`; `RecordView.fields: [FieldView]`; `FieldView.reveal: () throws -> RevealedValue`.
- Produces: no new public API — behavior change only (`openBlocks` list → `currentBlock` optional).

- [ ] **Step 1: Write the failing test**

Create `ios/SecretaryKit/Tests/SecretaryKitTests/RevealResidencyIntegrationTests.swift`. Mirror the temp-copy fixture setup from `VaultAccessIntegrationTests.swift` (copy `golden_vault_001` from `Bundle.module` to a temp dir in `setUp`, remove in `tearDown`).

```swift
import XCTest
import SecretaryVaultAccess
@testable import SecretaryKit

/// #251: navigating to another block must evict the prior block's decrypted
/// plaintext (a stale reveal closure must stop yielding plaintext), and
/// re-selecting the same block must not accumulate. Reads the single golden
/// block twice — proves eviction + dedup together.
final class RevealResidencyIntegrationTests: XCTestCase {
    private let goldenPassword = "correct horse battery staple"
    private var vaultCopy: URL!

    override func setUpWithError() throws {
        let bundled = try XCTUnwrap(
            Bundle.module.url(forResource: "golden_vault_001", withExtension: nil),
            "golden_vault_001 not bundled — run ios/scripts/build-xcframework.sh")
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("res-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        vaultCopy = tmp.appendingPathComponent("golden_vault_001", isDirectory: true)
        try FileManager.default.copyItem(at: bundled, to: vaultCopy)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: vaultCopy.deletingLastPathComponent())
    }

    func testNavigatingAwayEvictsPriorBlockPlaintext() async throws {
        let port = UniffiVaultOpenPort()
        let path = Data(vaultCopy.path.utf8)
        let session = try await port.openWithPassword(
            vaultPath: path, password: [UInt8](goldenPassword.utf8))
        defer { session.wipe() }

        let blocks = session.blockSummaries()
        let blockUuid = try XCTUnwrap(blocks.first?.uuid, "golden vault has one block")

        // First read: capture a reveal closure from this block's first revealable field.
        let firstRecords = try session.readBlock(blockUuid: blockUuid, includeDeleted: false)
        let staleField = try XCTUnwrap(
            firstRecords.flatMap(\.fields).first, "block has at least one field")
        _ = try staleField.reveal()  // sanity: reveals before we navigate away

        // Navigate (re-read the same block — the only one). The fix wipes the prior
        // BlockReadOutput, which cascades to the captured FieldHandle.
        _ = try session.readBlock(blockUuid: blockUuid, includeDeleted: false)

        // Pre-fix: the prior block stays in `openBlocks`, so this still yields plaintext.
        // Post-fix: the prior block was wiped, so reveal() throws.
        XCTAssertThrowsError(try staleField.reveal(),
            "stale reveal closure must fail after navigating away (block evicted)")
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `bash ios/scripts/run-ios-tests.sh` (or the script's documented filter for `RevealResidencyIntegrationTests`).
Expected: FAIL — `testNavigatingAwayEvictsPriorBlockPlaintext` does not throw (pre-fix the prior block is still retained and reveals plaintext).

- [ ] **Step 3: Implement the single-block bound**

In `UniffiVaultSession.swift`, replace the accumulator field (line ~13-14):

```swift
    /// The single retained decrypted block — the on-screen one. Bounding to one
    /// block (not a growing list) makes "≤1 block resident" a type-level invariant
    /// and dedups re-selection. The VM clears the reveal map on `selectBlock`, so no
    /// live reveal closure references a prior block when we evict it here (#251).
    private var currentBlock: BlockReadOutput?
```

In `readBlock`, replace `openBlocks.append(out)` (line ~56) with eviction-after-decrypt:

```swift
        // Decrypt-first ordering: `out` is already decoded above, so a thrown read
        // left the prior block retained. Now evict it before retaining the new one.
        currentBlock?.wipe()
        currentBlock = out  // keep alive for reveal closures + wipe
```

Replace `wipe()` (lines ~116-121):

```swift
    public func wipe() {
        currentBlock?.wipe()
        currentBlock = nil
        manifest.wipe()
        identity.wipe()
    }
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `bash ios/scripts/run-ios-tests.sh`
Expected: PASS — `RevealResidencyIntegrationTests` green; existing `VaultAccessIntegrationTests` / `BlockCrudRoundTripIntegrationTests` / `RecordEditIntegrationTests` still green (the on-screen block is always retained, so reveal-on-tap and the write paths are unaffected).

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSession.swift \
        ios/SecretaryKit/Tests/SecretaryKitTests/RevealResidencyIntegrationTests.swift
git commit -m "fix(ios): bound reveal-residency to the on-screen block (#251)"
```

---

### Task 2: #251 — bound Android `UniffiVaultSession` to the on-screen block

**Files:**
- Modify: `android/kit/src/main/kotlin/org/secretary/browse/UniffiVaultOpenPort.kt` (field + doc-comment at :104-108, append at :128, `wipe()` at :245-257)
- Test: `android/kit/src/androidTest/kotlin/org/secretary/browse/RevealResidencyInstrumentedTest.kt` (create)

**Interfaces:**
- Consumes: `uniffiVaultOpenPort(): VaultOpenPort`; `VaultOpenPort.openWithPassword(vaultFolder:String, password:ByteArray): VaultSession` (suspend); `VaultSession.blockSummaries(): List<BlockSummaryView>` (`.uuid: ByteArray`); `VaultSession.readBlock(blockUuid:ByteArray, includeDeleted:Boolean): List<RecordSummaryView>` (suspend); `RecordSummaryView.fields: List<RevealableField>`; `RevealableField.reveal: () -> RevealedValue` (throws `VaultBrowseError.CorruptVault`). Uses `GoldenVaultStaging.stageWritableVault(context)` from `org.secretary.sync`.
- Produces: no new public API — behavior change only.

- [ ] **Step 1: Write the failing test**

Create `android/kit/src/androidTest/kotlin/org/secretary/browse/RevealResidencyInstrumentedTest.kt`. (`GoldenVaultStaging` lives in package `org.secretary.sync` — import it.)

```kotlin
package org.secretary.browse

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.secretary.sync.GoldenVaultStaging
import java.io.File

/**
 * #251 (Android parity): navigating to another block must evict the prior block's decrypted
 * plaintext — a stale reveal closure must stop yielding plaintext. Reads the single golden
 * block twice (eviction + re-selection dedup in one). Real native FFI: host tests cannot
 * exercise the uniffi handle cascade.
 */
@RunWith(AndroidJUnit4::class)
class RevealResidencyInstrumentedTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val goldenPassword = "correct horse battery staple".toByteArray()
    private val toClean = mutableListOf<File>()

    @After fun cleanup() = toClean.forEach { it.deleteRecursively() }

    private fun stageVault(): File =
        GoldenVaultStaging.stageWritableVault(context).also { toClean += it.parentFile!! }

    @Test
    fun navigatingAwayEvictsPriorBlockPlaintext() = runBlocking {
        val vault = stageVault()
        val session = uniffiVaultOpenPort().openWithPassword(vault.path, goldenPassword)
        try {
            val blockUuid = session.blockSummaries().first().uuid

            // First read: capture a reveal closure from this block's first field.
            val firstRecords = session.readBlock(blockUuid, false)
            val staleField = firstRecords.flatMap { it.fields }.first()
            staleField.reveal()  // sanity: reveals before navigating away

            // Navigate (re-read the only block). The fix wipes the prior BlockReadOutput,
            // cascading to the captured FieldHandle.
            session.readBlock(blockUuid, false)

            // Pre-fix: prior block still in openBlocks → still reveals. Post-fix: throws.
            assertThrows(VaultBrowseError.CorruptVault::class.java) { staleField.reveal() }
        } finally {
            session.wipe()
        }
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run (emulator/device connected; `--tests` is rejected for instrumented runs — use the runner-arg class filter):
```bash
cd android && ./gradlew :kit:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.browse.RevealResidencyInstrumentedTest
```
Expected: FAIL — `staleField.reveal()` returns a value instead of throwing (pre-fix accumulation).

- [ ] **Step 3: Implement the single-block bound**

In `UniffiVaultOpenPort.kt`, replace the `openBlocks` field + its stale-tradeoff doc-comment (lines ~104-108):

```kotlin
    /** The single retained decrypted block — the on-screen one. Bounding to one block (not a
     *  growing list) makes "≤1 block resident" a type-level invariant and dedups re-selection.
     *  The VM clears the reveal map on selectBlock, so no live reveal closure references a prior
     *  block when we evict it here. Mirror of iOS UniffiVaultSession.currentBlock (#251). */
    private var currentBlock: BlockReadOutput? = null
```

In `readBlock`, replace `openBlocks += block` (line ~128) with eviction-after-decrypt (still inside `synchronized(sessionLock)`, after the `wiped` check):

```kotlin
                    // Decrypt-first ordering: `block` is decoded above; a thrown read left the
                    // prior block retained. Evict it before retaining the new one (NO .use{} —
                    // reveal closures depend on currentBlock until wipe()).
                    currentBlock?.wipe()
                    currentBlock = block
```

Replace the `openBlocks` lines in `wipe()` (lines ~252-253):

```kotlin
            currentBlock?.wipe()
            currentBlock = null
```

- [ ] **Step 4: Run the test to verify it passes**

Run:
```bash
cd android && ./gradlew :kit:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.browse.RevealResidencyInstrumentedTest
```
Expected: PASS. Then run the host unit tests to confirm no regression in the mapping/model layer:
```bash
cd android && ./gradlew :kit:testDebugUnitTest :vault-access:test
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add android/kit/src/main/kotlin/org/secretary/browse/UniffiVaultOpenPort.kt \
        android/kit/src/androidTest/kotlin/org/secretary/browse/RevealResidencyInstrumentedTest.kt
git commit -m "fix(android): bound reveal-residency to the on-screen block (#251)"
```

---

### Task 3: #229 — scrub the FFI-boundary password `Data` copy on iOS

**Files:**
- Create: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/ZeroizingData.swift`
- Test: `ios/SecretaryKit/Tests/SecretaryKitTests/ZeroizingDataTests.swift` (create)
- Modify: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultOpenPort.swift` (sites at :14, :26)
- Modify: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultCreatePort.swift` (the `createVaultInFolder` `Data(password)` site)
- Modify: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSyncPort.swift` (sites in `sync` :29 and `commitDecisions` :46)

**Interfaces:**
- Produces: `func zeroize(_ data: inout Data)`; `func withZeroizingData<T>(_ bytes: [UInt8], _ body: (Data) throws -> T) rethrows -> T`. Both internal to `SecretaryKit`.
- Consumes: existing FFI fns `openVaultWithPassword`/`openVaultWithRecovery`/`createVaultInFolder`/`syncVault`/`commitSyncDecisions` (whatever the current names are — only the `password:`/`mnemonic:` `Data` argument changes from `Data(x)` to the helper's `pw`).

- [ ] **Step 1: Write the failing test**

Create `ios/SecretaryKit/Tests/SecretaryKitTests/ZeroizingDataTests.swift`:

```swift
import XCTest
import Foundation
@testable import SecretaryKit

/// #229: the FFI-boundary password copy must be scrubbed after use.
final class ZeroizingDataTests: XCTestCase {
    func testZeroizeOverwritesAllBytes() {
        var d = Data([1, 2, 3, 4, 5])
        zeroize(&d)
        XCTAssertEqual(d, Data(repeating: 0, count: 5))
    }

    func testZeroizeEmptyDataIsNoOp() {
        var d = Data()
        zeroize(&d)  // must not crash on a zero-length range
        XCTAssertEqual(d.count, 0)
    }

    func testWithZeroizingDataExposesBytesToBody() {
        let bytes: [UInt8] = [9, 8, 7]
        let seen = withZeroizingData(bytes) { d in [UInt8](d) }
        XCTAssertEqual(seen, [9, 8, 7])
    }

    func testWithZeroizingDataReturnsBodyResult() {
        let n = withZeroizingData([1, 2, 3]) { d in d.count }
        XCTAssertEqual(n, 3)
    }

    func testWithZeroizingDataPropagatesThrow() {
        struct Boom: Error {}
        // The defer-scrub still runs on the throwing path; we assert the error propagates
        // (the scrub itself is proven by testZeroizeOverwritesAllBytes — same code path).
        XCTAssertThrowsError(try withZeroizingData([1, 2, 3]) { _ in throw Boom() })
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `bash ios/scripts/run-ios-tests.sh`
Expected: FAIL to compile — `zeroize` / `withZeroizingData` are undefined.

- [ ] **Step 3: Implement the helper**

Create `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/ZeroizingData.swift`:

```swift
import Foundation

/// Overwrite every byte of `data` in place. Pure; post-condition: all bytes are
/// zero. Mirrors the Rust core's `Sensitive<T>`/`SecretBytes` discipline at the
/// one heap copy the Swift FFI boundary owns. No-op on empty data (#229).
func zeroize(_ data: inout Data) {
    guard !data.isEmpty else { return }
    data.resetBytes(in: 0..<data.count)
}

/// Build a `Data` from `bytes`, hand it to `body`, and scrub that `Data` on the
/// way out — the `defer` fires on both a normal return and a thrown error, so the
/// FFI-boundary copy never lingers in the heap.
///
/// Scope/limitation: this scrubs the adapter-owned `Data` copy only. It does NOT
/// scrub the caller's `bytes` array — Swift arrays are copy-on-write, so mutating
/// our binding would allocate a throwaway buffer and leave the caller's storage
/// intact. The caller's lifetime is minimized separately by the "password passed
/// per call, never stored" port discipline (#229).
func withZeroizingData<T>(_ bytes: [UInt8], _ body: (Data) throws -> T) rethrows -> T {
    var data = Data(bytes)
    defer { zeroize(&data) }
    return try body(data)
}
```

- [ ] **Step 4: Run the helper tests to verify they pass**

Run: `bash ios/scripts/run-ios-tests.sh`
Expected: PASS — `ZeroizingDataTests` green.

- [ ] **Step 5: Apply the helper at all five FFI sites**

`UniffiVaultOpenPort.swift` — `openWithPassword` (replace lines ~13-14):

```swift
                let out = try withZeroizingData(password) { pw in
                    try SecretaryKit.openVaultWithPassword(folderPath: vaultPath, password: pw)
                }
```

`openWithRecovery` (replace lines ~25-26):

```swift
                let out = try withZeroizingData(phrase) { ph in
                    try SecretaryKit.openVaultWithRecovery(folderPath: vaultPath, mnemonic: ph)
                }
```

`UniffiVaultCreatePort.swift` — wrap the `createVaultInFolder` call so the `Data(password)` becomes the helper's `pw` (keep the surrounding `do/catch` mapping `VaultError`):

```swift
            let mnem: MnemonicOutput
            do {
                mnem = try withZeroizingData(password) { pw in
                    try SecretaryKit.createVaultInFolder(
                        folderPath: Data(folder.path.utf8),
                        password: pw,
                        displayName: displayName,
                        createdAtMs: UInt64(Date().timeIntervalSince1970 * 1000))
                }
            } catch let e as VaultError {
                throw mapProvisioningError(e)
            }
```

`UniffiVaultSyncPort.swift` — `sync` (the `password: Data(password)` argument, ~line 29):

```swift
                let dto = try withZeroizingData(password) { pw in
                    try SecretaryKit.syncVault(
                        stateDir: stateDir, vaultFolder: vaultFolder,
                        password: pw, nowMs: nowMs)
                }
```

`commitDecisions` (the `password: Data(password)` argument, ~line 46):

```swift
                let dto = try withZeroizingData(password) { pw in
                    try SecretaryKit.commitSyncDecisions(
                        stateDir: stateDir, vaultFolder: vaultFolder, password: pw,
                        decisions: dtoDecisions, manifestHash: Data(manifestHash), nowMs: nowMs)
                }
```

(Use the actual current FFI function names + argument labels found in each file — only the password/mnemonic `Data(...)` argument changes to `pw`/`ph`. Leave non-secret `Data(...)` conversions like `manifestHash` as-is.)

- [ ] **Step 6: Run the full iOS suite to verify no regression**

Run: `bash ios/scripts/run-ios-tests.sh`
Expected: PASS — the existing open/create/sync integration tests (`VaultAccessIntegrationTests`, `UniffiVaultCreatePortTests`, `UniffiVaultSyncPortOffMainActorTests`) still pass; the password path is unchanged except the boundary copy is now scrubbed after the FFI call consumes it.

- [ ] **Step 7: Commit**

```bash
git add ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/ZeroizingData.swift \
        ios/SecretaryKit/Tests/SecretaryKitTests/ZeroizingDataTests.swift \
        ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultOpenPort.swift \
        ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultCreatePort.swift \
        ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSyncPort.swift
git commit -m "fix(ios): scrub FFI-boundary password Data copy via withZeroizingData (#229)"
```

---

## Self-Review

**Spec coverage:**
- #251 iOS reveal-residency bound → Task 1. ✅
- #251 Android reveal-residency bound + stale doc-comment update → Task 2. ✅
- #251 dedup of re-selection → covered by both teeth tests (read same block twice) + the single-optional invariant. ✅
- #229 `zeroize` + `withZeroizingData` helper + 5 sites + documented CoW residual → Task 3. ✅
- #229 unit tests (zeroize post-condition, throw propagation) → Task 3 Step 1. ✅
- Out-of-scope Android `#229` analogue (no second buffer copy) → no task needed; will note in PR/handoff after verifying `UniffiVaultOpenPort.kt:47` forwards the `ByteArray` directly. ✅

**Placeholder scan:** No TBD/TODO; every code step shows full code. The only deferred specifics are the exact current FFI function names/labels in Task 3 Step 5, explicitly flagged to read from each file (they are mechanical 1-arg substitutions). ✅

**Type consistency:** `currentBlock: BlockReadOutput?` named identically in Tasks 1 & 2; `zeroize(_:inout Data)` / `withZeroizingData(_:_:)` signatures identical between the test (Step 1), the impl (Step 3), and the call sites (Step 5). ✅

## Verification gate (whole branch, before PR)

After all three tasks:
- iOS: `bash ios/scripts/run-ios-tests.sh` (host XCTest — runs on this machine).
- Android: `cd android && ./gradlew :kit:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.browse.RevealResidencyInstrumentedTest` + `./gradlew :kit:testDebugUnitTest :vault-access:test` (emulator/device for the instrumented test).
- Rust unchanged, but run `cargo test --release --workspace` + `cargo clippy --release --workspace --tests -- -D warnings` + `uv run core/tests/python/conformance.py` to prove no incidental drift (conformance must be byte-identical PASS).
- CI is the real gate once pushed (`test.yml` rust ×2 OS + swift/kotlin conformance + smoke; `rust-lint.yml`; CodeQL).
