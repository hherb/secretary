# #467 — Fail-Closed Guard on `privacy: .public` Error Logging — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make "no secret reaches a `privacy: .public` log line" a structural, fail-closed property of the Swift tree instead of a doc-comment convention.

**Architecture:** A `SecretFreeError` protocol with a defaulted `diagnosticDescription` is the allowlist; a free function `diagnosticDetail(_:)` is the only sanctioned renderer and default-denies any type that has not been reviewed and conformed. All nine `.public` sinks route through it, and a grep-level CI check forces new sites to do the same.

**Tech Stack:** Swift 6 (language mode 6, strict concurrency), swift-tools-version 6.0, XCTest, bash + GitHub Actions.

## Global Constraints

- **Working directory is the worktree.** Every Bash call spells out `cd /Users/hherb/src/secretary/.worktrees/467-public-log-secret-free-guard && …`. Session cwd persists across calls *and can reset without warning*. Edit-tool paths must spell out `.worktrees/467-public-log-secret-free-guard/…` or they hit the main checkout.
- **Branch:** `feature/467-public-log-secret-free-guard`. Spec commit `9882b37` is already on it.
- **Baseline to preserve:** `swift test` in `ios/SecretaryVaultAccess` = **344 tests, 0 failures**. Every task re-runs it.
- **No `core/` or `ffi/` change.** No on-disk-format change, no FFI signature change. `git diff main... --name-only -- core/ ffi/` must stay empty.
- **No user-facing copy change.** `#454`'s anti-oracle copy and `VaultAccessError.errorDescription` are untouched.
- **Never widen a `.public` interpolation.** The only permitted rendering of an `Error` into one is `diagnosticDetail(error)`.
- **The xcframework is already built** in this worktree (`ios/Secretary.xcframework`, `ios/SecretaryKit/Sources/SecretaryKit/secretary.swift`, `ios/SecretaryKit/Tests/SecretaryKitTests/Resources/` all present). Do not rebuild it unless a task says to.
- **Secret sentinels in tests are literals in TEST code only.** They are not crypto values, so [[feedback_test_crypto_random_not_hardcoded]] does not apply — these are deliberately fixed strings so an assertion can prove their absence.

---

## Deviation from the spec — read before Task 5

The spec's §5 describes `ios/scripts/check-public-log-hygiene.sh` with "an explicit allowlist file for recorded exceptions". **This plan drops the allowlist file.**

Reason: after Tasks 1–4 there are **zero** forbidden lines, and the one site we deliberately chose not to gate (`BookmarkVaultLocationStore:64`, which logs `location.displayName`) contains neither `String(describing:` nor `localizedDescription`, so it cannot be an allowlist entry. The file would ship empty with no possible entry — dead machinery.

The decision it was meant to record is written down instead in two places that a reader actually encounters: a comment at the `displayName` call site (Task 4) and the script's header (Task 5).

If you disagree, add the allowlist in Task 5; nothing else in the plan depends on the choice.

---

## File Structure

**Create:**

| Path | Responsibility |
|---|---|
| `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/SecretFreeError.swift` | The protocol, the `diagnosticDetail` renderer, and the five in-package conformances. ~90 lines incl. docs. |
| `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/SecretFreeErrorTests.swift` | Tests 1–5. |
| `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/SecretFreeErrorConformances.swift` | The one cross-package conformance (`DeviceUnlockError`). |
| `ios/SecretaryKit/Tests/SecretaryKitTests/SecretFreeErrorConformanceTests.swift` | Test 8. |
| `ios/scripts/check-public-log-hygiene.sh` | The grep-level guard + two-sided `--self-test`. |

**Modify:**

| Path | Change |
|---|---|
| `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/DiagnosticLog.swift` | `logFoldedError` → `foldDiagnostic`; formatter gains the gate. |
| `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/DiagnosticLogTests.swift` | Test 6. |
| 9 view models in `Sources/SecretaryVaultAccessUI/` | 23 fold sites, two lines → one. |
| `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultSelectionViewModelTests.swift` | Test 7. |
| `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/BookmarkVaultLocationStore.swift` | 1 error site gated; 1 `displayName` site commented. |
| `ios/SecretaryApp/Sources/SecretaryApp.swift` | 5 error sites gated. |
| `ios/SecretaryMacApp/Sources/MacUnlockView.swift` | 1 error site gated. |
| `.github/workflows/test.yml` | New `swift-log-hygiene` job. |
| `ROADMAP.md` | Assessed in Task 6. |

---

## Task 1: The policy — `SecretFreeError` + `diagnosticDetail`

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/SecretFreeError.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/SecretFreeErrorTests.swift`

**Interfaces:**
- Consumes: nothing (lowest layer).
- Produces:
  - `public protocol SecretFreeError: Error { var diagnosticDescription: String { get } }`
  - `public extension SecretFreeError { var diagnosticDescription: String }` — defaults to `String(describing: self)`
  - `public func diagnosticDetail(_ error: Error) -> String`
  - conformances: `VaultAccessError`, `VaultSyncError`, `VaultSelectionError`, `DeviceUuidStoreError`, `CancellationError`

- [ ] **Step 1: Write the failing tests**

Create `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/SecretFreeErrorTests.swift`:

```swift
import XCTest
@testable import SecretaryVaultAccess

/// Conforming, wholly safe: its `String(describing:)` is a known sentinel so the
/// DEFAULT rendering can be asserted byte-exactly.
private struct SafeSentinel: SecretFreeError, CustomStringConvertible {
    let description: String
}

/// Conforming but REDACTING at source: `String(describing:)` would expose the
/// secret; `diagnosticDescription` must not. This is the case that distinguishes
/// a rendering protocol from a bare marker.
private struct PartiallySafe: SecretFreeError, CustomStringConvertible {
    let secret: String
    var description: String { "PartiallySafe(secret: \(secret))" }
    var diagnosticDescription: String { "PartiallySafe(secret: <redacted>)" }
}

/// NON-conforming and secret-bearing — the exact case #467 exists to stop.
private struct UnreviewedSecretBearing: Error, CustomStringConvertible {
    let secret: String
    var description: String { "UnreviewedSecretBearing(secret: \(secret))" }
}

final class SecretFreeErrorTests: XCTestCase {
    /// A conformer with no override renders its full Swift description.
    func testConformerRendersFullDescriptionByDefault() {
        XCTAssertEqual(diagnosticDetail(SafeSentinel(description: "SAFE-7C1D")), "SAFE-7C1D")
    }

    /// SECURITY (#467): an explicit `diagnosticDescription` WINS over
    /// `String(describing:)`. Without this, sanitize-at-source would be
    /// decorative and the protocol would be a bare marker.
    func testCustomDiagnosticDescriptionWinsOverDescription() {
        let e = PartiallySafe(secret: "SECRET-4B2E")
        XCTAssertEqual(diagnosticDetail(e), "PartiallySafe(secret: <redacted>)")
        XCTAssertFalse(diagnosticDetail(e).contains("SECRET-4B2E"))
    }

    /// SECURITY (#467): the core leak assertion. An unreviewed type is NEVER
    /// described, so a future secret-bearing error cannot reach a `.public` line.
    func testUnreviewedErrorIsNeverDescribed() {
        let out = diagnosticDetail(UnreviewedSecretBearing(secret: "SECRET-9A03"))
        XCTAssertFalse(out.contains("SECRET-9A03"))
        XCTAssertTrue(out.hasPrefix("<undisclosed UnreviewedSecretBearing "),
                      "expected the default-deny marker, got: \(out)")
    }

    /// SECURITY (#467): `userInfo` is never read — it is the only part of an
    /// `NSError` that can carry arbitrary caller-supplied content. `domain` and
    /// `code` ARE emitted so the marker stays actionable.
    func testNSErrorUserInfoIsNotRendered() {
        let e = NSError(domain: "TestDomain", code: 42,
                        userInfo: ["leak": "SECRET-USERINFO-11B7"])
        let out = diagnosticDetail(e)
        XCTAssertFalse(out.contains("SECRET-USERINFO-11B7"))
        XCTAssertTrue(out.contains("domain=TestDomain"))
        XCTAssertTrue(out.contains("code=42"))
    }

    /// The five in-package conformances. A conformance silently removed would
    /// degrade every log line for that type to `<undisclosed …>` — safe, but a
    /// diagnostic regression nobody would notice without this test.
    func testInPackageConformancesHold() {
        XCTAssertTrue(VaultAccessError.other("x") is SecretFreeError)
        XCTAssertTrue(VaultSyncError.inProgress is SecretFreeError)
        XCTAssertTrue(VaultSelectionError.noVaultSelected is SecretFreeError)
        XCTAssertTrue(DeviceUuidStoreError.corruptLength(3) is SecretFreeError)
        XCTAssertTrue(CancellationError() is SecretFreeError)
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd /Users/hherb/src/secretary/.worktrees/467-public-log-secret-free-guard/ios/SecretaryVaultAccess && swift test --filter SecretFreeErrorTests
```

Expected: **compile failure** — `cannot find type 'SecretFreeError' in scope`, `cannot find 'diagnosticDetail' in scope`.

- [ ] **Step 3: Write the implementation**

Create `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/SecretFreeError.swift`:

```swift
import Foundation

/// A claim, made at the conformance site, that this error type's diagnostic text
/// carries NO secret — no vault plaintext, password, mnemonic, or key bytes — and
/// is therefore safe to emit at `os.Logger`'s `privacy: .public` (#467).
///
/// `privacy: .public` disables the unified log's default redaction so a diagnostic
/// survives into a sysdiagnose (#456). That is sound only while every error able
/// to reach such a site is secret-free. Before #467 that was maintained by a doc
/// comment; this protocol makes it structural and FAIL-CLOSED — an error type that
/// does not conform is never described (see `diagnosticDetail`).
///
/// Conforming is a SECURITY DECISION, reviewed like any other. Two forms:
///
///     // wholly secret-free — take the default rendering
///     extension DeviceUuidStoreError: SecretFreeError {}
///
///     // secret-free EXCEPT one case — redact AT SOURCE
///     extension FieldDecodeError: SecretFreeError {
///         public var diagnosticDescription: String {
///             switch self {
///             case .badUTF8: return "badUTF8"
///             case .value:   return "value(<redacted>)"
///             }
///         }
///     }
///
/// The second form is what makes this a rendering protocol rather than a bare
/// marker: a type safe in nine cases and secret-bearing in one keeps the nine
/// instead of being excluded wholesale.
public protocol SecretFreeError: Error {
    /// Secret-free one-line diagnostic text for this error.
    var diagnosticDescription: String { get }
}

public extension SecretFreeError {
    /// Default: the full Swift description, associated values included.
    /// Override whenever any case can carry a secret.
    var diagnosticDescription: String { String(describing: self) }
}

/// Render `error` for a `privacy: .public` log line. This is the ONLY sanctioned
/// way to do so — enforced by `ios/scripts/check-public-log-hygiene.sh`.
///
/// DEFAULT-DENY: a type that has not been reviewed and conformed to
/// `SecretFreeError` is never described. It degrades to a marker naming the type
/// plus the bridged `NSError` domain and code — enough to identify WHICH case
/// fired, and enough to tell a developer exactly which type to review and conform.
///
/// `userInfo` is deliberately NOT read: it is the only part of an `NSError` that
/// can carry arbitrary caller-supplied content.
///
/// The `NSError` bridge also closes a real trap. A Foundation file error arrives
/// in a `catch` with dynamic type `NSError`, so `error as? SecretFreeError` FAILS
/// even when `CocoaError` conforms — without this branch every real file error
/// would render as an opaque marker. Conforming `NSError` itself would also work
/// but hands a blanket allow to every bridged error; domain+code keeps the
/// diagnostic value without the blanket.
public func diagnosticDetail(_ error: Error) -> String {
    if let safe = error as? SecretFreeError { return safe.diagnosticDescription }
    let ns = error as NSError
    return "<undisclosed \(type(of: error)) domain=\(ns.domain) code=\(ns.code)>"
}

// MARK: - Reviewed conformances (this package)
//
// Each line below is a reviewed claim that the type's `String(describing:)`
// carries no secret. Adding one is a security decision — see `SecretFreeError`.
// No `@retroactive` is needed even for the stdlib type: the warning fires only
// when the declaring module owns NEITHER the type NOR the protocol, and the
// protocol is ours.

/// Paths, uuids, and short reason labels; never a credential. The three folded
/// "…OrCorrupt" cases carry nothing at all.
extension VaultAccessError: SecretFreeError {}

/// Sync-pass failures: lock state, state-decode reasons, FFI shape errors.
extension VaultSyncError: SecretFreeError {}

/// Selection failures: a bookmark-resolution reason string. No credential.
extension VaultSelectionError: SecretFreeError {}

/// An `OSStatus` or a byte length. The device UUID is a PUBLIC per-device
/// fingerprint (see `DeviceUuidStore`), not key material.
extension DeviceUuidStoreError: SecretFreeError {}

/// Stdlib cancellation sentinel — no payload at all.
extension CancellationError: SecretFreeError {}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd /Users/hherb/src/secretary/.worktrees/467-public-log-secret-free-guard/ios/SecretaryVaultAccess && swift test --filter SecretFreeErrorTests && swift test 2>&1 | tail -5
```

Expected: 5 filtered tests PASS; full run **349 tests, 0 failures** (344 baseline + 5).

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/467-public-log-secret-free-guard && \
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/SecretFreeError.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/SecretFreeErrorTests.swift && \
git commit -m "feat(#467): SecretFreeError protocol + default-deny diagnosticDetail

The allowlist for \`privacy: .public\` error rendering. An unreviewed type is
never described; it degrades to a marker with the bridged NSError domain/code,
which identifies the case without reading userInfo.

The NSError branch is not a nicety: a Foundation file error arrives in a catch
with dynamic type NSError, so \`as? SecretFreeError\` fails even when CocoaError
conforms. Without it every real file error would render opaque.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: The fold-site helper — `foldDiagnostic`

**Files:**
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/DiagnosticLog.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/DiagnosticLogTests.swift`

**Interfaces:**
- Consumes: `diagnosticDetail(_:)` from Task 1.
- Produces:
  - `func foldedErrorDiagnostic(underlying: Error, fileID: StaticString, function: StaticString, line: UInt) -> String` (unchanged signature, gated body)
  - `@discardableResult func foldDiagnostic(_ error: Error, fileID: StaticString = #fileID, function: StaticString = #function, line: UInt = #line) -> String`
  - `logFoldedError` is **removed** — Task 3 migrates its 23 callers.

- [ ] **Step 1: Write the failing tests**

Replace the whole body of `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/DiagnosticLogTests.swift`:

```swift
import XCTest
import SecretaryVaultAccess
@testable import SecretaryVaultAccessUI

/// A CONFORMING error whose `String(describing:)` is an exact sentinel — so the
/// formatter's output can be asserted byte-for-byte (proving no other content,
/// e.g. `.localizedDescription`, leaks into the logged line).
private struct SentinelError: SecretFreeError, CustomStringConvertible {
    let description: String
}

/// A NON-conforming, secret-bearing error — proves the fold seam inherits the
/// default-deny policy rather than re-implementing its own rendering.
private struct UnreviewedSecretBearing: Error, CustomStringConvertible {
    let secret: String
    var description: String { "UnreviewedSecretBearing(secret: \(secret))" }
}

final class DiagnosticLogTests: XCTestCase {
    func testDiagnosticIncludesUnderlyingDescription() {
        let out = foldedErrorDiagnostic(
            underlying: SentinelError(description: "UNDERLYING-BOOM"),
            fileID: "F.swift", function: "f()", line: 1
        )
        XCTAssertTrue(out.contains("UNDERLYING-BOOM"))
    }

    func testDiagnosticIncludesSite() {
        let out = foldedErrorDiagnostic(
            underlying: SentinelError(description: "x"),
            fileID: "Foo.swift", function: "bar()", line: 99
        )
        XCTAssertTrue(out.contains("Foo.swift"))
        XCTAssertTrue(out.contains("99"))
        XCTAssertTrue(out.contains("bar()"))
    }

    /// SECURITY (#456): the formatted line contains ONLY the site identifiers and
    /// the gated detail — nothing else. Byte-exact equality is the enforcement
    /// that the logged content stays diagnostic-only.
    func testDiagnosticIsSiteAndDetailOnly() {
        let out = foldedErrorDiagnostic(
            underlying: SentinelError(description: "DIAG-SENTINEL-9F3A"),
            fileID: "MyFile.swift", function: "myFunc()", line: 42
        )
        XCTAssertEqual(out, "[MyFile.swift:42 myFunc()] DIAG-SENTINEL-9F3A")
    }

    /// SECURITY (#467): the formatter renders through `diagnosticDetail`, so an
    /// unreviewed type is not described here either. The seam does NOT get its
    /// own rendering policy.
    func testFormatterAppliesDefaultDeny() {
        let out = foldedErrorDiagnostic(
            underlying: UnreviewedSecretBearing(secret: "SECRET-2D77"),
            fileID: "F.swift", function: "f()", line: 7
        )
        XCTAssertFalse(out.contains("SECRET-2D77"))
        XCTAssertTrue(out.contains("<undisclosed UnreviewedSecretBearing "))
    }

    /// SECURITY (#467): `foldDiagnostic` returns the SAME gated string it logs,
    /// which is what makes the log line and the carried payload unable to
    /// disagree at a fold site.
    func testFoldDiagnosticReturnsTheGatedDetail() {
        let returned = foldDiagnostic(UnreviewedSecretBearing(secret: "SECRET-5E19"))
        XCTAssertFalse(returned.contains("SECRET-5E19"))
        XCTAssertTrue(returned.contains("<undisclosed UnreviewedSecretBearing "))
    }

    /// A conformer round-trips its description through `foldDiagnostic` unchanged
    /// (the site prefix is on the LOG line, not on the returned payload).
    func testFoldDiagnosticReturnsDescriptionForConformer() {
        XCTAssertEqual(foldDiagnostic(SentinelError(description: "OK-1B4C")), "OK-1B4C")
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd /Users/hherb/src/secretary/.worktrees/467-public-log-secret-free-guard/ios/SecretaryVaultAccess && swift test --filter DiagnosticLogTests
```

Expected: **compile failure** — `cannot find 'foldDiagnostic' in scope`.

- [ ] **Step 3: Write the implementation**

Replace lines 21–70 of `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/DiagnosticLog.swift` (everything from the `foldedErrorDiagnostic` doc comment to end of file) with:

```swift
/// Build the one-line diagnostic string logged at a fold site.
///
/// Shape: `"[<fileID>:<line> <function>] <diagnosticDetail(underlying)>"`.
///
/// The ONLY dynamic component is `diagnosticDetail(underlying)`; the site
/// identifiers are compile-time `StaticString` / `UInt`. Keeping this a pure
/// function makes the "what content is emitted" decision host-testable in
/// isolation, which is what proves the logged content stays diagnostic-only — no
/// `.localizedDescription` or other interpolation can slip in (see
/// `DiagnosticLogTests`).
func foldedErrorDiagnostic(
    underlying: Error,
    fileID: StaticString,
    function: StaticString,
    line: UInt
) -> String {
    "[\(fileID):\(line) \(function)] \(diagnosticDetail(underlying))"
}

/// Log the underlying error folded at an untyped catch-all site, and return the
/// same gated detail for the typed error's carried payload.
///
/// ONE application of ONE policy. Because the caller writes
/// `self.error = .other(foldDiagnostic(error))`, two things become structurally
/// true rather than merely conventional:
///
/// 1. the `.public` log line and the carried payload CANNOT disagree; and
/// 2. a new fold site cannot set a folded payload without also logging — the gap
///    that nothing previously forced a new catch-all arm to call the logger at all.
///
/// `privacy: .public` is DELIBERATE (#456): it overrides `os.Logger`'s default
/// redaction so the diagnostic survives into a sysdiagnose (a `.private` value is
/// not persisted to the log store, defeating the purpose). What makes it SAFE is
/// no longer an enumeration of today's reachable error types — it is
/// `diagnosticDetail`'s default-deny (#467): an error type nobody has reviewed and
/// conformed to `SecretFreeError` is never described. To restore detail for a new
/// error source, conform it (redacting at source if any case can carry a secret);
/// do NOT widen this seam.
///
/// Returns `String` and never throws, so a fold's behaviour under `swift test` is
/// unchanged — the emitted unified-log line, if any, is invisible to the tests.
@discardableResult
func foldDiagnostic(
    _ error: Error,
    fileID: StaticString = #fileID,
    function: StaticString = #function,
    line: UInt = #line
) -> String {
    vaultAccessUILog.error(
        "\(foldedErrorDiagnostic(underlying: error, fileID: fileID, function: function, line: line), privacy: .public)"
    )
    return diagnosticDetail(error)
}
```

Also add `import SecretaryVaultAccess` under the existing `import Foundation` / `import os` at the top if it is not already there.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd /Users/hherb/src/secretary/.worktrees/467-public-log-secret-free-guard/ios/SecretaryVaultAccess && swift test --filter DiagnosticLogTests
```

Expected: 6 tests PASS. The full `swift test` will still FAIL to compile — the 23 view-model call sites still call the now-removed `logFoldedError`. That is expected and is Task 3's job. Do not "fix" it here by keeping `logFoldedError` around.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/467-public-log-secret-free-guard && \
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/DiagnosticLog.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/DiagnosticLogTests.swift && \
git commit -m "feat(#467): foldDiagnostic — one policy application per fold site

Replaces logFoldedError. Logs the gated detail at .public AND returns it for
the typed error's payload, so the two cannot disagree and a new fold site
cannot set a payload without logging.

The safety argument for .public is no longer an enumeration of today's
reachable error types; it is diagnosticDetail's default-deny.

Callers migrate in the next commit — the package does not build in between.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Migrate the 23 fold sites

**Files:**
- Modify (9 view models in `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/`):
  `VaultProvisioningViewModel.swift`, `UnlockViewModel.swift`, `DeviceSlotViewModel.swift`,
  `VaultSyncViewModel.swift`, `TrashViewModel.swift`, `VaultBrowseViewModel.swift`,
  `RecordEditViewModel.swift`, `SettingsViewModel.swift`, `VaultSelectionViewModel.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultSelectionViewModelTests.swift`

**Interfaces:**
- Consumes: `foldDiagnostic(_:)` from Task 2.
- Produces: no new API. All 23 sites collapse to the single-call form.

- [ ] **Step 1: Write the failing test**

Append to `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultSelectionViewModelTests.swift`, inside the `VaultSelectionViewModelTests` class (immediately after `testConsiderImportProbeErrorIsUnavailable`):

```swift
    /// SECURITY (#467): a fold site's CARRIED PAYLOAD is gated too, not just the
    /// log line. A non-conforming secret-bearing probe error must reach neither.
    /// Representative of all 23 fold sites — they share one helper, so one live
    /// site proving the wiring is enough; `DiagnosticLogTests` proves the policy.
    func testConsiderImportProbeErrorPayloadIsGated() {
        struct SecretBearing: Error, CustomStringConvertible {
            var description: String { "SecretBearing(secret: SECRET-VM-6C21)" }
        }
        let store = FakeVaultLocationStore()
        let probe = FakeVaultShapeProbe(answer: .failure(SecretBearing()))
        let vm = VaultSelectionViewModel(store: store, probe: probe)
        let outcome = vm.considerImport(url: URL(fileURLWithPath: "/x"),
                                        bookmark: Data("bm".utf8),
                                        displayName: "x")
        guard case .unavailable(let reason) = outcome else {
            return XCTFail("expected .unavailable, got \(outcome)")
        }
        XCTAssertFalse(reason.contains("SECRET-VM-6C21"))
        XCTAssertTrue(reason.contains("<undisclosed SecretBearing "))
    }
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd /Users/hherb/src/secretary/.worktrees/467-public-log-secret-free-guard/ios/SecretaryVaultAccess && swift test --filter VaultSelectionViewModelTests
```

Expected: **compile failure** — `cannot find 'logFoldedError' in scope` (the source still calls the removed function).

- [ ] **Step 3: Migrate every fold site**

At each of the 23 sites, replace the two-line pattern with one call. The transformation is uniform:

```swift
// BEFORE
} catch {
    logFoldedError(error)
    self.error = .other(String(describing: error))
}

// AFTER
} catch {
    self.error = .other(foldDiagnostic(error))
}
```

Apply it to every payload shape — the enum case is whatever was already there, only the argument changes:

| File | Sites | Payload shape(s) |
|---|---|---|
| `VaultProvisioningViewModel.swift` | 1 | `.createFailed(…)` |
| `UnlockViewModel.swift` | 1 | `state = .failed(.other(…))` |
| `DeviceSlotViewModel.swift` | 2 | `.reauthFailed(…)`, `.other(…)` |
| `VaultSyncViewModel.swift` | 2 | `lastError = .failed(…)` ×2 |
| `TrashViewModel.swift` | 3 | `.other(…)`, `.reauthFailed(…)`, `.other(…)` |
| `VaultBrowseViewModel.swift` | 4 | `.other(…)`, `.reauthFailed(…)`, `.other(…)`, `.other(…)` |
| `RecordEditViewModel.swift` | 4 | `.other(…)` ×3, `.reauthFailed(…)` |
| `SettingsViewModel.swift` | 4 | `.other(…)`, `.reauthFailed(…)`, `.other(…)`, `.other(…)` |
| `VaultSelectionViewModel.swift` | 2 | `return .unavailable(…)`, `state = .unavailable(reason: …)` |

Two sites are NOT the plain shape — handle them explicitly.

`UnlockViewModel.swift` (the fold assigns through a nested case):

```swift
        } catch {
            state = .failed(.other(foldDiagnostic(error)))
        }
```

`VaultSelectionViewModel.swift::beginAccess` (the fold is inside an `else` and the original error is still rethrown — do not touch the rethrow):

```swift
            if case VaultSelectionError.locationUnavailable(let reason) = error {
                state = .unavailable(reason: reason)
            } else {
                state = .unavailable(reason: foldDiagnostic(error))
            }
            throw error
```

Verify the count before moving on:

```bash
cd /Users/hherb/src/secretary/.worktrees/467-public-log-secret-free-guard && \
  grep -rn 'logFoldedError\|String(describing: error)' ios/SecretaryVaultAccess/Sources --include='*.swift'
```

Expected: **no output**.

- [ ] **Step 4: Run the full suite**

```bash
cd /Users/hherb/src/secretary/.worktrees/467-public-log-secret-free-guard/ios/SecretaryVaultAccess && swift test 2>&1 | tail -5
```

Expected: **351 tests, 0 failures** (344 baseline + 5 from Task 1 + 1 net from Task 2 + 1 here). If a count differs, reconcile it before committing — do not just accept a green run.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/467-public-log-secret-free-guard && \
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultSelectionViewModelTests.swift && \
git commit -m "refactor(#467): route all 23 fold sites through foldDiagnostic

Two lines become one at every untyped catch-all across the 9 view models. The
carried payload is now gated as well as the log line: leaving a raw
String(describing:) on the line after a gated call teaches the next reader that
the raw form is fine, which is how this invariant rotted into 'discipline, not
enforcement' in the first place.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: App-layer sites + the cross-package conformance

**Files:**
- Create: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/SecretFreeErrorConformances.swift`
- Create: `ios/SecretaryKit/Tests/SecretaryKitTests/SecretFreeErrorConformanceTests.swift`
- Modify: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/BookmarkVaultLocationStore.swift`
- Modify: `ios/SecretaryApp/Sources/SecretaryApp.swift`
- Modify: `ios/SecretaryMacApp/Sources/MacUnlockView.swift`

**Interfaces:**
- Consumes: `diagnosticDetail(_:)` and `SecretFreeError` from Task 1.
- Produces: `extension DeviceUnlockError: @retroactive SecretFreeError {}`.

- [ ] **Step 1: Write the failing test**

Create `ios/SecretaryKit/Tests/SecretaryKitTests/SecretFreeErrorConformanceTests.swift`:

```swift
import XCTest
import SecretaryDeviceUnlock
import SecretaryVaultAccess
@testable import SecretaryKit

final class SecretFreeErrorConformanceTests: XCTestCase {
    /// SECURITY (#467): `DeviceUnlockError` reaches an untyped fold arm via the
    /// re-auth gate (`BiometricAuthorizer.authorize` → `GraceWindowReauthGate`),
    /// but it lives in `SecretaryDeviceUnlock`, which `SecretaryVaultAccess` does
    /// not depend on — so `SecretaryVaultAccessTests` structurally cannot see this
    /// conformance. Its absence would silently degrade every biometric-gate
    /// diagnostic to `<undisclosed …>`.
    func testDeviceUnlockErrorConforms() {
        XCTAssertTrue(DeviceUnlockError.userCancelled is SecretFreeError)
    }

    /// The conformance must also be what `diagnosticDetail` actually picks up —
    /// a conformance that exists but is not found by the dynamic cast would be
    /// worthless.
    func testDeviceUnlockErrorRendersItsDescription() {
        XCTAssertEqual(diagnosticDetail(DeviceUnlockError.biometryLockout),
                       String(describing: DeviceUnlockError.biometryLockout))
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd /Users/hherb/src/secretary/.worktrees/467-public-log-secret-free-guard/ios/SecretaryKit && swift test --filter SecretFreeErrorConformanceTests
```

Expected: FAIL — `testDeviceUnlockErrorConforms` returns false, and `testDeviceUnlockErrorRendersItsDescription` gets the `<undisclosed …>` marker.

(If the build instead fails on a missing xcframework, run `bash ios/scripts/build-xcframework.sh` from the worktree root first — it is a multi-minute four-triple cross-compile, so run it in the background and poll the log.)

- [ ] **Step 3: Write the conformance**

Create `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/SecretFreeErrorConformances.swift`:

```swift
import SecretaryDeviceUnlock
import SecretaryVaultAccess

// Cross-package `SecretFreeError` conformances (#467).
//
// They live HERE, not in `SecretaryVaultAccess`, because `SecretaryVaultAccess`
// does not depend on `SecretaryDeviceUnlock` — `SecretaryKit` is the lowest
// target that sees both. Swift registers conformances process-globally, so the
// `as? SecretFreeError` cast inside `SecretaryVaultAccessUI` finds this one at
// runtime even though that module cannot see the declaration.
//
// `@retroactive` is required and correct: this module owns neither the type nor
// the protocol. It is also a useful marker — it says out loud that a conformance
// is being asserted across a boundary the type's own author never saw.

/// Biometric / Secure-Enclave gate failures. Every case is a fixed sentinel
/// except `.enclave(String)`, which carries a `Security.framework` OSStatus
/// description, and `.vault(VaultSlotError)`, which carries slot-shape state.
/// No wrapped secret, device secret, or key material is ever placed in either.
extension DeviceUnlockError: @retroactive SecretFreeError {}
```

- [ ] **Step 4: Gate the seven app-layer error sites**

`ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/BookmarkVaultLocationStore.swift` — one error site, plus a comment on the neighbouring `displayName` site:

```swift
        if isStale {
            do {
                let fresh = try url.bookmarkData()
                persist(VaultLocation(displayName: location.displayName, bookmark: fresh))
                // `displayName` is the vault FOLDER name from the system picker, not
                // an error and not a secret: anyone who can read the unified log can
                // read the filesystem, so this discloses nothing new (and
                // `VaultLocation`'s own doc records that no key or credential flows
                // through the type). Deliberately left `.public` — #467.
                Self.log.notice("Refreshed stale vault bookmark for \(location.displayName, privacy: .public)")
            } catch {
                Self.log.error("Stale vault bookmark refresh failed (using resolved URL): \(diagnosticDetail(error), privacy: .public)")
            }
        }
```

`ios/SecretaryApp/Sources/SecretaryApp.swift` — five sites. Replace `error.localizedDescription` with `diagnosticDetail(error)` in each, leaving the surrounding message text untouched:

```swift
appLog.error("sync state dir unavailable, using temp: \(diagnosticDetail(error), privacy: .public)")
appLog.error("folder-change monitor failed to start: \(diagnosticDetail(error), privacy: .public)")
appLog.error("device enroll failed: \(diagnosticDetail(error), privacy: .public)")
```

(two of these appear twice — once in the password-unlock path and once in the device-unlock path.)

`ios/SecretaryMacApp/Sources/MacUnlockView.swift` — one site:

```swift
macUnlockLog.error("device enroll failed: \(diagnosticDetail(error), privacy: .public)")
```

Add `import SecretaryVaultAccess` to any of these files that does not already have it.

- [ ] **Step 5: Run the tests and compile the apps**

```bash
cd /Users/hherb/src/secretary/.worktrees/467-public-log-secret-free-guard/ios/SecretaryKit && swift test --filter SecretFreeErrorConformanceTests
cd /Users/hherb/src/secretary/.worktrees/467-public-log-secret-free-guard && bash ios/scripts/build-app.sh
cd /Users/hherb/src/secretary/.worktrees/467-public-log-secret-free-guard && bash ios/scripts/build-macos-app.sh
```

Expected: 2 tests PASS; both app builds print `** BUILD SUCCEEDED **`. The app builds are the only thing that compiles `SecretaryApp.swift` / `MacUnlockView.swift` — `swift test` never touches them.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/467-public-log-secret-free-guard && \
git add ios/SecretaryKit ios/SecretaryApp ios/SecretaryMacApp && \
git commit -m "feat(#467): gate the 7 app-layer .public error sites

BookmarkVaultLocationStore, SecretaryApp x5, MacUnlockView now render errors
through diagnosticDetail. The six that logged .localizedDescription now emit
case-plus-associated-values, which is both better in a log and uniform with the
fold seam.

DeviceUnlockError's conformance lives in SecretaryKit because SecretaryVaultAccess
does not depend on SecretaryDeviceUnlock; Swift registers conformances globally,
so the cast inside SecretaryVaultAccessUI still finds it.

The eighth site logs location.displayName — a folder name, not an error.
Deliberately left .public, with the reasoning recorded at the call site.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: The hygiene check + CI wiring

**Files:**
- Create: `ios/scripts/check-public-log-hygiene.sh`
- Modify: `.github/workflows/test.yml`

**Interfaces:**
- Consumes: the state left by Tasks 1–4 (zero forbidden lines).
- Produces: `bash ios/scripts/check-public-log-hygiene.sh [--self-test]`, exit 0 clean / non-zero with offending lines printed.

- [ ] **Step 1: Write the script**

Create `ios/scripts/check-public-log-hygiene.sh`:

```bash
#!/usr/bin/env bash
#
# check-public-log-hygiene.sh — assert no `privacy: .public` log line renders an
# error by hand (#467).
#
# WHY THIS EXISTS
# ---------------
# `privacy: .public` disables the unified log's default redaction so a diagnostic
# survives into a sysdiagnose (#456). `SecretFreeError` + `diagnosticDetail` make
# the RENDERING fail-closed — an unreviewed error type is never described. But
# nothing in the type system forces a NEW log site to call `diagnosticDetail`
# instead of hand-rolling `String(describing:)` or `.localizedDescription`. This
# script is that tripwire; without it #467's acceptance criterion does not hold.
#
# THE ONE DELIBERATE EXCEPTION
# ----------------------------
# `BookmarkVaultLocationStore` logs `location.displayName` at `.public`. That is
# the vault FOLDER name from the system picker — not an error, and not a secret:
# anyone able to read the unified log can read the filesystem. It matches neither
# forbidden pattern, so it needs no allowlist entry; the reasoning is recorded at
# the call site.
#
# USAGE
# -----
#   bash ios/scripts/check-public-log-hygiene.sh              # guard ios/**/*.swift
#   bash ios/scripts/check-public-log-hygiene.sh --self-test  # prove the matcher works
#
# LIMITS (stated, not hidden)
# ---------------------------
# The matcher is LINE-BASED: a `.public` interpolation split across two source
# lines would evade it. Every current site is single-line and swift-format keeps
# them that way; parsing Swift to close that gap is far out of proportion. The
# `--self-test` controls document exactly what does and does not trip it.

set -euo pipefail

readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly SCAN_ROOT="$REPO_ROOT/ios"

# A line that emits at `privacy: .public` …
readonly PUBLIC_RE='privacy: \.public'
# … must not ALSO render an error by hand. `diagnosticDetail` is the only
# sanctioned renderer (see SecretFreeError.swift).
readonly FORBIDDEN_RE='String\(describing:|\.localizedDescription'

# Print every offending `<file>:<line>:<text>`; empty output means clean.
scan() {
  grep -rn --include='*.swift' -E "$PUBLIC_RE" "$1" 2>/dev/null \
    | grep -E "$FORBIDDEN_RE" || true
}

# Two-sided control: the matcher must fire on a known-positive AND stay silent on
# a known-negative. A check never observed failing is indistinguishable from a
# no-op; a check that fires on everything is worse than none.
self_test() {
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  printf '%s\n' 'log.error("boom: \(String(describing: error), privacy: .public)")' \
    > "$tmp/Positive.swift"
  printf '%s\n' 'log.error("boom: \(diagnosticDetail(error), privacy: .public)")' \
    > "$tmp/Negative.swift"

  local hits
  hits="$(scan "$tmp")"

  if ! grep -q 'Positive\.swift' <<<"$hits"; then
    echo "SELF-TEST FAILED: matcher did NOT fire on the known-positive control" >&2
    return 1
  fi
  if grep -q 'Negative\.swift' <<<"$hits"; then
    echo "SELF-TEST FAILED: matcher fired on the known-negative control" >&2
    return 1
  fi
  echo "self-test OK — matcher fires on the positive control, not on the negative"
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
  exit 0
fi

hits="$(scan "$SCAN_ROOT")"
if [[ -n "$hits" ]]; then
  echo "ERROR: an Error is rendered into a 'privacy: .public' log line without diagnosticDetail (#467):" >&2
  echo "$hits" >&2
  echo >&2
  echo "Fix: render via diagnosticDetail(error). If the type should keep its detail," >&2
  echo "conform it to SecretFreeError (redacting at source if any case can carry a secret)." >&2
  exit 1
fi
echo "OK — no hand-rolled error rendering at a 'privacy: .public' site"
```

- [ ] **Step 2: Run the self-test and the real check**

```bash
cd /Users/hherb/src/secretary/.worktrees/467-public-log-secret-free-guard && \
  chmod +x ios/scripts/check-public-log-hygiene.sh && \
  bash ios/scripts/check-public-log-hygiene.sh --self-test && \
  bash ios/scripts/check-public-log-hygiene.sh
```

Expected: `self-test OK …` then `OK — no hand-rolled error rendering …`, exit 0 both times.

- [ ] **Step 3: Prove it goes red on a real mutation, then revert**

```bash
cd /Users/hherb/src/secretary/.worktrees/467-public-log-secret-free-guard && \
  sed -i '' 's|\\(diagnosticDetail(error), privacy: .public)|\\(String(describing: error), privacy: .public)|' \
    ios/SecretaryMacApp/Sources/MacUnlockView.swift && \
  bash ios/scripts/check-public-log-hygiene.sh; echo "EXIT=$?"
```

Expected: **EXIT=1**, with `MacUnlockView.swift` printed. Then revert and re-confirm green:

```bash
cd /Users/hherb/src/secretary/.worktrees/467-public-log-secret-free-guard && \
  git checkout -- ios/SecretaryMacApp/Sources/MacUnlockView.swift && \
  bash ios/scripts/check-public-log-hygiene.sh; echo "EXIT=$?"
```

Expected: **EXIT=0**. Do not skip this — the mutation is the only evidence the check is not vacuous against the real tree (the self-test only proves it against synthetic files).

- [ ] **Step 4: Wire it into CI**

Append to `.github/workflows/test.yml`, as a new job at the same indent level as `ios-host`:

```yaml
  swift-log-hygiene:
    name: swift .public log hygiene
    # Pure grep over ios/**/*.swift — no Swift toolchain, no Xcode, no macOS
    # minutes, so it runs on ubuntu in seconds. `test.yml` has no path filter, so
    # this lands on every push to main and every PR. #467.
    runs-on: ubuntu-latest
    timeout-minutes: 10   # runaway cap (vs the 6h default); real duration ~10s
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      # --self-test FIRST: a guard never observed failing is indistinguishable
      # from a no-op — the same vacuity hazard proven against in #469 and guarded
      # the same way in ffi/scripts/check-lean-binding.sh.
      - name: 'check-public-log-hygiene.sh --self-test'
        run: bash ios/scripts/check-public-log-hygiene.sh --self-test
      - name: 'check-public-log-hygiene.sh'
        run: bash ios/scripts/check-public-log-hygiene.sh
```

Note the quoted step names: an unquoted ` #` inside a YAML `name:` starts a comment and silently truncates it — valid YAML, so `actionlint` stays green. That trap cost a fixup in #470; do not reintroduce it.

- [ ] **Step 5: Lint the workflow and verify the step names survived**

```bash
cd /Users/hherb/src/secretary/.worktrees/467-public-log-secret-free-guard && \
  actionlint .github/workflows/test.yml && \
  shellcheck ios/scripts/check-public-log-hygiene.sh && \
  python3 -c "
import yaml,sys
d=yaml.safe_load(open('.github/workflows/test.yml'))
j=d['jobs']['swift-log-hygiene']
print(j['name'])
for s in j['steps']: print(' -', s.get('name', s.get('uses')))
"
```

Expected: `actionlint` clean, `shellcheck` clean, and the printed step names read exactly `check-public-log-hygiene.sh --self-test` and `check-public-log-hygiene.sh` — not truncated.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/467-public-log-secret-free-guard && \
git add ios/scripts/check-public-log-hygiene.sh .github/workflows/test.yml && \
git commit -m "ci(#467): grep guard forcing .public error renders through diagnosticDetail

The protocol makes rendering fail-closed; nothing in the type system forces a
NEW log site to use it. This is that tripwire — without it #467's acceptance
criterion does not actually hold.

Two-sided --self-test (must fire on the positive control AND stay silent on the
negative), plus a real-tree mutation proof run before commit. Pure grep, so it
runs on ubuntu in seconds on every PR rather than needing macOS minutes.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Docs, full verification, handoff

**Files:**
- Modify: `ROADMAP.md` (only if the precedent check says so)
- Modify: `README.md` (only if the precedent check says so)
- Create: `docs/handoffs/2026-08-02-467-public-log-secret-free-guard-shipped.md`
- Modify: `NEXT_SESSION.md` (retarget the symlink)

- [ ] **Step 1: Run every gate**

```bash
cd /Users/hherb/src/secretary/.worktrees/467-public-log-secret-free-guard/ios/SecretaryVaultAccess && swift test 2>&1 | tail -5
cd /Users/hherb/src/secretary/.worktrees/467-public-log-secret-free-guard/ios/SecretaryDeviceUnlock && swift test 2>&1 | tail -5
cd /Users/hherb/src/secretary/.worktrees/467-public-log-secret-free-guard/ios/SecretaryKit && swift test 2>&1 | tail -5
cd /Users/hherb/src/secretary/.worktrees/467-public-log-secret-free-guard && bash ios/scripts/build-app.sh 2>&1 | tail -3
cd /Users/hherb/src/secretary/.worktrees/467-public-log-secret-free-guard && bash ios/scripts/build-macos-app.sh 2>&1 | tail -3
cd /Users/hherb/src/secretary/.worktrees/467-public-log-secret-free-guard && bash ios/scripts/check-public-log-hygiene.sh --self-test && bash ios/scripts/check-public-log-hygiene.sh
cd /Users/hherb/src/secretary/.worktrees/467-public-log-secret-free-guard && actionlint .github/workflows/test.yml && shellcheck ios/scripts/check-public-log-hygiene.sh
```

Expected: `SecretaryVaultAccess` **351 tests, 0 failures**; `SecretaryDeviceUnlock` unchanged from its own baseline; `SecretaryKit` +2; both apps `** BUILD SUCCEEDED **`; both checks exit 0; both linters clean.

- [ ] **Step 2: Confirm no Rust surface was touched**

```bash
cd /Users/hherb/src/secretary/.worktrees/467-public-log-secret-free-guard && \
  git diff main... --name-only -- core/ ffi/ && echo "(empty above = no Rust surface)"
```

Expected: no paths listed. If any appear, stop — the plan's Global Constraints were violated and the cargo/clippy/conformance gates would become mandatory.

- [ ] **Step 3: Decide README / ROADMAP by precedent, not assumption**

Check how the two comparable prior slices were treated before editing anything:

```bash
cd /Users/hherb/src/secretary/.worktrees/467-public-log-secret-free-guard && \
  grep -n '456\|466\|437\|469' ROADMAP.md README.md
```

Apply the same rule those slices established: README tracks slices in prose and does not enumerate CI coverage or internal seams; ROADMAP carries a per-slice clause where one already exists for the surrounding work. Concretely — extend the existing D.5.1 / iOS clause that mentions #456's fold-site logging so it records that the seam is now fail-closed and CI-guarded, and add nothing to README unless #456 itself appears there.

Write down which way you went and why in the handoff. "No change" is a valid outcome and must be justified by the grep, not by assumption.

- [ ] **Step 4: Write the handoff and retarget the symlink**

Create `docs/handoffs/2026-08-02-467-public-log-secret-free-guard-shipped.md` covering, per the session contract: (1) what shipped with commit SHAs, (2) what's next with concrete acceptance criteria, (3) open decisions and risks, (4) exact resume commands, (5) the symlink model.

Risks that must appear in (3):
- the line-based matcher's blind spot (multi-line `.public` interpolation);
- a missing future conformance degrades diagnostics silently rather than failing the build — safe direction, but real;
- the app-layer text change from `.localizedDescription` to case-plus-associated-values is a deliberate log-content change, visible to anyone reading existing sysdiagnoses;
- the allowlist deviation from spec §5, and why.

Then:

```bash
cd /Users/hherb/src/secretary/.worktrees/467-public-log-secret-free-guard && \
  ln -snf docs/handoffs/2026-08-02-467-public-log-secret-free-guard-shipped.md NEXT_SESSION.md && \
  ls -la NEXT_SESSION.md && head -3 NEXT_SESSION.md
```

- [ ] **Step 5: Commit, push, open the PR**

```bash
cd /Users/hherb/src/secretary/.worktrees/467-public-log-secret-free-guard && \
git add -A && \
git commit -m "docs(#467): ROADMAP clause + session handoff

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>" && \
git push -u origin feature/467-public-log-secret-free-guard
```

Then open the PR with `gh pr create`, body referencing `(#467)` (not `Closes #467` — this repo's convention keeps the reference form), and stating the acceptance evidence: test counts, the mutation proof, both app builds, and both linters.

---

## Self-review

**Spec coverage.** §1 policy → Task 1. §2 conformances → Task 1 (five) + Task 4 (`DeviceUnlockError`). §3 fold helper → Task 2; the 23 call sites → Task 3. §4 app-layer sites + the `displayName` decision → Task 4. §5 source-level check → Task 5 (allowlist deliberately dropped; deviation stated above and in the handoff). Testing §, tests 1–8 → Tasks 1 (1–5), 2 (6), 3 (7), 4 (8). Non-goals → Global Constraints. Risks → Task 6 Step 4.

**Type consistency.** `SecretFreeError` / `diagnosticDescription` / `diagnosticDetail(_:)` / `foldDiagnostic(_:fileID:function:line:)` / `foldedErrorDiagnostic(underlying:fileID:function:line:)` are spelled identically in every task. `logFoldedError` appears only where it is being removed.

**Known ordering hazard.** The tree does not compile between Task 2 and Task 3 — `logFoldedError` is deleted in Task 2 and its callers migrate in Task 3. This is deliberate (it keeps the policy change and the mechanical migration reviewable apart) and is called out in Task 2 Step 4 so an executor does not "fix" it by reinstating the old function. If you would rather every commit build, merge Tasks 2 and 3 into one.
