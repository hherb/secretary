# Fold-Site Diagnostic Logging (#456) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one redaction-aware `os.Logger` seam in `SecretaryVaultAccessUI` and call it at every untyped catch-all fold site, so a catch-all failure's underlying error is recorded (not lost on an in-memory enum value).

**Architecture:** A pure, host-tested formatter (`foldedErrorDiagnostic`) builds the log line; a thin `os.Logger` edge (`logFoldedError`) emits it with a deliberate `privacy: .public`. Each of the 23 untyped `catch { … String(describing: error) }` folds across 9 view models gains one line — `logFoldedError(error)` — immediately before its existing assignment. Additive only; no VM constructor, port, error type, or user-facing copy changes.

**Tech Stack:** Swift 6 (strict concurrency), `os.Logger`, XCTest, Swift Package Manager. Package `ios/SecretaryVaultAccess`, target `SecretaryVaultAccessUI` (FFI-free — inner loop is `swift test`, no xcframework).

## Global Constraints

- **Subsystem/category:** `Logger(subsystem: "com.secretary.vaultaccess", category: "vault-access-ui")` — one instance, package-private. (App layers use `com.secretary.app` / `com.secretary.macapp`; this shared package gets its own.)
- **Level:** `.error`. **Privacy:** `privacy: .public` (deliberate — folded errors are diagnostic-only; see the doc comment).
- **Only dynamic content logged** is `String(describing: underlying)`; site identifiers are compile-time `#fileID` / `#function` / `#line` (`StaticString` / `UInt`).
- **Scope:** the 23 **untyped** `catch { … String(describing: error) }` folds only. Do **not** touch the typed `catch let e as VaultAccessError { error = e }` arms.
- **No** `core` / `ffi` / `.udl` / `FfiVaultError` / on-disk-format change. **No** copy change, **no** telemetry/upload.
- Files stay well under 500 lines. `#![...]`-equivalent: the package builds under Swift 6 complete strict-concurrency — the seam is a free function + a `let` global `Logger` (`Sendable`), so no isolation annotations are needed.
- Existing tests must stay green; `os.Logger` is a no-op sink under `swift test`.

---

### Task 1: The `DiagnosticLog` seam (pure formatter + `os.Logger` edge)

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/DiagnosticLog.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/DiagnosticLogTests.swift`

**Interfaces:**
- Produces (package-internal, callable from every VM in the same target, no import needed):
  - `func foldedErrorDiagnostic(underlying: Error, fileID: StaticString, function: StaticString, line: UInt) -> String`
  - `func logFoldedError(_ underlying: Error, fileID: StaticString = #fileID, function: StaticString = #function, line: UInt = #line)`

- [ ] **Step 1: Write the failing test**

Create `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/DiagnosticLogTests.swift`:

```swift
import XCTest
@testable import SecretaryVaultAccessUI

/// An error whose `String(describing:)` is an exact, known sentinel — so the
/// formatter's output can be asserted byte-for-byte (proving no other content,
/// e.g. `.localizedDescription`, leaks into the logged line).
private struct SentinelError: Error, CustomStringConvertible {
    let description: String
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
    /// `String(describing: underlying)` — nothing else. Byte-exact equality is the
    /// enforcement that the logged content stays diagnostic-only.
    func testDiagnosticIsSiteAndDescriptionOnly() {
        let out = foldedErrorDiagnostic(
            underlying: SentinelError(description: "DIAG-SENTINEL-9F3A"),
            fileID: "MyFile.swift", function: "myFunc()", line: 42
        )
        XCTAssertEqual(out, "[MyFile.swift:42 myFunc()] DIAG-SENTINEL-9F3A")
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter DiagnosticLogTests`
Expected: FAIL to **compile** — `cannot find 'foldedErrorDiagnostic' in scope`.

- [ ] **Step 3: Write minimal implementation**

Create `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/DiagnosticLog.swift`:

```swift
import Foundation
import os

// Diagnostic logging seam for `SecretaryVaultAccessUI` view-model fold sites (#456).
//
// The view models fold an *untyped* underlying failure into a typed error's carried
// `String` at their catch-all `catch` arms (`.other` / `.reauthFailed` /
// `.createFailed` / `.failed` / `.unavailable`). #454 deliberately keeps that carried
// `String` out of the user-facing copy, so without a logger the only record of what
// went wrong lives on an in-memory enum value that nothing surfaces. This seam is that
// logger: a pure, host-tested formatter plus a thin `os.Logger` edge.

/// The unified-log destination for fold-site diagnostics. The app layers use
/// `com.secretary.app` / `com.secretary.macapp`; this shared package uses its own
/// `com.secretary.vaultaccess` subsystem so its lines filter cleanly in Console.app.
private let vaultAccessUILog = Logger(
    subsystem: "com.secretary.vaultaccess",
    category: "vault-access-ui"
)

/// Build the one-line diagnostic string logged at a fold site.
///
/// Shape: `"[<fileID>:<line> <function>] <String(describing: underlying)>"`.
///
/// The ONLY dynamic component is `String(describing: underlying)`; the site
/// identifiers are compile-time `StaticString` / `UInt`. Keeping this a pure function
/// makes the "what content is emitted" decision host-testable in isolation, which is
/// what proves the logged content stays diagnostic-only — no `.localizedDescription`
/// or other interpolation can slip in (see `DiagnosticLogTests`).
func foldedErrorDiagnostic(
    underlying: Error,
    fileID: StaticString,
    function: StaticString,
    line: UInt
) -> String {
    "[\(fileID):\(line) \(function)] \(String(describing: underlying))"
}

/// Log, at `.error` level, the underlying error folded at an untyped catch-all site.
///
/// `privacy: .public` is DELIBERATE (#456). The underlying errors folded at the call
/// sites are, exhaustively today: `FfiVaultError` (uniffi), Foundation file errors,
/// `DeviceUnlockError`, `VaultSyncError`, and `VaultSelectionError` — carrying
/// uuids / paths / labels / reasons, never vault plaintext, a password, a mnemonic,
/// or key bytes. This is the same `String(describing:)` the enum already retains in
/// memory (#454); logging it only newly exposes it to the unified log store, which is
/// why "diagnostic-only" must hold before choosing `.public`.
///
/// If you add a new error source that could carry a secret, sanitize it AT THAT
/// SOURCE (or drop to `privacy: .private` / `.sensitive` there) — do NOT widen this
/// seam silently. `os.Logger` is a no-op sink under `swift test`, so calling this from
/// a fold site keeps the pure view models host-testable.
func logFoldedError(
    _ underlying: Error,
    fileID: StaticString = #fileID,
    function: StaticString = #function,
    line: UInt = #line
) {
    vaultAccessUILog.error(
        "\(foldedErrorDiagnostic(underlying: underlying, fileID: fileID, function: function, line: line), privacy: .public)"
    )
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ios/SecretaryVaultAccess && swift test --filter DiagnosticLogTests`
Expected: PASS — 3 tests, 0 failures.

- [ ] **Step 5: Commit**

```bash
cd ios/SecretaryVaultAccess
git add Sources/SecretaryVaultAccessUI/DiagnosticLog.swift \
        Tests/SecretaryVaultAccessUITests/DiagnosticLogTests.swift
git commit -m "feat(ios,#456): DiagnosticLog seam — pure formatter + os.Logger edge

Package-internal foldedErrorDiagnostic (pure, host-tested) + logFoldedError
(thin .public os.Logger edge, auto-capturing #fileID/#function/#line). Sentinel-
equality test proves the line is site + String(describing:) only. No fold sites
wired yet (Task 2)."
```

---

### Task 2: Wire `logFoldedError(error)` at all 23 fold sites

**Files (Modify — one added line per fold, immediately before each `String(describing: error)` assignment):**
- `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/UnlockViewModel.swift` (1)
- `.../TrashViewModel.swift` (3)
- `.../VaultProvisioningViewModel.swift` (1)
- `.../SettingsViewModel.swift` (4)
- `.../VaultBrowseViewModel.swift` (4)
- `.../DeviceSlotViewModel.swift` (2)
- `.../VaultSyncViewModel.swift` (2)
- `.../VaultSelectionViewModel.swift` (2)
- `.../RecordEditViewModel.swift` (4)

**Interfaces:**
- Consumes: `logFoldedError(_:fileID:function:line:)` from Task 1 (same target — no import).
- Produces: nothing new; VM published state is unchanged (so existing VM tests stay green).

**The transformation (identical at every site):** insert `logFoldedError(error)` as the first statement of the untyped `catch { … }` block that folds via `String(describing: error)`. Example — `TrashViewModel.load()`:

```swift
// BEFORE
} catch {
    self.error = .other(String(describing: error))
}
// AFTER
} catch {
    logFoldedError(error)
    self.error = .other(String(describing: error))
}
```

Two sites need care (shown in full below): `VaultBrowseViewModel.readBlock` (the catch has a `records = nil` line — put `logFoldedError(error)` first) and `VaultSelectionViewModel.beginAccess` (the string fold is only in the `else` branch — the log goes there, **not** in the typed-`reason` `if` branch).

- [ ] **Step 1: Wire `UnlockViewModel.swift`**

The untyped catch (~line 38):

```swift
} catch {
    logFoldedError(error)
    state = .failed(.other(String(describing: error)))
}
```

- [ ] **Step 2: Wire `TrashViewModel.swift` (3 sites)**

`load()`:

```swift
} catch {
    logFoldedError(error)
    self.error = .other(String(describing: error))
}
```

`reauthedWrite` gate catch (`.reauthFailed`):

```swift
} catch {
    logFoldedError(error)
    self.error = .reauthFailed(String(describing: error))
    return nil
}
```

`reauthedWrite` op catch (`.other`):

```swift
} catch {
    logFoldedError(error)
    self.error = .other(String(describing: error))
    return nil
}
```

- [ ] **Step 3: Wire `VaultProvisioningViewModel.swift` (1 site)**

```swift
} catch {
    logFoldedError(error)
    self.error = .createFailed(String(describing: error))
}
```

- [ ] **Step 4: Wire `SettingsViewModel.swift` (4 sites)**

At each untyped catch, add `logFoldedError(error)` as the first line before the existing `self.error = .other(String(describing: error))` (×3) and `self.error = .reauthFailed(String(describing: error))` (×1) assignments.

- [ ] **Step 5: Wire `VaultBrowseViewModel.swift` (4 sites)**

`readBlock` catch (note the extra `records = nil` — log first):

```swift
} catch {
    logFoldedError(error)
    records = nil
    self.error = .other(String(describing: error))
}
```

The other three (`.reauthFailed` ×1, `.other` ×2): add `logFoldedError(error)` as the first line of each untyped catch, before its assignment.

- [ ] **Step 6: Wire `DeviceSlotViewModel.swift` (2 sites)**

Add `logFoldedError(error)` before the `.reauthFailed(String(describing: error))` and `.other(String(describing: error))` assignments.

- [ ] **Step 7: Wire `VaultSyncViewModel.swift` (2 sites)**

Both untyped catches:

```swift
} catch {
    logFoldedError(error)
    lastError = .failed(String(describing: error))
}
```

- [ ] **Step 8: Wire `VaultSelectionViewModel.swift` (2 sites)**

`evaluate` (return fold):

```swift
} catch {
    logFoldedError(error)
    return .unavailable(String(describing: error))
}
```

`beginAccess` — the log goes only in the `else` branch (the `if` branch extracts a **typed** `reason`, not a string fold):

```swift
} catch {
    if case VaultSelectionError.locationUnavailable(let reason) = error {
        state = .unavailable(reason: reason)
    } else {
        logFoldedError(error)
        state = .unavailable(reason: String(describing: error))
    }
    throw error
}
```

- [ ] **Step 9: Wire `RecordEditViewModel.swift` (4 sites)**

Add `logFoldedError(error)` as the first line of each untyped catch, before its `.other(String(describing: error))` (×3) / `.reauthFailed(String(describing: error))` (×1) assignment.

- [ ] **Step 10: Verify all 23 sites wired + no typed arm touched**

Run:
```bash
cd ios/SecretaryVaultAccess
grep -rc "logFoldedError(error)" Sources/SecretaryVaultAccessUI/ | grep -v ':0'
grep -rn "logFoldedError" Sources/SecretaryVaultAccessUI/ | wc -l
```
Expected: 23 `logFoldedError(error)` call sites across the 9 VMs (UnlockViewModel 1, TrashViewModel 3, VaultProvisioningViewModel 1, SettingsViewModel 4, VaultBrowseViewModel 4, DeviceSlotViewModel 2, VaultSyncViewModel 2, VaultSelectionViewModel 2, RecordEditViewModel 4).

- [ ] **Step 11: Run the full UI + package host suite to verify green (no regressions)**

Run: `cd ios/SecretaryVaultAccess && swift test`
Expected: all tests pass, 0 failures (existing suite + Task 1's `DiagnosticLogTests`). Published VM error state is unchanged, so no existing assertion changes.

- [ ] **Step 12: Commit**

```bash
cd ios/SecretaryVaultAccess
git add Sources/SecretaryVaultAccessUI/
git commit -m "feat(ios,#456): log underlying error at all 23 VM fold sites

One logFoldedError(error) before each untyped catch-all String(describing:)
fold across the 9 SecretaryVaultAccessUI view models. Typed
'catch let e as VaultAccessError' arms untouched. VM published state
unchanged — existing host suite stays green."
```

---

### Task 3: App-build sanity (shared package compiles into both apps)

**Files:** none (build verification only).

- [ ] **Step 1: Confirm no `core`/`ffi` surface touched**

Run: `git diff --name-only main... | grep -E '^(core|ffi)/' || echo "clean (no core/ffi change)"`
Expected: `clean (no core/ffi change)`.

- [ ] **Step 2: Build the iOS app (shared package links)**

Run (from the worktree root): `bash ios/scripts/build-app.sh`
Expected: `** BUILD SUCCEEDED **`. (Cold worktree: first run cross-compiles the Rust xcframework — multi-minute and silent; warm it before dispatching subagents.)

- [ ] **Step 3: Run the SecretaryKit/app test bundle**

Run (from the worktree root): `bash ios/scripts/run-ios-tests.sh`
Expected: `TEST + BUILD SUCCEEDED`.

*(macOS app: `SecretaryVaultAccessUI` is shared, so the iOS build proves compilation; a macOS build is an optional extra sanity check via `ios/scripts/run-macos-app.sh`/the mac target if quick.)*

---

## Self-Review

**1. Spec coverage:**
- "single logging seam" → Task 1 (`DiagnosticLog.swift`). ✓
- "underlying error logged at fold sites with correct privacy" → Task 2 (23 sites, `.public`). ✓
- "note/assertion logged content is diagnostic-only" → Task 1 doc comment + `testDiagnosticIsSiteAndDescriptionOnly`. ✓
- "host suites still green" → Task 2 Step 11. ✓
- "no copy change / no telemetry / no core-ffi change" → Global Constraints + Task 3 Step 1. ✓
- Fold-site scope (untyped only; typed arms untouched) → Global Constraints + Task 2 Step 10 grep. ✓

**2. Placeholder scan:** No TBD/TODO; every code step shows exact code; the repetitive 23 sites are enumerated per file with the exact resulting catch block for every non-trivial case. ✓

**3. Type consistency:** `foldedErrorDiagnostic(underlying:fileID:function:line:)` and `logFoldedError(_:fileID:function:line:)` signatures match between Task 1's definition, the test, and the Task 2 call sites (`logFoldedError(error)` relying on the three defaulted args). ✓
