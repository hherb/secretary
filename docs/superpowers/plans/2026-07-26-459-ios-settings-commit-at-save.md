# iOS Settings commit-at-Save (#459) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop the iOS Settings screen persisting a stale (or cleared-field) numeric value on tap-Save, by porting the macOS #458 text-buffered commit-at-Save treatment onto a shared, host-tested unit used by both platforms.

**Architecture:** A new pure `SettingsEditBuffer` value type plus a `@MainActor commitSettingsEdits(_:into:)` free function land in `SecretaryVaultAccessUI`. Both Settings views hold the buffer as `@State`, bind `TextField(text:)` (per-keystroke), and commit explicitly at Save. `SettingsViewModel` is **not** modified — leaving `save()` byte-identical is what makes this a zero-regression-risk change to the re-auth gate ordering invariant.

**Tech Stack:** Swift 5/6 + SwiftUI, SwiftPM (`ios/SecretaryVaultAccess`), XCTest. XcodeGen app targets (`ios/SecretaryApp`, `ios/SecretaryMacApp`). No new dependencies.

**Spec:** [`docs/superpowers/specs/2026-07-26-459-ios-settings-commit-at-save-design.md`](../specs/2026-07-26-459-ios-settings-commit-at-save-design.md)

## Global Constraints

- **`ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/SettingsViewModel.swift` MUST NOT be modified.** It carries the security ordering (gate against the pre-save window → re-read → write → retarget only on success). Any task that seems to need a change there is a plan error — stop and escalate.
- All user-facing copy is byte-exact. The input-error string is `Each field needs a whole number — settings were not saved.` using an em dash `—` (U+2014), matching the shipped macOS string it replaces.
- Parsing uses plain `Int(_:)` after `trimmingCharacters(in: .whitespaces)` — **never** a locale-aware `FormatStyle` (a grouping locale would accept `"3,650"`).
- Test bounds come from `FakeSettingsPort`: retention `1...3650` days (default 90), grace `0...60` minutes (default 2).
- Every new `public` symbol carries a doc comment explaining *why*, not just *what* — matching the density of the surrounding files.
- No emoji anywhere in code, comments, or commit messages.
- Keep files under 500 lines.
- Work happens in the worktree `/Users/hherb/src/secretary/.worktrees/459-ios-settings-commit-at-save` on branch `feature/459-ios-settings-commit-at-save`. Every `cd` must spell out the worktree path — the shell does not persist between tool calls.

## File Structure

| Action | Path | Responsibility |
|---|---|---|
| create | `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/SettingsEditBuffer.swift` | `SettingsEdits`, `SettingsEditBuffer`, `commitSettingsEdits` — the whole shared commit-at-Save unit |
| create | `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/SettingsEditBufferTests.swift` | Tests for the above (two classes: pure buffer, and the `@MainActor` commit) |
| modify | `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/SettingsErrorMessage.swift` | `+ settingsInputErrorMessage()` |
| modify | `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/SettingsErrorMessageTests.swift` | `+ 1 copy assertion` |
| modify | `ios/SecretaryMacApp/Sources/MacSettingsView.swift` | Rewire onto the shared unit; delete `commitEdits` + `syncTextFromViewModel` |
| modify | `ios/SecretaryApp/Sources/SettingsScreen.swift` | **The #459 fix**: text buffer + commit-at-Save + extracted message area |

---

### Task 1: `SettingsEditBuffer` — seed and parse

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/SettingsEditBuffer.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/SettingsEditBufferTests.swift`

**Interfaces:**
- Consumes: nothing (pure Foundation).
- Produces: `SettingsEdits(retentionDays: Int, graceMinutes: Int)` (`Equatable, Sendable`); `SettingsEditBuffer` with `var retentionText: String`, `var graceText: String`, `init()`, `mutating func seed(retentionDays: Int, graceMinutes: Int)`, `func parsed() -> SettingsEdits?`.

- [ ] **Step 1: Write the failing tests**

Create `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/SettingsEditBufferTests.swift`:

```swift
import XCTest
@testable import SecretaryVaultAccessUI

final class SettingsEditBufferTests: XCTestCase {

    // MARK: seed

    func testInitStartsEmpty() {
        let b = SettingsEditBuffer()
        XCTAssertEqual(b.retentionText, "")
        XCTAssertEqual(b.graceText, "")
    }

    func testSeedRendersUngroupedDigits() {
        // The largest in-range retention is the interesting case: a grouping locale
        // would render 3650 as "3,650", which `parsed()` deliberately rejects. Seed
        // must therefore always emit bare digits, or a seed→parse round trip breaks.
        var b = SettingsEditBuffer()
        b.seed(retentionDays: 3650, graceMinutes: 0)
        XCTAssertEqual(b.retentionText, "3650")
        XCTAssertEqual(b.graceText, "0")
    }

    func testSeedThenParseRoundTrips() {
        var b = SettingsEditBuffer()
        b.seed(retentionDays: 3650, graceMinutes: 60)
        XCTAssertEqual(b.parsed(), SettingsEdits(retentionDays: 3650, graceMinutes: 60))
    }

    // MARK: parsed

    func testParsesPlainIntegers() {
        var b = SettingsEditBuffer()
        b.retentionText = "45"
        b.graceText = "7"
        XCTAssertEqual(b.parsed(), SettingsEdits(retentionDays: 45, graceMinutes: 7))
    }

    func testTrimsSurroundingWhitespace() {
        var b = SettingsEditBuffer()
        b.retentionText = " 45 "
        b.graceText = "\t7 "
        XCTAssertEqual(b.parsed(), SettingsEdits(retentionDays: 45, graceMinutes: 7))
    }

    func testRejectsClearedField() {
        // The second #459 hole: a cleared field must NOT silently fall back to the
        // previously committed value.
        var b = SettingsEditBuffer()
        b.retentionText = ""
        b.graceText = "7"
        XCTAssertNil(b.parsed(), "cleared retention must not parse")

        b.retentionText = "45"
        b.graceText = ""
        XCTAssertNil(b.parsed(), "cleared grace must not parse")
    }

    func testRejectsWhitespaceOnlyField() {
        var b = SettingsEditBuffer()
        b.retentionText = "   "
        b.graceText = "7"
        XCTAssertNil(b.parsed())
    }

    func testRejectsNonNumericTextInEitherField() {
        // "3,650" is the load-bearing one: it is exactly what a grouping locale
        // would produce, and accepting it would reintroduce silent coercion.
        for bad in ["abc", "1.5", "3,650", "45d", "0x1f"] {
            var b = SettingsEditBuffer()
            b.retentionText = bad
            b.graceText = "7"
            XCTAssertNil(b.parsed(), "retention \(bad) must not parse")

            b.retentionText = "45"
            b.graceText = bad
            XCTAssertNil(b.parsed(), "grace \(bad) must not parse")
        }
    }

    func testAcceptsSignedValuesForTheClampToAbsorb() {
        // `Int(_:)` accepts a sign; out-of-range values are the view model's clamp
        // to deal with, not a parse failure. Pinned so the split of responsibility
        // stays deliberate.
        var b = SettingsEditBuffer()
        b.retentionText = "-5"
        b.graceText = "+7"
        XCTAssertEqual(b.parsed(), SettingsEdits(retentionDays: -5, graceMinutes: 7))
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd /Users/hherb/src/secretary/.worktrees/459-ios-settings-commit-at-save/ios/SecretaryVaultAccess && swift test --filter SettingsEditBufferTests
```

Expected: compile failure — `cannot find 'SettingsEditBuffer' in scope`.

- [ ] **Step 3: Write the implementation**

Create `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/SettingsEditBuffer.swift`:

```swift
import Foundation

/// The two numeric Settings inputs, parsed but **not** clamped to the vault's
/// projected bounds. Clamping belongs to `SettingsViewModel.setRetentionDays` /
/// `setGraceMinutes`, so this type carries no bounds dependency and stays trivially
/// testable.
public struct SettingsEdits: Equatable, Sendable {
    public let retentionDays: Int
    public let graceMinutes: Int

    public init(retentionDays: Int, graceMinutes: Int) {
        self.retentionDays = retentionDays
        self.graceMinutes = graceMinutes
    }
}

/// Raw text for the two numeric Settings inputs, held as view `@State` and
/// committed explicitly at Save.
///
/// **Why a text buffer instead of `TextField(value:format:)`.** That form commits
/// its binding only on Return or focus loss, and neither platform's Save button
/// reliably moves first responder first: an AppKit button click does not, and on
/// iOS `.keyboardType(.numberPad)` has no Return key at all, leaving focus loss as
/// the only commit trigger. A typed-then-tapped Save would therefore persist the
/// PREVIOUS value while the field still displayed the new one. The same binding
/// also leaves the bound value untouched when a parse fails, so CLEARING a field
/// would silently re-save the old value against a visibly empty box. Both break the
/// WYSIWYG contract `SettingsViewModel.save()` documents for itself — "whatever
/// value the screen shows is exactly what is written". Buffering the raw text and
/// committing explicitly at Save makes both paths deterministic. (#458 macOS,
/// #459 iOS.)
///
/// A `@FocusState`-defocus-before-save fix was considered and rejected in #458: the
/// focus resignation flushes on the next view update, so it races the
/// `Task { await save() }`.
public struct SettingsEditBuffer: Equatable, Sendable {
    public var retentionText: String
    public var graceText: String

    /// Both fields empty. Views construct this as `@State` and call `seed` from
    /// `.onAppear` once `SettingsViewModel.load()` has populated the view model.
    public init() {
        retentionText = ""
        graceText = ""
    }

    /// Render committed view-model values back into the fields as ungrouped digits.
    /// Called after `load()` and after every successful commit, so the display always
    /// matches the value that was — or is about to be — written.
    public mutating func seed(retentionDays: Int, graceMinutes: Int) {
        retentionText = String(retentionDays)
        graceText = String(graceMinutes)
    }

    /// Both fields as whole numbers, or `nil` if **either** is unparseable.
    ///
    /// Plain `Int(_:)` rather than a locale-aware `FormatStyle`: retention tops out
    /// at 3650 days, so a grouping locale could render or accept "3,650". `seed`
    /// only ever emits ungrouped digits, so a grouped value is necessarily
    /// hand-typed, and failing loudly beats silent coercion — which is the point of
    /// this whole path. Revisit if these fields are ever properly localized (#433).
    ///
    /// A sign is accepted (`Int("-5") == -5`) and absorbed by the view model's
    /// clamp. Only genuinely non-numeric text — including empty and
    /// whitespace-only — fails here.
    public func parsed() -> SettingsEdits? {
        guard let days = Int(retentionText.trimmingCharacters(in: .whitespaces)),
              let minutes = Int(graceText.trimmingCharacters(in: .whitespaces)) else {
            return nil
        }
        return SettingsEdits(retentionDays: days, graceMinutes: minutes)
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd /Users/hherb/src/secretary/.worktrees/459-ios-settings-commit-at-save/ios/SecretaryVaultAccess && swift test --filter SettingsEditBufferTests
```

Expected: 9 tests, 0 failures.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/459-ios-settings-commit-at-save && \
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/SettingsEditBuffer.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/SettingsEditBufferTests.swift && \
git commit -m "feat(459): SettingsEditBuffer — host-tested seed/parse for the numeric Settings fields

Pure value type backing the commit-at-Save treatment on both Settings
screens. parsed() rejects empty, whitespace-only, and non-numeric text
(including locale-grouped \"3,650\"); seed() only ever emits ungrouped
digits so the round trip is closed.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 2: `commitSettingsEdits` — clamping commit with re-seed

**Files:**
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/SettingsEditBuffer.swift` (append)
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/SettingsEditBufferTests.swift` (append a second class)

**Interfaces:**
- Consumes: `SettingsEditBuffer` / `SettingsEdits` (Task 1); `SettingsViewModel.setRetentionDays(_:)`, `.setGraceMinutes(_:)`, `.retentionDays`, `.graceMinutes` (existing, unmodified).
- Produces: `@MainActor func commitSettingsEdits(_ buffer: inout SettingsEditBuffer, into vm: SettingsViewModel) -> Bool`.

- [ ] **Step 1: Write the failing tests**

Append to `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/SettingsEditBufferTests.swift`, and add the two extra imports to the top of that file so it reads `import XCTest` / `@testable import SecretaryVaultAccessUI` / `import SecretaryVaultAccess` / `import SecretaryVaultAccessTesting`:

```swift
@MainActor
final class CommitSettingsEditsTests: XCTestCase {
    /// A view model over the standard fakes. `commitSettingsEdits` never touches the
    /// gate (it runs strictly before any `save()`), so the gate here only has to
    /// exist — its behaviour is exercised in `SettingsViewModelTests`.
    private func makeVM() -> SettingsViewModel {
        let gate = RetargetableReauthGate(
            window: .seconds(120),
            initialAuthAt: nil,
            clock: { MonotonicInstant(nanoseconds: 7_000_000) },
            makeDelegate: { _, _ in FakeWriteReauthGate() })
        return SettingsViewModel(port: FakeSettingsPort(), gate: gate)
    }

    func testCommitPushesTypedValuesIntoViewModel() {
        let vm = makeVM()
        var b = SettingsEditBuffer()
        b.retentionText = "45"
        b.graceText = "7"

        XCTAssertTrue(commitSettingsEdits(&b, into: vm))
        XCTAssertEqual(vm.retentionDays, 45)
        XCTAssertEqual(vm.graceMinutes, 7)
    }

    func testCommitClampsAndReSeedsBufferToClampedValues() {
        // Display == what is written. Out-of-range input clamps, and the fields are
        // rewritten to the CLAMPED values rather than left showing what was typed —
        // otherwise the screen would claim 9999 days while 3650 was persisted.
        let vm = makeVM()
        var b = SettingsEditBuffer()
        b.retentionText = "9999"
        b.graceText = "999"

        XCTAssertTrue(commitSettingsEdits(&b, into: vm))
        XCTAssertEqual(vm.retentionDays, 3650)
        XCTAssertEqual(vm.graceMinutes, 60)
        XCTAssertEqual(b.retentionText, "3650")
        XCTAssertEqual(b.graceText, "60")
    }

    func testCommitWritesNothingOnUnparseableInput() {
        // The #459 regression test. A refused commit is all-or-nothing: neither the
        // view model nor the buffer moves, so the caller cannot go on to save a
        // value the user never typed.
        let vm = makeVM()
        vm.setRetentionDays(45)
        vm.setGraceMinutes(7)
        var b = SettingsEditBuffer()
        b.retentionText = "abc"
        b.graceText = "30"

        XCTAssertFalse(commitSettingsEdits(&b, into: vm))
        XCTAssertEqual(vm.retentionDays, 45, "no write on a refused commit")
        XCTAssertEqual(vm.graceMinutes, 7, "the PARSEABLE field must not be committed either")
        XCTAssertEqual(b.retentionText, "abc", "buffer left as typed so the user can correct it")
        XCTAssertEqual(b.graceText, "30")
    }

    func testCommitOnClearedFieldDoesNotWriteStaleValue() {
        // The cleared-field hole, end to end: the old value must not be re-written
        // behind a visibly empty box.
        let vm = makeVM()
        vm.setGraceMinutes(30)
        var b = SettingsEditBuffer()
        b.seed(retentionDays: vm.retentionDays, graceMinutes: vm.graceMinutes)
        b.graceText = ""

        XCTAssertFalse(commitSettingsEdits(&b, into: vm))
        XCTAssertEqual(vm.graceMinutes, 30, "stale value not re-written")
        XCTAssertEqual(b.graceText, "", "still empty — the view surfaces an input error")
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd /Users/hherb/src/secretary/.worktrees/459-ios-settings-commit-at-save/ios/SecretaryVaultAccess && swift test --filter CommitSettingsEditsTests
```

Expected: compile failure — `cannot find 'commitSettingsEdits' in scope`.

- [ ] **Step 3: Write the implementation**

Append to `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/SettingsEditBuffer.swift`:

```swift
/// Parse `buffer`, push both values through the view model's clamping setters, then
/// re-seed `buffer` from the now-CLAMPED view-model values so the fields display
/// exactly what is about to be written.
///
/// Returns `false` — writing nothing, leaving `buffer` untouched — if either field
/// is unparseable. Callers surface that as an input error and MUST NOT go on to call
/// `SettingsViewModel.save()`.
///
/// The commit is all-or-nothing on purpose: a half-applied edit (one good field
/// written, one bad field refused) would persist a combination the user never saw.
///
/// Deliberately runs BEFORE the re-auth gate at the call site. It can only ever
/// refuse, and `RetargetableReauthGate` holds its own window rather than reading
/// `graceMinutes`, so ordering it ahead of the gate cannot affect gate strength —
/// while it does avoid raising a biometric prompt only to fail on garbage input.
@MainActor
public func commitSettingsEdits(_ buffer: inout SettingsEditBuffer,
                                into vm: SettingsViewModel) -> Bool {
    guard let edits = buffer.parsed() else { return false }
    vm.setRetentionDays(edits.retentionDays)
    vm.setGraceMinutes(edits.graceMinutes)
    buffer.seed(retentionDays: vm.retentionDays, graceMinutes: vm.graceMinutes)
    return true
}
```

- [ ] **Step 4: Run the whole package suite**

```bash
cd /Users/hherb/src/secretary/.worktrees/459-ios-settings-commit-at-save/ios/SecretaryVaultAccess && swift test
```

Expected: 326 baseline + 13 new = **339 tests, 0 failures**.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/459-ios-settings-commit-at-save && \
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/SettingsEditBuffer.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/SettingsEditBufferTests.swift && \
git commit -m "feat(459): commitSettingsEdits — all-or-nothing clamping commit with re-seed

Parses the buffer, pushes both values through the view model's clamping
setters, and re-seeds the buffer from the clamped values so the display
and the persisted value are identical. Refuses without writing anything
if either field is unparseable — the #459 regression test.

SettingsViewModel is untouched: the commit runs before the re-auth gate,
which holds its own window and never reads graceMinutes, so gate strength
is unaffected.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 3: Shared input-error copy

**Files:**
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/SettingsErrorMessage.swift` (append)
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/SettingsErrorMessageTests.swift` (append into the existing `SettingsErrorMessageTests` class)

**Interfaces:**
- Consumes: nothing.
- Produces: `func settingsInputErrorMessage() -> String`.

- [ ] **Step 1: Write the failing test**

Append inside the existing `final class SettingsErrorMessageTests: XCTestCase { … }` in `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/SettingsErrorMessageTests.swift`:

```swift
    // Unparseable input never reaches the view model, so this copy has no
    // VaultAccessError to map — it is a fixed string, pinned here so both Settings
    // screens keep saying the same thing. "Each" not "Both": it fires when EITHER
    // field is bad.
    func testInputErrorMessageAsksForAWholeNumberAndSaysNotSaved() {
        XCTAssertEqual(
            settingsInputErrorMessage(),
            "Each field needs a whole number — settings were not saved.")
    }
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /Users/hherb/src/secretary/.worktrees/459-ios-settings-commit-at-save/ios/SecretaryVaultAccess && swift test --filter SettingsErrorMessageTests
```

Expected: compile failure — `cannot find 'settingsInputErrorMessage' in scope`.

- [ ] **Step 3: Write the implementation**

Append to `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/SettingsErrorMessage.swift`:

```swift
/// Shown when a Settings numeric field doesn't hold a whole number at Save time.
///
/// A free function returning a fixed string rather than an arm of
/// `settingsErrorMessage`: unparseable text is refused by `commitSettingsEdits`
/// before it reaches the view model, so there is no `VaultAccessError` to map. The
/// views hold it in local state and clear it on every Save attempt.
///
/// "Each" not "Both": this fires when EITHER field is unparseable, and "Both fields
/// need…" reads as a diagnosis that both are wrong, sending the user hunting at the
/// valid one. Naming the offending field would be nicer still, but that is extra
/// branching on a render-untested path (#417) — deliberately not done.
public func settingsInputErrorMessage() -> String {
    "Each field needs a whole number — settings were not saved."
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd /Users/hherb/src/secretary/.worktrees/459-ios-settings-commit-at-save/ios/SecretaryVaultAccess && swift test --filter SettingsErrorMessageTests
```

Expected: 4 tests in `SettingsErrorMessageTests`, 0 failures.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/459-ios-settings-commit-at-save && \
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/SettingsErrorMessage.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/SettingsErrorMessageTests.swift && \
git commit -m "feat(459): share the Settings input-error copy across both platforms

Lifts the string macOS held inline into the module that already owns
user-facing settings copy, so iOS and macOS cannot drift.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 4: Rewire `MacSettingsView` onto the shared unit

Done before the iOS fix on purpose: macOS is the platform where this behaviour already works, so if the shared unit is wrong it fails here first, against a known-good baseline.

**Files:**
- Modify: `ios/SecretaryMacApp/Sources/MacSettingsView.swift`

**Interfaces:**
- Consumes: `SettingsEditBuffer` (Task 1), `commitSettingsEdits` (Task 2), `settingsInputErrorMessage()` (Task 3).
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Replace the two text `@State` properties with the buffer**

Replace this block (the `@State private var retentionText` / `graceText` declarations and the long doc comment above them, currently at roughly lines 23–37):

```swift
    /// Live text for the two numeric inputs, seeded from the VM after `load()`
    /// and pushed back into the VM by `commitEdits()` at Save.
    ///
    /// These are deliberately NOT `TextField(value:format:)` bindings. That form
    /// commits its binding only on Return or focus loss, and an AppKit button
    /// click does not move first responder — so a typed-then-mouse-clicked Save
    /// would persist the PREVIOUS value while the field still displayed the new
    /// one, breaking the WYSIWYG contract `SettingsViewModel.save()` documents
    /// ("whatever value the screen shows is exactly what is written"). It would
    /// also silently save the old value when the user cleared the field, since a
    /// failed parse leaves the bound value untouched. Buffering the raw text and
    /// committing explicitly at Save makes both paths deterministic.
    @State private var retentionText = ""
    @State private var graceText = ""
```

with:

```swift
    /// Live text for the two numeric inputs, seeded from the VM after `load()` and
    /// pushed back into it by `commitSettingsEdits` at Save. See `SettingsEditBuffer`
    /// for why these are buffered rather than bound with `TextField(value:format:)`.
    @State private var edits = SettingsEditBuffer()
```

- [ ] **Step 2: Repoint the two `TextField`s at the buffer**

`TextField("Days", text: $retentionText)` becomes `TextField("Days", text: $edits.retentionText)`.
`TextField("Minutes", text: $graceText)` becomes `TextField("Minutes", text: $edits.graceText)`.

Leave every attached modifier (`.labelsHidden()`, `.multilineTextAlignment(.trailing)`, `.frame(maxWidth: 80)`) and the surrounding comments exactly as they are.

- [ ] **Step 3: Rewrite `save()` and delete the two now-shared helpers**

Replace `save()`, `commitEdits()` and `syncTextFromViewModel()` (the final three methods of the file) with just:

```swift
    /// Commit the typed text into the VM, then save. On unparseable input nothing is
    /// written — surfacing that beats persisting a value the user never typed.
    /// `commitSettingsEdits` re-seeds the fields to the clamped values on success, so
    /// the display and the value being written stay identical.
    private func save() {
        inputError = nil
        guard commitSettingsEdits(&edits, into: viewModel) else {
            inputError = settingsInputErrorMessage()
            return
        }
        Task { await viewModel.save() }
    }
```

Keep the `@State private var inputError: String?` declaration and its comment, and keep the `inputError`-vs-banner precedence block in `body` untouched.

- [ ] **Step 4: Update `.onAppear`**

```swift
        .onAppear {
            viewModel.load()
            edits.seed(retentionDays: viewModel.retentionDays, graceMinutes: viewModel.graceMinutes)
        }
```

- [ ] **Step 5: Verify the macOS host tests and app compile**

```bash
cd /Users/hherb/src/secretary/.worktrees/459-ios-settings-commit-at-save && bash ios/scripts/run-macos-tests.sh
```

Expected: `** TEST SUCCEEDED **` and `** BUILD SUCCEEDED **`. This is the `macos-host.yml` CI gate.

If this is a cold worktree the first run cross-compiles the Rust staticlib and takes several minutes with no output. Run it in the background and poll the log rather than blocking.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/459-ios-settings-commit-at-save && \
git add ios/SecretaryMacApp/Sources/MacSettingsView.swift && \
git commit -m "refactor(459): MacSettingsView onto the shared SettingsEditBuffer

Drops the view-local commitEdits()/syncTextFromViewModel() in favour of
the host-tested shared unit. Behaviour is unchanged; the logic it used to
own is now covered by SettingsEditBufferTests.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 5: Fix `SettingsScreen` (iOS) — the #459 defect

**Files:**
- Modify: `ios/SecretaryApp/Sources/SettingsScreen.swift`

**Interfaces:**
- Consumes: `SettingsEditBuffer` (Task 1), `commitSettingsEdits` (Task 2), `settingsInputErrorMessage()` (Task 3).
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Mark the view `@MainActor` and swap the bindings for the buffer**

`commitSettingsEdits` is `@MainActor`, and `save()` is a plain method rather than part of `body`, so the struct needs explicit isolation exactly as `MacSettingsView` already has. Change:

```swift
struct SettingsScreen: View {
```

to:

```swift
@MainActor
struct SettingsScreen: View {
```

Then delete the two computed bindings entirely:

```swift
    private var retentionBinding: Binding<Int> {
        Binding(get: { viewModel.retentionDays }, set: { viewModel.setRetentionDays($0) })
    }
    private var graceBinding: Binding<Int> {
        Binding(get: { viewModel.graceMinutes }, set: { viewModel.setGraceMinutes($0) })
    }
```

and add these two properties next to `@State private var confirmForget = false`:

```swift
    /// Live text for the two numeric inputs, seeded from the VM after `load()` and
    /// pushed back into it by `commitSettingsEdits` at Save. See `SettingsEditBuffer`
    /// for why these are buffered rather than bound with `TextField(value:format:)`
    /// (#459 — on iOS the number pad has no Return key, so focus loss is the only
    /// commit trigger a `value:format:` binding gets).
    @State private var edits = SettingsEditBuffer()
    /// Set when a field doesn't hold a whole number at Save time. View-local on
    /// purpose: unparseable text never reaches the VM, so it has no VM error to
    /// surface. Cleared on every Save attempt.
    @State private var inputError: String?
```

- [ ] **Step 2: Extract the message area into a `@ViewBuilder` property**

Add this property to the struct (place it just above `var body`):

```swift
    /// The Form's shared message area. Extracted from `body` rather than written
    /// inline: `body` on this screen is already near SwiftUI's expression
    /// type-check ceiling, where one more nested branch trips "unable to type-check
    /// in reasonable time" (exit 65).
    ///
    /// `inputError` describes the most recent Save attempt, which was refused before
    /// reaching the VM — so the VM's banner/error still hold the PREVIOUS attempt's
    /// outcome and are shown only when there is no input error. Without this, a
    /// bad-input Save after a good one would render "Settings saved" directly above
    /// "not saved" (the VM clears its own banner inside `save()`, which this path
    /// never calls, and `banner` is private(set) so the view cannot clear it).
    /// Mirrors the same precedence rule in `MacSettingsView`.
    @ViewBuilder private var messages: some View {
        if let inputError {
            Text(inputError)
                .font(.footnote).foregroundStyle(Color.red)
                .accessibilityIdentifier("settings-input-error")
        } else {
            if let banner = viewModel.banner {
                Text(banner.text)
                    .font(.footnote).foregroundStyle(Color.secondary)
                    .accessibilityIdentifier("settings-notice")
            }
            if let error = viewModel.error {
                Text(settingsErrorMessage(error))
                    .font(.footnote).foregroundStyle(Color.red)
                    .accessibilityIdentifier("settings-error")
            }
        }
    }
```

Then replace the corresponding block at the top of the `Form` in `body`:

```swift
            if let banner = viewModel.banner {
                Text(banner.text)
                    .font(.footnote).foregroundStyle(Color.secondary)
                    .accessibilityIdentifier("settings-notice")
            }
            if let error = viewModel.error {
                Text(settingsErrorMessage(error))
                    .font(.footnote).foregroundStyle(Color.red)
                    .accessibilityIdentifier("settings-error")
            }
```

with a single line:

```swift
            messages
```

- [ ] **Step 3: Repoint both `TextField`s at the buffer**

`TextField("Days", value: retentionBinding, format: .number)` becomes `TextField("Days", text: $edits.retentionText)`.
`TextField("Minutes", value: graceBinding, format: .number)` becomes `TextField("Minutes", text: $edits.graceText)`.

Keep every attached modifier exactly as-is — in particular `.keyboardType(.numberPad)`, `.multilineTextAlignment(.trailing)`, `.frame(maxWidth: 80)` and both `.accessibilityIdentifier` hooks.

- [ ] **Step 4: Route the Save button through a `save()` method**

Replace the Save button's action:

```swift
                Button {
                    Task { await viewModel.save() }
                } label: {
                    Text("Save")
                }
```

with:

```swift
                Button {
                    save()
                } label: {
                    Text("Save")
                }
```

and add this method at the end of the struct, after `body`:

```swift
    /// Commit the typed text into the VM, then save. On unparseable input nothing is
    /// written — surfacing that beats persisting a value the user never typed.
    /// `commitSettingsEdits` re-seeds the fields to the clamped values on success, so
    /// the display and the value being written stay identical.
    private func save() {
        inputError = nil
        guard commitSettingsEdits(&edits, into: viewModel) else {
            inputError = settingsInputErrorMessage()
            return
        }
        Task { await viewModel.save() }
    }
```

- [ ] **Step 5: Seed the buffer in `.onAppear`**

Replace `.onAppear { viewModel.load() }` with:

```swift
        .onAppear {
            viewModel.load()
            edits.seed(retentionDays: viewModel.retentionDays, graceMinutes: viewModel.graceMinutes)
        }
```

- [ ] **Step 6: Verify the iOS app compiles**

```bash
cd /Users/hherb/src/secretary/.worktrees/459-ios-settings-commit-at-save && bash ios/scripts/build-app.sh
```

Expected: `** BUILD SUCCEEDED **`.

If this fails with *"unable to type-check this expression in reasonable time"* (exit 65) on `SettingsScreen.swift`, the fix is to extract more of `body` into additional `@ViewBuilder` properties — one per `Section` — not to simplify the logic. Do not revert the message extraction.

- [ ] **Step 7: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/459-ios-settings-commit-at-save && \
git add ios/SecretaryApp/Sources/SettingsScreen.swift && \
git commit -m "fix(459): commit-at-Save for the iOS Settings numeric fields

TextField(value:format:) commits only on Return or focus loss, and the
number pad has no Return key, so tapping the in-Form Save button could
persist the PREVIOUS value while the field showed the newly typed one —
and clearing a field silently re-saved the old value. Both broke the
WYSIWYG contract SettingsViewModel.save() documents, and the grace-window
field is the security-relevant one (a user who believes they set grace to
0 would keep the old, wider window).

Switches both fields to text bindings over the shared SettingsEditBuffer
and commits explicitly at Save. Mirrors the macOS treatment from #458.
The message area moves into a @ViewBuilder property to stay under
SwiftUI's expression type-check ceiling.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 6: Full acceptance sweep

**Files:** none modified (verification only, plus a docs update if warranted).

- [ ] **Step 1: Run the host suite**

```bash
cd /Users/hherb/src/secretary/.worktrees/459-ios-settings-commit-at-save/ios/SecretaryVaultAccess && swift test
```

Expected: **340 tests, 0 failures** (326 baseline + 14 new: 9 from Task 1, 4 from Task 2, 1 from Task 3).

- [ ] **Step 2: Run the iOS app compile and the SecretaryKit iOS tests**

```bash
cd /Users/hherb/src/secretary/.worktrees/459-ios-settings-commit-at-save && bash ios/scripts/build-app.sh
cd /Users/hherb/src/secretary/.worktrees/459-ios-settings-commit-at-save && bash ios/scripts/run-ios-tests.sh
```

Expected: `** BUILD SUCCEEDED **`; SecretaryKit 52 tests passing, `** TEST SUCCEEDED **`.

- [ ] **Step 3: Run the macOS host + app compile**

```bash
cd /Users/hherb/src/secretary/.worktrees/459-ios-settings-commit-at-save && bash ios/scripts/run-macos-tests.sh
```

Expected: `** TEST SUCCEEDED **` and `** BUILD SUCCEEDED **`.

- [ ] **Step 4: Confirm no Rust surface was touched**

```bash
cd /Users/hherb/src/secretary/.worktrees/459-ios-settings-commit-at-save && git diff --name-only main... | grep -E '^(core|ffi)/' || echo "clean — no core/ffi change, Rust gates not required"
```

Expected: `clean — no core/ffi change, Rust gates not required`.

- [ ] **Step 5: Check whether README/ROADMAP need updating**

#459 is a bug fix to an already-shipped screen — no new capability, no status change. Neither doc tracks per-bug state, and its siblings (#417, #433) are not listed in either. Expected outcome: **no change**. Record the decision either way in the handoff.

---

## Notes for the implementer

- **`swift test` in `ios/SecretaryVaultAccess` needs no xcframework** — the package is FFI-free, so the inner loop is fast. Only `build-app.sh` / `run-ios-tests.sh` / `run-macos-tests.sh` cross-compile Rust, and only on a cold worktree.
- **The shell does not persist between tool calls.** Every command above spells out its `cd`. A background script invocation without one runs from wherever the last foreground `cd` landed.
- **Edit tool paths must spell out `.worktrees/459-ios-settings-commit-at-save/…`** — a bare `ios/…` path edits the main checkout instead.
- **If a task appears to require editing `SettingsViewModel.swift`, stop.** That is a plan error, not a licence — see Global Constraints.
