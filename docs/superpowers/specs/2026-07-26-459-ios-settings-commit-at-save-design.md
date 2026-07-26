# Design — #459: commit-at-Save for the iOS Settings numeric fields

**Date:** 2026-07-26
**Issue:** [#459](https://github.com/hherb/secretary/issues/459) — *iOS Settings: `TextField(value:format:)` may save a stale value on tap-Save (macOS analogue fixed in #458)*
**Branch:** `feature/459-ios-settings-commit-at-save`

## Problem

`ios/SecretaryApp/Sources/SettingsScreen.swift` binds both numeric inputs with
`TextField(value:format:)`:

```swift
TextField("Days",    value: retentionBinding, format: .number).keyboardType(.numberPad)
TextField("Minutes", value: graceBinding,     format: .number).keyboardType(.numberPad)
```

That form commits its binding on Return or focus loss, not per keystroke. Two holes follow:

1. **Stale save.** Tapping the in-`Form` Save button does not reliably resign the field's
   first-responder status first, so a typed-then-tapped Save can persist the *previous*
   value while the field still displays the newly typed one. `.keyboardType(.numberPad)`
   sharpens this on iOS specifically: a number pad has no Return key, so focus loss is the
   *only* commit trigger.
2. **Cleared field.** Clearing a field makes the parse fail, which leaves the bound value
   untouched — so Save silently writes the old value against a visibly empty field.

Both break the WYSIWYG contract `SettingsViewModel.save()` documents for itself: *"The two
edited fields (retention / grace) are WYSIWYG from the bound controls — whatever value the
screen shows is exactly what is written."* The VM keeps its side of the bargain; the view
does not.

The grace-window field is the security-relevant one. A user who believes they set grace to
`0` (re-authenticate every write) while the old, wider window is what actually persisted has
a real — if narrow — security-expectation gap, not merely a UX papercut.

**Status of the evidence:** analysis-derived, not smoke-observed. Neither Settings screen has
render-layer coverage (#417). Hole 2 is provable by inspection (a failed `Int` parse leaves
the binding untouched); hole 1 rests on documented SwiftUI first-responder behaviour. On-device
confirmation is deliberately **out of scope for this slice** (see Non-goals).

## Prior art

PR #458 (D.5.4) hit the same defect on `MacSettingsView` and fixed it by buffering the raw
text and committing explicitly at Save: `@State` `retentionText` / `graceText` bound with
`TextField(text:)` (updates per keystroke), a `commitEdits()` that trims + parses + pushes
through the VM's clamping setters and returns `false` on unparseable input, and a re-seed
from the clamped VM values after a successful commit.

A `@FocusState`-defocus-before-save fix was considered and **rejected** in #458: the focus
resignation flushes on the next view update, so it races the `Task { await save() }`.

This design ports that behaviour to iOS and lifts the shared parts into a host-tested unit.

## Approach: shared buffer + commit helper, `SettingsViewModel` untouched

### Why not put the buffer in the view model

Considered and rejected. Moving the text buffers into `SettingsViewModel` would produce the
thinnest views and would let the macOS `inputError`-vs-banner precedence workaround be
deleted. It was rejected on **security** grounds:

- The asset being protected is `save()`'s ordering invariant — gate against the *current*
  (pre-save) grace window → re-read the persisted settings → write → retarget the gate only
  on success. This is what stops a user at an unlocked-but-unattended session outside the
  grace window from widening their own window to self-authorize the widening.
- `RetargetableReauthGate` holds its **own** window and never reads `viewModel.graceMinutes`
  (verified: `authorizeWrite` delegates to an inner gate constructed with a fixed window).
  So *when* an edited value is committed is security-neutral — only changing `save()` itself
  can weaken the invariant. Leaving `save()` byte-identical is therefore a zero-regression-risk
  choice, and any alternative that rewrites its entry path is not.
- The VM-buffer design also introduces a new invariant — *every path that mutates
  `retentionDays` / `graceMinutes` must also re-seed the text buffer* — or a later `save()`
  parses stale text and writes a value the user never typed. That is the same bug class as
  #459, relocated one layer up, into the one file that carries the security ordering.

Duplicating macOS's ~15 lines into the iOS view was also rejected: it ships the fix but adds
no tests and doubles the maintenance surface, leaving the grace=0 WYSIWYG behaviour unverified
on both platforms indefinitely.

### The unit

**New — `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/SettingsEditBuffer.swift`:**

```swift
/// The two numeric Settings inputs, parsed but NOT yet clamped.
public struct SettingsEdits: Equatable, Sendable {
    public let retentionDays: Int
    public let graceMinutes: Int
}

/// Raw text for the two numeric Settings inputs, owned as view `@State`.
public struct SettingsEditBuffer: Equatable, Sendable {
    public var retentionText: String
    public var graceText: String

    /// Both fields empty. Views construct this as `@State` and `seed` in `.onAppear`
    /// after `load()`, matching the shipped macOS idiom.
    public init()
    public mutating func seed(retentionDays: Int, graceMinutes: Int)
    /// nil if EITHER field isn't a whole number (after trimming whitespace).
    public func parsed() -> SettingsEdits?
}

/// Parse the buffer, push both values through the view model's clamping setters,
/// then re-seed the buffer from the now-CLAMPED view-model values so the display
/// and the value about to be written are identical.
/// Returns false — writing nothing — if either field is unparseable.
@MainActor
public func commitSettingsEdits(_ buffer: inout SettingsEditBuffer,
                                into vm: SettingsViewModel) -> Bool
```

`seed` renders ungrouped digits (`String(Int)`). `parsed()` trims whitespace and uses plain
`Int(_:)`, deliberately **not** a locale-aware `FormatStyle`: retention tops out at 3650 days,
so a grouping locale could render or accept `"3,650"`. Since `seed` only ever emits ungrouped
digits, a grouped value is necessarily hand-typed, and failing loudly beats silent coercion —
which is the entire point of this path. Revisit if these fields are ever properly localized
(#433).

The long "why text-buffered, not `TextField(value:format:)`" rationale currently carried as a
comment in `MacSettingsView` moves onto `SettingsEditBuffer` as the shared source of truth;
each view keeps a one-line pointer to it.

**Edited — `SecretaryVaultAccessUI/SettingsErrorMessage.swift`:** add

```swift
/// Shown when a Settings numeric field doesn't hold a whole number at Save.
public func settingsInputErrorMessage() -> String
```

moving macOS's inline copy string into the module that already owns user-facing settings copy,
so both platforms share one tested string. Copy is unchanged from #458: *"Each field needs a
whole number — settings were not saved."* ("Each", not "Both": it fires when *either* field is
unparseable, and "Both fields need…" reads as a diagnosis that both are wrong, sending the user
hunting at the valid one.)

## Data flow

1. `.onAppear` → `viewModel.load()` → `edits.seed(retentionDays:graceMinutes:)` from the VM.
2. User types → `TextField(text: $edits.retentionText)` updates the buffer per keystroke.
3. Tap Save → `commitSettingsEdits(&edits, into: viewModel)`.
   - `false` → set the view-local `inputError`, return. **No gate prompt, no write.**
   - `true` → `Task { await viewModel.save() }` runs the untouched gate → re-read → write →
     retarget path.

Parsing ahead of the gate is safe and preferable: it cannot affect gate strength (the gate
never reads `graceMinutes`), it can only ever *refuse*, and it avoids raising a Face ID prompt
only to fail on garbage input.

## Error handling

| Input | Behaviour |
|---|---|
| Either field unparseable or empty | Refuse both fields; `inputError` shown; nothing written |
| Digits out of range | **Not** an error — clamped by the VM's setters, and the field re-seeds to the clamped value so the user sees what was written |
| `"3,650"` (grouped) | Hard reject — see the `FormatStyle` note above |
| Leading/trailing whitespace | Trimmed, then parsed |
| Signed (`"-5"`, `"+45"`) | Accepted by `Int(_:)`, then clamped by the VM's setters (`-5` → the range minimum). Unchanged from shipped macOS behaviour; not treated as a parse error |

iOS mirrors macOS's `inputError`-vs-banner precedence: show `inputError` alone, otherwise the
VM's banner/error. A refused Save never reaches `viewModel.save()`, so the VM's `banner` still
describes the *previous* attempt; without the precedence rule a bad-input Save following a good
one would render "Settings saved" directly above "not saved". (`banner` is `private(set)`, so
the view cannot clear it — this is why the precedence rule exists rather than a clear.)

The macOS precedence logic is **kept as-is**. Removing it would require `save()` to own the
input error, which is the VM change this design deliberately avoids.

### SwiftUI type-check hazard

`SettingsScreen.body` is already near SwiftUI's expression-type-check ceiling — one extra
modifier has previously tripped *"unable to type-check in reasonable time"* (exit 65) on this
file's neighbours. The added `if let inputError { … } else { … }` message branch therefore goes
into an extracted `@ViewBuilder private var messages: some View`, **not** inline in `body`.

## Testing

New `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/SettingsEditBufferTests.swift`:

*Pure `SettingsEditBuffer`:*
1. `seed` emits ungrouped digits (3650 → `"3650"`, no grouping separator).
2. Parses plain integers.
3. Trims surrounding whitespace.
4. **Rejects a cleared field** (hole 2), in both field positions.
5. Rejects `"abc"`, `"1.5"`, `"3,650"`.
6. Rejects when either field is bad, in both orders.

*`commitSettingsEdits` (reusing the existing fake port + gate from `SettingsViewModelTests`):*

7. Commit pushes the typed values into the view model.
8. **Commit clamps and re-seeds the buffer to the clamped values** (display == what is written).
9. **Commit writes nothing on unparseable input** — the #459 regression test: the VM retains
   its prior values and the buffer text is untouched.
10. Commit on a cleared field does not write the stale value.

Plus one copy assertion for `settingsInputErrorMessage()` in `SettingsErrorMessageTests`.

**Deliberately uncovered:** the ~3 lines of view glue per platform (`guard commitSettingsEdits(…)
else { inputError = …; return }`), which are identical on both platforms and render-untested
pending #417.

## Files

| Action | Path |
|---|---|
| new | `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/SettingsEditBuffer.swift` |
| new | `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/SettingsEditBufferTests.swift` |
| edit | `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/SettingsErrorMessage.swift` |
| edit | `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/SettingsErrorMessageTests.swift` |
| edit | `ios/SecretaryApp/Sources/SettingsScreen.swift` |
| edit | `ios/SecretaryMacApp/Sources/MacSettingsView.swift` |

No `core/` or `ffi/` change. No Android change. No FFI-surface or on-disk-format change.
`SettingsViewModel.swift` is **not** modified.

## Acceptance

```bash
cd ios/SecretaryVaultAccess && swift test     # 326 → ~337, 0 failures (FFI-free, no xcframework)
bash ios/scripts/build-app.sh                 # iOS app compile — ** BUILD SUCCEEDED **
bash ios/scripts/run-macos-tests.sh           # macOS host + app compile (the macos-host.yml CI gate)
```

Both app compiles are required because both views are edited.

## Non-goals

- **On-device confirmation of the bug or the fix.** Decided for this slice: host-only. The
  handoff carries an explicit on-device verification note. This means the issue closes on an
  inferred repro, not an observed one.
- **Render-layer tests for either Settings screen** (#417) — needs a UI-test target.
- **Localization of the numeric fields** (#433). The plain-`Int` parse is explicitly scoped to
  the un-localized status quo and flagged for revisit.
- **Any change to `SettingsViewModel`**, including removing the macOS banner-precedence
  workaround.
- **Android.** Compose `TextField` is per-keystroke, so it does not carry this defect.
