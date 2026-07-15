# Design — #434 (iOS mirror of #269): warn-but-allow on a duplicate block name

**Date:** 2026-07-15
**Issue:** #434 (follow-on to #269 / PR #432)
**Branch:** `feature/ios-block-name-guard-269` off `main` @ `2f3c0993`
**Scope:** iOS only (SwiftUI/Swift). **No `core` / crypto / FFI / on-disk-format / error-variant change; no Rust touched.** Write path (`VaultBrowseViewModel.confirmBlockName`) is unchanged.

## Problem

PR #432 shipped a warn-but-allow guard on the **Android** block create/rename dialog: a duplicate display name shows an inline warning and relabels the confirm "Save" → "Save anyway"; a single deliberate tap still commits. iOS still **silently allows** two blocks to share a display name, so the block list and move picker read ambiguously. The #432 handoff recorded this as an intended, temporary parity gap — this slice closes it.

## Decision (preserved verbatim from #269 / PR #432 — do NOT re-litigate)

**Warn-but-allow**, **case-insensitive**, **trimmed candidate**, **one-tap "Save anyway"**.

Block-name uniqueness is **not** a correctness requirement: blocks are UUID-keyed and the FFI deliberately permits duplicate names (functionally harmless). This is a **render-layer affordance only** — the write path stays untouched and duplicate names remain writable. Contrast the record **field-name** hard-reject (`DuplicateFieldName`), where uniqueness *is* load-bearing because the bridge diffs fields by name.

- **Why not hard-reject:** it would remove the legitimate per-context duplicate-name use #269 calls out. Warn-but-allow also mirrors the repo's contacts "delete ≠ revoke" idiom.
- **Why case-insensitive:** a name differing only in case reads as an accidental near-duplicate.
- **Why one-tap:** the warning shows inline *first* (as the user types), so the relabeled "Save anyway" tap is itself the informed confirmation — no press-twice state machine.

## The iOS-specific fork: `.alert` cannot host a live warning

The Android affordance lives in a Compose `AlertDialog` whose content is a fully-dynamic `Column`: the warning and the button relabel recompute on every keystroke.

The current iOS block-name dialog is a SwiftUI `.alert` (`VaultBrowseScreen.swift`). `.alert` is UIKit-backed (`UIAlertController`), which **cannot update its button titles or message after presentation**, and its content closure only renders `TextField`s and `Button`s (a standalone warning `Text` is ignored). Therefore the decided UX — *live inline warning + one-tap "Save anyway" relabel* — **cannot be delivered inside the existing `.alert`.**

**Resolution (user decision):** replace the `.alert` with a custom `.sheet`-presented SwiftUI view (`BlockNameSheet`). A `.sheet` presents a real SwiftUI hierarchy that updates reactively with state, giving true parity with Android's live warn-but-allow UX, and (bonus) makes a future ViewInspector render test (#417) tractable.

## Architecture — three units, layered for host-testability

Only the SwiftUI render layer stays untested — the accepted #417-class gap. The collision *logic* and the create-vs-rename *wiring* both live below the view, where `swift test` covers them.

### Unit 1 — pure fn `BlockNamePolicy.hasNameCollision`

New file `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/BlockNamePolicy.swift`. FFI-free, mirror-named after `MovePolicy`. Direct port of Android `blockNameCollides`:

```swift
public enum BlockNamePolicy {
    /// True when `candidate` (trimmed) case-insensitively matches the name of some block in
    /// `existing` OTHER than `excludeUuid`. Locale-independent case fold. Mirror of Android
    /// `blockNameCollides`. UX-only: the write path always allows duplicate names.
    public static func hasNameCollision(candidate: String,
                                        existing: [BlockSummary],
                                        excludeUuid: [UInt8]? = nil) -> Bool
}
```

Semantics (parity with Android):
- Trim `candidate` (`.whitespacesAndNewlines`); **blank → `false`** (the blank-name guard in `confirmBlockName` owns that case).
- Compare **case-insensitively, locale-independently** via `caseInsensitiveCompare(_:) == .orderedSame` — deliberately **not** `localizedCaseInsensitiveCompare` (Turkish-i-class locale bugs), the Swift analogue of Android's `equals(ignoreCase = true)` over `lowercase(Locale.getDefault())`.
- Compare against `block.name` **untrimmed** — stored names are already trimmed on write. This can only ever *under*-warn (never falsely warn) if some other client stored an untrimmed name. Documented assumption.
- `excludeUuid` self-exclusion (the block being renamed; `nil` on create) so a no-op rename never warns.

### Unit 2 — VM wiring `VaultBrowseViewModel.blockNameCollides(_:)`

```swift
/// True when `candidate` collides with an existing block name (case-insensitive, trimmed),
/// excluding the block currently being renamed. Drives the sheet's warn-but-allow affordance;
/// the write path (`confirmBlockName`) is unchanged — duplicates remain writable.
public func blockNameCollides(_ candidate: String) -> Bool {
    let excludeUuid: [UInt8]?
    switch blockNameDialog {
    case .rename(let block): excludeUuid = block.uuid
    case .create, .none:     excludeUuid = nil
    }
    return BlockNamePolicy.hasNameCollision(candidate: candidate, existing: blocks, excludeUuid: excludeUuid)
}
```

The create-vs-rename exclude selection is the one non-trivial piece of wiring; keeping it in the VM (not the view) makes it **host-testable**. `.none` is unreachable in practice (the view only calls this while the sheet is open) but defaults to `nil` exclude for definedness.

### Unit 3 — render `BlockNameSheet` (replaces the `.alert`)

New `struct BlockNameSheet: View` in `ios/SecretaryApp/Sources/BlockCrudViews.swift` (alongside `MoveTargetPickerSheet`; the file is 39 lines — well under the 500-line threshold). Shape:

```swift
struct BlockNameSheet: View {
    @ObservedObject var viewModel: VaultBrowseViewModel
    @Binding var name: String
    let title: String                       // "New block" / "Rename block"
    var body: some View {
        NavigationStack {
            Form {
                TextField("Block name", text: $name).accessibilityIdentifier("block-name-field")
                if viewModel.blockNameCollides(name) {
                    Text("A block named \"\(name.trimmed)\" already exists.")
                        .font(.footnote).foregroundStyle(.red)     // app error-text idiom; Android used colorScheme.error
                        .accessibilityIdentifier("block-name-warning")
                }
                if let error = viewModel.error {                    // non-regression: a full-screen sheet would
                    Text(String(describing: error)).font(.footnote) //   otherwise hide the parent list's error section
                        .foregroundStyle(.red)                       //   on a failed write (the .alert left it merely behind)
                }
            }
            .navigationTitle(title)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { viewModel.cancelBlockNameDialog() }
                        .accessibilityIdentifier("block-name-cancel")
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(viewModel.blockNameCollides(name) ? "Save anyway" : "Save") {
                        Task { await viewModel.confirmBlockName(name) }
                    }
                    .accessibilityIdentifier("block-name-confirm")
                    .disabled(viewModel.isWriting)
                }
            }
        }
    }
}
```

Presentation in `VaultBrowseScreen.swift`: swap the `.alert(...)` modifier for `.sheet(isPresented: Binding(get: { viewModel.blockNameDialog != nil }, set: { if !$0 { viewModel.cancelBlockNameDialog() } }))` presenting `BlockNameSheet(viewModel:, name: $blockNameField, title: blockNameAlertTitle)`. The existing seeding (`blockNameField = block.name` on rename, `= ""` on create) and the `blockNameAlertTitle` computed property are reused unchanged. Success → `confirmBlockName` sets `blockNameDialog = nil` → binding flips false → sheet dismisses; a failed write keeps the sheet open with `viewModel.error` shown inline. TestTags (`block-name-field` / `-confirm` / `-cancel`) preserved.

`name.trimmed` is an inline `name.trimmingCharacters(in: .whitespacesAndNewlines)` (no new extension unless one already exists).

## Testing (TDD, host-only — runs in `swift test` Step 1, pre-xcframework, like `MovePolicyTests`)

**`BlockNamePolicyTests.swift`** (`Tests/SecretaryVaultAccessTests/`) — 8 cases mirroring `BlockNamePolicyTest.kt` one-for-one:
1. empty block list never collides
2. unique name does not collide
3. exact duplicate collides
4. surrounding whitespace trimmed before comparison
5. case-only difference collides (case-insensitive)
6. blank candidate never collides
7. rename to own current name does not collide (self excluded)
8. rename to a different existing name collides

**`VaultBrowseViewModelBlockNameWarnTests.swift`** (new, `Tests/SecretaryVaultAccessUITests/`; one-concept file) — VM exclude wiring + write-intactness:
- create-mode: collision → `true`; unique → `false`; blank → `false`
- rename-mode: candidate == own current name → `false` (self-excluded); candidate == a different existing block's name → `true`
- **warn-but-allow write-intact proof (load-bearing):** open create, `confirmBlockName` a name that collides → the write STILL happens (two blocks now share the name) and the dialog clears. Mirrors Android's strengthened `saveAnyway_stillCreates`.

Existing `VaultBrowseViewModelBlockCrudTests` must remain green (write path unchanged).

## Acceptance

```bash
# From the worktree. Host tests (fast, no simulator device needed for the packages):
ios/scripts/run-ios-tests.sh          # or the swift-test step — both new suites + existing block-CRUD suite green
```
- `BlockNamePolicyTests` 8/8, `VaultBrowseViewModelBlockNameWarnTests` all green, existing suites unaffected.
- Manual on-simulator check: the warning + "Save anyway" relabel appear **live as you type**; a single tap on "Save anyway" commits the duplicate.
- SwiftUI render itself untested (accepted #417-class gap; the sheet makes a future ViewInspector/#417 test tractable).

## Open decisions / risks

- **`hasNameCollision` is a UX layer, not a safety boundary.** The write path allows duplicate block names by design. Do **not** later harden this into a hard reject on the theory that the warning exists — that removes the legitimate per-context-duplicate use.
- **Collision is case-insensitive + trimmed, exact otherwise** (no whitespace-fuzzy matching). Candidate trimmed; `block.name` compared untrimmed. Can only *under*-warn, never falsely warn.
- **Container change (`.alert` → `.sheet`) is a real interaction-model change**, not a pure add. It is required by the UIKit static-alert limitation; the `.sheet` is the correct home for a dynamic warning. The one deliberate UX delta beyond Android parity — inline error display in the sheet — prevents a regression (a full-screen sheet hides the list's error section).
- **iOS SwiftUI render-test constraint** (same accepted class as #417): the sheet's rendering (warning visibility, button relabel) is not host-tested. The VM `blockNameCollides` and pure `hasNameCollision` — which carry all the logic — are. Verified manually on-simulator.
- **CI:** `test.yml` `ios-host` runs `run-ios-tests.sh`; both new host suites are covered there. No SwiftUI render test in CI (matches the #417 gap).
