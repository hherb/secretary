# Design: hide per-record Move affordance on mobile when there is nowhere to move (#429)

**Date:** 2026-07-14
**Issue:** [#429](https://github.com/hherb/secretary/issues/429) — Android + iOS parity with #273.
**Scope:** Android (Jetpack Compose) + iOS (SwiftUI) browse UIs. **No `core` / crypto / FFI / on-disk-format change; no new error variant; no Rust touched.** One combined PR closing #429.

## Problem

`#273` scoped the *"hide the per-record Move button when there is nowhere to move to"* UX polish to the **desktop** client only. Mobile still **always** renders the per-record Move affordance for a live record:

- **Android** — `BrowseScreen.kt`'s `RecordRow` renders the Move `TextButton` (`testTag("move-<uuid>")`) unconditionally.
- **iOS** — `VaultBrowseScreen.swift`'s `recordView` renders the leading-swipe `Move` `Button` (`accessibilityIdentifier("move-<uuid>")`) unconditionally.

In a single-block vault, tapping Move opens the move-target picker, which then shows an empty *"No other blocks"* state — functionally correct, mildly noisy. We mirror desktop: hide the affordance when the vault has ≤ 1 live block.

## Approach (chosen)

Mirror the #273 shape on each platform: derive the live-block count from the collection the browse view-model **already holds** (loaded for the block list), feed it to a **pure** `hasMoveTargets(blockCount) -> Bool` guard, and gate the Move affordance on the result. No extra FFI/IPC call.

Approaches rejected:
- **Stored `canMove`/`moveTargetCount` VM state** — another field to keep in sync; the count is already derivable (YAGNI).
- **Improve the picker empty-state only** — that is the status quo the issue improves.

### Shared shape

A pure `hasMoveTargets(blockCount) = blockCount >= MIN_BLOCKS_TO_MOVE`, with a **named constant `MIN_BLOCKS_TO_MOVE = 2`** (the record's own block + at least one distinct target). No magic number. Because the three platforms share no code (independent TypeScript / Kotlin / Swift), the guard is reimplemented per platform — exactly as the issue anticipates ("a pure `hasMoveTargets`-equivalent").

### Correctness property (tighter than desktop)

On mobile the count feeding the guard and the count feeding the move picker are the **literal same** `blocks` collection:

- Android: `RecordRow` gate reads `blocks.size`; `MovePickerDialog(blocks = blocks, …)` enumerates the same `blocks`, so `candidates == blocks − source`.
- iOS: VM `hasMoveTargets` reads `blocks.count`; `MoveTargetPickerSheet(viewModel:)` enumerates the same `viewModel.blocks`.

Desktop had two *projections* (`manifest.blockCount` vs `listBlocks()`) that merely agree today; mobile cannot diverge because there is one collection. The button is therefore hidden on exactly the range where the picker would show its empty state.

This remains a **UX layer, not a safety boundary** (same framing as #273): the picker empty-state and the Rust `move_record_impl` same-block guard stay in place and remain authoritative.

## Design

### Android

- **`browse-ui/.../BrowseRenderHelpers.kt`** (pure, host-tested home): add
  ```kotlin
  private const val MIN_BLOCKS_TO_MOVE = 2
  /** True when at least one block OTHER than the record's own exists … */
  fun hasMoveTargets(blockCount: Int): Boolean = blockCount >= MIN_BLOCKS_TO_MOVE
  ```
- **`browse-ui/.../BrowseScreen.kt`**: `RecordRow` gains a new `canMove: Boolean` parameter; the Move `TextButton` is wrapped `if (canMove) { … }` (Edit and Delete unchanged). Record branch call site computes `val canMove = hasMoveTargets(blocks.size)` and passes `canMove = canMove`.
- **Gate mechanism decision:** a `canMove: Boolean` param, *not* making `onMove` nullable (desktop's `{#if onMove}` idiom). Android's `RecordRow` has no existing `if (onMove != null)` gate, so a boolean is the smaller, clearer change and keeps `onMove` non-null.

### iOS

- **New `SecretaryVaultAccess/.../MovePolicy.swift`** (FFI-free, host-testable module; neighbor to `RevealPolicy.swift`):
  ```swift
  public enum MovePolicy {
      /// The record's own block + at least one distinct target block.
      static let minBlocksToMove = 2
      public static func hasMoveTargets(blockCount: Int) -> Bool { blockCount >= minBlocksToMove }
  }
  ```
- **`SecretaryVaultAccessUI/.../VaultBrowseViewModel.swift`**: add a computed property
  ```swift
  public var hasMoveTargets: Bool { MovePolicy.hasMoveTargets(blockCount: blocks.count) }
  ```
- **`SecretaryApp/Sources/VaultBrowseScreen.swift`**: in `recordView`, wrap the Move `Button` in `if viewModel.hasMoveTargets { … }` (Edit stays; the `.swipeActions(edge: .leading)` container and Delete/Restore trailing actions are unchanged).

### Data flow

`loadBlocks()` populates the `blocks` collection (already happens for the block list) → count derived (`.size` / `.count`) → pure `hasMoveTargets` → affordance shown or hidden. No new state, no new FFI/IPC, no new error surface. `blockCount` is a non-negative collection size, so there is no failure mode to handle.

## Testing (TDD — test-first each layer)

- **Android host unit** (`BrowseRenderHelpersTest.kt`, JVM `src/test`, no emulator): `hasMoveTargets(0) == false`, `(1) == false`, `(2) == true`, `(3) == true`.
- **Android instrumented render** (new `src/androidTest` file, emulator; mirrors `BrowseScreenSoftDeleteTest.kt`): a live record in a **single-block** vault renders **no** `move-<uuid>` node; a **2-block** vault renders it. (Edit/Delete present in both, to prove only Move is gated.)
- **iOS host unit** (`MovePolicyTests.swift` in `SecretaryVaultAccessTests`, `swift test`): boundary values `0,1 → false`, `2,3 → true`.
- **iOS host VM test** (extend `VaultBrowseViewModelTests.swift` in `SecretaryVaultAccessUITests`, `swift test`): seed the fake session with 1 block, select it → `hasMoveTargets == false`; seed 2 blocks → `true`.
- **iOS render layer:** no literal SwiftUI render assertion — that infra gap is tracked separately as #417. The SwiftUI gate references the host-tested VM property, so the render pattern is the existing one.

## Acceptance criteria (from #429)

- **Android:** a live record in a single-block vault renders no `move-<uuid>` action; a 2+-block vault still renders it (Compose instrumented test asserts both).
- **iOS:** same for the `move-<uuid>` swipe action; host-testable VM gating (pure `hasMoveTargets`-equivalent) + the existing render pattern.
- Picker empty-state and `move_record_impl` same-block guard remain in place.

## Out of scope / non-goals

- No change to `core`, crypto, FFI bridge, uniffi/pyo3 surface, on-disk format, or any error variant. No Rust touched.
- No change to the desktop client (#273 already shipped it).
- No literal SwiftUI render-assertion infrastructure (that is #417).
- No change to the move picker's empty-state or the `move_record_impl` guard.

## Files

**Android**
- `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/BrowseRenderHelpers.kt` (pure helper)
- `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/BrowseScreen.kt` (gate)
- `android/browse-ui/src/test/kotlin/org/secretary/browse/ui/BrowseRenderHelpersTest.kt` (host unit)
- `android/browse-ui/src/androidTest/kotlin/org/secretary/browse/ui/BrowseScreenMoveButtonTest.kt` (new instrumented render)

**iOS**
- `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/MovePolicy.swift` (new pure helper)
- `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultBrowseViewModel.swift` (VM property)
- `ios/SecretaryApp/Sources/VaultBrowseScreen.swift` (gate)
- `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/MovePolicyTests.swift` (new host unit)
- `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultBrowseViewModelTests.swift` (host VM test)
