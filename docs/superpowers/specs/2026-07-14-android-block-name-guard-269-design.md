# Design — Android duplicate block-name warn-but-allow guard (#269)

**Date:** 2026-07-14
**Issue:** [#269 — Android browse: no duplicate-name guard on block create/rename](https://github.com/hherb/secretary/issues/269)
**Scope:** Android `:browse-ui` + `:vault-access` only. **No** `core` / crypto / FFI / on-disk-format / error-variant change. No Rust touched.

## Problem

`VaultBrowseModel.confirmBlockName` accepts any non-blank name for both **create** and **rename**, so two blocks can share an identical display name. The underlying `create_block` / `rename_block` FFI ops are UUID-keyed and *intentionally* permit duplicate names, so this is **functionally harmless** — but the block list and the move-record picker become visually ambiguous when two blocks read identically.

Issue #269 asks us to pick one of: (1) disambiguate in the UI (uuid suffix), (2) warn-but-allow, or (3) leave as-is and close.

## Decision

**Warn-but-allow.** On a colliding name the create/rename dialog surfaces an inline warning and relabels its confirm button, but the user can still proceed with one deliberate tap. Duplicate block names remain fully writable — the warning is a render-layer affordance, not a block.

**Rationale:**
- Block-name uniqueness is **not** a correctness requirement. Blocks are UUID-keyed; the FFI deliberately permits duplicate names. Contrast the **field-name** guard (`RecordContentInput.validate` → typed `DuplicateFieldName`), which is a *hard reject* precisely because field uniqueness *is* load-bearing (the bridge diffs fields by name). Block names carry no such constraint, so a hard reject would remove a legitimate use (per-context blocks that share a display name), which the issue explicitly calls out.
- The repo already has a **warn-but-allow** idiom (contacts "delete ≠ revoke"), so this is the consistency-preserving choice.
- It fixes the actual pain (users unknowingly creating ambiguous blocks) at the point of creation, without touching the write/reauth/FFI path.

**Deliberately rejected:**
- *Hard reject* — removes the legitimate duplicate-name use the issue calls out; inconsistent with the UUID-keyed data model.
- *UI uuid-suffix disambiguation* — hex suffixes are unfriendly, touch the render path in more places, and give no creation-time feedback.
- *Leave as-is* — the ambiguity is a real (if minor) UX wart; warn-but-allow removes it at near-zero risk.

## Architecture

The write path *allows* duplicates (unchanged); the dialog *warns* before a deliberate confirm. One pure policy function plus a thin UI affordance. `VaultBrowseModel` is untouched.

### 1. Pure policy function — `:vault-access`, FFI-free, host-testable

New file `android/vault-access/src/main/kotlin/org/secretary/browse/BlockNamePolicy.kt`, mirror-named after the iOS `MovePolicy` introduced in #429. Domain policy lives in `:vault-access` alongside `RecordContentInput` (the field-name guard), keeping it host-testable without an emulator.

```kotlin
/**
 * True when [candidate] (after trimming) matches the display name of some existing block OTHER than
 * [excludeUuid], compared **case-insensitively** (a name differing only in case reads as an
 * accidental near-duplicate). The comparison is locale-independent via
 * `String.equals(other, ignoreCase = true)` — deliberately NOT `lowercase(Locale.getDefault())`,
 * which would be locale-sensitive (Turkish-i class bugs). Trimmed to match how names are stored +
 * displayed. [excludeUuid] is the block being renamed (null on create), so renaming a block without
 * changing its name is never a collision. Blank -> false (the blank-name guard in VaultBrowseModel
 * owns that case).
 */
fun blockNameCollides(
    candidate: String,
    existing: List<BlockSummaryView>,
    excludeUuid: ByteArray? = null,
): Boolean
```

**Predicate decisions (all deliberate, documented in the KDoc):**
- **Trimmed** candidate — names are stored + displayed trimmed (`session.createBlock(trimmed)`), so the comparison matches what the user sees.
- **Case-insensitive** match — `"Work"` and `"work"` read as accidental near-duplicates, so both warn. Implemented with `String.equals(ignoreCase = true)` (locale-independent — not `lowercase(Locale.getDefault())`, which would be locale-sensitive). No whitespace-fuzzy matching (double-space etc.) — out of scope.
- **`excludeUuid`** — on rename, the block being renamed is excluded by UUID, so opening the rename dialog on a block (seeded with its own name) shows no warning. On create, `excludeUuid` is null.
- **Blank → false** — the blank-name case is already rejected by `VaultBrowseModel.confirmBlockName`; this function does not duplicate that responsibility.

### 2. Dialog warn affordance — `:browse-ui`, `BlockCrudDialogs.kt`

`BlockNameDialog` gains an `existingBlocks: List<BlockSummaryView>` parameter. As the user types, it computes:

```kotlin
val renameUuid = (state as? BlockNameDialogState.RenameBlock)?.blockUuid
val collides = blockNameCollides(name, existingBlocks, renameUuid)
```

When `collides` is true:
- Render an inline warning `Text` (testTag `block-name-warning`): *"A block named \"<trimmed>\" already exists."*
- Relabel the confirm button **"Save" → "Save anyway"**. The `block-name-confirm` testTag stays stable so existing selectors keep working.

**One-tap flow (no press-twice state machine):** the warning is visible *before* the tap and the button reads "…anyway", so a single deliberate tap on the relabeled button *is* the informed confirmation. This keeps the dialog a pure function of `(name, existingBlocks, state)` with no extra mutable "pending confirmation" state.

### 3. Call site — `BrowseScreen.kt`

Pass `existingBlocks = blocks` to `BlockNameDialog` — the same already-collected `blocks` list that `MovePickerDialog` uses. One-line addition; `blocks` is already `collectAsStateWithLifecycle`-bound at the top of `BrowseScreen`.

### 4. Model — unchanged

`VaultBrowseModel.confirmBlockName` still always writes (allow); the blank-name guard stays. Zero change to the write / reauth / FFI path — the warn is entirely a render-layer affordance. This is what makes "warn-but-allow" true warn-but-allow: the model *allows*, and it does.

## Data flow

```
user types in dialog
        │
        ▼
BlockNameDialog (browse-ui)  ──reads──▶  existingBlocks (from viewModel.blocks)
        │                                        │
        │  blockNameCollides(name, existing, renameUuid)   ← pure fn (:vault-access)
        ▼
   collides? ──yes──▶ show warning + "Save anyway"
        │
        ▼
   tap confirm ──▶ onConfirm(name) ──▶ viewModel.confirmBlockName(name)
                                              │  (unchanged: blank guard, then write)
                                              ▼
                                   VaultBrowseModel.confirmBlockName  (ALLOWS duplicates)
```

## Testing (TDD)

Each unit is written test-first.

### Host unit — `:vault-access:testDebugUnitTest` (no emulator, fast)

`BlockNamePolicyTest` over `blockNameCollides`:

| Case | Expect |
|---|---|
| empty block list | `false` |
| unique name vs existing | `false` |
| exact duplicate of an existing name | `true` |
| candidate with surrounding whitespace matching a stored name | `true` (trimmed) |
| case-only difference (`"work"` vs stored `"Work"`) | `true` (case-insensitive) |
| blank / whitespace-only candidate | `false` |
| rename seeded to its own current name (`excludeUuid` = self) | `false` |
| rename to a *different* existing block's name | `true` |

### Instrumented render — `:browse-ui:connectedDebugAndroidTest` (emulator)

`BlockNameDialogWarnTest`:
- Type a colliding name → `block-name-warning` shown **and** confirm reads "Save anyway".
- Type a unique name → no warning, confirm reads "Save".
- Tapping the relabeled confirm still fires `onConfirm(name)` (allow verified).
- Open rename seeded with the block's own name → no warning (self excluded).

## Files touched

- **NEW** `android/vault-access/src/main/kotlin/org/secretary/browse/BlockNamePolicy.kt`
- **NEW** `android/vault-access/src/test/kotlin/org/secretary/browse/BlockNamePolicyTest.kt`
- **EDIT** `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/BlockCrudDialogs.kt`
- **EDIT** `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/BrowseScreen.kt`
- **NEW** `android/browse-ui/src/androidTest/kotlin/org/secretary/browse/ui/BlockNameDialogWarnTest.kt`

## Out of scope / non-goals

- **No model / FFI / write-path change.** Duplicate block names remain fully writable — the change is warn-only.
- **iOS mirror is a follow-on.** The same warn-but-allow decision applies to iOS (`VaultBrowseViewModel` + a `BlockNamePolicy`-equivalent); file/schedule it as a separate slice. This spec records the decision so the mirror is mechanical.
- **No case-insensitive / whitespace-fuzzy matching.** Exact-on-trim only, documented in the KDoc.
- **The move-picker empty-state and the Rust `move_record_impl` same-block guard are unrelated and untouched** — they remain authoritative for their own concerns.

## Commit plan

- **Task 1** — `BlockNamePolicy.blockNameCollides` + `BlockNamePolicyTest` (pure fn, host tests). TDD: tests first.
- **Task 2** — `BlockNameDialog` warn affordance + `BrowseScreen` call-site + `BlockNameDialogWarnTest` (instrumented). TDD: test first.

Two commits, matching the repo's task-per-commit rhythm.
