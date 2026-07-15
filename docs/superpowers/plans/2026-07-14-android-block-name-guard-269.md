# Android duplicate block-name warn-but-allow guard (#269) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When a user types a block name that collides (case-insensitively) with an existing block, the Android create/rename dialog shows an inline warning and relabels its confirm button "Save" → "Save anyway", but still lets them proceed.

**Architecture:** A pure `blockNameCollides()` in `:vault-access` (host-tested, FFI-free) computes the collision; `BlockNameDialog` in `:browse-ui` renders the warning + relabel as a pure function of `(name, existingBlocks, state)`. `VaultBrowseModel`'s write path is untouched — duplicate names remain writable.

**Tech Stack:** Kotlin, Jetpack Compose, Gradle. Host unit tests = JUnit 5 (`org.junit.jupiter.api`). Instrumented tests = JUnit 4 + Compose test rule (`androidx.compose.ui.test`).

**Spec:** [docs/superpowers/specs/2026-07-14-android-block-name-guard-269-design.md](../specs/2026-07-14-android-block-name-guard-269-design.md)

## Global Constraints

- **No `core` / crypto / FFI / on-disk-format / error-variant change.** No Rust touched. Android `:vault-access` + `:browse-ui` only.
- **Collision is case-insensitive + locale-independent:** `String.equals(other, ignoreCase = true)` — NOT `lowercase(Locale.getDefault())`.
- **Warn-but-allow:** the model always writes; the dialog only warns. Duplicate block names stay writable.
- **testTag stability:** `block-name-field`, `block-name-confirm`, `block-name-cancel` keep their tags (existing `BlockCrudUiTest` depends on them). New tag: `block-name-warning`.
- **Two commits** (task-per-commit), TDD (test first), no magic numbers, pure fn in a reusable module.

---

### Task 1: Pure `blockNameCollides` policy + host unit tests

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/BlockNamePolicy.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/BlockNamePolicyTest.kt`

**Interfaces:**
- Consumes: `BlockSummaryView` (existing, `org.secretary.browse.BrowseModels.kt`) — has `val uuid: ByteArray`, `val name: String`.
- Produces: `fun blockNameCollides(candidate: String, existing: List<BlockSummaryView>, excludeUuid: ByteArray? = null): Boolean` in package `org.secretary.browse`. Consumed by Task 2's dialog.

- [ ] **Step 1: Write the failing test**

Create `android/vault-access/src/test/kotlin/org/secretary/browse/BlockNamePolicyTest.kt`:

```kotlin
package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class BlockNamePolicyTest {
    private fun block(uuidByte: Int, name: String) =
        BlockSummaryView(ByteArray(16) { uuidByte.toByte() }, name, 0u, 0u)

    private val work = block(0x11, "Work")
    private val personal = block(0x22, "Personal")
    private val existing = listOf(work, personal)

    @Test
    fun `empty block list never collides`() {
        assertFalse(blockNameCollides("Work", emptyList()))
    }

    @Test
    fun `unique name does not collide`() {
        assertFalse(blockNameCollides("Finance", existing))
    }

    @Test
    fun `exact duplicate collides`() {
        assertTrue(blockNameCollides("Work", existing))
    }

    @Test
    fun `surrounding whitespace is trimmed before comparison`() {
        assertTrue(blockNameCollides("  Work  ", existing))
    }

    @Test
    fun `case-only difference collides (case-insensitive)`() {
        assertTrue(blockNameCollides("work", existing))
    }

    @Test
    fun `blank candidate never collides`() {
        assertFalse(blockNameCollides("   ", existing))
    }

    @Test
    fun `rename to own current name does not collide (self excluded)`() {
        assertFalse(blockNameCollides("Work", existing, excludeUuid = work.uuid))
    }

    @Test
    fun `rename to a different existing name collides`() {
        assertTrue(blockNameCollides("Personal", existing, excludeUuid = work.uuid))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ./gradlew :vault-access:test --tests "org.secretary.browse.BlockNamePolicyTest"`
Expected: FAIL — compilation error, `blockNameCollides` unresolved reference.

- [ ] **Step 3: Write minimal implementation**

Create `android/vault-access/src/main/kotlin/org/secretary/browse/BlockNamePolicy.kt`:

```kotlin
package org.secretary.browse

/**
 * True when [candidate] (after trimming) matches the display name of some existing block OTHER than
 * [excludeUuid], compared **case-insensitively** (a name differing only in case reads as an
 * accidental near-duplicate). The comparison is locale-independent via
 * `String.equals(other, ignoreCase = true)` — deliberately NOT `lowercase(Locale.getDefault())`,
 * which would be locale-sensitive (Turkish-i class bugs). Trimmed to match how names are stored +
 * displayed (`session.createBlock`/`renameBlock` write trimmed names). [excludeUuid] is the block
 * being renamed (null on create), so renaming a block without changing its name is never a collision.
 * Blank -> false (the blank-name guard in VaultBrowseModel.confirmBlockName owns that case).
 *
 * Pure + FFI-free so it is host-testable without an emulator. UX-only: the write path always allows
 * duplicate names (they are UUID-keyed and harmless); this only drives a warn-but-allow affordance.
 */
fun blockNameCollides(
    candidate: String,
    existing: List<BlockSummaryView>,
    excludeUuid: ByteArray? = null,
): Boolean {
    val trimmed = candidate.trim()
    if (trimmed.isEmpty()) return false
    return existing.any { block ->
        (excludeUuid == null || !block.uuid.contentEquals(excludeUuid)) &&
            trimmed.equals(block.name, ignoreCase = true)
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd android && ./gradlew :vault-access:test --tests "org.secretary.browse.BlockNamePolicyTest"`
Expected: PASS (8 tests).

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/android-block-name-guard-269
git add android/vault-access/src/main/kotlin/org/secretary/browse/BlockNamePolicy.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/BlockNamePolicyTest.kt
git commit -m "feat(android): pure blockNameCollides policy for #269 (host-tested)

Case-insensitive, locale-independent (equals ignoreCase), trimmed. Excludes
the block being renamed by UUID so a no-op rename never warns. Blank -> false
(the blank-name guard owns that). UX-only: the write path still allows dups.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Dialog warn affordance + call site + instrumented render test

**Files:**
- Modify: `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/BlockCrudDialogs.kt` (add `existingBlocks` param; compute `collides`; conditional warning `Text`; relabel confirm)
- Modify: `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/BrowseScreen.kt:63-68` (pass `existingBlocks = blocks`)
- Test: `android/browse-ui/src/androidTest/kotlin/org/secretary/browse/ui/BlockNameDialogWarnTest.kt`

**Interfaces:**
- Consumes: `blockNameCollides(...)` from Task 1; `BlockSummaryView`, `BlockNameDialogState.RenameBlock.blockUuid` (existing).
- Produces: `BlockNameDialog(state, existingBlocks, onConfirm, onCancel)` — a new required `existingBlocks: List<BlockSummaryView>` param inserted after `state`.

- [ ] **Step 1: Write the failing test**

Create `android/browse-ui/src/androidTest/kotlin/org/secretary/browse/ui/BlockNameDialogWarnTest.kt`:

```kotlin
package org.secretary.browse.ui

import androidx.compose.ui.test.assertDoesNotExist
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import org.junit.Rule
import org.junit.Test
import org.secretary.browse.BlockSummaryView
import org.secretary.browse.FakeVaultSession
import org.secretary.browse.VaultBrowseModel

/** #269: create/rename block-name dialog warns (but still allows) on a name that collides
 *  case-insensitively with an existing block. Duplicate names stay writable. */
class BlockNameDialogWarnTest {
    @get:Rule val composeRule = createComposeRule()

    private val personal = BlockSummaryView(ByteArray(16) { 0x1A }, "Personal", 0u, 0u)
    private val work = BlockSummaryView(ByteArray(16) { 0x2B }, "Work", 1u, 0u)

    private fun openBrowse(): VaultBrowseViewModel {
        val session = FakeVaultSession(
            vaultUuidHex = "aabbccdd",
            blocks = listOf(personal, work),
            recordsByBlockHex = emptyMap(),
        )
        val vm = VaultBrowseViewModel(VaultBrowseModel(session))
        composeRule.setContent { BrowseScreen(viewModel = vm, autoHideMillis = 60_000L) }
        composeRule.runOnIdle { vm.loadBlocks() }
        composeRule.waitForIdle()
        return vm
    }

    private fun openCreateDialog() {
        composeRule.onNodeWithTag("new-block").performClick()
        composeRule.waitForIdle()
    }

    @Test
    fun collidingName_showsWarning_andRelabelsConfirm() {
        openBrowse()
        openCreateDialog()
        composeRule.onNodeWithTag("block-name-field").performTextInput("Work")
        composeRule.waitForIdle()
        composeRule.onNodeWithTag("block-name-warning").assertIsDisplayed()
        composeRule.onNodeWithText("Save anyway").assertIsDisplayed()
    }

    @Test
    fun caseOnlyDifference_showsWarning() {
        openBrowse()
        openCreateDialog()
        composeRule.onNodeWithTag("block-name-field").performTextInput("work")
        composeRule.waitForIdle()
        composeRule.onNodeWithTag("block-name-warning").assertIsDisplayed()
    }

    @Test
    fun uniqueName_noWarning_andPlainConfirm() {
        openBrowse()
        openCreateDialog()
        composeRule.onNodeWithTag("block-name-field").performTextInput("Finance")
        composeRule.waitForIdle()
        composeRule.onNodeWithTag("block-name-warning").assertDoesNotExist()
        composeRule.onNodeWithText("Save").assertIsDisplayed()
    }

    @Test
    fun saveAnyway_stillCreates_dialogDismisses() {
        openBrowse()
        openCreateDialog()
        composeRule.onNodeWithTag("block-name-field").performTextInput("Work")
        composeRule.waitForIdle()
        composeRule.onNodeWithTag("block-name-confirm").performClick()
        composeRule.waitForIdle()
        // Allow verified: the write succeeded and the model closed the dialog.
        composeRule.onNodeWithTag("block-name-field").assertDoesNotExist()
    }

    @Test
    fun renameSeededWithOwnName_noWarning() {
        openBrowse()
        composeRule.onNodeWithTag("rename-${personal.uuidHex}").performClick()
        composeRule.waitForIdle()
        // Field pre-filled with "Personal"; self is excluded by UUID → no collision.
        composeRule.onNodeWithTag("block-name-warning").assertDoesNotExist()
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Ensure an emulator is running (`adb devices` shows a device). Then run:
`cd android && ./gradlew :browse-ui:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.browse.ui.BlockNameDialogWarnTest`
Expected: FAIL — `collidingName_showsWarning_andRelabelsConfirm` and `caseOnlyDifference_showsWarning` fail (no `block-name-warning` node; no "Save anyway"). The dialog does not yet compute a collision.

- [ ] **Step 3: Modify `BlockNameDialog` to add the warn affordance**

In `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/BlockCrudDialogs.kt`, add the import for the policy (with the other `org.secretary.browse` imports near line 19-21):

```kotlin
import org.secretary.browse.blockNameCollides
```

Replace the `BlockNameDialog` function body (currently lines 24-53) with:

```kotlin
/** Create/rename a block: one text field + confirm/cancel. Seeded from the current name on rename.
 *  Warns (but still allows — #269) when [name] collides case-insensitively with an existing block. */
@Composable
fun BlockNameDialog(
    state: BlockNameDialogState,
    existingBlocks: List<BlockSummaryView>,
    onConfirm: (String) -> Unit,
    onCancel: () -> Unit,
) {
    val initial = (state as? BlockNameDialogState.RenameBlock)?.currentName ?: ""
    var name by remember(state) { mutableStateOf(initial) }
    val title = if (state is BlockNameDialogState.RenameBlock) "Rename block" else "New block"
    val renameUuid = (state as? BlockNameDialogState.RenameBlock)?.blockUuid
    val collides = blockNameCollides(name, existingBlocks, renameUuid)
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text(title) },
        text = {
            Column {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag("block-name-field"),
                )
                if (collides) {
                    Text(
                        text = "A block named \"${name.trim()}\" already exists.",
                        modifier = Modifier.padding(top = 8.dp).testTag("block-name-warning"),
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(name) }, modifier = Modifier.testTag("block-name-confirm")) {
                Text(if (collides) "Save anyway" else "Save")
            }
        },
        dismissButton = {
            TextButton(onClick = onCancel, modifier = Modifier.testTag("block-name-cancel")) { Text("Cancel") }
        },
    )
}
```

Note: `Column`, `padding`, and `dp` are already imported in this file (used by `MovePickerDialog`). No new layout imports are needed — only `blockNameCollides`.

- [ ] **Step 4: Update the call site**

In `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/BrowseScreen.kt`, the `blockNameDialog?.let { state -> ... }` block (lines 63-69) — add `existingBlocks = blocks`:

```kotlin
        blockNameDialog?.let { state ->
            BlockNameDialog(
                state = state,
                existingBlocks = blocks,
                onConfirm = { viewModel.confirmBlockName(it) },
                onCancel = { viewModel.cancelBlockNameDialog() },
            )
        }
```

`blocks` is already collected at the top of `BrowseScreen` (`val blocks by viewModel.blocks.collectAsStateWithLifecycle()`), and `MovePickerDialog` already uses it — no new state wiring.

- [ ] **Step 5: Run the new test to verify it passes**

Run: `cd android && ./gradlew :browse-ui:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.browse.ui.BlockNameDialogWarnTest`
Expected: PASS (5 tests).

- [ ] **Step 6: Run the existing block-CRUD instrumented test for no regression**

The testTag change nests `block-name-field` in a `Column` but keeps its tag — verify the existing suite still passes:
Run: `cd android && ./gradlew :browse-ui:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.browse.ui.BlockCrudUiTest`
Expected: PASS (3 tests — `newBlock_tapConfirm_appearsInBlockList`, `moveRecord_tapTarget_recordLeavesSourceList`, `renameBlock_tapConfirm_newNameInBlockList`).

- [ ] **Step 7: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/android-block-name-guard-269
git add android/browse-ui/src/main/kotlin/org/secretary/browse/ui/BlockCrudDialogs.kt \
        android/browse-ui/src/main/kotlin/org/secretary/browse/ui/BrowseScreen.kt \
        android/browse-ui/src/androidTest/kotlin/org/secretary/browse/ui/BlockNameDialogWarnTest.kt
git commit -m "feat(android): warn-but-allow on duplicate block name (#269)

BlockNameDialog shows an inline warning (testTag block-name-warning) and
relabels its confirm 'Save' -> 'Save anyway' when the typed name collides
case-insensitively with an existing block; a single deliberate tap still
commits. Write path unchanged (duplicate names remain writable). Instrumented
render test covers collision / case-fold / unique / allow / rename-self.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Verification (whole-feature, after both tasks)

- [ ] Host unit: `cd android && ./gradlew :vault-access:test` — BUILD SUCCESSFUL (full module suite, not just the new class).
- [ ] Instrumented: `cd android && ./gradlew :browse-ui:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.browse.ui.BlockNameDialogWarnTest,org.secretary.browse.ui.BlockCrudUiTest` — both classes green on the emulator.
- [ ] `:kit` + `:app` compile (a `:browse-ui` public-API change ripples up): `cd android && ./gradlew :kit:compileDebugKotlin :app:compileDebugKotlin` — BUILD SUCCESSFUL. (Per [[project_secretary_conformance_scripts_dont_compile_kit]] / [[project_secretary_android_sealed_when_cross_module]]: build the consumers in the same task.)

## Notes / gotchas for the implementer

- **Emulator not on bare PATH** ([[project_secretary_android_toolchain]]): use the absolute `adb`/`emulator` paths if `adb devices` shows nothing. Instrumented tests need a booted emulator; host unit tests do not.
- **Instrumented tests reject `--tests`** ([[project_secretary_android_instrumented_test_gotchas]]): use `-Pandroid.testInstrumentationRunnerArguments.class=<FQCN>[,<FQCN>...]`. Host unit tests DO accept `--tests`.
- **No Kotlin style gate** exists (no ktlint/detekt/spotless) — match surrounding style by hand.
- **CI does not run `:browse-ui`** host/instrumented tests (android-host runs only `:vault-access:test`) — these gates are local-only. Run them locally and record evidence.
