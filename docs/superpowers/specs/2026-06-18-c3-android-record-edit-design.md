# C.3 Android slice 10 — record editing/adding (design)

**Date:** 2026-06-18
**Branch:** `feature/c3-android-record-edit` (worktree `.worktrees/c3-android-record-edit`)
**Status:** design approved; plan + TDD implementation to follow.

## Goal

Give the Android client a record **edit** and **add** path, mirroring the iOS
`RecordEditViewModel` / `EditableField` form (text + bytes-as-hex fields, editable
tags, kind picker, reveal-into-form on edit). This is the second Android slice that
WRITES to a vault; it builds directly on slice 9's write infrastructure
(device-UUID, `now_ms`, write seam under `sessionLock`+`wiped`, typed errors).

**Acceptance:** add a record (type/tags/fields) → re-read shows it; edit an existing
record (reveal-into-form → change → save) → re-read shows the change; both proven
on-device against a **staged copy** of the golden vault.

## Non-negotiable constraint: no core/ffi/format change

`append_record` / `edit_record` / `RecordContent` / `FieldInput` / `FieldInputValue`
already exist in `ffi/secretary-ffi-uniffi/src/secretary.udl` and the Rust bridge
(tested in `ffi/secretary-ffi-bridge/tests/edit.rs`). Slice 10 is a **pure
Android-layer projection** of that existing surface. Both guardrail greps stay empty:

```
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)'   # empty
git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'                # empty
```

## Architecture

Mirrors the existing `VaultBrowseModel` (pure, `:vault-access`) / `VaultBrowseViewModel`
(Compose, `:browse-ui`) split. The "extend the state machine" decision applies to
**navigation only**: an `editing` flow on the browse model selects a third UI state
(block-list / record-list / **edit-form**). Form logic lives in its own focused pure
model so neither file balloons past the 500-line guideline.

### `:vault-access` (pure, host-tested JUnit5)

- **New `RecordEditModel`** — pure mirror of iOS `RecordEditViewModel`. Constructed
  with `(session: VaultSession, blockUuid: ByteArray, mode: Mode)` where
  `Mode = Add | Edit(recordUuidHex: String)`. State:
  - `recordType: String`, `tags: List<String>`, `fields: List<EditableField>`
  - `error: VaultBrowseError?`, `committed: Boolean`, `loadFailed: Boolean`
    (exposed as `StateFlow`s, consistent with `VaultBrowseModel`).
  - Methods: `addField()`, `removeField(id)`, `addTag()`, `removeTag(index)`,
    `setRecordType`, field/tag mutators, `load(record: RecordSummaryView)`
    (reveal-into-form), `suspend commit()`.
- **New value types** (one concept per file, per the 500-line discipline):
  - `EditableField(id: Long, name: String, kind: FieldKind, rawText: String)` —
    `id` is a stable synthetic key for Compose list stability (monotonic counter,
    **not** crypto). `kind` reuses the existing read-side `FieldKind { Text, Bytes }`.
    `rawText` holds plaintext for `Text`, lowercase hex for `Bytes`.
  - `RecordContentInput(recordType, tags, fields: List<FieldContentInput>)` with
    pure `validate(): RecordContentInputError?`.
  - `FieldContentInput(name: String, value: FieldContentValue)` where
    `FieldContentValue = Text(String) | Bytes(ByteArray)`.
  - `RecordContentInputError { EmptyFieldName, DuplicateFieldName(name) }`.
  - `hex` / `parseHex` helpers added to existing `HexFormat.kt`.
- **`VaultSession` interface** gains:
  - `suspend fun appendRecord(blockUuid: ByteArray, content: RecordContentInput): ByteArray`
    (returns the freshly-minted 16-byte record UUID).
  - `suspend fun editRecord(blockUuid: ByteArray, recordUuid: ByteArray, content: RecordContentInput)`.
- **`VaultBrowseModel`** gains `editing: StateFlow<RecordEditModel?>` plus entry points
  `startAdd()` / `startEdit(record)` / `cancelEdit()` / `onEditCommitted()`. `editing != null`
  is the third UI state. `onEditCommitted()` clears `editing` and re-reads the selected
  block via the existing `commitThenReload` success-only re-read path. **`lock()` also
  clears `editing`** (drops in-progress plaintext on background→foreground).

### `:kit` (FFI-aware)

- `UniffiVaultSession` implements the two writers via the proven `write { dev, now -> … }`
  idiom (sessionLock + `wiped`-first guard, cached device-uuid, `now_ms` stamp).
- `appendRecord` mints the fresh 16-byte UUID via `SecureRandom` **inside the adapter**
  (keeps the pure model free of randomness), calls `uniffi.secretary.appendRecord`,
  returns the UUID. `editRecord` calls `uniffi.secretary.editRecord`.
- A `toFfi(RecordContentInput): RecordContent` converter wraps values in the generated
  `FieldInputValue.Text/Bytes`.
- **No new error arms.** Validation errors are pure (`InvalidArgument`); FFI errors reuse
  slice-9's `RecordNotFound` / `SaveCryptoFailure` / `CorruptVault` / `Failed` via the
  existing `mapErrors` / `mapVaultBrowseError`.

### `:browse-ui` (Compose, FFI-free)

- `VaultBrowseViewModel` re-exposes `editing` and forwards `startAdd`/`startEdit`/
  `cancelEdit` and the form's `commit`.
- New `RecordEditForm` composable: Type field, editable Tags (add/delete), Fields
  (name + Text/Bytes segmented picker + value + add/delete).
- `BrowseScreen` renders `RecordEditForm` when `editing != null`; adds an "Add record"
  affordance on the record-list and a per-row `edit-<uuidHex>` button on live records.

### `:app`

No structural change — `appendRecord` / `editRecord` reuse the device-uuid store wired
in slice 9 (`FileDeviceUuidStore(noBackupFilesDir/devices)`).

## Data flow

### Add
1. "Add record" → `VaultBrowseViewModel.startAdd()` → `VaultBrowseModel.startAdd()`
   builds `RecordEditModel(session, selectedBlock.uuid, Add)` (empty), publishes on `editing`.
2. `BrowseScreen` renders `RecordEditForm`. User fills type, tags, fields.
3. **Save** → `RecordEditModel.commit()`: build `RecordContentInput` (parse hex for
   `Bytes`), `validate()`. Validation failure → `error`, no write, form stays open.
   Success → `session.appendRecord(blockUuid, content)`. FFI failure → typed `error`,
   form stays open, **vault untouched**. Success → `committed = true`.
4. Browse model observes commit success → clears `editing` + re-reads. New record appears.

### Edit
1. `edit-<uuidHex>` on a live record → `startEdit(record)` builds
   `RecordEditModel(…, Edit(uuidHex))` and calls `load(record)`.
2. `load(record)` reveals each `RevealableField` into an `EditableField`
   (`Text → plaintext`, `Bytes → lowercase hex`). A reveal that throws sets
   `loadFailed = true` + `error`, which **disables Save** (never write a half-loaded record).
3. User edits names/values/kinds; adds/removes fields & tags.
4. **Save** → same `commit()` path but `session.editRecord(blockUuid, recordUuid, content)`.
   Success → clear `editing` + re-read; the changed record reflects.

### Cancel
`cancelEdit()` clears `editing` (dropping in-memory plaintext); no write.

### Invariants carried from slice 9
- Writes serialize under `sessionLock` with the `wiped`-first guard — a save racing
  lock-on-background refuses rather than touching zeroized handles.
- Failed write leaves the visible list intact (re-read on success only).
- Fresh record UUID minted via `SecureRandom` in the `:kit` adapter, not the pure model.
- Device-uuid + `now_ms` resolved inside the real session, same as delete/restore.

## Error handling

Two tiers, mirroring iOS:

- **Pure validation** (before any FFI call):
  - `EmptyFieldName` → `VaultBrowseError.InvalidArgument("a field name is empty")`.
  - `DuplicateFieldName(n)` → `InvalidArgument("duplicate field name: $n")` (the bridge
    diffs fields by name on edit; duplicates would alias — must reject).
  - Bad hex in a `Bytes` field → `InvalidArgument("field '<name>' is not valid hex")`.
- **FFI failures** reuse slice-9 typed arms with no new mapping: `RecordNotFound`
  (record deleted between open and save), `SaveCryptoFailure`, `CorruptVault`, plus the
  `Failed` else-fold.
- On any error: `RecordEditModel.error` is set, the form **stays open** with input intact,
  the vault is untouched.
- Empty `fields` allowed; record type & tags unconstrained; **blank tag strings dropped
  on build** (don't write empty tags).

## Secret hygiene (accepted tradeoff, matches iOS)

The form holds revealed plaintext as ordinary `String` in `rawText` (Compose state) for
the duration of editing — same posture as iOS's `@Published String` bindings. This is a
deliberate, documented widening for the edit surface only; the read-path
`RevealedValue` / `RevealableField` keep their existing discipline. `cancelEdit()` /
successful commit / `lock()` drop the `RecordEditModel`, releasing the plaintext.

## Lock interaction

Slice 8's lock-on-background calls `VaultBrowseModel.lock()` (wipes session, resets flows).
`lock()` will **also clear `editing`** so an in-progress edit's plaintext doesn't survive a
background→foreground cycle and a subsequent save can't run against a wiped session. Even
if it somehow did, the `:kit` `wiped`-first guard refuses it (defense in depth).

## Testing strategy (TDD)

### Pure host tests — JUnit5, `:vault-access` (bulk, no emulator)
- `RecordContentInputTest` — `validate()` returns `EmptyFieldName` (blank/whitespace),
  `DuplicateFieldName`, `null` when valid; empty fields OK; blank tags dropped on build.
- `HexFormatTest` (extend) — `parseHex` round-trips, accepts uppercase + whitespace,
  rejects odd-length/non-hex; `hex` is lowercase no-separator.
- `RecordEditModelTest` (against `FakeVaultSession`):
  - **Add:** fill type/tags/fields → `commit()` → fake records the appended content;
    `committed == true`.
  - **Edit:** `load(record)` reveals text→plaintext, bytes→hex; change a value →
    `commit()` → fake records the edited content for the right uuid.
  - **load failure:** a field whose `reveal` throws → `loadFailed == true`, `error` set,
    `commit()` is a no-op (no write).
  - **validation:** duplicate/empty field name and bad hex → typed `error`, no write.
  - **FFI failure:** fake configured to throw → `error` set, `committed == false`.
  - `addField`/`removeField`/`addTag`/`removeTag` mutate correctly.
- `VaultBrowseModelTest` (extend) — `startAdd`/`startEdit` publish non-null `editing`;
  `cancelEdit` clears it; commit success clears `editing` **and** re-reads; `lock()`
  clears `editing`.
- `FakeVaultSession` (extend) — `appended` / `edited` audit lists + `appendRecord` /
  `editRecord` impls (append flips into the in-memory record set so re-read shows it),
  mirroring the `tombstoned` / `resurrected` pattern.

### Compose instrumented — `:browse-ui` androidTest (emulator, fakes)
- `RecordEditFormTest` / extend `BrowseScreen…Test`: tap "Add record" → form shows;
  fill fields → Save → form dismisses, new row present. Tap `edit-<uuid>` → form
  pre-populated → change value → Save → row reflects change. Save disabled when
  `loadFailed`. testTags: `add-record`, `edit-<uuidHex>`, `field-name-<i>`,
  `field-value-<i>`, `field-kind-<i>`, `save-record`, `cancel-record`.

### Real-`.so` smoke — `:app` androidTest (emulator, staged golden vault)
- Extend `OpenBrowseSmokeTest`: against a **staged copy** of `golden_vault_001` (never
  the frozen fixture) — append a record → re-read shows it; edit an existing record's
  field → re-read shows the change. On-device proof exercising the real atomic
  manifest+block write tail.

### Acceptance gauntlet (mirrors slice 9)
```
./gradlew :vault-access:test :kit:testDebugUnitTest :browse-ui:test :app:test     # host green
./gradlew :browse-ui:connectedDebugAndroidTest :app:connectedDebugAndroidTest     # emulator
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)'   # empty
git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'                # empty
```

## Deliberate decisions (so a future reader doesn't "fix" them)

- **Nested pure `RecordEditModel`, not fields on `VaultBrowseModel`** — single
  responsibility; both files stay under 500 lines; mirrors iOS `makeEditViewModel`.
- **Fresh record UUID minted in the `:kit` adapter via `SecureRandom`** — keeps the pure
  model deterministic/host-testable; the FFI `append_record` takes the uuid as a param.
- **`EditableField.id` is a synthetic monotonic counter, not crypto** — Compose list-key
  stability only; never reaches the vault.
- **Edit form holds plaintext `String`** — accepted, scoped widening matching iOS;
  released on cancel/commit/lock.
- **`lock()` clears `editing`** — in-progress plaintext must not survive backgrounding.
- **Blank tags dropped, empty fields allowed** — matches iOS.
- **No new `VaultBrowseError` arms** — validation is pure `InvalidArgument`; FFI errors
  reuse slice-9's typed arms.

## Out of scope (future slices)
- Sync-badge re-integration onto `BrowseScreen`.
- Recovery-phrase / device-secret open paths on Android.
- `#252` read-path `wiped`-guard gap (cross-platform; tracked separately).
