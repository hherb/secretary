# NEXT_SESSION.md — C.3 Android slice 10: record editing/adding ✅

**Session date:** 2026-06-18. Flow: `/nextsession` → slice-9 baton said "push + open PR" but a **parallel session had already merged slice 9** (PR #253, `main` @ `45f4e98`) including its post-handoff fix `dcf0e51` (proven by a byte-identical `main`-vs-branch diff) → housekeeping (removed the merged `c3-android-soft-delete` worktree/branch; two parallel-session worktrees left untouched) → chose **Android slice 10** (record edit/add) → brainstormed (exact iOS parity; "extend the state machine" not a nav lib) → spec → 9-task TDD plan → **subagent-driven execution** (fresh implementer + spec/quality review per task; all review items fixed in-task) → final whole-branch review (opus, "READY TO MERGE") → docs + this handoff.

**Status:** ✅ **code-complete + all-green**, on branch `feature/c3-android-record-edit` (worktree `.worktrees/c3-android-record-edit`). **NOT yet pushed / no PR yet** (push + open PR is the immediate next step — see §4). This is the **second Android slice that WRITES to a vault** (after slice 9): full record **add** and **edit** — a Compose `RecordEditForm` over a pure `RecordEditModel`, mirroring iOS `RecordEditViewModel`. **Pure Android-layer projection of the existing `append_record`/`edit_record` uniffi surface** — no `core`/`ffi`/`ios`/format change (both guardrail greps empty; `append_record`/`edit_record`/`RecordContent` already existed in the UDL + Rust bridge, tested in `ffi/secretary-ffi-bridge/tests/edit.rs`).

## (1) What we shipped this session

**The central idea:** browsing gains an add/edit write path mirroring iOS. An `editing: StateFlow<RecordEditModel?>` on `VaultBrowseModel` selects a **third UI state** on the existing hand-rolled `BrowseScreen` (block-list / record-list / **edit-form**). The form logic lives in a focused **pure `RecordEditModel`** (host-tested, FFI-free). **Add** mints a fresh record; **edit** reveals an existing record's fields into the form (reveal-failure → `loadFailed` → Save disabled, never write a half-loaded record). `commit()` blocks the write on BOTH a validation tier (empty/duplicate field name → `InvalidArgument`) and a hex-parse tier (bad bytes-hex → `InvalidArgument`), then on success calls the real `:kit` writer; the browse model re-reads on success only. Writes serialize under the **same `sessionLock` + `wiped`-first guard as slice 9**, the fresh record UUID is minted via `SecureRandom` **inside the `:kit` adapter** (never the pure model), and `lock()` clears `editing` so in-progress edit plaintext doesn't survive backgrounding.

| Layer | What landed | Commit(s) |
|---|---|---|
| **Spec + plan** | slice-10 design doc + 9-task plan | `e5d0ec8` `fe8c143` |
| **Task 1 — pure input types** | `RecordContentInput`/`FieldContentInput`/`FieldContentValue` + `validate()`; `parseHexLenient` (`:vault-access`) | `015bf16` |
| **Task 2 — write contract + fake** | `VaultSession.appendRecord`/`editRecord`; `FakeVaultSession` impls + audit lists (review fix: `editRecord` throws `RecordNotFound` for absent block) | `bf5bf26` `4940add` |
| **Task 3 — pure RecordEditModel** | `EditableField` + `RecordEditModel` (add/edit/load/commit, loadFailed gate, both validation tiers) (+ 2 coverage tests: blank-tag drop, empty-field-name) | `173a9db` `b4d77b6` |
| **Task 4 — editing state machine** | `VaultBrowseModel.editing` + `startAdd`/`startEdit`/`cancelEdit`/`onEditCommitted`; `lock()` clears editing | `f7ed375` |
| **Task 5 — :kit real writers** | `UniffiVaultSession.appendRecord`/`editRecord` (generic `write<T>`, `SecureRandom` mint in-lock) + `toFfi(RecordContentInput): RecordContent` | `cc4208e` |
| **Task 6 — Compose form** | `RecordEditForm` + `VaultBrowseViewModel` forwarding + `BrowseScreen` third state, Add button, per-row `edit-<uuid>` | `08d137d` |
| **Task 7 — instrumented test** | `RecordEditFormTest` (add + edit) + functional append/edit on BOTH `:browse-ui` fakes | `f4b9ece` |
| **Task 8 — on-device smoke** | `OpenBrowseSmokeTest` append/edit round-trip via real `.so`; `hexToBytesPublic` façade | `83801c8` |
| **Final review + docs** | README/ROADMAP + wording fix + this handoff | `e9c2da1` `3e4ae00` (+ this commit) |

Branch from `main` @ `45f4e98`. **Squash-merge collapses to one commit on `main`** (per-task SHAs above are pre-squash).

### Architecture (where the pieces live)

- **`:vault-access` (package `org.secretary.browse`) — pure, host-tested JUnit5:**
  - `RecordContentInput.kt` — `FieldContentValue.Text(value)/.Bytes(value)` (Bytes has `contentEquals`), `FieldContentInput`, `RecordContentInput.validate(): RecordContentInputError?` (`EmptyFieldName`/`DuplicateFieldName`).
  - `RecordEditModel.kt` — `EditableField(id: Long, name, kind, rawText)` (id = deterministic monotonic counter, NOT crypto); `RecordEditModel(session, blockUuid, Mode.Add | Mode.Edit(recordUuid))` exposing `recordType`/`tags`/`fields`/`error`/`committed`/`loadFailed` StateFlows; mutators `setRecordType`/`addField`/`removeField(id)`/`setFieldName`/`setFieldKind`/`setFieldRawText`/`addTag`/`setTag`/`removeTag`; `load(record)` (reveal-into-form, Bytes → lowercase hex); `suspend commit()` (loadFailed gate → hex tier → validate tier → FFI; blank tags dropped on build).
  - `HexFormat.kt` — added `parseHexLenient(s): ByteArray?` (USER input: strips whitespace, case-insensitive, null on odd/non-hex) and `hexToBytesPublic` (trusted-input façade for `:app`).
  - `VaultBrowseModel` — `editing: StateFlow<RecordEditModel?>`; `startAdd`/`startEdit(record)`/`cancelEdit`/`suspend onEditCommitted()` (clears editing + re-reads); `lock()` clears editing.
  - `VaultSession` interface gains `suspend appendRecord(blockUuid, content): ByteArray` / `editRecord(blockUuid, recordUuid, content)`.
- **`:kit` (package `org.secretary.browse`):**
  - `UniffiVaultSession` — `write` made generic `<T>`; `appendRecord` mints `ByteArray(16)` via `SecureRandom` INSIDE the lambda (under lock, after the `wiped` guard), calls `uniffi.secretary.appendRecord`, returns the uuid; `editRecord` calls `uniffi.secretary.editRecord`. **No new error arms** (validation is pure `InvalidArgument`; FFI reuses slice-9 arms).
  - `RecordContentMapping.kt` — `internal fun toFfi(RecordContentInput): RecordContent` (Text→Text, Bytes→Bytes, name preserved).
- **`:browse-ui` (package `org.secretary.browse.ui`) — FFI-free Compose:**
  - `RecordEditForm` — Type field (`record-type-input`, free text), editable tags (`tag-<i>`, `add-tag`), fields with name (`field-name-<id>`) + Text/Bytes `FilterChip`s (`field-kind-text-<id>`/`field-kind-bytes-<id>`) + value (`field-value-<id>`), `add-field`, Save (`save-record`, disabled when `loadFailed`), Cancel (`cancel-record`).
  - `VaultBrowseViewModel` forwards `editing`/`startAdd`/`startEdit`/`cancelEdit`/`commitEdit`/`onEditCommitted`.
  - `BrowseScreen` — renders the form when `editing != null` (with `LaunchedEffect(committed) → onEditCommitted()`), Add button (`add-record`), per-row `edit-<uuidHex>` on live records. Existing reveal/delete/restore/show-deleted testTags unchanged.
- **`:app`** — `OpenBrowseSmokeTest` gains `append_thenReadShowsNewRecord` + `edit_thenReadShowsChange` (real `.so`, staged golden vault). No structural change (device-uuid store wired in slice 9).

### Acceptance (green — full gauntlet this session)

```
cd android && ./gradlew :vault-access:test :kit:testDebugUnitTest :browse-ui:test :app:test   → BUILD SUCCESSFUL (host JUnit5)
cd android && ./gradlew :browse-ui:connectedDebugAndroidTest :app:connectedDebugAndroidTest    → 14/14 on Medium_Phone_API_36.1:
    RecordEditFormTest 2/2 + BrowseScreenSoftDeleteTest 2/2 + BrowseScreenRevealTest 2/2 (:browse-ui 6/6)
    OpenBrowseSmokeTest 6/6 + MakeVaultSyncSmokeTest 2/2 (:app 8/8)
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)'   → empty
git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'               → empty
```

### Deliberate design decisions (so a future reader doesn't "fix" them)

- **Nested pure `RecordEditModel`, not fields on `VaultBrowseModel`** — single responsibility; both files under 500 lines; mirrors iOS `makeEditViewModel`.
- **Fresh record UUID minted via `SecureRandom` in the `:kit` adapter** — keeps the pure model deterministic/host-testable; the FFI `append_record` takes the uuid as a param.
- **`EditableField.id` is a synthetic monotonic `Long` counter, not crypto** — Compose list-key stability only; never reaches the vault.
- **Edit form holds plaintext `String` (rawText)** — accepted, scoped widening matching iOS; released on cancel/commit/lock.
- **`lock()` clears `editing`** — in-progress plaintext must not survive backgrounding (+ the `:kit` `wiped`-first guard is defense-in-depth).
- **Blank tags dropped, empty fields allowed; no client-side anything** — matches iOS; the Rust write primitives own preserve-on-edit / mint-on-add.
- **No new `VaultBrowseError`/`FfiVaultError` arms** — so the workspace-wide exhaustive-match + Swift/Kotlin conformance-harness obligation is NOT triggered.

## (2) What's next

- **Sync-badge re-integration onto `BrowseScreen`** — unify browse + edit with the slice-5 sync flow into one screen (`AppSyncStateDir` retained in `:app`). Acceptance: the browse/edit screen shows the sync badge and can sync-at-unlock without a separate screen.
- **Recovery-phrase + device-secret open paths** on Android (every slice so far is password-only; `open_with_recovery` / `open_with_device_secret` already exist on the uniffi surface). Acceptance: open the golden vault on-device via the recovery mnemonic; device-secret open via a per-device wrap slot.
- **Block create/rename + record move-between-blocks** — the next CRUD tier (slice 10 manages record *existence + content* within a block; not block lifecycle). Acceptance: create a new block, rename it, move a record across blocks, all re-read-verified on-device.
- **Address #254 (write-action debounce)** — disable Save/delete/restore while a write is in flight (cross-cutting: add/edit + slice-9 delete/restore + iOS) to close the concurrent-double-write gap. Also surface `error.message` detail in the form/browse error banners.
- **On-device veto round-trip** still needs a seeded concurrent state ([[project_secretary_sync_veto_needs_seeded_state]]).
- Optional `WorkManager` background detection (deferred from slice 3).

**Open follow-up issues (carried):** #224 / #234 / #192 / #193 / #190 / #189 / #186 / #161 / #162 / #167 / #202 / #251 / #252. **Filed this session:** **#254** (Android write actions not debounced → concurrent `commit()` can double-write in Add; cross-cutting with slice-9 delete/restore + iOS; also notes the error-banner-detail polish), **#255** (smoke tests leak per-test `devices-*` stores in `noBackupFilesDir`; pre-existing since slice 9; sweep in `@After`).

## (3) Open decisions and risks

- **#254 (filed, not fixed here):** Save/delete/restore have no in-flight guard and the buttons aren't disabled during a write; two fast taps can double-write (Add appends twice — edit is idempotent-ish). Low severity (requires a double-tap inside one write's ms-latency before the form unmounts on first success), same posture as slice-9 and iOS. Deliberately left as a cross-cutting follow-up rather than an add/edit-only patch.
- **Edit form holds plaintext `String`** — the accepted, scoped secret-hygiene widening (the read path's `RevealedValue`/`RevealableField` keep their discipline). Released on cancel/commit/lock; the final review confirmed no retained reference outlives the form.
- **`now_ms` is wall-clock** (`System.currentTimeMillis()`) — CRDT correctness tolerates skew (vector clocks order causally; the death clock handles ties). Same trust model as slice-9 / iOS.
- **Carried, not widened:** #251 (cross-platform `openBlocks` decrypted-plaintext accumulation — a post-write re-read appends another `BlockReadOutput`; unchanged here) and #252 (read-path `blockSummaries`/`vaultUuidHex` lack the `wiped` guard the write/read-block paths have; pre-existing, likely cross-platform).
- **Accepted Minors (final review triaged all as non-blocking):** `FieldContentValue.Bytes` has no `toString()` (deliberate, matches `RevealedValue.Bytes`); error banner shows class name not detail (consistent with the existing `ErrorBanner`, folded into #254); the two browse-ui `FakeVaultSession` copies duplicate the vault-access fake (existing per-source-set pattern). The doc-wording nit ("type picker" vs free-text type + per-field kind picker) was **fixed** (`3e4ae00`).

## (4) Exact commands to resume

```bash
# 0) THIS BRANCH IS NOT YET PUSHED. Immediate next step: push + open the PR.
cd /Users/hherb/src/secretary/.worktrees/c3-android-record-edit
git push -u origin feature/c3-android-record-edit
gh pr create --repo hherb/secretary --title "C.3 Android slice 10: record editing/adding — RecordEditForm + RecordEditModel (add/edit, text + bytes-as-hex)" --body "<summary>"
#    Then the user reviews + squash-merges (this session does not merge).

# 1) After the PR merges, housekeeping (from the MAIN checkout, not this worktree):
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/c3-android-record-edit && git branch -D feature/c3-android-record-edit
git worktree prune && git worktree list

# 2) Next direction (sync-badge re-integration OR recovery/device-secret open OR block CRUD — spec first):
git worktree add .worktrees/<slug> -b feature/<slug> main

# Re-run the gauntlet on this branch (emulator must be running for connected tests):
cd /Users/hherb/src/secretary/.worktrees/c3-android-record-edit/android && \
  ./gradlew :vault-access:test :kit:testDebugUnitTest :browse-ui:test :app:test        # host green
cd /Users/hherb/src/secretary/.worktrees/c3-android-record-edit/android && \
  PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :browse-ui:connectedDebugAndroidTest :app:connectedDebugAndroidTest        # 6/6 + 8/8, emulator running

# Guardrail greps (both must be empty):
cd /Users/hherb/src/secretary/.worktrees/c3-android-record-edit
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)'
git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'
```

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Authored once; the symlink is the pointer. `main` did NOT move during this session relative to the branch point (`45f4e98`), so the symlink retarget merges cleanly. Both this handoff + the retargeted symlink are committed on the feature branch ([[feedback_next_session_in_pr]]). If you resume this branch for fixups, first `git fetch origin && git merge origin/main` (branch-version-wins on the handoff path) before editing — closes the add/add gap ([[feedback_next_session_main_authoritative]]).

## Closing inventory

- **Branch on close:** `main` @ `45f4e98`; `feature/c3-android-record-edit` carries spec + plan + 12 task/fix commits + docs + this handoff commit. Squash-merge → one commit on `main`. **Not yet pushed; no PR yet.**
- **Acceptance:** green — `:vault-access`/`:kit`/`:browse-ui`/`:app` host suites + `RecordEditFormTest` 2/2 + `BrowseScreenSoftDeleteTest` 2/2 + `BrowseScreenRevealTest` 2/2 + `OpenBrowseSmokeTest` 6/6 + `MakeVaultSyncSmokeTest` 2/2 on `Medium_Phone_API_36.1`; both guardrails empty. See §1.
- **Process note:** subagent-driven (fresh implementer + spec/quality review per task; all per-task review items fixed in-task — Task 2 had 1 fix loop, Task 3 added 2 coverage tests). Final whole-branch review (opus) = "READY TO MERGE", all 6 invariants (no-core-change, wiped-first write guard, both commit tiers block, lock-clears-editing, loadFailed gate, FFI-free layering) verified end-to-end; 0 Critical/Important; Minors filed (#254, #255) or fixed (`3e4ae00`).
- **README.md / ROADMAP.md:** updated — Android C.3 slice 10 ✅ (record add + edit).
- **NEXT_SESSION.md:** symlink retargeted to this file.
