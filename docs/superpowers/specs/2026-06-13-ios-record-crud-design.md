# iOS record CRUD UI — design (Slice 2 of 2)

**Date:** 2026-06-13
**Status:** approved (architecture A; client-side tombstone filter)
**Predecessor:** Slice 1 — FFI projection of record-edit primitives (PR #220, merged `483d285`)

## 1. Purpose

Slice 1 projected the four record-edit bridge primitives onto the uniffi (Swift)
binding: `append_record`, `edit_record`, `tombstone_record`, `resurrect_record`.
This slice builds the **native-iOS record-editing UI** on that surface so that, in a
selected and unlocked vault, the user can:

- **Add** a new record (record type, tags, and an arbitrary set of text/bytes fields).
- **Edit** an existing record's *full content* — add/remove/rename fields, switch a
  field text↔bytes, edit values, and change record type + tags — losslessly
  (`edit_record` diffs and preserves per-field clocks for untouched fields).
- **Soft-delete** (tombstone) a record and **restore** (resurrect) it.

The writes are CRDT-correct (route through `edit_record` et al., **not** the
replace-semantics `save_block`), preserving per-field `last_mod`/`device_uuid`,
`created_at_ms`, `tombstoned_at_ms`, and forward-compat `unknown` maps.

## 2. Background the design depends on

- The browse flow is entered via **password/recovery unlock** (`UnlockScreen` →
  `VaultSession`). That session carries identity + manifest but **no device UUID**.
- Every record-edit FFI fn requires a 16-byte `device_uuid` (the per-field CRDT
  modifier clock) and a `now_ms` wall-clock timestamp.
- `read_block` surfaces **all** records including tombstoned ones, exposing deletion
  via a per-record `tombstone()` flag — it does **not** filter. The iOS read path has
  no `include_deleted` gate (desktop D.1.5 has one in Rust; we do not add it this slice).

## 3. Decisions

### 3.1 Write surface lives on `VaultSession` (architecture A)

`append/edit/tombstone/resurrect` become methods on the existing `VaultSession`
protocol. Rationale: identity + manifest are encapsulated inside
`UniffiVaultSession`, so the write must go through the session; one session object
keeps the write path symmetric with the read path. A write capability is strictly
*less* sensitive than the read capability the session already holds (it can already
decrypt all plaintext via `readBlock`), so this is not a privilege escalation and a
separate write protocol would not be a real security boundary. The *pure* work (input
types, device-UUID derivation, clock) stays in small free-function/value modules; only
the FFI commit is a session method.

**Security review verdict (no substantial implications):** no new authority; writes
route through the same Slice-1 FFI bridge (manifest verify-before-decrypt — not a
weaker open, no new `FfiVaultError` variant); `device_uuid` is a non-secret public
fingerprint; plaintext byte payloads passed to FFI are zeroized after each call and
not stashed. Residual (pre-existing, not a regression): SwiftUI binds in-progress text
entry to `String`, which can't be reliably zeroized — identical to how `UnlockScreen`
holds the master password today.

### 3.2 Device UUID — parity with desktop `load_or_create_device_uuid`

A new file-backed `DeviceUuidStore` mirrors
`desktop/.../settings/io.rs::load_or_create_device_uuid_in`:

- 16 random bytes from `SecRandomCopyBytes`, **per-(install, vault)**, keyed by
  lowercase vault-UUID hex.
- Persisted under `Application Support/Secretary/devices/<vaultHex>.dev`.
- **Excluded from iCloud/iTunes backup** (`URLResourceValues.isExcludedFromBackup`):
  one device must equal one CRDT fingerprint, so a restored backup must not clone it.
- Atomic create-or-read-back: on first call, write atomically and return the bytes; on
  subsequent calls (or a lost create race), read the persisted bytes and return *those*.
- A `_in`-style core takes an injected directory so it is **host-testable** with a temp
  dir, exactly like desktop's `load_or_create_device_uuid_in` tests.
- Not secret material → an Application-Support file (not Keychain/Secure Enclave) is the
  correct analog of desktop's plaintext `.dev` file.

The session resolves the device UUID lazily on first write and caches it for the
session lifetime.

### 3.3 `now_ms` via an injectable `Clock`

A `Clock` protocol (`func nowMs() -> UInt64`); production uses `Date()`
(`UInt64(Date().timeIntervalSince1970 * 1000)`), tests inject a fixed clock so
view-model assertions are deterministic.

### 3.4 Deleted records: hidden by default + "Show deleted" toggle

`read_block` returns tombstoned records; the browse view model filters them
**client-side in Swift**. A `showDeleted` toggle reveals them (dimmed), where a
**Restore** action calls `resurrect_record`. This mirrors desktop D.1.5's
`include_deleted` UX without adding an iOS Rust read gate this slice.

## 4. Module layout (kept small; FFI-free where possible)

### `SecretaryVaultAccess` (pure, no FFI)
- `VaultSession.swift` — add the four write methods to the protocol. Each takes
  *domain* inputs and returns after the commit + caller-driven refresh.
- `RecordContentInput.swift` — Swift domain type (`recordType`, `tags`,
  `fields: [FieldContentInput]`, value enum `text(String)` / `bytes([UInt8])`) so view
  models never name the uniffi `RecordContent`. Keeps this package FFI-free (it already
  abstracts `FieldHandle` behind closures).
- `Clock.swift` — `Clock` protocol.
- `DeviceUuidProviding.swift` — per-session provider protocol (`func deviceUuid() throws -> [UInt8]`).

### `SecretaryVaultAccessUI` (view models, host-tested)
- `RecordEditViewModel.swift` — drives add/edit form state, field add/remove/rename,
  text↔bytes toggle, validation, and `commit()` → `session.{append,edit}Record` →
  surface success/typed error. Prefill on edit pulls current values via the existing
  on-demand reveal closures.
- `VaultBrowseViewModel.swift` — gain `showDeleted: Bool`, a derived live/deleted
  partition (client-side `tombstone()` filter), and `tombstone(record:)` /
  `resurrect(record:)` actions that commit then re-read the block.

### `SecretaryVaultAccessTesting`
- `FakeVaultSession.swift` — gain an in-memory record store implementing the four
  writes so VM tests exercise real add/edit/delete/restore state transitions.

### `SecretaryKit` (FFI adapter)
- `UniffiVaultSession.swift` — implement the four writes: map `RecordContentInput` →
  uniffi `RecordContent`/`FieldInput`/`FieldInputValue`, **zeroize** the plaintext byte
  payloads after the call, mint a fresh 16-byte record UUID on add, resolve
  `device_uuid` (via `DeviceUuidStore`) + `now_ms` (via `Clock`), map `VaultError`.
- `DeviceUuidStore.swift` — the real file-backed provider (testable `_in` core +
  Application-Support default + backup exclusion).
- A production `Clock` impl.

### `SecretaryApp` (views)
- `RecordEditScreen.swift` — Form-based add/edit screen (same idiom as `UnlockScreen`),
  with an Error section for typed failures.
- `VaultBrowseScreen.swift` — add/edit/delete/restore entry points; "Show deleted"
  toggle; delete confirmation dialog; navigation/sheet into `RecordEditScreen`.
- `SecretaryApp.swift` (`RootView`) — minimal wiring if the edit screen needs routing.

## 5. Data flow

- **Add:** browse screen (a block is selected) → mint record UUID →
  `RecordEditScreen` (empty) → on save, `RecordEditViewModel.commit()` calls
  `session.appendRecord(blockUuid:recordUuid:content:)` → session resolves device UUID +
  `now_ms` → FFI `append_record` → browse re-reads the block → list refreshes.
- **Edit:** tap a (live) record → `RecordEditScreen` prefilled (values revealed on
  demand) → edit full content → `session.editRecord(...)` → re-read.
- **Delete:** confirmation dialog → `session.tombstoneRecord(...)` → re-read; the record
  leaves the live list (still visible under "Show deleted").
- **Restore:** Restore action on a shown deleted record → `session.resurrectRecord(...)`
  → re-read.

## 6. Error handling

Map `VaultError` (`RecordNotFound`, `InvalidArgument`, …) onto the typed
`VaultAccessError` surface the browse VM already uses. The edit screen renders failures
in an Error section (the `UnlockScreen` pattern) and never silently no-ops. Length
validation of the 3 UUIDs already happens binding-side (→ `InvalidArgument`); the Swift
layer mints correctly-sized UUIDs so that path is defensive only.

## 7. Testing (TDD, three-tier as established)

- **Host VM tests** (`swift test`, fakes): add/edit/delete/restore state transitions,
  field add/remove/rename + text↔bytes, validation, the `showDeleted` partition, and
  typed-error surfacing — via `FakeVaultSession`.
- **Host `DeviceUuidStore` tests** over a temp dir: create→persist→read-back stability,
  distinct-per-vault, length validation, backup-exclusion attribute set — mirroring
  desktop's `load_or_create_device_uuid_in` tests.
- **Simulator XCTest end-to-end round-trip:** unlock → add → edit → delete → restore,
  against a **`cp -R` temp copy of the golden vault — never the tracked fixture** (this
  slice writes, and `golden_vault_001` is a frozen KAT). The edit assertion proves
  losslessness: an untouched field keeps its prior `device_uuid` after an edit (the same
  per-field-clock proof the FFI smoke test makes).
- **On-device smoke:** manual add/edit/delete/restore on a hardware device.

## 8. Out of scope (follow-ups)

- iOS read-path `include_deleted` Rust gate (we filter client-side this slice).
- Biometric re-auth before a write (the session is already unlocked).
- iOS vault create/import (separate slice, mirrors desktop D.1.3).

## 9. Acceptance

In a selected, unlocked vault: add a new record, edit an existing record's full content
losslessly, soft-delete and restore a record. Host-tested view models + `DeviceUuidStore`
tests green via `swift test`; simulator XCTest round-trip green against a temp vault copy;
on-device smoke passes. No `core` / frozen-format / `FfiVaultError`-variant / conformance-KAT
change.
