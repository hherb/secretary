# Block CRUD tier — create / rename block + move record between blocks

**Date:** 2026-06-19
**Status:** Approved (brainstorming) — ready for implementation plan
**Scope:** FFI write-surface only. `core/` and the on-disk format / crypto spec are **untouched** (these ops compose the existing `core::vault::save_block`).

## Problem

The uniffi write surface (`ffi/secretary-ffi-uniffi/src/secretary.udl`) exposes record-level CRUD (`append_record` / `edit_record` / `tombstone_record` / `resurrect_record`) and block lifecycle (`save_block` / `share_block` / `trash_block` / `restore_block`), but three common operations have no first-class, ergonomic op:

1. **Create an (empty) block** — only possible via `save_block` with an empty `BlockInput`, forcing the caller to build the input struct. A bridge `create_block` helper already exists (`ffi/secretary-ffi-bridge/src/edit/mod.rs:50`) but is **not exposed** on the uniffi surface.
2. **Rename a block** — only possible as a side-effect of `save_block` (the new `block_name` overwrites the old, `orchestrators.rs:1045`), forcing the caller to decrypt and re-supply *every record* just to change the name.
3. **Move a record between blocks** — **does not exist** in any form. Today it would be `append_record(target)` + `tombstone_record(source)` driven by the caller, with no single primitive and no defined cross-block semantics.

## Goal

Add three new uniffi write ops — `create_block`, `rename_block`, `move_record` — following the established `append_record`/`edit_record` pattern, with full forward-compat `unknown` preservation, correct CRDT behaviour under concurrent sync, and host-level test coverage (cargo + Swift/Kotlin conformance + smoke). No new on-disk bytes, no new crypto, no new `FfiVaultError` variant.

## Existing pattern this builds on

Each mutating bridge primitive (`edit/mod.rs`):

1. Decrypts the target block to a native `core::vault::block::BlockPlaintext` via `decrypt_block_plaintext` (keeps untouched records as native `core::Record`, so block/record/field `unknown` survives).
2. Mutates only the target in memory.
3. Re-encrypts + atomically persists through the shared `save_plaintext` tail, which snapshots the manifest handle, builds a temporary `OpenVault`, calls `core::vault::save_block` (owner-only recipients), and writes the mutated manifest back into the handle.

`core::save_block` is insert-or-update by `block_uuid`: it ticks the block-level and vault-level vector clocks, bumps `last_mod_ms`, re-signs the manifest, and writes block-file-first / manifest-second atomically.

The whole surface is **caller-mints-UUIDs** (`append_record` takes `record_uuid`; `BlockInput` carries `block_uuid`) and every write op returns `void`. The new ops keep this convention.

## The three operations

### 1. `create_block`

```idl
[Throws=VaultError]
void create_block(
    UnlockedIdentity identity,
    OpenVaultManifest manifest,
    bytes block_uuid,
    string block_name,
    bytes device_uuid,
    u64 now_ms
);
```

Exposes the existing bridge `create_block` (`edit/mod.rs:50`) on the uniffi surface. Builds a fresh empty `BlockPlaintext` (`block_version = 1`, `schema_version = 1`, no records, empty `unknown`) and saves it. Caller mints `block_uuid` (CSPRNG, 128-bit), exactly as for record UUIDs; uniqueness rests on the caller's generation (a 2⁻¹²⁸ collision would update-in-place rather than error — documented, not enforced, matching the existing bridge contract).

- Empty `block_name` allowed.
- Errors: `InvalidArgument` (wrong-length `block_uuid` / `device_uuid`), `CorruptVault` (wiped handle), save-tail (`FolderInvalid` / `SaveCryptoFailure`).

### 2. `rename_block`

```idl
[Throws=VaultError]
void rename_block(
    UnlockedIdentity identity,
    OpenVaultManifest manifest,
    bytes block_uuid,
    string new_block_name,
    bytes device_uuid,
    u64 now_ms
);
```

New bridge primitive. Decrypts the block to a native `BlockPlaintext`, sets `block_name = new_block_name`, leaves `records` and **all `unknown` maps (block/record/field) untouched**, re-saves via `save_plaintext`. The manifest `BlockEntry.block_name` updates as a save side-effect; `core::save_block` ticks the clock + re-signs.

- Empty `new_block_name` allowed (spec permits empty names).
- Errors: `BlockNotFound(uuid_hex)` (UUID absent from manifest), `InvalidArgument` (wrong-length uuids), `CorruptVault` (wiped handle / decrypt failure).

### 3. `move_record` (the new primitive)

```idl
[Throws=VaultError]
void move_record(
    UnlockedIdentity identity,
    OpenVaultManifest manifest,
    bytes source_block_uuid,
    bytes target_block_uuid,
    bytes source_record_uuid,
    bytes new_record_uuid,
    bytes device_uuid,
    u64 now_ms
);
```

**Move = copy live record into the target block under a fresh UUID, then tombstone the source record.** Caller mints `new_record_uuid`.

**Why a fresh UUID in the target (not the same UUID across blocks):** the CRDT merge (`core/src/vault/conflict.rs`) is record-level *within a single block* — there is no cross-block identity tracking. If the moved record kept its UUID and a concurrent device edited it in the source while another moved it, the same `record_uuid` could be live in two different blocks with no reconciliation path (a permanent duplicate). A fresh UUID in the target keeps each block's CRDT self-contained: the source-side edit stays on the old UUID (which the source death-clock converges to tombstoned), and the target copy is an independent record.

**Order of operations (copy-before-delete — a crash mid-move yields a recoverable transient duplicate, never data loss):**

1. **Validate** `source_block_uuid != target_block_uuid` → else `InvalidArgument`. This check (and uuid-length validation) lives at the **uniffi wrapper** layer, returning the existing `VaultError::InvalidArgument` — the bridge `move_record` trusts its caller (the bridge has no `InvalidArgument` variant, and adding one is the workspace-wide-match obligation this slice avoids).
2. **Decrypt source block**; find the **live** record by `source_record_uuid` → else `RecordNotFound(uuid_hex)`.
3. **Decrypt target block** → else `BlockNotFound(target uuid_hex)`. (Done before any write, so a missing target fails with no side effect.)
4. **Build the target copy** natively — a **faithful move** (the moved entry keeps the secret's age + per-field authorship history; only its identity and record-level modification time are new):
   - `record_uuid = new_record_uuid` (caller-minted), `last_mod_ms = now_ms`, `tombstone = false`, `tombstoned_at_ms = 0`.
   - **Preserve `created_at_ms`** from the source record (the secret was not just created; it moved).
   - Copy `record_type`, `tags`, and each field's **value**.
   - **Preserve record-level `unknown` and each field's `unknown`** (forward-compat — same keystone principle as `edit_record`; a move round-trips the record's content into a new block and must not silently drop data a future schema added).
   - **Preserve each field's `last_mod` / `device_uuid`** (per-field authorship history survives the move). This is CRDT-safe: the fresh `record_uuid` means the copy never field-merges against the original, so preserved field clocks never cross-compare.
5. **Save target first** (`save_plaintext`) — the copy is now committed.
6. **Tombstone the source record** (`tombstone = true`, `tombstoned_at_ms = now_ms`, `last_mod_ms = now_ms`, fields retained so it stays resurrectable — identical to `tombstone_record`) and **save source second**.

`save_plaintext` re-snapshots the manifest handle on every call, so step 6 composes on top of step 5's updated manifest (target's `BlockEntry` already present; `core::save_block` updates the source entry while preserving the target entry). The two blocks' CRDTs remain self-contained; the source death-clock converges any peer that still has the record live.

**Crash/sync safety:** a crash between steps 5 and 6 leaves the record live in both blocks (transient duplicate); the user re-runs the move (or a later move/tombstone reconciles), and no data is lost. The reverse order (tombstone-then-copy) would lose the record on a crash, so it is rejected.

- Errors: `BlockNotFound` (source or target — `uuid_hex` disambiguates which), `RecordNotFound`, `CorruptVault` from the bridge; `InvalidArgument` (source==target, wrong-length uuids) from the uniffi wrapper. **No new `FfiVaultError` variant** (a new variant is a workspace-wide exhaustive-match obligation across uniffi/pyo3/core-KAT + the Swift/Kotlin conformance harnesses; the bridge has no `InvalidArgument`, so that check stays at the wrapper where `VaultError::InvalidArgument` already exists).

## Files touched

| Layer | Change |
|---|---|
| **core/** | none (guardrail: `git diff main...HEAD --name-only \| grep -E 'core/\|crypto-design\|vault-format'` → empty). |
| **bridge** (`ffi/secretary-ffi-bridge/src/edit/`) | New `rename_block` + `move_record` primitives. Expose existing `create_block`. If `edit/mod.rs` approaches 500 lines, split `move_record` into `edit/move_record.rs` (one concept per file). |
| **uniffi** (`ffi/secretary-ffi-uniffi/`) | UDL declarations for the three ops + `wrappers/` projections with uuid-length validation → `InvalidArgument` (matching `wrappers/save.rs`). |
| **conformance/smoke** | Extend Swift + Kotlin smoke (`SmokeRecordEdit.{swift,kt}` or a sibling `SmokeBlockCrud.{swift,kt}`) to exercise create → move → read-back through the real generated bindings on both languages. No `conformance_kat.json` change. |
| **docs** | ROADMAP row (Block CRUD tier). README unchanged unless a user-facing surface note is warranted. |

## Testing (TDD — host-only acceptance bar)

**Bridge cargo tests** (write the test first, then the primitive):

- `create_block` round-trips: block appears in manifest, `block_count` increments, read-back has 0 records + the given name.
- `rename_block` changes only the name: records + block/record/field `unknown` preserved; manifest `block_name` updated; `last_mod_ms` bumped.
- `rename_block` on absent UUID → `BlockNotFound`.
- `move_record` happy path: target gains a record with `new_record_uuid` + copied values + **preserved record-level & field-level `unknown`** + **preserved `created_at_ms` and per-field `last_mod`/`device_uuid`** (faithful move) + fresh record-level `last_mod_ms`; source record is tombstoned (live count drops, `include_deleted` shows it tombstoned).
- `move_record` source == target → `InvalidArgument`; missing source/target block → `BlockNotFound`; non-live/absent source record → `RecordNotFound`.
- `move_record` copy-before-delete ordering: a CRDT-merge / convergence check that the target copy and the source tombstone both survive a merge (target copy is an independent record; source converges to tombstoned).

**uniffi:** cargo tests for the wrapper uuid-length validation (`InvalidArgument` on wrong-length inputs).

**Swift + Kotlin conformance + smoke runners:** create → move → read-back through the real generated bindings; assert via `read_block` (record count, names, secret values, tombstone state).

**Full gauntlet (acceptance):**

```bash
cargo test --release -p secretary-ffi-bridge -p secretary-ffi-uniffi
cargo clippy --release --workspace --tests -- -D warnings
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh
( cd android && ./gradlew :kit:test )
bash ios/scripts/run-ios-tests.sh
# Guardrail (core/spec untouched):
git diff main...HEAD --name-only | grep -E 'core/|crypto-design|vault-format'   # empty
```

No on-device run: these are pure vault-file ops (no enclave/biometric); the real generated bindings exercised by the conformance/smoke harnesses give full behavioural signal.

## Deliberate decisions (so a future reader doesn't "fix" them)

- **Caller-mints all UUIDs; ops return `void`.** Matches `append_record` / `BlockInput`. `move_record` does not return the new uuid because the caller already minted it; introducing a return value would make it the only write op that returns one.
- **Fresh UUID in the target on move** — keeps each block's CRDT self-contained (cross-block identity collisions are impossible). Do not "preserve the original UUID across blocks."
- **Copy-before-delete order on move** — never lose data on a crash; transient duplicate self-heals. Do not reorder to tombstone-first.
- **Preserve forward-compat `unknown` on rename and move** — same keystone principle enforced for `edit_record`.
- **No new `FfiVaultError` / `VaultError` variant** — existing `BlockNotFound` / `RecordNotFound` / `InvalidArgument` / `CorruptVault` cover every case; a new variant is a heavy workspace-wide match + conformance-harness obligation.
- **No `core/` change** — these are bridge compositions over `core::save_block`; the frozen on-disk format and crypto spec stay untouched.

## Out of scope

- Hard-delete (vs tombstone) of records — CRDT requires tombstones for convergence.
- Block-level move/merge (moving all records between blocks in one op) — record-level move is the requested tier.
- On-device round-trip smoke — deferred (host bindings harnesses are the acceptance bar for this slice).
- pyo3 projection of the three ops — uniffi is the mobile path; add pyo3 only if a desktop/Python caller needs them (follow-up).
