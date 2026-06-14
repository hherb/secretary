# C.3 (iOS) — Sync orchestration core

**Date:** 2026-06-14
**Milestone:** C.3 (mobile sync adapters), iOS portion, slice 1 of N
**Status:** design — approved approach, pending spec review
**Scope:** iOS only. Orchestration core only. No file-change detection, no SwiftUI, no Android.

## 1. Purpose

Give the iOS app the ability to run **one sync pass** against an already-selected,
already-unlockable vault folder and carry a tombstone-veto conflict to resolution —
entirely in pure, host-testable Swift over the **existing** uniffi sync surface
(`sync_status` / `sync_vault` / `sync_commit_decisions`, projected in #187).

This slice deliberately stops short of:

- **File-change detection** (`NSFilePresenter` / `NSMetadataQuery`) — a later slice.
- **UI** (sync button, conflict-resolution modal, status display) — a later slice.
- **Android** (SAF + `WorkManager`) — a separate milestone.

What ships is the layer those later slices sit on: pure ports, value types, a host-tested
`SyncCoordinator` that threads the two-call inspect→commit round-trip, a real uniffi
adapter, and a scriptable fake.

## 2. Why the iOS core is thin

All sync *logic* already lives in Rust and is frozen by the C.1/C.2 work:

- `core::sync::sync_once → prepare_merge → commit_with_decisions` (the state machine,
  the silent-merge vector-clock LUB fold, the CRDT merge).
- The FFI bridge composes those into two caller-facing operations and projects them
  onto uniffi (#187):
  - **`sync_vault(state_dir, vault_folder, password, now_ms) → SyncOutcomeDto`** —
    inspect / pause-on-conflict. Auto-applies every safe arm; on a tombstone dispute it
    returns `ConflictsPending { vetoes, collisions, manifest_hash }` **without writing**.
  - **`sync_commit_decisions(state_dir, vault_folder, password, decisions, manifest_hash, now_ms)
    → SyncOutcomeDto`** — re-runs the pass, re-checks `manifest_hash` (TOCTOU freshness
    gate) **before** any write, then commits the operator's per-record decisions.
  - **`sync_status(state_dir, vault_uuid) → SyncStatusDto`** — read-only device-clock view.

iOS therefore does **not** re-implement merge, conflict detection, or the freshness gate.
The Swift core only:

1. Maps uniffi DTOs ↔ pure Swift value types (so the rest of the app never imports the
   generated `secretaryFFI` module — same firewall convention as `VaultSession`/`BlockSummary`).
2. Maps `VaultError` → `VaultAccessError`.
3. Offloads the CPU-heavy calls off the calling actor (see §5).
4. Threads the `manifest_hash` token across the inspect→commit round-trip (the
   `SyncCoordinator`).

## 3. Two hard constraints discovered while scoping

### 3a. `sync_vault` runs Argon2id

`sync_vault` (and `sync_commit_decisions`) re-open the vault identity from the password
internally → they pay the full ~0.5–1 s Argon2id cost. They are **as CPU-heavy as `open`**.
Therefore the real adapter MUST offload them via the `SecretaryKit.runOffMainActor` helper
shipped in #227, exactly like `UniffiVaultOpenPort`. A `@MainActor` caller must `await`
and stay responsive, not block. `sync_status` is a cheap disk read (no KDF) and does **not**
need offloading, but is `async` for protocol uniformity and future-proofing.

### 3b. Two-call freshness round-trip

The `manifest_hash` returned by `sync_vault`'s `conflictsPending` is an opaque 32-byte
freshness token. It MUST be passed back **verbatim** to `sync_commit_decisions`. If a
concurrent writer advanced the on-disk manifest between the two calls, the Rust side
returns `EvidenceStale` *before* writing a byte. The `SyncCoordinator` is the unit that
owns this token between calls; it is non-secret metadata and safe to hold.

## 4. Components

### 4a. `SecretaryVaultAccess` (pure ports + value types) — new files

| File | Contents |
|---|---|
| `VaultSyncPort.swift` | `protocol VaultSyncPort` with three `async throws` methods (below). |
| `SyncOutcome.swift` | `enum SyncOutcome` — the six arms; `conflictsPending` carries the detail. |
| `SyncStatus.swift` | `struct SyncStatus { hasState; deviceClocks: [DeviceClock]; lastStateWriteMs: UInt64? }` + `struct DeviceClock { deviceUuidHex; counter }`. |
| `SyncVeto.swift` | `struct SyncVeto` (metadata-only — record UUID, type, tags, field *names*, timestamps, peer device) + `struct SyncCollision { recordUuidHex; fieldNames }` + `struct SyncVetoDecision { recordUuidHex; keepLocal }`. |
| `SyncCoordinator.swift` | The round-trip orchestrator (§4d). |

`VaultSyncPort`:

```swift
public protocol VaultSyncPort {
    func status(stateDir: String, vaultUuid: [UInt8]) async throws -> SyncStatus
    func sync(stateDir: String, vaultFolder: String,
              password: [UInt8], nowMs: UInt64) async throws -> SyncOutcome
    func commitDecisions(stateDir: String, vaultFolder: String,
                         password: [UInt8], decisions: [SyncVetoDecision],
                         manifestHash: [UInt8], nowMs: UInt64) async throws -> SyncOutcome
}
```

`SyncOutcome`:

```swift
public enum SyncOutcome: Equatable {
    case nothingToDo
    case appliedAutomatically
    case silentMerge
    case mergedClean
    case rollbackRejected
    case conflictsPending(vetoes: [SyncVeto], collisions: [SyncCollision], manifestHash: [UInt8])
}
```

The value types are plain `Equatable` structs/enums (no secret material — vetoes are
metadata-only by the bridge's own design; field *values* never cross this boundary).
`manifestHash` is `[UInt8]` (opaque token).

### 4b. `SecretaryVaultAccessTesting` — new file

`FakeVaultSyncPort.swift` — a scriptable fake (same convention as `FakeVaultOpenPort`):
records the calls it received and returns caller-queued `SyncOutcome` / `SyncStatus`
values or throws a queued error. Enough to drive every `SyncCoordinator` path in host
tests, including the conflict round-trip and the stale-token error.

### 4c. `SecretaryKit` (real adapter) — new file

`VaultAccess/UniffiVaultSyncPort.swift`:

- `status` → `secretaryFFI.syncStatus(...)`, map `SyncStatusDto` → `SyncStatus`.
- `sync` → `runOffMainActor { secretaryFFI.syncVault(...) }`, map `SyncOutcomeDto` → `SyncOutcome`.
- `commitDecisions` → `runOffMainActor { secretaryFFI.syncCommitDecisions(...) }`,
  map decisions Swift→DTO, map result DTO → `SyncOutcome`.
- All `VaultError` throws mapped through the existing `VaultErrorMapping` to
  `VaultAccessError` (extend the mapping with the sync-specific variants:
  `SyncInProgress`, `SyncStateVaultMismatch`, `SyncStateCorrupt`, `SyncEvidenceStale`,
  `SyncDecisionsIncomplete`, `SyncFailed`, `WrongPasswordOrCorrupt`, `InvalidArgument`).
  The exact variant set is taken from the bridge `FfiVaultError` / uniffi `VaultError`
  enum at implementation time — see [[project_secretary_ffivaulterror_workspace_match]].

### 4d. `SyncCoordinator` (the orchestration unit)

A small value/reference type that owns the inspect→commit round-trip and the freshness
token. Password is **passed per call, never stored** (only the non-secret token + veto
metadata persist between calls).

```swift
public actor SyncCoordinator {
    public init(port: VaultSyncPort, stateDir: String, vaultFolder: String)

    /// Inspect pass. Returns the outcome; on `.conflictsPending` the coordinator
    /// stashes (manifestHash, vetoes) internally for a subsequent `resolve`.
    public func runPass(password: [UInt8], nowMs: UInt64) async throws -> SyncOutcome

    /// The pending conflict detail from the last `runPass`, if any (for the UI).
    public var pendingConflict: PendingConflict? { get }

    /// Commit decisions against the stashed freshness token. Throws
    /// `VaultAccessError.syncNoPendingConflict` if `runPass` did not pause on a conflict.
    public func resolve(decisions: [SyncVetoDecision],
                        password: [UInt8], nowMs: UInt64) async throws -> SyncOutcome
}
```

- `runPass` clears any previously stashed conflict on every non-conflict arm and stashes
  on `.conflictsPending`.
- `resolve` reads the stashed `manifestHash`, calls `commitDecisions`, and on a
  non-`conflictsPending` result clears the stash. (If the recompute re-raised conflicts —
  rare — the new detail replaces the old.)
- An `actor` to serialize concurrent `runPass`/`resolve` calls against the same vault
  (the Rust side already holds a per-vault lockfile and would return `SyncInProgress`, but
  the actor gives a clean Swift-side rendezvous and avoids a redundant FFI hop).

`PendingConflict` is a small value type `{ vetoes: [SyncVeto], collisions: [SyncCollision] }`
(the token is held privately, not exposed — callers never need to thread it themselves).

## 5. Concurrency & secret hygiene

- `sync` / `commitDecisions` adapters wrap the synchronous FFI call in `runOffMainActor`
  (the #227 helper: `withCheckedThrowingContinuation` + `DispatchQueue.global(.userInitiated)`).
  Rationale identical to `open`: a `@MainActor` caller suspends rather than blocks during
  Argon2id. The return types (`SyncOutcome` / `SyncStatus`) are `Sendable` value types, so —
  unlike the `VaultSession` case in #227 — `Task.detached` would also compile here; we still
  use `runOffMainActor` for **consistency** with the open path (one offload helper, one
  reviewed primitive), documented in the adapter.
- Password is `[UInt8]`, passed per call and dropped at the call boundary; the coordinator
  never retains it. (Swift arrays aren't zeroize-typed; this matches the existing
  `VaultOpenPort` convention — the secret's authoritative lifetime is on the Rust side,
  which wraps it in `SecretBytes`/`ZeroizeOnDrop` immediately.)
- Veto detail is metadata-only by construction (the bridge DTO carries field *names*, never
  values), so the Swift value types hold no plaintext secret material.

## 6. Testing (TDD)

Host tests (`swift test` in `SecretaryVaultAccess`) drive the coordinator against
`FakeVaultSyncPort`:

1. `runPass` maps each safe arm (`nothingToDo` / `appliedAutomatically` / `silentMerge` /
   `mergedClean` / `rollbackRejected`) straight through; `pendingConflict` stays `nil`.
2. `runPass` on `conflictsPending` stashes the detail; `pendingConflict` returns the
   vetoes + collisions.
3. `resolve` after a conflict calls `commitDecisions` with the **stashed** token and the
   supplied decisions; on `mergedClean` it clears the stash.
4. `resolve` without a prior conflict throws `syncNoPendingConflict` (no FFI call made).
5. `resolve` surfacing `EvidenceStale` from the port propagates as `VaultAccessError`.
6. Error propagation: a thrown `VaultAccessError` from any port method surfaces unchanged.
7. Password is forwarded to the port verbatim and not retained (assert the fake saw it;
   coordinator exposes no password accessor).

Adapter-level verification: the `SecretaryKit` simulator suite gets a focused test that
the adapter offloads `sync` off the main actor (mirror the `RunOffMainActorTests` /
`testMainActorIsFreeWhileOpening` pattern via a `SuspensionGate`-style fake port), proving
a `@MainActor` caller stays free during a (faked-slow) sync. The real cross-language sync
behaviour is already covered by the Rust/bridge tests; this slice does not add Rust tests.

## 7. Out of scope (explicit)

- No `NSFilePresenter` / `NSMetadataQuery` (later slice).
- No SwiftUI view, view-model, sync button, or conflict modal (later slice).
- No state-dir path policy / app-group container decision (later slice — host tests pass a
  tempdir; the real `state_dir` choice rides with the file-detection/UI slice).
- No Rust / FFI / bridge / on-disk-format / crypto / CRDT change. `git diff main...HEAD`
  must touch only `ios/**` + `docs/**`.

## 8. Acceptance

- `cd ios/SecretaryVaultAccess && swift test` → all green, including the new
  `SyncCoordinator` host tests (§6.1–6.7).
- `bash ios/scripts/run-ios-tests.sh` → SecretaryKit simulator suite green (incl. the
  adapter off-main-actor test) + app build succeeds.
- Zero new Swift concurrency/Sendable warnings.
- `git diff main...HEAD --name-only | grep -vE '^(ios/|docs/)'` → empty.
- `git diff main...HEAD --name-only | grep -E 'core/|ffi/|crypto-design|vault-format|conflict.rs|core/tests/data'`
  → empty.

## 9. Build sequence (for the plan)

1. **Value types + port protocol** (`SyncOutcome`, `SyncStatus`/`DeviceClock`, `SyncVeto`/
   `SyncCollision`/`SyncVetoDecision`, `VaultSyncPort`) + `FakeVaultSyncPort` + the new
   `VaultAccessError` cases (`syncNoPendingConflict`, plus sync error variants). No logic
   yet; compiles + fake is usable.
2. **`SyncCoordinator`** TDD: write the host tests (§6.1–6.7) first, then the actor.
3. **`UniffiVaultSyncPort`** real adapter (DTO mapping + `runOffMainActor` + error mapping)
   + the SecretaryKit off-main-actor adapter test.
4. **Docs**: README row + ROADMAP C.3 progress note (iOS orchestration core ✅, detection
   + UI pending).
