# iOS `UniffiVaultSession.readBlock`/`wipe()` race — serialize FFI-handle access (#300)

**Date:** 2026-06-25
**Issue:** #300 (`security`, follow-up to #251 / PR #298)
**Scope:** iOS only. No Rust-core / on-disk-format / spec / conformance change.

## Problem

PR #298 (#251 reveal-residency bound) added `currentBlock?.wipe()` inside
`UniffiVaultSession.readBlock` (`ios/SecretaryKit/.../VaultAccess/UniffiVaultSession.swift`).
The iOS `UniffiVaultSession` is a plain `final class` with **no lock**, unlike the
Android `UniffiVaultSession`, which serializes `readBlock` vs `wipe()` under a
`sessionLock` + a `wiped` race guard (per #250). On iOS both `readBlock` (mutates +
wipes `currentBlock`) and `wipe()` (mutates + wipes `currentBlock`, then `manifest`,
then `identity`) touch shared FFI state. If they ever run concurrently on different
threads, they race.

### Why iOS is safe *today* (proven, not assumed)

- The only production caller of `UniffiVaultSession.wipe()` is
  `VaultBrowseViewModel.lock()` (`@MainActor`), including the scene-phase
  `.background` handler (`SecretaryApp.swift`), which runs on the main actor.
- `readBlock` is synchronous and runs on the `@MainActor` VM via `reload`.
- `UniffiVaultSession` is **non-`Sendable`**, and the only off-actor seam,
  `runOffMainActor`, requires `@Sendable` work — so the compiler already bars the
  session from crossing an actor boundary.

This is a sound proof, but it is *convention enforced by a doc-comment a future
maintainer can violate* (e.g. by introducing an off-actor `wipe()` path). On a
security path we prefer enforcement over a plausibility argument.

### Why `@MainActor` enforcement is ruled out

Marking `UniffiVaultSession` / the `VaultSession` protocol `@MainActor` would force
session **construction** onto the main actor. But `UniffiVaultSession(output:)` is
deliberately built **inside** the `runOffMainActor` closure in `UniffiVaultOpenPort`
(off the main actor, so Argon2id open does not block the UI). The session would then
have to cross an actor hop carrying a non-`Sendable` `OpenVaultOutput` FFI handle —
defeating the off-actor open or forcing unsafe contortions. Rejected.

## Decision

Mirror Android: make the iOS type **thread-safe by construction** with an internal
lock + `wiped` guard, serializing *all* shared-FFI-handle access. This also closes
the symmetric write-vs-`wipe()` race (a write touches `identity`/`manifest`, which
`wipe()` zeroizes — the same race class as the issue's `readBlock`/`currentBlock`),
so we do not fix one side and leave the sibling gap open.

### Implementation

`ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSession.swift`:

- Add `private let lock = NSLock()` and `private var wiped = false`.
  (`NSLock.withLock` is available macOS 13 / iOS 16; targets are macOS 13 / iOS 17.
  Chosen over `OSAllocatedUnfairLock.withLock`, whose return value carries a
  `Sendable` constraint that `[RecordView]` — escaping reveal closures — cannot
  satisfy.)
- Wrap in `lock.withLock { … }`, mirroring Android's serialization:
  - `blockSummaries()` — reads `manifest`.
  - `readBlock(...)` — full body. Preserve decrypt-first ordering: decrypt, then
    `if wiped { out.wipe(); return [] }`, then evict prior + retain new + build
    `RecordView`s. (Same flag position as Android: a sequential post-`wipe()` read
    hits the FFI error on dead handles first; the `wiped` branch is defensive depth
    for the genuine concurrent-mid-read case.)
  - private `write(...)` helper — `if wiped { throw .other("write on a wiped
    session") }` **before** resolving device-uuid / running the body, so a write on a
    wiped session short-circuits without touching zeroized handles.
  - `wipe()` — set `wiped = true`, then the existing
    `currentBlock` → `manifest` → `identity` cascade.
- Leave `vaultUuidHex` unguarded (mirrors Android — read-only derived metadata).
- Rewrite the class doc-comment to state the lock + `wiped` rationale and
  cross-reference #300 / #250, matching Android's comment.

Reveal closures (`makeFieldView`) are still invoked later, **outside** the lock, by
the user — unchanged.

## Tests (TDD)

New integration file in `SecretaryKitTests`, opening a temp copy of
`golden_vault_001` with a `FixedDeviceUuid` provider (mirrors
`RecordEditIntegrationTests`; never mutates the frozen KAT):

1. `write_afterWipe_throwsWipedSessionError` — **red→green teeth.** After `wipe()`,
   `appendRecord` throws the wiped-session error. RED on current code (throws a
   *different* FFI-on-dead-handle error), GREEN once the flag-guard short-circuits.
2. `readBlock_afterWipe_yieldsNoRecords` — safety-contract guard: after `wipe()`,
   `readBlock` must not return records (throws / empty).
3. `wipe_isIdempotent` — calling `wipe()` twice is a safe no-op.

Mutual exclusion under genuine concurrency is provided by `NSLock` and documented —
not unit-tested. A deterministic concurrency test would need an injected
mid-`readBlock` seam (over-engineering); a stress test would be flaky (which the
project bans). This matches how Android shipped the same guard.

## Out of scope / non-goals

- No change to `readBlock`'s normal-path behavior (existing reveal-residency +
  record-edit integration tests cover it).
- No `@MainActor` annotation on the type or protocol (see "ruled out").
- No `VaultAccessError` variant added — reuse `.other(String)`.
- README / ROADMAP unchanged (forensic/thread-safety hardening of shipped behavior;
  no new capability or milestone).
