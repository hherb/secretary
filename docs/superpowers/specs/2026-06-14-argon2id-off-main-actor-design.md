# Argon2id off the main actor — design

**Date:** 2026-06-14
**Slice:** iOS UI responsiveness during the Argon2id KDF
**Branch:** `feature/argon2id-off-main-actor`
**Scope:** iOS Swift only — no Rust core / FFI bridge / on-disk-format / crypto / CRDT change.

## Problem

Two `@MainActor` view-models call **synchronous** port methods inline inside their
`async` methods:

- `UnlockViewModel.unlock` → `port.openWithPassword(...)` / `port.openWithRecovery(...)`
- `VaultProvisioningViewModel.create` → `createPort.create(...)`

The underlying open/create runs Argon2id (`Argon2idParams::V1_DEFAULT` =
m=256 MiB, t=3, p=1), which takes roughly 0.5–1 s. Because the call is
synchronous and the view-model is main-actor-isolated, the KDF executes **on the
main actor**, freezing the UI for the whole derivation. Both view-models document
this as an accepted-for-now stall with a noted background-offload follow-up; this
slice is that follow-up.

Device unlock is intentionally **out of scope**: its key release derives
`device_kek = HKDF-SHA-256(device_secret)`, which is fast — there is no Argon2id
on that path, so its view-model does not stall.

## Approach (chosen: A — async ports, adapter offloads)

The offload concern lives at the FFI-adapter boundary, not in the pure package.
The pure, host-testable `SecretaryVaultAccess` package gains `async` on three port
requirements; the real `SecretaryKit` adapters own the executor hop; the pure
view-models stay clean orchestration that just `await`.

Rejected alternatives:

- **B — offload inside the view-model (`Task.detached` in the VM, ports stay
  synchronous).** Smaller surface, but the *pure* package would capture the
  non-`Sendable` port existential and copy secret bytes across a `Sendable`
  boundary — a hard error under Swift 6 strict concurrency — and would put the
  thread-safety judgement in the view-model, which has no way to know the port is
  thread-safe. Couples the pure package to concurrency plumbing.
- **C — inject a `@Sendable` background-runner abstraction.** Most testable in
  theory but over-engineered for two call sites.

### Offload mechanism: an explicit `runOffMainActor` helper (not bare `async`, not `Task.detached`)

A `nonisolated async` method called from a `@MainActor` caller already hops off
the main actor onto the global concurrent executor (SE-0338), so simply adding
`async` would free the main actor. We nonetheless make the offload **explicit**
via a small `SecretaryKit` helper:

```swift
/// Run a synchronous, CPU-bound (Argon2id) throwing closure off the calling
/// actor on a user-initiated global queue, suspending the caller rather than
/// blocking it.
func runOffMainActor<T>(_ work: @escaping @Sendable () throws -> T) async throws -> T {
    try await withCheckedThrowingContinuation { cont in
        DispatchQueue.global(qos: .userInitiated).async {
            do { cont.resume(returning: try work()) }
            catch { cont.resume(throwing: error) }
        }
    }
}
```

Why this shape, specifically:

1. **Self-documenting** — the offload intent is explicit at the call site rather
   than implied by a language rule a future reader may not know.
2. **Off the bounded cooperative pool** — the KDF runs on a GCD global queue, so
   it never occupies one of the (bounded) Swift cooperative-pool threads.
3. **No `Sendable` warning on a non-`Sendable` return.** `Task.detached { … }`
   constrains `Success: Sendable`; the open path returns `any VaultSession` (a
   non-`Sendable` `AnyObject` existential), which would emit a Swift-5.9 Sendable
   warning — the repo keeps builds clean. `CheckedContinuation<T, _>` deliberately
   does **not** constrain `T`, so the freshly-constructed session/`CreatedVault`
   transfers back across the suspension without a warning. The closure is
   `@Sendable` and captures only `Sendable` values (`Data`, `[UInt8]`, `URL`,
   `String`) — no `self`, since both adapters call module-level FFI functions.
4. Stays correct even if someone later annotates an adapter `@MainActor`.

The helper is the single offload primitive both adapters share (DRY).

## Components changed

1. **Port protocols** (`SecretaryVaultAccess`):
   - `VaultOpenPort.openWithPassword` / `.openWithRecovery` → `async throws`.
   - `VaultCreatePort.create` → `async throws`.
2. **Real adapters** (`SecretaryKit`):
   - `UniffiVaultOpenPort`, `UniffiVaultCreatePort` wrap the synchronous uniffi
     call in `try await runOffMainActor { … }` (the helper above).
   - Typed-error mapping (`mapVaultAccessError` / the provisioning error map)
     stays **inside** the offloaded closure so `VaultAccessError` /
     `VaultProvisioningError` propagate out of the continuation unchanged.
3. **Fakes** (`SecretaryVaultAccessTesting`):
   - `FakeVaultOpenPort`, `FakeVaultCreatePort` gain `async` (bodies unchanged).
   - One open fake grows an optional test-controlled suspension point (a
     continuation gate) so a responsiveness test can hold the port mid-call.
4. **View-models** (`SecretaryVaultAccessUI`):
   - Add `await` to the two port calls. No state-machine change.
   - `state = .busy` is published **before** the `await` suspension, so the UI
     shows progress immediately while the KDF runs in the background.
   - Update the two doc comments that currently describe the accepted main-actor
     stall.

Call sites are unaffected: the VM methods are already `async` and already invoked
via `await` (tests) and `Task { await … }` (SwiftUI).

## Data flow

```
VM (main actor): state = .busy           ← published immediately
  → await port.openWith… / create        ← main actor SUSPENDS here (UI free)
      runOffMainActor (GCD global queue): Argon2id KDF runs
      → typed result, or typed error mapped inside the closure
  → resume on main actor
VM: state = .unlocked(session) / .failed(e)        (unlock)
VM: store.persist + step = .mnemonic / error = …   (create)
```

Secret bytes (`[UInt8]`) move into the detached closure by value. The existing
zeroize discipline is unchanged: the view-models still own clearing their own
Swift-side copies (`VaultProvisioningViewModel` continues to scrub the retained
recovery phrase in `acknowledgeMnemonic`/`cancel`/`deinit`).

## Error handling

Identical typed-error surface. `VaultAccessError` (open) and
`VaultProvisioningError` (create) are thrown from inside the detached closure and
propagate out through `.value`. No new error cases; no change to error mapping
logic, only its execution context.

## Testing

- **Preserve correctness:** all existing transition tests keep passing with
  `async` fakes (the change is one `async` keyword on the fake methods; bodies
  unchanged). Proves the state machine is intact.
- **Prove the offload (new test, both VMs):** a fake port that suspends on a
  test-controlled continuation. The test starts `Task { await vm.unlock(…) }`,
  observes `vm.state == .busy` **while the port is still suspended**, then
  releases the continuation and asserts `.unlocked`. Observing `.busy` mid-call
  is only possible if the main actor was not blocked — against the old
  synchronous-on-main-actor code this test would hang, so it structurally proves
  the offload. Mirror the same shape for `create` (observe `.credentials`→work
  in flight, no main-actor block).
- **Real-adapter sanity (SecretaryKit sim):** the existing integration test that
  opens a temp-copy vault keeps passing through the now-`async` adapter,
  confirming the `runOffMainActor` hop returns the session/typed errors correctly
  against the real FFI.

## Acceptance criteria

- `VaultOpenPort` / `VaultCreatePort` open/create requirements are `async throws`;
  the KDF runs off the main actor via `runOffMainActor` (GCD global queue).
- The two view-models `await` the port calls; `state = .busy` is published before
  suspension; no state-machine regression.
- New responsiveness tests prove the main actor is free while the port is mid-call
  (would hang against the old code).
- Typed-error surface unchanged (`VaultAccessError` / `VaultProvisioningError`).
- Full gauntlet green: `swift test` (host VMs), `run-ios-tests.sh` (SecretaryKit
  sim + app build). No Rust/FFI/format change (`git diff main...HEAD --name-only`
  touches only `ios/**` + docs).

## Out of scope (YAGNI)

- Device-unlock view-model (no Argon2id on that path).
- Any runner/executor abstraction beyond the single `runOffMainActor` helper.
- Cancellation of an in-flight KDF, progress reporting, or priority tuning.
- Any Rust-core, FFI-bridge, conformance-KAT, or on-disk-format change.
