# iOS biometric re-auth before a write — design

**Date:** 2026-06-20
**Branch:** `feature/ios-write-reauth`
**Scope:** iOS only. No `core/`, crypto/vault spec, `*.udl`, pyo3, or Android changes. This sits over the already-shipped device-unlock (`DeviceSecretEnclave.release`) and the host-tested browse/edit view models. ROADMAP C.3 remaining; carried since the #261 baton.

## Problem

Today an iOS vault session authenticates **once** at unlock, then every mutating write (add / edit / delete / restore record, move record, create / rename block) runs against the open session with no further proof of presence. A device left unlocked-and-open lets anyone mutate the vault. We want a biometric (Face ID / Touch ID) re-auth gate **before** each mutating write.

## Decisions (locked during brainstorm)

1. **Policy = grace window.** A write prompts for biometry only if more than `ReauthWindow.v1Default` seconds have elapsed since the last successful auth (the unlock event seeds this clock). One prompt covers a burst of edits. The window is a **named constant**, not a magic number.
   - **`ReauthWindow.v1Default = 30` seconds** (v1; one global value, no per-write-type tuning).
2. **Primitive = Secure-Enclave key-release.** Re-auth reuses the *same* biometry-bound gate as unlock — `DeviceSecretEnclave.release(reason:)` — which decrypts the non-exportable SE key and returns the 32-byte device secret. The secret is **immediately zeroized and discarded** (re-auth only cares that the release succeeded). This is strictly stronger than a bare `LAContext.evaluatePolicy` presence check: it proves both biometry *and* that the SE key is intact.
3. **Gate predicate = `enclave.isEnrolled`.** Re-auth applies when device-unlock is enrolled (the SE key exists), independent of how *this* session was opened. **Not enrolled → no gate; writes proceed exactly as today** (there is no SE key to release; we do not block deliberately password-only users).
4. **Injection point = view-model level.** The gate is an abstract port injected into the two host-tested view models, keeping the security logic in the pure, FFI-free, host-tested layer.

## Non-goals (YAGNI)

- No settings toggle to disable re-auth.
- No per-write-type custom windows.
- No change to background / auto-lock behavior (separate concern).
- No bare `LAContext.evaluatePolicy` path (rejected in favour of key-release).
- No rendered XCUITest (iOS has no XCUITest harness; on-device Face ID is a manual checklist item, as #202 was).

## Architecture

```
SecretaryVaultAccess  (pure, FFI-free)
  ├─ WriteReauthGate (protocol)            func authorizeWrite(reason: String) async throws
  ├─ needsReauth(lastAuthAt:now:window:) -> Bool        ← pure function: the entire policy
  └─ ReauthWindow.v1Default: TimeInterval = 30          ← named constant
  └─ VaultAccessError.reauthFailed(reason:)             ← new case (local to this enum)

SecretaryVaultAccessUI
  ├─ BiometricAuthorizer (protocol)        var isEnrolled: Bool { get }
  │                                        func authorize(reason: String) async throws
  ├─ GraceWindowReauthGate : WriteReauthGate           @MainActor reference holder
  │     - stores `lastAuthAt: Date?`, seeded at session open / unlock
  │     - on authorizeWrite: if !isEnrolled → return (no-op)
  │                          else if !needsReauth(lastAuthAt, clock(), window) → return
  │                          else try await authorizer.authorize(reason:); lastAuthAt = clock()
  │     - deps: `BiometricAuthorizer` + `clock: () -> Date` (injected for tests)
  ├─ VaultBrowseViewModel    ← gate injected; mutating actions become `async`
  └─ RecordEditViewModel     ← gate injected; `commit()` becomes `async`

SecretaryKit  (real, FFI)
  └─ EnclaveBiometricAuthorizer : BiometricAuthorizer
        - isEnrolled = enclave.isEnrolled
        - authorize(reason:) = { let s = try await enclave.release(reason:); s.zeroized(); discard }

SecretaryVaultAccessTesting
  ├─ FakeBiometricAuthorizer   (spy: callCount, failNextAuth: DeviceUnlockError?, isEnrolled toggle)
  └─ FakeWriteReauthGate       (pass-through default; spy: authorizeCount, failNextAuthorize)
```

### Why the gate is a VM-level port (not a session-level wrapper)

Wrapping `UniffiVaultSession.write()` would land the security/grace/cancel logic in `SecretaryKit` (FFI, simulator-only tests), force blocking-async-from-sync (`write()` is sync, `release()` is async), and prevent the VM from keeping a dialog open on cancel or showing a tailored reason. The VM-level port keeps the whole policy in the pure host-tested layer with a fake gate, reuses `release()` verbatim, and the grace decision is a pure function.

### Package dependency note

`SecretaryVaultAccess` stays FFI-free and does **not** gain a dependency on `SecretaryDeviceUnlock`: it sees only the abstract `WriteReauthGate` / `BiometricAuthorizer` protocols. Only the real `EnclaveBiometricAuthorizer` conformer (in `SecretaryKit`) touches `DeviceSecretEnclave`.

## Data flow (one write)

```
user taps Delete / Save / Move / Create block / Rename
  ▼  VaultBrowseViewModel.delete(record:)   [now async]
  └─ await gate.authorizeWrite(reason: "Confirm deleting this entry")
        ▼ GraceWindowReauthGate.authorizeWrite
        ├─ guard authorizer.isEnrolled else { return }            // not enrolled: no-op
        ├─ if !needsReauth(lastAuthAt, clock(), window) return    // inside grace: no prompt
        ├─ try await authorizer.authorize(reason:)                // Face ID → SE release → zeroize
        └─ lastAuthAt = clock()                                   // only on success
  │  (gate throws → caught below; write NOT attempted; dialog/sheet stays open)
  ▼  guardedWrite(onSuccess: reload) { try session.tombstoneRecord(...) }   // unchanged
```

Three terminal outcomes per write:
1. **Authorized** — enrolled+prompt OK, *or* enrolled within grace, *or* not enrolled → existing write runs.
2. **Cancelled / failed biometric** — write not attempted; `error = .reauthFailed(reason:)`; any open dialog/sheet **stays open** (mirrors the existing "failed write keeps it open" rule).
3. **Clock seeding** — session open / `lock()` sets `lastAuthAt = clock()` from the unlock biometric, so the first write within the window needs no second prompt. (`lock()` itself clears the session; seeding applies to a freshly opened session.)

## Error handling

- `BiometricAuthorizer.authorize` throws `DeviceUnlockError` (already typed: `userCancelled`, `authenticationFailed`, `biometryLockout`, `biometryUnavailable`, …).
- The gate / VM maps that into **one new `VaultAccessError` case — `.reauthFailed(reason: String)`** — carrying a short human label derived from the `DeviceUnlockError`. It is surfaced read-only via the VM's existing `error: VaultAccessError?` property, exactly like every other write error.
- **`.reauthFailed` is internal to `SecretaryVaultAccess`.** `VaultAccessError` is a Swift-only enum, distinct from the Rust-bridge `FfiVaultError`. Adding a case does **not** touch `FfiVaultError`, any `*.udl`, or the Swift/Kotlin conformance harnesses. (The "FfiVaultError variant ⇒ workspace-wide match obligation" rule does **not** apply here — verified: `FfiVaultError` appears only in `SecretaryKit/.../VaultSyncErrorMapping.swift`.)
- All gate failures (including `userCancelled`) set `error`. We do **not** special-case cancel as a silent dismiss in v1 — the UI can choose to render cancel softly later; the VM contract is uniform.

## Affected write sites

| View model | Action(s) | Gated reason string (illustrative) |
|---|---|---|
| `VaultBrowseViewModel` | `delete(record:)` | "Confirm deleting this entry" |
| `VaultBrowseViewModel` | `restore(record:)` | "Confirm restoring this entry" |
| `VaultBrowseViewModel` | `confirmMove(target:)` | "Confirm moving this entry" |
| `VaultBrowseViewModel` | `confirmBlockName(_:)` create | "Confirm creating this block" |
| `VaultBrowseViewModel` | `confirmBlockName(_:)` rename | "Confirm renaming this block" |
| `RecordEditViewModel` | `commit()` append/edit | "Confirm saving this entry" |

Each action awaits `gate.authorizeWrite(reason:)` and only then runs the existing `guardedWrite` / `commitThenReload` / `commit` write. The same-block and blank-name guards stay **before** the gate (no biometric prompt for an input the VM would reject anyway).

## Testing (TDD)

**Pure function `needsReauth(lastAuthAt:now:window:)`** — the whole policy, zero I/O:
- `lastAuthAt == nil` → `true`.
- elapsed `< window` → `false`.
- elapsed `>= window` (boundary at exactly `window`) → `true`. (Boundary direction documented: `>=`.)

**`GraceWindowReauthGate`** (fake `BiometricAuthorizer` + injected `clock`):
- not enrolled → `authorizeWrite` is a no-op; authorizer never called.
- enrolled, never authed → authorizer called once; `lastAuthAt` set.
- enrolled, within grace → authorizer **not** called.
- enrolled, past grace → authorizer called again.
- authorizer throws → `lastAuthAt` unchanged; error propagates.
- success advances the clock so the next immediate write is free.

**`VaultBrowseViewModel` / `RecordEditViewModel`** (fake gate + fake session):
- gate authorizes → write happens; reload/commit as today.
- gate throws → **zero** `session` write calls (spy); `error == .reauthFailed`; dialog/sheet stays open.
- not-enrolled gate → writes proceed (regression: today's behavior preserved).
- existing block-CRUD + record tests updated to `await` the now-async actions with a pass-through fake gate.

**Real-FFI / simulator proof** (`SecretaryKitTests`): `EnclaveBiometricAuthorizer` over the fake enclave (the simulator pattern already used for `SecureEnclaveDeviceSecretStore` compile-verification) — asserts `authorize` calls `release`, zeroizes the returned secret, and `isEnrolled` reflects the enclave.

**On-device Face ID proof** — manual checklist item in the handoff (biometry can't be automated in CI), consistent with #202.

## Acceptance criteria

- A mutating vault write (add/edit/delete/restore/move/create-block/rename-block) on an **enrolled** session prompts a biometric eval first when outside the grace window; within the window it does not re-prompt.
- A biometric cancel/failure **prevents** the write (spy asserts zero session writes) and surfaces `.reauthFailed`, keeping any open dialog/sheet open.
- A **non-enrolled** session writes exactly as today (no gate, no regression).
- Host gauntlet green: `swift test` in `SecretaryVaultAccess` (new `needsReauth`, gate, and VM tests, plus updated existing tests) and `SecretaryDeviceUnlock`.
- `run-ios-tests.sh` green incl. the `EnclaveBiometricAuthorizer` simulator proof.
- Guardrails empty: no `core/` / crypto-design / vault-format / `*.udl` / `secretary-ffi-py` / `android/` / `*.rs` / `Cargo` changes.

## Risks / open notes

- **Async ripple.** Six write actions across two VMs go sync→async; SwiftUI callers already wrap them in `Task {}`, so the call-site cost is low, but every existing test that calls these actions must `await` them. Enumerated in the plan.
- **Grace window value.** 30s is a v1 default; trivially tunable (one constant) if on-device use suggests otherwise.
- **Clock source.** A `() -> Date` injected into the gate keeps the grace logic deterministic in host tests; production passes `Date.init`.
