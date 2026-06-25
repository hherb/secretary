# Design: iOS/Android memory-hygiene hardening (#251 + #229)

**Date:** 2026-06-25
**Issues:** #251 (reveal-residency accumulation, iOS + Android), #229 (iOS FFI-boundary password copy not scrubbed)
**Scope:** `ios/` + `android/` FFI port-adapter surface only. No Rust-core / on-disk-format / spec change; `conformance.py` untouched.

## Problem

Two independent, pre-existing gaps in the Swift/Kotlin layer that widen the in-memory
plaintext-residency window beyond what the feature needs. Both run against the
zeroize/minimize-residency discipline the Rust core follows (`Sensitive<T>` / `SecretBytes`,
CLAUDE.md "Memory hygiene: zeroize discipline").

### #251 — `openBlocks` accumulates every visited block's plaintext until lock

`UniffiVaultSession.readBlock` appends each decrypted `BlockReadOutput` to an `openBlocks`
list (iOS `UniffiVaultSession.swift:56`, Android `UniffiVaultOpenPort.kt:128`) and never
releases it until the whole session is wiped (lock / background). Consequences:

- **Accumulation across navigation.** Browsing A → B → A leaves block A's *entire* decrypted
  contents (every field, not just revealed ones) resident even after navigating away. The
  reveal map is cleared on every `selectBlock` (VM layer), so no live reveal closure
  references a prior block — yet its plaintext stays decrypted.
- **Duplicate retention.** Re-selecting the same block appends another `BlockReadOutput`;
  nothing dedups. A long browse session monotonically grows the resident plaintext set.

The reveal architecture is a deliberate cross-platform mirror, so this is a **parity
property**, not an Android-only bug. The Android concurrency hazard (read racing `wipe()`)
was already fixed in #250 via `sessionLock` + a `wiped` guard; that fix does **not** change
the accumulation behavior tracked here.

### #229 — iOS FFI-boundary password `Data` copy is never scrubbed

Master passwords / recovery phrases are passed as `[UInt8]` and copied into `Data(password)`
at the FFI boundary; the `Data` buffer is not overwritten after the call. uniffi copies the
`Data` into Rust (where it *is* zeroized), so the residue is the Swift-side `Data` copy.
Five sites across three port adapters:

- `UniffiVaultOpenPort.openWithPassword` / `openWithRecovery`
- `UniffiVaultCreatePort.create`
- `UniffiVaultSyncPort.sync` / `commitDecisions`

(The create port already correctly scrubs its recovery-phrase *output* via
`phrase.resetBytes`; #229 is strictly about the *input* password/phrase copy.)

## Design

### Part A — #251: bound reveal-residency to the on-screen block

Replace the unbounded accumulator with a single retained block, making "≤1 block resident"
a **type-level invariant** (accidental accumulation becomes impossible):

- Field type changes `openBlocks: [BlockReadOutput]` → `currentBlock: BlockReadOutput?` on
  both `UniffiVaultSession` (iOS Swift + Android Kotlin).
- On each **successful** `readBlock`: decrypt the new block first; if it succeeds, wipe + drop
  the previously-retained block, then retain the new one.
  **Decrypt-first ordering is load-bearing:** if the new decrypt throws, the prior block stays
  retained so the on-screen block's live reveal closures remain valid (no use-after-wipe).
- `wipe()` becomes `currentBlock?.wipe(); currentBlock = nil; manifest.wipe(); identity.wipe()`
  (same blocks → manifest → identity order).

Platform specifics:

- **iOS** (`readBlock` is synchronous): `out = try readBlock(...)` → `currentBlock?.wipe()` →
  `currentBlock = out`.
- **Android** (`readBlock` runs on `ioDispatcher`, `wipe()` on main): the eviction happens
  **inside the existing `sessionLock`**, after the `wiped`-race check. Both the `sessionLock`
  serialization and the `wiped` guard are preserved unchanged. Sequence under the lock:
  decrypt → if `wiped` { wipe new block; return empty } → else { `currentBlock?.wipe()`;
  `currentBlock = block` }.
- Update the stale Android doc-comment (`UniffiVaultOpenPort.kt:104-107`) that currently cites
  #251 as an *accepted* residency tradeoff — it is now fixed.

**Safety argument.** The VM clears the reveal map on `selectBlock`, so at the moment a new
`readBlock` evicts the prior block, no live reveal closure references it. This is exactly the
invariant the issue identifies as making option 1 safe. Retains the exact reveal behavior;
bounds both decrypted plaintext and native FFI handles to one block; dedups re-selection.

### Part B — #229: scrub the FFI-boundary `Data` copy

A small reusable helper in `SecretaryKit`, decomposed into a pure, directly-testable core:

```swift
/// Overwrite every byte of `data` in place. Pure; post-condition: all bytes zero.
func zeroize(_ data: inout Data)

/// Build a `Data` from `bytes`, run `body`, and scrub the `Data` on the way out
/// (defer fires on both normal return and a thrown error).
func withZeroizingData<T>(_ bytes: [UInt8], _ body: (Data) throws -> T) rethrows -> T {
    var data = Data(bytes)
    defer { zeroize(&data) }
    return try body(data)
}
```

Applied at all five sites, e.g.:

```swift
try withZeroizingData(password) { pw in
    try SecretaryKit.openVaultWithPassword(folderPath: vaultPath, password: pw)
}
```

### Documented residual (honest scope)

The adapter **cannot** scrub the caller's (VM-owned) `[UInt8]`: Swift arrays are
copy-on-write, so mutating the adapter's binding triggers CoW into a fresh throwaway buffer
and leaves the caller's storage untouched. The achievable scrub is the adapter-owned `Data`
copy — the one concrete heap copy the boundary owns. The VM-owned input array's lifetime is
already minimized by the existing "password passed per call, never stored" discipline; its
residue is a separate concern and is documented as a known limitation in the helper's doc
comment, mirroring how the Rust side documents `Sensitive<T>`.

## Testing (TDD)

- **#251 teeth test** (one per platform — iOS `SecretaryKitTests`, Android instrumented/host
  with a real vault fixture): `readBlock(A)` → capture a field reveal closure → `readBlock(B)`
  → invoking A's now-stale reveal closure returns `nil` / throws, proving A's `BlockReadOutput`
  was wiped on navigation. Fails on the current accumulate-forever code; passes after the fix.
  Also assert re-selecting the same block does not grow residency (single-optional invariant).
- **#229 unit tests** (`SecretaryKitTests`): `zeroize(&data)` overwrites all bytes
  (all-zero post-condition); `withZeroizingData` returns the body result on success and still
  scrubs when the body throws.

## Out of scope

- The unprojected contact primitives (`enumerate/delete/revoke`, #206 follow-up).
- VM-side input-array scrubbing (separate VM concern; documented residual above).
- Android `#229` analogue: Kotlin forwards the password `ByteArray` directly to the uniffi
  function (`UniffiVaultOpenPort.kt:47`) with no second buffer copy, so there is no
  adapter-owned copy to scrub. Verified during implementation; noted, no change.

## Risks

- None to honest-vault behavior. #251's eviction only drops blocks the user has navigated
  away from (reveal map already cleared); the on-screen block is always retained. #229 only
  overwrites a copy after the FFI call has consumed it.
- No new error variant, no format/semantics change → `conformance.py`, conformance KATs, and
  the Swift/Kotlin conformance harnesses are unaffected.
