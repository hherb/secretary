# iOS app — password/recovery unlock + read-only browse

**Date:** 2026-06-12
**Status:** approved (brainstorming) → ready for implementation plan
**Slice of:** "Grow the iOS app beyond the device-unlock walking skeleton"
**Branch:** `feature/ios-vault-unlock-browse`

## Context

The iOS app today (`ios/SecretaryApp/`) is a device-unlock walking skeleton: it
opens a *pre-staged* vault via a *pre-enrolled* Secure-Enclave device secret
(#202, shipped). It cannot open a vault from its credentials, and it cannot show
what is inside one.

This slice adds the smallest genuinely-useful increment: **open an existing
vault by password or recovery phrase, then browse its blocks and records
read-only**, with secret field values revealed only on demand. It is the iOS
analogue of the desktop walking-skeleton (unlock-an-existing-vault + a real
block list).

It is the first of several independent "grow the app" slices. Explicitly
deferred to later slices: record editing/saving, vault create/import, a real
folder picker, search, sync UI, trash UI.

### What already exists (no Rust / uniffi work in this slice)

The complete FFI surface is already implemented in the bridge crate and
**projected to Swift** via `secretary-ffi-uniffi`:

- `open_vault_with_password(folder_path, password) -> OpenVaultOutput { identity, manifest }`
- `open_vault_with_recovery(folder_path, mnemonic) -> OpenVaultOutput { identity, manifest }`
- `OpenVaultManifest.block_summaries() -> [BlockSummary { block_uuid, block_name, created_at_ms, last_modified_ms, recipient_uuids }]`
- `read_block(identity, manifest, block_uuid) -> BlockReadOutput`
- `BlockReadOutput.record_at(idx) -> Record`; `Record.field_at/field_by_name -> FieldHandle`
- `FieldHandle.is_text/is_bytes/expose_text/expose_bytes/wipe`

`expose_text/expose_bytes` re-materialize plaintext on each call — i.e. exposure
is naturally on-demand at the FFI layer. Every handle (`UnlockedIdentity`,
`OpenVaultManifest`, `BlockReadOutput`, `Record`, `FieldHandle`) exposes `wipe()`
which cascades to children.

**This slice is 100% Swift.** It calls the same `open_vault_with_password`
(hence the same manifest verify-before-decrypt, hybrid KEM/sig, Argon2id floor)
as every other open path — it is not a weaker open, and the Swift layer cannot
weaken the core's cryptographic guarantees.

## Goals / non-goals

**Goals**
- Unlock the app-staged demo vault by **password** *and* by **24-word recovery
  phrase**.
- Browse the opened vault: list blocks → list a block's records → reveal a
  field's plaintext on explicit tap.
- Keep all orchestration logic in an FFI-free, host-testable package so the
  secret-lifecycle invariants (wipe-on-teardown, reveal-on-demand-only, no
  plaintext retention after hide) are **enforced as unit-test assertions**.

**Non-goals (later slices)**
- Editing / saving records; creating / importing vaults; folder picker; search;
  sync; trash. No Rust or uniffi changes.

## Architecture

A new FFI-free SPM package `ios/SecretaryVaultAccess/`, mirroring the product
split of `ios/SecretaryDeviceUnlock/`:

| Product | Contents | FFI? |
|---|---|---|
| `SecretaryVaultAccess` | ports (protocols), pure models, typed `VaultAccessError` | no |
| `SecretaryVaultAccessUI` | `@MainActor` view models | no |
| `SecretaryVaultAccessTesting` | in-memory fakes | no |

Real uniffi adapters live in `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/`
(links the xcframework). SwiftUI screens live in `ios/SecretaryApp/Sources/`.
Dependency direction is identical to the device-unlock arc:

```
SecretaryApp ──▶ SecretaryKit ──▶ secretary-ffi-uniffi (xcframework)
     │                │
     └──▶ SecretaryVaultAccess(UI) ◀── SecretaryKit (adapters conform to ports)
                          ▲
        SecretaryVaultAccessTesting (fakes, used by host tests)
```

## Components

### Ports (pure package)

```swift
public protocol VaultOpenPort {
    func openWithPassword(vaultPath: Data, password: [UInt8]) throws -> VaultSession
    func openWithRecovery(vaultPath: Data, phrase: [UInt8]) throws -> VaultSession
}

public protocol VaultSession: AnyObject {
    var vaultUuidHex: String { get }
    func blockSummaries() -> [BlockSummary]
    func readBlock(blockUuid: [UInt8]) throws -> [RecordView]
    func wipe()
}
```

`VaultSession` is the boundary that keeps the pure package from ever naming a
uniffi handle type. The real implementation holds `identity` + `manifest`; the
fake holds in-memory fixtures.

### Pure models

```swift
public struct BlockSummary: Equatable {
    public let uuidHex: String
    public let name: String
    public let createdAtMs: UInt64
    public let lastModMs: UInt64
}

public struct RecordView: Equatable {
    public let uuidHex: String
    public let type: String
    public let tags: [String]
    public let fields: [FieldView]
}

public struct FieldView {
    public enum Kind { case text, bytes }
    public let name: String
    public let kind: Kind
    // Lazy: materializes plaintext ONLY when called. Provided by the session.
    public let reveal: () throws -> RevealedValue
}

public enum RevealedValue {
    case text(String)
    case bytes([UInt8])
}
```

Record/field **metadata** (names, types, tags, kind) carries no plaintext.
Plaintext is materialized only by `FieldView.reveal()`, which the real adapter
maps to `expose_text` / `expose_bytes`.

### View models (UI product, `@MainActor`)

- `UnlockViewModel`
  - publishes `state: UnlockState` (`.idle`, `.busy`, `.unlocked(VaultSession)`, `.failed(VaultAccessError)`)
  - `mode: .password | .recovery`
  - `unlock(secret: [UInt8])` → calls the matching port method
  - Like `DeviceUnlockViewModel`, the synchronous CPU-heavy Argon2id open
    briefly blocks the main actor on the password path — **documented, accepted
    for this slice** (same carried risk + background-offload follow-up as #202).
- `VaultBrowseViewModel`
  - owns the `VaultSession`
  - publishes `blocks: [BlockSummary]`, `selectedBlockRecords: [RecordView]?`,
    and a transient per-field reveal map
  - `selectBlock(_:)` → `readBlock`; `reveal(field:)` / `hide(field:)`
  - **owns `wipe()`**: called on teardown, on lock, and on `scenePhase ==
    .background`

### Adapters (SecretaryKit, `VaultAccess/`)

- `UniffiVaultOpenPort: VaultOpenPort` — wraps `openVaultWithPassword` /
  `openVaultWithRecovery`; maps uniffi `VaultError` → `VaultAccessError` via a
  **file-private** mapping function (same discipline as
  `UniffiVaultDeviceSlotPort.mapVaultError`, so a vault-access mapping is never
  reused on a non-vault-access path).
- `UniffiVaultSession: VaultSession` — wraps `OpenVaultOutput`
  (`identity` + `manifest`); `blockSummaries()` reads `manifest.blockSummaries()`;
  `readBlock` calls the namespace `readBlock` and maps each `Record` /
  `FieldHandle` into `RecordView` / `FieldView`, wiring `FieldView.reveal` to
  `expose_text` / `expose_bytes`; `wipe()` wipes the block-read outputs +
  manifest + identity.

### Screens (SecretaryApp)

- `UnlockScreen` — segmented control (Password | Recovery phrase); secure text
  field for password, multi-line field for the 24-word phrase; unlock button;
  typed error banner. Reuses `AppVaultProvisioning.stageGoldenVault()`.
- `VaultBrowseScreen` — block list → record list (metadata only) → tap field to
  reveal; revealed value shows with an auto-hide affordance.

## Data flow

```
stageGoldenVault()                                  (existing)
  → UnlockScreen collects password | 24-word phrase
  → VaultOpenPort.openWith{Password,Recovery}
  → VaultSession  (holds identity + manifest)
  → VaultBrowseScreen: session.blockSummaries()      (metadata, no plaintext)
  → tap block → session.readBlock(uuid) → [RecordView] (metadata, no plaintext)
  → tap field → FieldView.reveal() → expose_text/bytes (plaintext, transient)
  → dismiss / timeout / background → drop revealed value
  → teardown / lock / background → session.wipe()
```

## Secret-lifecycle & security

The cryptography is enforced in the core and is identical across all open
paths; the security work *in this slice* is Swift-side lifecycle discipline:

1. **Reveal-on-demand, never eager.** Record/field rows render names + types
   only. `expose_text/bytes` is invoked **solely** on explicit user reveal.
2. **Drop revealed plaintext promptly.** A revealed `String` / `[UInt8]` is
   discarded on dismiss, on an auto-hide timeout, and on backgrounding.
3. **Wipe handles deterministically.** `VaultSession.wipe()` (cascades to
   identity / manifest / block / record / field handles) runs on browse-screen
   teardown, on app-lock, and on `scenePhase → .background`.
4. **Backgrounding redaction.** Revealed values are blurred / redacted when the
   app resigns active, so no plaintext lands in the app-switcher snapshot.
5. **No plaintext to logs / diagnostics.** Preserve the #202 rule: diagnostics
   capture domain/code only, never field contents.
6. **Carried, documented residue risk (unchanged from the skeleton, §63 of the
   B.3 handoff):** the password / recovery `String` and any revealed
   `String`/`[UInt8]` cannot be reliably zeroized under Swift value/COW
   semantics; the FFI zeroizes the Rust-side copy. We minimize the exposure
   window; we do not claim to eliminate the Swift-side residue.

## Error handling

Typed `VaultAccessError` in the pure package. **The mapping must preserve the
core's anti-oracle conflation** (`error/unlock.rs`): the uniffi variants are
`WrongPasswordOrCorrupt()` and `WrongMnemonicOrCorrupt()` — "wrong credential"
and "vault corruption" are **deliberately one variant** so a caller cannot use
the error to distinguish a wrong password from a tampered vault (no
padding/auth oracle). The Swift mirror must **not** split these into separate
"wrong credential" vs "corrupt" cases.

| Case | Source |
|---|---|
| `.wrongPasswordOrCorrupt` | `VaultError.WrongPasswordOrCorrupt` (password open — conflated by design) |
| `.wrongMnemonicOrCorrupt` | `VaultError.WrongMnemonicOrCorrupt` (recovery open — conflated by design) |
| `.invalidMnemonic(detail)` | `VaultError.InvalidMnemonic` — **malformed** phrase (a format error, not an oracle; safe to distinguish) |
| `.vaultMismatch` | `VaultError.VaultMismatch` |
| `.corruptVault(detail)` | `VaultError.CorruptVault` (block decrypt/decode failure during browse) |
| `.blockNotFound(uuidHex)` | `VaultError.BlockNotFound` |
| `.invalidArgument(detail)` | wrong-length uuid (`VaultError.InvalidArgument`) |
| `.folderInvalid(detail)` | missing / unreadable folder (`VaultError.FolderInvalid`) |
| `.other(detail)` | any unmapped variant (never a raw panic) |

The mapping lives file-private in the adapter; the VM renders a typed case and
never a raw string. Two properties asserted in tests: (a) a wrong password /
phrase surfaces the **conflated** `.wrongPasswordOrCorrupt` /
`.wrongMnemonicOrCorrupt` variant (it is **not** distinguishable from
corruption — the anti-oracle property), and (b) no failure is mislabeled in a
way that *narrows* the conflation (the #214 `mapDecryptError` lesson, inverted
for this surface: don't turn a deliberately-broad variant into a precise one).

## Testing strategy (TDD; tests precede implementation)

1. **Host (`swift test`, zero native deps)** — fakes implement
   `VaultOpenPort` / `VaultSession`:
   - unlock success on password and recovery; each `VaultAccessError` mapping,
     including that wrong password/phrase surfaces the **conflated**
     `.wrongPasswordOrCorrupt` / `.wrongMnemonicOrCorrupt` (anti-oracle: it is
     *not* split out from corruption);
   - browse navigation (blocks → records);
   - **reveal materializes plaintext only on demand** (fake counts
     `reveal` calls; zero before tap);
   - **`wipe()` called on teardown / lock / background** (fake records wipe);
   - **no revealed plaintext retained after hide**.
2. **Simulator XCTest (SecretaryKit)** — real `UniffiVaultOpenPort` opens the
   *staged* golden vault by password, enumerates blocks, reads one, reveals a
   known field, asserts against the pinned fixture (à la
   `DeviceUnlockIntegrationTests`). Includes a wrong-password →
   `.wrongPasswordOrCorrupt` assertion.
3. **On-device manual smoke** — unlock the staged vault by password on a real
   iPhone, browse, reveal, background→redaction, relaunch.
4. Wire host + simulator runs into `ios/scripts/run-ios-tests.sh`.

## Acceptance criteria

- `cd ios/SecretaryVaultAccess && swift test` — all green; the lifecycle
  invariants above are explicit assertions.
- `bash ios/scripts/run-ios-tests.sh` — host + simulator XCTest + app build all
  succeed.
- The app, on simulator and on a Face-ID device, unlocks the staged vault by
  **password** and by **recovery phrase**, lists blocks, lists a block's
  records, and reveals a text field on tap; backgrounding redacts; relaunch
  re-locks.
- `git diff main..HEAD --name-only | grep -E '\.rs$'` is **empty** (no Rust /
  frozen-format / FFI-surface change).
- Clippy / Rust workspace untouched and unaffected.

## Open decisions / risks

- **Main-actor KDF block on the password path** — accepted for this slice
  (documented), background-offload is a noted follow-up (shared with #202).
- **Swift-side secret residue** — carried, documented (see Security §6).
- **Auto-hide timeout value** — a UX constant to pick during implementation
  (no magic number: named constant with rationale).
- **Recovery-phrase input UX** — single multi-line field, trimmed/normalized
  before passing to the FFI; word-grid input is a later polish, not this slice.
