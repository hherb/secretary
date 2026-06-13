# iOS Vault Create / Import UI — Design (Slice 2 of 2)

**Date:** 2026-06-14
**Branch:** `feature/ios-vault-create-import` (from `main` @ `1cb67e5`)
**Scope:** 100% Swift. No `core/src` change, no FFI change, no frozen-format change.
**Builds on:** Slice 1 (#223) — the FFI folder-writing `createVaultInFolder` surface.

## Purpose

The iOS app can today *select* an existing vault folder and *unlock* it
(selection → unlock → browse → record CRUD). It cannot **create a brand-new
vault**, and it has no explicit **import** affordance or "is this folder
actually a vault?" feedback. This slice adds both, sitting natively on the
Slice-1 FFI surface and mirroring desktop D.1.3 parity.

## Locked decisions

1. **Folder model — pick parent + name → mkdir subfolder.** The user picks a
   *parent* location via the system folder picker and types a vault name; we
   `mkdir` a fresh subfolder inside it. A fresh subfolder is always empty, so
   the bridge's "existing empty dir" precondition is satisfied structurally and
   no emptiness probe is needed.
2. **Post-create — re-enter password (desktop parity).** After the user
   confirms "I wrote down my recovery phrase", route to the existing Unlock
   screen with the new vault selected; the user re-enters the master password to
   open. No auto-open, no secret carried forward into browse.
3. **Import — entry choice + lightweight `vault.toml` detection.** Add a clear
   Create-vs-Import branch on the selection screen. Import reuses the existing
   folder-pick → unlock flow, plus a Swift-side `vault.toml`-presence check to
   show "this folder isn't a vault" before the user types a password. No new
   crypto, no cross-linking into Create from an empty folder.

## Architecture (Approach 1 — dedicated provisioning module)

The wizard logic and view-model never touch the FFI or the filesystem; they go
through ports, exactly like `UnlockViewModel` uses `VaultOpenPort` today. All
non-I/O logic is pure.

```
SecretaryVaultAccess  (pure, FFI-free)
  ├─ VaultProvisioningStep            enum + pure transitions (folder → credentials → mnemonic → done)
  ├─ validateVaultName(_:)            pure: non-empty, no path separators / "." ".." / traversal
  ├─ passwordsMatch(_:_:)             pure
  ├─ groupMnemonic(_:)                pure: 24 words → numbered rows for display
  ├─ VaultCreatePort   (protocol)     create boundary: mkdir + createVaultInFolder + persist bookmark
  ├─ VaultShapeProbe   (protocol)     import boundary: "does this folder contain a vault?"
  ├─ CreatedVault                     value type: persisted VaultLocation + one-shot phrase bytes
  └─ VaultProvisioningError           typed: invalidName, folderNotEmpty, folderInvalid, createFailed, …

SecretaryVaultAccessUI  (pure, host-tested)
  └─ VaultProvisioningViewModel       @MainActor, drives the wizard over VaultCreatePort

SecretaryKit  (real adapters, FFI + filesystem)
  ├─ UniffiVaultCreatePort            mkdir subfolder in security scope → createVaultInFolder → bookmark → persist
  └─ FileManagerVaultShapeProbe       FileManager check for vault.toml in the picked folder

SecretaryApp  (SwiftUI)
  ├─ VaultSelectionScreen (extended)  entry gains Create / Import branching
  └─ CreateVaultWizardView + 3 step subviews
```

`CreatedVault` carries the persisted `VaultLocation` (so the new vault
immediately becomes the "located" vault for the existing unlock path) plus the
one-shot recovery-phrase bytes for the mnemonic screen.

## Create flow & security-scoped bookmark lifecycle

1. **Folder step** — `fileImporter(allowedContentTypes: [.folder])` yields a
   *parent* URL with security-scoped access. User types a vault name;
   `validateVaultName` runs (rejects empty, path separators, `.`/`..`,
   traversal).
2. **Credentials step** — display name + password + confirm; `passwordsMatch`
   gates Continue. No password-strength UI (desktop parity).
3. **On create**, the view-model calls `VaultCreatePort.create(...)`. The real
   `UniffiVaultCreatePort`:
   - `parent.startAccessingSecurityScopedResource()` with `defer { stop }`
   - `mkdir` the named subfolder inside the scoped parent → guaranteed empty
   - `SecretaryKit.createVaultInFolder(subfolderPathBytes, password, displayName, nowMs)` → `MnemonicOutput`
   - **while still in scope**, create a bookmark of the new subfolder URL and
     persist it via the existing `VaultLocationStore` → the new vault is now the
     "located" vault
   - `takePhrase()` once → carry bytes into `CreatedVault`; `wipe()` the handle
4. **Mnemonic step** — `groupMnemonic` renders the 24 words; "I have written
   down my recovery phrase" checkbox gates Continue. On dismiss/leave, the
   phrase bytes are zeroized.
5. **Done** — route to the existing Unlock screen with the just-persisted vault
   selected; user re-enters the password → existing `open_vault_with_password` →
   browse.

**Secret lifetime:** password owned as `[UInt8]`, zeroized after the port call
returns; phrase bytes zeroized when the mnemonic step is dismissed.

**Two timing invariants:**
- (a) the bookmark is created **inside** the parent's security scope (standard
  pattern for bookmarking a child URL);
- (b) the bookmark is persisted **before** the mnemonic screen is shown, so an
  app kill mid-flow leaves a recoverable, openable vault rather than an orphaned
  folder.

## Import flow & vault-shape detection

The selection screen entry point gains an explicit **Create new vault** /
**Import existing vault** branch (today: a single "Select a vault…" button).

Import reuses the existing folder-pick → unlock path almost verbatim, plus one
addition: after `fileImporter` yields a folder, `VaultShapeProbe.looksLikeVault`
runs before the unlock screen. The real `FileManagerVaultShapeProbe` checks for
the presence of `vault.toml`:

- **Has `vault.toml`** → proceed to the existing unlock screen (unchanged).
- **No `vault.toml`** → show "This folder doesn't contain a vault"; let the user
  pick again (don't persist the bookmark, don't advance to unlock).
- **Probe error** (unreadable) → surface as the existing `.unavailable(reason)`
  selection state.

This is folder-*shape* detection, not validation. A folder with a `vault.toml`
but corrupt contents still surfaces through the existing
`WrongPasswordOrCorrupt`/`CorruptVault` errors at unlock time, exactly as today.

## Error mapping

`VaultProvisioningError` (pure, typed) maps the FFI `VaultError` to user-facing
wizard states:

| FFI `VaultError` | Wizard surface |
|---|---|
| `VaultFolderNotEmpty` | "A folder with that name already exists here — choose a different name" (back to folder step; structurally rare since we mkdir fresh) |
| `FolderInvalid(detail)` | "That location can't be used" (back to folder step) |
| `InvalidArgument(detail)` | a name that passed Swift validation but the bridge rejected — treated as `invalidName` |
| others (`CorruptVault`, …) | generic "Couldn't create the vault" with detail in a diagnostics line |

`validateVaultName` failures never reach the FFI — caught in the folder step as
`.invalidName` before any `mkdir`.

## Testing strategy

Following the existing iOS split (host-tested view-models with fakes; a thin
simulator test for the real FFI).

**Host tests (`swift test`, no simulator) — the bulk:**
- **Pure helpers:** `validateVaultName` (empty, separators, `.`/`..`, traversal,
  valid), `passwordsMatch`, `groupMnemonic` (24 words → correct rows/numbering),
  `VaultProvisioningStep` transitions.
- **`VaultProvisioningViewModel`** over a `FakeVaultCreatePort`: full happy path
  (folder+name → credentials → create → mnemonic → done with persisted
  location), password-mismatch gate, invalid-name gate, `FakeVaultCreatePort`
  throwing each mapped error → correct `VaultProvisioningError` surface, and
  phrase/password zeroization asserted (the fake records whether the secret
  buffers were zeroed).
- **Import detection** over a `FakeVaultShapeProbe`: has-vault → proceeds;
  no-vault → "not a vault" state; probe-error → unavailable.

**Simulator test (real FFI, one end-to-end) — mirrors the `DeviceUnlockViewModel`
on-device proof pattern:**
- Create a vault in a **fresh tempdir** (`FileManager.default.temporaryDirectory`
  + a unique subfolder) via the real `UniffiVaultCreatePort` → assert
  `MnemonicOutput` yields 24 words → then `open_vault_with_password` the same
  folder → assert `display_name` round-trips. Never touches the bundled golden
  fixture (uses a tempdir, not even a copy).

**TDD order:** pure helpers first (red→green each), then the view-model state
machine against the fake, then wire the real adapters, then the simulator
end-to-end last.

## Out of scope (explicitly deferred)

- "This empty folder — create a vault here?" cross-linking from Import into
  Create (the rejected larger import option).
- Password-strength UI / verify-by-re-entry of the mnemonic.
- Auto-open / carrying the password into browse.
- Any Rust / FFI / on-disk-format change.

## Acceptance

- From the selection screen, the user can create a brand-new encrypted vault
  (parent + name → master password + confirm → display name → 24-word
  recovery-phrase screen with "I wrote it down" confirmation) which flows into
  the existing unlock → browse → CRUD path.
- Import = pick a folder containing a vault and unlock it, with "this folder
  isn't a vault" feedback for a non-vault folder before any password entry.
- Host-tested `VaultProvisioningViewModel` + pure-helper tests all green via
  `swift test`.
- A simulator test creates a vault in a tempdir and opens it (display name
  round-trips).
- No `core/src`, FFI, or frozen-format change.
