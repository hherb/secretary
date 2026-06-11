# iOS app — vault selection (real folder picker + persisted security-scoped bookmark)

**Date:** 2026-06-12
**Branch:** `feature/ios-vault-selection` (from `main` @ `acc53ae`)
**Status:** design approved; ready for implementation plan
**Scope:** 100% Swift. No Rust / on-disk-format / FFI-surface change.

## Problem

The iOS app (shipped in #216) can unlock a vault by password or recovery phrase and
browse it read-only — but it only ever opens **one hardcoded, bundled vault**
(`golden_vault_001`, staged from `Fixtures/` into Application Support) with the
golden password **prefilled** in the unlock screen. That prefill is explicitly
marked "MUST be removed when real vault selection lands."

This slice lets the app open a **user's own vault folder**, selected via the system
file picker, and **remember it across launches** via a persisted security-scoped
bookmark. It is the iOS analogue of desktop vault selection and the natural
prerequisite to making the app genuinely usable.

## What ships

1. The user can pick a vault **folder** with the system picker (`.fileImporter([.folder])`).
2. The picked location is persisted as a **security-scoped bookmark** so the next
   launch reopens straight to that vault's unlock screen.
3. A "Choose a different vault" action re-picks and **replaces** the remembered vault.
4. The bundled golden vault is retained as an **explicit, opt-in "Try the demo vault"**
   button — never the default, with **no prefilled password**.
5. The prefilled demo password in `UnlockScreen` is **deleted**.

### Persistence scope (decided)

**Single remembered vault** — one bookmark for the last-opened vault. A multi-vault
"recent vaults" list is explicitly **out of scope** for this slice (YAGNI; can come later).

### Demo vault (decided)

**Keep as an explicit opt-in** — the selection screen offers both "Select a vault…"
(real picker) and "Try the demo vault" (bundled golden). The demo password is **not**
prefilled. This retains an easy on-device smoke path while making real selection the
primary flow.

## Approach (decided: A — pure port + host-tested selection VM)

Matches the existing codebase discipline (FFI-free pure ports + uniffi/Foundation
adapters + host-tested ViewModels). The genuinely error-prone logic — the
security-scope **begin/end balance** and **stale-bookmark handling** — lives behind a
port so it is **unit-tested against a fake**, while the iOS-only Foundation calls stay
behind the boundary.

### Security rationale for A over "all in the app layer" (B)

A and B are **security-equivalent at the boundary level**: same Foundation
bookmark/security-scope APIs, in-process, same app target, no trust/process boundary
crossed. The real security boundary (manifest verify-before-decrypt + anti-oracle
conflation) lives in the Rust FFI and is **untouched** by both. A does **not** add a
security boundary.

What A buys is converting two security-*adjacent* invariants from untested app code
into **unit-tested properties**:

1. **Security-scope begin/end balance (leak prevention).** Every
   `startAccessingSecurityScopedResource()` must be paired with a `stop…` on lock/wipe.
   A leak keeps a live, accessible handle to the user's out-of-sandbox vault folder
   open longer than the unlocked session, and iOS caps simultaneously-open
   security-scoped resources (opens eventually fail). Under A this balance is an
   asserted invariant against a fake's counter; under B it is only ever exercised by
   hand in the simulator.
2. **No silent fallback on a stale/invalid bookmark.** An unresolvable bookmark must
   surface as a typed error → re-pick prompt, never a silent fall-through or swallowed
   error (consistent with the project's no-silent-failure posture). Under A this is a
   tested state transition; under B it is ad-hoc `try?` handling.

Explicitly **not** claimed as security wins for A (to avoid overselling):
- **No secret material flows through the selection layer at all** — it handles only
  the *folder path*. The password/phrase still go straight
  `UnlockViewModel → port → FFI`. No zeroize/secret-residue dimension to this choice.
- **A security-scoped bookmark is not a secret** — it is an opaque path token with no
  key material — so persisting it in `UserDefaults` is fine under both A and B.

## Components

### New pure types — `SecretaryVaultAccess` (FFI-free, host-tested)

| Type | Role |
|---|---|
| `VaultLocation` | Value model: `displayName: String` + opaque `bookmark: Data`. No key material — picker token + label. `Equatable`. |
| `VaultLocationStore` (protocol) | The **port**. `load() -> VaultLocation?`, `persist(_:)`, `clear()`, `beginAccess(_ location: VaultLocation) throws -> ScopedVaultPath`. |
| `ScopedVaultPath` | Handle returned by `beginAccess`: exposes `pathData: Data` (UTF-8 folder path for the FFI) and `end()` releasing the scope. Models "scope held while this lives." `end()` is idempotent. |
| `VaultSelectionError` | Typed, selection-layer (distinct from `VaultAccessError`): `.noVaultSelected`, `.locationUnavailable(String)`, `.accessDenied(String)`. |
| `VaultSelectionViewModel` | `@MainActor` state machine. State: `.empty` / `.located(displayName)` / `.unavailable(reason)`. API: `loadPersisted()`, `recordSelection(bookmark:displayName:)`, `chooseDifferent()`, `beginAccess() throws -> ScopedVaultPath`. Host-tested against a fake. |

### Real adapter — `SecretaryKit/Sources/SecretaryKit/VaultAccess/`

- `BookmarkVaultLocationStore: VaultLocationStore`
  - persist/load via a named `UserDefaults` suite (bookmark `Data` + display name).
  - `beginAccess`: `URL(resolvingBookmarkData:options:relativeTo:bookmarkDataIsStale:)`
    → on stale, **refresh the bookmark and re-persist** (logged, not silent) →
    `startAccessingSecurityScopedResource()`; if it returns `false`, throw
    `.accessDenied`. Returns a `ScopedVaultPath` whose `end()` calls
    `stopAccessingSecurityScopedResource()` exactly once.
  - iOS bookmark-API note: iOS does **not** use the macOS `.withSecurityScope`
    create/resolve options; a bookmark created from a document-picker URL is
    implicitly security-scoped on iOS. (Verify exact option set during impl.)
  - One focused file (<300 lines); split if it grows.

### Testing product — `SecretaryVaultAccessTesting`

- `FakeVaultLocationStore` — in-memory location + a **start/stop access counter** so
  tests assert begin/end balance and leak-freedom.

### App — `SecretaryApp`

- `VaultSelectionScreen` (new): "Select a vault…" → `.fileImporter([.folder])`; opt-in
  "Try the demo vault" button (no prefilled password).
- `RootView`: route becomes `select → unlock → browse`; on lock/background, release
  the scope (`scoped.end()`) and route back appropriately.
- `UnlockScreen`: **delete** the prefilled demo password.
- `AppVaultProvisioning`: retained, reached **only** via the explicit
  "Try the demo vault" path.
- No new iOS entitlement expected (UIDocumentPicker grants user-selected access on iOS
  without one — verify during impl).

## Data flow & the security-scope lifecycle

**Launch / selection:**
```
App launch → VaultSelectionViewModel.loadPersisted()
   store.load() == nil      → .empty            → "Select a vault…" / "Try demo"
   store.load() == location → .located(name)    → unlock screen for it
```

**Picking a vault:**
```
"Select a vault…" → .fileImporter([.folder])
   on pick(url): url.startAccessingSecurityScopedResource()   (brief, to bookmark)
                 bookmark = url.bookmarkData()
                 url.stopAccessingSecurityScopedResource()
                 store.persist(VaultLocation(name: url.lastPathComponent, bookmark))
                 VM → .located(name)
```

**Opening + browsing — scope held for the WHOLE session:**
```
entering unlock for a .located vault:
   scoped = try VM.beginAccess()       // resolve bookmark → URL,
                                        // startAccessingSecurityScopedResource(),
                                        // refresh+re-persist if stale,
                                        // returns ScopedVaultPath{ pathData }
   UnlockViewModel(port, vaultPath: scoped.pathData)
   … unlock → VaultSession (lazy block reads use the SAME held scope) …
   on lock / background:
        session.wipe()
        scoped.end()                     // stopAccessingSecurityScopedResource()
        route back to UNLOCK for the same remembered vault (no re-pick needed)
   on "choose different vault":
        session.wipe() (if open); scoped.end() (if held); store.clear()
        route to SELECT
```

Routing rule (disambiguated): a background/lock returns to the **unlock** screen for
the *still-remembered* vault — the user re-enters their password, not the picker.
Only the explicit "choose different vault" action clears the bookmark and routes to
the **select** screen.

**Invariant:** the scope opened by `beginAccess()` is held from before the FFI open
through every lazy block read, and released exactly once on lock/wipe. `RootView`
already locks on `.background`; that same path now also calls `scoped.end()`.
`ScopedVaultPath` is the single owner of the live scope, so begin/end pairing is
structurally enforced and unit-testable via the fake's counter.

**Failure paths (all typed, no silent fallback):**
- bookmark won't resolve → `.locationUnavailable` → `.unavailable(reason)` → re-pick.
- stale bookmark → resolve, **refresh + re-persist**, continue (logged, not silent).
- `startAccessing…` returns `false` → `.accessDenied` → surfaced, not swallowed.

## Testing strategy

**Host tests (`SecretaryVaultAccess`, no simulator) — the bulk:**
- `VaultSelectionViewModel` against `FakeVaultLocationStore`:
  - `loadPersisted`: nil → `.empty`; present → `.located(name)`.
  - `recordSelection` persists + → `.located`; `chooseDifferent` clears → `.empty`.
  - `beginAccess` on `.empty` throws `.noVaultSelected`; on `.located` returns a
    `ScopedVaultPath` whose `pathData` matches.
  - unresolvable bookmark → `.unavailable`; `accessDenied` surfaces, not swallowed.
  - **begin/end balance:** fake counts start/stop; after N unlock→lock cycles
    `started == stopped`, no live scopes leak; `end()` idempotent (double-end does not
    double-decrement).
- `VaultLocation` equatable / model tests.

**Simulator + FFI test (`SecretaryKit`):**
- `BookmarkVaultLocationStore` real round-trip: temp folder URL → `persist` (real
  bookmark + test `UserDefaults` suite) → `load` → `beginAccess` → assert `pathData`
  decodes to the folder path and access balance holds → `end`. Then drive the
  **golden vault** through the resolved path: `openVaultWithPassword` succeeds —
  proving a *bookmarked* path opens identically to the staged path. Exercise the
  stale-bookmark refresh path where feasible on simulator.

**App build proof:** `build-app.sh` (XcodeGen + simulator compile) stays green with the
new screen + routing.

**Harness:** `run-ios-tests.sh` already host-runs `SecretaryVaultAccess` and
simulator-runs `SecretaryKit`; new tests slot into both with no harness change.

## Out of scope (named, not silently dropped)

- Multi-vault "recent vaults" list.
- Vault create / import (separate slice; `create_vault` already projected).
- **On-device manual smoke** — needs a physical device + a side-loaded vault folder.
  Carried as an acceptance item (same posture as #216 / #202): pick a vault from
  Files, persist, relaunch reopens it, unlock by password AND recovery, browse, reveal,
  background→redaction+re-lock.

## Acceptance

- Host `swift test` (`SecretaryVaultAccess`) green incl. the new selection-VM +
  scope-balance tests.
- Simulator `SecretaryKit` green incl. the bookmark round-trip opening the golden vault.
- App `build-app.sh` BUILD SUCCEEDED with the selection screen + `select→unlock→browse`
  routing and the prefilled password removed.
- `git diff main..HEAD --name-only | grep -E '\.rs$'` empty (no Rust touched).
- On-device manual smoke noted as the one carried, device-dependent item.
