# D.5.2 — Native macOS read-only vault viewer (design)

**Date:** 2026-07-17
**Sub-project:** D.5 (native macOS SwiftUI client, [ADR 0011](../../adr/0011-macos-native-swiftui.md))
**Depends on:** D.5.1 (enclave walking skeleton, shipped 2026-07-16)
**Status:** design approved; implementation plan to follow

## 1. Summary

Grow the macOS app from the D.5.1 device-unlock skeleton into a usable **read-only
vault viewer** with the iOS-parity flow **select → unlock → browse**. This is a
**presentation port**: every view model and adapter already exists in the shared,
macOS-compatible Swift packages and is host-tested; this slice writes macOS-idiomatic
SwiftUI views plus a small amount of macOS glue over them. No `core` / `.udl` /
`FfiVaultError` / on-disk-format change. No new FFI surface.

The Tauri macOS build remains the shipping macOS client; D.5.2 **coexists** and does
not cut over (per ADR 0011).

## 2. Scope

### In scope
- **Select** — show the one remembered vault (the shared `VaultLocationStore` is
  **single-vault** by design: `persist` replaces the prior location, `load()` returns
  one `VaultLocation?`), "Open other…" via `NSOpenPanel` folder pick, and "Open demo
  vault" (the existing bundled-golden path, retained). Backed by the shared
  `VaultSelectionViewModel`.
- **Unlock** — password field + "Unlock with Touch ID" (shown only when *this* vault
  is enrolled) + "Remember this Mac" checkbox (enrolls a device slot on password
  unlock). Backed by `UnlockViewModel` + the D.5.1-proven `DeviceUnlockOpen` path.
- **Browse** — a three-column `NavigationSplitView` (blocks sidebar | records list |
  field detail) with per-field reveal/mask and copy-with-auto-clear. Backed by
  `VaultBrowseViewModel`.
- **Lock** — an explicit "Lock" affordance (wipe session, drop reveals, return to
  select) + drop revealed plaintext on `resignActive` + wipe on window close.

### Non-goals (explicitly deferred to later D.5 slices)
- All mutation UI: create-vault wizard, record edit, block CRUD, trash, share /
  contacts, revoke.
- Settings screen.
- **Sync UI + folder-change monitor** — no sync badge, no auto-refresh on external
  vault change in this slice (re-open to pick up external changes).
- App Sandbox + security-scoped bookmarks + notarization + Mac App Store.
- Intel (`x86_64`) — Apple Silicon (M1+) only, matching D.5.1.
- Auto-lock timeout and a full privacy cover (screenshot/screen-share blanking).

## 3. Architecture

A **fresh macOS `RootView` state machine** mirroring the proven iOS `RootView`, but
macOS-flavored — *not* an incremental bolt-on to `MacDeviceUnlockView`, and *not* a
shared cross-platform view layer. iOS and macOS chrome diverge too much to share
views this early (three-column split vs push-stack; window lifecycle vs `scenePhase`;
app-switcher privacy cover vs none). We share **view models**, which is where the
logic and the existing tests live.

```
Route =
  | .select
  | .unlock(ScopedVaultPath)
  | .browse(VaultBrowseViewModel, ScopedVaultPath)
```

The current `MacDeviceUnlockView` (demo-only, biometric-only, enroll-button harness)
is **retired as the root**: the demo vault becomes one entry in the selection screen,
opened through the same real unlock flow as any user-selected vault.
`MacVaultProvisioning` (bundled-golden staging) is kept, SKELETON-ONLY-guarded exactly
as today.

### Reuse map (no new logic)

| Concern | Reused symbol | Package |
|---|---|---|
| Vault selection state | `VaultSelectionViewModel` | `SecretaryVaultAccessUI` |
| Vault-shape probe | `FileManagerVaultShapeProbe` | `SecretaryKit` |
| Unlock state (password) | `UnlockViewModel`, `UniffiVaultOpenPort` | `SecretaryVaultAccessUI` / `SecretaryKit` |
| Biometric open + enroll | `makePerVaultDeviceUnlock`, `DeviceUnlockCoordinator` | `SecretaryKit` / `SecretaryDeviceUnlock` |
| Biometric open flow | `DeviceUnlockOpen` (internal to `SecretaryApp` → **ported** to macOS, not imported) | `SecretaryApp` (copied) |
| Browse state | `VaultBrowseViewModel`, `UniffiVaultSession` | `SecretaryVaultAccessUI` / `SecretaryKit` |
| Session open orchestration | core `open_vault` (verify-before-decrypt) | `secretary-core` (via FFI) |

## 4. New components

### 4.1 macOS view files (`ios/SecretaryMacApp/Sources/`)
One screen per file, each targeted < ~200 lines (split proactively):
- `MacRootView.swift` — the `Route` state machine + window-lifecycle lock wiring;
  becomes `@main`'s scene root.
- `MacVaultSelectionView.swift` — remembered-vault list, `NSOpenPanel` picker, demo
  button; binds `VaultSelectionViewModel`.
- `MacUnlockView.swift` — password + Touch ID (when enrolled) + "Remember this Mac";
  binds `UnlockViewModel`, calls `DeviceUnlockOpen`.
- `MacBrowseView.swift` — three-column `NavigationSplitView`; binds
  `VaultBrowseViewModel`; per-field reveal/mask/copy-with-auto-clear.

### 4.2 New pure / shared code

**`FileVaultLocationStore`** (⚑ decision 1 → **SecretaryVaultAccess package**):
a pure-Foundation `VaultLocationStore` conformer that persists the one remembered
vault as a **plain folder path** (paths only — never secrets) in `UserDefaults`
(matching iOS's `BookmarkVaultLocationStore` pattern; an injectable `UserDefaults`
suite makes it host-testable). It reuses the existing `VaultLocation.bookmark: Data`
field to carry the UTF-8 path bytes — that field is documented as a non-secret
"path-style token", and a plain path is exactly that, so **no protocol or model
change** is needed. It is FFI-free, so it host-tests fast in the VaultAccess suite
(run-macos-tests.sh Step 1, no xcframework build). iOS keeps its
`BookmarkVaultLocationStore` (security-scoped bookmarks) in SecretaryKit; macOS gets
this FFI-free plain-path store. On macOS pre-sandbox, `beginAccess` returns a
`ScopedVaultPath` with a **no-op scope** (direct path access needs no security scope
until App Sandbox — a later slice — at which point a bookmark-backed store swaps in
with no view-model change).

**`makeRetargetableReauthGate` hoisted into SecretaryKit** (⚑ decision 2): the
iOS app-target factory (`ios/SecretaryApp/Sources/RetargetableGateFactory.swift`) is
moved to a public factory in **SecretaryKit** and the iOS app imports it instead of
declaring its own. One shared factory, no duplication; forward-compatible with the
later macOS write slice (which needs the *real* gate). The factory already builds
only on cross-platform SecretaryKit + SecretaryVaultAccessUI symbols
(`makePerVaultDeviceUnlock`, `EnclaveBiometricAuthorizer`, `RetargetableReauthGate`,
`GraceWindowReauthGate`, `SettingsPort`, `reauthWindowDefaultMs`). SecretaryKit is the
correct home because it already depends on SecretaryVaultAccessUI *and* owns
`makePerVaultDeviceUnlock`/`EnclaveBiometricAuthorizer`; hoisting into
SecretaryVaultAccessUI would invert the dependency (a cycle). This move touches the
iOS app target — iOS host tests + `run-ios-tests.sh` guard it.

> Read-only browse never triggers the gate: `VaultBrowseViewModel.reveal()` does not
> route through `reauthedWrite`; only mutations (deferred to later slices) do. The
> gate is constructed and correct from the start so the write slice is drop-in.

### 4.3 Modified
- `ios/SecretaryMacApp/project.yml` — add the `SecretaryVaultAccess` package
  dependency (products `SecretaryVaultAccess` + `SecretaryVaultAccessUI`), bringing
  the macOS app to the same 4-product set the iOS app uses.
- `ios/SecretaryMacApp/Sources/SecretaryMacApp.swift` — point `WindowGroup` at
  `MacRootView`.
- `ios/SecretaryApp/Sources/RetargetableGateFactory.swift` — deleted; iOS imports the
  hoisted SecretaryKit factory.

## 5. Data flow

1. **Select.** `VaultSelectionViewModel(store: FileVaultLocationStore(),
   probe: FileManagerVaultShapeProbe())` loads the remembered vault (if any) via
   `loadPersisted()`. "Open other…" runs `NSOpenPanel` → the picked folder is checked
   with `considerImport(url:bookmark:displayName:)` (which probes shape + persists) →
   surfaced. "Open demo" stages the bundled golden vault into a transient
   `ScopedVaultPath` (not persisted). The remembered/imported paths yield a
   `ScopedVaultPath` via `viewModel.beginAccess()` (no-op scope pre-sandbox) → route
   `.unlock`. On macOS the "bookmark" passed to `recordSelection`/`considerImport` is
   the UTF-8 folder path (see `FileVaultLocationStore`), not a security-scoped
   bookmark.
2. **Unlock.** At route entry, snapshot `biometricEnrolled` **once** (per-vault; one
   Keychain + Secure-Enclave read — the iOS #347 pattern; never per-render).
   `MacUnlockView` offers password (→ `UniffiVaultOpenPort.open`) and, if enrolled,
   Touch ID (→ `DeviceUnlockOpen.open`). "Remember this Mac" + password unlock →
   `coordinator.enroll` offloaded off the main actor (the iOS best-effort,
   non-fatal, off-`@MainActor` enrollment pattern). On success → build
   `VaultBrowseViewModel(session:gate:)` → route `.browse`. Both open paths go through
   the **same B.2 `open_with_device_secret` / password verify-before-decrypt** — the
   device path is never a weaker open.
3. **Browse.** `loadBlocks()` → select a block → `visibleRecords` → reveal a field on
   click (`reveal()` pulls plaintext across FFI on demand), copy auto-clears the
   pasteboard, mask/hide drops the reveal. `showDeleted` stays off (read-only viewer;
   trash is a later slice).

## 6. Security invariants preserved

- **Verify-before-decrypt** for both password and device paths (unchanged core
  orchestrator; the device path funnels through the same open as password/recovery).
- **Reveal is explicit + short-lived:** plaintext materializes only on user action;
  `hideAll()` on resign / lock; `session.wipe()` on lock (all existing VM behavior).
- **No new secret-bearing storage:** `FileVaultLocationStore` persists only folder
  paths — never passwords or key material. No `Sensitive`/`SecretBytes` widening.
- **Demo vault stays SKELETON-ONLY-guarded:** it carries a test password and must
  never ride in a shipped/notarized build; the #438 guard-rails are retained, and the
  later notarization slice strips it.

## 7. macOS lock behavior (this slice)

- **Explicit "Lock" button** in the browse chrome → `VaultBrowseViewModel.lock()`
  (drop reveals + `session.wipe()`), release scope, route `.select` (which still
  shows the remembered vault — one click re-opens).
- **Drop revealed plaintext on `resignActive`** (`hideAll()`) — a cheap privacy win
  when the app loses focus; does not wipe the session.
- **Wipe on window close.**
- **Deferred:** auto-lock timeout; a full privacy cover for screenshot / screen-share
  blanking.

## 8. Testing strategy

- **View models:** already host-tested (`SecretaryVaultAccessUITests`) — no new VM
  tests.
- **New pure logic** (`FileVaultLocationStore`; any path/formatting helpers): TDD
  host tests in the **FFI-free** VaultAccess suite (fast; run-macos-tests.sh Step 1,
  no xcframework).
- **Hoisted gate factory:** covered by the existing iOS host tests + `run-ios-tests.sh`
  after the move (behavior-preserving relocation); it also compiles into the macOS
  app.
- **Views:** no render-layer unit tests (that infra — ViewInspector / a UI-test
  target — is the deferred #417 decision). Coverage is the **`macos-host.yml`
  compile-proof** (`SecretaryMac.app` must build) + a manual smoke against a **temp
  copy** of the golden vault (never the tracked fixture — settings are stored *in* the
  vault; opening the fixture would mutate a frozen KAT).

### Acceptance
- `bash ios/scripts/run-macos-tests.sh` PASS (xcframework + SecretaryKit macOS host
  test + `SecretaryMac.app` compile).
- `bash ios/scripts/run-ios-tests.sh` still green (gate-factory move touches the iOS
  app).
- New `FileVaultLocationStore` host tests green.
- `cargo` gates unaffected (no Rust change) but re-run per task discipline if any
  Rust file is touched (none expected).

## 9. Risks & open items

- **Gate-factory move touches iOS.** Behavior-preserving relocation; the iOS host
  test suite + `run-ios-tests.sh` are the guard. If the move proves noisier than
  expected, fall back to porting the factory verbatim into the macOS app target
  (decision ⚑2 option b) — a duplication we would then track for later dedup.
- **`NSOpenPanel` under the current (non-sandboxed) entitlements** grants direct path
  access; this is correct pre-sandbox. The App Sandbox slice must revisit with
  security-scoped bookmarks (the `VaultLocationStore` abstraction is the seam).
- **No folder-change monitor** in this slice: a vault mutated externally while open
  won't refresh until re-open. Acceptable for a read-only viewer; the sync slice adds
  the monitor.
- **xcframework build cost:** a fresh worktree rebuilds all four target triples, so
  any `run-macos-tests.sh` invocation is multi-minute and mostly silent — run it in
  the background and poll its log rather than blocking on it.

## 10. Non-goals recap (single source of truth)

Mutation UI · Settings · Sync UI / monitor · App Sandbox · bookmarks · notarization ·
Intel · auto-lock timeout · privacy cover · Tauri cutover. Each is a distinct later
D.5 slice.
