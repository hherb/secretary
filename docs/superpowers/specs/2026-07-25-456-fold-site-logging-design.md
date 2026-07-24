# Design — #456: redaction-aware fold-site diagnostic logging

**Issue:** #456 — *iOS/macOS: log the retained `VaultAccessError` diagnostic at the VM fold sites (redaction-aware)*
**Date:** 2026-07-25
**Scope:** iOS + macOS shared package `SecretaryVaultAccessUI`. No `core` / `ffi` / `.udl` / on-disk-format change.

## Problem

`#454` gave `VaultAccessError` / `VaultSelectionError` (and the sync/provisioning
enums) a `LocalizedError` conformance whose user-facing copy **deliberately omits**
each case's carried diagnostic `String` (paths, uuids, underlying reasons) — correct
for a secrets app, enforced by `testCarriedDiagnosticIsNeverInterpolatedIntoCopy`.

The diagnostic is not lost from the *type* — the view models fold the underlying
failure into the typed error's associated value at their catch-all sites
(`catch { self.error = .other(String(describing: error)) }`, `.reauthFailed(...)`,
`.createFailed(...)`, `.failed(...)`, `.unavailable(...)`). But **nothing reads it**:
there is no logger anywhere in `SecretaryVaultAccessUI`. So for a catch-all failure
the only record of what actually went wrong lives on an in-memory enum value that is
never surfaced — an on-device bug report ("it said 'Something went wrong'") is not
actionable without attaching a debugger.

The right destination is a **log**, not the screen (which #454 correctly cleaned).

## Goal

Add one redaction-aware logging seam in `SecretaryVaultAccessUI` and call it at every
**untyped catch-all fold site**, logging the underlying error with a deliberate
`privacy: .public` annotation — because the folded errors are diagnostic-only
(uuids/paths/labels/reasons), never vault plaintext or a credential.

## Non-goals

- No change to the user-facing `errorDescription` copy (stays clean-prose, anti-oracle).
- No new telemetry / network upload — local `os.Logger` only.
- No injected logging port, no VM-constructor change, no port/error-type change.
- The already-typed `catch let e as VaultAccessError { error = e }` arms are **not**
  touched — those errors are already typed and surfaced; logging them would be
  redundant noise.

## Design (chosen: pure formatter + thin `os.Logger` edge)

One new file — `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/DiagnosticLog.swift`
(~40 lines) — holding two package-internal free functions, plus one added line at each
untyped catch-all fold. Additive only.

### Components

**`foldedErrorDiagnostic(underlying:fileID:function:line:) -> String` — pure, host-tested.**
Builds the one-line message:

```
[<fileID>:<line> <function>] <String(describing: underlying)>
```

The only *dynamic* content is `String(describing: underlying)`. The site identifiers
are compile-time `StaticString` / `UInt` (`#fileID` / `#function` / `#line`), so nothing
dynamic beyond the underlying error can ever enter the message.

**`logFoldedError(_:fileID:=#fileID,function:=#function,line:=#line)` — thin edge.**
Logs the formatter's output via a package-internal
`Logger(subsystem: "com.secretary.vaultaccess", category: "vault-access-ui")` at
`.error` level with `privacy: .public`. The auto-captured `#fileID` / `#function` /
`#line` defaults mean each call site is literally `logFoldedError(error)` — zero
hand-written labels to mistype or copy-paste wrong.

This matches the repo's existing app-layer convention
(`ios/SecretaryApp`, `ios/SecretaryMacApp`, `ios/SecretaryKit/.../BookmarkVaultLocationStore.swift`
already log `String(describing: error)` / `error.localizedDescription` with `privacy: .public`).

### Fold-site scope (all untyped catch-all folds — 9 VMs)

One line — `logFoldedError(error)` — immediately **before** each untyped
`String(describing: error)` fold assignment:

| View model | Arm(s) | Count |
|---|---|---|
| `UnlockViewModel` | `.failed(.other(…))` | 1 |
| `TrashViewModel` | `.other`, `.reauthFailed`, `.other` | 3 |
| `VaultProvisioningViewModel` | `.createFailed` | 1 |
| `SettingsViewModel` | `.other` ×3, `.reauthFailed` | 4 |
| `VaultBrowseViewModel` | `.other` ×3, `.reauthFailed` | 4 |
| `DeviceSlotViewModel` | `.reauthFailed`, `.other` | 2 |
| `VaultSyncViewModel` | `.failed` ×2 | 2 |
| `VaultSelectionViewModel` | `.unavailable` (`evaluate` return), `.unavailable(reason:)` (`else` branch only) | 2 |
| `RecordEditViewModel` | `.other` ×3, `.reauthFailed` | 4 |

**≈23 fold sites.** `VaultSelectionViewModel`'s `beginAccess` catch has an
`if case VaultSelectionError.locationUnavailable(let reason)` branch that extracts a
**typed** `reason` (not `String(describing:)`); the log goes only in the `else`
branch, precisely where the string fold happens. Placing the call immediately before
each string-fold assignment (rather than at catch-top) keeps it faithful to "log the
underlying error at the fold site" and avoids double-logging the typed branch.

## Privacy invariant (the security core)

`privacy: .public` is **deliberate**. The folded underlying errors are, exhaustively
today:

- `FfiVaultError` (uniffi) — uuids / paths / labels / reasons.
- Foundation file errors — paths.
- `DeviceUnlockError` — `LAError`-derived presence-check failures.
- `VaultSyncError` — uuids / manifest hashes / decode reasons (`.failed(String)`,
  `.stateCorrupt(String)`, `.invalidArgument(String)`).
- `VaultSelectionError` — bookmark / location reasons (paths).

None carry vault plaintext, a password, a mnemonic, or key bytes. This is the *same*
`String(describing:)` the enum already retains in memory (#454), so we log nothing the
fold didn't already carry — the *new* exposure is only that it reaches the unified log
store, which is exactly why "diagnostic-only" must hold before choosing `.public`.

**Asserted two ways:**
1. A doc comment on `logFoldedError` enumerating the error sources and a **"re-check
   when adding a new error source"** note (the invariant is not self-maintaining).
2. A host test on the pure formatter proving the output contains *only*
   `String(describing: underlying)` plus the compile-time site — a sentinel-error
   equality test, so no other stringification (e.g. `.localizedDescription`) can slip in.

If a future error source could carry a secret, the fix is to sanitize at that source
(or use `privacy: .private`/`.sensitive` there) — not to widen this seam silently.

## Testing (TDD)

New `Tests/SecretaryVaultAccessUITests/DiagnosticLogTests.swift`:

1. **Includes the underlying description** — output contains `String(describing: err)`
   for a sample error.
2. **Includes the site** — output contains the passed `fileID` / `function` / `line`.
3. **Diagnostic-only (security)** — for an error whose `String(describing:)` is a known
   sentinel, `foldedErrorDiagnostic(...)` equals exactly
   `"[<fileID>:<line> <function>] <sentinel>"`, proving no extra content leaks in.

Existing VM tests stay **green unchanged**: adding `logFoldedError(error)` before a
fold does not change the VM's published error state, and `os.Logger` is a no-op sink
under `swift test`, so no output pollution and no assertion churn.

## Files touched

- **New:** `.../SecretaryVaultAccessUI/DiagnosticLog.swift` (formatter + edge).
- **New:** `.../SecretaryVaultAccessUITests/DiagnosticLogTests.swift` (3 tests).
- **Edit (1 line each, ~23 sites):** the 9 view models above.

All under the FFI-free `SecretaryVaultAccess` package — fast inner loop is
`cd ios/SecretaryVaultAccess && swift test` (no xcframework needed).

## Acceptance

- A single logging seam in `SecretaryVaultAccessUI`; underlying error logged at every
  untyped catch-all fold with `privacy: .public`.
- A doc-comment assertion + a formatter test proving logged content is diagnostic-only
  (no secret-bearing bytes).
- `swift test` in `SecretaryVaultAccess` green (existing + new).
- Shared package still compiles into both apps (`build-app.sh` / macOS build sanity).
- No `core` / `ffi` / `.udl` / `FfiVaultError` / on-disk-format change.
