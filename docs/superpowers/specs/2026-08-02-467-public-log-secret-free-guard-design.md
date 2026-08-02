# Design — #467: fail-closed guard on `privacy: .public` error logging

**Date:** 2026-08-02
**Issue:** [#467](https://github.com/hherb/secretary/issues/467) (follow-up to #456 / PR #466)
**Branch:** `feature/467-public-log-secret-free-guard`

## Problem

`SecretaryVaultAccessUI` logs folded errors at `privacy: .public`, which
deliberately overrides `os.Logger`'s default redaction so the diagnostic
survives into a sysdiagnose. That is the right product call **only while** no
error reaching a fold site carries a secret.

Today that invariant holds — it was verified against the production adapter in
#466 — but it is maintained by a doc comment, not by the compiler or a test. A
future error source that embedded a decrypted field value, a password, or key
bytes would reach the unified log store silently, with `os.Logger`'s built-in
redaction fully disabled for that seam.

### The issue understates the surface

#467 is written as though `DiagnosticLog.swift` were the only `.public` error
sink. It is not. There are **eight** more, none of which has the doc comment,
the pure formatter, or the byte-exact test that the fold-site seam has:

| Site | Rendered at `.public` |
|---|---|
| `SecretaryKit/.../BookmarkVaultLocationStore.swift:64` | `location.displayName` (not an error) |
| `SecretaryKit/.../BookmarkVaultLocationStore.swift:66` | `String(describing: error)` |
| `SecretaryApp/Sources/SecretaryApp.swift` × 5 | `error.localizedDescription` |
| `SecretaryMacApp/Sources/MacUnlockView.swift:172` | `error.localizedDescription` |

A guard scoped to `SecretaryVaultAccessUI` alone would harden the seam that
already has the most protection and leave the eight bare ones untouched. Scope
is therefore **all nine `.public` sinks**.

### The constraint that determines the mechanism

`BiometricAuthorizer.authorize` throws `DeviceUnlockError`-class failures
(`Reauth.swift:12`); `GraceWindowReauthGate` propagates them untyped, so they
land in the fold arms. `DeviceUnlockError` lives in **`SecretaryDeviceUnlock`**,
which is *not* a dependency of `SecretaryVaultAccess`.

Consequence: a closed `switch`/`is`-list inside `DiagnosticLog.swift`
**structurally cannot** cover the reachable error set. The allowlist must be
conformable from outside the package, and the default for an unlisted type must
be **deny**.

## Approach

Default-deny rendering behind a protocol, plus a source-level check that forces
every `.public` error render through it.

Three options were weighed:

1. **Injected `@MainActor` sink + fixture test** (the issue's Option 1). Adds
   coverage that is genuinely missing — nothing today proves any of the 23 fold
   sites calls the logger at all — but it is not a leak guard. It can only
   assert about errors a test already knows are secret-bearing, which is exactly
   the case that is never the problem. **Rejected as the primary mechanism.**
2. **Bare marker protocol.** Smallest surface, but a type that is safe in nine
   cases and secret-bearing in one has no way to conform partially; it must be
   excluded wholesale, losing the nine safe cases' diagnostic value.
   **Rejected.**
3. **Rendering protocol with a defaulted requirement.** Conforming a safe type
   stays one line; a partially-secret type overrides the property and redacts at
   source. Makes the "sanitize it AT THAT SOURCE" instruction already present in
   the `logFoldedError` doc comment structural instead of advisory. **Chosen.**

## Components

### 1. The policy (`SecretaryVaultAccess`)

New file `Sources/SecretaryVaultAccess/SecretFreeError.swift`. It lives in
`SecretaryVaultAccess` because that is the only target visible to all four
consumers (`SecretaryVaultAccessUI`, `SecretaryKit`, `SecretaryApp`,
`SecretaryMacApp`) — a dependency-graph fact, not a preference.

```swift
public protocol SecretFreeError: Error {
    /// Secret-free one-line diagnostic text, reviewed as safe for `.public`.
    var diagnosticDescription: String { get }
}

public extension SecretFreeError {
    var diagnosticDescription: String { String(describing: self) }
}

/// The ONLY sanctioned rendering of an `Error` into a `privacy: .public` line.
public func diagnosticDetail(_ error: Error) -> String {
    if let safe = error as? SecretFreeError { return safe.diagnosticDescription }
    let ns = error as NSError
    return "<undisclosed \(type(of: error)) domain=\(ns.domain) code=\(ns.code)>"
}
```

**The `NSError` fallback is load-bearing, not decoration.**

- A bare type name would be a *weaker* diagnostic than what ships today.
  `domain` + `code` identifies which case fired even for an unlisted type, and
  both are compile-time-derived identifiers.
- `userInfo` is never read. That is the only part of an `NSError` that can carry
  arbitrary caller-supplied content.
- It closes a bridging trap: Foundation file errors arrive in a `catch` with
  dynamic type `NSError`, so `error as? SecretFreeError` **fails** even when
  `CocoaError` conforms. Without the fallback every real file error would
  degrade to `<undisclosed>`. Conforming `NSError` wholesale would also work but
  hands a blanket allow to every bridged error; the domain/code fallback keeps
  the diagnostic value without the blanket.

### 2. Initial conformances

Each is a reviewed claim, one line each.

| Module | Types |
|---|---|
| `SecretaryVaultAccess` | `VaultAccessError`, `VaultSyncError`, `VaultSelectionError`, `DeviceUuidStoreError`, `CancellationError` |
| `SecretaryKit` | `DeviceUnlockError` — needs `@retroactive` (owns neither type nor protocol) |

Conformances declared in `SecretaryVaultAccess` need no `@retroactive`: the
warning fires only when the declaring module owns neither the type nor the
protocol, and the protocol is ours.

**Forgetting a conformance degrades a log line; it never leaks.** That asymmetry
is the point of default-deny.

### 3. The fold-site helper (`SecretaryVaultAccessUI`)

`logFoldedError` is replaced by:

```swift
@discardableResult
func foldDiagnostic(_ error: Error,
                    fileID: StaticString = #fileID,
                    function: StaticString = #function,
                    line: UInt = #line) -> String
```

It applies the policy once, logs the gated detail at `.public`, and returns the
same string for the typed error's payload. Each of the 23 fold sites collapses:

```swift
// before — two independent renderings of the same error
} catch {
    logFoldedError(error)
    self.error = .other(String(describing: error))
}

// after — one policy application
} catch {
    self.error = .other(foldDiagnostic(error))
}
```

Two properties fall out for free:

- the log line and the carried payload **cannot disagree**, because there is one
  application of one function;
- a new fold site cannot set a folded payload **without** logging, which closes
  the separate, currently-unguarded gap that nothing forces a new catch-all arm
  to call the logger at all.

Net effect at the call sites is a line removed, not added.

`foldedErrorDiagnostic` remains as the pure formatter and keeps its byte-exact
test; `diagnosticDetail(underlying)` replaces `String(describing: underlying)`
inside it.

Payload exposure is lower than the log's — it is in-memory, dies with the view
model, and #454's `testCarriedDiagnosticIsNeverInterpolatedIntoCopy` already
proves it is never interpolated into user copy. It is gated anyway because
leaving a raw `String(describing:)` on the line *after* a gated call teaches the
next reader that the raw form is acceptable, which is precisely how the
invariant rotted into "discipline, not enforcement" in the first place.

### 4. The app-layer sites

Seven render an error and become `diagnosticDetail(error)`:
`BookmarkVaultLocationStore:66` (was `String(describing:)`), `SecretaryApp` × 5
and `MacUnlockView:172` (were `.localizedDescription`). For a conformer this
changes the text from friendly copy to case-plus-associated-values — better in a
log, and now uniform with the fold seam.

The eighth, `BookmarkVaultLocationStore:64`, logs `location.displayName`, which
is not an error, so the gate does not apply. **Decision: keep it `.public`, with
a comment recording why.** It is the vault folder name taken from the system
picker (or the name supplied at create time); anyone able to read the unified
log store can also read the filesystem, so it discloses nothing new, and
`VaultLocation`'s own doc already records that no key or credential flows
through the type. The decision is written down and given an explicit allowlist
entry rather than left implicit.

### 5. The source-level check

The protocol makes *rendering* fail-closed, but nothing yet forces a new site to
call `diagnosticDetail` rather than hand-rolling `String(describing:)`. Without
this step #467's acceptance criterion does not actually hold.

`ios/scripts/check-public-log-hygiene.sh`, in the shape the repo already uses
for `ffi/scripts/check-lean-binding.sh`: readonly tunables at the top, an
explicit allowlist file for recorded exceptions, and a `--self-test` mode that
proves the matcher fires on a known-positive control before a green run is
trusted (a check never observed failing is indistinguishable from a no-op — the
same vacuity hazard #469 was proven against).

**Rule:** no line carrying `privacy: .public` may also carry
`String(describing:` or `localizedDescription`, except for lines listed in the
allowlist file with a reason.

It is pure `grep`, needs no macOS toolchain, and therefore wires into `test.yml`
so it runs on **every** PR rather than behind `macos-host.yml`'s `ios/** +
ffi/** + core/**` path gate. That matters: the app-layer sites it guards live in
`ios/`, but a reviewer's mental model of "the Swift checks are path-gated" is
exactly what would let an ungated edit through.

## Testing

Tests are written before the implementation. Baseline to preserve:
**344 tests, 0 failures** (`swift test` in `ios/SecretaryVaultAccess`).

| # | Target | Asserts |
|---|---|---|
| 1 | `SecretaryVaultAccessTests` | A conformer renders via the default `String(describing:)` |
| 2 | `SecretaryVaultAccessTests` | A custom `diagnosticDescription` **wins** over `String(describing:)` — sanitize-at-source is real, not decorative |
| 3 | `SecretaryVaultAccessTests` | A non-conforming secret-bearing error → output does **not** contain the secret sentinel |
| 4 | `SecretaryVaultAccessTests` | `NSError` with a sentinel planted in `userInfo` → sentinel absent, `domain` + `code` present (pins the "never read `userInfo`" decision) |
| 5 | `SecretaryVaultAccessTests` | The five in-package conformances hold (catches an accidental removal) |
| 6 | `SecretaryVaultAccessUITests` | `foldDiagnostic` returns the gated detail; `foldedErrorDiagnostic` stays byte-exact |
| 7 | `SecretaryVaultAccessUITests` | One representative view-model fold: the carried payload is `<undisclosed …>`, not the secret |
| 8 | `SecretaryKitTests` | `DeviceUnlockError` conforms — it is the one conformance the `SecretaryVaultAccess` tests structurally cannot see, and the one whose absence would silently degrade the biometric-gate diagnostics |

`SecretaryKitTests` (test 8) links the binary `SecretaryFFI` target, so it needs
a prebuilt `ios/Secretary.xcframework`; a cold worktree has none and the first
build cross-compiles four Apple triples. Warm it before that leg rather than
inside it.

Plus `bash ios/scripts/check-public-log-hygiene.sh --self-test` followed by a
clean run, and a local mutation proof: add a `String(describing: error)` at a
`.public` site, confirm the check goes red, revert.

Existing `.other("disk full")` / `.reauthFailed("cancelled")` assertions are
unaffected — those values are thrown as `VaultAccessError` by fakes and are
caught by the **typed** `catch let e as VaultAccessError` arm, never by the
untyped fold.

## Non-goals

- No change to user-facing copy (anti-oracle, unchanged since #454).
- No new telemetry or upload — local `os.Logger` only.
- No change to any `core/` or `ffi/` surface, the on-disk format, or the FFI
  signature set.
- Android's logging surface is out of scope; if the same gap exists there it is
  a separate issue against `:vault-access` / `:browse-ui`.

## Risks

- **Diagnostic regression for an unlisted type.** A real error whose type nobody
  conforms renders as `<undisclosed …>` instead of its description. This is the
  intended fail-closed trade, and it is *loud* — the marker tells a developer
  exactly which type to review and conform. The `domain`/`code` fallback keeps
  it actionable rather than opaque.
- **Conformance is a claim, and claims can be careless.** The protocol name is
  chosen so the conformance site reads as an assertion
  (`extension DeviceUnlockError: SecretFreeError {}`). The mitigation is review,
  not machinery; the machinery's job is to make the claim explicit and
  greppable, which it was not before.
- **A missing conformance in `SecretaryKit` is not a build error.** It degrades
  a log line silently. Test 5 covers the initial set; a later addition relies on
  the same review discipline. Accepted, because the failure direction is safe.
- **The check is line-based.** A `.public` interpolation split across lines
  would evade it. Rejected as a reason not to ship: every current site is
  single-line, `swift-format` keeps them that way, and the alternative (parsing
  Swift) is far out of proportion. The `--self-test` control documents what the
  matcher does and does not catch.
