# Design — #472: fail-closed gate on Android logcat error rendering

Issue: [#472](https://github.com/hherb/secretary/issues/472) — "Android logs raw
`Throwable`s to logcat with no `.public`-equivalent gate".

Sibling of #467, which made the same guarantee structural on iOS/macOS. This is
the Android half. It is a port in intent, not in mechanism: three of the five
facts below have no iOS analogue, and one iOS mechanism has no Kotlin analogue.

## Problem

`android.util.Log` writes to logcat, which is readable via `adb logcat` on a
debuggable build and is captured into bug reports. logcat has **no redaction
concept at all** — there is no `privacy:` qualifier to opt into or out of. Every
line is the equivalent of iOS's `privacy: .public`.

Seven sites log today, all in `:app`:

| Site | Form |
|---|---|
| `AppRoot.kt:438` | `Log.w(TAG, "folder-change monitor failed to start", e)` |
| `AppRoot.kt:572` | `Log.w(TAG, "device enroll failed; password open still succeeded", e)` |
| `AppRoot.kt:582` | `Log.w(TAG, "unlock/open failed; returning to unlock screen", e)` |
| `CloudVaultOpen.kt:191` | `Log.w(TAG, "cloud device enroll failed; password open still succeeded", e)` |
| `CloudVaultOpen.kt:256` | `Log.i(TAG, it)` — the `RetryingCloudFolderPort` retry message |
| `CloudVaultOpen.kt:298` | `Log.w(TAG, "cloud vault CREATED but not synced …", e)` |
| `CloudVaultOpen.kt:300` | `Log.w(TAG, "cloud open/create failed; returning to unlock with same target", e)` |

The three-argument `Log.w(tag, msg, throwable)` form prints
`Log.getStackTraceString(throwable)`, which is `throwable.toString()` — class
name **plus message** — followed by the frames, then the same for every cause.

### The exposure is live, not hypothetical

Every one of the six throwable sites catches `Exception`, the widest possible
catch, so the reachable type set is unbounded. One concrete path, traced end to
end:

1. `RecordError::DuplicateKey { key }` (`core/src/vault/record.rs:660`) formats
   the **decrypted CBOR field name** into `"duplicate map key: {key}"`.
2. It crosses the FFI as `VaultException.CorruptVault(detail)`.
3. `BrowseMapping.kt:21` maps that to `VaultBrowseError.CorruptVault(detail)`,
   which passes `detail` to the `Exception(message)` constructor.
4. `AppRoot.kt:582`'s `catch (e: Exception)` hands it to `Log.w(TAG, msg, e)`.
5. `toString()` prints the field name to logcat.

This is the same chain #467 closed on iOS, still open on Android. Tracked at the
Rust root as #474 and deliberately **not** fixed here (see Non-goals).

### Three facts with no iOS analogue

**1. There is no marker to key on.** iOS rule 1 counts `privacy: .public`
interpolations against `diagnosticDetail(` renders on the same line. Android has
no such token — the sink itself is the thing to guard.

**2. The laundering surface is already live, and larger.** iOS's review round 1
found that `diagnosticDetail` denies unreviewed *types*, not unreviewed
*content*: pre-render an unreviewed error into a `String`, stash it in a
**conformed** error's payload, and it walks straight through the gate. On iOS
that was nine sites. On Android it is **eighteen**, and they are not incidental —
`BrowseMapping.kt:47` (`VaultBrowseError.Failed(e.toString())`) is the FFI
mapper's else-fold, i.e. the designated carrier of every Rust `Display` string
the explicit arms do not name.

**3. Android has iOS's decrypted-field-name problem too.**
`RecordEditModel.kt:178` builds `"field '${f.name}' is not valid hex"` and `:192`
builds `"duplicate field name: ${v.name}"`, both into
`VaultBrowseError.InvalidArgument`. `f.name` is a decrypted record field name.

### The constraint that determines the mechanism

**Kotlin has no retroactive conformance.** On iOS, `extension CocoaError:
SecretFreeError {}` is legal, and `diagnosticDetail`'s `NSError` branch gives an
unconformed type a `domain=…code=…` fallback that is still diagnostic. Neither
exists in Kotlin. `VaultException` (uniffi-generated), `IOException`,
`SecurityException`, `KeyStoreException`, `CancellationException` — none can ever
implement an interface we declare.

Those are exactly the types most likely to arrive at a `catch (e: Exception)`.
So on Android the **deny path is the normal path**, not the degenerate one, and
its rendering carries far more weight than iOS's marker does.

Conversely, Kotlin permits something Swift does not: `android.util.Log` is a
plain object with ordinary methods, so it can be wrapped such that the unsafe
call is unrepresentable. `os.Logger`'s interpolation-based API cannot.

## Approach

Four parts, mirroring #467's shape where the shape ports and diverging where the
language forces it:

1. **A rendering policy** — `SecretFreeThrowable` + `diagnosticDetail`, in the
   pure-JVM `:vault-access` module. Default-deny, as on iOS.
2. **A sanctioned sink** — `SecretaryLog` in `:kit`, the only file in the tree
   permitted to reference `android.util.Log`. It accepts a `Throwable` and
   renders it through `diagnosticDetail` internally, so no call site can hand a
   raw throwable to logcat. This is the `foldDiagnostic` analogue: the policy is
   applied once, at one place.
3. **Laundering cleanup** — the eighteen sites: fourteen fixed, four recorded as
   reviewed allowlist entries because they are on-screen copy rather than logs.
   Two *innocent* `.toString()` calls are deleted rather than allowlisted, one of
   them a duplicated hex encoder that should have been a call to `hexOfBytes`.
4. **A grep-level guard** — `android/scripts/check-log-hygiene.sh`, fail-closed,
   two-sided `--self-test`, wired into `test.yml`. Ported from #467 including
   the exact-trimmed-line allowlist matching and its A1/A2 regression control.

### Why the sink is a wrapper rather than a line rule

The alternative was a literal port of iOS rule 1: rewrite each site as
`Log.w(TAG, "$msg: ${diagnosticDetail(e)}")` and have the script verify every
`Log.*` line renders through `diagnosticDetail`. That requires deciding,
line-based, whether a `Log` call carries a third argument — which means
distinguishing an argument separator from a comma inside a string literal:

```kotlin
Log.w(TAG, "cloud open failed, retrying", e)   // 3 args — must FAIL
Log.w(TAG, "cloud open failed, retrying")      // 2 args — must PASS
```

Identical comma counts. The iOS script documents parsing Swift as out of
proportion for a *stated limit*; here it would be load-bearing. Making the unsafe
overload nonexistent removes the question: the rule becomes "`android.util.Log`
appears in exactly one file", which is exact, has no multi-line blind spot, and
is strictly tighter than iOS rule 1.

## Components

### 1. The policy (`:vault-access`)

`:vault-access` is `kotlin("jvm")` — pure JVM, no Android dependency, already
host-tested by the existing `android-host` CI job, and the leaf every other
module can see. It is the structural equivalent of iOS's FFI-free
`SecretaryVaultAccess`.

```kotlin
/**
 * A claim, made at the declaration site, that this throwable's diagnostic text
 * carries NO secret — no vault plaintext, password, mnemonic, or key bytes — and
 * is therefore safe to write to logcat (#472).
 *
 * Implementing this is a SECURITY DECISION, reviewed like any other.
 */
interface SecretFreeThrowable {
    /** Default: the full description, associated values included. */
    val diagnosticDescription: String get() = toString()
}

/**
 * Render [error] for logcat. The ONLY sanctioned way to do so — enforced by
 * android/scripts/check-log-hygiene.sh.
 *
 * DEFAULT-DENY: a type that has not been reviewed is never described.
 */
fun diagnosticDetail(error: Throwable): String
```

Named `SecretFreeThrowable`, not `SecretFreeError`: `java.lang.Error` already
means "unrecoverable throwable", and the collision would misread.

The default getter is `toString()`, which resolves to the implementing object's
override. For a `data class` arm that is the Kotlin-generated
`Failed(detail=…)`; for a `data object` arm it is the arm name; for a
non-`data` throwable it is `Throwable.toString()`'s `class: message`. All three
include the payload, which is the intent — the default is the *safe-type*
rendering.

#### The deny rendering, and why it differs from iOS

Because unconformable types are the normal case here, `diagnosticDetail` appends
the **cause chain as qualified type names** — for conformed and unconformed
alike:

```
VaultBrowseError.Failed(detail=…)  <-  CloudFolderException  <-  java.io.FileNotFoundException
<undisclosed android.system.ErrnoException>  <-  java.io.IOException
```

Three properties make this the right trade:

- **Provably data-free.** A class name is a compile-time constant in the binary.
  It cannot carry runtime data, so the chain is exactly as fail-closed as a bare
  type marker.
- **It recovers most of what the stack trace was worth.** `VaultBrowseError.Failed`
  alone does not distinguish "SAF handed us a revoked URI" from "the working copy
  is missing"; the chain does. This directly answers the diagnostic dead end
  #467 accepted for `UniffiInternalError`.
- **It is needed for conformed types too.** `Throwable.toString()` omits the
  cause. Without the appended chain, a conformed wrapper silently discards
  everything beneath it.

Depth-capped, with an identity-set cycle guard (a `Throwable` cause cycle is
constructible even though `initCause` rejects self-causation).

### 2. Conformances and redactions

Five sealed types implement the interface, in-class — Kotlin has no
extension-based conformance
([[project_secretary_kotlin_interface_conformance_in_class]]):
`VaultBrowseError`, `VaultSyncError`, `DeviceUnlockError`,
`VaultProvisioningError`, `VaultNameError`.

**Three** arms are redacted at source. The third was found by carrying out the
payload-origin audit below, and would not have been caught by porting the iOS
redaction list:

```kotlin
sealed class VaultBrowseError(message: String? = null) : Exception(message), SecretFreeThrowable {
    override val diagnosticDescription: String get() = when (this) {
        is CorruptVault       -> "CorruptVault(<redacted>)"
        is InvalidArgument    -> "InvalidArgument(<redacted>)"
        is SaveCryptoFailure  -> "SaveCryptoFailure(<redacted>)"
        else                  -> toString()
    }
    // …arms unchanged…
}
```

- `CorruptVault(detail)` — a Rust-authored string passed through verbatim. We do
  not author it, so its content cannot be reviewed here; `RecordError::DuplicateKey`
  is a known member that embeds vault plaintext. This is the "unreviewed content"
  class the policy exists to deny.
- `InvalidArgument(detail)` — `RecordEditModel` interpolates a decrypted record
  field name into it.
- `SaveCryptoFailure(detail)` — **carries the same plaintext as `CorruptVault`,
  one arm over.** The bridge's `map_core_vault_error_*` folds
  `VaultError::Record(_)` and `VaultError::Block(_)` into
  `FfiVaultError::SaveCryptoFailure { detail: format!("{e}") }`
  (`retention/orchestration.rs:205` and five siblings in `revoke` / `trash` /
  `purge` / `restore` / `save`). `VaultError::Record(_)` renders as
  `"record CBOR error: {0}"` over the inner `RecordError`, so
  `RecordError::DuplicateKey`'s decrypted CBOR field name lands in `detail`
  exactly as it does in `CorruptVault`'s.

**iOS is not exposed here, and the reason is worth recording.** Its
`VaultAccessError` has no `.saveCryptoFailure` case at all, so
`VaultException.SaveCryptoFailure` falls to `VaultErrorMapping.swift:53`'s
`default: return .other(diagnosticDetail(e))` — gated at construction, because
uniffi's `VaultException` is not `SecretFreeError`-conformed and therefore
default-denies. Android's `BrowseMapping.kt:26` instead maps the arm
**explicitly** and carries the raw `detail`. The divergence is in the mapper, not
in the policy, which is why an audit of Android's own arms was required rather
than a port of iOS's redaction list.

**Redacting `diagnosticDescription` does not touch `message`.** `RecordEditForm.kt:62`
renders `it.message` on screen and still shows the user which field is bad. No
UX change.

#### Payload-origin audit

Every arm not redacted above renders **in full**, which is a security claim per
arm, not per type. The audit is complete; it ships as a doc comment beside the
conformance. Arms with no payload (`data object`) are omitted — they are safe by
construction.

| Arm | Payload origin | Verdict |
|---|---|---|
| `VaultBrowseError.CorruptVault` | Rust `VaultError` Display; folds `Record(_)`/`Block(_)` | **REDACT** |
| `VaultBrowseError.SaveCryptoFailure` | same, via `map_core_vault_error_*` | **REDACT** |
| `VaultBrowseError.InvalidArgument` | Kotlin-side; `RecordEditModel` interpolates a decrypted field name | **REDACT** |
| `VaultBrowseError.InvalidRecoveryPhrase` | `MnemonicError` Display: word **index** (`core/src/unlock/mnemonic.rs:54`), word count (`:46`), or the fixed `"BIP-39 checksum failed"` (`:59`) — never the word | render |
| `VaultBrowseError.FolderInvalid` | `format!("{context}: {source}")` — filesystem path + errno. Paths are disclosed under the threat model | render |
| `VaultBrowseError.DeviceUuidMismatch` | device UUIDs — a public per-device fingerprint, not key material | render |
| `VaultBrowseError.BlockNotFound` / `RecordNotFound` | hex-encoded UUIDs. The `BlockNotInTrash` / `BlockPurged` folds also `hex::encode` (`purge/orchestration.rs:153`), so no block *name* reaches them | render |
| `VaultBrowseError.ReauthFailed` | Android-constructed at the biometric gate from fixed labels | render |
| `VaultBrowseError.Failed` | gated at construction once §4 lands — payload becomes `diagnosticDetail` output | render |
| `VaultSyncError.StateCorrupt` | `SyncState` CBOR codec error. Describes the schema's own structure; `SyncState` holds vault UUID, block hashes and clocks, never vault plaintext | render |
| `VaultSyncError.InvalidArgument` | binding-layer wrong-length UUID/hash — the caller's own input | render |
| `VaultSyncError.Failed` | gated at construction once §4 lands | render |
| `VaultProvisioningError.CreateFailed` | gated at construction once §4 lands | render |
| `DeviceUnlockError.Enclave` | Keystore / BiometricPrompt message about a key operation, never vault content. iOS carries the same four `.enclave` sites as reviewed allowlist entries | render |
| `VaultNameError.*` | all three arms are `data object` with fixed user-facing copy | render |

The rule applied throughout: an arm whose origin **cannot be established** is
redacted, not assumed safe. Three were redacted on that basis; `SaveCryptoFailure`
is the one that a port of the iOS list would have missed.

### 3. The sanctioned sink (`:kit`)

```kotlin
object SecretaryLog {
    fun warn(tag: String, message: String, error: Throwable) =
        Log.w(tag, "$message: ${diagnosticDetail(error)}")
    fun warn(tag: String, message: String) = Log.w(tag, message)
    fun info(tag: String, message: String) = Log.i(tag, message)
}
```

No overload hands a `Throwable` to `Log`, so the stack-trace form is
unrepresentable at call sites. Seven sites change; `AppRoot.kt` and
`CloudVaultOpen.kt` lose their `android.util.Log` import; no other file in the
tree has one.

It lives in `:kit` because it needs `android.util.Log` and therefore cannot live
in the pure-JVM `:vault-access`. `:browse-ui` and `:sync-ui` do not depend on
`:kit`, so they cannot reach the sanctioned sink — and the guard fails them if
they import `android.util.Log` directly. Fail-closed by construction.

`SecretaryLog` is a two-line delegation and is deliberately not host-tested:
`android.util.Log` is a stub that throws in JVM unit tests. All the logic it
delegates to is tested in `:vault-access`.

### 4. Laundering cleanup

Fourteen sites take the same mechanical fix, `e.toString()` / `${e.message}` →
`diagnosticDetail(e)`. (`VaultProvisioningViewModel.kt:71` is a single line that
trips both rule B1 and rule B2, which is why the rule-by-rule hit counts sum to
more than the site count.)

| File | Line | Current |
|---|---|---|
| `vault-access/…/RecordEditModel.kt` | 116, 161 | `VaultBrowseError.Failed(e.toString())` |
| `vault-access/…/VaultBrowseModel.kt` | 112 | `VaultBrowseError.Failed(e.toString())` |
| `vault-access/…/VaultProvisioningViewModel.kt` | 71 | `CreateFailed(e.message ?: e.toString())` |
| `vault-access/…/DeviceUuid.kt` | 59 | `"… for ${file.name}: ${e.message}"` |
| `vault-access/…/mirror/VaultMirror.kt` | 72, 74 | `"$label failed: ${e.message}"` |
| `vault-access/…/mirror/RetryingCloudFolderPort.kt` | 102, 104 | `"$op … failed: ${e.message}"` |
| `kit/…/BrowseMapping.kt` | 47 | `VaultBrowseError.Failed(e.toString())` |
| `kit/…/VaultSyncErrorMapping.kt` | 29 | `VaultSyncError.Failed(e.toString())` |
| `kit/…/UniffiVaultCreatePort.kt` | 68 | `CreateFailed(e.message ?: …)` |
| `kit/…/UniffiVaultOpenPort.kt` | 252 | `"device-uuid resolve failed: ${e.message}"` |
| `kit/…/mirror/SafCloudFolderPort.kt` | 33 | `"SAF $op failed: ${e.message}"` |

All are in `:vault-access` or in `:kit`, which exposes it via `api`, so
`diagnosticDetail` is in scope at every one.

Four are on-screen copy, not logs, and become reviewed allowlist entries:

- `app/…/CreateVaultWizardScreen.kt:63` — `it.message` on a `VaultNameError`,
  whose message **is** the friendly copy. Legitimate; #454-compliant.
- `app/…/CreateVaultWizardScreen.kt:81, :93` — `it.message` on a
  `VaultProvisioningError`, whose `CreateFailed(detail)` arm is a carried
  diagnostic.
- `browse-ui/…/RecordEditForm.kt:62` — `it.message` on a `VaultBrowseError`,
  likewise.

The last three are the Android sibling of #473 (carried diagnostics rendered as
user-facing copy). They are **filed, not fixed** — changing that copy is a UX
decision, exactly as #467 concluded for `DeviceUnlockFailureDisplay`. Recording
them as allowlist entries rather than excluding their paths is what makes them
machine-visible.

#### Two innocent `.toString()` calls are deleted rather than allowlisted

Rule B2 needs an entry per innocent `.toString()`. Two of the six should not
exist in the first place, and removing them is an improvement on its own merits
— which is the test for whether a change like this is honest rather than a lint
dodge:

- `app/…/ProvisioningRouting.kt:30-37` (`cloudVaultKey`) reimplements
  `HexFormat.hexOfBytes` — same loop, same nibble arithmetic, with the hex-digit
  string inlined as a literal *twice* instead of using the named constant. `:app`
  already depends on `:vault-access`, so it calls `hexOfBytes(digest)` instead.
  Removes an allowlist entry and a copy-paste duplication.
- `vault-access/…/HexFormat.kt:16` converts to
  `buildString(bytes.size * 2) { … }`, which preserves the pre-sizing and is the
  idiomatic form.

The remaining four (`uri.toString()` ×2, a relativized `Path.toString()`, a
settings `value.toString()`) stay. `Uri.toString()` *is* how an Android `Uri` is
serialized; replacing them with shims to satisfy a checker would make the code
worse.

**Allowlist total: eight entries** — the four on-screen renders under rule B1,
plus the four surviving innocent `.toString()` calls under rule B2. Rules A and
C have none. Eight is the number to check the implementation against; a larger
one means something was allowlisted that should have been fixed.

### 5. The guard (`android/scripts/check-log-hygiene.sh`)

Bash + grep, no toolchain, runs on Linux in ~1s. Scope is `android/**/*.kt`,
excluding test sources and generated bindings.

**RULE A — single sink.** `android.util.Log` may be referenced in exactly one
file, named as a `readonly` constant in the script. Matching the import catches
the aliased form (`import android.util.Log as L`); matching the qualified call
catches `android.util.Log.w(…)`. No counting, no line-parsing, no multi-line
blind spot.

**RULE B1 — throwable-specific laundering.** `.message`, `.localizedMessage`,
`.stackTraceToString(`, `.printStackTrace(` denied tree-wide, opened only by an
exact-line allowlist entry. These constructs are throwable-shaped, so this rule
is **name-blind** — the property iOS rule 2 needed two review rounds to reach.

**RULE B2 — `.toString()`.** Denied tree-wide, opened only by an exact-line
allowlist entry. `.toString()` is how six of the eighteen sites launder,
including the FFI else-fold. Unlike Swift's `String(describing:)` it has
overwhelmingly innocent uses: of the twelve `.toString()` calls in the tree
today, six are the laundering sites above and six are innocent. Two of those six
are deleted rather than allowlisted (§4), leaving **four** entries.

The alternative considered and rejected was matching `.toString()` only on
conventional catch-binding names (`e`, `error`, `caught`, …). That has zero
friction and still catches all six current sites, but `problem.toString()`
walks through — precisely the bypass class iOS review round 3 found and closed.
The ongoing cost is one allowlist line whenever someone adds an innocent
`.toString()`: friction with no security value, accepted because keeping every
load-bearing rule construct-based and name-blind is what survived two
adversarial reviews.

**RULE C — bare interpolation, BEST EFFORT.** `"$e"` / `"${e}"` for a fixed list
of conventional catch-binding names. Name-based by necessity — `"$x"` is the most
common construct in Kotlin, so matching it wholesale is unusable. Labelled a
denylist in the header rather than dressed up as coverage, exactly as iOS rule 3
is. Rules A, B1 and B2 are the load-bearing ones.

**The matcher is bare-only, and that boundary is deliberate.** `${e}` is matched;
`${e.detail}`, `${e.blockUuidHex}`, `${error::class.simpleName}` are not. The
distinction is that interpolating the throwable *itself* is `toString()` by
another name — the whole payload, unreviewed — whereas interpolating a **named
typed field** is a specific, reviewable choice. Seven such typed-field renders
exist today, all of them deliberate user-facing copy in `TrashScreen`,
`BrowseScreen`, `SettingsErrorMessage`, `BrowseMapping` and
`DeviceUnlockFailureDisplay`. Matching them would generate seven allowlist
entries that assert nothing and would drown the rule. iOS rule 3 draws the same
line: its regex requires the closing paren immediately, so `\(error)` is matched
and `\(error.detail)` is not.

Rule C therefore has **zero hits and zero allowlist entries today** — it is
purely preventive, guarding a construct a developer reaches for by reflex. Its
`--self-test` controls are the only place it is ever observed firing, which is
exactly why those controls have to exist.

**Allowlist** (`android/scripts/log-hygiene-allowlist.txt`) is ported verbatim
in format and semantics from #467: TSV of
`<repo-relative-path><TAB><rule><TAB><exact trimmed source line><TAB><reason>`,
matched on the **exact trimmed line**, never a substring. Re-indenting an
exempted line keeps the entry valid; editing its content does not. The reason
field is mandatory.

**It is split into two sections by review weight**, because a rule-B2 entry and
a rule-A/B1/C entry are not the same kind of claim:

- **SECURITY DECISIONS** (rules A, B1, C) — each entry asserts that a value which
  *can* carry a secret is safe to render here. Reviewed like any other security
  change. Four entries, all on-screen copy.
- **NON-THROWABLE RECEIVERS** (rule B2 only) — each entry asserts only that the
  receiver is not a `Throwable`. That is a two-second check against the
  surrounding code, not a security argument. Four entries.

The split is not cosmetic. The whole file otherwise reads as a list of security
decisions, and burying four `Uri`/`Path`/`StringBuilder` receivers among them
trains a reviewer to skim — which is precisely how an allowlist decays into a
rubber stamp. Keeping the security section short is what keeps its entries
meaningful. The parser treats both sections identically; only the headings and
the review bar differ.

**CI.** New `kotlin-log-hygiene` job in `.github/workflows/test.yml` on
`ubuntu-latest`, alongside `swift-log-hygiene`, running `--self-test` then the
real scan as two steps. Step names quoted — an unquoted ` #` in a YAML `name:`
silently truncates it ([[project_secretary_ci_lint_tooling_local]]).

## Testing

**`SecretFreeThrowableTest` (`:vault-access`, JUnit 5, host-run).** Written
first, per TDD:

- an unconformed type renders `<undisclosed …>` and never its message —
  asserted with a message containing a sentinel that must not appear in the
  output;
- a conformed type takes the default rendering, payload included;
- `CorruptVault` and `InvalidArgument` render redacted, with a sentinel-bearing
  detail proven absent;
- redaction leaves `message` intact (the on-screen path is unaffected);
- the cause chain renders as type names, in order;
- the chain is depth-capped;
- a cause cycle terminates rather than hanging.

**Guard `--self-test`.** Two-sided, mirroring #467: a positive control per
bypass the design considered (aliased import, qualified call, each rule-B
construct, each rule-C binding name) and a negative control per legitimate form.
Includes the **A1/A2 allowlist control pair** — one file, two lines, where line 1
is an exact-line entry and line 2 shares its distinctive substring and must still
be caught. That pair is what detects a regression from exact-line to substring
matching; #467 records an earlier version of this control being vacuous because
it used two files.

**Mutation proof.** Reintroduce a raw site (a three-argument `Log.w`, and
separately an `e.toString()` launder) → guard exits 1 naming the line; revert →
exits 0. A check never observed failing is indistinguishable from a no-op.

**Regression.** `:vault-access:test` and `:kit`/`:app` builds must stay green.
Existing tests asserting on `Failed(detail)` text will need updating where the
detail changes — that is the evidence the laundering fix landed, not collateral.
Per [[project_secretary_android_sealed_when_cross_module]], `:app` is built in
the same task as any `:vault-access` sealed-type change.

## Non-goals

- **#474** (`RecordError::DuplicateKey` carrying a decrypted field name at the
  Rust root). Deferred deliberately. Fixing it lets **both** platforms narrow
  their `CorruptVault` / `.corruptVault` redaction in one coherent change,
  rather than narrowing iOS now and Android later. Keeps this slice free of the
  Rust core, so `git diff main... -- core/ ffi/` stays empty and no
  cargo/clippy/rustdoc/conformance gate is in play.
- **The Android #473 sibling** — the three on-screen sites that render a carried
  diagnostic as copy. Filed, allowlisted with reasons, not rewritten: the copy
  is a UX decision.
- **A type-aware replacement for the grep rules.** Rules B1, B2 and C all
  approximate a question only the type system can answer: is this receiver a
  `Throwable`? A custom **detekt** rule with type resolution answers it exactly —
  which would let rule B2's innocent allowlist be deleted outright, make B1
  precise, and close rule C's name-based gap (`problem.toString()` is invisible
  to a name list but obvious to a type check). Not built here: it needs a new
  tool, a custom-rule module, and a CI job, and the repo currently has no
  detekt/ktlint/spotless and runs no Gradle lint task, so there is nothing to
  piggyback on. Type resolution also needs a compiling classpath — cheap for the
  pure-JVM `:vault-access`, but it pulls in the Android SDK for the other
  modules. **Filed as a follow-up issue**; the grep guard ships now and would be
  retired by it, not layered under it.

- **No on-disk format, `.udl`, `FfiVaultError`, or FFI signature change.**
- **No new Compose UI, and no instrumented tests.** Everything here is
  host-testable or grep-level.

## Risks

- **Rule B2 imposes permanent friction.** Every future innocent `.toString()`
  needs an allowlist line. Accepted knowingly: the name-based alternative is the
  exact shape two iOS reviews rejected. The friction exists *only* because grep
  cannot answer a type question — "is this receiver a `Throwable`?" — which is
  why the durable fix is a type-aware rule rather than a better regex (filed as
  a follow-up, see Non-goals). Mitigated three ways here: two of the six innocent
  calls are deleted rather than allowlisted, the remaining four sit in their own
  low-weight allowlist section, and the reason field is mandatory. The rule
  starts at four such entries; if that count roughly doubles, the trade should be
  revisited — as a decision, not a silent loosening. The failure mode to watch
  for is entries added by reflex, which converts a fail-closed rule into a rubber
  stamp.
- **A missing future conformance is not a build error.** It degrades a log line
  to `<undisclosed …>`. Safe by design, but "did anyone conform the new error
  type?" is answered by review, not by the compiler — the same residual risk
  #467 records.
- **The payload-origin table is a point-in-time claim, and it already caught
  one.** An arm's payload can change from an edit in the Rust core with **no
  Kotlin diff at all** — which is exactly how `SaveCryptoFailure` came to carry a
  decrypted field name without anyone deciding it should. `CorruptVault`,
  `SaveCryptoFailure` and `InvalidArgument` are redacted precisely because their
  content is unreviewable from here; the remaining Rust-authored arms
  (`InvalidRecoveryPhrase`, `FolderInvalid`, `StateCorrupt`) are narrow enough to
  render, but the risk is of the same kind and nothing enforces it. Adding an arm
  to a Rust umbrella fold is invisible to every gate in this design.
- **Rule A depends on `SecretaryLog` staying honest.** The guard proves nothing
  else touches `android.util.Log`; it does not prove `SecretaryLog` itself
  renders through `diagnosticDetail`. That is one reviewed file, pinned by rule
  B — but it is review, not enforcement.
- **Cause-chain type names are a small disclosure.** They reveal which library
  failed (e.g. that SAF was involved). The threat model already treats
  application structure as known to a local attacker, and the alternative
  discards the chain entirely.
- **Rules are line-based**, so a construct split across two source lines evades
  them. This repo has no Kotlin formatter in CI, so nothing enforces the
  single-line status quo. Stated in the script header rather than assumed away —
  the same limit #467 records for Swift.
