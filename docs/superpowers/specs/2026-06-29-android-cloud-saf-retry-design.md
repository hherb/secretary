# Design: `RetryingCloudFolderPort` — harden cloud flush against eventually-consistent SAF providers (#330)

**Date:** 2026-06-29
**Issue:** [#330](https://github.com/hherb/secretary/issues/330) — Android cloud-vault create/sync over Google Drive SAF is flaky (eventually-consistent provider)
**Scope:** Kotlin/Android only. No change to the on-disk format, crypto spec, `conformance.py`, conflict KATs, observable bytes, or the FFI surface.

## Problem

Creating or syncing a vault in a **Google Drive** folder via SAF intermittently fails on the first
attempt and succeeds on retry. Google Drive's SAF `DocumentsProvider` is eventually-consistent: it
caches directory listings, defers writes, and can report stale state. Two concrete failure modes
were observed on a RedMagic 11 Pro (Android 16) over a real Google Drive folder:

1. **Write throws.** A `createDirectory` / `createFile` / write inside `SafCloudFolderPort`'s
   `findOrCreate` fails because a just-created parent segment is not yet visible to `findFile`.
2. **Write succeeds but is not yet visible.** A write reports success, but an immediate re-list /
   re-read does not see the file (stale listing cache).

Both surface today as a `CloudFolderException` → `VaultMirrorException` → the cloud open routes
silently back to Unlock (now a Toast after `4f2bdbc`). A later identical retry works with no code
change. This is SAF-provider compatibility hardening, not a defect in the biometric-reauth feature.

The full flush path: `mirror.flush()` → `VaultMirror.flush` → `cloud.write` / `cloud.delete` →
`SafCloudFolderPort` seams → real `DocumentFile` operations. The eventual consistency bites at the
SAF layer, but every operation is reachable through the four `CloudFolderPort` seams (`list` /
`read` / `write` / `delete`). Crucially, the messy nested-directory `findOrCreate` logic lives
*inside* the `write` seam, so a write-level retry covers folder-creation flakiness too.

## Approach

Add a **decorator** `RetryingCloudFolderPort` that implements `CloudFolderPort` by delegating to an
inner port and adding bounded retry-with-backoff plus a post-write read-back verification.

This was chosen over (B) retrying inside `VaultMirror` — coarser, couples retry policy into the
mirror, and a single end-of-pass re-list verify is a weaker guarantee than per-file read-back — and
(C) retrying inside the `safCloudFolderPort` factory — that factory is the one piece deliberately
*not* host-tested, so retry logic buried there would be untestable.

The decorator lives in `vault-access` (pure JVM, no Android types), is fully host-testable with a
flaky fake port, and leaves `VaultMirror`, the SAF factory, and the `CloudFolderPort` interface
unchanged. Production wiring is a one-line wrap in `openCloudTarget`:

```kotlin
VaultMirror(RetryingCloudFolderPort(safCloudFolderPort(context, location.treeUri)))
```

## Components

### `RetryingCloudFolderPort` (new, `vault-access/.../mirror/RetryingCloudFolderPort.kt`)

```kotlin
class RetryingCloudFolderPort(
    private val inner: CloudFolderPort,
    private val policy: RetryPolicy = RetryPolicy.CLOUD_DEFAULT,
    private val sleep: (Long) -> Unit = Thread::sleep,
    private val onRetry: (String) -> Unit = {},
) : CloudFolderPort
```

- **`sleep`** seam defaults to `Thread::sleep`. The flush already runs off the main thread (the
  cloud open path is a `suspend` fn dispatched on IO), so a blocking sleep is acceptable. Host tests
  inject a recording no-op sleeper → deterministic, instant tests.
- **`onRetry`** defaults to `{}` (no `android.util.Log` dependency, so the class stays host-test-safe,
  matching `CloudDeviceEnroll`'s discipline). Receives a short human-readable reason per retry; a
  production caller may wire it to a logger.

### `RetryPolicy` (new, same file)

```kotlin
data class RetryPolicy(val maxAttempts: Int, val baseDelayMs: Long, val maxDelayMs: Long) {
    companion object {
        val CLOUD_DEFAULT = RetryPolicy(maxAttempts = 5, baseDelayMs = 250, maxDelayMs = 2000)
    }
}
```

`CLOUD_DEFAULT` → delays 250 / 500 / 1000 / 2000 / (2000) ms, worst-case ≈ 5.75 s of waiting across
4 backoffs before the 5th-attempt failure rethrows. No magic numbers: every value is a named field
or companion constant.

### `backoffDelayMs` (new, same file — pure function)

```kotlin
fun backoffDelayMs(attempt: Int, policy: RetryPolicy): Long  // min(base * 2^(attempt-1), maxDelay)
```

`attempt` is 1-based (the delay taken *after* attempt N fails, before attempt N+1). Pure, unit-tested
independently with a table of inputs.

## Behavior per operation

| Op | Retry on exception | Read-back verify | Rationale |
|---|---|---|---|
| `write` | yes | **yes** — `inner.read(path)` byte-equals `bytes` | data-loss-critical; absorbs both flaky modes |
| `read` | yes | n/a (it *is* a read) | absorbs stale-listing throw |
| `list` | yes | n/a | absorbs stale-listing throw at start of flush/materialize |
| `delete` | yes | **no** | idempotent; stale-present file is re-deleted next pass |

**`write` — two retry loops, write then verify (review-fix #335).** Phase 1 retries
`inner.write(path, bytes)` on its own throw. Phase 2, a *separate* retry loop, polls
`inner.read(path)` + plain byte-equality and retries **only the read** — it never re-issues the
write. Re-writing while the prior write is not yet visible is unsafe, not merely redundant: on an
eventually-consistent provider the not-yet-visible file is also invisible to
`SafCloudFolderPort.findOrCreate`'s overwrite `findFile`, so the re-write skips its delete-then-create
and forks a **duplicate** physical file (SAF display names are not unique), which a later `resolve`
matches as a stale copy — diverging cloud from working copy. A genuine persistent mismatch falls out
of phase 2 as a throw; the caller's next flush re-writes from the top (no duplicate). After
`maxAttempts` in either phase, throw `CloudFolderException("write|verify ... failed after N
attempts: <path>")`. Byte comparison correctness (not timing) is what matters — ciphertext blocks,
not secrets compared in constant time. (Defense-in-depth: `findOrCreate` now also deletes *every*
same-named child, so any duplicate that does get forked self-heals on the next overwrite.)

**`read` / `list`.** Attempt loop = call `inner`; on `CloudFolderException`, back off and retry;
after `maxAttempts`, rethrow the last exception. No verify step.

**`delete`.** Same retry-on-exception loop as read/list; **no** read-back verify. Documented inline:
delete is idempotent and a stale-still-present file is simply re-deleted on the next flush pass — it
never corrupts the vault — whereas a lost write loses data. Verifying absence would mean treating a
"no such file" read exception as the success signal, which is uglier than the negligible risk it
removes.

**Exception handling.** Only `CloudFolderException` is retried (the typed boundary the inner SAF
port already folds every provider error into). A non-`CloudFolderException` would be a programming
error and propagates immediately. We cannot distinguish transient from permanent failures (a revoked
SAF permission also folds to `CloudFolderException`); retrying a permanent failure simply burns the
bounded backoff budget and then rethrows — acceptable, and the eventually-consistent nature means
most real failures *are* transient.

## Data flow

1. `openCloudTarget` builds `VaultMirror(RetryingCloudFolderPort(safCloudFolderPort(...)))`.
2. `coordinator.createThenOpen` / `openExisting` calls `mirror.flush()` / `mirror.materialize()`.
3. `VaultMirror` issues `list` / `read` / `write` / `delete` against the retrying port.
4. Each op transparently retries against the inner SAF port until it succeeds (and, for writes,
   verifies) or the budget is exhausted → `CloudFolderException` → `VaultMirrorException` → the
   existing failure route (Toast + back to Unlock), unchanged.

## Testing (TDD, host-only)

Extend `FakeCloudFolderPort` with **count-scoped fault injection** so a test can simulate eventual
consistency precisely (without breaking existing tests that use `failWith`):

- `failNextN: Int` — the next N mutating/reading ops throw `CloudFolderException`, then succeed.
- a "hide read-back for the next K reads" hook — a write lands in the map but `read` reports the
  file missing K times, simulating write-succeeded-but-not-visible.

New `RetryingCloudFolderPortTest`:

- write succeeds after N transient write-throws; `onRetry` and `sleep` invoked the right number of
  times with the expected delays (recorded sleeper).
- write succeeds after the read-back is invisible for K attempts then appears.
- write that never verifies → throws `CloudFolderException` after exactly `maxAttempts`, with bounded
  total sleep.
- read / list retried and eventually succeed; a permanent failure rethrows after the budget.
- delete retried on exception; **no** read-back read is issued (assert via fake call recording).
- `backoffDelayMs` pure-function table test (attempt 1..6 against `CLOUD_DEFAULT`, capped at maxDelay).
- integration-style: a `VaultMirror.flush` over a flaky retrying port completes and pushes all files,
  proving the seam composes end-to-end.

All deterministic and instant via the injected no-op sleeper. No emulator/on-device dependency.

## Documentation

Add a **"Supported SAF providers"** note to the Android docs (located during planning — Android
README or `docs/`): tested/supported providers vs best-effort eventually-consistent ones (Google
Drive), and that #330's retry/verify hardening makes the best-effort providers usable but slower on
first write. Reference #330.

## Out of scope (explicit)

- No `looksLikeVault` / manifest-present post-write gate — the per-write read-back verify is a
  stronger, more general guarantee than a single manifest check.
- No native provider SDK (Dropbox/Drive OAuth) — that is an additive `CloudFolderPort` impl tracked
  as its own epic with a threat-model/ADR gate ([#334](https://github.com/hherb/secretary/issues/334)).
  This SAF-hardening slice helps *every* eventually-consistent SAF provider and is valuable
  independent of whether native providers ever land.
- No change to `VaultMirror` semantics, the `CloudFolderPort` interface, the on-disk format, the
  crypto spec, `conformance.py`, conflict KATs, or the FFI surface.
- On-device Google Drive proof on the RedMagic is a nice-to-have validation, **not** a gate — the
  slice is fully provable by host tests with the flaky fake. Conformance stays 27/27.
