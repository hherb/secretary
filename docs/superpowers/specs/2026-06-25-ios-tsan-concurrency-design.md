# iOS `UniffiVaultSession` TSan concurrency coverage — design

**Date:** 2026-06-25
**Issue:** #300 follow-up (TSan depth — flagged in the #300 handoff as an optional, unfiled follow-up).
**Scope:** iOS test + CI only. **No** Rust-core / on-disk-format / spec / `conformance.py` change; **no** `UniffiVaultSession` production-code change.

## Problem

PR #304 (#300) made `UniffiVaultSession` thread-safe by serializing every touch of
its mutable FFI-adjacent state under an `NSLock` plus a `wiped` flag (mirror of the
Android session, #250). But that mutual-exclusion property is currently asserted
**by construction and by doc-comment only** — the existing
`SessionWipeGuardIntegrationTests` exercises the `wiped`-guard semantics on a single
thread and its own docstring states the concurrency property is "not unit-tested …
a stress test would be flaky."

That leaves a gap: nothing actually drives the lock under genuine concurrency, so a
future change that drops or narrows the lock (e.g. a new off-actor `wipe()` caller)
could reintroduce the race with the suite still green.

## Why a concurrency test is *not* flaky here

ThreadSanitizer detects data races via happens-before tracking, not by observing a
race manifest as corruption. `NSLock` is TSan-aware, so:

- **With** the lock, TSan sees a clean happens-before edge between any two critical
  sections → no report.
- **Without** the lock, TSan flags the unsynchronized accesses to the three
  **mutable stored properties** the lock protects — `currentBlock`, `wiped`,
  `cachedDeviceUuid` — regardless of the exact interleaving.

The flakiness the #300 handoff worried about comes only from asserting a *specific
timing-dependent outcome* (e.g. "wipe definitely won the race"). This design asserts
**only** timing-independent invariants (no crash, TSan-clean, plus a count/contents
check that holds under any valid interleaving). The FFI handles `identity`/`manifest`
are immutable `let`s — reading them from two threads is not a Swift-level race — so
they are not the subject under test; the three mutable stored properties are.

## Deliverables

### 1. Concurrency tests — `SessionConcurrencyIntegrationTests.swift`

New file under `ios/SecretaryKit/Tests/SecretaryKitTests/`, reusing the
temp-copy-of-`golden_vault_001` harness pattern from
`SessionWipeGuardIntegrationTests` (never mutates the frozen KAT — see
[[feedback_smoke_test_temp_copy_golden_vault]]). Three tests, each asserting only
timing-independent invariants:

1. **`testConcurrentReadsAreRaceFree`** — N threads call `readBlock` on the same
   block concurrently. Exercises the `currentBlock` evict-and-replace path
   (`currentBlock?.wipe(); currentBlock = out`). Assert: every read returns the same
   record count as a single-threaded baseline; no throw; no crash.
   *Without the lock:* `currentBlock` write/write race + a double `BlockReadOutput.wipe()`
   (use-after-free) → TSan report and/or crash.

2. **`testConcurrentReadAndWipeAreRaceFree`** — across M fresh sessions, several
   reader threads run concurrently with one `wipe()` on each session. Exercises the
   `currentBlock` + `wiped` race. Assert: no crash; each read either returns records,
   returns empty, or throws a typed error (all are valid open/closed outcomes).
   *Without the lock:* `currentBlock`/`wiped` read-write race → TSan report.

3. **`testConcurrentWritesAreRaceFree`** — N threads call `appendRecord`
   concurrently on one session. Exercises the `write()` serialization and the
   first-write `cachedDeviceUuid` memoization. Assert: no crash; a final
   single-threaded read shows exactly the N appended records.
   *Without the lock:* `cachedDeviceUuid` write/write race + concurrent FFI writes →
   TSan report.

**Sharing the non-`Sendable` session across threads:** an explicit
`@unchecked Sendable` box (a tiny `final class` holding the session), documented as
the deliberate bypass — the entire point under test is that the lock makes this
otherwise-unsafe sharing safe. This keeps the project's zero-warning bar
(see [[project_secretary_ios_value_types_sendable_offload]]) instead of tripping
Swift 6 concurrency diagnostics on a raw capture.

**No magic numbers:** thread/iteration counts are named constants — modest enough to
keep the normal (non-TSan) suite fast, large enough that concurrent accesses reliably
overlap.

### 2. Scripts — `run-ios-tsan.sh` + extracted simulator resolver

- **`ios/scripts/lib/resolve-simulator.sh`** (new) — a sourceable helper exposing one
  function that resolves a simulator *name* to a concrete UDID (echoes the UDID, or
  exits non-zero with the available-device list). This is the ~20-line block currently
  inlined in `run-ios-tests.sh`, extracted verbatim so both scripts share one
  implementation (prefer pure, reusable units — see [[feedback_pure_functions]]).

- **`ios/scripts/run-ios-tests.sh`** (modified) — source the helper instead of
  inlining the resolver. Behavior identical; this is a pure extraction.

- **`ios/scripts/run-ios-tsan.sh`** (new) — single responsibility: build the
  xcframework (`build-xcframework.sh`), resolve the simulator via the shared helper,
  then `xcodebuild test -scheme SecretaryKit -destination "…,id=$SIM_ID"
  -enableThreadSanitizer YES` over the **whole** `SecretaryKitTests` suite
  (defense-in-depth — any future race anywhere is caught, and the three new tests are
  the teeth). It does **not** run the host-only `swift test` packages or build the app
  (no concurrency to instrument; already covered by `run-ios-tests.sh`). Honors the
  same `IOS_SIM` override.

### 3. CI job — `ios-tsan` in `.github/workflows/test.yml`

- `runs-on: macos-latest`; `actions/checkout@v4`; `Swatinem/rust-cache@v2`; then
  `bash ios/scripts/run-ios-tsan.sh`.
- **Path-gated to `ios/**` (plus the workflow file).** A workflow-level `paths:`
  filter is unsuitable — the other jobs (rust/desktop/conformance) must still run on
  non-iOS PRs. Instead a lightweight guard makes the job a no-op when no iOS files
  changed, implemented **without an unpinned third-party action** (consistent with the
  repo's existing stance — cf. the kotlin-conformance snap comment), e.g. an inline
  `git diff --name-only` guard step whose output gates the heavy steps. Exact
  mechanism finalized in the plan; the constraint is: no unpinned third-party action,
  and the job must not fire on PRs that don't touch `ios/**`.

## TDD red→green proof

The lock already exists (#304 merged), so "red" is demonstrated by temporarily
reverting it in the worktree: comment out the `lock.withLock { … }` wrappers in
`UniffiVaultSession`, run `run-ios-tsan.sh`, and capture the TSan data-race report
(and/or crash) on `currentBlock` / `wiped` / `cachedDeviceUuid`. Restore the lock →
green (TSan-clean, full suite passes). The actual red output is recorded in the
handoff as evidence the tests have teeth (see [[feedback_verify_deferred_items]] —
prove enforcement, don't assume it).

## Docs

- Update the `SessionWipeGuardIntegrationTests` docstring that claims concurrency is
  "not unit-tested … a stress test would be flaky" → reference the new TSan-verified
  tests.
- **README.md / ROADMAP.md: no change** — this adds test/CI coverage, not a capability
  or milestone (same rationale as the #300 pure-hardening work).
- **Spec / `conformance.py`: untouched** — zero `core/` change, no observable
  byte/semantic change, no `FfiVaultError` variant.

## Risks

- **TSan false positives from the uninstrumented Rust dylib / system frameworks.** If
  the suite isn't TSan-clean out of the box, add a narrowly-scoped, commented
  `TSAN_OPTIONS=suppressions=…` file rather than weakening TSan. Resolve any report
  explicitly (real Swift-side race vs. opaque-FFI false positive) — do not blanket-
  suppress.
- **CI time.** The Argon2id open (m=256 MiB) runs ~5–15× slower under TSan; expected
  to stay within runner limits, but watch the job duration on first run.

## Out of scope (YAGNI)

- No change to `UniffiVaultSession` production code.
- No Android-side TSan (Kotlin equivalent is a separate concern).
- No app build under TSan.
- No stress test that asserts a specific interleaving outcome (that *would* be flaky).
