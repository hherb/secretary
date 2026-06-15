# C.3 (Android) — Sync orchestration core

**Date:** 2026-06-15
**Milestone:** C.3 (mobile sync adapters), Android portion, slice 1 of N
**Status:** design — approved approach, pending spec review
**Scope:** Android only. Pure orchestration core only. No FFI, no Jetpack Compose, no folder-watch (SAF/`WorkManager`), no iOS change.

## 1. Purpose

Give the Android client the ability to run **one sync pass** against an already-selected,
already-unlockable vault folder and carry a tombstone-veto conflict to resolution —
entirely in **pure, host-testable Kotlin** with no FFI and no Android-framework dependency.

This is the faithful Android mirror of the iOS slice 1 (#228,
[`2026-06-14-c3-ios-sync-orchestration-core-design.md`](2026-06-14-c3-ios-sync-orchestration-core-design.md)).
What ships is the layer the later Android slices sit on: pure ports, metadata-only value
types, a host-tested `SyncCoordinator` that threads the two-call inspect→commit round-trip,
and a scriptable fake.

This slice deliberately stops short of:

- **The real FFI adapter** (`UniffiVaultSyncPort` over the generated `uniffi.secretary`
  Kotlin bindings + `jniLibs` `.so`) — a later slice; needs the Android NDK build + emulator.
- **Folder-change detection** (Storage Access Framework + `WorkManager`) — a later slice.
- **UI** (Compose sync badge, conflict-resolution sheet, sync-at-unlock) — a later slice;
  this is where `SyncBadgeState`, the `ViewModel`/`StateFlow`, and the `WallClock` seam land,
  exactly as on iOS (those shipped in iOS slice 3, #233).
- **iOS** — unchanged.

## 2. Why the Android core is thin (same reason as iOS)

All sync *logic* already lives in Rust and is frozen by the C.1/C.2 work, and is already
projected onto uniffi for Kotlin (#187). The Kotlin client calls exactly three functions
(generated, lowerCamelCase) from `uniffi.secretary`:

- **`syncVault(stateDir, vaultFolder, password, nowMs) → SyncOutcomeDto`** — inspect /
  pause-on-conflict. Auto-applies every safe arm; on a tombstone dispute it returns
  `ConflictsPending(vetoes, collisions, manifestHash)` **without writing**.
- **`syncCommitDecisions(stateDir, vaultFolder, password, decisions, manifestHash, nowMs)
  → SyncOutcomeDto`** — re-runs the pass, re-checks `manifestHash` (TOCTOU freshness gate)
  **before** any write, then commits the caller's per-record decisions.
- **`syncStatus(stateDir, vaultUuid) → SyncStatusDto`** — read-only device-clock view.

Those throw `VaultException` (uniffi projection of `FfiVaultError`). The bridge already
enforces the anti-oracle separation (§13): `WrongPasswordOrCorrupt` conflates wrong
password with vault corruption; all messages are path-neutral.

**This slice does not call any of that.** It defines the pure Kotlin *shape* those calls
will be adapted into, isolated behind a `VaultSyncPort` interface, so the orchestration is
built and host-tested once with a fake, before the FFI adapter lands. This mirrors the iOS
discipline: `VaultSyncPort` is the seam; `UniffiVaultSyncPort` (next slice) is the only
type that ever imports the generated bindings.

## 3. Module structure

`android/` becomes a Gradle root. This slice adds the wrapper and **one** module — the pure
core, mirroring iOS's `SecretaryVaultAccess` package. The multi-module skeleton is laid down
correctly from day one; only the pure module exists this slice.

```
android/
  settings.gradle.kts          # includes :vault-access
  build.gradle.kts             # root: Kotlin JVM plugin version pin, repositories
  gradle.properties            # offline-friendly defaults
  gradlew / gradlew.bat        # wrapper (uses a cached distribution)
  gradle/wrapper/              # wrapper jar + properties (pinned distribution URL + sha256)
  vault-access/                # Gradle module :vault-access — PURE, no Android, no FFI
    build.gradle.kts           # kotlin("jvm"); deps: coroutines-core, test: junit5 + coroutines-test
    src/main/kotlin/org/secretary/sync/
      SyncModels.kt
      VaultSyncError.kt
      VaultSyncPort.kt
      SyncCoordinator.kt
    src/test/kotlin/org/secretary/sync/
      FakeVaultSyncPort.kt
      SyncCoordinatorTest.kt
      SyncModelsTest.kt
      VaultSyncErrorTest.kt
```

Later slices add `:kit` (Android library; real uniffi adapters + `jniLibs`) and `:app`
(Compose). They are **not** created here — `settings.gradle.kts` includes only `:vault-access`.

### Build tooling decisions

- **Gradle, Kotlin DSL.** First Gradle project in the repo (the existing
  `ffi/secretary-ffi-uniffi/tests/kotlin/` conformance harness uses raw `kotlinc` + JNA and
  stays as-is — it is a test harness, not an app platform). Android genuinely needs Gradle
  for the eventual NDK build, Compose, and instrumented tests, so it is introduced correctly now.
- **Pure JVM module, not Android library.** `:vault-access` uses `kotlin("jvm")`, not the
  Android Gradle Plugin. It has zero Android-framework dependency, so its tests run on plain
  JUnit5 on any JDK — **no emulator, no Android SDK** — on CI (Linux + macOS). This is the
  Kotlin equivalent of iOS's `swift test` host-testing of `SecretaryVaultAccess`.
- **Offline-capable.** `~/.gradle` already caches the needed Gradle distributions and the
  `kotlinx-coroutines-core/-test` + `junit-jupiter` artifacts; versions are pinned to what is
  cached. A `gradle.properties` keeps the build from reaching out unnecessarily. Network
  availability for first resolution is the one risk (see §8); verified first in the plan.
- **Toolchain pins.** Kotlin and coroutines versions are pinned explicitly in the root
  `build.gradle.kts`; the Gradle distribution is pinned by URL + sha256 in
  `gradle/wrapper/gradle-wrapper.properties`. Security-adjacent dependency hygiene matches the
  repo's exact-pin discipline.

## 4. The pure types (Swift → Kotlin mapping)

Package `org.secretary.sync`. Every type is immutable and framework-free.

| iOS (pure `SecretaryVaultAccess`) | Android (`:vault-access`, `org.secretary.sync`) |
|---|---|
| `protocol VaultSyncPort` (async funcs) | `interface VaultSyncPort` (`suspend fun`) |
| `enum VaultSyncError: Error, Equatable` | `sealed class VaultSyncError : Exception()` |
| `actor SyncCoordinator` | `class SyncCoordinator` + `Mutex`, `suspend fun`s |
| value structs (`Sendable`) | immutable `data class`es |
| `enum SyncOutcome` (associated values) | `sealed interface SyncOutcome` w/ data-class arms |
| `[UInt8]` password / manifest hash | `ByteArray` |
| `FakeVaultSyncPort` (testing product) | `FakeVaultSyncPort` in `src/test` |

### 4.1 `SyncModels.kt` — metadata-only value types

All `data class`/`sealed interface`; **metadata only** — field **names** only, never field
*values*. Mirrors iOS `SyncModels.swift` one-to-one and the uniffi DTOs.

```kotlin
data class DeviceClock(val deviceUuidHex: String, val counter: ULong)

data class SyncStatus(
    val hasState: Boolean,
    val deviceClocks: List<DeviceClock>,
    val lastStateWriteMs: ULong?,
)

data class SyncVeto(
    val recordUuidHex: String,
    val recordType: String,
    val tags: List<String>,
    val fieldNames: List<String>,        // names only, never values
    val localLastModMs: ULong,
    val peerTombstonedAtMs: ULong,
    val peerDeviceHex: String,
)

data class SyncCollision(val recordUuidHex: String, val fieldNames: List<String>)

data class SyncVetoDecision(val recordUuidHex: String, val keepLocal: Boolean)

data class PendingConflict(val vetoes: List<SyncVeto>, val collisions: List<SyncCollision>)

sealed interface SyncOutcome {
    data object NothingToDo : SyncOutcome
    data object AppliedAutomatically : SyncOutcome
    data object SilentMerge : SyncOutcome
    data object MergedClean : SyncOutcome
    data object RollbackRejected : SyncOutcome
    data class ConflictsPending(
        val vetoes: List<SyncVeto>,
        val collisions: List<SyncCollision>,
        val manifestHash: ByteArray,     // opaque freshness token; equals()/hashCode() override
    ) : SyncOutcome
}
```

Note: `ConflictsPending` holds a `ByteArray`, so it gets explicit `equals`/`hashCode`
(content-based) — `data class` structural equality on `ByteArray` is referential by default.

The six `SyncOutcome` arms correspond exactly to the uniffi `SyncOutcomeDto` arms
(`NothingToDo`, `AppliedAutomatically`, `SilentMerge`, `MergedClean`, `ConflictsPending`,
`RollbackRejected`). The 1:1 mapping is what the next slice's `UniffiVaultSyncPort` will
translate; keeping the arms identical keeps that adapter a dumb transcription.

### 4.2 `VaultSyncError.kt`

```kotlin
sealed class VaultSyncError(message: String? = null) : Exception(message) {
    data object WrongPasswordOrCorrupt : VaultSyncError()   // anti-oracle §13 — do NOT split
    data object InProgress : VaultSyncError()
    data object StateVaultMismatch : VaultSyncError()
    data class  StateCorrupt(val detail: String) : VaultSyncError(detail)
    data object EvidenceStale : VaultSyncError()            // TOCTOU freshness gate tripped
    data object DecisionsIncomplete : VaultSyncError()
    data class  InvalidArgument(val detail: String) : VaultSyncError(detail)
    data class  Failed(val detail: String) : VaultSyncError(detail)
    data object NoPendingConflict : VaultSyncError()        // Kotlin-side guard only
}
```

- **Separate from any future `VaultAccessError`.** The sync FFI surface returns a different
  `FfiVaultError`/`VaultException` variant set than vault-access; folding the two error types
  would misattribute. This mirrors iOS keeping `VaultSyncError` distinct from `VaultAccessError`.
- `WrongPasswordOrCorrupt` is deliberately conflated (anti-oracle §13). Do not split it into a
  "wrong credential" arm.
- `NoPendingConflict` is a coordinator-internal guard (caller invoked `resolve` with nothing
  stashed); it has no FFI origin, exactly like the iOS `noPendingConflict` arm.

### 4.3 `VaultSyncPort.kt`

```kotlin
interface VaultSyncPort {
    suspend fun status(stateDir: String, vaultUuid: ByteArray): SyncStatus
    suspend fun sync(
        stateDir: String, vaultFolder: String, password: ByteArray, nowMs: ULong,
    ): SyncOutcome
    suspend fun commitDecisions(
        stateDir: String, vaultFolder: String, password: ByteArray,
        decisions: List<SyncVetoDecision>, manifestHash: ByteArray, nowMs: ULong,
    ): SyncOutcome
}
```

- Every method is `suspend` for uniformity (even cheap `status`); the future real adapter
  runs `sync`/`commitDecisions` on `Dispatchers.IO` (off the main/UI dispatcher) because they
  re-open the vault and run Argon2id, while `status` is a cheap disk read.
- **Password discipline.** `password: ByteArray` is passed per call and **never stored** by
  the port or the coordinator. The caller (a future ViewModel) is responsible for clearing its
  own copy after the call; the port does not retain it.
- The interface throws `VaultSyncError` (Kotlin functions don't declare checked exceptions;
  documented in KDoc). Failures from the future FFI adapter are mapped to these arms there.

### 4.4 `SyncCoordinator.kt`

```kotlin
class SyncCoordinator(
    private val port: VaultSyncPort,
    private val stateDir: String,
    private val vaultFolder: String,
) {
    private val mutex = Mutex()
    private var stashedToken: ByteArray? = null      // manifestHash from a paused pass
    private var stashedConflict: PendingConflict? = null

    suspend fun pendingConflict(): PendingConflict?  // mutex-guarded read
    suspend fun status(vaultUuid: ByteArray): SyncStatus
    suspend fun runPass(password: ByteArray, nowMs: ULong): SyncOutcome
    suspend fun resolve(
        decisions: List<SyncVetoDecision>, password: ByteArray, nowMs: ULong,
    ): SyncOutcome
}
```

**Responsibility** — thread the two-call inspect→commit round-trip and hold the freshness
token + conflict detail privately between the two calls:

- `runPass` → `port.sync(...)`. On `ConflictsPending`, stash `manifestHash` + `PendingConflict`
  and return the outcome. On every other arm, clear any stash and return.
- `resolve` → requires a stashed token; else throws `NoPendingConflict`. Calls
  `port.commitDecisions(..., manifestHash = stashedToken, ...)`. On a resolved (non-conflict)
  arm, clear the stash. On `ConflictsPending` again (peer moved), re-stash the new token +
  conflict. On `EvidenceStale`/`DecisionsIncomplete` (thrown), **preserve** the stash so the
  caller can retry without re-running `runPass`.

**Concurrency model — the one deliberate divergence from iOS.** The Swift `actor` is reentrant:
it releases isolation at each `await`, so a second call could interleave (the design assumes a
single serial driver per vault). The Kotlin coordinator instead holds a **non-reentrant
`Mutex` across the whole suspending port call**, so a second concurrent `runPass`/`resolve`
*blocks* until the first completes rather than interleaving. This is *stronger* serialization,
it is simpler to reason about, and it cannot deadlock because the public methods never call one
another. The per-vault FFI lockfile (which surfaces `InProgress`) remains the real cross-process
guard; the `Mutex` is the in-process single-driver guarantee. This divergence is documented in
the `SyncCoordinator` KDoc.

- **`nowMs: ULong` is a parameter, not injected.** The `WallClock` seam lives at the ViewModel
  layer and arrives in the UI slice — identical to iOS slice 1, where `SyncCoordinator.runPass`
  also took `nowMs` directly.
- **No password retention.** The coordinator stashes only the freshness token (a manifest hash,
  not a secret) and conflict *metadata*; never the password.

## 5. Data flow

```
caller (future ViewModel)        SyncCoordinator                 VaultSyncPort (fake this slice)
  runPass(pw, now) ───────────▶  mutex.withLock {
                                   port.sync(...) ─────────────▶  returns SyncOutcome
                                   if ConflictsPending:
                                     stash token + conflict
                                 } ◀─────────────── outcome
  (user picks Keep-mine/Accept-delete per veto)
  resolve(decisions, pw, now) ─▶ mutex.withLock {
                                   require stashedToken (else NoPendingConflict)
                                   port.commitDecisions(.., stashedToken, ..) ▶ returns outcome
                                   if resolved: clear stash
                                   if ConflictsPending: re-stash
                                   (EvidenceStale/DecisionsIncomplete thrown → stash preserved)
                                 } ◀─────────────── outcome
```

## 6. Error handling

- The coordinator surfaces `VaultSyncError` arms unchanged from the port; it adds only
  `NoPendingConflict` (resolve with nothing stashed).
- Stash lifetime is the retry contract: cleared on resolved arms, preserved on
  `EvidenceStale`/`DecisionsIncomplete` so the caller re-`resolve`s without a fresh `runPass`.
- No error message constructed in this layer leaks a path or distinguishes wrong-password from
  corruption (the conflation is already done upstream; this layer must not undo it).

## 7. Testing

Host-tested as a JVM module — `./gradlew :vault-access:test` — JUnit5 + `kotlinx-coroutines-test`
(`runTest`). No emulator, no FFI. `FakeVaultSyncPort` seeds a queue of outcomes (or a thrown
error) per method and records inputs (a spy) so the round-trip is asserted both ways.

TDD order (red → green per behavior):

1. **`SyncModelsTest`** — `ConflictsPending` content-based `equals`/`hashCode` over `ByteArray`;
   value-type equality for the rest.
2. **`VaultSyncErrorTest`** — arm identity; `StateCorrupt`/`InvalidArgument`/`Failed` carry detail;
   `WrongPasswordOrCorrupt` is a single conflated arm.
3. **`SyncCoordinatorTest`**:
   - each safe `SyncOutcome` arm passes through and leaves no stash;
   - `runPass` → `ConflictsPending` stashes token + conflict; `pendingConflict()` reflects it;
   - `resolve` passes the **stashed** `manifestHash` to `port.commitDecisions` (spy asserts the
     exact bytes), clears stash on a resolved arm;
   - `resolve` with no stash throws `NoPendingConflict` without calling the port;
   - `resolve` → `EvidenceStale`/`DecisionsIncomplete` **preserves** the stash (retry works);
   - `resolve` → `ConflictsPending` again re-stashes the new token;
   - password bytes are not retained by the coordinator after a call (assert via the spy that
     each call received the bytes passed, and the coordinator exposes no password accessor).

## 8. Risks / open items

- **First-resolution network.** Gradle dependency resolution may need Maven Central on the
  first run. The needed artifacts are already in `~/.gradle/caches/modules-2`, so an
  `--offline` build is expected to work; the plan verifies `./gradlew :vault-access:test
  --offline` early and falls back to online resolution (or, worst case, the raw-`kotlinc`
  harness pattern) only if the cache proves insufficient.
- **`ByteArray` equality footgun.** Any `data class` carrying a `ByteArray` (`ConflictsPending`)
  must override `equals`/`hashCode`; a test pins this so a future field addition can't silently
  regress to referential equality.
- **`ULong` across the boundary.** The uniffi DTOs use `u64`/`ULong`; the pure types use
  `ULong` to match, so the next slice's adapter is a straight copy with no narrowing.
- **`SyncBadgeState` and `ViewModel`/`StateFlow`/`WallClock` are intentionally absent.** They
  are UI-slice concerns (iOS shipped them in slice 3). Adding them here would blur the slice
  boundary that makes this mirror reviewable against iOS slice 1.

## 9. Out of scope (explicit)

No Rust/core change. No on-disk-format, crypto, CRDT, or FFI-surface change. No generated-binding
change. No iOS change. No Android library/`jniLibs`/NDK, no Compose, no SAF/`WorkManager`, no
instrumented (emulator) test. The `git diff main...HEAD` for this slice touches only `android/**`
+ `docs/**` + `README.md` + `ROADMAP.md`.
