# Design — Re-target the cloud write-reauth gate once the vault UUID is resolved (#340)

**Issue:** [#340](https://github.com/hherb/secretary/issues/340) — `security`. Android: the write-reauth gate is selected as `NOOP` on the **first** biometric/password open of a remembered (SAF-picked) cloud vault whose UUID isn't known before the open. Subsequent writes in that session are therefore not re-auth-gated. Android analog of iOS [#284](https://github.com/hherb/secretary/issues/284).

**Scope:** `android/vault-access` (one new pure class + host test) and `android/app` (`CloudVaultOpen.kt` + extend `CloudReauthRouteTest`). No FFI-surface, on-disk-format, `core`/`ffi`, spec, `conformance.py`, or conflict-KAT change. The new class is additive and is **not** a sealed-type arm, so there is no cross-module exhaustive-`when` impact.

---

## 1. Problem (verified at source)

For a remembered SAF cloud vault opened for the first time on this device, `location.vaultUuidHex == ""` — the real UUID is only learned *during* the open.

`openCloudBrowse` ([CloudVaultOpen.kt:138](../../../android/app/src/main/kotlin/org/secretary/app/CloudVaultOpen.kt)) builds the write-reauth gate at the **top** of the function from that empty `vaultId`:

```kotlin
val vaultId = location.vaultUuidHex          // "" for a first-open SAF-picked vault
val gate = when (cloudReauthRoute(deviceUnlock.enclaveEnrolled, vaultId, deviceUnlock.metadataVaultId)) { … }
```

`cloudReauthRoute` returns `GRACE_WINDOW` only when `metadataVaultId == openVaultId`. With `openVaultId == ""` and a real enrolled UUID, `"" != enrolledUUID` → `NOOP`. (Even if `GRACE_WINDOW` were forced, the `CoordinatorBiometricAuthorizer` would be bound to `""` and `coordinator.unlock("")` would mismatch.)

The real UUID is learned at [BrowseSession.kt:67-68](../../../android/app/src/main/kotlin/org/secretary/app/BrowseSession.kt) (`session.vaultUuidHex()` → `onVaultUuidLearned`), **after** the gate has already been built, handed to `VaultBrowseModel`, and seeded. Net effect: the first biometric/password session of a remembered, enrolled cloud vault writes through `NoopReauthGate` — ungated.

**Not a weaker open.** The open credential guard uses `metadataVaultId`, not the empty location UUID, so the *open* is correctly authorized. This is strictly a defense-in-depth gap in the **write-reauth gate** for that first session.

## 2. Fix — re-target the gate after the UUID is resolved

Chosen approach (of two considered): a **re-targetable wrapper gate**, retargeted from the cloud path's existing `onVaultUuidLearned` callback. Rejected alternative: turning `openBrowseWithSync`'s `gate` param into a `(resolvedHex) -> WriteReauthGate` factory — conceptually the decision happens once at the resolution point, but it changes the signature of a function shared by the demo path and ~5 instrumented callers. The wrapper keeps `openBrowseWithSync`, the demo path, and every instrumented caller untouched, and is exactly the "re-target the gate after `onVaultUuidLearned` fires" fix the issue suggests, mirroring the `learnedVaultId` post-resolution-correction idiom (#333).

### 2.1 New pure unit — `RetargetableReauthGate`

`android/vault-access/src/main/kotlin/org/secretary/browse/RetargetableReauthGate.kt`. Implements `WriteReauthGate`; a decorator over a swappable delegate.

```kotlin
class RetargetableReauthGate : WriteReauthGate {
    private var delegate: WriteReauthGate = NoopReauthGate
    private var seededAtMs: Long? = null

    override suspend fun authorizeWrite(reason: String) = delegate.authorizeWrite(reason)
    override fun seed(nowMs: Long) { seededAtMs = nowMs; delegate.seed(nowMs) }
    override fun reset() { seededAtMs = null; delegate.reset() }

    /** Swap the delegate; if the wrapper was already seeded, seed the new delegate with the
     *  recorded instant so the grace window opens from the unlock time regardless of whether
     *  seed() or retarget() ran first. */
    fun retarget(newGate: WriteReauthGate) {
        delegate = newGate
        seededAtMs?.let { newGate.seed(it) }
    }
}
```

- Initial delegate `NoopReauthGate` — before the UUID resolves, the placeholder authorizes (the browse model isn't yet accepting writes; this is a construction-time placeholder, not a runtime window).
- The re-seed-on-retarget branch makes the final state independent of seed/retarget ordering. In production `onVaultUuidLearned` (retarget) fires at `BrowseSession.kt:68` **before** `gate.seed(…)` at line 74, so at retarget time `seededAtMs` is still null and the seed at line 74 forwards to the freshly-retargeted grace delegate. The re-seed branch is the belt-and-suspenders that makes correctness a local invariant rather than relying on that ordering — the same discipline as the existing `learnedVaultId.isNotEmpty()` guard.
- **Not thread-safe** — plain mutable state; single-threaded by construction (all callers on the main dispatcher), identical to `GraceWindowReauthGate`. Documented on the class.

### 2.2 Cloud path change — `CloudVaultOpen.kt`

- Replace the up-front `when (cloudReauthRoute(…, vaultId, …))` block with `val gate = RetargetableReauthGate()`.
- In the existing `onVaultUuidLearned` callback (currently sets `learnedVaultId` and forwards), add `gate.retarget(cloudGateForResolvedVault(deviceUnlock, resolvedHex, clock))`.
- New small private helper in `CloudVaultOpen.kt`:

```kotlin
private fun cloudGateForResolvedVault(
    deviceUnlock: CloudDeviceUnlock,
    resolvedVaultId: String,
    clock: () -> Long,
): WriteReauthGate =
    when (cloudReauthRoute(deviceUnlock.enclaveEnrolled, resolvedVaultId, deviceUnlock.metadataVaultId)) {
        GateChoice.GRACE_WINDOW ->
            GraceWindowReauthGate(CoordinatorBiometricAuthorizer(deviceUnlock.coordinator, resolvedVaultId), clock)
        GateChoice.NOOP -> NoopReauthGate
    }
```

`clock` is the same monotonic `{ SystemClock.elapsedRealtime() }` the demo path and the current cloud path already use.

Because the gate is always rebuilt from the **resolved** UUID, the create path (UUID known up front, `resolvedHex == vaultId`) and the password/biometric open path are handled uniformly — no empty-vs-known special-casing. For an un-enrolled or stale-enrollment vault the helper still yields `NOOP`, preserving today's behavior.

## 3. Testing (host-only)

`openCloudBrowse` is Context/FragmentActivity-bound and not host-testable (matching why `cloudReauthRoute` is already host-tested but `openCloudBrowse` is not). The two new pure units carry the coverage; the thin retarget-in-callback glue is verified by reading + the existing instrumented cloud-open suite.

- **`RetargetableReauthGateTest`** (new, `android/vault-access/src/test/kotlin/org/secretary/browse/`) over a fake recording `WriteReauthGate`:
  - default (un-retargeted) delegate authorizes and forwards nothing to a real gate;
  - `seed(t)` then `retarget(g)` → `g` is seeded with `t`;
  - `retarget(g)` then `seed(t)` → `g` is seeded with `t` (ordering independence);
  - `authorizeWrite` forwards to the current delegate; `reset` clears the recorded seed and forwards.
- **Extend `CloudReauthRouteTest.kt`** — assert the bug/fix directly:
  - `cloudReauthRoute("", enrolled = true, meta = <hex>) == NOOP` (the pre-resolution state that caused the gap);
  - `cloudReauthRoute(<hex>, enrolled = true, meta = <hex>) == GRACE_WINDOW` (after resolution).

Full host gate to run green before push:
`:vault-access:test :app:testDebugUnitTest :kit:testDebugUnitTest :app:compileDebugKotlin :app:compileDebugAndroidTestKotlin`.

## 4. Non-goals / risks

- **Enroll-during-this-open still arms on the *next* open.** The retarget reads pre-open enrollment state (`deviceUnlock.enclaveEnrolled` at callback time, before `cloudEnrollThisDevice` runs later in `openCloudBrowse`), identical to the demo path. #340 concerns a vault enrolled on a *prior* session; enroll-then-write in the same session is out of scope and consistent with existing behavior.
- **No new crypto, no FFI change.** `CoordinatorBiometricAuthorizer` reuse is unchanged; only its `vaultId` argument now comes from the resolved UUID.
- **Backgrounding / process restart** re-runs the open and re-resolves the UUID, so the gate is re-armed correctly each open; no durable state involved.
