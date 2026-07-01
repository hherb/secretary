# Cloud write-reauth gate re-target (#340) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Arm the write-reauth gate on the first biometric/password open of a remembered SAF cloud vault (whose UUID is `""` until resolved during open), instead of falling to `NOOP`.

**Architecture:** A pure `RetargetableReauthGate` decorator (initial delegate `NoopReauthGate`) is handed to `openBrowseWithSync`; the cloud path re-targets it from its existing `onVaultUuidLearned` callback using the resolved UUID. `openBrowseWithSync`, the demo path, and all instrumented callers are untouched.

**Tech Stack:** Kotlin, JUnit 5 (jupiter), kotlinx-coroutines-test, Gradle. Modules `:vault-access` (pure) and `:app`.

## Global Constraints

- Additive, no weaker open: the open credential guard already uses `metadataVaultId`; this only fixes the **write-reauth gate**. Do not alter the open path.
- No FFI-surface / on-disk-format / spec / `conformance.py` / conflict-KAT change. `RetargetableReauthGate` is a new class, NOT a sealed-type arm → no cross-module exhaustive-`when` impact.
- New/modified secret handling: none beyond reusing `CoordinatorBiometricAuthorizer` with the resolved `vaultId`.
- Gate holders are single-threaded (main dispatcher). Document new mutable-state types as NOT thread-safe, mirroring `GraceWindowReauthGate`.
- Full host gate must be green before push: `:vault-access:test :app:testDebugUnitTest :kit:testDebugUnitTest :app:compileDebugKotlin :app:compileDebugAndroidTestKotlin`.
- `cd` into `android/` for Gradle; the worktree is `.worktrees/android-cloud-reauth-gate-retarget-340`. Spell out worktree paths in Edit/Write/Read (bare repo-root paths hit MAIN).

---

### Task 1: `RetargetableReauthGate` (pure decorator + host test)

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/RetargetableReauthGate.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/RetargetableReauthGateTest.kt`

**Interfaces:**
- Consumes: `WriteReauthGate` (interface with `suspend authorizeWrite(reason)`, `seed(nowMs)`, `reset()`), `NoopReauthGate` (both in `org.secretary.browse.WriteReauthGate.kt`).
- Produces: `class RetargetableReauthGate : WriteReauthGate` with `fun retarget(newGate: WriteReauthGate)`. Semantics: initial delegate `NoopReauthGate`; `seed(n)` records `n` and forwards; `reset()` clears the recorded instant and forwards; `authorizeWrite` forwards to the current delegate; `retarget(g)` swaps the delegate and, if already seeded, seeds `g` with the recorded instant (ordering-independent).

- [ ] **Step 1: Write the failing test**

Create `android/vault-access/src/test/kotlin/org/secretary/browse/RetargetableReauthGateTest.kt`:

```kotlin
package org.secretary.browse

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** Records seed/reset/authorize calls so the wrapper's forwarding is observable host-side. */
private class RecordingGate : WriteReauthGate {
    val seeds = mutableListOf<Long>()
    val authorizeReasons = mutableListOf<String>()
    var resets = 0
    override suspend fun authorizeWrite(reason: String) { authorizeReasons += reason }
    override fun seed(nowMs: Long) { seeds += nowMs }
    override fun reset() { resets++ }
}

class RetargetableReauthGateTest {
    @Test
    fun `default delegate authorizes (no crash, no real gate needed)`() = runTest {
        RetargetableReauthGate().authorizeWrite("w") // NoopReauthGate delegate → completes silently
    }

    @Test
    fun `seed then retarget seeds the new delegate with the recorded instant`() {
        val gate = RetargetableReauthGate()
        gate.seed(1_000L)
        val g = RecordingGate()
        gate.retarget(g)
        assertEquals(listOf(1_000L), g.seeds)
    }

    @Test
    fun `retarget then seed also seeds the new delegate (ordering independent)`() {
        val gate = RetargetableReauthGate()
        val g = RecordingGate()
        gate.retarget(g)          // not seeded yet → g not seeded here
        gate.seed(1_000L)         // forwards to current delegate g
        assertEquals(listOf(1_000L), g.seeds)
    }

    @Test
    fun `authorizeWrite forwards to the current delegate`() = runTest {
        val gate = RetargetableReauthGate()
        val g = RecordingGate()
        gate.retarget(g)
        gate.authorizeWrite("confirm delete")
        assertEquals(listOf("confirm delete"), g.authorizeReasons)
    }

    @Test
    fun `reset forwards and clears the recorded seed so a later retarget does not re-seed`() {
        val gate = RetargetableReauthGate()
        val g = RecordingGate()
        gate.retarget(g)
        gate.seed(1_000L)
        gate.reset()
        assertEquals(1, g.resets)                 // reset forwarded to current delegate
        val g2 = RecordingGate()
        gate.retarget(g2)
        assertTrue(g2.seeds.isEmpty())            // recorded instant cleared by reset
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.RetargetableReauthGateTest'`
Expected: FAIL — compilation error, `RetargetableReauthGate` is unresolved.

- [ ] **Step 3: Write minimal implementation**

Create `android/vault-access/src/main/kotlin/org/secretary/browse/RetargetableReauthGate.kt`:

```kotlin
package org.secretary.browse

/**
 * A [WriteReauthGate] whose delegate can be swapped after construction. Used by the cloud open path
 * (#340): a remembered SAF cloud vault's UUID is unknown before the open, so the real gate cannot be
 * chosen up front. The caller hands this placeholder (delegating to [NoopReauthGate]) to the open,
 * then calls [retarget] once `onVaultUuidLearned` resolves the UUID.
 *
 * [seed] records the unlock instant and forwards it; [retarget] seeds the incoming delegate with that
 * instant if the wrapper was already seeded, so the grace window opens from the unlock time regardless
 * of whether [seed] or [retarget] runs first (in production `onVaultUuidLearned` — hence [retarget] —
 * fires before `openBrowseWithSync` seeds the gate). This makes correctness a LOCAL invariant rather
 * than one relying on call ordering.
 *
 * NOT thread-safe: plain mutable state, single-threaded by construction (all callers on the main
 * dispatcher), identical to [GraceWindowReauthGate].
 */
class RetargetableReauthGate : WriteReauthGate {
    private var delegate: WriteReauthGate = NoopReauthGate
    private var seededAtMs: Long? = null

    override suspend fun authorizeWrite(reason: String) = delegate.authorizeWrite(reason)

    override fun seed(nowMs: Long) {
        seededAtMs = nowMs
        delegate.seed(nowMs)
    }

    override fun reset() {
        seededAtMs = null
        delegate.reset()
    }

    /** Swap the delegate; re-seed it with the recorded instant if the wrapper was already seeded. */
    fun retarget(newGate: WriteReauthGate) {
        delegate = newGate
        seededAtMs?.let { newGate.seed(it) }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.RetargetableReauthGateTest'`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.RetargetableReauthGateTest' \
  && cd .. && git add android/vault-access/src/main/kotlin/org/secretary/browse/RetargetableReauthGate.kt \
     android/vault-access/src/test/kotlin/org/secretary/browse/RetargetableReauthGateTest.kt \
  && git commit -m "feat(android): RetargetableReauthGate — swappable write-reauth gate delegate (#340)"
```

---

### Task 2: Wire the cloud open path to re-target the gate on UUID resolution

**Files:**
- Modify: `android/app/src/main/kotlin/org/secretary/app/CloudVaultOpen.kt` (gate construction ~L137-158; doc comment L104-108; imports)
- Modify: `android/app/src/test/kotlin/org/secretary/app/CloudReauthRouteTest.kt` (add empty-UUID characterization test)

**Interfaces:**
- Consumes: `RetargetableReauthGate` (Task 1); existing `cloudReauthRoute(enclaveEnrolled, openVaultId, metadataVaultId): GateChoice`, `GateChoice`, `CloudDeviceUnlock` (with `.enclaveEnrolled`, `.metadataVaultId`, `.coordinator`), `GraceWindowReauthGate`, `CoordinatorBiometricAuthorizer`, `NoopReauthGate`.
- Produces: nothing new consumed downstream (internal wiring); adds a private helper `cloudGateForResolvedVault`.

- [ ] **Step 1: Add the boundary characterization test (documents the bug)**

In `android/app/src/test/kotlin/org/secretary/app/CloudReauthRouteTest.kt`, add after `enrolled_null_metadata_uses_noop` (before `device_secret_dir_is_namespaced_by_key`):

```kotlin
    @Test fun empty_openVaultId_uses_noop_even_when_enrolled() {
        // #340: a remembered SAF cloud vault's UUID is "" until it is resolved during open. Chosen
        // from "", the gate falls to NOOP even for an enrolled vault — which is why openCloudBrowse
        // must re-target the gate from the resolved UUID (see cloudGateForResolvedVault). Once
        // resolved, enrolled_matching_vault_uses_grace_window above shows the same vault picks GRACE.
        assertEquals(GateChoice.NOOP, cloudReauthRoute(enclaveEnrolled = true, openVaultId = "", metadataVaultId = "abcd"))
    }
```

- [ ] **Step 2: Run it (passes immediately — cloudReauthRoute is already correct; the bug was in *when* it was called)**

Run: `cd android && ./gradlew :app:testDebugUnitTest --tests 'org.secretary.app.CloudReauthRouteTest'`
Expected: PASS (existing 6 + new 1 = 7). This is a characterization test that pins the pre-resolution boundary; the fix is the wiring in the next steps.

- [ ] **Step 3: Import `RetargetableReauthGate`**

In `android/app/src/main/kotlin/org/secretary/app/CloudVaultOpen.kt`, add to the import block (alphabetically near the other `org.secretary.browse.*` gate imports around L9-15):

```kotlin
import org.secretary.browse.RetargetableReauthGate
```

- [ ] **Step 4: Replace the up-front gate with a retargetable placeholder**

Replace this block (currently ~L138-144):

```kotlin
        val gate: WriteReauthGate = when (cloudReauthRoute(deviceUnlock.enclaveEnrolled, vaultId, deviceUnlock.metadataVaultId)) {
            GateChoice.GRACE_WINDOW -> GraceWindowReauthGate(
                authorizer = CoordinatorBiometricAuthorizer(deviceUnlock.coordinator, vaultId),
                clock = { SystemClock.elapsedRealtime() },
            )
            GateChoice.NOOP -> NoopReauthGate
        }
        var learnedVaultId = vaultId // will be overwritten by onVaultUuidLearned with the real resolved uuid
```

with:

```kotlin
        // #340: a remembered SAF cloud vault's UUID is "" until it is resolved during open, so the
        // write-reauth gate cannot be chosen up front (cloudReauthRoute("") falls to NOOP even for an
        // enrolled vault). Hand a retargetable placeholder to the open and re-target it from the
        // resolved UUID inside onVaultUuidLearned (which fires before openBrowseWithSync seeds it).
        val gate = RetargetableReauthGate()
        val clock = { SystemClock.elapsedRealtime() }
        var learnedVaultId = vaultId // will be overwritten by onVaultUuidLearned with the real resolved uuid
```

- [ ] **Step 5: Re-target inside the `onVaultUuidLearned` callback**

Replace the callback (currently ~L154-157):

```kotlin
            onVaultUuidLearned = { resolvedHex ->
                learnedVaultId = resolvedHex
                onVaultUuidLearned(resolvedHex)
            },
```

with:

```kotlin
            onVaultUuidLearned = { resolvedHex ->
                learnedVaultId = resolvedHex
                gate.retarget(cloudGateForResolvedVault(deviceUnlock, resolvedHex, clock))
                onVaultUuidLearned(resolvedHex)
            },
```

- [ ] **Step 6: Add the private gate-builder helper**

In `android/app/src/main/kotlin/org/secretary/app/CloudVaultOpen.kt`, add immediately after the closing brace of `openCloudBrowse`:

```kotlin
/**
 * Build the write-reauth gate for a cloud open from the RESOLVED vault UUID (#340). A remembered SAF
 * cloud vault's UUID is unknown before the open, so the gate is chosen here — from `onVaultUuidLearned`
 * — rather than up front. GRACE_WINDOW only when a device secret is enrolled for exactly this vault
 * (see [cloudReauthRoute]); otherwise NOOP (un-enrolled or stale enrollment, which must not block
 * writes). [clock] MUST be the same monotonic source the demo path uses (`SystemClock.elapsedRealtime`).
 */
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

- [ ] **Step 7: Refresh the `openCloudBrowse` doc comment**

In the KDoc for `openCloudBrowse` (currently ~L104-108), replace the "Write-reauth gate:" paragraph:

```kotlin
 * Write-reauth gate: [cloudDeviceUnlockCoordinator] reads enrollment state for this cloud vault;
 * [cloudReauthRoute] selects [GateChoice.GRACE_WINDOW] when a device secret is enrolled for this
 * exact vault UUID, or [GateChoice.NOOP] otherwise (un-enrolled or stale enrollment). The grace
 * window is seeded inside [openBrowseWithSync] (it seeds the gate it is handed), so the window starts
 * at the real unlock instant — this path does not seed again.
```

with:

```kotlin
 * Write-reauth gate (#340): a remembered SAF cloud vault's UUID is "" until it is resolved during the
 * open, so the gate is a [RetargetableReauthGate] placeholder re-targeted from `onVaultUuidLearned`
 * via [cloudGateForResolvedVault] — [cloudReauthRoute] then selects [GateChoice.GRACE_WINDOW] when a
 * device secret is enrolled for the RESOLVED vault UUID, or [GateChoice.NOOP] otherwise (un-enrolled
 * or stale enrollment). The grace window is seeded inside [openBrowseWithSync] (it seeds the gate it
 * is handed); the wrapper re-seeds the retargeted delegate so seeding is correct regardless of order.
```

- [ ] **Step 8: Run the full host gate + build**

Run:
```bash
cd android && ./gradlew :vault-access:test :app:testDebugUnitTest :kit:testDebugUnitTest \
  :app:compileDebugKotlin :app:compileDebugAndroidTestKotlin
```
Expected: BUILD SUCCESSFUL. `CloudReauthRouteTest` 7/7, `RetargetableReauthGateTest` 5/5, no compile regressions in `:app`/`:kit`/androidTest.

- [ ] **Step 9: Commit**

```bash
git add android/app/src/main/kotlin/org/secretary/app/CloudVaultOpen.kt \
        android/app/src/test/kotlin/org/secretary/app/CloudReauthRouteTest.kt
git commit -m "fix(android): re-target cloud write-reauth gate from resolved vault UUID (#340)"
```

---

### Task 3: Docs — README / ROADMAP / handoff

**Files:**
- Modify (if warranted): `README.md`, `ROADMAP.md`
- Create: `docs/handoffs/2026-07-01-android-cloud-reauth-gate-retarget-340-shipped.md`; retarget `NEXT_SESSION.md` symlink.

- [ ] **Step 1: Assess README/ROADMAP**

Grep for a cloud write-reauth / device-enrollment status line:
```bash
cd .worktrees/android-cloud-reauth-gate-retarget-340 || cd . ; grep -n "re-auth\|reauth\|write.reauth\|device enroll" README.md ROADMAP.md
```
If a status bullet describes the cloud write-reauth gate, add a one-line note that the gate now arms on the first open of a remembered cloud vault (#340). If neither doc tracks it at that granularity, skip — do not invent a section (per README-style: brief, dot-point).

- [ ] **Step 2: Write the handoff + retarget the symlink** (per nextsession workflow)

```bash
# author docs/handoffs/2026-07-01-android-cloud-reauth-gate-retarget-340-shipped.md, then:
ln -snf docs/handoffs/2026-07-01-android-cloud-reauth-gate-retarget-340-shipped.md NEXT_SESSION.md
ls -la NEXT_SESSION.md && head -3 NEXT_SESSION.md
```

- [ ] **Step 3: Commit docs + handoff**

```bash
git add README.md ROADMAP.md docs/handoffs/2026-07-01-android-cloud-reauth-gate-retarget-340-shipped.md NEXT_SESSION.md
git commit -m "docs: README/ROADMAP + handoff for cloud write-reauth gate re-target (#340)"
```

---

## Self-Review

- **Spec coverage:** §2.1 `RetargetableReauthGate` → Task 1. §2.2 cloud-path wiring + helper → Task 2 (steps 3-7). §3 tests → Task 1 (wrapper) + Task 2 step 1 (boundary). §4 non-goals need no code (enroll-during-open unchanged by construction). Docs → Task 3. Covered.
- **Placeholder scan:** all code shown in full; no TBD/TODO.
- **Type consistency:** `retarget`, `seededAtMs`, `cloudGateForResolvedVault`, `cloudReauthRoute`, `GateChoice.{GRACE_WINDOW,NOOP}`, `CoordinatorBiometricAuthorizer(coordinator, vaultId)` all match across tasks and existing source (verified against `WriteReauthGate.kt`, `CloudDeviceUnlock.kt`, `CloudVaultOpen.kt`).
