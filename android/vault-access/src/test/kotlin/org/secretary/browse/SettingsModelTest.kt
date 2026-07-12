package org.secretary.browse

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

@OptIn(ExperimentalCoroutinesApi::class)
class SettingsModelTest {
    /** Records seed instants; the gate factory hands these out as the new-window delegates. */
    private class RecGate : WriteReauthGate {
        val seeds = mutableListOf<Long>()
        override suspend fun authorizeWrite(reason: String) {}
        override fun seed(nowMs: Long) { seeds += nowMs }
    }

    /**
     * Builds a model with an installed pre-save gate delegate that records call ordering (how many
     * writes had happened at authorize time) and can be scripted to refuse. The [makeGraceGate]
     * factory records the requested window and the writes-at-retarget count, so the ordering
     * (authorize → write → retarget) is observable without a shared event log.
     */
    private class Fixture(
        seed: VaultSettings = defaultVaultSettings(),
        private val now: Long = 9_000L,
        failNextWrite: VaultBrowseError? = null,
        failNextRead: VaultBrowseError? = null,
        refuseWith: DeviceUnlockError? = null,
        writeGate: CompletableDeferred<Unit>? = null,
    ) {
        val port = FakeSettingsPort(
            settings = seed,
            failNextWrite = failNextWrite,
            failNextRead = failNextRead,
            writeGate = writeGate,
        )
        val gate = RetargetableReauthGate()
        val authorizeReasons = mutableListOf<String>()
        val writtenAtAuthorize = mutableListOf<Int>()
        val builtWindows = mutableListOf<Long>()
        val writtenAtRetarget = mutableListOf<Int>()
        val builtGates = mutableListOf<RecGate>()

        init {
            gate.retarget(object : WriteReauthGate {
                override suspend fun authorizeWrite(reason: String) {
                    authorizeReasons += reason
                    writtenAtAuthorize += port.writtenSettings.size
                    refuseWith?.let { throw it }
                }
            })
        }

        val makeGraceGate: (Long) -> WriteReauthGate = { w ->
            builtWindows += w
            writtenAtRetarget += port.writtenSettings.size
            RecGate().also { builtGates += it }
        }

        val model = SettingsModel(port, gate, makeGraceGate, nowMs = { now })
    }

    @Test
    fun `load populates controls from persisted settings`() = runTest {
        val f = Fixture(seed = VaultSettings(600_000L, true, 5L * MS_PER_MINUTE, 30L * MS_PER_DAY))
        f.model.load()
        assertEquals(30, f.model.retentionDays.value)
        assertEquals(5, f.model.graceMinutes.value)
        assertNull(f.model.error.value)
    }

    @Test
    fun `load on a read error falls back to defaults and sets error`() = runTest {
        val f = Fixture(failNextRead = VaultBrowseError.CorruptVault("x"))
        f.model.load()
        assertEquals(90, f.model.retentionDays.value)
        assertEquals(2, f.model.graceMinutes.value)
        assertEquals(VaultBrowseError.CorruptVault("x"), f.model.error.value)
    }

    @Test
    fun `setters clamp to the projected bounds`() = runTest {
        val f = Fixture()
        f.model.setRetentionDays(0); assertEquals(1, f.model.retentionDays.value)
        f.model.setRetentionDays(9999); assertEquals(3650, f.model.retentionDays.value)
        f.model.setGraceMinutes(-5); assertEquals(0, f.model.graceMinutes.value)
        f.model.setGraceMinutes(999); assertEquals(60, f.model.graceMinutes.value)
    }

    @Test
    fun `save writes new retention and grace, preserves UI-less fields, retargets, sets notice`() = runTest {
        val f = Fixture(seed = VaultSettings(600_000L, true, 120_000L, 90L * MS_PER_DAY), now = 9_000L)
        f.model.load()
        f.model.setRetentionDays(30)
        f.model.setGraceMinutes(5)
        f.model.save()

        val w = f.port.writtenSettings.single()
        assertEquals(30L * MS_PER_DAY, w.retentionWindowMs)
        assertEquals(5L * MS_PER_MINUTE, w.reauthGraceWindowMs)
        assertEquals(600_000L, w.autoLockTimeoutMs)     // preserved
        assertTrue(w.requirePasswordBeforeEdits)         // preserved
        assertEquals(settingsSavedBanner(), f.model.notice.value)
        assertEquals(listOf(5L * MS_PER_MINUTE), f.builtWindows) // retargeted to the new grace window
        assertEquals(listOf(9_000L), f.builtGates.single().seeds) // new gate seeded at now
        assertFalse(f.model.writing.value)
        assertNull(f.model.error.value)
    }

    @Test
    fun `retarget happens strictly after the write (a widening cannot self-authorize)`() = runTest {
        val f = Fixture(seed = VaultSettings(600_000L, true, 120_000L, 90L * MS_PER_DAY))
        f.model.load()
        f.model.setGraceMinutes(5)     // grace change → will retarget
        f.model.save()
        assertEquals(listOf(0), f.writtenAtAuthorize)  // authorize ran BEFORE any write
        assertEquals(listOf(1), f.writtenAtRetarget)   // retarget ran AFTER the write
        assertEquals(listOf("Confirm changing vault settings"), f.authorizeReasons)
    }

    @Test
    fun `a retention-only save does not retarget`() = runTest {
        val f = Fixture(seed = VaultSettings(600_000L, true, 120_000L, 90L * MS_PER_DAY))
        f.model.load()
        f.model.setRetentionDays(30)   // grace unchanged (still 2 min)
        f.model.save()
        assertTrue(f.builtWindows.isEmpty())   // makeGraceGate never called → no retarget
        assertEquals(settingsSavedBanner(), f.model.notice.value)
        assertEquals(30L * MS_PER_DAY, f.port.writtenSettings.single().retentionWindowMs)
    }

    @Test
    fun `save re-reads UI-less fields at write time (closes the load-save TOCTOU)`() = runTest {
        val f = Fixture(seed = VaultSettings(600_000L, true, 120_000L, 90L * MS_PER_DAY))
        f.model.load()
        // another client changes the two UI-less fields AFTER our load
        f.port.settings = f.port.settings.copy(autoLockTimeoutMs = 700_000L, requirePasswordBeforeEdits = false)
        f.model.setRetentionDays(30)
        f.model.save()
        val w = f.port.writtenSettings.single()
        assertEquals(700_000L, w.autoLockTimeoutMs)  // reflects the re-read, not the load snapshot
        assertFalse(w.requirePasswordBeforeEdits)
    }

    @Test
    fun `save preserves the UI-less fields even when load never ran`() = runTest {
        // seed has non-default UI-less fields; the model saves WITHOUT calling load() first, so the
        // controls hold construction defaults (90 d / 2 min) and only the re-read supplies the rest.
        val f = Fixture(seed = VaultSettings(700_000L, false, 120_000L, 90L * MS_PER_DAY))
        f.model.save()
        val w = f.port.writtenSettings.single()
        assertEquals(700_000L, w.autoLockTimeoutMs)  // preserved from the save-time re-read
        assertFalse(w.requirePasswordBeforeEdits)
    }

    @Test
    fun `a CancellationException from the gate propagates and is not recorded as an error`() = runTest {
        val port = FakeSettingsPort()
        val gate = RetargetableReauthGate()
        gate.retarget(object : WriteReauthGate {
            override suspend fun authorizeWrite(reason: String) = throw CancellationException("cancelled")
        })
        val model = SettingsModel(port, gate, makeGraceGate = { RecGate() }, nowMs = { 0L })
        var propagated = false
        try {
            model.save()
        } catch (e: CancellationException) {
            propagated = true // NOT swallowed by the DeviceUnlockError catch (guards against a future widen to Exception)
        }
        assertTrue(propagated)
        assertFalse(model.writing.value)          // the finally still reset it
        assertTrue(port.writtenSettings.isEmpty())
        assertNull(model.error.value)             // not misrecorded as a reauth error
    }

    @Test
    fun `a user-cancelled reauth aborts silently (no write, no retarget, no notice, no error)`() = runTest {
        val f = Fixture(refuseWith = DeviceUnlockError.UserCancelled)
        f.model.load()
        f.model.setGraceMinutes(5)
        f.model.save()
        assertTrue(f.port.writtenSettings.isEmpty())
        assertTrue(f.builtWindows.isEmpty())
        assertNull(f.model.notice.value)
        assertNull(f.model.error.value)
        assertFalse(f.model.writing.value)
    }

    @Test
    fun `a failed reauth surfaces an error and does not write or retarget`() = runTest {
        val f = Fixture(refuseWith = DeviceUnlockError.BiometryLockout)
        f.model.save()
        assertTrue(f.port.writtenSettings.isEmpty())
        assertTrue(f.builtWindows.isEmpty())
        assertEquals(
            VaultBrowseError.ReauthFailed(reauthFailedMessage(DeviceUnlockError.BiometryLockout)),
            f.model.error.value,
        )
        assertNull(f.model.notice.value)
    }

    @Test
    fun `a write failure surfaces the error and does not retarget or notice`() = runTest {
        val f = Fixture(failNextWrite = VaultBrowseError.InvalidArgument("bad"))
        f.model.load()
        f.model.setGraceMinutes(5)
        f.model.save()
        assertEquals(VaultBrowseError.InvalidArgument("bad"), f.model.error.value)
        assertTrue(f.builtWindows.isEmpty())
        assertNull(f.model.notice.value)
    }

    @Test
    fun `load clears a prior save notice (the VM outlives a screen visit)`() = runTest {
        val f = Fixture()
        f.model.load()
        f.model.setGraceMinutes(5)
        f.model.save()
        assertEquals(settingsSavedBanner(), f.model.notice.value) // banner shown after the save
        f.model.load()                                            // re-enter the screen
        assertNull(f.model.notice.value)                          // stale banner dropped
    }

    @Test
    fun `a second save while a write is in flight is a no-op`() = runTest {
        val writeGate = CompletableDeferred<Unit>()
        val f = Fixture(writeGate = writeGate)
        val job = launch { f.model.save() }
        runCurrent()                       // advance to the suspended writeSettings
        assertTrue(f.model.writing.value)
        f.model.save()                     // second call — rejected by the re-entrancy guard
        writeGate.complete(Unit)
        advanceUntilIdle()
        assertEquals(1, f.port.writtenSettings.size)
        job.join()
    }
}
