package org.secretary.sync

import kotlin.time.Duration

/**
 * Real [SyncMonitorHook] wrapping a [ChangeDetectionMonitor]. [muteSelfWrite] suppresses detector
 * pulses for [muteWindow] from now (so a sync pass's own manifest rewrite is not re-detected);
 * [acknowledge] consumes the monitor's pending-change signal after a clean pass. [now] defaults to
 * the Android monotonic clock and is injected only for host tests.
 */
class MonitorSyncHook(
    private val monitor: ChangeDetectionMonitor,
    private val muteWindow: Duration = ChangeDetectionTuning.defaultSelfWriteMuteWindow,
    private val now: () -> MonotonicInstant = ::monotonicNow,
) : SyncMonitorHook {
    override fun muteSelfWrite() {
        monitor.muteUntil(now().advancedBy(muteWindow))
    }

    override fun acknowledge() {
        monitor.acknowledge()
    }
}
