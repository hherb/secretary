package org.secretary.sync

/**
 * The model's outbound seam onto the change monitor. [muteSelfWrite] suppresses the detector's
 * self-write false positives around a sync pass's own manifest rewrite; [acknowledge] consumes
 * the pending-change signal after a clean pass. The inbound `pendingChanges` signal flows the
 * other way, pushed into the model via [VaultSyncModel.pendingChangesRaised]. The real conformer
 * is `:kit`'s MonitorSyncHook, wrapping ChangeDetectionMonitor.
 */
interface SyncMonitorHook {
    fun muteSelfWrite()
    fun acknowledge()
}
