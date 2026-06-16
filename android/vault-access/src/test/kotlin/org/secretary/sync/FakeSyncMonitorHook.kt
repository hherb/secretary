package org.secretary.sync

/** Host-test [SyncMonitorHook] that counts forwarded calls (spy). */
class FakeSyncMonitorHook : SyncMonitorHook {
    var muteCount: Int = 0
        private set
    var acknowledgeCount: Int = 0
        private set

    override fun muteSelfWrite() {
        muteCount++
    }

    override fun acknowledge() {
        acknowledgeCount++
    }
}
