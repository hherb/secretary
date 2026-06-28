package org.secretary.mirror

/**
 * A durable one-bit "the working copy holds edits not yet pushed to the cloud" flag. Set when a
 * flush fails (offline / SAF error); checked on the next open to enforce push-before-pull. Kept
 * behind a port so the coordinator's ordering logic is host-testable with an in-memory fake.
 */
interface PendingFlushMarker {
    fun isSet(): Boolean
    fun set()
    fun clear()
}
