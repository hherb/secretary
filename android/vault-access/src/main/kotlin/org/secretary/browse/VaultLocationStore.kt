package org.secretary.browse

/**
 * Persists ONE remembered vault location and reports whether its SAF permission is
 * still granted. The port keeps the platform persistence + SAF permission machinery
 * behind a boundary so the (later) selection view-model is host-testable against a
 * fake. Single-vault by design (this slice): [persist] replaces any prior location.
 *
 * Kotlin mirror of iOS `VaultLocationStore`, minus iOS's `beginAccess`: on Android a
 * SAF tree exposes no real filesystem path, so resolving a location to an operable
 * path is the working-copy *materialize* step (a later slice), not this store's job.
 */
interface VaultLocationStore {
    /** The remembered location, or null if none has been selected. */
    fun load(): VaultLocation?

    /** Remember [location], replacing any prior one. */
    fun persist(location: VaultLocation)

    /** Forget the remembered location. */
    fun clear()

    /**
     * Whether the persistable SAF permission for [location] is still held (the tree has
     * not been revoked / the granting provider uninstalled). The selection screen uses a
     * false result to prompt a re-pick (mirrors iOS's stale-bookmark `.unavailable`).
     */
    fun isAvailable(location: VaultLocation): Boolean
}
