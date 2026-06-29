package org.secretary.app

import org.secretary.browse.DeviceUnlockCoordinator

/**
 * Enrol this device against a cloud working copy, ATOMICALLY including the cloud round-trip.
 *
 * 1. If [alreadyEnrolledForThisVault], do nothing (avoids minting a duplicate slot on re-open). The
 *    caller computes it as `enclave.isEnrolled && metadata.load()?.vaultId == vaultId` — keeping the
 *    metadata read at the call site so this function takes no extra dependency and stays pure-ish.
 * 2. `coordinator.enroll` mints `devices/<uuid>.wrap` into the working copy, stores the secret in the
 *    keyed Keystore enclave, and saves keyed metadata (its own internal rollback covers slot/enclave/
 *    metadata failures).
 * 3. [flushWorkingToCloud] pushes the new wrap file to the cloud (the THROWING `mirror.flush()`, not
 *    `afterCommit` which swallows). If it throws, the slot lives only locally — a half-enrolled state
 *    that the next materialize would silently invalidate — so we [DeviceUnlockCoordinator.disenroll]
 *    to roll the whole enrollment back, then rethrow. This is the one deliberate deviation from the
 *    #327 "set marker, retry later" pattern: a partially-enrolled device is worse than an un-enrolled
 *    one.
 *
 * [password] is caller-owned (forwarded to enroll, not zeroized here — the caller's `finally` does it).
 */
suspend fun cloudEnrollThisDevice(
    coordinator: DeviceUnlockCoordinator,
    alreadyEnrolledForThisVault: Boolean,
    workingDirPath: String,
    vaultId: String,
    password: ByteArray,
    flushWorkingToCloud: suspend () -> Unit,
) {
    if (alreadyEnrolledForThisVault) return

    coordinator.enroll(workingDirPath, vaultId, password)
    try {
        flushWorkingToCloud()
    } catch (e: Throwable) {
        runCatching { coordinator.disenroll(workingDirPath) }
        throw e
    }
}
