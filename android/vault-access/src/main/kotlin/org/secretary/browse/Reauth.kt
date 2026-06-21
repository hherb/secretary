package org.secretary.browse

/** Grace-window defaults for write re-authentication. Mirror of iOS `ReauthWindow.v1Default`. */
object ReauthWindow {
    /** Default seconds-as-millis a fresh presence proof stays valid before a write re-prompts.
     *  30 s matches the iOS biometric sibling; biometric prompts are fast, so a short window is
     *  low-friction. Not user-configurable in this slice (see the design doc, §2). */
    const val V1_DEFAULT_MS: Long = 30_000L
}

/**
 * Does a mutating write need a fresh presence proof?
 *
 * Pure policy — the single source of truth shared by every gate decision (host-tested in isolation).
 *
 * @param lastAuthAtMs epoch-millis of the last successful proof this session, or null if none yet.
 * @param nowMs        current epoch-millis.
 * @param windowMs     grace window; within it a write is silently authorized.
 * @return true if the user must re-prove presence:
 *   - `lastAuthAtMs == null`            → true  (never authed this session)
 *   - `nowMs - lastAuthAtMs >= window`  → true  (window elapsed; boundary INCLUSIVE)
 *   - otherwise                         → false (still inside the grace window)
 */
fun needsReauth(lastAuthAtMs: Long?, nowMs: Long, windowMs: Long): Boolean {
    if (lastAuthAtMs == null) return true
    return nowMs - lastAuthAtMs >= windowMs
}
