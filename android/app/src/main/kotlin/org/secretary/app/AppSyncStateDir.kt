package org.secretary.app

import java.io.File

/** Subdirectory of the app's private storage that holds per-vault sync state. */
private const val SYNC_STATE_DIRNAME = "sync-state"

/**
 * Resolves the sync-state directory under a given base (the app's `filesDir` in production).
 * Pure (no Android dependency) so the base→subdir mapping is host-testable; the production
 * caller passes `context.filesDir` and is responsible for creating the directory.
 */
fun syncStateDir(base: File): File = File(base, SYNC_STATE_DIRNAME)
