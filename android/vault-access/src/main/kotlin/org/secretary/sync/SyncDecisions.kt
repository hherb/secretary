package org.secretary.sync

/**
 * Build the per-record veto decisions from the slice-5 UI's override map, one decision per veto
 * in veto order. A record with no explicit override defaults to `keepLocal = true` ("Keep mine",
 * the no-data-loss choice), matching desktop D.1.15.
 */
fun collectDecisions(
    vetoes: List<SyncVeto>,
    overrides: Map<String, Boolean>,
): List<SyncVetoDecision> =
    vetoes.map { SyncVetoDecision(it.recordUuidHex, overrides[it.recordUuidHex] ?: true) }

/**
 * True iff every veto has an explicit override entry. Mirrors the desktop "Apply enabled" gate;
 * slice 5 decides whether to require explicitness or allow the keep-mine default to stand.
 */
fun decisionsComplete(
    vetoes: List<SyncVeto>,
    overrides: Map<String, Boolean>,
): Boolean =
    vetoes.all { overrides.containsKey(it.recordUuidHex) }
