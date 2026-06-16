package org.secretary.sync.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.secretary.sync.SyncVetoDecision

/**
 * Wires a [VaultSyncViewModel]'s collected state into the three surfaces: the always-visible badge,
 * the password sheet (gated on [VaultSyncViewModel.passwordSheetVisible]), and the conflict sheet
 * (gated on [VaultSyncViewModel.pendingConflict] != null). The composables stay stateless; the VM
 * owns the durable state.
 *
 * ## Interactive password lifetime (mirrors desktop D.1.15 / iOS)
 *
 * The just-submitted password is held ONLY in this screen's transient Compose state
 * ([heldPassword]) — never on the VM or the model (spec §6) — so it can be reused for the
 * conflict resolve in a second port call. It is zeroized (`fill(0)`) + dropped on every terminal
 * path:
 *   - a clean pass: when both `pendingConflict` and `passwordSheetVisible` are false.
 *   - conflict cancel: via [VaultSyncViewModel.cancelConflict] callback.
 *   - sheet dismiss: via [VaultSyncViewModel.dismissPasswordSheet] callback.
 *
 * The VM deliberately does NOT zeroize the password buffer (it is a pass-through); this screen is
 * the designated owner of the ByteArray's lifetime and is the sole site responsible for `fill(0)`.
 *
 * ## Sheet sequencing
 *
 * On a conflict outcome, `lastError` is null so the VM closes the password sheet and surfaces
 * `pendingConflict`. On an error outcome (e.g. wrong password), `lastError` is non-null and the
 * password sheet stays open for an inline retry — the VM never closes it on error.
 *
 * @param viewModel  The [VaultSyncViewModel] provided by the host (:kit or a test double).
 */
@Composable
fun SyncScreen(viewModel: VaultSyncViewModel) {
    val badge by viewModel.badge.collectAsStateWithLifecycle()
    val passwordVisible by viewModel.passwordSheetVisible.collectAsStateWithLifecycle()
    val pendingConflict by viewModel.pendingConflict.collectAsStateWithLifecycle()
    val lastError by viewModel.lastError.collectAsStateWithLifecycle()

    // The interactive password, retained from submit until the conflict resolves (or is cancelled
    // or dismissed). Transient UI state only — not rememberSaveable; never persisted.
    var heldPassword by remember { mutableStateOf<ByteArray?>(null) }

    /** Zeroize the byte buffer and drop the reference on every terminal path. */
    fun dropPassword() {
        heldPassword?.fill(0) // zeroize the buffer before dropping the reference
        heldPassword = null
    }

    // When a pass completes clean (conflict sheet gone, password sheet closed), drop the held
    // password. Both flags are consumed together so a conflict→resolve→clean cycle clears once.
    LaunchedEffect(pendingConflict, passwordVisible) {
        if (pendingConflict == null && !passwordVisible) dropPassword()
    }

    SyncBadge(
        state = badge,
        nowMs = System.currentTimeMillis().toULong(),
        onTap = { viewModel.beginInteractiveSync() },
    )

    SyncPasswordSheet(
        visible = passwordVisible,
        error = lastError,
        onSubmit = { pw ->
            heldPassword = pw
            viewModel.submitPassword(pw)
        },
        onDismiss = {
            dropPassword()
            viewModel.dismissPasswordSheet()
        },
    )

    pendingConflict?.let { conflict ->
        ConflictResolutionSheet(
            conflict = conflict,
            error = lastError,
            onResolve = { decisions: List<SyncVetoDecision> ->
                heldPassword?.let { viewModel.resolve(decisions, it) }
            },
            onCancel = {
                dropPassword()
                viewModel.cancelConflict()
            },
        )
    }
}
