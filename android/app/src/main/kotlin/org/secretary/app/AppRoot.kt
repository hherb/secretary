package org.secretary.app

import android.content.Context
import android.os.SystemClock
import android.util.Log
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import org.secretary.browse.CoordinatorBiometricAuthorizer
import org.secretary.browse.DeviceSettingsState
import org.secretary.browse.DeviceSettingsViewModel
import org.secretary.browse.DeviceUnlockCoordinator
import org.secretary.browse.DeviceUnlockState
import org.secretary.browse.DeviceUnlockViewModel
import org.secretary.browse.FileDeviceEnrollmentMetadataStore
import org.secretary.browse.FileDeviceUuidStore
import org.secretary.browse.GraceWindowReauthGate
import org.secretary.browse.KeystoreDeviceSecretEnclave
import org.secretary.browse.MnemonicWord
import org.secretary.browse.UniffiVaultDeviceSlotPort
import org.secretary.browse.UnlockCredential
import org.secretary.browse.VaultLocation
import org.secretary.browse.VaultNameError
import org.secretary.browse.VaultProvisioningError
import org.secretary.browse.VaultProvisioningStep
import org.secretary.browse.VaultProvisioningViewModel
import org.secretary.browse.VaultSelectionState
import org.secretary.browse.VaultSelectionViewModel
import org.secretary.browse.displayNameForTree
import org.secretary.browse.hexOfBytes
import org.secretary.browse.safVaultLocationStore
import org.secretary.browse.uniffiVaultCreatePort
import org.secretary.browse.uniffiVaultOpenPort
import java.io.File

private const val TAG = "AppRoot"

/** The app's screens; Browse carries the live session for the unlocked vault. `internal` (not
 *  `private`) so the cloud-open orchestration in [CloudVaultOpen] can return a [Route]. */
internal sealed interface Route {
    data object Selection : Route
    data object CreateWizard : Route

    /**
     * The unlock screen. [cloudTarget] null = the demo golden vault (the `onDemo` path, unchanged);
     * non-null = a cloud vault whose credential, once entered here, is applied to THAT vault via the
     * working-copy coordinator. Both cloud paths (open-remembered + just-created) route through here.
     */
    data class Unlock(
        val cloudTarget: CloudVaultTarget? = null,
        val unsyncedCreateWarning: Boolean = false,
    ) : Route

    /**
     * The unlocked browse session. [cloudTarget] is carried so backgrounding (ON_STOP) returns to an
     * Unlock screen still targeting the SAME cloud vault (a demo session, [cloudTarget] null, backs
     * to the demo unlock).
     */
    data class Browse(
        val session: BrowseSession,
        val folder: File,
        val showSettings: Boolean = false,
        val cloudTarget: CloudVaultTarget? = null,
    ) : Route
}

/**
 * Top-level routing for the walking skeleton: Unlock → Browse. On unlock it opens the REAL vault
 * (open_vault_with_password, Argon2id offloaded to IO inside the port), builds a BrowseSession
 * (browse VM + sync VM + monitor), fires a background sync-at-unlock, and routes to the unified
 * BrowseWithSyncScreen. On background (ON_STOP) the app routes back to Unlock; leaving Browse
 * disposes its composition, whose DisposableEffect stops the monitor and calls browse.lock() —
 * the session is wiped, so returning requires the password again (lock-on-background, mirroring
 * iOS). FLAG_SECURE (set on the Activity) blocks screenshot/recents capture.
 */
@Composable
fun AppRoot() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var route by remember { mutableStateOf<Route>(Route.Selection) }
    var rememberDevice by remember { mutableStateOf(false) }
    var isUnlocking by remember { mutableStateOf(false) }

    val locationStore = remember { safVaultLocationStore(context) }
    val selectionVm = remember(locationStore) { VaultSelectionViewModel(locationStore) }
    var selectionState by remember { mutableStateOf<VaultSelectionState>(VaultSelectionState.Empty) }
    val provisioningVm = remember(locationStore) {
        VaultProvisioningViewModel(uniffiVaultCreatePort(), locationStore)
    }
    // Mirror the VM's published fields into Compose state. The VM is a pure `:vault-access` class
    // (no Compose dep), so its `step`/`nameError`/`error`/`isCreating`/`mnemonicRows` are plain
    // fields, not Snapshot state. Mirroring ONLY `step` would silently drop error/validation
    // feedback: those change on paths that leave `step` unchanged (a `data object` singleton or the
    // same `Credentials` instance), and `mutableStateOf`'s structural-equality policy then schedules
    // no recomposition. Every field is mirrored and refreshed via [syncProvisioning] after each call.
    var provStep by remember { mutableStateOf<VaultProvisioningStep>(VaultProvisioningStep.Folder) }
    var provNameError by remember { mutableStateOf<VaultNameError?>(null) }
    var provError by remember { mutableStateOf<VaultProvisioningError?>(null) }
    var provIsCreating by remember { mutableStateOf(false) }
    var provMnemonicRows by remember { mutableStateOf<List<MnemonicWord>?>(null) }
    fun syncProvisioning() {
        provStep = provisioningVm.step
        provNameError = provisioningVm.nameError
        provError = provisioningVm.error
        provIsCreating = provisioningVm.isCreating
        provMnemonicRows = provisioningVm.mnemonicRows
    }
    var pickedTreeUri by remember { mutableStateOf<String?>(null) }
    var pickedFolderLabel by remember { mutableStateOf<String?>(null) }
    // The same launcher serves both the Selection screen and the create wizard; this records WHY
    // it was launched so the result is routed to the right consumer (a pick from Selection becomes
    // a recorded VaultLocation → Located; a pick from the wizard fills the parent-folder draft).
    var pendingPick by remember { mutableStateOf(FolderPickTarget.None) }

    val pickFolderLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocumentTree(),
    ) { uri ->
        if (uri != null) {
            val label = displayNameForTree(context, uri)
            when (pendingPick) {
                FolderPickTarget.SelectExisting -> {
                    selectionVm.recordSelection(VaultLocation(label, uri.toString()))
                    selectionState = selectionVm.state
                }
                FolderPickTarget.WizardParent -> {
                    pickedTreeUri = uri.toString()
                    pickedFolderLabel = label
                }
                FolderPickTarget.None -> {}
            }
        }
        pendingPick = FolderPickTarget.None
    }

    val activity = LocalContext.current as? FragmentActivity
        ?: error("AppRoot must be hosted in a FragmentActivity")
    val vaultId = remember { hexOfBytes(AppVaultProvisioning.goldenVaultUuid(context)) }
    val coordinator = remember(activity) {
        val gate = biometricPromptGate(activity, title = "Unlock Secretary")
        val enclave = KeystoreDeviceSecretEnclave(
            dir = File(context.noBackupFilesDir, "devicesecret"),
            gate = gate,
        )
        val metadata = FileDeviceEnrollmentMetadataStore(File(context.noBackupFilesDir, "devicesecret"))
        DeviceUnlockCoordinator(UniffiVaultDeviceSlotPort(), enclave, metadata)
    }
    val deviceVm = remember(coordinator) { DeviceUnlockViewModel(coordinator) }
    var deviceState by remember { mutableStateOf<DeviceUnlockState>(DeviceUnlockState.Unenrolled) }
    // Per-cloud-vault biometric enrollment, computed prompt-free on entering a cloud Unlock screen
    // (see LaunchedEffect(route)). Drives whether the biometric button shows for a cloud target.
    var cloudEnrolled by remember { mutableStateOf(false) }
    val settingsVm = remember(coordinator) { DeviceSettingsViewModel(coordinator) }
    var settingsState by remember { mutableStateOf(DeviceSettingsState(enrolled = false)) }
    LaunchedEffect(route) {
        val current = route
        if (current is Route.Unlock) {
            // #342: clear the "Remember this device" tick on every Unlock-screen entry so it never
            // carries across vaults (tick on vault A → back out → open vault B must start unticked).
            rememberDevice = false
            deviceVm.refresh()
            deviceState = deviceVm.state
            // For a cloud target, read its per-cloud-vault enrollment (enclave blob AND metadata),
            // keyed by the cloud treeUri. Cheap and prompt-free (constructs the Keystore wrapper but
            // never releases). Demo targets leave cloudEnrolled false (the demo path drives the button).
            val cloudTarget = current.cloudTarget
            cloudEnrolled = if (cloudTarget != null) {
                cloudDeviceUnlockCoordinator(
                    activity,
                    context.noBackupFilesDir,
                    cloudVaultKey(cloudTarget.location.treeUri),
                ).coordinator.isEnrolled
            } else {
                false
            }
        }
        if (current is Route.Selection) {
            selectionVm.loadPersisted()
            selectionState = selectionVm.state
        }
    }

    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP) {
                // Re-target the same cloud vault on resume; a demo Browse (cloudTarget null) backs to
                // the demo unlock. Any non-Browse route backgrounds to the demo unlock as before.
                route = Route.Unlock((route as? Route.Browse)?.cloudTarget)
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    when (val r = route) {
        is Route.Selection -> VaultSelectionScreen(
            state = selectionState,
            onCreate = {
                provisioningVm.cancel()
                syncProvisioning()
                pickedTreeUri = null
                pickedFolderLabel = null
                route = Route.CreateWizard
            },
            onOpen = {
                // Open the remembered cloud vault: route to the SAME Unlock screen carrying a cloud
                // target. The working-copy materialize + open runs AFTER the credential is entered
                // (inside the Unlock handler), so the password is captured by the open closure and
                // zeroized there. The working dir is keyed by the cloud treeUri (stable across opens
                // even before the uuid is known; may carry un-pushed edits — NOT reset).
                val loc = locationStore.load()
                if (loc == null) {
                    selectionVm.markUnavailable("No remembered vault to open.")
                    selectionState = selectionVm.state
                } else {
                    val workingDir = cloudWorkingVaultDir(context.filesDir, loc.treeUri, reset = false)
                    route = Route.Unlock(CloudVaultTarget(loc, workingDir, isCreate = false))
                }
            },
            onChooseDifferent = {
                // Delete the forgotten vault's local artifacts (#366) BEFORE chooseDifferent()
                // clears the pref — read the treeUri while it is still known.
                locationStore.load()?.let {
                    forgetCloudVaultArtifacts(context.filesDir, context.noBackupFilesDir, it.treeUri)
                }
                selectionVm.chooseDifferent()
                selectionState = selectionVm.state
            },
            onPickFolder = { pendingPick = FolderPickTarget.SelectExisting; pickFolderLauncher.launch(null) },
            onDemo = { route = Route.Unlock() },
        )
        is Route.CreateWizard -> CreateVaultWizardScreen(
            step = provStep,
            nameError = provNameError,
            error = provError,
            isCreating = provIsCreating,
            mnemonicRows = provMnemonicRows,
            onPickParent = { pendingPick = FolderPickTarget.WizardParent; pickFolderLauncher.launch(null) },
            pickedFolderLabel = pickedFolderLabel,
            onChooseFolder = { name ->
                val tree = pickedTreeUri
                if (tree == null) {
                    Toast.makeText(context, "Choose a cloud folder first.", Toast.LENGTH_SHORT).show()
                } else {
                    provisioningVm.chooseFolder(tree, name)
                    syncProvisioning()
                }
            },
            onCreate = { password, confirm ->
                val creds = provisioningVm.step as? VaultProvisioningStep.Credentials
                if (creds != null) {
                    val pw = password.toByteArray()
                    val cf = confirm.toByteArray()
                    // Key the create working dir by the cloud treeUri (stable across the later reopen),
                    // reset to honor createInFolder's empty-dir contract. The same key is used by the
                    // create-then-open and open-remembered paths, so un-pushed edits never orphan.
                    val workingDir = cloudWorkingVaultDir(context.filesDir, creds.treeUri, reset = true)
                    // Reflect the in-flight create synchronously so the button disables (and shows
                    // "Creating…") while the suspending Argon2id create runs; syncProvisioning()
                    // below settles the final isCreating/error/step from the VM.
                    provIsCreating = true
                    provError = null
                    scope.launch {
                        try {
                            provisioningVm.create(workingDir.path, pw, cf)
                        } finally {
                            pw.fill(0); cf.fill(0)
                        }
                        syncProvisioning()
                    }
                }
            },
            onAcknowledge = {
                provisioningVm.acknowledgeMnemonic()
                val done = provisioningVm.step as? VaultProvisioningStep.Done
                if (done != null) {
                    // Created vault: the location is already persisted (in create()). Do NOT auto-open
                    // with the wizard password (matches desktop "no auto-open"): route to the SAME
                    // Unlock screen carrying a create cloud target. On credential submit the handler
                    // runs createThenOpen (flush working→cloud pushes the new vault up, then open+sync).
                    // The working dir is the SAME treeUri-keyed dir create wrote into, resolved WITHOUT
                    // reset (a reset would wipe the freshly-created vault).
                    selectionVm.recordSelection(done.location)
                    selectionState = selectionVm.state
                    val workingDir = cloudWorkingVaultDir(context.filesDir, done.location.treeUri, reset = false)
                    Toast.makeText(context, "Vault created.", Toast.LENGTH_SHORT).show()
                    route = Route.Unlock(CloudVaultTarget(done.location, workingDir, isCreate = true))
                } else {
                    syncProvisioning() // surfaces a store-fault error on the mnemonic step
                }
            },
            onCancel = {
                provisioningVm.cancel()
                syncProvisioning()
                route = Route.Selection
            },
        )
        is Route.Unlock -> UnlockScreen(
            title = unlockScreenTitle(r.cloudTarget),
            // Biometric-OPEN is now available for a cloud target too (#337): a cloud target follows its
            // per-cloud-vault enrollment (cloudEnrolled), the demo target follows the demo enclave. The
            // "Remember this device" checkbox (shown when !isEnrolled) stays live for enrolling a new device.
            isEnrolled = unlockBiometricEnrolled(
                isCloudTarget = r.cloudTarget != null,
                demoEnrolled = deviceState is DeviceUnlockState.Enrolled,
                cloudEnrolled = cloudEnrolled,
            ),
            rememberDevice = rememberDevice,
            isUnlocking = isUnlocking,
            onUnlock = { credential ->
                // Publish the in-flight flag synchronously so the button disables before the next
                // frame — prevents a double-tap launching two concurrent opens (mirrors onEnroll below).
                isUnlocking = true
                scope.launch {
                    try {
                        val target = r.cloudTarget
                        route = if (target != null) {
                            openCloudTarget(context, activity, target, credential, enrollThisDevice = rememberDevice, locationStore, selectionVm).also { result ->
                                selectionState = selectionVm.state
                                // openCloudTarget returns Route.Unlock (same target) on any open/create
                                // failure — surface it instead of silently re-showing the Unlock screen
                                // (a SAF provider hiccup, e.g. eventually-consistent cloud, or a wrong
                                // password otherwise looks like a dead button).
                                if (result is Route.Unlock) {
                                    Toast.makeText(
                                        context,
                                        "Couldn't open the cloud vault — check the folder is reachable and the password is correct, then try again.",
                                        Toast.LENGTH_LONG,
                                    ).show()
                                }
                            }
                        } else {
                            unlockAndOpen(context, scope, credential, enrollAfter = rememberDevice, coordinator, vaultId)
                        }
                    } finally {
                        isUnlocking = false
                    }
                }
            },
            onEnrollChoice = { rememberDevice = it },
            onBiometricUnlock = {
                // Publish the in-flight flag synchronously (see onUnlock) so a double-tap can't launch
                // two concurrent biometric prompts before the button disables.
                isUnlocking = true
                scope.launch {
                    try {
                        val cloudTarget = r.cloudTarget
                        if (cloudTarget != null) {
                            // Cloud biometric open: build the per-cloud-vault coordinator, release the
                            // secret behind the prompt, then route the DeviceSecret credential through the
                            // SAME openCloudTarget pipeline the password path uses (enrollThisDevice=false:
                            // a biometric unlock means the device is already enrolled). The vaultId guard
                            // is the ENROLLED id (metadataVaultId): the location's UUID may be empty/stale,
                            // and DeviceUnlockCoordinator.unlock checks enrollment.vaultId == vaultId before
                            // prompting. The open itself uses the deviceUuid carried in the credential.
                            val cdu = cloudDeviceUnlockCoordinator(
                                activity,
                                context.noBackupFilesDir,
                                cloudVaultKey(cloudTarget.location.treeUri),
                            )
                            val cloudVm = DeviceUnlockViewModel(cdu.coordinator)
                            cloudVm.unlockWithBiometrics(
                                vaultId = cdu.metadataVaultId ?: "",
                                reason = "Unlock your vault",
                            ) { credential ->
                                route = openCloudTarget(
                                    context, activity, cloudTarget, credential,
                                    enrollThisDevice = false, locationStore, selectionVm,
                                ).also { result ->
                                    selectionState = selectionVm.state
                                    if (result is Route.Unlock) {
                                        Toast.makeText(
                                            context,
                                            "Couldn't open the cloud vault — check the folder is reachable, then try again.",
                                            Toast.LENGTH_LONG,
                                        ).show()
                                    }
                                }
                            }
                            // #341: surface a non-cancel biometric failure, symmetric with the demo path
                            // (UserCancelled stays silent). The open-stage failure Toast (openCloudTarget →
                            // Route.Unlock) is complementary — it covers the post-credential open failure.
                            toastBiometricFailure(context, cloudVm.state)
                            // Recompute prompt-free so a cancel/failed prompt keeps the button (the screen
                            // stays on Unlock; LaunchedEffect(route) won't re-fire).
                            cloudEnrolled = cdu.coordinator.isEnrolled
                        } else {
                            deviceVm.unlockWithBiometrics(
                                vaultId = vaultId,
                                reason = "Unlock your vault",
                            ) { credential -> route = unlockAndOpen(context, scope, credential, enrollAfter = false, coordinator, vaultId) }
                            // #341: a non-cancel DeviceUnlockError leaves state=Failed and never opened —
                            // surface it (UserCancelled stays silent) BEFORE refresh() overwrites the state.
                            toastBiometricFailure(context, deviceVm.state)
                            // On success we've already routed to Browse. On a failed/cancelled prompt the VM
                            // leaves state=Failed; recompute enrolled-vs-unenrolled from the blob (prompt-free)
                            // so the "Unlock with biometrics" button persists — a cancel must not strand the
                            // user on the password-only screen (LaunchedEffect(route) won't re-fire here).
                            deviceVm.refresh()
                            deviceState = deviceVm.state
                        }
                    } finally {
                        isUnlocking = false
                    }
                }
            },
            unsyncedCreateWarning = r.unsyncedCreateWarning,
        )
        is Route.Browse -> {
            // Monitor + session lifecycle keyed on the SESSION instance only — flipping showSettings
            // keeps the same instance, so a Settings excursion never disposes/locks the vault. Only
            // ON_STOP (→ Route.Unlock) tears it down.
            DisposableEffect(r.session) {
                try {
                    r.session.monitor.start()
                } catch (e: Exception) {
                    Log.w(TAG, "folder-change monitor failed to start", e)
                }
                onDispose {
                    r.session.monitor.stop()
                    r.session.browse.lock()
                }
            }
            if (r.showSettings) {
                DeviceSettingsScreen(
                    state = settingsState,
                    onEnroll = { password ->
                        // Publish working=true synchronously so the button disables during the
                        // in-flight enroll (incl. the biometric prompt) — prevents a double-tap.
                        settingsState = settingsState.copy(working = true, error = null)
                        scope.launch {
                            try {
                                settingsVm.enroll(r.folder.path, vaultId, password)
                            } finally {
                                password.fill(0) // zeroize the re-prompted password on every exit
                            }
                            settingsState = settingsVm.state
                        }
                    },
                    onDisenroll = {
                        settingsState = settingsState.copy(working = true, error = null)
                        scope.launch {
                            settingsVm.disenroll(r.folder.path)
                            settingsState = settingsVm.state
                        }
                    },
                    onBack = { route = r.copy(showSettings = false) },
                )
            } else {
                BrowseWithSyncScreen(
                    browse = r.session.browse,
                    sync = r.session.sync,
                    onOpenSettings = {
                        // Refresh enrolled-vs-not (prompt-free, synchronous) BEFORE routing in, so the
                        // Settings screen's first frame shows the true status — no "not enrolled" flash.
                        settingsVm.refresh()
                        settingsState = settingsVm.state
                        route = r.copy(showSettings = true)
                    },
                )
            }
        }
    }
}

/**
 * #341: Toast a non-cancel biometric [DeviceUnlockState.Failed] via the pure [deviceUnlockFailureDisplay]
 * classifier. [DeviceUnlockError.UserCancelled] (→ `Silent`) and any non-`Failed` terminal state show
 * nothing — a deliberate cancel or a success must not nag. Shared by the demo and cloud biometric
 * branches so the surfaced set is symmetric.
 */
private fun toastBiometricFailure(context: Context, state: DeviceUnlockState) {
    val failed = state as? DeviceUnlockState.Failed ?: return
    when (val display = deviceUnlockFailureDisplay(failed.error)) {
        DeviceUnlockFailureDisplay.Silent -> {}
        is DeviceUnlockFailureDisplay.Message ->
            Toast.makeText(context, display.text, Toast.LENGTH_LONG).show()
    }
}

/**
 * Opens the vault for browsing with [credential], assembles the sync model+monitor, fires the
 * post-open sync action ([dispatchPostOpenSync]: password → background sync-at-unlock; recovery →
 * status refresh, since Android sync is password-keyed), and returns the Browse route. Runs on the
 * main `scope` (Argon2id hops to IO inside the open port; makeVaultSync inside [openBrowseWithSync]
 * requires main — satisfied here).
 *
 * Secret hygiene: the credential bytes are zeroized in a `finally` wrapping the whole body — on
 * every exit (success, open failure, early provisioning throw). Enroll (when [enrollAfter] is true)
 * runs BEFORE the finally so it can copy the password into the enclave before zeroize. Enroll
 * failure is non-fatal: it is logged and the successful Browse route is still returned. For the
 * password credential the background sync-at-unlock receives a COPY ([launchSyncAtUnlock]);
 * zeroizing the original here cannot corrupt that copy. The recovery credential hands no copy to a
 * background job, so its bytes are fully owned here.
 */
private suspend fun unlockAndOpen(
    context: Context,
    scope: CoroutineScope,
    credential: UnlockCredential,
    enrollAfter: Boolean,
    coordinator: DeviceUnlockCoordinator,
    vaultId: String,
): Route {
    try {
        val folder = AppVaultProvisioning.stageGoldenVault(context)
        val deviceUuids = FileDeviceUuidStore(File(context.noBackupFilesDir, "devices"))
        val stateDir = syncStateDir(context.filesDir).apply { mkdirs() }
        val uuid = AppVaultProvisioning.goldenVaultUuid(context)
        val writeReauthGate = GraceWindowReauthGate(
            // Monotonic clock — see BrowseSession.openBrowseWithSync; the seed there shares this base.
            authorizer = CoordinatorBiometricAuthorizer(coordinator, vaultId),
            clock = { SystemClock.elapsedRealtime() },
        )
        val session = openBrowseWithSync(
            uniffiVaultOpenPort(deviceUuids), folder, stateDir, uuid, credential, writeReauthGate)
        // Password → background sync-at-unlock from a COPY (deliberately outlives Browse disposal:
        // it opens its own vault handle and never touches the browse session; binding it to the
        // Browse scope would cancel the in-flight Argon2id on background). Recovery → status refresh
        // only: Android sync is password-keyed, so a recovery session has no password to sync with;
        // the user syncs manually via the badge re-prompt.
        dispatchPostOpenSync(
            credential,
            onPassword = { pw -> launchSyncAtUnlock(scope, pw, session.sync::syncAtUnlock) },
            onRecovery = { session.sync.refreshStatus() },
        )
        if (enrollAfter && credential is UnlockCredential.Password) {
            try {
                coordinator.enroll(folder.path, vaultId, credential.secret)
            } catch (e: Exception) {
                // Non-fatal: the password open already succeeded, so we route to Browse regardless.
                // Common cause is no strong biometric enrolled on the device (Keystore key-gen
                // rejects auth-required keys then). Surface it so a user who ticked "remember this
                // device" isn't left silently un-enrolled with no idea why.
                Log.w(TAG, "device enroll failed; password open still succeeded", e)
                Toast.makeText(
                    context,
                    "Couldn't enable biometric unlock — check that a fingerprint/face is enrolled.",
                    Toast.LENGTH_LONG,
                ).show()
            }
        }
        return Route.Browse(session, folder)
    } catch (e: Exception) {
        Log.w(TAG, "unlock/open failed; returning to unlock screen", e)
        Toast.makeText(context, unlockFailureMessage(e), Toast.LENGTH_LONG).show()
        return Route.Unlock()
    } finally {
        credential.secret.fill(0) // zeroize on every exit; the password background copy is independent
    }
}
